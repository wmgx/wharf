//! `wharf doctor`：只读诊断。沿每个域名的访问链路逐层检查：
//! 域名解析 → HTTPS（从控制面访问）→ 网关容器 → 网关所在机器连上游 → 服务容器。
//! 每层独立检查，第一个不通的就是要先看的地方。

use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{AgentOp, ProbeTarget},
  spec::GatewayKind,
  view::{
    CheckStatus, DoctorCheck, DoctorReport, Perm, RouteDiagnosis,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  doctor_diagnose::{self, Target},
  render::Net,
  snapshot::{self, Snapshot},
  state::AppState,
  views::{LiveMap, live_states, route_view_with_upstream_error},
  world::gateway_project,
};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
pub struct DoctorQuery {
  /// 只查这个域名。
  pub host: Option<String>,
}

/// `GET /api/doctor[?host=]`：现查。查全部域名时顺便更新后台检查的结果。
pub async fn doctor(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<DoctorQuery>,
) -> ApiResult<DoctorReport> {
  auth.require(Perm::Read)?;
  let (report, vendors) = tokio::try_join!(
    run(&s, q.host.as_deref(), true),
    crate::vendor_checks::checks(&s)
  )?;
  let report = DoctorReport { vendors, ..report };
  if q.host.is_none() {
    crate::vendor_checks::record(&s, &report.vendors).await;
    remember(report.clone());
  }
  Ok(Json(report))
}

/// 最近一次检查全部域名的结果（后台每 2 分钟一次，或手动 `doctor`）。
static LAST: std::sync::RwLock<Option<DoctorReport>> =
  std::sync::RwLock::new(None);

fn remember(report: DoctorReport) {
  if let Ok(mut last) = LAST.write() {
    *last = Some(report);
  }
}

pub fn last() -> Option<DoctorReport> {
  LAST.read().ok().and_then(|l| l.clone())
}

/// 启动后先等 agent 连上再查，否则第一次全是"容器查不到"。
const FIRST_TICK: Duration = Duration::from_secs(20);
const TICK: Duration = Duration::from_secs(120);

/// 后台定时检查全部域名：页面上"服务好不好"以网址能不能打开为准。
pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    loop {
      match run(&state, None, false).await {
        Ok(report) => {
          crate::probe::observe(&state, &report).await;
          remember(report)
        }
        Err(e) => tracing::warn!("域名检查失败：{e}"),
      }
      tokio::time::sleep(TICK).await;
    }
  });
}

/// 逐层检查域名；`host` 为空时检查全部。
pub async fn run(
  s: &AppState,
  host: Option<&str>,
  manual: bool,
) -> Result<DoctorReport, wharf_api_types::ApiError> {
  let snap = snapshot::load(&s.db).await?;
  if let Some(host) = host
    && !snap.world.routes.contains_key(host)
  {
    return Err(
      wharf_api_types::ApiError::not_found(format!(
        "没有域名 {host}"
      ))
      .suggest("wharf route ls"),
    );
  }
  let expired =
    crate::share::expired(&snap.world, Utc::now().timestamp_millis());
  if let Some(host) = host
    && expired.iter().any(|h| h == host)
  {
    return Err(
      wharf_api_types::ApiError::invalid(format!(
        "临时分享 {host} 已失效，不做体检"
      ))
      .suggest(format!("wharf route rm {host} --apply")),
    );
  }
  let net = snap.net(&snap.world);
  let live = live_states(s, &snap.world).await;
  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(HTTP_TIMEOUT)
    .tls_info(true)
    .build()
    .map_err(|e| {
      wharf_api_types::ApiError::internal(format!("HTTP 客户端：{e}"))
    })?;
  let hosts: Vec<&String> = snap
    .world
    .routes
    .keys()
    .filter(|h| {
      host.is_none_or(|q| q == h.as_str()) && !expired.contains(h)
    })
    .collect();
  let mut routes: Vec<_> = futures_util::future::join_all(
    hosts
      .into_iter()
      .map(|h| route(s, &snap, &net, &live, &client, h, manual)),
  )
  .await
  .into_iter()
  .flatten()
  .collect();
  if manual {
    doctor_diagnose::enrich(s, &mut routes).await;
  }
  Ok(DoctorReport {
    checked_at: Utc::now(),
    servers: servers(s, &snap),
    routes: routes.into_iter().map(|(route, _)| route).collect(),
    vendors: vec![],
    config: crate::lint::doctor_warnings(&snap)
      .into_iter()
      .map(|(subject, detail)| {
        // plan 里是“服务 X 的…”连着读；doctor 主语单独一列，去掉开头的“的”。
        let detail = detail.trim_start_matches('的').trim_start();
        check("config", subject, CheckStatus::Warn, detail)
      })
      .collect(),
  })
}

pub(crate) fn check(
  layer: &str,
  subject: impl Into<String>,
  status: CheckStatus,
  detail: impl Into<String>,
) -> DoctorCheck {
  DoctorCheck {
    layer: layer.into(),
    subject: subject.into(),
    status,
    detail: detail.into(),
    at: Utc::now(),
  }
}

fn servers(s: &AppState, snap: &Snapshot) -> Vec<DoctorCheck> {
  let mut checks: Vec<_> = snap
    .world
    .servers
    .keys()
    .map(|name| {
      if s.hub.is_online(name) {
        check("agent", name, CheckStatus::Ok, "在线")
      } else if snap.agent(name).is_none() {
        check("agent", name, CheckStatus::Warn, "还没有加入")
      } else {
        check("agent", name, CheckStatus::Bad, "离线")
      }
    })
    .collect();
  checks.extend(
    crate::net_conflict::conflicts(snap).into_iter().map(
      |(server, detail)| {
        check(
          "network",
          server,
          CheckStatus::Bad,
          format!("{detail}。{}", crate::net_conflict::FIX),
        )
      },
    ),
  );
  checks
}

async fn route(
  s: &AppState,
  snap: &Snapshot,
  net: &Net,
  live: &LiveMap,
  client: &reqwest::Client,
  host: &str,
  manual: bool,
) -> Option<(RouteDiagnosis, Option<Target>)> {
  let (view, upstream_error) =
    route_view_with_upstream_error(snap, net, host)?;
  let world = &snap.world;
  let gateway = view
    .gateway
    .as_ref()
    .and_then(|g| world.gateways.get(g).map(|row| (g, &row.spec)));
  let mut checks = vec![
    dns(host, gateway.map(|g| g.1), net, view.spec.internal).await,
  ];
  let (mut https, cert_expires, bad_gateway) =
    https(client, &view.url, view.spec.auth).await;
  let auto_tls = gateway.is_some_and(|(_, g)| {
    g.kind == wharf_api_types::spec::GatewayKind::Caddy
      && g.tls == wharf_api_types::spec::GatewayTls::Auto
  });
  if auto_tls
    && https.status == CheckStatus::Bad
    && tls_failed(&https.detail)
  {
    https.detail = format!(
      "证书还没签下来（申请中或申请失败），执行 wharf route cert {host} 看原因：{}",
      https.detail
    );
  }
  checks.push(https);
  let mut diagnosis = RouteDiagnosis {
    hostname: host.into(),
    url: view.url,
    checks,
    cert_expires,
    domain_expires: crate::rdap::expires_of(host),
  };
  let Some((gw_name, gw)) =
    gateway.filter(|_| view.spec.redirect.is_none())
  else {
    // 边缘应用和跳转路由只查到 HTTPS 这一层。
    return Some((diagnosis, None));
  };
  let gateway = gateway_check(live, gw_name, &gw.server);
  let service = if view.spec.upstream.is_none() {
    world.services.get(&view.spec.service)
  } else {
    None
  };
  let cross_host =
    service.is_some_and(|row| row.spec.server != gw.server);
  let (link_check, link_unreachable) = match &view.upstream {
    Some(up) => link(s, &gw.server, up, cross_host).await,
    None => (
      check(
        "link",
        format!("{} → 上游", gw.server),
        CheckStatus::Bad,
        upstream_error.map_or_else(
          || "算不出上游地址，执行 wharf plan 看原因".into(),
          |e| match e.hint {
            Some(hint) => format!("{}（{hint}）", e.message),
            None => e.message,
          },
        ),
      ),
      false,
    ),
  };
  let target = service.and_then(|row| {
    let active = live
      .get(&row.spec.server)
      .and_then(|states| states.as_ref().ok())
      .and_then(|states| states.get(&view.spec.service))
      .is_some_and(|p| {
        p.containers.iter().any(|c| {
          !c.foreign
            && matches!(c.state.as_str(), "running" | "restarting")
        })
      });
    if !doctor_diagnose::should_diagnose(
      manual,
      view.upstream.is_some()
        && link_check.status == CheckStatus::Bad,
      bad_gateway,
      gateway.status == CheckStatus::Ok,
      active,
    ) {
      return None;
    }
    let port = *row.host_ports.get(world.route_port(&view.spec)?)?;
    Some(Target {
      service: view.spec.service.clone(),
      server: row.spec.server.clone(),
      port,
      same_host: !cross_host,
      http_failed: bad_gateway && gateway.status == CheckStatus::Ok,
      link_unreachable,
    })
  });
  diagnosis.checks.extend([
    gateway,
    link_check,
    container(world, live, &view.spec),
  ]);
  Some((diagnosis, target))
}

/// caddy 网关的域名应该解析到网关机器的公网 IP；经 CDN 代理或隧道时是厂商的 IP。
async fn dns(
  host: &str,
  gateway: Option<&wharf_api_types::spec::GatewaySpec>,
  net: &Net,
  internal: bool,
) -> DoctorCheck {
  let lookup = tokio::time::timeout(
    DNS_TIMEOUT,
    tokio::net::lookup_host((host, 443)),
  )
  .await;
  let ips: Vec<IpAddr> = match lookup {
    Err(_) => {
      return check("dns", host, CheckStatus::Bad, "解析超时");
    }
    Ok(Err(e)) => {
      return check(
        "dns",
        host,
        CheckStatus::Bad,
        format!("解析失败：{e}"),
      );
    }
    Ok(Ok(addrs)) => {
      let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
      ips.dedup();
      ips
    }
  };
  let shown = ips
    .iter()
    .map(IpAddr::to_string)
    .collect::<Vec<_>>()
    .join(", ");
  let expected = gateway
    .filter(|g| g.kind == GatewayKind::Caddy)
    .and_then(|g| {
      let ip = if internal {
        net.private.get(&g.server).map(|a| &a.ip)
      } else {
        net.public_ip.get(&g.server)
      };
      ip.map(|ip| (g, ip))
    });
  match expected {
    Some((g, ip)) if !ips.iter().any(|a| a.to_string() == *ip) => {
      check(
        "dns",
        host,
        CheckStatus::Warn,
        if internal {
          format!(
            "解析到 {shown}，不是入口所在 {} 的内网地址 {ip}",
            g.server
          )
        } else {
          format!(
            "解析到 {shown}，不是网关所在 {} 的公网 IP {ip}（经 CDN 代理时正常）",
            g.server
          )
        },
      )
    }
    _ => {
      check("dns", host, CheckStatus::Ok, format!("解析到 {shown}"))
    }
  }
}

/// 从控制面访问一次。502 / 504 是网关连不上上游，看后面几层。
/// 顺带读证书到期时间，快到期时标黄。
async fn https(
  client: &reqwest::Client,
  url: &str,
  auth: bool,
) -> (DoctorCheck, Option<DateTime<Utc>>, bool) {
  let layer = if url.starts_with("https") {
    "https"
  } else {
    "http"
  };
  match client.get(url).send().await {
    Err(e) => (
      check(layer, url, CheckStatus::Bad, error_chain(&e)),
      None,
      false,
    ),
    Ok(r) => {
      let expires = r
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|t| t.peer_certificate())
        .and_then(crate::cert::not_after);
      let code = r.status();
      let status = if code.is_server_error() {
        CheckStatus::Bad
      } else if code == reqwest::StatusCode::UNAUTHORIZED && auth {
        CheckStatus::Ok
      } else if code.is_client_error()
        && code != reqwest::StatusCode::UNAUTHORIZED
      {
        CheckStatus::Warn
      } else {
        CheckStatus::Ok
      };
      let mut detail = format!("HTTP {}", code.as_u16());
      let bad_gateway = matches!(code.as_u16(), 502 | 504);
      if bad_gateway {
        detail.push_str("：网关连不上上游");
      }
      if let Some(to) =
        r.headers().get("location").and_then(|v| v.to_str().ok())
      {
        detail.push_str(&format!(" → {to}"));
      }
      let mut status = status;
      if let Some(t) = expires {
        let days = (t - Utc::now()).num_days();
        detail.push_str(&format!("，证书剩 {days} 天"));
        if days < crate::cert::WARN_DAYS && status == CheckStatus::Ok
        {
          status = CheckStatus::Warn;
        }
      }
      (check(layer, url, status, detail), expires, bad_gateway)
    }
  }
}

/// TLS 握手失败：Caddy 还没有这个域名的证书时会直接断开握手。
fn tls_failed(detail: &str) -> bool {
  let d = detail.to_ascii_lowercase();
  ["tls", "handshake", "certificate", "ssl"]
    .iter()
    .any(|k| d.contains(k))
}

/// reqwest 的错误信息在 source 链里（证书、连接拒绝等）。
fn error_chain(e: &dyn std::error::Error) -> String {
  let mut parts = vec![e.to_string()];
  let mut source = e.source();
  while let Some(s) = source {
    parts.push(s.to_string());
    source = s.source();
  }
  parts.dedup();
  parts.join("：")
}

fn gateway_check(
  live: &LiveMap,
  name: &str,
  server: &str,
) -> DoctorCheck {
  let subject = format!("{server} 上的网关 {name}");
  match live.get(server) {
    None => check("gateway", subject, CheckStatus::Bad, "查不到状态"),
    Some(Err(e)) => {
      check("gateway", subject, CheckStatus::Bad, e.message.clone())
    }
    Some(Ok(states)) => match states.get(&gateway_project(name)) {
      Some(p) if p.all_running() => {
        check("gateway", subject, CheckStatus::Ok, "运行中")
      }
      Some(p) if !p.containers.is_empty() => check(
        "gateway",
        subject,
        CheckStatus::Bad,
        p.containers
          .iter()
          .map(|c| format!("{} {}", c.service, c.status))
          .collect::<Vec<_>>()
          .join("，"),
      ),
      _ => check("gateway", subject, CheckStatus::Bad, "没有部署"),
    },
  }
}

/// 网关所在机器的 agent 去连上游地址（agent 用主机网络，和网关看到的一样）。
async fn link(
  s: &AppState,
  server: &str,
  upstream: &str,
  cross_host: bool,
) -> (DoctorCheck, bool) {
  let subject = format!("{server} → {upstream}");
  if !s.hub.is_online(server) {
    return (
      check("link", subject, CheckStatus::Skip, "agent 离线，测不了"),
      false,
    );
  }
  let result: Result<Vec<bool>, _> = s
    .hub
    .call(
      server,
      AgentOp::Probe {
        targets: vec![ProbeTarget {
          server: String::new(),
          addr: upstream.to_string(),
          plain: true,
        }],
      },
      PROBE_TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await;
  match result {
    Ok(r) if r.first() == Some(&true) => {
      (check("link", subject, CheckStatus::Ok, "能连上"), false)
    }
    Ok(_) => (
      check(
        "link",
        subject,
        CheckStatus::Bad,
        if cross_host {
          "连不上：上游没在监听，或者两台机器之间不通（wharf network --probe）"
        } else {
          "连不上上游，检查应用的监听地址和端口"
        },
      ),
      true,
    ),
    Err(e) => {
      (check("link", subject, CheckStatus::Bad, e.message), false)
    }
  }
}

fn container(
  world: &crate::world::World,
  live: &LiveMap,
  route: &wharf_api_types::spec::RouteSpec,
) -> DoctorCheck {
  if route.upstream.is_some() {
    return check(
      "container",
      "外部上游",
      CheckStatus::Skip,
      "不归 Wharf 管",
    );
  }
  let Some(row) = world.services.get(&route.service) else {
    return check(
      "container",
      &route.service,
      CheckStatus::Bad,
      "服务不存在",
    );
  };
  let server = &row.spec.server;
  let subject = format!("{server} 上的 {}", route.service);
  let states = match live.get(server) {
    None => {
      return check(
        "container",
        subject,
        CheckStatus::Bad,
        "查不到状态",
      );
    }
    Some(Err(e)) => {
      return check(
        "container",
        subject,
        CheckStatus::Bad,
        e.message.clone(),
      );
    }
    Some(Ok(states)) => states,
  };
  let Some(p) = states
    .get(&route.service)
    .filter(|p| !p.containers.is_empty())
  else {
    return check("container", subject, CheckStatus::Bad, "没有容器");
  };
  if row.spec.stopped {
    return check(
      "container",
      subject,
      CheckStatus::Warn,
      "按配置停止",
    );
  }
  let bad: Vec<String> = p
    .containers
    .iter()
    .filter(|c| !c.foreign)
    .filter(|c| {
      c.state != "running" || c.health.as_deref() == Some("unhealthy")
    })
    .map(|c| format!("{} {}", c.service, c.status))
    .collect();
  if bad.is_empty() {
    let starting = p
      .containers
      .iter()
      .any(|c| c.health.as_deref() == Some("health: starting"));
    if starting {
      check(
        "container",
        subject,
        CheckStatus::Warn,
        "健康检查还在进行",
      )
    } else {
      check("container", subject, CheckStatus::Ok, "运行中")
    }
  } else {
    check("container", subject, CheckStatus::Bad, bad.join("，"))
  }
}
