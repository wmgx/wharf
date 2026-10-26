//! `wharf doctor`：只读诊断。沿每个域名的访问链路逐层检查：
//! 域名解析 → HTTPS（从控制面访问）→ 网关容器 → 网关所在机器连上游 → 服务容器。
//! 每层独立检查，第一个不通的就是要先看的地方。

use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Query, State},
};
use chrono::Utc;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{AgentOp, ProbeTarget},
  spec::GatewayKind,
  view::{
    CheckStatus, DoctorCheck, DoctorReport, RouteDiagnosis,
    TokenScope,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  render::Net,
  snapshot::{self, Snapshot},
  state::AppState,
  views::{LiveMap, live_states, route_view},
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

/// `GET /api/doctor[?host=]`
pub async fn doctor(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<DoctorQuery>,
) -> ApiResult<DoctorReport> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if let Some(host) = &q.host
    && !snap.world.routes.contains_key(host)
  {
    return Err(
      wharf_api_types::ApiError::not_found(format!(
        "没有域名 {host}"
      ))
      .suggest("wharf route ls")
      .into(),
    );
  }
  let net = snap.net(&snap.world);
  let live = live_states(&s, &snap.world).await;
  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(HTTP_TIMEOUT)
    .build()
    .map_err(|e| {
      wharf_api_types::ApiError::internal(format!("HTTP 客户端：{e}"))
    })?;
  let hosts: Vec<&String> = snap
    .world
    .routes
    .keys()
    .filter(|h| q.host.as_ref().is_none_or(|q| q == *h))
    .collect();
  let routes = futures_util::future::join_all(
    hosts
      .into_iter()
      .map(|h| route(&s, &snap, &net, &live, &client, h)),
  )
  .await
  .into_iter()
  .flatten()
  .collect();
  Ok(Json(DoctorReport {
    checked_at: Utc::now(),
    servers: servers(&s, &snap),
    routes,
  }))
}

fn check(
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
  snap
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
    .collect()
}

async fn route(
  s: &AppState,
  snap: &Snapshot,
  net: &Net,
  live: &LiveMap,
  client: &reqwest::Client,
  host: &str,
) -> Option<RouteDiagnosis> {
  let view = route_view(snap, net, host)?;
  let world = &snap.world;
  let gateway = view
    .gateway
    .as_ref()
    .and_then(|g| world.gateways.get(g).map(|row| (g, &row.spec)));
  let mut checks = vec![dns(host, gateway.map(|g| g.1), net).await];
  checks.push(https(client, &view.url, view.spec.auth).await);
  let Some((gw_name, gw)) = gateway else {
    // 边缘应用的域名直接指到厂商，不经过网关和服务器。
    return Some(RouteDiagnosis {
      hostname: host.into(),
      url: view.url,
      checks,
    });
  };
  checks.push(gateway_check(live, gw_name, &gw.server));
  checks.push(match &view.upstream {
    Some(up) => link(s, &gw.server, up).await,
    None => check(
      "link",
      format!("{} → 上游", gw.server),
      CheckStatus::Bad,
      "算不出上游地址，执行 wharf plan 看原因",
    ),
  });
  checks.push(container(world, live, &view.spec));
  Some(RouteDiagnosis {
    hostname: host.into(),
    url: view.url,
    checks,
  })
}

/// caddy 网关的域名应该解析到网关机器的公网 IP；经 CDN 代理或隧道时是厂商的 IP。
async fn dns(
  host: &str,
  gateway: Option<&wharf_api_types::spec::GatewaySpec>,
  net: &Net,
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
    .and_then(|g| net.public_ip.get(&g.server).map(|ip| (g, ip)));
  match expected {
    Some((g, ip)) if !ips.iter().any(|a| a.to_string() == *ip) => {
      check(
        "dns",
        host,
        CheckStatus::Warn,
        format!(
          "解析到 {shown}，不是网关所在 {} 的公网 IP {ip}（经 CDN 代理时正常）",
          g.server
        ),
      )
    }
    _ => {
      check("dns", host, CheckStatus::Ok, format!("解析到 {shown}"))
    }
  }
}

/// 从控制面访问一次。502 / 504 是网关连不上上游，看后面几层。
async fn https(
  client: &reqwest::Client,
  url: &str,
  auth: bool,
) -> DoctorCheck {
  let layer = if url.starts_with("https") {
    "https"
  } else {
    "http"
  };
  match client.get(url).send().await {
    Err(e) => check(layer, url, CheckStatus::Bad, error_chain(&e)),
    Ok(r) => {
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
      if matches!(code.as_u16(), 502 | 504) {
        detail.push_str("：网关连不上上游");
      }
      if let Some(to) =
        r.headers().get("location").and_then(|v| v.to_str().ok())
      {
        detail.push_str(&format!(" → {to}"));
      }
      check(layer, url, status, detail)
    }
  }
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
) -> DoctorCheck {
  let subject = format!("{server} → {upstream}");
  if !s.hub.is_online(server) {
    return check(
      "link",
      subject,
      CheckStatus::Skip,
      "agent 离线，测不了",
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
      check("link", subject, CheckStatus::Ok, "能连上")
    }
    Ok(_) => check(
      "link",
      subject,
      CheckStatus::Bad,
      "连不上：上游没在监听，或者两台机器之间不通（wharf network --probe）",
    ),
    Err(e) => check("link", subject, CheckStatus::Bad, e.message),
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
