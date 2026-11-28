//! `wharf doctor`：只读诊断。沿每个域名的访问链路逐层检查：
//! 域名解析 → HTTPS（从控制面访问）→ 网关容器 → 网关所在机器连上游 → 服务容器。
//! 每层独立检查，第一个不通的就是要先看的地方。

use std::{
  collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration,
};

use axum::{
  Json,
  extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HttpCheckResult, ProbeTarget},
  gateway_http::inspect,
  spec::{
    GatewayKind, GatewaySpec, GatewayTls, MonitorSpec, Region,
    RouteSpec, SsoMode,
  },
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
  world::{World, gateway_project},
};

mod special;
#[cfg(test)]
mod tests;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
pub struct DoctorQuery {
  pub host: Option<String>,
  pub service: Option<String>,
  pub server: Option<String>,
}

#[derive(PartialEq, Eq)]
pub(crate) enum DoctorScope {
  All,
  Host(String),
  Service(String),
  Server(String),
}

impl DoctorQuery {
  fn scope(self) -> Result<DoctorScope, ApiError> {
    match (self.host, self.service, self.server) {
      (None, None, None) => Ok(DoctorScope::All),
      (Some(host), None, None) => Ok(DoctorScope::Host(normalize_host(&host))),
      (None, Some(service), None) => Ok(DoctorScope::Service(service)),
      (None, None, Some(server)) => Ok(DoctorScope::Server(server)),
      _ => Err(ApiError::invalid("host、service、server 一次只能指定一个")
        .with_hint("例如 wharf doctor <域名>、wharf doctor --service <服务> 或 wharf doctor --server <服务器>")),
    }
  }
}

fn normalize_host(host: &str) -> String {
  host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub async fn doctor(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<DoctorQuery>,
) -> ApiResult<DoctorReport> {
  auth.require(Perm::Read)?;
  let scope = q.scope()?;
  if scope == DoctorScope::All && auth.services.is_none() {
    let (mut report, vendors) = tokio::try_join!(
      run(&s, &scope, true, None),
      crate::vendor_checks::checks(&s),
    )?;
    report.vendors = vendors;
    crate::vendor_checks::record(&s, &report.vendors).await;
    crate::probe::observe_routes(&s, &report.routes).await;
    remember(report.clone());
    return Ok(Json(report));
  }
  let report = run(&s, &scope, true, Some(&auth)).await?;
  if matches!(scope, DoctorScope::Host(_) | DoctorScope::Service(_)) {
    crate::probe::observe_routes(&s, &report.routes).await;
    remember_routes(&report.routes);
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

fn remember_routes(updated: &[RouteDiagnosis]) {
  if let Ok(mut guard) = LAST.write()
    && let Some(last) = guard.as_mut()
  {
    for route in updated {
      if let Some(previous) = last
        .routes
        .iter_mut()
        .find(|r| r.hostname == route.hostname)
      {
        *previous = route.clone();
      } else {
        last.routes.push(route.clone());
      }
    }
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
      match run(&state, &DoctorScope::All, false, None).await {
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

#[derive(Default)]
struct Selection {
  hosts: Vec<String>,
  edge: Vec<(String, String)>,
  services: BTreeSet<String>,
  gateways: BTreeSet<String>,
  servers: BTreeSet<String>,
}

fn route_services(route: &RouteSpec) -> impl Iterator<Item = &str> {
  (route.upstream.is_none()
    && route.redirect.is_none()
    && !route.service.is_empty())
  .then_some(route.service.as_str())
  .into_iter()
  .chain(route.paths.iter().filter_map(|p| p.service.as_deref()))
}

fn selection(
  snap: &Snapshot,
  scope: &DoctorScope,
  auth: Option<&Auth>,
) -> Result<Selection, ApiError> {
  let world = &snap.world;
  let allowed = auth.and_then(|a| a.services.as_ref());
  let expired =
    crate::share::expired(world, Utc::now().timestamp_millis());
  let mut result = Selection::default();
  match scope {
    DoctorScope::All => {
      result.services.extend(
        world
          .services
          .keys()
          .filter(|n| allowed.is_none_or(|a| a.contains(*n)))
          .cloned(),
      );
      if allowed.is_none() {
        result.servers.extend(world.servers.keys().cloned());
        result.gateways.extend(world.gateways.keys().cloned());
      }
    }
    DoctorScope::Host(host) => {
      if let Some(auth) = auth {
        crate::token_scope::require_route_by_host(auth, world, host)?;
      }
      if expired.contains(host) {
        return Err(
          ApiError::invalid(format!(
            "临时分享 {host} 已失效，不做体检"
          ))
          .suggest(format!("wharf route rm {host} --apply")),
        );
      }
    }
    DoctorScope::Service(name) => {
      if let Some(auth) = auth {
        crate::token_scope::require_service(auth, name)?;
      }
      if !world.services.contains_key(name) {
        return Err(
          ApiError::not_found(format!("没有服务 {name}"))
            .suggest("wharf service ls"),
        );
      }
      result.services.insert(name.clone());
      result.gateways.extend(
        world
          .gateways
          .iter()
          .filter(|(_, g)| {
            g.spec
              .layer4
              .iter()
              .any(|f| f.service.as_deref() == Some(name))
          })
          .map(|(name, _)| name.clone()),
      );
    }
    DoctorScope::Server(name) => {
      if allowed.is_some() {
        return Err(
          ApiError::new(
            ErrorCode::Forbidden,
            "限定服务的令牌不能做整机体检",
          )
          .with_hint("改用 wharf doctor --service <服务>"),
        );
      }
      if !world.servers.contains_key(name) {
        return Err(
          ApiError::not_found(format!("没有服务器 {name}"))
            .suggest("wharf server ls"),
        );
      }
      result.servers.insert(name.clone());
      result.services.extend(
        world
          .services
          .iter()
          .filter(|(_, row)| row.spec.server == *name)
          .map(|(n, _)| n.clone()),
      );
      result.gateways.extend(
        world
          .gateways
          .iter()
          .filter(|(_, row)| row.spec.server == *name)
          .map(|(n, _)| n.clone()),
      );
    }
  }
  for (host, row) in &world.routes {
    let spec = &row.spec;
    if expired.contains(host)
      || allowed.is_some_and(|a| {
        !crate::token_scope::route_spec_in_scope(a, spec)
      })
    {
      continue;
    }
    let gateway = world.live_gateway(host, spec);
    let matches = match scope {
      DoctorScope::All => true,
      DoctorScope::Host(name) => name == host,
      DoctorScope::Service(name) => {
        route_services(spec).any(|service| service == name)
      }
      DoctorScope::Server(name) => {
        world.route_gateways(spec).into_iter().any(|g| {
          world
            .gateways
            .get(g)
            .is_some_and(|row| row.spec.server == *name)
        }) || route_services(spec).any(|svc| {
          world
            .services
            .get(svc)
            .is_some_and(|row| row.spec.server == *name)
        })
      }
    };
    if matches {
      result.hosts.push(host.clone());
      result
        .services
        .extend(route_services(spec).map(str::to_owned));
      result.gateways.extend(gateway.map(str::to_owned));
    }
  }
  if allowed.is_none()
    && matches!(scope, DoctorScope::All | DoctorScope::Host(_))
  {
    for (name, app) in &world.edge_apps {
      for host in &app.spec.domains {
        if !world.routes.contains_key(host)
          && (scope == &DoctorScope::All
            || scope == &DoctorScope::Host(host.clone()))
        {
          result.edge.push((host.clone(), name.clone()));
        }
      }
    }
  }
  if let DoctorScope::Host(host) = scope
    && result.hosts.is_empty()
    && result.edge.is_empty()
  {
    return Err(
      ApiError::not_found(format!("没有域名 {host}"))
        .suggest("wharf route ls"),
    );
  }
  if !matches!(scope, DoctorScope::Server(_)) {
    result.servers.extend(result.services.iter().filter_map(|n| {
      if matches!(scope, DoctorScope::Service(service) if service != n) {
        return None;
      }
      Some(world.services.get(n)?.spec.server.clone())
    }));
    result
      .servers
      .extend(result.gateways.iter().filter_map(|n| {
        Some(world.gateways.get(n)?.spec.server.clone())
      }));
  }
  Ok(result)
}

pub(crate) async fn run(
  s: &AppState,
  scope: &DoctorScope,
  manual: bool,
  auth: Option<&Auth>,
) -> Result<DoctorReport, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let mut selected = selection(&snap, scope, auth)?;
  if !manual {
    selected.hosts.retain(|host| {
      !crate::rules::lifecycle::stopped_route(
        &snap.world,
        &snap.world.routes[host].spec,
      )
    });
  }
  let net = snap.net(&snap.world);
  let clients = Clients::new(&snap)?;
  let mut world = snap.world.clone();
  world
    .services
    .retain(|name, _| selected.services.contains(name));
  world
    .gateways
    .retain(|name, _| selected.gateways.contains(name));
  let live = live_states(s, &world).await;
  let ctx = RouteChecks {
    s,
    snap: &snap,
    net: &net,
    live: &live,
    clients: &clients,
    manual,
  };
  let (routes, edge, checks) = tokio::join!(
    futures_util::future::join_all(
      selected.hosts.iter().map(|h| ctx.route(h))
    ),
    futures_util::future::join_all(
      selected.edge.iter().map(|(h, app)| ctx.edge_route(h, app))
    ),
    special::checks(&ctx, scope)
  );
  let mut routes: Vec<_> = routes.into_iter().flatten().collect();
  if manual {
    doctor_diagnose::enrich(
      s,
      routes
        .iter_mut()
        .map(|(r, targets)| (&mut r.checks, std::mem::take(targets))),
    )
    .await;
  }
  let mut report = DoctorReport {
    checked_at: Utc::now(),
    servers: servers(s, &snap, &selected.servers),
    routes: routes
      .into_iter()
      .map(|(route, _)| route)
      .chain(edge)
      .collect(),
    vendors: vec![],
    config: crate::lint::scoped_warnings(
      &snap,
      &selected.services,
      &selected.servers,
    )
    .into_iter()
    .map(|(subject, detail)| {
      check(
        "config",
        subject,
        CheckStatus::Warn,
        detail.trim_start_matches('的').trim_start(),
      )
    })
    .collect(),
    checks,
  };
  let now = Utc::now();
  report.config.extend(
    crate::link_cert::leaf_expiries(&snap, &net)
      .filter(|(gateway, _)| selected.gateways.contains(*gateway))
      .map(|(gateway, expires)| {
        let days = crate::link_cert::days_left(expires, now);
        let (status, detail) = if days <= 0 {
          (CheckStatus::Bad, "隧道证书已过期".into())
        } else {
          let status = if expires - now
            < chrono::Duration::days(
              crate::link_cert::LEAF_ALERT_DAYS,
            ) {
            CheckStatus::Warn
          } else {
            CheckStatus::Ok
          };
          (status, format!("隧道证书 {days} 天后到期"))
        };
        check("gateway", format!("网关 {gateway}"), status, detail)
      }),
  );
  if let Some(allowed) = auth.and_then(|a| a.services.as_ref()) {
    crate::scope_filter::filter_doctor(
      allowed,
      &snap.world,
      &mut report,
    );
  }
  Ok(report)
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

fn servers(
  s: &AppState,
  snap: &Snapshot,
  selected: &BTreeSet<String>,
) -> Vec<DoctorCheck> {
  let mut checks: Vec<_> = snap
    .world
    .servers
    .keys()
    .filter(|name| selected.contains(*name))
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
    crate::net_conflict::conflicts(snap)
      .into_iter()
      .filter(|(name, _)| selected.contains(*name))
      .map(|(server, detail)| {
        check(
          "network",
          server,
          CheckStatus::Bad,
          format!("{detail}。{}", crate::net_conflict::FIX),
        )
      }),
  );
  checks
}

struct Clients {
  direct: reqwest::Client,
  internal: reqwest::Client,
  egress:
    Option<(String, reqwest::Client, wharf_providers::http::Route)>,
  doh: crate::dns_check::DohClients,
}

impl Clients {
  fn new(snap: &Snapshot) -> Result<Self, ApiError> {
    let builder = || {
      reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .tls_info(true)
    };
    let failed = |_| ApiError::internal("无法初始化体检 HTTP 客户端");
    let route = crate::egress::api_route(snap);
    let doh = crate::dns_check::DohClients::new(
      route.as_ref().map(|(_, r)| r.proxy.clone()),
    );
    let egress = route.and_then(|(name, route)| {
      let client =
        builder().proxy(route.proxy.clone()).build().ok()?;
      Some((name.to_owned(), client, route))
    });
    Ok(Self {
      direct: builder().build().map_err(failed)?,
      internal: builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(failed)?,
      egress,
      doh,
    })
  }
}

struct RouteChecks<'a> {
  s: &'a AppState,
  snap: &'a Snapshot,
  net: &'a Net,
  live: &'a LiveMap,
  clients: &'a Clients,
  manual: bool,
}

fn use_egress_for_doctor(
  snap: &Snapshot,
  route: Option<(&RouteSpec, &GatewaySpec)>,
  matches_exit: bool,
) -> bool {
  if let Some((r, g)) = route {
    if r.internal || g.tls == GatewayTls::Internal {
      return false;
    }
    if g.kind == GatewayKind::CloudflareTunnel
      || r.cf_origin_only
      || snap
        .world
        .servers
        .get(&g.server)
        .is_some_and(|s| s.settings.region == Some(Region::Overseas))
    {
      return true;
    }
  }
  matches_exit
}

impl RouteChecks<'_> {
  async fn route(
    &self,
    host: &str,
  ) -> Option<(RouteDiagnosis, Vec<Target>)> {
    let (view, upstream_error) =
      route_view_with_upstream_error(self.snap, self.net, host)?;
    let world = &self.snap.world;
    let spec = &view.spec;
    let gateway = view
      .gateway
      .as_ref()
      .and_then(|g| world.gateways.get(g).map(|row| (g, &row.spec)));
    let gateway_spec = gateway.map(|(_, g)| g);
    let use_egress = use_egress_for_doctor(
      self.snap,
      gateway_spec.map(|g| (spec, g)),
      self
        .clients
        .egress
        .as_ref()
        .is_some_and(|(_, _, r)| r.matches(host)),
    );
    let service = spec
      .upstream
      .is_none()
      .then(|| world.services.get(&spec.service))
      .flatten();
    let main_stopped = spec.redirect.is_none()
      && service.is_some_and(|row| row.spec.stopped);
    let probe_path = if main_stopped {
      spec
        .paths
        .iter()
        .find(|p| crate::rules::lifecycle::active_path(world, p))
    } else {
      None
    };
    let stopped = crate::rules::lifecycle::stopped_route(world, spec);
    let probe_url = probe_path.map(|p| {
      let path = p.path.trim_end_matches('*');
      format!("{}{path}", view.url.trim_end_matches('/'))
    });
    let (dns, (mut https, cert_expires, bad_gateway)) = if stopped {
      (
        check("dns", host, CheckStatus::Skip, "服务已停用"),
        (
          check("https", host, CheckStatus::Skip, "服务已停用"),
          None,
          false,
        ),
      )
    } else {
      let proxy_ranges = !spec.internal
        && gateway_spec
          .is_some_and(|g| g.tls != GatewayTls::Internal);
      let expected = gateway_spec
        .filter(|g| g.kind == GatewayKind::Caddy)
        .and_then(|g| {
          if spec.internal {
            self.net.private.get(&g.server).map(|a| a.ip.as_str())
          } else {
            self.net.public_ip.get(&g.server).map(String::as_str)
          }
        });
      tokio::join!(
        dns(
          self.clients,
          host,
          use_egress,
          expected,
          spec.cf_origin_only,
          proxy_ranges,
          false
        ),
        self.route_https(
          host,
          probe_url.as_deref().unwrap_or(&view.url),
          spec,
          gateway_spec,
          service
            .filter(|_| !main_stopped)
            .and_then(|r| r.spec.monitor.as_ref()),
          use_egress
        ),
      )
    };
    let auto_tls = gateway_spec.is_some_and(|g| {
      g.kind == GatewayKind::Caddy && g.tls == GatewayTls::Auto
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
    let mut checks = vec![dns, https];
    append_cert(&mut checks, host, cert_expires);
    let mut diagnosis = RouteDiagnosis {
      hostname: host.into(),
      url: view.url,
      checks,
      cert_expires,
      domain_expires: crate::rdap::expires_of(host),
      edge_app: None,
    };
    if stopped {
      return Some((diagnosis, vec![]));
    }
    let Some((gw_name, gw)) = gateway else {
      diagnosis.checks.push(check(
        "gateway",
        host,
        CheckStatus::Bad,
        "没有可用的网关",
      ));
      return Some((diagnosis, vec![]));
    };
    if spec.redirect.is_some() {
      return Some((diagnosis, vec![]));
    }
    let gateway = gateway_check(self.live, gw_name, &gw.server);
    let gateway_ok = gateway.status == CheckStatus::Ok;
    diagnosis.checks.push(gateway);
    let main = if spec.upstream.is_some() {
      let check = if let Some(up) = view.upstream.as_deref() {
        link(self.s, &gw.server, up, false).await.0
      } else {
        missing_upstream(&gw.server, upstream_error)
      };
      (vec![check, check_external()], None)
    } else {
      self
        .service_hop(
          gw,
          spec,
          ServiceHop {
            service: &spec.service,
            port: world.route_port(spec),
            path: None,
            upstream: view.upstream.ok_or(upstream_error),
            bad_gateway: bad_gateway && gateway_ok,
          },
        )
        .await
    };
    let paths = futures_util::future::join_all(
      spec.paths.iter().map(|p| async {
        if let Some(up) = &p.upstream {
          let mut check = link(self.s, &gw.server, up, false).await.0;
          check.subject.push_str(&format!(" ({})", p.path));
          (vec![check], None)
        } else if let Some(service) = &p.service {
          let port = world.service_port(service, p.port.as_deref());
          let upstream = port
            .map(|port| {
              crate::render::upstream(
                world, self.net, gw, service, port, spec.link,
              )
            })
            .transpose()
            .map_err(Some)
            .and_then(|u| u.ok_or(None));
          self
            .service_hop(
              gw,
              spec,
              ServiceHop {
                service,
                port,
                path: Some(&p.path),
                upstream,
                bad_gateway: bad_gateway
                  && gateway_ok
                  && probe_path == Some(p),
              },
            )
            .await
        } else {
          (vec![], None)
        }
      }),
    )
    .await;
    let mut targets = Vec::new();
    for (checks, target) in std::iter::once(main).chain(paths) {
      diagnosis.checks.extend(checks);
      targets.extend(target);
    }
    Some((diagnosis, targets))
  }

  async fn service_hop(
    &self,
    gw: &GatewaySpec,
    spec: &RouteSpec,
    hop: ServiceHop<'_>,
  ) -> (Vec<DoctorCheck>, Option<Target>) {
    let world = &self.snap.world;
    let row = world.services.get(hop.service);
    let cross_host = row.is_some_and(|r| r.spec.server != gw.server);
    let via_tunnel = cross_host
      && hop.port.is_some_and(|port| {
        matches!(
          crate::link::choose(
            world,
            self.net,
            gw,
            hop.service,
            port,
            spec.link
          ),
          Ok(crate::link::Choice::Tunnel)
        )
      });
    let (mut link, unreachable) =
      if row.is_some_and(|r| r.spec.stopped) {
        (
          check("link", &gw.server, CheckStatus::Skip, "服务已停用"),
          false,
        )
      } else {
        match hop.upstream {
          Ok(up) => {
            link(self.s, &gw.server, &up, cross_host && !via_tunnel)
              .await
          }
          Err(e) => (missing_upstream(&gw.server, e), false),
        }
      };
    let mut container =
      container_of_service(world, self.live, hop.service);
    if let Some(path) = hop.path {
      link.subject.push_str(&format!(" ({path})"));
      container.subject.push_str(&format!(" ({path})"));
    }
    let target =
      row.filter(|row| !row.spec.stopped).and_then(|row| {
        let active = self
          .live
          .get(&row.spec.server)
          .and_then(|states| states.as_ref().ok())
          .and_then(|states| states.get(hop.service))
          .is_some_and(|p| {
            p.containers.iter().any(|c| !c.foreign && c.is_active())
          });
        if !doctor_diagnose::should_diagnose(
          self.manual,
          link.status == CheckStatus::Bad,
          hop.bad_gateway,
          true,
          container.status == CheckStatus::Bad,
          active,
        ) {
          return None;
        }
        Some(Target {
          service: hop.service.into(),
          server: row.spec.server.clone(),
          port: Some(*row.host_ports.get(hop.port?)?),
          local_loopback_ok: !cross_host || via_tunnel,
          http_failed: hop.bad_gateway,
          link_unreachable: unreachable,
          link_subject: Some(link.subject.clone()),
          container_subject: container.subject.clone(),
        })
      });
    (vec![link, container], target)
  }

  async fn route_https(
    &self,
    host: &str,
    url: &str,
    spec: &RouteSpec,
    gateway: Option<&GatewaySpec>,
    monitor: Option<&MonitorSpec>,
    use_egress: bool,
  ) -> (DoctorCheck, Option<DateTime<Utc>>, bool) {
    let internal = gateway.is_some_and(|g| {
      g.kind == GatewayKind::Caddy && g.tls == GatewayTls::Internal
    });
    let gated = url.starts_with("https://")
      && gateway.is_some_and(|g| {
        g.kind == GatewayKind::Caddy && g.tls != GatewayTls::Off
      })
      && spec.sso.as_ref().is_some_and(|s| s.gated())
      && spec.redirect.is_none();
    // 验证不了对端证书时，不能把门禁凭据发给它。
    let cookie = if gated && !internal {
      crate::gate::probe_cookie(&self.s.db, host).await
    } else {
      None
    };
    let options = HttpProbe {
      cookie,
      internal,
      use_egress,
      ..HttpProbe::for_route(spec, gated, monitor)
    };
    let monitor_url = options.monitor.map(|m| {
      format!(
        "{}/{}",
        url.trim_end_matches('/'),
        m.path.trim_start_matches('/')
      )
    });
    self
      .https(monitor_url.as_deref().unwrap_or(url), options)
      .await
  }

  async fn edge_route(
    &self,
    host: &str,
    app: &str,
  ) -> RouteDiagnosis {
    let url = format!("https://{host}");
    let (dns, (https, cert_expires, _)) = tokio::join!(
      dns(self.clients, host, true, None, false, true, true),
      self.https(
        &url,
        HttpProbe {
          use_egress: true,
          ..Default::default()
        }
      ),
    );
    let mut checks = vec![dns, https];
    append_cert(&mut checks, host, cert_expires);
    if let Some(row) = self.snap.world.edge_apps.get(app)
      && let Some(detail) = crate::edge_sync::drift(
        &crate::edge_sync::target(app, &row.spec),
        self.snap.edge_cache.get(app),
        self.snap.edge_expected.get(app),
      )
    {
      checks.push(check("edge", app, CheckStatus::Warn, detail));
    }
    RouteDiagnosis {
      hostname: host.into(),
      url,
      checks,
      cert_expires,
      domain_expires: crate::rdap::expires_of(host),
      edge_app: Some(app.into()),
    }
  }

  async fn https(
    &self,
    url: &str,
    options: HttpProbe<'_>,
  ) -> (DoctorCheck, Option<DateTime<Utc>>, bool) {
    let request = |client: &reqwest::Client| {
      let mut request = client.get(url);
      if let Some(cookie) = &options.cookie {
        request =
          request.header(reqwest::header::COOKIE, cookie.clone());
      }
      request
    };
    let mut via = None;
    let result = if options.internal {
      request(&self.clients.internal).send().await
    } else if let Some((name, client, _)) =
      self.clients.egress.as_ref().filter(|_| options.use_egress)
    {
      match request(client).send().await {
        Err(e) if e.is_connect() => {
          request(&self.clients.direct).send().await
        }
        result => {
          if result.is_ok() {
            via = Some(name);
          }
          result
        }
      }
    } else {
      request(&self.clients.direct).send().await
    };
    let subject = url.split(['?', '#']).next().unwrap_or(url);
    let layer = if url.starts_with("https://") {
      "https"
    } else {
      "http"
    };
    let response = match result {
      Ok(r) => r,
      Err(e) => {
        return (
          check(
            layer,
            subject,
            CheckStatus::Bad,
            error_chain(&e.without_url()),
          ),
          None,
          false,
        );
      }
    };
    let expires = response
      .extensions()
      .get::<reqwest::tls::TlsInfo>()
      .and_then(|t| t.peer_certificate())
      .and_then(crate::cert::not_after);
    let (code, gate_rejected, body) = inspect(
      response,
      options.gate,
      options.monitor.is_some_and(|m| m.keyword.is_some()),
    )
    .await;
    let (status, mut detail, bad_gateway) =
      http_status(code, &options, gate_rejected, &body);
    if options.internal {
      detail.push_str("（自签证书）");
    }
    if let Some(via) = via {
      detail.push_str(&format!("（经 {via} 出口）"));
    }
    (check(layer, subject, status, detail), expires, bad_gateway)
  }
}

struct ServiceHop<'a> {
  service: &'a str,
  port: Option<&'a str>,
  path: Option<&'a str>,
  upstream: Result<String, Option<ApiError>>,
  bad_gateway: bool,
}

fn missing_upstream(
  server: &str,
  error: Option<ApiError>,
) -> DoctorCheck {
  check(
    "link",
    format!("{server} → 上游"),
    CheckStatus::Bad,
    error.map_or_else(
      || "算不出上游地址，执行 wharf plan 看原因".into(),
      |e| match e.hint {
        Some(hint) => format!("{}（{hint}）", e.message),
        None => e.message,
      },
    ),
  )
}

fn covers_monitor(matcher: &str, path: &str) -> bool {
  if matcher.starts_with('@') {
    return true;
  }
  let path = path.split('?').next().unwrap_or_default();
  let path = format!("/{}", path.trim_start_matches('/'));
  matcher.strip_suffix('*').map_or_else(
    || path == matcher,
    |prefix| path.starts_with(prefix),
  )
}

#[derive(Default)]
struct HttpProbe<'a> {
  basic_auth: bool,
  gate: bool,
  header: bool,
  cookie: Option<reqwest::header::HeaderValue>,
  monitor: Option<&'a MonitorSpec>,
  internal: bool,
  use_egress: bool,
}

impl<'a> HttpProbe<'a> {
  fn for_route(
    spec: &RouteSpec,
    gated: bool,
    monitor: Option<&'a MonitorSpec>,
  ) -> Self {
    let monitor = monitor.filter(|m| {
      gated
        // 自定义请求头只发给 agent 探测的本机服务端口。
        && m.headers.is_empty()
        && !spec.auth
        && !spec
          .paths
          .iter()
          .any(|p| covers_monitor(&p.path, &m.path))
    });
    Self {
      basic_auth: spec.auth,
      gate: gated,
      header: monitor.is_none()
        && spec
          .sso
          .as_ref()
          .is_some_and(|s| s.mode == SsoMode::Header),
      monitor,
      ..Self::default()
    }
  }
}

fn http_status(
  code: reqwest::StatusCode,
  probe: &HttpProbe<'_>,
  rejected: bool,
  body: &[u8],
) -> (CheckStatus, String, bool) {
  let n = code.as_u16();
  let bad_gateway = matches!(n, 502 | 504);
  let mut detail = format!("HTTP {n}");
  let status = if code.is_server_error() {
    if bad_gateway {
      detail.push_str("：网关连不上上游");
    }
    CheckStatus::Bad
  } else if probe.gate && probe.internal && rejected {
    detail.push_str("：门禁正常要求登录，未穿透验证应用");
    CheckStatus::Ok
  } else if probe.gate
    && !probe.internal
    && (rejected || probe.cookie.is_none())
  {
    return (
      CheckStatus::Warn,
      "门禁未放行控制面探针，检查网关门禁公钥和证书（wharf plan）"
        .into(),
      false,
    );
  } else if probe.basic_auth && n == 401 {
    CheckStatus::Ok
  } else if let Some(monitor) = probe.monitor {
    let result = HttpCheckResult {
      status: Some(n),
      found: monitor
        .keyword
        .as_ref()
        .map(|k| String::from_utf8_lossy(body).contains(k.as_str())),
      ..Default::default()
    };
    let (ok, reason) = crate::monitor::judge(monitor, &result);
    detail = reason;
    if ok {
      CheckStatus::Ok
    } else {
      CheckStatus::Bad
    }
  } else if probe.header
    && probe.cookie.is_some()
    && matches!(n, 401 | 403)
  {
    return (
      CheckStatus::Ok,
      format!("HTTP {n}（已穿过门禁，后端存活但拒识探针用户）"),
      false,
    );
  } else if code.is_client_error() {
    CheckStatus::Warn
  } else {
    CheckStatus::Ok
  };
  if probe.cookie.is_some() && !(probe.basic_auth && n == 401) {
    detail.push_str("（已穿过门禁）");
  }
  (status, detail, bad_gateway)
}

fn append_cert(
  checks: &mut Vec<DoctorCheck>,
  host: &str,
  expires: Option<DateTime<Utc>>,
) {
  if let Some(t) = expires {
    let days = (t - Utc::now()).num_days();
    if days < crate::cert::WARN_DAYS {
      checks.push(check(
        "cert",
        host,
        CheckStatus::Warn,
        format!("证书剩 {days} 天"),
      ));
    }
  }
}

async fn dns(
  clients: &Clients,
  host: &str,
  use_doh: bool,
  expected: Option<&str>,
  cf_origin_only: bool,
  check_ranges: bool,
  edge: bool,
) -> DoctorCheck {
  let ips = if use_doh {
    clients.doh.lookup(host).await
  } else {
    match tokio::time::timeout(
      DNS_TIMEOUT,
      tokio::net::lookup_host((host, 443)),
    )
    .await
    {
      Ok(Ok(addrs)) => Some(addrs.map(|a| a.ip()).collect()),
      _ => None,
    }
  };
  let Some(ips) = ips.filter(|ips| !ips.is_empty()) else {
    return check(
      "dns",
      host,
      CheckStatus::Bad,
      "解析失败或没有 A / AAAA 记录",
    );
  };
  let ips: BTreeSet<IpAddr> = ips.into_iter().collect();
  let shown = ips
    .iter()
    .map(IpAddr::to_string)
    .collect::<Vec<_>>()
    .join(", ");
  let wrong_ip = expected.is_some_and(|ip| {
    ip.parse::<IpAddr>().is_ok_and(|ip| !ips.contains(&ip))
  });
  let cf = if check_ranges
    && (edge || wrong_ip || expected.is_none())
    && !cf_origin_only
  {
    crate::dns_check::cf_ranges().await.map(|ranges| {
      ips.iter().all(|ip| ranges.iter().any(|r| r.contains(ip)))
    })
  } else {
    None
  };
  if cf_origin_only || cf == Some(true) {
    check(
      "dns",
      host,
      CheckStatus::Ok,
      format!("解析到 {shown}（经 Cloudflare 代理）"),
    )
  } else if wrong_ip {
    check(
      "dns",
      host,
      CheckStatus::Warn,
      format!(
        "解析到 {shown}，期望 {}",
        expected.unwrap_or_default()
      ),
    )
  } else if edge && cf == Some(false) {
    check(
      "dns",
      host,
      CheckStatus::Warn,
      format!("解析到 {shown}，不在 Cloudflare 网段"),
    )
  } else {
    check("dns", host, CheckStatus::Ok, format!("解析到 {shown}"))
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
      Some(p) if p.containers.iter().any(|c| !c.foreign) => check(
        "gateway",
        subject,
        CheckStatus::Bad,
        p.containers
          .iter()
          .filter(|c| !c.foreign)
          .map(|c| format!("{} {}", c.service, c.status))
          .collect::<Vec<_>>()
          .join("，"),
      ),
      _ => check("gateway", subject, CheckStatus::Bad, "没有部署"),
    },
  }
}

fn probe_addr(upstream: &str) -> Option<String> {
  let upstream = upstream.trim();
  if upstream.contains("://") {
    let url = reqwest::Url::parse(upstream).ok()?;
    Some(format!(
      "{}:{}",
      url.host_str()?,
      url.port_or_known_default()?
    ))
  } else {
    (!upstream.is_empty()).then(|| upstream.to_string())
  }
}

/// 网关所在机器的 agent 去连上游地址（agent 用主机网络，和网关看到的一样）。
async fn link(
  s: &AppState,
  server: &str,
  upstream: &str,
  cross_host: bool,
) -> (DoctorCheck, bool) {
  let Some(addr) = probe_addr(upstream) else {
    return (
      check(
        "link",
        server,
        CheckStatus::Bad,
        "上游地址格式不对，无法做 TCP 探测",
      ),
      false,
    );
  };
  let subject = format!("{server} → {addr}");
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
          addr,
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

fn check_external() -> DoctorCheck {
  check("container", "外部上游", CheckStatus::Skip, "不归 Wharf 管")
}

fn container_of_service(
  world: &World,
  live: &LiveMap,
  service: &str,
) -> DoctorCheck {
  let Some(row) = world.services.get(service) else {
    return check(
      "container",
      service,
      CheckStatus::Bad,
      "服务不存在",
    );
  };
  let server = &row.spec.server;
  let subject = format!("{server} 上的 {}", service);
  if row.spec.stopped {
    return check(
      "container",
      subject,
      CheckStatus::Skip,
      "按配置停止",
    );
  }
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
    .get(service)
    .filter(|p| p.containers.iter().any(|c| !c.foreign))
  else {
    return check("container", subject, CheckStatus::Bad, "没有容器");
  };
  let has_running =
    p.containers.iter().any(|c| !c.foreign && c.is_running());
  let mut bad: Vec<String> = p
    .containers
    .iter()
    .filter(|c| !c.foreign)
    .filter(|c| {
      !c.is_healthy_state(has_running)
        || (c.is_running()
          && c.health.as_deref() == Some("unhealthy"))
    })
    .map(|c| format!("{} {}", c.service, c.status))
    .collect();
  let expected =
    crate::render::service_expected_components(service, &row.spec);
  bad.extend(
    crate::render::missing_components(&expected, &p.containers)
      .into_iter()
      .map(|c| format!("缺少组件 {c}")),
  );
  if bad.is_empty() {
    let starting = p.containers.iter().any(|c| {
      !c.foreign
        && c.is_running()
        && c.health.as_deref() == Some("starting")
    });
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
