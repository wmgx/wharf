//! 组装 API 视图，必要时向 agent 查实时状态。

use chrono::{DateTime, Utc};
use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use wharf_api_types::{
  ApiError,
  agent::ProjectState,
  spec::{Fleet, GatewayKind, GatewayTls},
  view::{
    BookmarkView, EdgeAppView, EdgeLive, EdgeProjectView,
    GatewayView, ImportRecord, Issue, IssueLevel, IssueSubject,
    LiveState, RouteView, ServerView, ServiceView, Status, Tone,
  },
};

use crate::{
  db::to_time,
  render::Net,
  snapshot::{self, Snapshot},
  state::AppState,
  world::{World, gateway_project},
};

/// 服务器 → project → 现状；查不到时是错误信息。
pub type LiveMap =
  BTreeMap<String, Result<BTreeMap<String, ProjectState>, ApiError>>;

/// 查实时状态的超时，status 要快。
const LIVE_TIMEOUT: Duration = Duration::from_secs(6);

pub fn server_view(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
) -> Option<ServerView> {
  let row = snap.world.servers.get(name)?;
  let agent = snap.agent(name);
  let mut report = agent.and_then(|a| a.report.clone());
  let agent_usage =
    crate::resource_top::agent_usage(&row.settings, report.as_ref());
  if let Some(report) = &mut report {
    report.metrics = None;
    report.agent_memory = None;
    report.time_ms = None;
  }
  Some(ServerView {
    note: snap.server_notes.get(name).cloned(),
    name: name.to_string(),
    settings: row.settings.clone(),
    agent: agent_usage,
    joined: agent.is_some_and(|a| a.public_key.is_some()),
    online: state.hub.is_online(name),
    host_shell: state.hub.supports_host_shell(name),
    rtt_ms: state.hub.rtt_ms(name),
    last_seen: agent.and_then(|a| a.last_seen).map(to_time),
    public_ip: row
      .settings
      .public_ip
      .clone()
      .or_else(|| report.as_ref().and_then(|r| r.public_ip.clone())),
    private_addr: row.settings.private_addr.clone().or_else(|| {
      report.as_ref().and_then(|r| r.private_addr.clone())
    }),
    agent_outdated: state.hub.is_online(name)
      && crate::agent_upgrade::outdated(
        report.as_ref().map(|r| r.build.as_str()),
      ),
    tailnet_key: crate::vendor_checks::key(
      name,
      crate::tailnet_probe::address(snap, name),
    ),
    report,
    version: row.version,
    baseline_drift: crate::baseline::drift(name),
    disk_days_left: crate::disk_forecast::days_left(name),
    clock_offset_ms: if state.hub.is_online(name) {
      crate::clock::offset_of(name)
    } else {
      None
    },
  })
}

/// 每台在线服务器查一次全部 project 的现状。
pub async fn live_states(state: &AppState, world: &World) -> LiveMap {
  let mut projects: BTreeMap<String, Vec<String>> = BTreeMap::new();
  for (name, s) in &world.services {
    projects
      .entry(s.spec.server.clone())
      .or_default()
      .push(name.clone());
  }
  for (name, g) in &world.gateways {
    projects
      .entry(g.spec.server.clone())
      .or_default()
      .push(gateway_project(name));
  }
  let futures =
    projects.into_iter().map(|(server, projects)| async move {
      let result = snapshot::project_status(
        &state.hub,
        &server,
        projects,
        LIVE_TIMEOUT,
      )
      .await;
      (server, result)
    });
  let live: LiveMap = futures_util::future::join_all(futures)
    .await
    .into_iter()
    .collect();
  if let Ok(mut seen) = OBSERVED.lock() {
    let now = Utc::now();
    for (server, r) in &live {
      if r.is_ok() {
        seen.insert(server.clone(), now);
      }
    }
  }
  live
}

/// 每台服务器最后一次查到现状的时间，只在内存里（控制面重启后清空）。
static OBSERVED: Mutex<BTreeMap<String, DateTime<Utc>>> =
  Mutex::new(BTreeMap::new());

fn observed_at(server: &str) -> Option<DateTime<Utc>> {
  OBSERVED.lock().ok()?.get(server).copied()
}

/// 后台每隔 [LIVE_EVERY] 查一次各服务器现状，`status` 读这份缓存，不用等最慢的那台。
static LIVE_CACHE: Mutex<Option<(Instant, LiveMap)>> =
  Mutex::new(None);
const LIVE_EVERY: Duration = Duration::from_secs(5);
/// 缓存比这更旧（后台卡住）时 `status` 自己现查。
const LIVE_STALE: Duration = Duration::from_secs(30);

async fn refresh_live(state: &AppState) -> Result<LiveMap, ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let live = live_states(state, &snap.world).await;
  if let Ok(mut c) = LIVE_CACHE.lock() {
    *c = Some((Instant::now(), live.clone()));
  }
  Ok(live)
}

/// 有改动执行完一步时调用：马上刷新一次，页面不用等下一轮。
pub fn refresh_live_soon(state: Arc<AppState>) {
  tokio::spawn(async move {
    let _ = refresh_live(&state).await;
  });
}

pub fn spawn_live(state: Arc<AppState>) {
  tokio::spawn(async move {
    loop {
      if let Err(e) = refresh_live(&state).await {
        tracing::warn!("刷新服务器现状失败：{e}");
      }
      tokio::time::sleep(LIVE_EVERY).await;
    }
  });
}

/// 缓存里的现状；没有或太旧时现查。
pub async fn cached_live(state: &AppState, world: &World) -> LiveMap {
  let cached = LIVE_CACHE
    .lock()
    .ok()
    .and_then(|c| c.clone())
    .filter(|(at, _)| at.elapsed() < LIVE_STALE);
  match cached {
    Some((_, live)) => live,
    None => live_states(state, world).await,
  }
}

/// `stopped`：配置要求停止，这时容器停着才算和配置一致。
fn live_of(
  live: &LiveMap,
  server: &str,
  project: &str,
  expected_hash: Option<&str>,
  stopped: bool,
) -> LiveState {
  match live.get(server) {
    None => LiveState {
      state: "unknown".into(),
      containers: vec![],
      in_sync: None,
      error: None,
    },
    Some(Err(e)) => LiveState {
      state: "unknown".into(),
      containers: vec![],
      in_sync: None,
      error: Some(e.message.clone()),
    },
    Some(Ok(states)) => {
      let s = states.get(project);
      let containers =
        s.map(|s| s.containers.clone()).unwrap_or_default();
      let running =
        containers.iter().filter(|c| c.state == "running").count();
      let state = if containers.is_empty() {
        "missing"
      } else if running == containers.len() {
        "running"
      } else if running == 0 {
        "stopped"
      } else {
        "partial"
      };
      LiveState {
        state: state.into(),
        in_sync: expected_hash.map(|h| {
          s.and_then(|s| s.hash.as_deref()) == Some(h)
            && state == if stopped { "stopped" } else { "running" }
        }),
        containers,
        error: None,
      }
    }
  }
}

/// 还没部署的导入在服务的 meta 里，部署过的在导入记录表里。
fn import_record(
  snap: &Snapshot,
  name: &str,
) -> Option<ImportRecord> {
  let row = &snap.world.services[name];
  match &row.import {
    Some(a) => Some(ImportRecord {
      server: row.spec.server.clone(),
      project: a.project.clone(),
      containers: a.containers.clone(),
      retired: Vec::new(),
      done_at: None,
    }),
    None => snap.imports.get(name).cloned(),
  }
}

/// 服务器上没有这个服务的容器。
fn empty_project(name: &str) -> ProjectState {
  ProjectState {
    project: name.to_string(),
    hash: None,
    config_hash: None,
    containers: Vec::new(),
  }
}

pub fn service_view(
  snap: &Snapshot,
  net: &Net,
  name: &str,
  live: Option<&LiveMap>,
) -> Option<ServiceView> {
  let row = snap.world.services.get(name)?;
  let addresses = row
    .host_ports
    .iter()
    .map(|(port, host)| {
      let ip = net
        .private
        .get(&row.spec.server)
        .map(|a| a.ip.clone())
        .unwrap_or_else(|| "127.0.0.1".into());
      let suffix =
        if row.spec.find_port(Some(port)).is_some_and(|p| p.udp) {
          "/udp"
        } else {
          ""
        };
      (port.clone(), format!("{ip}:{host}{suffix}"))
    })
    .collect();
  let lan_addresses = net
    .lan_addrs
    .get(&row.spec.server)
    .map(|ips| {
      row
        .host_ports
        .iter()
        .map(|(port, host)| {
          let suffix = if row
            .spec
            .find_port(Some(port))
            .is_some_and(|p| p.udp)
          {
            "/udp"
          } else {
            ""
          };
          (
            port.clone(),
            ips
              .iter()
              .map(|ip| format!("{ip}:{host}{suffix}"))
              .collect(),
          )
        })
        .collect()
    })
    .unwrap_or_default();
  let hash = live.and_then(|_| {
    snapshot::service_resolved(
      &snap.world,
      net,
      name,
      &snap.render_values(&snap.world, name),
    )
    .ok()
    .map(|(_, h)| h)
  });
  let status = live.map(|live| {
    let project = live
      .get(&row.spec.server)
      .map(|r| r.as_ref().map(|states| states.get(name)));
    let missing = empty_project(name);
    let project = project.map(|r| r.map(|p| p.unwrap_or(&missing)));
    crate::status::service_status(crate::status::Inputs {
      want_running: !row.spec.stopped,
      desired_hash: hash.clone(),
      applied: snap.applied.get(name),
      live: project.as_ref(),
      last_op: snap.ops.get(name),
      observed_at: observed_at(&row.spec.server),
    })
  });
  let containers = live
    .and_then(|l| l.get(&row.spec.server))
    .and_then(|r| r.as_ref().ok())
    .and_then(|states| states.get(name))
    .map(|p| p.containers.clone())
    .unwrap_or_default();
  Some(ServiceView {
    risks: if crate::agent_upgrade::outdated(
      snap
        .agent(&row.spec.server)
        .and_then(|a| a.report.as_ref())
        .map(|r| r.build.as_str()),
    ) {
      vec![]
    } else {
      crate::exposure::service_risks(&row.spec.server, name)
    },
    name: name.to_string(),
    spec: crate::service_monitor::heartbeat::redact(&row.spec),
    host_ports: row.host_ports.clone(),
    addresses,
    lan_addresses,
    note: snap.notes.get(name).cloned(),
    version: row.version,
    containers,
    data: crate::data::mounts(name, &row.spec),
    import: import_record(snap, name),
    status,
    monitor: crate::monitor::last(name),
    log_alerts: crate::service_monitor::log_views(name, &row.spec),
    port_checks: crate::service_monitor::port_views(name, row),
    heartbeat: crate::service_monitor::heartbeat::view(
      snap, name, false,
    ),
    uses: crate::refs::uses(&row.spec),
    used_by: snap
      .world
      .services
      .iter()
      .filter(|(_, r)| {
        crate::refs::uses(&r.spec).iter().any(|u| u == name)
      })
      .map(|(n, _)| n.clone())
      .collect(),
  })
}

pub fn gateway_view(
  snap: &Snapshot,
  net: &Net,
  name: &str,
  live: Option<&LiveMap>,
) -> Option<GatewayView> {
  let world = &snap.world;
  let row = world.gateways.get(name)?;
  let routes = world
    .routes
    .iter()
    .filter(|(_, r)| world.route_gateways(&r.spec).contains(&name))
    .map(|(h, _)| h.clone())
    .collect();
  let live = live.map(|live| {
    let mut l = live_of(
      live,
      &row.spec.server,
      &gateway_project(name),
      None,
      false,
    );
    if let (Ok(r), Some(Ok(states))) = (
      snapshot::gateway_render(world, net, name),
      live.get(&row.spec.server),
    ) {
      l.in_sync = states.get(&gateway_project(name)).map(|s| {
        let applied = match row.spec.kind {
          GatewayKind::Caddy => s.config_hash.as_deref(),
          GatewayKind::CloudflareTunnel => {
            snap.tunnels.get(name).map(|t| t.config_hash.as_str())
          }
        };
        s.hash.as_deref() == Some(r.compose_hash.as_str())
          && applied == Some(r.config_hash.as_str())
          && s.all_running()
      });
    }
    l
  });
  Some(GatewayView {
    name: name.to_string(),
    spec: row.spec.clone(),
    routes,
    version: row.version,
    live,
  })
}

pub fn route_view(
  snap: &Snapshot,
  net: &Net,
  hostname: &str,
) -> Option<RouteView> {
  route_view_with_upstream_error(snap, net, hostname)
    .map(|(view, _)| view)
}

pub(crate) fn route_view_with_upstream_error(
  snap: &Snapshot,
  net: &Net,
  hostname: &str,
) -> Option<(RouteView, Option<ApiError>)> {
  let world = &snap.world;
  let row = world.routes.get(hostname)?;
  let gateway =
    world.live_gateway(hostname, &row.spec).map(str::to_string);
  let on_backup = row.spec.backup_gateway.is_some()
    && crate::failover::active(hostname);
  let gw_spec = gateway.as_ref().and_then(|g| world.gateways.get(g));
  let (upstream, upstream_error) = match gw_spec
    .map(|g| world.route_upstream(net, &g.spec, hostname, &row.spec))
  {
    Some(Ok(upstream)) => (Some(upstream), None),
    Some(Err(error)) => (None, Some(error)),
    None => (None, None),
  };
  let url = match gw_spec.map(|g| &g.spec) {
    Some(g) if g.tls == GatewayTls::Off => {
      match g.http_port.filter(|p| *p != 80) {
        Some(port) => format!("http://{hostname}:{port}"),
        None => format!("http://{hostname}"),
      }
    }
    g => match g.and_then(|g| g.https_port).filter(|p| *p != 443) {
      Some(port) => format!("https://{hostname}:{port}"),
      None => format!("https://{hostname}"),
    },
  };
  Some((
    RouteView {
      core: crate::gate::is_core_host(world, net, hostname),
      note: snap.route_notes.get(hostname).cloned(),
      sso_login: row
        .spec
        .sso
        .as_ref()
        .filter(|s| s.mode == wharf_api_types::spec::SsoMode::Login)
        .and_then(|_| snap.sso_login.get(hostname))
        .and_then(|s| serde_json::from_str(s).ok()),
      id: row.id.clone(),
      spec: row.spec.clone(),
      gateway,
      upstream,
      probe: crate::probe::last(hostname),
      url,
      version: row.version,
      on_backup,
    },
    upstream_error,
  ))
}

pub(crate) fn problems_text(issues: &[Issue]) -> Vec<String> {
  issues
    .iter()
    .filter(|i| i.level != IssueLevel::Info)
    .map(|i| {
      format!("{}{}", i.title, i.hint.as_deref().unwrap_or(""))
    })
    .collect()
}

mod status;
pub use status::status;

pub fn edge_view(snap: &Snapshot, name: &str) -> Option<EdgeAppView> {
  let row = snap.world.edge_apps.get(name)?;
  let target = crate::edge_sync::target(name, &row.spec);
  let cache =
    snap.edge_cache.get(name).filter(|c| c.target == target);
  Some(EdgeAppView {
    name: name.to_string(),
    spec: row.spec.clone(),
    version: row.version,
    live: cache.map(|c| c.live.clone()),
    drift: crate::edge_sync::drift(
      &target,
      cache,
      snap.edge_expected.get(name),
    ),
  })
}

pub fn export(world: &World) -> Fleet {
  Fleet {
    bookmarks: world
      .bookmarks
      .iter()
      .map(|(id, r)| (id.clone(), r.spec.clone()))
      .collect(),
    servers: world
      .servers
      .iter()
      .map(|(n, r)| (n.clone(), r.settings.clone()))
      .collect(),
    services: world
      .services
      .iter()
      .map(|(n, r)| {
        (
          n.clone(),
          crate::service_monitor::heartbeat::redact(&r.spec),
        )
      })
      .collect(),
    gateways: world
      .gateways
      .iter()
      .map(|(n, r)| (n.clone(), r.spec.clone()))
      .collect(),
    edge_apps: world
      .edge_apps
      .iter()
      .map(|(n, r)| (n.clone(), r.spec.clone()))
      .collect(),
    routes: world.routes.values().map(|r| r.spec.clone()).collect(),
  }
}

const GB: f64 = (1u64 << 30) as f64;

/// 剩余不到 10% 或不到 5 GB。
/// 剩余不到总量的 10%，或者不到 5 GB 且不到总量的 25%（小盘不会因为总量本来就小而一直告警）。
fn low_disk(d: wharf_api_types::agent::Disk) -> bool {
  d.free < d.total / 10
    || ((d.free as f64) < 5.0 * GB && d.free < d.total / 4)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn problems_text_keeps_hint_and_omits_info() {
    let issues = vec![
      Issue {
        code: "gateway_drift".into(),
        level: IssueLevel::Warn,
        subject: None,
        title: "网关 s1 和配置不一致".into(),
        hint: Some("，执行 wharf plan 查看".into()),
        ack: None,
        alert: None,
      },
      Issue {
        code: "update_available".into(),
        level: IssueLevel::Info,
        subject: None,
        title: "s1 有新版本".into(),
        hint: None,
        ack: None,
        alert: None,
      },
    ];
    assert_eq!(
      problems_text(&issues),
      vec!["网关 s1 和配置不一致，执行 wharf plan 查看"]
    );
  }
}
