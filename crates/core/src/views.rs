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
  let report = agent.and_then(|a| a.report.clone());
  Some(ServerView {
    name: name.to_string(),
    settings: row.settings.clone(),
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
      (port.clone(), format!("{ip}:{host}"))
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
          (
            port.clone(),
            ips.iter().map(|ip| format!("{ip}:{host}")).collect(),
          )
        })
        .collect()
    })
    .unwrap_or_default();
  let hash = live.and_then(|_| {
    snapshot::service_resolved(&snap.world, net, name, &snap.secrets)
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
    name: name.to_string(),
    spec: row.spec.clone(),
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
  let world = &snap.world;
  let row = world.routes.get(hostname)?;
  let gateway =
    world.live_gateway(hostname, &row.spec).map(str::to_string);
  let on_backup = row.spec.backup_gateway.is_some()
    && crate::failover::active(hostname);
  let gw_spec = gateway.as_ref().and_then(|g| world.gateways.get(g));
  let upstream = gw_spec.and_then(|g| {
    world.route_upstream(net, &g.spec, hostname, &row.spec).ok()
  });
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
  Some(RouteView {
    id: row.id.clone(),
    spec: row.spec.clone(),
    gateway,
    upstream,
    probe: crate::probe::last(hostname),
    url,
    version: row.version,
    on_backup,
  })
}

fn problems_text(issues: &[Issue]) -> Vec<String> {
  issues
    .iter()
    .filter(|i| i.level != IssueLevel::Info)
    .map(|i| {
      format!("{}{}", i.title, i.hint.as_deref().unwrap_or(""))
    })
    .collect()
}

pub async fn status(
  state: &AppState,
) -> Result<Status, wharf_api_types::ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let net = snap.net(&snap.world);
  let live = cached_live(state, &snap.world).await;
  let mut issues = Vec::new();
  let servers: Vec<ServerView> = snap
    .world
    .servers
    .keys()
    .filter_map(|n| server_view(state, &snap, n))
    .collect();
  for s in &servers {
    if !s.joined {
      issues.push(Issue {
        code: "server_not_joined".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: s.name.clone(),
        }),
        title: format!("服务器 {} 还没有完成 agent 加入", s.name),
        hint: None,
      });
    } else if !s.online {
      issues.push(Issue {
        code: "server_offline".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: s.name.clone(),
        }),
        title: format!("服务器 {} 离线", s.name),
        hint: None,
      });
    }
    let disks = s
      .report
      .as_ref()
      .map(|r| [("磁盘", r.disk), ("Docker 所在磁盘", r.docker_disk)])
      .unwrap_or_default();
    for (label, d) in disks {
      if let Some(d) = d
        && low_disk(d)
      {
        issues.push(Issue {
          code: "disk_low".into(),
          level: IssueLevel::Warn,
          subject: Some(IssueSubject {
            kind: "server".into(),
            name: s.name.clone(),
          }),
          title: format!(
            "服务器 {} {label}只剩 {:.1} GB",
            s.name,
            d.free as f64 / GB
          ),
          hint: None,
        });
      }
    }
  }
  let services: Vec<ServiceView> = snap
    .world
    .services
    .keys()
    .filter_map(|n| service_view(&snap, &net, n, Some(&live)))
    .collect();
  let gateways: Vec<GatewayView> = snap
    .world
    .gateways
    .keys()
    .filter_map(|n| gateway_view(&snap, &net, n, Some(&live)))
    .collect();
  for s in &services {
    if let Some(st) = &s.status
      && matches!(st.tone, Tone::Warn | Tone::Bad)
    {
      issues.push(Issue {
        code: "service_unhealthy".into(),
        level: if st.tone == Tone::Bad {
          IssueLevel::Fault
        } else {
          IssueLevel::Warn
        },
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: s.name.clone(),
        }),
        title: format!("服务 {}：{}", s.name, st.summary),
        hint: None,
      });
    }
  }
  for (kind, name, live) in
    gateways.iter().map(|g| ("网关", &g.name, &g.live))
  {
    let Some(live) = live else { continue };
    if live.state != "running" && live.state != "unknown" {
      issues.push(Issue {
        code: "gateway_state".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "gateway".into(),
          name: name.clone(),
        }),
        title: format!("{kind} {name} 状态是 {}", live.state),
        hint: None,
      });
    } else if live.in_sync == Some(false) {
      issues.push(Issue {
        code: "gateway_drift".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "gateway".into(),
          name: name.clone(),
        }),
        title: format!("{kind} {name} 和配置不一致"),
        hint: Some("，执行 wharf plan 查看".into()),
      });
    }
  }
  let edge_apps: Vec<EdgeAppView> = snap
    .world
    .edge_apps
    .keys()
    .filter_map(|n| edge_view(&snap, n))
    .collect();
  for app in &edge_apps {
    if let Some(d) = &app.drift {
      issues.push(Issue {
        code: "edge_drift".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "edge".into(),
          name: app.name.clone(),
        }),
        title: format!("边缘应用 {}：{d}", app.name),
        hint: None,
      });
    } else if let Some(EdgeLive { error: Some(e), .. }) = &app.live {
      issues.push(Issue {
        code: "edge_sync".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "edge".into(),
          name: app.name.clone(),
        }),
        title: format!("边缘应用 {} 同步失败：{e}", app.name),
        hint: None,
      });
    }
  }
  issues.extend(crate::tasks::issues(state).await);
  issues.extend(crate::probe::issues());
  issues.extend(crate::alerts::issues());
  issues.extend(crate::monitor::issues());
  issues.extend(crate::rdap::issues());
  issues.extend(crate::disk_forecast::issues());
  issues.extend(crate::clock::issues());
  issues.extend(crate::baseline::issues());
  issues.extend(crate::host_units::issues());
  let updates = crate::updates::last();
  if let Some(updates) = &updates {
    for (name, check) in &updates.services {
      if check.newer && services.iter().any(|s| &s.name == name) {
        issues.push(Issue {
          code: "update_available".into(),
          level: IssueLevel::Info,
          subject: Some(IssueSubject {
            kind: "service".into(),
            name: name.clone(),
          }),
          title: format!("{name} 有新版本"),
          hint: None,
        });
      }
    }
    if let Some(pending) = &updates.pending
      && !pending.items.is_empty()
    {
      let items = &pending.items;
      issues.push(Issue {
        code: "pending_changes".into(),
        level: IssueLevel::Info,
        subject: None,
        title: format!(
          "有 {} 项改动还没执行：{}{}",
          items.len(),
          items
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("、"),
          if items.len() > 3 { " 等" } else { "" }
        ),
        hint: None,
      });
    }
  }
  let problems = problems_text(&issues);
  issues.sort_by_key(|i| match i.level {
    IssueLevel::Fault => 0,
    IssueLevel::Warn => 1,
    IssueLevel::Info => 2,
  });
  let mut edge_unmanaged: Vec<EdgeProjectView> =
    snap.edge_accounts.values().flatten().cloned().collect();
  crate::edge_sync::mark_managed(&snap, &mut edge_unmanaged);
  edge_unmanaged.retain(|p| p.managed_as.is_none());
  let routes = snap
    .world
    .routes
    .keys()
    .filter_map(|h| route_view(&snap, &net, h))
    .collect();
  let mut bookmarks: Vec<_> = snap
    .world
    .bookmarks
    .iter()
    .map(|(id, r)| BookmarkView {
      id: id.clone(),
      spec: r.spec.clone(),
      version: r.version,
    })
    .collect();
  bookmarks.sort_by(|a, b| {
    a.spec
      .order
      .cmp(&b.spec.order)
      .then_with(|| a.spec.title.cmp(&b.spec.title))
  });
  Ok(Status {
    bookmarks,
    servers,
    services,
    edge_apps,
    edge_unmanaged,
    gateways,
    routes,
    problems,
    issues,
    health: crate::doctor::last(),
    updates,
  })
}

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
      .map(|(n, r)| (n.clone(), r.spec.clone()))
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
fn low_disk(d: wharf_api_types::agent::Disk) -> bool {
  d.free < d.total / 10 || (d.free as f64) < 5.0 * GB
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
      },
      Issue {
        code: "update_available".into(),
        level: IssueLevel::Info,
        subject: None,
        title: "s1 有新版本".into(),
        hint: None,
      },
    ];
    assert_eq!(
      problems_text(&issues),
      vec!["网关 s1 和配置不一致，执行 wharf plan 查看"]
    );
  }
}
