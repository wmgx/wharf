//! 组装 API 视图，必要时向 agent 查实时状态。

use std::{collections::BTreeMap, time::Duration};

use wharf_api_types::{
  agent::ProjectState,
  spec::{Fleet, GatewayTls},
  view::{
    GatewayView, LiveState, RouteView, ServerView, ServiceView,
    Status,
  },
};

use crate::{
  db::to_time,
  render::{self, Net},
  snapshot::{self, Snapshot},
  state::AppState,
  world::{World, gateway_project},
};

/// 服务器 → project → 现状；查不到时是错误信息。
pub type LiveMap =
  BTreeMap<String, Result<BTreeMap<String, ProjectState>, String>>;

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
    last_seen: agent.and_then(|a| a.last_seen).map(to_time),
    public_ip: row
      .settings
      .public_ip
      .clone()
      .or_else(|| report.as_ref().and_then(|r| r.public_ip.clone())),
    report,
    version: row.version,
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
      .await
      .map_err(|e| e.message);
      (server, result)
    });
  futures_util::future::join_all(futures)
    .await
    .into_iter()
    .collect()
}

fn live_of(
  live: &LiveMap,
  server: &str,
  project: &str,
  expected_hash: Option<&str>,
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
      error: Some(e.clone()),
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
            && state == "running"
        }),
        containers,
        error: None,
      }
    }
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
        .tailscale_ip
        .get(&row.spec.server)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".into());
      (port.clone(), format!("{ip}:{host}"))
    })
    .collect();
  let live = live.map(|live| {
    let hash = snapshot::service_resolved(
      &snap.world,
      net,
      name,
      &snap.secrets,
    )
    .ok()
    .map(|(_, h)| h);
    live_of(live, &row.spec.server, name, hash.as_deref())
  });
  Some(ServiceView {
    name: name.to_string(),
    spec: row.spec.clone(),
    host_ports: row.host_ports.clone(),
    addresses,
    version: row.version,
    live,
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
    .filter(|(_, r)| world.route_gateway(&r.spec) == Some(name))
    .map(|(h, _)| h.clone())
    .collect();
  let live = live.map(|live| {
    let mut l =
      live_of(live, &row.spec.server, &gateway_project(name), None);
    if let (Ok(r), Some(Ok(states))) = (
      snapshot::gateway_render(world, net, name),
      live.get(&row.spec.server),
    ) {
      l.in_sync = states.get(&gateway_project(name)).map(|s| {
        s.hash.as_deref() == Some(r.compose_hash.as_str())
          && s.config_hash.as_deref()
            == Some(r.caddyfile_hash.as_str())
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
  let gateway = world.route_gateway(&row.spec).map(str::to_string);
  let gw_spec = gateway.as_ref().and_then(|g| world.gateways.get(g));
  let upstream = gw_spec.and_then(|g| {
    let port = world.route_port(&row.spec)?;
    render::upstream(
      world,
      net,
      &g.spec.server,
      &row.spec.service,
      port,
    )
    .ok()
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
    url,
    version: row.version,
  })
}

pub async fn status(
  state: &AppState,
) -> Result<Status, wharf_api_types::ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let net = snap.net(&snap.world);
  let live = live_states(state, &snap.world).await;
  let mut problems = Vec::new();
  let servers: Vec<ServerView> = snap
    .world
    .servers
    .keys()
    .filter_map(|n| server_view(state, &snap, n))
    .collect();
  for s in &servers {
    if !s.joined {
      problems
        .push(format!("服务器 {} 还没有完成 agent 加入", s.name));
    } else if !s.online {
      problems.push(format!("服务器 {} 离线", s.name));
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
  for (kind, name, live) in services
    .iter()
    .map(|s| ("服务", &s.name, &s.live))
    .chain(gateways.iter().map(|g| ("网关", &g.name, &g.live)))
  {
    let Some(live) = live else { continue };
    if live.state != "running" && live.state != "unknown" {
      problems.push(format!("{kind} {name} 状态是 {}", live.state));
    } else if live.in_sync == Some(false) {
      problems.push(format!(
        "{kind} {name} 和配置不一致，执行 wharf plan 查看"
      ));
    }
  }
  let routes = snap
    .world
    .routes
    .keys()
    .filter_map(|h| route_view(&snap, &net, h))
    .collect();
  Ok(Status {
    servers,
    services,
    gateways,
    routes,
    problems,
  })
}

pub fn export(world: &World) -> Fleet {
  Fleet {
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
    routes: world.routes.values().map(|r| r.spec.clone()).collect(),
  }
}
