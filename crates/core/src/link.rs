//! 链路：网关怎么连到服务（design 2.7.2）。
//!
//! 同机走 127.0.0.1；网关所在机器能连到服务所在机器的内网地址就直连；
//! 否则走反向隧道：网关那台跑 frps，只监听本机，由 Caddy 网关在 443 上转发；
//! 服务那台跑 frpc，用 wss 主动连过去，不用另开端口。
//! cloudflare_tunnel 网关的连接器本身就是主动往外连，不需要隧道：连不到就在服务那台建一个。

use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, PROBE_PORT, ProbeTarget},
  spec::{GatewayKind, GatewaySpec, LinkMode, RouteSpec},
};

use crate::{
  db,
  render::{self, Net},
  state::AppState,
  world::World,
};

/// 网关所在机器上的 frps。
pub const SERVER_PROJECT: &str = "wharf-link";
/// frps 和 frpc 之间的认证密钥，第一次部署隧道时自动生成。
pub const TOKEN_SECRET: &str = "WHARF_LINK_TOKEN";
/// frps 只监听 127.0.0.1，Caddy 把 `FRP_PATH` 转发过来。
pub const FRPS_PORT: u16 = 7000;
/// frp 的 websocket 路径，frps 认这个路径。
pub const FRP_PATH: &str = "/~!frp";
/// frpc 握手时带的名字（SNI 和 Host）。按 IP 连时不带 SNI，Caddy 选不出证书。
pub const LINK_HOST: &str = "link.wharf.internal";
/// frps 只把隧道端口绑在 127.0.0.1，从这个范围里取。
const TUNNEL_PORTS: std::ops::RangeInclusive<u16> = 30000..=39999;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// 服务所在机器上连到 `gateway_server` 的 frpc。
pub fn client_project(gateway_server: &str) -> String {
  format!("{SERVER_PROJECT}-{gateway_server}")
}

pub fn is_link_project(project: &str) -> bool {
  project == SERVER_PROJECT
    || project.starts_with(&format!("{SERVER_PROJECT}-"))
}

#[derive(Debug, PartialEq)]
pub enum Choice {
  Local,
  Direct(String),
  Tunnel,
}

pub fn choose(
  world: &World,
  net: &Net,
  gateway: &GatewaySpec,
  service: &str,
  mode: LinkMode,
) -> Result<Choice, ApiError> {
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::invalid(format!("服务 {service} 不存在"))
  })?;
  let server = &row.spec.server;
  let gateway_server = &gateway.server;
  if server == gateway_server {
    return Ok(Choice::Local);
  }
  let reach = net
    .reach
    .get(&(gateway_server.clone(), server.clone()))
    .copied();
  let choice = match net.private.get(server) {
    Some(addr)
      if mode != LinkMode::Tunnel && reach != Some(false) =>
    {
      Choice::Direct(addr.ip.clone())
    }
    _ => Choice::Tunnel,
  };
  if choice == Choice::Tunnel
    && gateway.kind == GatewayKind::CloudflareTunnel
  {
    return Err(ApiError::invalid(format!(
      "服务 {service} 在 {server} 上，cloudflare_tunnel 网关所在的 {gateway_server} 连不到它"
    ))
    .with_hint(format!(
      "在 {server} 上建一个 cloudflare_tunnel 网关，路由改用它，不需要开端口"
    )));
  }
  Ok(choice)
}

/// 路由指向的 Wharf 服务：`(服务, 端口名)`，包括按路径转发的。
fn route_targets(
  world: &World,
  route: &RouteSpec,
) -> Vec<(String, String)> {
  let mut out = Vec::new();
  if route.upstream.is_none()
    && world.services.contains_key(&route.service)
    && let Some(port) = world.route_port(route)
  {
    out.push((route.service.clone(), port.to_string()));
  }
  for p in &route.paths {
    if let (None, Some(svc)) = (&p.upstream, &p.service)
      && world.services.contains_key(svc)
      && let Some(port) = world.service_port(svc, p.port.as_deref())
    {
      out.push((svc.clone(), port.to_string()));
    }
  }
  out
}

/// 路由所在的网关，以及它指向的服务。
fn routes_by_gateway(
  world: &World,
) -> impl Iterator<Item = (&GatewaySpec, &RouteSpec, Vec<(String, String)>)>
{
  world.routes.values().filter_map(move |r| {
    let gw = world.route_gateway(&r.spec)?;
    let spec = &world.gateways.get(gw)?.spec;
    Some((spec, &r.spec, route_targets(world, &r.spec)))
  })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
  pub gateway_server: String,
  pub service_server: String,
  pub service: String,
  pub port: String,
  pub local_port: u16,
  pub remote_port: u16,
}

/// 全部要走隧道的端口。隧道端口按名字散列取，增删别的隧道时基本不变。
pub fn tunnels(
  world: &World,
  net: &Net,
) -> Result<Vec<Tunnel>, ApiError> {
  let mut wanted = BTreeSet::new();
  for (gateway, route, targets) in routes_by_gateway(world) {
    for (service, port) in targets {
      if choose(world, net, gateway, &service, route.link)?
        == Choice::Tunnel
      {
        wanted.insert((gateway.server.clone(), service, port));
      }
    }
  }
  let mut used: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
  for row in world.services.values() {
    used
      .entry(row.spec.server.clone())
      .or_default()
      .extend(row.host_ports.values());
  }
  let mut out = Vec::new();
  for (gateway_server, service, port) in wanted {
    let row = &world.services[&service];
    let local_port = *row.host_ports.get(&port).ok_or_else(|| {
      ApiError::internal(format!(
        "服务 {service} 的端口 {port} 没有分配"
      ))
    })?;
    let taken = used.entry(gateway_server.clone()).or_default();
    let remote_port = pick_port(&format!("{service}/{port}"), taken)
      .ok_or_else(|| {
        ApiError::invalid(format!(
          "服务器 {gateway_server} 上的隧道端口用完了"
        ))
      })?;
    out.push(Tunnel {
      service_server: row.spec.server.clone(),
      gateway_server,
      service,
      port,
      local_port,
      remote_port,
    });
  }
  Ok(out)
}

fn pick_port(key: &str, taken: &mut BTreeSet<u16>) -> Option<u16> {
  let base = *TUNNEL_PORTS.start() as u32;
  let n = TUNNEL_PORTS.len() as u32;
  // FNV-1a：跨版本稳定，同一个服务端口每次算出来一样。
  let hash = key.bytes().fold(0x811c9dc5u32, |h, b| {
    (h ^ b as u32).wrapping_mul(0x01000193)
  });
  (0..n)
    .map(|i| (base + (hash % n + i) % n) as u16)
    .find(|p| taken.insert(*p))
}

/// 网关上游里隧道的地址。
pub fn tunnel_upstream(
  world: &World,
  net: &Net,
  gateway_server: &str,
  service: &str,
  port: &str,
) -> Result<String, ApiError> {
  tunnels(world, net)?
    .into_iter()
    .find(|t| {
      t.gateway_server == gateway_server
        && t.service == service
        && t.port == port
    })
    .map(|t| format!("127.0.0.1:{}", t.remote_port))
    .ok_or_else(|| {
      ApiError::internal(format!("服务 {service} 的隧道没有分配端口"))
    })
}

/// 一台机器上要部署的隧道项目（frps 或 frpc）。compose 里密钥是占位，部署时才替换。
#[derive(Debug, Clone)]
pub struct LinkProject {
  pub server: String,
  pub project: String,
  pub compose: String,
  pub hash: String,
  /// 给人看的说明。
  pub summary: String,
}

pub fn projects(
  world: &World,
  net: &Net,
) -> Result<Vec<LinkProject>, ApiError> {
  let tunnels = tunnels(world, net)?;
  let mut clients: BTreeMap<(String, String), Vec<&Tunnel>> =
    BTreeMap::new();
  for t in &tunnels {
    clients
      .entry((t.service_server.clone(), t.gateway_server.clone()))
      .or_default()
      .push(t);
  }
  let servers: BTreeSet<&str> =
    tunnels.iter().map(|t| t.gateway_server.as_str()).collect();
  let mut out = Vec::new();
  for server in servers {
    let compose = render::frps_compose(SERVER_PROJECT);
    out.push(LinkProject {
      server: server.to_string(),
      project: SERVER_PROJECT.to_string(),
      hash: render::hash(&compose),
      compose,
      summary: "隧道服务端 frps，经 Caddy 网关的 443 接入"
        .to_string(),
    });
  }
  for ((service_server, gateway_server), list) in clients {
    let addr = frps_addr(net, &gateway_server)?;
    let port = link_gateway(world, &gateway_server)
      .and_then(|(_, g)| g.https_port)
      .unwrap_or(443);
    let project = client_project(&gateway_server);
    let proxies: Vec<(String, u16, u16)> = list
      .iter()
      .map(|t| {
        (
          format!("{}.{}", t.service, t.port),
          t.local_port,
          t.remote_port,
        )
      })
      .collect();
    let compose =
      render::frpc_compose(&project, &addr, port, &proxies);
    let names: Vec<String> = list
      .iter()
      .map(|t| format!("{}:{}", t.service, t.port))
      .collect();
    out.push(LinkProject {
      server: service_server.clone(),
      hash: render::hash(&compose),
      compose,
      project,
      summary: format!(
        "{service_server} → {gateway_server} 反向隧道：{}",
        names.join("、")
      ),
    });
  }
  Ok(out)
}

/// 一台机器上给 frps 做转发的 Caddy 网关：按名字排第一个。
fn link_gateway<'a>(
  world: &'a World,
  server: &str,
) -> Option<(&'a str, &'a GatewaySpec)> {
  world
    .gateways
    .iter()
    .find(|(_, g)| {
      g.spec.server == server && g.spec.kind == GatewayKind::Caddy
    })
    .map(|(n, g)| (n.as_str(), &g.spec))
}

/// Caddy 网关 `name` 要不要给 frps 做转发。
pub fn caddy_site(
  world: &World,
  net: &Net,
  name: &str,
  gateway: &GatewaySpec,
) -> Result<bool, ApiError> {
  Ok(
    link_gateway(world, &gateway.server).map(|(n, _)| n)
      == Some(name)
      && tunnels(world, net)?
        .iter()
        .any(|t| t.gateway_server == gateway.server),
  )
}

/// frpc 连 frps 用的地址：网关所在机器的公网 IP，没有就用内网地址。
fn frps_addr(
  net: &Net,
  gateway_server: &str,
) -> Result<String, ApiError> {
  net
    .public_ip
    .get(gateway_server)
    .or_else(|| net.private.get(gateway_server).map(|a| &a.ip))
    .cloned()
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务器 {gateway_server} 没有公网 IP，别的机器连不过来，不能做反向隧道的服务端"
      ))
      .suggest(format!("wharf server set {gateway_server} --public-ip <IP> --apply"))
    })
}

/// 一台机器要探测哪些机器：from → {to}。
pub type Pairs = BTreeMap<String, BTreeSet<String>>;

/// 做计划前探测：网关所在机器能不能连到服务所在机器的内网地址。结果写进数据库并返回合并后的结果。
/// agent 离线或版本太旧时跳过，保留原来的结果。
pub async fn probe(
  state: &AppState,
  net: &Net,
  world: &World,
) -> db::Reach {
  let mut pairs = Pairs::new();
  for (gateway, route, targets) in routes_by_gateway(world) {
    let gateway_server = gateway.server.as_str();
    if route.link == LinkMode::Tunnel {
      continue;
    }
    for (service, _) in targets {
      let to = &world.services[&service].spec.server;
      if to != gateway_server && net.private.contains_key(to) {
        pairs
          .entry(gateway_server.to_string())
          .or_default()
          .insert(to.clone());
      }
    }
  }
  probe_pairs(state, net, pairs).await
}

/// 两台机器之间要直接传数据（迁移、备份）时先探测，连不上就报错（design 2.10）。
pub async fn require_reach(
  state: &AppState,
  net: &Net,
  from: &str,
  to: &str,
  what: &str,
) -> Result<(), ApiError> {
  let pairs = Pairs::from([(
    from.to_string(),
    BTreeSet::from([to.to_string()]),
  )]);
  let reach = probe_pairs(state, net, pairs).await;
  if reach.get(&(from.to_string(), to.to_string())) == Some(&false) {
    return Err(
      ApiError::invalid(format!(
        "{from} 连不上 {to} 的内网地址，不能{what}"
      ))
      .with_hint(
        "两台机器要在同一个组网（Tailscale）或同一个内网里；wharf network 查看谁能连谁",
      ),
    );
  }
  Ok(())
}

/// 探测 `pairs` 里每个方向，`to` 没有内网地址的跳过。结果写进数据库并返回合并后的结果。
pub async fn probe_pairs(
  state: &AppState,
  net: &Net,
  pairs: Pairs,
) -> db::Reach {
  let calls = pairs.into_iter().map(|(from, to)| async move {
    let to: Vec<String> = to
      .into_iter()
      .filter(|t| net.private.contains_key(t))
      .collect();
    if to.is_empty() {
      return vec![];
    }
    let targets = to
      .iter()
      .map(|t| {
        let ip = &net.private[t].ip;
        let host = if ip.contains(':') {
          format!("[{ip}]")
        } else {
          ip.clone()
        };
        ProbeTarget {
          server: t.clone(),
          addr: format!("{host}:{PROBE_PORT}"),
          plain: false,
        }
      })
      .collect();
    let result: Result<Vec<bool>, ApiError> = state
      .hub
      .call(
        &from,
        AgentOp::Probe { targets },
        PROBE_TIMEOUT,
        None,
        &CancellationToken::new(),
      )
      .await;
    match result {
      Ok(oks) if oks.len() == to.len() => to
        .into_iter()
        .zip(oks)
        .map(|(t, ok)| (from.clone(), t, ok))
        .collect(),
      _ => vec![],
    }
  });
  let results: Vec<(String, String, bool)> =
    futures_util::future::join_all(calls)
      .await
      .into_iter()
      .flatten()
      .collect();
  let mut reach = net.reach.clone();
  for (from, to, ok) in &results {
    reach.insert((from.clone(), to.clone()), *ok);
  }
  if !results.is_empty() {
    let now = chrono::Utc::now().timestamp_millis();
    let _ = state
      .db
      .call(move |c| db::set_reach(c, &results, now))
      .await;
  }
  reach
}

#[cfg(test)]
mod tests {
  use serde_json::json;
  use wharf_api_types::spec::{Change, PrivateAddr, PrivateNetwork};

  use super::*;

  /// edge1 上一个 caddy 网关，home1 上一个服务，一条路由。
  fn world() -> World {
    let mut w = World::default();
    for name in ["home1", "edge1"] {
      w.servers.insert(
        name.into(),
        crate::world::ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
    }
    let from =
      |v: serde_json::Value| serde_json::from_value(v).unwrap();
    w.apply_changes(&[
      from(json!({"op": "upsert_gateway", "name": "edge", "spec": {"kind": "caddy", "server": "edge1", "default": true}})),
      from(json!({"op": "upsert_service", "name": "app", "spec": {"server": "home1", "source": {"image": "traefik/whoami"}, "ports": [{"name": "http", "port": 80}]}})),
      from(json!({"op": "upsert_route", "spec": {"hostname": "app.example.com", "service": "app"}})),
    ] as &[Change])
    .unwrap();
    w.allocate_ports().unwrap();
    w
  }

  fn net(reach: Option<bool>) -> Net {
    let mut net = Net::default();
    net.public_ip.insert("edge1".into(), "203.0.113.5".into());
    net.private.insert(
      "home1".into(),
      PrivateAddr {
        ip: "100.64.0.2".into(),
        network: PrivateNetwork::Tailscale,
      },
    );
    if let Some(ok) = reach {
      net.reach.insert(("edge1".into(), "home1".into()), ok);
    }
    net
  }

  #[test]
  fn picks_direct_or_tunnel_by_reach() {
    let w = world();
    let route = &w.routes["app.example.com"].spec;
    let up = |n: &Net| {
      w.route_upstream(
        n,
        &w.gateways["edge"].spec,
        "app.example.com",
        route,
      )
    };
    // 没探测过按原来的做法直连；探测到连不上就走隧道。
    assert_eq!(up(&net(None)).unwrap(), "100.64.0.2:20000");
    assert_eq!(up(&net(Some(true))).unwrap(), "100.64.0.2:20000");
    assert!(projects(&w, &net(Some(true))).unwrap().is_empty());
    let tunneled = up(&net(Some(false))).unwrap();
    let port: u16 = tunneled
      .strip_prefix("127.0.0.1:")
      .unwrap()
      .parse()
      .unwrap();
    assert!(TUNNEL_PORTS.contains(&port));
  }

  #[test]
  fn renders_frps_on_gateway_and_frpc_on_service_server() {
    let w = world();
    let ps = projects(&w, &net(Some(false))).unwrap();
    let names: Vec<(&str, &str)> = ps
      .iter()
      .map(|p| (p.server.as_str(), p.project.as_str()))
      .collect();
    assert_eq!(
      names,
      [("edge1", "wharf-link"), ("home1", "wharf-link-edge1")]
    );
    let frpc = &ps[1].compose;
    assert!(frpc.contains(r#"serverAddr = "203.0.113.5""#), "{frpc}");
    assert!(frpc.contains("localPort = 20000"));
    assert!(frpc.contains("[[WHARF_LINK_TOKEN]]"));
    assert!(frpc.contains("network_mode: host"));
    assert!(frpc.contains("serverPort = 443"));
    assert!(frpc.contains(r#"transport.protocol = "wss""#));
    assert!(ps[0].compose.contains(r#"bindAddr = "127.0.0.1""#));
    let gw = &w.gateways["edge"].spec;
    assert!(caddy_site(&w, &net(Some(false)), "edge", gw).unwrap());
    assert!(!caddy_site(&w, &net(Some(true)), "edge", gw).unwrap());
  }

  #[test]
  fn tunnel_gateway_never_uses_frp() {
    let mut w = world();
    w.gateways.get_mut("edge").unwrap().spec.kind =
      GatewayKind::CloudflareTunnel;
    assert!(tunnels(&w, &net(Some(false))).is_err());
    assert!(tunnels(&w, &net(Some(true))).unwrap().is_empty());
  }
}
