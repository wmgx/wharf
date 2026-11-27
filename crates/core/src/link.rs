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
  spec::{GatewayKind, GatewaySpec, GatewayTls, LinkMode, RouteSpec},
};

use crate::{
  db,
  render::{self, Net},
  state::AppState,
  world::World,
};

/// 网关所在机器上的 frps。
pub const SERVER_PROJECT: &str = "wharf-link";
pub const SECRET_PREFIX: &str = "WHARF_LINK_";
pub const TOKEN_PREFIX: &str = "WHARF_LINK_TOKEN_";
pub const CERT_PREFIX: &str = "WHARF_LINK_CERT_";
pub const KEY_PREFIX: &str = "WHARF_LINK_KEY_";
pub const CA_CERT_SECRET: &str = "WHARF_LINK_CA_CERT";
pub const CA_KEY_SECRET: &str = "WHARF_LINK_CA_KEY";
pub const GATEWAY_SECRET_PREFIXES: &[&str] =
  &[TOKEN_PREFIX, CERT_PREFIX, KEY_PREFIX];
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
  port: &str,
  mode: LinkMode,
) -> Result<Choice, ApiError> {
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::invalid(format!("服务 {service} 不存在"))
  })?;
  let server = &row.spec.server;
  let gateway_server = &gateway.server;
  let bind = service_port_bind(row, port);
  if bind == PortBind::LoopbackV6Only {
    return Err(ApiError::invalid(format!(
      "服务 {service} 的端口 {port} 只绑定了 IPv6 回环地址 [::1]，网关无法转发"
    )).with_hint("把 Compose 端口改为绑定 127.0.0.1 或内网地址"));
  }
  if server == gateway_server {
    return Ok(Choice::Local);
  }
  let reach = net
    .reach
    .get(&(gateway_server.clone(), server.clone()))
    .copied();
  let choice = match net.private.get(server) {
    Some(addr)
      if mode != LinkMode::Tunnel
        && reach != Some(false)
        && bind != PortBind::LoopbackV4Only =>
    {
      Choice::Direct(addr.ip.clone())
    }
    _ => Choice::Tunnel,
  };
  if choice == Choice::Tunnel
    && gateway.kind == GatewayKind::CloudflareTunnel
  {
    if bind == PortBind::LoopbackV4Only {
      return Err(ApiError::invalid(format!(
        "服务 {service} 的端口 {port} 只绑定了本机回环地址 127.0.0.1，跨机 cloudflare_tunnel 网关连不到它"
      )));
    }
    return Err(ApiError::invalid(format!(
      "服务 {service} 在 {server} 上，cloudflare_tunnel 网关所在的 {gateway_server} 连不到它"
    ))
    .with_hint(format!(
      "在 {server} 上建一个 cloudflare_tunnel 网关，路由改用它，不需要开端口"
    )));
  }
  if choice == Choice::Tunnel
    && link_gateway(world, gateway_server).is_none()
  {
    return Err(ApiError::invalid(format!(
      "服务 {service} 在 {server} 上，服务器 {gateway_server} 没有开启 TLS 的 Caddy 网关，无法建立加密反向隧道（tls=off）"
    )).with_hint("把该机 Caddy 网关的 TLS 改为 auto 或 internal，或让两台机器加入同一个组网直连"));
  }
  Ok(choice)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortBind {
  DirectableOrUnknown,
  LoopbackV4Only,
  LoopbackV6Only,
}

pub(crate) fn service_port_bind(
  row: &crate::world::ServiceRow,
  port: &str,
) -> PortBind {
  if let wharf_api_types::spec::Source::Compose {
    content: Some(content),
    ..
  } = &row.spec.source
    && let Some(host) = row.host_ports.get(port)
  {
    let udp = row.spec.ports.iter().any(|p| p.name == port && p.udp);
    return compose_port_bind(content, *host, udp);
  }
  PortBind::DirectableOrUnknown
}

fn compose_port_bind(
  content: &str,
  host_port: u16,
  udp: bool,
) -> PortBind {
  use serde_yaml_ng::Value;
  let Ok(mut compose) = serde_yaml_ng::from_str::<Value>(content)
  else {
    return PortBind::DirectableOrUnknown;
  };
  if compose.apply_merge().is_err() {
    return PortBind::DirectableOrUnknown;
  }
  let protocol = if udp { "udp" } else { "tcp" };
  let entries = compose["services"]
    .as_mapping()
    .into_iter()
    .flat_map(|s| s.values())
    .flat_map(|s| s["ports"].as_sequence().into_iter().flatten());
  let mut binding = None;
  for entry in entries {
    let (ip, start, end, proto) = if let Some(short) = entry.as_str()
    {
      let (address, proto) =
        short.split_once('/').unwrap_or((short, "tcp"));
      let Some((host, _)) = address.rsplit_once(':') else {
        continue;
      };
      let (ip, published) =
        host.rsplit_once(':').unwrap_or(("", host));
      let Some((start, end)) = published_range(published) else {
        continue;
      };
      (ip, start, end, proto)
    } else {
      let published = &entry["published"];
      let range =
        published.as_str().and_then(published_range).or_else(|| {
          published
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .map(|n| (n, n))
        });
      let Some((start, end)) = range else { continue };
      (
        entry["host_ip"].as_str().unwrap_or(""),
        start,
        end,
        entry["protocol"].as_str().unwrap_or("tcp"),
      )
    };
    if proto != protocol || !(start..=end).contains(&host_port) {
      continue;
    }
    let ip = ip.trim_matches(['[', ']']);
    let current = match ip.parse::<std::net::IpAddr>() {
      Ok(std::net::IpAddr::V4(v)) if v.is_loopback() => {
        PortBind::LoopbackV4Only
      }
      Ok(std::net::IpAddr::V6(v)) if v.is_loopback() => {
        PortBind::LoopbackV6Only
      }
      _ if ip == "localhost" => PortBind::LoopbackV4Only,
      _ => return PortBind::DirectableOrUnknown,
    };
    if binding.is_some_and(|old| old != current) {
      return PortBind::DirectableOrUnknown;
    }
    binding = Some(current);
  }
  binding.unwrap_or(PortBind::DirectableOrUnknown)
}

fn published_range(value: &str) -> Option<(u16, u16)> {
  let (start, end) = value.split_once('-').unwrap_or((value, value));
  Some((start.parse().ok()?, end.parse().ok()?))
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
  world.routes.values().flat_map(move |r| {
    world
      .route_gateways(&r.spec)
      .into_iter()
      .filter_map(|gw| world.gateways.get(gw))
      .map(|g| (&g.spec, &r.spec, route_targets(world, &r.spec)))
      .collect::<Vec<_>>()
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
      if choose(world, net, gateway, &service, &port, route.link)?
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

/// 一台机器上要部署的隧道项目。compose 可能包含明文，只用于计算指纹和下发。
pub struct LinkProject {
  pub gateway: String,
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
  projects_with_secrets(world, net, &BTreeMap::new())
}

pub fn projects_with_secrets(
  world: &World,
  net: &Net,
  secrets: &BTreeMap<String, String>,
) -> Result<Vec<LinkProject>, ApiError> {
  let token = |gateway: &str| {
    secrets
      .get(&format!("{TOKEN_PREFIX}{gateway}"))
      .or_else(|| net.link_token_hashes.get(gateway))
      .map(String::as_str)
      .unwrap_or("pending")
  };
  let ca = secrets
    .get(CA_CERT_SECRET)
    .or(net.link_ca_cert.as_ref())
    .map(String::as_str)
    .unwrap_or("pending");
  let carrier = |server: &str| {
    link_gateway(world, server).ok_or_else(|| {
      ApiError::internal(format!(
        "服务器 {server} 没有承载反向隧道的网关"
      ))
    })
  };
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
    let (gateway, _) = carrier(server)?;
    let compose =
      render::frps_compose(SERVER_PROJECT, token(gateway));
    out.push(LinkProject {
      gateway: gateway.to_string(),
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
    let (gateway, spec) = carrier(&gateway_server)?;
    let port = spec.https_port.unwrap_or(443);
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
    let compose = render::frpc_compose(
      &project,
      &addr,
      port,
      &proxies,
      token(gateway),
      ca,
    );
    let names: Vec<String> = list
      .iter()
      .map(|t| format!("{}:{}", t.service, t.port))
      .collect();
    out.push(LinkProject {
      gateway: gateway.to_string(),
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
pub fn link_gateway<'a>(
  world: &'a World,
  server: &str,
) -> Option<(&'a str, &'a GatewaySpec)> {
  world
    .gateways
    .iter()
    .find(|(_, g)| {
      g.spec.server == server
        && g.spec.kind == GatewayKind::Caddy
        && g.spec.tls != GatewayTls::Off
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
pub fn validate_private_addr(
  name: &str,
  addr: Option<&wharf_api_types::spec::PrivateAddr>,
) -> Result<(), ApiError> {
  let Some(addr) = addr else {
    return Ok(());
  };
  use std::net::IpAddr;
  let ip = &addr.ip;
  let private = match ip.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => {
      ip.is_private()
        || (ip.octets()[0] == 100
          && (64..128).contains(&ip.octets()[1]))
    }
    Ok(IpAddr::V6(ip)) => ip.is_unique_local(),
    Err(_) => false,
  };
  if !private {
    return Err(ApiError::invalid(format!("服务器 {name} 的内网地址 {ip} 不合法，必须是私网或组网 IP"))
      .with_hint("填写 10/8、172.16/12、192.168/16、100.64/10 或私有 IPv6 地址，不能填 127.0.0.1 或公网地址"));
  }
  Ok(())
}

#[derive(Clone, Copy)]
pub enum ProbeMode {
  Plan,
  Persist,
}

impl ProbeMode {
  async fn record(self, write: impl AsyncFnOnce()) {
    if matches!(self, Self::Persist) {
      write().await;
    }
  }
}

pub async fn probe(
  state: &AppState,
  net: &Net,
  world: &World,
) -> db::Reach {
  let mut pairs = Pairs::new();
  for (gateway, route, targets) in routes_by_gateway(world) {
    let gateway_server = gateway.server.as_str();
    if gateway.kind == GatewayKind::Caddy
      && route.sso.is_some()
      && let Some(core) = &net.core_server
      && core != gateway_server
      && net
        .private
        .get(core)
        .is_some_and(|addr| addr.network.encrypted())
      && net.core_listener.is_some_and(|(_, only)| !only)
    {
      pairs
        .entry(gateway_server.into())
        .or_default()
        .insert(core.clone());
    }
    if route.link == LinkMode::Tunnel {
      continue;
    }
    for (service, port) in targets {
      let row = &world.services[&service];
      let to = &row.spec.server;
      if to != gateway_server
        && net.private.contains_key(to)
        && service_port_bind(row, &port)
          == PortBind::DirectableOrUnknown
      {
        pairs
          .entry(gateway_server.to_string())
          .or_default()
          .insert(to.clone());
      }
    }
  }
  for gateway in world
    .gateways
    .values()
    .filter(|g| g.spec.kind == GatewayKind::Caddy)
  {
    for service in gateway
      .spec
      .layer4
      .iter()
      .filter_map(|f| world.services.get(f.service.as_deref()?))
    {
      let to = &service.spec.server;
      if to != &gateway.spec.server && net.private.contains_key(to) {
        pairs
          .entry(gateway.spec.server.clone())
          .or_default()
          .insert(to.clone());
      }
    }
  }
  probe_pairs(state, net, pairs, ProbeMode::Plan).await
}

/// 两台机器之间要直接传数据（迁移、备份）时先探测，连不上就报错（design 2.10）。
pub async fn require_reach(
  state: &AppState,
  net: &Net,
  from: &str,
  to: &str,
  what: &str,
  mode: ProbeMode,
) -> Result<(), ApiError> {
  if !net.private.contains_key(to) {
    return Err(
      ApiError::invalid(format!(
        "目标服务器 {to} 没有内网地址，不能{what}"
      ))
      .suggest(format!("wharf server set {to} --private-ip <ip>")),
    );
  }
  if !state.hub.is_online(from) {
    return Err(ApiError::new(
      wharf_api_types::ErrorCode::AgentOffline,
      format!(
        "服务器 {from} 不在线，无法验证到 {to} 的内网连通性，不能{what}"
      ),
    ));
  }
  let pairs = Pairs::from([(
    from.to_string(),
    BTreeSet::from([to.to_string()]),
  )]);
  let mut fresh = net.clone();
  let pair = (from.to_string(), to.to_string());
  fresh.reach.remove(&pair);
  let reach = probe_pairs(state, &fresh, pairs, mode).await;
  if !reach.contains_key(&pair) {
    return Err(
      ApiError::invalid(format!(
        "探测 {from} 到 {to} 的内网连通性失败，不能{what}"
      ))
      .with_hint(
        "检查两台机器的组网和 agent 状态；wharf network 查看连通性",
      ),
    );
  }
  if reach.get(&pair) == Some(&false) {
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

/// 探测 `pairs` 里每个方向，跳过没有内网地址的目标，返回合并后的结果。
pub async fn probe_pairs(
  state: &AppState,
  net: &Net,
  pairs: Pairs,
  mode: ProbeMode,
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
  mode
    .record(async || {
      if !results.is_empty() {
        let now = chrono::Utc::now().timestamp_millis();
        let _ = state
          .db
          .call(move |c| db::set_reach(c, &results, now))
          .await;
      }
    })
    .await;
  reach
}

#[cfg(test)]
mod tests {
  use serde_json::json;
  use wharf_api_types::spec::{Change, PrivateAddr, PrivateNetwork};

  #[tokio::test]
  async fn plan_probe_does_not_persist_reach() {
    let writes = std::cell::Cell::new(0);
    super::ProbeMode::Plan
      .record(async || writes.set(writes.get() + 1))
      .await;
    assert_eq!(writes.get(), 0);
    super::ProbeMode::Persist
      .record(async || writes.set(writes.get() + 1))
      .await;
    assert_eq!(writes.get(), 1);
  }

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
      from(json!({"op": "upsert_service", "name": "app", "spec": {"server": "home1", "source": {"image": "traefik/whoami"}, "ports": [{"name": "http", "container": 80}]}})),
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
  fn ipv6_deploy_port_and_direct_upstream_use_brackets() {
    let w = world();
    let mut net = net(None);
    let ip = "fd7a:115c:a1e0::1";
    net.private.get_mut("home1").unwrap().ip = ip.into();
    let (compose, _) = crate::snapshot::service_resolved(
      &w,
      &net,
      "app",
      &Default::default(),
    )
    .unwrap();
    let doc = crate::render::parse_compose(&compose).unwrap();
    assert_eq!(
      doc["services"]["app"]["ports"][1],
      "[fd7a:115c:a1e0::1]:20000:80"
    );
    assert_eq!(
      w.route_upstream(
        &net,
        &w.gateways["edge"].spec,
        "app.example.com",
        &w.routes["app.example.com"].spec
      )
      .unwrap(),
      "[fd7a:115c:a1e0::1]:20000"
    );
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
    assert!(frpc.contains("/etc/frp/ca.pem"));
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
