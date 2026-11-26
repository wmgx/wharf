use std::{
  collections::BTreeSet,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  sync::{LazyLock, OnceLock, RwLock},
};

use axum::http::HeaderMap;
use ipnet::{IpNet, Ipv4Net};
use wharf_api_types::{
  ApiError,
  spec::{GatewayKind, GatewaySpec},
  trusted_proxies::parse_cidr,
};

use crate::{lockout::OriginZone, render::Net, world::World};

mod caddy;
pub use caddy::{render_proxy_headers, render_proxy_options};

pub fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
  let [a, b, ..] = ip.octets();
  a == 100 && (64..128).contains(&b)
}

pub fn is_tailscale_ula_v6(ip: Ipv6Addr) -> bool {
  ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0]
}

pub fn is_private_or_mesh(ip: IpAddr) -> bool {
  match ip {
    IpAddr::V4(ip) => {
      ip.is_loopback() || ip.is_private() || is_cgnat_v4(ip)
    }
    IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
  }
}

pub fn is_global_unicast(ip: IpAddr) -> bool {
  !is_private_or_mesh(ip)
    && !ip.is_unspecified()
    && !ip.is_multicast()
    && match ip {
      IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
      IpAddr::V6(ip) => !ip.is_unicast_link_local(),
    }
}

pub fn private_ipv4s(ips: &[String]) -> Vec<String> {
  ips
    .iter()
    .filter_map(|ip| {
      ip.parse::<Ipv4Addr>().ok().filter(Ipv4Addr::is_private)
    })
    .map(|ip| ip.to_string())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

fn outside_docker(net: &Net, server: &str, ip: Ipv4Addr) -> bool {
  !net
    .docker_subnets
    .get(server)
    .into_iter()
    .flatten()
    .filter_map(|subnet| subnet.parse::<Ipv4Net>().ok())
    .any(|subnet| subnet.contains(&ip))
}

fn server_hosts<'a>(
  net: &'a Net,
  server: &'a str,
) -> impl Iterator<Item = IpNet> + 'a {
  net
    .private
    .get(server)
    .into_iter()
    .chain(net.reported_private.get(server))
    .filter_map(|addr| addr.ip.parse::<IpAddr>().ok())
    .map(|ip| ip.to_canonical())
    .filter(move |ip| {
      is_private_or_mesh(*ip)
        && match ip {
          IpAddr::V4(ip) => outside_docker(net, server, *ip),
          IpAddr::V6(_) => true,
        }
    })
    .map(IpNet::from)
}

fn cluster_mesh_cidrs(net: &Net) -> impl Iterator<Item = IpNet> + '_ {
  net
    .private
    .keys()
    .chain(net.reported_private.keys())
    .flat_map(|server| server_hosts(net, server))
}

fn lan_ips<'a>(
  net: &'a Net,
  server: &'a str,
  include_reported: bool,
) -> impl Iterator<Item = Ipv4Addr> + 'a {
  net
    .lan_addrs
    .get(server)
    .into_iter()
    .flatten()
    .chain(
      net
        .lan_ips
        .get(server)
        .filter(|_| include_reported)
        .into_iter()
        .flatten(),
    )
    .filter_map(|raw| raw.parse::<Ipv4Addr>().ok())
    .filter(move |ip| {
      ip.is_private() && outside_docker(net, server, *ip)
    })
}

const LOCAL_RANGES: [&str; 2] = ["127.0.0.0/8", "::1/128"];
const LOCAL_HOSTS: [&str; 2] = ["127.0.0.1/32", "::1/128"];

fn lan_ranges<'a>(
  net: &'a Net,
  server: &'a str,
  include_reported: bool,
) -> impl Iterator<Item = Ipv4Net> + 'a {
  lan_ips(net, server, include_reported)
    .map(|ip| Ipv4Net::new(ip, 24).expect("IPv4 /24").trunc())
}

fn access_ranges(
  net: &Net,
  server: &str,
  include_reported: bool,
) -> Vec<String> {
  LOCAL_RANGES
    .map(str::to_string)
    .into_iter()
    .chain(cluster_mesh_cidrs(net).map(|cidr| cidr.to_string()))
    .chain(net.tailnet_ips.iter().map(ToString::to_string))
    .chain(
      lan_ranges(net, server, include_reported)
        .map(|cidr| cidr.to_string()),
    )
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

pub fn gate_trusted_ranges(net: &Net, server: &str) -> Vec<String> {
  access_ranges(net, server, true)
}

pub fn internal_route_ranges(net: &Net, server: &str) -> Vec<String> {
  access_ranges(net, server, false)
}

fn parse_networks(
  cidrs: &[impl AsRef<str>],
) -> impl Iterator<Item = IpNet> + '_ {
  cidrs.iter().filter_map(|cidr| cidr.as_ref().parse().ok())
}

pub fn gateway_trusted_proxies(
  world: &World,
  net: &Net,
  spec: &GatewaySpec,
  cf_cidrs: &[String],
) -> Vec<String> {
  let Some(tp) = &spec.trusted_proxies else {
    return vec![];
  };
  let mut cidrs = BTreeSet::new();
  if tp.cloudflare {
    cidrs.extend(cf_cidrs.iter().cloned());
  }
  if tp.cluster {
    cidrs.extend(LOCAL_HOSTS.map(str::to_string));
    cidrs
      .extend(cluster_mesh_cidrs(net).map(|cidr| cidr.to_string()));
    for gateway in world.gateways.values() {
      cidrs.extend(
        lan_ips(net, &gateway.spec.server, false)
          .map(|ip| IpNet::from(IpAddr::V4(ip)).to_string()),
      );
    }
  }
  cidrs.extend(
    tp.cidrs
      .iter()
      .filter_map(|cidr| parse_cidr(cidr).ok())
      .map(|cidr| cidr.to_string()),
  );
  cidrs.into_iter().collect()
}

#[derive(Debug, Default)]
pub struct CoreProxyCache {
  pub direct_proxies: Vec<IpNet>,
  pub chain_proxies: Vec<IpNet>,
  pub internal_nets: Vec<IpNet>,
}

static EXTRA_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();
static CORE_PROXIES: LazyLock<RwLock<CoreProxyCache>> =
  LazyLock::new(Default::default);

pub fn init_extra_proxies(raw: &[String]) -> Result<(), ApiError> {
  let nets = raw
    .iter()
    .map(|cidr| parse_cidr(cidr))
    .collect::<Result<_, _>>()?;
  EXTRA_PROXIES
    .set(nets)
    .map_err(|_| ApiError::internal("控制面可信代理重复初始化"))
}

fn compute_core_proxies(
  world: &World,
  net: &Net,
  extra: &[IpNet],
  core_server: Option<&str>,
) -> CoreProxyCache {
  let mut direct = extra.iter().copied().collect::<BTreeSet<_>>();
  if !world.gateways.is_empty() {
    direct.extend(parse_networks(&LOCAL_HOSTS));
  }
  let mut internal = parse_networks(&LOCAL_RANGES)
    .chain(cluster_mesh_cidrs(net))
    .chain(net.tailnet_ips.iter().copied())
    .collect::<BTreeSet<_>>();
  for gateway in world.gateways.values() {
    let server = &gateway.spec.server;
    direct.extend(server_hosts(net, server));
    direct.extend(
      lan_ips(net, server, false)
        .map(|ip| IpNet::from(IpAddr::V4(ip))),
    );
    internal.extend(lan_ranges(net, server, true).map(IpNet::V4));
  }
  if let Some(server) = core_server {
    internal.extend(lan_ranges(net, server, true).map(IpNet::V4));
  }

  let mut chain = direct.clone();
  for gateway in world.gateways.values() {
    chain.extend(parse_networks(&gateway_trusted_proxies(
      world,
      net,
      &gateway.spec,
      &net.cloudflare_ips,
    )));
  }
  if world
    .gateways
    .values()
    .any(|gw| gw.spec.kind == GatewayKind::CloudflareTunnel)
  {
    chain.extend(parse_networks(&net.cloudflare_ips));
  }
  CoreProxyCache {
    direct_proxies: direct.into_iter().collect(),
    chain_proxies: chain.into_iter().collect(),
    internal_nets: internal.into_iter().collect(),
  }
}

pub fn refresh_core_proxies(world: &World, net: &Net) {
  let core = crate::join::core_server(net, &crate::join::own_ipv4s());
  let cache = compute_core_proxies(
    world,
    net,
    EXTRA_PROXIES.get().map(Vec::as_slice).unwrap_or_default(),
    core.as_deref(),
  );
  *CORE_PROXIES.write().unwrap_or_else(|e| e.into_inner()) = cache;
}

fn ip_in_nets(ip: IpAddr, nets: &[IpNet]) -> bool {
  nets.iter().any(|net| net.contains(&ip))
}

pub fn resolve_client_ip(
  peer: IpAddr,
  headers: &HeaderMap,
  direct: &[IpNet],
  chain: &[IpNet],
) -> IpAddr {
  let peer = peer.to_canonical();
  if !ip_in_nets(peer, direct) {
    return peer;
  }
  let mut last = peer;
  for header in headers.get_all("x-forwarded-for").iter().rev() {
    let Ok(value) = header.to_str() else {
      return last;
    };
    for item in value
      .rsplit(',')
      .map(str::trim)
      .filter(|item| !item.is_empty())
    {
      let Ok(ip) = item.parse::<IpAddr>() else {
        return last;
      };
      let ip = ip.to_canonical();
      if !ip_in_nets(ip, chain) {
        return ip;
      }
      last = ip;
    }
  }
  last
}

pub fn client_key(peer: IpAddr, headers: &HeaderMap) -> String {
  let cache = CORE_PROXIES.read().unwrap_or_else(|e| e.into_inner());
  resolve_client_ip(
    peer,
    headers,
    &cache.direct_proxies,
    &cache.chain_proxies,
  )
  .to_string()
}

pub fn classify_zone(key: &str) -> OriginZone {
  let Ok(ip) = key.parse::<IpAddr>() else {
    return OriginZone::Public;
  };
  let ip = ip.to_canonical();
  let cache = CORE_PROXIES.read().unwrap_or_else(|e| e.into_inner());
  if ip.is_loopback() || ip_in_nets(ip, &cache.internal_nets) {
    OriginZone::Internal
  } else {
    OriginZone::Public
  }
}

#[cfg(test)]
#[path = "source_trust_tests.rs"]
mod tests;
