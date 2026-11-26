use super::*;
use crate::{
  auth::{TokenPeer, check_token},
  db::TokenRow,
  world::GatewayRow,
};
use axum::http::Method;

fn fixture() -> (World, Net) {
  let mut world = World::default();
  world.gateways.insert("edge".into(), GatewayRow {
    version: 1,
    spec: serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1", "trusted_proxies": {"cloudflare": true}
    })).unwrap(),
  });
  let mut net = Net {
    cloudflare_ips: vec!["173.245.48.0/20".into()],
    ..Default::default()
  };
  for (server, ip) in [("s1", "100.64.0.7"), ("s2", "100.64.0.9")] {
    net.reported_private.insert(
      server.into(),
      wharf_api_types::spec::PrivateAddr {
        ip: ip.into(),
        network: wharf_api_types::spec::PrivateNetwork::Tailscale,
      },
    );
  }
  net.lan_addrs.insert(
    "s1".into(),
    vec!["10.20.0.5".into(), "172.20.0.1".into()],
  );
  net.lan_ips.insert(
    "s1".into(),
    vec!["10.20.1.5".into(), "203.0.113.7".into()],
  );
  net
    .docker_subnets
    .insert("s1".into(), vec!["172.20.0.0/16".into()]);
  (world, net)
}

#[test]
fn internal_and_gate_ranges_use_real_addresses() {
  let (_, net) = fixture();
  assert_eq!(
    internal_route_ranges(&net, "s1"),
    [
      "10.20.0.0/24",
      "100.64.0.7/32",
      "100.64.0.9/32",
      "127.0.0.0/8",
      "::1/128"
    ]
  );
  assert!(
    gate_trusted_ranges(&net, "s1").contains(&"10.20.1.0/24".into())
  );
}

#[test]
fn tailnet_devices_are_internal_without_becoming_proxies() {
  let (world, mut net) = fixture();
  net.tailnet_ips = ["100.64.0.20/32", "fd7a:115c:a1e0::20/128"]
    .map(|cidr| cidr.parse().unwrap())
    .to_vec();
  let cache = compute_core_proxies(&world, &net, &[], None);
  let route = internal_route_ranges(&net, "s1");
  let gate = gate_trusted_ranges(&net, "s1");
  for cidr in &net.tailnet_ips {
    assert!(route.contains(&cidr.to_string()));
    assert!(gate.contains(&cidr.to_string()));
    assert!(cache.internal_nets.contains(cidr));
    assert!(!cache.direct_proxies.contains(cidr));
    assert!(!cache.chain_proxies.contains(cidr));
  }
}

#[test]
fn only_gateway_peers_supply_forwarded_client_ip() {
  let (world, net) = fixture();
  let cache = compute_core_proxies(&world, &net, &[], None);
  let resolve = |peer: &str, headers: &HeaderMap| {
    resolve_client_ip(
      peer.parse().unwrap(),
      headers,
      &cache.direct_proxies,
      &cache.chain_proxies,
    )
  };
  let mut headers = HeaderMap::new();
  headers.insert(
    "x-forwarded-for",
    "203.0.113.7, ::ffff:198.51.100.4".parse().unwrap(),
  );
  headers.append("x-forwarded-for", "173.245.48.2".parse().unwrap());
  for peer in ["127.0.0.1", "100.64.0.7"] {
    assert_eq!(resolve(peer, &headers).to_string(), "198.51.100.4");
  }
  headers.insert("x-forwarded-for", "100.64.0.1".parse().unwrap());
  for peer in
    ["100.64.0.9", "10.20.0.8", "198.51.100.7", "173.245.48.2"]
  {
    assert_eq!(resolve(peer, &headers).to_string(), peer);
  }
  let row = TokenRow {
    name: "test".into(),
    perms: "read".into(),
    expires_at: None,
    allowed_from: Some("100.64.0.1/32".into()),
    services: None,
  };
  let peer = resolve("100.64.0.9", &headers);
  assert!(
    check_token(
      &row,
      chrono::Utc::now(),
      TokenPeer::Address {
        ip: Some(peer),
        label: &peer.to_string()
      },
      &Method::GET,
      "/api/status"
    )
    .is_err()
  );

  headers.append("x-forwarded-for", "malformed".parse().unwrap());
  assert_eq!(
    resolve("100.64.0.7", &headers).to_string(),
    "100.64.0.7"
  );
}
