use std::collections::BTreeMap;

use super::*;
use crate::{
  render::Net,
  world::{ServerRow, ServiceRow, World},
};

fn world(host_port: u16) -> World {
  let spec = serde_json::from_value(serde_json::json!({
    "server": "s1",
    "source": {"image": "nginx:1"},
    "ports": [{"name": "http", "container": 80}],
  }))
  .unwrap();
  let mut world = World::default();
  world.servers.insert(
    "s1".to_string(),
    ServerRow {
      settings: Default::default(),
      version: 1,
    },
  );
  world.services.insert(
    "app".to_string(),
    ServiceRow {
      spec,
      host_ports: BTreeMap::from([("http".to_string(), host_port)]),
      import: None,
      pins: BTreeMap::new(),
      commit: None,
      version: 1,
    },
  );
  world
}

fn fingerprint(compose: &str, config: &str) -> String {
  GatewayRender {
    compose: compose.to_string(),
    compose_hash: render::hash(compose),
    config: config.to_string(),
    config_hash: render::hash(config),
    sites: Vec::new(),
    needs_acme_dns: false,
  }
  .fingerprint()
}

#[test]
fn service_hash_follows_the_rendered_compose() {
  let net = Net::default();
  let secrets = BTreeMap::new();
  let same = world(21000);
  let moved = world(21001);
  let hash =
    |w: &World| service_resolved(w, &net, "app", &secrets).unwrap().1;
  assert_eq!(hash(&same), hash(&same));
  assert_ne!(hash(&same), hash(&moved));
}

#[test]
fn references_follow_the_target_service() {
  use wharf_api_types::spec::{PrivateAddr, PrivateNetwork};
  let mut net = Net::default();
  for (s, ip) in [("s1", "100.64.0.1"), ("s2", "100.64.0.2")] {
    net.private.insert(
      s.to_string(),
      PrivateAddr {
        ip: ip.to_string(),
        network: PrivateNetwork::Tailscale,
      },
    );
  }
  let with_web = |db_server: &str| {
    let mut w = world(21000);
    w.servers.insert(
      "s2".to_string(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    let mut web = w.services["app"].clone();
    web.spec.env.insert("DB".into(), "http://[[@app]]/".into());
    w.services.insert("web".to_string(), web);
    w.services.get_mut("app").unwrap().spec.server = db_server.into();
    w
  };
  let secrets = BTreeMap::new();
  let (here, _) =
    service_resolved(&with_web("s1"), &net, "web", &secrets).unwrap();
  assert!(here.contains("http://100.64.0.1:21000/"));
  let (moved, _) =
    service_resolved(&with_web("s2"), &net, "web", &secrets).unwrap();
  assert!(moved.contains("http://100.64.0.2:21000/"));

  let mut gone = with_web("s1");
  gone.services.remove("app");
  let err =
    service_resolved(&gone, &net, "web", &secrets).unwrap_err();
  assert!(err.message.contains("不存在"));
}

#[test]
fn gateway_fingerprint_covers_both_payloads() {
  assert_eq!(fingerprint("a", "b"), fingerprint("a", "b"));
  assert_ne!(fingerprint("a", "b"), fingerprint("a2", "b"));
  assert_ne!(fingerprint("a", "b"), fingerprint("a", "b2"));
}
#[test]
fn gate_core_uses_local_upstream() {
  let mut world = World::default();
  for (name, server) in [("edge", "s1"), ("other", "s2")] {
    world.gateways.insert(
      name.into(),
      crate::world::GatewayRow {
        version: 1,
        spec: serde_json::from_value(
          serde_json::json!({"kind":"caddy","server":server}),
        )
        .unwrap(),
      },
    );
  }
  for (host, gateway, sso) in [
    ("core.example.test", "edge", false),
    ("a.example.test", "edge", true),
    ("b.example.test", "other", true),
  ] {
    let spec=serde_json::from_value(serde_json::json!({"hostname":host,"gateway":gateway,"upstream":"127.0.0.1:7700","sso":if sso {Some(serde_json::json!({"mode":"gate"}))} else {None}})).unwrap();
    world.routes.insert(
      host.into(),
      crate::world::RouteRow {
        id: host.into(),
        version: 1,
        spec,
      },
    );
  }
  let net = Net {
    gate_login: Some("https://core.example.test".into()),
    gate_public: Some("public".into()),
    ..Default::default()
  };
  assert!(
    gateway_render(&world, &net, "edge")
      .unwrap()
      .config
      .contains("core http://127.0.0.1:7700")
  );
  assert!(
    gateway_render(&world, &net, "other")
      .unwrap()
      .config
      .contains("core https://core.example.test")
  );
}
