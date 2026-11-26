use super::*;
use crate::{db::ResourceRow, render::Net};
use serde_json::json;
use wharf_api_types::{
  agent::{DockerSubnet, HostTraffic, ProjectMetrics},
  spec::{PrivateAddr, PrivateNetwork},
};

fn private(ip: &str) -> PrivateAddr {
  PrivateAddr {
    ip: ip.into(),
    network: PrivateNetwork::Tailscale,
  }
}

#[test]
fn sanitize_report_blocks_injection_and_non_private_ips() {
  for raw in [
    "100.64.0.9\ninvalid",
    "127.0.0.1",
    "100.100.100.200",
    "203.0.113.5",
  ] {
    let mut r = AgentReport {
      private_addr: Some(private(raw)),
      ..Default::default()
    };
    sanitize_report(&mut r);
    assert!(r.private_addr.is_none());
  }
  for raw in [
    "203.0.113.1\ninvalid",
    "127.0.0.1",
    &Ipv4Addr::new(192, 168, 1, 1).to_string(),
  ] {
    let mut r = AgentReport {
      public_ip: Some(raw.into()),
      ..Default::default()
    };
    sanitize_report(&mut r);
    assert!(r.public_ip.is_none());
  }
  let lan = Ipv4Addr::new(192, 168, 1, 5).to_string();
  let mut r = AgentReport {
    private_addr: Some(private("100.64.0.2")),
    public_ip: Some("203.0.113.10".into()),
    lan_ips: vec![lan.clone(), "203.0.113.1".into(), lan.clone()],
    docker_subnets: vec![DockerSubnet {
      name: "s1".into(),
      subnet: "0.0.0.0/0".into(),
    }],
    ..Default::default()
  };
  sanitize_report(&mut r);
  assert_eq!(r.lan_ips, [lan]);
  assert_eq!(r.private_addr.unwrap().ip, "100.64.0.2");
  assert_eq!(r.public_ip.as_deref(), Some("203.0.113.10"));
  assert!(r.docker_subnets.is_empty());
}

#[test]
fn report_ip_conflict_blocks_cross_server_hijack() {
  let mut servers = ["s1", "s2"]
    .into_iter()
    .map(|name| {
      (
        name.to_string(),
        ServerRow {
          version: 1,
          settings: Default::default(),
        },
      )
    })
    .collect::<BTreeMap<_, _>>();
  let original = AgentReport {
    private_addr: Some(private("100.64.0.2")),
    public_ip: Some("203.0.113.2".into()),
    ..Default::default()
  };
  let agents = ["s1", "s2"].map(|server| AgentRow {
    server: server.into(),
    public_key: None,
    report: Some(original.clone()),
    last_seen: None,
  });
  let mut report = original.clone();
  strip_conflicting_ips("s1", &mut report, &servers, &agents);
  assert!(
    report.private_addr.is_none() && report.public_ip.is_none()
  );
  let net = Net::derive(&servers, &agents);
  assert!(net.private.is_empty() && net.public_ip.is_empty());

  let s2 = &mut servers.get_mut("s2").unwrap().settings;
  s2.private_addr = original.private_addr;
  s2.public_ip = original.public_ip;
  let net = Net::derive(&servers, &agents);
  assert!(
    !net.private.contains_key("s1")
      && !net.public_ip.contains_key("s1")
  );
  assert_eq!(net.private["s2"].ip, "100.64.0.2");
  assert_eq!(net.public_ip["s2"], "203.0.113.2");
}

#[test]
fn metrics_and_alerts_drop_foreign_projects_and_hosts() {
  let row = |kind: &str, name: &str, spec| ResourceRow {
    kind: kind.into(),
    name: name.into(),
    spec,
    meta: json!({}),
    version: 1,
  };
  let world = World::from_rows(vec![
    row("service", "web", json!({"server":"s1", "source":{"image":"nginx:1"}})),
    row("service", "db", json!({"server":"s2", "source":{"image":"postgres:16"}})),
    row("gateway", "gw1", json!({"server":"s1", "kind":"caddy"})),
    row("gateway", "gw2", json!({"server":"s2", "kind":"caddy"})),
    row("route", "a.example.test", json!({"hostname":"a.example.test", "service":"web", "gateway":"gw1"})),
    row("route", "b.example.test", json!({"hostname":"b.example.test", "service":"db", "gateway":"gw2"})),
  ]).unwrap();
  let mut m = Metrics::default();
  for p in ["web", "db", "wharf-gw-gw1"] {
    m.projects.insert(p.into(), ProjectMetrics::default());
  }
  for i in 0..300 {
    m.projects
      .insert(format!("fake-{i}"), ProjectMetrics::default());
  }
  for h in ["a.example.test", "b.example.test"] {
    m.hosts.insert(h.into(), HostTraffic::default());
  }
  m.oom = Some(vec!["web".into(), "db".into()]);
  filter_owned_metrics("s1", &mut m, &world, &BTreeMap::new());
  assert_eq!(
    m.projects.into_keys().collect::<Vec<_>>(),
    ["web", "wharf-gw-gw1"]
  );
  assert_eq!(m.oom.unwrap(), ["web"]);
  assert_eq!(
    m.hosts.into_keys().collect::<Vec<_>>(),
    ["a.example.test"]
  );
  assert_eq!(
    route_owned_by_server(&world, "s1", "b.example.test"),
    None
  );
  assert_eq!(
    route_owned_by_server(&world, "s1", "a.example.test").as_deref(),
    Some("web")
  );
}

#[test]
fn report_rate_gate_throttles_flood_but_allows_upgrade_first_report()
{
  use RateDecision::*;
  let gate = RateGate::default();
  let start = Instant::now();
  let check = |at, id, metrics| {
    gate.check("s1", id, metrics, start + Duration::from_secs(at))
  };
  assert_eq!(check(0, 1, true), AcceptAll);
  assert_eq!(check(3, 1, true), DropAll);
  assert_eq!(check(12, 1, true), AcceptNoMetrics);
  assert_eq!(check(30, 1, true), AcceptAll);
  assert_eq!(check(31, 2, false), DropAll);
  assert_eq!(check(33, 2, false), AcceptAll);
  assert_eq!(check(35, 3, true), AcceptNoMetrics);
}
