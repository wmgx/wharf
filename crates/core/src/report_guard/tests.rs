use super::*;
use serde_json::json;
use wharf_api_types::{
  agent::{DockerSubnet, HostTraffic, ProjectMetrics},
  spec::{PrivateAddr, PrivateNetwork},
};

use crate::{render::Net, world::ServerRow};

fn private(ip: &str) -> PrivateAddr {
  PrivateAddr {
    ip: ip.into(),
    network: PrivateNetwork::Tailscale,
  }
}

#[test]
fn sanitize_report_blocks_injection_and_non_private_ips() {
  // 1. YAML/TOML 注入、回环、云元数据、公网 IP 填进 private_addr 均被拒绝。
  for bad in [
    "100.64.0.9\n  privileged: true",
    "127.0.0.1",
    "100.100.100.200",
    "203.0.113.5",
    "::1",
    "fd00:ec2::254",
  ] {
    let mut r = AgentReport {
      private_addr: Some(private(bad)),
      ..Default::default()
    };
    let w = sanitize_report("s1", &mut r);
    assert!(r.private_addr.is_none(), "应拒绝 private_addr={bad}");
    assert!(!w.is_empty());
  }

  // 2. TOML 注入、私网、回环填进 public_ip 均被拒绝。
  for bad in [
    "203.0.113.1\"\n[[proxies]]",
    "10.0.1.1",
    "172.16.0.1",
    "127.0.0.1",
    "100.64.0.2",
  ] {
    let mut r = AgentReport {
      public_ip: Some(bad.into()),
      ..Default::default()
    };
    let w = sanitize_report("s1", &mut r);
    assert!(r.public_ip.is_none(), "应拒绝 public_ip={bad}");
    assert!(!w.is_empty());
  }

  // 3. docker_subnets 含 0.0.0.0/0 与非法项被过滤；合法项保留。
  let mut r = AgentReport {
    private_addr: Some(private("100.64.0.2")),
    public_ip: Some("203.0.113.10".into()),
    lan_ips: vec!["10.0.1.5".into(), "203.0.113.1".into()],
    docker_subnets: vec![
      DockerSubnet {
        name: "evil".into(),
        subnet: "0.0.0.0/0".into(),
      },
      DockerSubnet {
        name: "bridge".into(),
        subnet: "172.17.0.0/16".into(),
      },
    ],
    ..Default::default()
  };
  sanitize_report("s1", &mut r);
  assert_eq!(
    r.private_addr.as_ref().map(|a| a.ip.as_str()),
    Some("100.64.0.2")
  );
  assert_eq!(r.public_ip.as_deref(), Some("203.0.113.10"));
  assert_eq!(r.lan_ips, vec!["10.0.1.5"]);
  assert_eq!(r.docker_subnets.len(), 1);
  assert_eq!(r.docker_subnets[0].subnet, "172.17.0.0/16");
}

#[test]
fn report_ip_conflict_blocks_cross_server_hijack() {
  let mut world = World::default();
  for s in ["s1", "s2"] {
    world.servers.insert(
      s.into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
  }
  let s2_agent = AgentRow {
    server: "s2".into(),
    public_key: None,
    report: Some(AgentReport {
      private_addr: Some(private("100.64.0.2")),
      public_ip: Some("203.0.113.2".into()),
      ..Default::default()
    }),
    last_seen: None,
  };

  // s1 字典序排在 s2 前，尝试抢占 s2 的 IP，strip_conflicting_ips 必须剥离 s1 的冲突 IP。
  let mut s1_report = AgentReport {
    private_addr: Some(private("100.64.0.2")),
    public_ip: Some("203.0.113.2".into()),
    ..Default::default()
  };
  let w = strip_conflicting_ips(
    "s1",
    &mut s1_report,
    &world,
    std::slice::from_ref(&s2_agent),
  );
  assert!(s1_report.private_addr.is_none());
  assert!(s1_report.public_ip.is_none());
  assert_eq!(w.len(), 2);

  // 纵深防御：即使库里已有双机同 IP 脏数据，未配置时 Net::derive 双向忽略。
  let dirty_agents = vec![
    AgentRow {
      server: "s1".into(),
      public_key: None,
      report: Some(AgentReport {
        private_addr: Some(private("100.64.0.2")),
        public_ip: Some("203.0.113.2".into()),
        ..Default::default()
      }),
      last_seen: None,
    },
    s2_agent.clone(),
  ];
  let net_both = Net::derive(&world.servers, &dirty_agents);
  assert!(!net_both.private.contains_key("s1"));
  assert!(!net_both.private.contains_key("s2"));
  assert!(!net_both.public_ip.contains_key("s1"));
  assert!(!net_both.public_ip.contains_key("s2"));

  // 若 s2 手动配置了该 IP，Net::derive 保留 s2，绝不让字典序更前的 s1 抢占。
  let s2_cfg = &mut world.servers.get_mut("s2").unwrap().settings;
  s2_cfg.private_addr = Some(private("100.64.0.2"));
  s2_cfg.public_ip = Some("203.0.113.2".into());
  let net_cfg = Net::derive(&world.servers, &dirty_agents);
  assert!(!net_cfg.private.contains_key("s1"));
  assert_eq!(net_cfg.private["s2"].ip, "100.64.0.2");
  assert!(!net_cfg.public_ip.contains_key("s1"));
  assert_eq!(net_cfg.public_ip["s2"], "203.0.113.2");
}

#[test]
fn metrics_and_alerts_drop_foreign_projects_and_hosts() {
  let mut world = World::default();
  for s in ["s1", "s2"] {
    world.servers.insert(
      s.into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
  }
  world
    .apply_changes(&[
      wharf_api_types::spec::Change::UpsertService {
        name: "web".into(),
        spec: serde_json::from_value(
          json!({"server": "s1", "source": {"image": "nginx:1"}}),
        )
        .unwrap(),
        adopt: None,
      },
      wharf_api_types::spec::Change::UpsertService {
        name: "db".into(),
        spec: serde_json::from_value(
          json!({"server": "s2", "source": {"image": "postgres:16"}}),
        )
        .unwrap(),
        adopt: None,
      },
      wharf_api_types::spec::Change::UpsertGateway {
        name: "gw1".into(),
        spec: serde_json::from_value(
          json!({"kind": "caddy", "server": "s1"}),
        )
        .unwrap(),
      },
      wharf_api_types::spec::Change::UpsertGateway {
        name: "gw2".into(),
        spec: serde_json::from_value(
          json!({"kind": "caddy", "server": "s2"}),
        )
        .unwrap(),
      },
      wharf_api_types::spec::Change::UpsertRoute {
        spec: serde_json::from_value(json!({
          "hostname": "a.example.com",
          "gateway": "gw1",
          "service": "web"
        }))
        .unwrap(),
      },
      wharf_api_types::spec::Change::UpsertRoute {
        spec: serde_json::from_value(json!({
          "hostname": "b.example.com",
          "gateway": "gw2",
          "service": "db"
        }))
        .unwrap(),
      },
    ])
    .unwrap();

  let mut report = AgentReport {
    metrics: Some(Box::new(Metrics {
      projects: {
        let mut p = BTreeMap::new();
        p.insert("web".into(), ProjectMetrics::default());
        p.insert("db".into(), ProjectMetrics::default());
        p.insert("wharf-gw-gw1".into(), ProjectMetrics::default());
        for i in 0..300 {
          p.insert(format!("fake-{i:03}"), ProjectMetrics::default());
        }
        p
      },
      hosts: BTreeMap::from([
        ("a.example.com".into(), HostTraffic::default()),
        ("b.example.com".into(), HostTraffic::default()),
      ]),
      oom: Some(vec!["web".into(), "db".into(), "fake".into()]),
      ..Default::default()
    })),
    ..Default::default()
  };
  sanitize_report("s1", &mut report);
  let m = report.metrics.as_mut().unwrap();
  assert!(m.projects.len() <= MAX_PROJECTS);
  m.projects.insert("web".into(), ProjectMetrics::default());
  m.projects.insert("db".into(), ProjectMetrics::default());
  m.projects
    .insert("wharf-gw-gw1".into(), ProjectMetrics::default());
  filter_owned_metrics("s1", m, &world, &BTreeMap::new());

  assert!(m.projects.contains_key("web"));
  assert!(m.projects.contains_key("wharf-gw-gw1"));
  assert!(!m.projects.contains_key("db"));
  assert!(!m.projects.keys().any(|k| k.starts_with("fake-")));
  assert_eq!(m.oom.as_deref(), Some(&["web".to_string()][..]));

  assert_eq!(
    route_owned_by_server(&world, "s1", "a.example.com").as_deref(),
    Some("web")
  );
  assert_eq!(
    route_owned_by_server(&world, "s1", "b.example.com"),
    None
  );
}

#[test]
fn report_rate_gate_throttles_flood_but_allows_upgrade_first_report()
{
  let gate = RateGate::default();
  let t0 = Instant::now();
  assert_eq!(gate.check("s1", 1, true, t0), RateDecision::AcceptAll);
  assert_eq!(
    gate.check("s1", 1, false, t0 + Duration::from_secs(3)),
    RateDecision::DropAll
  );
  assert_eq!(
    gate.check("s1", 1, true, t0 + Duration::from_secs(12)),
    RateDecision::AcceptNoMetrics
  );
  assert_eq!(
    gate.check("s1", 1, true, t0 + Duration::from_secs(30)),
    RateDecision::AcceptAll
  );
  // 升级重连（新 conn_id=2，间隔 3s，无 metrics）：放行 touch，不吞掉新 build。
  assert_eq!(
    gate.check("s1", 2, false, t0 + Duration::from_secs(33)),
    RateDecision::AcceptAll
  );
  assert_eq!(
    gate.check("s1", 3, false, t0 + Duration::from_secs(34)),
    RateDecision::DropAll
  );
  assert_eq!(
    gate.check("s1", 3, true, t0 + Duration::from_secs(35)),
    RateDecision::AcceptNoMetrics
  );
}
