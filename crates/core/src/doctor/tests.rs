use super::*;
use crate::world::{
  EdgeRow, GatewayRow, RouteRow, ServerRow, ServiceRow,
};
use serde_json::json;
use wharf_api_types::agent::{AgentReport, Disk};

fn fixture() -> Snapshot {
  let mut snap = Snapshot::default();
  for name in ["s1", "s2"] {
    snap.world.servers.insert(
      name.into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
  }
  for (name, server) in [("app", "s1"), ("db", "s1"), ("other", "s2")]
  {
    snap.world.services.insert(name.into(), ServiceRow {
      frozen_defaults: Default::default(),
      host_groups: Default::default(),
      instance_id: format!("svc_{name}"),
      spec: serde_json::from_value(json!({
        "server": server, "source": {"image": "nginx:1"},
        "ports": [{"name":"http","container":80}],
        "env": if name == "other" { json!({"PASS":"fixture-password"}) } else { json!({}) },
      })).unwrap(),
      host_ports: std::collections::BTreeMap::from([("http".into(), 21000)]),
      import: None, pins: Default::default(), commit: None, version: 1,
    });
  }
  snap.world.gateways.insert("entry".into(), GatewayRow {
    spec: serde_json::from_value(json!({
      "kind":"caddy", "server":"s1",
      "layer4":[{"listen": 5432, "service":"db", "port":"http", "udp":true}],
    })).unwrap(),
    version: 1,
  });
  snap
}

fn add_route(snap: &mut Snapshot, paths: serde_json::Value) {
  let host = "app.example.test";
  snap.world.routes.insert(host.into(), RouteRow {
    id: "route_fixture".into(), version: 1,
    spec: serde_json::from_value(json!({
      "hostname": host, "service":"app", "gateway":"entry", "paths": paths
    })).unwrap(),
  });
}

#[test]
fn host_filter_excludes_unrelated_servers_and_config() {
  let mut snap = fixture();
  add_route(&mut snap, json!([]));
  let sel = selection(
    &snap,
    &DoctorScope::Host(normalize_host(" APP.example.test. ")),
    None,
  )
  .unwrap();
  assert_eq!(sel.hosts, ["app.example.test"]);
  assert_eq!(sel.servers, BTreeSet::from(["s1".into()]));
  let lint =
    crate::lint::scoped_warnings(&snap, &sel.services, &sel.servers);
  assert!(lint.iter().all(|(subject, _)| subject != "服务 other"));
}

#[tokio::test]
async fn doctor_service_and_server_scopes() {
  let mut snap = fixture();
  snap.agents.push(crate::db::AgentRow {
    server: "s1".into(),
    public_key: None,
    last_seen: None,
    report: Some(AgentReport {
      disk: Some(Disk {
        total: 1 << 34,
        free: 0,
      }),
      ..Default::default()
    }),
  });
  let state = crate::rules::tests::test_state();
  let net = snap.net(&snap.world);
  let clients = Clients::new(&snap).unwrap();
  let live = LiveMap::default();
  let ctx = RouteChecks {
    s: &state,
    snap: &snap,
    net: &net,
    live: &live,
    clients: &clients,
    manual: true,
  };
  let service = DoctorScope::Service("db".into());
  assert!(selection(&snap, &service, None).unwrap().hosts.is_empty());
  let report = special::checks(&ctx, &service).await;
  for layer in ["container", "port", "layer4"] {
    assert!(report.iter().any(|c| c.layer == layer));
  }
  let server = DoctorScope::Server("s1".into());
  let allowed = Auth {
    name: "fixture".into(),
    perms: BTreeSet::from([Perm::Read]),
    expires_at: None,
    allowed_from: vec![],
    services: Some(BTreeSet::from(["db".into()])),
    human: false,
  };
  assert!(
    matches!(selection(&snap, &server, Some(&allowed)), Err(e) if e.code == ErrorCode::Forbidden)
  );
  let report = special::checks(&ctx, &server).await;
  assert!(
    report
      .iter()
      .any(|c| c.layer == "disk" && c.status == CheckStatus::Bad)
  );
  assert!(report.iter().any(|c| c.layer == "gateway"));
}

#[tokio::test]
async fn stopped_main_still_probes_active_paths() {
  let mut snap = fixture();
  add_route(&mut snap, json!([{"path":"/api/*","service":"db"}]));
  snap.world.services.get_mut("app").unwrap().spec.stopped = true;
  let state = crate::rules::tests::test_state();
  let net = snap.net(&snap.world);
  let clients = Clients::new(&snap).unwrap();
  let live = LiveMap::from([("s1".into(), Ok(std::collections::BTreeMap::from([
    ("db".into(), serde_json::from_value(json!({
      "project":"db", "containers":[{"service":"db","name":"db-1","state":"exited"}]
    })).unwrap()),
  ])))]);
  let ctx = RouteChecks {
    s: &state,
    snap: &snap,
    net: &net,
    live: &live,
    clients: &clients,
    manual: true,
  };
  let (report, targets) =
    ctx.route("app.example.test").await.unwrap();
  assert!(report.checks.iter().any(|c| c.layer == "container"
    && c.subject.contains("/api/*")
    && c.status == CheckStatus::Bad));
  assert!(
    report
      .checks
      .iter()
      .any(|c| c.layer == "link" && c.subject.contains("/api/*"))
  );
  assert_eq!(targets[0].service, "db");
  for layer in ["dns", "https"] {
    assert!(
      report
        .checks
        .iter()
        .any(|c| c.layer == layer && c.status != CheckStatus::Skip)
    );
  }
  assert!(
    report
      .checks
      .iter()
      .any(|c| c.layer == "https" && c.subject.ends_with("/api/"))
  );
  assert!(report.checks.iter().any(|c| c.layer == "link"
    && !c.subject.contains("/api/*")
    && c.status == CheckStatus::Skip));
  let stopped = container_of_service(&snap.world, &live, "app");
  assert_eq!(stopped.status, CheckStatus::Skip);
  snap.world.services.get_mut("db").unwrap().spec.stopped = true;
  let ctx = RouteChecks {
    s: &state,
    snap: &snap,
    net: &net,
    live: &live,
    clients: &clients,
    manual: true,
  };
  let (report, targets) =
    ctx.route("app.example.test").await.unwrap();
  assert!(targets.is_empty());
  assert_eq!(report.checks.len(), 2);
  assert!(
    report.checks.iter().all(|c| c.status == CheckStatus::Skip)
  );
}

#[test]
fn edge_domains_included_and_egress_routing_rules() {
  let mut snap = fixture();
  add_route(&mut snap, json!([]));
  snap.world.edge_apps.insert("site".into(), EdgeRow {
    spec: serde_json::from_value(json!({"kind":"worker","account":"example","domains":["edge.example.test"]})).unwrap(),
    version: 1,
  });
  let selected = selection(
    &snap,
    &DoctorScope::Host("edge.example.test".into()),
    None,
  )
  .unwrap();
  assert_eq!(
    selected.edge,
    [("edge.example.test".to_string(), "site".to_string())]
  );
  let should_egress =
    |snap: &Snapshot, patch: &RouteSpec, gw: &GatewaySpec| {
      use_egress_for_doctor(snap, Some((patch, gw)), false)
    };
  let mut route = snap.world.routes["app.example.test"].spec.clone();
  let mut gateway = snap.world.gateways["entry"].spec.clone();
  assert!(use_egress_for_doctor(&snap, None, true));
  assert!(!should_egress(&snap, &route, &gateway));
  gateway.kind = GatewayKind::CloudflareTunnel;
  assert!(should_egress(&snap, &route, &gateway));
  gateway.kind = GatewayKind::Caddy;
  snap.world.servers.get_mut("s1").unwrap().settings.region =
    Some(Region::Overseas);
  assert!(should_egress(&snap, &route, &gateway));
  route.internal = true;
  assert!(!should_egress(&snap, &route, &gateway));
}

#[test]
fn probe_addr_parses_urls_and_unauth_401_is_warn() {
  for (url, target) in [
    ("http://203.0.113.2:8080/api", "203.0.113.2:8080"),
    ("https://api.example.test", "api.example.test:443"),
    ("http://[2001:db8::1]/", "[2001:db8::1]:80"),
  ] {
    assert_eq!(probe_addr(url).as_deref(), Some(target));
  }
  assert_eq!(
    http_status(
      reqwest::StatusCode::UNAUTHORIZED,
      &HttpProbe::default(),
      false,
      b""
    )
    .0,
    CheckStatus::Warn
  );
}

#[test]
fn probe_cookie_verifies_and_penetrates_gate() {
  let options = HttpProbe {
    gate: true,
    header: true,
    cookie: Some(reqwest::header::HeaderValue::from_static(
      "probe-fixture",
    )),
    ..Default::default()
  };
  for (code, rejected, status, bad_gateway) in [
    (502, false, CheckStatus::Bad, true),
    (302, true, CheckStatus::Warn, false),
    (401, false, CheckStatus::Ok, false),
    (403, false, CheckStatus::Ok, false),
    (500, false, CheckStatus::Bad, false),
  ] {
    let (actual, _, bad) = http_status(
      reqwest::StatusCode::from_u16(code).unwrap(),
      &options,
      rejected,
      b"",
    );
    assert_eq!((actual, bad), (status, bad_gateway));
  }
}

#[test]
fn internal_gate_login_is_expected_without_a_probe_cookie() {
  let probe = HttpProbe {
    gate: true,
    internal: true,
    ..Default::default()
  };
  let classify = |code, rejected| {
    http_status(
      reqwest::StatusCode::from_u16(code).unwrap(),
      &probe,
      rejected,
      b"",
    )
  };
  for code in [302, 401] {
    let (status, detail, _) = classify(code, true);
    assert_eq!(status, CheckStatus::Ok);
    assert!(detail.contains("未穿透验证应用"));
  }
  assert_eq!(classify(200, false).0, CheckStatus::Ok);
  assert_eq!(classify(403, false).0, CheckStatus::Warn);
  assert_eq!(classify(502, false).0, CheckStatus::Bad);
}

#[test]
fn filtered_monitor_preserves_header_gate_response() {
  let mut snap = fixture();
  add_route(&mut snap, json!([{"path":"/api/*","service":"db"}]));
  let route =
    &mut snap.world.routes.get_mut("app.example.test").unwrap().spec;
  route.sso =
    Some(serde_json::from_value(json!({"mode":"header"})).unwrap());
  let mut monitor: MonitorSpec =
    serde_json::from_value(json!({"path":"/api/health"})).unwrap();
  for auth in [false, true] {
    route.auth = auth;
    if auth {
      route.paths.clear();
    }
    let probe = HttpProbe {
      cookie: Some(reqwest::header::HeaderValue::from_static(
        "probe-fixture",
      )),
      ..HttpProbe::for_route(route, true, Some(&monitor))
    };
    assert!(probe.monitor.is_none());
    for code in [
      reqwest::StatusCode::UNAUTHORIZED,
      reqwest::StatusCode::FORBIDDEN,
    ] {
      assert_eq!(
        http_status(code, &probe, false, b"").0,
        CheckStatus::Ok
      );
    }
  }
  route.auth = false;
  assert!(
    HttpProbe::for_route(route, true, Some(&monitor))
      .monitor
      .is_some()
  );
  monitor
    .headers
    .insert("Host".into(), "local.example.test".into());
  let probe = HttpProbe::for_route(route, true, Some(&monitor));
  assert!(probe.monitor.is_none());
  assert!(probe.header);
}

#[tokio::test]
async fn portless_worker_reports_crash_diagnostics() {
  let mut snap = fixture();
  let worker = snap.world.services.get_mut("app").unwrap();
  worker.host_ports.clear();
  worker.spec.ports.clear();
  let state = crate::rules::tests::test_state();
  state.hub.mock_agent("s1", false, |op| {
    match op {
      AgentOp::DiagnoseContainer { project, ports } if project == "app" => {
        assert!(ports.is_empty());
        Ok(json!([{
          "name":"app-1", "running":false, "restarting":false, "exit_code":137,
          "oom_killed":true, "started_at":"", "restart_count":0,
          "network_mode":"bridge", "ports":{}, "mounts":[], "log_keywords":[]
        }]))
      }
      _ => Err(ApiError::internal("测试不处理此操作")),
    }
  });
  state.hub.enable_mock_container_diagnosis("s1");
  let net = snap.net(&snap.world);
  let clients = Clients::new(&snap).unwrap();
  let live = LiveMap::default();
  let ctx = RouteChecks {
    s: &state,
    snap: &snap,
    net: &net,
    live: &live,
    clients: &clients,
    manual: true,
  };
  for scope in [
    DoctorScope::Service("app".into()),
    DoctorScope::Server("s1".into()),
  ] {
    let checks = special::checks(&ctx, &scope).await;
    assert!(checks.iter().any(|c| c.layer == "container"
      && c.detail.contains("退出码 137")
      && c.detail.contains("内存不够被杀")));
  }
}
