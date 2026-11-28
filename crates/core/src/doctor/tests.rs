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
async fn route_checks_include_path_services() {
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
      use_egress_for_doctor(
        snap,
        &patch.hostname,
        Some((patch, gw)),
        false,
      )
    };
  let mut route = snap.world.routes["app.example.test"].spec.clone();
  let mut gateway = snap.world.gateways["entry"].spec.clone();
  assert!(use_egress_for_doctor(
    &snap,
    "edge.example.test",
    None,
    true
  ));
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
