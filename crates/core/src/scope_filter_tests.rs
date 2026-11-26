use super::*;
use axum::http::Method;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rusqlite::params;
use serde_json::json;
use wharf_api_types::{
  ErrorCode,
  plan::RunStatus,
  spec::{RouteSpec, ServiceSpec},
  view::{
    AlertHistoryView, AlertLevel, AlertRuleView, FiringView,
    IssueLevel, IssueSubject, NoticeView, Perm, RouteView,
    ServiceView,
  },
};

use crate::{
  db::Db,
  host_access::tests::auth,
  world::{RouteRow, ServiceRow},
};

fn test_world() -> World {
  let mut world = World::default();
  let svc = || ServiceRow {
    spec: serde_json::from_value::<ServiceSpec>(json!({
      "server": "home",
      "source": { "image": "nginx" }
    }))
    .unwrap(),
    version: 1,
    host_ports: Default::default(),
    import: None,
    pins: Default::default(),
    commit: None,
  };
  world.services.insert("blog".into(), svc());
  world.services.insert("other".into(), svc());
  let add_route = |world: &mut World, spec: serde_json::Value| {
    let spec: RouteSpec = serde_json::from_value(spec).unwrap();
    let host = spec.hostname.clone();
    world.routes.insert(
      host,
      RouteRow {
        id: "r1".into(),
        spec,
        version: 1,
      },
    );
  };
  add_route(
    &mut world,
    json!({"hostname": "blog.example.com", "service": "blog"}),
  );
  add_route(
    &mut world,
    json!({"hostname": "other.example.com", "service": "other"}),
  );
  add_route(
    &mut world,
    json!({
      "hostname": "mixed.example.com",
      "service": "blog",
      "paths": [{"path": "/api", "service": "other"}]
    }),
  );
  add_route(
    &mut world,
    json!({
      "hostname": "ext.example.com",
      "upstream": "127.0.0.1:9000"
    }),
  );
  world
}

fn test_state() -> AppState {
  AppState {
    db: Db::memory(),
    hub: Default::default(),
    key: SigningKey::from_bytes(&[7u8; 32]),
    runs: Default::default(),
    apply_lock: Default::default(),
    public_url: None,
    agent_image: "wharf-agent:test".into(),
    listen_port: 7700,
    data_dir: std::path::PathBuf::from("/tmp"),
    downloads: Default::default(),
    edge_syncing: Default::default(),
  }
}

fn svc_view(name: &str, spec: &ServiceSpec) -> ServiceView {
  serde_json::from_value(json!({
    "name": name,
    "spec": spec,
    "host_ports": {},
    "addresses": {},
    "version": 1,
  }))
  .unwrap()
}

fn route_view(spec: &RouteSpec) -> RouteView {
  RouteView {
    note: None,
    sso_login: None,
    id: "r1".into(),
    url: format!("https://{}", spec.hostname),
    spec: spec.clone(),
    gateway: None,
    upstream: None,
    version: 1,
    probe: None,
    on_backup: false,
  }
}

#[test]
fn scope_filter_trims_status_export_secrets_and_alerts() {
  let world = test_world();
  let allowed = BTreeSet::from(["blog".into()]);
  let now = Utc::now();

  let mut status: Status = serde_json::from_value(json!({
    "bookmarks": [{"id": "b1", "spec": {"title": "t", "url": "https://a.test"}, "version": 1}],
    "servers": [{"name": "home", "settings": {}, "joined": true, "online": true, "version": 1}],
    "services": [
      svc_view("blog", &world.services["blog"].spec),
      svc_view("other", &world.services["other"].spec),
    ],
    "edge_apps": [{"name": "w", "spec": {"account": "cf", "kind": "worker"}, "version": 1}],
    "edge_unmanaged": [],
    "gateways": [{"name": "edge", "spec": {"kind": "caddy", "server": "home"}, "routes": [], "version": 1, "live": {"state":"running","containers":[]}}],
    "routes": [
      route_view(&world.routes["blog.example.com"].spec),
      route_view(&world.routes["other.example.com"].spec),
      route_view(&world.routes["mixed.example.com"].spec),
    ],
    "issues": [
      Issue {
        code: "http_5xx".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject { kind: "service".into(), name: "blog".into() }),
        title: "blog 5xx".into(),
        hint: None,
        ack: None,
        alert: None,
      },
      Issue {
        code: "server_offline".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject { kind: "server".into(), name: "home".into() }),
        title: "home 离线".into(),
        hint: None,
        ack: None,
        alert: None,
      },
    ],
  }))
  .unwrap();
  filter_status(&allowed, &world, &mut status);
  assert!(status.servers.is_empty());
  assert!(status.gateways.is_empty());
  assert!(status.edge_apps.is_empty());
  assert!(status.bookmarks.is_empty());
  assert_eq!(status.services.len(), 1);
  assert_eq!(status.services[0].name, "blog");
  assert_eq!(status.routes.len(), 1);
  assert_eq!(status.routes[0].spec.hostname, "blog.example.com");
  assert_eq!(status.issues.len(), 1);
  assert_eq!(status.problems, vec!["blog 5xx"]);

  let mut fleet = crate::views::export(&world);
  filter_export(&allowed, &mut fleet);
  assert!(fleet.servers.is_empty());
  assert!(fleet.gateways.is_empty());
  assert!(fleet.edge_apps.is_empty());
  assert!(fleet.bookmarks.is_empty());
  assert_eq!(fleet.services.keys().collect::<Vec<_>>(), vec!["blog"]);
  assert_eq!(fleet.routes.len(), 1);
  assert_eq!(fleet.routes[0].hostname, "blog.example.com");

  let mut secrets = vec![
    SecretView {
      name: "WHARF_BACKUP_KEY".into(),
      updated_at: now,
      used_by: vec!["备份".into()],
      managed: true,
      system: Some("备份".into()),
    },
    SecretView {
      name: "BLOG_DB".into(),
      updated_at: now,
      used_by: vec!["blog".into(), "other".into()],
      managed: false,
      system: None,
    },
    SecretView {
      name: "OTHER_DB".into(),
      updated_at: now,
      used_by: vec!["other".into()],
      managed: false,
      system: None,
    },
  ];
  filter_secrets(&allowed, &mut secrets);
  assert_eq!(secrets.len(), 1);
  assert_eq!(secrets[0].name, "BLOG_DB");
  assert_eq!(secrets[0].used_by, vec!["blog"]);

  let mut alerts = AlertsView {
    rules: vec![
      AlertRuleView {
        id: "http_5xx".into(),
        name: "5xx".into(),
        metric: "req.err".into(),
        condition: String::new(),
        op: ">".into(),
        threshold: 5.0,
        for_n: 3,
        threshold_editable: true,
        enabled: true,
        level: AlertLevel::Urgent,
        muted_until: None,
        customized: false,
      },
      AlertRuleView {
        id: "server_offline".into(),
        name: "离线".into(),
        metric: "server.online".into(),
        condition: String::new(),
        op: "<".into(),
        threshold: 1.0,
        for_n: 3,
        threshold_editable: false,
        enabled: true,
        level: AlertLevel::Urgent,
        muted_until: None,
        customized: false,
      },
    ],
    notices: vec![NoticeView {
      id: "login".into(),
      name: "登录".into(),
      enabled: true,
      level: AlertLevel::Urgent,
      muted_until: None,
      customized: false,
    }],
    firing: vec![
      FiringView {
        rule: "http_5xx".into(),
        subject: "blog".into(),
        title: "blog 5xx".into(),
        since: 1,
        ack: None,
      },
      FiringView {
        rule: "server_offline".into(),
        subject: "home".into(),
        title: "home 离线".into(),
        since: 1,
        ack: None,
      },
    ],
    history: vec![
      AlertHistoryView {
        at: 1,
        source: "http_5xx".into(),
        title: "blog 5xx".into(),
        ok: false,
        skipped: None,
      },
      AlertHistoryView {
        at: 2,
        source: "server_offline".into(),
        title: "home 离线".into(),
        ok: false,
        skipped: None,
      },
    ],
    include_logs: false,
    builtin_suppressions: vec![],
    suppressions: vec![],
    service_overrides: vec![],
    custom_rules: vec![],
  };
  let subjects = vec![
    ("http_5xx".into(), Some("blog".into())),
    ("server_offline".into(), Some("home".into())),
  ];
  filter_alerts(&allowed, &world, &mut alerts, &subjects);
  assert_eq!(alerts.rules.len(), 1);
  assert!(alerts.notices.is_empty());
  assert_eq!(alerts.firing.len(), 1);
  assert_eq!(alerts.firing[0].subject, "blog");
  assert_eq!(alerts.history.len(), 1);
  assert_eq!(alerts.history[0].source, "http_5xx");
}

#[tokio::test]
async fn scoped_token_cannot_view_or_cancel_foreign_run() {
  let state = test_state();
  let allowed = BTreeSet::from(["blog".into()]);
  let make = |id: &str, scope: Vec<String>| StoredRun {
    run: Run {
      run_id: id.into(),
      plan_id: String::new(),
      status: RunStatus::Running,
      started_at: Utc::now(),
      finished_at: None,
      steps: vec![],
    },
    scope_services: Some(scope),
  };
  let r_other = make("r_other", vec!["other".into()]);
  let r_core = make(
    "r_core",
    step_scope_services(&Step::CoreBackup { user_key: None }),
  );
  let r_blog = make(
    "r_blog",
    step_scope_services(&Step::Rebuild {
      service: "blog".into(),
    }),
  );
  let rows: Vec<(String, String)> = [&r_other, &r_core, &r_blog]
    .into_iter()
    .map(|r| {
      (r.run.run_id.clone(), serde_json::to_string(r).unwrap())
    })
    .collect();
  state
    .db
    .call(move |c| {
      for (idx, (id, body)) in rows.into_iter().enumerate() {
        c.execute(
          "INSERT INTO runs (id, plan_id, status, body, started_at) VALUES (?1, '', 'running', ?2, ?3)",
          params![id, body, 1000 + idx as i64],
        )
        .map_err(sql_err)?;
      }
      Ok(())
    })
    .await
    .unwrap();

  assert!(
    !run_in_scope(
      &state,
      &allowed,
      &r_other.run,
      r_other.scope_services.as_deref()
    )
    .await
  );
  assert!(
    !run_in_scope(
      &state,
      &allowed,
      &r_core.run,
      r_core.scope_services.as_deref()
    )
    .await
  );
  assert!(
    run_in_scope(
      &state,
      &allowed,
      &r_blog.run,
      r_blog.scope_services.as_deref()
    )
    .await
  );

  let mut scoped = auth([Perm::Read, Perm::Apply], false);
  scoped.services = Some(allowed);
  assert_eq!(
    load_run_for(&state, &scoped, "r_other")
      .await
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert_eq!(
    require_run_scope(&state, &scoped, "r_core")
      .await
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  assert!(load_run_for(&state, &scoped, "r_blog").await.is_ok());
  assert!(require_run_scope(&state, &scoped, "r_blog").await.is_ok());
}

#[test]
fn scoped_token_rejects_other_service_alerts_and_foreign_routes() {
  let world = test_world();
  let services = BTreeSet::from(["blog".into()]);
  assert!(!token_scope::check_service_scope(
    &services,
    &Method::PUT,
    "/api/alerts/http_5xx/services/other"
  ));
  assert!(!token_scope::check_service_scope(
    &services,
    &Method::PUT,
    "/api/alerts/options"
  ));
  assert!(!alert_in_scope(
    &services,
    &world,
    None,
    "http_5xx",
    Some("other")
  ));
  assert!(!alert_in_scope(
    &services,
    &world,
    None,
    "server_offline",
    Some("home")
  ));
  assert!(!alert_in_scope(
    &services,
    &world,
    None,
    "domain_down",
    Some("other.example.com")
  ));
  let mut scoped = auth([Perm::Read, Perm::Apply], false);
  scoped.services = Some(services);
  for host in
    ["other.example.com", "ext.example.com", "mixed.example.com"]
  {
    let err =
      token_scope::require_route_by_host(&scoped, &world, host)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden, "host={host}");
  }
}

#[test]
fn scoped_token_allows_own_service_and_route_reads() {
  let world = test_world();
  let services = BTreeSet::from(["blog".into()]);
  for path in [
    "/api/status",
    "/api/services/blog",
    "/api/services/blog/logs",
    "/api/services/blog/files/download",
    "/api/routes/blog.example.com/cert",
    "/api/routes/blog.example.com/dns-check",
    "/api/metrics",
    "/api/alerts",
    "/api/export",
    "/api/whoami",
  ] {
    assert!(
      token_scope::check_service_scope(&services, &Method::GET, path),
      "expected GET {path} to be allowed"
    );
  }
  let mut scoped = auth([Perm::Read], false);
  scoped.services = Some(services);
  assert!(
    token_scope::require_route_by_host(
      &scoped,
      &world,
      "blog.example.com"
    )
    .is_ok()
  );
}

#[test]
fn scoped_token_allows_own_service_alerts_and_route_writes() {
  let world = test_world();
  let services = BTreeSet::from(["blog".into()]);
  for (method, path) in [
    (Method::PUT, "/api/alerts/http_5xx/services/blog"),
    (Method::POST, "/api/alerts/ack"),
    (Method::POST, "/api/alerts/unack"),
    (Method::POST, "/api/alerts/custom"),
    (Method::DELETE, "/api/alerts/custom/slow"),
    (Method::POST, "/api/routes/blog.example.com/cert/retry"),
    (Method::PUT, "/api/routes/blog.example.com/note"),
  ] {
    assert!(
      token_scope::check_service_scope(&services, &method, path),
      "expected {method} {path} to be allowed"
    );
  }
  assert!(alert_in_scope(
    &services,
    &world,
    None,
    "http_5xx",
    Some("blog")
  ));
  assert!(alert_in_scope(
    &services,
    &world,
    None,
    "port_down",
    Some("blog:8080")
  ));
  assert!(alert_in_scope(
    &services,
    &world,
    None,
    "domain_down",
    Some("blog.example.com")
  ));
}
