use serde_json::json;
use wharf_api_types::{ErrorCode, view::Perm};

use super::*;
use crate::{
  host_access::tests::auth, token_scope::require_route_by_host,
  world::RouteRow,
};

fn world() -> World {
  let mut world = World::default();
  for (host, spec) in [
    (
      "blog.example.com",
      json!({"hostname":"blog.example.com","service":"blog"}),
    ),
    (
      "other.example.com",
      json!({"hostname":"other.example.com","service":"other"}),
    ),
    (
      "mixed.example.com",
      json!({"hostname":"mixed.example.com","service":"blog","paths":[{"path":"/other","service":"other"}]}),
    ),
    (
      "external.example.com",
      json!({"hostname":"external.example.com","service":"blog","upstream":"https://example.net"}),
    ),
  ] {
    world.routes.insert(
      host.into(),
      RouteRow {
        id: host.into(),
        spec: serde_json::from_value(spec).unwrap(),
        version: 1,
      },
    );
  }
  world
}

#[test]
fn scope_filter_trims_status_export_secrets_and_alerts() {
  let allowed = BTreeSet::from(["blog".into()]);
  let world = world();
  let spec = json!({"server":"s1","source":{"image":"nginx:1"}});
  let routes: Vec<_> = world.routes.values().map(|row| json!({
    "id":row.id,"spec":row.spec,"url":format!("https://{}", row.id),"version":1
  })).collect();
  let gateway = json!({"kind":"caddy","server":"s1"});
  let bookmark = json!({"title":"服务","url":"https://example.net"});
  let edge = json!({"account":"cf","kind":"worker"});
  let mut status: Status = serde_json::from_value(json!({
    "servers":[{"name":"s1","settings":{},"joined":false,"online":false,"version":1}],
    "services":[{"name":"blog","spec":spec,"host_ports":{},"addresses":{},"version":1},
                {"name":"other","spec":spec,"host_ports":{},"addresses":{},"version":1}],
    "routes":routes,
    "gateways":[{"name":"gw","spec":gateway,"routes":[],"version":1}],
    "edge_apps":[{"name":"edge","spec":edge,"version":1}],
    "bookmarks":[{"id":"note","spec":bookmark,"version":1}],
    "issues":[{"code":"server_offline","level":"fault","subject":{"kind":"server","name":"s1"},"title":"服务器离线"}],
    "problems":["服务器离线"]
  })).unwrap();
  filter_status(&allowed, &world, &mut status);
  assert_eq!(
    status
      .services
      .iter()
      .map(|s| s.name.as_str())
      .collect::<Vec<_>>(),
    ["blog"]
  );
  assert_eq!(
    status
      .routes
      .iter()
      .map(|r| r.spec.hostname.as_str())
      .collect::<Vec<_>>(),
    ["blog.example.com"]
  );
  assert!(
    status.servers.is_empty()
      && status.gateways.is_empty()
      && status.edge_apps.is_empty()
      && status.bookmarks.is_empty()
      && status.issues.is_empty()
      && status.problems.is_empty()
  );

  let mut fleet: Fleet = serde_json::from_value(json!({
    "services":{"blog":spec,"other":spec}, "routes":world.routes.values().map(|r|&r.spec).collect::<Vec<_>>(),
    "servers":{"s1":{}},"gateways":{"gw":gateway},"edge_apps":{"edge":edge},"bookmarks":{"note":bookmark}
  })).unwrap();
  filter_export(&allowed, &mut fleet);
  assert_eq!(
    fleet
      .services
      .keys()
      .map(String::as_str)
      .collect::<Vec<_>>(),
    ["blog"]
  );
  assert_eq!(
    fleet
      .routes
      .iter()
      .map(|r| r.hostname.as_str())
      .collect::<Vec<_>>(),
    ["blog.example.com"]
  );
  assert!(
    fleet.servers.is_empty()
      && fleet.gateways.is_empty()
      && fleet.edge_apps.is_empty()
      && fleet.bookmarks.is_empty()
  );

  let mut secrets = [
    ("WHARF_BACKUP_KEY", true, vec!["blog", "other"]),
    ("BLOG_DB", false, vec!["blog", "other"]),
    ("OTHER_DB", false, vec!["other"]),
  ]
  .into_iter()
  .map(|(name, managed, users)| SecretView {
    fingerprint: None,
    has_previous: false,
    prev_expires_at: None,
    prev_fingerprint: None,
    other_refs: vec![],
    allowed_services: None,
    name: name.into(),
    updated_at: chrono::Utc::now(),
    managed,
    system: managed.then(|| "备份".into()),
    used_by: users.into_iter().map(str::to_string).collect(),
  })
  .collect();
  filter_secrets(&allowed, &mut secrets);
  assert_eq!(secrets.len(), 1);
  assert_eq!(secrets[0].name, "BLOG_DB");
  assert_eq!(secrets[0].used_by, ["blog"]);

  let mut alerts: AlertsView = serde_json::from_value(json!({
    "rules":[],"notices":[],
    "firing":[{"rule":"http_5xx","subject":"blog","title":"blog","since":1},
              {"rule":"http_5xx","subject":"other","title":"other","since":1},
              {"rule":"server_offline","subject":"s1","title":"s1","since":1}],
    "history":[{"at":1,"source":"http_5xx","title":"blog","ok":false},
               {"at":2,"source":"server_offline","title":"s1","ok":false}]
  })).unwrap();
  filter_alerts(
    &allowed,
    &world,
    &mut alerts,
    &[
      ("http_5xx".into(), Some("blog".into())),
      ("server_offline".into(), Some("s1".into())),
    ],
    &BTreeSet::new(),
  );
  assert_eq!(alerts.firing.len(), 1);
  assert_eq!(alerts.firing[0].subject, "blog");
  assert_eq!(alerts.history.len(), 1);
  assert_eq!(alerts.history[0].title, "blog");
}

pub(crate) fn rejects_foreign_alerts_and_routes() {
  let allowed = BTreeSet::from(["blog".into()]);
  let world = world();
  for (rule, subject) in [
    ("http_5xx", "other"),
    ("server_offline", "s1"),
    ("domain_down", "other.example.com"),
  ] {
    assert!(!alert_in_scope(
      &allowed,
      &world,
      None,
      rule,
      Some(subject)
    ));
  }
  let mut auth = auth([Perm::Read], false);
  auth.services = Some(allowed);
  for host in [
    "other.example.com",
    "external.example.com",
    "mixed.example.com",
    "missing.example.com",
  ] {
    assert_eq!(
      require_route_by_host(&auth, &world, host).unwrap_err().code,
      ErrorCode::Forbidden
    );
  }
}

pub(crate) fn allows_own_route() {
  let mut auth = auth([Perm::Read], false);
  auth.services = Some(BTreeSet::from(["blog".into()]));
  assert!(
    require_route_by_host(&auth, &world(), "blog.example.com")
      .is_ok()
  );
}

pub(crate) fn allows_own_alerts() {
  let allowed = BTreeSet::from(["blog".into()]);
  let world = world();
  for (rule, subject) in [
    ("http_5xx", "blog"),
    ("port_down", "blog:8080"),
    ("domain_down", "blog.example.com"),
  ] {
    assert!(alert_in_scope(
      &allowed,
      &world,
      None,
      rule,
      Some(subject)
    ));
  }
}
