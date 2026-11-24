use serde_json::json;

use super::super::tests::notification_db;
use super::*;

#[test]
fn offline_host_suppresses_its_service_only() {
  let mut world = World::default();
  world.services.insert(
    "web".into(),
    crate::world::ServiceRow {
      spec: serde_json::from_value(
        json!({ "server": "box", "source": { "image": "nginx" } }),
      )
      .unwrap(),
      host_ports: BTreeMap::new(),
      import: None,
      pins: BTreeMap::new(),
      commit: None,
      version: 1,
    },
  );
  let mut firing = Firing::from([(
    ("server_offline".into(), "box".into()),
    (0, "box 离线".into()),
  )]);
  let cfg = BTreeMap::new();
  assert_eq!(
    built_in(&world, &cfg, &firing, "monitor_failed", "web")
      .as_deref(),
    Some("box 离线")
  );
  assert_eq!(
    built_in(&world, &cfg, &firing, "monitor_failed", "other"),
    None
  );
  firing.clear();
  assert_eq!(
    built_in(&world, &cfg, &firing, "monitor_failed", "web"),
    None
  );
}

#[test]
fn suppressed_active_service_is_selected_once_for_replay() {
  let c = notification_db();
  c.execute("INSERT INTO alert_firing VALUES ('monitor_failed', 'web', 1000, '监控失败')", []).unwrap();
  c.execute(
    "INSERT INTO alert_episode VALUES ('monitor_failed', 'web', 1000, '监控失败', '超时', '被抑制：box 离线', NULL)",
    [],
  ).unwrap();
  let candidates = pending(&c).unwrap();
  assert_eq!(candidates.len(), 1);
  assert_eq!(candidates[0].1, "web");
  assert_eq!(candidates[0].2.body, "超时");
  let previous =
    super::super::policy::episode(&c, "monitor_failed", "web")
      .unwrap()
      .unwrap();
  super::super::policy::persist(
    &c,
    Delivery {
      id: "monitor_failed",
      subject: Some("web"),
      paired: true,
      ok: false,
      now: 2000,
      replay: true,
    },
    &candidates[0].2,
    None,
    Some(&previous),
  )
  .unwrap();
  assert!(pending(&c).unwrap().is_empty());
}

#[test]
fn custom_source_matches_only_its_subject_until_recovery() {
  let items = [AlertSuppression {
    id: 1,
    source: "server_offline:x".into(),
    ignore: "monitor_failed".into(),
  }];
  let mut firing = Firing::from([
    (("server_offline".into(), "x".into()), (0, "x 离线".into())),
    (("server_offline".into(), "y".into()), (0, "y 离线".into())),
  ]);
  for subject in ["web", "db"] {
    assert_eq!(
      custom(&items, &firing, "monitor_failed", subject).as_deref(),
      Some("x 离线")
    );
  }
  firing.remove(&("server_offline".into(), "x".into()));
  assert_eq!(custom(&items, &firing, "monitor_failed", "web"), None);
}
