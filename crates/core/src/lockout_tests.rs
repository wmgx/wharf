use super::*;
use LockScope::{AdminLogin, GateKey};
use OriginZone::{Internal, Public};

#[test]
fn admin_locks_each_zone_and_only_triggers_on_thresholds() {
  let mut table = LockoutTable::default();
  let now = Instant::now();
  let key = "203.0.113.7";
  for _ in 0..4 {
    assert!(table.record_at(AdminLogin, Public, key, now).is_none());
  }
  let event = table.record_at(AdminLogin, Public, key, now).unwrap();
  assert_eq!((event.kind, event.count), (LockKind::PerIp, 5));
  assert_eq!(table.locked_at(AdminLogin, Public, key, now), Some(15));
  assert!(table.record_at(AdminLogin, Public, key, now).is_none());

  for _ in 0..13 {
    table.record_at(AdminLogin, Public, "203.0.113.8", now);
  }
  let event = table
    .record_at(AdminLogin, Public, "203.0.113.9", now)
    .unwrap();
  assert_eq!((event.kind, event.count), (LockKind::ZoneTotal, 20));
  assert!(
    table
      .record_at(AdminLogin, Public, "203.0.113.9", now)
      .is_none()
  );
  assert_eq!(
    table.locked_at(AdminLogin, Public, "203.0.113.10", now),
    Some(15)
  );
  assert_eq!(
    table.locked_at(AdminLogin, Internal, "100.64.0.7", now),
    None
  );
  assert_eq!(
    table.locked_at(AdminLogin, Public, key, now + LOCKOUT),
    None
  );
}

#[test]
fn gate_locks_only_the_failing_source() {
  let mut table = LockoutTable::default();
  let now = Instant::now();
  let key = "203.0.113.7";
  let alerts = (0..25)
    .filter_map(|_| table.record_at(GateKey, Public, key, now))
    .collect::<Vec<_>>();
  assert_eq!(alerts.len(), 1);
  assert_eq!(
    (alerts[0].kind, alerts[0].count),
    (LockKind::PerIp, 10)
  );
  assert_eq!(table.locked_at(GateKey, Public, key, now), Some(15));
  assert_eq!(
    table.locked_at(GateKey, Public, "203.0.113.8", now),
    None
  );
  assert_eq!(table.locked_at(AdminLogin, Public, key, now), None);
  table.clear(GateKey, Public, key);
  assert_eq!(table.locked_at(GateKey, Public, key, now), None);
}

#[tokio::test]
async fn lockout_notice_records_alert_history() {
  let state = AppState {
    db: crate::db::Db::memory(),
    hub: Default::default(),
    key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]).into(),
    runs: Default::default(),
    locks: Default::default(),
    public_url: None,
    agent_image: String::new(),
    listen_port: 7700,
    data_dir: Default::default(),
    downloads: Default::default(),
    safe_mode: Default::default(),
    resumed_at: Default::default(),
    edge_syncing: Default::default(),
    cleanup_cache: Default::default(),
  };
  let mut table = LockoutTable::default();
  let now = Instant::now();
  let event = (0..10)
    .find_map(|_| {
      table.record_at(GateKey, Public, "203.0.113.9", now)
    })
    .unwrap();
  notify(&state, event, Some("a.example.test")).await;
  let title = state.db.call(|c| c.query_row(
    "SELECT title FROM alert_history WHERE source = 'login_lockout' AND ok = 0",
    [], |row| row.get::<_, String>(0),
  ).map_err(crate::db::sql_err)).await.unwrap();
  assert!(title.contains("门禁访问凭证触发锁定"));
}
