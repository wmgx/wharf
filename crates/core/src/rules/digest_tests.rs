use super::super::tests::notification_db;
use super::*;

fn stamp(time: &str) -> i64 {
  chrono::DateTime::parse_from_rfc3339(time)
    .unwrap()
    .timestamp_millis()
}

fn enqueue(c: &Connection) {
  c.execute(
    "INSERT INTO alert_digest (source, at, title, paired) VALUES ('update', ?1, 'web 有新版本', 0)",
    [stamp("2026-11-25T07:55:00+08:00")],
  ).unwrap();
}

#[test]
fn digest_sends_at_nine_only_once() {
  let c = notification_db();
  enqueue(&c);
  assert!(
    claim(&c, stamp("2026-11-25T08:59:00+08:00"))
      .unwrap()
      .is_none()
  );
  assert!(
    claim(&c, stamp("2026-11-25T09:00:00+08:00"))
      .unwrap()
      .unwrap()
      .contains("web 有新版本")
  );
  assert!(
    claim(&c, stamp("2026-11-25T09:01:00+08:00"))
      .unwrap()
      .is_none()
  );
}

#[test]
fn digest_empty_slot_does_not_send_late_arrivals() {
  let c = notification_db();
  assert!(
    claim(&c, stamp("2026-11-25T09:00:00+08:00"))
      .unwrap()
      .is_none()
  );
  enqueue(&c);
  assert!(
    claim(&c, stamp("2026-11-25T09:01:00+08:00"))
      .unwrap()
      .is_none()
  );
  assert!(
    claim(&c, stamp("2026-11-26T09:00:00+08:00"))
      .unwrap()
      .is_some()
  );
}

#[test]
fn digest_catches_up_once_after_restart() {
  let before_restart = notification_db();
  enqueue(&before_restart);
  assert!(
    claim(&before_restart, stamp("2026-11-25T08:59:00+08:00"))
      .unwrap()
      .is_none()
  );

  // 调度器重启后只看同一 SQLite 里的队列和日期。
  assert!(
    claim(&before_restart, stamp("2026-11-25T10:00:00+08:00"))
      .unwrap()
      .is_some()
  );
  assert_eq!(
    db::setting(&before_restart, LAST).unwrap().as_deref(),
    Some("2026-11-25")
  );
  assert!(
    claim(&before_restart, stamp("2026-11-25T10:01:00+08:00"))
      .unwrap()
      .is_none()
  );
}
