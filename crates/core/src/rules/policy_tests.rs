use super::super::tests::notification_db;
use super::*;

const NOW: i64 = 10_000_000;

fn request() -> AlertAckRequest {
  AlertAckRequest {
    rule: "server_offline".into(),
    subject: "box".into(),
    acked: true,
    note: Some("正在处理".into()),
  }
}

fn acknowledged() -> Connection {
  let c = notification_db();
  c.execute("INSERT INTO alert_firing VALUES ('server_offline', 'box', ?1, '离线')", [NOW]).unwrap();
  let ack =
    write_ack(&c, request(), "operator", NOW).unwrap().unwrap();
  assert_eq!(ack.by, "operator");
  assert_eq!(ack.note.as_deref(), Some("正在处理"));
  c
}

fn offline(c: &Connection, now: i64, ok: bool) -> Decision {
  let o = Override::default();
  let g = guard(
    &o,
    is_acked(c, "server_offline", "box", now).unwrap(),
    now,
  );
  decide(g, None, o.level("server_offline"), ok, None)
}

#[test]
fn ack_skips_recovery_and_refire_at_59_minutes() {
  let c = acknowledged();
  let recovered = NOW + 1000;
  update_ack(&c, "server_offline", "box", false, recovered).unwrap();
  assert_eq!(
    offline(&c, recovered, true),
    Decision::Skip("已确认".into())
  );
  let refire = recovered + 59 * 60_000;
  update_ack(&c, "server_offline", "box", true, refire).unwrap();
  assert_eq!(
    offline(&c, refire, false),
    Decision::Skip("已确认".into())
  );
  let recovered_again = refire + 1000;
  update_ack(&c, "server_offline", "box", false, recovered_again)
    .unwrap();
  assert_eq!(
    offline(&c, recovered_again + 59 * 60_000, false),
    Decision::Skip("已确认".into())
  );
}

#[test]
fn ack_expires_after_61_continuously_recovered_minutes() {
  let c = acknowledged();
  update_ack(&c, "server_offline", "box", false, NOW + 1000).unwrap();
  let refire = NOW + 1000 + 61 * 60_000;
  update_ack(&c, "server_offline", "box", true, refire).unwrap();
  assert_eq!(offline(&c, refire, false), Decision::Send);
  assert_eq!(
    c.query_row("SELECT COUNT(*) FROM alert_ack", [], |r| r
      .get::<_, i64>(0))
      .unwrap(),
    0
  );
}

#[test]
fn ack_rejects_non_firing_alert() {
  let c = notification_db();
  let error = write_ack(&c, request(), "operator", NOW).unwrap_err();
  assert_eq!(error.code, wharf_api_types::ErrorCode::NotFound);
  assert_eq!(error.hint.as_deref(), Some("wharf alert firing"));
}

#[test]
fn digest_level_queues_the_trigger() {
  let c = notification_db();
  let id = "disk_forecast";
  let o = Override::default();
  assert_eq!(
    decide(None, None, o.level(id), false, None),
    Decision::Digest
  );
  persist(
    &c,
    Delivery {
      id,
      subject: Some("box"),
      paired: true,
      ok: false,
      now: NOW,
      replay: false,
    },
    &ev("磁盘预测".into(), String::new()),
    Some(DIGEST_SKIP),
    None,
  )
  .unwrap();
  let skipped: String = c
    .query_row("SELECT skipped FROM alert_history", [], |r| r.get(0))
    .unwrap();
  assert_eq!(skipped, DIGEST_SKIP);
  assert!(
    super::super::digest::preview(&c)
      .unwrap()
      .unwrap()
      .contains("仍在触发")
  );
}

#[test]
fn digest_marks_recovery_before_send() {
  let c = notification_db();
  let mut d = Delivery {
    id: "disk_forecast",
    subject: Some("box"),
    paired: true,
    ok: false,
    now: NOW,
    replay: false,
  };
  let event = ev("磁盘预测".into(), String::new());
  persist(&c, d, &event, Some(DIGEST_SKIP), None).unwrap();
  let previous = episode(&c, d.id, "box").unwrap().unwrap();
  assert_eq!(
    decide(None, None, AlertLevel::Urgent, true, Some(&previous)),
    Decision::Digest
  );
  d.ok = true;
  d.now += 60_000;
  persist(&c, d, &event, Some(DIGEST_SKIP), Some(&previous)).unwrap();
  let body = super::super::digest::preview(&c).unwrap().unwrap();
  assert_eq!(body.matches("box").count(), 1);
  assert!(body.contains("已恢复（"));
}

#[test]
fn mute_has_precedence_over_digest() {
  let c = notification_db();
  let d = Delivery {
    id: "disk_forecast",
    subject: Some("box"),
    paired: true,
    ok: false,
    now: NOW,
    replay: false,
  };
  let o = Override {
    muted_until: Some(NOW + 60_000),
    ..Override::default()
  };
  let decision =
    decide(guard(&o, false, NOW), None, o.level(d.id), false, None);
  let Decision::Skip(reason) = decision else {
    panic!("应跳过静默告警")
  };
  assert_eq!(reason, "静默中");
  persist(
    &c,
    d,
    &ev("磁盘预测".into(), String::new()),
    Some(&reason),
    None,
  )
  .unwrap();
  assert_eq!(super::super::digest::preview(&c).unwrap(), None);
}

#[test]
fn suppressed_fire_has_no_recovery_delivery() {
  let c = notification_db();
  let mut d = Delivery {
    id: "monitor_failed",
    subject: Some("web"),
    paired: true,
    ok: false,
    now: NOW,
    replay: false,
  };
  let event = ev("监控失败".into(), String::new());
  persist(&c, d, &event, Some("被抑制：服务器离线"), None).unwrap();
  let previous = episode(&c, d.id, "web").unwrap().unwrap();
  d.ok = true;
  d.now += 60_000;
  let Decision::Skip(reason) =
    decide(None, None, AlertLevel::Urgent, true, Some(&previous))
  else {
    panic!("未通知触发时应跳过恢复");
  };
  assert_eq!(reason, "被抑制：服务器离线");
  persist(&c, d, &event, Some(&reason), Some(&previous)).unwrap();
  assert!(episode(&c, d.id, "web").unwrap().is_none());
}
