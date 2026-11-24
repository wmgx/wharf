use std::sync::Arc;

use chrono::TimeZone;
use serde_json::json;
use wharf_api_types::view::AlertSuppressionRequest;

use super::*;

pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

fn rule(id: &str) -> &'static Rule {
  RULES.iter().find(|r| r.id == id).unwrap()
}

fn v(points: &[f64]) -> VecDeque<f64> {
  points.iter().copied().collect()
}

pub(crate) fn reset_memory() {
  with(|m| *m = Memory::default());
}

fn state_with_db(db: db::Db) -> Arc<AppState> {
  Arc::new(AppState {
    db,
    hub: Default::default(),
    key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]),
    runs: Default::default(),
    apply_lock: Default::default(),
    public_url: None,
    agent_image: String::new(),
    listen_port: 7700,
    data_dir: Default::default(),
    downloads: Default::default(),
    edge_syncing: Default::default(),
  })
}

fn test_state() -> Arc<AppState> {
  state_with_db(db::Db::memory())
}

async fn seed_server_service(
  state: &AppState,
  server: &str,
  service: &str,
) {
  let srv = server.to_string();
  let svc = service.to_string();
  state
    .db
    .call(move |c| {
      db::apply_write(
        c,
        &db::Write::Upsert {
          kind: "server".into(),
          name: srv.clone(),
          spec: json!({}),
          meta: json!({}),
        },
      )?;
      db::apply_write(
        c,
        &db::Write::Upsert {
          kind: "service".into(),
          name: svc,
          spec: json!({
            "server": srv,
            "source": { "image": "nginx:1" }
          }),
          meta: json!({}),
        },
      )
    })
    .await
    .unwrap();
}

async fn history_rows(
  state: &AppState,
) -> Vec<(String, Option<String>, bool, Option<String>)> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT source, subject, ok, skipped FROM alert_history ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      stmt
        .query_map([], |r| {
          Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)
    })
    .await
    .unwrap()
}

fn delivered(skipped: &Option<String>) -> bool {
  skipped.is_none() || skipped.as_deref() == Some("没有配置通知渠道")
}

fn beijing_ms(y: i32, m: u32, d: u32, h: u32, min: u32) -> i64 {
  digest::beijing()
    .with_ymd_and_hms(y, m, d, h, min, 0)
    .single()
    .unwrap()
    .timestamp_millis()
}

#[test]
fn consecutive_fires_after_n_and_recovers_on_good() {
  let r = rule("server_offline");
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[1.0, 0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[0.0, 0.0, 0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, 1.0, 3, &v(&[0.0, 0.0, 1.0])),
    Verdict::Recover
  ));
}

#[test]
fn oom_fires_once_in_a_thirty_sample_window() {
  let r = rule("oom_killed");
  assert_eq!(r.for_n, 1);
  assert!(matches!(r.mode, Mode::Window(30)));
  let event = (r.fire)(&Ctx {
    subject: "web",
    value: 1.0,
    detail: "上限 32 MB",
    threshold: r.threshold,
    for_n: r.for_n,
  });
  assert_eq!(event.title, "服务 web 因内存超限被杀");
}

#[test]
fn window_and_hysteresis() {
  let r = rule("container_restarting");
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[1.0, 0.0, 1.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[1.0, 0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, 1.0, 2, &v(&[0.0, 0.0])),
    Verdict::Recover
  ));
  let h = rule("http_5xx");
  assert!(matches!(judge(h, 10.0, 1, &v(&[12.0])), Verdict::Fire));
  assert!(matches!(judge(h, 10.0, 1, &v(&[5.0])), Verdict::Hold));
  assert!(matches!(judge(h, 10.0, 1, &v(&[1.0])), Verdict::Recover));
}

#[test]
fn service_port_three_failures_and_one_success() {
  let r = rule("port_down");
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0, 0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0, 0.0, 0.0, 1.0])),
    Verdict::Recover
  ));
}

#[test]
fn log_rule_holds_below_threshold_until_window_is_empty() {
  let r = rule("log_keyword");
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[-1.0])),
    Verdict::Hold
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[0.0])),
    Verdict::Fire
  ));
  assert!(matches!(
    judge(r, r.threshold, r.for_n, &v(&[-f64::MAX])),
    Verdict::Recover
  ));
}

#[tokio::test]
async fn ack_suppresses_until_one_hour_quiet_and_rejects_non_firing()
{
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  const MIN: i64 = 60_000;
  let t0 = beijing_ms(2026, 6, 1, 10, 0);

  // 未触发时确认报错，且 hint 给 wharf alert firing。
  let err =
    ack::ack_at(&s, "host_unit_down", "s1:app", "admin", None, t0)
      .await
      .unwrap_err();
  assert!(
    err
      .hint
      .as_deref()
      .unwrap_or("")
      .contains("wharf alert firing")
  );

  // 触发 -> 推送；然后确认。
  observe_at(&s, t0, "hostunit.running", "s1:app", 0.0, "dead").await;
  ack::ack_at(
    &s,
    "host_unit_down",
    "s1:app",
    "admin",
    Some("维护中".into()),
    t0 + MIN,
  )
  .await
  .unwrap();

  // 确认后恢复再触发：都不推。
  observe_at(&s, t0 + 5 * MIN, "hostunit.running", "s1:app", 1.0, "")
    .await;
  observe_at(
    &s,
    t0 + 10 * MIN,
    "hostunit.running",
    "s1:app",
    0.0,
    "",
  )
  .await;

  // 恢复满 59 分钟又触发：计时清零，仍不推。
  observe_at(
    &s,
    t0 + 15 * MIN,
    "hostunit.running",
    "s1:app",
    1.0,
    "",
  )
  .await;
  observe_at(
    &s,
    t0 + 74 * MIN,
    "hostunit.running",
    "s1:app",
    0.0,
    "",
  )
  .await;

  // 恢复满 61 分钟：确认自动失效，再触发要推。
  observe_at(
    &s,
    t0 + 75 * MIN,
    "hostunit.running",
    "s1:app",
    1.0,
    "",
  )
  .await;
  observe_at(
    &s,
    t0 + 136 * MIN,
    "hostunit.running",
    "s1:app",
    0.0,
    "",
  )
  .await;

  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 7);
  assert!(delivered(&rows[0].3));
  for row in &rows[1..6] {
    assert_eq!(row.3.as_deref(), Some("已确认"));
  }
  assert!(delivered(&rows[6].3));
}

#[tokio::test]
async fn digest_batches_sends_at_nine_and_catches_up_once_after_restart()
 {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let db = db::Db::memory();
  let s = state_with_db(db.clone());

  // digest 规则触发不立即推；s2 当天先触发后恢复。
  observe_at(
    &s,
    beijing_ms(2026, 6, 1, 8, 0),
    "disk.days_left",
    "s1",
    5.0,
    "",
  )
  .await;
  observe_at(
    &s,
    beijing_ms(2026, 6, 1, 8, 10),
    "disk.days_left",
    "s2",
    5.0,
    "",
  )
  .await;
  observe_at(
    &s,
    beijing_ms(2026, 6, 1, 8, 30),
    "disk.days_left",
    "s2",
    30.0,
    "",
  )
  .await;

  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 3);
  assert!(
    rows.iter().all(|r| r.3.as_deref() == Some("并入每日汇总"))
  );

  let pv = digest::preview(&s).await.unwrap();
  assert_eq!(pv.count, 2);
  let body = pv.body.unwrap();
  assert!(body.contains("s1") && body.contains("仍在触发"));
  assert!(body.contains("s2") && body.contains("已恢复"));

  // 08:59 不发、09:00 发、09:01 不重复。
  assert!(!digest::tick_at(&s, beijing_ms(2026, 6, 1, 8, 59)).await);
  assert!(digest::tick_at(&s, beijing_ms(2026, 6, 1, 9, 0)).await);
  assert!(!digest::tick_at(&s, beijing_ms(2026, 6, 1, 9, 1)).await);

  let sent = || async {
    history_rows(&s)
      .await
      .into_iter()
      .filter(|r| r.0 == digest::SOURCE_ID)
      .count()
  };
  assert_eq!(sent().await, 1);

  // 次日 09:00 空内容不发。
  assert!(!digest::tick_at(&s, beijing_ms(2026, 6, 2, 9, 0)).await);
  assert_eq!(sent().await, 1);

  // 第三天 08:30 有待汇总内容，重启跨过 09:00 到 09:30 补发一次，再检查不重复。
  observe_at(
    &s,
    beijing_ms(2026, 6, 3, 8, 30),
    "disk.days_left",
    "s2",
    5.0,
    "",
  )
  .await;
  reset_memory();
  let restarted = state_with_db(db);
  assert!(
    digest::tick_at(&restarted, beijing_ms(2026, 6, 3, 9, 30)).await
  );
  assert!(
    !digest::tick_at(&restarted, beijing_ms(2026, 6, 3, 10, 0)).await
  );
  let total = history_rows(&restarted)
    .await
    .into_iter()
    .filter(|r| r.0 == digest::SOURCE_ID)
    .count();
  assert_eq!(total, 2);
}

#[tokio::test]
async fn suppress_offline_flushes_on_recovery_and_skips_unpushed_recovery()
 {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  seed_server_service(&s, "s1", "web").await;
  const MIN: i64 = 60_000;
  let t0 = beijing_ms(2026, 6, 1, 12, 0);

  // 机器 s1 离线（连续 3 次）。
  for i in 0..3 {
    observe_at(&s, t0 + i * MIN, "server.online", "s1", 0.0, "")
      .await;
  }
  // s1 上的服务 web 监控失败：被离线抑制。
  for i in 0..3 {
    observe_at(
      &s,
      t0 + (3 + i) * MIN,
      "monitor.ok",
      "web",
      0.0,
      "timeout",
    )
    .await;
  }
  // s1 恢复在线：web 仍在触发，应补推一次。
  observe_at(&s, t0 + 10 * MIN, "server.online", "s1", 1.0, "").await;

  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 4);
  assert_eq!(rows[0].0, "server_offline");
  assert!(delivered(&rows[0].3));
  assert_eq!(rows[1].0, "monitor_failed");
  assert_eq!(rows[1].3.as_deref(), Some("被抑制：服务器 s1 离线"));
  assert_eq!(rows[2].0, "server_offline");
  assert!(rows[2].2 && delivered(&rows[2].3));
  assert_eq!(rows[3].0, "monitor_failed");
  assert!(!rows[3].2 && delivered(&rows[3].3));

  // web 恢复后再次演示：离线期间触发又恢复，恢复也不推。
  observe_at(&s, t0 + 12 * MIN, "monitor.ok", "web", 1.0, "ok").await;
  for i in 0..3 {
    observe_at(
      &s,
      t0 + (20 + i) * MIN,
      "server.online",
      "s1",
      0.0,
      "",
    )
    .await;
  }
  for i in 0..3 {
    observe_at(
      &s,
      t0 + (23 + i) * MIN,
      "monitor.ok",
      "web",
      0.0,
      "timeout",
    )
    .await;
  }
  observe_at(&s, t0 + 27 * MIN, "monitor.ok", "web", 1.0, "ok").await;
  let rows = history_rows(&s).await;
  let last = rows.last().unwrap();
  assert_eq!(last.0, "monitor_failed");
  assert!(last.2);
  assert_eq!(last.3.as_deref(), Some("被抑制：服务器 s1 离线"));
}

#[tokio::test]
async fn custom_suppression_blocks_until_source_recovers() {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  const MIN: i64 = 60_000;
  let t0 = beijing_ms(2026, 6, 1, 14, 0);

  // 自定义：A:x（host_unit_down:s1:db）触发时忽略 B（monitor_failed 任意对象）。
  suppress::add_rule(
    &s,
    AlertSuppressionRequest {
      source_rule: "host_unit_down".into(),
      source_subject: Some("s1:db".into()),
      target_rule: "monitor_failed".into(),
      target_subject: None,
    },
    t0,
  )
  .await
  .unwrap();

  // A:x 触发。
  observe_at(&s, t0 + MIN, "hostunit.running", "s1:db", 0.0, "dead")
    .await;
  // B 触发 -> 被抑制。
  for i in 0..3 {
    observe_at(
      &s,
      t0 + (2 + i) * MIN,
      "monitor.ok",
      "api",
      0.0,
      "502",
    )
    .await;
  }
  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 2);
  assert_eq!(rows[1].0, "monitor_failed");
  assert_eq!(rows[1].3.as_deref(), Some("被抑制：s1 上的 db 停了"));

  // A:x 恢复 -> B 补推；此后 B 恢复、再次触发均不再受抑制。
  observe_at(
    &s,
    t0 + 6 * MIN,
    "hostunit.running",
    "s1:db",
    1.0,
    "running",
  )
  .await;
  observe_at(&s, t0 + 7 * MIN, "monitor.ok", "api", 1.0, "ok").await;
  for i in 0..3 {
    observe_at(
      &s,
      t0 + (8 + i) * MIN,
      "monitor.ok",
      "api",
      0.0,
      "502",
    )
    .await;
  }
  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 6);
  assert!(delivered(&rows[3].3));
  assert!(rows[4].2 && delivered(&rows[4].3));
  assert!(!rows[5].2 && delivered(&rows[5].3));
}

#[tokio::test]
async fn muted_beats_digest_priority() {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  let t0 = beijing_ms(2026, 6, 1, 8, 0);
  ensure_loaded(&s).await;
  with(|m| {
    m.config.insert(
      "disk_forecast".into(),
      Override {
        muted_until: Some(t0 + 3_600_000),
        ..Default::default()
      },
    );
  });

  observe_at(&s, t0, "disk.days_left", "s1", 5.0, "").await;

  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 1);
  assert_eq!(rows[0].3.as_deref(), Some("静默中"));
  let pv = digest::preview(&s).await.unwrap();
  assert_eq!(pv.count, 0);
  assert!(pv.body.is_none());
}

#[tokio::test]
async fn digest_keeps_rows_on_failure_and_preserves_inflight_inserts()
{
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();

  observe_at(
    &s,
    beijing_ms(2026, 6, 1, 8, 0),
    "disk.days_left",
    "s1",
    5.0,
    "",
  )
  .await;
  assert!(
    digest::tick_at_with(
      &s,
      beijing_ms(2026, 6, 1, 9, 0),
      |_| async { Some("发送失败：超时".into()) }
    )
    .await
  );
  assert_eq!(digest::preview(&s).await.unwrap().count, 1);
  assert!(!digest::tick_at(&s, beijing_ms(2026, 6, 1, 9, 1)).await);

  let s_inflight = s.clone();
  assert!(
    digest::tick_at_with(
      &s,
      beijing_ms(2026, 6, 2, 9, 0),
      move |_| async move {
        observe_at(
          &s_inflight,
          beijing_ms(2026, 6, 2, 9, 0),
          "disk.days_left",
          "s2",
          5.0,
          "",
        )
        .await;
        None
      },
    )
    .await
  );
  let pv = digest::preview(&s).await.unwrap();
  assert_eq!(pv.count, 1);
  let body = pv.body.unwrap();
  assert!(!body.contains("s1") && body.contains("s2"));
}

#[path = "custom_tests.rs"]
mod custom_tests;
