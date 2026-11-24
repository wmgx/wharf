use chrono::TimeZone;
use wharf_api_types::view::{AlertAckRequest, AlertSuppressRequest};

use super::*;
use crate::state::AppState;

static TEST_LOCK: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

fn test_state() -> AppState {
  AppState {
    db: crate::db::Db::memory(),
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
  }
}

async fn seed_server_services(
  state: &AppState,
  server: &str,
  services: &[&str],
) {
  let s = server.to_string();
  let svcs: Vec<String> =
    services.iter().map(|x| (*x).to_string()).collect();
  state
    .db
    .call(move |c| {
      crate::db::apply_write(
        c,
        &crate::db::Write::Upsert {
          kind: crate::world::KIND_SERVER.into(),
          name: s.clone(),
          spec: serde_json::json!({}),
          meta: serde_json::json!({}),
        },
      )?;
      for svc in svcs {
        crate::db::apply_write(
          c,
          &crate::db::Write::Upsert {
            kind: crate::world::KIND_SERVICE.into(),
            name: svc,
            spec: serde_json::json!({
              "server": s,
              "source": { "image": "nginx" }
            }),
            meta: serde_json::json!({}),
          },
        )?;
      }
      Ok(())
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
        .prepare("SELECT source, subject, ok, skipped FROM alert_history ORDER BY id ASC")
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

fn bj_ms(
  year: i32,
  month: u32,
  day: u32,
  hour: u32,
  min: u32,
) -> i64 {
  digest::beijing()
    .with_ymd_and_hms(year, month, day, hour, min, 0)
    .unwrap()
    .timestamp_millis()
}

fn rule(id: &str) -> &'static Rule {
  RULES.iter().find(|r| r.id == id).unwrap()
}

fn v(points: &[f64]) -> VecDeque<f64> {
  points.iter().copied().collect()
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
async fn ack_suppresses_flapping_and_expires_after_one_hour() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let min = 60_000i64;
  let t0 = 1_700_000_000_000i64;

  // 触发并推送（测试库未配通知渠道，skipped 为"没有配置通知渠道"表示策略已放行）。
  observe_at(&state, t0, "req.err_pct_5m", "web", 15.0, "").await;
  ack::ack_at(
    &state,
    "admin",
    AlertAckRequest {
      rule: "http_5xx".into(),
      subject: "web".into(),
      note: Some("已知问题".into()),
    },
    t0,
  )
  .await
  .unwrap();

  // 恢复 -> 被确认跳过。
  let t1 = t0 + min;
  observe_at(&state, t1, "req.err_pct_5m", "web", 1.0, "").await;

  // 恢复满 59 分钟再触发 -> 仍被确认跳过，且恢复计时清零。
  let t2 = t1 + 59 * min;
  observe_at(&state, t2, "req.err_pct_5m", "web", 15.0, "").await;

  // 再次恢复 -> 仍被确认跳过。
  let t3 = t2 + min;
  observe_at(&state, t3, "req.err_pct_5m", "web", 1.0, "").await;

  // 恢复满 61 分钟再触发 -> 确认已失效，重新推送。
  let t4 = t3 + 61 * min;
  observe_at(&state, t4, "req.err_pct_5m", "web", 15.0, "").await;

  let rows = history_rows(&state).await;
  let skipped: Vec<Option<&str>> =
    rows.iter().map(|r| r.3.as_deref()).collect();
  assert_eq!(
    skipped,
    [
      Some("没有配置通知渠道"),
      Some("已确认"),
      Some("已确认"),
      Some("已确认"),
      Some("没有配置通知渠道"),
    ]
  );
}

#[tokio::test]
async fn ack_non_firing_alert_returns_error() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let err = ack::ack_at(
    &state,
    "admin",
    AlertAckRequest {
      rule: "http_5xx".into(),
      subject: "web".into(),
      note: None,
    },
    1_700_000_000_000,
  )
  .await
  .unwrap_err();
  assert!(
    err
      .hint
      .as_deref()
      .is_some_and(|h| h.contains("wharf alert firing"))
  );
}

#[tokio::test]
async fn digest_schedule_formats_recovery_and_skips_empty() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();

  // disk_forecast 默认是 digest 级别。
  let t_fire = bj_ms(2026, 5, 1, 8, 10);
  let t_ok = bj_ms(2026, 5, 1, 8, 40);
  observe_at(&state, t_fire, "disk.days_left", "s1", 5.0, "").await;
  observe_at(&state, t_ok, "disk.days_left", "s1", 30.0, "").await;

  let rows = history_rows(&state).await;
  assert_eq!(rows.len(), 2);
  assert_eq!(rows[0].3.as_deref(), Some("并入每日汇总"));
  assert_eq!(rows[1].3.as_deref(), Some("并入每日汇总"));

  // 预览应显示"已恢复"。
  let pending = digest::load_pending(&state).await.unwrap();
  let (_, body) =
    digest::format_digest("2026-05-01", &pending).unwrap();
  assert!(body.contains("s1"));
  assert!(body.contains("已恢复（08:40）"));

  // 08:59 不发，09:00 发，09:01 不重复。
  assert!(
    !digest::tick_at(&state, bj_ms(2026, 5, 1, 8, 59))
      .await
      .unwrap()
  );
  assert!(
    digest::tick_at(&state, bj_ms(2026, 5, 1, 9, 0))
      .await
      .unwrap()
  );
  assert!(
    !digest::tick_at(&state, bj_ms(2026, 5, 1, 9, 1))
      .await
      .unwrap()
  );

  let rows = history_rows(&state).await;
  assert_eq!(rows.len(), 3);
  assert_eq!(rows[2].0, "digest");

  // 次日空内容不发。
  assert!(
    !digest::tick_at(&state, bj_ms(2026, 5, 2, 9, 0))
      .await
      .unwrap()
  );
  assert_eq!(history_rows(&state).await.len(), 3);
}

#[tokio::test]
async fn digest_catchup_after_restart_sends_only_once() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();

  observe_at(
    &state,
    bj_ms(2026, 5, 1, 8, 30),
    "disk.days_left",
    "s1",
    5.0,
    "",
  )
  .await;

  // 模拟控制面重启跨过 09:00：10:15 补发一次，10:20 不重复发。
  reset_memory();
  assert!(
    digest::tick_at(&state, bj_ms(2026, 5, 1, 10, 15))
      .await
      .unwrap()
  );
  reset_memory();
  assert!(
    !digest::tick_at(&state, bj_ms(2026, 5, 1, 10, 20))
      .await
      .unwrap()
  );
  let digest_count = history_rows(&state)
    .await
    .into_iter()
    .filter(|r| r.0 == "digest")
    .count();
  assert_eq!(digest_count, 1);
}

#[tokio::test]
async fn suppress_offline_rechecks_on_recovery_and_skips_unpushed_recovery()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_services(&state, "s1", &["web", "api"]).await;
  let min = 60_000i64;
  let t0 = 1_700_000_000_000i64;

  // s1 连续 3 次离线触发 server_offline。
  for i in 0..3 {
    observe_at(&state, t0 + i * min, "server.online", "s1", 0.0, "")
      .await;
  }

  // s1 上的服务 web、api 触发 http_5xx：均被机器离线抑制。
  let t1 = t0 + 3 * min;
  observe_at(&state, t1, "req.err_pct_5m", "web", 20.0, "").await;
  observe_at(&state, t1, "req.err_pct_5m", "api", 20.0, "").await;

  // api 在 s1 仍离线时恢复：触发未推过，恢复也不推。
  let t2 = t1 + min;
  observe_at(&state, t2, "req.err_pct_5m", "api", 1.0, "").await;

  // s1 恢复在线：web 仍在触发，自动补推一次。
  let t3 = t2 + min;
  observe_at(&state, t3, "server.online", "s1", 1.0, "").await;

  let rows = history_rows(&state).await;
  // 0: server_offline fire
  // 1: http_5xx web suppressed
  // 2: http_5xx api suppressed
  // 3: http_5xx api recover -> skipped "触发未推送"
  // 4: server_offline recover
  // 5: http_5xx web recheck pushed
  assert_eq!(rows.len(), 6);
  assert_eq!(rows[0].0, "server_offline");
  assert_eq!(rows[0].3.as_deref(), Some("没有配置通知渠道"));
  assert_eq!(rows[1].0, "http_5xx");
  assert_eq!(rows[1].1.as_deref(), Some("web"));
  assert!(
    rows[1]
      .3
      .as_deref()
      .is_some_and(|s| s.starts_with("被抑制："))
  );
  assert_eq!(rows[2].1.as_deref(), Some("api"));
  assert!(
    rows[2]
      .3
      .as_deref()
      .is_some_and(|s| s.starts_with("被抑制："))
  );
  assert_eq!(rows[3].1.as_deref(), Some("api"));
  assert!(rows[3].2);
  assert_eq!(rows[3].3.as_deref(), Some("触发未推送"));
  assert_eq!(rows[4].0, "server_offline");
  assert!(rows[4].2);
  assert_eq!(rows[5].0, "http_5xx");
  assert_eq!(rows[5].1.as_deref(), Some("web"));
  assert!(!rows[5].2);
  assert_eq!(rows[5].3.as_deref(), Some("没有配置通知渠道"));
}

#[tokio::test]
async fn custom_suppression_blocks_target_until_source_recovers() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let min = 60_000i64;
  let t0 = 1_700_000_000_000i64;

  // 自定义规则：http_5xx:web --ignore oom_killed（任意对象）。
  suppress::add_impl(
    &state,
    AlertSuppressRequest {
      source_rule: "http_5xx".into(),
      source_subject: Some("web".into()),
      target_rule: "oom_killed".into(),
      target_subject: None,
    },
  )
  .await
  .unwrap();

  // A:x 触发 -> B 被抑制。
  observe_at(&state, t0, "req.err_pct_5m", "web", 15.0, "").await;
  observe_at(&state, t0 + min, "container.oom", "api", 1.0, "").await;

  // A:x 恢复 -> B 仍在触发被补推；之后再触发其他 B 不再被抑制。
  observe_at(&state, t0 + 2 * min, "req.err_pct_5m", "web", 1.0, "")
    .await;
  observe_at(
    &state,
    t0 + 3 * min,
    "container.oom",
    "worker",
    1.0,
    "",
  )
  .await;

  let rows = history_rows(&state).await;
  assert_eq!(rows.len(), 5);
  assert_eq!(rows[1].0, "oom_killed");
  assert_eq!(
    rows[1].3.as_deref(),
    Some("被抑制：服务 web 的 5xx 变多")
  );
  assert_eq!(rows[3].0, "oom_killed");
  assert_eq!(rows[3].1.as_deref(), Some("api"));
  assert_eq!(rows[3].3.as_deref(), Some("没有配置通知渠道"));
  assert_eq!(rows[4].0, "oom_killed");
  assert_eq!(rows[4].1.as_deref(), Some("worker"));
  assert_eq!(rows[4].3.as_deref(), Some("没有配置通知渠道"));
}

#[tokio::test]
async fn muted_digest_rule_does_not_enter_digest_queue() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let t0 = bj_ms(2026, 5, 1, 8, 10);

  let cfg = serde_json::json!({
    "disk_forecast": { "muted_until": t0 + 3_600_000 }
  })
  .to_string();
  state
    .db
    .call(move |c| db::set_setting(c, CONFIG_KEY, Some(&cfg)))
    .await
    .unwrap();
  reset_memory();

  observe_at(&state, t0, "disk.days_left", "s1", 5.0, "").await;
  let rows = history_rows(&state).await;
  assert_eq!(rows.len(), 1);
  assert_eq!(rows[0].3.as_deref(), Some("静默中"));
  assert!(digest::load_pending(&state).await.unwrap().is_empty());
}
