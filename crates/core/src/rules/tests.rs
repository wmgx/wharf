use std::sync::Arc;

use chrono::TimeZone;
use serde_json::json;
use wharf_api_types::view::AlertSuppressionRequest;

use super::*;
use crate::db;

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
    key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]).into(),
    runs: Default::default(),
    locks: Default::default(),
    public_url: None,
    agent_image: String::new(),
    listen_port: 7700,
    data_dir: Default::default(),
    downloads: Default::default(),
    edge_syncing: Default::default(),
  })
}

pub(crate) fn test_state() -> Arc<AppState> {
  state_with_db(db::Db::memory())
}

pub(crate) async fn notice_titles(
  state: &AppState,
  source: &'static str,
) -> Vec<String> {
  state.db.call(move |c| {
    let mut stmt = c.prepare("SELECT title FROM alert_history WHERE source = ?1 ORDER BY id").map_err(db::sql_err)?;
    stmt.query_map([source], |row| row.get(0))
      .and_then(Iterator::collect)
      .map_err(db::sql_err)
  }).await.unwrap()
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

#[tokio::test]
async fn stopping_service_clears_alert_state_and_keeps_history() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  let old = state
    .db
    .call(|c| World::from_rows(db::all_resources(c)?))
    .await
    .unwrap();
  let mut before = old.clone();
  before.routes.insert(
    "app.example.com".into(),
    crate::world::RouteRow {
      id: "fixture".into(),
      spec: serde_json::from_value(
        json!({"hostname": "app.example.com", "service": "web"}),
      )
      .unwrap(),
      version: 1,
    },
  );
  let mut after = before.clone();
  after.services.get_mut("web").unwrap().spec.stopped = true;
  assert!(lifecycle::stopped_route(
    &after,
    &after.routes["app.example.com"].spec
  ));

  observe_at(&state, 10, "cert.days", "app.example.com", 2.0, "")
    .await;
  observe_at(&state, 10, "cert.days", "other.example.com", 2.0, "")
    .await;
  state.db.call(|c| {
    c.execute("INSERT INTO alert_acks (rule, subject, by_actor, at) VALUES ('cert_expiring', 'app.example.com', 'fixture', 10)", []).map_err(db::sql_err)?;
    db::set_setting(c, "notify.state.restart.web", Some("fail"))
  }).await.unwrap();
  let changes = lifecycle::Changes::between(&before, &after);
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      changes.clear_storage(&tx)?;
      tx.commit().map_err(db::sql_err)?;
      changes.clear_after_commit();
      Ok(())
    })
    .await
    .unwrap();

  reset_memory();
  ensure_loaded(&state).await;
  assert!(firing_since("cert_expiring", "app.example.com").is_none());
  assert!(
    firing_since("cert_expiring", "other.example.com").is_some()
  );
  assert!(!with(|m| m.acks.contains_key(&(
    "cert_expiring".into(),
    "app.example.com".into()
  ))));
  state.db.call(|c| {
    let digest: i64 = c.query_row("SELECT count(*) FROM alert_digest WHERE subject = 'app.example.com'", [], |r| r.get(0)).map_err(db::sql_err)?;
    assert_eq!(digest, 0);
    assert!(db::setting(c, "notify.state.cert.app.example.com")?.is_none());
    assert!(db::setting(c, "notify.state.restart.web")?.is_none());
    Ok(())
  }).await.unwrap();
  assert_eq!(history_rows(&state).await.len(), 2);
}

#[tokio::test]
async fn controlled_operation_suppresses_only_matching_transient_samples()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let guard = state
    .locks
    .acquire(crate::locks::LockSpec::apply(["web".into()]), "部署")
    .unwrap();
  guard.silence_alerts(
    [op_silence::Target::Service("web".into())].into(),
    "部署 web".into(),
  );
  for subject in ["web", "other"] {
    for _ in 0..3 {
      observe(&state, "port.ok", subject, 0.0, "").await;
    }
  }
  assert!(firing_since("port_down", "web").is_none());
  assert!(firing_since("port_down", "other").is_some());
  observe(&state, "container.oom", "web", 1.0, "").await;
  assert!(firing_since("oom_killed", "web").is_some());

  with(|m| {
    m.config.entry(op_silence::ID.into()).or_default().enabled =
      Some(false)
  });
  for _ in 0..3 {
    observe(&state, "port.ok", "web", 0.0, "").await;
  }
  assert!(firing_since("port_down", "web").is_some());
}

#[tokio::test]
async fn vendor_oauth_delete_clears_without_fake_recovery_and_external_issues()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  observe(&state, "vendor.invalid", "Tailscale OAuth", 1.0, "").await;
  observe(&state, "external.incident", "GitHub", 1.0, "").await;
  let mut snap = crate::snapshot::Snapshot::default();
  snap
    .secrets
    .insert(crate::tailscale::OAUTH_SECRET.into(), "fixture".into());
  let issues = crate::external_checks::issues(&[], &snap);
  for code in ["vendor_token_invalid", "external_incident"] {
    assert!(
      issues.iter().any(|i| i.code == code && i.alert.is_some())
    );
  }
  let history = history_rows(&state).await.len();
  crate::vendor_checks::record(
    &state,
    &[crate::doctor::check(
      "vendor",
      "Tailscale OAuth",
      wharf_api_types::view::CheckStatus::Skip,
      "",
    )],
  )
  .await;
  lifecycle::clear(&state, "external_incident", "GitHub").await;
  assert!(
    firing_since("vendor_token_invalid", "Tailscale OAuth").is_none()
  );
  assert!(firing_since("external_incident", "GitHub").is_none());
  assert_eq!(history_rows(&state).await.len(), history);
  state
    .db
    .call(|c| {
      assert_eq!(
        c.query_row("SELECT count(*) FROM alert_digest", [], |r| r
          .get::<_, i64>(
          0
        ))
        .map_err(db::sql_err)?,
        0
      );
      db::set_setting(
        c,
        "notify.state.external.incident.github",
        Some("fail"),
      )?;
      db::set_setting(
        c,
        "notify.state.agent.mem.high.s1",
        Some("fail"),
      )
    })
    .await
    .unwrap();
  lifecycle::clear(&state, "external_incident", "GitHub").await;
  retain_subjects(&state, "server_offline", &BTreeSet::new()).await;
  state
    .db
    .call(|c| {
      assert!(
        db::setting(c, "notify.state.external.incident.github")?
          .is_none()
      );
      assert_eq!(
        db::setting(c, "notify.state.agent.mem.high.s1")?.as_deref(),
        Some("fail")
      );
      Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn host_unit_unwatch_clears_alert_and_issues_reads_engine() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  let snap = crate::snapshot::load(&state.db).await.unwrap();
  observe(&state, "hostunit.running", "s1:db.service", 0.0, "").await;
  assert_eq!(crate::host_units::issues(&snap.world).len(), 1);
  lifecycle::reconcile_world(&state, snap).await.unwrap();
  assert!(firing_since("host_unit_down", "s1:db.service").is_none());
  observe(&state, "hostunit.running", "s1:db.service", 0.0, "").await;
  assert_eq!(
    history_rows(&state)
      .await
      .iter()
      .filter(|r| r.0 == "host_unit_down")
      .count(),
    2
  );
}

#[tokio::test]
async fn deleting_service_route_server_and_clearing_limits_purge_all_alerts()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  let mut world =
    crate::snapshot::load(&state.db).await.unwrap().world;
  world.services.get_mut("web").unwrap().spec.limits =
    serde_json::from_value(json!({"memory_mb": 64})).unwrap();
  custom::add_rule(
    &state,
    wharf_api_types::view::CustomAlertRuleRequest {
      name: "mem-high".into(),
      service: "web".into(),
      metric: "mem_pct".into(),
      op: ">".into(),
      threshold: 50.0,
      for_n: 1,
      level: AlertLevel::Urgent,
    },
    now_ms(),
  )
  .await
  .unwrap();
  let mut without_limit = world.clone();
  without_limit.services.get_mut("web").unwrap().spec.limits =
    Default::default();
  observe(&state, "svc.mem_pct", "web", 99.0, "").await;
  assert!(firing_since("mem-high", "web").is_some());
  let changes = lifecycle::Changes::between(&world, &without_limit);
  state
    .db
    .call(move |c| {
      changes.clear_storage(c)?;
      changes.clear_after_commit();
      Ok(())
    })
    .await
    .unwrap();
  assert!(firing_since("mem-high", "web").is_none());

  observe(&state, "container.oom", "web", 1.0, "").await;
  observe(&state, "cert.days", "gone.example.com", 2.0, "").await;
  observe(&state, "disk.days_left", "gone", 1.0, "").await;
  lifecycle::reconcile_world(
    &state,
    crate::snapshot::Snapshot::default(),
  )
  .await
  .unwrap();
  for (name, subject) in [
    ("oom_killed", "web"),
    ("cert_expiring", "gone.example.com"),
    ("disk_forecast", "gone"),
  ] {
    assert!(firing_since(name, subject).is_none());
  }
  observe(&state, "container.oom", "web", 1.0, "").await;
  assert!(firing_since("oom_killed", "web").is_some());
  assert_eq!(
    history_rows(&state)
      .await
      .iter()
      .filter(|r| r.0 == "oom_killed")
      .count(),
    2
  );
}

#[tokio::test]
async fn probe_and_monitor_issues_follow_rule_for_n_and_enabled() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  let mut world =
    crate::snapshot::load(&state.db).await.unwrap().world;
  world.services.get_mut("web").unwrap().spec.monitor =
    Some(serde_json::from_value(json!({"path": "/health"})).unwrap());
  world.routes.insert(
    "app.example.com".into(),
    crate::world::RouteRow {
      id: "fixture".into(),
      version: 1,
      spec: serde_json::from_value(
        json!({"hostname":"app.example.com","service":"web"}),
      )
      .unwrap(),
    },
  );
  ensure_loaded(&state).await;
  with(|m| {
    m.config.entry("domain_down".into()).or_default().for_n = Some(5);
    m.config.entry("monitor_failed".into()).or_default().enabled =
      Some(false);
  });
  for _ in 0..3 {
    observe(&state, "probe.ok", "app.example.com", 0.0, "").await;
    observe(&state, "monitor.ok", "web", 0.0, "").await;
  }
  assert!(crate::probe::issues(&world).is_empty());
  assert!(crate::monitor::issues(&world).is_empty());
  for _ in 0..2 {
    observe(&state, "probe.ok", "app.example.com", 0.0, "").await;
  }
  assert_eq!(crate::probe::issues(&world).len(), 1);
}

#[tokio::test]
async fn firing_refreshes_certificate_text_and_suppression_rejects_cycle()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  observe_at(&state, 1, "cert.days", "app.example.com", 2.0, "")
    .await;
  observe_at(&state, 2, "cert.days", "app.example.com", -3.0, "")
    .await;
  assert_eq!(
    firing_since("cert_expiring", "app.example.com"),
    Some(1)
  );
  assert!(
    firing_subjects("cert_expiring")[0]
      .1
      .contains("已过期 3 天")
  );
  let edge = |source: &str, target: &str| AlertSuppressionRequest {
    source_rule: source.into(),
    target_rule: target.into(),
    source_subject: None,
    target_subject: None,
  };
  suppress::add_rule(
    &state,
    edge("cert_expiring", "monitor_failed"),
    3,
  )
  .await
  .unwrap();
  assert!(
    suppress::add_rule(
      &state,
      edge("monitor_failed", "cert_expiring"),
      4
    )
    .await
    .is_err()
  );
  for _ in 0..3 {
    observe_at(&state, 5, "monitor.ok", "web", 0.0, "").await;
  }
  assert!(
    history_rows(&state)
      .await
      .last()
      .unwrap()
      .3
      .as_deref()
      .unwrap()
      .starts_with("被抑制：")
  );
  lifecycle::clear(&state, "cert_expiring", "app.example.com").await;
  assert!(delivered(&history_rows(&state).await.last().unwrap().3));
}

#[tokio::test]
async fn expired_service_mute_global_disable_and_subpath_suppress() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  seed_server_service(&state, "s2", "api").await;
  let mut world =
    crate::snapshot::load(&state.db).await.unwrap().world;
  world.routes.insert("app.example.com".into(), crate::world::RouteRow {
    id: "fixture".into(), version: 1,
    spec: serde_json::from_value(json!({
      "hostname":"app.example.com","service":"web","paths":[{"path":"/api/*","service":"api"}]
    })).unwrap(),
  });
  let now = now_ms();
  let global = Override {
    muted_until: Some(now + 60_000),
    ..Default::default()
  };
  let past = Override {
    muted_until: Some(now - 1),
    ..Default::default()
  };
  assert_eq!(
    service_overrides::effective_override(
      Some(&global),
      Some(&past),
      now
    )
    .muted_until,
    global.muted_until
  );
  assert!(
    suppress::related_servers(
      "domain_down",
      "app.example.com",
      &world,
      &BTreeMap::new()
    )
    .contains(&"s2".into())
  );
  service_overrides::set_override(
    &state,
    "http_5xx",
    "web",
    wharf_api_types::view::AlertPatch {
      enabled: Some(true),
      ..Default::default()
    },
    now,
  )
  .await
  .unwrap();
  for name in ["web", "api"] {
    observe(&state, "req.err_pct_5m", name, 25.0, "").await;
  }
  api::patch(
    axum::extract::State(state.clone()),
    crate::host_access::tests::auth(
      [wharf_api_types::view::Perm::Admin],
      false,
    ),
    axum::extract::Path("http_5xx".into()),
    axum::Json(wharf_api_types::view::AlertPatch {
      enabled: Some(false),
      ..Default::default()
    }),
  )
  .await
  .unwrap();
  assert!(firing_since("http_5xx", "web").is_some());
  assert!(firing_since("http_5xx", "api").is_none());
  service_overrides::set_override(
    &state,
    "http_5xx",
    "web",
    wharf_api_types::view::AlertPatch {
      reset: true,
      ..Default::default()
    },
    now,
  )
  .await
  .unwrap();
  assert!(firing_since("http_5xx", "web").is_none());
}

#[tokio::test]
async fn stopped_service_route_skipped_in_bg_doctor_and_clears_domain_down()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  seed_server_service(&state, "s1", "api").await;
  state.db.call(|c| {
    c.execute("UPDATE resources SET spec = json_set(spec, '$.stopped', json('true')) WHERE kind = 'service' AND name = 'web'", []).map_err(db::sql_err)?;
    db::apply_write(c, &db::Write::Upsert {
      kind: "route".into(), name: "app.example.com".into(),
      spec: json!({"hostname":"app.example.com","service":"web"}), meta: json!({}),
    })
  }).await.unwrap();
  let background =
    crate::doctor::run(&state, None, false, None).await.unwrap();
  assert!(background.routes.is_empty());
  let manual =
    crate::doctor::run(&state, Some("app.example.com"), true, None)
      .await
      .unwrap();
  assert!(manual.routes[0].checks.iter().any(|c| c.layer == "https"
    && c.status == wharf_api_types::view::CheckStatus::Skip));
  for _ in 0..3 {
    observe(&state, "probe.ok", "app.example.com", 0.0, "").await;
  }
  crate::probe::observe(&state, &background).await;
  assert!(firing_since("domain_down", "app.example.com").is_none());
  let mut world =
    crate::snapshot::load(&state.db).await.unwrap().world;
  world.routes.get_mut("app.example.com").unwrap().spec.paths =
    serde_json::from_value(
      json!([{"path":"/api/*","service":"api"}]),
    )
    .unwrap();
  assert!(!lifecycle::stopped_route(
    &world,
    &world.routes["app.example.com"].spec
  ));
  world.edge_apps.insert("edge".into(), crate::world::EdgeRow {
    spec: serde_json::from_value(json!({"account":"fixture","kind":"worker","domains":["edge.example.com"]})).unwrap(),
    version: 1,
  });
  assert!(lifecycle::active_route(
    &world,
    "edge.example.com",
    now_ms()
  ));
}

#[tokio::test]
async fn op_silence_blocks_transient_during_backup_and_alerts_if_still_broken_after()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let lock = state
    .locks
    .acquire(crate::locks::LockSpec::Backup("web".into()), "备份 web")
    .unwrap();
  lock.silence_alerts(
    [op_silence::Target::Service("web".into())].into(),
    "备份 web".into(),
  );
  for _ in 0..4 {
    observe(&state, "monitor.ok", "web", 0.0, "").await;
  }
  assert!(firing_since("monitor_failed", "web").is_none());
  assert!(!with(|m| m
    .series
    .contains_key(&("monitor.ok".into(), "web".into()))));
  let rows = history_rows(&state).await;
  assert_eq!(rows.len(), 1);
  assert_eq!(rows[0].3.as_deref(), Some("被抑制：备份 web"));
  lock.finish_silence(false);
  drop(lock);
  let after = now_ms() + 16_000;
  for (i, expected) in [false, false, true].into_iter().enumerate() {
    observe_at(
      &state,
      after + i as i64,
      "monitor.ok",
      "web",
      0.0,
      "",
    )
    .await;
    assert_eq!(
      firing_since("monitor_failed", "web").is_some(),
      expected
    );
  }
  assert!(delivered(&history_rows(&state).await.last().unwrap().3));
}

#[tokio::test]
async fn op_silence_preserves_prefiring_and_recovers_when_heal_fixes()
{
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  for _ in 0..3 {
    observe(&state, "monitor.ok", "web", 0.0, "").await;
  }
  let since = firing_since("monitor_failed", "web").unwrap();
  let lock = state
    .locks
    .acquire(
      crate::locks::LockSpec::apply(["web".into()]),
      "重启 web",
    )
    .unwrap();
  lock.silence_alerts(
    [op_silence::Target::Service("web".into())].into(),
    "自动自愈：重启 web".into(),
  );
  observe(&state, "monitor.ok", "web", 0.0, "").await;
  assert_eq!(firing_since("monitor_failed", "web"), Some(since));
  lock.finish_silence(true);
  drop(lock);
  observe(&state, "monitor.ok", "web", 1.0, "").await;
  assert!(firing_since("monitor_failed", "web").is_none());
  assert!(history_rows(&state).await.last().unwrap().2);
}

#[tokio::test]
async fn disabling_one_expiry_rule_preserves_shared_samples() {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  observe_at(
    &state,
    1,
    "expiry.days",
    "domain:app.example.com",
    2.0,
    "",
  )
  .await;
  retain_subjects(&state, "expiry_soon", &BTreeSet::new()).await;
  assert!(with(|m| m.series.contains_key(&(
    "expiry.days".into(),
    "domain:app.example.com".into()
  ))));
}

#[tokio::test]
async fn gateway_http_only_clears_stale_certificate_without_clearing_domain()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  state.db.call(|c| {
    for (kind, name, spec) in [
      ("gateway", "entry", json!({"server":"s1", "kind":"caddy", "tls":"off"})),
      ("route", "app.example.com", json!({"hostname":"app.example.com","service":"web","gateway":"entry"})),
    ] {
      db::apply_write(c, &db::Write::Upsert {
        kind: kind.into(), name: name.into(), spec, meta: json!({}),
      })?;
    }
    Ok(())
  }).await.unwrap();
  let snap = crate::snapshot::load(&state.db).await.unwrap();
  assert!(!lifecycle::route_has_tls(&snap.world, "app.example.com"));
  observe(&state, "cert.days", "app.example.com", 2.0, "").await;
  for _ in 0..3 {
    observe(&state, "probe.ok", "app.example.com", 0.0, "").await;
  }
  lifecycle::reconcile_world(&state, snap).await.unwrap();
  assert!(firing_since("cert_expiring", "app.example.com").is_none());
  assert!(firing_since("domain_down", "app.example.com").is_some());
}

#[tokio::test]
async fn tailnet_and_gateway_operations_silence_only_matching_samples()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  state.db.call(|c| {
    for (kind, name, spec) in [
      ("gateway", "entry", json!({"server":"s1", "kind":"caddy", "tls":"off"})),
      ("route", "app.example.com", json!({"hostname":"app.example.com","service":"web","gateway":"entry"})),
    ] {
      db::apply_write(c, &db::Write::Upsert {
        kind: kind.into(), name: name.into(), spec, meta: json!({}),
      })?;
    }
    Ok(())
  }).await.unwrap();
  let steps = [
    crate::planner::Step::TailscaleUp {
      server: "s1".into(),
    },
    crate::planner::Step::GatewaySync {
      gateway: "entry".into(),
      expect: None,
    },
  ]
  .map(|step| crate::planner::StepPlan {
    step,
    items: vec![],
    title: "部署".into(),
  });
  let lock = state
    .locks
    .acquire(crate::locks::LockSpec::apply([]), "部署")
    .unwrap();
  lock.silence_alerts(op_silence::steps_scope(&steps), "部署".into());
  for _ in 0..3 {
    observe(&state, "probe.ok", "app.example.com", 0.0, "").await;
    observe(&state, "server.online", "s1", 0.0, "").await;
    observe(&state, "server.online", "s2", 0.0, "").await;
  }
  assert!(firing_since("domain_down", "app.example.com").is_none());
  assert!(firing_since("server_offline", "s1").is_none());
  assert!(firing_since("server_offline", "s2").is_some());
}
