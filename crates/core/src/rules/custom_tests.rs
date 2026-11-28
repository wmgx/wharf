use wharf_api_types::view::{
  AlertLevel, AlertPatch, AlertTarget, CustomAlertRuleRequest,
};

use super::super::{
  api, custom, firing_since, observe_at, service_overrides,
};
use super::{
  TEST_LOCK, beijing_ms, delivered, history_rows, reset_memory,
  seed_server_service, test_state,
};
use crate::{db, world::World};

#[tokio::test]
async fn service_override_threshold_off_and_reset() {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  seed_server_service(&s, "s1", "web").await;
  seed_server_service(&s, "s1", "api").await;
  const MIN: i64 = 60_000;
  let t0 = beijing_ms(2026, 6, 1, 10, 0);

  // 非服务类规则（对象是服务器）不允许按服务覆盖。
  let err = service_overrides::set_override(
    &s,
    "host_cpu_high",
    "web",
    AlertPatch {
      threshold: Some(50.0),
      ..Default::default()
    },
    t0,
  )
  .await
  .unwrap_err();
  assert!(err.message.contains("不是服务"));

  // 给 web 覆盖 http_5xx 阈值为 5.0（全局默认 10.0）。
  service_overrides::set_override(
    &s,
    "http_5xx",
    "web",
    AlertPatch {
      threshold: Some(5.0),
      ..Default::default()
    },
    t0,
  )
  .await
  .unwrap();

  // 同一个值 7.0：web 触发，api 不触发。
  observe_at(&s, t0 + MIN, "req.err_pct_5m", "web", 7.0, "").await;
  observe_at(&s, t0 + MIN, "req.err_pct_5m", "api", 7.0, "").await;
  assert!(firing_since("http_5xx", "web").is_some());
  assert!(firing_since("http_5xx", "api").is_none());

  // 恢复 web。
  observe_at(&s, t0 + 2 * MIN, "req.err_pct_5m", "web", 1.0, "")
    .await;
  assert!(firing_since("http_5xx", "web").is_none());

  // --off 后即使超过全局阈值也不触发。
  service_overrides::set_override(
    &s,
    "http_5xx",
    "web",
    AlertPatch {
      enabled: Some(false),
      ..Default::default()
    },
    t0 + 3 * MIN,
  )
  .await
  .unwrap();
  observe_at(&s, t0 + 4 * MIN, "req.err_pct_5m", "web", 50.0, "")
    .await;
  assert!(firing_since("http_5xx", "web").is_none());

  // --reset 恢复全局：7.0 不触发，15.0（超过全局 10.0）触发。
  service_overrides::set_override(
    &s,
    "http_5xx",
    "web",
    AlertPatch {
      reset: true,
      ..Default::default()
    },
    t0 + 5 * MIN,
  )
  .await
  .unwrap();
  observe_at(&s, t0 + 6 * MIN, "req.err_pct_5m", "web", 7.0, "")
    .await;
  assert!(firing_since("http_5xx", "web").is_none());
  observe_at(&s, t0 + 7 * MIN, "req.err_pct_5m", "web", 15.0, "")
    .await;
  assert!(firing_since("http_5xx", "web").is_some());
}

#[tokio::test]
async fn custom_rule_p95_consecutive_three_and_service_delete_cleanup()
 {
  let _g = TEST_LOCK.lock().await;
  reset_memory();
  let s = test_state();
  seed_server_service(&s, "s1", "web").await;
  const MIN: i64 = 60_000;
  let t0 = beijing_ms(2026, 6, 1, 11, 0);

  // 同时建一条服务覆盖和一条自定义规则：p95 > 500 连续 3 次。
  service_overrides::set_override(
    &s,
    "http_5xx",
    "web",
    AlertPatch {
      threshold: Some(5.0),
      ..Default::default()
    },
    t0,
  )
  .await
  .unwrap();
  custom::add_rule(
    &s,
    CustomAlertRuleRequest {
      name: "web-p95-high".into(),
      service: "web".into(),
      metric: "p95".into(),
      op: ">".into(),
      threshold: 500.0,
      for_n: 3,
      level: AlertLevel::Urgent,
    },
    t0,
  )
  .await
  .unwrap();

  // 第 1、2 次超过 500 不触发。
  observe_at(&s, t0 + MIN, "req.p95", "web", 600.0, "").await;
  assert!(firing_since("web-p95-high", "web").is_none());
  observe_at(&s, t0 + 2 * MIN, "req.p95", "web", 600.0, "").await;
  assert!(firing_since("web-p95-high", "web").is_none());

  // 第 3 次触发，并进入推送记录和“需要注意”。
  observe_at(&s, t0 + 3 * MIN, "req.p95", "web", 650.0, "").await;
  assert!(firing_since("web-p95-high", "web").is_some());
  let rows = history_rows(&s).await;
  assert_eq!(rows.len(), 1);
  assert_eq!(rows[0].0, "web-p95-high");
  assert_eq!(rows[0].1.as_deref(), Some("web"));
  assert!(!rows[0].2 && delivered(&rows[0].3));

  let world = s
    .db
    .call(|c| World::from_rows(db::all_resources(c)?))
    .await
    .unwrap();
  let issues = custom::issues(&world);
  assert_eq!(issues.len(), 1);
  assert_eq!(
    issues[0].alert,
    Some(AlertTarget {
      rule: "web-p95-high".into(),
      subject: "web".into(),
    })
  );

  // 删除服务后，覆盖和自定义规则从内存与数据库一并消失。
  s.db
    .call(|c| {
      db::apply_write(
        c,
        &db::Write::Delete {
          kind: "service".into(),
          name: "web".into(),
        },
      )
    })
    .await
    .unwrap();
  custom::on_service_deleted(&s, "web").await;

  let v = api::view(&s).await.unwrap();
  assert!(v.service_overrides.is_empty());
  assert!(v.custom_rules.is_empty());
  assert!(firing_since("web-p95-high", "web").is_none());

  // 清空内存缓存重新从库里加载，确认持久化数据也已清理。
  reset_memory();
  let v = api::view(&s).await.unwrap();
  assert!(v.service_overrides.is_empty());
  assert!(v.custom_rules.is_empty());
}

#[tokio::test]
async fn idle_http_recovers_an_upper_bound_without_firing_a_lower_bound()
 {
  let _guard = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  seed_server_service(&state, "s1", "web").await;
  let now = db::now_ms();
  for (name, op, threshold) in
    [("error-high", ">", 5.0), ("latency-low", "<", 100.0)]
  {
    custom::add_rule(
      &state,
      CustomAlertRuleRequest {
        name: name.into(),
        service: "web".into(),
        metric: if op == ">" { "err" } else { "p95" }.into(),
        op: op.into(),
        threshold,
        for_n: 1,
        level: AlertLevel::Urgent,
      },
      now,
    )
    .await
    .unwrap();
  }
  observe_at(&state, now, "req.err", "web", 90.0, "").await;
  assert!(firing_since("error-high", "web").is_some());
  super::super::recover_idle_http(
    &state,
    now + 90_000,
    &Default::default(),
  )
  .await;
  assert!(firing_since("error-high", "web").is_none());
  assert!(firing_since("latency-low", "web").is_none());
}
