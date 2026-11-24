use serde_json::json;

use super::*;
use crate::db::{self, Db};

fn seed_world(c: &Connection) -> World {
  db::apply_write(
    c,
    &db::Write::Upsert {
      kind: "server".into(),
      name: "s1".into(),
      spec: json!({}),
      meta: json!({}),
    },
  )
  .unwrap();
  db::apply_write(
    c,
    &db::Write::Upsert {
      kind: "service".into(),
      name: "web".into(),
      spec: json!({
        "server": "s1",
        "source": { "image": "nginx:1" }
      }),
      meta: json!({}),
    },
  )
  .unwrap();
  World::from_rows(db::all_resources(c).unwrap()).unwrap()
}

fn insert_point(
  c: &Connection,
  name: &str,
  subject: &str,
  at: i64,
  value: f64,
) {
  c.execute(
    "INSERT OR REPLACE INTO points (name, subject, at, value) VALUES (?1, ?2, ?3, ?4)",
    params![name, subject, at, value],
  )
  .unwrap();
}

#[tokio::test]
async fn linear_growth_matches_hand_calculation_and_picks_biggest_change()
 {
  let db = Db::memory();
  let now = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
  let total_hours = 14 * 24;

  let report = db
    .call(move |c| {
      let world = seed_world(c);
      // 造 14 天匀速增长数据，混用真实压缩粒度（7~14 天整点、1~7 天 10 分钟、1 天内每分钟）。
      // host.cpu：从 10 匀速涨到 30 -> 上期均值 15，本期均值 25 -> +66.67%
      // svc.cpu：从 10 匀速涨到 50 -> 上期均值 20，本期均值 40 -> +100.0%
      // req.p95：从 50 匀速涨到 250 -> 上期均值 100，本期均值 200 -> +100.0%
      // req.qps：从 10 匀速涨到 70 -> 上期均值 25，本期均值 55 -> +120.0%（变化最大）
      for h in 0..total_hours {
        let base = now - (total_hours - h) * HOUR_MS;
        let step_ms = if total_hours - h <= 24 {
          60_000
        } else if total_hours - h <= 7 * 24 {
          10 * 60_000
        } else {
          HOUR_MS
        };
        let steps = HOUR_MS / step_ms;
        for k in 0..steps {
          let at = base + k * step_ms;
          let mid = at + step_ms / 2;
          let frac =
            (mid - (now - 14 * DAY_MS)) as f64 / (14 * DAY_MS) as f64;
          insert_point(c, "host.cpu", "s1", at, 10.0 + 20.0 * frac);
          insert_point(c, "svc.cpu", "web", at, 10.0 + 40.0 * frac);
          insert_point(c, "req.p95", "web", at, 50.0 + 200.0 * frac);
          insert_point(c, "req.qps", "web", at, 10.0 + 60.0 * frac);
        }
      }
      compute_at(c, &world, now, 7, None, None, MAX_SCAN_POINTS)
    })
    .await
    .unwrap();

  assert!(report.coverage.has_current);
  assert!(report.coverage.has_previous);
  let s1 = &report.servers[0];
  let host_pct = s1.cpu_avg.change_pct.unwrap();
  assert!(
    (host_pct - 66.67).abs() <= 1.0,
    "host.cpu change_pct={host_pct}"
  );
  let web = &report.services[0];
  let svc_cpu_pct = web.cpu_avg.change_pct.unwrap();
  assert!(
    (svc_cpu_pct - 100.0).abs() <= 1.0,
    "svc.cpu change_pct={svc_cpu_pct}"
  );
  let qps_pct = web.requests.change_pct.unwrap();
  assert!(
    (qps_pct - 120.0).abs() <= 1.0,
    "requests change_pct={qps_pct}"
  );
  // 摘要第一条应挑出变化最大的请求数（+120%）。
  assert!(
    report.summary[0].contains("请求数"),
    "summary={:?}",
    report.summary
  );
}

#[tokio::test]
async fn three_days_data_has_no_previous_comparison_and_valid_coverage()
 {
  let db = Db::memory();
  let now = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
  let first_at = now - 3 * DAY_MS;
  let last_at = now - HOUR_MS;

  let report = db
    .call(move |c| {
      let world = seed_world(c);
      for h in 0..(3 * 24) {
        let at = first_at + h * HOUR_MS;
        insert_point(c, "host.cpu", "s1", at, 20.0);
        insert_point(c, "svc.cpu", "web", at, 15.0);
      }
      compute_at(c, &world, now, 7, None, None, MAX_SCAN_POINTS)
    })
    .await
    .unwrap();

  assert!(report.coverage.has_current);
  assert!(!report.coverage.has_previous);
  assert_eq!(report.coverage.earliest_at, Some(first_at));
  assert_eq!(report.coverage.latest_at, Some(last_at));
  assert_eq!(report.servers[0].cpu_avg.previous, None);
  assert_eq!(report.servers[0].cpu_avg.change_pct, None);
  assert_eq!(report.services[0].cpu_avg.previous, None);
  assert_eq!(report.services[0].cpu_avg.change_pct, None);
  assert_eq!(report.summary, vec!["和上期相比没有明显变化"]);
}

#[tokio::test]
async fn scan_limit_returns_error_with_hint() {
  let db = Db::memory();
  let now = 1_700_000_000_000 / HOUR_MS * HOUR_MS;

  let err = db
    .call(move |c| {
      let world = seed_world(c);
      for h in 0..10 {
        insert_point(
          c,
          "host.cpu",
          "s1",
          now - (h + 1) * HOUR_MS,
          20.0,
        );
      }
      compute_at(c, &world, now, 7, None, None, 5)
    })
    .await
    .unwrap_err();

  assert!(err.message.contains("上限"));
  assert!(
    err.hint.as_deref().unwrap_or("").contains("--server"),
    "hint={:?}",
    err.hint
  );
}
