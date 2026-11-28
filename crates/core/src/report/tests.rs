use serde_json::json;

use super::*;
use crate::db::{self, Db};
use crate::world::World;

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
      compute_at(
        c,
        &snapshot::Snapshot {
          world,
          ..Default::default()
        },
        now,
        7,
        None,
        None,
        MAX_SCAN_POINTS,
        None,
      )
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
      compute_at(
        c,
        &snapshot::Snapshot {
          world,
          ..Default::default()
        },
        now,
        7,
        None,
        None,
        MAX_SCAN_POINTS,
        None,
      )
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
      compute_at(
        c,
        &snapshot::Snapshot {
          world,
          ..Default::default()
        },
        now,
        7,
        None,
        None,
        5,
        None,
      )
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

#[tokio::test]
async fn partial_previous_ten_minutes_disables_comparison() {
  let db = Db::memory();
  let now = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
  let period_start = now - 7 * DAY_MS;
  let prev_point = period_start - 10 * 60_000;

  let report = db
    .call(move |c| {
      let world = seed_world(c);
      // 上期只在边界前 10 分钟有极少数据，覆盖率远低于 80%。
      insert_point(c, "host.cpu", "s1", prev_point, 10.0);
      insert_point(c, "host.mem", "s1", prev_point, 100.0);
      insert_point(c, "host.net_rx", "s1", prev_point, 10.0);
      insert_point(c, "host.net_tx", "s1", prev_point, 5.0);
      insert_point(c, "svc.cpu", "web", prev_point, 5.0);
      insert_point(c, "svc.mem", "web", prev_point, 50.0);
      insert_point(c, "req.qps", "web", prev_point, 0.01);
      insert_point(c, "req.err", "web", prev_point, 0.1);
      insert_point(c, "req.p95", "web", prev_point, 20.0);
      c.execute(
        "INSERT INTO alert_history (at, source, subject, title, ok, skipped)
         VALUES (?1, 'http_5xx', 'web', '5xx', 0, NULL)",
        params![prev_point],
      )
      .unwrap();

      // 本期 7 天完整数据，且数值远高于上期 10 分钟样本。
      for h in 0..(7 * 24) {
        let at = period_start + h * HOUR_MS;
        insert_point(c, "host.cpu", "s1", at, 30.0);
        insert_point(c, "host.mem", "s1", at, 200.0);
        insert_point(c, "host.net_rx", "s1", at, 10_000.0);
        insert_point(c, "host.net_tx", "s1", at, 5_000.0);
        insert_point(c, "svc.cpu", "web", at, 25.0);
        insert_point(c, "svc.mem", "web", at, 100.0);
        insert_point(c, "req.qps", "web", at, 20.0);
        insert_point(c, "req.err", "web", at, 1.0);
        insert_point(c, "req.p95", "web", at, 120.0);
      }
      for i in 0..2 {
        c.execute(
          "INSERT INTO alert_history (at, source, subject, title, ok, skipped)
           VALUES (?1, 'http_5xx', 'web', '5xx', 0, NULL)",
          params![period_start + (i + 1) * HOUR_MS],
        )
        .unwrap();
      }
      compute_at(c, &snapshot::Snapshot { world, ..Default::default() }, now, 7, None, None, MAX_SCAN_POINTS, None)
    })
    .await
    .unwrap();

  assert!(report.coverage.has_current);
  assert!(!report.coverage.has_previous);
  assert!(report.coverage.previous_ratio > 0.0);
  assert!(report.coverage.previous_ratio < 0.01);

  let s1 = &report.servers[0];
  for d in [
    &s1.cpu_avg,
    &s1.cpu_peak,
    &s1.mem_avg,
    &s1.mem_peak,
    &s1.disk_change,
    &s1.net_rx_bytes,
    &s1.net_tx_bytes,
  ] {
    assert_eq!(d.previous, None);
    assert_eq!(d.change_pct, None);
  }
  let web = &report.services[0];
  for d in [
    &web.cpu_avg,
    &web.mem_avg,
    &web.mem_peak,
    &web.requests,
    &web.err_pct,
    &web.p95_ms,
  ] {
    assert_eq!(d.previous, None);
    assert_eq!(d.change_pct, None);
  }
  assert_eq!(report.alerts.len(), 1);
  assert_eq!(report.alerts[0].current, 2);
  assert_eq!(report.alerts[0].previous, None);
  assert_eq!(report.alerts[0].change_pct, None);
  assert!(report.summary.iter().all(|line| !line.contains('%')));
  assert_eq!(report.summary, vec!["和上期相比没有明显变化"]);
}

#[tokio::test]
async fn report_filters_domain_expiry_and_notices_by_server_and_service()
 {
  Db::memory().call(|c| {
    seed_world(c);
    for (kind, name, spec) in [
      ("service", "api", json!({"server":"s1","source":{"image":"app:1"}})),
      ("gateway", "gw1", json!({"kind":"caddy","server":"s1"})),
      ("route", "web.example.test", json!({
        "hostname":"web.example.test", "service":"web","gateway":"gw1",
        "paths":[{"path":"/api","service":"api"}]
      })),
    ] {
      db::apply_write(c, &db::Write::Upsert {
        kind: kind.into(), name: name.into(), spec, meta: json!({}),
      })?;
    }
    let world = World::from_rows(db::all_resources(c)?)?;
    let now = 1_750_000_000_000;
    for (rule, subject) in [
      ("domain_down", "web.example.test"), ("cert_expiring", "web.example.test"),
      ("expiry_soon", "server:s1"), ("link_cert_expiring", "gw1"), ("backup", "web"),
    ] {
      c.execute("INSERT INTO alert_history(at, source, subject, title, ok) VALUES (?1, ?2, ?3, '', 0)",
        params![now - MINUTE_MS, rule, subject]).map_err(sql_err)?;
    }
    for (server, service, count) in [(Some("s1"), None, 5), (None, Some("web"), 3), (None, Some("api"), 2)] {
      let report = compute_at(c, &world, now, 1, server, service, MAX_SCAN_POINTS, None)?;
      assert_eq!(report.alerts.len(), count);
    }
    Ok(())
  }).await.unwrap();
}

#[tokio::test]
async fn compact_preserves_peak_and_report_compares_same_granularity()
{
  Db::memory()
    .call(|c| {
      let world = seed_world(c);
      let now = 1_750_000_000_000 / HOUR_MS * HOUR_MS;
      for minute in 0..14 * 24 * 60 {
        insert_point(
          c,
          "host.cpu",
          "s1",
          now - 14 * DAY_MS + minute * MINUTE_MS,
          if minute % 60 == 1 { 90.0 } else { 10.0 },
        );
      }
      metrics::compact_at(c, now)?;
      assert!(
        !metrics::read(c, "s1", &[], now - 14 * DAY_MS, HOUR_MS)?
          .contains_key("host.cpu.max")
      );
      let view = compute_at(
        c,
        &world,
        now,
        7,
        None,
        None,
        MAX_SCAN_POINTS,
        None,
      )?;
      let peak = &view.servers[0].cpu_peak;
      assert_eq!(
        (peak.current, peak.previous, peak.change_pct),
        (Some(90.0), Some(90.0), Some(0.0))
      );
      c.execute("DELETE FROM points WHERE name = 'host.cpu.max'", [])
        .map_err(sql_err)?;
      let view = compute_at(
        c,
        &world,
        now,
        7,
        None,
        None,
        MAX_SCAN_POINTS,
        None,
      )?;
      assert!(
        view.servers[0].cpu_peak.change_pct.unwrap().abs() < 0.01
      );
      assert!(view.summary.iter().any(|s| s.contains("接近上限")));
      Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn report_weights_err_by_qps_integrates_real_gaps_and_scopes_coverage()
 {
  Db::memory().call(|c| {
    let world = seed_world(c);
    let now = 1_750_000_000_000 / HOUR_MS * HOUR_MS;
    let earliest = now - 14 * DAY_MS + HOUR_MS;
    insert_point(c, "host.cpu", "s1", earliest, 10.0);
    c.execute("INSERT INTO alert_history(at, source, title, ok) VALUES (?1, 'http_5xx', '', 0)", [earliest - MINUTE_MS]).map_err(sql_err)?;
    for i in 0..10 {
      let at = now - HOUR_MS + (i + 1) * MINUTE_MS;
      insert_point(c, "host.net_rx", "s1", at, 10_000_000.0);
    }
    for h in 1..=11 {
      let at = now - h * HOUR_MS;
      insert_point(c, "req.err", "web", at, if h == 1 { 100.0 } else { 0.0 });
      insert_point(c, "req.qps", "web", at, if h == 1 { 1.0 / 3600.0 } else { 10.0 });
    }
    let view = compute_at(c, &world, now, 7, None, None, MAX_SCAN_POINTS, None)?;
    assert_eq!(view.coverage.earliest_at, Some(earliest));
    assert!(view.coverage.has_previous);
    assert_eq!(view.servers[0].net_rx_bytes.current, Some(6_000_000_000.0));
    assert!(view.services[0].err_pct.current.unwrap() < 0.1);
    assert_eq!(view.services[0].previous_ratio, Some(0.0));
    assert_eq!(view.services[0].requests.previous, None);
    Ok(())
  }).await.unwrap();
}
