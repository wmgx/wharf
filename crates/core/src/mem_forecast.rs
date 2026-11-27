//! 按近 3 天的小时末值粗估内存用完的时间。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use rusqlite::{OptionalExtension, params};
use wharf_api_types::ApiError;

use crate::{db, rules, snapshot, state::AppState};

const HOUR: i64 = 3_600_000;
const LOOKBACK: i64 = 72 * HOUR;

#[derive(Debug, PartialEq)]
enum Forecast {
  Insufficient,
  Flat,
  Growing { used: f64, daily: f64, days: f64 },
}

fn forecast(points: &[(i64, f64)], total: f64) -> Forecast {
  let mut hours = BTreeMap::new();
  for &(at, used) in points {
    let point = hours.entry(at / HOUR).or_insert((at, used));
    if at > point.0 {
      *point = (at, used);
    }
  }
  let (Some((_, &(first, _))), Some((_, &(last, used)))) =
    (hours.first_key_value(), hours.last_key_value())
  else {
    return Forecast::Insufficient;
  };
  if total <= 0.0 || hours.len() < 36 || last - first < 24 * HOUR {
    return Forecast::Insufficient;
  }
  let mut sum = 0.0;
  let mut count = 0;
  for ((h0, (_, before)), (h1, (_, after))) in
    hours.iter().zip(hours.iter().skip(1))
  {
    let diff = after - before;
    if h1 - h0 == 1 && diff.abs() <= total * 0.10 {
      sum += diff;
      count += 1;
    }
  }
  if count == 0 {
    return Forecast::Insufficient;
  }
  let daily = sum / f64::from(count) * 24.0;
  if daily <= 0.0 {
    return Forecast::Flat;
  }
  Forecast::Growing {
    used,
    daily,
    days: ((total - used) / daily).max(0.0),
  }
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
      if let Err(e) = round(&state).await {
        tracing::warn!("内存预测失败：{}", e.message);
      }
      tokio::time::sleep(Duration::from_secs(3600)).await;
    }
  });
}

async fn round(state: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let from = db::now_ms() - LOOKBACK;
  let mut subjects = Vec::new();
  for name in snap.world.servers.keys() {
    subjects.push((name.clone(), name.clone(), "host.mem", None));
  }
  for (name, service) in &snap.world.services {
    if service.spec.stopped {
      continue;
    }
    subjects.push((
      name.clone(),
      service.spec.server.clone(),
      "svc.mem",
      rules::resources::service_limit(&service.spec),
    ));
  }
  for (name, server, series, limit) in subjects {
    let subject = if series == "host.mem" {
      format!("服务器 {name}")
    } else {
      format!("服务 {name}")
    };
    let machine = if series == "svc.mem" {
      format!("所在机器 {server}，")
    } else {
      String::new()
    };
    let capacity = if limit.is_some() { "上限" } else { "整机" };
    let result = state.db.call(move |c| {
      let total = if let Some(limit) = limit {
        limit as f64
      } else {
        c.query_row(
          "SELECT value FROM points WHERE subject = ?1 AND name = 'host.mem_total' AND at >= ?2 ORDER BY at DESC LIMIT 1",
          params![server, from], |r| r.get(0),
        ).optional().map_err(db::sql_err)?.unwrap_or(0.0)
      };
      let mut stmt = c.prepare_cached(
        "SELECT at, value FROM points WHERE subject = ?1 AND name = ?2 AND at >= ?3 ORDER BY at",
      ).map_err(db::sql_err)?;
      let points = stmt.query_map(params![name, series, from], |r| Ok((r.get(0)?, r.get(1)?)))
        .and_then(Iterator::collect::<Result<Vec<_>, _>>).map_err(db::sql_err)?;
      Ok((forecast(&points, total), total))
    }).await;
    let (value, detail) = match result {
      Ok((Forecast::Growing { used, daily, days }, total)) => {
        let mib = rules::resources::mib;
        (
          days,
          format!(
            "{machine}当前 {}，{capacity} {}，每天增长 {}",
            mib(used),
            mib(total),
            mib(daily)
          ),
        )
      }
      Ok((Forecast::Flat, _)) => (f64::MAX, String::new()),
      Ok((Forecast::Insufficient, _)) => continue,
      Err(e) => {
        tracing::warn!("{subject} 的内存预测失败：{}", e.message);
        continue;
      }
    };
    rules::observe(state, "mem.days_left", &subject, value, &detail)
      .await;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn rising() -> Vec<(i64, f64)> {
    (0..=71)
      .map(|h| (h * HOUR, 700.0 - (71 - h) as f64 * 100.0 / 24.0))
      .collect()
  }

  fn expect_growth(points: &[(i64, f64)]) {
    let Forecast::Growing { used, daily, days } =
      forecast(points, 1000.0)
    else {
      panic!("应有增长预测")
    };
    assert_eq!(used, 700.0);
    assert!((daily - 100.0).abs() <= 1.0, "{daily}");
    assert!((days - 3.0).abs() <= 0.03, "{days}");
  }

  #[test]
  fn predicts_three_days_with_steady_growth() {
    expect_growth(&rising());
  }

  #[test]
  fn mixed_resolution_matches_raw_forecast() {
    const MINUTE: i64 = HOUR / 60;
    let raw: Vec<_> = (0..72 * 60)
      .map(|m| (HOUR / 2 + m * MINUTE + 1, 400.0 + m as f64 / 14.4))
      .collect();
    let (older, recent) = raw.split_at(2 * 24 * 60);
    let mut mixed: Vec<_> = older
      .chunks_exact(10)
      .map(|bucket| {
        (
          bucket[0].0 - 1,
          bucket.iter().map(|p| p.1).sum::<f64>() / 10.0,
        )
      })
      .collect();
    mixed.extend_from_slice(recent);
    mixed.reverse();
    let growth =
      |points: &[(i64, f64)]| match forecast(points, 1000.0) {
        Forecast::Growing { used, daily, days } => {
          [used, daily, days]
        }
        other => panic!("应有增长预测，实际为 {other:?}"),
      };
    for (compressed, original) in
      growth(&mixed).into_iter().zip(growth(&raw))
    {
      assert!(
        (compressed / original - 1.0).abs() <= 0.02,
        "{compressed} / {original}"
      );
    }
  }

  #[test]
  fn ignores_restart_jump() {
    let mut points = rising();
    points[36].1 = 200.0;
    expect_growth(&points);
  }

  #[test]
  fn flat() {
    let points: Vec<_> = (0..36).map(|h| (h * HOUR, 700.0)).collect();
    assert_eq!(forecast(&points, 1000.0), Forecast::Flat);
  }

  #[test]
  fn needs_at_least_36_hourly_points() {
    assert_eq!(
      forecast(&rising()[..20], 1000.0),
      Forecast::Insufficient
    );
  }
}
