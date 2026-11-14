//! 按近 7 天磁盘的小时末值预测写满时间，排除一次性跳变。

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use rusqlite::{OptionalExtension, params};
use wharf_api_types::{
  ApiError,
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::{db, rules, snapshot, state::AppState};

pub enum Forecast {
  Insufficient,
  Flat,
  DaysLeft(f64),
}

pub fn forecast(points: &[(i64, f64)], total: f64) -> Forecast {
  if points.len() < 200
    || points.last().unwrap().0 - points[0].0 < 3 * 86_400_000
  {
    return Forecast::Insufficient;
  }
  let mut hours = BTreeMap::new();
  for &(at, used) in points {
    hours.insert(at / 3_600_000, used);
  }
  let hours: Vec<_> = hours.into_iter().collect();
  let (mut sum, mut count) = (0.0, 0);
  for w in hours.windows(2) {
    let diff = w[1].1 - w[0].1;
    if w[1].0 - w[0].0 == 1 && diff.abs() <= total * 0.03 {
      sum += diff;
      count += 1;
    }
  }
  if count == 0 {
    return Forecast::Insufficient;
  }
  let daily = sum / f64::from(count) * 24.0;
  if daily <= 0.0 {
    Forecast::Flat
  } else {
    Forecast::DaysLeft(
      ((total - hours.last().unwrap().1) / daily).max(0.0),
    )
  }
}

static LAST: Mutex<BTreeMap<String, f64>> =
  Mutex::new(BTreeMap::new());

pub fn days_left(server: &str) -> Option<f64> {
  LAST.lock().ok()?.get(server).copied()
}

pub fn issues() -> Vec<Issue> {
  rules::firing_subjects("disk_forecast")
    .into_iter()
    .map(|(name, title)| Issue {
      code: "disk_forecast".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "server".into(),
        name,
      }),
      title,
      hint: None,
    })
    .collect()
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
      if let Err(e) = round(&state).await {
        tracing::warn!("磁盘预测失败：{}", e.message);
      }
      tokio::time::sleep(Duration::from_secs(3600)).await;
    }
  });
}

async fn round(state: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  for name in snap.world.servers.keys() {
    let server = name.clone();
    let result = state.db.call(move |c| {
      let mut stmt = c.prepare(
        "SELECT at, value FROM points WHERE subject = ?1 AND name = 'host.disk' AND at >= ?2 ORDER BY at",
      ).map_err(db::sql_err)?;
      let points = stmt.query_map(
        params![server, db::now_ms() - 7 * 86_400_000],
        |r| Ok((r.get(0)?, r.get(1)?)),
      ).and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(db::sql_err)?;
      let total = c.query_row(
        "SELECT value FROM points WHERE subject = ?1 AND name = 'host.disk_total' ORDER BY at DESC LIMIT 1",
        params![server], |r| r.get::<_, f64>(0),
      ).optional().map_err(db::sql_err)?;
      Ok(total.map_or(Forecast::Insufficient, |t| forecast(&points, t)))
    }).await;
    let result = match result {
      Ok(r) => r,
      Err(e) => {
        tracing::warn!("服务器 {name} 的磁盘预测失败：{}", e.message);
        continue;
      }
    };
    {
      let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
      if let Forecast::DaysLeft(d) = result {
        last.insert(name.clone(), d);
      } else {
        last.remove(name);
      }
    }
    let value = match result {
      Forecast::DaysLeft(d) => d,
      Forecast::Flat => 9999.0,
      Forecast::Insufficient => continue,
    };
    rules::observe(state, "disk.days_left", name, value, "").await;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ignores_a_one_time_jump() {
    let gb = (1_u64 << 30) as f64;
    let points: Vec<_> = (0..=7 * 1440)
      .map(|m| {
        let jump = if m >= 3 * 1440 { 30.0 } else { 0.0 };
        (m * 60_000, (20.0 + m as f64 / 1440.0 + jump) * gb)
      })
      .collect();
    let Forecast::DaysLeft(days) = forecast(&points, 100.0 * gb)
    else {
      panic!("应当有写满预测");
    };
    let expected = (100.0 * gb - points.last().unwrap().1) / gb;
    assert!((days - expected).abs() / expected < 0.05);
  }

  #[test]
  fn insufficient_or_flat() {
    assert!(matches!(forecast(&[], 100.0), Forecast::Insufficient));
    let points: Vec<_> = (0..=7 * 144)
      .map(|m| (m * 600_000, 20.0))
      .collect();
    assert!(matches!(forecast(&points, 100.0), Forecast::Flat));
  }
}
