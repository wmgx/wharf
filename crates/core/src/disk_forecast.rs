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

const HOUR: i64 = 3_600_000;

pub(crate) fn hourly_points(
  points: &[(i64, f64)],
) -> Vec<(i64, f64)> {
  let mut hours = BTreeMap::new();
  for &(at, used) in
    points.iter().filter(|(_, used)| used.is_finite())
  {
    let point =
      hours.entry(at.div_euclid(HOUR)).or_insert((at, used));
    if at > point.0 {
      *point = (at, used);
    }
  }
  hours.into_values().collect()
}

fn median(mut values: Vec<f64>) -> f64 {
  let even = values.len().is_multiple_of(2);
  let mid = values.len() / 2;
  let (lower, central, _) =
    values.select_nth_unstable_by(mid, f64::total_cmp);
  if even {
    let before = lower
      .iter()
      .copied()
      .max_by(f64::total_cmp)
      .unwrap_or(*central);
    return (before + *central) / 2.0;
  }
  *central
}

pub(crate) fn daily_growth(
  hours: &[(i64, f64)],
  jump: f64,
  stable_hours: i64,
) -> f64 {
  let mut rapid = Vec::new();
  for pair in hours.windows(2).rev() {
    let [(from, before), (to, after)] = pair else {
      unreachable!()
    };
    let diff = after - before;
    if to.div_euclid(HOUR) - from.div_euclid(HOUR) != 1
      || diff <= jump
    {
      break;
    }
    rapid.push(diff);
  }
  if rapid.len() >= 3 {
    return median(rapid) * 24.0;
  }
  let start = hours
    .windows(2)
    .rposition(|pair| {
      pair[1].0.div_euclid(HOUR) - pair[0].0.div_euclid(HOUR) == 1
        && pair[0].1 - pair[1].1 > jump
    })
    .map_or(0, |i| i + 1);
  let hours = &hours[start..];
  let (Some(first), Some(last)) = (hours.first(), hours.last())
  else {
    return 0.0;
  };
  if last.0 - first.0 < stable_hours * HOUR {
    return 0.0;
  }
  let slopes = hours
    .iter()
    .enumerate()
    .flat_map(|(i, a)| {
      hours[i + 1..]
        .iter()
        .map(move |b| (b.1 - a.1) / (b.0 - a.0) as f64)
    })
    .collect();
  let quarter = (hours.len() / 4).max(1);
  let early = &hours[..quarter];
  let late = &hours[hours.len() - quarter..];
  let gain = median(late.iter().map(|p| p.1).collect())
    - median(early.iter().map(|p| p.1).collect());
  let gap = late[quarter / 2].0 - early[quarter / 2].0;
  let rate = median(slopes).min(gain / gap as f64);
  rate.max(0.0) * (24 * HOUR) as f64
}

pub fn forecast(points: &[(i64, f64)], total: f64) -> Forecast {
  let hours = hourly_points(points);
  let (Some(first), Some(last)) = (hours.first(), hours.last())
  else {
    return Forecast::Insufficient;
  };
  if total <= 0.0
    || points.len() < 200
    || last.0 - first.0 < 72 * HOUR
  {
    return Forecast::Insufficient;
  }
  let daily = daily_growth(&hours, total * 0.03, 24);
  if daily <= 0.0 {
    Forecast::Flat
  } else {
    Forecast::DaysLeft(((total - last.1) / daily).max(0.0))
  }
}

static LAST: Mutex<BTreeMap<String, f64>> =
  Mutex::new(BTreeMap::new());

pub(crate) fn forget_server(server: &str) {
  if let Ok(mut last) = LAST.lock() {
    last.remove(server);
  }
}

pub fn days_left(server: &str) -> Option<f64> {
  LAST.lock().ok()?.get(server).copied()
}

pub fn issues(world: &crate::world::World) -> Vec<Issue> {
  rules::firing_subjects("disk_forecast")
    .into_iter()
    .filter(|(server, _)| world.servers.contains_key(server))
    .map(|(name, title)| {
      let (alert, ack) = rules::issue_alert("disk_forecast", &name);
      Issue {
        code: "disk_forecast".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name,
        }),
        title,
        hint: None,
        ack,
        alert,
      }
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
  rules::retain_subjects(
    state,
    "disk_forecast",
    &snap.world.servers.keys().cloned().collect(),
  )
  .await;
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
    let points: Vec<_> =
      (0..=7 * 144).map(|m| (m * 600_000, 20.0)).collect();
    assert!(matches!(forecast(&points, 100.0), Forecast::Flat));
  }
}
