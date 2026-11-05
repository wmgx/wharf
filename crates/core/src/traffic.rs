//! 本月流量：agent 上报的是网速（字节每秒，按两次采样的间隔平均），
//! 乘上离上一次上报的时间就是这段时间的流量，按北京时间的天累加成 `traffic.rx` / `traffic.tx` 事件点
//! （保留 90 天）。查询时从这个周期的重置日加到今天。agent 重启后的第一次采样只记基准，那一段不计。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, State},
};
use chrono::{Datelike, FixedOffset, NaiveDate, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use wharf_api_types::{ApiError, view::Perm};

use crate::{
  api::ApiResult, auth::Auth, db::sql_err, snapshot, state::AppState,
};

/// 两次上报隔得太久（控制面停过）时不按间隔乘，免得一个旧速率算出一大笔。
const MAX_GAP_MS: i64 = 10 * 60 * 1000;

fn beijing() -> FixedOffset {
  FixedOffset::east_opt(8 * 3600).expect("固定时区")
}

/// 北京时间当天 0 点的毫秒时间戳。
fn day_start(at_ms: i64) -> i64 {
  let t = beijing()
    .timestamp_millis_opt(at_ms)
    .single()
    .unwrap_or_default();
  let d = t.date_naive();
  midnight(d)
}

fn midnight(d: NaiveDate) -> i64 {
  beijing()
    .from_local_datetime(&d.and_hms_opt(0, 0, 0).expect("0 点"))
    .single()
    .map(|t| t.timestamp_millis())
    .unwrap_or_default()
}

/// 在上一次 `host.net_rx` 点和这次之间累加流量，要在写入这次的点之前调用。
pub fn add(
  c: &Connection,
  server: &str,
  at: i64,
  rx_rate: u64,
  tx_rate: u64,
) -> Result<(), ApiError> {
  let last: Option<i64> = c
    .query_row(
      "SELECT MAX(at) FROM points WHERE subject = ?1 AND name = 'host.net_rx'",
      params![server],
      |r| r.get(0),
    )
    .optional()
    .map_err(sql_err)?
    .flatten();
  let Some(last) = last else { return Ok(()) };
  let gap = at - last;
  if gap <= 0 || gap > MAX_GAP_MS {
    return Ok(());
  }
  let day = day_start(at);
  let mut stmt = c
    .prepare_cached(
      "INSERT INTO points (name, subject, at, value) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (subject, name, at) DO UPDATE SET value = value + excluded.value",
    )
    .map_err(sql_err)?;
  let secs = gap as f64 / 1000.0;
  for (name, rate) in
    [("traffic.rx", rx_rate), ("traffic.tx", tx_rate)]
  {
    stmt
      .execute(params![name, server, day, rate as f64 * secs])
      .map_err(sql_err)?;
  }
  Ok(())
}

/// 当前周期的开始日：今天的日子到了重置日就是本月的重置日，否则是上个月的。
fn period_start(today: NaiveDate, reset_day: u32) -> NaiveDate {
  let this = today.with_day(reset_day).unwrap_or(today);
  if today.day() >= reset_day {
    return this;
  }
  let (y, m) = if today.month() == 1 {
    (today.year() - 1, 12)
  } else {
    (today.year(), today.month() - 1)
  };
  NaiveDate::from_ymd_opt(y, m, reset_day).unwrap_or(this)
}

#[derive(Serialize)]
pub struct TrafficView {
  /// 这个周期从哪天开始（北京时间）。
  pub since: NaiveDate,
  pub rx: u64,
  pub tx: u64,
  /// 额度，字节；没设置时没有。
  #[serde(skip_serializing_if = "Option::is_none")]
  pub quota: Option<u64>,
}

/// `GET /api/servers/{name}/traffic`：这个周期收发了多少。
pub async fn traffic(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<TrafficView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .servers
    .get(&name)
    .ok_or_else(|| crate::world::server_not_found(&name))?;
  let reset = row.settings.traffic_reset_day.unwrap_or(1) as u32;
  let quota = row
    .settings
    .traffic_quota_gb
    .map(|g| g as u64 * (1 << 30));
  let today = Utc::now().with_timezone(&beijing()).date_naive();
  let since = period_start(today, reset);
  let from = midnight(since);
  let (rx, tx) = s
    .db
    .call(move |c| {
      c.query_row(
        "SELECT
           COALESCE(SUM(CASE WHEN name = 'traffic.rx' THEN value END), 0),
           COALESCE(SUM(CASE WHEN name = 'traffic.tx' THEN value END), 0)
         FROM points WHERE subject = ?1 AND at >= ?2
           AND name IN ('traffic.rx', 'traffic.tx')",
        params![name, from],
        |r| Ok((r.get::<_, f64>(0)?, r.get::<_, f64>(1)?)),
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(Json(TrafficView {
    since,
    rx: rx as u64,
    tx: tx as u64,
    quota,
  }))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn period_start_wraps_month() {
    let d = |y, m, d| NaiveDate::from_ymd_opt(y, m, d).unwrap();
    assert_eq!(period_start(d(2026, 11, 6), 1), d(2026, 11, 1));
    assert_eq!(period_start(d(2026, 11, 6), 10), d(2026, 10, 10));
    assert_eq!(period_start(d(2026, 1, 3), 15), d(2025, 12, 15));
  }

  #[tokio::test]
  async fn adds_rate_times_gap() {
    let db = crate::db::Db::memory();
    let total = db
      .call(|c| {
        let t0 = day_start(crate::db::now_ms()) + 3_600_000;
        c.execute(
          "INSERT INTO points VALUES ('host.net_rx', 'a', ?1, 0)",
          params![t0],
        )
        .map_err(sql_err)?;
        add(c, "a", t0 + 60_000, 100, 10)?;
        add(c, "a", t0 + 60_000 + MAX_GAP_MS + 1, 100, 10)?;
        c.query_row(
          "SELECT value FROM points WHERE name = 'traffic.rx'",
          [],
          |r| r.get::<_, f64>(0),
        )
        .map_err(sql_err)
      })
      .await
      .unwrap();
    assert_eq!(total, 6000.0);
  }
}
