//! 打点：一张通用的表，每个点是（名称，对象，时间，数值）。
//! - `host.*`：服务器资源，对象是服务器名，agent 每分钟上报；
//! - `svc.*`：服务（compose project）的容器资源，对象是 project 名；
//! - 其余是事件：部署、备份的耗时和结果，自动重启，对象是服务名。
//!
//! 资源点 24 小时后合成 10 分钟一个，保留 7 天；事件保留 90 天。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Query, State},
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{ApiError, agent::Metrics, view::TokenScope};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{now_ms, sql_err},
  planner::Step,
  state::AppState,
};

const MINUTE_MS: i64 = 60 * 1000;
const COARSE_MS: i64 = 10 * MINUTE_MS;
const DAY_MS: i64 = 24 * 60 * MINUTE_MS;
const KEEP_RESOURCE_MS: i64 = 7 * DAY_MS;
const KEEP_EVENT_MS: i64 = 90 * DAY_MS;

/// 合成和按时间段平均的只有资源点，事件点原样保留。
const RESOURCE: &str = "(name LIKE 'host.%' OR name LIKE 'svc.%')";

fn insert(
  c: &Connection,
  at: i64,
  points: &[(&str, &str, f64)],
) -> Result<(), ApiError> {
  let mut stmt = c
    .prepare_cached(
      "INSERT OR REPLACE INTO points (name, subject, at, value) VALUES (?1, ?2, ?3, ?4)",
    )
    .map_err(sql_err)?;
  for (name, subject, value) in points {
    stmt
      .execute(params![name, subject, at, value])
      .map_err(sql_err)?;
  }
  Ok(())
}

/// agent 上报的资源采样。
pub async fn record_report(
  state: &AppState,
  server: &str,
  m: Metrics,
) {
  let owned = server.to_string();
  let result = state
    .db
    .call(move |c| {
      let at = now_ms();
      let s = owned.as_str();
      insert(
        c,
        at,
        &[
          ("host.cpu", s, m.cpu as f64),
          ("host.mem", s, m.mem_used as f64),
          ("host.mem_total", s, m.mem_total as f64),
          ("host.net_rx", s, m.net_rx as f64),
          ("host.net_tx", s, m.net_tx as f64),
          ("host.disk", s, m.disk_used as f64),
          ("host.disk_total", s, m.disk_total as f64),
        ],
      )?;
      for (p, v) in &m.projects {
        let p = p.as_str();
        insert(
          c,
          at,
          &[
            ("svc.cpu", p, v.cpu as f64),
            ("svc.mem", p, v.mem as f64),
            ("svc.net_rx", p, v.net_rx as f64),
            ("svc.net_tx", p, v.net_tx as f64),
          ],
        )?;
      }
      Ok(())
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录 {server} 的资源采样失败：{e}");
  }
}

/// 记一个事件点，失败只记日志。
pub async fn event(
  state: &AppState,
  name: &str,
  subject: &str,
  value: f64,
) {
  let (n, s) = (name.to_string(), subject.to_string());
  let result = state
    .db
    .call(move |c| insert(c, now_ms(), &[(&n, &s, value)]))
    .await;
  if let Err(e) = result {
    tracing::warn!("记录 {name} 失败：{e}");
  }
}

/// 执行完一个步骤：部署和备份记耗时，失败另记一个点。
pub async fn step_done(
  state: &AppState,
  step: &Step,
  took: Duration,
  ok: bool,
) {
  let (kind, subject) = match step {
    Step::ServiceUp { service, .. } | Step::Rebuild { service } => {
      ("deploy", service.as_str())
    }
    Step::Backup { service } => ("backup", service.as_str()),
    Step::CoreBackup { .. } => ("backup", crate::core_backup::REPO),
    _ => return,
  };
  if ok {
    event(
      state,
      &format!("{kind}.secs"),
      subject,
      took.as_secs_f64(),
    )
    .await;
  } else {
    event(state, &format!("{kind}.fail"), subject, 1.0).await;
  }
}

/// 定时任务调用：旧的资源点合成 10 分钟一个，删掉过期的点。
pub async fn compact(state: &AppState) -> Result<(), ApiError> {
  state.db.call(|c| compact_at(c, now_ms())).await
}

fn compact_at(c: &mut Connection, now: i64) -> Result<(), ApiError> {
  // 对齐到 10 分钟，保证每个时间段一次合成完。合成后的点时间正好对齐，
  // 原始点几乎不会对齐，用这个区分。
  let cutoff = (now - DAY_MS) / COARSE_MS * COARSE_MS;
  let tx = c.transaction().map_err(sql_err)?;
  tx.execute(
    &format!(
      "INSERT OR REPLACE INTO points (name, subject, at, value)
       SELECT name, subject, at / ?2 * ?2, AVG(value) FROM points
       WHERE at < ?1 AND at % ?2 != 0 AND {RESOURCE}
       GROUP BY name, subject, at / ?2"
    ),
    params![cutoff, COARSE_MS],
  )
  .map_err(sql_err)?;
  tx.execute(
    &format!(
      "DELETE FROM points WHERE at < ?1 AND at % ?2 != 0 AND {RESOURCE}"
    ),
    params![cutoff, COARSE_MS],
  )
  .map_err(sql_err)?;
  tx.execute(
    &format!("DELETE FROM points WHERE at < ?1 AND {RESOURCE}"),
    params![now - KEEP_RESOURCE_MS],
  )
  .map_err(sql_err)?;
  tx.execute(
    &format!("DELETE FROM points WHERE at < ?1 AND NOT {RESOURCE}"),
    params![now - KEEP_EVENT_MS],
  )
  .map_err(sql_err)?;
  tx.commit().map_err(sql_err)
}

#[derive(Deserialize)]
pub struct MetricsQuery {
  /// 服务器名或服务名。
  pub subject: String,
  /// 逗号分隔；不给时按对象类型给资源点（`host.*` 或 `svc.*`）和事件。
  pub names: Option<String>,
  /// `1h`、`24h`（默认）、`7d`、`30d`。
  pub range: Option<String>,
}

#[derive(Serialize)]
pub struct MetricsView {
  pub subject: String,
  pub from: i64,
  pub to: i64,
  /// 资源点按这个间隔平均。
  pub step_ms: i64,
  /// 名称到 `[时间, 数值]`。
  pub series: BTreeMap<String, Vec<(i64, f64)>>,
}

fn range_ms(range: &str) -> Result<(i64, i64), ApiError> {
  // 每个范围大约 150 到 300 个点。
  Ok(match range {
    "1h" => (3600 * 1000, MINUTE_MS),
    "24h" => (DAY_MS, 5 * MINUTE_MS),
    "7d" => (7 * DAY_MS, 30 * MINUTE_MS),
    "30d" => (30 * DAY_MS, 3 * 60 * MINUTE_MS),
    other => {
      return Err(ApiError::invalid(format!(
        "范围 {other} 不认识，可以是 1h、24h、7d、30d"
      )));
    }
  })
}

/// `GET /api/metrics?subject=&names=&range=`
pub async fn query(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<MetricsQuery>,
) -> ApiResult<MetricsView> {
  auth.require(TokenScope::Read)?;
  let (span, step) = range_ms(q.range.as_deref().unwrap_or("24h"))?;
  let names: Vec<String> = q
    .names
    .as_deref()
    .map(|n| {
      n.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
    })
    .unwrap_or_default();
  let to = now_ms();
  let from = to - span;
  let subject = q.subject.clone();
  let series = s
    .db
    .call(move |c| read(c, &subject, &names, from, step))
    .await?;
  Ok(Json(MetricsView {
    subject: q.subject,
    from,
    to,
    step_ms: step,
    series,
  }))
}

type Series = BTreeMap<String, Vec<(i64, f64)>>;

fn read(
  c: &Connection,
  subject: &str,
  names: &[String],
  from: i64,
  step: i64,
) -> Result<Series, ApiError> {
  let wanted =
    |name: &str| names.is_empty() || names.iter().any(|n| n == name);
  let mut out: Series = BTreeMap::new();
  let mut stmt = c
    .prepare_cached(&format!(
      "SELECT name, at / ?3 * ?3 AS t, AVG(value) FROM points
       WHERE subject = ?1 AND at >= ?2 AND {RESOURCE}
       GROUP BY name, t ORDER BY name, t"
    ))
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![subject, from, step], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, i64>(1)?,
        r.get::<_, f64>(2)?,
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (name, at, v) = row.map_err(sql_err)?;
    if wanted(&name) {
      out.entry(name).or_default().push((at, v));
    }
  }
  let mut stmt = c
    .prepare_cached(&format!(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND NOT {RESOURCE} ORDER BY name, at"
    ))
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![subject, from], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, i64>(1)?,
        r.get::<_, f64>(2)?,
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (name, at, v) = row.map_err(sql_err)?;
    if wanted(&name) {
      out.entry(name).or_default().push((at, v));
    }
  }
  Ok(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn compact_averages_old_points() {
    let db = crate::db::Db::memory();
    let s = db
      .call(|c| {
        let now = now_ms();
        let old = (now - 2 * DAY_MS) / COARSE_MS * COARSE_MS;
        insert(
          c,
          old + 1,
          &[("host.cpu", "a", 10.0), ("deploy.secs", "a", 5.0)],
        )?;
        insert(
          c,
          old + 2,
          &[("host.cpu", "a", 30.0), ("deploy.secs", "a", 7.0)],
        )?;
        insert(c, now - 8 * DAY_MS, &[("host.cpu", "a", 99.0)])?;
        insert(c, now, &[("host.cpu", "a", 50.0)])?;
        compact_at(c, now)?;
        Ok((old, now, read(c, "a", &[], 0, 1)?))
      })
      .await
      .unwrap();
    let (old, now, series) = s;
    assert_eq!(series["host.cpu"], vec![(old, 20.0), (now, 50.0)]);
    assert_eq!(series["deploy.secs"].len(), 2);
  }
}
