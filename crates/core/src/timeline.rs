//! 服务的部署、备份、任务、自动重启、告警和操作记录。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, Query, State},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use wharf_api_types::view::{Perm, Timeline, TimelineItem};

use crate::{
  api::{ApiResult, service_not_found},
  auth::Auth,
  db::sql_err,
  snapshot,
  state::AppState,
};

#[derive(Deserialize)]
pub struct TimelineQuery {
  before: Option<i64>,
  limit: Option<u32>,
}

/// `GET /api/services/{name}/timeline`
pub async fn show(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<TimelineQuery>,
) -> ApiResult<Timeline> {
  auth.require(Perm::Read)?;
  if !snapshot::load(&state.db).await?.world.services.contains_key(&name) {
    return Err(service_not_found(&name).into());
  }
  let before = q.before.unwrap_or(i64::MAX);
  let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
  let rows = state
    .db
    .call(move |c| read(c, &name, before, limit).map_err(sql_err))
    .await?;
  let (items, next_before) = merge(rows, limit);
  Ok(Json(Timeline { items, next_before }))
}

fn read(
  c: &Connection,
  name: &str,
  before: i64,
  limit: usize,
) -> rusqlite::Result<Vec<TimelineItem>> {
  let mut rows = Vec::new();
  // 按完整时间组取数，边界同一毫秒的记录不会在下一页被跳过。
  let mut stmt = c.prepare(
      "SELECT created_at FROM (
         SELECT created_at, DENSE_RANK() OVER (ORDER BY created_at DESC) AS page
         FROM deployments WHERE service = ?1 AND created_at < ?2
       ) WHERE page <= ?3 ORDER BY created_at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "deploy".into(),
        title: "部署".into(),
        ok: Some(true),
        actor: None,
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  let mut stmt = c.prepare(
      "SELECT created_at, ok FROM (
         SELECT created_at, ok, DENSE_RANK() OVER (ORDER BY created_at DESC) AS page
         FROM backups WHERE service = ?1 AND created_at < ?2
       ) WHERE page <= ?3 ORDER BY created_at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "backup".into(),
        title: "备份".into(),
        ok: Some(r.get(1)?),
        actor: None,
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  let mut stmt = c.prepare(
      "SELECT started_at, task, status FROM (
         SELECT r.started_at, r.task, r.status, DENSE_RANK() OVER (ORDER BY r.started_at DESC) AS page
         FROM task_runs r JOIN tasks t ON t.name = r.task WHERE json_extract(t.spec, '$.kind') = 'exec' AND json_extract(t.spec, '$.service') = ?1 AND r.started_at < ?2
       ) WHERE page <= ?3 ORDER BY started_at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "task".into(),
        title: format!("任务 {}", r.get::<_, String>(1)?),
        ok: match r.get::<_, String>(2)?.as_str() {
            "succeeded" => Some(true),
            "running" => None,
            _ => Some(false),
          },
        actor: None,
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  let mut stmt = c.prepare(
      "SELECT at FROM (
         SELECT at, DENSE_RANK() OVER (ORDER BY at DESC) AS page
         FROM points WHERE subject = ?1 AND name = 'heal.restart' AND at < ?2
       ) WHERE page <= ?3 ORDER BY at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "heal".into(),
        title: "自动重启".into(),
        ok: None,
        actor: None,
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  let mut stmt = c.prepare(
      "SELECT at, title, ok FROM (
         SELECT at, title, ok, DENSE_RANK() OVER (ORDER BY at DESC) AS page
         FROM alert_history WHERE subject = ?1 AND source IN ('container_restarting', 'monitor_failed', 'http_5xx') AND at < ?2
       ) WHERE page <= ?3 ORDER BY at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "alert".into(),
        title: r.get(1)?,
        ok: Some(r.get(2)?),
        actor: None,
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  let mut stmt = c.prepare(
      "SELECT at, actor, method, path, status FROM (
         SELECT at, actor, method, path, status, DENSE_RANK() OVER (ORDER BY at DESC) AS page
         FROM audit_log WHERE kind = 'api' AND path LIKE '/api/services/' || ?1 || '/%' AND at < ?2
       ) WHERE page <= ?3 ORDER BY at DESC",
    )?;
  rows.extend(
    stmt.query_map(params![name, before, limit as i64 + 1], |r| {
      let path: String = r.get(3)?;
      let prefix = format!("/api/services/{name}");
      Ok(TimelineItem {
        at: r.get(0)?,
        kind: "op".into(),
        title: format!("{} {}", r.get::<_, String>(2)?, &path[prefix.len()..]),
        ok: Some(r.get::<_, u16>(4)? < 400),
        actor: Some(r.get(1)?),
      })
    })?.collect::<rusqlite::Result<Vec<_>>>()?,
  );
  Ok(rows)
}

fn merge(
  mut rows: Vec<TimelineItem>,
  limit: usize,
) -> (Vec<TimelineItem>, Option<i64>) {
  rows.sort_by(|a, b| b.at.cmp(&a.at).then(a.kind.cmp(&b.kind)));
  if rows.len() <= limit {
    return (rows, None);
  }
  let t = rows[limit - 1].at;
  let next_before = rows.iter().any(|r| r.at < t).then_some(t);
  rows.retain(|r| r.at >= t);
  (rows, next_before)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn merge_keeps_complete_milliseconds() {
    let rows = |times: &[i64]| {
      times.iter().map(|&at| TimelineItem {
        at,
        kind: "deploy".into(),
        title: "部署".into(),
        ok: Some(true),
        actor: None,
      }).collect()
    };
    let (items, next) = merge(rows(&[1, 3, 2]), 5);
    assert_eq!(items.iter().map(|i| i.at).collect::<Vec<_>>(), [3, 2, 1]);
    assert_eq!(next, None);
    let (items, next) = merge(rows(&[5, 4, 3, 2, 1]), 3);
    assert_eq!(items.len(), 3);
    assert_eq!(next, Some(3));
    let (items, next) = merge(rows(&[5, 4, 3, 3, 2]), 3);
    assert_eq!(items.len(), 4);
    assert_eq!(next, Some(3));
    assert_eq!(merge(rows(&[3, 3, 3]), 2).1, None);
  }

  #[tokio::test]
  async fn query_keeps_large_millisecond_groups() {
    let db = crate::db::Db::memory();
    db.call(|c| {
      for at in std::iter::repeat_n(2, 52).chain([1]) {
        c.execute(
          "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at)
           VALUES ('s1', 's2', '', '', '', '[]', ?1)",
          [at],
        ).map_err(sql_err)?;
      }
      let (first, next) = merge(read(c, "s1", i64::MAX, 50).map_err(sql_err)?, 50);
      assert_eq!(first.len(), 52);
      assert!(first.iter().all(|i| i.at == 2));
      assert_eq!(next, Some(2));
      let (last, next) = merge(read(c, "s1", next.unwrap(), 50).map_err(sql_err)?, 50);
      assert_eq!(last.len(), 1);
      assert_eq!(last[0].at, 1);
      assert_eq!(next, None);
      Ok(())
    }).await.unwrap();
  }
}
