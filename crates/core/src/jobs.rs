//! 定时任务，每 10 分钟检查一次：
//! - 开启备份的服务，上次成功备份超过 24 小时就备份（失败后 1 小时内不重试）；
//! - 迁移后留在旧服务器上的数据，7 天后删除（服务又迁回来了就不删）。

use std::{sync::Arc, time::Duration};

use rusqlite::params;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, ErrorCode, agent::AgentOp};

use crate::{
  apply,
  db::{now_ms, sql_err},
  planner::Step,
  snapshot,
  state::AppState,
};

const TICK: Duration = Duration::from_secs(10 * 60);
const FIRST_TICK: Duration = Duration::from_secs(2 * 60);
const BACKUP_EVERY_MS: i64 = 24 * 3600 * 1000;
const RETRY_AFTER_MS: i64 = 3600 * 1000;
/// 迁移后旧数据保留多久。
pub const KEEP_OLD_DATA_MS: i64 = 7 * 24 * 3600 * 1000;

/// 边缘应用现状的刷新间隔。
const EDGE_REFRESH: Duration = Duration::from_secs(5 * 60);

pub fn spawn(state: Arc<AppState>) {
  let edge_state = state.clone();
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(10)).await;
    loop {
      if let Err(e) = crate::edge_sync::sync_all(&edge_state).await {
        tracing::warn!("同步边缘应用失败：{e}");
      }
      tokio::time::sleep(EDGE_REFRESH).await;
    }
  });
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    loop {
      if let Err(e) = cleanups(&state).await {
        tracing::warn!("清理迁移留下的旧数据失败：{e}");
      }
      if let Err(e) = backups(&state).await {
        tracing::warn!("定时备份失败：{e}");
      }
      if let Err(e) = crate::uploads::cleanup(&state).await {
        tracing::warn!("清理代码包失败：{e}");
      }
      tokio::time::sleep(TICK).await;
    }
  });
}

/// 每次最多发起一个备份：备份占用 apply 锁，其他的等下一轮。
async fn backups(state: &Arc<AppState>) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let now = now_ms();
  // 控制面自己先备份：它丢了，服务备份的口令也跟着丢了。
  let (core_on, core_ok, core_any): (bool, Option<i64>, Option<i64>) =
    state
      .db
      .call(|c| {
        let any = c
          .query_row(
            "SELECT MAX(created_at) FROM backups WHERE service = ?1",
            params![crate::core_backup::REPO],
            |r| r.get(0),
          )
          .map_err(sql_err)?;
        Ok((
          crate::core_backup::enabled(c)?,
          crate::core_backup::last_ok(c)?,
          any,
        ))
      })
      .await?;
  let backoff = core_any
    .is_some_and(|t| core_any != core_ok && now - t < RETRY_AFTER_MS);
  if core_on
    && core_ok.is_none_or(|t| now - t >= BACKUP_EVERY_MS)
    && !backoff
  {
    apply::start_task(
      state.clone(),
      "备份控制面".into(),
      Step::CoreBackup { user_key: None },
    )
    .await?;
    return Ok(());
  }
  for (name, row) in &snap.world.services {
    if row.spec.backup.is_none() {
      continue;
    }
    let n = name.clone();
    let (last_ok, last_any): (Option<i64>, Option<i64>) = state
      .db
      .call(move |c| {
        c.query_row(
          "SELECT MAX(CASE WHEN ok THEN created_at END), MAX(created_at) FROM backups WHERE service = ?1",
          params![n],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql_err)
      })
      .await?;
    let stale = last_ok.is_none_or(|t| now - t >= BACKUP_EVERY_MS);
    let backoff = last_any.is_some_and(|t| {
      last_any != last_ok && now - t < RETRY_AFTER_MS
    });
    if !stale || backoff {
      continue;
    }
    match apply::start_task(
      state.clone(),
      format!("定时备份 {name}"),
      Step::Backup {
        service: name.clone(),
      },
    )
    .await
    {
      Ok(r) => {
        tracing::info!("定时备份 {name}：{}", r.run_id);
        return Ok(());
      }
      Err(e) if e.code == ErrorCode::Busy => return Ok(()),
      Err(e) => return Err(e),
    }
  }
  Ok(())
}

/// 迁移成功后记下旧服务器上要删除的数据。
pub async fn schedule_cleanup(
  state: &AppState,
  service: &str,
  server: &str,
) -> Result<(), ApiError> {
  let (service, server) = (service.to_string(), server.to_string());
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO cleanups (service, server, due_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (service, server) DO UPDATE SET due_at = excluded.due_at",
        params![service, server, now_ms() + KEEP_OLD_DATA_MS],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

async fn cleanups(state: &AppState) -> Result<(), ApiError> {
  let now = now_ms();
  let due: Vec<(String, String)> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT service, server FROM cleanups WHERE due_at <= ?1",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  if due.is_empty() {
    return Ok(());
  }
  let snap = snapshot::load(&state.db).await?;
  for (service, server) in due {
    // 服务又回到这台机器上了：数据在用，不删。
    let back = snap
      .world
      .services
      .get(&service)
      .is_some_and(|s| s.spec.server == server)
      || snap.deployed.get(&service) == Some(&server);
    if !back {
      if !state.hub.is_online(&server) {
        continue;
      }
      let removed = state
        .hub
        .call::<serde_json::Value>(
          &server,
          AgentOp::RemoveData {
            service: service.clone(),
          },
          Duration::from_secs(30 * 60),
          None,
          &CancellationToken::new(),
        )
        .await;
      if let Err(e) = removed {
        tracing::warn!(
          "删除 {server} 上 {service} 的旧数据失败：{e}"
        );
        continue;
      }
      tracing::info!("已删除 {server} 上 {service} 迁移前的旧数据");
    }
    let (s, v) = (service.clone(), server.clone());
    state
      .db
      .call(move |c| {
        c.execute(
          "DELETE FROM cleanups WHERE service = ?1 AND server = ?2",
          params![s, v],
        )
        .map_err(sql_err)?;
        Ok(())
      })
      .await?;
  }
  Ok(())
}
