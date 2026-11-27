//! 定时任务，每 10 分钟检查一次：
//! - 开启备份的服务，上次成功备份超过 24 小时就备份（失败后 1 小时内不重试）；
//! - 迁移后留在旧服务器上的数据，7 天后删除（服务又迁回来了就不删）。

use std::{sync::Arc, time::Duration};

use rusqlite::params;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, ErrorCode, agent::RemoveDataResult};

use crate::{
  apply,
  db::{now_ms, sql_err},
  hub::ProgressFn,
  planner::Step,
  snapshot,
  state::AppState,
};

/// 连通性重新探测的间隔，远小于结果的有效期（一天）。
const REACH_REFRESH: Duration = Duration::from_secs(6 * 3600);
const TICK: Duration = Duration::from_secs(10 * 60);
const FIRST_TICK: Duration = Duration::from_secs(2 * 60);
const BACKUP_EVERY_MS: i64 = 24 * 3600 * 1000;
const RETRY_AFTER_MS: i64 = 3600 * 1000;
/// 迁移后旧数据保留多久。
pub const KEEP_OLD_DATA_MS: i64 = 7 * 24 * 3600 * 1000;

/// 边缘应用现状的刷新间隔。
const EDGE_REFRESH: Duration = Duration::from_secs(5 * 60);

fn core_backup_error(
  result: Result<wharf_api_types::plan::ApplyResponse, ApiError>,
) -> Option<ApiError> {
  result.err().filter(|e| e.code != ErrorCode::Busy)
}

fn is_backup_candidate(
  snap: &snapshot::Snapshot,
  name: &str,
  row: &crate::world::ServiceRow,
  online: impl Fn(&str) -> bool,
) -> bool {
  row.spec.backup.as_ref().is_some_and(|backup| {
    snap.deployed.contains_key(name)
      && online(&row.spec.server)
      && online(&backup.to)
  })
}

pub fn spawn(state: Arc<AppState>) {
  let edge_state = state.clone();
  let reach_state = state.clone();
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    loop {
      if let Err(e) = crate::network::probe_all(&reach_state).await {
        tracing::warn!("探测机器之间的连通性失败：{e}");
      }
      tokio::time::sleep(REACH_REFRESH).await;
    }
  });
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
      if let Err(e) = crate::metrics::compact(&state).await {
        tracing::warn!("整理打点失败：{e}");
      }
      if let Err(e) = crate::audit::cleanup(&state).await {
        tracing::warn!("清理操作记录失败：{e}");
      }
      if let Err(e) = crate::db_snapshot::cleanup(&state).await {
        tracing::warn!("清理本机热快照失败：{}", e.message);
      }
      if let Err(e) = crate::uploads::cleanup(&state).await {
        tracing::warn!("清理代码包失败：{e}");
      }
      if let Err(e) = crate::sso_login::cleanup(&state).await {
        tracing::warn!("读取待清理的代登录配置失败：{e}");
      }
      if let Err(e) = crate::gate::revocations::cleanup(&state).await
      {
        tracing::warn!("清理门禁吊销名单失败：{e}");
      }
      match state
        .db
        .call(|c| {
          crate::db::cleanup_expired_secret_prevs(c, now_ms())
        })
        .await
      {
        Ok(0) => {}
        Ok(_) => crate::log_redact::refresh(&state.db).await,
        Err(e) => tracing::warn!("清理过期密钥旧值失败：{e}"),
      }
      if let Err(e) = crate::key_rotation::cleanup(&state).await {
        tracing::warn!("清理过期通信密钥失败：{e}");
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
  let (target, core_ok, core_any) = state
    .db
    .call(|c| {
      let any: Option<i64> = c
        .query_row(
          "SELECT MAX(created_at) FROM backups WHERE service = ?1",
          params![crate::core_backup::REPO],
          |r| r.get(0),
        )
        .map_err(sql_err)?;
      Ok((
        crate::core_backup::target(c)?,
        crate::core_backup::last_ok(c)?,
        any,
      ))
    })
    .await?;
  let backoff = core_any
    .is_some_and(|t| core_any != core_ok && now - t < RETRY_AFTER_MS);
  if target
    .as_deref()
    .is_some_and(|name| state.hub.is_online(name))
    && crate::core_node::server_of(&snap)
      .is_some_and(|name| state.hub.is_online(&name))
    && core_ok.is_none_or(|t| now - t >= BACKUP_EVERY_MS)
    && !backoff
  {
    let result = apply::start_task(
      state.clone(),
      "备份控制面".into(),
      Step::CoreBackup { user_key: None },
    )
    .await;
    if let Some(error) = core_backup_error(result) {
      tracing::warn!("定时备份控制面失败：{error}");
    }
  }
  let mut candidates = vec![];
  for (name, row) in &snap.world.services {
    if !is_backup_candidate(&snap, name, row, |server| {
      state.hub.is_online(server)
    }) {
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
    if stale && !backoff {
      candidates.push((last_ok, name));
    }
  }
  let Some((_, name)) = candidates.into_iter().min() else {
    return Ok(());
  };
  match apply::start_task(
    state.clone(),
    format!("定时备份 {name}"),
    Step::Backup {
      service: name.clone(),
    },
  )
  .await
  {
    Ok(r) => tracing::info!("定时备份 {name}：{}", r.run_id),
    Err(e) if e.code == ErrorCode::Busy => {}
    Err(e) => return Err(e),
  }
  Ok(())
}

/// 迁移成功后记下旧服务器上要删除的数据。
pub async fn schedule_cleanup(
  state: &AppState,
  service: &str,
  server: &str,
  instance_id: Option<&str>,
) -> Result<(), ApiError> {
  let (service, server) = (service.to_string(), server.to_string());
  let instance_id = instance_id.map(str::to_string);
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO cleanups (service, server, due_at, instance_id) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (service, server) DO UPDATE SET due_at = excluded.due_at, instance_id = excluded.instance_id",
        params![service, server, now_ms() + KEEP_OLD_DATA_MS, instance_id],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

async fn cleanups(state: &Arc<AppState>) -> Result<(), ApiError> {
  let now = now_ms();
  let due: Vec<(String, String, Option<String>)> = state.db.call(move |c| {
    let mut stmt = c.prepare("SELECT service, server, instance_id FROM cleanups WHERE due_at <= ?1 ORDER BY due_at ASC").map_err(sql_err)?;
    let rows = stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(sql_err)?;
    rows.collect::<Result<_, _>>().map_err(sql_err)
  }).await?;
  for (service, server, instance_id) in due {
    if !state.hub.is_online(&server) {
      continue;
    }
    if !state.hub.supports_safe_delete(&server) {
      tracing::warn!(
        "服务器 {server} 的 agent 版本旧，升级后再清理 {service} 的旧数据"
      );
      continue;
    }
    let result = apply::start_task(
      state.clone(),
      format!("清理 {server} 上 {service} 的旧数据"),
      Step::CleanupData {
        service,
        server,
        instance_id,
      },
    )
    .await;
    return match result {
      Err(e) if e.code == ErrorCode::Busy => Ok(()),
      result => result.map(|_| ()),
    };
  }
  Ok(())
}

pub(crate) async fn cleanup_data(
  state: &AppState,
  (service, server, instance_id): (&str, &str, Option<&str>),
  progress: ProgressFn,
  cancel: &CancellationToken,
  guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<(), ApiError> {
  let key = (
    service.to_string(),
    server.to_string(),
    instance_id.map(str::to_string),
  );
  let query = key.clone();
  // 先留出重试间隔，避免同一条清理重复下发或挡住其余到期清理。
  let claimed = state.db.call(move |c| {
    let now = now_ms();
    let retry_at = now + RETRY_AFTER_MS;
    let updated = c.execute(
      "UPDATE cleanups SET due_at = ?5 WHERE service = ?1 AND server = ?2 AND instance_id IS ?3 AND due_at <= ?4",
      params![query.0, query.1, query.2, now, retry_at],
    ).map_err(sql_err)?;
    Ok((updated != 0).then_some(retry_at))
  }).await?;
  let Some(retry_at) = claimed else {
    return Ok(());
  };
  let snap = snapshot::load(&state.db).await?;
  let row = snap.world.services.get(service);
  if row.is_some_and(|r| r.spec.server == server)
    || snap.deployed.get(service).is_some_and(|s| s == server)
  {
    progress(format!("服务已回到 {server}，取消清理"));
    drop(guard);
  } else if row
    .is_some_and(|r| Some(r.instance_id.as_str()) != instance_id)
  {
    progress(format!(
      "服务 {service} 已同名重建，取消旧实例的数据清理"
    ));
    drop(guard);
  } else {
    let result: RemoveDataResult = state
      .hub
      .dispatch_cleanup(
        server,
        service,
        progress.clone(),
        cancel,
        guard,
      )
      .await?;
    if result.removed {
      progress(format!("已删除 {server} 上 /srv/{service}"));
    } else {
      progress(format!(
        "跳过删除 {server} 上 /srv/{service}：仍有容器挂载（{}）",
        result.blocked_by.join("、")
      ));
    }
  }
  state.db.call(move |c| {
    c.execute("DELETE FROM cleanups WHERE service = ?1 AND server = ?2 AND instance_id IS ?3 AND due_at = ?4", params![key.0, key.1, key.2, retry_at]).map_err(sql_err)?;
    Ok(())
  }).await
}

#[test]
fn backups_skips_busy_core_offline_and_undeployed() {
  let mut snap = snapshot::Snapshot::default();
  let row = crate::world::ServiceRow {
    instance_id: "svc_fixture".into(),
    spec: serde_json::from_value(serde_json::json!({
      "server":"s1", "source":{"image":"fixture:1"}, "backup":{"to":"s2"}, "stopped":true
    })).unwrap(),
    host_ports: Default::default(), import: None, pins: Default::default(),
    commit: None, version: 1,
  };
  assert!(
    core_backup_error(Err(ApiError::new(ErrorCode::Busy, "忙")))
      .is_none()
  );
  assert!(!is_backup_candidate(&snap, "app", &row, |_| true));
  snap.deployed.insert("app".into(), "hash".into());
  assert!(!is_backup_candidate(&snap, "app", &row, |s| s == "s1"));
  assert!(is_backup_candidate(&snap, "app", &row, |_| true));
}

#[tokio::test]
async fn cleanup_skips_when_service_moved_back_or_rebuilt() {
  let state = crate::rules::tests::test_state();
  state
    .hub
    .mock_safe_delete_agent("s1", |_| panic!("不应发送清理请求"));
  state
    .db
    .call(|c| {
      c.execute_batch(
        "INSERT INTO cleanups (service, server, due_at, instance_id)
      VALUES ('app', 's1', 0, 'svc_old')",
      )
      .map_err(sql_err)
    })
    .await
    .unwrap();
  let locked = state.apply_lock.lock().await;
  cleanups(&state).await.unwrap();
  assert!(
    state
      .db
      .call(|c| c
        .query_row("SELECT EXISTS(SELECT 1 FROM cleanups)", [], |r| r
          .get::<_, bool>(0))
        .map_err(sql_err))
      .await
      .unwrap()
  );
  drop(locked);
  for (server, instance) in [("s1", "svc_old"), ("s2", "svc_new")] {
    state.db.call(move |c| {
      c.execute("INSERT OR REPLACE INTO cleanups (service, server, due_at, instance_id)
        VALUES ('app', 's1', 0, 'svc_old')", []).map_err(sql_err)?;
      c.execute("INSERT OR REPLACE INTO resources (kind, name, spec, meta, version, created_at, updated_at)
        VALUES ('service', 'app', json_object('server', ?1, 'source', json_object('image', 'fixture:1')),
          json_object('instance_id', ?2), 1, 0, 0)", params![server, instance]).map_err(sql_err)
    }).await.unwrap();
    let lock = state.apply_lock.clone().lock_owned().await;
    cleanup_data(
      &state,
      ("app", "s1", Some("svc_old")),
      Arc::new(|_| {}),
      &CancellationToken::new(),
      lock,
    )
    .await
    .unwrap();
    let count = state
      .db
      .call(|c| {
        c.query_row("SELECT COUNT(*) FROM cleanups", [], |r| {
          r.get::<_, i64>(0)
        })
        .map_err(sql_err)
      })
      .await
      .unwrap();
    assert_eq!(count, 0);
  }
}

#[tokio::test]
async fn failed_cleanup_does_not_starve_next_due_record() {
  let state = crate::rules::tests::test_state();
  state.hub.mock_safe_delete_agent("s1", |_| {
    Err(ApiError::invalid("项目仍在部署"))
  });
  let (sent, received) = tokio::sync::oneshot::channel();
  let mut sent = Some(sent);
  state.hub.mock_safe_delete_agent("s2", move |op| {
    assert!(matches!(op, wharf_api_types::agent::AgentOp::RemoveData { service } if service == "s2"));
    sent.take().unwrap().send(()).unwrap();
    Ok(serde_json::json!({"removed": true, "blocked_by": []}))
  });
  state.db.call(|c| {
    c.execute_batch(
      "INSERT INTO cleanups (service, server, due_at) VALUES ('s1', 's1', 0), ('s2', 's2', 1)",
    ).map_err(sql_err)
  }).await.unwrap();
  let guard = state.apply_lock.clone().lock_owned().await;
  let err = cleanup_data(
    &state,
    ("s1", "s1", None),
    Arc::new(|_| {}),
    &CancellationToken::new(),
    guard,
  )
  .await
  .unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  cleanups(&state).await.unwrap();
  tokio::time::timeout(Duration::from_secs(2), received)
    .await
    .unwrap()
    .unwrap();
}
