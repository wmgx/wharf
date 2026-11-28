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
    !snap.pending.backup_moves.contains_key(name)
      && snap.deployed.contains_key(name)
      && snapshot::service_runtime_server(snap, name)
        .is_some_and(&online)
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
      if !edge_state.is_safe_mode()
        && let Err(e) = crate::edge_sync::sync_all(&edge_state).await
      {
        tracing::warn!("同步边缘应用失败：{e}");
      }
      tokio::time::sleep(EDGE_REFRESH).await;
    }
  });
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    loop {
      if state.is_safe_mode() {
        tokio::time::sleep(TICK).await;
        continue;
      }
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
      if let Err(e) = crate::run_logs::cleanup(&state).await {
        tracing::warn!("清理执行日志失败：{e}");
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

/// 每轮可独立发起一个控制面备份和一个业务备份。
async fn backups(state: &Arc<AppState>) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let history = crate::data::history(&state.db).await?;
  let now = now_ms();
  let core = state.db.call(|c| crate::core_backup::target(c)).await?;
  if let Some(target) = core {
    let repo = crate::core_backup::REPO;
    let h = history.get(&(repo.to_string(), target.clone()));
    let empty = crate::data::repo_verified_empty(
      state, &snap, &target, repo, h,
    );
    if !snap.pending.backup_moves.contains_key(repo)
      && state.hub.is_online(&target)
      && crate::core_node::server_of(&snap)
        .is_some_and(|name| state.hub.is_online(&name))
      && due(h, empty, now)
    {
      let result = apply::start_task_by(
        state.clone(),
        "备份控制面".into(),
        Step::CoreBackup {
          options: Default::default(),
          user_key: None,
          target: None,
          owner_secret: None,
        },
        Some("定时备份".into()),
      )
      .await;
      if let Some(e) = core_backup_error(result) {
        tracing::warn!("发起控制面备份失败：{e}");
      }
    }
    let issues = crate::core_backup::issues(&state.db).await?;
    let current = issues.is_empty();
    crate::rules::notice(
      state,
      "backup",
      Some(crate::core_backup::REPO),
      Some("backup.wharf-core.key"),
      current,
      crate::notify::Event {
        title: if current {
          "控制面备份恢复口令已同步".into()
        } else {
          "控制面备份的登录密码恢复口令已失效".into()
        },
        body: issues
          .first()
          .and_then(|i| i.hint.clone())
          .unwrap_or_default(),
      },
    )
    .await;
  }
  let mut candidates = Vec::new();
  for (name, row) in &snap.world.services {
    if !is_backup_candidate(&snap, name, row, |server| {
      state.hub.is_online(server)
    }) {
      continue;
    }
    let Some(backup) = &row.spec.backup else {
      continue;
    };
    let h = history.get(&(name.clone(), backup.to.clone()));
    let ok = h.and_then(|h| h.ok);
    let empty = crate::data::repo_verified_empty(
      state, &snap, &backup.to, name, h,
    );
    if due(h, empty, now) {
      candidates.push((ok.filter(|_| !empty), name));
    }
  }
  candidates.sort_unstable();
  for (_, name) in candidates {
    match apply::start_task_by(
      state.clone(),
      format!("定时备份 {name}"),
      Step::Backup {
        options: Default::default(),
        service: name.clone(),
      },
      Some("定时备份".into()),
    )
    .await
    {
      Ok(r) => {
        tracing::info!("定时备份 {name}：{}", r.run_id);
        break;
      }
      Err(e) if e.code == ErrorCode::Busy => continue,
      Err(e) => return Err(e),
    }
  }
  Ok(())
}

fn due(
  history: Option<&crate::data::BackupHistory>,
  empty: bool,
  now: i64,
) -> bool {
  let ok = history.and_then(|h| h.ok);
  let failed = history.and_then(|h| h.failed);
  let backoff = failed.is_some_and(|f| {
    ok.is_none_or(|ok| f >= ok) && now - f < RETRY_AFTER_MS
  });
  !backoff
    && (empty || ok.is_none_or(|ok| now - ok >= BACKUP_EVERY_MS))
}

/// 迁移成功后记下旧服务器上要删除的数据。
pub fn schedule_cleanup(
  c: &rusqlite::Connection,
  service: &str,
  server: &str,
  instance_id: Option<&str>,
) -> Result<(), ApiError> {
  c.execute(
    "INSERT INTO cleanups (service, server, due_at, instance_id) VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT (service, server) DO UPDATE SET due_at = excluded.due_at, instance_id = excluded.instance_id",
    params![service, server, now_ms() + KEEP_OLD_DATA_MS, instance_id],
  )
  .map_err(sql_err)?;
  Ok(())
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
    let result = apply::start_task_by(
      state.clone(),
      format!("清理 {server} 上 {service} 的旧数据"),
      Step::CleanupData {
        service,
        server,
        instance_id,
      },
      Some("到期清理".into()),
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
  guard: crate::locks::OpLockGuard,
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
  if let Some(consumer) =
    crate::shared_volumes::consumers_on(&snap.world, service, server)
      .next()
  {
    progress(format!(
      "跳过清理 {server} 上 /srv/{service}：{consumer} 仍在引用共享卷"
    ));
    return Ok(());
  }
  if row.is_some_and(|r| r.spec.server == server)
    || snap.deployed.get(service).is_some_and(|s| s == server)
    || snapshot::service_runtime_server(&snap, service)
      == Some(server)
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
  snap.world.services.insert("app".into(), crate::world::ServiceRow {
    instance_id: "svc_fixture".into(),
    spec: serde_json::from_value(serde_json::json!({
      "server":"s1", "source":{"image":"fixture:1"}, "backup":{"to":"s2"}, "stopped":true
    })).unwrap(),
    host_ports: Default::default(), import: None, pins: Default::default(),
    commit: None, version: 1,
  });
  let row = &snap.world.services["app"];
  assert!(
    core_backup_error(Err(ApiError::new(ErrorCode::Busy, "忙")))
      .is_none()
  );
  assert!(!is_backup_candidate(&snap, "app", row, |_| true));
  snap.deployed.insert("app".into(), "s1".into());
  assert!(!is_backup_candidate(&snap, "app", row, |s| s == "s1"));
  assert!(is_backup_candidate(&snap, "app", row, |s| matches!(
    s,
    "s1" | "s2"
  )));
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
  let locked = state
    .locks
    .acquire(crate::locks::LockSpec::apply([]), "测试")
    .unwrap();
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
    let lock = state
      .locks
      .acquire(
        crate::locks::LockSpec::apply(["s1".into(), "app".into()]),
        "测试",
      )
      .unwrap();
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
  let guard = state
    .locks
    .acquire(
      crate::locks::LockSpec::apply(["s1".into(), "app".into()]),
      "测试",
    )
    .unwrap();
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

#[test]
fn scheduler_uses_target_and_empty_repo_state() {
  let now = BACKUP_EVERY_MS * 2;
  let ok = crate::data::BackupHistory {
    ok: Some(now - 180_000),
    ..Default::default()
  };
  assert!(!due(Some(&ok), false, now));
  assert!(due(Some(&ok), true, now));
  assert!(due(None, false, now));
  let failed = crate::data::BackupHistory {
    failed: Some(now - 500),
    ..Default::default()
  };
  assert!(!due(Some(&failed), true, now));
  assert!(due(Some(&failed), true, now + RETRY_AFTER_MS));
}

#[tokio::test]
async fn failed_core_backup_does_not_starve_service_backups() {
  let state = crate::rules::tests::test_state();
  crate::backup::tests::seed_servers(&state).await;
  crate::backup::tests::seed_service(&state, "svc-a", true).await;
  seed_scheduled_backup_agents(&state, &["s1", "s2"]).await;
  state
    .db
    .call(|c| {
      c.execute(
        "INSERT INTO agents (server, public_key) VALUES ('s1', 's1')",
        [],
      )
      .map_err(sql_err)?;
      crate::db::set_setting(
        c,
        crate::core_node::SERVER_KEY,
        Some("s1"),
      )?;
      crate::db::set_setting(
        c,
        crate::core_node::PUBKEY_KEY,
        Some("s1"),
      )?;
      crate::db::set_setting(c, crate::core_backup::TO, Some("s2"))
    })
    .await
    .unwrap();
  backups(&state).await.unwrap();
  tokio::time::timeout(Duration::from_secs(2), async {
    loop {
      let history = crate::data::history(&state.db).await.unwrap();
      if history.len() == 2 {
        break;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .unwrap();
  let history = crate::data::history(&state.db).await.unwrap();
  assert!(history.values().all(|record| !due(
    Some(record),
    true,
    now_ms()
  )));
}

#[tokio::test]
async fn scheduler_picks_oldest_backup_first() {
  let state = crate::rules::tests::test_state();
  crate::backup::tests::seed_servers(&state).await;
  for service in ["svc-a", "svc-m", "svc-z"] {
    crate::backup::tests::seed_service(&state, service, true).await;
  }
  seed_scheduled_backup_agents(&state, &["s1", "s2"]).await;
  state.db.call(|c| {
    let at = now_ms() - BACKUP_EVERY_MS;
    for (name, age) in [("svc-a", 3_600_000), ("svc-m", 16 * 3_600_000)] {
      c.execute("INSERT INTO backups (service, server, target, run_id, ok, body, created_at)
        VALUES (?1, 's1', 's2', 'r1', 1, '{}', ?2)", params![name, at - age]).map_err(sql_err)?;
    }
    Ok(())
  }).await.unwrap();
  for expected in ["svc-z", "svc-m", "svc-a"] {
    backups(&state).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
      loop {
        let rows =
          crate::backup::records(&state, expected, 1).await.unwrap();
        if rows.first().is_some_and(|row| !row.ok)
          && state
            .locks
            .acquire(
              crate::locks::LockSpec::Backup(expected.into()),
              "测试",
            )
            .is_ok()
        {
          break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    })
    .await
    .unwrap();
  }
}

#[tokio::test]
async fn backup_target_busy_is_rejected_before_snapshot_or_run() {
  use crate::locks::LockSpec;

  let dir = tempfile::tempdir().unwrap();
  let mut state = crate::rules::tests::test_state();
  let inner = Arc::get_mut(&mut state).unwrap();
  inner.data_dir = dir.path().into();
  inner.db =
    crate::db::Db::open(&dir.path().join("wharf.db")).unwrap();
  crate::backup::tests::seed_servers(&state).await;
  for service in ["svc-a", "svc-b", "svc-c"] {
    crate::backup::tests::seed_service(&state, service, true).await;
  }
  state.db.call(|c| {
    crate::db::apply_write(c, &crate::db::Write::Upsert {
      kind: "server".into(), name: "s3".into(),
      spec: serde_json::json!({"private_addr": {"ip": "100.64.0.3", "network": "lan"}}),
      meta: serde_json::json!({}),
    })?;
    c.execute("UPDATE resources SET spec = json_set(spec, '$.backup.to', 's3')
      WHERE kind = 'service' AND name = 'svc-c'", []).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();

  seed_scheduled_backup_agents(&state, &["s1", "s2", "s3"]).await;

  let backup = state
    .locks
    .acquire(LockSpec::Backup("svc-a".into()), "备份")
    .unwrap();
  backup.reserve_backup_target("s2".into()).unwrap();
  backup.set_run("r_backup");
  let err = crate::backup::restore_now(
    axum::extract::State(state.clone()),
    crate::security_receipt::tests::auth(true),
    axum::extract::Path("svc-b".into()),
    None,
    Default::default(),
    axum::Json(wharf_api_types::view::RestoreRequest {
      target: None,
      snapshot: "abcd1234".into(),
      confirm: "service/svc-b".into(),
      skip_snapshot: false,
    }),
  )
  .await
  .err()
  .unwrap()
  .0;
  assert_eq!(err.code, ErrorCode::Busy);
  assert_eq!(err.suggest, ["wharf run cancel r_backup"]);
  assert!(!dir.path().join("snapshots").exists());
  drop(backup);

  let restore = state
    .locks
    .acquire(LockSpec::apply(["svc-b".into()]), "恢复")
    .unwrap();
  restore.reserve_backup_target("s2".into()).unwrap();
  restore.set_run("r_restore");
  let err = apply::start_task(
    state.clone(),
    "备份 svc-a".into(),
    Step::Backup {
      options: Default::default(),
      service: "svc-a".into(),
    },
  )
  .await
  .err()
  .unwrap();
  assert_eq!(err.code, ErrorCode::Busy);
  assert_eq!(err.suggest, ["wharf run cancel r_restore"]);
  backups(&state).await.unwrap();
  let titles = state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT json_extract(body, '$.steps[0].title') FROM runs",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await
    .unwrap();
  assert_eq!(titles, ["定时备份 svc-c"]);
}

#[cfg(test)]
async fn seed_scheduled_backup_agents(
  state: &AppState,
  servers: &[&str],
) {
  for server in servers {
    state.hub.mock_agent(server, false, |op| {
      assert!(matches!(
        op,
        wharf_api_types::agent::AgentOp::ProjectStatus { .. }
      ));
      Ok(serde_json::json!([]))
    });
  }
  state.db.call(|c| {
    c.execute(
      "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, instance_id)
       SELECT name, json_extract(spec, '$.server'), 'r_fixture', 'fixture', '', '[]', 0,
              json_extract(meta, '$.instance_id') FROM resources WHERE kind = 'service'",
      [],
    ).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
}
