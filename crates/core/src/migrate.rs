//! 迁移服务的数据：`/srv/<service>/` 从一台服务器搬到另一台，走内网地址。
//!
//! 1. 目标机器起 rsync 接收端（一次性口令，只接受源机器的地址）；
//! 2. 源机器在服务运行时推送一遍，传完大部分数据；
//! 3. 停掉源机器上的容器，再增量推送一遍；
//! 4. 关掉接收端。之后由普通的步骤在新机器上起服务、切网关、删旧容器。
//!
//! 第 3 步之后失败时把源机器上的容器重新启动，不让服务一直停着。

use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use serde::Deserialize;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BindMountQuery, BindMountUser, OneTimeSecret,
    SYNC_BACKUP, SYNC_READY, SyncPass, SyncPush, SyncServe,
  },
};

use crate::{
  hub::ProgressFn,
  pending::{self, MigratePhase},
  render::Net,
  state::AppState,
};

const SERVE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
const PUSH_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Deserialize)]
struct Pushed {
  synced: bool,
}

fn private_ip(net: &Net, server: &str) -> Result<String, ApiError> {
  net
    .private
    .get(server)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务器 {server} 没有内网地址，迁移数据走不通"
      ))
      .suggest(format!("wharf server set {server} --private-ip <ip>"))
    })
}

fn one_time_password() -> OneTimeSecret {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  OneTimeSecret(hex::encode(bytes))
}

async fn check_writers(
  state: &AppState,
  source: (&str, u64),
  service: &str,
  exclude_owner: bool,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let users: Vec<BindMountUser> = state
    .hub
    .call_bound(
      source,
      AgentOp::BindMountUsers(BindMountQuery {
        path: format!("/srv/{service}"),
        running_only: true,
        writable_only: true,
        exclude_projects: if exclude_owner {
          vec![service.to_string()]
        } else {
          Vec::new()
        },
      }),
      STOP_TIMEOUT,
      None,
      cancel,
    )
    .await?;
  if users.is_empty() {
    return Ok(());
  }
  let users = users
    .into_iter()
    .map(|u| u.project.unwrap_or(u.container))
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>()
    .join("、");
  Err(ApiError::new(ErrorCode::Conflict, format!(
    "无法迁移 {service}：仍有活动容器可写挂载 /srv/{service}（{users}）"
  )).with_hint("先用 wharf service stop 停止共用该目录的服务，或将挂载改为只读（:ro）"))
}

pub async fn volume_sync(
  state: &AppState,
  net: &Net,
  service: &str,
  (from, to, shared): (&str, &str, bool),
  source_should_run: bool,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  for server in [from, to] {
    state.hub.require_safe_migrate(server)?;
  }
  let source_ip = private_ip(net, from)?;
  let target_ip = private_ip(net, to)?;
  let password = one_time_password();
  let name = service.to_string();
  let existing = state
    .db
    .call(move |c| Ok(pending::load(c)?.migrations.remove(&name)))
    .await?;
  if existing.as_ref().is_some_and(|m| {
    m.payload.from == from
      && m.payload.to == to
      && m.phase != MigratePhase::Pending
  }) {
    return Ok(());
  }
  let mount_conn =
    if shared || state.hub.supports_shared_volumes(from) {
      Some(state.hub.shared_volumes_conn_id(from)?)
    } else {
      None
    };
  if let Some(conn) = mount_conn {
    check_writers(state, (from, conn), service, true, cancel).await?;
  }
  let preserve_existing = existing.as_ref().is_none_or(|m| {
    !m.payload.target_prepared && m.payload.target_backup.is_none()
  });
  let already_stopped =
    existing.is_some_and(|m| m.payload.source_stopped);

  let serve_cancel = cancel.child_token();
  let work_cancel = cancel.child_token();
  let (ready_tx, ready_rx) =
    oneshot::channel::<(u16, Option<String>)>();
  let ready = Arc::new(Mutex::new((Some(ready_tx), None)));
  let serve_progress: ProgressFn = {
    let progress = progress.clone();
    let to = to.to_string();
    Arc::new(move |line: String| {
      if let Some(backup) = line.strip_prefix(SYNC_BACKUP) {
        ready.lock().unwrap_or_else(|p| p.into_inner()).1 =
          Some(backup.to_string());
        progress(format!(
          "目标机原有 /srv 目录非空，已改名保留到 {backup}"
        ));
      } else if let Some(port) =
        line.strip_prefix(SYNC_READY).and_then(|p| p.parse().ok())
      {
        let mut ready =
          ready.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tx) = ready.0.take() {
          let _ = tx.send((port, ready.1.take()));
        }
        progress(format!("{to} 上的接收端已就绪"));
      } else {
        progress(format!("[{to}] {line}"));
      }
    })
  };
  let serve = async {
    let result = state
      .hub
      .call::<serde_json::Value>(
        to,
        AgentOp::SyncServe(SyncServe {
          service: service.to_string(),
          bind: target_ip.clone(),
          allow: source_ip,
          password: password.clone(),
          preserve_existing,
        }),
        SERVE_TIMEOUT,
        Some(serve_progress),
        &serve_cancel,
      )
      .await;
    if !serve_cancel.is_cancelled() {
      work_cancel.cancel();
    }
    result
  };

  let may_need_restart =
    std::sync::atomic::AtomicBool::new(already_stopped);
  let work = async {
    let (port, backup) = tokio::select! {
      ready = ready_rx => ready.map_err(|_| ApiError::new(
        ErrorCode::AgentFailed,
        format!("{to} 上的 rsync 接收端没有启动"),
      ))?,
      _ = tokio::time::sleep(READY_TIMEOUT) => return Err(ApiError::new(
        ErrorCode::Timeout,
        format!("{to} 上的 rsync 接收端 {} 秒内没有就绪", READY_TIMEOUT.as_secs()),
      )),
      _ = work_cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
    };
    let name = service.to_string();
    state
      .db
      .call(move |c| {
        pending::update_migration(c, &name, |m| {
          m.payload.target_prepared = true;
          if backup.is_some() {
            m.payload.target_backup = backup;
          }
        })
      })
      .await?;
    let push = async |pass| {
      let op = AgentOp::SyncPush(SyncPush {
        service: service.to_string(),
        host: target_ip.clone(),
        port,
        password: password.clone(),
        pass,
      });
      let result: Pushed = if let Some(conn) = mount_conn {
        state
          .hub
          .call_bound(
            (from, conn),
            op,
            PUSH_TIMEOUT,
            Some(progress.clone()),
            &work_cancel,
          )
          .await?
      } else {
        state
          .hub
          .call(
            from,
            op,
            PUSH_TIMEOUT,
            Some(progress.clone()),
            &work_cancel,
          )
          .await?
      };
      if !result.synced {
        return Err(ApiError::new(
          ErrorCode::AgentFailed,
          "源数据没有同步，中止迁移",
        ));
      }
      Ok(())
    };
    progress("第一遍同步（服务继续运行）".into());
    push(SyncPass::Live).await?;
    progress(format!("停止 {from} 上的 {service}"));
    if source_should_run {
      let name = service.to_string();
      state
        .db
        .call(move |c| {
          pending::update_migration(c, &name, |m| {
            m.payload.source_stopped = true;
          })
        })
        .await?;
      may_need_restart
        .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let stopped = state
      .hub
      .call::<bool>(
        from,
        AgentOp::ProjectStop {
          project: service.to_string(),
        },
        STOP_TIMEOUT,
        Some(progress.clone()),
        &work_cancel,
      )
      .await?;
    if !stopped && source_should_run {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("源服务器 {from} 上找不到 {service} 的容器配置"),
      ));
    }
    if let Some(conn) = mount_conn {
      check_writers(
        state,
        (from, conn),
        service,
        false,
        &work_cancel,
      )
      .await?;
    }
    progress("增量同步（服务已停止）".into());
    push(SyncPass::Final).await
  };
  let work = async {
    let result = work.await;
    serve_cancel.cancel();
    result
  };
  let (result, served) = tokio::join!(work, serve);
  let result = match (result, served) {
    (_, Err(e)) if e.code != ErrorCode::Cancelled => Err(e),
    (result, _) => result,
  };
  if let Err(e) = result {
    if may_need_restart.load(std::sync::atomic::Ordering::Relaxed)
      && restart_source(state, from, service, &progress).await
    {
      reset_after_restart(state, service).await?;
    }
    return Err(e);
  }
  let name = service.to_string();
  if let Err(e) = state
    .db
    .call(move |c| {
      pending::update_migration(c, &name, |m| {
        m.phase = MigratePhase::Synced;
      })
    })
    .await
  {
    if may_need_restart.load(std::sync::atomic::Ordering::Relaxed)
      && restart_source(state, from, service, &progress).await
    {
      reset_after_restart(state, service).await?;
    }
    return Err(e);
  }
  Ok(())
}

pub async fn reset_after_restart(
  state: &AppState,
  service: &str,
) -> Result<(), ApiError> {
  let name = service.to_string();
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(crate::db::sql_err)?;
      if let Some(m) = pending::load(&tx)?.migrations.remove(&name) {
        tx.execute("DELETE FROM cleanups WHERE service=?1 AND server=?2 AND instance_id IS ?3",
          rusqlite::params![name, m.payload.from, m.payload.instance_id]).map_err(crate::db::sql_err)?;
        pending::update_migration(&tx, &name, |m| {
          m.phase = MigratePhase::Pending;
          m.payload.source_stopped = false;
        })?;
      }
      tx.commit().map_err(crate::db::sql_err)
    })
    .await
}

/// 增量同步失败时，把旧服务器上停掉的容器拉起来。用新的令牌，取消执行时也要做。
pub async fn restart_source(
  state: &AppState,
  server: &str,
  service: &str,
  progress: &ProgressFn,
) -> bool {
  progress(format!("迁移失败，重新启动 {server} 上的 {service}"));
  let result = async {
    pending::source_changed(state, service).await?;
    state
      .hub
      .call::<bool>(
        server,
        AgentOp::ProjectStart {
          project: service.to_string(),
          containers: Vec::new(),
        },
        STOP_TIMEOUT,
        Some(progress.clone()),
        &CancellationToken::new(),
      )
      .await
  }
  .await;
  match result {
    Ok(true) => true,
    other => {
      let detail = other
        .err()
        .map(|e| e.message)
        .unwrap_or_else(|| "容器不存在".into());
      progress(format!(
        "重新启动失败：{detail}，需要手动处理：wharf service restart {service}"
      ));
      false
    }
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use serde_json::json;
  use wharf_api_types::spec::{PrivateAddr, PrivateNetwork};

  pub(crate) async fn seed_service(stopped: bool) -> Arc<AppState> {
    let state = crate::rules::tests::test_state();
    state.db.call(move |c| {
      for server in ["s1", "s2"] {
        crate::db::apply_write(c, &crate::db::Write::Upsert {
          kind: "server".into(), name: server.into(), spec: json!({}), meta: json!({}),
        })?;
      }
      crate::db::apply_write(c, &crate::db::Write::Upsert {
        kind: "service".into(), name: "notes".into(),
        spec: json!({"server": "s2", "source": {"image": "fixture:1"},
          "stopped": stopped, "volumes": [{"name": "data", "target": "/data"}]}),
        meta: json!({}),
      })
    }).await.unwrap();
    state
  }

  pub(crate) async fn seed_migration(
    state: &AppState,
    phase: &'static str,
    source_stopped: bool,
  ) {
    state.db.call(move |c| {
      let instance = &crate::db::service_instances(c)?["service/notes"];
      let payload = json!({"service": "notes", "from": "s1", "to": "s2",
        "instance_id": instance, "has_managed_data": true, "source_stopped": source_stopped});
      c.execute("INSERT INTO pending_steps (kind,target_key,run_id,instance_id,phase,payload,updated_at)
        VALUES ('migrate','notes','r1',?1,?2,?3,0)",
        rusqlite::params![instance, phase, payload.to_string()]).map_err(crate::db::sql_err)?;
      Ok(())
    }).await.unwrap();
  }

  fn migration_net() -> Net {
    Net {
      private: [("s1", "100.64.0.1"), ("s2", "100.64.0.2")]
        .into_iter()
        .map(|(s, ip)| {
          (
            s.into(),
            PrivateAddr {
              ip: ip.into(),
              network: PrivateNetwork::Tailscale,
            },
          )
        })
        .collect(),
      ..Net::default()
    }
  }

  fn mock_receiver(state: &AppState) {
    state.hub.mock_safe_migrate_agent("s2", |op, progress| {
      let AgentOp::SyncServe(job) = op else {
        panic!("应启动接收端")
      };
      assert!(job.preserve_existing);
      progress.unwrap()(format!("{SYNC_READY}1000"));
      None
    });
  }

  #[tokio::test]
  async fn volume_sync_blocks_running_writer_and_restarts_owner_on_final_conflict()
   {
    for initially_running in [true, false] {
      let state = seed_service(false).await;
      seed_migration(&state, "pending", false).await;
      if initially_running {
        state.hub.mock_safe_migrate_agent("s2", |_, _| {
          panic!("应在目标机写入前拦截")
        });
      } else {
        mock_receiver(&state);
      }
      let (restart, mut restarted) = oneshot::channel();
      let mut restart = Some(restart);
      state.hub.mock_safe_migrate_agent("s1", move |op, _| Some(Ok(match op {
        AgentOp::BindMountUsers(q) => {
          assert!(q.running_only && q.writable_only);
          if initially_running || q.exclude_projects.is_empty() {
            json!([{"container":"writer","source":"/srv/notes/data","rw":true}])
          } else {
            assert_eq!(q.exclude_projects, ["notes"]);
            json!([])
          }
        }
        AgentOp::SyncPush(p) if !initially_running && p.pass == SyncPass::Live => json!({"synced":true}),
        AgentOp::ProjectStop { project } if !initially_running && project == "notes" => json!(true),
        AgentOp::ProjectStart { project, .. } if !initially_running && project == "notes" => {
          restart.take().unwrap().send(()).unwrap();
          json!(true)
        }
        _ => panic!("不应停止共享方或发送最终同步"),
      })));
      state.hub.mock_shared_volumes_agent("s1");
      let err = volume_sync(
        &state,
        &migration_net(),
        "notes",
        ("s1", "s2", true),
        true,
        Arc::new(|_| {}),
        &CancellationToken::new(),
      )
      .await
      .unwrap_err();
      assert_eq!(err.code, ErrorCode::Conflict);
      assert!(err.message.contains("writer"));
      if !initially_running {
        restarted.try_recv().unwrap();
      }
    }
  }

  #[tokio::test]
  async fn volume_sync_sends_live_then_final_pass() {
    let state = seed_service(false).await;
    seed_migration(&state, "pending", false).await;
    mock_receiver(&state);
    let mut expected = [SyncPass::Live, SyncPass::Final].into_iter();
    let mut stopped = false;
    state.hub.mock_safe_migrate_agent("s1", move |op, _| {
      Some(Ok(match op {
        AgentOp::SyncPush(job) => {
          assert_eq!(Some(job.pass), expected.next());
          assert_eq!(stopped, job.pass == SyncPass::Final);
          json!({"synced": true})
        }
        AgentOp::ProjectStop { .. } => {
          stopped = true;
          json!(true)
        }
        _ => panic!("意外请求"),
      }))
    });
    volume_sync(
      &state,
      &migration_net(),
      "notes",
      ("s1", "s2", false),
      true,
      Arc::new(|_| {}),
      &CancellationToken::new(),
    )
    .await
    .unwrap();
    state
      .db
      .call(|c| {
        assert_eq!(
          pending::load(c)?.migrations["notes"].phase,
          MigratePhase::Synced
        );
        assert_eq!(
          c.query_row("SELECT count(*) FROM cleanups", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
          0
        );
        Ok(())
      })
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn offline_agent_is_reported_offline_for_safe_migrate_operations()
   {
    let state = seed_service(true).await;
    let progress: ProgressFn = Arc::new(|_| {});
    let cancel = CancellationToken::new();
    let error = volume_sync(
      &state,
      &migration_net(),
      "notes",
      ("s1", "s2", false),
      false,
      progress.clone(),
      &cancel,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::AgentOffline);
    assert!(error.message.contains("s1"));
    let step = crate::planner::Step::ServiceUp {
      service: "notes".into(),
      instance_id: None,
      expect: None,
    };
    let error =
      crate::apply::run_step(&state, "r1", &step, progress, &cancel)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::AgentOffline);
    assert!(error.message.contains("s2"));
  }

  #[tokio::test]
  async fn stop_failure_restarts_source() {
    let state = seed_service(false).await;
    seed_migration(&state, "pending", false).await;
    mock_receiver(&state);
    let (sent, mut received) = oneshot::channel();
    let mut sent = Some(sent);
    state.hub.mock_safe_migrate_agent("s1", move |op, _| {
      Some(match op {
        AgentOp::SyncPush(job) if job.pass == SyncPass::Live => {
          Ok(json!({"synced": true}))
        }
        AgentOp::ProjectStop { .. } => {
          Err(ApiError::internal("无法停机"))
        }
        AgentOp::ProjectStart { .. } => {
          sent.take().unwrap().send(()).unwrap();
          Ok(json!(true))
        }
        _ => panic!("意外请求"),
      })
    });
    assert!(
      volume_sync(
        &state,
        &migration_net(),
        "notes",
        ("s1", "s2", false),
        true,
        Arc::new(|_| {}),
        &CancellationToken::new()
      )
      .await
      .is_err()
    );
    received.try_recv().unwrap();
    state
      .db
      .call(|c| {
        assert!(
          !pending::load(c)?.migrations["notes"]
            .payload
            .source_stopped
        );
        Ok(())
      })
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn serve_crash_cancels_push() {
    let state = seed_service(false).await;
    seed_migration(&state, "pending", false).await;
    let target =
      state.hub.mock_safe_migrate_agent("s2", |op, progress| {
        assert!(matches!(op, AgentOp::SyncServe(_)));
        progress.unwrap()(format!("{SYNC_READY}1000"));
        None
      });
    state.hub.mock_safe_migrate_agent("s1", move |op, _| {
      assert!(
        matches!(op, AgentOp::SyncPush(p) if p.pass == SyncPass::Live)
      );
      target.cancel();
      None
    });
    let e = tokio::time::timeout(
      Duration::from_secs(5),
      volume_sync(
        &state,
        &migration_net(),
        "notes",
        ("s1", "s2", false),
        true,
        Arc::new(|_| {}),
        &CancellationToken::new(),
      ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::AgentOffline);
  }

  #[tokio::test]
  async fn volume_sync_fails_when_source_dir_missing_and_does_not_schedule_cleanup()
   {
    let state = seed_service(false).await;
    seed_migration(&state, "pending", false).await;
    mock_receiver(&state);
    state.hub.mock_safe_migrate_agent("s1", |op, _| {
      assert!(
        matches!(op, AgentOp::SyncPush(p) if p.pass == SyncPass::Live)
      );
      Some(Err(ApiError::not_found("源目录不存在")))
    });
    let error = volume_sync(
      &state,
      &migration_net(),
      "notes",
      ("s1", "s2", false),
      true,
      Arc::new(|_| {}),
      &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    state
      .db
      .call(|c| {
        assert_eq!(
          c.query_row("SELECT count(*) FROM cleanups", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
          0
        );
        Ok(())
      })
      .await
      .unwrap();
  }
}
