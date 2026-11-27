use super::*;
use crate::{
  rules::tests::test_state, security_receipt::tests::auth,
};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) async fn seed_servers(state: &AppState) {
  state.db.call(|c| {
    for (name, ip) in [("s1", "100.64.0.1"), ("s2", "100.64.0.2")] {
      db::apply_write(c, &db::Write::Upsert {
        kind: "server".into(), name: name.into(),
        spec: json!({"private_addr": {"ip": ip, "network": "lan"}}),
        meta: json!({}),
      })?;
    }
    Ok(())
  }).await.unwrap();
}

pub(crate) async fn seed_service(
  state: &AppState,
  name: &'static str,
  enabled: bool,
) {
  state
    .db
    .call(move |c| {
      db::apply_write(
        c,
        &db::Write::Upsert {
          kind: "service".into(),
          name: name.into(),
          spec: json!({
            "server": "s1", "source": {"image": "nginx:1"},
            "volumes": [{"name": "data", "target": "/data"}],
            "backup": enabled.then(|| json!({"to": "s2"})),
          }),
          meta: json!({}),
        },
      )
    })
    .await
    .unwrap();
}

async fn seed_legacy(state: &AppState) -> String {
  state.db.call_credentials(|c, key| {
    c.execute("INSERT INTO backups (service, server, target, run_id, ok, body, created_at)
      VALUES ('svc-a', 's1', 's2', 'r1', 1, '{}', 0)", []).map_err(sql_err)?;
    for name in [LEGACY_HTTP_SECRET, LEGACY_HTTP_HASH_SECRET] {
      db::ensure_secret(c, key, name, now_ms())?;
    }
    db::ensure_secret(c, key, LEGACY_KEY_SECRET, now_ms())
  }).await.unwrap()
}

async fn secret_count(state: &AppState) -> usize {
  state
    .db
    .call(|c| {
      c.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0))
        .map_err(sql_err)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn service_credentials_are_isolated_per_service() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", true).await;
  seed_service(&state, "svc-b", true).await;
  let (a, same) = tokio::join!(
    ensure_service_creds(&state, "svc-a"),
    ensure_service_creds(&state, "svc-a"),
  );
  let (a, same) = (a.unwrap(), same.unwrap());
  let b = ensure_service_creds(&state, "svc-b").await.unwrap();
  let snap = snapshot::load(&state.db).await.unwrap();
  let w =
    location(&snap, "svc-a", service_target(&snap, "svc-a").unwrap());
  let htpasswd = target_htpasswd(&state, &snap, &w.target, None)
    .await
    .unwrap();
  let (a_hash, b_hash) = (
    htpasswd
      .lines()
      .next()
      .unwrap()
      .strip_prefix("svc-a:")
      .unwrap(),
    htpasswd
      .lines()
      .nth(1)
      .unwrap()
      .strip_prefix("svc-b:")
      .unwrap(),
  );
  assert!(a.key == same.key && a.http == same.http);
  assert!(a.key != b.key && a.http != b.http && a_hash != b_hash);
  assert!(bcrypt::verify(&a.http, a_hash).unwrap());
  assert!(bcrypt::verify(&b.http, b_hash).unwrap());
  let op = job(
    &snap,
    &w.server,
    "svc-a",
    rest_repo(&w.target_ip, REST_SERVER_PORT, "svc-a", &a.http),
    &a.key,
    ResticAction::Snapshots,
  );
  let AgentOp::Restic(op) = op else {
    panic!("不是备份任务")
  };
  let ResticRepo::Rest { user, password, .. } = op.repo else {
    panic!("不是远程仓库")
  };
  assert_eq!(user, op.service);
  assert_eq!(user, "svc-a");
  assert!(op.password.0 == a.key && password.0 == a.http);
}

#[test]
fn rest_server_compose_uses_private_repos_and_inline_configs() {
  let compose = render::backup_server_compose(
    "100.64.0.2",
    "svc-a:$2b$12$hash-a\nsvc-b:$2b$12$hash-b\n",
  );
  let yaml: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&compose).unwrap();
  let service = &yaml["services"]["rest-server"];
  let cmd = service["command"].as_sequence().unwrap();
  for flag in [
    "--private-repos",
    "--append-only",
    "--htpasswd-file",
    "/etc/rest-server/htpasswd",
    "100.64.0.2:7710",
  ] {
    assert!(cmd.iter().any(|arg| arg.as_str() == Some(flag)));
  }
  let mount = &service["configs"][0];
  assert_eq!(
    mount["target"].as_str(),
    Some("/etc/rest-server/htpasswd")
  );
  let source = mount["source"].as_str().unwrap();
  assert!(source.starts_with("wharf-htpasswd-"));
  assert_eq!(
    yaml["configs"][source]["content"].as_str(),
    Some("svc-a:$$2b$$12$$hash-a\nsvc-b:$$2b$$12$$hash-b\n")
  );
  assert!(service["environment"].is_null());
}

#[tokio::test]
async fn deleting_service_keeps_backup_key_and_drops_http_creds() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", true).await;
  let creds = ensure_service_creds(&state, "svc-a").await.unwrap();
  state
    .db
    .call(|c| {
      let tx = c.transaction().map_err(sql_err)?;
      db::apply_write(
        &tx,
        &db::Write::Delete {
          kind: "service".into(),
          name: "svc-a".into(),
        },
      )?;
      tx.commit().map_err(sql_err)
    })
    .await
    .unwrap();
  assert!(
    repository_secrets(&state, "svc-a").await.unwrap().0
      == Some(creds.key)
  );
  assert_eq!(secret_count(&state).await, 1);
  let snap = snapshot::load(&state.db).await.unwrap();
  assert!(
    target_htpasswd(&state, &snap, "s2", None)
      .await
      .unwrap()
      .is_empty()
  );
}

#[tokio::test]
async fn legacy_repo_adds_service_key_before_cleanup() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", false).await;
  let legacy = seed_legacy(&state).await;
  let known_old = legacy.clone();
  let mut new = None::<String>;
  state.hub.mock_agent_with_backup("s2", false, true, false, move |op| {
    let AgentOp::Restic(job) = op else { panic!("不是备份任务") };
    assert!(matches!(job.repo, ResticRepo::Local));
    assert_eq!(job.service, "svc-a");
    let is_legacy = job.password.0 == known_old;
    let valid = is_legacy || new.as_ref() == Some(&job.password.0);
    match job.action {
      ResticAction::ListKeys if valid => Ok(json!([{"id":"abcd", "current":true}])),
      ResticAction::Snapshots if valid => Ok(json!([{
        "id": "abcd", "short_id": "abcd", "time": "2026-01-01T00:00:00Z", "hostname": "s1"
      }])),
      ResticAction::Snapshots | ResticAction::ListKeys => Err(ApiError::new(ErrorCode::Forbidden, "备份仓库口令不匹配")),
      ResticAction::AddKey { new_password } => {
        assert!(is_legacy && new.is_none());
        new = Some(new_password.0);
        Ok(json!("cafe"))
      }
      _ => panic!("意外任务"),
    }
  });
  let show = || {
    let mut read_only = auth(false);
    read_only.perms = [Perm::Read].into_iter().collect();
    list(State(state.clone()), read_only, Path("svc-a".into()))
  };
  let before = secret_count(&state).await;
  assert_eq!(
    show().await.map_err(|e| e.0).unwrap().0.snapshots.len(),
    1
  );
  assert_eq!(secret_count(&state).await, before);
  let creds = ensure_service_creds(&state, "svc-a").await.unwrap();
  assert_eq!(
    show().await.map_err(|e| e.0).unwrap().0.snapshots.len(),
    1
  );
  assert_eq!(secret_count(&state).await, before + 3);
  let report = migrate_all(State(state.clone()), auth(true))
    .await
    .map_err(|e| e.0)
    .unwrap()
    .0;
  assert!(matches!(
    report.repositories[0].status,
    MigrationStatus::Migrated
  ));
  let view = show().await.map_err(|e| e.0).unwrap().0;
  assert_eq!(view.records.len(), 1);
  assert_eq!(view.snapshots.len(), 1);
  assert!(
    repository_secrets(&state, "svc-a").await.unwrap()
      == (Some(creds.key), Some(legacy))
  );
}

#[tokio::test]
async fn cleanup_legacy_requires_confirm_and_aborts_if_target_offline()
 {
  let dir = tempfile::tempdir().unwrap();
  let mut state = test_state();
  let inner = Arc::get_mut(&mut state).unwrap();
  inner.data_dir = dir.path().into();
  inner.db = db::Db::open(&dir.path().join("wharf.db")).unwrap();
  seed_servers(&state).await;
  let legacy = seed_legacy(&state).await;
  let clean = |confirm: Option<&str>| {
    cleanup_legacy(
      State(state.clone()),
      auth(true),
      None,
      Default::default(),
      Json(CleanupRequest {
        confirm: confirm.map(str::to_string),
        skip_snapshot: false,
      }),
    )
  };
  assert_eq!(
    clean(None).await.err().unwrap().0.code,
    ErrorCode::ConfirmRequired
  );
  assert_eq!(secret_count(&state).await, 3);
  assert_eq!(
    clean(Some("backup/legacy")).await.err().unwrap().0.code,
    ErrorCode::AgentOffline
  );
  assert_eq!(secret_count(&state).await, 3);
  let creds = ensure_service_creds(&state, "svc-a").await.unwrap();
  let removed = Arc::new(AtomicBool::new(false));
  let agent_removed = removed.clone();
  state.hub.mock_agent_with_backup(
    "s2",
    false,
    true,
    false,
    move |op| {
      let AgentOp::Restic(job) = op else {
        panic!("不是备份任务")
      };
      assert!(matches!(job.repo, ResticRepo::Local));
      match job.action {
        ResticAction::ListKeys if job.password.0 == legacy => {
          if agent_removed.load(Ordering::Relaxed) {
            Err(ApiError::new(
              ErrorCode::Forbidden,
              "备份仓库口令不匹配",
            ))
          } else {
            Ok(json!([{"id": "abcd", "current": true}]))
          }
        }
        ResticAction::ListKeys => {
          assert!(job.password.0 == creds.key);
          Ok(json!([{"id": "cafe", "current": true}]))
        }
        ResticAction::RemoveKey { id } => {
          assert!(job.password.0 == creds.key);
          assert_eq!(id, "abcd");
          agent_removed.store(true, Ordering::Relaxed);
          Ok(serde_json::Value::Null)
        }
        _ => panic!("意外任务"),
      }
    },
  );
  let report = clean(Some("backup/legacy"))
    .await
    .map_err(|e| e.0)
    .unwrap()
    .0;
  assert_eq!(report.removed_keys, 1);
  assert_eq!(report.deleted_secrets, 3);
  assert_eq!(secret_count(&state).await, 3);
  assert!(removed.load(Ordering::Relaxed));
}

#[tokio::test]
async fn rejects_reserved_backup_service_names_and_port_7711() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", false).await;
  let mut world = snapshot::load(&state.db).await.unwrap().world;
  assert!(world.validate().is_ok());
  let mut row = world.services.remove("svc-a").unwrap();
  for name in [render::CORE_BACKUP_PROJECT, crate::core_backup::REPO]
  {
    world.services.insert(name.into(), row.clone());
    let err = world.validate().unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("留给控制面备份"));
    world.services.remove(name);
  }
  row.spec.ports.push(wharf_api_types::spec::PortSpec {
    name: "http".into(),
    container: Some(80),
    host: Some(7711),
    udp: false,
  });
  row.host_ports.insert("http".into(), 7711);
  world.services.insert("svc-a".into(), row);
  let err = world.validate().unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  assert!(err.message.contains("7711"));
}

#[tokio::test]
async fn backup_isolation_rejects_old_agent_without_capability() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", true).await;
  state
    .hub
    .mock_agent("s2", false, |_| panic!("不应发任务给旧 agent"));
  let snap = snapshot::load(&state.db).await.unwrap();
  let cancel = CancellationToken::new();
  let progress: ProgressFn = Arc::new(|_| {});
  let w =
    location(&snap, "svc-a", service_target(&snap, "svc-a").unwrap());
  let err =
    ensure_server(&state, &snap, &w, None, &progress, &cancel)
      .await
      .unwrap_err();
  assert_eq!(err.code, ErrorCode::Conflict);
  assert!(err.hint.unwrap().contains("upgrade"));
  let err = local_call::<Vec<ResticKeyInfo>>(
    &state,
    &snap,
    ("s2", "svc-a"),
    &random_hex(),
    ResticAction::ListKeys,
    &cancel,
  )
  .await
  .unwrap_err();
  assert_eq!(err.code, ErrorCode::Conflict);
  assert!(err.hint.unwrap().contains("upgrade"));
  assert_eq!(secret_count(&state).await, 0);
}

fn mock_backup_path(
  state: &AppState,
  source: impl FnMut(AgentOp) -> Result<serde_json::Value, ApiError>
  + Send
  + 'static,
  expect_prune: Option<Arc<AtomicBool>>,
) {
  state
    .hub
    .mock_agent_with_backup("s1", false, true, false, source);
  state.hub.mock_agent_with_backup("s2", false, true, false, move |op| match op {
    AgentOp::ProjectStatus { .. } => Ok(json!([])),
    AgentOp::ProjectUp(up) => {
      assert!(up.compose.contains("svc-a:"));
      Ok(json!({"containers":[{"name":"rest-server","service":"rest-server","state":"running"}], "images":[]}))
    }
    AgentOp::Restic(job) => match job.action {
      ResticAction::ListKeys => Ok(json!([{"id":"cafe","current":true}])),
      ResticAction::Prune => {
        expect_prune.as_ref().expect("不应清理快照").store(true, Ordering::Relaxed);
        Ok(json!(null))
      }
      _ => panic!("意外的仓库任务"),
    },
    _ => panic!("意外的备份目标机任务"),
  });
  state.hub.mock_safe_backup_agent("s1");
  state.hub.mock_safe_backup_agent("s2");
}

#[tokio::test]
async fn preflight_failure_never_stops_service() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", true).await;
  let mut probes = 0;
  mock_backup_path(
    &state,
    move |op| match op {
      AgentOp::Probe { .. } => Ok(json!([true])),
      AgentOp::Restic(job)
        if matches!(job.action, ResticAction::Preflight(_)) =>
      {
        probes += 1;
        if probes == 1 {
          Err(ApiError::new(ErrorCode::AgentFailed, "镜像没有拉到"))
        } else {
          Ok(
            json!({"conflicting_users":[{"container":"writer","source":"/srv/svc-a/data","rw":true}]}),
          )
        }
      }
      _ => panic!("预检失败后仍尝试停服或传输"),
    },
    None,
  );
  for code in [ErrorCode::AgentFailed, ErrorCode::Conflict] {
    let err = backup(
      &state,
      "r1",
      "svc-a",
      Arc::new(|_| {}),
      &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code);
  }
  assert!(
    records(&state, "svc-a", 2)
      .await
      .unwrap()
      .iter()
      .all(|r| !r.ok && r.target == "s2")
  );
}

#[tokio::test]
async fn restore_works_after_backup_disabled_and_includes_htpasswd() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", false).await;
  seed_legacy(&state).await;
  let mut stops = 0;
  mock_backup_path(
    &state,
    move |op| match op {
      AgentOp::Probe { .. } => Ok(json!([true])),
      AgentOp::ServiceStopForData { .. } => {
        stops += 1;
        if stops == 1 {
          Err(ApiError::new(ErrorCode::Conflict, "仍有活动容器"))
        } else {
          Ok(json!({"containers":[]}))
        }
      }
      AgentOp::Restic(job) => match job.action {
        ResticAction::Preflight(_) => Ok(json!({})),
        ResticAction::Restore { .. } if stops == 2 => Ok(json!(null)),
        _ => panic!("意外的恢复任务"),
      },
      _ => panic!("恢复启动了原先已停的服务，或未停服就传输了数据"),
    },
    None,
  );
  let cancel = CancellationToken::new();
  assert_eq!(
    restore(
      &state,
      "svc-a",
      "abcd1234",
      None,
      Arc::new(|_| {}),
      &cancel
    )
    .await
    .unwrap_err()
    .code,
    ErrorCode::Conflict
  );
  restore(
    &state,
    "svc-a",
    "abcd1234",
    None,
    Arc::new(|_| {}),
    &cancel,
  )
  .await
  .unwrap();
  assert!(
    snapshot::load(&state.db).await.unwrap().world.services["svc-a"]
      .spec
      .backup
      .is_none()
  );
}

#[tokio::test]
async fn backup_list_returns_historical_snapshot_target_when_disabled()
 {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", false).await;
  seed_legacy(&state).await;
  state.hub.mock_agent("s2", false, |op| {
    assert!(matches!(op, AgentOp::Restic(job) if matches!(job.action, ResticAction::Snapshots)));
    Ok(json!([{
      "id": "abcd1234", "short_id": "abcd1234", "hostname": "s1",
      "time": "2026-01-01T00:00:00Z", "paths": ["/srv/svc-a"]
    }]))
  });
  let Json(view) =
    list(State(state), auth(true), Path("svc-a".into()))
      .await
      .map_err(|e| e.0)
      .unwrap();
  assert_eq!(view.target, None);
  assert_eq!(view.snapshot_target.as_deref(), Some("s2"));
  assert_eq!(view.snapshots[0].id, "abcd1234");
}

#[tokio::test]
async fn backup_records_ok_and_prunes_even_when_restart_fails() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", true).await;
  let pruned = Arc::new(AtomicBool::new(false));
  mock_backup_path(
    &state,
    |op| match op {
      AgentOp::Probe { .. } => Ok(json!([true])),
      AgentOp::ServiceStopForData { .. } => {
        Ok(json!({"containers":["web"]}))
      }
      AgentOp::Restic(job) => match job.action {
        ResticAction::Preflight(_) => Ok(json!({})),
        ResticAction::Backup { .. } => Ok(
          json!({"snapshot_id":"abcd1234","files":1,"bytes":5,"added_bytes":5}),
        ),
        _ => panic!("意外的传输任务"),
      },
      AgentOp::ProjectStart { containers, .. } => {
        assert_eq!(containers, ["web"]);
        Err(ApiError::new(ErrorCode::AgentFailed, "容器没起来"))
      }
      _ => panic!("意外的源机任务"),
    },
    Some(pruned.clone()),
  );
  let err = backup(
    &state,
    "r1",
    "svc-a",
    Arc::new(|_| {}),
    &CancellationToken::new(),
  )
  .await
  .unwrap_err();
  assert!(err.hint.unwrap().contains("快照已写入"));
  let entry =
    records(&state, "svc-a", 1).await.unwrap().pop().unwrap();
  assert!(
    entry.ok
      && entry.summary.is_some()
      && pruned.load(Ordering::Relaxed)
  );
}

#[tokio::test]
async fn unlock_service_runs_local_and_respects_backup_lock() {
  let state = test_state();
  seed_servers(&state).await;
  seed_service(&state, "svc-a", false).await;
  let legacy = seed_legacy(&state).await;
  state.hub.mock_agent_with_backup(
    "s2",
    false,
    true,
    false,
    move |op| {
      let AgentOp::Restic(job) = op else {
        panic!("需要本机仓库操作")
      };
      assert!(matches!(job.repo, ResticRepo::Local));
      assert!(job.password.0 == legacy);
      assert!(matches!(
        job.action,
        ResticAction::Unlock { remove_all: true }
      ));
      Ok(json!(null))
    },
  );
  state.hub.mock_safe_backup_agent("s2");
  let call = || {
    unlock(
      State(state.clone()),
      auth(true),
      Path("svc-a".into()),
      None,
    )
  };
  let guard = state
    .locks
    .acquire(crate::locks::LockSpec::Backup("svc-a".into()), "备份")
    .unwrap();
  assert_eq!(call().await.err().unwrap().0.code, ErrorCode::Busy);
  drop(guard);
  let _ = call().await.map_err(|e| e.0).unwrap();
}

#[tokio::test]
async fn deploy_server_rejects_empty_containers() {
  let state = test_state();
  seed_servers(&state).await;
  state
    .hub
    .mock_agent_with_backup(
      "s2",
      false,
      true,
      false,
      |op| match op {
        AgentOp::ProjectStatus { .. } => Ok(json!([])),
        AgentOp::ProjectUp(_) => {
          Ok(json!({"containers":[],"images":[]}))
        }
        _ => panic!("意外的备份任务"),
      },
    );
  let snap = snapshot::load(&state.db).await.unwrap();
  let w = Where {
    server: "s1".into(),
    target: "s2".into(),
    target_ip: "100.64.0.2".into(),
  };
  let progress: ProgressFn = Arc::new(|_| {});
  let err = deploy_server(
    &state,
    &snap,
    &w,
    (BACKUP_PROJECT, String::new()),
    &progress,
    &CancellationToken::new(),
  )
  .await
  .unwrap_err();
  assert_eq!(err.code, ErrorCode::AgentFailed);
}
