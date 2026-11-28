use super::*;
use wharf_api_types::agent::CleanupScanResult;

fn auth(services: Option<&[&str]>) -> Auth {
  Auth {
    name: "fixture".into(),
    perms: Perm::ALL.into_iter().collect(),
    expires_at: None,
    allowed_from: vec![],
    services: services
      .map(|items| items.iter().map(|s| s.to_string()).collect()),
    human: false,
  }
}

async fn seed(state: &AppState, sql: &'static str) {
  state
    .db
    .call(move |c| c.execute_batch(sql).map_err(sql_err))
    .await
    .unwrap();
}

async fn migrations(state: &AppState) {
  seed(state, "
    INSERT INTO cleanups (service, server, due_at, instance_id)
    VALUES ('app', 's1', 0, 'svc_old'), ('other', 's2', 0, 'svc_other');
  ").await;
}

fn entry(
  kind: CleanupKind,
  service: Option<&str>,
  target: &str,
) -> AgentCleanupEntry {
  serde_json::from_value(json!({
    "kind":kind, "service":service, "target":target, "display":target
  }))
  .unwrap()
}

#[tokio::test]
async fn cleanup_list_and_blocked_entry_survives_without_mutating_due_at()
 {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  state.hub.mock_safe_delete_agent("s1", |_| {
    Ok(json!({
      "removed":false, "blocked_by":["other-1"]
    }))
  });
  let guard = state
    .locks
    .acquire(LockSpec::apply(["app".into()]), "测试")
    .unwrap();
  crate::jobs::cleanup_data(
    &state,
    ("app", "s1", Some("svc_old")),
    Arc::new(|_| {}),
    &CancellationToken::new(),
    guard,
  )
  .await
  .unwrap();
  let row = state.db.call(|c| c.query_row(
    "SELECT due_at, next_retry_at, blocked_reason FROM cleanups WHERE service = 'app'", [],
    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
  ).map_err(sql_err)).await.unwrap();
  assert_eq!(row.0, 0);
  assert!(row.1 > db::now_ms());
  assert_eq!(row.2, "仍有容器挂载：other-1");
  let Json(view) =
    overview(State(state), auth(None), Query(Filters::default()))
      .await
      .unwrap_or_else(|e| panic!("{}", e.0));
  assert!(
    view
      .items
      .iter()
      .any(|i| i.service.as_deref() == Some("app")
        && i.expired
        && i.blocked)
  );
}

#[tokio::test]
async fn backup_move_retired_blocks_if_target_reactivated_and_deletes_setting()
 {
  let state = crate::rules::tests::test_state();
  seed(&state, r#"
    INSERT INTO settings (key, value) VALUES ('backup_move.retired.app@s2',
      '{"service":"app","is_core":false,"server":"s2","path":"/srv/wharf-backup/app","moved_at":0,"expires_at":1}');
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at)
    VALUES ('service','app','{"server":"s1","source":{"image":"fixture:1"},"backup":{"to":"s2"}}',1,0,0);
  "#).await;
  state.hub.mock_data_cleanup_agent("s2", |op| match op {
    AgentOp::CleanupScan(_) => {
      Ok(json!(CleanupScanResult::default()))
    }
    AgentOp::CleanupDelete(req) => {
      assert_eq!(req.kind, BackupMoveRetired);
      Ok(json!({"removed":true}))
    }
    _ => panic!("不相关的请求"),
  });
  let cancel = CancellationToken::new();
  let filters = Filters::default();
  let current = list(&state, &filters, false, &cancel).await.unwrap();
  assert_eq!(current.items.len(), 1);
  assert!(
    !delete_candidate(&state, &current.items[0], &cancel)
      .await
      .unwrap()
      .removed
  );
  seed(&state, "UPDATE resources SET spec = json_set(spec, '$.backup.to', 's3') WHERE name = 'app'").await;
  let current = list(&state, &filters, false, &cancel).await.unwrap();
  assert!(
    delete_candidate(&state, &current.items[0], &cancel)
      .await
      .unwrap()
      .removed
  );
  assert!(state.db.call(inventory).await.unwrap().records.is_empty());
}

#[tokio::test]
async fn stale_cleanup_items_appear_in_status_issues_and_respect_scope()
 {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  for (allowed, expected) in
    [(None, 2), (Some(BTreeSet::from(["app".into()])), 1)]
  {
    let status = crate::views::status(&state, allowed.as_ref())
      .await
      .unwrap();
    assert_eq!(
      status
        .issues
        .iter()
        .filter(|i| i.code == "stale_cleanup_data")
        .count(),
      expected
    );
  }
}

#[tokio::test]
async fn orphan_service_and_backup_repo_never_flag_active_or_disabled_backup_services()
 {
  let state = crate::rules::tests::test_state();
  seed(&state, r#"
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at) VALUES
      ('service','alive','{"server":"s1","source":{"compose":{"content":"services: {}\nvolumes: {live: {name: active-volume}}\nnetworks: {live: {name: active-network}}"}}}',1,0,0),
      ('service','paused','{"server":"s1","source":{"image":"fixture:1"}}',1,0,0);
    INSERT INTO cleanups (service,server,due_at) VALUES ('ghost','s1',0);
  "#).await;
  let snap = snapshot::load_inner(&state.db).await.unwrap();
  let inv = state.db.call(inventory).await.unwrap();
  for (kind, svc, target, active) in [
    (OrphanServiceData, Some("alive"), "/srv/alive", true),
    (OrphanServiceData, Some("ghost"), "/srv/ghost", true),
    (OrphanServiceData, Some("deleted"), "/srv/deleted", false),
    (
      OrphanBackupRepo,
      Some("paused"),
      "/srv/wharf-backup/paused",
      true,
    ),
    (
      OrphanBackupRepo,
      Some("deleted"),
      "/srv/wharf-backup/deleted",
      false,
    ),
    (OrphanVolume, Some("old"), "active-volume", true),
    (OrphanNetwork, Some("old"), "active-network", true),
  ] {
    assert_eq!(
      active_resource(
        &snap,
        &inv,
        "s1",
        &entry(kind, svc, target),
        &Ok(vec![])
      ),
      active,
      "{target}"
    );
  }
}

#[tokio::test]
async fn orphan_caddy_and_frpc_dirs_detected_and_active_protected() {
  let state = crate::rules::tests::test_state();
  seed(&state, r#"
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at)
    VALUES ('gateway','live','{"server":"s1","kind":"caddy"}',1,0,0);
  "#).await;
  let snap = snapshot::load_inner(&state.db).await.unwrap();
  let inv = state.db.call(inventory).await.unwrap();
  let links = Ok(vec![crate::link::LinkProject {
    gateway: "live".into(),
    server: "s1".into(),
    project: "wharf-link-s2".into(),
    compose: String::new(),
    hash: String::new(),
    reload: None,
    summary: String::new(),
  }]);
  for (kind, name, path, active) in [
    (OrphanCaddy, Some("live"), "/srv/wharf-gw-live", true),
    (OrphanCaddy, Some("old"), "/srv/wharf-gw-old", false),
    (OrphanFrpc, None, "wharf-link-s2", true),
    (OrphanFrpc, None, "wharf-link-s9", false),
    (OrphanNetwork, Some("wharf-gw-live"), "live-net", true),
    (OrphanNetwork, Some("wharf-gw-old"), "old-net", false),
    (
      OrphanNetwork,
      Some("wharf-link-s2"),
      "link-current-net",
      true,
    ),
    (OrphanNetwork, Some("wharf-link-s9"), "link-old-net", false),
  ] {
    assert_eq!(
      active_resource(
        &snap,
        &inv,
        "s1",
        &entry(kind, name, path),
        &links
      ),
      active
    );
  }
}

#[tokio::test]
async fn cleanup_rejects_mismatched_instance_id_after_recreate() {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  state.hub.mock_data_cleanup_agent("s1", |op| {
    assert!(matches!(op, AgentOp::CleanupScan(_)));
    Ok(json!(CleanupScanResult::default()))
  });
  let cancel = CancellationToken::new();
  let current = list(&state, &Filters::default(), false, &cancel)
    .await
    .unwrap();
  let item = current
    .items
    .iter()
    .find(|c| c.item.server == "s1")
    .unwrap();
  seed(&state, r#"
    INSERT INTO resources (kind,name,spec,meta,version,created_at,updated_at)
    VALUES ('service','app','{"server":"s2","source":{"image":"fixture:1"}}','{"instance_id":"svc_new"}',1,0,0);
  "#).await;
  let result = delete_candidate(&state, item, &cancel).await.unwrap();
  assert_eq!(result.detail.as_deref(), Some("服务已同名重建"));
  assert!(
    state
      .db
      .call(inventory)
      .await
      .unwrap()
      .records
      .keys()
      .all(|key| key.2 != "app")
  );
}

#[tokio::test]
async fn cleanup_blocks_when_shared_volume_consumer_exists_on_same_server()
 {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  seed(&state, r#"
    INSERT INTO resources (kind,name,spec,meta,version,created_at,updated_at) VALUES
      ('service','app','{"server":"s2","source":{"image":"fixture:1"}}','{"instance_id":"svc_old"}',1,0,0),
      ('service','indexer','{"server":"s1","source":{"image":"fixture:1"},"volumes":[{"target":"/data","from_service":"app:originals"}]}','{}',1,0,0);
  "#).await;
  let cancel = CancellationToken::new();
  let current = list(&state, &Filters::default(), false, &cancel)
    .await
    .unwrap();
  let app = current
    .items
    .iter()
    .find(|c| c.item.server == "s1")
    .unwrap();
  assert!(
    app
      .item
      .blocked_reason
      .as_deref()
      .unwrap()
      .contains("indexer")
  );
  assert!(
    !delete_candidate(&state, app, &cancel)
      .await
      .unwrap()
      .removed
  );
}

#[tokio::test]
async fn old_agent_degrades_on_scan_and_blocks_on_delete() {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  state.hub.mock_data_cleanup_agent("s1", |_| {
    Ok(json!(CleanupScanResult::default()))
  });
  state.hub.mock_safe_delete_agent("s2", |_| {
    panic!("旧 agent 不应收到新请求")
  });
  let Json(view) = overview(
    State(state.clone()),
    auth(None),
    Query(Filters::default()),
  )
  .await
  .unwrap_or_else(|e| panic!("{}", e.0));
  assert_eq!(view.total_items, 2);
  assert_eq!(view.skipped_servers[0].server, "s2");
  let req = DataCleanupExecRequest {
    ids: vec![
      view
        .items
        .iter()
        .find(|i| i.server == "s2")
        .unwrap()
        .id
        .clone(),
    ],
    ..Default::default()
  };
  let err = execute(
    State(state),
    auth(None),
    Extension(AuditSlot::default()),
    Json(req),
  )
  .await
  .err()
  .unwrap()
  .0;
  assert_eq!(err.code, ErrorCode::Conflict);
  assert_eq!(err.suggest, ["wharf upgrade"]);
}

#[tokio::test]
async fn scoped_token_isolation_confirm_gate_and_audit() {
  use axum::{
    body::{Body, to_bytes},
    http::Request,
  };
  use tower::ServiceExt;

  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  state.db.call(|c| {
    crate::auth::insert_token(c, "fixture", &[Perm::Read, Perm::Apply, Perm::Confirm], "fixture-cleanup")?;
    c.execute("UPDATE api_tokens SET services = 'app' WHERE name = 'fixture'", []).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  state.hub.mock_data_cleanup_agent("s1", |op| match op {
    AgentOp::CleanupScan(_) => {
      Ok(json!(CleanupScanResult::default()))
    }
    AgentOp::CleanupDelete(req) if req.target == "/srv/app" => {
      Ok(json!({"removed":true,"freed_bytes":7}))
    }
    _ => panic!("不能删除范围外资源"),
  });
  let app = crate::api::router(state.clone());
  let send = |method: &str, body: serde_json::Value| {
    app.clone().oneshot(
      Request::builder()
        .method(method)
        .uri("/api/data/cleanup")
        .header("authorization", "Bearer fixture-cleanup")
        .header("content-type", "application/json")
        .extension(crate::cli_tunnel::Sealed)
        .body(Body::from(body.to_string()))
        .unwrap(),
    )
  };
  let response = send("GET", json!(null)).await.unwrap();
  let view: DataCleanupView = serde_json::from_slice(
    &to_bytes(response.into_body(), 64_000).await.unwrap(),
  )
  .unwrap();
  assert_eq!(view.total_items, 1);
  let id = &view.items[0].id;
  assert_eq!(view.items[0].service.as_deref(), Some("app"));
  assert_eq!(
    send("POST", json!({"ids":["cln_other"]}))
      .await
      .unwrap()
      .status()
      .as_u16(),
    403
  );
  let response = send("POST", json!({"ids":[id]})).await.unwrap();
  assert_eq!(response.status().as_u16(), 409);
  let error: ApiError = serde_json::from_slice(
    &to_bytes(response.into_body(), 64_000).await.unwrap(),
  )
  .unwrap();
  assert_eq!(error.code, ErrorCode::ConfirmRequired);
  assert_eq!(
    send(
      "POST",
      json!({"ids":[id],"confirm":error.details.unwrap()["confirm"]})
    )
    .await
    .unwrap()
    .status()
    .as_u16(),
    200
  );
  assert!(state.db.call(|c| c.query_row("SELECT EXISTS(SELECT 1 FROM audit_log WHERE detail LIKE 'data_cleanup deleted=1%')",
    [], |r| r.get::<_, bool>(0)).map_err(sql_err)).await.unwrap());
}

#[tokio::test]
async fn auto_expire_defaults_off_and_never_auto_deletes_backup_repos_or_orphans()
 {
  let state = crate::rules::tests::test_state();
  seed(&state, "
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at)
    VALUES ('server','s1','{}',1,0,0);
  ").await;
  let deletes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let count = deletes.clone();
  state.hub.mock_data_cleanup_agent("s1", move |op| match op {
    AgentOp::CleanupScan(_) => Ok(json!({"entries":[
      {"kind":"restore_backup","service":"app","target":"/srv/.wharf-restore/app-before-20260101-000000-a1b2c3d4","display":"restored","created_at":0},
      {"kind":"backup_move_archive","service":"app","target":"/srv/wharf-backup/.wharf-backup-archive/app-replaced-20260101-000000","display":"archive","created_at":0},
      {"kind":"orphan_service_data","service":"app","target":"/srv/app","display":"app"}
    ]})),
    AgentOp::CleanupDelete(req) => {
      assert_eq!(req.kind, RestoreBackup);
      count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      Ok(json!({"removed":true}))
    }
    _ => panic!("不相关的请求"),
  });
  refresh_cache(&state).await.unwrap();
  assert_eq!(deletes.load(std::sync::atomic::Ordering::Relaxed), 0);
  seed(&state, r#"INSERT INTO settings VALUES ('data_cleanup.policy','{"auto_expire":true}');"#).await;
  state
    .safe_mode
    .store(true, std::sync::atomic::Ordering::Release);
  assert!(!crate::jobs::auto_cleanup_enabled(&state).await.unwrap());
  refresh_cache(&state).await.unwrap();
  assert_eq!(deletes.load(std::sync::atomic::Ordering::Relaxed), 0);
  let Json(resumed) = crate::state::resume(
    State(state.clone()),
    auth(None),
    Extension(AuditSlot::default()),
  )
  .await
  .map_err(|e| e.0)
  .unwrap();
  assert_eq!(resumed.resumed, Some(true));
  assert!(crate::jobs::auto_cleanup_enabled(&state).await.unwrap());
  refresh_cache(&state).await.unwrap();
  assert_eq!(deletes.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn active_service_filter_keeps_only_its_stale_ephemeral_containers()
 {
  let state = crate::rules::tests::test_state();
  seed(&state, r#"
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at)
    VALUES ('service','app','{"server":"s1","source":{"image":"fixture:1"}}',1,0,0);
  "#).await;
  let snap = snapshot::load_inner(&state.db).await.unwrap();
  let inv = state.db.call(inventory).await.unwrap();
  let mut container =
    entry(OrphanContainer, Some("app"), "container-id");
  assert!(active_resource(
    &snap,
    &inv,
    "s1",
    &container,
    &Ok(vec![])
  ));
  container.ephemeral = true;
  assert!(!active_resource(
    &snap,
    &inv,
    "s1",
    &container,
    &Ok(vec![])
  ));
}

#[tokio::test]
async fn batch_preflight_preserves_old_agent_and_offline_errors() {
  let state = crate::rules::tests::test_state();
  seed(&state, "
    INSERT INTO cleanups (service, server, due_at) VALUES
    ('a','old',0), ('b','old',0), ('a','offline',0), ('b','offline',0);
  ").await;
  state.hub.mock_safe_delete_agent("old", |_| {
    panic!("旧 agent 不应收到清理请求")
  });
  for (server, code, suggestions) in [
    ("old", ErrorCode::Conflict, &["wharf upgrade"][..]),
    (
      "offline",
      ErrorCode::AgentOffline,
      &["wharf server show offline"][..],
    ),
  ] {
    let response = execute(
      State(state.clone()),
      auth(None),
      Extension(AuditSlot::default()),
      Json(DataCleanupExecRequest {
        server: Some(server.into()),
        expired_only: true,
        ..Default::default()
      }),
    )
    .await;
    let err = response.err().unwrap().0;
    assert_eq!(err.code, code);
    assert_eq!(err.suggest, suggestions);
  }
}

#[tokio::test]
async fn stale_cleanup_status_uses_measured_record_and_archive_sizes()
{
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  seed(&state, r#"
    INSERT INTO settings (key, value) VALUES ('backup_move.retired.app@s1',
      '{"service":"app","is_core":false,"server":"s1","path":"/srv/wharf-backup/app","moved_at":0,"expires_at":1}');
  "#).await;
  state.hub.mock_data_cleanup_agent("s1", |op| match op {
    AgentOp::CleanupScan(request) => {
      assert!(request.compute_sizes);
      Ok(json!({
        "path_stats": {
          "/srv/app": {"exists":true,"size_bytes":100},
          "/srv/wharf-backup/app": {"exists":true,"size_bytes":250}
        },
        "entries": [{
          "kind":"restore_backup","service":"app","target":"/srv/.wharf-restore/snapshot",
          "display":"snapshot","created_at":0,"size_bytes":300
        }]
      }))
    }
    _ => panic!("只刷新清理缓存"),
  });
  refresh_cache(&state).await.unwrap();
  let snap = snapshot::load_inner(&state.db).await.unwrap();
  let titles: Vec<_> = issues(&state, &snap)
    .await
    .unwrap()
    .into_iter()
    .map(|i| i.title)
    .collect();
  assert_eq!(
    titles,
    [
      "app 有 3 项超期留底（约 650 字节）",
      "other 有 1 项超期留底（大小待统计）"
    ]
  );
}

#[tokio::test]
async fn service_cleanup_allows_unrelated_apply_and_reserves_repo_target()
 {
  let state = crate::rules::tests::test_state();
  state.hub.mock_data_cleanup_agent("s1", |op| match op {
    AgentOp::CleanupDelete(req) if req.kind == OrphanBackupRepo => {
      Ok(json!({"removed":true}))
    }
    _ => panic!("只应删除测试仓库"),
  });
  let c = Candidate::new(
    "s1",
    entry(OrphanBackupRepo, Some("app"), "/srv/wharf-backup/app"),
    None,
    7,
  );
  let cancel = CancellationToken::new();
  let other = state
    .locks
    .acquire(LockSpec::apply(["other".into()]), "部署其他服务")
    .unwrap();
  assert!(
    delete_candidate(&state, &c, &cancel).await.unwrap().removed
  );
  drop(other);
  let backup = state
    .locks
    .acquire(LockSpec::Backup("other".into()), "同服务器备份")
    .unwrap();
  backup.reserve_backup_target("s1".into()).unwrap();
  assert_eq!(
    delete_candidate(&state, &c, &cancel)
      .await
      .unwrap_err()
      .code,
    ErrorCode::Busy
  );
}

#[tokio::test]
async fn migration_and_archive_expiry_record_runs_and_audit() {
  let state = crate::rules::tests::test_state();
  migrations(&state).await;
  seed(&state, r#"
    INSERT INTO settings VALUES ('data_cleanup.policy','{"auto_expire":true}');
    INSERT INTO resources (kind,name,spec,version,created_at,updated_at)
    VALUES ('server','s3','{}',1,0,0);
  "#).await;
  state.hub.mock_safe_delete_agent("s1", |op| {
    assert!(matches!(op, AgentOp::RemoveData { service } if service == "app"));
    Ok(json!({"removed":true}))
  });
  state.hub.mock_data_cleanup_agent("s3", |op| match op {
    AgentOp::CleanupScan(_) => Ok(json!({"entries":[{
      "kind":"restore_backup","service":"app","target":"/srv/.wharf-restore/snapshot",
      "display":"snapshot","created_at":0
    }]})),
    AgentOp::CleanupDelete(req) if req.kind == RestoreBackup => Ok(json!({"removed":true})),
    _ => panic!("不相关的请求"),
  });
  let migration = crate::apply::start_task_by(
    state.clone(),
    "迁移旧数据".into(),
    crate::planner::Step::CleanupData {
      service: "app".into(),
      server: "s1".into(),
      instance_id: Some("svc_old".into()),
    },
    Some(AUTO_ACTOR.into()),
  )
  .await
  .unwrap();
  tokio::time::timeout(Duration::from_secs(3), async {
    while state.runs.is_active(&migration.run_id) {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .unwrap();
  refresh_cache(&state).await.unwrap();
  let linked = state.db.call(|c| c.query_row(
    "SELECT COUNT(*) FROM runs JOIN audit_log ON instr(audit_log.detail, runs.id) = 1
     WHERE runs.actor = '到期清理' AND runs.status = 'succeeded'
       AND audit_log.actor = '到期清理' AND audit_log.kind = 'cleanup' AND audit_log.status = 200",
    [], |r| r.get::<_, usize>(0),
  ).map_err(sql_err)).await.unwrap();
  assert_eq!(linked, 2);
  assert!(
    state
      .db
      .call(inventory)
      .await
      .unwrap()
      .records
      .keys()
      .all(|(_, _, svc)| svc != "app")
  );
}
