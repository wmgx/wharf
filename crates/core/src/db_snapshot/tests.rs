use super::*;
use crate::{
  apply,
  planner::{self, Planned},
};
use wharf_api_types::plan::{
  Action, ApplyRequest, Layer, PlanItem, PlanStatus,
};

fn disk_state() -> (tempfile::TempDir, Arc<AppState>) {
  let dir = tempfile::tempdir().unwrap();
  let mut state = crate::rules::tests::test_state();
  let s = Arc::get_mut(&mut state).unwrap();
  s.db = Db::open(&dir.path().join("wharf.db")).unwrap();
  s.data_dir = dir.path().into();
  (dir, state)
}

fn test_plan(address: &str, impact: Impact) -> Plan {
  let item = PlanItem {
    id: 1,
    address: address.into(),
    layer: Layer::Config,
    action: Action::Delete,
    before: None,
    after: None,
    impacts: vec![impact],
    reason: String::new(),
    changes: vec![],
    host_access: vec![],
  };
  let needs_confirm = if item.needs_confirm() {
    vec![address.into()]
  } else {
    vec![]
  };
  Plan {
    plan_id: "p1".into(),
    status: PlanStatus::Pending,
    created_at: Utc::now(),
    expires_at: Utc::now() + chrono::TimeDelta::minutes(5),
    base_versions: Default::default(),
    inputs: None,
    items: vec![item],
    warnings: vec![],
    needs_host: vec![],
    needs_confirm,
    suggest: vec![],
    note: None,
  }
}

#[test]
fn high_risk_trigger() {
  let safe = test_plan("service/app", Impact::Restart);
  assert!(plan_trigger_reason(&safe, &[]).is_none());
  for (address, impact) in [
    ("service/app", Impact::Remove),
    ("gateway/gw1", Impact::Remove),
    ("service/app", Impact::Overwrite),
    ("route/example.test", Impact::Public),
  ] {
    assert!(
      plan_trigger_reason(&test_plan(address, impact), &[]).is_some()
    );
  }
  for step in [
    Step::VolumeSync {
      service: "app".into(),
      from: "s1".into(),
      to: "s2".into(),
      instance_id: None,
    },
    Step::ServiceDown {
      server: "s1".into(),
      service: "app".into(),
      purge_data: true,
      instance_id: None,
      has_relative_mounts: false,
    },
  ] {
    assert!(
      plan_trigger_reason(
        &safe,
        &[StepPlan {
          items: vec![],
          title: String::new(),
          step
        }]
      )
      .is_some()
    );
  }
}

async fn service_present(db: &Db) -> bool {
  db.call(|c| Ok(service_count(c) == 1)).await.unwrap()
}

fn service_count(c: &Connection) -> i64 {
  c.query_row("SELECT COUNT(*) FROM resources WHERE kind = 'service' AND name = 'app'", [], |r| r.get(0)).unwrap()
}

#[tokio::test]
async fn apply_snapshot_failure_is_atomic_and_admin_skip_is_audited()
{
  let (_dir, s) = disk_state();
  crate::backup::tests::seed_servers(&s).await;
  let mut plan = test_plan("service/app", Impact::Remove);
  plan.base_versions = s
    .db
    .call(|c| {
      db::apply_write(
        c,
        &db::Write::Upsert {
          kind: "service".into(),
          name: "app".into(),
          spec: json!({"server":"s1","source":{"image":"nginx:1"}}),
          meta: json!({}),
        },
      )?;
      db::versions(c)
    })
    .await
    .unwrap();
  let mut planned = Planned {
    plan,
    base_instances: Default::default(),
    account_refs: Default::default(),
    host_requirements: vec![],
    route_effects: Default::default(),
    steps: vec![],
    writes: vec![db::Write::Delete {
      kind: "service".into(),
      name: "app".into(),
    }],
  };
  planner::save(&s, &planned).await.unwrap();
  let mut auth = crate::security_receipt::tests::auth(true);
  auth.perms = [Perm::Apply, Perm::Confirm].into_iter().collect();
  let request = |id: &str, skip_snapshot| ApplyRequest {
    plan_id: id.into(),
    confirm: vec!["service/app".into()],
    skip_snapshot,
    verify_before_dns: None,
  };
  let path = s.data_dir.join("snapshots");
  fs::write(&path, b"blocked").unwrap();
  for (skip, code) in
    [(false, ErrorCode::Conflict), (true, ErrorCode::Forbidden)]
  {
    let e = apply::start(
      s.clone(),
      request("p1", skip),
      &auth.perms,
      Some((&auth, "test".into())),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, code);
    if !skip {
      assert!(e.hint.is_some() && !e.suggest.is_empty());
    }
    assert!(service_present(&s.db).await);
    assert_eq!(
      apply::load_plan(&s, "p1").await.unwrap().status,
      PlanStatus::Pending
    );
  }
  auth.perms.insert(Perm::Admin);
  fs::remove_file(&path).unwrap();
  apply::start(
    s.clone(),
    request("p1", false),
    &auth.perms,
    Some((&auth, "test".into())),
  )
  .await
  .unwrap();
  let saved = entries(&path).unwrap().pop().unwrap();
  assert_eq!(saved.trigger, "apply");
  assert_eq!(saved.plan_id.as_deref(), Some("p1"));
  assert_eq!(
    service_count(
      &Connection::open(path.join(format!("{}.db", saved.id)))
        .unwrap()
    ),
    1
  );
  assert!(!service_present(&s.db).await);

  planned.plan.plan_id = "p2".into();
  planned.plan.base_versions =
    s.db.call(|c| db::versions(c)).await.unwrap();
  planned.writes.clear();
  planner::save(&s, &planned).await.unwrap();
  fs::rename(&path, s.data_dir.join("saved")).unwrap();
  fs::write(&path, b"blocked").unwrap();
  apply::start(
    s.clone(),
    request("p2", true),
    &auth.perms,
    Some((&auth, "test".into())),
  )
  .await
  .unwrap();
  let audit: String = s
    .db
    .call(|c| {
      c.query_row(
        "SELECT detail FROM audit_log WHERE method = 'snapshot_skip'",
        [],
        |r| r.get(0),
      )
      .map_err(db::sql_err)
    })
    .await
    .unwrap();
  assert!(audit.contains("跳过数据库热快照"));
  assert!(
    crate::rules::tests::notice_titles(&s, "security_receipt")
      .await
      .iter()
      .any(|t| t.contains("跳过数据库热快照"))
  );
}

#[tokio::test]
async fn upgrade_snapshot_gates_dispatch() {
  use crate::agent_upgrade::upgrade_with_snapshot;
  use wharf_api_types::agent::{UpgradePreparation, UpgradeResult};
  let (_dir, s) = disk_state();
  let dir = s.data_dir.join("snapshots");
  let prepare = async || {
    Ok(UpgradePreparation {
      image: "test".into(),
      image_id: Some("sha256:test".into()),
    })
  };
  fs::write(&dir, b"blocked").unwrap();
  let err = upgrade_with_snapshot(&s, None, &prepare, async |_| {
    panic!("升级不应派发")
  })
  .await
  .unwrap_err();
  assert_eq!(err.code, ErrorCode::Conflict);
  fs::remove_file(&dir).unwrap();
  upgrade_with_snapshot(&s, None, prepare, async |image_id| {
    assert_eq!(image_id, "sha256:test");
    assert_eq!(entries(&dir)?[0].trigger, "upgrade");
    Ok(UpgradeResult {
      started: true,
      image: "test".into(),
    })
  })
  .await
  .unwrap();
  assert_eq!(entries(&dir).unwrap().len(), 1);
}

#[tokio::test]
async fn noop_upgrade_bypasses_snapshot_preflight() {
  use crate::agent_upgrade::upgrade_with_snapshot;
  use wharf_api_types::agent::UpgradePreparation;
  let (_temp, s) = disk_state();
  let dir = directory(&s.data_dir).unwrap();
  for id in ["older", "newer"] {
    private_file(&dir.join(format!("{id}.db")))
      .unwrap()
      .set_len(150 * 1024 * 1024)
      .unwrap();
  }
  // 投影出低盘预检会淘汰的旧快照，无需填满 CI 磁盘。
  let before: Vec<_> =
    entries(&dir).unwrap().into_iter().map(|e| e.id).collect();
  assert!(
    space_pruning(&entries(&dir).unwrap(), 1, None)
      .is_some_and(|ids| ids.len() == 1)
  );
  let result = upgrade_with_snapshot(
    &s,
    None,
    async || {
      Ok(UpgradePreparation {
        image: "test".into(),
        image_id: None,
      })
    },
    async |_| panic!("空升级不应派发"),
  )
  .await
  .unwrap();
  assert!(!result.started);
  let after: Vec<_> =
    entries(&dir).unwrap().into_iter().map(|e| e.id).collect();
  assert_eq!(after, before);
}

#[tokio::test]
async fn damaged_entries_do_not_block_snapshot_operations() {
  let (_temp, s) = disk_state();
  let dir = directory(&s.data_dir).unwrap();
  let broken = "20000101-000000Z-manual-0000";
  let outside = s.data_dir.join("outside");
  fs::write(&outside, b"untouched").unwrap();
  fs::write(dir.join(format!("{broken}.db")), b"fixture").unwrap();
  fs::write(dir.join(format!("{broken}.json")), b"{").unwrap();
  std::os::unix::fs::symlink(&outside, dir.join("link.db")).unwrap();
  fs::create_dir(dir.join("directory.db")).unwrap();
  let listed = view(&dir).unwrap();
  assert_eq!(listed.snapshots.len(), 1);
  assert_eq!(listed.snapshots[0].id, broken);
  assert_eq!(listed.snapshots[0].trigger, "manual");
  assert!(entry(&dir, broken, false).is_err());
  let saved =
    create(&s.db, &s.data_dir, info(Trigger::Manual, "test".into()))
      .await
      .unwrap();
  assert_eq!(view(&dir).unwrap().snapshots[0].id, saved.id);
  assert!(!dir.join(format!("{broken}.db")).exists());
  assert_eq!(fs::read(outside).unwrap(), b"untouched");
  assert!(dir.join("link.db").is_symlink());
  assert!(dir.join("directory.db").is_dir());
}

#[test]
fn pruning_keeps_upgrade_and_proves_space_before_deletion() {
  let now = Utc::now();
  let rows: Vec<_> = (0..12)
    .map(|i| DbSnapshotInfo {
      id: i.to_string(),
      created_at: now - chrono::TimeDelta::days(i),
      size_bytes: 10,
      trigger: if i == 11 { "upgrade" } else { "manual" }.into(),
      ..Default::default()
    })
    .collect();
  assert_eq!(plan_pruning(&rows, now, None), ["10", "9"]);
  assert_eq!(
    plan_pruning(&rows, now + chrono::TimeDelta::days(15), None)
      .len(),
    10
  );
  assert_eq!(space_pruning(&rows, 20, None).unwrap(), ["10", "9"]);
  assert!(space_pruning(&rows, 101, None).is_none());
}

#[test]
fn pruning_evicts_upgrade_as_last_resort_for_byte_limit() {
  let now = Utc::now();
  let rows = [
    DbSnapshotInfo {
      id: "newer".into(),
      trigger: "manual".into(),
      created_at: now,
      size_bytes: 150 * 1024 * 1024,
      ..Default::default()
    },
    DbSnapshotInfo {
      id: "upgrade".into(),
      trigger: "upgrade".into(),
      created_at: now - chrono::TimeDelta::days(1),
      size_bytes: 150 * 1024 * 1024,
      ..Default::default()
    },
  ];
  assert_eq!(plan_pruning(&rows, now, Some("newer")), ["upgrade"]);
  assert!(plan_pruning(&rows, now, Some("upgrade")).is_empty());
}

#[tokio::test]
async fn hot_snapshot_captures_wal_and_restores_offline() {
  let (temp, s) = disk_state();
  let path = temp.path();
  s.db
    .call_credentials(|c, key| {
      key.put_secret(c, "test-key", "fixture-value", 1, false)?;
      db::set_setting(c, "test", Some("before"))
    })
    .await
    .unwrap();
  assert!(fs::metadata(path.join("wharf.db-wal")).unwrap().len() > 0);
  let saved =
    create(&s.db, path, info(Trigger::Manual, "test".into()))
      .await
      .unwrap();
  let dir = path.join("snapshots");
  assert_eq!(
    fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
    0o700
  );
  let snapshot = dir.join(format!("{}.db", saved.id));
  let sidecar = dir.join(format!("{}.json", saved.id));
  for file in [&snapshot, &sidecar] {
    assert_eq!(
      fs::metadata(file).unwrap().permissions().mode() & 0o777,
      0o600
    );
  }
  let c = Connection::open_with_flags(
    &snapshot,
    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
  )
  .unwrap();
  assert_eq!(
    c.query_row("PRAGMA integrity_check(1)", [], |r| r
      .get::<_, String>(0))
      .unwrap(),
    "ok"
  );
  assert_eq!(
    db::setting(&c, "test").unwrap().as_deref(),
    Some("before")
  );
  drop(c);
  assert_eq!(view(&dir).unwrap().snapshots[0].sha256, saved.sha256);
  assert!(
    !fs::read_to_string(&sidecar)
      .unwrap()
      .contains("fixture-value")
  );
  s.db
    .call(|c| db::set_setting(c, "test", Some("after")))
    .await
    .unwrap();
  let not_confirmed = offline(
    path,
    OfflineCommand::Restore {
      id: saved.id.clone(),
      yes: false,
      no_pre_snapshot: false,
    },
  )
  .unwrap_err();
  assert_eq!(not_confirmed.code, ErrorCode::ConfirmRequired);
  let lock = process_lock(path, false).unwrap();
  assert_eq!(
    offline::restore(path, &saved.id, false).unwrap_err().code,
    ErrorCode::Busy
  );
  drop(lock);
  drop(s);

  let reject = || {
    assert_eq!(
      offline::restore(path, &saved.id, false).unwrap_err().code,
      ErrorCode::Conflict
    );
    assert_eq!(entries(&dir).unwrap().len(), 1);
    let current = Connection::open(path.join("wharf.db")).unwrap();
    assert_eq!(
      db::setting(&current, "test").unwrap().as_deref(),
      Some("after")
    );
  };
  let key = path.join(db::CREDENTIALS_KEY_FILE);
  let original = fs::read(&key).unwrap();
  fs::write(&key, [0; 32]).unwrap();
  reject();
  fs::write(&key, original).unwrap();
  let original = fs::read(&snapshot).unwrap();
  fs::write(&snapshot, b"damaged").unwrap();
  reject();
  fs::write(&snapshot, original).unwrap();

  // 没有 sidecar 时仍要拒绝高版本数据库，且正常快照可按文件名找回。
  fs::remove_file(&sidecar).unwrap();
  let c = Connection::open(&snapshot).unwrap();
  c.pragma_update(None, "user_version", db::SCHEMA_VERSION + 1)
    .unwrap();
  drop(c);
  reject();
  assert_eq!(
    entries(&dir).unwrap()[0].created_at.timestamp(),
    saved.created_at.timestamp()
  );
  let c = Connection::open(&snapshot).unwrap();
  c.pragma_update(None, "user_version", db::SCHEMA_VERSION)
    .unwrap();
  drop(c);

  offline::restore(path, &saved.id, false).unwrap();
  assert!(snapshot.is_file());
  assert_eq!(entries(&dir).unwrap()[0].trigger, "pre_restore");
  assert!(
    !path.join("wharf.db-wal").exists()
      && !path.join("wharf.db-shm").exists()
  );
  let db = Db::open(&path.join("wharf.db")).unwrap();
  db.call_credentials(|c, key| {
    assert_eq!(db::setting(c, "test")?.as_deref(), Some("before"));
    assert_eq!(
      key.secret(c, "test-key")?.as_deref(),
      Some("fixture-value")
    );
    Ok(())
  })
  .await
  .unwrap();
}

#[test]
fn offline_restore_recovers_damaged_or_missing_db() {
  let temp = tempfile::tempdir().unwrap();
  let path = temp.path();
  let dir = directory(path).unwrap();
  let id = "fixture";
  let current = path.join("wharf.db");
  let c = Connection::open(dir.join("fixture.db")).unwrap();
  c.execute_batch(
    "CREATE TABLE restored (value); INSERT INTO restored VALUES (42)",
  )
  .unwrap();
  drop(c);
  let broken: [(&str, &[u8]); 3] = [
    ("wharf.db", b"damaged database"),
    ("wharf.db-wal", b"damaged WAL"),
    ("wharf.db-shm", b"damaged shared memory"),
  ];
  for (name, bytes) in broken {
    fs::write(path.join(name), bytes).unwrap();
  }
  offline::restore(path, id, true).unwrap();
  let archive = fs::read_dir(path)
    .unwrap()
    .map(|entry| entry.unwrap())
    .find(|entry| {
      entry
        .file_name()
        .to_string_lossy()
        .starts_with(".wharf.db.before-restore-")
    })
    .unwrap()
    .path();
  for (name, bytes) in broken {
    assert_eq!(fs::read(archive.join(name)).unwrap(), bytes);
    if name != "wharf.db" {
      assert!(!path.join(name).exists());
    }
  }
  let check = || {
    let c = Connection::open(&current).unwrap();
    let value: i64 = c
      .query_row("SELECT value FROM restored", [], |r| r.get(0))
      .unwrap();
    assert_eq!(value, 42);
  };
  check();
  fs::remove_file(&current).unwrap();
  offline::restore(path, id, false).unwrap();
  check();
  assert_eq!(entries(&dir).unwrap().len(), 1);
}

#[test]
fn snapshot_paths_reject_symlinks_and_traversal() {
  let temp = tempfile::tempdir().unwrap();
  let dir = directory(temp.path()).unwrap();
  let outside = temp.path().join("outside");
  fs::write(&outside, b"unchanged").unwrap();
  std::os::unix::fs::symlink(&outside, dir.join("link.db")).unwrap();
  for id in ["../wharf", "link"] {
    assert_eq!(
      remove(&dir, id).unwrap_err().code,
      ErrorCode::InvalidInput
    );
    assert_eq!(
      offline::restore(temp.path(), id, false).unwrap_err().code,
      ErrorCode::InvalidInput
    );
  }
  assert_eq!(fs::read(outside).unwrap(), b"unchanged");
}
