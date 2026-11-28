use super::*;
use crate::{
  backup::tests::{seed_servers, seed_service},
  rules::tests::test_state,
};
use std::sync::atomic::{AtomicU8, Ordering};
use wharf_api_types::agent::SYNC_READY;

fn snapshots(count: u8) -> Value {
  json!(
    (0..count)
      .map(|n| json!({
        "id":n.to_string(), "short_id":n.to_string(),
        "time":"2026-01-01T00:00:00Z", "hostname":"s1",
      }))
      .collect::<Vec<_>>()
  )
}

#[tokio::test]
async fn backup_move_resumes_verifies_snapshots_and_retains_old_repo()
{
  let s = test_state();
  seed_servers(&s).await;
  seed_service(&s, "app", true).await;
  s.db.call(|c| {
      db::apply_write(c, &db::Write::Upsert {
        kind: "server".into(), name: "s3".into(),
        spec: json!({"private_addr":{"ip":"100.64.0.3","network":"lan"}}), meta: json!({}),
      })?;
      c.execute("INSERT INTO backups(service, server, target, run_id, ok, body, created_at)
        VALUES ('app','s1','s2','original',1,'{}',1234)", []).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
  backup::ensure_service_creds(&s, "app").await.unwrap();
  let phase = Arc::new(AtomicU8::new(0));
  let source = phase.clone();
  s.hub.mock_backup_move_agent("s2", move |op, _| {
    Some(match op {
      AgentOp::Probe { .. } => Ok(json!([true])),
      AgentOp::Restic(job)
        if matches!(job.action, ResticAction::Snapshots) =>
      {
        Ok(snapshots(3))
      }
      AgentOp::SyncPush(job) => {
        assert_eq!(job.kind, SyncKind::BackupRepo);
        if source.load(Ordering::Relaxed) == 0 {
          Err(ApiError::new(ErrorCode::AgentFailed, "连接中断"))
        } else {
          Ok(json!({"synced":true}))
        }
      }
      _ => panic!("源仓库只可探测、读取或发送"),
    })
  });
  let target = phase.clone();
  s.hub.mock_backup_move_agent("s3", move |op, progress| Some(match op {
      AgentOp::Restic(job) if matches!(job.action, ResticAction::RepoNonempty) => Ok(json!(false)),
      AgentOp::Restic(job) if matches!(job.action, ResticAction::Snapshots) => {
        Ok(snapshots(if target.load(Ordering::Relaxed) == 1 { 2 } else { 3 }))
      }
      AgentOp::SyncServe(job) => {
        assert_eq!(job.require_empty, target.load(Ordering::Relaxed) == 0);
        assert!(!job.preserve_existing);
        progress.unwrap()(format!("{SYNC_READY}1000"));
        return None;
      }
      AgentOp::ProjectStatus { .. } => Ok(json!([])),
      AgentOp::ProjectUp(_) => Ok(json!({
        "containers":[{"name":"rest-server","service":"rest-server","state":"running"}],"images":[]
      })),
      _ => panic!("目标仓库收到意外操作"),
    }));
  let step = Step::BackupMove {
    service: "app".into(),
    is_core: false,
    from: "s2".into(),
    to: "s3".into(),
    replace_target: false,
  };
  let cancel = CancellationToken::new();
  let progress: ProgressFn = Arc::new(|_| {});
  for (attempt, expected) in
    [(0, ErrorCode::AgentFailed), (1, ErrorCode::Conflict)]
  {
    phase.store(attempt, Ordering::Relaxed);
    let snap = snapshot::load(&s.db).await.unwrap();
    assert_eq!(
      execute(&s, &snap, "r1", &step, &progress, &cancel)
        .await
        .unwrap_err()
        .code,
      expected
    );
    let snap = snapshot::load(&s.db).await.unwrap();
    assert_eq!(
      snap.world.services["app"].spec.backup.as_ref().unwrap().to,
      "s2"
    );
    assert!(snap.pending.backup_moves["app"].target_prepared);
    assert!(require_idle(&snap, "app").is_err());
  }
  phase.store(2, Ordering::Relaxed);
  let snap = snapshot::load(&s.db).await.unwrap();
  execute(&s, &snap, "r2", &step, &progress, &cancel)
    .await
    .unwrap();
  let snap = snapshot::load(&s.db).await.unwrap();
  assert_eq!(
    snap.world.services["app"].spec.backup.as_ref().unwrap().to,
    "s3"
  );
  assert!(!snap.pending.backup_moves.contains_key("app"));
  s.db
    .call(|c| {
      assert!(
        db::setting(c, "backup_move.retired.app@s2")?.is_some()
      );
      let original: i64 = c
        .query_row(
          "SELECT created_at FROM backups WHERE run_id='r2'",
          [],
          |r| r.get(0),
        )
        .map_err(sql_err)?;
      assert_eq!(original, 1234);
      Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn backup_move_core_preserves_user_key_and_confirms_nonempty_target()
 {
  let s = test_state();
  let movement = Move {
    service: core_backup::REPO.into(),
    is_core: true,
    from: "s2".into(),
    to: "s3".into(),
  };
  let snap = snapshot::load(&s.db).await.unwrap();
  s.hub.mock_backup_move_agent("s3", |op, _| {
    Some(match op {
      AgentOp::Restic(job) => {
        assert!(matches!(job.repo, ResticRepo::LocalCore));
        match job.action {
          ResticAction::RepoNonempty => Ok(json!(true)),
          ResticAction::Snapshots => Ok(snapshots(1)),
          _ => panic!("目标仓库只可预检"),
        }
      }
      _ => panic!("目标仓库只可预检"),
    })
  });
  let view = movement
    .preview(&s, &snap, "", 3, None, &CancellationToken::new())
    .await
    .unwrap();
  assert!(view.needs_confirm);
  assert_eq!(view.confirm.as_deref(), Some("backup-move/wharf-core"));
  s.db
    .call(move |c| {
      db::set_setting(c, core_backup::TO, Some("s2"))?;
      db::set_setting(c, "core_backup.user_key_target", Some("s2"))?;
      db::set_setting(c, "core_backup.user_key", Some("abc"))?;
      finish(c, &movement, "r1", 3)?;
      assert_eq!(core_backup::target(c)?.as_deref(), Some("s3"));
      assert_eq!(
        db::setting(c, "core_backup.user_key_target")?.as_deref(),
        Some("s3")
      );
      assert_eq!(
        db::setting(c, "core_backup.user_key")?.as_deref(),
        Some("abc")
      );
      Ok(())
    })
    .await
    .unwrap();
}
