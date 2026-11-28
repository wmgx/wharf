use super::*;

#[tokio::test]
async fn scan_and_delete_migrate_target_backup() {
  let tmp = tempfile::tempdir().unwrap();
  let srv = tmp.path().canonicalize().unwrap();
  let path = srv.join(".wharf-migrate/app-before-20261101-120000");
  std::fs::create_dir_all(&path).unwrap();
  std::fs::write(path.join("data"), b"test").unwrap();
  let ctx = Ctx::detached();
  let list =
    directory_entries(&srv, &srv.join("projects"), &ctx).unwrap();
  assert_eq!(list[0].kind, MigrateTargetBackup);
  assert_eq!(list[0].created_at, Some(1793534400000));
  let req = CleanupDeleteRequest {
    kind: list[0].kind,
    target: list[0].target.clone(),
    service: Some("app".into()),
    is_core: false,
    extra_project: None,
  };
  let (base, rel, _) =
    directory_target(&req, &srv, &srv.join("projects")).unwrap();
  assert_eq!(
    stat_path(
      &path,
      Some(Instant::now() + Duration::from_secs(1)),
      &ctx
    )
    .unwrap()
    .size_bytes,
    Some(4)
  );
  let outside = srv.join(".outside");
  std::fs::rename(&path, &outside).unwrap();
  std::os::unix::fs::symlink(&outside, &path).unwrap();
  assert_eq!(
    dirfd::remove_tree_under(&base, &rel, &ctx)
      .await
      .unwrap_err()
      .code,
    ErrorCode::InvalidInput
  );
  assert!(outside.join("data").exists());
  std::fs::remove_file(&path).unwrap();
  std::fs::rename(&outside, &path).unwrap();
  dirfd::remove_tree_under(&base, &rel, &ctx).await.unwrap();
  assert!(!path.exists());
}

#[tokio::test]
async fn restore_backup_delete_blocks_when_container_mounts_it() {
  let (tmp, docker) = crate::docker::fake_docker(
    r#"
case "$1:$2" in
  ps:-aq) echo c1 ;;
  container:inspect)
    printf '%s\t%s\n' '"/reader" "" "reader" [{"Type":"bind","Source":"/srv/.wharf-restore","Destination":"/data","RW":false}]' '["c1","/reader","exited","2026-11-01T12:00:00Z","image",{},[],{}]' ;;
esac
  "#,
  );
  let shell = crate::host_shell::HostShell::prepare(
    docker.clone(),
    "s1".into(),
  )
  .await;
  let reporter = crate::report::Reporter::new(docker.clone(), None);
  let ops = Ops::new(
    docker,
    reporter,
    String::new(),
    shell,
    tmp.path().into(),
  );
  let result = delete(
    &ops,
    CleanupDeleteRequest {
      kind: RestoreBackup,
      target:
        "/srv/.wharf-restore/app-before-20261101-120000-a1b2c3d4"
          .into(),
      service: Some("app".into()),
      is_core: false,
      extra_project: None,
    },
    &Ctx::detached(),
  )
  .await
  .unwrap();
  assert!(!result.removed);
  assert_eq!(result.blocked_by, ["reader"]);
}
