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

#[tokio::test]
async fn orphan_image_removes_multiple_tags_without_force_and_protects_referenced_images()
 {
  let (tmp, docker) = crate::docker::fake_docker(
    r#"
case "$1:$2" in
  ps:-aq) echo c1 ;;
  container:inspect)
    printf '%s\t%s\n' '"/reader" "" "" []' '["c1","/reader","exited","2026-11-01T12:00:00Z","used-image",{},[],{}]' ;;
  image:ls) printf '%s\n' free-image used-image ;;
  image:inspect)
    printf '%s\n' '["free-image",["wharf-build/app:1","wharf-build/app:2"],17,"2026-11-01T12:00:00Z",{}]' '["used-image",["wharf-build/app:3","wharf-build/app:4"],17,"2026-11-01T12:00:00Z",{}]' ;;
  image:rm)
    [ "$*" = "image rm --no-prune -- wharf-build/app:1 wharf-build/app:2" ] || exit 1
    touch removed ;;
esac
"#,
  );
  let shell = crate::host_shell::HostShell::prepare(
    docker.clone(),
    "s1".into(),
  )
  .await;
  let ops = Ops::new(
    docker.clone(),
    crate::report::Reporter::new(docker, None),
    String::new(),
    shell,
    tmp.path().into(),
  );
  let req = |target: &str| CleanupDeleteRequest {
    kind: OrphanImage,
    target: target.into(),
    service: Some("app".into()),
    is_core: false,
    extra_project: None,
  };
  assert_eq!(
    delete(&ops, req("used-image"), &Ctx::detached())
      .await
      .unwrap_err()
      .code,
    ErrorCode::Conflict
  );
  assert!(!tmp.path().join("removed").exists());
  assert!(
    delete(&ops, req("free-image"), &Ctx::detached())
      .await
      .unwrap()
      .removed
  );
  assert!(tmp.path().join("removed").exists());
}

#[tokio::test]
async fn pulled_dangling_images_are_candidates_but_tagged_registry_images_are_not()
 {
  let (_tmp, docker) = crate::docker::fake_docker(
    r#"
case "$1:$2" in
  image:ls) printf '%s\n' dangling tagged ;;
  image:inspect)
    case "$4" in
      *RepoDigests*) printf '%s\n' '["dangling",[],["registry/app@sha256:old"],17,"2026-11-01T12:00:00Z",{}]' '["tagged",["registry/app:latest"],["registry/app@sha256:new"],20,"2026-11-01T12:00:00Z",{}]' ;;
      *) printf '%s\n' '["dangling",[],17,"2026-11-01T12:00:00Z",{}]' '["tagged",["registry/app:latest"],20,"2026-11-01T12:00:00Z",{}]' ;;
    esac ;;
esac
"#,
  );
  let current = runtime(&docker, &Ctx::detached()).await.unwrap();
  let entries = docker_entries(&current, &docker, Utc::now());
  assert_eq!(entries.len(), 1);
  assert_eq!(entries[0].target, "dangling");
  assert_eq!(entries[0].service, None);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn orphan_project_cleanup_removes_only_its_unused_networks() {
  let (tmp, docker) = crate::docker::fake_docker(
    r#"
case "$1:$2" in
  network:ls) printf '%s\n' free foreign occupied ;;
  network:inspect)
    printf '%s\n' '["free","old_default",{"com.docker.compose.project":"wharf-link-old"},{}]' '["foreign","other",{"com.docker.compose.project":"somebody-else"},{}]' '["occupied","in-use",{"com.docker.compose.project":"wharf-link-old"},{"consumer":{}}]' ;;
  network:rm)
    [ "$*" = "network rm -- free" ] || exit 1
    touch removed ;;
esac
"#,
  );
  let path = docker.project_dir("wharf-link-old");
  std::fs::create_dir_all(&path).unwrap();
  let shell = crate::host_shell::HostShell::prepare(
    docker.clone(),
    "s1".into(),
  )
  .await;
  let ops = Ops::new(
    docker.clone(),
    crate::report::Reporter::new(docker, None),
    String::new(),
    shell,
    tmp.path().into(),
  );
  let result = delete(
    &ops,
    CleanupDeleteRequest {
      kind: OrphanFrpc,
      target: "wharf-link-old".into(),
      service: None,
      is_core: false,
      extra_project: None,
    },
    &Ctx::detached(),
  )
  .await
  .unwrap();
  assert!(result.removed);
  assert!(tmp.path().join("removed").exists());
  assert!(!path.exists());
}
