use super::*;
use std::{fs, os::unix::fs::symlink};

#[test]
fn restore_blocks_symlink_root_and_escaping_child_links() {
  let dir = tempfile::tempdir().unwrap();
  let srv = dir.path().join("srv");
  let staging = srv.join(".wharf-restore");
  let fresh = staging.join("work/srv/s1");
  let old = srv.join("s1");
  let outside = dir.path().join("outside");
  fs::create_dir_all(&outside).unwrap();
  fs::create_dir_all(fresh.parent().unwrap()).unwrap();
  fs::create_dir_all(&old).unwrap();
  fs::write(old.join("original"), "kept").unwrap();

  let install =
    || install_restored_tree(&srv, "s1", "work", "kept", "abcd1234");
  let rejected = |target: &str| {
    let error = install().unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert!(error.message.contains("abcd1234"), "{}", error.message);
    assert!(
      error.message.contains(&format!(" -> {target}")),
      "{}",
      error.message
    );
    assert_eq!(error.hint.as_deref(), Some(RESTORE_HINT));
    assert_eq!(
      fs::read_to_string(old.join("original")).unwrap(),
      "kept"
    );
    assert!(!staging.join("kept").exists());
  };
  let restored_srv = fresh.parent().unwrap();
  fs::remove_dir(restored_srv).unwrap();
  symlink(&outside, restored_srv).unwrap();
  rejected(outside.to_str().unwrap());
  fs::remove_file(restored_srv).unwrap();
  fs::create_dir(restored_srv).unwrap();

  symlink(&outside, &fresh).unwrap();
  rejected(outside.to_str().unwrap());
  fs::create_dir(&fresh).unwrap();
  symlink(&outside, fresh.join("data")).unwrap();
  rejected(outside.to_str().unwrap());
  fs::create_dir_all(fresh.join("data/deep")).unwrap();
  symlink("../../../outside", fresh.join("data/deep/link")).unwrap();
  rejected("../../../outside");
  fs::create_dir_all(fresh.join("data")).unwrap();
  fs::write(fresh.join("data/v2"), "new").unwrap();
  symlink("v2", fresh.join("data/cur")).unwrap();
  assert!(install().unwrap());
  assert_eq!(
    fs::read_to_string(old.join("data/cur")).unwrap(),
    "new"
  );
  assert_eq!(
    fs::read_to_string(staging.join("kept/original")).unwrap(),
    "kept"
  );
}

#[test]
fn restore_installs_staged_tree_after_original_entry_changes() {
  let dir = tempfile::tempdir().unwrap();
  let srv = dir.path().join("srv");
  let restore = srv.join(".wharf-restore");
  let work = restore.join("work/srv");
  let fresh = work.join("s1");
  let live = srv.join("s1");
  fs::create_dir_all(&fresh).unwrap();
  fs::create_dir_all(&live).unwrap();
  fs::write(fresh.join("new"), "checked").unwrap();
  fs::write(live.join("old"), "kept").unwrap();
  let srv_fd = DirFd::open_dir(&srv).unwrap();
  let restore_fd = DirFd::open_dir(&restore).unwrap();
  let fresh_parent = DirFd::open_dir(&work).unwrap();
  let staged =
    StagedRestore::new(&restore_fd, &restore, &fresh_parent, c"s1")
      .unwrap();
  staged.validate(&live, "abcd1234").unwrap();

  symlink(dir.path(), &fresh).unwrap();
  let kept = restore.join("kept");
  assert!(
    install_checked_tree(
      &staged,
      &srv_fd,
      &restore_fd,
      c"s1",
      &kept,
      &live
    )
    .unwrap()
  );
  assert_eq!(
    fs::read_to_string(live.join("new")).unwrap(),
    "checked"
  );
  assert_eq!(fs::read_to_string(kept.join("old")).unwrap(), "kept");
  assert!(fresh.symlink_metadata().unwrap().is_symlink());
}

#[test]
fn detect_escaped_mounts_finds_symlink_outside_root() {
  let dir = tempfile::tempdir().unwrap();
  let root = dir.path().join("s1");
  let link = root.join("originals");
  fs::create_dir(&root).unwrap();
  symlink("/mnt/nonexistent-in-agent/originals", &link).unwrap();
  let mounts = [link.display().to_string()];
  assert_eq!(
    detect_escaped_mounts(dir.path(), "s1", &mounts).unwrap(),
    [EscapedMount {
      source: mounts[0].clone(),
      resolved: "/mnt/nonexistent-in-agent/originals".into(),
    }]
  );
}

#[test]
fn mountpoint_detected_even_when_parent_and_child_share_device() {
  let dir = tempfile::tempdir().unwrap();
  let service = dir.path().join("s1");
  fs::create_dir(&service).unwrap();
  let info = format!(
    "22 1 0:1 / {} rw - ext4 /dev/disk rw",
    service.display()
  );
  assert!(is_mountpoint(dir.path(), "s1", Some(&info)).unwrap());
  assert!(!is_mountpoint(dir.path(), "s1", None).unwrap());
}

#[test]
fn cleanup_stale_work_keeps_before_dirs_and_prune_respects_days() {
  let dir = tempfile::tempdir().unwrap();
  let root = dir.path().join(".wharf-restore");
  let work = root.join("s1-20260101-000000-abcdef12");
  let kept = root.join("s1-before-20260101-000000-abcdef12");
  fs::create_dir_all(&work).unwrap();
  fs::create_dir(&kept).unwrap();
  cleanup_stale_restore_work(dir.path());
  assert!(kept.is_dir() && !work.exists());
  let prune = |days| {
    prune_restore_kept(dir.path(), days, &Ctx::detached())
      .unwrap()
      .removed
  };
  assert_eq!(prune(7), 0);
  assert_eq!(prune(0), 1);
  assert!(!kept.exists());
}

#[test]
fn locked_repo_error_maps_to_unlock_hint() {
  let error = check_restic_output(
    Output {
      success: false,
      code: Some(1),
      stdout: String::new(),
      stderr: "repository is already locked exclusively".into(),
    },
    "restic backup",
    "s1",
  )
  .unwrap_err();
  assert_eq!(error.code, ErrorCode::Conflict);
  assert_eq!(error.suggest, ["wharf backup unlock s1"]);
}
