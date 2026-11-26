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
