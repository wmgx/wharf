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

  let install = || install_restored_tree(&srv, "s1", "work", "kept");
  let rejected = || {
    assert_eq!(install().unwrap_err().code, ErrorCode::InvalidInput);
    assert_eq!(
      fs::read_to_string(old.join("original")).unwrap(),
      "kept"
    );
    assert!(!staging.join("kept").exists());
  };
  symlink(&outside, &fresh).unwrap();
  rejected();
  fs::remove_file(&fresh).unwrap();
  fs::create_dir(&fresh).unwrap();
  symlink(&outside, fresh.join("data")).unwrap();
  rejected();
  fs::remove_file(fresh.join("data")).unwrap();
  fs::create_dir_all(fresh.join("data/deep")).unwrap();
  symlink("../../../outside", fresh.join("data/deep/link")).unwrap();
  rejected();
  fs::remove_file(fresh.join("data/deep/link")).unwrap();
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
