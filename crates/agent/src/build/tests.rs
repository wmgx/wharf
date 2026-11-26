use super::*;

#[test]
fn picks_commit_from_ls_remote() {
  let a = "a".repeat(40);
  let b = "b".repeat(40);
  let c = "c".repeat(40);
  let out = format!(
    "{a}\trefs/heads/main\n{b}\trefs/tags/v1\n{c}\trefs/tags/v1^{{}}\n"
  );
  assert_eq!(pick_commit(&out, "main"), Some(a));
  // 附注标签取它指向的 commit。
  assert_eq!(pick_commit(&out, "v1"), Some(c));
  assert_eq!(pick_commit(&out, "dev"), None);
}

#[test]
fn build_error_keeps_only_error_lines() {
  let log = "#8 RUN pip install\n#8 1.5 ERROR: HTTP 403\n#8 ERROR: exit 1\n------\n#8 1.5 ERROR: HTTP 403\nERROR: failed to solve";
  let e = build_failed(log);
  assert_eq!(
    e.message,
    "构建失败：#8 1.5 ERROR: HTTP 403\n#8 ERROR: exit 1\nERROR: failed to solve"
  );
}

#[test]
fn paths_stay_inside_the_code() {
  assert!(relative("app").is_ok());
  assert!(relative("./svc/api").is_ok());
  for bad in ["", "/etc", "../x", "a/../../b"] {
    assert!(relative(bad).is_err(), "{bad}");
  }
}

#[test]
fn build_tree_check_rejects_git_or_unpacked_escaping_symlinks() {
  use std::{fs, os::unix::fs::symlink};
  let dir = tempfile::tempdir().unwrap();
  let root = dir.path().join("src");
  let outside = dir.path().join("outside");
  fs::create_dir_all(&root).unwrap();
  fs::create_dir_all(&outside).unwrap();
  symlink(&outside, root.join("sub")).unwrap();
  assert_eq!(
    check_tree(&root).unwrap_err().code,
    ErrorCode::InvalidInput
  );
  assert_eq!(
    checked_subdir(&root, Some("sub")).unwrap_err().code,
    ErrorCode::InvalidInput
  );
  fs::remove_file(root.join("sub")).unwrap();
  fs::create_dir(root.join("sub")).unwrap();
  fs::create_dir(root.join("app")).unwrap();
  symlink("../app", root.join("sub/inside")).unwrap();
  assert!(check_tree(&root).is_ok());
  assert_eq!(
    checked_subdir(&root, Some("sub/inside")).unwrap(),
    root.join("app").canonicalize().unwrap()
  );
}

#[test]
fn tree_lists_dirs_with_slash() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::create_dir(dir.path().join("cmd")).unwrap();
  std::fs::write(dir.path().join("go.mod"), "module x").unwrap();
  let tree = FsTree(dir.path());
  let mut names = tree.list("");
  names.sort();
  assert_eq!(names, vec!["cmd/", "go.mod"]);
  assert_eq!(tree.read("go.mod").as_deref(), Some("module x"));
}
