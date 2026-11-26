//! 构建源码目录树的安全路径检查（R13.2 软链部分）。
//!
//! 防止上传包或 Git 仓库里的绝对/相对/链式软链接把宿主机目录带进构建或发布容器。

use std::path::{Component, Path, PathBuf};

use wharf_api_types::{ApiError, build::SourceTree};

use crate::{
  dirfd::{DirFd, validate_tree_symlinks},
  docker::io_err,
};

/// 只接受代码里的相对路径，不能跳出去。
pub(crate) fn relative(p: &str) -> Result<PathBuf, ApiError> {
  let path = PathBuf::from(p.trim_start_matches("./"));
  let ok = !p.is_empty()
    && path
      .components()
      .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
  if ok {
    Ok(path)
  } else {
    Err(ApiError::invalid(format!(
      "路径 {p} 不合法：要写代码里的相对路径"
    )))
  }
}

/// 递归检查解压或 Git 克隆后的源码目录树，拒绝任何指向源码根之外或链式逃逸的软链接。
pub(crate) fn validate_src_tree(src: &Path) -> Result<(), ApiError> {
  let root = DirFd::open_dir(src).map_err(io_err(src))?;
  validate_tree_symlinks(&root, false)
}

/// 校验子目录路径在词法与物理规范路径上均停留在 `root` 内部且为目录。
pub(crate) fn checked_subdir(
  root: &Path,
  rel: Option<&str>,
) -> Result<PathBuf, ApiError> {
  let root_canon = root.canonicalize().map_err(io_err(root))?;
  let candidate = match rel {
    Some(p) => root.join(relative(p)?),
    None => root.to_path_buf(),
  };
  let canon = candidate.canonicalize().map_err(|_| {
    ApiError::invalid(format!(
      "代码里没有目录 {}",
      rel.unwrap_or_default()
    ))
  })?;
  if !canon.starts_with(&root_canon) {
    return Err(ApiError::invalid(format!(
      "子目录 {} 指向了代码目录之外，已拒绝",
      rel.unwrap_or_default()
    )));
  }
  if !canon.is_dir() {
    return Err(ApiError::invalid(format!(
      "代码里没有目录 {}",
      rel.unwrap_or_default()
    )));
  }
  Ok(canon)
}

/// 校验文件在 `root` 内：不存在返回 `Ok(None)`，若存在但软链解析逃出 `root` 返回错误。
pub(crate) fn checked_file_in(
  root: &Path,
  rel: &str,
) -> Result<Option<PathBuf>, ApiError> {
  let rel_path = relative(rel)?;
  let root_canon = root.canonicalize().map_err(io_err(root))?;
  let candidate = root.join(&rel_path);
  let meta = match std::fs::symlink_metadata(&candidate) {
    Ok(m) => m,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(None);
    }
    Err(e) => return Err(io_err(&candidate)(e)),
  };
  let canon = candidate.canonicalize().map_err(|_| {
    ApiError::invalid(format!("文件 {rel} 无效或指向不存在的目标"))
  })?;
  if !canon.starts_with(&root_canon) {
    return Err(ApiError::invalid(format!(
      "文件 {rel} 指向了构建目录之外，已拒绝"
    )));
  }
  if meta.file_type().is_symlink() && !canon.is_file() {
    return Ok(None);
  }
  Ok(canon.is_file().then_some(canon))
}

pub(crate) struct FsTree<'a>(pub(crate) &'a Path);

impl FsTree<'_> {
  fn root_canon(&self) -> Option<PathBuf> {
    self.0.canonicalize().ok()
  }

  fn safe_path(&self, rel: &str) -> Option<PathBuf> {
    let root = self.root_canon()?;
    let target = if rel.is_empty() || rel == "." {
      self.0.to_path_buf()
    } else {
      self.0.join(relative(rel).ok()?)
    };
    let canon = target.canonicalize().ok()?;
    canon.starts_with(&root).then_some(canon)
  }
}

impl SourceTree for FsTree<'_> {
  fn read(&self, path: &str) -> Option<String> {
    let path = self.safe_path(path)?;
    // 只读小文件：判断语言用不到大文件。
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
      return None;
    }
    std::fs::read_to_string(path).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    let Some(path) = self.safe_path(dir) else {
      return vec![];
    };
    let Ok(entries) = std::fs::read_dir(path) else {
      return vec![];
    };
    entries
      .filter_map(Result::ok)
      .map(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
          format!("{name}/")
        } else {
          name
        }
      })
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{fs, os::unix::fs::symlink};

  #[test]
  fn paths_stay_inside_the_code() {
    assert!(relative("app").is_ok());
    assert!(relative("./svc/api").is_ok());
    for bad in ["", "/etc", "../x", "a/../../b"] {
      assert!(relative(bad).is_err(), "{bad}");
    }
  }

  #[test]
  fn tree_lists_dirs_with_slash() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("cmd")).unwrap();
    fs::write(dir.path().join("go.mod"), "module x").unwrap();
    let tree = FsTree(dir.path());
    let mut names = tree.list("");
    names.sort();
    assert_eq!(names, vec!["cmd/", "go.mod"]);
    assert_eq!(tree.read("go.mod").as_deref(), Some("module x"));
  }

  #[test]
  fn build_tree_check_rejects_git_or_unpacked_escaping_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("Dockerfile"), "FROM scratch").unwrap();

    // 1. 模拟 Git 克隆结果含 sub -> outside 绝对软链：validate_src_tree 与 checked_subdir 均拒绝。
    let src1 = tmp.path().join("src1");
    fs::create_dir_all(&src1).unwrap();
    symlink(&outside, src1.join("sub")).unwrap();
    assert!(validate_src_tree(&src1).is_err());
    assert!(checked_subdir(&src1, Some("sub")).is_err());

    // 2. 链式逃逸软链：sub/l1 -> .. + sub/l2 -> l1/.. -> 拒绝。
    let src2 = tmp.path().join("src2");
    fs::create_dir_all(src2.join("sub")).unwrap();
    symlink("..", src2.join("sub/l1")).unwrap();
    symlink("l1/..", src2.join("sub/l2")).unwrap();
    assert!(validate_src_tree(&src2).is_err());

    // 3. Dockerfile 是指向外部的软链：checked_file_in 拒绝。
    let src3 = tmp.path().join("src3");
    fs::create_dir_all(&src3).unwrap();
    symlink(outside.join("Dockerfile"), src3.join("Dockerfile"))
      .unwrap();
    assert!(checked_file_in(&src3, "Dockerfile").is_err());
    assert!(FsTree(&src3).read("Dockerfile").is_none());

    // 4. 目录内合法子目录与内部相对软链通过。
    let src4 = tmp.path().join("src4");
    fs::create_dir_all(src4.join("app/bin")).unwrap();
    fs::create_dir_all(src4.join("app/dist")).unwrap();
    fs::write(src4.join("app/dist/main.js"), "ok").unwrap();
    symlink("../dist/main.js", src4.join("app/bin/run")).unwrap();
    assert!(validate_src_tree(&src4).is_ok());
    assert!(checked_subdir(&src4, Some("app")).is_ok());
  }
}
