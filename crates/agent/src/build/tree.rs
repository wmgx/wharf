use super::*;

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

pub(super) fn check_tree(root: &Path) -> Result<(), ApiError> {
  let fd = crate::dirfd::DirFd::open_dir(root)
    .map_err(|e| crate::dirfd::dir_error(root, e))?;
  crate::dirfd::validate_tree(&fd, false)
}

pub(crate) fn checked_path(
  root: &Path,
  path: &Path,
) -> Result<PathBuf, ApiError> {
  let base = root.canonicalize().map_err(io_err(root))?;
  let candidate = path.canonicalize().map_err(io_err(path))?;
  if candidate.starts_with(base) {
    Ok(candidate)
  } else {
    Err(ApiError::invalid(format!(
      "路径 {} 指向构建目录之外",
      path.display()
    )))
  }
}

pub(crate) fn checked_subdir(
  root: &Path,
  rel: Option<&str>,
) -> Result<PathBuf, ApiError> {
  let path =
    root.join(rel.map(relative).transpose()?.unwrap_or_default());
  let path = checked_path(root, &path)?;
  if !path.is_dir() {
    return Err(ApiError::invalid(format!(
      "代码里没有目录 {}",
      rel.unwrap_or_default()
    )));
  }
  Ok(path)
}

pub(super) struct FsTree<'a>(pub(super) &'a Path);

impl SourceTree for FsTree<'_> {
  fn read(&self, path: &str) -> Option<String> {
    let path = checked_path(self.0, &self.0.join(path)).ok()?;
    // 只读小文件：判断语言用不到大文件。
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
      return None;
    }
    std::fs::read_to_string(path).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    let Ok(path) = checked_path(self.0, &self.0.join(dir)) else {
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
