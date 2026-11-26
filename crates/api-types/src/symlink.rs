//! 打包、解包和恢复共用的相对路径校验。

use std::{
  collections::{BTreeMap, VecDeque},
  ffi::OsString,
  path::{Component, Path, PathBuf},
};

use crate::ApiError;

const MAX_SYMLINK_DEPTH: usize = 40;

pub fn check_relative_entry(
  path: &Path,
) -> Result<PathBuf, ApiError> {
  let mut rel = PathBuf::new();
  for part in path.components() {
    match part {
      Component::Normal(name)
        if !name.as_encoded_bytes().contains(&0) =>
      {
        rel.push(name)
      }
      Component::CurDir => {}
      _ => {
        return Err(ApiError::invalid(format!(
          "归档条目路径不合法：{}",
          path.display()
        )));
      }
    }
  }
  Ok(rel)
}

fn link_error(rel: &Path, target: &Path) -> ApiError {
  ApiError::invalid(format!("软链接 {} 的目标 {} 越界或存在循环", rel.display(), target.display()))
    .with_hint("删掉这个软链接、把它加入 .dockerignore / .gitignore，或改用目录内相对链接")
}

fn relative_parts(path: &Path) -> Option<Vec<OsString>> {
  path
    .components()
    .filter(|c| *c != Component::CurDir)
    .map(|c| match c {
      Component::ParentDir => Some("..".into()),
      Component::Normal(s) if !s.as_encoded_bytes().contains(&0) => {
        Some(s.to_owned())
      }
      _ => None,
    })
    .collect()
}

pub fn check_single_link(
  rel: &Path,
  target: &Path,
) -> Result<PathBuf, ApiError> {
  resolve(rel, target, &BTreeMap::new())
}

pub fn validate_symlinks(
  links: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), ApiError> {
  for (rel, target) in links {
    check_single_link(rel, target)?;
    resolve(rel, target, links)?;
  }
  Ok(())
}

fn resolve(
  rel: &Path,
  target: &Path,
  links: &BTreeMap<PathBuf, PathBuf>,
) -> Result<PathBuf, ApiError> {
  let error = || link_error(rel, target);
  let rel = check_relative_entry(rel)?;
  let parent = rel.parent().ok_or_else(error)?;
  let mut resolved = parent.to_path_buf();
  let mut pending =
    VecDeque::from(relative_parts(target).ok_or_else(error)?);
  let mut followed = 0;
  while let Some(part) = pending.pop_front() {
    if part == ".." {
      if !resolved.pop() {
        return Err(error());
      }
      continue;
    }
    resolved.push(part);
    if let Some(target) = links.get(&resolved) {
      followed += 1;
      if followed > MAX_SYMLINK_DEPTH {
        return Err(error());
      }
      resolved.pop();
      for part in
        relative_parts(target).ok_or_else(error)?.into_iter().rev()
      {
        pending.push_front(part);
      }
    }
  }
  Ok(resolved)
}
