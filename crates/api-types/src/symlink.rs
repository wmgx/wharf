//! 软链接与归档路径安全校验（打包、上传、构建与恢复共用）。
//!
//! 拒绝绝对路径、越界相对路径（`..`）以及链式软链接逃逸，
//! 同时保留指向目录内部的正常相对软链接（如 `node_modules/.bin/*`）。

use std::{
  collections::{BTreeMap, VecDeque},
  ffi::OsString,
  path::{Component, Path, PathBuf},
};

use crate::ApiError;

/// POSIX 路径解析最大软链接展开深度，防循环软链。
pub const MAX_SYMLINK_DEPTH: usize = 40;

const SYMLINK_HINT: &str = "删掉这个软链接、把它加入 .dockerignore / .gitignore，或改用目录内相对链接";

#[derive(Debug, Clone)]
enum Step {
  Parent,
  Normal(OsString),
}

fn has_nul(path: &Path) -> bool {
  path.as_os_str().as_encoded_bytes().contains(&0)
}

/// 校验并规范化归档内相对条目路径：跳过前导 `.`，拒绝绝对路径、`..` 和 `\0`。
pub fn check_relative_entry(
  path: &Path,
) -> Result<PathBuf, ApiError> {
  if has_nul(path) {
    return Err(ApiError::invalid(format!(
      "路径包含非法空字节：{}",
      path.display()
    )));
  }
  let mut out = PathBuf::new();
  for comp in path.components() {
    match comp {
      Component::CurDir => {}
      Component::Normal(seg) => out.push(seg),
      Component::RootDir
      | Component::Prefix(_)
      | Component::ParentDir => {
        return Err(ApiError::invalid(format!(
          "归档条目路径越界或不合法：{}",
          path.display()
        )));
      }
    }
  }
  Ok(out)
}

/// 校验单条软链接 `rel -> target` 在词法上停留在根目录内，返回规范化的相对目标路径。
pub fn check_single_link(
  rel: &Path,
  target: &Path,
) -> Result<PathBuf, ApiError> {
  let rel = check_relative_entry(rel)?;
  if rel.as_os_str().is_empty() {
    return Err(ApiError::invalid("软链接路径不能为空"));
  }
  if has_nul(target) || target.is_absolute() {
    return Err(
      ApiError::invalid(format!(
        "软链接 {} 指向了目录之外（{}）",
        rel.display(),
        target.display()
      ))
      .with_hint(SYMLINK_HINT),
    );
  }
  let mut stack: Vec<OsString> = rel
    .parent()
    .into_iter()
    .flat_map(Path::components)
    .filter_map(|c| match c {
      Component::Normal(s) => Some(s.to_os_string()),
      _ => None,
    })
    .collect();
  for comp in target.components() {
    match comp {
      Component::CurDir => {}
      Component::Normal(seg) => stack.push(seg.to_os_string()),
      Component::ParentDir => {
        if stack.pop().is_none() {
          return Err(
            ApiError::invalid(format!(
              "软链接 {} 指向了目录之外（{}）",
              rel.display(),
              target.display()
            ))
            .with_hint(SYMLINK_HINT),
          );
        }
      }
      Component::RootDir | Component::Prefix(_) => {
        return Err(
          ApiError::invalid(format!(
            "软链接 {} 指向了目录之外（{}）",
            rel.display(),
            target.display()
          ))
          .with_hint(SYMLINK_HINT),
        );
      }
    }
  }
  Ok(stack.into_iter().collect())
}

fn target_steps(
  rel: &Path,
  target: &Path,
) -> Result<Vec<Step>, ApiError> {
  if has_nul(target) || target.is_absolute() {
    return Err(
      ApiError::invalid(format!(
        "软链接 {} 指向了目录之外（{}）",
        rel.display(),
        target.display()
      ))
      .with_hint(SYMLINK_HINT),
    );
  }
  let mut steps = Vec::new();
  for comp in target.components() {
    match comp {
      Component::CurDir => {}
      Component::ParentDir => steps.push(Step::Parent),
      Component::Normal(seg) => {
        steps.push(Step::Normal(seg.to_os_string()))
      }
      Component::RootDir | Component::Prefix(_) => {
        return Err(
          ApiError::invalid(format!(
            "软链接 {} 指向了目录之外（{}）",
            rel.display(),
            target.display()
          ))
          .with_hint(SYMLINK_HINT),
        );
      }
    }
  }
  Ok(steps)
}

/// 校验整棵目录树的全部软链接：单条不越界，且按 POSIX 逐级展开后不越界、无循环。
pub fn validate_symlinks(
  links: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), ApiError> {
  let mut norm = BTreeMap::new();
  for (rel, target) in links {
    let key = check_relative_entry(rel)?;
    check_single_link(&key, target)?;
    norm.insert(key, target.clone());
  }
  for (rel, target) in &norm {
    let mut pending: VecDeque<Step> = VecDeque::new();
    if let Some(parent) = rel.parent() {
      for comp in parent.components() {
        if let Component::Normal(seg) = comp {
          pending.push_back(Step::Normal(seg.to_os_string()));
        }
      }
    }
    for step in target_steps(rel, target)? {
      pending.push_back(step);
    }

    let mut stack: Vec<OsString> = Vec::new();
    let mut depth = 0usize;
    while let Some(step) = pending.pop_front() {
      match step {
        Step::Parent => {
          if stack.pop().is_none() {
            return Err(
              ApiError::invalid(format!(
                "软链接 {} 展开后指向了目录之外（{}）",
                rel.display(),
                target.display()
              ))
              .with_hint(SYMLINK_HINT),
            );
          }
        }
        Step::Normal(seg) => {
          stack.push(seg);
          let cur: PathBuf = stack.iter().collect();
          if let Some(next_target) = norm.get(&cur) {
            depth += 1;
            if depth > MAX_SYMLINK_DEPTH {
              return Err(
                ApiError::invalid(format!(
                  "检测到循环或过深的软链接：{}",
                  rel.display()
                ))
                .with_hint(SYMLINK_HINT),
              );
            }
            stack.pop();
            let next_steps = target_steps(&cur, next_target)?;
            for s in next_steps.into_iter().rev() {
              pending.push_front(s);
            }
          }
        }
      }
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_escaping_chained_and_loop_symlinks() {
    assert!(check_relative_entry(Path::new("/etc/passwd")).is_err());
    assert!(check_relative_entry(Path::new("../outside")).is_err());
    assert_eq!(
      check_relative_entry(Path::new("./a/b")).unwrap(),
      PathBuf::from("a/b")
    );

    let ok = BTreeMap::from([(
      PathBuf::from("bin/cli"),
      PathBuf::from("../dist/cli.js"),
    )]);
    assert!(validate_symlinks(&ok).is_ok());

    let abs = BTreeMap::from([(
      PathBuf::from("a"),
      PathBuf::from("/etc/passwd"),
    )]);
    assert!(validate_symlinks(&abs).is_err());

    let chained = BTreeMap::from([
      (PathBuf::from("sub/l1"), PathBuf::from("..")),
      (PathBuf::from("sub/l2"), PathBuf::from("l1/..")),
    ]);
    assert!(validate_symlinks(&chained).is_err());

    let looped = BTreeMap::from([
      (PathBuf::from("a"), PathBuf::from("b")),
      (PathBuf::from("b"), PathBuf::from("a")),
    ]);
    assert!(validate_symlinks(&looped).is_err());
  }
}
