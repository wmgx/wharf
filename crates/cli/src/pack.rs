//! `wharf deploy <目录>`：把目录打成 tar.gz。
//!
//! - 按 `.gitignore`、`.dockerignore` 排除文件（不要求是 git 仓库），不打包 `.git`；
//! - 内容相同就得到相同的包：文件按路径排序，时间、属主固定，权限只保留可执行位。
//!   代码没变时 sha256 不变，控制面不用重新接收，服务也不用重新构建。

use std::{
  io::Write,
  path::{Path, PathBuf},
};

use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use wharf_api_types::{ApiError, build::SourceTree};

/// 和控制面接收上传的上限一致。
pub const MAX_ARCHIVE: usize = 512 * 1024 * 1024;

pub struct Packed {
  pub bytes: Vec<u8>,
  pub sha256: String,
  pub files: usize,
}

fn io_err(path: &Path, e: impl std::fmt::Display) -> ApiError {
  ApiError::invalid(format!("{}：{e}", path.display()))
}

/// 要打包的文件（相对路径，按路径排序）。
fn list_files(dir: &Path) -> Result<Vec<PathBuf>, ApiError> {
  let walker = ignore::WalkBuilder::new(dir)
    .hidden(false)
    .git_ignore(true)
    .git_exclude(true)
    .git_global(false)
    .require_git(false)
    .add_custom_ignore_filename(".dockerignore")
    .filter_entry(|e| e.file_name() != ".git")
    .build();
  let mut files = Vec::new();
  for entry in walker {
    let entry = entry.map_err(|e| io_err(dir, e))?;
    let is_file_or_link = entry
      .file_type()
      .is_some_and(|t| t.is_file() || t.is_symlink());
    if !is_file_or_link {
      continue;
    }
    let rel = entry
      .path()
      .strip_prefix(dir)
      .map_err(|e| io_err(entry.path(), e))?
      .to_path_buf();
    files.push(rel);
  }
  files.sort();
  Ok(files)
}

pub fn pack(dir: &Path) -> Result<Packed, ApiError> {
  if !dir.is_dir() {
    return Err(ApiError::invalid(format!(
      "{} 不是目录",
      dir.display()
    )));
  }
  let files = list_files(dir)?;
  if files.is_empty() {
    return Err(ApiError::invalid(format!(
      "{} 里没有要部署的文件",
      dir.display()
    )));
  }
  let gz = GzBuilder::new()
    .mtime(0)
    .write(Vec::new(), Compression::default());
  let mut tar = tar::Builder::new(gz);
  for rel in &files {
    let path = dir.join(rel);
    let meta = std::fs::symlink_metadata(&path)
      .map_err(|e| io_err(&path, e))?;
    let mut header = tar::Header::new_gnu();
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    let name = rel.to_string_lossy().replace('\\', "/");
    if meta.file_type().is_symlink() {
      let target =
        std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
      header.set_entry_type(tar::EntryType::Symlink);
      header.set_size(0);
      header.set_mode(0o777);
      tar
        .append_link(&mut header, &name, &target)
        .map_err(|e| io_err(&path, e))?;
      continue;
    }
    header.set_size(meta.len());
    header.set_mode(if executable(&meta) { 0o755 } else { 0o644 });
    let file =
      std::fs::File::open(&path).map_err(|e| io_err(&path, e))?;
    tar
      .append_data(&mut header, &name, file)
      .map_err(|e| io_err(&path, e))?;
    if tar.get_ref().get_ref().len() > MAX_ARCHIVE {
      return Err(too_big());
    }
  }
  let mut gz = tar.into_inner().map_err(|e| io_err(dir, e))?;
  gz.flush().map_err(|e| io_err(dir, e))?;
  let bytes = gz.finish().map_err(|e| io_err(dir, e))?;
  if bytes.len() > MAX_ARCHIVE {
    return Err(too_big());
  }
  let sha256 = hex::encode(Sha256::digest(&bytes));
  Ok(Packed {
    bytes,
    sha256,
    files: files.len(),
  })
}

fn too_big() -> ApiError {
  ApiError::invalid("打包后超过 512 MiB").with_hint(
    "把构建产物、数据文件、依赖目录写进 .gitignore 或 .dockerignore",
  )
}

#[cfg(unix)]
fn executable(meta: &std::fs::Metadata) -> bool {
  use std::os::unix::fs::PermissionsExt;
  meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &std::fs::Metadata) -> bool {
  false
}

/// 部署前在本机预览：用和 agent 一样的逻辑判断语言和启动命令。
pub struct LocalTree(pub PathBuf);

impl SourceTree for LocalTree {
  fn read(&self, path: &str) -> Option<String> {
    let path = self.0.join(path);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
      return None;
    }
    std::fs::read_to_string(path).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(self.0.join(dir)) else {
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

  #[test]
  fn respects_gitignore_and_is_reproducible() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join(".gitignore"), "venv/\n*.log\n").unwrap();
    std::fs::write(d.join("main.py"), "print(1)").unwrap();
    std::fs::write(d.join("x.log"), "noise").unwrap();
    std::fs::create_dir_all(d.join("venv/lib")).unwrap();
    std::fs::write(d.join("venv/lib/big"), "x").unwrap();
    std::fs::create_dir_all(d.join(".git")).unwrap();
    std::fs::write(d.join(".git/HEAD"), "ref").unwrap();
    assert_eq!(
      list_files(d).unwrap(),
      vec![PathBuf::from(".gitignore"), PathBuf::from("main.py")]
    );
    let a = pack(d).unwrap();
    let b = pack(d).unwrap();
    assert_eq!(a.sha256, b.sha256);
    std::fs::write(d.join("main.py"), "print(2)").unwrap();
    assert_ne!(pack(d).unwrap().sha256, a.sha256);
  }
}
