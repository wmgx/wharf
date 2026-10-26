//! 服务数据目录的文件浏览：只在 `/srv/<service>/` 里，符号链接不跟出去。
//! 大文件由控制面分块调用，每块独立完成，不在 agent 上保持状态。

use std::{
  io::{Read, Seek, SeekFrom, Write},
  os::unix::fs::MetadataExt,
  path::{Component, Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{FILE_CHUNK, FileChunk, FileEntry, FilesOp},
  validate_name,
};

use crate::docker::io_err;

const UPLOAD_SUFFIX: &str = ".wharf-upload";

pub fn handle(op: FilesOp) -> Result<Value, ApiError> {
  match op {
    FilesOp::List { service, path } => {
      to_value(list(&resolve(&service, &path)?)?)
    }
    FilesOp::Read {
      service,
      path,
      offset,
      len,
    } => to_value(read(&resolve(&service, &path)?, offset, len)?),
    FilesOp::Write {
      service,
      path,
      offset,
      data,
      last,
    } => {
      write(&service, &path, offset, &data, last)?;
      Ok(Value::Null)
    }
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

fn root(service: &str) -> Result<PathBuf, ApiError> {
  validate_name("服务", service)?;
  Ok(Path::new("/srv").join(service))
}

/// 相对路径只允许普通的一级级目录名。
fn join(root: &Path, rel: &str) -> Result<PathBuf, ApiError> {
  let rel = Path::new(rel.trim_start_matches('/'));
  if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
    return Err(ApiError::invalid(format!(
      "路径不对：{}",
      rel.display()
    )));
  }
  Ok(root.join(rel))
}

/// 已存在的路径：解开符号链接后仍要在数据目录里。
fn resolve(service: &str, rel: &str) -> Result<PathBuf, ApiError> {
  let root = root(service)?;
  let real_root = root.canonicalize().map_err(|_| {
    ApiError::new(
      ErrorCode::NotFound,
      format!("这台机器上没有 {service} 的数据目录"),
    )
  })?;
  let path = join(&root, rel)?;
  let real = path.canonicalize().map_err(|_| {
    ApiError::new(ErrorCode::NotFound, format!("没有 {rel}"))
  })?;
  inside(&real, &real_root)?;
  Ok(real)
}

fn inside(path: &Path, root: &Path) -> Result<(), ApiError> {
  if path.starts_with(root) {
    Ok(())
  } else {
    Err(ApiError::invalid("不能访问数据目录以外的文件"))
  }
}

fn list(dir: &Path) -> Result<Vec<FileEntry>, ApiError> {
  let mut out = Vec::new();
  for entry in std::fs::read_dir(dir).map_err(io_err(dir))? {
    let entry = entry.map_err(io_err(dir))?;
    let Ok(meta) = entry.path().symlink_metadata() else {
      continue;
    };
    let name = entry.file_name().to_string_lossy().into_owned();
    if name.ends_with(UPLOAD_SUFFIX) {
      continue;
    }
    out.push(FileEntry {
      name,
      dir: meta.is_dir(),
      link: meta.file_type().is_symlink(),
      size: meta.len(),
      modified: meta.mtime() * 1000,
    });
  }
  out.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.cmp(&b.name)));
  Ok(out)
}

fn read(
  path: &Path,
  offset: u64,
  len: u32,
) -> Result<FileChunk, ApiError> {
  let mut f = std::fs::File::open(path).map_err(io_err(path))?;
  let meta = f.metadata().map_err(io_err(path))?;
  if !meta.is_file() {
    return Err(ApiError::invalid("只能读文件"));
  }
  f.seek(SeekFrom::Start(offset)).map_err(io_err(path))?;
  let mut buf = Vec::new();
  f.take(len.min(FILE_CHUNK) as u64)
    .read_to_end(&mut buf)
    .map_err(io_err(path))?;
  Ok(FileChunk {
    data: STANDARD.encode(&buf),
    size: meta.len(),
  })
}

/// 先写 `<文件>.wharf-upload`，最后一块写完再改名，传到一半失败不会弄坏原文件。
fn write(
  service: &str,
  rel: &str,
  offset: u64,
  data: &str,
  last: bool,
) -> Result<(), ApiError> {
  let root = root(service)?;
  let real_root = root.canonicalize().map_err(io_err(&root))?;
  let target = join(&root, rel)?;
  let parent = target
    .parent()
    .ok_or_else(|| ApiError::invalid("路径不对"))?;
  let real_parent = parent.canonicalize().map_err(|_| {
    ApiError::new(ErrorCode::NotFound, "目录不存在".to_string())
  })?;
  inside(&real_parent, &real_root)?;
  let name = target
    .file_name()
    .ok_or_else(|| ApiError::invalid("路径不对"))?;
  let target = real_parent.join(name);
  if target.symlink_metadata().is_ok_and(|m| !m.is_file()) {
    return Err(ApiError::invalid("只能覆盖普通文件"));
  }
  let mut tmp = target.clone().into_os_string();
  tmp.push(UPLOAD_SUFFIX);
  let tmp = PathBuf::from(tmp);
  let bytes = STANDARD
    .decode(data)
    .map_err(|e| ApiError::invalid(format!("数据不对：{e}")))?;
  let mut f = std::fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(offset == 0)
    .open(&tmp)
    .map_err(io_err(&tmp))?;
  f.seek(SeekFrom::Start(offset)).map_err(io_err(&tmp))?;
  f.write_all(&bytes).map_err(io_err(&tmp))?;
  if !last {
    return Ok(());
  }
  f.sync_all().map_err(io_err(&tmp))?;
  // 属主跟原文件走；新文件跟所在目录走，服务以非 root 运行时也能读写。
  let owner = target
    .metadata()
    .or_else(|_| real_parent.metadata())
    .map_err(io_err(&real_parent))?;
  if let Ok(m) = target.metadata() {
    let _ = std::fs::set_permissions(&tmp, m.permissions());
  }
  std::os::unix::fs::chown(
    &tmp,
    Some(owner.uid()),
    Some(owner.gid()),
  )
  .map_err(io_err(&tmp))?;
  std::fs::rename(&tmp, &target).map_err(io_err(&target))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_escapes() {
    let root = Path::new("/srv/app");
    assert!(join(root, "../etc").is_err());
    assert!(join(root, "a/../../etc").is_err());
    assert!(join(root, "./a").is_err());
    assert_eq!(join(root, "/data/x").unwrap(), root.join("data/x"));
    assert!(inside(Path::new("/etc/passwd"), root).is_err());
    assert!(inside(Path::new("/srv/app2/x"), root).is_err());
    assert!(inside(Path::new("/srv/app/x"), root).is_ok());
  }
}
