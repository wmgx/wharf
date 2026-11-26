//! 服务数据目录的文件浏览和分块读写。每一层目录都通过父目录 fd 打开。

use std::{
  ffi::{CStr, CString},
  fs::File,
  io::{self, Read, Seek, SeekFrom, Write},
  os::fd::AsRawFd,
  path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use wharf_api_types::{
  ApiError,
  agent::{FILE_CHUNK, FileChunk, FilesOp},
};

use crate::{
  dirfd::{DirFd, NOFOLLOW, check, stat},
  docker::io_err,
};

const UPLOAD_SUFFIX: &str = ".wharf-upload";
fn parse_rel(rel: &str) -> Result<Vec<CString>, ApiError> {
  let trimmed = rel.trim_start_matches('/');
  if trimmed.contains('\0') {
    return Err(ApiError::invalid("路径不对"));
  }
  trimmed
    .split('/')
    .filter(|seg| !seg.is_empty())
    .map(|seg| {
      if matches!(seg, "." | "..") {
        return Err(ApiError::invalid(format!(
          "路径不对：{trimmed}"
        )));
      }
      CString::new(seg).map_err(|_| ApiError::invalid("路径不对"))
    })
    .collect()
}

fn walk(
  root: DirFd,
  dirs: &[CString],
  path: &str,
  write: bool,
) -> Result<DirFd, ApiError> {
  root.walk_dirs(dirs).map_err(|e| match e.raw_os_error() {
    Some(libc::ENOENT) if write => ApiError::not_found("目录不存在"),
    Some(libc::ENOENT) => ApiError::not_found(format!("没有 {path}")),
    Some(libc::ELOOP | libc::ENOTDIR) if write => {
      ApiError::invalid("不能写入符号链接目录")
    }
    Some(libc::ELOOP | libc::ENOTDIR) => {
      ApiError::invalid("不能访问符号链接或非目录路径")
    }
    _ => io_err(Path::new(path))(e),
  })
}

pub fn handle(op: FilesOp) -> Result<Value, ApiError> {
  handle_in(Path::new("/srv"), op)
}

fn handle_in(base: &Path, op: FilesOp) -> Result<Value, ApiError> {
  let (service, path) = match &op {
    FilesOp::List { service, path }
    | FilesOp::Read { service, path, .. }
    | FilesOp::Write { service, path, .. } => (service, path),
  };
  let root = DirFd::open_service_root(base, service)?;
  let segs = parse_rel(path)?;
  if matches!(op, FilesOp::List { .. }) {
    return to_value(
      walk(root, &segs, path, false)?
        .read_entries(Path::new(path))?,
    );
  }
  let (name, dirs) = segs
    .split_last()
    .ok_or_else(|| ApiError::invalid("路径不对"))?;
  let parent =
    walk(root, dirs, path, matches!(op, FilesOp::Write { .. }))?;
  match op {
    FilesOp::Read {
      path, offset, len, ..
    } => to_value(read(&parent, name, &path, offset, len)?),
    FilesOp::Write {
      path,
      offset,
      data,
      last,
      ..
    } => {
      write(&parent, name, &path, offset, &data, last)?;
      Ok(Value::Null)
    }
    FilesOp::List { .. } => unreachable!(),
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

fn read(
  parent: &DirFd,
  name: &CStr,
  path: &str,
  offset: u64,
  len: u32,
) -> Result<FileChunk, ApiError> {
  let err = io_err(Path::new(path));
  let fd = parent
    .open_file(name, libc::O_RDONLY | NOFOLLOW, 0)
    .map_err(|e| match e.raw_os_error() {
      Some(libc::ENOENT) => {
        ApiError::not_found(format!("没有 {path}"))
      }
      Some(libc::ELOOP) => ApiError::invalid("不能读取符号链接"),
      _ => err(e),
    })?;
  let mut f = File::from(fd);
  let meta = f.metadata().map_err(&err)?;
  if !meta.is_file() {
    return Err(ApiError::invalid("只能读文件"));
  }
  f.seek(SeekFrom::Start(offset)).map_err(&err)?;
  let mut buf = Vec::new();
  f.take(u64::from(len.min(FILE_CHUNK)))
    .read_to_end(&mut buf)
    .map_err(err)?;
  Ok(FileChunk {
    data: STANDARD.encode(&buf),
    size: meta.len(),
  })
}

fn regular_target(
  parent: &DirFd,
  name: &CStr,
  path: &Path,
) -> Result<Option<libc::stat>, ApiError> {
  match parent.lstat(name) {
    Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFREG => {
      Ok(Some(st))
    }
    Ok(_) => Err(ApiError::invalid("只能覆盖普通文件")),
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
    Err(e) => Err(io_err(path)(e)),
  }
}

/// 先写临时文件，最后一块写完再原子改名。
fn write(
  parent: &DirFd,
  name: &CStr,
  path: &str,
  offset: u64,
  data: &str,
  last: bool,
) -> Result<(), ApiError> {
  if name.to_bytes().ends_with(UPLOAD_SUFFIX.as_bytes()) {
    return Err(ApiError::invalid("路径不对"));
  }
  let path = Path::new(path);
  let err = io_err(path);
  regular_target(parent, name, path)?;
  let bytes = STANDARD
    .decode(data)
    .map_err(|e| ApiError::invalid(format!("数据不对：{e}")))?;
  let tmp = CString::new(
    [name.to_bytes(), UPLOAD_SUFFIX.as_bytes()].concat(),
  )
  .map_err(|_| ApiError::invalid("路径不对"))?;
  if offset == 0
    && let Err(e) = parent.unlink(&tmp)
    && e.kind() != io::ErrorKind::NotFound
  {
    return Err(err(e));
  }
  let flags = libc::O_WRONLY
    | NOFOLLOW
    | if offset == 0 {
      libc::O_CREAT | libc::O_EXCL
    } else {
      0
    };
  let fd = parent.open_file(&tmp, flags, 0o600).map_err(&err)?;
  let mut f = File::from(fd);
  let meta = stat(f.as_raw_fd()).map_err(&err)?;
  if meta.st_mode & libc::S_IFMT != libc::S_IFREG
    || meta.st_nlink != 1
  {
    return Err(ApiError::invalid("临时文件被替换了，请重新上传"));
  }
  f.seek(SeekFrom::Start(offset)).map_err(&err)?;
  f.write_all(&bytes).map_err(&err)?;
  if !last {
    return Ok(());
  }
  f.sync_all().map_err(&err)?;
  let previous =
    regular_target(parent, name, path).inspect_err(|_| {
      let _ = parent.unlink(&tmp);
    })?;
  let owner = match &previous {
    Some(st) => (st.st_uid, st.st_gid),
    None => {
      let st = parent.stat_self().map_err(&err)?;
      (st.st_uid, st.st_gid)
    }
  };
  // chown 可能清除 set-ID 位，先改属主再恢复原文件权限。
  std::os::unix::fs::fchown(&f, Some(owner.0), Some(owner.1))
    .map_err(&err)?;
  if let Some(st) = previous {
    check(unsafe {
      libc::fchmod(f.as_raw_fd(), st.st_mode & 0o7777)
    })
    .map_err(&err)?;
  }
  let entry = parent.lstat(&tmp).map_err(&err)?;
  if entry.st_ino != meta.st_ino
    || entry.st_dev != meta.st_dev
    || entry.st_nlink != 1
  {
    return Err(ApiError::invalid("临时文件被替换了，请重新上传"));
  }
  drop(f);
  parent.rename(&tmp, name).map_err(err)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
  };

  #[test]
  fn openat_blocks_symlink_escape_for_list_read_write() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("srv");
    let app = base.join("app");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(app.join("sub")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), "outside").unwrap();
    fs::rename(app.join("sub"), app.join("safe")).unwrap();
    symlink(&outside, app.join("sub")).unwrap();
    symlink(outside.join("secret"), app.join("link")).unwrap();

    let list = |path: &str| {
      handle_in(
        &base,
        FilesOp::List {
          service: "app".into(),
          path: path.into(),
        },
      )
    };
    let read = |path: &str| {
      handle_in(
        &base,
        FilesOp::Read {
          service: "app".into(),
          path: path.into(),
          offset: 0,
          len: FILE_CHUNK,
        },
      )
    };
    let write = |path: &str, offset, data: &[u8], last| {
      handle_in(
        &base,
        FilesOp::Write {
          service: "app".into(),
          path: path.into(),
          offset,
          data: STANDARD.encode(data),
          last,
        },
      )
    };
    assert!(list("sub").is_err());
    for path in ["sub/secret", "link", "safe/../link"] {
      assert!(read(path).is_err());
      assert!(write(path, 0, b"escape", true).is_err());
    }
    assert!(write("sub/new", 0, b"escape", true).is_err());
    assert_eq!(
      fs::read_to_string(outside.join("secret")).unwrap(),
      "outside"
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);

    write("/safe/file", 0, b"first", false).unwrap();
    assert_eq!(list("safe").unwrap(), serde_json::json!([]));
    write("safe/file", 5, b"second", true).unwrap();
    let path = app.join("safe/file");
    assert_eq!(
      read("safe/file").unwrap()["data"],
      STANDARD.encode(b"firstsecond")
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
      .unwrap();
    write("safe/file", 0, b"replacement", true).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
    assert_eq!(
      fs::metadata(path).unwrap().permissions().mode() & 0o777,
      0o640
    );
    let root = list("/").unwrap();
    let entries = root.as_array().unwrap();
    assert_eq!(entries[0]["name"], "safe");
    assert!(
      entries
        .iter()
        .any(|e| e["name"] == "link" && e["link"] == true)
    );
    assert!(list("..").is_err());
  }
}
