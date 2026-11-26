//! 服务数据目录的文件浏览：只在 `/srv/<service>/` 里，基于目录 fd 使用 `openat` 逐级打开（`O_NOFOLLOW`），
//! 根治父目录符号链接 TOCTOU。大文件由控制面分块调用，每块独立完成，不在 agent 上保持状态。

use std::{
  ffi::{CStr, CString},
  io::{ErrorKind, Read, Seek, SeekFrom, Write},
  mem::MaybeUninit,
  os::{
    fd::{AsRawFd, FromRawFd, OwnedFd},
    unix::{ffi::OsStrExt, fs::MetadataExt},
  },
  path::{Component, Path},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{FILE_CHUNK, FileChunk, FileEntry, FilesOp},
  validate_name,
};

const UPLOAD_SUFFIX: &str = ".wharf-upload";

pub fn handle(op: FilesOp) -> Result<Value, ApiError> {
  handle_in(Path::new("/srv"), op)
}

fn handle_in(base: &Path, op: FilesOp) -> Result<Value, ApiError> {
  match op {
    FilesOp::List { service, path } => {
      to_value(list(base, &service, &path)?)
    }
    FilesOp::Read {
      service,
      path,
      offset,
      len,
    } => to_value(read(base, &service, &path, offset, len)?),
    FilesOp::Write {
      service,
      path,
      offset,
      data,
      last,
    } => {
      write(base, &service, &path, offset, &data, last)?;
      Ok(Value::Null)
    }
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

fn cstring(s: &str) -> std::io::Result<CString> {
  CString::new(s).map_err(|_| {
    std::io::Error::new(ErrorKind::InvalidInput, "路径含 NUL")
  })
}

/// 相对路径只允许普通的一级级目录名；剥离前导 `/`，拒绝 `\0`、`.`、`..`。
fn parse_rel(rel: &str) -> Result<Vec<String>, ApiError> {
  if rel.contains('\0') {
    return Err(ApiError::invalid("路径不对"));
  }
  let trimmed = rel.trim_start_matches('/');
  if trimmed.is_empty() {
    return Ok(vec![]);
  }
  if trimmed.split('/').any(|s| s == "." || s == "..") {
    return Err(ApiError::invalid(format!("路径不对：{trimmed}")));
  }
  let mut segs = Vec::new();
  for comp in Path::new(trimmed).components() {
    match comp {
      Component::Normal(os) => {
        let Some(s) = os.to_str() else {
          return Err(ApiError::invalid(format!(
            "路径不对：{trimmed}"
          )));
        };
        if s.is_empty() || s == "." || s == ".." || s.contains('/') {
          return Err(ApiError::invalid(format!(
            "路径不对：{trimmed}"
          )));
        }
        segs.push(s.to_string());
      }
      _ => {
        return Err(ApiError::invalid(format!(
          "路径不对：{trimmed}"
        )));
      }
    }
  }
  Ok(segs)
}

struct DirFd(OwnedFd);

struct DirGuard(*mut libc::DIR);

impl Drop for DirGuard {
  fn drop(&mut self) {
    unsafe {
      libc::closedir(self.0);
    }
  }
}

impl DirFd {
  /// 打开根目录（如 `/srv`），随后以 `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` 打开服务子目录 `<service>`。
  fn open_service_root(
    base: &Path,
    service: &str,
  ) -> Result<Self, ApiError> {
    validate_name("服务", service)?;
    let c_base = CString::new(base.as_os_str().as_bytes())
      .map_err(|_| ApiError::invalid("路径不对"))?;
    let base_raw = unsafe {
      libc::open(
        c_base.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
      )
    };
    if base_raw < 0 {
      let e = std::io::Error::last_os_error();
      return Err(if e.kind() == ErrorKind::NotFound {
        ApiError::new(
          ErrorCode::NotFound,
          format!("这台机器上没有 {service} 的数据目录"),
        )
      } else {
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("打开 {} 失败：{e}", base.display()),
        )
      });
    }
    let base_dir = DirFd(unsafe { OwnedFd::from_raw_fd(base_raw) });
    base_dir.open_subdir(service).map_err(|e| {
      if e.kind() == ErrorKind::NotFound {
        ApiError::new(
          ErrorCode::NotFound,
          format!("这台机器上没有 {service} 的数据目录"),
        )
      } else if matches!(
        e.raw_os_error(),
        Some(libc::ELOOP | libc::ENOTDIR)
      ) {
        ApiError::invalid("不能访问数据目录以外的文件")
      } else {
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("打开 {service} 数据目录失败：{e}"),
        )
      }
    })
  }

  /// 相对当前目录 fd 打开单级子目录：必须含 `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`。
  fn open_subdir(&self, name: &str) -> std::io::Result<Self> {
    let c = cstring(name)?;
    let fd = unsafe {
      libc::openat(
        self.0.as_raw_fd(),
        c.as_ptr(),
        libc::O_RDONLY
          | libc::O_DIRECTORY
          | libc::O_NOFOLLOW
          | libc::O_CLOEXEC,
      )
    };
    if fd < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
  }

  /// 按单级分量列表逐级 `open_subdir` 走到目标目录 fd。
  fn walk_dirs(
    &self,
    segs: &[String],
    not_found_msg: &str,
    symlink_msg: &str,
  ) -> Result<Self, ApiError> {
    let mut cur = self.0.try_clone().map(DirFd).map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("打开目录失败：{e}"),
      )
    })?;
    for seg in segs {
      cur = cur.open_subdir(seg).map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
          ApiError::new(
            ErrorCode::NotFound,
            not_found_msg.to_string(),
          )
        } else if matches!(
          e.raw_os_error(),
          Some(libc::ELOOP | libc::ENOTDIR)
        ) {
          ApiError::invalid(symlink_msg)
        } else {
          ApiError::new(
            ErrorCode::AgentFailed,
            format!("打开目录 {seg} 失败：{e}"),
          )
        }
      })?;
    }
    Ok(cur)
  }

  fn lstat_cstr(&self, name: &CStr) -> std::io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    let rc = unsafe {
      libc::fstatat(
        self.0.as_raw_fd(),
        name.as_ptr(),
        st.as_mut_ptr(),
        libc::AT_SYMLINK_NOFOLLOW,
      )
    };
    if rc < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(unsafe { st.assume_init() })
    }
  }

  fn lstat(&self, name: &str) -> std::io::Result<libc::stat> {
    self.lstat_cstr(&cstring(name)?)
  }

  fn stat_self(&self) -> std::io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    let rc =
      unsafe { libc::fstat(self.0.as_raw_fd(), st.as_mut_ptr()) };
    if rc < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(unsafe { st.assume_init() })
    }
  }

  fn open_file(
    &self,
    name: &str,
    flags: libc::c_int,
    mode: libc::c_uint,
  ) -> std::io::Result<OwnedFd> {
    let c = cstring(name)?;
    let fd = unsafe {
      libc::openat(self.0.as_raw_fd(), c.as_ptr(), flags, mode)
    };
    if fd < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
  }

  fn unlink(&self, name: &str) -> std::io::Result<()> {
    let c = cstring(name)?;
    let rc =
      unsafe { libc::unlinkat(self.0.as_raw_fd(), c.as_ptr(), 0) };
    if rc < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(())
    }
  }

  fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
    let c_from = cstring(from)?;
    let c_to = cstring(to)?;
    let rc = unsafe {
      libc::renameat(
        self.0.as_raw_fd(),
        c_from.as_ptr(),
        self.0.as_raw_fd(),
        c_to.as_ptr(),
      )
    };
    if rc < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(())
    }
  }

  fn read_entries(&self) -> Result<Vec<FileEntry>, ApiError> {
    let dup_fd = unsafe {
      libc::fcntl(self.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
    };
    if dup_fd < 0 {
      let e = std::io::Error::last_os_error();
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("读取目录失败：{e}"),
      ));
    }
    let raw_dir = unsafe { libc::fdopendir(dup_fd) };
    if raw_dir.is_null() {
      let e = std::io::Error::last_os_error();
      unsafe {
        libc::close(dup_fd);
      }
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("读取目录失败：{e}"),
      ));
    }
    let dir = DirGuard(raw_dir);
    let mut out = Vec::new();
    loop {
      let ent = unsafe { libc::readdir(dir.0) };
      if ent.is_null() {
        break;
      }
      let c_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
      let name = c_name.to_string_lossy().into_owned();
      if name == "." || name == ".." || name.ends_with(UPLOAD_SUFFIX)
      {
        continue;
      }
      let Ok(st) = self.lstat_cstr(c_name) else {
        continue;
      };
      let kind = st.st_mode & libc::S_IFMT;
      out.push(FileEntry {
        name,
        dir: kind == libc::S_IFDIR,
        link: kind == libc::S_IFLNK,
        size: st.st_size.max(0) as u64,
        modified: st.st_mtime.saturating_mul(1000),
      });
    }
    out.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.cmp(&b.name)));
    Ok(out)
  }
}

fn list(
  base: &Path,
  service: &str,
  rel: &str,
) -> Result<Vec<FileEntry>, ApiError> {
  let root = DirFd::open_service_root(base, service)?;
  let segs = parse_rel(rel)?;
  let dir = root.walk_dirs(
    &segs,
    &format!("没有 {rel}"),
    "不能访问符号链接或非目录路径",
  )?;
  dir.read_entries()
}

fn read(
  base: &Path,
  service: &str,
  rel: &str,
  offset: u64,
  len: u32,
) -> Result<FileChunk, ApiError> {
  let root = DirFd::open_service_root(base, service)?;
  let segs = parse_rel(rel)?;
  let (file_name, parent_segs) = segs
    .split_last()
    .ok_or_else(|| ApiError::invalid("路径不对"))?;
  let parent = root.walk_dirs(
    parent_segs,
    &format!("没有 {rel}"),
    "不能访问符号链接或非目录路径",
  )?;
  let fd = parent
    .open_file(
      file_name,
      libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK,
      0,
    )
    .map_err(|e| {
      if e.kind() == ErrorKind::NotFound {
        ApiError::new(ErrorCode::NotFound, format!("没有 {rel}"))
      } else if e.raw_os_error() == Some(libc::ELOOP) {
        ApiError::invalid("不能读取符号链接")
      } else {
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("读取 {rel} 失败：{e}"),
        )
      }
    })?;
  let mut f = std::fs::File::from(fd);
  let meta = f.metadata().map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("读取 {rel} 失败：{e}"),
    )
  })?;
  if !meta.is_file() {
    return Err(ApiError::invalid("只能读文件"));
  }
  f.seek(SeekFrom::Start(offset)).map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("读取 {rel} 失败：{e}"),
    )
  })?;
  let mut buf = Vec::new();
  f.take(len.min(FILE_CHUNK) as u64)
    .read_to_end(&mut buf)
    .map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("读取 {rel} 失败：{e}"),
      )
    })?;
  Ok(FileChunk {
    data: STANDARD.encode(&buf),
    size: meta.len(),
  })
}

/// 先写 `<文件>.wharf-upload`，最后一块写完再改名，传到一半失败不会弄坏原文件。
fn write(
  base: &Path,
  service: &str,
  rel: &str,
  offset: u64,
  data: &str,
  last: bool,
) -> Result<(), ApiError> {
  let root = DirFd::open_service_root(base, service)?;
  let segs = parse_rel(rel)?;
  let (file_name, parent_segs) = segs
    .split_last()
    .ok_or_else(|| ApiError::invalid("路径不对"))?;
  if file_name.ends_with(UPLOAD_SUFFIX) {
    return Err(ApiError::invalid("路径不对"));
  }
  let parent = root.walk_dirs(
    parent_segs,
    "目录不存在",
    "不能写入符号链接目录",
  )?;
  match parent.lstat(file_name) {
    Ok(st) if (st.st_mode & libc::S_IFMT) != libc::S_IFREG => {
      return Err(ApiError::invalid("只能覆盖普通文件"));
    }
    Err(e) if e.kind() != ErrorKind::NotFound => {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("检查 {rel} 失败：{e}"),
      ));
    }
    _ => {}
  }
  let bytes = STANDARD
    .decode(data)
    .map_err(|e| ApiError::invalid(format!("数据不对：{e}")))?;
  let tmp_name = format!("{file_name}{UPLOAD_SUFFIX}");
  if offset == 0
    && let Err(e) = parent.unlink(&tmp_name)
    && e.kind() != ErrorKind::NotFound
  {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("清理临时文件失败：{e}"),
    ));
  }
  let mut flags = libc::O_WRONLY
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC
    | libc::O_NONBLOCK;
  if offset == 0 {
    flags |= libc::O_CREAT | libc::O_EXCL;
  }
  let fd =
    parent.open_file(&tmp_name, flags, 0o600).map_err(|e| {
      if e.raw_os_error() == Some(libc::ELOOP) {
        ApiError::invalid("临时文件被替换了，请重新上传")
      } else {
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("打开临时文件失败：{e}"),
        )
      }
    })?;
  let mut f = std::fs::File::from(fd);
  let tmp_meta = f.metadata().map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("读取临时文件属性失败：{e}"),
    )
  })?;
  if !tmp_meta.is_file() || tmp_meta.nlink() != 1 {
    return Err(ApiError::invalid("临时文件被替换了，请重新上传"));
  }
  f.seek(SeekFrom::Start(offset)).map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("写入 {rel} 失败：{e}"),
    )
  })?;
  f.write_all(&bytes).map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("写入 {rel} 失败：{e}"),
    )
  })?;
  if !last {
    return Ok(());
  }
  f.sync_all().map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("落盘 {rel} 失败：{e}"),
    )
  })?;
  let (uid, gid) = match parent.lstat(file_name) {
    Ok(st) => {
      if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        let _ = parent.unlink(&tmp_name);
        return Err(ApiError::invalid("只能覆盖普通文件"));
      }
      let mode = st.st_mode & 0o7777;
      let _ = unsafe { libc::fchmod(f.as_raw_fd(), mode) };
      (st.st_uid, st.st_gid)
    }
    Err(e) if e.kind() == ErrorKind::NotFound => {
      let st = parent.stat_self().map_err(|e| {
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("读取目录属性失败：{e}"),
        )
      })?;
      (st.st_uid, st.st_gid)
    }
    Err(e) => {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("检查 {rel} 失败：{e}"),
      ));
    }
  };
  std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(
    |e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("设置文件属主失败：{e}"),
      )
    },
  )?;
  drop(f);
  parent.rename(&tmp_name, file_name).map_err(|e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("保存 {rel} 失败：{e}"),
    )
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::{PermissionsExt, symlink};

  #[test]
  fn openat_blocks_symlink_escape_for_list_read_write() {
    let dir = tempfile::tempdir().unwrap();
    let srv = dir.path().join("srv");
    let app = srv.join("app");
    let sub = app.join("sub");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let secret = outside.join("secret");
    std::fs::write(&secret, b"top-secret").unwrap();

    // 1. 将 srv/app/sub 换为指向 outside 的符号链接，List/Read/Write 均拒绝。
    std::fs::remove_dir(&sub).unwrap();
    symlink(&outside, &sub).unwrap();
    assert!(
      handle_in(
        &srv,
        FilesOp::List {
          service: "app".into(),
          path: "sub".into(),
        },
      )
      .is_err()
    );
    assert!(
      handle_in(
        &srv,
        FilesOp::Read {
          service: "app".into(),
          path: "sub/secret".into(),
          offset: 0,
          len: 64,
        },
      )
      .is_err()
    );
    assert!(
      handle_in(
        &srv,
        FilesOp::Write {
          service: "app".into(),
          path: "sub/pwn".into(),
          offset: 0,
          data: STANDARD.encode(b"evil"),
          last: true,
        },
      )
      .is_err()
    );
    assert_eq!(std::fs::read(&secret).unwrap(), b"top-secret");
    assert!(!outside.join("pwn").exists());

    // 2. srv/app/link 指向 outside/secret，Read/Write 均拒绝。
    let link = app.join("link");
    symlink(&secret, &link).unwrap();
    assert!(
      handle_in(
        &srv,
        FilesOp::Read {
          service: "app".into(),
          path: "link".into(),
          offset: 0,
          len: 64,
        },
      )
      .is_err()
    );
    assert!(
      handle_in(
        &srv,
        FilesOp::Write {
          service: "app".into(),
          path: "link".into(),
          offset: 0,
          data: STANDARD.encode(b"overwrite"),
          last: true,
        },
      )
      .is_err()
    );
    assert_eq!(std::fs::read(&secret).unwrap(), b"top-secret");

    // 3. 合法子目录读写、列目录标出 link: true、覆盖普通文件保留权限、.. 被拒。
    let real_sub = app.join("data");
    std::fs::create_dir_all(&real_sub).unwrap();
    let cfg = real_sub.join("app.conf");
    std::fs::write(&cfg, b"old").unwrap();
    std::fs::set_permissions(
      &cfg,
      std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();

    handle_in(
      &srv,
      FilesOp::Write {
        service: "app".into(),
        path: "data/app.conf".into(),
        offset: 0,
        data: STANDARD.encode(b"new-value"),
        last: true,
      },
    )
    .unwrap();
    let chunk: FileChunk = serde_json::from_value(
      handle_in(
        &srv,
        FilesOp::Read {
          service: "app".into(),
          path: "data/app.conf".into(),
          offset: 0,
          len: 64,
        },
      )
      .unwrap(),
    )
    .unwrap();
    assert_eq!(STANDARD.decode(&chunk.data).unwrap(), b"new-value");
    assert_eq!(
      std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777,
      0o640
    );

    let entries: Vec<FileEntry> = serde_json::from_value(
      handle_in(
        &srv,
        FilesOp::List {
          service: "app".into(),
          path: "/".into(),
        },
      )
      .unwrap(),
    )
    .unwrap();
    assert!(entries.iter().any(|e| e.name == "link" && e.link));
    assert!(entries.iter().any(|e| e.name == "data" && e.dir));

    assert!(parse_rel("../etc").is_err());
    assert!(parse_rel("a/../../etc").is_err());
    assert!(parse_rel("./a").is_err());
    assert_eq!(parse_rel("/data/x").unwrap(), vec!["data", "x"]);
  }
}
