use std::{
  collections::BTreeMap,
  ffi::{CStr, CString},
  fs::File,
  io::{Read, Seek, SeekFrom},
  os::unix::ffi::OsStrExt,
  path::Path,
  sync::{LazyLock, Mutex},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode, agent::FileChunk, data_sync::*,
};

use crate::dirfd::{DirFd, NOFOLLOW, check};

const SRV: &str = "/srv";
static SNAPS: LazyLock<
  Mutex<BTreeMap<String, tempfile::NamedTempFile>>,
> = LazyLock::new(Default::default);

fn io(err: std::io::Error) -> ApiError {
  ApiError::internal(format!("访问服务数据失败：{err}"))
}

fn cancelled(cancel: &CancellationToken) -> Result<(), ApiError> {
  if cancel.is_cancelled() {
    Err(ApiError::new(ErrorCode::Cancelled, "数据操作已取消"))
  } else {
    Ok(())
  }
}

fn parts(path: &str) -> Result<Vec<CString>, ApiError> {
  path_parts(path)?
    .into_iter()
    .map(|part| {
      CString::new(part)
        .map_err(|_| ApiError::invalid("数据路径无效"))
    })
    .collect()
}

pub(crate) fn manifest(
  service: &str,
  req: ManifestRequest,
  cancel: &CancellationToken,
) -> Result<DataManifestResult, ApiError> {
  let mut out = DataManifestResult::default();
  let dir = match DirFd::open_service_root(Path::new(SRV), service) {
    Ok(root) => root.walk_dirs(&parts(&req.subpath)?),
    Err(e) if e.code == ErrorCode::NotFound => return Ok(out),
    Err(e) => return Err(e),
  };
  let dir = match dir {
    Ok(dir) => dir,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(out);
    }
    Err(e)
      if matches!(
        e.raw_os_error(),
        Some(libc::ELOOP | libc::ENOTDIR)
      ) =>
    {
      return Err(ApiError::invalid("不能访问符号链接或非目录路径"));
    }
    Err(e) => return Err(io(e)),
  };
  let mut hash_budget =
    req.hash_max_bytes.unwrap_or(32 << 20).min(64 << 20);
  scan(&dir, "", &req, &mut out, &mut hash_budget, cancel)?;
  Ok(out)
}

fn scan(
  root: &DirFd,
  prefix: &str,
  req: &ManifestRequest,
  out: &mut DataManifestResult,
  hash_budget: &mut u64,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let limit =
    req.max_entries.unwrap_or(MAX_MANIFEST).min(MAX_MANIFEST);
  let (mut names, limited) =
    root.read_names_limited(MAX_MANIFEST).map_err(io)?;
  if limited {
    out.truncated = true;
    return Ok(());
  }
  names.sort_unstable();
  for name in names {
    cancelled(cancel)?;
    if out.entries.len()
      + out.skipped_special.len()
      + out.excluded.len()
      >= limit
    {
      out.truncated = true;
      return Ok(());
    }
    let Ok(segment) = name.to_str() else {
      out
        .skipped_special
        .push(format!("{prefix}[非 UTF-8 文件名]"));
      continue;
    };
    let path = format!("{prefix}{segment}");
    if excluded(&path, &req.excludes) {
      out.excluded.push(path);
      continue;
    }
    if join(&req.subpath, &path).is_err() {
      out.skipped_special.push(path);
      continue;
    }
    let st = match root.lstat(&name) {
      Ok(st) => st,
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
      Err(e) => return Err(io(e)),
    };
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFREG && segment.ends_with("-wal") {
      let db = segment.trim_end_matches("-wal");
      if sqlite_path(db) {
        out.sqlite_wal_files.push(format!("{prefix}{db}"));
      }
    }
    if !matches!(kind, libc::S_IFDIR | libc::S_IFREG) {
      out.skipped_special.push(path);
      continue;
    }
    let dir = kind == libc::S_IFDIR;
    let size = if dir { 0 } else { st.st_size.max(0) as u64 };
    let sha256 = if !dir && size <= (*hash_budget).min(4 << 20) {
      let file = File::from(
        root
          .open_file(&name, libc::O_RDONLY | NOFOLLOW, 0)
          .map_err(io)?,
      );
      if !file.metadata().map_err(io)?.is_file() {
        return Err(ApiError::invalid("数据文件已变化"));
      }
      *hash_budget -= size;
      let (read, hash) = digest(file.take(size + 1), cancel)?;
      (read == size).then_some(hash)
    } else {
      None
    };
    out.total_bytes = out.total_bytes.saturating_add(size);
    out.entries.push(DataFileEntry {
      path: path.clone(),
      dir,
      size,
      mtime_ms: st.st_mtime.saturating_mul(1000),
      mode: st.st_mode & 0o777,
      sha256,
    });
    if dir {
      let child = root.open_subdir(&name).map_err(io)?;
      scan(
        &child,
        &format!("{path}/"),
        req,
        out,
        hash_budget,
        cancel,
      )?;
      if out.truncated {
        return Ok(());
      }
    }
  }
  Ok(())
}

fn digest(
  mut reader: impl Read,
  cancel: &CancellationToken,
) -> Result<(u64, String), ApiError> {
  let mut hash = Sha256::new();
  let mut bytes = vec![0; CHUNK];
  let mut total = 0u64;
  loop {
    cancelled(cancel)?;
    let n = reader.read(&mut bytes).map_err(io)?;
    if n == 0 {
      break;
    }
    hash.update(&bytes[..n]);
    total += n as u64;
  }
  Ok((total, hex::encode(hash.finalize())))
}

pub(crate) fn mkdir(
  base: &Path,
  service: &str,
  path: &str,
) -> Result<(), ApiError> {
  let base_dir = DirFd::open_dir(base).map_err(io)?;
  wharf_api_types::validate_name("服务", service)?;
  let svc = CString::new(service)
    .map_err(|_| ApiError::invalid("服务名无效"))?;
  let mut fd = base_dir.ensure_subdir(&svc, 0o755).map_err(io)?;
  for name in parts(path)? {
    let owner = fd.stat_self().map_err(io)?;
    let created = match fd.mkdir(&name, 0o755) {
      Ok(()) => true,
      Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
        false
      }
      Err(e) => return Err(io(e)),
    };
    fd = fd.open_subdir(&name).map_err(io)?;
    if created {
      check(unsafe {
        libc::chown(
          crate::dirfd::component(fd.fd_path().as_os_str())
            .map_err(io)?
            .as_ptr(),
          owner.st_uid,
          owner.st_gid,
        )
      })
      .map_err(io)?;
    }
  }
  Ok(())
}

pub(crate) fn remove(
  base: &Path,
  service: &str,
  path: &str,
  upload: Option<&str>,
) -> Result<(), ApiError> {
  let parts = parts(path)?;
  let (name, dirs) = parts
    .split_last()
    .ok_or_else(|| ApiError::invalid("不能删除服务数据根目录"))?;
  let parent = DirFd::open_service_root(base, service)?
    .walk_dirs(dirs)
    .map_err(io)?;
  if let Some(upload) = upload {
    let temp = crate::files::upload_name(name, Some(upload))?;
    return match parent.unlink(&temp) {
      Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
        Err(io(e))
      }
      _ => Ok(()),
    };
  }
  let stat = match parent.lstat(name) {
    Ok(stat) => stat,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(());
    }
    Err(e) => return Err(io(e)),
  };
  let kind = stat.st_mode & libc::S_IFMT;
  if !matches!(kind, libc::S_IFREG | libc::S_IFDIR)
    || stat.st_dev != parent.stat_self().map_err(io)?.st_dev
  {
    return Err(ApiError::invalid(
      "不能删除挂载点、符号链接或特殊文件",
    ));
  }
  let flags = if kind == libc::S_IFDIR {
    libc::AT_REMOVEDIR
  } else {
    0
  };
  parent.unlink_with(name, flags).map_err(io)
}

pub(crate) fn sqlite_path(path: &str) -> bool {
  Path::new(path)
    .extension()
    .and_then(|s| s.to_str())
    .is_some_and(|s| matches!(s, "db" | "sqlite" | "sqlite3"))
}

pub(crate) async fn sqlite_snap(
  service: String,
  path: String,
  cancel: CancellationToken,
) -> Result<SqliteSnapHandle, ApiError> {
  let work_cancel = cancel.clone();
  let (handle, temp) = tokio::task::spawn_blocking(move || {
    snapshot(Path::new(SRV), &service, &path, &work_cancel)
  })
  .await
  .map_err(|_| ApiError::internal("数据库快照任务失败"))??;
  cancelled(&cancel)?;
  let id = handle.snap_id.clone();
  SNAPS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(id.clone(), temp);
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(600)).await;
    sqlite_close(&id);
  });
  Ok(handle)
}

fn snapshot(
  srv: &Path,
  service: &str,
  path: &str,
  cancel: &CancellationToken,
) -> Result<(SqliteSnapHandle, tempfile::NamedTempFile), ApiError> {
  use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
  };
  if !sqlite_path(path) {
    return Err(ApiError::invalid(
      "SQLite 快照需要 .db、.sqlite 或 .sqlite3 文件",
    ));
  }
  let parts = parts(path)?;
  let (name, dirs) = parts
    .split_last()
    .ok_or_else(|| ApiError::invalid("需要数据库路径"))?;
  let dir = DirFd::open_service_root(srv, service)?
    .walk_dirs(dirs)
    .map_err(io)?;
  let safe = |name: &CStr| -> Result<bool, ApiError> {
    match dir.lstat(name) {
      Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFREG => {
        Ok(true)
      }
      Ok(_) => {
        Err(ApiError::invalid("SQLite 文件或日志不是普通文件"))
      }
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
      Err(e) => Err(io(e)),
    }
  };
  if !safe(name)? {
    return Err(ApiError::not_found("SQLite 数据库不存在"));
  }
  for suffix in ["-wal", "-shm", "-journal"] {
    safe(
      &CString::new([name.to_bytes(), suffix.as_bytes()].concat())
        .map_err(|_| ApiError::invalid("数据库路径无效"))?,
    )?;
  }
  let err = |_| ApiError::invalid("无法在线读取 SQLite 数据库");
  let path = dir
    .fd_path()
    .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
  let source = Connection::open_with_flags_and_vfs(
    path,
    OpenFlags::SQLITE_OPEN_READ_ONLY
      | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    anchored_sqlite_vfs()?,
  )
  .map_err(err)?;
  let temp = tempfile::Builder::new()
    .prefix("wharf-sqlsnap-")
    .suffix(".db")
    .tempfile()
    .map_err(io)?;
  let mut dest = Connection::open(temp.path()).map_err(err)?;
  {
    let job = Backup::new(&source, &mut dest).map_err(err)?;
    let started = Instant::now();
    loop {
      cancelled(cancel)?;
      if started.elapsed() >= Duration::from_secs(90)
        || temp.as_file().metadata().map_err(io)?.len()
          > MAX_FILE_BYTES
      {
        return Err(ApiError::invalid(
          "SQLite 快照超时或超过文件上限",
        ));
      }
      match job.step(128).map_err(err)? {
        StepResult::Done => break,
        StepResult::More => {}
        _ => std::thread::sleep(Duration::from_millis(20)),
      }
    }
  }
  drop(dest);
  let (size, sha256) = digest(
    temp.reopen().map_err(io)?.take(MAX_FILE_BYTES + 1),
    cancel,
  )?;
  if size > MAX_FILE_BYTES {
    return Err(ApiError::invalid("SQLite 快照超过文件上限"));
  }
  let snap_id = crate::build::random_suffix();
  Ok((
    SqliteSnapHandle {
      snap_id,
      size,
      sha256,
    },
    temp,
  ))
}

pub(crate) fn sqlite_read(
  id: &str,
  offset: u64,
) -> Result<FileChunk, ApiError> {
  let mut file = SNAPS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .get(id)
    .ok_or_else(|| ApiError::not_found("SQLite 快照已关闭"))?
    .reopen()
    .map_err(io)?;
  let size = file.metadata().map_err(io)?.len();
  file.seek(SeekFrom::Start(offset)).map_err(io)?;
  let mut bytes = Vec::new();
  file
    .take(CHUNK as u64)
    .read_to_end(&mut bytes)
    .map_err(io)?;
  Ok(FileChunk {
    mode: None,
    data: STANDARD.encode(bytes),
    size,
    version: None,
  })
}

pub(crate) fn sqlite_close(id: &str) {
  SNAPS.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
}

fn anchored_sqlite_vfs() -> Result<&'static str, ApiError> {
  use rusqlite::ffi;
  use std::sync::OnceLock;
  static READY: OnceLock<bool> = OnceLock::new();

  // 默认 VFS 的路径规范化会解开 /proc/self/fd，丢失已验证的父目录。
  unsafe extern "C" fn full_path(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const libc::c_char,
    cap: libc::c_int,
    out: *mut libc::c_char,
  ) -> libc::c_int {
    let raw = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    if !raw.starts_with(b"/proc/self/fd/")
      || cap < 1
      || raw.len() > cap as usize
    {
      return ffi::SQLITE_CANTOPEN;
    }
    unsafe {
      std::ptr::copy_nonoverlapping(
        raw.as_ptr().cast(),
        out,
        raw.len(),
      );
    }
    ffi::SQLITE_OK
  }

  if !*READY.get_or_init(|| unsafe {
    let vfs = ffi::sqlite3_vfs_find(c"unix".as_ptr());
    if vfs.is_null() {
      return false;
    }
    let mut vfs = Box::new(*vfs);
    vfs.pNext = std::ptr::null_mut();
    vfs.zName = c"wharf-anchored".as_ptr();
    vfs.xFullPathname = Some(full_path);
    if ffi::sqlite3_vfs_register(&mut *vfs, 0) != ffi::SQLITE_OK {
      return false;
    }
    let _ = Box::leak(vfs);
    true
  }) {
    return Err(ApiError::internal("SQLite 安全路径初始化失败"));
  }
  Ok("wharf-anchored")
}

#[cfg(target_os = "linux")]
#[test]
fn sqlite_safe_reads_uncheckpointed_wal_without_following_links() {
  let dir = tempfile::tempdir().unwrap();
  let svc = dir.path().join("app");
  std::fs::create_dir(&svc).unwrap();
  let path = svc.join("live.db");
  let live = rusqlite::Connection::open(&path).unwrap();
  live.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE events(v); INSERT INTO events VALUES (42);").unwrap();
  let cancel = CancellationToken::new();
  let (_, copy) =
    snapshot(dir.path(), "app", "live.db", &cancel).unwrap();
  let copied = rusqlite::Connection::open(copy.path()).unwrap();
  assert_eq!(
    copied
      .query_row("SELECT v FROM events", [], |r| r.get::<_, i64>(0))
      .unwrap(),
    42
  );
  std::os::unix::fs::symlink(path, svc.join("link.db")).unwrap();
  assert!(snapshot(dir.path(), "app", "link.db", &cancel).is_err());
}
