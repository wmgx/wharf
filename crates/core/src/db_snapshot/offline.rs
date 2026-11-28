use super::*;
use rusqlite::OpenFlags;
use std::os::fd::AsRawFd;

#[derive(clap::Subcommand)]
pub enum OfflineCommand {
  /// 查看本机热快照。
  List {
    #[arg(long)]
    json: bool,
  },
  /// 控制面已停时恢复本机热快照。
  Restore {
    id: String,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_pre_snapshot: bool,
  },
}

pub fn process_lock(
  data_dir: &Path,
  restore: bool,
) -> Result<File, ApiError> {
  let file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .truncate(false)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW)
    .open(data_dir.join(".wharf.db.restore.lock"))
    .map_err(io_error)?;
  if restore {
    file.try_lock()
  } else {
    file.try_lock_shared()
  }
  .map_err(|_| {
    ApiError::new(
      ErrorCode::Busy,
      "控制面正在使用数据库或恢复正在进行",
    )
  })?;
  Ok(file)
}

pub fn offline(
  data_dir: &Path,
  cmd: OfflineCommand,
) -> Result<(), ApiError> {
  match cmd {
    OfflineCommand::List { json } => {
      let _lock = process_lock(data_dir, true)?;
      let _sqlite = lock_sqlite(&data_dir.join("wharf.db"))?;
      let v = view(&directory(data_dir)?)?;
      if json {
        println!(
          "{}",
          serde_json::to_string_pretty(&v)
            .map_err(|_| conflict("无法输出快照清单"))?
        );
      } else {
        for e in v.snapshots {
          println!(
            "{}  {}  {} B  {}",
            e.id, e.trigger, e.size_bytes, e.reason
          );
        }
        println!("{}", v.restore_hint);
      }
      Ok(())
    }
    OfflineCommand::Restore {
      id,
      yes,
      no_pre_snapshot,
    } => {
      if !yes {
        return Err(
          ApiError::new(
            ErrorCode::ConfirmRequired,
            "恢复会覆盖当前数据库，确认后请加 --yes",
          )
          .with_hint(SNAPSHOT_RESTORE_HINT),
        );
      }
      restore(data_dir, &id, no_pre_snapshot).map_err(|error| {
        let hint = error.hint.as_deref().unwrap_or_default();
        let hint = if hint.is_empty() {
          SNAPSHOT_RESTORE_HINT.into()
        } else {
          format!("{hint}\n{SNAPSHOT_RESTORE_HINT}")
        };
        crate::log_redact::redact_error(error.with_hint(hint))
      })?;
      println!("已恢复 {id}。启动控制面后执行 wharf plan 检查漂移。");
      Ok(())
    }
  }
}

fn validate_restore(
  data_dir: &Path,
  dir: &Path,
  id: &str,
) -> Result<(), ApiError> {
  let info = entry(dir, id, false)?;
  let source = dir.join(format!("{id}.db"));
  for suffix in ["-wal", "-shm", "-journal"] {
    if metadata(&dir.join(format!("{id}.db{suffix}")), false)?
      .is_some()
    {
      return Err(conflict("快照带有 SQLite 伴生文件"));
    }
  }
  if !info.sha256.is_empty() && hash(&source)? != info.sha256 {
    return Err(conflict("快照 SHA-256 校验失败"));
  }
  let c = Connection::open_with_flags(
    source,
    OpenFlags::SQLITE_OPEN_READ_ONLY,
  )
  .map_err(|_| conflict("快照不是可读的 SQLite 数据库"))?;
  let check: String = c
    .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
    .map_err(|_| conflict("SQLite 完整性校验失败"))?;
  if check != "ok" {
    return Err(conflict("SQLite 完整性校验失败"));
  }
  if schema_version(&c)? > db::SCHEMA_VERSION {
    return Err(
      conflict("快照 schema 高于当前版本")
        .with_hint("用兼容的较新控制面镜像恢复"),
    );
  }
  if !info.key_fingerprint.is_empty()
    && fingerprint(data_dir)? != info.key_fingerprint
  {
    return Err(
      conflict("快照主密钥不匹配")
        .with_hint("核对数据目录中的 secrets.key"),
    );
  }
  db::verify_snapshot_decryptable(
    &c,
    &data_dir.join(db::CREDENTIALS_KEY_FILE),
  )
}

// SQLite 在 1 GiB 边界的字节范围上做进程间锁，补查未使用恢复锁的旧控制面。
pub(crate) fn lock_sqlite(
  path: &Path,
) -> Result<Option<File>, ApiError> {
  if metadata(path, false)?.is_none() {
    return Ok(None);
  }
  let file = OpenOptions::new()
    .read(true)
    .write(true)
    .custom_flags(libc::O_NOFOLLOW)
    .open(path)
    .map_err(io_error)?;
  let mut lock: libc::flock = unsafe { std::mem::zeroed() };
  lock.l_type = libc::F_WRLCK as _;
  lock.l_whence = libc::SEEK_SET as _;
  lock.l_start = 0x4000_0000;
  lock.l_len = 512;
  // fd 保持打开直到替换完成。
  if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) }
    < 0
  {
    return Err(ApiError::new(
      ErrorCode::Busy,
      "SQLite 数据库仍在使用，请先停止控制面",
    ));
  }
  Ok(Some(file))
}

fn replace_and_archive(
  data_dir: &Path,
  staging: &Path,
  current: &Path,
  files: &[&Path],
) -> Result<(), ApiError> {
  if files.is_empty() {
    return fs::rename(staging, current).map_err(io_error);
  }
  let mut salt = [0; 8];
  getrandom::fill(&mut salt).map_err(|_| conflict("随机数不可用"))?;
  let name =
    format!(".wharf.db.before-restore-{}", hex::encode(salt));
  let archive = data_dir.join(&name);
  fs::DirBuilder::new()
    .mode(0o700)
    .create(&archive)
    .map_err(io_error)?;
  let mut moved = Vec::new();
  let result = (|| {
    for &path in files {
      let backup = archive.join(path.file_name().unwrap());
      fs::rename(path, &backup).map_err(io_error)?;
      moved.push((backup, path));
    }
    sync_dir(&archive)?;
    sync_dir(data_dir)?;
    fs::rename(staging, current).map_err(io_error)
  })();
  if let Err(error) = result {
    for (backup, path) in moved.into_iter().rev() {
      if fs::rename(backup, path).is_err() {
        return Err(error.with_hint(format!(
          "恢复未完成，原库文件可能仍在数据目录的 {name} 中"
        )));
      }
    }
    let _ = fs::remove_dir(archive);
    return Err(error);
  }
  println!("原库文件保留在数据目录的 {name} 中");
  Ok(())
}

pub(super) fn restore(
  data_dir: &Path,
  id: &str,
  no_pre_snapshot: bool,
) -> Result<(), ApiError> {
  validate_id(id)?;
  let _lock = process_lock(data_dir, true)?;
  let dir = directory(data_dir)?;
  validate_restore(data_dir, &dir, id)?;
  let current = data_dir.join("wharf.db");
  let wal = data_dir.join("wharf.db-wal");
  let shm = data_dir.join("wharf.db-shm");
  let journal = data_dir.join("wharf.db-journal");
  let mut files = Vec::new();
  for path in [&current, &wal, &shm, &journal] {
    if metadata(path, false)?.is_some() {
      files.push(path.as_path());
    }
  }
  let mut sqlite_lock = lock_sqlite(&current)?;
  let staging = data_dir.join(".wharf.db.restore.tmp");
  // 独占恢复锁下清理上次中断的暂存文件。
  if metadata(&staging, false)?.is_some() {
    fs::remove_file(&staging).map_err(io_error)?;
  }
  let mut dest = private_file(&staging)?;
  let result = (|| {
    let mut source =
      File::open(dir.join(format!("{id}.db"))).map_err(io_error)?;
    io::copy(&mut source, &mut dest).map_err(io_error)?;
    dest.sync_all().map_err(io_error)?;
    if no_pre_snapshot || !files.contains(&current.as_path()) {
      replace_and_archive(data_dir, &staging, &current, &files)?;
      return sync_dir(data_dir);
    }
    drop(sqlite_lock.take());
    let pre = {
      let c = Connection::open_with_flags(
        &current,
        OpenFlags::SQLITE_OPEN_READ_WRITE,
      )
      .map_err(|_| {
        conflict("无法打开当前库进行恢复前留底").with_hint(
          "当前库损坏时可加 --no-pre-snapshot，原库文件会改名留底",
        )
      })?;
      let started = Instant::now();
      let pre = write_snapshot(
        &c,
        data_dir,
        &dir,
        info(Trigger::PreRestore, "恢复控制面前".into()),
        Some(id),
        move || started.elapsed() >= TIMEOUT,
      )
      .map_err(|error| {
        let hint = error.hint.as_deref().unwrap_or_default();
        let hint = format!("{hint}。无法为当前库留快照时可加 --no-pre-snapshot，原库文件会改名留底");
        error.with_hint(hint)
      })?;
      let (busy, _, _): (i64, i64, i64) = c
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
          Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(|_| {
          conflict("恢复前无法安全落盘当前库的 WAL").with_hint(
            "当前库损坏时可加 --no-pre-snapshot，原库文件会改名留底",
          )
        })?;
      if busy != 0 {
        return Err(ApiError::new(
          ErrorCode::Busy,
          "SQLite 数据库仍在使用，请先停止控制面",
        ));
      }
      pre
    };
    let _sqlite = lock_sqlite(&current)?;
    if metadata(&wal, false)?.is_some_and(|m| m.len() != 0)
      || metadata(&journal, false)?.is_some_and(|m| m.len() != 0)
    {
      return Err(conflict("当前库仍有未确认落盘的 SQLite 日志"));
    }
    for path in [&wal, &shm, &journal] {
      if metadata(path, false)?.is_some() {
        fs::remove_file(path).map_err(io_error)?;
      }
    }
    fs::rename(&staging, &current).map_err(io_error)?;
    sync_dir(data_dir)?;
    prune_after_create(&dir, id);
    println!("恢复前快照 {}", pre.id);
    Ok(())
  })();
  if result.is_err() {
    let _ = fs::remove_file(staging);
  }
  result
}
