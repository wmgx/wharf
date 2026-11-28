use std::{
  fs::{self, File},
  io::{self, IsTerminal, Read},
  path::Path,
};

use rusqlite::{Connection, OpenFlags};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  core_export::{
    OPTIONAL, REQUIRED, TempDir, decrypt_to_staging, io_error,
    open_regular,
  },
  db, db_snapshot,
};

const OLD_FILES: [&str; 8] = [
  "wharf.db",
  "wharf.db-wal",
  "wharf.db-shm",
  "wharf.db-journal",
  "core.key",
  "core.key.prev",
  "secrets.key",
  "admin.token",
];

pub fn restore_from_file(
  data_dir: &Path,
  file: &Path,
  yes: bool,
) -> Result<(), ApiError> {
  restore(data_dir, file, yes, || {
    let password = if io::stdin().is_terminal() {
      rpassword::prompt_password(
        "解密密码（导出时的控制面登录密码）：",
      )
      .map_err(io_error)?
    } else {
      let mut line = String::new();
      io::stdin().read_line(&mut line).map_err(io_error)?;
      line.trim_end_matches(['\r', '\n']).to_owned()
    };
    if password.is_empty() {
      return Err(ApiError::invalid("没有读到解密密码"));
    }
    Ok(password)
  })
}

pub(crate) fn restore(
  data_dir: &Path,
  file: &Path,
  yes: bool,
  password: impl FnOnce() -> Result<String, ApiError>,
) -> Result<(), ApiError> {
  fs::create_dir_all(data_dir).map_err(io_error)?;
  let _process = db_snapshot::process_lock(data_dir, true)?;
  let _sqlite = db_snapshot::lock_sqlite(&data_dir.join("wharf.db"))?;
  let mut existing = Vec::new();
  for name in OLD_FILES {
    match fs::symlink_metadata(data_dir.join(name)) {
      Ok(m) if m.is_file() => existing.push(name),
      Ok(_) => {
        return Err(ApiError::invalid(
          "数据目录中的控制面文件必须是普通文件",
        ));
      }
      Err(e) if e.kind() == io::ErrorKind::NotFound => {}
      Err(e) => return Err(io_error(e)),
    }
  }
  if !existing.is_empty() && !yes {
    return Err(
      ApiError::new(
        ErrorCode::ConfirmRequired,
        "恢复会先归档现有控制面文件",
      )
      .with_hint("确认后添加 --yes"),
    );
  }
  let password = password()?;
  let stage = TempDir::new(data_dir, ".wharf-core-restore-")?;
  decrypt_to_staging(file, &password, &stage.0)?;
  let files = validate_staging(&stage.0)?;
  let archive = replace_files(data_dir, &stage.0, &existing, &files)?;
  if let Some(archive) = archive {
    println!("原控制面文件保留在 {}", archive.display());
  }
  println!(
    "已恢复控制面灾备包。请以 WHARF_SAFE_MODE=1 启动，核对状态后执行 wharf core resume。"
  );
  Ok(())
}

pub(crate) fn validate_staging(
  stage: &Path,
) -> Result<Vec<&'static str>, ApiError> {
  let mut files = Vec::new();
  for name in REQUIRED.into_iter().chain(OPTIONAL) {
    match open_regular(&stage.join(name)) {
      Ok(file) => {
        if name == "secrets.key"
          && file.metadata().map_err(io_error)?.len() != 32
        {
          return Err(ApiError::invalid("凭据主密钥格式无效"));
        }
        files.push(name);
      }
      Err(e)
        if e.kind() == io::ErrorKind::NotFound
          && OPTIONAL.contains(&name) => {}
      Err(_) => {
        return Err(ApiError::invalid(format!(
          "灾备包缺少有效的 {name}"
        )));
      }
    }
  }
  for name in files.iter().filter(|name| name.starts_with("core.key"))
  {
    let mut key = String::new();
    let mut file =
      open_regular(&stage.join(name)).map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() > 65 {
      return Err(ApiError::invalid("控制面签名密钥格式无效"));
    }
    file.read_to_string(&mut key).map_err(io_error)?;
    let key = key.trim();
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit())
    {
      return Err(ApiError::invalid("控制面签名密钥格式无效"));
    }
  }
  let c = Connection::open_with_flags(
    stage.join("wharf.db"),
    OpenFlags::SQLITE_OPEN_READ_ONLY,
  )
  .map_err(|_| ApiError::invalid("灾备包数据库无法打开"))?;
  let check: String = c
    .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
    .map_err(|_| ApiError::invalid("数据库完整性校验失败"))?;
  if check != "ok"
    || db_snapshot::schema_version(&c)? > db::SCHEMA_VERSION
  {
    return Err(ApiError::invalid(
      "灾备包数据库损坏或 schema 版本过新",
    ));
  }
  db::verify_snapshot_decryptable(&c, &stage.join("secrets.key"))?;
  Ok(files)
}

fn replace_files(
  data_dir: &Path,
  stage: &Path,
  existing: &[&str],
  files: &[&str],
) -> Result<Option<std::path::PathBuf>, ApiError> {
  let archive = if existing.is_empty() {
    None
  } else {
    Some(TempDir::new(data_dir, ".wharf-before-restore-")?)
  };
  let mut moved = Vec::new();
  let result = (|| {
    if let Some(archive) = &archive {
      for name in existing {
        let source = data_dir.join(name);
        let dest = archive.0.join(name);
        fs::rename(&source, &dest).map_err(io_error)?;
        moved.push((source, dest));
      }
      File::open(&archive.0)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
      File::open(data_dir)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    }
    for name in files {
      let source = stage.join(name);
      let dest = data_dir.join(name);
      fs::rename(&source, &dest).map_err(io_error)?;
      moved.push((source, dest));
    }
    File::open(data_dir)
      .and_then(|f| f.sync_all())
      .map_err(io_error)
  })();
  // 归档一旦装入旧文件就不能由 Drop 清除，包括回滚失败时。
  let archive = archive.map(|mut guard| std::mem::take(&mut guard.0));
  if let Err(error) = result {
    let mut rollback_failed = false;
    for (source, dest) in moved.into_iter().rev() {
      rollback_failed |= fs::rename(dest, source).is_err();
    }
    if rollback_failed {
      return Err(error.with_hint("自动回滚未完成，请检查 .wharf-before-restore-* 归档和数据目录"));
    }
    if let Some(archive) = &archive {
      let _ = fs::remove_dir(archive);
    }
    return Err(error);
  }
  Ok(archive)
}
