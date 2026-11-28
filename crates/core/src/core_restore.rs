use std::{
  fs::{self, File},
  os::unix::fs::{DirBuilderExt, PermissionsExt},
  path::{Path, PathBuf},
  process::Stdio,
  time::Duration,
};

use rusqlite::{Connection, OpenFlags};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{CORE_BACKUP_DIR, CORE_REST_SERVER_PORT},
};

use crate::{backup, db, db_snapshot};

const REQUIRED: [&str; 3] =
  ["wharf.db", "core.key", db::CREDENTIALS_KEY_FILE];
const OPTIONAL: [&str; 2] = ["core.key.prev", "admin.token"];

#[derive(clap::Args)]
pub struct Args {
  #[arg(long)]
  from: String,
  #[arg(
    long,
    required_unless_present = "recovery_key",
    conflicts_with = "recovery_key"
  )]
  user: Option<String>,
  #[arg(long)]
  recovery_key: Option<PathBuf>,
  #[arg(long, default_value = "latest")]
  snapshot: String,
  #[arg(long, default_value = "restic")]
  restic_bin: PathBuf,
  #[arg(long)]
  yes: bool,
}

struct Stage(PathBuf);

impl Drop for Stage {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

fn io_error(error: std::io::Error) -> ApiError {
  ApiError::internal(format!("恢复文件操作失败：{}", error.kind()))
}

fn private_dir(
  parent: &Path,
  prefix: &str,
) -> Result<PathBuf, ApiError> {
  let dir = parent.join(format!("{prefix}{}", backup::random_hex()));
  fs::DirBuilder::new()
    .mode(0o700)
    .create(&dir)
    .map_err(io_error)?;
  Ok(dir)
}

fn repo(from: &str) -> Result<String, ApiError> {
  let invalid =
    || ApiError::invalid("备份地址须为 IP 或主机名，可附端口");
  if let Ok(ip) = from.parse::<std::net::Ipv6Addr>() {
    return Ok(format!(
      "rest:http://[{ip}]:{CORE_REST_SERVER_PORT}/wharf-core"
    ));
  }
  if from.is_empty()
    || from
      .bytes()
      .any(|b| !b.is_ascii_alphanumeric() && !b".-:[]".contains(&b))
  {
    return Err(invalid());
  }
  let url = reqwest::Url::parse(&format!("http://{from}"))
    .map_err(|_| invalid())?;
  let host = url.host_str().ok_or_else(invalid)?;
  let port_part = if from.starts_with('[') {
    from
      .split_once(']')
      .and_then(|(_, suffix)| suffix.strip_prefix(':'))
  } else {
    from.split_once(':').map(|(_, port)| port)
  };
  let port = port_part
    .map(|part| {
      part
        .parse::<u16>()
        .ok()
        .filter(|&n| n != 0)
        .ok_or_else(invalid)
    })
    .transpose()?
    .unwrap_or(CORE_REST_SERVER_PORT);
  Ok(format!("rest:http://{host}:{port}/wharf-core"))
}

fn parse_recovery_env(text: &str) -> Result<[String; 3], ApiError> {
  let mut values = [None, None, None];
  for line in text.lines() {
    let Some((key, value)) = line.trim().split_once('=') else {
      continue;
    };
    let index = match key {
      "RESTIC_PASSWORD" => 0,
      "RESTIC_REST_USERNAME" => 1,
      "RESTIC_REST_PASSWORD" => 2,
      _ => continue,
    };
    if value.is_empty()
      || value.chars().any(char::is_control)
      || values[index].replace(value.to_owned()).is_some()
    {
      return Err(ApiError::invalid("恢复密钥文件字段无效或重复"));
    }
  }
  match values {
    [Some(key), Some(user), Some(password)] => {
      Ok([key, user, password])
    }
    _ => Err(ApiError::invalid("恢复密钥文件缺少必需字段")),
  }
}

fn verify(stage: &Path) -> Result<Vec<String>, ApiError> {
  let mut files = Vec::new();
  for entry in fs::read_dir(stage).map_err(io_error)? {
    let entry = entry.map_err(io_error)?;
    let name = entry.file_name();
    let name = name
      .to_str()
      .ok_or_else(|| ApiError::invalid("恢复文件名无效"))?;
    if !entry.file_type().map_err(io_error)?.is_file()
      || !(REQUIRED.contains(&name)
        || OPTIONAL.contains(&name)
        || name == ".marker")
    {
      return Err(ApiError::invalid(
        "快照中有软链或不允许恢复的文件",
      ));
    }
    if name != ".marker" {
      let file = File::open(entry.path()).map_err(io_error)?;
      file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(io_error)?;
      file.sync_all().map_err(io_error)?;
      files.push(name.to_owned());
    }
  }
  if !REQUIRED.iter().all(|name| files.iter().any(|f| f == name)) {
    return Err(ApiError::invalid("快照缺少数据库或密钥"));
  }
  for name in ["core.key", "core.key.prev"] {
    if !files.iter().any(|f| f == name) {
      continue;
    }
    let key =
      fs::read_to_string(stage.join(name)).map_err(io_error)?;
    if key.trim().len() != 64
      || !key.trim().bytes().all(|b| b.is_ascii_hexdigit())
    {
      return Err(ApiError::invalid("控制面签名密钥格式错误"));
    }
  }
  if fs::metadata(stage.join(db::CREDENTIALS_KEY_FILE))
    .map_err(io_error)?
    .len()
    != 32
  {
    return Err(ApiError::invalid("控制面主密钥格式错误"));
  }
  let c = Connection::open_with_flags(
    stage.join("wharf.db"),
    OpenFlags::SQLITE_OPEN_READ_ONLY,
  )
  .map_err(|_| ApiError::invalid("快照数据库无法读取"))?;
  let bad_db = |_| ApiError::invalid("快照数据库完整性校验失败");
  let check: String = c
    .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
    .map_err(bad_db)?;
  let version: usize = c
    .query_row("PRAGMA user_version", [], |r| r.get(0))
    .map_err(bad_db)?;
  if check != "ok" || version > db::SCHEMA_VERSION {
    return Err(ApiError::invalid("快照数据库损坏或版本过高"));
  }
  db::verify_snapshot_decryptable(
    &c,
    &stage.join(db::CREDENTIALS_KEY_FILE),
  )?;
  Ok(files)
}

fn install(
  data: &Path,
  stage: &Path,
  files: &[String],
  yes: bool,
) -> Result<(), ApiError> {
  let archive = private_dir(data, ".wharf-before-restore-")?;
  let mut archived = Vec::new();
  let mut installed = Vec::new();
  let result = (|| {
    for name in REQUIRED.into_iter().chain(OPTIONAL).chain([
      "wharf.db-wal",
      "wharf.db-shm",
      "wharf.db-journal",
    ]) {
      let current = data.join(name);
      match fs::symlink_metadata(&current) {
        Ok(m) if m.is_file() && yes => {
          fs::rename(&current, archive.join(name))
            .map_err(io_error)?;
          archived.push(name);
        }
        Ok(m) if m.is_file() => return Err(confirm_restore()),
        Ok(_) => {
          return Err(ApiError::invalid(
            "现有控制面文件不是普通文件",
          ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(e)),
      }
    }
    File::open(&archive)
      .and_then(|f| f.sync_all())
      .map_err(io_error)?;
    File::open(data)
      .and_then(|f| f.sync_all())
      .map_err(io_error)?;
    for name in files {
      fs::rename(stage.join(name), data.join(name))
        .map_err(io_error)?;
      installed.push(name);
    }
    File::open(data)
      .and_then(|f| f.sync_all())
      .map_err(io_error)
  })();
  if let Err(error) = result {
    let mut rollback_ok = true;
    for name in installed.into_iter().rev() {
      rollback_ok &=
        fs::rename(data.join(name), stage.join(name)).is_ok();
    }
    for name in archived.into_iter().rev() {
      rollback_ok &=
        fs::rename(archive.join(name), data.join(name)).is_ok();
    }
    if !rollback_ok {
      return Err(error.with_hint(format!(
        "回滚未完成，原文件可能在 {}",
        archive.display()
      )));
    }
    let _ = fs::remove_dir(&archive);
    let _ = File::open(data).and_then(|f| f.sync_all());
    return Err(error);
  }
  if archived.is_empty() {
    let _ = fs::remove_dir(&archive);
  } else {
    println!("原文件已归档到 {}", archive.display());
  }
  Ok(())
}

fn confirm_restore() -> ApiError {
  ApiError::new(
    ErrorCode::ConfirmRequired,
    "恢复会归档并替换当前控制面文件，确认后请加 --yes",
  )
}

pub async fn run(data: &Path, args: &Args) -> Result<(), ApiError> {
  let repo = repo(&args.from)?;
  wharf_api_types::backup::validate_snapshot_id(&args.snapshot)?;
  fs::create_dir_all(data).map_err(io_error)?;
  let _process = db_snapshot::process_lock(data, true)?;
  let current = data.join("wharf.db");
  let _sqlite = db_snapshot::lock_sqlite(&current)?;
  if !args.yes && fs::symlink_metadata(&current).is_ok() {
    return Err(confirm_restore());
  }
  let [key, user, password] = if let Some(path) = &args.recovery_key {
    parse_recovery_env(&fs::read_to_string(path).map_err(io_error)?)?
  } else {
    let user = args.user.clone().ok_or_else(|| {
      ApiError::invalid("请提供 --user 或 --recovery-key")
    })?;
    let password =
      rpassword::prompt_password("登录密码：").map_err(|_| {
        ApiError::invalid("无法读取登录密码")
          .with_hint("使用交互终端或传入 --recovery-key")
      })?;
    [password.clone(), user, password]
  };
  let stage = Stage(private_dir(data, ".wharf-core-restore-")?);
  let mut command = tokio::process::Command::new(&args.restic_bin);
  command
    .args([
      "--no-cache",
      "-r",
      &repo,
      "restore",
      &format!("{}:{CORE_BACKUP_DIR}", args.snapshot),
      "--target",
    ])
    .arg(&stage.0)
    .env("RESTIC_PASSWORD", key)
    .env("RESTIC_REST_USERNAME", user)
    .env("RESTIC_REST_PASSWORD", password)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .kill_on_drop(true);
  let mut child = command.spawn().map_err(io_error)?;
  let result = tokio::select! {
    result = child.wait() => result.map_err(io_error),
    _ = tokio::time::sleep(Duration::from_secs(600)) => Err(ApiError::new(ErrorCode::Timeout, "恢复快照超时")),
    _ = tokio::signal::ctrl_c() => Err(ApiError::new(ErrorCode::Conflict, "恢复已取消")),
  };
  if result.is_err() {
    let _ = child.kill().await;
  }
  let status = result?;
  if !status.success() {
    return Err(
      ApiError::new(ErrorCode::Conflict, "无法读取恢复快照")
        .with_hint("核对备份地址、快照和恢复凭证"),
    );
  }
  let files = verify(&stage.0)?;
  install(data, &stage.0, &files, args.yes)?;
  println!(
    "已恢复控制面快照 {}。接管时用 wharf-core --safe-mode 启动。",
    args.snapshot
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn core_restore_uses_configured_restic_binary() {
    use clap::Parser;

    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("custom-restic");
    let recovery = dir.path().join("recovery");
    fs::write(&binary, "#!/bin/sh\ntouch \"$0.called\"\nexit 1\n")
      .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
      .unwrap();
    fs::write(&recovery, "RESTIC_PASSWORD=fixture\nRESTIC_REST_USERNAME=fixture\nRESTIC_REST_PASSWORD=fixture\n").unwrap();
    let cli = crate::Cli::try_parse_from([
      std::ffi::OsStr::new("wharf-core"),
      "restore".as_ref(),
      "--from".as_ref(),
      "s2".as_ref(),
      "--recovery-key".as_ref(),
      recovery.as_os_str(),
      "--restic-bin".as_ref(),
      binary.as_os_str(),
    ])
    .unwrap();
    let Some(crate::Command::Restore(args)) = cli.command else {
      panic!("需要恢复命令");
    };
    assert_eq!(
      run(dir.path(), &args).await.unwrap_err().code,
      ErrorCode::Conflict
    );
    assert!(dir.path().join("custom-restic.called").exists());
  }

  #[test]
  fn core_restore_rejects_damaged_database_and_symlink() {
    use std::os::unix::fs::symlink;
    let stage = tempfile::tempdir().unwrap();
    let path = stage.path();
    fs::write(path.join("wharf.db"), b"broken").unwrap();
    fs::write(path.join("core.key"), "a".repeat(64)).unwrap();
    fs::write(path.join("secrets.key"), [0; 32]).unwrap();
    assert!(verify(path).unwrap_err().message.contains("数据库"));
    fs::remove_file(path.join("core.key")).unwrap();
    symlink(path.join("secrets.key"), path.join("core.key")).unwrap();
    assert!(verify(path).unwrap_err().message.contains("软链"));
  }
}
