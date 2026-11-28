use std::{
  fs::{self, File, OpenOptions},
  io::{self, Write},
  os::unix::fs::OpenOptionsExt,
  path::{Path, PathBuf},
  time::Duration,
};

use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode, view::CoreBackupExportResult,
};

use crate::{
  client::{CliResult, Client, read_secret},
  commands::out,
};

const TIMEOUT: Duration = Duration::from_secs(30 * 60);

struct Temp(PathBuf);

impl Drop for Temp {
  fn drop(&mut self) {
    let _ = fs::remove_file(&self.0);
  }
}

fn io_error(e: io::Error) -> ApiError {
  ApiError::internal(format!("保存灾备包失败：{e}"))
}

fn check_target(path: &Path, force: bool) -> Result<(), ApiError> {
  match fs::symlink_metadata(path) {
    Ok(m) if m.file_type().is_symlink() => {
      Err(ApiError::invalid("目标路径是符号链接，已拒绝覆盖"))
    }
    Ok(m) if !m.is_file() => {
      Err(ApiError::invalid("目标必须是普通文件"))
    }
    Ok(_) if !force => Err(
      ApiError::new(ErrorCode::Conflict, "输出文件已存在")
        .with_hint("更换输出路径，或添加 --force 覆盖"),
    ),
    Ok(_) => Ok(()),
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(io_error(e)),
  }
}

fn temporary(target: &Path) -> Result<(File, Temp), ApiError> {
  let mut nonce = [0; 12];
  getrandom::fill(&mut nonce)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  let path = target.with_file_name(format!(
    ".wharf-export-{}.tmp",
    hex::encode(nonce)
  ));
  let file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW)
    .open(&path)
    .map_err(io_error)?;
  Ok((file, Temp(path)))
}

fn publish(
  temp: &Temp,
  target: &Path,
  force: bool,
) -> Result<(), ApiError> {
  check_target(target, force)?;
  if force {
    fs::rename(&temp.0, target).map_err(io_error)
  } else {
    publish_new(&temp.0, target).map_err(|e| {
      if e.kind() == io::ErrorKind::AlreadyExists {
        ApiError::new(ErrorCode::Conflict, "输出文件已存在")
      } else {
        io_error(e)
      }
    })
  }
}

fn publish_new(temp: &Path, target: &Path) -> io::Result<()> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    let source =
      std::ffi::CString::new(temp.as_os_str().as_encoded_bytes())?;
    let dest =
      std::ffi::CString::new(target.as_os_str().as_encoded_bytes())?;
    // 两个路径都由存活的 CString 持有，系统调用不会覆写已有目标。
    #[cfg(target_os = "linux")]
    let result = unsafe {
      libc::syscall(
        libc::SYS_renameat2,
        libc::AT_FDCWD,
        source.as_ptr(),
        libc::AT_FDCWD,
        dest.as_ptr(),
        libc::RENAME_NOREPLACE,
      )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
      libc::renamex_np(
        source.as_ptr(),
        dest.as_ptr(),
        libc::RENAME_EXCL,
      )
    };
    if result == 0 {
      return Ok(());
    }
    let error = io::Error::last_os_error();
    let errno = error.raw_os_error();
    if errno != Some(libc::ENOTSUP)
      && !matches!(
        errno,
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
      )
    {
      return Err(error);
    }
  }
  fs::hard_link(temp, target)
}

pub(crate) async fn download(
  c: &Client,
  output: Option<PathBuf>,
  force: bool,
  j: bool,
) -> CliResult<()> {
  let endpoint = "/api/core-backup/export";
  if output.as_deref() == Some(Path::new("-")) {
    if j {
      return Err(
        ApiError::invalid("--json 与 --export -o - 不能同时使用")
          .into(),
      );
    }
    let password = read_secret("控制面登录密码：")?;
    let mut stdout = io::stdout();
    c.post_download(
      endpoint,
      &json!({"password": password}),
      TIMEOUT,
      |chunk| stdout.write_all(chunk),
    )
    .await?;
    return stdout.flush().map_err(|e| io_error(e).into());
  }
  let basename = || {
    format!(
      "wharf-core-{}.wharf-core.enc",
      chrono::Utc::now().format("%Y%m%d-%H%M%S")
    )
  };
  let default_name = output.as_ref().is_none_or(|path| {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
  });
  let mut target = match output {
    Some(path) if default_name => path.join(basename()),
    Some(path) => path,
    None => PathBuf::from(basename()),
  };
  check_target(&target, force)?;
  let password = read_secret("控制面登录密码：")?;
  let (mut file, temp) = temporary(&target)?;
  let meta = c
    .post_download(
      endpoint,
      &json!({"password": password}),
      TIMEOUT,
      |chunk| file.write_all(chunk),
    )
    .await?;
  file.sync_all().map_err(io_error)?;
  drop(file);
  if default_name && let Some(filename) = meta.filename {
    target.set_file_name(filename);
  }
  publish(&temp, &target, force)?;
  let output = target.display().to_string();
  let quoted = format!("'{}'", output.replace('\'', "'\\''"));
  let result = CoreBackupExportResult {
    output,
    size_bytes: meta.size,
    sha256: meta.sha256,
    format: meta.format,
    restore_command: format!("wharf-core restore --file {quoted}"),
  };
  out(j, &result, |r| {
    println!("已导出 {}（{} B）", r.output, r.size_bytes);
    println!("{}", r.restore_command);
    println!(
      "恢复后以 WHARF_SAFE_MODE=1 启动控制面，核对状态后运行 wharf core resume。"
    );
  });
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::{PermissionsExt, symlink};

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn core_export_publishes_with_noreplace_rename() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("export.enc");
    let (_, temp) = temporary(&target).unwrap();
    fs::write(&temp.0, b"encrypted").unwrap();
    fs::write(&target, b"existing").unwrap();
    assert_eq!(
      publish_new(&temp.0, &target).unwrap_err().kind(),
      io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&target).unwrap(), b"existing");
    fs::remove_file(&target).unwrap();
    publish(&temp, &target, false).unwrap();
    assert!(!temp.0.exists());
    assert_eq!(fs::read(&target).unwrap(), b"encrypted");
  }

  #[test]
  fn core_export_cli_writes_0600_and_refuses_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("export.enc");
    let (mut file, temp) = temporary(&target).unwrap();
    file.write_all(b"encrypted bytes").unwrap();
    file.sync_all().unwrap();
    publish(&temp, &target, false).unwrap();
    assert_eq!(
      fs::metadata(&target).unwrap().permissions().mode() & 0o777,
      0o600
    );
    let link = dir.path().join("link.enc");
    symlink(&target, &link).unwrap();
    assert_eq!(
      publish(&temp, &link, true).unwrap_err().code,
      ErrorCode::InvalidInput
    );
    assert_eq!(fs::read(target).unwrap(), b"encrypted bytes");
  }
}
