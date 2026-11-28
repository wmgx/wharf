use std::{
  ffi::{CString, OsStr},
  fs::File,
  io::{self, Write},
  os::{
    fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::PermissionsExt},
  },
  path::{Component, Path, PathBuf},
  time::Duration,
};

use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError, ErrorCode,
  backup::{
    BackupExtractResult, EXTRACT_LIMIT, normalize_snapshot_rel,
    validate_snapshot_id,
  },
};

use crate::{
  client::{CliResult, Client},
  commands::out,
};

pub(crate) fn safe_extract_mode(
  snapshot_mode: u32,
  umask: u32,
) -> u32 {
  (snapshot_mode & 0o755) & !umask
}

fn process_umask() -> u32 {
  if let Ok(status) = std::fs::read_to_string("/proc/self/status")
    && let Some(mask) =
      status.lines().find_map(|l| l.strip_prefix("Umask:"))
    && let Ok(mask) = u32::from_str_radix(mask.trim(), 8)
  {
    return mask;
  }
  unsafe {
    let mask = libc::umask(0o077);
    libc::umask(mask);
    #[cfg(target_os = "macos")]
    return u32::from(mask);
    #[cfg(not(target_os = "macos"))]
    mask
  }
}

fn component(name: &OsStr) -> Result<CString, ApiError> {
  CString::new(name.as_bytes())
    .map_err(|_| ApiError::invalid("输出路径无效"))
}

fn path_error() -> ApiError {
  ApiError::invalid("输出路径无效或经过符号链接")
}

fn file_error(e: io::Error) -> ApiError {
  ApiError::internal(format!("提取文件保存失败：{}", e.kind()))
}

fn open_from(
  dir: &File,
  name: &CString,
  flags: libc::c_int,
) -> io::Result<File> {
  let fd = unsafe {
    libc::openat(
      dir.as_raw_fd(),
      name.as_ptr(),
      flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
      0o600,
    )
  };
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}

fn open_dir(path: &Path) -> Result<File, ApiError> {
  let mut dir =
    File::open(if path.is_absolute() { "/" } else { "." })
      .map_err(file_error)?;
  for part in path.components() {
    let name = match part {
      Component::RootDir | Component::CurDir => continue,
      Component::Normal(name) => name,
      Component::ParentDir => OsStr::new(".."),
      _ => return Err(path_error()),
    };
    dir = open_from(
      &dir,
      &component(name)?,
      libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .map_err(|_| path_error())?;
  }
  Ok(dir)
}

fn target_state(
  dir: &File,
  name: &CString,
) -> Result<Option<libc::mode_t>, ApiError> {
  let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
  let code = unsafe {
    libc::fstatat(
      dir.as_raw_fd(),
      name.as_ptr(),
      stat.as_mut_ptr(),
      libc::AT_SYMLINK_NOFOLLOW,
    )
  };
  if code == 0 {
    return Ok(Some(
      unsafe { stat.assume_init() }.st_mode & libc::S_IFMT,
    ));
  }
  let error = io::Error::last_os_error();
  if error.kind() == io::ErrorKind::NotFound {
    Ok(None)
  } else {
    Err(file_error(error))
  }
}

fn check_destination(
  dir: &File,
  name: &CString,
  force: bool,
) -> Result<(), ApiError> {
  match target_state(dir, name)? {
    None => Ok(()),
    Some(libc::S_IFREG) if force => Ok(()),
    Some(libc::S_IFREG) => Err(
      ApiError::new(ErrorCode::Conflict, "目标文件已存在")
        .with_hint("加 --force 覆盖，或用 -o 指定其他路径"),
    ),
    _ => Err(ApiError::invalid(
      "目标路径是符号链接或非普通文件，已拒绝覆盖",
    )),
  }
}

struct OutputFile {
  path: PathBuf,
  dir: File,
  name: CString,
  temp: CString,
  file: File,
}

impl Drop for OutputFile {
  fn drop(&mut self) {
    unsafe {
      libc::unlinkat(self.dir.as_raw_fd(), self.temp.as_ptr(), 0)
    };
  }
}

impl OutputFile {
  fn open(
    path: &Path,
    basename: &str,
    force: bool,
  ) -> Result<Self, ApiError> {
    let mut path = path.to_owned();
    let (dir, name) = if path.file_name().is_none() {
      let dir = open_dir(&path)?;
      path = path.join(basename);
      (dir, component(OsStr::new(basename))?)
    } else {
      let name = component(path.file_name().ok_or_else(path_error)?)?;
      let dir = open_dir(path.parent().ok_or_else(path_error)?)?;
      if target_state(&dir, &name)? == Some(libc::S_IFDIR) {
        path = path.join(basename);
        let dir =
          open_from(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| path_error())?;
        (dir, component(OsStr::new(basename))?)
      } else {
        (dir, name)
      }
    };
    check_destination(&dir, &name, force)?;
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)
      .map_err(|_| ApiError::internal("随机数不可用"))?;
    let temp = component(OsStr::new(&format!(
      ".wharf-extract-{}.tmp",
      hex::encode(bytes)
    )))?;
    let file = open_from(
      &dir,
      &temp,
      libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(file_error)?;
    Ok(Self {
      path,
      dir,
      name,
      temp,
      file,
    })
  }

  fn commit(&self, mode: u32, force: bool) -> Result<(), ApiError> {
    self
      .file
      .set_permissions(std::fs::Permissions::from_mode(mode))
      .map_err(file_error)?;
    self.file.sync_all().map_err(file_error)?;
    check_destination(&self.dir, &self.name, force)?;
    let fd = self.dir.as_raw_fd();
    let result = unsafe {
      if force {
        libc::renameat(fd, self.temp.as_ptr(), fd, self.name.as_ptr())
      } else {
        libc::linkat(
          fd,
          self.temp.as_ptr(),
          fd,
          self.name.as_ptr(),
          0,
        )
      }
    };
    if result != 0 {
      let error = io::Error::last_os_error();
      if error.kind() == io::ErrorKind::AlreadyExists {
        check_destination(&self.dir, &self.name, force)?;
      }
      return Err(file_error(error));
    }
    Ok(())
  }
}

pub(crate) async fn run(
  c: &Client,
  url: &str,
  service: &str,
  path: &str,
  output: Option<&str>,
  force: bool,
  json: bool,
) -> CliResult<()> {
  let path = normalize_snapshot_rel(path)?;
  let basename = path
    .rsplit('/')
    .next()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| ApiError::invalid("请指定快照中的普通文件"))?;
  let raw = output == Some("-");
  if raw && json {
    return Err(
      ApiError::invalid("-o - 不能与 --json 同时使用").into(),
    );
  }
  let mut target = (!raw)
    .then(|| {
      OutputFile::open(
        Path::new(output.unwrap_or(basename)),
        basename,
        force,
      )
    })
    .transpose()?;
  let mut response =
    c.download_response(url, Duration::from_secs(600)).await?;
  let header = |name| {
    response
      .headers()
      .get(name)
      .and_then(|v| v.to_str().ok())
      .ok_or_else(|| ApiError::internal("提取响应缺少校验信息"))
  };
  let size = response
    .content_length()
    .filter(|n| *n <= EXTRACT_LIMIT)
    .ok_or_else(|| ApiError::internal("提取响应的大小无效"))?;
  let snap_mode =
    u32::from_str_radix(header("x-wharf-file-mode")?, 8)
      .ok()
      .filter(|m| *m <= 0o777)
      .ok_or_else(|| ApiError::internal("提取响应的权限无效"))?;
  let snapshot = header("x-wharf-snapshot")?.to_owned();
  validate_snapshot_id(&snapshot)?;
  let expected = header("x-wharf-file-sha256")?.to_owned();
  if expected.len() != 64
    || !expected.bytes().all(|b| b.is_ascii_hexdigit())
  {
    return Err(ApiError::internal("提取响应的 SHA-256 无效").into());
  }
  let mut hash = Sha256::new();
  let mut received = 0;
  let mut stdout = io::stdout();
  while let Some(bytes) = response
    .chunk()
    .await
    .map_err(|_| ApiError::internal("提取传输中断"))?
  {
    received += bytes.len() as u64;
    if received > size {
      return Err(ApiError::internal("提取文件大小超过预期").into());
    }
    hash.update(&bytes);
    if let Some(target) = &mut target {
      target.file.write_all(&bytes).map_err(file_error)?;
    } else {
      stdout.write_all(&bytes).map_err(file_error)?;
    }
  }
  let sha256 = hex::encode(hash.finalize());
  if received != size || sha256 != expected {
    return Err(
      ApiError::internal("提取文件大小或 SHA-256 校验失败").into(),
    );
  }
  let Some(target) = target else {
    return Ok(stdout.flush().map_err(file_error)?);
  };
  let mode = safe_extract_mode(snap_mode, process_umask());
  target.commit(mode, force)?;
  let value = BackupExtractResult {
    service: service.into(),
    snapshot,
    path: path.into(),
    output: target.path.display().to_string(),
    size,
    mode,
    sha256,
  };
  out(json, &value, |v| {
    println!("已提取到 {}（{} 字节）", v.output, v.size)
  });
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extract_blocks_symlink_escape_and_never_widens_mode() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    let target = dir.path().join("link");
    std::os::unix::fs::symlink(&outside, &target).unwrap();
    let err = OutputFile::open(&target, "link", true).err().unwrap();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(!outside.exists());
    assert_eq!(
      [0o600, 0o4777, 0o400]
        .map(|mode| safe_extract_mode(mode, 0o022)),
      [0o600, 0o755, 0o400]
    );
  }
}
