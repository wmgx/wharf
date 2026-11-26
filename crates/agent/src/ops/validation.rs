//! agent 请求中的名字和宿主机路径校验。

use std::path::Path;

use wharf_api_types::{ApiError, ErrorCode, validate_name};

use crate::{
  dirfd::{DirFd, cstring},
  docker::io_err,
};

/// project 名会拼进路径，必须先校验。网关 project 是 `wharf-gw-<name>`。
pub(super) fn check_project(project: &str) -> Result<(), ApiError> {
  validate_name(
    "project",
    project
      .strip_prefix(wharf_api_types::agent::TASK_DATA_PREFIX)
      .unwrap_or(project),
  )
}

/// 只允许读 Wharf 自己的容器：agent 本身，或者控制面按容器 id 指定的它自己。
pub(super) fn check_own_container(
  container: &str,
) -> Result<(), ApiError> {
  let hex_id = (12..=64).contains(&container.len())
    && container.bytes().all(|b| b.is_ascii_hexdigit());
  if container == "wharf-agent" || hex_id {
    return Ok(());
  }
  Err(ApiError::invalid(format!(
    "只能看 Wharf 自己的容器日志，不能看 {container}"
  )))
}

/// 只允许在 `/srv/` 下建目录，全程使用 `openat(O_DIRECTORY | O_NOFOLLOW)`，防止符号链接逃逸。
pub(super) fn ensure_dir(dir: &str) -> Result<(), ApiError> {
  ensure_dir_under(Path::new("/srv"), "/srv/", dir)
}

pub(crate) fn ensure_dir_under(
  base: &Path,
  prefix: &str,
  dir: &str,
) -> Result<(), ApiError> {
  let path = Path::new(dir);
  let ok = path.is_absolute()
    && dir.starts_with(prefix)
    && path.components().all(|c| {
      matches!(
        c,
        std::path::Component::RootDir
          | std::path::Component::Normal(_)
      )
    });
  if !ok {
    return Err(ApiError::new(
      ErrorCode::InvalidInput,
      format!("数据目录必须在 /srv/ 下：{dir}"),
    ));
  }
  let rel = &dir[prefix.len()..];
  let mut cur =
    DirFd::open_dir(base).map_err(|e| match e.raw_os_error() {
      Some(libc::ELOOP | libc::ENOTDIR) => ApiError::invalid(
        format!("路径 {dir} 经过了符号链接或非目录，已拒绝"),
      ),
      _ => io_err(base)(e),
    })?;
  for seg in rel.split('/').filter(|s| !s.is_empty()) {
    let cname = cstring(seg)?;
    cur = cur.ensure_subdir(&cname, 0o755).map_err(|e| {
      match e.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => ApiError::invalid(
          format!("路径 {dir} 经过了符号链接或非目录，已拒绝"),
        ),
        _ => io_err(path)(e),
      }
    })?;
  }
  Ok(())
}

/// 删除 `/srv/<service>` 前检查顶层项：遇符号链接或非目录直接拒绝，仅删除真实目录。
/// 返回是否实际执行了删除。
pub(crate) fn check_removable_service_dir(
  base: &Path,
  service: &str,
) -> Result<bool, ApiError> {
  check_project(service)?;
  let base_fd = match DirFd::open_dir(base) {
    Ok(fd) => fd,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(false);
    }
    Err(e)
      if matches!(
        e.raw_os_error(),
        Some(libc::ELOOP | libc::ENOTDIR)
      ) =>
    {
      return Err(ApiError::invalid(format!(
        "{} 是符号链接或非目录，已拒绝删除",
        base.display()
      )));
    }
    Err(e) => return Err(io_err(base)(e)),
  };
  let cname = cstring(service)?;
  let dir = base.join(service);
  match base_fd.lstat(&cname) {
    Ok(st) => match st.st_mode & libc::S_IFMT {
      libc::S_IFDIR => Ok(true),
      libc::S_IFLNK => Err(ApiError::invalid(format!(
        "{} 是符号链接，已拒绝删除",
        dir.display()
      ))),
      _ => Err(ApiError::invalid(format!(
        "{} 不是目录，已拒绝删除",
        dir.display()
      ))),
    },
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
    Err(e) => Err(io_err(&dir)(e)),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{fs, os::unix::fs::symlink};

  #[test]
  fn dirs_stay_under_srv() {
    assert!(ensure_dir("/etc/x").is_err());
    assert!(ensure_dir("/srv/../etc").is_err());
    assert!(ensure_dir("srv/a").is_err());
  }

  #[test]
  fn previous_tracks_config_or_image_change() {
    assert!(super::super::has_previous("a", "b", None, None));
    assert!(super::super::has_previous(
      "a",
      "a",
      Some("old"),
      Some("new")
    ));
    assert!(!super::super::has_previous(
      "a",
      "a",
      Some("old"),
      Some("old")
    ));
    assert!(!super::super::has_previous("a", "a", None, None));
  }

  #[test]
  fn srv_dir_ops_reject_symlink_service_root() {
    let tmp = tempfile::tempdir().unwrap();
    let srv = tmp.path().join("srv");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&srv).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep"), "stay").unwrap();
    symlink(&outside, srv.join("app")).unwrap();

    // 1. ensure_dir 拒绝经过软链在 outside 内建目录。
    assert!(
      ensure_dir_under(&srv, "/srv/", "/srv/app/nested").is_err()
    );
    assert!(!outside.join("nested").exists());

    // 2. 备份前 DirFd::open_service_root 拒绝软链服务根目录。
    let err = DirFd::open_service_root(&srv, "app").err().unwrap();
    assert_eq!(err.code, ErrorCode::InvalidInput);

    // 3. 删除数据前置检查拒绝软链服务根目录，outside 完好无损。
    let err = check_removable_service_dir(&srv, "app").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(
      fs::read_to_string(outside.join("keep")).unwrap(),
      "stay"
    );

    // 4. 真实目录各项操作正常通过。
    ensure_dir_under(&srv, "/srv/", "/srv/real/sub").unwrap();
    assert!(srv.join("real/sub").is_dir());
    assert!(DirFd::open_service_root(&srv, "real").is_ok());
    assert!(check_removable_service_dir(&srv, "real").unwrap());
  }
}
