//! agent 请求中的名字和宿主机路径校验。

use std::path::Path;

use wharf_api_types::{ApiError, ErrorCode, validate_name};

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

/// 只允许在 `/srv/` 下建目录，防止控制面被冒充时随便写。
pub(super) fn data_dir_relative(
  dir: &str,
) -> Result<&Path, ApiError> {
  let path = Path::new(dir);
  let ok = path.is_absolute()
    && path.starts_with("/srv/")
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
  Ok(path.strip_prefix("/srv").expect("已校验前缀"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::dirfd;

  #[tokio::test]
  async fn srv_dir_ops_reject_symlink_service_root() {
    let ctx = crate::exec::Ctx::detached();
    let dir = tempfile::tempdir().unwrap();
    let srv = dir.path().join("srv");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&srv).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("data"), "untouched").unwrap();
    std::os::unix::fs::symlink(&outside, srv.join("s1")).unwrap();
    assert!(
      matches!(dirfd::ensure_beneath(&srv, Path::new("s1/new")), Err(e) if e.code == ErrorCode::InvalidInput)
    );
    assert!(
      matches!(dirfd::DirFd::open_service_root(&srv, "s1"), Err(e) if e.code == ErrorCode::InvalidInput)
    );
    assert_eq!(
      dirfd::remove_service(&srv, "s1", &ctx)
        .await
        .unwrap_err()
        .code,
      ErrorCode::InvalidInput
    );
    assert!(!outside.join("new").exists());
    assert_eq!(
      std::fs::read_to_string(outside.join("data")).unwrap(),
      "untouched"
    );
    assert!(dirfd::ensure_beneath(&srv, Path::new("s2/new")).is_ok());
    assert!(dirfd::DirFd::open_service_root(&srv, "s2").is_ok());
    let cancelled = crate::exec::Ctx::detached();
    cancelled.cancel.cancel();
    assert_eq!(
      dirfd::remove_service(&srv, "s2", &cancelled)
        .await
        .unwrap_err()
        .code,
      ErrorCode::Cancelled,
    );
    assert!(srv.join("s2/new").is_dir());
    assert!(dirfd::remove_service(&srv, "s2", &ctx).await.is_ok());
  }

  #[test]
  fn dirs_stay_under_srv() {
    assert!(data_dir_relative("/etc/x").is_err());
    assert!(data_dir_relative("/srv/../etc").is_err());
    assert!(data_dir_relative("srv/a").is_err());
  }
}
