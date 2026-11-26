//! agent 请求中的名字和宿主机路径校验。

use std::path::Path;

use wharf_api_types::{ApiError, ErrorCode, validate_name};

use crate::docker::io_err;

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
pub(super) fn ensure_dir(dir: &str) -> Result<(), ApiError> {
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
  std::fs::create_dir_all(path).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dirs_stay_under_srv() {
    assert!(ensure_dir("/etc/x").is_err());
    assert!(ensure_dir("/srv/../etc").is_err());
    assert!(ensure_dir("srv/a").is_err());
  }
}
