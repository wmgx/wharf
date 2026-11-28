use std::{io, path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode, agent::ServiceCopy, validate_name,
};

use crate::{
  dirfd::{DirFd, component, dir_error},
  docker::{Docker, io_err, write_private},
  exec::{Cmd, Ctx},
};

pub(super) const ROOT: &str = "/srv/.wharf-copy";
const SRV: &str = "/srv";

#[derive(Serialize, Deserialize)]
struct Receipt {
  target: String,
  device: libc::dev_t,
  inode: libc::ino_t,
}

impl Receipt {
  fn matches(&self, stat: &libc::stat) -> bool {
    self.device == stat.st_dev && self.inode == stat.st_ino
  }
}

fn occupied() -> ApiError {
  ApiError::new(ErrorCode::Conflict, "克隆目标已存在")
    .with_hint("换一个名称")
}

fn missing(error: &io::Error) -> bool {
  error.kind() == io::ErrorKind::NotFound
}

async fn check_project(
  docker: &Docker,
  target: &str,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let dir = docker.project_dir(target);
  match std::fs::symlink_metadata(&dir) {
    Ok(_) => return Err(occupied()),
    Err(e) if missing(&e) => {}
    Err(e) => return Err(io_err(&dir)(e)),
  }
  let status = docker.status(&[target.into()], false, ctx).await?;
  if status
    .iter()
    .any(|p| p.hash.is_some() || !p.containers.is_empty())
  {
    return Err(occupied());
  }
  Ok(())
}

fn read_receipt(path: &Path) -> Result<Option<Receipt>, ApiError> {
  match std::fs::read(path) {
    Ok(raw) => serde_json::from_slice(&raw)
      .map(Some)
      .map_err(|_| ApiError::internal("无法核实复制暂存凭据")),
    Err(e) if missing(&e) => Ok(None),
    Err(e) => Err(io_err(path)(e)),
  }
}

pub(crate) async fn run(
  docker: &Docker,
  job: ServiceCopy,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let (target, id) = match &job {
    ServiceCopy::CheckBackup { service } => {
      return check_backup(service);
    }
    ServiceCopy::Archive { service, receipt } => {
      return archive(docker, service, receipt, ctx).await;
    }
    ServiceCopy::Check { target } => (target, None),
    ServiceCopy::Stage { target, receipt }
    | ServiceCopy::Local {
      target, receipt, ..
    }
    | ServiceCopy::Commit { target, receipt } => {
      (target, Some(receipt))
    }
  };
  validate_name("服务", target)?;
  check_project(docker, target, ctx).await?;
  let srv = DirFd::open_dir(Path::new(SRV))
    .map_err(|e| dir_error(Path::new(SRV), e))?;
  let name =
    component(target.as_ref()).map_err(io_err(Path::new(SRV)))?;
  let target_stat = match srv.lstat(&name) {
    Ok(stat) => Some(stat),
    Err(e) if missing(&e) => None,
    Err(e) => return Err(io_err(Path::new(SRV))(e)),
  };
  let Some(id) = id else {
    return if target_stat.is_none() {
      Ok(json!({"committed": false}))
    } else {
      Err(occupied())
    };
  };
  validate_name("复制暂存", id)?;
  let stage =
    component(id.as_ref()).map_err(io_err(Path::new(ROOT)))?;
  let stage_root = srv
    .ensure_subdir(c".wharf-copy", 0o700)
    .map_err(io_err(Path::new(ROOT)))?;
  let stat =
    stage_root.stat_self().map_err(io_err(Path::new(ROOT)))?;
  if stat.st_uid != 0 || stat.st_mode & 0o077 != 0 {
    return Err(ApiError::invalid("复制暂存目录权限不安全"));
  }
  let meta_path = stage_root.fd_path().join(format!(".{id}.receipt"));
  let mut receipt = read_receipt(&meta_path)?;
  if let Some(stat) = target_stat {
    if receipt
      .as_ref()
      .is_some_and(|r| r.target == *target && r.matches(&stat))
    {
      return Ok(json!({"committed": true}));
    }
    return Err(occupied());
  }
  if receipt.is_none() && matches!(job, ServiceCopy::Stage { .. }) {
    stage_root
      .mkdir(&stage, 0o700)
      .map_err(io_err(Path::new(ROOT)))?;
    let stat =
      stage_root.lstat(&stage).map_err(io_err(Path::new(ROOT)))?;
    let new = Receipt {
      target: target.clone(),
      device: stat.st_dev,
      inode: stat.st_ino,
    };
    let raw = serde_json::to_string(&new)
      .map_err(|_| ApiError::internal("保存复制暂存凭据失败"))?;
    write_private(&meta_path, &raw)?;
    receipt = Some(new);
  }
  let stat =
    stage_root.lstat(&stage).map_err(io_err(Path::new(ROOT)))?;
  if !receipt
    .as_ref()
    .is_some_and(|r| r.target == *target && r.matches(&stat))
  {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "复制暂存目录归属无法核实",
    ));
  }
  let staged = stage_root
    .open_subdir(&stage)
    .map_err(io_err(Path::new(ROOT)))?;
  match &job {
    ServiceCopy::Local { source, .. } => {
      if source == target {
        return Err(ApiError::invalid("源和目标服务不能相同"));
      }
      let source = DirFd::open_service_root(Path::new(SRV), source)?;
      copy_local(&source, &staged, ctx).await?;
    }
    ServiceCopy::Commit { .. } => {
      crate::dirfd::validate_tree(&staged, true)?;
      if ctx.cancel.is_cancelled() {
        return Err(ApiError::new(
          ErrorCode::Cancelled,
          "复制已取消",
        ));
      }
      stage_root.rename_noreplace(&stage, &srv, &name).map_err(
        |error| {
          if error.kind() == io::ErrorKind::AlreadyExists {
            occupied()
          } else {
            io_err(Path::new(SRV))(error)
          }
        },
      )?;
      return Ok(json!({"committed": true}));
    }
    _ => {}
  }
  Ok(json!({"committed": false}))
}

fn in_child(fd: &DirFd) -> std::path::PathBuf {
  Path::new("/proc")
    .join(std::process::id().to_string())
    .join("fd")
    .join(fd.fd_path().file_name().expect("fd"))
}

fn check_backup(service: &str) -> Result<Value, ApiError> {
  validate_name("服务", service)?;
  let root = Path::new(wharf_api_types::agent::BACKUP_ROOT);
  let ok = json!({"committed": false});
  let dir = match DirFd::open_dir(root) {
    Ok(dir) => dir,
    Err(e) if missing(&e) => return Ok(ok),
    Err(e) => return Err(dir_error(root, e)),
  };
  let key = component(service.as_ref()).map_err(io_err(root))?;
  let occupied = || {
    ApiError::new(
      ErrorCode::Conflict,
      "无法安全改名：存在备份仓库或归档",
    )
    .with_hint("先克隆后手动切换")
  };
  match dir.lstat(&key) {
    Ok(_) => return Err(occupied()),
    Err(e) if missing(&e) => {}
    Err(e) => return Err(io_err(root)(e)),
  }
  match dir.open_subdir(c".wharf-backup-archive") {
    Ok(archive) => {
      if archive.read_names().map_err(io_err(root))?.iter().any(
        |name| {
          name
            .to_string_lossy()
            .starts_with(&format!("{service}-replaced-"))
        },
      ) {
        return Err(occupied());
      }
    }
    Err(e) if missing(&e) => {}
    Err(e) => return Err(io_err(root)(e)),
  }
  Ok(ok)
}

async fn archive(
  docker: &Docker,
  name: &str,
  receipt: &str,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  validate_name("服务", name)?;
  let stamp = receipt
    .strip_prefix("rename-")
    .filter(|stamp| {
      chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S")
        .is_ok()
    })
    .ok_or_else(|| ApiError::invalid("改名归档凭据无效"))?;
  check_project(docker, name, ctx).await?;
  let srv = DirFd::open_dir(Path::new(SRV))
    .map_err(|e| dir_error(Path::new(SRV), e))?;
  let dir = srv
    .ensure_subdir(c".wharf-migrate", 0o700)
    .map_err(io_err(Path::new(SRV)))?;
  let key =
    component(name.as_ref()).map_err(io_err(Path::new(SRV)))?;
  let target = component(std::ffi::OsStr::new(&format!(
    "{name}-before-{stamp}"
  )))
  .map_err(io_err(Path::new(SRV)))?;
  match srv.open_subdir(&key) {
    Ok(root) => {
      crate::dirfd::validate_tree(&root, true)?;
      if ctx.cancel.is_cancelled() {
        return Err(ApiError::new(
          ErrorCode::Cancelled,
          "改名归档已取消",
        ));
      }
      srv
        .rename_noreplace(&key, &dir, &target)
        .map_err(io_err(Path::new(SRV)))?;
    }
    Err(e) if missing(&e) => {
      dir.open_subdir(&target).map_err(io_err(Path::new(SRV)))?;
    }
    Err(e) => return Err(io_err(Path::new(SRV))(e)),
  }
  Ok(json!({"committed": true}))
}

async fn copy_local(
  source: &DirFd,
  staged: &DirFd,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  crate::dirfd::validate_tree(source, true)?;
  Cmd::new("rsync")
    .args([
      "-aH",
      "--numeric-ids",
      "--checksum",
      "--delete",
      "--one-file-system",
    ])
    .arg(format!("{}/", in_child(source).display()))
    .arg(format!("{}/", in_child(staged).display()))
    .stream(true)
    .timeout(Duration::from_secs(4 * 3600))
    .run(ctx)
    .await?
    .check("复制托管数据")?;
  Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn local_copy_preserves_source_and_never_replaces_a_destination()
 {
  if std::env::var_os("GITHUB_ACTIONS").is_none() {
    return;
  }
  let tmp = tempfile::tempdir().unwrap();
  for name in ["a", "staged", "b"] {
    std::fs::create_dir(tmp.path().join(name)).unwrap();
  }
  std::fs::write(tmp.path().join("a/marker"), "data").unwrap();
  std::fs::write(tmp.path().join("b/marker"), "other").unwrap();
  let root = DirFd::open_dir(tmp.path()).unwrap();
  let src = root.open_subdir(c"a").unwrap();
  let staged = root.open_subdir(c"staged").unwrap();
  copy_local(&src, &staged, &Ctx::detached()).await.unwrap();
  assert_eq!(
    std::fs::read_to_string(tmp.path().join("staged/marker"))
      .unwrap(),
    "data"
  );
  assert!(root.rename_noreplace(c"staged", &root, c"b").is_err());
  assert_eq!(
    std::fs::read_to_string(tmp.path().join("b/marker")).unwrap(),
    "other"
  );
  assert_eq!(
    std::fs::read_to_string(tmp.path().join("a/marker")).unwrap(),
    "data"
  );
}
