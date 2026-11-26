//! restic 备份、列快照、恢复、清理旧快照。restic 跑在临时容器里，agent 镜像里不用装。
//!
//! - 只碰 `/srv/<service>/`，路径由服务名拼出；
//! - 仓库地址和口令走环境变量传给 docker，不出现在命令行里；
//! - 容器有固定名字：杀掉 `docker run` 并不会停掉容器，取消或超时后用名字删掉它。

use std::{
  net::IpAddr,
  path::{Path, PathBuf},
  time::Duration,
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    BACKUP_ROOT, BackupSummary, CORE_BACKUP_DIR, RESTIC_IMAGE,
    ResticAction, ResticJob, ResticRepo, Snapshot,
  },
  validate_name,
};

use crate::{
  dirfd::{DirFd, component, dir_error, validate_tree},
  docker::{Docker, io_err},
  exec::{Ctx, Output},
};

const LONG_TIMEOUT: Duration = Duration::from_secs(6 * 3600);
const SHORT_TIMEOUT: Duration = Duration::from_secs(120);
/// restic 的退出码：仓库不存在。
const NO_REPO: i32 = 10;
/// 恢复时的临时目录和原目录的保留位置，和 `/srv/<service>` 在同一个文件系统上，改名是原子的。
const RESTORE_DIR: &str = "/srv/.wharf-restore";

struct Job<'a> {
  docker: &'a Docker,
  service: &'a str,
  repo: String,
  password: &'a str,
  /// 额外的 `-v`。
  mounts: Vec<String>,
}

impl Job<'_> {
  fn container(&self) -> String {
    format!("wharf-restic-{}", self.service)
  }

  async fn restic(
    &self,
    args: &[&str],
    timeout: Duration,
    stream: bool,
    ctx: &Ctx,
  ) -> Result<Output, ApiError> {
    let name = self.container();
    self.remove_container(&name).await;
    let mut cmd = self
      .docker
      .cmd()
      .args([
        "run",
        "--rm",
        "--label",
        "wharf.temp=1",
        "--name",
        &name,
        "--network",
        "host",
      ])
      .args(["-e", "RESTIC_REPOSITORY", "-e", "RESTIC_PASSWORD"]);
    for m in &self.mounts {
      cmd = cmd.args(["-v", m.as_str()]);
    }
    cmd = cmd
      .arg(RESTIC_IMAGE)
      .args(args.iter().copied())
      .env("RESTIC_REPOSITORY", &self.repo)
      .env("RESTIC_PASSWORD", self.password)
      .timeout(timeout);
    if stream {
      cmd = cmd.stream(false);
    }
    let result = cmd.run(ctx).await;
    if result.is_err() {
      self.remove_container(&name).await;
    }
    result
  }

  async fn remove_container(&self, name: &str) {
    let _ = self
      .docker
      .cmd()
      .args(["rm", "-f", name])
      .timeout(Duration::from_secs(30))
      .run(&Ctx::detached())
      .await;
  }
}

fn data_root(service: &str) -> Result<PathBuf, ApiError> {
  validate_name("service", service)?;
  Ok(Path::new("/srv").join(service))
}

fn rest_url(
  host: &str,
  port: u16,
  user: &str,
  password: &str,
  service: &str,
) -> Result<String, ApiError> {
  let ip: IpAddr = host.parse().map_err(|_| {
    ApiError::invalid(format!("备份服务器地址不是 IP：{host}"))
  })?;
  let host = match ip {
    IpAddr::V6(v6) => format!("[{v6}]"),
    IpAddr::V4(v4) => v4.to_string(),
  };
  Ok(format!(
    "rest:http://{user}:{password}@{host}:{port}/{service}"
  ))
}

pub async fn run(
  docker: &Docker,
  job: &ResticJob,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let root = match &job.core_marker {
    Some(marker) => core_root(docker, marker, ctx).await?,
    None => data_root(&job.service)?,
  };
  let (repo, mut mounts) = match &job.repo {
    ResticRepo::Rest {
      host,
      port,
      user,
      password,
    } => (
      rest_url(host, *port, user, &password.0, &job.service)?,
      vec![],
    ),
    ResticRepo::Local => {
      let dir = Path::new(BACKUP_ROOT).join(&job.service);
      match DirFd::open_service_root(
        Path::new(BACKUP_ROOT),
        &job.service,
      ) {
        Ok(_) => {}
        Err(e) if e.code == ErrorCode::NotFound => {
          ctx.say("这台机器上还没有这个服务的备份");
          return match job.action {
            ResticAction::Snapshots => {
              to_value(Vec::<Snapshot>::new())
            }
            _ => Ok(Value::Null),
          };
        }
        Err(e) => return Err(e),
      }
      (
        "/repo".to_string(),
        vec![format!("{}:/repo", dir.display())],
      )
    }
  };
  if !docker.image_exists(RESTIC_IMAGE, ctx).await {
    docker
      .pull(RESTIC_IMAGE, &job.pull, ctx, &mut vec![])
      .await?;
  }
  match &job.action {
    ResticAction::Backup { host } => {
      // 控制面的目录不在 agent 容器里，上面已经在宿主机上确认过了。
      if job.core_marker.is_none() {
        DirFd::open_service_root(Path::new("/srv"), &job.service)
          .map_err(|e| {
            if e.code == ErrorCode::NotFound {
              ApiError::invalid(format!(
                "{} 不存在，没有数据可以备份",
                root.display()
              ))
            } else {
              e
            }
          })?;
      }
      mounts.push(format!(
        "{}:{}:ro",
        root.display(),
        root.display()
      ));
      let j = Job {
        docker,
        service: &job.service,
        repo,
        password: &job.password.0,
        mounts,
      };
      ensure_repo(&j, ctx).await?;
      ctx.say(format!("备份 {}", root.display()));
      let path = root.display().to_string();
      let out = j
        .restic(
          &[
            "backup", &path, "--host", host, "--tag", "wharf",
            "--json",
          ],
          LONG_TIMEOUT,
          false,
          ctx,
        )
        .await?
        .check("restic backup")?;
      let summary = parse_summary(&out.stdout)?;
      ctx.say(format!(
        "快照 {}：{} 个文件，{}，新增 {}",
        &summary.snapshot_id[..8.min(summary.snapshot_id.len())],
        summary.files,
        human(summary.bytes),
        human(summary.added_bytes)
      ));
      to_value(summary)
    }
    ResticAction::Snapshots => {
      let j = Job {
        docker,
        service: &job.service,
        repo,
        password: &job.password.0,
        mounts,
      };
      let out = j
        .restic(&["snapshots", "--json"], SHORT_TIMEOUT, false, ctx)
        .await?;
      if out.code == Some(NO_REPO) {
        return to_value(Vec::<Snapshot>::new());
      }
      let out = out.check("restic snapshots")?;
      let mut list: Vec<Snapshot> = serde_json::from_str(&out.stdout)
        .map_err(|e| {
          ApiError::internal(format!("解析 restic 快照列表失败：{e}"))
        })?;
      list.sort_by_key(|s| std::cmp::Reverse(s.time));
      to_value(list)
    }
    ResticAction::Restore { snapshot } => {
      if job.core_marker.is_some() {
        return Err(ApiError::invalid(
          "控制面备份请在宿主机上手动恢复",
        ));
      }
      restore(docker, job, repo, mounts, &root, snapshot, ctx).await
    }
    ResticAction::AddKey { new_password } => {
      let j = Job {
        docker,
        service: &job.service,
        repo,
        password: &job.password.0,
        mounts,
      };
      add_key(docker, j, &new_password.0, ctx).await
    }
    ResticAction::RemoveKey { id } => {
      if !id.bytes().all(|c| c.is_ascii_hexdigit()) || id.is_empty() {
        return Err(ApiError::invalid(format!(
          "钥匙 id 不合法：{id}"
        )));
      }
      let j = Job {
        docker,
        service: &job.service,
        repo,
        password: &job.password.0,
        mounts,
      };
      ctx.say("删除旧口令");
      j.restic(&["key", "remove", id], SHORT_TIMEOUT, true, ctx)
        .await?
        .check("restic key remove")?;
      Ok(Value::Null)
    }
    ResticAction::Prune => {
      let j = Job {
        docker,
        service: &job.service,
        repo,
        password: &job.password.0,
        mounts,
      };
      ctx.say("清理旧快照：保留最近 7 天、4 周、6 个月各一份");
      j.restic(
        &[
          "forget",
          "--keep-daily",
          "7",
          "--keep-weekly",
          "4",
          "--keep-monthly",
          "6",
          "--prune",
        ],
        LONG_TIMEOUT,
        true,
        ctx,
      )
      .await?
      .check("restic forget")?;
      Ok(Value::Null)
    }
  }
}

/// 控制面自身备份的目录。用标记确认这台就是控制面所在的机器。
/// 目录在宿主机上、不在 agent 容器里，借 agent 自己的镜像（每台都有）去读；
/// `--mount` 遇到不存在的目录会报错，不会像 `-v` 那样在别的机器上建出空目录。
async fn core_root(
  docker: &Docker,
  marker: &str,
  ctx: &Ctx,
) -> Result<PathBuf, ApiError> {
  let image = crate::adopt::self_image(docker, ctx).await?;
  let found = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--label",
      "wharf.temp=1",
      "--network",
      "none",
      "--entrypoint",
      "cat",
      "--mount",
    ])
    .arg(format!("type=bind,src={CORE_BACKUP_DIR},dst=/c,readonly"))
    .args([image.as_str(), "/c/.marker"])
    .timeout(SHORT_TIMEOUT)
    .run(ctx)
    .await
    .ok()
    .filter(|o| o.success)
    .map(|o| o.stdout);
  let root = PathBuf::from(CORE_BACKUP_DIR);
  if found.as_deref().map(str::trim) != Some(marker) {
    return Err(ApiError::new(
      ErrorCode::NotFound,
      "控制面不在这台机器上",
    ));
  }
  Ok(root)
}

/// 新口令写进 agent 数据目录下的临时文件（宿主机路径相同）挂给 restic，用完删掉。
async fn add_key(
  docker: &Docker,
  mut j: Job<'_>,
  new_password: &str,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let before = key_ids(&j, ctx).await?;
  let file = docker
    .data_dir
    .join(format!(".restic-newkey-{}", std::process::id()));
  crate::docker::write_private(&file, new_password)?;
  j.mounts.push(format!("{}:/newkey:ro", file.display()));
  ctx.say("给备份仓库加一把口令");
  let added = j
    .restic(
      &["key", "add", "--new-password-file", "/newkey"],
      SHORT_TIMEOUT,
      false,
      ctx,
    )
    .await
    .and_then(|o| o.check("restic key add"));
  let _ = std::fs::remove_file(&file);
  added?;
  j.mounts.pop();
  let after = key_ids(&j, ctx).await?;
  let new = after
    .into_iter()
    .find(|id| !before.contains(id))
    .ok_or_else(|| ApiError::internal("加了口令但没找到新钥匙"))?;
  to_value(new)
}

async fn key_ids(
  j: &Job<'_>,
  ctx: &Ctx,
) -> Result<Vec<String>, ApiError> {
  #[derive(serde::Deserialize)]
  struct Key {
    id: String,
  }
  let out = j
    .restic(&["key", "list", "--json"], SHORT_TIMEOUT, false, ctx)
    .await?
    .check("restic key list")?;
  let keys: Vec<Key> =
    serde_json::from_str(&out.stdout).map_err(|e| {
      ApiError::internal(format!("解析 restic 钥匙列表失败：{e}"))
    })?;
  Ok(keys.into_iter().map(|k| k.id).collect())
}

async fn ensure_repo(j: &Job<'_>, ctx: &Ctx) -> Result<(), ApiError> {
  let out = j
    .restic(&["cat", "config"], SHORT_TIMEOUT, false, ctx)
    .await?;
  if out.success {
    return Ok(());
  }
  if out.code != Some(NO_REPO) {
    out.check("restic cat config")?;
  }
  ctx.say("初始化备份仓库");
  j.restic(&["init"], SHORT_TIMEOUT, true, ctx)
    .await?
    .check("restic init")?;
  Ok(())
}

/// 快照 id：restic 的十六进制 id（可以是短 id）或 `latest`。
fn check_snapshot(id: &str) -> Result<(), ApiError> {
  let ok = id == "latest"
    || (id.len() >= 8
      && id.len() <= 64
      && id.bytes().all(|c| c.is_ascii_hexdigit()));
  if ok {
    Ok(())
  } else {
    Err(ApiError::invalid(format!("快照 id 不合法：{id}")))
  }
}

async fn restore(
  docker: &Docker,
  job: &ResticJob,
  repo: String,
  mut mounts: Vec<String>,
  root: &Path,
  snapshot: &str,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  check_snapshot(snapshot)?;
  let nonce = crate::build::random_suffix();
  let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
  let work_name = format!("{}-{stamp}-{nonce}", job.service);
  let kept_name = format!("{}-before-{stamp}-{nonce}", job.service);
  let srv = Path::new("/srv");
  let srv_fd = DirFd::open_dir(srv).map_err(|e| dir_error(srv, e))?;
  let restore_dir = Path::new(RESTORE_DIR);
  let restore_fd = srv_fd
    .ensure_subdir(c".wharf-restore", 0o700)
    .map_err(|e| dir_error(restore_dir, e))?;
  let work = restore_dir.join(&work_name);
  let work_name_fd =
    component(work_name.as_ref()).map_err(io_err(&work))?;
  restore_fd
    .mkdir(&work_name_fd, 0o700)
    .map_err(io_err(&work))?;
  let _work = RestoreWork(work.clone());
  mounts.push(format!("{}:/restore", work.display()));
  let j = Job {
    docker,
    service: &job.service,
    repo,
    password: &job.password.0,
    mounts,
  };
  ctx.say(format!("恢复快照 {snapshot}"));
  let include = root.display().to_string();
  j.restic(
    &[
      "restore",
      snapshot,
      "--target",
      "/restore",
      "--include",
      &include,
    ],
    LONG_TIMEOUT,
    true,
    ctx,
  )
  .await?
  .check("restic restore")?;
  if install_restored_tree(
    srv,
    &job.service,
    &work_name,
    &kept_name,
    snapshot,
  )
  .map_err(|e| {
    if e.code == ErrorCode::NotFound {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("快照 {snapshot} 里没有 {}", root.display()),
      )
    } else {
      e
    }
  })? {
    let kept = restore_dir.join(kept_name);
    ctx.say(format!("原来的数据保留在 {}", kept.display()));
    to_value(kept.display().to_string())
  } else {
    Ok(Value::Null)
  }
}

struct RestoreWork(PathBuf);
impl Drop for RestoreWork {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn install_restored_tree(
  srv: &Path,
  service: &str,
  work_name: &str,
  kept_name: &str,
  snapshot: &str,
) -> Result<bool, ApiError> {
  let srv_fd = DirFd::open_dir(srv).map_err(|e| dir_error(srv, e))?;
  let restore = srv.join(".wharf-restore");
  let restore_fd = srv_fd
    .open_subdir(c".wharf-restore")
    .map_err(|e| dir_error(&restore, e))?;
  let work = restore.join(work_name);
  let work_name =
    component(work_name.as_ref()).map_err(io_err(&work))?;
  let work_fd = restore_fd
    .open_subdir(&work_name)
    .map_err(|e| dir_error(&work, e))?;
  let fresh_parent =
    open_restored_dir(&work_fd, c"srv", srv, snapshot)?;
  let root = srv.join(service);
  let service = component(service.as_ref()).map_err(io_err(&root))?;
  let staged = StagedRestore::new(
    &restore_fd,
    &restore,
    &fresh_parent,
    &service,
  )
  .map_err(|e| dir_error(&root, e))?;
  staged.validate(&root, snapshot)?;
  install_checked_tree(
    &staged,
    &srv_fd,
    &restore_fd,
    &service,
    &restore.join(kept_name),
    &root,
  )
}

struct StagedRestore {
  dir: DirFd,
  _cleanup: RestoreWork,
}

const RESTORE_HINT: &str =
  "检查备份服务器是否异常，或换一份更早的快照";

impl StagedRestore {
  fn new(
    restore: &DirFd,
    path: &Path,
    fresh_parent: &DirFd,
    service: &std::ffi::CStr,
  ) -> std::io::Result<Self> {
    // 先把目录项移出 restic 的挂载范围，再扫描最终要落位的目录项。
    let name = format!(".install-{}", crate::build::random_suffix());
    let name_fd = component(name.as_ref())?;
    restore.mkdir(&name_fd, 0o700)?;
    let cleanup = RestoreWork(path.join(name));
    let dir = restore.open_subdir(&name_fd)?;
    fresh_parent.rename_to(service, &dir, c"tree")?;
    Ok(Self {
      dir,
      _cleanup: cleanup,
    })
  }

  fn validate(
    &self,
    root: &Path,
    snapshot: &str,
  ) -> Result<(), ApiError> {
    let fresh =
      open_restored_dir(&self.dir, c"tree", root, snapshot)?;
    validate_tree(&fresh, true).map_err(|e| {
      if e.code == ErrorCode::InvalidInput {
        ApiError::invalid(format!("快照 {snapshot} 包含指向服务目录之外的符号链接（{}），已拒绝恢复", e.message))
          .with_hint(RESTORE_HINT)
      } else { e }
    })
  }
}

fn open_restored_dir(
  parent: &DirFd,
  name: &std::ffi::CStr,
  path: &Path,
  snapshot: &str,
) -> Result<DirFd, ApiError> {
  parent.open_subdir(name).map_err(|e| {
    if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
      let link = parent.readlink(name).ok()
        .map(|target| format!("（{} -> {}）", path.display(), target.display()))
        .unwrap_or_default();
      ApiError::invalid(format!(
        "快照 {snapshot} 中的 {} 是符号链接或非目录，已拒绝恢复{link}", path.display()
      )).with_hint(RESTORE_HINT)
    } else {
      dir_error(path, e)
    }
  })
}

fn install_checked_tree(
  staged: &StagedRestore,
  srv_fd: &DirFd,
  restore_fd: &DirFd,
  service: &std::ffi::CStr,
  kept_path: &Path,
  root: &Path,
) -> Result<bool, ApiError> {
  let kept_name =
    component(kept_path.file_name().expect("保留目录有文件名"))
      .map_err(io_err(kept_path))?;
  let had_old = match srv_fd.lstat(service) {
    Ok(_) => {
      srv_fd
        .rename_to(service, restore_fd, &kept_name)
        .map_err(io_err(root))?;
      true
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
    Err(e) => return Err(io_err(root)(e)),
  };
  if let Err(e) = staged.dir.rename_to(c"tree", srv_fd, service) {
    if had_old {
      restore_fd.rename_to(&kept_name, srv_fd, service).map_err(|rollback| {
        ApiError::internal(format!("恢复落位失败：{e}。无法还原原目录：{rollback}。原数据保留在 {}", kept_path.display()))
      })?;
    }
    return Err(io_err(root)(e));
  }
  Ok(had_old)
}

/// `restic backup --json` 最后一行是汇总。
fn parse_summary(stdout: &str) -> Result<BackupSummary, ApiError> {
  stdout
    .lines()
    .rev()
    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
    .find(|v| v["message_type"] == "summary")
    .map(|v| BackupSummary {
      snapshot_id: v["snapshot_id"]
        .as_str()
        .unwrap_or_default()
        .into(),
      files: v["total_files_processed"].as_u64().unwrap_or(0),
      bytes: v["total_bytes_processed"].as_u64().unwrap_or(0),
      added_bytes: v["data_added"].as_u64().unwrap_or(0),
    })
    .ok_or_else(|| ApiError::internal("restic backup 没有输出汇总"))
}

fn human(bytes: u64) -> String {
  const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
  let mut v = bytes as f64;
  let mut unit = 0;
  while v >= 1024.0 && unit < UNITS.len() - 1 {
    v /= 1024.0;
    unit += 1;
  }
  if unit == 0 {
    format!("{bytes} B")
  } else {
    format!("{v:.1} {}", UNITS[unit])
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn summary_from_last_line() {
    let out = r#"{"message_type":"status","percent_done":0.5}
{"message_type":"summary","snapshot_id":"abcdef0123456789","total_files_processed":3,"total_bytes_processed":2048,"data_added":100}"#;
    let s = parse_summary(out).unwrap();
    assert_eq!(s.snapshot_id, "abcdef0123456789");
    assert_eq!((s.files, s.bytes, s.added_bytes), (3, 2048, 100));
    assert!(parse_summary("").is_err());
  }

  #[test]
  fn snapshot_ids_are_checked() {
    assert!(check_snapshot("latest").is_ok());
    assert!(check_snapshot("4f2a9c1e").is_ok());
    assert!(check_snapshot("--target=/").is_err());
    assert!(check_snapshot("abc").is_err());
  }
}

#[cfg(test)]
mod restore_tests;
