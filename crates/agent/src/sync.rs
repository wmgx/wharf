//! 迁移数据：接收端在内网地址上临时起 rsync daemon，发送端推送。
//!
//! - 只同步 `/srv/<service>/`，路径由服务名拼出，不接受任意路径；
//! - daemon 只接受发送端内网地址的连接，口令一次性、只写在 0600 的文件里；
//! - daemon 跟着请求走：请求被取消（或超时）就杀掉进程、删掉临时配置。

use std::{
  net::{IpAddr, SocketAddr},
  os::unix::fs::DirBuilderExt,
  path::{Path, PathBuf},
  time::Duration,
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    BACKUP_ROOT, CORE_BACKUP_ROOT, SYNC_BACKUP, SYNC_READY, SyncKind,
    SyncPass, SyncPush, SyncServe,
  },
  validate_name,
};

use crate::{
  docker::{io_err, write_private},
  exec::{Cmd, Ctx},
};

mod service_copy;
pub(crate) use service_copy::run as service_copy;

const SERVE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
const PUSH_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const PUSH_ATTEMPTS: u32 = 6;
const RETRY_DELAY: Duration = Duration::from_secs(3);
const MODULE: &str = "wharf";
const USER: &str = "wharf";

fn sync_root(
  kind: SyncKind,
  service: &str,
) -> Result<&'static Path, ApiError> {
  validate_name("service", service)?;
  match kind {
    SyncKind::ServiceData | SyncKind::CloneSource => {
      Ok(Path::new("/srv"))
    }
    SyncKind::CloneData => Ok(Path::new(service_copy::ROOT)),
    SyncKind::BackupRepo => Ok(Path::new(BACKUP_ROOT)),
    SyncKind::CoreBackupRepo if service == "wharf-core" => {
      Ok(Path::new(CORE_BACKUP_ROOT))
    }
    SyncKind::CoreBackupRepo => {
      Err(ApiError::invalid("控制面备份仓库名必须是 wharf-core"))
    }
  }
}

fn parse_ip(what: &str, ip: &str) -> Result<IpAddr, ApiError> {
  ip.parse().map_err(|_| {
    ApiError::new(
      ErrorCode::InvalidInput,
      format!("{what} 不是 IP 地址：{ip}"),
    )
  })
}

/// 临时目录，结束时删除。
struct TempDir(PathBuf);

impl Drop for TempDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn preserve_nonempty_target(
  root: &Path,
  service: &str,
  stamp: &str,
  kind: SyncKind,
) -> Result<Option<PathBuf>, ApiError> {
  let path = root.join(service);
  if std::fs::read_dir(&path)
    .map_err(io_err(&path))?
    .next()
    .transpose()
    .map_err(io_err(&path))?
    .is_none()
  {
    return Ok(None);
  }
  let (dir, tag) = if kind.is_service_data() {
    (".wharf-migrate", "before")
  } else {
    (".wharf-backup-archive", "replaced")
  };
  let archive = root.join(dir);
  match std::fs::DirBuilder::new().mode(0o700).create(&archive) {
    Ok(()) => {}
    Err(e)
      if e.kind() == std::io::ErrorKind::AlreadyExists
        && std::fs::symlink_metadata(&archive)
          .is_ok_and(|m| m.is_dir()) => {}
    Err(e) => return Err(io_err(&archive)(e)),
  }
  let backup = archive.join(format!("{service}-{tag}-{stamp}"));
  if std::fs::symlink_metadata(&backup).is_ok() {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "迁移保留目录已存在，稍后重试",
    ));
  }
  std::fs::rename(&path, &backup).map_err(io_err(&path))?;
  std::fs::create_dir(&path).map_err(io_err(&path))?;
  Ok(Some(backup))
}

pub async fn serve(
  s: &SyncServe,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let base = sync_root(s.kind, &s.service)?;
  let root = base.join(&s.service);
  if s.kind == SyncKind::CloneData {
    if s.preserve_existing {
      return Err(ApiError::invalid("复制只能写到本次暂存目录"));
    }
    crate::dirfd::DirFd::open_service_root(base, &s.service)?;
  } else if !s.kind.is_service_data() {
    let relative = base.strip_prefix("/srv").expect("固定备份根目录");
    crate::dirfd::ensure_beneath(Path::new("/srv"), relative)?;
  }
  let bind = parse_ip("监听地址", &s.bind)?;
  let allow = parse_ip("发送端地址", &s.allow)?;
  if s.kind != SyncKind::CloneData {
    crate::dirfd::ensure_beneath(base, Path::new(&s.service))?;
  }
  if s.require_empty
    && std::fs::read_dir(&root)
      .map_err(io_err(&root))?
      .next()
      .transpose()
      .map_err(io_err(&root))?
      .is_some()
  {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "目标仓库已出现数据，请重新预检并确认归档",
    ));
  }

  if s.preserve_existing
    && let Some(path) = preserve_nonempty_target(
      base,
      &s.service,
      &chrono::Utc::now().format("%Y%m%d-%H%M%S-%f").to_string(),
      s.kind,
    )?
  {
    ctx.say(format!("{SYNC_BACKUP}{}", path.display()));
  }

  // 先占一个空闲端口再交给 rsync。中间有极短的空窗，冲突时 rsync 会直接报错。
  let port = std::net::TcpListener::bind((bind, 0))
    .and_then(|l| l.local_addr())
    .map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!(
          "无法在 {bind} 上监听：{e}（内网地址是不是这台机器的？）"
        ),
      )
    })?
    .port();

  let tmp = TempDir(
    std::env::temp_dir()
      .join(format!("wharf-sync-{}-{port}", s.service)),
  );
  std::fs::create_dir_all(&tmp.0).map_err(io_err(&tmp.0))?;
  let secrets = tmp.0.join("secrets");
  write_private(&secrets, &format!("{USER}:{}\n", s.password.0))?;
  let conf = tmp.0.join("rsyncd.conf");
  write_private(
    &conf,
    &rsyncd_config(&root, &tmp.0.join("rsyncd.log"), &secrets, allow),
  )?;

  let daemon = Cmd::new("rsync")
    .args(["--daemon", "--no-detach"])
    .arg(format!("--address={bind}"))
    .arg(format!("--port={port}"))
    .arg(format!("--config={}", conf.display()))
    .timeout(SERVE_TIMEOUT);
  let daemon_cancel = ctx.cancel.child_token();
  let run_ctx = Ctx {
    cancel: daemon_cancel.clone(),
    progress: ctx.progress.clone(),
  };
  let mut task =
    tokio::spawn(async move { daemon.run(&run_ctx).await });

  // 等端口能连上再报告就绪。
  let addr = SocketAddr::new(bind, port);
  let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
  loop {
    if tokio::time::timeout(
      Duration::from_millis(200),
      tokio::net::TcpStream::connect(addr),
    )
    .await
    .is_ok_and(|result| result.is_ok())
    {
      break;
    }
    if task.is_finished()
      || tokio::time::Instant::now() > deadline
      || ctx.cancel.is_cancelled()
    {
      daemon_cancel.cancel();
      let result =
        match tokio::time::timeout(Duration::from_secs(5), &mut task)
          .await
        {
          Ok(result) => result,
          Err(_) => {
            task.abort();
            task.await
          }
        };
      if ctx.cancel.is_cancelled() {
        return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
      }
      let detail = match result {
        Ok(Ok(out)) => crate::exec::tail_lines(&out.stderr, 5),
        Ok(Err(e)) => e.message,
        Err(_) => "启动超时".into(),
      };
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("rsync 接收端没能启动：{detail}"),
      ));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
  }
  ctx.say(format!("{SYNC_READY}{port}"));

  // 一直运行到被取消。被取消是正常结束。
  match (&mut task).await {
    Ok(Err(e)) if e.code == ErrorCode::Cancelled => Ok(Value::Null),
    Ok(Err(e)) => Err(e),
    Ok(Ok(out)) => Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!(
        "rsync 接收端提前退出：{}",
        crate::exec::tail_lines(&out.stderr, 5)
      ),
    )),
    Err(e) => Err(ApiError::internal(e.to_string())),
  }
}

pub async fn push(
  p: &SyncPush,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  if p.kind == SyncKind::CloneData {
    return Err(ApiError::invalid("复制暂存目录只能作为接收端"));
  }
  let base = sync_root(p.kind, &p.service)?;
  let root = base.join(&p.service);
  let host = parse_ip("接收端地址", &p.host)?;
  let opened =
    match crate::dirfd::DirFd::open_service_root(base, &p.service) {
      Err(e) if e.code == ErrorCode::NotFound => {
        return Err(
          ApiError::not_found(format!(
            "源服务器上的数据目录 {} 不存在，中止迁移",
            root.display()
          ))
          .with_hint(
            "检查源机 /srv 目录是否被改名或卸载；确认后再重试",
          ),
        );
      }
      Err(e) => return Err(e),
      Ok(dir) => dir,
    };
  if p.kind == SyncKind::CloneSource {
    crate::dirfd::validate_tree(&opened, true)?;
  }
  let source = if p.kind == SyncKind::CloneSource {
    Path::new("/proc")
      .join(std::process::id().to_string())
      .join("fd")
      .join(opened.fd_path().file_name().expect("fd"))
  } else {
    root.clone()
  };
  let host = match host {
    IpAddr::V6(v6) => format!("[{v6}]"),
    IpAddr::V4(v4) => v4.to_string(),
  };
  ctx.say(format!("同步 {} → {host}", root.display()));
  // 跨地域的内网连接偶尔建不上（SYN 被丢），rsync 是幂等的，失败就重试。
  let mut attempt = 1;
  loop {
    let result = Cmd::new("rsync")
      .args(rsync_args(p.pass, p.kind, p.bwlimit_kbps))
      .arg(format!("{}/", source.display()))
      .arg(format!("rsync://{USER}@{host}:{}/{MODULE}/", p.port))
      // 口令走环境变量，不出现在命令行里。
      .env("RSYNC_PASSWORD", &p.password.0)
      .timeout(PUSH_TIMEOUT)
      .stream(true)
      .run(ctx)
      .await?;
    let code = result.code;
    match classify_rsync_exit(code, p.pass) {
      RsyncOutcome::Ok => {
        return Ok(serde_json::json!({ "synced": true }));
      }
      RsyncOutcome::VanishedOk => {
        ctx.say("热同步期间部分源文件消失（退出码 24），将在停机后的第二遍同步补齐");
        return Ok(serde_json::json!({ "synced": true }));
      }
      RsyncOutcome::Retryable if attempt < PUSH_ATTEMPTS => {
        ctx.say(format!(
          "第 {attempt} 次同步失败，{}秒后重试：{}",
          RETRY_DELAY.as_secs(),
          rsync_error(result).message
        ));
        tokio::select! {
          _ = tokio::time::sleep(RETRY_DELAY) => {}
          _ = ctx.cancel.cancelled() => {
            return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
          }
        }
        attempt += 1;
      }
      _ => return Err(rsync_error(result)),
    }
  }
}

fn rsyncd_config(
  root: &Path,
  log: &Path,
  secrets: &Path,
  allow: IpAddr,
) -> String {
  format!(
    "use chroot = no\n\
       munge symlinks = no\n\
       max connections = 4\n\
       log file = {log}\n\
       [{MODULE}]\n\
       path = {root}\n\
       read only = no\n\
       uid = 0\n\
       gid = 0\n\
       auth users = {USER}\n\
       secrets file = {secrets}\n\
       strict modes = yes\n\
       hosts allow = {allow}\n\
       hosts deny = *\n",
    log = log.display(),
    root = root.display(),
    secrets = secrets.display(),
  )
}

fn rsync_args(
  pass: SyncPass,
  kind: SyncKind,
  bwlimit_kbps: Option<u32>,
) -> Vec<String> {
  let mut args = vec!["-aH", "--numeric-ids"];
  if kind == SyncKind::CloneSource {
    args.extend(["--delete", "--checksum", "--one-file-system"]);
  } else if !kind.is_service_data() {
    args.extend([
      "--partial",
      "--delete-after",
      "--exclude=/locks/",
      "--safe-links",
    ]);
  } else if pass == SyncPass::Final {
    args.extend(["--delete", "--checksum"]);
  }
  args.extend([
    "--stats",
    "--human-readable",
    "--contimeout=15",
    "--timeout=300",
  ]);
  let mut args: Vec<_> =
    args.into_iter().map(str::to_string).collect();
  if let Some(limit) = bwlimit_kbps.filter(|v| *v > 0) {
    args.push(format!("--bwlimit={limit}"));
  }
  args
}

pub(crate) fn dir_space(
  srv: &Path,
  service: &str,
  measure_data: bool,
  cancel: &tokio_util::sync::CancellationToken,
) -> Result<wharf_api_types::agent::DirSpaceInfo, ApiError> {
  use crate::dirfd::DirFd;
  let root = match DirFd::open_service_root(srv, service) {
    Ok(root) => Some(root),
    Err(err) if !measure_data && err.code == ErrorCode::NotFound => {
      None
    }
    Err(err) => return Err(err),
  };
  let path = root
    .as_ref()
    .map_or_else(|| srv.to_path_buf(), DirFd::fd_path);
  let (disk, _) =
    crate::report::disk_stat(&path).ok_or_else(|| {
      ApiError::internal("无法读取 /srv 文件系统的可用空间")
    })?;
  let bytes = root
    .as_ref()
    .map(|root| tree_bytes(root, cancel))
    .transpose()?;
  let data_bytes = bytes.filter(|_| measure_data);
  Ok(wharf_api_types::agent::DirSpaceInfo {
    fs_avail_bytes: disk.free,
    fs_total_bytes: disk.total,
    data_bytes,
    existing_bytes: bytes.filter(|_| !measure_data).unwrap_or(0),
  })
}

fn tree_bytes(
  root: &crate::dirfd::DirFd,
  cancel: &tokio_util::sync::CancellationToken,
) -> Result<u64, ApiError> {
  use crate::dirfd::DirFd;
  use std::collections::HashSet;
  fn walk(
    dir: &DirFd,
    seen: &mut HashSet<(libc::dev_t, libc::ino_t)>,
    cancel: &tokio_util::sync::CancellationToken,
    depth: usize,
  ) -> Result<u64, ApiError> {
    if depth > 256 {
      return Err(ApiError::invalid("数据目录层级太深"));
    }
    let io = crate::docker::io_err(Path::new("/srv"));
    let mut bytes = 0u64;
    for name in dir.read_names().map_err(&io)? {
      if cancel.is_cancelled() {
        return Err(ApiError::new(
          ErrorCode::Cancelled,
          "磁盘预检已取消",
        ));
      }
      let st = match dir.lstat(&name) {
        Ok(st) => st,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
          continue;
        }
        Err(err) => return Err(io(err)),
      };
      let size = match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => walk(
          &dir.open_subdir(&name).map_err(&io)?,
          seen,
          cancel,
          depth + 1,
        )?,
        libc::S_IFREG
          if st.st_nlink == 1
            || seen.insert((st.st_dev, st.st_ino)) =>
        {
          st.st_size.max(0) as u64
        }
        _ => 0,
      };
      bytes = bytes.saturating_add(size);
    }
    Ok(bytes)
  }
  walk(root, &mut HashSet::new(), cancel, 0)
}

#[derive(Debug, PartialEq, Eq)]
enum RsyncOutcome {
  Ok,
  VanishedOk,
  Retryable,
  Fatal,
}

fn classify_rsync_exit(
  code: Option<i32>,
  pass: SyncPass,
) -> RsyncOutcome {
  match code {
    Some(0) => RsyncOutcome::Ok,
    Some(24) if pass == SyncPass::Live => RsyncOutcome::VanishedOk,
    Some(10 | 12 | 30 | 35) => RsyncOutcome::Retryable,
    _ => RsyncOutcome::Fatal,
  }
}

fn rsync_error(result: crate::exec::Output) -> ApiError {
  let reason = match result.code {
    Some(5) => "认证或协议错误",
    Some(11) => "读写失败，请检查磁盘空间",
    Some(24) => "停机后仍有文件变动，请检查占用进程",
    _ => "同步失败",
  };
  let label = format!("rsync（退出码 {:?}，{reason}）", result.code);
  result.check(&label).expect_err("rsync 没有成功退出")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rsync_args_live_omits_delete_and_final_enables_checksum_and_hardlinks()
   {
    let live =
      rsync_args(SyncPass::Live, SyncKind::ServiceData, Some(3072));
    let final_pass =
      rsync_args(SyncPass::Final, SyncKind::ServiceData, None);
    assert!(live.iter().any(|arg| arg == "--bwlimit=3072"));
    assert!(live.contains(&"-aH".to_string()));
    assert!(final_pass.contains(&"-aH".to_string()));
    for arg in ["--delete", "--checksum"] {
      assert!(!live.iter().any(|item| item == arg));
      assert!(final_pass.iter().any(|item| item == arg));
    }
  }

  #[test]
  fn preserve_nonempty_target_renames_existing_dir_without_loss() {
    let tmp = tempfile::tempdir().unwrap();
    let photos = tmp.path().join("photos");
    std::fs::create_dir(&photos).unwrap();
    std::fs::write(photos.join("old.jpg"), "old").unwrap();
    let backup = preserve_nonempty_target(
      tmp.path(),
      "photos",
      "test",
      SyncKind::ServiceData,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
      std::fs::read_to_string(backup.join("old.jpg")).unwrap(),
      "old"
    );
    assert!(
      preserve_nonempty_target(
        tmp.path(),
        "photos",
        "test",
        SyncKind::ServiceData
      )
      .unwrap()
      .is_none()
    );
  }

  #[test]
  fn rsyncd_conf_disables_munge_symlinks_and_exit_24_only_ok_in_live()
  {
    let p = Path::new("/srv/notes");
    assert!(
      rsyncd_config(p, p, p, "100.64.0.1".parse().unwrap())
        .contains("munge symlinks = no\n")
    );
    assert_eq!(
      classify_rsync_exit(Some(24), SyncPass::Live),
      RsyncOutcome::VanishedOk
    );
    assert_eq!(
      classify_rsync_exit(Some(24), SyncPass::Final),
      RsyncOutcome::Fatal
    );
  }

  #[test]
  fn dir_space_measures_existing_target_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let target =
      || dir_space(temp.path(), "app", false, &cancel).unwrap();
    assert_eq!(target().existing_bytes, 0);
    std::fs::create_dir(temp.path().join("app")).unwrap();
    std::fs::write(temp.path().join("app/received"), b"1234")
      .unwrap();
    let measured = target();
    assert_eq!(measured.existing_bytes, 4);
    assert_eq!(measured.data_bytes, None);
  }

  #[test]
  fn classify_rsync_exit_retries_only_transient_network_codes() {
    for code in [5, 11, 23] {
      assert_eq!(
        classify_rsync_exit(Some(code), SyncPass::Final),
        RsyncOutcome::Fatal
      );
    }
    for code in [10, 12, 30, 35] {
      assert_eq!(
        classify_rsync_exit(Some(code), SyncPass::Final),
        RsyncOutcome::Retryable
      );
    }
  }

  #[tokio::test]
  async fn push_returns_not_found_when_source_dir_missing() {
    let job = SyncPush {
      service: "wharf-test-missing-70ca".into(),
      host: "100.64.0.2".into(),
      port: 1,
      password: wharf_api_types::agent::OneTimeSecret(String::new()),
      pass: SyncPass::Live,
      kind: SyncKind::ServiceData,
      bwlimit_kbps: None,
    };
    assert_eq!(
      push(&job, &Ctx::detached()).await.unwrap_err().code,
      ErrorCode::NotFound
    );
  }

  #[test]
  fn only_service_dirs() {
    assert_eq!(
      sync_root(SyncKind::ServiceData, "blog").unwrap(),
      Path::new("/srv")
    );
    assert!(sync_root(SyncKind::ServiceData, "../etc").is_err());
    assert!(sync_root(SyncKind::ServiceData, "a/b").is_err());
    assert!(sync_root(SyncKind::CoreBackupRepo, "blog").is_err());
  }
}
