//! 迁移数据：接收端在内网地址上临时起 rsync daemon，发送端推送。
//!
//! - 只同步 `/srv/<service>/`，路径由服务名拼出，不接受任意路径；
//! - daemon 只接受发送端内网地址的连接，口令一次性、只写在 0600 的文件里；
//! - daemon 跟着请求走：请求被取消（或超时）就杀掉进程、删掉临时配置。

use std::{
  net::{IpAddr, SocketAddr},
  path::{Path, PathBuf},
  time::Duration,
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{SYNC_READY, SyncPush, SyncServe},
  validate_name,
};

use crate::{
  docker::{io_err, write_private},
  exec::{Cmd, Ctx},
};

const SERVE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
const PUSH_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const PUSH_ATTEMPTS: u32 = 6;
const RETRY_DELAY: Duration = Duration::from_secs(3);
const MODULE: &str = "wharf";
const USER: &str = "wharf";

fn data_root(service: &str) -> Result<PathBuf, ApiError> {
  validate_name("service", service)?;
  Ok(Path::new("/srv").join(service))
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

pub async fn serve(
  s: &SyncServe,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let root = data_root(&s.service)?;
  let bind = parse_ip("监听地址", &s.bind)?;
  let allow = parse_ip("发送端地址", &s.allow)?;
  std::fs::create_dir_all(&root).map_err(io_err(&root))?;

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
    &format!(
      "use chroot = no\n\
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
      log = tmp.0.join("rsyncd.log").display(),
      root = root.display(),
      secrets = secrets.display(),
    ),
  )?;

  let daemon = Cmd::new("rsync")
    .args(["--daemon", "--no-detach"])
    .arg(format!("--address={bind}"))
    .arg(format!("--port={port}"))
    .arg(format!("--config={}", conf.display()))
    .timeout(SERVE_TIMEOUT);
  let run_ctx = ctx.clone();
  let mut task =
    tokio::spawn(async move { daemon.run(&run_ctx).await });

  // 等端口能连上再报告就绪。
  let addr = SocketAddr::new(bind, port);
  let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
  loop {
    if tokio::net::TcpStream::connect(addr).await.is_ok() {
      break;
    }
    if task.is_finished() || tokio::time::Instant::now() > deadline {
      task.abort();
      let detail = match task.await {
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
  let root = data_root(&p.service)?;
  let host = parse_ip("接收端地址", &p.host)?;
  if !root.exists() {
    ctx.say(format!("{} 不存在，没有数据要迁移", root.display()));
    return Ok(serde_json::json!({ "synced": false }));
  }
  let host = match host {
    IpAddr::V6(v6) => format!("[{v6}]"),
    IpAddr::V4(v4) => v4.to_string(),
  };
  ctx.say(format!("同步 {} → {host}", root.display()));
  // 跨地域的内网连接偶尔建不上（SYN 被丢），rsync 是幂等的，失败就重试。
  let mut attempt = 1;
  loop {
    let result = Cmd::new("rsync")
      .args([
        "-a",
        "--numeric-ids",
        "--delete",
        "--stats",
        "--human-readable",
        "--contimeout=15",
        "--timeout=300",
      ])
      .arg(format!("{}/", root.display()))
      .arg(format!("rsync://{USER}@{host}:{}/{MODULE}/", p.port))
      // 口令走环境变量，不出现在命令行里。
      .env("RSYNC_PASSWORD", &p.password.0)
      .timeout(PUSH_TIMEOUT)
      .stream(true)
      .run(ctx)
      .await?
      .check("rsync");
    match result {
      Ok(_) => return Ok(serde_json::json!({ "synced": true })),
      Err(e) if attempt < PUSH_ATTEMPTS => {
        ctx.say(format!(
          "第 {attempt} 次同步失败，{}秒后重试：{}",
          RETRY_DELAY.as_secs(),
          e.message
        ));
        tokio::select! {
          _ = tokio::time::sleep(RETRY_DELAY) => {}
          _ = ctx.cancel.cancelled() => {
            return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
          }
        }
        attempt += 1;
      }
      Err(e) => return Err(e),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn only_service_dirs() {
    assert_eq!(
      data_root("blog").unwrap(),
      PathBuf::from("/srv/blog")
    );
    assert!(data_root("../etc").is_err());
    assert!(data_root("a/b").is_err());
  }
}
