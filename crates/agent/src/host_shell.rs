//! 通过临时特权容器进入宿主机命名空间，提供终端和一次性命令执行。

use std::{
  fs::File,
  io::{Read, Write},
  path::Path,
  process::Stdio,
  sync::atomic::{AtomicU64, Ordering},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio::{io::AsyncReadExt, sync::mpsc};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    HostExecFailure, HostExecJob, HostExecOutcome, HostExecResult,
    TerminalInput, TerminalSize,
  },
};

use crate::{
  docker::Docker,
  exec::Ctx,
  terminal::{io, open_pty, resize},
};

const FEATURE_LABEL: &str = "com.wharf.host-shell=1";
const SERVER_LABEL: &str = "com.wharf.host-shell.server";
const GENERATION_LABEL: &str = "com.wharf.host-shell.generation";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_STEP_TIMEOUT: Duration = Duration::from_secs(3);
const OUTPUT_LIMIT: usize = 64 * 1024;
const COMMAND_LIMIT: usize = 64 * 1024;
const TAIL_LIMIT: usize = 512;
const HOST_SHELL: &str = "cd /root 2>/dev/null || cd /; command -v bash >/dev/null 2>&1 && exec bash -l || exec sh -l";
const EXEC_WRAPPER: &str = "/bin/sh -c \"$1\"; code=$?; printf '\\n%s%d\\n' \"$2\" \"$code\" >&2; exit \"$code\"";

struct Prepared {
  image: String,
}

pub struct HostShell {
  docker: Docker,
  server: String,
  generation: String,
  prepared: Result<Prepared, ApiError>,
  next: AtomicU64,
}

impl HostShell {
  pub async fn prepare(docker: Docker, server: String) -> Self {
    let generation = random_id();
    let prepared = prepare(&docker, &server).await;
    if let Err(e) = &prepared {
      tracing::warn!("宿主机终端暂不可用：{e}");
    }
    Self {
      docker,
      server,
      generation,
      prepared,
      next: AtomicU64::new(0),
    }
  }

  fn image(&self) -> Result<&str, ApiError> {
    self
      .prepared
      .as_ref()
      .map(|p| p.image.as_str())
      .map_err(Clone::clone)
  }

  fn name(&self) -> String {
    let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
    format!("wharf-shell-{}-{id}", self.generation)
  }

  fn run_args(
    &self,
    name: &str,
    cwd: &str,
    tty: bool,
    image: &str,
  ) -> Vec<String> {
    let mut args = vec!["run", "--rm"];
    if tty {
      args.push("-it");
    }
    let mut args: Vec<String> =
      args.into_iter().map(str::to_string).collect();
    if tty {
      args.extend(["-e".into(), "TERM=xterm-256color".into()]);
    }
    args.extend([
      "--privileged".into(),
      "--pid=host".into(),
      "--net=host".into(),
      "--name".into(),
      name.into(),
      "--label".into(),
      FEATURE_LABEL.into(),
      "--label".into(),
      format!("{SERVER_LABEL}={}", self.server),
      "--label".into(),
      format!("{GENERATION_LABEL}={}", self.generation),
      "-e".into(),
      "HOME=/root".into(),
      "-e".into(),
      "USER=root".into(),
      "-e".into(),
      "LOGNAME=root".into(),
      "-e".into(),
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
      "--entrypoint".into(),
      "nsenter".into(),
      image.into(),
      "-t".into(),
      "1".into(),
      "-m".into(),
      "-u".into(),
      "-i".into(),
      "-n".into(),
      "-p".into(),
      "--root".into(),
      format!("--wdns={cwd}"),
      "--".into(),
    ]);
    args
  }

  pub async fn terminal(
    &self,
    size: TerminalSize,
    ctx: &Ctx,
    mut input: mpsc::Receiver<TerminalInput>,
  ) -> Result<Value, ApiError> {
    let image = self.image()?;
    let name = self.name();
    let (master, slave) = open_pty(size)?;
    let mut writer = File::from(master.try_clone().map_err(io)?);
    let mut reader = File::from(master.try_clone().map_err(io)?);
    let mut args = self.run_args(&name, "/", true, image);
    args.extend(["/bin/sh".into(), "-c".into(), HOST_SHELL.into()]);
    let mut cmd = tokio::process::Command::new(&self.docker.bin);
    cmd
      .args(args)
      .stdin(Stdio::from(slave.try_clone().map_err(io)?))
      .stdout(Stdio::from(slave.try_clone().map_err(io)?))
      .stderr(Stdio::from(slave))
      .kill_on_drop(true);
    unsafe {
      cmd.pre_exec(|| {
        libc::setsid();
        libc::ioctl(0, libc::TIOCSCTTY as _, 0);
        Ok(())
      });
    }
    let mut child = cmd.spawn().map_err(io)?;
    drop(cmd);

    let say = ctx.clone();
    let pump = tokio::task::spawn_blocking(move || {
      let mut buf = [0u8; 8192];
      while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
          break;
        }
        say.say(STANDARD.encode(&buf[..n]));
      }
    });

    let result = loop {
      tokio::select! {
        status = child.wait() => break status.map_err(io).map(exit_code),
        Some(msg) = input.recv() => {
          if let Some(data) = msg.data.and_then(|d| STANDARD.decode(d).ok())
            && let Err(e) = writer.write_all(&data)
          {
            break Err(io(e));
          }
          if let Some(size) = msg.size {
            resize(&master, size);
          }
        }
        _ = ctx.cancel.cancelled() => break Err(ApiError::new(ErrorCode::Cancelled, "终端已关闭")),
      }
    };
    let first_cleanup = self.remove(&name).await;
    let _ = child.start_kill();
    let _ =
      tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let second_cleanup = self.remove(&name).await;
    drop(writer);
    drop(master);
    let _ = tokio::time::timeout(Duration::from_secs(1), pump).await;
    first_cleanup.and(second_cleanup)?;
    result.map(Value::from)
  }

  pub async fn exec(
    &self,
    job: HostExecJob,
    ctx: &Ctx,
  ) -> HostExecOutcome {
    let started = Instant::now();
    match self.exec_inner(&job, ctx).await {
      Ok(mut result) => {
        result.duration_ms = started.elapsed().as_millis() as u64;
        HostExecOutcome::Finished(result)
      }
      Err((error, output_bytes)) => {
        HostExecOutcome::Failed(HostExecFailure {
          error,
          duration_ms: started.elapsed().as_millis() as u64,
          output_bytes,
        })
      }
    }
  }

  async fn exec_inner(
    &self,
    job: &HostExecJob,
    ctx: &Ctx,
  ) -> Result<HostExecResult, (ApiError, u64)> {
    let image = self.image().map_err(|e| (e, 0))?;
    validate_exec(job).map_err(|e| (e, 0))?;
    let name = self.name();
    let marker = format!("__WHARF_EXIT_{}__=", random_id());
    let marker_prefix = format!("\n{marker}");
    let mut args = self.run_args(&name, &job.cwd, false, image);
    args.extend([
      "/bin/sh".into(),
      "-c".into(),
      EXEC_WRAPPER.into(),
      "wharf-host-exec".into(),
      job.command.clone(),
      marker,
    ]);
    let mut command = tokio::process::Command::new(&self.docker.bin);
    command
      .args(args)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .kill_on_drop(true)
      .process_group(0);
    let mut child = command.spawn().map_err(|e| {
      (
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("无法启动宿主机命令：{e}"),
        ),
        0,
      )
    })?;
    let mut stdout = tokio::spawn(capture(child.stdout.take()));
    let mut stderr = tokio::spawn(capture(child.stderr.take()));
    let deadline =
      tokio::time::sleep(Duration::from_secs(job.timeout_secs));
    tokio::pin!(deadline);
    let end = tokio::select! {
      status = child.wait() => status.map_err(|e| ApiError::internal(format!("等待宿主机命令失败：{e}"))),
      _ = &mut deadline => Err(ApiError::new(ErrorCode::Timeout, format!("宿主机命令超过 {} 秒未完成，已终止", job.timeout_secs))),
      _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "宿主机命令已取消")),
    };
    let first_cleanup = self.remove(&name).await;
    let _ = child.start_kill();
    let _ =
      tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let second_cleanup = self.remove(&name).await;
    let out = finish_capture(&mut stdout).await;
    let err = finish_capture(&mut stderr).await;
    let output_bytes = out.total.saturating_add(err.total);
    if let Err(e) = first_cleanup.and(second_cleanup) {
      return Err((e, output_bytes));
    }
    if let Err(e) = end {
      return Err((e, output_bytes));
    }
    let (err, exit_code) =
      finish_stderr(err, marker_prefix.as_bytes())
        .map_err(|e| (e, output_bytes))?;
    let output_bytes = out.total.saturating_add(err.total);
    let (stdout, stdout_truncated) = output_text(out);
    let (stderr, stderr_truncated) = output_text(err);
    Ok(HostExecResult {
      exit_code,
      stdout,
      stderr,
      truncated: stdout_truncated || stderr_truncated,
      duration_ms: 0,
      output_bytes,
    })
  }

  async fn remove(&self, name: &str) -> Result<(), ApiError> {
    let ctx = Ctx::detached();
    let out = tokio::time::timeout(
      CLEANUP_STEP_TIMEOUT,
      self
        .docker
        .cmd()
        .args(["rm", "-f", name])
        .timeout(CLEANUP_STEP_TIMEOUT)
        .run(&ctx),
    )
    .await
    .map_err(|_| {
      ApiError::new(ErrorCode::Timeout, "清理宿主机命令容器超时")
    })??;
    if out.success || missing_container(&out.stderr) {
      Ok(())
    } else {
      Err(ApiError::new(
        ErrorCode::AgentFailed,
        "清理宿主机命令容器失败",
      ))
    }
  }
}

async fn prepare(
  docker: &Docker,
  server: &str,
) -> Result<Prepared, ApiError> {
  let ctx = Ctx::detached();
  let image = crate::adopt::self_image(docker, &ctx).await?;
  let check = docker
    .cmd()
    .args(["run", "--rm", "--entrypoint", "sh", &image, "-c"])
    .arg(
      "command -v nsenter >/dev/null && nsenter --version >/dev/null",
    )
    .timeout(Duration::from_secs(30))
    .run(&ctx)
    .await?
    .check("检查 nsenter")?;
  drop(check);
  tokio::time::timeout(CLEANUP_TIMEOUT, cleanup_old(docker, server))
    .await
    .map_err(|_| {
      ApiError::new(ErrorCode::Timeout, "清理遗留宿主机命令容器超时")
    })??;
  Ok(Prepared { image })
}

async fn cleanup_old(
  docker: &Docker,
  server: &str,
) -> Result<(), ApiError> {
  let ctx = Ctx::detached();
  let server_label = format!("{SERVER_LABEL}={server}");
  let out = docker
    .cmd()
    .args([
      "ps",
      "-aq",
      "--filter",
      &format!("label={FEATURE_LABEL}"),
      "--filter",
      &format!("label={server_label}"),
    ])
    .timeout(CLEANUP_TIMEOUT)
    .run(&ctx)
    .await?
    .check("查找遗留宿主机命令容器")?;
  for id in out.stdout.lines().filter(|id| !id.is_empty()) {
    docker
      .cmd()
      .args(["rm", "-f", id])
      .timeout(CLEANUP_TIMEOUT)
      .run(&ctx)
      .await?
      .check("清理遗留宿主机命令容器")?;
  }
  Ok(())
}

fn validate_exec(job: &HostExecJob) -> Result<(), ApiError> {
  if job.command.trim().is_empty() {
    return Err(ApiError::invalid("命令不能为空"));
  }
  if job.command.len() > COMMAND_LIMIT {
    return Err(ApiError::invalid("命令不能超过 64 KiB"));
  }
  if job.command.contains('\0') {
    return Err(ApiError::invalid("命令不能包含 NUL"));
  }
  if !(1..=600).contains(&job.timeout_secs) {
    return Err(ApiError::invalid("超时必须在 1 到 600 秒之间"));
  }
  if !Path::new(&job.cwd).is_absolute() || job.cwd.contains('\0') {
    return Err(ApiError::invalid(
      "工作目录必须是绝对路径且不能包含 NUL",
    ));
  }
  Ok(())
}

#[derive(Default)]
struct Captured {
  kept: Vec<u8>,
  tail: Vec<u8>,
  total: u64,
}

impl Captured {
  fn push(&mut self, chunk: &[u8]) {
    self.total = self.total.saturating_add(chunk.len() as u64);
    let remaining = OUTPUT_LIMIT.saturating_sub(self.kept.len());
    self
      .kept
      .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    self.tail.extend_from_slice(chunk);
    if self.tail.len() > TAIL_LIMIT {
      self.tail.drain(..self.tail.len() - TAIL_LIMIT);
    }
  }
}

async fn capture(
  stream: Option<impl tokio::io::AsyncRead + Unpin>,
) -> Captured {
  let Some(mut stream) = stream else {
    return Captured::default();
  };
  let mut captured = Captured::default();
  let mut buf = [0u8; 8192];
  while let Ok(n) = stream.read(&mut buf).await {
    if n == 0 {
      break;
    }
    captured.push(&buf[..n]);
  }
  captured
}

async fn finish_capture(
  task: &mut tokio::task::JoinHandle<Captured>,
) -> Captured {
  match tokio::time::timeout(Duration::from_secs(2), &mut *task).await
  {
    Ok(Ok(captured)) => captured,
    _ => {
      task.abort();
      Captured::default()
    }
  }
}

fn finish_stderr(
  mut captured: Captured,
  marker: &[u8],
) -> Result<(Captured, i32), ApiError> {
  let start = captured
    .tail
    .windows(marker.len())
    .rposition(|w| w == marker)
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::AgentFailed,
        "宿主机命令没有返回退出状态",
      )
    })?;
  let digits = start + marker.len();
  let end = digits
    + captured.tail[digits..]
      .iter()
      .position(|&b| b == b'\n')
      .ok_or_else(|| {
        ApiError::internal("宿主机命令退出状态不完整")
      })?;
  if end + 1 != captured.tail.len() {
    return Err(ApiError::internal("宿主机命令退出状态不在输出末尾"));
  }
  let code = std::str::from_utf8(&captured.tail[digits..end])
    .ok()
    .and_then(|s| s.parse().ok())
    .ok_or_else(|| ApiError::internal("宿主机命令退出状态不合法"))?;
  let marker_len = marker.len() + end - digits + 1;
  captured.total = captured.total.saturating_sub(marker_len as u64);
  captured
    .kept
    .truncate(captured.kept.len().min(captured.total as usize));
  Ok((captured, code))
}

fn output_text(captured: Captured) -> (String, bool) {
  let mut text = String::from_utf8_lossy(&captured.kept).into_owned();
  let mut truncated = captured.total > OUTPUT_LIMIT as u64;
  if text.len() > OUTPUT_LIMIT {
    let mut end = OUTPUT_LIMIT;
    while !text.is_char_boundary(end) {
      end -= 1;
    }
    text.truncate(end);
    truncated = true;
  }
  (text, truncated)
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
  use std::os::unix::process::ExitStatusExt;
  status
    .code()
    .or_else(|| status.signal().map(|signal| 128 + signal))
    .unwrap_or(-1)
}

fn missing_container(stderr: &str) -> bool {
  stderr.contains("No such container")
    || stderr.contains("No such object")
}

fn random_id() -> String {
  let mut bytes = [0u8; 8];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn capture_keeps_exact_prefix_and_exit_marker() {
    for size in [0, 65_535, 65_536, 65_537] {
      let mut captured = Captured::default();
      captured.push(&vec![b'x'; size]);
      let (text, truncated) = output_text(captured);
      assert_eq!(text.len(), size.min(OUTPUT_LIMIT));
      assert_eq!(truncated, size > OUTPUT_LIMIT);
    }

    let marker = b"\n__WHARF_EXIT_test__=";
    let mut captured = Captured::default();
    captured.push(b"warning\xff");
    captured.push(marker);
    captured.push(b"137\n");
    let (captured, code) = finish_stderr(captured, marker).unwrap();
    let (text, truncated) = output_text(captured);
    assert_eq!(code, 137);
    assert_eq!(text, "warning\u{fffd}");
    assert!(!truncated);

    let mut captured = Captured::default();
    captured.push(&vec![b'x'; OUTPUT_LIMIT - marker.len() / 2]);
    captured.push(marker);
    captured.push(b"0\n");
    let (captured, code) = finish_stderr(captured, marker).unwrap();
    let (text, truncated) = output_text(captured);
    assert_eq!(code, 0);
    assert!(text.bytes().all(|byte| byte == b'x'));
    assert!(!truncated);
  }

  #[test]
  fn validates_exec_boundaries() {
    let valid = HostExecJob {
      command: "printf ok".into(),
      timeout_secs: 600,
      cwd: "/tmp".into(),
    };
    assert!(validate_exec(&valid).is_ok());
    assert!(
      validate_exec(&HostExecJob {
        timeout_secs: 0,
        ..valid.clone()
      })
      .is_err()
    );
    assert!(
      validate_exec(&HostExecJob {
        cwd: "tmp".into(),
        ..valid
      })
      .is_err()
    );
  }
}
