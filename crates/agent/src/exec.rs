//! 执行外部命令：一律有超时、可取消，超时或取消时杀掉整个进程组。
//!
//! 教训：Komodo 的 periphery 里 `docker pull` 挂了 30 多分钟，部署一直"忙"，
//! 只能重启。这里每条命令都在自己的进程组里跑，杀的时候连 compose 插件
//! 等子进程一起杀掉。

use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

use tokio::{
  io::{AsyncBufReadExt, AsyncRead, BufReader},
  process::Command,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, ErrorCode};

/// 执行中的进度行，转发给控制面。
pub type Progress = Arc<dyn Fn(String) + Send + Sync>;

/// 一次请求的执行上下文。
#[derive(Clone)]
pub struct Ctx {
  pub cancel: CancellationToken,
  pub progress: Option<Progress>,
}

impl Ctx {
  pub fn detached() -> Self {
    Self {
      cancel: CancellationToken::new(),
      progress: None,
    }
  }

  pub fn say(&self, line: impl Into<String>) {
    if let Some(progress) = &self.progress {
      progress(line.into());
    }
  }
}

#[derive(Debug)]
pub struct Output {
  pub success: bool,
  /// 退出码，被信号杀掉时没有。
  pub code: Option<i32>,
  pub stdout: String,
  pub stderr: String,
}

impl Output {
  /// 失败时用 stderr 的最后几行做错误信息。
  pub fn check(self, what: &str) -> Result<Output, ApiError> {
    if self.success {
      return Ok(self);
    }
    let tail = tail_lines(&self.stderr, 15);
    let tail = if tail.is_empty() {
      tail_lines(&self.stdout, 15)
    } else {
      tail
    };
    Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{what} 失败：{tail}"),
    ))
  }
}

pub fn tail_lines(text: &str, n: usize) -> String {
  let lines: Vec<&str> =
    text.lines().filter(|l| !l.trim().is_empty()).collect();
  lines[lines.len().saturating_sub(n)..].join("\n")
}

/// 单个流最多保留的字节数，防止输出把内存撑爆。
const MAX_CAPTURE: usize = 8 * 1024 * 1024;

pub struct Cmd {
  program: String,
  args: Vec<String>,
  cwd: Option<std::path::PathBuf>,
  env: Vec<(String, String)>,
  timeout: Duration,
  /// 把 stdout 也转发为进度（默认只转发 stderr）。
  stream_stdout: bool,
  stream: bool,
}

impl Cmd {
  pub fn new(program: &str) -> Self {
    Self {
      program: program.to_string(),
      args: Vec::new(),
      cwd: None,
      env: Vec::new(),
      timeout: Duration::from_secs(60),
      stream_stdout: false,
      stream: false,
    }
  }

  pub fn arg(mut self, arg: impl Into<String>) -> Self {
    self.args.push(arg.into());
    self
  }

  pub fn args<I, S>(mut self, args: I) -> Self
  where
    I: IntoIterator<Item = S>,
    S: Into<String>,
  {
    self.args.extend(args.into_iter().map(Into::into));
    self
  }

  pub fn cwd(mut self, dir: &Path) -> Self {
    self.cwd = Some(dir.to_path_buf());
    self
  }

  /// 只设置给子进程，不会出现在命令行里（`ps` 看不到），适合放口令。
  pub fn env(mut self, key: &str, value: &str) -> Self {
    self.env.push((key.to_string(), value.to_string()));
    self
  }

  pub fn timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// 把输出转发为进度。
  pub fn stream(mut self, stdout_too: bool) -> Self {
    self.stream = true;
    self.stream_stdout = stdout_too;
    self
  }

  fn describe(&self) -> String {
    let mut parts = vec![self.program.clone()];
    parts.extend(self.args.iter().take(4).cloned());
    parts.join(" ")
  }

  pub async fn run(self, ctx: &Ctx) -> Result<Output, ApiError> {
    let what = self.describe();
    if ctx.cancel.is_cancelled() {
      return Err(cancelled(&what));
    }
    let mut command = Command::new(&self.program);
    command
      .args(&self.args)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .kill_on_drop(true)
      .process_group(0);
    if let Some(cwd) = &self.cwd {
      command.current_dir(cwd);
    }
    command.envs(self.env.iter().map(|(k, v)| (k, v)));
    let mut child = command.spawn().map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("无法执行 {}：{e}", self.program),
      )
    })?;
    let pid = child.id();
    let progress = if self.stream {
      ctx.progress.clone()
    } else {
      None
    };
    let stdout = tokio::spawn(capture(
      child.stdout.take(),
      if self.stream_stdout {
        progress.clone()
      } else {
        None
      },
    ));
    let stderr = tokio::spawn(capture(child.stderr.take(), progress));

    let status = tokio::select! {
      status = child.wait() => Some(status),
      _ = tokio::time::sleep(self.timeout) => None,
      _ = ctx.cancel.cancelled() => None,
    };
    let status = match status {
      Some(status) => status.map_err(|e| {
        ApiError::internal(format!("等待 {what} 失败：{e}"))
      })?,
      None => {
        kill_group(pid, &mut child).await;
        stdout.abort();
        stderr.abort();
        return Err(if ctx.cancel.is_cancelled() {
          cancelled(&what)
        } else {
          ApiError::new(
            ErrorCode::Timeout,
            format!(
              "{what} 超过 {} 秒未完成，已终止",
              self.timeout.as_secs()
            ),
          )
        });
      }
    };
    Ok(Output {
      success: status.success(),
      code: status.code(),
      stdout: stdout.await.unwrap_or_default(),
      stderr: stderr.await.unwrap_or_default(),
    })
  }
}

fn cancelled(what: &str) -> ApiError {
  ApiError::new(ErrorCode::Cancelled, format!("{what} 已取消"))
}

async fn capture(
  stream: Option<impl AsyncRead + Unpin>,
  progress: Option<Progress>,
) -> String {
  let Some(stream) = stream else {
    return String::new();
  };
  let mut lines = BufReader::new(stream).lines();
  let mut out = String::new();
  while let Ok(Some(line)) = lines.next_line().await {
    if let Some(progress) = &progress
      && !line.trim().is_empty()
    {
      progress(line.clone());
    }
    if out.len() + line.len() < MAX_CAPTURE {
      out.push_str(&line);
      out.push('\n');
    }
  }
  out
}

/// 先 SIGTERM 整个进程组，5 秒后还在就 SIGKILL。
async fn kill_group(
  pid: Option<u32>,
  child: &mut tokio::process::Child,
) {
  if let Some(pid) = pid {
    // SAFETY: 向自己创建的进程组发信号。
    unsafe {
      libc::kill(-(pid as i32), libc::SIGTERM);
    }
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
      .await
      .is_ok()
    {
      return;
    }
    unsafe {
      libc::kill(-(pid as i32), libc::SIGKILL);
    }
  }
  let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn timeout_kills_the_whole_group() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    let started = std::time::Instant::now();
    let err = Cmd::new("sh")
      .args([
        "-c".to_string(),
        format!("sleep 30 & echo $! > {}; wait", pidfile.display()),
      ])
      .timeout(Duration::from_millis(500))
      .run(&Ctx::detached())
      .await
      .unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(4));
    // 后台的 sleep 是孙进程，也必须被杀掉。
    let pid: i32 = std::fs::read_to_string(&pidfile)
      .unwrap()
      .trim()
      .parse()
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "grandchild {pid} still alive");
  }

  #[tokio::test]
  async fn cancel_stops_the_command() {
    let ctx = Ctx::detached();
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move {
      tokio::time::sleep(Duration::from_millis(200)).await;
      cancel.cancel();
    });
    let err = Cmd::new("sleep")
      .arg("30")
      .timeout(Duration::from_secs(60))
      .run(&ctx)
      .await
      .unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled);
  }

  #[tokio::test]
  async fn failure_reports_stderr_tail() {
    let err = Cmd::new("sh")
      .args(["-c", "echo boom >&2; exit 3"])
      .run(&Ctx::detached())
      .await
      .unwrap()
      .check("测试命令")
      .unwrap_err();
    assert!(err.message.contains("boom"), "{}", err.message);
  }
}
