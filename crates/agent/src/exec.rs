//! 执行外部命令：一律有超时、可取消，超时或取消时杀掉整个进程组。
//!
//! 教训：Komodo 的 periphery 里 `docker pull` 挂了 30 多分钟，部署一直"忙"，
//! 只能重启。这里每条命令都在自己的进程组里跑，杀的时候连 compose 插件
//! 等子进程一起杀掉。

use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

use tokio::{
  io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
  process::Command,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, ErrorCode};

/// 执行中的进度行，转发给控制面。
pub type Progress = Arc<dyn Fn(String) + Send + Sync>;
type ProgressMatcher = Box<dyn FnMut(&str) -> bool + Send>;

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

  pub fn detached_with_progress(&self) -> Self {
    Self {
      progress: self.progress.clone(),
      ..Self::detached()
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
  stall: Option<(Duration, ProgressMatcher)>,
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
      stall: None,
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

  pub fn env_arg(self, flag: &str, key: &str, value: &str) -> Self {
    self.args([flag, key]).env(key, value)
  }

  pub fn envs(
    mut self,
    vars: impl IntoIterator<Item = (&'static str, String)>,
  ) -> Self {
    self
      .env
      .extend(vars.into_iter().map(|(k, v)| (k.to_string(), v)));
    self
  }

  pub fn timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  pub fn stall_timeout(
    mut self,
    duration: Duration,
    matcher: impl FnMut(&str) -> bool + Send + 'static,
  ) -> Self {
    self.stall = Some((duration, Box::new(matcher)));
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

  fn command(&self) -> Command {
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
    command
  }

  pub async fn stream_bounded(
    self,
    ctx: &Ctx,
    lines: tokio::sync::mpsc::Sender<String>,
  ) -> bool {
    if ctx.cancel.is_cancelled() {
      return false;
    }
    let Ok(mut child) = self.command().spawn() else {
      return false;
    };
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let streams = async {
      tokio::join!(
        bounded_lines(stdout, &lines),
        bounded_lines(stderr, &lines)
      );
      child.wait().await.is_ok_and(|status| status.success())
    };
    let normal = tokio::select! {
      normal = streams => normal,
      _ = tokio::time::sleep(self.timeout) => true,
      _ = ctx.cancel.cancelled() => false,
    };
    // Compose 退出后仍可能留下 CLI 插件。
    if let Some(pid) = pid {
      unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
      }
    }
    let _ = child.wait().await;
    normal
  }

  pub(crate) async fn stdout_bounded(
    self,
    ctx: &Ctx,
    limit: u64,
  ) -> Option<Vec<u8>> {
    let mut child =
      self.command().stderr(Stdio::null()).spawn().ok()?;
    let pid = child.id();
    let mut stdout = child.stdout.take()?.take(limit + 1);
    let mut bytes = Vec::new();
    let read = async {
      stdout.read_to_end(&mut bytes).await.ok()?;
      if bytes.len() as u64 > limit {
        return None;
      }
      child.wait().await.ok()?.success().then_some(())
    };
    let result = tokio::select! {
      result = read => result,
      _ = tokio::time::sleep(self.timeout) => None,
      _ = ctx.cancel.cancelled() => None,
    };
    if result.is_none() {
      kill_group(pid, &mut child).await;
    }
    result.map(|()| bytes)
  }

  pub(crate) async fn stdout_to(
    self,
    ctx: &Ctx,
    limit: u64,
    dest: &mut (impl tokio::io::AsyncWrite + Unpin),
  ) -> Result<Option<i32>, ApiError> {
    let what = self.describe();
    if ctx.cancel.is_cancelled() {
      return Err(cancelled(&what));
    }
    let mut child = self
      .command()
      .stderr(Stdio::null())
      .spawn()
      .map_err(|_| ApiError::internal("无法启动读取操作"))?;
    let pid = child.id();
    let mut stdout =
      child.stdout.take().expect("已接管 stdout").take(limit + 1);
    let read = async {
      let bytes = tokio::io::copy(&mut stdout, dest)
        .await
        .map_err(|_| ApiError::internal("写入临时输出失败"))?;
      if bytes > limit {
        return Err(ApiError::invalid("备份文件或索引超过读取上限"));
      }
      child
        .wait()
        .await
        .map(|status| status.code())
        .map_err(|_| ApiError::internal("读取命令未完成"))
    };
    let result = tokio::select! {
      result = read => result,
      _ = tokio::time::sleep(self.timeout) => Err(ApiError::new(ErrorCode::Timeout, "读取备份超时")),
      _ = ctx.cancel.cancelled() => Err(cancelled(&what)),
    };
    if result.is_err() {
      kill_group(pid, &mut child).await;
    }
    result
  }

  pub async fn run(mut self, ctx: &Ctx) -> Result<Output, ApiError> {
    let what = self.describe();
    if ctx.cancel.is_cancelled() {
      return Err(cancelled(&what));
    }
    let mut command = self.command();
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
    let (stall, output) = match self.stall.take() {
      Some((duration, mut matches_progress)) => {
        let (activity, receiver) =
          tokio::sync::watch::channel(tokio::time::Instant::now());
        let matcher: Progress = Arc::new({
          let matcher = std::sync::Mutex::new(move |line: &str| {
            if matches_progress(line) {
              activity.send_replace(tokio::time::Instant::now());
            }
          });
          move |line| (matcher.lock().unwrap())(&line)
        });
        (Some((duration, receiver)), Some(matcher))
      }
      None => (None, None),
    };
    let output =
      |progress: Option<Progress>| match (progress, output.clone()) {
        (None, matcher) | (matcher, None) => matcher,
        (Some(progress), Some(matcher)) => {
          let both: Progress = Arc::new(move |line: String| {
            matcher(line.clone());
            progress(line);
          });
          Some(both)
        }
      };
    let stdout = tokio::spawn(capture(
      child.stdout.take(),
      output(self.stream_stdout.then(|| progress.clone()).flatten()),
    ));
    let stderr =
      tokio::spawn(capture(child.stderr.take(), output(progress)));

    let mut stalled = false;
    let status = tokio::select! {
      status = child.wait() => Some(status),
      _ = tokio::time::sleep(self.timeout) => None,
      _ = ctx.cancel.cancelled() => None,
      _ = wait_for_stall(stall) => { stalled = true; None },
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
        } else if stalled {
          ApiError::new(
            ErrorCode::Timeout,
            format!("{what} 长时间无进展，已终止"),
          )
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

async fn wait_for_stall(
  stall: Option<(
    Duration,
    tokio::sync::watch::Receiver<tokio::time::Instant>,
  )>,
) {
  let Some((interval, mut activity)) = stall else {
    return std::future::pending().await;
  };
  loop {
    let until = *activity.borrow_and_update() + interval;
    match tokio::time::timeout_at(until, activity.changed()).await {
      Ok(Ok(())) => {}
      Ok(Err(_)) => {
        tokio::time::sleep_until(until).await;
        return;
      }
      Err(_) => return,
    }
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

async fn bounded_lines(
  stream: impl AsyncRead + Unpin,
  lines: &tokio::sync::mpsc::Sender<String>,
) {
  let mut stream = BufReader::new(stream);
  let mut line = Vec::with_capacity(4096);
  while let Ok(chunk) = stream.fill_buf().await {
    if chunk.is_empty() {
      break;
    }
    let end = chunk.iter().position(|b| *b == b'\n');
    let len = end.unwrap_or(chunk.len());
    line.extend_from_slice(&chunk[..len.min(4096 - line.len())]);
    if end.is_some() {
      let text = String::from_utf8_lossy(&line)
        .trim_end_matches('\r')
        .to_string();
      if lines.send(text).await.is_err() {
        return;
      }
      line.clear();
    }
    stream.consume(len + usize::from(end.is_some()));
  }
  if !line.is_empty() {
    let _ = lines
      .send(String::from_utf8_lossy(&line).into_owned())
      .await;
  }
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
  async fn stall_timeout_kills_hung_command_even_with_unchanged_status()
   {
    let result = Cmd::new("sh")
      .args(["-c", "while :; do echo unchanged; sleep 0.02; done"])
      .timeout(Duration::from_secs(5))
      .stall_timeout(Duration::from_millis(100), |_| false)
      .run(&Ctx::detached())
      .await
      .unwrap_err();
    assert_eq!(result.code, ErrorCode::Timeout);
    assert!(result.message.contains("无进展"));
  }

  #[tokio::test]
  async fn watch_lines_discard_bytes_past_four_kib() {
    let input = format!("{}\nnext\n", "x".repeat(100_000));
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    bounded_lines(input.as_bytes(), &tx).await;
    assert_eq!(rx.recv().await.unwrap().len(), 4096);
    assert_eq!(rx.recv().await.unwrap(), "next");
  }

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

#[test]
fn child_env_argument_contains_only_key() {
  for flag in ["--build-arg", "-e"] {
    let command = Cmd::new("docker")
      .env_arg(flag, "FIXTURE_KEY", "fixture-value")
      .command();
    let command = command.as_std();
    assert_eq!(
      command.get_args().collect::<Vec<_>>(),
      [flag, "FIXTURE_KEY"]
    );
    assert!(
      command.get_envs().any(|(key, value)| key == "FIXTURE_KEY"
        && value.is_some_and(|value| value == "fixture-value"))
    );
  }
}
