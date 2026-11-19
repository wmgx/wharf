//! 容器终端：开一个伪终端，在里面跑 `docker exec -it <容器> sh`。
//! 输出原样（base64）作为进度推给控制面，输入和窗口大小经 `CoreMsg::Input` 送进来。
//! 每个容器一个会话：浏览器断开后会话留着，重新打开时补发最近的输出接着用；
//! 没人连着并且 30 分钟没有输入输出就挂断。可以同时开几个窗口看同一个会话。

use std::{
  collections::{HashMap, VecDeque},
  fs::File,
  io::{Read, Write},
  os::fd::{AsRawFd, FromRawFd, OwnedFd},
  process::Stdio,
  sync::{Arc, LazyLock},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, watch};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{TerminalInput, TerminalJob, TerminalSize},
};

use crate::{docker::Docker, exec::Ctx};

/// 先报出 shell 在容器里的进程号（exec 之后不变），再换成 bash，没有 bash 用 sh。
/// 杀掉 docker exec 客户端不会结束容器里的进程，关闭时要靠这个进程号去挂断它。
const SHELL: &str = "printf '\\033]777;wharf-pid;%s\\007' $$; command -v bash >/dev/null 2>&1 && exec bash || exec sh";
const PID_MARK: &[u8] = b"\x1b]777;wharf-pid;";
/// 进程号标记应该在最开头，攒这么多还没找到就不找了。
const PID_SCAN: usize = 4096;

/// 浏览器断开后会话保留这么久（期间没有输出），超时挂断。
const IDLE: Duration = Duration::from_secs(30 * 60);
/// 重新连上时补发的最近输出。
const REPLAY: usize = 64 * 1024;

/// 一个容器一个会话：断开只是离开，重新打开接着用，和宿主机终端的 tmux 会话一样。
struct Session {
  container: String,
  master: OwnedFd,
  writer: std::sync::Mutex<File>,
  /// 最近的输出和订阅放在同一把锁里，补发和实时输出不会重复也不会漏。
  out: std::sync::Mutex<(VecDeque<u8>, broadcast::Sender<Vec<u8>>)>,
  last: std::sync::Mutex<Instant>,
  pid: watch::Receiver<Option<u32>>,
  exited: watch::Receiver<Option<i32>>,
  /// docker exec 客户端的进程号，挂断时一起杀掉。
  client: Option<u32>,
}

static SESSIONS: LazyLock<
  std::sync::Mutex<HashMap<String, Arc<Session>>>,
> = LazyLock::new(Default::default);

pub async fn run(
  docker: &Docker,
  job: &TerminalJob,
  ctx: &Ctx,
  mut input: mpsc::Receiver<TerminalInput>,
) -> Result<Value, ApiError> {
  let state = docker.one_status(&job.project, ctx).await?;
  let container = state
    .containers
    .iter()
    .filter(|c| !c.foreign && c.state == "running")
    .find(|c| job.service.as_deref().is_none_or(|s| s == c.service))
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::NotFound,
        format!("{} 没有在运行的容器", job.project),
      )
    })?;
  let existing = SESSIONS
    .lock()
    .unwrap()
    .get(&container.name)
    .filter(|s| s.exited.borrow().is_none())
    .cloned();
  let session = match existing {
    Some(s) => {
      resize(&s.master, job.size);
      s
    }
    None => {
      let s = spawn(docker, &container.name, job.size)?;
      SESSIONS
        .lock()
        .unwrap()
        .insert(container.name.clone(), s.clone());
      s
    }
  };
  let (replay, mut rx) = {
    let out = session.out.lock().unwrap();
    (
      out.0.iter().copied().collect::<Vec<u8>>(),
      out.1.subscribe(),
    )
  };
  if !replay.is_empty() {
    ctx.say(STANDARD.encode(&replay));
  }
  let mut exited = session.exited.clone();
  loop {
    tokio::select! {
      chunk = rx.recv() => match chunk {
        Ok(chunk) => ctx.say(STANDARD.encode(&chunk)),
        Err(broadcast::error::RecvError::Lagged(_)) => {}
        Err(broadcast::error::RecvError::Closed) => {}
      },
      _ = exited.changed() => {
        let code = (*exited.borrow()).unwrap_or(-1);
        // 把最后一点输出送完。
        while let Ok(chunk) = rx.try_recv() {
          ctx.say(STANDARD.encode(&chunk));
        }
        return Ok(Value::from(code));
      }
      Some(msg) = input.recv() => {
        *session.last.lock().unwrap() = Instant::now();
        if let Some(data) = msg.data.and_then(|d| STANDARD.decode(d).ok()) {
          session.writer.lock().unwrap().write_all(&data).map_err(io)?;
        }
        if let Some(size) = msg.size {
          resize(&session.master, size);
        }
      }
      _ = ctx.cancel.cancelled() => {
        // 只是离开：会话留着，空闲超时后再挂断。
        *session.last.lock().unwrap() = Instant::now();
        return Err(ApiError::new(ErrorCode::Cancelled, "终端已断开，会话保留 30 分钟"));
      }
    }
  }
}

/// 在容器里开一个新 shell，起读输出、等退出、空闲挂断三个后台任务。
fn spawn(
  docker: &Docker,
  container: &str,
  size: TerminalSize,
) -> Result<Arc<Session>, ApiError> {
  let (master, slave) = open_pty(size)?;
  let mut cmd = tokio::process::Command::new(&docker.bin);
  cmd
    .args(["exec", "-it", "-e", "TERM=xterm-256color"])
    .arg(container)
    .args(["sh", "-c", SHELL])
    .stdin(Stdio::from(slave.try_clone().map_err(io)?))
    .stdout(Stdio::from(slave.try_clone().map_err(io)?))
    .stderr(Stdio::from(slave))
    .kill_on_drop(true);
  // 新会话并把伪终端设为控制终端，docker exec 才认它是 tty。
  unsafe {
    cmd.pre_exec(|| {
      libc::setsid();
      libc::ioctl(0, libc::TIOCSCTTY as _, 0);
      Ok(())
    });
  }
  let mut child = cmd.spawn().map_err(io)?;
  // 子进程已经拿到了自己那份 slave，这里的都关掉，shell 退出时读端才会结束。
  drop(cmd);
  let (pid_tx, pid) = watch::channel(None::<u32>);
  let (exit_tx, exited) = watch::channel(None::<i32>);
  let session = Arc::new(Session {
    container: container.to_string(),
    writer: std::sync::Mutex::new(File::from(
      master.try_clone().map_err(io)?,
    )),
    out: std::sync::Mutex::new((
      VecDeque::new(),
      broadcast::channel(1024).0,
    )),
    last: std::sync::Mutex::new(Instant::now()),
    pid,
    exited,
    client: child.id(),
    master: master.try_clone().map_err(io)?,
  });

  let mut reader = File::from(master);
  let pump = session.clone();
  tokio::task::spawn_blocking(move || {
    let mut buf = [0u8; 8192];
    // 找到进程号之前先攒着，标记从输出里去掉。
    let mut head = Some(Vec::new());
    while let Ok(n) = reader.read(&mut buf) {
      if n == 0 {
        break;
      }
      let chunk = match head.take() {
        None => buf[..n].to_vec(),
        Some(mut pending) => {
          pending.extend_from_slice(&buf[..n]);
          match take_pid(&pending) {
            Some((pid, rest)) => {
              let _ = pid_tx.send(Some(pid));
              rest
            }
            None if pending.len() < PID_SCAN => {
              head = Some(pending);
              continue;
            }
            None => pending,
          }
        }
      };
      if chunk.is_empty() {
        continue;
      }
      *pump.last.lock().unwrap() = Instant::now();
      let mut out = pump.out.lock().unwrap();
      out.0.extend(&chunk);
      let extra = out.0.len().saturating_sub(REPLAY);
      out.0.drain(..extra);
      let _ = out.1.send(chunk);
    }
  });

  let done = session.clone();
  tokio::spawn(async move {
    let code =
      child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
    let _ = exit_tx.send(Some(code));
    let mut all = SESSIONS.lock().unwrap();
    if all
      .get(&done.container)
      .is_some_and(|s| Arc::ptr_eq(s, &done))
    {
      all.remove(&done.container);
    }
  });

  let idle = session.clone();
  let docker = docker.clone();
  tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_secs(60)).await;
      if idle.exited.borrow().is_some() {
        return;
      }
      let watching = idle.out.lock().unwrap().1.receiver_count() > 0;
      let quiet = idle.last.lock().unwrap().elapsed() > IDLE;
      if !watching && quiet {
        let pid = *idle.pid.borrow();
        if let Some(pid) = pid {
          hang_up(&docker, &idle.container, pid).await;
        }
        if let Some(client) = idle.client {
          unsafe {
            libc::kill(client as i32, libc::SIGKILL);
          }
        }
        return;
      }
    }
  });
  Ok(session)
}

/// 在输出开头找 `ESC ]777;wharf-pid;<pid> BEL`，返回进程号和去掉标记后的输出。
fn take_pid(out: &[u8]) -> Option<(u32, Vec<u8>)> {
  let start =
    out.windows(PID_MARK.len()).position(|w| w == PID_MARK)?;
  let digits = start + PID_MARK.len();
  let end = digits + out[digits..].iter().position(|&b| b == 0x07)?;
  let pid =
    std::str::from_utf8(&out[digits..end]).ok()?.parse().ok()?;
  let mut rest = out[..start].to_vec();
  rest.extend_from_slice(&out[end + 1..]);
  Some((pid, rest))
}

/// 挂断容器里的 shell：它退出时内核会挂断它的前台任务，bash 还会挂断后台任务。
async fn hang_up(docker: &Docker, container: &str, pid: u32) {
  let ctx = Ctx::detached();
  let _ = docker
    .cmd()
    .args(["exec", container, "kill", "-HUP", &pid.to_string()])
    .timeout(Duration::from_secs(10))
    .run(&ctx)
    .await;
}

pub(crate) fn open_pty(
  size: TerminalSize,
) -> Result<(OwnedFd, OwnedFd), ApiError> {
  let mut master = 0;
  let mut slave = 0;
  let ws = winsize(size);
  let rc = unsafe {
    libc::openpty(
      &mut master,
      &mut slave,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      &ws as *const _ as *mut _,
    )
  };
  if rc != 0 {
    return Err(io(std::io::Error::last_os_error()));
  }
  unsafe {
    Ok((OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)))
  }
}

pub(crate) fn resize(master: &OwnedFd, size: TerminalSize) {
  let ws = winsize(size);
  unsafe {
    libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws);
  }
}

fn winsize(size: TerminalSize) -> libc::winsize {
  libc::winsize {
    ws_row: size.rows.max(1),
    ws_col: size.cols.max(1),
    ws_xpixel: 0,
    ws_ypixel: 0,
  }
}

pub(crate) fn io(e: std::io::Error) -> ApiError {
  ApiError::new(ErrorCode::AgentFailed, format!("终端：{e}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn strips_pid_mark() {
    let out = b"\x1b]777;wharf-pid;42\x07/ # ";
    assert_eq!(take_pid(out), Some((42, b"/ # ".to_vec())));
    assert_eq!(take_pid(b"\x1b]777;wharf-pid;4"), None);
  }
}
