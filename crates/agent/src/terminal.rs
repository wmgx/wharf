//! 容器终端：开一个伪终端，在里面跑 `docker exec -it <容器> sh`。
//! 输出原样（base64）作为进度推给控制面，输入和窗口大小经 `CoreMsg::Input` 送进来。

use std::{
  fs::File,
  io::{Read, Write},
  os::fd::{AsRawFd, FromRawFd, OwnedFd},
  process::Stdio,
  time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio::sync::mpsc;
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

pub async fn run(
  docker: &Docker,
  job: &TerminalJob,
  ctx: &Ctx,
  mut input: mpsc::UnboundedReceiver<TerminalInput>,
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
  let (master, slave) = open_pty(job.size)?;
  let mut cmd = tokio::process::Command::new(&docker.bin);
  cmd
    .args(["exec", "-it", "-e", "TERM=xterm-256color"])
    .arg(&container.name)
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

  let mut writer = File::from(master.try_clone().map_err(io)?);
  let mut reader = File::from(master.try_clone().map_err(io)?);
  let say = ctx.clone();
  let (pid_tx, mut pid_rx) = tokio::sync::watch::channel(None::<u32>);
  let pump = tokio::task::spawn_blocking(move || {
    let mut buf = [0u8; 8192];
    // 找到进程号之前先攒着，标记从输出里去掉。
    let mut head = Some(Vec::new());
    while let Ok(n) = reader.read(&mut buf) {
      if n == 0 {
        break;
      }
      let Some(mut pending) = head.take() else {
        say.say(STANDARD.encode(&buf[..n]));
        continue;
      };
      pending.extend_from_slice(&buf[..n]);
      match take_pid(&pending) {
        Some((pid, rest)) => {
          let _ = pid_tx.send(Some(pid));
          if !rest.is_empty() {
            say.say(STANDARD.encode(&rest));
          }
        }
        None if pending.len() < PID_SCAN => head = Some(pending),
        None => say.say(STANDARD.encode(&pending)),
      }
    }
  });

  let code = loop {
    tokio::select! {
      status = child.wait() => break status.map_err(io)?.code().unwrap_or(-1),
      Some(msg) = input.recv() => {
        if let Some(data) = msg.data.and_then(|d| STANDARD.decode(d).ok()) {
          writer.write_all(&data).map_err(io)?;
        }
        if let Some(size) = msg.size {
          resize(&master, size);
        }
      }
      _ = ctx.cancel.cancelled() => {
        let pid = *pid_rx.borrow_and_update();
        if let Some(pid) = pid {
          hang_up(docker, &container.name, pid).await;
        }
        let _ = child.start_kill();
        return Err(ApiError::new(ErrorCode::Cancelled, "终端已关闭"));
      }
    }
  };
  drop(writer);
  drop(master);
  // 把最后一点输出送完。
  let _ = tokio::time::timeout(Duration::from_secs(1), pump).await;
  Ok(Value::from(code))
}

/// 在输出开头找 `ESC ]777;wharf-pid;<pid> BEL`，返回进程号和去掉标记后的输出。
fn take_pid(out: &[u8]) -> Option<(u32, Vec<u8>)> {
  let start = out.windows(PID_MARK.len()).position(|w| w == PID_MARK)?;
  let digits = start + PID_MARK.len();
  let end = digits + out[digits..].iter().position(|&b| b == 0x07)?;
  let pid = std::str::from_utf8(&out[digits..end]).ok()?.parse().ok()?;
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

fn open_pty(size: TerminalSize) -> Result<(OwnedFd, OwnedFd), ApiError> {
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
  unsafe { Ok((OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))) }
}

fn resize(master: &OwnedFd, size: TerminalSize) {
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

fn io(e: std::io::Error) -> ApiError {
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
