//! 端口转发：`wharf connect` 经控制面中转时，agent 这一端连上目标端口，
//! 读到的字节作为进度推回，控制面送来的输入写给目标。一条 TCP 连接一个请求。

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
  sync::mpsc,
};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentMsg, ForwardJob, TerminalInput},
};

use crate::{docker::Docker, exec::Ctx};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 32 * 1024;

/// `out` 是发往控制面的通道：等它有空位再读下一块，目标比控制面快时自然限速。
pub async fn run(
  docker: &Docker,
  job: &ForwardJob,
  ctx: &Ctx,
  mut input: mpsc::Receiver<TerminalInput>,
  id: u64,
  out: mpsc::Sender<AgentMsg>,
) -> Result<Value, ApiError> {
  let addr = target(docker, job, ctx).await?;
  let stream = tokio::select! {
    r = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)) => match r {
      Ok(Ok(s)) => s,
      Ok(Err(e)) => return Err(ApiError::new(ErrorCode::AgentFailed, format!("连不上 {addr}：{e}"))),
      Err(_) => return Err(ApiError::new(ErrorCode::Timeout, format!("连接 {addr} 超时"))),
    },
    _ = ctx.cancel.cancelled() => return Err(cancelled()),
  };
  let _ = stream.set_nodelay(true);
  // 空进度表示已连上：控制面收到它才开始送输入，保证输入不会先于本请求到达。
  if out
    .send(AgentMsg::Progress {
      id,
      line: String::new(),
    })
    .await
    .is_err()
  {
    return Err(cancelled());
  }
  let (mut rd, mut wr) = stream.into_split();
  let mut buf = vec![0u8; CHUNK];
  let mut total: u64 = 0;
  let mut input_open = true;
  loop {
    tokio::select! {
      n = rd.read(&mut buf) => {
        let n = n.map_err(io)?;
        if n == 0 {
          break;
        }
        total += n as u64;
        let line = STANDARD.encode(&buf[..n]);
        if out.send(AgentMsg::Progress { id, line }).await.is_err() {
          return Err(cancelled());
        }
      }
      msg = input.recv(), if input_open => match msg {
        Some(m) => {
          let Some(data) = m.data.and_then(|d| STANDARD.decode(d).ok()) else { continue };
          // 空数据表示对端不再发送：半关闭写方向，继续收目标的回应。
          if data.is_empty() {
            let _ = wr.shutdown().await;
            input_open = false;
            continue;
          }
          total += data.len() as u64;
          wr.write_all(&data).await.map_err(io)?;
        }
        None => input_open = false,
      },
      _ = ctx.cancel.cancelled() => return Err(cancelled()),
    }
  }
  Ok(Value::from(total))
}

async fn target(
  docker: &Docker,
  job: &ForwardJob,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let Some(project) = &job.project else {
    return Ok(format!("127.0.0.1:{}", job.port));
  };
  let state = docker.one_status(project, ctx).await?;
  let container = state
    .containers
    .iter()
    .filter(|c| !c.foreign && c.state == "running")
    .find(|c| job.service.as_deref().is_none_or(|s| s == c.service))
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::NotFound,
        format!("{project} 没有在运行的容器"),
      )
    })?;
  let out = docker
    .cmd()
    .args([
      "inspect",
      "--format",
      "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
      &container.name,
    ])
    .timeout(Duration::from_secs(15))
    .run(ctx)
    .await?
    .check("查容器地址")?;
  let ip = out.stdout.split_whitespace().next().ok_or_else(|| {
    ApiError::new(
      ErrorCode::NotFound,
      format!("容器 {} 没有网络地址", container.name),
    )
    .with_hint("host 网络的容器请用宿主机端口连接")
  })?;
  Ok(format!("{ip}:{}", job.port))
}

fn cancelled() -> ApiError {
  ApiError::new(ErrorCode::Cancelled, "转发已关闭")
}

fn io(e: std::io::Error) -> ApiError {
  ApiError::new(ErrorCode::AgentFailed, format!("转发：{e}"))
}
