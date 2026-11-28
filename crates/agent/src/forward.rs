//! 端口转发：`wharf connect` 经控制面中转时，agent 这一端连上目标端口，
//! 读到的字节作为进度推回，控制面送来的输入写给目标。一条 TCP 连接一个请求。

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
  sync::mpsc,
};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ForwardJob, TerminalInput},
};

use crate::{
  docker::Docker,
  exec::Ctx,
  outbound::{DataSender, SendError},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const CHUNK: usize = 32 * 1024;

/// `out` 是发往控制面的通道：等它有空位再读下一块，目标比控制面快时自然限速。
pub async fn run(
  docker: &Docker,
  job: &ForwardJob,
  ctx: &Ctx,
  mut input: mpsc::Receiver<TerminalInput>,
  out: &DataSender,
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
  send(out, ctx, String::new()).await?;
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
        send(out, ctx, line).await?;
      }
      msg = input.recv(), if input_open => match msg {
        Some(m) => {
          let Some(data) = m.data.and_then(|d| STANDARD.decode(d).ok()) else { continue };
          // 空数据表示对端不再发送：半关闭写方向，继续收目标的回应。
          if data.is_empty() {
            tokio::select! {
              _ = ctx.cancel.cancelled() => return Err(cancelled()),
              r = tokio::time::timeout(SHUTDOWN_TIMEOUT, wr.shutdown()) =>
                r.map_err(|_| ApiError::new(ErrorCode::Timeout, "关闭目标端口写入超时"))?.map_err(io)?,
            }
            input_open = false;
            continue;
          }
          total += data.len() as u64;
          tokio::select! {
            _ = ctx.cancel.cancelled() => return Err(cancelled()),
            r = tokio::time::timeout(WRITE_TIMEOUT, wr.write_all(&data)) =>
              r.map_err(|_| ApiError::new(ErrorCode::Timeout, "写入目标端口超时"))?.map_err(io)?,
          }
        }
        None => input_open = false,
      },
      _ = ctx.cancel.cancelled() => return Err(cancelled()),
    }
  }
  Ok(Value::from(total))
}

async fn send(
  out: &DataSender,
  ctx: &Ctx,
  line: String,
) -> Result<(), ApiError> {
  out
    .send(line, &ctx.cancel, WRITE_TIMEOUT)
    .await
    .map_err(|err| match err {
      SendError::Cancelled => cancelled(),
      SendError::Timeout => {
        ApiError::new(ErrorCode::Timeout, "转发写入控制面超时")
      }
    })
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
      "{{json .NetworkSettings.Networks}}",
      &container.name,
    ])
    .timeout(Duration::from_secs(15))
    .run(ctx)
    .await?
    .check("查容器地址")?;
  let ip =
    pick_container_ip(&out.stdout, project).ok_or_else(|| {
      ApiError::new(
        ErrorCode::NotFound,
        format!("容器 {} 没有网络地址", container.name),
      )
      .with_hint("host 网络的容器请用宿主机端口连接")
    })?;
  Ok(format_host_port(&ip, job.port))
}

#[derive(serde::Deserialize)]
#[serde(default)]
#[derive(Default)]
struct NetEndpoint {
  #[serde(rename = "IPAddress")]
  ipv4: String,
  #[serde(rename = "GlobalIPv6Address")]
  ipv6: String,
  #[serde(rename = "Gateway")]
  gateway: String,
  #[serde(rename = "IPv6Gateway")]
  ipv6_gateway: String,
}

fn pick_container_ip(
  networks_json: &str,
  project: &str,
) -> Option<String> {
  let networks: BTreeMap<String, NetEndpoint> =
    serde_json::from_str(networks_json).ok()?;
  let prefix = format!("{project}_");
  networks
    .into_iter()
    .filter_map(|(name, endpoint)| {
      let ip: IpAddr = endpoint
        .ipv4
        .parse()
        .or_else(|_| endpoint.ipv6.parse())
        .ok()?;
      let internal = endpoint.gateway.is_empty()
        && endpoint.ipv6_gateway.is_empty();
      let foreign = !name.starts_with(&prefix);
      Some(((internal, foreign, ip.is_ipv6(), name), ip))
    })
    .min_by(|a, b| a.0.cmp(&b.0))
    .map(|(_, ip)| ip.to_string())
}

fn format_host_port(ip: &str, port: u16) -> String {
  if ip.contains(':') {
    format!("[{ip}]:{port}")
  } else {
    format!("{ip}:{port}")
  }
}

fn cancelled() -> ApiError {
  ApiError::new(ErrorCode::Cancelled, "转发已关闭")
}

fn io(e: std::io::Error) -> ApiError {
  ApiError::new(ErrorCode::AgentFailed, format!("转发：{e}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn pick_ip_prefers_routable_and_brackets_ipv6() {
    let networks = r#"{"a_default":{"IPAddress":"100.64.0.2"},"b":{"GlobalIPv6Address":"fd00::2","IPv6Gateway":"fd00::1"}}"#;
    let ip = pick_container_ip(networks, "a").unwrap();
    assert_eq!(format_host_port(&ip, 5432), "[fd00::2]:5432");
  }

  #[tokio::test]
  async fn cancelled_forward_exits_while_outbound_full() {
    let (_out, _ctrl, _logs, mux) = crate::outbound::Outbound::new();
    let out = mux.register(1, 1);
    let ctx = Ctx::detached();
    send(&out, &ctx, String::new()).await.unwrap();
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move { cancel.cancel() });
    let error = tokio::time::timeout(
      Duration::from_millis(100),
      send(&out, &ctx, "data".into()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
  }
}
