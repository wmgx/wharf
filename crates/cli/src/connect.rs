//! `wharf connect`：按服务名在本机开一个端口，连到服务的端口。
//!
//! 路径自动选：组网地址 → 局域网地址 → 经控制面中转（CLI ⇄ 控制面 ⇄ agent ⇄ 服务）。
//! 先逐个探测直连地址，通了就直连；都不通或端口没发布到宿主机时走中转。
//! 到期（`--ttl`）或 Ctrl-C 时停止监听并断开所有连接。

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::Message;
use wharf_api_types::{ApiError, view::ServiceView};

use crate::client::{CliResult, Client, seg};

const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const CHUNK: usize = 32 * 1024;

#[derive(Serialize)]
struct Opened {
  local: String,
  service: String,
  /// direct（直连）或 relay（经控制面中转）。
  via: &'static str,
  /// 直连时连的地址。
  #[serde(skip_serializing_if = "Option::is_none")]
  target: Option<String>,
  ttl_secs: u64,
}

pub struct Args {
  pub service: String,
  pub port: Option<String>,
  pub component: Option<String>,
  pub local: Option<u16>,
  pub ttl: Duration,
  pub relay: bool,
}

pub async fn run(c: &Client, a: Args, j: bool) -> CliResult<()> {
  let view: ServiceView =
    c.get(&format!("/api/services/{}", seg(&a.service))).await?;
  let declared = view.spec.find_port(a.port.as_deref());
  if declared.is_none()
    && a
      .port
      .as_deref()
      .and_then(|p| p.parse::<u16>().ok())
      .is_none()
  {
    let names: Vec<&str> =
      view.spec.ports.iter().map(|p| p.name.as_str()).collect();
    return Err(
      ApiError::invalid(match &a.port {
        Some(p) => format!("服务 {} 没有端口 {p}", a.service),
        None => format!(
          "服务 {} 要指定端口，现有：{}",
          a.service,
          names.join("、")
        ),
      })
      .with_hint("用 --port 指定端口名或容器端口")
      .into(),
    );
  }
  let candidates: Vec<String> = match declared {
    Some(p) if a.component.is_none() && !a.relay => view
      .addresses
      .get(&p.name)
      .into_iter()
      .chain(view.lan_addresses.get(&p.name).into_iter().flatten())
      .cloned()
      .collect(),
    _ => vec![],
  };
  let mut direct = None;
  for addr in candidates {
    if probe(&addr).await {
      direct = Some(addr);
      break;
    }
  }
  // 本地端口：没指定时优先用服务自己的端口号（5432 之类），占用了就随机。
  let want = a.local.or_else(|| {
    declared
      .and_then(|p| p.container)
      .or_else(|| a.port.as_deref().and_then(|p| p.parse().ok()))
  });
  let listener = match want {
    Some(port) => {
      match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(_) if a.local.is_none() => bind_any().await?,
        Err(e) => {
          return Err(
            ApiError::invalid(format!("本机端口 {port} 不能用：{e}"))
              .into(),
          );
        }
      }
    }
    None => bind_any().await?,
  };
  let local = listener
    .local_addr()
    .map_err(|e| ApiError::internal(e.to_string()))?
    .to_string();
  let mut path =
    format!("/api/services/{}/connect?", seg(&a.service));
  if let Some(p) = &a.port {
    path.push_str(&format!("port={}&", seg(p)));
  }
  if let Some(comp) = &a.component {
    path.push_str(&format!("component={}", seg(comp)));
  }
  let opened = Opened {
    local: local.clone(),
    service: a.service.clone(),
    via: if direct.is_some() { "direct" } else { "relay" },
    target: direct.clone(),
    ttl_secs: a.ttl.as_secs(),
  };
  if j {
    crate::print::json(&opened);
  } else {
    let how = match &direct {
      Some(t) => format!("直连 {t}"),
      None => "经控制面中转".to_string(),
    };
    println!(
      "{local} → {}（{how}），{} 分钟后断开，Ctrl-C 结束",
      a.service,
      a.ttl.as_secs() / 60
    );
  }
  let serve = async {
    loop {
      let Ok((sock, _)) = listener.accept().await else {
        continue;
      };
      let _ = sock.set_nodelay(true);
      let direct = direct.clone();
      let req = c.ws_request(&path);
      tokio::spawn(async move {
        let result = match (direct, req) {
          (Some(addr), _) => pipe_direct(sock, &addr).await,
          (None, Ok(req)) => pipe_relay(sock, req).await,
          (None, Err(_)) => Err("地址无效".into()),
        };
        if let Err(e) = result {
          eprintln!("连接出错：{e}");
        }
      });
    }
  };
  tokio::select! {
    _ = serve => {}
    _ = tokio::time::sleep(a.ttl) => {
      if !j { println!("已到期，断开"); }
    }
    _ = tokio::signal::ctrl_c() => {}
  }
  Ok(())
}

/// `90s`、`30m`、`2h`、`1d`，不带单位按分钟。最长 12 小时（控制面单条连接的上限）。
pub fn parse_ttl(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let (num, unit) = s.split_at(
    s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()),
  );
  let n: u64 = num.parse().map_err(|_| format!("时长写错了：{s}"))?;
  let secs = match unit {
    "s" => n,
    "" | "m" => n * 60,
    "h" => n * 3600,
    "d" => n * 86400,
    _ => return Err(format!("时长单位只能是 s、m、h、d：{s}")),
  };
  if secs == 0 || secs > 12 * 3600 {
    return Err("时长要在 1 秒到 12 小时之间".into());
  }
  Ok(Duration::from_secs(secs))
}

async fn bind_any() -> CliResult<TcpListener> {
  TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| {
    ApiError::internal(format!("本机开不了端口：{e}")).into()
  })
}

async fn probe(addr: &str) -> bool {
  matches!(
    tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
      .await,
    Ok(Ok(_))
  )
}

async fn pipe_direct(
  mut sock: TcpStream,
  addr: &str,
) -> Result<(), String> {
  let mut up =
    tokio::time::timeout(PROBE_TIMEOUT * 4, TcpStream::connect(addr))
      .await
      .map_err(|_| format!("连接 {addr} 超时"))?
      .map_err(|e| format!("连不上 {addr}：{e}"))?;
  let _ = up.set_nodelay(true);
  tokio::io::copy_bidirectional(&mut sock, &mut up)
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

async fn pipe_relay(
  sock: TcpStream,
  req: tokio_tungstenite::tungstenite::handshake::client::Request,
) -> Result<(), String> {
  let (ws, _) = tokio::time::timeout(
    Duration::from_secs(15),
    tokio_tungstenite::connect_async(req),
  )
  .await
  .map_err(|_| "连接控制面超时".to_string())?
  .map_err(ws_err)?;
  let (mut tx, mut rx) = ws.split();
  let (mut rd, mut wr) = sock.into_split();
  let upload = async {
    let mut buf = vec![0u8; CHUNK];
    loop {
      let n = rd.read(&mut buf).await.map_err(|e| e.to_string())?;
      // 空帧告诉对端这边不再发送。
      tx.send(Message::Binary(buf[..n].to_vec().into()))
        .await
        .map_err(|e| e.to_string())?;
      if n == 0 {
        return Ok::<_, String>(());
      }
    }
  };
  let download = async {
    while let Some(msg) = rx.next().await {
      match msg.map_err(|e| e.to_string())? {
        Message::Binary(b) => {
          wr.write_all(&b).await.map_err(|e| e.to_string())?
        }
        Message::Text(t) => return Err(t.to_string()),
        Message::Close(_) => break,
        _ => {}
      }
    }
    let _ = wr.shutdown().await;
    Ok(())
  };
  tokio::pin!(download);
  tokio::select! {
    r = upload => match r {
      // 本地发完了，等对端把回应送完。
      Ok(()) => download.await,
      Err(e) => Err(e),
    },
    r = &mut download => r,
  }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> String {
  use tokio_tungstenite::tungstenite::Error;
  match e {
    Error::Http(resp) => {
      let body = resp.body().as_deref().unwrap_or_default();
      serde_json::from_slice::<ApiError>(body)
        .map(|e| match e.hint {
          Some(h) => format!("{}（{h}）", e.message),
          None => e.message,
        })
        .unwrap_or_else(|_| {
          format!("控制面返回 HTTP {}", resp.status())
        })
    }
    other => other.to_string(),
  }
}
