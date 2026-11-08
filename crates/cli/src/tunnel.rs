//! CLI 加密通道（协议见 [wharf_api_types::tunnel]）。
//!
//! 在本机 127.0.0.1 开一个随机端口，HTTP 客户端和 WebSocket 都连它；
//! 每条本地连接对应一条到控制面 `/api/tunnel` 的加密 WebSocket，原样转发字节。
//! 上层只是换了个地址，不感知加密。

use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use anyhow::{Context, anyhow, bail};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::Message;
use wharf_api_types::{
  seal::{KeyShare, Opener, Role, Sealer},
  tunnel::{TUNNEL_PATH, TunnelHello, TunnelWelcome, tunnel_payload},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME: usize = 64 * 1024;

pub struct Tunnel {
  /// 本地地址，例如 `http://127.0.0.1:53124`。
  pub local: String,
  /// 最近一次建通道失败的原因，HTTP 客户端报错时附上。
  pub last_error: Arc<Mutex<Option<String>>>,
}

pub fn parse_core_key(hex_key: &str) -> anyhow::Result<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key.trim())
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("控制面公钥格式不对（应为 64 位十六进制）")?;
  VerifyingKey::from_bytes(&bytes).context("控制面公钥无效")
}

/// 必须在 tokio 运行时里调用。
pub fn start(base: &str, core_key: VerifyingKey) -> anyhow::Result<Tunnel> {
  let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
  listener.set_nonblocking(true)?;
  let local = format!("http://{}", listener.local_addr()?);
  let listener = TcpListener::from_std(listener)?;
  let url = format!("{base}{TUNNEL_PATH}")
    .replacen("http://", "ws://", 1)
    .replacen("https://", "wss://", 1);
  let last_error: Arc<Mutex<Option<String>>> = Default::default();
  let errors = last_error.clone();
  tokio::spawn(async move {
    while let Ok((sock, _)) = listener.accept().await {
      let url = url.clone();
      let errors = errors.clone();
      tokio::spawn(async move {
        if let Err(e) = pipe(sock, &url, &core_key).await {
          *errors.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(format!("{e:#}"));
        }
      });
    }
  });
  Ok(Tunnel { local, last_error })
}

type Ws = tokio_tungstenite::WebSocketStream<
  tokio_tungstenite::MaybeTlsStream<TcpStream>,
>;

async fn handshake(
  url: &str,
  core_key: &VerifyingKey,
) -> anyhow::Result<(Ws, Sealer, Opener)> {
  let (mut ws, _) = tokio::time::timeout(
    HANDSHAKE_TIMEOUT,
    tokio_tungstenite::connect_async(url),
  )
  .await
  .context("连接控制面超时")?
  .map_err(|e| match e {
    tokio_tungstenite::tungstenite::Error::Http(resp)
      if resp.status() == 404 =>
    {
      anyhow!("控制面版本太旧，不支持加密通道，请先升级控制面")
    }
    e => anyhow!("连接控制面失败：{e}"),
  })?;
  let share = KeyShare::generate();
  let mut nonce = [0u8; 24];
  getrandom::fill(&mut nonce).map_err(|e| anyhow!("随机数不可用：{e}"))?;
  let hello = TunnelHello {
    kx: share.public.clone(),
    nonce: hex::encode(nonce),
  };
  ws.send(Message::text(serde_json::to_string(&hello)?)).await?;
  let welcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
    loop {
      match ws.next().await {
        Some(Ok(Message::Text(t))) => {
          return serde_json::from_str::<TunnelWelcome>(&t)
            .context("控制面握手格式不对");
        }
        Some(Ok(_)) => continue,
        Some(Err(e)) => return Err(e.into()),
        None => bail!("控制面关闭了连接"),
      }
    }
  })
  .await
  .context("握手超时")??;
  let sig: [u8; 64] = hex::decode(&welcome.signature)
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("控制面签名格式不对")?;
  core_key
    .verify(
      &tunnel_payload(&hello.nonce, &welcome.kx, &hello.kx),
      &Signature::from_bytes(&sig),
    )
    .map_err(|_| {
      anyhow!(
        "控制面签名和记下的公钥对不上：可能连到了假的控制面（中间人），或者控制面换过密钥"
      )
    })?;
  let (sealer, opener) = share
    .finish(&welcome.kx, &hello.nonce, Role::Agent)
    .map_err(|e| anyhow!("{e}"))?;
  Ok((ws, sealer, opener))
}

async fn pipe(
  sock: TcpStream,
  url: &str,
  core_key: &VerifyingKey,
) -> anyhow::Result<()> {
  let (ws, mut sealer, mut opener) = handshake(url, core_key).await?;
  let (mut sink, mut stream) = ws.split();
  let (mut rx, mut tx) = sock.into_split();
  let up = async move {
    let mut buf = vec![0u8; FRAME];
    loop {
      let n = rx.read(&mut buf).await?;
      if n == 0 {
        break;
      }
      let frame = Message::Binary(sealer.seal(&buf[..n]).into());
      tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(frame))
        .await
        .context("发送超时")??;
    }
    let _ = sink.close().await;
    anyhow::Ok(())
  };
  let down = async move {
    while let Some(msg) = stream.next().await {
      match msg? {
        Message::Binary(frame) => {
          let plain = opener.open(&frame).map_err(|e| anyhow!("{e}"))?;
          tx.write_all(&plain).await?;
        }
        Message::Close(_) => break,
        _ => {}
      }
    }
    let _ = tx.shutdown().await;
    anyhow::Ok(())
  };
  tokio::try_join!(up, down)?;
  Ok(())
}
