//! CLI 加密通道的控制面一端（协议见 [wharf_api_types::tunnel]）。
//!
//! 握手后把解密出来的字节流当成一条普通 HTTP/1.1 连接，交给同一套路由处理（支持 WebSocket 升级），
//! 所以各接口完全不感知加密。经通道进来的请求带 [Sealed] 标记，用 token 的请求必须有它。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
  extract::{
    ConnectInfo, State,
    ws::{Message, WebSocket, WebSocketUpgrade},
  },
  response::Response,
};
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wharf_api_types::{
  seal::{KeyShare, Role},
  tunnel::{TunnelHello, TunnelWelcome, tunnel_payload},
};

use crate::state::AppState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 一个加密帧最多装多少明文。
const FRAME: usize = 64 * 1024;

/// 请求经加密通道进来。
#[derive(Clone, Copy)]
pub struct Sealed;

/// 通道内请求要沿用外层连接的这些头：Host 是 CLI 真正连的控制面地址
/// （通道内是本机端口），`X-Forwarded-*` 是网关加的。
const OUTER_HEADERS: [&str; 4] =
  ["host", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"];

/// `GET /api/tunnel`（WebSocket）。不需要登录：通道只负责加密，里面的请求照常带 token。
pub async fn open(
  State(s): State<Arc<AppState>>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: axum::http::HeaderMap,
  ws: WebSocketUpgrade,
) -> Response {
  let outer: Vec<_> = OUTER_HEADERS
    .iter()
    .filter_map(|name| {
      headers.get(*name).map(|v| (*name, v.clone()))
    })
    .collect();
  ws.on_upgrade(move |socket| async move {
    if let Err(e) = serve(s, peer, outer, socket).await {
      tracing::debug!("CLI 加密通道 {peer} 结束：{e:#}");
    }
  })
}

async fn handshake(
  s: &AppState,
  socket: &mut WebSocket,
) -> anyhow::Result<(
  wharf_api_types::seal::Sealer,
  wharf_api_types::seal::Opener,
)> {
  let hello = loop {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
      .await
      .map_err(|_| anyhow::anyhow!("握手超时"))?
      .ok_or_else(|| anyhow::anyhow!("连接关闭"))??;
    if let Message::Text(text) = msg {
      break serde_json::from_str::<TunnelHello>(&text)?;
    }
  };
  let share = KeyShare::generate();
  let kx = share.public.clone();
  let signature = s.key.sign(&tunnel_payload(&hello.nonce, &kx, &hello.kx));
  let welcome = TunnelWelcome {
    kx,
    signature: hex::encode(signature.to_bytes()),
  };
  tokio::time::timeout(
    SOCKET_WRITE_TIMEOUT,
    socket.send(Message::text(serde_json::to_string(&welcome)?)),
  )
  .await
  .map_err(|_| anyhow::anyhow!("发送握手超时"))??;
  share
    .finish(&hello.kx, &hello.nonce, Role::Core)
    .map_err(|e| anyhow::anyhow!("{e}"))
}

async fn serve(
  s: Arc<AppState>,
  peer: SocketAddr,
  outer: Vec<(&'static str, axum::http::HeaderValue)>,
  mut socket: WebSocket,
) -> anyhow::Result<()> {
  let (mut sealer, mut opener) = handshake(&s, &mut socket).await?;
  let (inner, plain) = tokio::io::duplex(4 * FRAME);
  let (mut outer_rx, mut outer_tx) = tokio::io::split(plain);
  let (mut sink, mut stream) = socket.split();

  // 密文帧 → 解密 → HTTP 连接。
  let up = async move {
    while let Some(msg) = stream.next().await {
      match msg? {
        Message::Binary(frame) => {
          let plain =
            opener.open(&frame).map_err(|e| anyhow::anyhow!("{e}"))?;
          outer_tx.write_all(&plain).await?;
        }
        Message::Close(_) => break,
        _ => {}
      }
    }
    let _ = outer_tx.shutdown().await;
    anyhow::Ok(())
  };
  // HTTP 连接 → 加密 → 密文帧。
  let down = async move {
    let mut buf = vec![0u8; FRAME];
    loop {
      let n = outer_rx.read(&mut buf).await?;
      if n == 0 {
        break;
      }
      let frame = Message::Binary(sealer.seal(&buf[..n]).into());
      tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(frame))
        .await
        .map_err(|_| anyhow::anyhow!("发送超时"))??;
    }
    let _ = sink.close().await;
    anyhow::Ok(())
  };

  let router = crate::api::router(s);
  let service = hyper::service::service_fn(
    move |mut req: hyper::Request<hyper::body::Incoming>| {
      let h = req.headers_mut();
      for name in OUTER_HEADERS {
        h.remove(name);
      }
      for (name, value) in &outer {
        h.insert(*name, value.clone());
      }
      req.extensions_mut().insert(ConnectInfo(peer));
      req.extensions_mut().insert(Sealed);
      tower::ServiceExt::oneshot(router.clone(), req)
    },
  );
  let http = async move {
    hyper::server::conn::http1::Builder::new()
      .serve_connection(TokioIo::new(inner), service)
      .with_upgrades()
      .await
      .map_err(anyhow::Error::from)
  };
  tokio::try_join!(http, up, down)?;
  Ok(())
}
