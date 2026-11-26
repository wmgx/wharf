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
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
pub fn start(
  base: &str,
  core_key: VerifyingKey,
) -> anyhow::Result<Tunnel> {
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

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

type Ws = tokio_tungstenite::WebSocketStream<
  tokio_tungstenite::MaybeTlsStream<Box<dyn Transport>>,
>;

fn resolve_proxy_for(url: &reqwest::Url) -> Option<String> {
  let get = |key: &str| std::env::var(key).ok();
  proxy_from(url, get)
}

fn proxy_from(
  url: &reqwest::Url,
  get: impl Fn(&str) -> Option<String>,
) -> Option<String> {
  let host = url.host_str()?.trim_matches(['[', ']']);
  let no_proxy = get("no_proxy")
    .or_else(|| get("NO_PROXY"))
    .unwrap_or_default();
  if no_proxy.split(',').map(str::trim).any(|entry| {
    let entry = entry.trim_start_matches('.');
    if entry == "*"
      || host.eq_ignore_ascii_case(entry.trim_matches(['[', ']']))
    {
      return true;
    }
    if let Some((domain, port)) = entry.rsplit_once(':')
      && let Ok(port) = port.parse::<u16>()
      && url.port().or_else(|| match url.scheme() {
        "ws" | "http" => Some(80),
        "wss" | "https" => Some(443),
        _ => None,
      }) == Some(port)
      && host.eq_ignore_ascii_case(domain.trim_matches(['[', ']']))
    {
      return true;
    }
    if entry.contains('/')
      && let Ok(ip) = host.parse()
    {
      return wharf_api_types::token::ip_in_ranges(
        ip,
        &[entry.to_string()],
      );
    }
    !entry.is_empty()
      && host
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", entry.to_ascii_lowercase()))
  }) {
    return None;
  }
  let variables = if matches!(url.scheme(), "https" | "wss") {
    ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
  } else {
    ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
  };
  variables
    .into_iter()
    .filter_map(get)
    .find(|url| !url.is_empty())
}

async fn via_proxy(
  proxy: &str,
  destination: &str,
) -> anyhow::Result<Box<dyn Transport>> {
  let url = reqwest::Url::parse(proxy)
    .map_err(|_| anyhow!("代理地址无效"))?;
  anyhow::ensure!(
    matches!(url.scheme(), "http" | "https"),
    "代理只支持 HTTP CONNECT"
  );
  let host = url
    .host_str()
    .context("代理缺少主机名")?
    .trim_matches(['[', ']']);
  let port = url.port_or_known_default().context("代理缺少端口")?;
  let socket = TcpStream::connect((host, port))
    .await
    .context("无法连接代理")?;
  let mut socket: Box<dyn Transport> = if url.scheme() == "https" {
    use tokio_rustls::rustls::{
      ClientConfig, RootCertStore, pki_types::ServerName,
    };
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(
      rustls_native_certs::load_native_certs().certs,
    );
    let config = ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();
    let server = ServerName::try_from(host.to_string())
      .map_err(|_| anyhow!("代理主机名无效"))?;
    Box::new(
      tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server, socket)
        .await
        .context("代理 TLS 握手失败")?,
    )
  } else {
    Box::new(socket)
  };
  let connect = format!(
    "CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n"
  );
  socket.write_all(connect.as_bytes()).await?;
  if !url.username().is_empty() || url.password().is_some() {
    let auth = reqwest::Client::new()
      .get("http://localhost")
      .basic_auth(
        decode_userinfo(url.username())?,
        url.password().map(decode_userinfo).transpose()?,
      )
      .build()
      .map_err(|_| anyhow!("代理凭据格式无效"))?;
    if let Some(value) = auth.headers().get("authorization") {
      socket.write_all(b"Proxy-Authorization: ").await?;
      socket.write_all(value.as_bytes()).await?;
      socket.write_all(b"\r\n").await?;
    }
  }
  socket.write_all(b"\r\n").await?;
  socket.flush().await?;
  let mut response = Vec::new();
  while response.len() < 8192 && !response.ends_with(b"\r\n\r\n") {
    response
      .push(socket.read_u8().await.context("读取代理应答失败")?);
  }
  let code = response
    .split(|b| *b == b'\n')
    .next()
    .and_then(|line| std::str::from_utf8(line).ok())
    .and_then(|line| line.split_ascii_whitespace().nth(1));
  anyhow::ensure!(
    response.ends_with(b"\r\n\r\n") && code == Some("200"),
    "代理拒绝建立通道"
  );
  Ok(socket)
}

fn decode_userinfo(input: &str) -> anyhow::Result<String> {
  let mut out = Vec::new();
  let mut bytes = input.bytes();
  while let Some(byte) = bytes.next() {
    if byte == b'%' {
      let hex = [
        bytes.next().context("代理凭据编码无效")?,
        bytes.next().context("代理凭据编码无效")?,
      ];
      let hex =
        std::str::from_utf8(&hex).context("代理凭据编码无效")?;
      out.push(
        u8::from_str_radix(hex, 16).context("代理凭据编码无效")?,
      );
    } else {
      out.push(byte);
    }
  }
  String::from_utf8(out).map_err(|_| anyhow!("代理凭据编码无效"))
}

async fn connect_ws(raw: &str) -> anyhow::Result<Ws> {
  let url = reqwest::Url::parse(raw).context("控制面地址无效")?;
  let host = url.host_str().context("控制面缺少主机名")?;
  let port = url.port().unwrap_or(if url.scheme() == "wss" {
    443
  } else {
    80
  });
  let socket: Box<dyn Transport> =
    if let Some(proxy) = resolve_proxy_for(&url) {
      via_proxy(&proxy, &format!("{host}:{port}")).await?
    } else {
      let socket =
        TcpStream::connect((host.trim_matches(['[', ']']), port))
          .await?;
      socket.set_nodelay(true)?;
      Box::new(socket)
    };
  tokio_tungstenite::client_async_tls_with_config(
    raw, socket, None, None,
  )
  .await
  .map(|(ws, _)| ws)
  .map_err(|e| match e {
    tokio_tungstenite::tungstenite::Error::Http(resp)
      if resp.status() == 404 =>
    {
      anyhow!("控制面版本太旧，不支持加密通道，请先升级控制面")
    }
    _ => anyhow!("连接控制面失败"),
  })
}

async fn handshake(
  url: &str,
  core_key: &VerifyingKey,
) -> anyhow::Result<(Ws, Sealer, Opener)> {
  let mut ws =
    tokio::time::timeout(HANDSHAKE_TIMEOUT, connect_ws(url))
      .await
      .context("连接控制面超时")??;
  let share = KeyShare::generate();
  let mut nonce = [0u8; 24];
  getrandom::fill(&mut nonce)
    .map_err(|e| anyhow!("随机数不可用：{e}"))?;
  let hello = TunnelHello {
    kx: share.public.clone(),
    nonce: hex::encode(nonce),
  };
  ws.send(Message::text(serde_json::to_string(&hello)?))
    .await?;
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
          let plain =
            opener.open(&frame).map_err(|e| anyhow!("{e}"))?;
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

#[test]
fn websocket_proxy_uses_https_and_honors_no_proxy() {
  let env = |key: &str| match key {
    "HTTPS_PROXY" => Some("http://127.0.0.1:8118".into()),
    "NO_PROXY" => {
      Some(".example.test,100.64.0.0/10,203.0.113.3:8443".into())
    }
    _ => None,
  };
  for raw in [
    "wss://core.example.test",
    "wss://100.64.0.5",
    "wss://203.0.113.3:8443",
  ] {
    assert_eq!(
      proxy_from(&reqwest::Url::parse(raw).unwrap(), env),
      None
    );
  }
  assert_eq!(
    proxy_from(
      &reqwest::Url::parse("wss://core.example.net").unwrap(),
      env
    )
    .as_deref(),
    Some("http://127.0.0.1:8118")
  );
}
