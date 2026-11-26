//! agent 的密钥和加入信息，存在 data_dir 下，权限 0600。

use std::{
  net::IpAddr,
  path::{Path, PathBuf},
  time::Duration,
};

use anyhow::{Context, anyhow, bail};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use wharf_api_types::{
  seal::{KeyShare, Role},
  tunnel::{TUNNEL_PATH, TunnelHello, TunnelWelcome, tunnel_payload},
  view::{JoinRequest, JoinResponse},
};

const KEY_FILE: &str = "agent.key";
const JOIN_FILE: &str = "agent.json";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_JOIN_RESPONSE: usize = 64 * 1024;

/// join 之后记下的信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Joined {
  /// 控制面地址，例如 `http://100.64.0.1:7700`。
  pub core_url: String,
  pub server: String,
  pub core_public_key: String,
}

impl Joined {
  pub fn ws_url(&self) -> String {
    ws_base(&self.core_url, "/agent/ws")
  }

  pub fn core_key(&self) -> anyhow::Result<VerifyingKey> {
    parse_public_key(&self.core_public_key)
  }

  pub fn load(data_dir: &Path) -> anyhow::Result<Option<Self>> {
    let path = data_dir.join(JOIN_FILE);
    match std::fs::read_to_string(&path) {
      Ok(text) => Ok(Some(
        serde_json::from_str(&text)
          .with_context(|| format!("{} 格式不对", path.display()))?,
      )),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
      Err(e) => Err(e).context(format!("读取 {}", path.display())),
    }
  }

  fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
    write_private(
      &data_dir.join(JOIN_FILE),
      &serde_json::to_string_pretty(self)?,
    )
  }
}

fn ws_base(core_url: &str, path: &str) -> String {
  let base = core_url.trim_end_matches('/');
  let base = base
    .strip_prefix("https://")
    .map(|rest| format!("wss://{rest}"))
    .or_else(|| {
      base
        .strip_prefix("http://")
        .map(|rest| format!("ws://{rest}"))
    })
    .unwrap_or_else(|| format!("ws://{base}"));
  format!("{base}{path}")
}

fn url_authority(core_url: &str) -> anyhow::Result<(String, String)> {
  let parsed = reqwest::Url::parse(core_url)
    .with_context(|| format!("控制面地址格式不对：{core_url}"))?;
  let host = parsed
    .host_str()
    .context("控制面地址缺少主机名")?
    .to_string();
  let host_header = match parsed.port() {
    Some(p) => format!("{host}:{p}"),
    None => host.clone(),
  };
  Ok((host, host_header))
}

fn is_loopback_host(host: &str) -> bool {
  let bare = host.trim_matches(['[', ']']);
  bare.eq_ignore_ascii_case("localhost")
    || bare
      .parse::<IpAddr>()
      .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

pub fn parse_public_key(
  hex_key: &str,
) -> anyhow::Result<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key.trim())
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("公钥格式不对")?;
  VerifyingKey::from_bytes(&bytes).context("公钥无效")
}

pub fn parse_signature(hex_sig: &str) -> anyhow::Result<Signature> {
  let bytes: [u8; 64] = hex::decode(hex_sig.trim())
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("签名格式不对")?;
  Ok(Signature::from_bytes(&bytes))
}

pub fn load_or_create_key(
  data_dir: &Path,
) -> anyhow::Result<SigningKey> {
  let path = data_dir.join(KEY_FILE);
  match std::fs::read_to_string(&path) {
    Ok(text) => {
      let seed: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{} 格式不对", path.display()))?;
      Ok(SigningKey::from_bytes(&seed))
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      let mut seed = [0u8; 32];
      getrandom::fill(&mut seed)
        .map_err(|e| anyhow!("生成随机数失败：{e}"))?;
      write_private(&path, &hex::encode(seed))?;
      Ok(SigningKey::from_bytes(&seed))
    }
    Err(e) => Err(e).context(format!("读取 {}", path.display())),
  }
}

fn write_private(
  path: &PathBuf,
  content: &str,
) -> anyhow::Result<()> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
  }
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .with_context(|| format!("写入 {}", path.display()))?;
  file.write_all(content.as_bytes())?;
  Ok(())
}

/// 用一次性凭据加入控制面。
///
/// 非本机控制面必须提供 `--core-key`：先经 `/api/tunnel` 验证控制面私钥签名并建立加密通道，
/// 验签通过后再发送 `join_token`，确保中间人拿不到加入凭据。
pub async fn join(
  data_dir: &Path,
  core_url: &str,
  join_token: &str,
  core_key: Option<&str>,
) -> anyhow::Result<Joined> {
  let core_url = core_url.trim().trim_end_matches('/').to_string();
  let (host, host_header) = url_authority(&core_url)?;
  let expected_hex =
    core_key.map(str::trim).filter(|k| !k.is_empty());

  if expected_hex.is_none() && !is_loopback_host(&host) {
    bail!(
      "加入非本机控制面必须提供 --core-key，防止中间人窃取加入凭据（直接复制 wharf server add 或页面生成的完整加入命令）"
    );
  }

  let key = load_or_create_key(data_dir)?;
  let req = JoinRequest {
    join_token: join_token.to_string(),
    public_key: hex::encode(key.verifying_key().to_bytes()),
  };

  let joined = match expected_hex {
    Some(expected) => {
      let verifying = parse_public_key(expected)?;
      join_via_tunnel(&core_url, &host_header, &verifying, &req)
        .await?
    }
    None => join_local_plain(&core_url, &req).await?,
  };

  parse_public_key(&joined.core_public_key)?;
  if let Some(expected) = expected_hex
    && !expected.eq_ignore_ascii_case(&joined.core_public_key)
  {
    bail!(
      "控制面返回的公钥和加入命令里的不一致：可能连到了假的控制面（中间人）。没有加入"
    );
  }
  let joined = Joined {
    core_url,
    server: joined.server,
    core_public_key: joined.core_public_key,
  };
  joined.save(data_dir)?;
  Ok(joined)
}

async fn join_local_plain(
  core_url: &str,
  req: &JoinRequest,
) -> anyhow::Result<JoinResponse> {
  let client =
    reqwest::Client::builder().timeout(JOIN_TIMEOUT).build()?;
  let resp = client
    .post(format!("{core_url}/agent/join"))
    .json(req)
    .send()
    .await
    .with_context(|| format!("连接控制面 {core_url} 失败"))?;
  if !resp.status().is_success() {
    let status = resp.status();
    let body: serde_json::Value =
      resp.json().await.unwrap_or_default();
    bail!(
      "加入失败（HTTP {status}）：{}",
      body["message"].as_str().unwrap_or("未知错误")
    );
  }
  Ok(resp.json().await?)
}

async fn join_via_tunnel(
  core_url: &str,
  host_header: &str,
  core_key: &VerifyingKey,
  req: &JoinRequest,
) -> anyhow::Result<JoinResponse> {
  let url = ws_base(core_url, TUNNEL_PATH);
  let (mut ws, _) = tokio::time::timeout(
    HANDSHAKE_TIMEOUT,
    tokio_tungstenite::connect_async(&url),
  )
  .await
  .context("连接控制面超时")?
  .with_context(|| format!("连接控制面 {core_url} 失败"))?;

  let share = KeyShare::generate();
  let mut nonce = [0u8; 24];
  getrandom::fill(&mut nonce)
    .map_err(|e| anyhow!("随机数不可用：{e}"))?;
  let hello = TunnelHello {
    kx: share.public.clone(),
    nonce: hex::encode(nonce),
  };
  tokio::time::timeout(
    HANDSHAKE_TIMEOUT,
    ws.send(Message::text(serde_json::to_string(&hello)?)),
  )
  .await
  .context("发送握手超时")??;

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

  // 先用 --core-key 验证控制面签名；不通过立即中止，join_token 绝不离开进程。
  core_key
    .verify(
      &tunnel_payload(&hello.nonce, &welcome.kx, &hello.kx),
      &parse_signature(&welcome.signature)?,
    )
    .map_err(|_| {
      anyhow!(
        "控制面签名和 --core-key 不一致：可能连到了假的控制面（中间人）。加入凭据没有发出"
      )
    })?;

  let (mut sealer, mut opener) = share
    .finish(&welcome.kx, &hello.nonce, Role::Agent)
    .map_err(|e| anyhow!("{e}"))?;

  let body = serde_json::to_vec(req)?;
  let http_req = format!(
    "POST /agent/join HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
    body.len()
  );
  let mut raw_req = http_req.into_bytes();
  raw_req.extend_from_slice(&body);

  let raw_resp = tokio::time::timeout(JOIN_TIMEOUT, async {
    ws.send(Message::Binary(sealer.seal(&raw_req).into()))
      .await?;
    let mut buf = Vec::new();
    while let Some(msg) = ws.next().await {
      match msg? {
        Message::Binary(frame) => {
          let plain =
            opener.open(&frame).map_err(|e| anyhow!("{e}"))?;
          if buf.len() + plain.len() > MAX_JOIN_RESPONSE {
            bail!("加入响应过大");
          }
          buf.extend_from_slice(&plain);
          if http_response_complete(&buf) {
            break;
          }
        }
        Message::Close(_) => break,
        _ => {}
      }
    }
    let _ = ws.close(None).await;
    anyhow::Ok(buf)
  })
  .await
  .context("加入请求超时")??;

  let (status, resp_body) = parse_http_response(&raw_resp)?;
  if !(200..300).contains(&status) {
    let body: serde_json::Value =
      serde_json::from_slice(&resp_body).unwrap_or_default();
    bail!(
      "加入失败（HTTP {status}）：{}",
      body["message"].as_str().unwrap_or("未知错误")
    );
  }
  serde_json::from_slice::<JoinResponse>(&resp_body)
    .context("解析控制面加入响应失败")
}

fn http_response_complete(buf: &[u8]) -> bool {
  let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
  else {
    return false;
  };
  let head = String::from_utf8_lossy(&buf[..pos]);
  let body = &buf[pos + 4..];
  for line in head.lines().skip(1) {
    if let Some((k, v)) = line.split_once(':') {
      if k.trim().eq_ignore_ascii_case("content-length")
        && let Ok(len) = v.trim().parse::<usize>()
      {
        return body.len() >= len;
      }
      if k.trim().eq_ignore_ascii_case("transfer-encoding")
        && v.to_ascii_lowercase().contains("chunked")
      {
        return decode_chunked(body).is_some();
      }
    }
  }
  false
}

fn parse_http_response(raw: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
  let pos = raw
    .windows(4)
    .position(|w| w == b"\r\n\r\n")
    .context("控制面返回的 HTTP 响应不完整")?;
  let head = std::str::from_utf8(&raw[..pos])
    .context("控制面返回的 HTTP 头不是 UTF-8")?;
  let status_line = head.lines().next().context("缺少状态行")?;
  let status: u16 = status_line
    .split_whitespace()
    .nth(1)
    .and_then(|s| s.parse().ok())
    .context("无法解析 HTTP 状态码")?;

  let mut chunked = false;
  let mut content_len: Option<usize> = None;
  for line in head.lines().skip(1) {
    if let Some((k, v)) = line.split_once(':') {
      if k.trim().eq_ignore_ascii_case("transfer-encoding")
        && v.to_ascii_lowercase().contains("chunked")
      {
        chunked = true;
      } else if k.trim().eq_ignore_ascii_case("content-length") {
        content_len = v.trim().parse().ok();
      }
    }
  }
  let raw_body = &raw[pos + 4..];
  let body = if chunked {
    decode_chunked(raw_body).context("解析分块响应失败")?
  } else if let Some(len) = content_len {
    if raw_body.len() < len {
      bail!("控制面返回的响应体不完整");
    }
    raw_body[..len].to_vec()
  } else {
    raw_body.to_vec()
  };
  Ok((status, body))
}

fn decode_chunked(mut input: &[u8]) -> Option<Vec<u8>> {
  let mut out = Vec::new();
  loop {
    let crlf = input.windows(2).position(|w| w == b"\r\n")?;
    let size_str = std::str::from_utf8(&input[..crlf])
      .ok()?
      .split(';')
      .next()?
      .trim();
    let size = usize::from_str_radix(size_str, 16).ok()?;
    input = &input[crlf + 2..];
    if size == 0 {
      return Some(out);
    }
    if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
      return None;
    }
    out.extend_from_slice(&input[..size]);
    input = &input[size + 2..];
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  #[test]
  fn ws_urls() {
    let j = |url: &str| Joined {
      core_url: url.into(),
      server: "node1".into(),
      core_public_key: String::new(),
    };
    assert_eq!(
      j("http://203.0.113.4:7700/").ws_url(),
      "ws://203.0.113.4:7700/agent/ws"
    );
    assert_eq!(
      j("https://wharf.example.test").ws_url(),
      "wss://wharf.example.test/agent/ws"
    );
  }

  #[test]
  fn key_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let a = load_or_create_key(dir.path()).unwrap();
    let b = load_or_create_key(dir.path()).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
  }

  #[tokio::test]
  async fn join_client_aborts_on_wrong_core_key_before_sending_token()
  {
    use axum::{
      Router,
      extract::ws::{Message as WsMsg, WebSocketUpgrade},
      routing::get,
    };
    use ed25519_dalek::Signer;

    let real_core = SigningKey::from_bytes(&[1u8; 32]);
    let mitm_core = SigningKey::from_bytes(&[2u8; 32]);
    let real_key_hex =
      hex::encode(real_core.verifying_key().to_bytes());
    let binary_frames = Arc::new(AtomicUsize::new(0));
    let seen = binary_frames.clone();

    let app = Router::new().route(
      TUNNEL_PATH,
      get(move |ws: WebSocketUpgrade| {
        let mitm = mitm_core.clone();
        let seen = seen.clone();
        async move {
          ws.on_upgrade(move |mut socket| async move {
            let Some(Ok(WsMsg::Text(t))) = socket.recv().await else {
              return;
            };
            let hello: TunnelHello =
              serde_json::from_str(&t).unwrap();
            let share = KeyShare::generate();
            let sig = mitm.sign(&tunnel_payload(
              &hello.nonce,
              &share.public,
              &hello.kx,
            ));
            let welcome = TunnelWelcome {
              kx: share.public,
              signature: hex::encode(sig.to_bytes()),
            };
            let _ = socket
              .send(WsMsg::Text(
                serde_json::to_string(&welcome).unwrap().into(),
              ))
              .await;
            while let Some(Ok(msg)) = socket.recv().await {
              if matches!(msg, WsMsg::Binary(_)) {
                seen.fetch_add(1, Ordering::SeqCst);
              }
            }
          })
        }
      }),
    );

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
      let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let err = join(
      dir.path(),
      &format!("http://{addr}"),
      "wj_secret",
      Some(&real_key_hex),
    )
    .await
    .unwrap_err();
    assert!(
      err.to_string().contains("加入凭据没有发出"),
      "unexpected err: {err:#}"
    );
    // 给服务端短暂收尾时间，确认中间人收到的二进制帧严格为 0。
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(binary_frames.load(Ordering::SeqCst), 0);
    srv.abort();

    // 非本机 http:// 不传 --core-key 在建连前立刻拒绝。
    let err =
      join(dir.path(), "http://192.0.2.10:7700", "wj_secret", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--core-key"), "{err:#}");
  }
}
