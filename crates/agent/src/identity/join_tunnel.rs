use std::time::Duration;

use anyhow::{Context, bail, ensure};
use ed25519_dalek::{Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{
  Message, protocol::WebSocketConfig,
};
use wharf_api_types::{
  seal::{KeyShare, Role},
  tunnel::{TUNNEL_PATH, TunnelHello, TunnelWelcome, tunnel_payload},
  view::{JoinRequest, JoinResponse},
};

const HANDSHAKE: Duration = Duration::from_secs(15);
const REQUEST: Duration = Duration::from_secs(20);
pub(super) const MAX_RESPONSE: usize = 64 * 1024;

pub(super) async fn join(
  url: &reqwest::Url,
  core_key: &VerifyingKey,
  req: &JoinRequest,
) -> anyhow::Result<JoinResponse> {
  let base = url.as_str().trim_end_matches('/');
  let ws_url = format!("ws{}{TUNNEL_PATH}", &base[4..]);
  let config = WebSocketConfig::default()
    .max_message_size(Some(MAX_RESPONSE + 16))
    .max_frame_size(Some(MAX_RESPONSE + 16));
  let (mut ws, mut sealer, mut opener) =
    tokio::time::timeout(HANDSHAKE, async {
      let (mut ws, _) = tokio_tungstenite::connect_async_with_config(
        ws_url,
        Some(config),
        false,
      )
      .await?;
      let share = KeyShare::generate();
      let mut nonce = [0u8; 24];
      getrandom::fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("生成随机数失败"))?;
      let hello = TunnelHello {
        kx: share.public.clone(),
        nonce: hex::encode(nonce),
      };
      ws.send(Message::text(serde_json::to_string(&hello)?))
        .await?;
      let welcome: TunnelWelcome = loop {
        match ws.next().await.transpose()? {
          Some(Message::Text(text)) => {
            break serde_json::from_str(&text)?;
          }
          Some(Message::Close(_)) | None => {
            bail!("控制面关闭了加入连接")
          }
          _ => {}
        }
      };
      let payload =
        tunnel_payload(&hello.nonce, &welcome.kx, &hello.kx);
      ensure!(
        [&welcome.signature]
          .into_iter()
          .chain(welcome.alt_signature.as_ref())
          .filter_map(
            |signature| super::parse_signature(signature).ok()
          )
          .any(|signature| core_key
            .verify(&payload, &signature)
            .is_ok()),
        "控制面签名和 --core-key 不一致，加入凭据没有发出"
      );
      let (sealer, opener) =
        share.finish(&welcome.kx, &hello.nonce, Role::Agent)?;
      Ok::<_, anyhow::Error>((ws, sealer, opener))
    })
    .await
    .context("加入握手超时")??;

  tokio::time::timeout(REQUEST, async {
    let host = url.host_str().context("控制面地址缺少主机")?;
    let host = url.port().map_or_else(|| host.to_string(), |port| format!("{host}:{port}"));
    let body = serde_json::to_string(req)?;
    let request = format!(
      "POST /agent/join HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
      body.len(),
    );
    ws.send(Message::binary(sealer.seal(request.as_bytes()))).await?;
    let mut http = Vec::new();
    while let Some(msg) = ws.next().await.transpose()? {
      match msg {
        Message::Binary(frame) => {
          let plain = opener.open(&frame)?;
          ensure!(http.len() + plain.len() <= MAX_RESPONSE, "加入响应太大");
          http.extend_from_slice(&plain);
          if let Some(result) = response(&http)? {
            return Ok(result);
          }
        }
        Message::Close(_) => break,
        _ => {}
      }
    }
    bail!("控制面未返回完整加入响应")
  }).await.context("加入请求超时")?
}

fn response(http: &[u8]) -> anyhow::Result<Option<JoinResponse>> {
  let Some(end) = http.windows(4).position(|w| w == b"\r\n\r\n")
  else {
    return Ok(None);
  };
  let mut headers = std::str::from_utf8(&http[..end])?.split("\r\n");
  let status = headers
    .next()
    .and_then(|h| h.strip_prefix("HTTP/1.1 "))
    .and_then(|h| h.split_whitespace().next())
    .context("加入响应状态不合法")?
    .parse::<u16>()?;
  let mut len = None;
  for header in headers {
    let (key, value) =
      header.split_once(':').context("加入响应头不合法")?;
    if key.eq_ignore_ascii_case("content-length") {
      ensure!(len.is_none(), "加入响应长度不明确");
      len = Some(value.trim().parse::<usize>()?);
    }
    ensure!(
      !key.eq_ignore_ascii_case("transfer-encoding"),
      "加入响应不支持分块编码"
    );
  }
  let len = len.context("加入响应缺少长度")?;
  let body = &http[end + 4..];
  ensure!(
    len <= MAX_RESPONSE - end - 4 && body.len() <= len,
    "加入响应长度不合法"
  );
  if body.len() < len {
    return Ok(None);
  }
  super::decode_response(status, body).map(Some)
}

#[cfg(test)]
mod tests {
  use super::*;
  use ed25519_dalek::Signer;

  #[tokio::test]
  async fn join_with_previous_core_key_trusts_both_keys() {
    use ed25519_dalek::SigningKey;
    let dir = tempfile::tempdir().unwrap();
    let old = SigningKey::from_bytes(&[21; 32]);
    let current = SigningKey::from_bytes(&[22; 32]);
    let old_public = hex::encode(old.verifying_key().to_bytes());
    let new_public = hex::encode(current.verifying_key().to_bytes());
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let previous_core_public_key = Some(old_public.clone());
    let core_public_key = new_public.clone();
    let server = tokio::spawn(async move {
      let (socket, _) = listener.accept().await.unwrap();
      let mut ws =
        tokio_tungstenite::accept_async(socket).await.unwrap();
      let hello = ws.next().await.unwrap().unwrap();
      let hello: TunnelHello =
        serde_json::from_str(hello.to_text().unwrap()).unwrap();
      let share = KeyShare::generate();
      let payload =
        tunnel_payload(&hello.nonce, &share.public, &hello.kx);
      let welcome = TunnelWelcome {
        signature: hex::encode(current.sign(&payload).to_bytes()),
        alt_signature: Some(hex::encode(
          old.sign(&payload).to_bytes(),
        )),
        kx: share.public.clone(),
      };
      let (mut tx, mut rx) =
        share.finish(&hello.kx, &hello.nonce, Role::Core).unwrap();
      ws.send(Message::text(
        serde_json::to_string(&welcome).unwrap(),
      ))
      .await
      .unwrap();
      let request = ws.next().await.unwrap().unwrap().into_data();
      assert!(
        rx.open(&request).unwrap().starts_with(b"POST /agent/join ")
      );
      let body = serde_json::to_string(&JoinResponse {
        server: "s1".into(),
        core_public_key,
        previous_core_public_key,
      })
      .unwrap();
      let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
      );
      ws.send(Message::binary(tx.seal(response.as_bytes())))
        .await
        .unwrap();
    });
    let mut token = [0u8; 24];
    getrandom::fill(&mut token).unwrap();
    let joined = super::super::join(
      dir.path(),
      &url,
      &hex::encode(token),
      Some(&old_public),
    )
    .await
    .unwrap();
    assert_eq!(joined.core_public_key, new_public);
    assert_eq!(joined.core_public_key_alt, Some(old_public));
    server.await.unwrap();
  }

  #[tokio::test]
  async fn join_client_aborts_on_wrong_core_key_before_sending_token()
  {
    let dir = tempfile::tempdir().unwrap();
    let expected =
      super::super::load_or_create_key(dir.path()).unwrap();
    let wrong_dir = tempfile::tempdir().unwrap();
    let wrong =
      super::super::load_or_create_key(wrong_dir.path()).unwrap();
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
      let (socket, _) = listener.accept().await.unwrap();
      let mut ws =
        tokio_tungstenite::accept_async(socket).await.unwrap();
      let hello = ws.next().await.unwrap().unwrap();
      let hello: TunnelHello =
        serde_json::from_str(hello.to_text().unwrap()).unwrap();
      let share = KeyShare::generate();
      let sig = wrong.sign(&tunnel_payload(
        &hello.nonce,
        &share.public,
        &hello.kx,
      ));
      let welcome = TunnelWelcome {
        alt_signature: None,
        kx: share.public,
        signature: hex::encode(sig.to_bytes()),
      };
      ws.send(Message::text(
        serde_json::to_string(&welcome).unwrap(),
      ))
      .await
      .unwrap();
      let mut frames = 0;
      while let Some(Ok(msg)) = ws.next().await {
        if msg.is_binary() {
          frames += 1;
        }
      }
      frames
    });
    let mut token = [0u8; 24];
    getrandom::fill(&mut token).unwrap();
    let token = hex::encode(token);
    let key = hex::encode(expected.verifying_key().to_bytes());
    let err =
      super::super::join(dir.path(), &url, &token, Some(&key))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("加入凭据没有发出"));
    assert_eq!(
      tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap(),
      0
    );
    let err = super::super::join(
      dir.path(),
      "http://192.0.2.2:7700",
      &token,
      None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("必须提供 --core-key"));
  }
}
