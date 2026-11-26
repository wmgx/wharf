use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use ed25519_dalek::{Signature, VerifyingKey};
use wharf_api_types::{
  PROTOCOL,
  agent::CoreMsg,
  seal::{Opener, Sealer},
};

pub(super) const HANDSHAKE_TIMEOUT: Duration =
  Duration::from_secs(15);
pub(super) const SOCKET_WRITE_TIMEOUT: Duration =
  Duration::from_secs(10);

pub(super) fn random_nonce() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

pub(super) fn decode_key(hex_key: &str) -> Option<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
  VerifyingKey::from_bytes(&bytes).ok()
}

pub(super) fn decode_sig(hex_sig: &str) -> Option<Signature> {
  let bytes: [u8; 64] = hex::decode(hex_sig).ok()?.try_into().ok()?;
  Some(Signature::from_bytes(&bytes))
}

pub(super) async fn recv_text(
  socket: &mut WebSocket,
) -> anyhow::Result<String> {
  loop {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
      .await
      .map_err(|_| anyhow::anyhow!("握手超时"))?
      .ok_or_else(|| anyhow::anyhow!("连接关闭"))??;
    match msg {
      Message::Text(text) => return Ok(text.to_string()),
      Message::Close(_) => anyhow::bail!("连接关闭"),
      _ => continue,
    }
  }
}

pub(super) async fn send_msg(
  socket: &mut WebSocket,
  msg: &CoreMsg,
) -> anyhow::Result<()> {
  tokio::time::timeout(
    SOCKET_WRITE_TIMEOUT,
    socket.send(Message::text(serde_json::to_string(msg)?)),
  )
  .await
  .map_err(|_| anyhow::anyhow!("发送 WebSocket 消息超时"))??;
  Ok(())
}

/// 协议版本是否兼容。旧 agent（含不发这个字段的 0）只能明文连接，只接受升级请求。
pub(super) fn protocol_ok(agent: u32) -> bool {
  agent == PROTOCOL
}

/// 握手之后的收发：新 agent 全部加密；旧 agent 明文，只用于下发升级。
pub(super) enum Wire {
  Plain,
  Sealed(Sealer, Opener),
}

impl Wire {
  pub(super) fn encode(
    &mut self,
    msg: &CoreMsg,
  ) -> anyhow::Result<Message> {
    let text = serde_json::to_string(msg)?;
    Ok(match self {
      Wire::Plain => Message::text(text),
      Wire::Sealed(tx, _) => {
        Message::binary(tx.seal(text.as_bytes()))
      }
    })
  }

  /// `Ok(None)`：不是这种通道该收的帧，忽略。解密失败返回错误，调用方断开。
  pub(super) fn decode(
    &mut self,
    msg: Message,
  ) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(match (self, msg) {
      (Wire::Plain, Message::Text(t)) => Some(t.as_bytes().to_vec()),
      (Wire::Sealed(_, rx), Message::Binary(b)) => Some(rx.open(&b)?),
      _ => None,
    })
  }
}
