//! 通知：把事件推到一个地方。只在状态变化时发（成功 → 失败、失败 → 恢复），不做告警规则。
//!
//! 渠道从密钥里读，有哪个就用哪个；以后加渠道就是 [Channel] 多一种。
//! - 飞书群自定义机器人：`NOTIFY_FEISHU_WEBHOOK`，开了签名校验时再设 `NOTIFY_FEISHU_SECRET`。

use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{db, state::AppState};

pub const FEISHU_WEBHOOK: &str = "NOTIFY_FEISHU_WEBHOOK";
pub const FEISHU_SECRET: &str = "NOTIFY_FEISHU_SECRET";
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Event {
  /// 例如"定时任务 sign 失败"。
  pub title: String,
  pub body: String,
}

enum Channel {
  Feishu { url: String, secret: Option<String> },
}

async fn channels(
  state: &AppState,
) -> Result<Vec<Channel>, ApiError> {
  let secrets = state.db.call(|c| db::secrets(c)).await?;
  let get = |n: &str| {
    secrets
      .get(n)
      .map(|v| v.trim().to_string())
      .filter(|v| !v.is_empty())
  };
  Ok(
    get(FEISHU_WEBHOOK)
      .map(|url| Channel::Feishu {
        url,
        secret: get(FEISHU_SECRET),
      })
      .into_iter()
      .collect(),
  )
}

/// 发给所有已配置的渠道。没有配置渠道时返回错误，带上怎么配。
pub async fn send(
  state: &AppState,
  event: &Event,
) -> Result<(), ApiError> {
  let channels = channels(state).await?;
  if channels.is_empty() {
    return Err(ApiError::invalid("没有配置通知渠道").with_hint(
      format!(
        "设置密钥 {FEISHU_WEBHOOK}（飞书群机器人的 Webhook 地址）"
      ),
    ));
  }
  let client = reqwest::Client::builder()
    .timeout(TIMEOUT)
    .build()
    .map_err(|e| ApiError::internal(format!("HTTP 客户端：{e}")))?;
  for ch in &channels {
    match ch {
      Channel::Feishu { url, secret } => {
        feishu(&client, url, secret.as_deref(), event).await?
      }
    }
  }
  Ok(())
}

/// 状态变化时才发：`key` 上次的结果存在设置 `notify.state.<key>` 里。
/// 第一次就成功不发；发送失败只记日志，不影响调用方。
pub async fn on_result(
  state: &AppState,
  key: &str,
  ok: bool,
  event: Event,
) {
  let setting = format!("notify.state.{key}");
  let now = if ok { "ok" } else { "fail" };
  let prev = state
    .db
    .call(move |c| {
      let prev = db::setting(c, &setting)?;
      db::set_setting(c, &setting, Some(now))?;
      Ok(prev)
    })
    .await;
  let changed = match prev.as_ref().map(|p| p.as_deref()) {
    Ok(Some(p)) => p != now,
    Ok(None) => !ok,
    Err(_) => false,
  };
  if !changed {
    return;
  }
  match send(state, &event).await {
    Ok(()) => {}
    Err(e) if channels(state).await.is_ok_and(|c| c.is_empty()) => {
      tracing::debug!("没有通知渠道，跳过：{}", e.message)
    }
    Err(e) => tracing::warn!("发送通知失败：{}", e.message),
  }
}

/// `POST /api/notify/test`：发一条测试消息。
pub async fn test(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
) -> crate::api::ApiResult<serde_json::Value> {
  auth.require(wharf_api_types::view::Perm::Admin)?;
  send(
    &s,
    &Event {
      title: "测试消息".into(),
      body: "通知渠道配置正确。".into(),
    },
  )
  .await?;
  Ok(axum::Json(serde_json::json!({ "ok": true })))
}

async fn feishu(
  client: &reqwest::Client,
  url: &str,
  secret: Option<&str>,
  event: &Event,
) -> Result<(), ApiError> {
  let text = format!("【Wharf】{}\n{}", event.title, event.body);
  let mut body = serde_json::json!({
    "msg_type": "text",
    "content": { "text": text },
  });
  if let Some(secret) = secret {
    let ts = chrono::Utc::now().timestamp();
    body["timestamp"] = ts.to_string().into();
    body["sign"] = feishu_sign(ts, secret).into();
  }
  let resp =
    client.post(url).json(&body).send().await.map_err(|e| {
      ApiError::new(
        ErrorCode::Provider,
        format!("请求飞书失败：{}", e.without_url()),
      )
    })?;
  let status = resp.status();
  let v: serde_json::Value = resp.json().await.unwrap_or_default();
  let code = v["code"]
    .as_i64()
    .or(v["StatusCode"].as_i64())
    .unwrap_or(-1);
  if !status.is_success() || code != 0 {
    return Err(
      ApiError::new(
        ErrorCode::Provider,
        format!(
          "飞书返回 {status}：{}",
          v["msg"].as_str().unwrap_or("")
        ),
      )
      .with_hint(
        "检查 Webhook 地址；机器人开了签名校验时要设签名密钥",
      ),
    );
  }
  Ok(())
}

/// 飞书签名：以 `timestamp + "\n" + 密钥` 为 key，对空串做 HMAC-SHA256，再 base64。
fn feishu_sign(ts: i64, secret: &str) -> String {
  let key = format!("{ts}\n{secret}");
  base64::engine::general_purpose::STANDARD
    .encode(hmac_sha256(key.as_bytes(), b""))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
  const BLOCK: usize = 64;
  let mut k = [0u8; BLOCK];
  if key.len() > BLOCK {
    k[..32].copy_from_slice(&Sha256::digest(key));
  } else {
    k[..key.len()].copy_from_slice(key);
  }
  let pad = |b: u8| k.map(|x| x ^ b);
  let inner = Sha256::new()
    .chain_update(pad(0x36))
    .chain_update(msg)
    .finalize();
  Sha256::new()
    .chain_update(pad(0x5c))
    .chain_update(inner)
    .finalize()
    .into()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hmac_matches_rfc4231() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String =
      mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
      hex,
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
  }
}
