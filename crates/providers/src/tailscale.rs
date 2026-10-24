//! Tailscale API：用 OAuth 客户端现开一次性加入密钥（design 2.10）。
//!
//! - OAuth 客户端要有 Auth Keys 写权限，并允许打 `tag`；通过 OAuth 开的密钥必须带标签。
//! - 密钥只能用一次、预先批准、1 小时内有效。
//! - 凭据和密钥不出现在错误里。

use std::time::Duration;

use reqwest::Client;
use serde_json::{Value, json};

use crate::error::{ProviderError, code, redact};

const API: &str = "https://api.tailscale.com/api/v2";
const KEY_TTL_SECS: u64 = 3600;

/// `credential` 是 `client_id:client_secret`。返回一个只能用一次的加入密钥。
pub async fn auth_key(
  credential: &str,
  tag: &str,
  description: &str,
) -> Result<String, ProviderError> {
  let (id, secret) = credential.split_once(':').ok_or_else(|| {
    ProviderError::invalid(
      "Tailscale 凭据格式不对，应为 client_id:client_secret",
    )
  })?;
  let client = Client::builder()
    .timeout(Duration::from_secs(25))
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .map_err(|e| {
      ProviderError::internal(redact(&e.to_string(), secret))
    })?;
  let fail = |e: reqwest::Error| {
    ProviderError::new(
      code::PROVIDER_UNAVAILABLE,
      "连不上 Tailscale API",
    )
    .retryable()
    .with_detail(redact(&e.to_string(), secret))
  };

  let resp = client
    .post(format!("{API}/oauth/token"))
    .header("content-type", "application/x-www-form-urlencoded")
    .body(format!(
      "client_id={}&client_secret={}",
      urlencoding::encode(id),
      urlencoding::encode(secret)
    ))
    .send()
    .await
    .map_err(fail)?;
  if !resp.status().is_success() {
    return Err(ProviderError::new(
      code::AUTH_FAILED,
      format!(
        "Tailscale OAuth 客户端认证失败（HTTP {}）",
        resp.status().as_u16()
      ),
    ));
  }
  let body: Value = resp.json().await.map_err(fail)?;
  let token = body["access_token"].as_str().ok_or_else(|| {
    ProviderError::new(
      code::PROVIDER_RESPONSE,
      "Tailscale 没有返回 access_token",
    )
  })?;

  let resp = client
    .post(format!("{API}/tailnet/-/keys"))
    .bearer_auth(token)
    .json(&json!({
      "capabilities": { "devices": { "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": true,
        "tags": [tag],
      }}},
      "expirySeconds": KEY_TTL_SECS,
      "description": description,
    }))
    .send()
    .await
    .map_err(fail)?;
  let status = resp.status();
  if !status.is_success() {
    let text = resp.text().await.unwrap_or_default();
    let reason = serde_json::from_str::<Value>(&text)
      .ok()
      .and_then(|v| v["message"].as_str().map(str::to_string))
      .unwrap_or_default();
    return Err(ProviderError::new(
      code::PROVIDER_REJECTED,
      format!(
        "Tailscale 拒绝创建加入密钥（HTTP {}）{reason}",
        status.as_u16()
      ),
    ));
  }
  let body: Value = resp.json().await.map_err(fail)?;
  body["key"].as_str().map(str::to_string).ok_or_else(|| {
    ProviderError::new(
      code::PROVIDER_RESPONSE,
      "Tailscale 没有返回密钥",
    )
  })
}
