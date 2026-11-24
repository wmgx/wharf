//! Tailscale API：用 OAuth 客户端现开一次性加入密钥（design 2.10）。
//!
//! - OAuth 客户端要有 Auth Keys 写权限，并允许打 `tag`；通过 OAuth 开的密钥必须带标签。
//! - 密钥只能用一次、预先批准、1 小时内有效。
//! - 凭据和密钥不出现在错误里。

use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{ProviderError, code};

const API: &str = "https://api.tailscale.com/api/v2";
const KEY_TTL_SECS: u64 = 3600;

/// `credential` 是 `client_id:client_secret`。返回一个只能用一次的加入密钥。
pub async fn auth_key(
  credential: &str,
  tag: &str,
  description: &str,
) -> Result<String, ProviderError> {
  let client = crate::http::Http::new(Duration::from_secs(25))
    .map_err(|_| {
      ProviderError::internal("无法初始化 Tailscale HTTP 客户端")
    })?;
  let fail = |_: reqwest::Error| {
    ProviderError::new(
      code::PROVIDER_UNAVAILABLE,
      "连不上 Tailscale API",
    )
    .retryable()
  };

  let token = access_token(credential).await.map_err(|e| {
    ProviderError::new(
      if e.denied() {
        code::AUTH_FAILED
      } else {
        code::PROVIDER_UNAVAILABLE
      },
      e.message(),
    )
  })?;

  let body = json!({
    "capabilities": { "devices": { "create": {
      "reusable": false,
      "ephemeral": false,
      "preauthorized": true,
      "tags": [tag],
    }}},
    "expirySeconds": KEY_TTL_SECS,
    "description": description,
  });
  let resp = client
    .send(|c| {
      c.post(format!("{API}/tailnet/-/keys"))
        .bearer_auth(&token)
        .json(&body)
    })
    .await
    .map_err(fail)?;
  let status = resp.status();
  if !status.is_success() {
    return Err(ProviderError::new(
      code::PROVIDER_REJECTED,
      format!(
        "Tailscale 拒绝创建加入密钥（HTTP {}）",
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

#[derive(Debug, Clone, Copy)]
pub enum ReadError {
  InvalidCredential,
  Http(reqwest::StatusCode),
  Unavailable,
}

impl ReadError {
  pub fn denied(self) -> bool {
    matches!(
      self,
      Self::InvalidCredential
        | Self::Http(
          reqwest::StatusCode::BAD_REQUEST
            | reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
        )
    )
  }

  /// Tailscale OAuth 对缺 scope 的只读接口可能返回 404，和 401/403 一样按缺权限处理。
  pub fn missing_scope(self) -> bool {
    matches!(
      self,
      Self::Http(
        reqwest::StatusCode::UNAUTHORIZED
          | reqwest::StatusCode::FORBIDDEN
          | reqwest::StatusCode::NOT_FOUND
      )
    )
  }

  pub fn message(self) -> String {
    match self {
      Self::InvalidCredential => {
        "Tailscale 凭据格式应为 client_id:client_secret".into()
      }
      Self::Http(status) => {
        format!("Tailscale API 返回 HTTP {}", status.as_u16())
      }
      Self::Unavailable => "Tailscale API 查不到".into(),
    }
  }
}

fn read_client() -> Result<crate::http::Http, ReadError> {
  crate::http::Http::new(Duration::from_secs(10))
    .map_err(|_| ReadError::Unavailable)
}

fn checked(
  resp: reqwest::Response,
) -> Result<reqwest::Response, ReadError> {
  if resp.status().is_success() {
    Ok(resp)
  } else {
    Err(ReadError::Http(resp.status()))
  }
}

pub async fn access_token(
  credential: &str,
) -> Result<String, ReadError> {
  let (id, secret) = credential
    .split_once(':')
    .filter(|(id, secret)| !id.is_empty() && !secret.is_empty())
    .ok_or(ReadError::InvalidCredential)?;
  let client = read_client()?;
  let resp = client
    .send(|c| {
      c.post(format!("{API}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
          "client_id={}&client_secret={}",
          urlencoding::encode(id),
          urlencoding::encode(secret)
        ))
    })
    .await
    .map_err(|_| ReadError::Unavailable)?;
  let body: Value = checked(resp)?
    .json()
    .await
    .map_err(|_| ReadError::Unavailable)?;
  body["access_token"]
    .as_str()
    .map(str::to_string)
    .ok_or(ReadError::Unavailable)
}

pub async fn devices(token: &str) -> Result<Value, ReadError> {
  let resp = read_client()?
    .send(|c| {
      c.get(format!("{API}/tailnet/-/devices")).bearer_auth(token)
    })
    .await
    .map_err(|_| ReadError::Unavailable)?;
  let data: Value = checked(resp)?
    .json()
    .await
    .map_err(|_| ReadError::Unavailable)?;
  if !data["devices"].is_array() {
    return Err(ReadError::Unavailable);
  }
  Ok(data)
}

pub async fn policy(
  token: &str,
) -> Result<(String, Option<String>), ReadError> {
  let resp = read_client()?
    .send(|c| {
      c.get(format!("{API}/tailnet/-/acl"))
        .bearer_auth(token)
        .header("accept", "application/hujson")
    })
    .await
    .map_err(|_| ReadError::Unavailable)?;
  let resp = checked(resp)?;
  let modified = resp
    .headers()
    .get("last-modified")
    .and_then(|v| v.to_str().ok())
    .map(str::to_string);
  let raw = resp.text().await.map_err(|_| ReadError::Unavailable)?;
  Ok((raw, modified))
}
