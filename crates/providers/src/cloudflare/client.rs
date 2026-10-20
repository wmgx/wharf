//! Thin Cloudflare v4 HTTP client.
//!
//! - 25s timeout, redirects disabled.
//! - Only GET is retried (429 / 5xx, honoring `Retry-After`, max 10s).
//!   Mutations are never replayed: the next plan observes the real state.
//! - Provider response bodies and the token never appear in errors.
//! - No `Debug` impl, the token must not leak through formatting.

use std::time::Duration;

use reqwest::{Client, Method, StatusCode};
use serde_json::Value;

use crate::error::{ProviderError, code, redact};

type Result<T> = std::result::Result<T, ProviderError>;

pub struct CloudflareClient {
  client: Client,
  token: String,
  #[cfg(test)]
  base_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
  pub id: String,
  pub name: String,
}

fn malformed(detail: &str) -> ProviderError {
  ProviderError::new(
    code::PROVIDER_RESPONSE,
    "Provider returned an invalid response",
  )
  .with_detail(detail)
}

/// Provider identifiers are interpolated into URL paths.
pub fn segment(value: &str) -> Result<&str> {
  if value.is_empty()
    || !value
      .bytes()
      .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
  {
    return Err(ProviderError::invalid(
      "Invalid provider object identifier",
    ));
  }
  Ok(value)
}

impl CloudflareClient {
  pub fn new(token: &str) -> Result<Self> {
    if token.is_empty() {
      return Err(ProviderError::new(
        code::AUTH_FAILED,
        "Account token is empty",
      ));
    }
    let client = Client::builder()
      .timeout(Duration::from_secs(25))
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .map_err(|e| {
        ProviderError::internal(redact(&e.to_string(), token))
      })?;
    Ok(Self {
      client,
      token: token.to_string(),
      #[cfg(test)]
      base_url: None,
    })
  }

  fn endpoint(&self, path: &str) -> String {
    #[cfg(test)]
    if let Some(base) = &self.base_url {
      return format!("{base}{path}");
    }
    format!("https://api.cloudflare.com/client/v4{path}")
  }

  async fn request(
    &self,
    method: Method,
    path: &str,
    body: Option<&Value>,
  ) -> Result<Value> {
    let mut attempt = 0u32;
    loop {
      let mut req = self
        .client
        .request(method.clone(), self.endpoint(path))
        .bearer_auth(&self.token);
      if let Some(body) = body {
        req = req.json(body);
      }
      let response = req.send().await.map_err(|e| {
        let timed_out = e.is_timeout();
        let detail =
          redact(&e.without_url().to_string(), &self.token);
        if timed_out {
          ProviderError::new(
            code::TIMEOUT,
            "Provider request timed out",
          )
          .retryable()
          .with_detail(detail)
        } else {
          ProviderError::new(
            code::PROVIDER_UNAVAILABLE,
            "Provider request failed",
          )
          .retryable()
          .with_detail(detail)
        }
      })?;
      let status = response.status();
      if method == Method::GET
        && attempt < 2
        && (status == StatusCode::TOO_MANY_REQUESTS
          || status.is_server_error())
      {
        let delay = response
          .headers()
          .get("retry-after")
          .and_then(|v| v.to_str().ok())
          .and_then(|v| v.parse::<u64>().ok())
          .unwrap_or(1 << attempt)
          .min(10);
        attempt += 1;
        tokio::time::sleep(Duration::from_secs(delay)).await;
        continue;
      }
      if !status.is_success() {
        let detail =
          format!("HTTP {} on {method} {path}", status.as_u16());
        return Err(
          match status.as_u16() {
            401 | 403 => ProviderError::new(
              code::AUTH_FAILED,
              "Provider authorization failed",
            ),
            404 => ProviderError::new(
              code::PROVIDER_REJECTED,
              "Provider object was not found",
            ),
            429 => ProviderError::new(
              code::RATE_LIMITED,
              "Provider rate limit reached",
            )
            .retryable(),
            500..=599 => ProviderError::new(
              code::PROVIDER_UNAVAILABLE,
              "Provider is unavailable",
            )
            .retryable(),
            _ => ProviderError::new(
              code::PROVIDER_REJECTED,
              "Provider rejected the request",
            ),
          }
          .with_detail(detail),
        );
      }
      let data: Value = response
        .json()
        .await
        .map_err(|e| malformed(&e.without_url().to_string()))?;
      if data["success"] != true {
        return Err(
          ProviderError::new(
            code::PROVIDER_REJECTED,
            "Provider rejected the operation",
          )
          .with_detail(format!("success=false on {method} {path}")),
        );
      }
      return Ok(data);
    }
  }

  /// True if the error is a provider 404 (`GET` of a missing object).
  pub fn is_not_found(error: &ProviderError) -> bool {
    error
      .detail
      .as_deref()
      .is_some_and(|d| d.starts_with("HTTP 404 "))
  }

  /// All zones the token can access.
  pub async fn list_zones(&self) -> Result<Vec<Zone>> {
    let mut zones = Vec::new();
    for page in 1..=200 {
      let data = self
        .request(
          Method::GET,
          &format!("/zones?per_page=50&page={page}"),
          None,
        )
        .await?;
      let items = data["result"]
        .as_array()
        .ok_or_else(|| malformed("zones result is not an array"))?;
      for item in items {
        if let (Some(id), Some(name)) =
          (item["id"].as_str(), item["name"].as_str())
        {
          zones.push(Zone {
            id: id.to_string(),
            name: name.to_ascii_lowercase(),
          });
        }
      }
      if items.len() < 50
        || data["result_info"]["total_pages"]
          .as_u64()
          .is_some_and(|n| page >= n)
      {
        return Ok(zones);
      }
    }
    Err(
      ProviderError::new(
        code::PROVIDER_RESPONSE,
        "Zone pagination limit exceeded",
      )
      .with_detail("more than 200 pages of zones"),
    )
  }

  /// DNS records named exactly `hostname`.
  pub async fn list_dns(
    &self,
    zone: &str,
    hostname: &str,
  ) -> Result<Vec<Value>> {
    let zone = segment(zone)?;
    let mut records = Vec::new();
    for page in 1..=1000 {
      let data = self
        .request(
          Method::GET,
          &format!(
            "/zones/{zone}/dns_records?name={}&page={page}&per_page=100",
            urlencoding::encode(hostname)
          ),
          None,
        )
        .await?;
      let items = data["result"]
        .as_array()
        .ok_or_else(|| malformed("dns result is not an array"))?;
      // Enforce exact host matching locally even if provider filtering changes.
      records.extend(
        items
          .iter()
          .filter(|record| {
            record["name"].as_str().is_some_and(|name| {
              name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(hostname.trim_end_matches('.'))
            })
          })
          .cloned(),
      );
      if items.len() < 100
        || data["result_info"]["total_pages"]
          .as_u64()
          .is_some_and(|n| page >= n)
      {
        return Ok(records);
      }
    }
    Err(
      ProviderError::new(
        code::PROVIDER_RESPONSE,
        "DNS pagination limit exceeded",
      )
      .with_detail("more than 1000 pages of dns records"),
    )
  }

  /// `None` if the record doesn't exist.
  pub async fn get_dns(
    &self,
    zone: &str,
    id: &str,
  ) -> Result<Option<Value>> {
    let path = format!(
      "/zones/{}/dns_records/{}",
      segment(zone)?,
      segment(id)?
    );
    match self.request(Method::GET, &path, None).await {
      Ok(data) => Ok(Some(data["result"].clone())),
      Err(e) if Self::is_not_found(&e) => Ok(None),
      Err(e) => Err(e),
    }
  }

  pub async fn create_dns(
    &self,
    zone: &str,
    body: &Value,
  ) -> Result<Value> {
    let path = format!("/zones/{}/dns_records", segment(zone)?);
    Ok(
      self.request(Method::POST, &path, Some(body)).await?["result"]
        .clone(),
    )
  }

  /// PATCH only changes the given fields, so unmanaged fields survive.
  pub async fn patch_dns(
    &self,
    zone: &str,
    id: &str,
    body: &Value,
  ) -> Result<Value> {
    let path = format!(
      "/zones/{}/dns_records/{}",
      segment(zone)?,
      segment(id)?
    );
    Ok(
      self.request(Method::PATCH, &path, Some(body)).await?["result"]
        .clone(),
    )
  }

  pub async fn delete_dns(&self, zone: &str, id: &str) -> Result<()> {
    let path = format!(
      "/zones/{}/dns_records/{}",
      segment(zone)?,
      segment(id)?
    );
    self.request(Method::DELETE, &path, None).await?;
    Ok(())
  }

  async fn list_pages(
    &self,
    path: &str,
    what: &str,
  ) -> Result<Vec<Value>> {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut all = Vec::new();
    for page in 1..=200 {
      let data = self
        .request(
          Method::GET,
          &format!("{path}{sep}per_page=50&page={page}"),
          None,
        )
        .await?;
      let items = data["result"].as_array().ok_or_else(|| {
        malformed(&format!("{what} result is not an array"))
      })?;
      all.extend(items.iter().cloned());
      if items.len() < 50
        || data["result_info"]["total_pages"]
          .as_u64()
          .is_some_and(|n| page >= n)
      {
        return Ok(all);
      }
    }
    Err(
      ProviderError::new(
        code::PROVIDER_RESPONSE,
        "Pagination limit exceeded",
      )
      .with_detail(format!("more than 200 pages of {what}")),
    )
  }

  /// token 能访问的账户 `(id, name)`。token 没有账户读取权限时 `/accounts`
  /// 返回空，所以再从可见 zone 的所属账户推出来。
  pub async fn list_accounts(&self) -> Result<Vec<(String, String)>> {
    let listed = self.list_pages("/accounts", "accounts").await;
    let zones = self.list_pages("/zones", "zones").await;
    let mut accounts: Vec<(String, String)> = Vec::new();
    let mut add = |a: &Value| {
      let Some(id) = a["id"].as_str() else { return };
      if !accounts.iter().any(|(existing, _)| existing == id) {
        accounts.push((
          id.to_string(),
          a["name"].as_str().unwrap_or_default().to_string(),
        ));
      }
    };
    if let Ok(listed) = &listed {
      listed.iter().for_each(&mut add);
    }
    if let Ok(zones) = &zones {
      zones.iter().for_each(|z| add(&z["account"]));
    }
    match (accounts.is_empty(), listed, zones) {
      (false, _, _) => Ok(accounts),
      (true, Err(e), _) | (true, _, Err(e)) => Err(e),
      (true, Ok(_), Ok(_)) => Ok(accounts),
    }
  }

  /// 账户里没删除的隧道（原始对象）。
  pub async fn list_tunnels(
    &self,
    account: &str,
  ) -> Result<Vec<Value>> {
    self
      .list_pages(
        &format!(
          "/accounts/{}/cfd_tunnel?is_deleted=false",
          segment(account)?
        ),
        "tunnels",
      )
      .await
  }

  pub async fn put_tunnel_config(
    &self,
    account: &str,
    tunnel: &str,
    config: &Value,
  ) -> Result<()> {
    let path = format!(
      "/accounts/{}/cfd_tunnel/{}/configurations",
      segment(account)?,
      segment(tunnel)?
    );
    self
      .request(
        Method::PUT,
        &path,
        Some(&serde_json::json!({ "config": config })),
      )
      .await?;
    Ok(())
  }

  /// 创建由 Cloudflare 远程管理配置的隧道，返回 id。
  pub async fn create_tunnel(
    &self,
    account: &str,
    name: &str,
  ) -> Result<String> {
    let path = format!("/accounts/{}/cfd_tunnel", segment(account)?);
    let data = self
      .request(
        Method::POST,
        &path,
        Some(&serde_json::json!({
          "name": name,
          "config_src": "cloudflare",
        })),
      )
      .await?;
    data["result"]["id"]
      .as_str()
      .map(str::to_string)
      .ok_or_else(|| malformed("created tunnel has no id"))
  }

  /// 连接器的 token。不要打印返回值。
  pub async fn tunnel_token(
    &self,
    account: &str,
    tunnel: &str,
  ) -> Result<String> {
    let path = format!(
      "/accounts/{}/cfd_tunnel/{}/token",
      segment(account)?,
      segment(tunnel)?
    );
    let data = self.request(Method::GET, &path, None).await?;
    data["result"]
      .as_str()
      .filter(|t| !t.is_empty())
      .map(str::to_string)
      .ok_or_else(|| malformed("tunnel token is not a string"))
  }

  /// 隧道状态：healthy / degraded / down / inactive。
  pub async fn tunnel_status(
    &self,
    account: &str,
    tunnel: &str,
  ) -> Result<String> {
    let path = format!(
      "/accounts/{}/cfd_tunnel/{}",
      segment(account)?,
      segment(tunnel)?
    );
    let data = self.request(Method::GET, &path, None).await?;
    Ok(
      data["result"]["status"]
        .as_str()
        .unwrap_or("inactive")
        .to_string(),
    )
  }

  /// 先清掉已经不在的连接器留下的连接，再删除隧道。隧道不存在也算成功。
  pub async fn delete_tunnel(
    &self,
    account: &str,
    tunnel: &str,
  ) -> Result<()> {
    let base = format!(
      "/accounts/{}/cfd_tunnel/{}",
      segment(account)?,
      segment(tunnel)?
    );
    for path in [format!("{base}/connections"), base] {
      match self.request(Method::DELETE, &path, None).await {
        Ok(_) => {}
        Err(e) if Self::is_not_found(&e) => {}
        Err(e) => return Err(e),
      }
    }
    Ok(())
  }
}

#[cfg(test)]
mod http_tests;
