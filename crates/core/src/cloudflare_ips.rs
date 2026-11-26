//! Cloudflare 官方回源网段。同步只更新缓存，网关配置由 plan/apply 生效。

use std::{net::IpAddr, sync::RwLock, time::Duration};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use wharf_providers::http::{Http, limited_body};

use crate::{
  db::{self, Db},
  source_trust::is_global_unicast,
};

const SETTING: &str = "cloudflare.ips";
const EXPIRES: Duration = Duration::from_secs(24 * 3600);
const RETRY: Duration = Duration::from_secs(3600);
const TIMEOUT: Duration = Duration::from_secs(15);
const BUILTIN_V4: &[&str] = &[
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];
const BUILTIN_V6: &[&str] = &[
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

#[derive(Deserialize, Serialize)]
struct CloudflareIps {
  v4: Vec<String>,
  v6: Vec<String>,
  updated_at: i64,
}

static CACHE: RwLock<Option<CloudflareIps>> = RwLock::new(None);

impl CloudflareIps {
  fn validate(mut self) -> Result<Self, String> {
    if !(5..=100).contains(&self.v4.len())
      || !(3..=100).contains(&self.v6.len())
    {
      return Err("Cloudflare 网段数量异常".into());
    }
    for s in &mut self.v4 {
      let net = s
        .parse::<Ipv4Net>()
        .map_err(|_| "Cloudflare IPv4 网段格式异常")?
        .trunc();
      if net.prefix_len() < 8
        || !is_global_unicast(IpAddr::V4(net.network()))
      {
        return Err("Cloudflare IPv4 网段范围异常".into());
      }
      *s = net.to_string();
    }
    for s in &mut self.v6 {
      let net = s
        .parse::<Ipv6Net>()
        .map_err(|_| "Cloudflare IPv6 网段格式异常")?
        .trunc();
      if net.prefix_len() < 16
        || net.network().segments()[0] & 0xe000 != 0x2000
      {
        return Err("Cloudflare IPv6 网段范围异常".into());
      }
      *s = net.to_string();
    }
    self.v4.sort();
    self.v4.dedup();
    self.v6.sort();
    self.v6.dedup();
    if self.v4.len() < 5 || self.v6.len() < 3 {
      return Err("Cloudflare 去重后网段数量不足".into());
    }
    Ok(self)
  }
}

fn parse_and_validate(body: &[u8]) -> Result<CloudflareIps, String> {
  #[derive(Deserialize)]
  struct Response {
    success: bool,
    result: Ranges,
  }
  #[derive(Deserialize)]
  struct Ranges {
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
  }

  let response: Response = serde_json::from_slice(body)
    .map_err(|_| "Cloudflare 网段响应格式异常")?;
  if !response.success {
    return Err("Cloudflare 未返回有效网段".into());
  }
  CloudflareIps {
    v4: response.result.ipv4_cidrs,
    v6: response.result.ipv6_cidrs,
    updated_at: 0,
  }
  .validate()
}

pub fn cached_cidrs() -> Vec<String> {
  let cache = CACHE.read().unwrap_or_else(|e| e.into_inner());
  let mut cidrs: Vec<_> = match cache.as_ref() {
    Some(ips) => ips.v4.iter().chain(&ips.v6).cloned().collect(),
    None => BUILTIN_V4
      .iter()
      .chain(BUILTIN_V6)
      .map(|s| (*s).to_string())
      .collect(),
  };
  cidrs.sort();
  cidrs
}

pub async fn init(db: &Db) {
  if let Ok(Some(json)) = db.call(|c| db::setting(c, SETTING)).await
    && let Ok(ips) = serde_json::from_str::<CloudflareIps>(&json)
    && let Ok(ips) = ips.validate()
  {
    *CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some(ips);
  }
}

async fn fetch() -> Result<CloudflareIps, String> {
  let http = Http::new(TIMEOUT)
    .map_err(|_| "无法初始化 Cloudflare HTTP 客户端")?;
  let response = http
    .send(|c| c.get("https://api.cloudflare.com/client/v4/ips"))
    .await
    .map_err(|_| "连不上 Cloudflare 网段 API")?;
  if response.status() != reqwest::StatusCode::OK {
    return Err(format!(
      "Cloudflare 网段 API 返回 HTTP {}",
      response.status().as_u16()
    ));
  }
  parse_and_validate(&limited_body(response, 64 * 1024).await?)
}

async fn sync(db: &Db) -> Result<(), String> {
  let mut ips = tokio::time::timeout(TIMEOUT, fetch())
    .await
    .map_err(|_| "同步 Cloudflare 网段超时")??;
  ips.updated_at = db::now_ms();
  let json = serde_json::to_string(&ips)
    .map_err(|_| "无法编码 Cloudflare 网段")?;
  db.call(move |c| db::set_setting(c, SETTING, Some(&json)))
    .await
    .map_err(|e| e.message)?;
  *CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some(ips);
  crate::snapshot::load(db).await.map_err(|e| e.message)?;
  Ok(())
}

pub fn spawn(db: Db) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(15)).await;
    let updated_at = CACHE
      .read()
      .unwrap_or_else(|e| e.into_inner())
      .as_ref()
      .map(|ips| ips.updated_at);
    if let Some(updated_at) = updated_at {
      let age = Duration::from_millis(
        db::now_ms().saturating_sub(updated_at).max(0) as u64,
      );
      tokio::time::sleep(EXPIRES.saturating_sub(age)).await;
    }
    loop {
      let delay = match sync(&db).await {
        Ok(()) => EXPIRES,
        Err(error) => {
          tracing::warn!("{error}");
          RETRY
        }
      };
      tokio::time::sleep(delay).await;
    }
  });
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn validates_official_ranges() {
    let mut response = serde_json::json!({
      "success": true,
      "result": { "ipv4_cidrs": BUILTIN_V4, "ipv6_cidrs": BUILTIN_V6 },
    });
    let parse = |value: &serde_json::Value| {
      parse_and_validate(&serde_json::to_vec(value).unwrap())
    };
    let parsed = parse(&response).unwrap();
    assert_eq!(parsed.v4.len(), BUILTIN_V4.len());
    assert_eq!(parsed.v6.len(), BUILTIN_V6.len());
    for bad in ["0.0.0.0/0", "10.0.0.0/8"] {
      response["result"]["ipv4_cidrs"][0] = bad.into();
      assert!(parse(&response).is_err());
    }
    response["result"]["ipv4_cidrs"] =
      serde_json::json!(["203.0.113.0/24"]);
    assert!(parse(&response).is_err());
    assert_eq!(
      cached_cidrs().len(),
      BUILTIN_V4.len() + BUILTIN_V6.len()
    );
  }
}
