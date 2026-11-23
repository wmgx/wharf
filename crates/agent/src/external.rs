//! 低频获取本机出口信息和匿名镜像拉取额度。
use std::{
  net::{IpAddr, Ipv6Addr},
  time::{Duration, Instant},
};

use chrono::Utc;
use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  external::{DockerQuota, EgressInfo, Upstream},
};

const IPV6_URL: &str = "https://api-ipv6.ip.sb/ip";
const GEO_URL: &str = "https://api.ip.sb/geoip";
const DOCKER_AUTH: &str = "https://auth.docker.io/token";
const DOCKER_PREVIEW: &str = "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest";
const TTL_V6: Duration = Duration::from_secs(3600);
const TTL_GEO: Duration = Duration::from_secs(6 * 3600);
const TTL_QUOTA: Duration = Duration::from_secs(24 * 3600);

type CachedQuota = (Instant, Option<DockerQuota>);
static QUOTA: tokio::sync::Mutex<Option<CachedQuota>> =
  tokio::sync::Mutex::const_new(None);

#[derive(Default)]
pub struct EgressCache {
  info: EgressInfo,
  ipv6_at: Option<Instant>,
  geo: Option<(Instant, Option<IpAddr>)>,
}

impl EgressCache {
  pub async fn get(&mut self, ipv4: Option<String>) -> EgressInfo {
    let changed = self.info.ipv4 != ipv4;
    self.info.ipv4 = ipv4;
    let previous_ipv6 = self.info.ipv6.clone();
    if changed || self.ipv6_at.is_none_or(|at| at.elapsed() >= TTL_V6)
    {
      self.info.ipv6 = async {
        let resp = client()?
          .get(IPV6_URL)
          .send()
          .await
          .ok()?
          .error_for_status()
          .ok()?;
        let address =
          resp.text().await.ok()?.trim().parse::<Ipv6Addr>().ok()?;
        Some(address.to_string())
      }
      .await;
      self.ipv6_at = Some(Instant::now());
    }
    let ip = self
      .info
      .ipv4
      .as_deref()
      .or(self.info.ipv6.as_deref())
      .and_then(|ip| ip.parse().ok());
    if previous_ipv6 != self.info.ipv6
      || self.geo.is_none_or(|(at, previous)| {
        at.elapsed() >= TTL_GEO || previous != ip
      })
    {
      let geo = match ip {
        Some(ip) => geo_lookup(ip).await.unwrap_or_default(),
        None => Geo::default(),
      };
      self.info.asn = geo.asn.map(|n| format!("AS{n}"));
      self.info.operator =
        geo.isp.or(geo.asn_organization).or(geo.organization);
      self.info.country = geo.country;
      self.info.city = geo.city;
      self.geo = Some((Instant::now(), ip));
    }
    self.info.clone()
  }
}

#[derive(Default, Deserialize)]
struct Geo {
  asn: Option<u32>,
  asn_organization: Option<String>,
  isp: Option<String>,
  organization: Option<String>,
  country: Option<String>,
  city: Option<String>,
}

async fn geo_lookup(ip: IpAddr) -> Option<Geo> {
  client()?
    .get(format!("{GEO_URL}/{ip}"))
    .send()
    .await
    .ok()?
    .error_for_status()
    .ok()?
    .json()
    .await
    .ok()
}

fn client() -> Option<reqwest::Client> {
  reqwest::Client::builder()
    .timeout(Duration::from_secs(6))
    .redirect(reqwest::redirect::Policy::none())
    .no_proxy()
    .user_agent("wharf-agent")
    .build()
    .ok()
}

pub async fn quota() -> Option<DockerQuota> {
  let mut saved = QUOTA.lock().await;
  if let Some((at, quota)) = *saved
    && at.elapsed() < TTL_QUOTA
  {
    return quota;
  }
  let result = fetch_quota().await;
  *saved = Some((Instant::now(), result));
  result
}

async fn fetch_quota() -> Option<DockerQuota> {
  #[derive(Deserialize)]
  struct Auth {
    token: String,
  }
  let client = client()?;
  let auth: Auth = client
    .get(DOCKER_AUTH)
    .query(&[
      ("service", "registry.docker.io"),
      ("scope", "repository:ratelimitpreview/test:pull"),
    ])
    .send()
    .await
    .ok()?
    .error_for_status()
    .ok()?
    .json()
    .await
    .ok()?;
  let response = client
    .head(DOCKER_PREVIEW)
    .bearer_auth(auth.token)
    .send()
    .await
    .ok()?;
  let quota_header = |name| {
    let text = response.headers().get(name)?.to_str().ok()?;
    let (value, window) = text.split_once(";w=")?;
    Some((
      value.trim().parse::<u32>().ok()?,
      window.trim().parse::<u32>().ok()?,
    ))
  };
  let (limit, window_secs) = quota_header("ratelimit-limit")?;
  let (remaining, remaining_window) =
    quota_header("ratelimit-remaining")?;
  if limit == 0
    || window_secs == 0
    || remaining_window != window_secs
    || remaining > limit
  {
    return None;
  }
  Some(DockerQuota {
    remaining,
    limit,
    window_secs,
    checked_at: Utc::now(),
  })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RateLimit {
  None,
  TooManyRequests,
  PullQuota,
}

pub fn rate_limit(image: &str, error: &str) -> RateLimit {
  let error = error.to_ascii_lowercase();
  let (registry, _, _) = crate::docker::split_image(image);
  if !matches!(
    registry.as_str(),
    "docker.io" | "registry-1.docker.io" | "index.docker.io"
  ) && !error.contains("registry-1.docker.io/")
    && !error.contains("docker.com/increase-rate-limit")
  {
    return RateLimit::None;
  }
  if error.contains("pull rate limit")
    || error.contains("docker.com/increase-rate-limit")
  {
    RateLimit::PullQuota
  } else if error.contains("toomanyrequests")
    || error.contains("429 too many requests")
    || error.contains("http 429")
    || error.contains("status code 429")
  {
    RateLimit::TooManyRequests
  } else {
    RateLimit::None
  }
}

pub fn image_error(
  mut error: ApiError,
  image: &str,
  rate: RateLimit,
) -> ApiError {
  let (registry, _, _) = crate::docker::split_image(image);
  error.upstream = match registry.as_str() {
    "docker.io" | "registry-1.docker.io" | "index.docker.io" => {
      Some(Upstream::DockerHub)
    }
    "ghcr.io" => Some(Upstream::GitHub),
    _ => None,
  };
  if rate == RateLimit::PullQuota
    || rate == RateLimit::TooManyRequests
  {
    error.upstream = Some(Upstream::DockerHub);
    error.message = match rate {
      RateLimit::PullQuota => {
        "Docker Hub 拉取次数用完了（匿名按 IP 计）".into()
      }
      _ => "Docker Hub 请求被限流（HTTP 429）".into(),
    };
    let mut hint = "给这台机器设镜像源（wharf server set <server> --mirror docker.io=<镜像源>），或等额度恢复".to_string();
    if let Some((at, Some(quota))) =
      QUOTA.try_lock().ok().and_then(|r| *r)
      && at.elapsed()
        <= Duration::from_secs(u64::from(quota.window_secs))
    {
      hint.push_str(&format!(
        "。最近测得剩余 {} / {}（{} UTC）",
        quota.remaining,
        quota.limit,
        quota.checked_at.format("%Y-%m-%d %H:%M")
      ));
    }
    error.hint = Some(hint);
  }
  error
}

pub fn github_error(
  mut error: ApiError,
  repo: &str,
  token: Option<&str>,
) -> ApiError {
  if let Some(token) = token.filter(|t| !t.is_empty()) {
    error.message = error.message.replace(token, "***");
  }
  if error.code != ErrorCode::Cancelled
    && reqwest::Url::parse(repo)
      .ok()
      .is_some_and(|u| u.host_str() == Some("github.com"))
  {
    error.upstream = Some(Upstream::GitHub);
  }
  error
}

pub fn wrangler_progress(
  ctx: &crate::exec::Ctx,
  token: &str,
) -> crate::exec::Ctx {
  let mut ctx = ctx.clone();
  if let Some(progress) = ctx.progress.take() {
    let token = token.to_string();
    ctx.progress = Some(std::sync::Arc::new(move |line| {
      progress(if token.is_empty() {
        line
      } else {
        line.replace(&token, "***")
      });
    }));
  }
  ctx
}

pub fn wrangler_error(mut error: ApiError, token: &str) -> ApiError {
  if !token.is_empty() {
    error.message = error.message.replace(token, "***");
  }
  if error.message.contains("wrangler 发布失败") {
    error.upstream = Some(Upstream::Cloudflare);
  }
  error
}

pub fn build_error(error: ApiError, detail: &str) -> ApiError {
  if detail.contains("docker.io/")
    || detail.contains("docker.com/increase-rate-limit")
  {
    image_error(
      error,
      "docker.io/library/placeholder",
      rate_limit("docker.io/library/placeholder", detail),
    )
  } else if detail.contains("ghcr.io/") {
    image_error(error, "ghcr.io/placeholder", RateLimit::None)
  } else {
    error
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn docker_hub_rate_limit_messages() {
    let image = "library/alpine:latest";
    assert_eq!(
      rate_limit(
        image,
        "toomanyrequests: You have reached your pull rate limit."
      ),
      RateLimit::PullQuota
    );
    assert_eq!(
      rate_limit(image, "429 Too Many Requests"),
      RateLimit::TooManyRequests
    );
    assert_eq!(
      rate_limit(image, "dial tcp: i/o timeout"),
      RateLimit::None
    );
    assert_eq!(
      rate_limit("ghcr.io/test/app", "429 Too Many Requests"),
      RateLimit::None
    );
  }
}
