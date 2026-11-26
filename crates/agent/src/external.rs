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

/// 公网 IPv6 探测地址：国内能直连的放前面，海外兜底放后面。
const IPV6_URLS: &[&str] = &[
  "https://6.ipw.cn",
  "https://api-ipv6.ip.sb/ip",
  "https://api6.ipify.org",
];
/// 归属查询接口：
/// - api.ip.sb：免密钥、HTTPS、无公开硬限额（海外稳定，国内常超时）
/// - ipwho.is：免密钥、HTTPS、免费 1,000 次/天（按 IP，国内可直连）
/// - ip-api.com：免密钥、HTTP、免费 45 次/分钟（按 IP、限非商业，国内可直连）
const GEO_IP_SB: &str = "https://api.ip.sb/geoip";
const GEO_IP_WHOIS: &str = "https://ipwho.is";
const GEO_IP_API: &str = "http://ip-api.com/json";
const DOCKER_AUTH: &str = "https://auth.docker.io/token";
const DOCKER_PREVIEW: &str = "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest";
const TTL_V6: Duration = Duration::from_secs(3600);
const TTL_GEO: Duration = Duration::from_secs(6 * 3600);
const TTL_GEO_RETRY: Duration = Duration::from_secs(15 * 60);
const TTL_QUOTA: Duration = Duration::from_secs(24 * 3600);
const TTL_QUOTA_RETRY: Duration = Duration::from_secs(3600);

type CachedQuota = (Instant, DockerQuota);
static QUOTA: tokio::sync::Mutex<Option<CachedQuota>> =
  tokio::sync::Mutex::const_new(None);

#[derive(Default)]
pub struct EgressCache {
  info: EgressInfo,
  ipv6_at: Option<Instant>,
  geo: Option<(Instant, Option<IpAddr>, bool)>,
}

impl EgressCache {
  pub async fn get(&mut self, ipv4: Option<String>) -> EgressInfo {
    let changed = self.info.ipv4 != ipv4;
    self.info.ipv4 = ipv4;
    let previous_ipv6 = self.info.ipv6.clone();
    if changed || self.ipv6_at.is_none_or(|at| at.elapsed() >= TTL_V6)
    {
      self.info.ipv6 = match client() {
        Some(c) => detect_ipv6_from(&c, IPV6_URLS).await,
        None => None,
      };
      self.ipv6_at = Some(Instant::now());
    }
    let ip = self
      .info
      .ipv4
      .as_deref()
      .or(self.info.ipv6.as_deref())
      .and_then(|ip| ip.parse().ok());
    if previous_ipv6 != self.info.ipv6
      || self.geo.is_none_or(|(at, previous, ok)| {
        let ttl = if ok { TTL_GEO } else { TTL_GEO_RETRY };
        at.elapsed() >= ttl || previous != ip
      })
    {
      let looked_up = match ip {
        Some(ip) => geo_lookup(ip).await,
        None => None,
      };
      let ok = looked_up.is_some();
      let geo = looked_up.unwrap_or_default();
      self.info.asn = geo.asn;
      self.info.operator = geo.operator;
      self.info.country = geo.country;
      self.info.city = geo.city;
      self.geo = Some((Instant::now(), ip, ok || ip.is_none()));
    }
    self.info.clone()
  }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Geo {
  asn: Option<String>,
  operator: Option<String>,
  country: Option<String>,
  city: Option<String>,
}

impl Geo {
  fn is_empty(&self) -> bool {
    self.asn.is_none()
      && self.operator.is_none()
      && self.country.is_none()
      && self.city.is_none()
  }
}

#[derive(Clone, Copy)]
enum GeoProvider {
  Sb,
  WhoIs,
  Api,
}

fn non_empty(value: Option<String>) -> Option<String> {
  value.and_then(|s| {
    let trimmed = s.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
  })
}

fn first_non_empty(
  values: impl IntoIterator<Item = Option<String>>,
) -> Option<String> {
  values.into_iter().find_map(non_empty)
}

fn parse_as_field(
  raw: Option<String>,
) -> (Option<String>, Option<String>) {
  let Some(raw) = non_empty(raw) else {
    return (None, None);
  };
  let mut parts = raw.splitn(2, char::is_whitespace);
  let first = parts.next().unwrap_or_default();
  let rest = parts.next().map(str::trim).filter(|s| !s.is_empty());
  if first.strip_prefix("AS").is_some_and(|digits| {
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
  }) {
    (Some(first.to_string()), rest.map(str::to_string))
  } else {
    (None, Some(raw))
  }
}

fn parse_geo(provider: GeoProvider, bytes: &[u8]) -> Option<Geo> {
  let geo = match provider {
    GeoProvider::Sb => {
      #[derive(Deserialize)]
      struct Resp {
        asn: Option<u32>,
        asn_organization: Option<String>,
        isp: Option<String>,
        organization: Option<String>,
        country: Option<String>,
        city: Option<String>,
      }
      let r: Resp = serde_json::from_slice(bytes).ok()?;
      Geo {
        asn: r.asn.filter(|&n| n > 0).map(|n| format!("AS{n}")),
        operator: first_non_empty([
          r.isp,
          r.asn_organization,
          r.organization,
        ]),
        country: non_empty(r.country),
        city: non_empty(r.city),
      }
    }
    GeoProvider::WhoIs => {
      #[derive(Deserialize)]
      struct Conn {
        asn: Option<u32>,
        isp: Option<String>,
        org: Option<String>,
      }
      #[derive(Deserialize)]
      struct Resp {
        success: bool,
        country: Option<String>,
        city: Option<String>,
        connection: Option<Conn>,
      }
      let r: Resp = serde_json::from_slice(bytes).ok()?;
      if !r.success {
        return None;
      }
      let (asn, operator) = match r.connection {
        Some(c) => (
          c.asn.filter(|&n| n > 0).map(|n| format!("AS{n}")),
          first_non_empty([c.isp, c.org]),
        ),
        None => (None, None),
      };
      Geo {
        asn,
        operator,
        country: non_empty(r.country),
        city: non_empty(r.city),
      }
    }
    GeoProvider::Api => {
      #[derive(Deserialize)]
      struct Resp {
        status: String,
        country: Option<String>,
        city: Option<String>,
        isp: Option<String>,
        org: Option<String>,
        #[serde(rename = "as")]
        as_field: Option<String>,
      }
      let r: Resp = serde_json::from_slice(bytes).ok()?;
      if r.status != "success" {
        return None;
      }
      let (asn, as_org) = parse_as_field(r.as_field);
      Geo {
        asn,
        operator: first_non_empty([r.isp, r.org, as_org]),
        country: non_empty(r.country),
        city: non_empty(r.city),
      }
    }
  };
  (!geo.is_empty()).then_some(geo)
}

async fn detect_ipv6_from(
  client: &reqwest::Client,
  urls: &[&str],
) -> Option<String> {
  for url in urls {
    let Ok(resp) = client.get(*url).send().await else {
      continue;
    };
    if !resp.status().is_success() {
      continue;
    }
    let Some(bytes) = read_body_limited(resp, 4 * 1024).await else {
      continue;
    };
    if let Ok(address) =
      String::from_utf8_lossy(&bytes).trim().parse::<Ipv6Addr>()
    {
      return Some(address.to_string());
    }
  }
  None
}

async fn geo_lookup_from(
  client: &reqwest::Client,
  endpoints: &[(GeoProvider, String)],
) -> Option<Geo> {
  for (provider, url) in endpoints {
    let Ok(resp) = client.get(url).send().await else {
      continue;
    };
    if !resp.status().is_success() {
      continue;
    }
    let Some(bytes) = read_body_limited(resp, 64 * 1024).await else {
      continue;
    };
    if let Some(geo) = parse_geo(*provider, &bytes) {
      return Some(geo);
    }
  }
  None
}

async fn geo_lookup(ip: IpAddr) -> Option<Geo> {
  let client = client()?;
  let endpoints = [
    (GeoProvider::Sb, format!("{GEO_IP_SB}/{ip}")),
    (GeoProvider::WhoIs, format!("{GEO_IP_WHOIS}/{ip}")),
    (
      GeoProvider::Api,
      format!(
        "{GEO_IP_API}/{ip}?fields=status,country,city,isp,org,as"
      ),
    ),
  ];
  geo_lookup_from(&client, &endpoints).await
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

pub async fn quota() -> DockerQuota {
  let mut saved = QUOTA.lock().await;
  if let Some((at, quota)) = saved.as_ref() {
    let ttl = if quota.error.is_none() {
      TTL_QUOTA
    } else {
      TTL_QUOTA_RETRY
    };
    if at.elapsed() < ttl {
      return quota.clone();
    }
  }
  let result = fetch_quota().await;
  *saved = Some((Instant::now(), result.clone()));
  result
}

fn quota_failed(reason: impl Into<String>) -> DockerQuota {
  DockerQuota {
    remaining: None,
    limit: None,
    window_secs: None,
    error: Some(reason.into()),
    checked_at: Utc::now(),
  }
}

fn reqwest_reason(
  error: &reqwest::Error,
  timeout: &str,
  host: &str,
) -> String {
  if error.is_timeout() {
    timeout.into()
  } else if error.is_connect() {
    format!("连不上 {host}")
  } else {
    format!("请求 {host} 失败")
  }
}

async fn fetch_quota_from(
  client: &reqwest::Client,
  auth_url: &str,
  preview_url: &str,
) -> DockerQuota {
  #[derive(Deserialize)]
  struct Auth {
    token: String,
  }
  let auth_resp = match client
    .get(auth_url)
    .query(&[
      ("service", "registry.docker.io"),
      ("scope", "repository:ratelimitpreview/test:pull"),
    ])
    .send()
    .await
  {
    Ok(r) => r,
    Err(e) => {
      return quota_failed(reqwest_reason(
        &e,
        "认证超时",
        "auth.docker.io",
      ));
    }
  };
  if !auth_resp.status().is_success() {
    return quota_failed(format!(
      "auth.docker.io 返回 HTTP {}",
      auth_resp.status().as_u16()
    ));
  }
  let auth: Auth = match auth_resp.json().await {
    Ok(a) => a,
    Err(_) => return quota_failed("解析认证响应失败"),
  };
  let response = match client
    .head(preview_url)
    .bearer_auth(auth.token)
    .send()
    .await
  {
    Ok(r) => r,
    Err(e) => {
      return quota_failed(reqwest_reason(
        &e,
        "查询超时",
        "registry-1.docker.io",
      ));
    }
  };
  let quota_header = |name| {
    let text = response.headers().get(name)?.to_str().ok()?;
    let (value, window) = text.split_once(";w=")?;
    Some((
      value.trim().parse::<u32>().ok()?,
      window.trim().parse::<u32>().ok()?,
    ))
  };
  let parsed = quota_header("ratelimit-limit")
    .zip(quota_header("ratelimit-remaining"))
    .filter(
      |&((limit, window_secs), (remaining, remaining_window))| {
        limit > 0
          && window_secs > 0
          && remaining_window == window_secs
          && remaining <= limit
      },
    );
  match parsed {
    Some(((limit, window_secs), (remaining, _))) => DockerQuota {
      remaining: Some(remaining),
      limit: Some(limit),
      window_secs: Some(window_secs),
      error: None,
      checked_at: Utc::now(),
    },
    None if !response.status().is_success() => quota_failed(format!(
      "registry-1.docker.io 返回 HTTP {}",
      response.status().as_u16()
    )),
    None => quota_failed("响应缺少额度信息"),
  }
}

async fn fetch_quota() -> DockerQuota {
  let Some(client) = client() else {
    return quota_failed("客户端不可用");
  };
  fetch_quota_from(&client, DOCKER_AUTH, DOCKER_PREVIEW).await
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
    if let Some((at, quota)) =
      QUOTA.try_lock().ok().and_then(|r| r.clone())
      && let (Some(remaining), Some(limit), Some(window_secs)) =
        (quota.remaining, quota.limit, quota.window_secs)
      && at.elapsed() <= Duration::from_secs(u64::from(window_secs))
    {
      hint.push_str(&format!(
        "。最近测得剩余 {remaining} / {limit}（{} UTC）",
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

  async fn mock_http(reply: &'static str, delay: Duration) -> String {
    use tokio::{
      io::{AsyncReadExt, AsyncWriteExt},
      net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
      if let Ok((mut conn, _)) = listener.accept().await {
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf).await;
        if !delay.is_zero() {
          tokio::time::sleep(delay).await;
        }
        if !reply.is_empty() {
          let _ = conn.write_all(reply.as_bytes()).await;
        }
      }
    });
    format!("http://{addr}")
  }

  fn test_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
      .timeout(timeout)
      .redirect(reqwest::redirect::Policy::none())
      .no_proxy()
      .user_agent("wharf-agent")
      .build()
      .unwrap()
  }

  #[tokio::test]
  async fn ipv6_probe_falls_back_to_second_url() {
    let first = mock_http(
      "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
      Duration::ZERO,
    )
    .await;
    let second = mock_http(
      "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n2001:db8::1",
      Duration::ZERO,
    )
    .await;
    let client = test_client(Duration::from_secs(2));
    let urls = [first.as_str(), second.as_str()];
    assert_eq!(
      detect_ipv6_from(&client, &urls).await.as_deref(),
      Some("2001:db8::1")
    );
  }

  #[tokio::test]
  async fn geo_lookup_switches_to_fallback_providers() {
    let client = test_client(Duration::from_secs(2));

    // 主接口 ip.sb 失败，切换到 ipwho.is
    let primary_fail = mock_http(
      "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
      Duration::ZERO,
    )
    .await;
    let whois_body = r#"{"success":true,"country":"China","city":"Beijing","connection":{"asn":37963,"isp":"Alibaba","org":"Alibaba Cloud"}}"#;
    let whois_reply = Box::leak(
      format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{whois_body}",
        whois_body.len()
      )
      .into_boxed_str(),
    );
    let fallback_whois = mock_http(whois_reply, Duration::ZERO).await;
    let geo = geo_lookup_from(
      &client,
      &[
        (GeoProvider::Sb, primary_fail),
        (GeoProvider::WhoIs, fallback_whois),
      ],
    )
    .await
    .unwrap();
    assert_eq!(
      geo,
      Geo {
        asn: Some("AS37963".into()),
        operator: Some("Alibaba".into()),
        country: Some("China".into()),
        city: Some("Beijing".into()),
      }
    );

    // ip.sb 超时 + ipwho.is 返回 success=false，切换到 ip-api.com
    let sb_timeout = mock_http("", Duration::from_secs(2)).await;
    let whois_false = mock_http(
      "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"success\":false}",
      Duration::ZERO,
    )
    .await;
    let ipapi_body = r#"{"status":"success","country":"China","city":"Shanghai","isp":"China Telecom","org":"","as":"AS4134 Chinanet"}"#;
    let ipapi_reply = Box::leak(
      format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{ipapi_body}",
        ipapi_body.len()
      )
      .into_boxed_str(),
    );
    let fallback_ipapi = mock_http(ipapi_reply, Duration::ZERO).await;
    let short_client = test_client(Duration::from_millis(200));
    let geo = geo_lookup_from(
      &short_client,
      &[
        (GeoProvider::Sb, sb_timeout),
        (GeoProvider::WhoIs, whois_false),
        (GeoProvider::Api, fallback_ipapi),
      ],
    )
    .await
    .unwrap();
    assert_eq!(
      geo,
      Geo {
        asn: Some("AS4134".into()),
        operator: Some("China Telecom".into()),
        country: Some("China".into()),
        city: Some("Shanghai".into()),
      }
    );
  }

  #[tokio::test]
  async fn docker_quota_records_error_reason_and_success() {
    let client = test_client(Duration::from_millis(200));

    // 认证超时
    let slow_auth = mock_http("", Duration::from_secs(2)).await;
    let q =
      fetch_quota_from(&client, &slow_auth, "http://127.0.0.1:1")
        .await;
    assert_eq!(q.remaining, None);
    assert_eq!(q.error.as_deref(), Some("认证超时"));

    // 认证返回 HTTP 403
    let auth_403 = mock_http(
      "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
      Duration::ZERO,
    )
    .await;
    let q =
      fetch_quota_from(&client, &auth_403, "http://127.0.0.1:1")
        .await;
    assert_eq!(
      q.error.as_deref(),
      Some("auth.docker.io 返回 HTTP 403")
    );

    // 正常返回额度
    let auth_ok = mock_http(
      "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"token\":\"tok\"}",
      Duration::ZERO,
    )
    .await;
    let preview_ok = mock_http(
      "HTTP/1.1 200 OK\r\nratelimit-limit: 100;w=21600\r\nratelimit-remaining: 88;w=21600\r\nContent-Length: 0\r\n\r\n",
      Duration::ZERO,
    )
    .await;
    let q = fetch_quota_from(&client, &auth_ok, &preview_ok).await;
    assert_eq!(q.remaining, Some(88));
    assert_eq!(q.limit, Some(100));
    assert_eq!(q.window_secs, Some(21600));
    assert_eq!(q.error, None);
  }
}

pub(crate) async fn read_body_limited(
  mut resp: reqwest::Response,
  max_bytes: usize,
) -> Option<Vec<u8>> {
  if resp
    .content_length()
    .is_some_and(|len| len > max_bytes as u64)
  {
    return None;
  }
  let mut body = Vec::new();
  while let Some(chunk) = resp.chunk().await.ok()? {
    if chunk.len() > max_bytes - body.len() {
      return None;
    }
    body.extend_from_slice(&chunk);
  }
  Some(body)
}
