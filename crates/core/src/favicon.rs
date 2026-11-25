//! 代取首页服务与书签站点的 `/favicon.ico`，带超时、大小限制与内存缓存。
//! 找不到或抓取失败一律返回 204，避免浏览器在控制台打印 404 或协议错误。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use axum::{
  extract::{Query, State},
  http::{StatusCode, header},
  response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio::sync::Semaphore;
use wharf_api_types::view::Perm;
use wharf_providers::http::Http;

use crate::{
  api::AppError,
  auth::Auth,
  snapshot::{self, Snapshot},
  state::AppState,
};

const FETCH_TIMEOUT: Duration = Duration::from_secs(4);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const HIT_TTL: Duration = Duration::from_secs(3600);
const MISS_TTL: Duration = Duration::from_secs(600);
const MAX_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_CACHE_ENTRIES: usize = 256;
const MAX_IN_FLIGHT: usize = 6;

#[derive(Clone)]
struct Cached {
  at: Instant,
  icon: Option<Icon>,
}

#[derive(Clone)]
struct Icon {
  content_type: &'static str,
  bytes: Vec<u8>,
}

static CACHE: Mutex<BTreeMap<String, Cached>> =
  Mutex::new(BTreeMap::new());
static IN_FLIGHT: Semaphore = Semaphore::const_new(MAX_IN_FLIGHT);

#[derive(Deserialize)]
pub struct FaviconQuery {
  #[serde(default)]
  url: String,
}

/// 只接受 http/https，提取规范化的 origin 和小写 host。
fn parse_origin(raw: &str) -> Option<(String, String)> {
  let url = reqwest::Url::parse(raw.trim()).ok()?;
  let scheme = url.scheme();
  if scheme != "http" && scheme != "https" {
    return None;
  }
  let host = url.host_str()?.to_ascii_lowercase();
  let origin = match url.port() {
    Some(port) => format!("{scheme}://{host}:{port}"),
    None => format!("{scheme}://{host}"),
  };
  Some((origin, host))
}

/// 只允许抓取当前已纳管路由、边缘应用与书签的站点，防止 SSRF。
fn allowed_hosts(snap: &Snapshot) -> BTreeSet<String> {
  let mut hosts = BTreeSet::new();
  for hostname in snap.world.routes.keys() {
    hosts.insert(hostname.to_ascii_lowercase());
  }
  for app in snap.world.edge_apps.values() {
    for domain in &app.spec.domains {
      hosts.insert(domain.to_ascii_lowercase());
    }
  }
  for cache in snap.edge_cache.values() {
    if let Some(url) = cache.live.url.as_deref()
      && let Some((_, host)) = parse_origin(url)
    {
      hosts.insert(host);
    }
  }
  for bookmark in snap.world.bookmarks.values() {
    if let Some((_, host)) = parse_origin(&bookmark.spec.url) {
      hosts.insert(host);
    }
  }
  hosts
}

/// 识别并白名单化图片类型；拒绝空体、超限内容与非图片（如 HTML）。
fn validate_icon(
  content_type: Option<&str>,
  bytes: &[u8],
) -> Option<&'static str> {
  if bytes.is_empty() || bytes.len() > MAX_BYTES {
    return None;
  }
  let mime = content_type
    .and_then(|v| v.split(';').next())
    .map(|v| v.trim().to_ascii_lowercase());
  if matches!(
    mime.as_deref(),
    Some("text/html" | "text/plain" | "application/json")
  ) {
    return None;
  }
  if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
    return Some("image/png");
  }
  if bytes.starts_with(b"\x00\x00\x01\x00")
    || bytes.starts_with(b"\x00\x00\x02\x00")
  {
    return Some("image/x-icon");
  }
  if bytes.starts_with(b"\xff\xd8\xff") {
    return Some("image/jpeg");
  }
  if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
    return Some("image/gif");
  }
  if bytes.len() >= 12
    && &bytes[0..4] == b"RIFF"
    && &bytes[8..12] == b"WEBP"
  {
    return Some("image/webp");
  }
  let head = std::str::from_utf8(&bytes[..bytes.len().min(256)])
    .ok()
    .map(|s| s.trim_start().to_ascii_lowercase());
  if head.as_deref().is_some_and(|s| {
    s.starts_with("<svg")
      || (s.starts_with("<?xml") && s.contains("<svg"))
  }) {
    return Some("image/svg+xml");
  }
  match mime.as_deref() {
    Some("image/x-icon" | "image/vnd.microsoft.icon") => {
      Some("image/x-icon")
    }
    Some("image/png") => Some("image/png"),
    Some("image/jpeg") => Some("image/jpeg"),
    Some("image/gif") => Some("image/gif"),
    Some("image/webp") => Some("image/webp"),
    Some("image/svg+xml") => Some("image/svg+xml"),
    _ => None,
  }
}

fn cache_get(origin: &str) -> Option<Option<Icon>> {
  let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
  let entry = cache.get(origin)?;
  let ttl = if entry.icon.is_some() {
    HIT_TTL
  } else {
    MISS_TTL
  };
  (entry.at.elapsed() < ttl).then(|| entry.icon.clone())
}

fn cache_put(origin: String, icon: Option<Icon>) {
  let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
  if cache.len() >= MAX_CACHE_ENTRIES
    && !cache.contains_key(&origin)
    && let Some(oldest) = cache
      .iter()
      .min_by_key(|(_, v)| v.at)
      .map(|(k, _)| k.clone())
  {
    cache.remove(&oldest);
  }
  cache.insert(
    origin,
    Cached {
      at: Instant::now(),
      icon,
    },
  );
}

async fn fetch_favicon(origin: &str, host: &str) -> Option<Icon> {
  let http = Http::new(FETCH_TIMEOUT).ok()?;
  let mut url =
    reqwest::Url::parse(&format!("{origin}/favicon.ico")).ok()?;
  for _ in 0..=MAX_REDIRECTS {
    let current = url.clone();
    let mut resp = http
      .send(|c| {
        c.get(current.clone())
          .header(reqwest::header::USER_AGENT, "wharf")
          .header(reqwest::header::ACCEPT, "image/*,*/*;q=0.8")
      })
      .await
      .ok()?;
    if resp.status().is_redirection() {
      let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())?;
      let next = url.join(loc).ok()?;
      let scheme = next.scheme();
      let next_host = next.host_str()?.to_ascii_lowercase();
      if (scheme != "http" && scheme != "https") || next_host != host
      {
        return None;
      }
      url = next;
      continue;
    }
    if !resp.status().is_success() {
      return None;
    }
    if resp.content_length().is_some_and(|n| n > MAX_BYTES as u64) {
      return None;
    }
    let ct = resp
      .headers()
      .get(reqwest::header::CONTENT_TYPE)
      .and_then(|v| v.to_str().ok())
      .map(str::to_string);
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
      if bytes.len() + chunk.len() > MAX_BYTES {
        return None;
      }
      bytes.extend_from_slice(&chunk);
    }
    let content_type = validate_icon(ct.as_deref(), &bytes)?;
    return Some(Icon {
      content_type,
      bytes,
    });
  }
  None
}

fn respond(icon: Option<Icon>) -> Response {
  match icon {
    Some(icon) => (
      StatusCode::OK,
      [
        (header::CONTENT_TYPE, icon.content_type),
        (header::CACHE_CONTROL, "private, max-age=3600"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::CONTENT_SECURITY_POLICY, "sandbox"),
      ],
      icon.bytes,
    )
      .into_response(),
    None => (
      StatusCode::NO_CONTENT,
      [(header::CACHE_CONTROL, "private, max-age=600")],
      (),
    )
      .into_response(),
  }
}

/// `GET /api/favicon?url=<站点地址>`
pub async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<FaviconQuery>,
) -> Result<Response, AppError> {
  auth.require(Perm::Read)?;
  let Some((origin, host)) = parse_origin(&q.url) else {
    return Ok(respond(None));
  };
  if let Some(hit) = cache_get(&origin) {
    return Ok(respond(hit));
  }
  let snap = snapshot::load(&s.db).await?;
  if !allowed_hosts(&snap).contains(&host) {
    return Ok(respond(None));
  }
  let Ok(Ok(_permit)) =
    tokio::time::timeout(TOTAL_TIMEOUT, IN_FLIGHT.acquire()).await
  else {
    return Ok(respond(None));
  };
  if let Some(hit) = cache_get(&origin) {
    return Ok(respond(hit));
  }
  let icon = tokio::time::timeout(
    TOTAL_TIMEOUT,
    fetch_favicon(&origin, &host),
  )
  .await
  .ok()
  .flatten();
  cache_put(origin, icon.clone());
  Ok(respond(icon))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepts_valid_origin_and_icon_types() {
    assert_eq!(
      parse_origin("https://App.Example.com:8443/some/path?x=1"),
      Some((
        "https://app.example.com:8443".into(),
        "app.example.com".into()
      ))
    );
    assert_eq!(
      parse_origin("http://s1.example.com/"),
      Some(("http://s1.example.com".into(), "s1.example.com".into()))
    );
    assert_eq!(
      validate_icon(
        Some("application/octet-stream"),
        b"\x89PNG\r\n\x1a\nrest"
      ),
      Some("image/png")
    );
    assert_eq!(
      validate_icon(None, b"\x00\x00\x01\x00icon"),
      Some("image/x-icon")
    );
    assert_eq!(
      validate_icon(
        Some("image/svg+xml; charset=utf-8"),
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"
      ),
      Some("image/svg+xml")
    );
  }

  #[test]
  fn rejects_invalid_origin_non_image_and_oversized_icon() {
    assert_eq!(parse_origin("ftp://s1.example.com"), None);
    assert_eq!(parse_origin("not-a-url"), None);
    assert_eq!(validate_icon(Some("image/png"), b""), None);
    assert_eq!(
      validate_icon(Some("text/html; charset=utf-8"), b"<html>"),
      None
    );
    let mut oversized = b"\x89PNG\r\n\x1a\n".to_vec();
    oversized.resize(MAX_BYTES + 1, 0);
    assert_eq!(validate_icon(Some("image/png"), &oversized), None);
  }
}
