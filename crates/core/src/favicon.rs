//! 首页的站点图标。控制面只读取已配置站点的公开图标。
use std::{
  collections::BTreeMap,
  net::IpAddr,
  sync::Arc,
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{Query, State},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Url, header, redirect::Policy};
use serde::Deserialize;
use tokio::sync::{Mutex, OnceCell, Semaphore};
use wharf_api_types::view::Perm;

use crate::{
  api::ApiResult, auth::Auth, db, render::Net, snapshot::Snapshot,
  state::AppState, views, world::World,
};

const TIMEOUT: Duration = Duration::from_secs(3);
const TTL: Duration = Duration::from_secs(300);
const MAX_BYTES: usize = 128 * 1024;
const MAX_ENTRIES: usize = 128;
type CachedIcon = Arc<OnceCell<Option<String>>>;
static CACHE: Mutex<BTreeMap<String, (Instant, CachedIcon)>> =
  Mutex::const_new(BTreeMap::new());
static REQUESTS: Semaphore = Semaphore::const_new(8);

#[derive(Deserialize)]
pub(crate) struct IconQuery {
  origin: String,
}

pub(crate) async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(query): Query<IconQuery>,
) -> ApiResult<Option<String>> {
  auth.require(Perm::Read)?;
  if !auth.human || query.origin.len() > 300 {
    return Ok(Json(None));
  }
  let Some(url) = Url::parse(&query.origin).ok().filter(web_url)
  else {
    return Ok(Json(None));
  };
  let origin = url.origin();
  let key = origin.ascii_serialization();
  let cached = {
    let now = Instant::now();
    let mut cache = CACHE.lock().await;
    cache.retain(|_, (expires, _)| *expires > now);
    if let Some((_, icon)) = cache.get(&key) {
      icon.clone()
    } else {
      if cache.len() >= MAX_ENTRIES
        && let Some(oldest) = cache
          .iter()
          .min_by_key(|(_, (expires, _))| *expires)
          .map(|(key, _)| key.clone())
      {
        cache.remove(&oldest);
      }
      let icon = Arc::new(OnceCell::new());
      cache.insert(key, (now + TTL, icon.clone()));
      icon
    }
  };

  let icon = cached
    .get_or_init(|| async {
      tokio::time::timeout(TIMEOUT, async {
        let _permit = REQUESTS.acquire().await.ok()?;
        let snap = state
          .db
          .call(|conn| {
            let edge_cache = db::edge_cache(conn)?
              .into_iter()
              .filter_map(|(key, (data, _))| {
                Some((
                  key.strip_prefix("app:")?.to_owned(),
                  serde_json::from_str(&data).ok()?,
                ))
              })
              .collect();
            Ok(Snapshot {
              world: World::from_rows(db::all_resources(conn)?)?,
              edge_cache,
              ..Snapshot::default()
            })
          })
          .await
          .ok()?;
        let same_origin = |value: &str| {
          Url::parse(value).is_ok_and(|u| u.origin() == origin)
        };
        let host = url.host_str()?;
        let configured =
          views::route_view(&snap, &Net::default(), host)
            .is_some_and(|route| same_origin(&route.url))
            || snap
              .world
              .bookmarks
              .values()
              .any(|b| same_origin(&b.spec.url))
            || snap.world.edge_apps.iter().any(|(name, row)| {
              if let Some(domain) = row.spec.domains.first() {
                same_origin(&format!("https://{domain}"))
              } else {
                views::edge_view(&snap, name)
                  .and_then(|edge| edge.live?.url)
                  .is_some_and(|value| same_origin(&value))
              }
            });
        if !configured {
          return None;
        }
        fetch(&url).await
      })
      .await
      .ok()
      .flatten()
    })
    .await;
  Ok(Json(icon.clone()))
}

fn web_url(url: &Url) -> bool {
  matches!(url.scheme(), "http" | "https")
    && url.username().is_empty()
    && url.password().is_none()
    && url.host_str().is_some()
}

fn public_ip(ip: IpAddr) -> bool {
  match ip.to_canonical() {
    IpAddr::V4(ip) => !matches!(
      ip.octets(),
      [0 | 10 | 127 | 224..=255, ..]
        | [100, 64..=127, ..]
        | [169, 254, ..]
        | [172, 16..=31, ..]
        | [192, 0, 0 | 2, _]
        | [192, 88, 99, _]
        | [192, 168, ..]
        | [198, 18 | 19, ..]
        | [198, 51, 100, _]
        | [203, 0, 113, _]
    ),
    IpAddr::V6(ip) => {
      let segments = ip.segments();
      (0x2000..=0x3fff).contains(&segments[0])
        && !matches!(
          segments,
          [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002 | 0x3fff, ..]
        )
    }
  }
}

async fn fetch(url: &Url) -> Option<String> {
  let host = url.host_str()?;
  let port = url.port_or_known_default()?;
  let addresses =
    tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
      .await
      .ok()?
      .filter(|addr| public_ip(addr.ip()))
      .collect::<Vec<_>>();
  if addresses.is_empty() {
    return None;
  }
  let origin = url.origin();
  // 固定使用检查过的地址，跳转也必须留在同一来源。
  let client = Client::builder()
    .no_proxy()
    .resolve_to_addrs(host, &addresses)
    .redirect(Policy::custom(move |attempt| {
      if attempt.previous().len() <= 3
        && web_url(attempt.url())
        && attempt.url().origin() == origin
      {
        attempt.follow()
      } else {
        attempt.stop()
      }
    }))
    .build()
    .ok()?;
  let mut response = client
    .get(url.join("/favicon.ico").ok()?)
    .header(header::ACCEPT, "image/*")
    .send()
    .await
    .ok()?;
  if !response.status().is_success()
    || response
      .content_length()
      .is_some_and(|len| len > MAX_BYTES as u64)
  {
    return None;
  }
  let svg = response
    .headers()
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(';').next())
    .is_some_and(|mime| {
      mime.trim().eq_ignore_ascii_case("image/svg+xml")
    });
  let mut bytes = Vec::new();
  while let Some(chunk) = response.chunk().await.ok()? {
    if chunk.len() > MAX_BYTES - bytes.len() {
      return None;
    }
    bytes.extend_from_slice(&chunk);
  }
  data_url(&bytes, svg)
}

fn data_url(bytes: &[u8], svg: bool) -> Option<String> {
  let mime = match bytes {
    [0, 0, 1, 0, ..] => "image/x-icon",
    [137, b'P', b'N', b'G', 13, 10, 26, 10, ..] => "image/png",
    [255, 216, 255, ..] => "image/jpeg",
    [b'G', b'I', b'F', b'8', b'7' | b'9', b'a', ..] => "image/gif",
    [
      b'R',
      b'I',
      b'F',
      b'F',
      _,
      _,
      _,
      _,
      b'W',
      b'E',
      b'B',
      b'P',
      ..,
    ] => "image/webp",
    _ if svg && !bytes.is_empty() => "image/svg+xml",
    _ => return None,
  };
  Some(format!("data:{mime};base64,{}", STANDARD.encode(bytes)))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ico_is_encoded_for_display() {
    assert_eq!(
      data_url(&[0, 0, 1, 0, 1, 0], false).as_deref(),
      Some("data:image/x-icon;base64,AAABAAEA"),
    );
  }

  #[test]
  fn private_dns_answers_are_rejected() {
    assert!(public_ip("1.1.1.1".parse().unwrap()));
    assert!(!public_ip("100.64.0.1".parse().unwrap()));
    assert!(!public_ip("::ffff:127.0.0.1".parse().unwrap()));
    assert!(!public_ip("fd7a:115c:a1e0::1".parse().unwrap()));
  }
}
