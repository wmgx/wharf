//! 厂商状态页、后台告警和失败提示。
use std::{
  collections::BTreeMap,
  sync::{Arc, RwLock},
  time::Duration,
};

use axum::{
  Json,
  extract::{Path, State},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  external::{ExternalIncident, ExternalStatus, Upstream},
  view::Perm,
};
use wharf_providers::http::Http;

use crate::{api::ApiResult, auth::Auth, db, rules, state::AppState};

pub const INTERVAL: Duration = Duration::from_secs(300);
const KEY: &str = "external.status_pages";
const DEFAULTS: &[(&str, &str)] = &[
  ("Cloudflare", "https://www.cloudflarestatus.com"),
  ("GitHub", "https://www.githubstatus.com"),
  ("Docker Hub", "https://www.dockerstatus.com"),
  ("Tailscale", "https://status.tailscale.com"),
];
static CACHE: RwLock<BTreeMap<String, ExternalStatus>> =
  RwLock::new(BTreeMap::new());
static UPDATE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

#[derive(Clone, Serialize, Deserialize)]
struct Page {
  url: String,
  enabled: bool,
}

fn defaults() -> BTreeMap<String, Page> {
  DEFAULTS
    .iter()
    .map(|(name, url)| {
      (
        name.to_string(),
        Page {
          url: url.to_string(),
          enabled: true,
        },
      )
    })
    .collect()
}

fn builtin(name: &str) -> bool {
  DEFAULTS.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

async fn pages(
  s: &AppState,
) -> Result<BTreeMap<String, Page>, ApiError> {
  let saved = s.db.call(|c| db::setting(c, KEY)).await?;
  let mut pages = defaults();
  if let Some(saved) = saved {
    pages.extend(
      serde_json::from_str::<BTreeMap<String, Page>>(&saved)
        .map_err(db::json_err)?,
    );
  }
  Ok(pages)
}

async fn save(
  s: &AppState,
  pages: &BTreeMap<String, Page>,
) -> Result<(), ApiError> {
  let data = serde_json::to_string(pages).map_err(db::json_err)?;
  s.db
    .call(move |c| db::set_setting(c, KEY, Some(&data)))
    .await
}

fn page_url(value: &str) -> Result<String, ApiError> {
  let bad =
    || ApiError::invalid("请填写公开的 HTTPS Statuspage 地址");
  let mut url = reqwest::Url::parse(value).map_err(|_| bad())?;
  if url.scheme() != "https"
    || !url.host_str().is_some_and(|name| {
      name.contains('.')
        && name.parse::<std::net::IpAddr>().is_err()
        && !name.trim_end_matches('.').ends_with(".localhost")
    })
    || !url.username().is_empty()
    || url.password().is_some()
    || url.port().is_some()
    || url.query().is_some()
    || url.fragment().is_some()
    || !matches!(
      url.path(),
      "/" | "/api/v2/summary.json" | "/api/v2/status.json"
    )
  {
    return Err(bad());
  }
  url.set_path("/");
  Ok(url.as_str().trim_end_matches('/').to_string())
}

fn shell(name: &str, page: &Page) -> ExternalStatus {
  ExternalStatus {
    name: name.to_string(),
    url: page.url.clone(),
    enabled: page.enabled,
    indicator: None,
    description: if page.enabled {
      "还没检查".into()
    } else {
      "已关闭".into()
    },
    incidents: vec![],
    checked_at: None,
  }
}

#[derive(Deserialize)]
struct Summary {
  status: Status,
  #[serde(default)]
  incidents: Vec<Incident>,
}

#[derive(Deserialize)]
struct Status {
  indicator: String,
  description: String,
}

#[derive(Deserialize)]
struct Incident {
  name: String,
  #[serde(default)]
  shortlink: String,
  #[serde(default)]
  id: String,
  status: String,
}

fn severity(indicator: &str) -> Option<bool> {
  match indicator {
    "none" | "minor" => Some(false),
    "major" | "critical" => Some(true),
    "maintenance" => None,
    _ => None,
  }
}

async fn get<T: serde::de::DeserializeOwned>(
  http: &Http,
  url: &str,
) -> Result<T, ApiError> {
  let unavailable = || {
    ApiError::invalid("状态页查不到或返回的内容不是 Statuspage 格式")
  };
  let mut response = http
    .send(|c| c.get(url))
    .await
    .map_err(|_| unavailable())?
    .error_for_status()
    .map_err(|_| unavailable())?;
  let mut bytes = Vec::new();
  while let Some(chunk) =
    response.chunk().await.map_err(|_| unavailable())?
  {
    if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
      return Err(unavailable());
    }
    bytes.extend_from_slice(&chunk);
  }
  serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

async fn check(
  name: &str,
  page: &Page,
) -> Result<ExternalStatus, ApiError> {
  let http = Http::new(Duration::from_secs(10))
    .map_err(|_| ApiError::internal("状态页客户端不可用"))?;
  let mut summary: Summary =
    get(&http, &format!("{}/api/v2/summary.json", page.url)).await?;
  if severity(&summary.status.indicator).is_none()
    && summary.status.indicator != "maintenance"
  {
    return Err(ApiError::invalid("状态页返回了未知状态"));
  }
  // Docker 的新版状态页把事件放在独立接口。
  if page.url == DEFAULTS[2].1 && summary.status.indicator != "none" {
    #[derive(Deserialize)]
    struct Incidents {
      incidents: Vec<Incident>,
    }
    if let Ok(data) = get::<Incidents>(
      &http,
      &format!("{}/api/v2/incidents.json", page.url),
    )
    .await
    {
      summary.incidents = data.incidents;
    }
  }
  Ok(ExternalStatus {
    indicator: Some(summary.status.indicator),
    description: summary.status.description,
    incidents: summary
      .incidents
      .into_iter()
      .filter(|i| {
        !matches!(
          i.status.as_str(),
          "resolved" | "postmortem" | "completed" | "scheduled"
        )
      })
      .filter_map(|mut i| {
        if i.shortlink.is_empty()
          && i.id.len() == 26
          && i.id.bytes().all(|b| b.is_ascii_alphanumeric())
          && page.url == DEFAULTS[2].1
        {
          i.shortlink = format!("{}/incidents/{}", page.url, i.id);
        }
        let url = reqwest::Url::parse(&i.shortlink).ok()?;
        (matches!(url.scheme(), "https" | "http")
          && url.username().is_empty()
          && url.password().is_none())
        .then_some(ExternalIncident {
          name: i.name,
          url: i.shortlink,
        })
      })
      .collect(),
    checked_at: Some(Utc::now()),
    ..shell(name, page)
  })
}

async fn record(s: &AppState, result: ExternalStatus) {
  if let Ok(mut cache) = CACHE.write() {
    cache.insert(result.name.clone(), result.clone());
  }
  if let Some(bad) = result.indicator.as_deref().and_then(severity) {
    let detail = std::iter::once(result.description)
      .chain(
        result
          .incidents
          .into_iter()
          .map(|i| format!("{} {}", i.name, i.url)),
      )
      .collect::<Vec<_>>()
      .join("\n");
    rules::observe(
      s,
      "external.incident",
      &result.name,
      u8::from(bad).into(),
      &detail,
    )
    .await;
  }
}

pub async fn refresh(s: &AppState) -> Result<(), ApiError> {
  // 加减条目与后台检查互斥，避免关掉后还写回一条旧检查结果。
  let _update = UPDATE.lock().await;
  let pages = pages(s).await?;
  crate::snapshot::load(&s.db).await?;
  futures_util::future::join_all(
    pages.iter().filter(|(_, p)| p.enabled).map(
      |(name, page)| async move {
        let result = check(name, page).await.unwrap_or_else(|_| {
          ExternalStatus {
            description: "状态页查不到".into(),
            checked_at: Some(Utc::now()),
            ..shell(name, page)
          }
        });
        record(s, result).await;
      },
    ),
  )
  .await;
  Ok(())
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<ExternalStatus>> {
  auth.require(Perm::Read)?;
  let pages = pages(&s).await?;
  let cache = CACHE.read().ok();
  Ok(Json(
    pages
      .iter()
      .map(|(name, page)| {
        cache
          .as_ref()
          .and_then(|c| c.get(name))
          .filter(|r| r.enabled == page.enabled && r.url == page.url)
          .cloned()
          .unwrap_or_else(|| shell(name, page))
      })
      .collect(),
  ))
}

#[derive(Deserialize)]
pub struct Add {
  name: String,
  url: String,
}

pub async fn add(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<Add>,
) -> ApiResult<ExternalStatus> {
  auth.require(Perm::Admin)?;
  let name = req.name.trim();
  if name.is_empty()
    || name.len() > 80
    || name.chars().any(char::is_control)
  {
    return Err(ApiError::invalid("状态页名称不合法").into());
  }
  let page = Page {
    url: page_url(&req.url)?,
    enabled: true,
  };
  let _update = UPDATE.lock().await;
  let mut pages = pages(&s).await?;
  if pages.keys().any(|n| n.eq_ignore_ascii_case(name)) {
    return Err(ApiError::invalid("已经有同名状态页").into());
  }
  crate::snapshot::load(&s.db).await?;
  let result = check(name, &page).await?;
  pages.insert(name.to_string(), page);
  save(&s, &pages).await?;
  record(&s, result.clone()).await;
  Ok(Json(result))
}

#[derive(Deserialize)]
pub struct Set {
  enabled: bool,
}

pub async fn set(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<Set>,
) -> ApiResult<ExternalStatus> {
  auth.require(Perm::Admin)?;
  let _update = UPDATE.lock().await;
  let mut pages = pages(&s).await?;
  let page = pages
    .get_mut(&name)
    .ok_or_else(|| ApiError::not_found("没有这个外部状态页"))?;
  page.enabled = req.enabled;
  let result = shell(&name, page);
  save(&s, &pages).await?;
  if !req.enabled {
    clear(&s, &name).await;
  }
  Ok(Json(result))
}

pub async fn rm(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<()> {
  auth.require(Perm::Admin)?;
  if builtin(&name) {
    return Err(ApiError::invalid("默认状态页可以关闭").into());
  }
  let _update = UPDATE.lock().await;
  let mut pages = pages(&s).await?;
  if pages.remove(&name).is_none() {
    return Err(ApiError::not_found("没有这个外部状态页").into());
  }
  save(&s, &pages).await?;
  clear(&s, &name).await;
  Ok(Json(()))
}

async fn clear(s: &AppState, name: &str) {
  if let Ok(mut cache) = CACHE.write() {
    cache.remove(name);
  }
  rules::external::clear_incident(s, name).await;
}

pub fn incident_hint(service: &str) -> Option<String> {
  let cache = CACHE.read().ok()?;
  let status = cache.get(service)?;
  if status.indicator.as_deref().is_none_or(|i| i == "none") {
    return None;
  }
  let title = if status.incidents.is_empty() {
    status.description.clone()
  } else {
    status
      .incidents
      .iter()
      .map(|i| i.name.as_str())
      .collect::<Vec<_>>()
      .join("、")
  };
  Some(format!("{service} 正在故障：{title}"))
}

pub fn failure(mut error: ApiError, service: &str) -> ApiError {
  if let Some(incident) = incident_hint(service) {
    let hint = error.hint.get_or_insert_with(String::new);
    if !hint.is_empty() {
      hint.push('。');
    }
    hint.push_str(&incident);
  }
  error
}

pub fn agent_failure(mut error: ApiError, server: &str) -> ApiError {
  match error.upstream.take() {
    Some(Upstream::DockerHub) => {
      if let Some(hint) = &mut error.hint {
        *hint = hint.replace("<server>", server);
      }
      failure(error, "Docker Hub")
    }
    Some(Upstream::GitHub) => failure(error, "GitHub"),
    Some(Upstream::Cloudflare) => failure(error, "Cloudflare"),
    None => error,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn statuspage_severity() {
    for (indicator, bad) in [
      ("none", false),
      ("minor", false),
      ("major", true),
      ("critical", true),
    ] {
      let data: Summary = serde_json::from_value(serde_json::json!({
        "status": {"indicator": indicator, "description": "status"}
      }))
      .unwrap();
      assert_eq!(severity(&data.status.indicator), Some(bad));
    }
  }
}
