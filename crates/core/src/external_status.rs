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
  incidents: Option<Vec<Incident>>,
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
  shortlink: Option<String>,
  #[serde(default)]
  id: Option<String>,
  status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchError {
  Client,
  Timeout,
  Connect,
  Request,
  Http(u16),
  TooLarge,
  Parse,
  UnknownIndicator(String),
}

impl FetchError {
  fn reason(&self) -> String {
    match self {
      Self::Client => "客户端不可用".into(),
      Self::Timeout => "超时".into(),
      Self::Connect => "连接失败".into(),
      Self::Request => "请求失败".into(),
      Self::Http(code) => format!("HTTP {code}"),
      Self::TooLarge => "响应过大".into(),
      Self::Parse => "解析失败".into(),
      Self::UnknownIndicator(s) => format!("未知状态 {s}"),
    }
  }

  fn from_reqwest(error: &reqwest::Error) -> Self {
    if error.is_timeout() {
      Self::Timeout
    } else if error.is_connect() {
      Self::Connect
    } else {
      Self::Request
    }
  }
}

fn unavailable(
  name: &str,
  page: &Page,
  error: &FetchError,
) -> ExternalStatus {
  ExternalStatus {
    description: format!("状态页查不到（{}）", error.reason()),
    checked_at: Some(Utc::now()),
    ..shell(name, page)
  }
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
) -> Result<T, FetchError> {
  let mut response = http
    .send(|c| {
      c.get(url)
        .header("user-agent", "wharf")
        .header("accept", "application/json")
    })
    .await
    .map_err(|e| FetchError::from_reqwest(&e))?;
  if !response.status().is_success() {
    return Err(FetchError::Http(response.status().as_u16()));
  }
  let mut bytes = Vec::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(|e| FetchError::from_reqwest(&e))?
  {
    if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
      return Err(FetchError::TooLarge);
    }
    bytes.extend_from_slice(&chunk);
  }
  serde_json::from_slice(&bytes).map_err(|_| FetchError::Parse)
}

async fn check_with(
  http: &Http,
  name: &str,
  page: &Page,
) -> Result<ExternalStatus, FetchError> {
  let mut summary: Summary =
    get(http, &format!("{}/api/v2/summary.json", page.url)).await?;
  if severity(&summary.status.indicator).is_none()
    && summary.status.indicator != "maintenance"
  {
    return Err(FetchError::UnknownIndicator(
      summary.status.indicator,
    ));
  }
  let mut incidents = summary.incidents.take().unwrap_or_default();
  // Docker 的新版状态页把事件放在独立接口。
  if page.url == DEFAULTS[2].1 && summary.status.indicator != "none" {
    #[derive(Deserialize)]
    struct Incidents {
      #[serde(default)]
      incidents: Option<Vec<Incident>>,
    }
    if let Ok(data) = get::<Incidents>(
      http,
      &format!("{}/api/v2/incidents.json", page.url),
    )
    .await
    {
      incidents = data.incidents.unwrap_or_default();
    }
  }
  Ok(ExternalStatus {
    indicator: Some(summary.status.indicator),
    description: summary.status.description,
    incidents: incidents
      .into_iter()
      .filter(|i| {
        !matches!(
          i.status.as_str(),
          "resolved" | "postmortem" | "completed" | "scheduled"
        )
      })
      .filter_map(|i| {
        let mut shortlink = i.shortlink.unwrap_or_default();
        let id = i.id.unwrap_or_default();
        if shortlink.is_empty()
          && id.len() == 26
          && id.bytes().all(|b| b.is_ascii_alphanumeric())
          && page.url == DEFAULTS[2].1
        {
          shortlink = format!("{}/incidents/{id}", page.url);
        }
        let url = reqwest::Url::parse(&shortlink).ok()?;
        (matches!(url.scheme(), "https" | "http")
          && url.username().is_empty()
          && url.password().is_none())
        .then_some(ExternalIncident {
          name: i.name,
          url: shortlink,
        })
      })
      .collect(),
    checked_at: Some(Utc::now()),
    ..shell(name, page)
  })
}

async fn check(
  name: &str,
  page: &Page,
) -> Result<ExternalStatus, FetchError> {
  let http = Http::new(Duration::from_secs(15))
    .map_err(|_| FetchError::Client)?;
  check_with(&http, name, page).await
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
        let result = check(name, page)
          .await
          .unwrap_or_else(|e| unavailable(name, page, &e));
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
  let result = check(name, &page).await.map_err(|e| {
    if e == FetchError::Client {
      ApiError::internal("状态页客户端不可用")
    } else {
      ApiError::invalid(format!("状态页查不到（{}）", e.reason()))
    }
  })?;
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

const MAX_HINT_INCIDENTS: usize = 3;

fn format_incident_hint(
  service: &str,
  status: &ExternalStatus,
) -> Option<String> {
  if status.indicator.as_deref().and_then(severity) != Some(true) {
    return None;
  }
  let title = if status.incidents.is_empty() {
    status.description.clone()
  } else {
    let shown = status
      .incidents
      .iter()
      .take(MAX_HINT_INCIDENTS)
      .map(|i| i.name.as_str())
      .collect::<Vec<_>>()
      .join("、");
    if status.incidents.len() > MAX_HINT_INCIDENTS {
      format!("{shown} 等 {} 条", status.incidents.len())
    } else {
      shown
    }
  };
  Some(format!("{service} 正在故障：{title}"))
}

pub fn incident_hint(service: &str) -> Option<String> {
  let cache = CACHE.read().ok()?;
  let status = cache.get(service)?;
  format_incident_hint(service, status)
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

  fn sample_status(
    indicator: Option<&str>,
    incidents: &[&str],
  ) -> ExternalStatus {
    ExternalStatus {
      name: "Cloudflare".into(),
      url: "https://www.cloudflarestatus.com".into(),
      enabled: true,
      indicator: indicator.map(str::to_string),
      description: "Partial System Outage".into(),
      incidents: incidents
        .iter()
        .enumerate()
        .map(|(idx, title)| ExternalIncident {
          name: (*title).into(),
          url: format!("https://example.com/incidents/{idx}"),
        })
        .collect(),
      checked_at: Some(Utc::now()),
    }
  }

  #[test]
  fn incident_hint_filters_by_severity_and_truncates() {
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(Some("none"), &["无关事件"])
      ),
      None
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(
          Some("minor"),
          &["法国邮件路由", "Magic Transit"]
        )
      ),
      None
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(Some("maintenance"), &["例行维护"])
      ),
      None
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(None, &["状态页查不到"])
      ),
      None
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(Some("major"), &["DNS 故障", "API 异常"])
      )
      .as_deref(),
      Some("Cloudflare 正在故障：DNS 故障、API 异常")
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(Some("critical"), &["A", "B", "C"])
      )
      .as_deref(),
      Some("Cloudflare 正在故障：A、B、C")
    );
    assert_eq!(
      format_incident_hint(
        "Cloudflare",
        &sample_status(Some("major"), &["A", "B", "C", "D", "E"])
      )
      .as_deref(),
      Some("Cloudflare 正在故障：A、B、C 等 5 条")
    );
  }

  #[tokio::test]
  async fn check_reports_failure_reasons() {
    use tokio::{
      io::{AsyncReadExt, AsyncWriteExt},
      net::TcpListener,
    };

    async fn serve_once(
      reply: &'static str,
      delay: Duration,
    ) -> String {
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

    let http = Http::new(Duration::from_millis(200)).unwrap();

    // HTTP 状态码失败
    let url = serve_once(
      "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
      Duration::ZERO,
    )
    .await;
    let page = Page { url, enabled: true };
    let err =
      check_with(&http, "Docker Hub", &page).await.unwrap_err();
    assert_eq!(err, FetchError::Http(503));
    assert_eq!(
      unavailable("Docker Hub", &page, &err).description,
      "状态页查不到（HTTP 503）"
    );

    // 解析失败
    let url = serve_once(
      "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nnot a json",
      Duration::ZERO,
    )
    .await;
    let page = Page { url, enabled: true };
    let err =
      check_with(&http, "Docker Hub", &page).await.unwrap_err();
    assert_eq!(err, FetchError::Parse);
    assert_eq!(
      unavailable("Docker Hub", &page, &err).description,
      "状态页查不到（解析失败）"
    );

    // 超时
    let url = serve_once("", Duration::from_secs(2)).await;
    let page = Page { url, enabled: true };
    let err =
      check_with(&http, "Docker Hub", &page).await.unwrap_err();
    assert_eq!(err, FetchError::Timeout);
    assert_eq!(
      unavailable("Docker Hub", &page, &err).description,
      "状态页查不到（超时）"
    );
  }
}
