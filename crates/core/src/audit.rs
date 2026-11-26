//! 通过鉴权的操作和页面登录记录。

use std::{
  collections::HashMap,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{ConnectInfo, Query, Request, State},
  http::Method,
  middleware::Next,
  response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  view::{AuditEntry, Perm},
};

use crate::{
  api::{ApiResult, AppError},
  auth::Auth,
  db::{now_ms, sql_err},
  state::AppState,
};

/// 请求处理过程中往里写“谁”和摘要，中间层在响应后读出来记一条。
#[derive(Clone, Default)]
pub struct AuditSlot(Arc<Mutex<Slot>>);

#[derive(Default)]
struct Slot {
  actor: Option<String>,
  detail: Option<String>,
  required: bool,
  rejection: Option<(String, String)>,
}

impl AuditSlot {
  pub fn set_actor(&self, actor: &str) {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).actor =
      Some(actor.to_string());
  }

  pub fn set_rejected(&self, actor: &str, reason: &str) {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).rejection =
      Some((actor.to_string(), reason.to_string()));
  }

  pub fn skip_record(&self) {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).actor = None;
  }

  pub fn set_detail(&self, detail: String) {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).detail =
      Some(detail);
  }

  pub fn require_record(&self, detail: String) {
    let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
    slot.detail = Some(detail);
    slot.required = true;
  }
}

pub async fn layer(
  State(state): State<Arc<AppState>>,
  mut req: Request,
  next: Next,
) -> Response {
  let method = req.method().clone();
  let path = req.uri().path().to_string();
  let started = Instant::now();
  let reason = reason(&req);
  let source = req
    .extensions()
    .get::<ConnectInfo<std::net::SocketAddr>>()
    .map(|peer| crate::login::client_key(peer.0.ip(), req.headers()));
  let slot = AuditSlot::default();
  req.extensions_mut().insert(slot.clone());
  let resp = next.run(req).await;
  let (actor, detail, required, rejection) = {
    let mut slot = slot.0.lock().unwrap_or_else(|e| e.into_inner());
    (
      slot.actor.take(),
      slot.detail.take(),
      slot.required,
      slot.rejection.take(),
    )
  };
  let status = resp.status().as_u16();
  let rejected = matches!(status, 401 | 403)
    && path.starts_with("/api/")
    && !matches!(
      path.as_str(),
      "/api/login" | "/api/setup" | "/api/logout"
    );
  if rejected || (actor.is_some() && should_record(&method, &path)) {
    let (actor, detail) = rejection.map_or_else(
      || (actor.unwrap_or_else(|| "anonymous".into()), detail),
      |(actor, detail)| (actor, Some(detail)),
    );
    let detail = if rejected {
      detail.or_else(|| Some("权限校验拒绝".into()))
    } else {
      match (detail, reason) {
        (Some(d), Some(r)) => Some(format!("{d} 原因：{r}")),
        (None, Some(r)) => Some(format!("原因：{r}")),
        (d, None) => d,
      }
    };
    let row = AuditEntry {
      id: 0,
      at: now_ms(),
      kind: "api".into(),
      actor,
      method: method.to_string(),
      path,
      status: Some(status),
      duration_ms: Some(started.elapsed().as_millis() as i64),
      detail,
      source,
    };
    if rejected {
      let (record, summary) =
        REJECTS.lock().unwrap_or_else(|e| e.into_inner()).record(
          (
            &row.actor,
            row.source.as_deref().unwrap_or_default(),
            status,
          ),
          Instant::now(),
        );
      if summary > 0 {
        let mut summary_row = row.clone();
        summary_row.detail =
          Some(format!("同类拒绝已折叠 {summary} 次"));
        let _ = insert(&state, summary_row).await;
      }
      if !record {
        return resp;
      }
    }
    let result = insert(&state, row).await;
    if required && let Err(error) = result {
      return AppError(error).into_response();
    }
  }
  resp
}

/// CLI 的 `--reason`：请求头里百分号编码的一句话，最多 200 个字符。
fn reason(req: &Request) -> Option<String> {
  let raw = req.headers().get(REASON_HEADER)?.to_str().ok()?;
  let text = percent_decode(raw)?;
  let text = text.trim();
  (!text.is_empty()).then(|| text.chars().take(200).collect())
}

pub const REASON_HEADER: &str = "x-wharf-reason";

fn percent_decode(s: &str) -> Option<String> {
  let mut out = Vec::with_capacity(s.len());
  let mut bytes = s.bytes();
  while let Some(b) = bytes.next() {
    if b == b'%' {
      let hex = [bytes.next()?, bytes.next()?];
      let hex = std::str::from_utf8(&hex).ok()?;
      out.push(u8::from_str_radix(hex, 16).ok()?);
    } else {
      out.push(b);
    }
  }
  String::from_utf8(out).ok()
}

pub fn should_record(method: &Method, path: &str) -> bool {
  if !path.starts_with("/api/")
    || matches!(path, "/api/login" | "/api/logout" | "/api/setup")
  {
    return false;
  }
  if matches!(
    *method,
    Method::POST | Method::PUT | Method::PATCH | Method::DELETE
  ) {
    return true;
  }
  *method == Method::GET
    && (path == "/api/export"
      || path == "/api/shell-log"
      || (path.starts_with("/api/oidc/clients/")
        && path.ends_with("/secret"))
      || (path.starts_with("/api/servers/")
        && (path.ends_with("/dirs")
          || path.ends_with("/host-units")
          || (path.contains("/host-units/")
            && path.ends_with("/logs"))))
      || (path.starts_with("/api/edge/")
        && path.ends_with("/script"))
      || path == "/api/sso/accounts"
      || path.starts_with("/api/sso/accounts/")
      || path.ends_with("/terminal")
      || path.ends_with("/files/download")
      || path.ends_with("/connect"))
}

const WINDOW: Duration = Duration::from_secs(60);

struct Bucket {
  at: Instant,
  details: usize,
  folded: usize,
}

#[derive(Default)]
struct RejectLimiter {
  global: Option<(Instant, usize)>,
  buckets: HashMap<(String, String, u16), Bucket>,
}

static REJECTS: LazyLock<Mutex<RejectLimiter>> =
  LazyLock::new(Default::default);

impl RejectLimiter {
  fn record(
    &mut self,
    key: (&str, &str, u16),
    now: Instant,
  ) -> (bool, usize) {
    let global = self.global.get_or_insert((now, 0));
    if now.duration_since(global.0) >= WINDOW {
      *global = (now, 0);
      self.buckets.retain(|_, bucket| {
        bucket.folded > 0 || now.duration_since(bucket.at) < WINDOW
      });
    }
    let key = (key.0.to_string(), key.1.to_string(), key.2);
    if self.buckets.len() >= 4096
      && !self.buckets.contains_key(&key)
      && let Some(oldest) = self
        .buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.at)
        .map(|(key, _)| key.clone())
    {
      self.buckets.remove(&oldest);
    }
    let limit = if key.0 == "anonymous" { 5 } else { 30 };
    let bucket = self.buckets.entry(key).or_insert(Bucket {
      at: now,
      details: 0,
      folded: 0,
    });
    let expired = now.duration_since(bucket.at) >= WINDOW;
    let mut summary = 0;
    if (expired || bucket.folded >= 99)
      && bucket.folded > 0
      && global.1 < 120
    {
      summary = std::mem::take(&mut bucket.folded);
      global.1 += 1;
    }
    if expired {
      bucket.at = now;
      bucket.details = 0;
    }
    if bucket.details < limit && global.1 < 120 {
      bucket.details += 1;
      global.1 += 1;
      (true, summary)
    } else if summary > 0 && !expired {
      (false, summary + 1)
    } else {
      bucket.folded = bucket.folded.saturating_add(1);
      (false, summary)
    }
  }
}

fn redact_row(row: &mut AuditEntry) {
  row.path = crate::log_redact::redact_text(&row.path);
  row.detail = row
    .detail
    .take()
    .map(|s| crate::log_redact::redact_text(&s));
  row.source = row
    .source
    .take()
    .map(|s| crate::log_redact::redact_text(&s));
}

async fn insert(
  state: &AppState,
  mut row: AuditEntry,
) -> Result<(), ApiError> {
  redact_row(&mut row);
  let result = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO audit_log (at, kind, actor, method, path, status, duration_ms, detail, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![row.at, row.kind, row.actor, row.method, row.path,
          row.status, row.duration_ms, row.detail, row.source],
      )
      .map(|_| ())
      .map_err(sql_err)
    })
    .await;
  if let Err(e) = &result {
    tracing::warn!("记录操作失败：{}", e.message);
  }
  result
}

pub async fn cleanup(state: &AppState) -> Result<(), ApiError> {
  static LAST_CLEANUP: Mutex<Option<Instant>> = Mutex::new(None);
  {
    let mut last =
      LAST_CLEANUP.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_some_and(|at| at.elapsed() < Duration::from_secs(3600))
    {
      return Ok(());
    }
    *last = Some(Instant::now());
  }
  state.db.call(|c| cleanup_rows(c, now_ms())).await
}

fn cleanup_rows(
  c: &rusqlite::Connection,
  now: i64,
) -> Result<(), ApiError> {
  const DAY: i64 = 24 * 3600 * 1000;
  c.execute(
    "DELETE FROM audit_log WHERE at < ?1
       OR (method IN ('login_failed', 'gate_key_failed') AND at < ?2)
       OR (actor = 'anonymous' AND status IN (401, 403) AND at < ?2)",
    params![now - 90 * DAY, now - 7 * DAY],
  )
  .map(|_| ())
  .map_err(sql_err)
}

/// 记一条登录类的记录。`action` 是 login / login_failed / gate_key_failed / logout / setup。
pub async fn login_event(
  state: &AppState,
  action: &str,
  actor: &str,
  source: String,
) {
  let _ = insert(
    state,
    AuditEntry {
      id: 0,
      at: now_ms(),
      kind: "login".into(),
      actor: actor.to_string(),
      method: action.to_string(),
      path: String::new(),
      status: None,
      duration_ms: None,
      detail: None,
      source: Some(source),
    },
  )
  .await;
}

#[derive(Deserialize)]
pub struct AuditQuery {
  actor: Option<String>,
  kind: Option<String>,
  before: Option<i64>,
  limit: Option<u32>,
}

/// `GET /api/audit`
pub async fn list(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<AuditQuery>,
) -> ApiResult<Vec<AuditEntry>> {
  auth.require(Perm::Admin)?;
  let mut rows: Vec<AuditEntry> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT id, at, kind, actor, method, path, status, duration_ms, detail, source
           FROM audit_log WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR kind = ?2)
           AND (?3 IS NULL OR id < ?3) ORDER BY id DESC LIMIT ?4",
        )
        .map_err(sql_err)?;
      stmt
        .query_map(
          params![q.actor, q.kind, q.before, q.limit.unwrap_or(100).min(500)],
          |r| {
            Ok(AuditEntry {
              id: r.get(0)?,
              at: r.get(1)?,
              kind: r.get(2)?,
              actor: r.get(3)?,
              method: r.get(4)?,
              path: r.get(5)?,
              status: r.get(6)?,
              duration_ms: r.get(7)?,
              detail: r.get(8)?,
              source: r.get(9)?,
            })
          },
        )
        .and_then(Iterator::collect)
        .map_err(sql_err)
    })
    .await?;
  rows.iter_mut().for_each(redact_row);
  Ok(Json(rows))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decodes_reason() {
    assert_eq!(
      percent_decode("%E5%8D%87%E7%BA%A7%20a").as_deref(),
      Some("升级 a")
    );
    assert_eq!(percent_decode("%E5%8"), None);
  }

  #[test]
  fn only_operations_and_sensitive_reads_are_recorded() {
    assert!(should_record(&Method::POST, "/api/apply"));
    assert!(should_record(&Method::DELETE, "/api/secrets/X"));
    assert!(should_record(&Method::GET, "/api/export"));
    assert!(should_record(
      &Method::GET,
      "/api/services/blog/terminal"
    ));
    assert!(!should_record(&Method::GET, "/api/services"));
    assert!(!should_record(&Method::GET, "/api/services/blog/logs"));
    assert!(!should_record(&Method::POST, "/ping/abc"));
    assert!(!should_record(&Method::POST, "/agent/join"));
    assert!(!should_record(&Method::POST, "/api/login"));
  }
}

#[cfg(test)]
#[test]
fn shell_log_redacts_commands_and_audit_records_sensitive_reads() {
  assert_eq!(
    crate::redact::redact_command(
      "curl -H 'Authorization: Bearer tok123' -e API_KEY=xyz https://example.com"
    ),
    "curl -H 'Authorization: Bearer ***' -e API_KEY=*** https://example.com",
  );
  for path in [
    "/api/shell-log",
    "/api/oidc/clients/a.com/secret",
    "/api/servers/s1/dirs",
    "/api/edge/w/script",
    "/api/servers/s1/host-units",
    "/api/servers/s1/host-units/app.service/logs",
  ] {
    assert!(should_record(&Method::GET, path), "{path}");
  }
}

#[test]
fn folds_anonymous_rejections_into_one_summary() {
  let mut limiter = RejectLimiter::default();
  let now = Instant::now();
  let source = ("anonymous", "203.0.113.1", 401);
  for i in 0..20 {
    assert_eq!(limiter.record(source, now), (i < 5, 0));
  }
  assert_eq!(limiter.record(source, now + WINDOW), (true, 15));
}
