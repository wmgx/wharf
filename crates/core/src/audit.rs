//! 通过鉴权的操作和页面登录记录。

use std::{
  sync::{Arc, Mutex},
  time::Instant,
};

use axum::{
  Json,
  extract::{Query, Request, State},
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
}

impl AuditSlot {
  pub fn set_actor(&self, actor: &str) {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).actor =
      Some(actor.to_string());
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
  let slot = AuditSlot::default();
  req.extensions_mut().insert(slot.clone());
  let resp = next.run(req).await;
  let (actor, detail, required) = {
    let mut slot = slot.0.lock().unwrap_or_else(|e| e.into_inner());
    (slot.actor.take(), slot.detail.take(), slot.required)
  };
  if let Some(actor) = actor
    && should_record(&method, &path)
  {
    let result = insert(
      &state,
      AuditEntry {
        id: 0,
        at: now_ms(),
        kind: "api".into(),
        actor,
        method: method.to_string(),
        path,
        status: Some(resp.status().as_u16()),
        duration_ms: Some(started.elapsed().as_millis() as i64),
        detail: match (detail, reason) {
          (Some(d), Some(r)) => Some(format!("{d} 原因：{r}")),
          (None, Some(r)) => Some(format!("原因：{r}")),
          (d, None) => d,
        },
        source: None,
      },
    )
    .await;
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

async fn insert(
  state: &AppState,
  row: AuditEntry,
) -> Result<(), ApiError> {
  let result = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO audit_log (at, kind, actor, method, path, status, duration_ms, detail, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![row.at, row.kind, row.actor, row.method, row.path,
          row.status, row.duration_ms, row.detail, row.source],
      )
      .and_then(|_| {
        c.execute(
          "DELETE FROM audit_log WHERE at < ?1 OR (method IN ('login_failed', 'gate_key_failed') AND at < ?2)",
          params![row.at - 90 * 24 * 3600 * 1000, row.at - 7 * 24 * 3600 * 1000],
        )
      })
      .map(|_| ())
      .map_err(sql_err)
    })
    .await;
  if let Err(e) = &result {
    tracing::warn!("记录操作失败：{}", e.message);
  }
  result
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
  let rows = state
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
