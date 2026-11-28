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
  skipped: bool,
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
    self.0.lock().unwrap_or_else(|e| e.into_inner()).skipped = true;
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
  let (actor, detail, required, skipped, rejection) = {
    let mut slot = slot.0.lock().unwrap_or_else(|e| e.into_inner());
    (
      slot.actor.take(),
      slot.detail.take(),
      slot.required,
      slot.skipped,
      slot.rejection.take(),
    )
  };
  let status = resp.status().as_u16();
  let rejected = matches!(status, 401 | 403)
    && path.starts_with("/api/")
    && !matches!(path.as_str(), "/api/login" | "/api/setup");
  if rejected
    || (!skipped && actor.is_some() && should_record(&method, &path))
  {
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
      || path.ends_with("/artifacts/download")
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

pub(crate) async fn insert(
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
    params![
      now
        - i64::from(crate::config_api::number(
          c,
          "retention.audit_days"
        )?)
          * DAY,
      now - 7 * DAY
    ],
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

#[derive(Default, Deserialize)]
pub struct AuditQuery {
  actor: Option<String>,
  kind: Option<String>,
  before: Option<i64>,
  limit: Option<u32>,
  since: Option<String>,
  until: Option<String>,
  target: Option<String>,
  errors: Option<String>,
  status: Option<u16>,
}

pub(crate) fn parse_time_bound(
  raw: &str,
  is_until: bool,
  offset: chrono::FixedOffset,
) -> Result<i64, ApiError> {
  use chrono::TimeZone;
  let raw = raw.trim();
  let now = now_ms();
  if raw == "now" {
    return Ok(now);
  }
  if let Ok(ms) = raw.parse::<i64>() {
    return Ok(ms);
  }
  if let Ok(at) = chrono::DateTime::parse_from_rfc3339(raw) {
    return Ok(at.timestamp_millis());
  }
  if let Some(relative) = crate::log_search::since_arg(raw) {
    let (digits, unit) = relative.split_at(relative.len() - 1);
    let multiplier = match unit {
      "h" => 3_600_000,
      "m" => 60_000,
      _ => 1_000,
    };
    if let Some(at) = digits
      .parse::<i64>()
      .ok()
      .and_then(|n| n.checked_mul(multiplier))
      .and_then(|ms| now.checked_sub(ms))
    {
      return Ok(at);
    }
  }
  let local =
    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M")
      .ok()
      .or_else(|| {
        let day =
          chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
        if is_until {
          day.and_hms_milli_opt(23, 59, 59, 999)
        } else {
          day.and_hms_opt(0, 0, 0)
        }
      });
  local
    .and_then(|at| offset.from_local_datetime(&at).single())
    .map(|at| at.timestamp_millis())
    .ok_or_else(|| {
      ApiError::invalid("审计时间格式不对").with_hint(
        "可以用 24h、2026-11-28、2026-11-28 10:00 或 RFC3339 时间",
      )
    })
}

pub(crate) fn target_patterns(
  target: &str,
) -> Result<(Vec<String>, String), ApiError> {
  let escape = |s: &str| {
    s.replace('\\', "\\\\")
      .replace('%', "\\%")
      .replace('_', "\\_")
  };
  let target = target.trim();
  if target.is_empty() {
    return Err(ApiError::invalid("审计目标不能为空"));
  }
  let Some((kind, name)) = target.split_once('/') else {
    let name = escape(target);
    return Ok((
      vec![format!("%/{name}"), format!("%/{name}/%")],
      format!("%{name}%"),
    ));
  };
  if name.is_empty() || name.contains('/') {
    return Err(ApiError::invalid("审计目标应写成 类型/名称"));
  }
  let name = escape(name);
  let collection = match kind {
    "service" => "services",
    "server" => "servers",
    "gateway" => "gateways",
    "route" => "routes",
    "secret" => "secrets",
    "task" => "tasks",
    "token" => "tokens",
    "edge" => "edge",
    "account" => "accounts",
    _ => return Err(ApiError::invalid("未知审计目标类型")),
  };
  let mut paths = vec![
    format!("/api/{collection}/{name}"),
    format!("/api/{collection}/{name}/%"),
  ];
  if kind == "service" {
    paths.push(format!("/api/alerts/%/services/{name}"));
  }
  if kind == "route" {
    paths.push(format!("/api/oidc/clients/{name}/%"));
  }
  let detail = match kind {
    "secret" => format!("%{name}%"),
    "task" | "token" | "edge" | "account" => String::new(),
    _ => format!("%{kind}/{name}%"),
  };
  Ok((paths, detail))
}

/// `GET /api/audit`
pub async fn list(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<AuditQuery>,
) -> ApiResult<Vec<AuditEntry>> {
  auth.require(Perm::Admin)?;
  let mut rows = state.db.call(move |c| query_rows(c, q)).await?;
  rows.iter_mut().for_each(redact_row);
  Ok(Json(rows))
}

fn query_rows(
  c: &rusqlite::Connection,
  q: AuditQuery,
) -> Result<Vec<AuditEntry>, ApiError> {
  let offset = crate::config_api::offset(c)?;
  let bound = |raw: Option<String>, until| {
    raw
      .as_deref()
      .map(|s| parse_time_bound(s, until, offset))
      .transpose()
  };
  let since = bound(q.since, false)?;
  let until = bound(q.until, true)?;
  if since.zip(until).is_some_and(|(since, until)| since > until) {
    return Err(
      ApiError::invalid("since 不能晚于 until")
        .with_hint("例如 --since 24h --until now"),
    );
  }
  if q.status.is_some_and(|code| !(100..=599).contains(&code)) {
    return Err(ApiError::invalid("审计状态码须在 100 到 599 之间"));
  }
  let mut sql = String::from(
    "SELECT id, at, kind, actor, method, path, status, duration_ms, detail, source
     FROM audit_log WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR kind = ?2)
     AND (?3 IS NULL OR id < ?3) AND (?4 IS NULL OR at >= ?4) AND (?5 IS NULL OR at <= ?5)
     AND (?6 IS NULL OR status = ?6)
     AND ?8 >= 0 AND (NOT ?7 OR status >= 400 OR method IN ('login_failed', 'gate_key_failed'))"
  );
  let limit = q.limit.unwrap_or(100).min(500);
  let errors = matches!(q.errors.as_deref(), Some("1" | "true"));
  let mut bind: Vec<&dyn rusqlite::ToSql> = vec![
    &q.actor, &q.kind, &q.before, &since, &until, &q.status, &errors,
    &limit,
  ];
  let target =
    q.target.as_deref().map(target_patterns).transpose()?;
  if let Some((paths, detail)) = &target {
    sql.push_str(" AND (");
    for (i, path) in paths.iter().enumerate() {
      if i > 0 {
        sql.push_str(" OR ");
      }
      sql.push_str("path LIKE ? ESCAPE '\\'");
      bind.push(path);
    }
    if !detail.is_empty() {
      if q
        .target
        .as_deref()
        .is_some_and(|t| t.trim().starts_with("secret/"))
      {
        sql.push_str(" OR (path = '/api/secrets/import' AND detail LIKE ? ESCAPE '\\')");
      } else {
        sql.push_str(" OR detail LIKE ? ESCAPE '\\'");
      }
      bind.push(detail);
    }
    sql.push(')');
  }
  sql.push_str(" ORDER BY id DESC LIMIT ?8");
  let mut stmt = c.prepare(&sql).map_err(sql_err)?;
  stmt
    .query_map(rusqlite::params_from_iter(bind), |r| {
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
    })
    .and_then(Iterator::collect)
    .map_err(sql_err)
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

#[tokio::test]
async fn audit_cleanup_keeps_seven_and_ninety_day_windows() {
  const DAY: i64 = 24 * 3600 * 1000;
  let db = crate::db::Db::memory();
  db.call(|c| {
    for (actor, method, status, days) in [
      ("anonymous", "GET", Some(401), 8),
      ("anonymous", "GET", Some(403), 6),
      ("s1", "GET", Some(403), 8),
      ("s1", "GET", Some(403), 91),
      ("s1", "login_failed", None, 8),
    ] {
      c.execute("INSERT INTO audit_log (at, kind, actor, method, path, status) VALUES (?1, 'api', ?2, ?3, '/api/services', ?4)",
        params![(100 - days) * DAY, actor, method, status]).map_err(sql_err)?;
    }
    cleanup_rows(c, 100 * DAY)?;
    let mut stmt = c.prepare("SELECT actor FROM audit_log ORDER BY id").map_err(sql_err)?;
    let actors = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(sql_err)?
      .collect::<Result<Vec<_>, _>>().map_err(sql_err)?;
    assert_eq!(actors, ["anonymous", "s1"]);
    Ok(())
  }).await.unwrap();
}

#[tokio::test]
async fn invalid_session_cookie_uses_anonymous_audit_limits() {
  use axum::body::Body;
  use tower::ServiceExt;

  let state = crate::rules::tests::test_state();
  let app = crate::api::router(state.clone());
  for (origin, status) in
    [(None, 401), (Some("https://other.test"), 403)]
  {
    for _ in 0..6 {
      let mut request = axum::http::Request::builder()
        .uri("/api/services")
        .header("host", "wharf.test")
        .header("cookie", "wharf_session=fixture-invalid")
        .extension(ConnectInfo(
          "203.0.113.17:12345"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        ));
      if let Some(origin) = origin {
        request = request.header("origin", origin);
      }
      let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
      assert_eq!(response.status().as_u16(), status);
    }
  }
  state
    .db
    .call(|c| {
      let (all, anonymous): (i64, i64) = c
        .query_row(
          "SELECT count(*), sum(actor = 'anonymous') FROM audit_log",
          [],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql_err)?;
      assert_eq!((all, anonymous), (10, 10));
      let now = now_ms();
      c.execute(
        "UPDATE audit_log SET at = ?1",
        [now - 8 * 86_400_000],
      )
      .map_err(sql_err)?;
      cleanup_rows(c, now)?;
      let remaining: i64 = c
        .query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))
        .map_err(sql_err)?;
      assert_eq!(remaining, 0);
      Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn out_of_scope_plan_audits_the_authenticated_actor() {
  use axum::body::Body;
  use tower::ServiceExt;

  let state = crate::rules::tests::test_state();
  state
    .db
    .call(|c| {
      crate::auth::insert_token(
        c,
        "ci",
        &[Perm::Plan],
        "fixture-plan",
      )?;
      c.execute(
        "UPDATE api_tokens SET services = 'svc-a' WHERE name = 'ci'",
        [],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
    .unwrap();
  let request = axum::http::Request::post("/api/plan")
    .header("authorization", "Bearer fixture-plan")
    .header("content-type", "application/json")
    .extension(crate::cli_tunnel::Sealed)
    .body(Body::from(
      r#"{"changes":[{"op":"remove_service","name":"svc-b"}]}"#,
    ))
    .unwrap();
  let response = crate::api::router(state.clone())
    .oneshot(request)
    .await
    .unwrap();
  assert_eq!(response.status().as_u16(), 403);
  let actor = state.db.call(|c| {
    c.query_row("SELECT actor FROM audit_log WHERE path = '/api/plan' AND status = 403", [], |r| r.get::<_, String>(0))
      .map_err(sql_err)
  }).await.unwrap();
  assert_eq!(actor, "ci");
}

#[tokio::test]
async fn requests_audit_anonymous_expired_and_service_scope_rejections()
 {
  use axum::{
    Router, body::Body, middleware::from_fn_with_state, routing::get,
  };
  use tower::ServiceExt;
  let state = crate::rules::tests::test_state();
  state
    .db
    .call(|c| {
      crate::auth::insert_token(
        c,
        "expired",
        &[Perm::Read],
        "fixture-expired",
      )?;
      crate::auth::insert_token(
        c,
        "scoped",
        &[Perm::Read],
        "fixture-scoped",
      )?;
      c.execute_batch(
        "UPDATE api_tokens SET expires_at = 1 WHERE name = 'expired';
      UPDATE api_tokens SET services = 'app1' WHERE name = 'scoped'",
      )
      .map_err(sql_err)
    })
    .await
    .unwrap();
  let app = Router::new()
    .route("/api/services", get(|_: Auth| async { "ok" }))
    .route("/api/services/app2/logs", get(|_: Auth| async { "ok" }))
    .layer(from_fn_with_state(state.clone(), layer))
    .with_state(state.clone());
  for (path, token, expected) in [
    ("/api/services", None, 401),
    ("/api/services", Some("fixture-expired"), 401),
    ("/api/services/app2/logs", Some("fixture-scoped"), 403),
  ] {
    let mut request = axum::http::Request::builder()
      .uri(path)
      .extension(ConnectInfo(
        "203.0.113.16:12345"
          .parse::<std::net::SocketAddr>()
          .unwrap(),
      ))
      .extension(crate::cli_tunnel::Sealed);
    if let Some(token) = token {
      request =
        request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
      .clone()
      .oneshot(request.body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status().as_u16(), expected);
  }
  state.db.call(|c| {
    let mut stmt = c.prepare("SELECT actor, source, status, detail FROM audit_log ORDER BY id").map_err(sql_err)?;
    let entries = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u16>(2)?, row.get::<_, String>(3)?)))
      .map_err(sql_err)?.collect::<Result<Vec<_>, _>>().map_err(sql_err)?;
    assert_eq!(entries.len(), 3);
    for ((actor, source, status, detail), (expected_actor, expected_status)) in entries.iter().zip([("anonymous", 401), ("expired", 401), ("scoped", 403)]) {
      assert_eq!(actor, expected_actor);
      assert_eq!(source, "203.0.113.16");
      assert_eq!(*status, expected_status);
      assert!(!detail.is_empty() && !detail.contains("fixture-"));
    }
    Ok(())
  }).await.unwrap();
}

#[tokio::test]
async fn audit_filters_recent_target_failures() {
  let db = crate::db::Db::memory();
  db.call(|c| {
    let now = now_ms();
    for (at, method, path, status) in [
      (now - 86_400_000, "GET", "/api/services/blog", Some(200)),
      (now, "GET", "/api/services/blog/logs", Some(403)),
      (now, "GET", "/api/services/other", Some(200)),
      (now, "login_failed", "", None),
    ] {
      c.execute("INSERT INTO audit_log (at, kind, actor, method, path, status) VALUES (?1, 'api', 'fixture', ?2, ?3, ?4)",
        params![at, method, path, status]).map_err(sql_err)?;
    }
    let filtered = query_rows(c, AuditQuery { since: Some("6h".into()), target: Some("service/blog".into()), errors: Some("true".into()), ..Default::default() })?;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].status, Some(403));
    assert_eq!(query_rows(c, AuditQuery { errors: Some("true".into()), ..Default::default() })?.len(), 2);
    assert!(query_rows(c, AuditQuery { since: Some("10".into()), until: Some("1".into()), ..Default::default() }).is_err());
    Ok(())
  }).await.unwrap();
}
