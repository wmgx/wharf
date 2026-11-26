//! 通知出口：给自己的服务和脚本发通知用的地址 `POST /notify/<口令>`，消息走 Wharf 已配置的通知渠道。
//!
//! 每个调用方一个凭证（按名字）。完整地址同时存成密钥 `NOTIFY_URL_<名字>`，
//! 服务在环境变量里写 `[[NOTIFY_URL_<名字>]]` 就能用，不用把地址抄来抄去。删凭证时密钥一起删。

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{ConnectInfo, Path, State},
  http::{HeaderMap, StatusCode},
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use wharf_api_types::{ApiError, validate_name, view::Perm};

use crate::{
  api::ApiResult,
  auth::{Auth, hash_token, new_token},
  db::{now_ms, sql_err},
  notify::{self, Event},
  state::AppState,
};

pub const SECRET_PREFIX: &str = "NOTIFY_URL_";
/// 消息最长 8 KB，超出截断。
const MAX_BODY: usize = 8 * 1024;
/// 每个凭证每分钟最多发这么多条，防止脚本写错了刷屏。
const PER_MINUTE: usize = 20;

pub fn secret_name(name: &str) -> String {
  format!(
    "{SECRET_PREFIX}{}",
    name.to_ascii_uppercase().replace('-', "_")
  )
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<Value>> {
  auth.require(Perm::Read)?;
  Ok(Json(
    s.db
      .call(|c| {
        let mut stmt = c
          .prepare("SELECT name, created_at, last_used_at FROM notify_keys ORDER BY name")
          .map_err(sql_err)?;
        let rows = stmt
          .query_map([], |r| {
            let name: String = r.get(0)?;
            Ok(json!({
              "name": name,
              "secret": secret_name(&name),
              "created_at": r.get::<_, i64>(1)?,
              "last_used_at": r.get::<_, Option<i64>>(2)?,
            }))
          })
          .map_err(sql_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
      })
      .await?,
  ))
}

/// 新建凭证，返回完整地址。同名已存在时换一个新口令，旧地址失效。
pub async fn create(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  validate_name("通知凭证", &name)?;
  let base = crate::join::default_url(&s).await.ok_or_else(|| {
    ApiError::invalid("不知道控制面的访问地址，没法生成通知地址")
      .with_hint("先给控制面配一个域名或公网地址")
  })?;
  let token =
    format!("wnk_{}", new_token().trim_start_matches("wh_"));
  let url = format!("{}/notify/{token}", base.trim_end_matches('/'));
  let secret = secret_name(&name);
  let (n, sec, u) = (name.clone(), secret.clone(), url.clone());
  s.db
    .call_credentials(move |c, key| {
      let tx = c.unchecked_transaction().map_err(sql_err)?;
      tx.execute(
        "INSERT INTO notify_keys (name, hash, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (name) DO UPDATE SET hash = excluded.hash, created_at = excluded.created_at, last_used_at = NULL",
        params![n, hash_token(&token), now_ms()],
      )
      .map_err(sql_err)?;
      key.put_secret(&tx, &sec, &u, now_ms(), true)?;
      tx.commit().map_err(sql_err)
    })
    .await?;
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(json!({ "name": name, "secret": secret, "url": url })))
}

pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let secret = secret_name(&name);
  let removed = s
    .db
    .call(move |c| {
      let tx = c.unchecked_transaction().map_err(sql_err)?;
      let n = tx
        .execute("DELETE FROM notify_keys WHERE name = ?1", [&name])
        .map_err(sql_err)?;
      tx.execute("DELETE FROM secrets WHERE name = ?1", [&secret])
        .map_err(sql_err)?;
      tx.commit().map_err(sql_err)?;
      Ok(n)
    })
    .await?;
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(json!({ "removed": removed > 0 })))
}

/// 消息的标题和正文：JSON `{ "title", "text" }`，或者整个请求体就是正文。
fn message(
  headers: &HeaderMap,
  body: &str,
) -> (Option<String>, String) {
  let json = headers
    .get("content-type")
    .and_then(|v| v.to_str().ok())
    .is_some_and(|v| v.starts_with("application/json"));
  let (title, text) = match serde_json::from_str::<Value>(body) {
    Ok(v) if json || v.is_object() => (
      v["title"].as_str().map(str::to_string),
      v["text"]
        .as_str()
        .or_else(|| v["message"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| body.to_string()),
    ),
    _ => (None, body.to_string()),
  };
  let mut text = crate::log_redact::redact_text(text.trim());
  if text.len() > MAX_BODY {
    let mut end = MAX_BODY;
    while !text.is_char_boundary(end) {
      end -= 1;
    }
    text.truncate(end);
    text.push_str("\n…（太长，已截断）");
  }
  (title.filter(|t| !t.trim().is_empty()), text)
}

#[derive(Default)]
pub(crate) struct RequestLimit {
  seen: HashMap<String, Vec<Instant>>,
  pruned_at: Option<Instant>,
}

impl RequestLimit {
  pub fn blocked(&mut self, key: &str, limit: usize) -> bool {
    let now = Instant::now();
    let active = |time: &Instant| {
      now.duration_since(*time) < Duration::from_secs(60)
    };
    if self.pruned_at.is_none_or(|last| !active(&last)) {
      self
        .seen
        .retain(|_, times| times.last().is_some_and(active));
      self.pruned_at = Some(now);
    }
    self.seen.get_mut(key).is_some_and(|times| {
      times.retain(active);
      times.len() >= limit
    })
  }

  pub fn record(&mut self, key: &str, limit: usize) -> bool {
    if self.blocked(key, limit) {
      return false;
    }
    if self.seen.len() >= 4096
      && !self.seen.contains_key(key)
      && let Some(oldest) = self
        .seen
        .iter()
        .min_by_key(|(_, times)| times.last())
        .map(|(key, _)| key.clone())
    {
      self.seen.remove(&oldest);
    }
    self
      .seen
      .entry(key.to_string())
      .or_default()
      .push(Instant::now());
    true
  }
}

static INVALID_SEEN: std::sync::LazyLock<Mutex<RequestLimit>> =
  std::sync::LazyLock::new(Default::default);
static SEEN: std::sync::LazyLock<Mutex<RequestLimit>> =
  std::sync::LazyLock::new(Default::default);

fn limited() -> (StatusCode, Json<Value>) {
  (
    StatusCode::TOO_MANY_REQUESTS,
    Json(json!({ "ok": false, "error": "请求过于频繁" })),
  )
}

/// `POST /notify/{token}`：不用登录，口令就是凭证。
pub async fn send(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
  body: String,
) -> (StatusCode, Json<Value>) {
  let source = crate::login::client_key(peer.ip(), &headers);
  if INVALID_SEEN
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .blocked(&source, PER_MINUTE)
  {
    return limited();
  }
  let hash = hash_token(&token);
  let h = hash.clone();
  let found = s
    .db
    .call(move |c| {
      c.query_row(
        "SELECT name FROM notify_keys WHERE hash = ?1",
        [&h],
        |r| r.get::<_, String>(0),
      )
      .optional()
      .map_err(sql_err)
    })
    .await;
  let name = match found {
    Ok(Some(name)) => name,
    Ok(None) => {
      if !INVALID_SEEN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record(&source, PER_MINUTE)
      {
        return limited();
      }
      return (
        StatusCode::NOT_FOUND,
        Json(json!({ "ok": false, "error": "地址不对或已失效" })),
      );
    }
    Err(_) => {
      return (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "error": "稍后再试" })),
      );
    }
  };
  if !SEEN
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .record(&hash, PER_MINUTE)
  {
    return (
      StatusCode::TOO_MANY_REQUESTS,
      Json(
        json!({ "ok": false, "error": format!("每分钟最多 {PER_MINUTE} 条") }),
      ),
    );
  }
  let (title, text) = message(&headers, &body);
  if text.is_empty() && title.is_none() {
    return (
      StatusCode::BAD_REQUEST,
      Json(json!({ "ok": false, "error": "消息是空的" })),
    );
  }
  let event = Event {
    title: match title {
      Some(t) => format!("{name}：{t}"),
      None => name.clone(),
    },
    body: text,
  };
  match notify::send(&s, &event).await {
    Ok(()) => {
      let now = now_ms();
      let _ = s.db.call(move |c| {
        c.execute(
          "UPDATE notify_keys SET last_used_at = MAX(COALESCE(last_used_at, 0), ?2) WHERE hash = ?1",
          params![hash, now],
        ).map_err(sql_err)
      }).await;
      (StatusCode::OK, Json(json!({ "ok": true })))
    }
    Err(e) => {
      tracing::warn!(
        "通知出口 {name} 发送失败：{}",
        crate::log_redact::redact_text(&e.message)
      );
      (
        StatusCode::BAD_GATEWAY,
        Json(
          json!({ "ok": false, "error": "通知发送失败，请检查控制面通知渠道配置" }),
        ),
      )
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_json_or_plain_text() {
    let json_headers = HeaderMap::from_iter([(
      axum::http::header::CONTENT_TYPE,
      "application/json".parse().unwrap(),
    )]);
    assert_eq!(
      message(&json_headers, r#"{"title":"备份","text":"完成"}"#),
      (Some("备份".into()), "完成".into())
    );
    assert_eq!(
      message(&HeaderMap::new(), "磁盘快满了\n"),
      (None, "磁盘快满了".into())
    );
    assert_eq!(secret_name("nas-backup"), "NOTIFY_URL_NAS_BACKUP");
  }
}

#[test]
fn limits_invalid_notification_sources() {
  let mut seen = RequestLimit::default();
  for _ in 0..20 {
    assert!(seen.record("203.0.113.1", PER_MINUTE));
  }
  assert!(seen.blocked("203.0.113.1", PER_MINUTE));
  assert!(!seen.blocked("203.0.113.2", PER_MINUTE));
}

#[tokio::test]
async fn notify_limits_unknown_tokens_and_only_marks_successful_delivery()
 {
  let state = crate::rules::tests::test_state();
  let peer = ConnectInfo("203.0.113.13:12345".parse().unwrap());
  let send_to = |token: &str, peer| {
    send(
      State(state.clone()),
      Path(token.to_string()),
      peer,
      HeaderMap::new(),
      "fixture message".into(),
    )
  };
  for index in 0..25 {
    let (status, _) = send_to("invalid-fixture", peer).await;
    assert_eq!(
      status,
      if index < 20 {
        StatusCode::NOT_FOUND
      } else {
        StatusCode::TOO_MANY_REQUESTS
      }
    );
  }
  state.db.call(|c| {
    c.execute("INSERT INTO notify_keys (name, hash, created_at) VALUES ('fixture', ?1, 0)", [hash_token("fixture-valid")])
      .map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let (status, body) = send_to(
    "fixture-valid",
    ConnectInfo("203.0.113.14:12345".parse().unwrap()),
  )
  .await;
  assert_eq!(status, StatusCode::BAD_GATEWAY);
  assert_eq!(
    body.0["error"],
    "通知发送失败，请检查控制面通知渠道配置"
  );
  let last = state
    .db
    .call(|c| {
      c.query_row(
        "SELECT last_used_at FROM notify_keys WHERE name = 'fixture'",
        [],
        |row| row.get::<_, Option<i64>>(0),
      )
      .map_err(sql_err)
    })
    .await
    .unwrap();
  assert!(last.is_none());
}
