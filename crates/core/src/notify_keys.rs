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
  extract::{Path, State},
  http::{HeaderMap, StatusCode},
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use wharf_api_types::{ApiError, validate_name, view::Perm};

use crate::{
  api::ApiResult,
  auth::{Auth, hash_token, new_token},
  db::{now_ms, sql_err},
  notify::Event,
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
  let mut text = text.trim().to_string();
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

fn rate_ok(hash: &str) -> bool {
  static SEEN: Mutex<Option<HashMap<String, Vec<Instant>>>> =
    Mutex::new(None);
  let mut guard = SEEN.lock().unwrap_or_else(|e| e.into_inner());
  let seen = guard.get_or_insert_with(HashMap::new);
  let now = Instant::now();
  let list = seen.entry(hash.to_string()).or_default();
  list.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
  if list.len() >= PER_MINUTE {
    return false;
  }
  list.push(now);
  true
}

/// `POST /notify/{token}`：不用登录，口令就是凭证。
pub async fn send(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  headers: HeaderMap,
  body: String,
) -> (StatusCode, Json<Value>) {
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
  if !rate_ok(&hash) {
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
  let now = now_ms();
  let _ = s
    .db
    .call(move |c| {
      c.execute(
        "UPDATE notify_keys SET last_used_at = ?2 WHERE hash = ?1",
        params![hash, now],
      )
      .map_err(sql_err)
    })
    .await;
  let skipped = crate::rules::notice(
    &s,
    "notify_hook",
    Some(&name),
    None,
    false,
    event,
  )
  .await;
  match skipped.as_deref() {
    Some(reason)
      if reason == "没有配置通知渠道"
        || reason.starts_with("发送失败：")
        || reason.starts_with("处理失败：") =>
    {
      (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "ok": false, "error": reason })),
      )
    }
    _ => (StatusCode::OK, Json(json!({ "ok": true }))),
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
