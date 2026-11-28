//! 通知渠道：把消息推到一个地方。什么时候推由 [crate::rules] 决定（告警规则和事件通知的开关）。
//!
//! 渠道从密钥里读，有哪个就用哪个；以后加渠道就是 [Channel] 多一种。
//! - 飞书群自定义机器人：`NOTIFY_FEISHU_WEBHOOK`，开了签名校验时再设 `NOTIFY_FEISHU_SECRET`。

use std::{sync::Arc, time::Duration};

use rusqlite::params;
use wharf_providers::http::Http;

use base64::Engine;
use sha2::{Digest, Sha256};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{db, state::AppState};

pub const FEISHU_WEBHOOK: &str = "NOTIFY_FEISHU_WEBHOOK";
pub const FEISHU_SECRET: &str = "NOTIFY_FEISHU_SECRET";
const TIMEOUT: Duration = Duration::from_secs(10);
const IMMEDIATE_DELAYS: &[u64] = &[1, 3];
const RETRY_DELAYS_MS: [i64; 4] = [30_000, 120_000, 300_000, 900_000];
const RETRY_TTL_MS: i64 = 3_600_000;
const MAX_RETRY_QUEUE: i64 = 100;

pub const RETRY_MIGRATION: &str = "
  CREATE TABLE notify_retry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_id INTEGER,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_error TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX notify_retry_next ON notify_retry (next_at);";

pub(crate) enum SendErr {
  Retryable(ApiError),
  Permanent(ApiError),
}

impl SendErr {
  pub(crate) fn api(self) -> ApiError {
    match self {
      Self::Retryable(e) | Self::Permanent(e) => e,
    }
  }
}

fn request_error(e: reqwest::Error) -> SendErr {
  let permanent = e.is_builder() || e.is_decode();
  let error = ApiError::new(
    ErrorCode::Provider,
    crate::log_redact::redact_text(&e.without_url().to_string()),
  );
  if permanent {
    SendErr::Permanent(error)
  } else {
    SendErr::Retryable(error)
  }
}

pub struct Event {
  /// 例如"定时任务 sign 失败"。
  pub title: String,
  pub body: String,
}

enum Channel {
  Feishu { url: String, secret: Option<String> },
}

async fn channels(
  state: &AppState,
) -> Result<Vec<Channel>, ApiError> {
  let secrets = state
    .db
    .call_credentials(|c, key| db::secrets(c, key))
    .await?;
  let get = |n: &str| {
    secrets
      .get(n)
      .map(|v| v.trim().to_string())
      .filter(|v| !v.is_empty())
  };
  Ok(
    get(FEISHU_WEBHOOK)
      .map(|url| Channel::Feishu {
        url,
        secret: get(FEISHU_SECRET),
      })
      .into_iter()
      .collect(),
  )
}

/// 发给所有已配置的渠道。没有配置渠道时返回错误，带上怎么配。
pub async fn send(
  state: &AppState,
  event: &Event,
) -> Result<(), ApiError> {
  send_with_retry(state, event, IMMEDIATE_DELAYS)
    .await
    .map_err(SendErr::api)
}

pub(crate) fn redact_event(event: &Event) -> Event {
  Event {
    title: crate::log_redact::redact_text(&event.title),
    body: crate::log_redact::redact_text(&event.body),
  }
}

pub(crate) async fn send_with_retry(
  state: &AppState,
  event: &Event,
  delays: &[u64],
) -> Result<(), SendErr> {
  if state.is_safe_mode() {
    return Err(SendErr::Permanent(ApiError::new(
      ErrorCode::Conflict,
      "安全接管模式已暂停外发通知",
    )));
  }
  let channels = channels(state).await.map_err(SendErr::Permanent)?;
  if channels.is_empty() {
    return Err(SendErr::Permanent(
      ApiError::not_found("没有配置通知渠道").with_hint(format!(
        "设置密钥 {FEISHU_WEBHOOK}（飞书群机器人的 Webhook 地址）"
      )),
    ));
  }
  let event = redact_event(event);
  for ch in &channels {
    for delay in delays.iter().copied().map(Some).chain([None]) {
      let http = Http::new(TIMEOUT).map_err(request_error)?;
      let result = match ch {
        Channel::Feishu { url, secret } => {
          feishu(&http, url, secret.as_deref(), &event).await
        }
      };
      match (result, delay) {
        (Err(SendErr::Retryable(_)), Some(secs)) => {
          tokio::time::sleep(Duration::from_secs(secs)).await;
        }
        (result, _) => {
          result?;
          break;
        }
      }
    }
  }
  Ok(())
}

pub(crate) async fn deliver_tracked(
  state: &AppState,
  event: &Event,
) -> Result<(), SendErr> {
  send_with_retry(state, event, IMMEDIATE_DELAYS).await
}

pub(crate) fn enqueue(
  c: &rusqlite::Connection,
  history_id: i64,
  event: &Event,
  error: &str,
) -> rusqlite::Result<()> {
  let now = db::now_ms();
  c.execute(
    "INSERT INTO notify_retry (history_id, title, body, next_at, created_at, last_error)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![history_id, event.title, event.body, now + RETRY_DELAYS_MS[0], now, error],
  )?;
  c.execute(
    "UPDATE alert_history SET skipped = '重试后仍失败：通知队列已满'
     WHERE id IN (SELECT history_id FROM notify_retry ORDER BY id DESC LIMIT -1 OFFSET ?1)",
    [MAX_RETRY_QUEUE],
  )?;
  c.execute(
    "DELETE FROM notify_retry WHERE id IN (
       SELECT id FROM notify_retry ORDER BY id DESC LIMIT -1 OFFSET ?1
     )",
    [MAX_RETRY_QUEUE],
  )?;
  Ok(())
}

pub fn spawn_retry(state: Arc<AppState>) {
  tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_secs(15)).await;
      if !state.is_safe_mode()
        && let Err(e) = retry_at(&state, db::now_ms()).await
      {
        tracing::warn!("读取通知重试队列失败：{}", e.message);
      }
    }
  });
}

async fn retry_at(
  state: &AppState,
  now: i64,
) -> Result<(), ApiError> {
  let rows = state.db.call(move |c| {
    let mut stmt = c.prepare(
      "SELECT id, history_id, title, body, attempts, created_at, last_error
       FROM notify_retry WHERE next_at <= ?1 OR created_at <= ?2
       ORDER BY next_at, id LIMIT 10",
    ).map_err(db::sql_err)?;
    stmt.query_map(params![now, now - RETRY_TTL_MS], |r| {
      Ok((
        r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?,
        Event { title: r.get(2)?, body: r.get(3)? },
        r.get::<_, usize>(4)?, r.get::<_, i64>(5)?, r.get::<_, String>(6)?,
      ))
    }).map_err(db::sql_err)?.collect::<Result<Vec<_>, _>>().map_err(db::sql_err)
  }).await?;
  for (id, history_id, event, attempts, created_at, last_error) in
    rows
  {
    let result = if created_at <= now - RETRY_TTL_MS {
      Err(SendErr::Permanent(ApiError::new(
        ErrorCode::Provider,
        last_error,
      )))
    } else {
      send_with_retry(state, &event, &[]).await
    };
    if let Err(SendErr::Retryable(e)) = &result
      && let Some(delay) = RETRY_DELAYS_MS.get(attempts + 1)
    {
      let (delay, error) = (*delay, e.message.clone());
      let next = db::now_ms() + delay;
      state.db.call(move |c| {
        c.execute(
          "UPDATE notify_retry SET attempts = attempts + 1, next_at = ?2, last_error = ?3 WHERE id = ?1",
          params![id, next, error],
        ).map_err(db::sql_err)?;
        Ok(())
      }).await?;
      continue;
    }
    let skipped = result.err().map(|e| {
      let error = e.api().message;
      tracing::warn!("通知重试结束：{error}");
      format!("重试后仍失败：{error}")
    });
    state
      .db
      .call(move |c| {
        finish_retry(c, id, history_id, skipped).map_err(db::sql_err)
      })
      .await?;
  }
  Ok(())
}

fn finish_retry(
  c: &rusqlite::Connection,
  id: i64,
  history_id: Option<i64>,
  skipped: Option<String>,
) -> rusqlite::Result<()> {
  let tx = c.unchecked_transaction()?;
  let deleted =
    tx.execute("DELETE FROM notify_retry WHERE id = ?1", [id])?;
  // 发送成功时，即使在途条目被队列淘汰，也要更新历史。
  if deleted > 0 || skipped.is_none() {
    tx.execute(
      "UPDATE alert_history SET skipped = ?1 WHERE id = ?2",
      params![skipped, history_id],
    )?;
  }
  tx.commit()
}

/// 记下 `key` 这次的结果（存在设置 `notify.state.<key>`），返回状态是不是变了。
/// 第一次就成功不算变化；读写失败也不算。
pub async fn transition(
  state: &AppState,
  key: &str,
  ok: bool,
) -> bool {
  let key = key.to_string();
  state
    .db
    .call(move |c| {
      transition_row(c, &format!("notify.state.{key}"), ok)
    })
    .await
    .unwrap_or(false)
}

pub(crate) fn transition_row(
  c: &rusqlite::Connection,
  setting: &str,
  ok: bool,
) -> Result<bool, ApiError> {
  let now = if ok { "ok" } else { "fail" };
  let prev = db::setting(c, setting)?;
  db::set_setting(c, setting, Some(now))?;
  Ok(prev.as_deref().map_or(!ok, |prev| prev != now))
}

/// 发出去，失败只记日志；返回没发出去的原因。
pub async fn deliver(
  state: &AppState,
  event: &Event,
) -> Option<String> {
  match send(state, event).await {
    Ok(()) => None,
    Err(e) if e.code == ErrorCode::NotFound => {
      tracing::debug!("没有通知渠道，跳过：{}", e.message);
      Some("没有配置通知渠道".into())
    }
    Err(e) => {
      tracing::warn!("发送通知失败：{}", e.message);
      Some(format!("发送失败：{}", e.message))
    }
  }
}

/// `POST /api/notify/test`：发一条测试消息。
pub async fn test(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
) -> crate::api::ApiResult<serde_json::Value> {
  auth.require(wharf_api_types::view::Perm::Admin)?;
  send_with_retry(
    &s,
    &Event {
      title: "测试消息".into(),
      body: "通知渠道配置正确。".into(),
    },
    &[1],
  )
  .await
  .map_err(SendErr::api)?;
  Ok(axum::Json(serde_json::json!({ "ok": true })))
}

async fn feishu(
  http: &Http,
  url: &str,
  secret: Option<&str>,
  event: &Event,
) -> Result<(), SendErr> {
  let text = format!("【Wharf】{}\n{}", event.title, event.body);
  let mut body = serde_json::json!({
    "msg_type": "text",
    "content": { "text": text },
  });
  if let Some(secret) = secret {
    let ts = chrono::Utc::now().timestamp();
    body["timestamp"] = ts.to_string().into();
    body["sign"] = feishu_sign(ts, secret).into();
  }
  let mut resp = http
    .send(|client| client.post(url).json(&body))
    .await
    .map_err(request_error)?;
  let status = resp.status();
  const MAX: usize = 16 * 1024;
  let mut bytes = Vec::new();
  while bytes.len() < MAX {
    let Some(chunk) = resp.chunk().await.map_err(request_error)?
    else {
      break;
    };
    let remaining = MAX - bytes.len();
    bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
  }
  feishu_reply(status, &String::from_utf8_lossy(&bytes)).map_err(
    |e| {
      if status.is_server_error()
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
      {
        SendErr::Retryable(e)
      } else {
        SendErr::Permanent(e)
      }
    },
  )
}

fn feishu_reply(
  status: reqwest::StatusCode,
  raw: &str,
) -> Result<(), ApiError> {
  let v: serde_json::Value =
    serde_json::from_str(raw).unwrap_or_default();
  let code = v["code"]
    .as_i64()
    .or(v["StatusCode"].as_i64())
    .unwrap_or(-1);
  if !status.is_success() || code != 0 {
    return Err(
      ApiError::new(
        ErrorCode::Provider,
        format!(
          "飞书返回 {status}：{}",
          crate::log_redact::redact_text(
            v["msg"]
              .as_str()
              .filter(|s| !s.is_empty())
              .unwrap_or(raw)
          )
          .chars()
          .take(200)
          .collect::<String>()
        ),
      )
      .with_hint(
        "检查 Webhook 地址；机器人开了签名校验时要设签名密钥",
      ),
    );
  }
  Ok(())
}

/// 飞书签名：以 `timestamp + "\n" + 密钥` 为 key，对空串做 HMAC-SHA256，再 base64。
fn feishu_sign(ts: i64, secret: &str) -> String {
  let key = format!("{ts}\n{secret}");
  base64::engine::general_purpose::STANDARD
    .encode(hmac_sha256(key.as_bytes(), b""))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
  const BLOCK: usize = 64;
  let mut k = [0u8; BLOCK];
  if key.len() > BLOCK {
    k[..32].copy_from_slice(&Sha256::digest(key));
  } else {
    k[..key.len()].copy_from_slice(key);
  }
  let pad = |b: u8| k.map(|x| x ^ b);
  let inner = Sha256::new()
    .chain_update(pad(0x36))
    .chain_update(msg)
    .finalize();
  Sha256::new()
    .chain_update(pad(0x5c))
    .chain_update(inner)
    .finalize()
    .into()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hmac_matches_rfc4231() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String =
      mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
      hex,
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
  }
}

#[test]
fn feishu_keeps_only_first_200_chars_of_html_error() {
  let html = format!("<html>{}尾</html>", "字".repeat(200));
  let error = feishu_reply(reqwest::StatusCode::BAD_GATEWAY, &html)
    .unwrap_err();
  assert!(
    error
      .message
      .ends_with(&format!("<html>{}", "字".repeat(194)))
  );
  assert!(!error.message.contains('尾'));
}

#[tokio::test]
async fn notify_retries_transient_error_and_enqueues_on_exhaustion() {
  use axum::{Json, Router, http::StatusCode, routing::post};
  use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

  let requests = Arc::new(AtomicUsize::new(0));
  let hits = requests.clone();
  let previous_ts = Arc::new(AtomicI64::new(0));
  let app = Router::new().route(
    "/",
    post(move |Json(body): Json<serde_json::Value>| {
      let ts =
        body["timestamp"].as_str().unwrap().parse::<i64>().unwrap();
      assert_eq!(
        body["sign"].as_str(),
        Some(feishu_sign(ts, "fixture-signature-key").as_str())
      );
      let previous = previous_ts.swap(ts, Ordering::Relaxed);
      let n = hits.fetch_add(1, Ordering::Relaxed);
      if n < 3 {
        assert!(ts > previous);
      }
      async move {
        match n {
          2 | 7 => {
            (StatusCode::OK, Json(serde_json::json!({"code":0})))
          }
          3 => {
            (StatusCode::OK, Json(serde_json::json!({"code":19021})))
          }
          _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({})),
          ),
        }
      }
    }),
  );
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let url = format!("http://{}", listener.local_addr().unwrap());
  let server =
    tokio::spawn(
      async move { axum::serve(listener, app).await.unwrap() },
    );
  let state = crate::rules::tests::test_state();
  state
    .db
    .call_credentials(move |c, key| {
      key.put_secret(c, FEISHU_WEBHOOK, &url, db::now_ms(), false)?;
      key.put_secret(
        c,
        FEISHU_SECRET,
        "fixture-signature-key",
        db::now_ms(),
        false,
      )
    })
    .await
    .unwrap();
  let event = Event {
    title: "故障".into(),
    body: "测试".into(),
  };
  assert!(
    send_with_retry(&state, &event, IMMEDIATE_DELAYS)
      .await
      .is_ok()
  );
  assert!(matches!(
    send_with_retry(&state, &event, &[0, 0]).await,
    Err(SendErr::Permanent(_))
  ));
  let Err(SendErr::Retryable(error)) =
    send_with_retry(&state, &event, &[0, 0]).await
  else {
    panic!("瞬态错误应入队");
  };
  state.db.call(move |c| {
    c.execute("INSERT INTO alert_history(at, source, title, ok, skipped) VALUES (?1, 'task', '故障', 0, '重试中')", [db::now_ms()]).map_err(db::sql_err)?;
    enqueue(c, c.last_insert_rowid(), &event, &error.message).map_err(db::sql_err)
  }).await.unwrap();
  retry_at(&state, db::now_ms() + 30_001).await.unwrap();
  assert_eq!(requests.load(Ordering::Relaxed), 8);
  state.db.call(|c| {
    let result: (i64, Option<String>) = c.query_row(
      "SELECT (SELECT COUNT(*) FROM notify_retry), skipped FROM alert_history", [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(db::sql_err)?;
    assert_eq!(result, (0, None));
    Ok(())
  }).await.unwrap();
  server.abort();
}

#[tokio::test]
async fn successful_retry_clears_history_after_queue_eviction() {
  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    let event = Event { title: "故障".into(), body: String::new() };
    let mut first = None;
    for _ in 0..=MAX_RETRY_QUEUE {
      c.execute("INSERT INTO alert_history (at, source, title, ok, skipped) VALUES (0, 'task', '故障', 0, '重试中')", []).map_err(db::sql_err)?;
      let history_id = c.last_insert_rowid();
      enqueue(c, history_id, &event, "连接超时").map_err(db::sql_err)?;
      first.get_or_insert((c.last_insert_rowid(), history_id));
    }
    let (id, history_id) = first.unwrap();
    let skipped = || c.query_row("SELECT skipped FROM alert_history WHERE id = ?1", [history_id], |r| r.get::<_, Option<String>>(0)).map_err(db::sql_err);
    assert_eq!(skipped()?.as_deref(), Some("重试后仍失败：通知队列已满"));
    finish_retry(c, id, Some(history_id), None).map_err(db::sql_err)?;
    assert_eq!(skipped()?, None);
    Ok(())
  }).await.unwrap();
}
