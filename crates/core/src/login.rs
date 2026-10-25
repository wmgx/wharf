//! 页面登录：管理员账号密码，登录后发 HttpOnly 会话 cookie。CLI 和 AI 仍用 API token。
//!
//! - 还没有管理员账号时，控制面启动后 30 分钟内可以在页面上设置，过期要重启控制面
//!   （防止内网里别人抢先打开页面占走账号）；
//! - 忘记密码：`docker exec -it wharf-core wharf-core reset-password`；
//! - 密码用 argon2 存，会话只存 SHA-256，30 天过期；
//! - 同一来源连续输错 5 次锁 15 分钟（控制面可以经网关挂在公网上）。

use std::{
  collections::HashMap,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};

use argon2::{
  Argon2,
  password_hash::{PasswordHasher, PasswordVerifier},
};
use axum::{
  Json,
  http::{HeaderMap, header},
  response::{AppendHeaders, IntoResponse, Response},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  api::AppError,
  auth::{hash_token, new_token},
  db::{Db, now_ms, sql_err},
  state::AppState,
};

pub const COOKIE: &str = "wharf_session";
const SETUP_WINDOW: Duration = Duration::from_secs(30 * 60);
const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);

/// 来源 → (连续失败次数, 最后一次失败的时间)。
static FAILURES: LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
  LazyLock::new(Default::default);

/// 登录请求的来源：经网关时是 Caddy 追加在 `X-Forwarded-For` 最后的客户端地址，
/// 直连时所有请求算同一个来源。
fn client_key(headers: &HeaderMap) -> String {
  headers
    .get("x-forwarded-for")
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.rsplit(',').next())
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty())
    .unwrap_or_else(|| "direct".into())
}

/// 还在锁定期时返回剩余分钟数。
fn locked(key: &str) -> Option<u64> {
  let map = FAILURES.lock().unwrap_or_else(|e| e.into_inner());
  let (count, at) = map.get(key)?;
  let left = LOCKOUT.checked_sub(at.elapsed())?;
  (*count >= MAX_FAILURES).then(|| left.as_secs().div_ceil(60))
}

fn record_failure(key: &str) {
  let mut map = FAILURES.lock().unwrap_or_else(|e| e.into_inner());
  map.retain(|_, (_, at)| at.elapsed() < LOCKOUT);
  let entry =
    map.entry(key.to_string()).or_insert((0, Instant::now()));
  *entry = (entry.0 + 1, Instant::now());
}

#[derive(Serialize)]
pub struct SessionView {
  /// 当前浏览器已登录时是账号名。
  username: Option<String>,
  /// 还没有管理员账号。
  setup_needed: bool,
  /// 现在可以在页面上设置管理员账号（启动后 30 分钟内）。
  setup_open: bool,
}

#[derive(Deserialize)]
pub struct Credentials {
  username: String,
  password: String,
}

pub fn hash_password(password: &str) -> Result<String, ApiError> {
  let mut salt = [0u8; 16];
  getrandom::fill(&mut salt)
    .map_err(|e| ApiError::internal(format!("随机数不可用：{e}")))?;
  Argon2::default()
    .hash_password_with_salt(password.as_bytes(), &salt)
    .map(|h| h.to_string())
    .map_err(|e| ApiError::internal(format!("密码哈希失败：{e}")))
}

pub(crate) fn verify_password(password: &str, hash: &str) -> bool {
  Argon2::default()
    .verify_password(password.as_bytes(), hash)
    .is_ok()
}

pub fn check_credentials(
  username: &str,
  password: &str,
) -> Result<(), ApiError> {
  let name_ok = (1..=32).contains(&username.len())
    && username.bytes().all(|c| {
      c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || b"-_.".contains(&c)
    });
  if !name_ok {
    return Err(ApiError::invalid(
      "账号只能用小写字母、数字和 - _ .，最多 32 个字符",
    ));
  }
  if password.chars().count() < 8 || password.len() > 128 {
    return Err(ApiError::invalid("密码至少 8 个字符"));
  }
  Ok(())
}

/// 写入（或覆盖）管理员账号，并让所有已登录的会话失效。
pub fn set_admin(
  conn: &rusqlite::Connection,
  username: &str,
  password_hash: &str,
) -> Result<(), ApiError> {
  conn
    .execute(
      "INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, ?1, ?2, ?3)
       ON CONFLICT (id) DO UPDATE SET username = ?1, password_hash = ?2",
      params![username, password_hash, now_ms()],
    )
    .map_err(sql_err)?;
  conn.execute("DELETE FROM sessions", []).map_err(sql_err)?;
  Ok(())
}

async fn admin(
  db: &Db,
) -> Result<Option<(String, String)>, ApiError> {
  db.call(|c| {
    c.query_row(
      "SELECT username, password_hash FROM admin WHERE id = 1",
      [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(sql_err)
  })
  .await
}

fn cookie_value(headers: &HeaderMap) -> Option<&str> {
  headers
    .get_all(header::COOKIE)
    .iter()
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(';'))
    .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")))
    .filter(|v| !v.is_empty())
}

/// 请求带的会话 cookie 有效时返回账号名。
pub async fn session_user(
  state: &AppState,
  headers: &HeaderMap,
) -> Result<Option<String>, ApiError> {
  let Some(id) = cookie_value(headers) else {
    return Ok(None);
  };
  let hash = hash_token(id);
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT a.username FROM sessions s, admin a
         WHERE s.hash = ?1 AND s.expires_at > ?2 AND a.id = 1",
        params![hash, now_ms()],
        |r| r.get(0),
      )
      .optional()
      .map_err(sql_err)
    })
    .await
}

fn setup_open(state: &AppState) -> bool {
  state.started.elapsed() < SETUP_WINDOW
}

/// `GET /api/session`：页面打开时判断显示登录、首次设置还是主界面。不需要登录。
pub async fn show(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  headers: HeaderMap,
) -> Result<Json<SessionView>, AppError> {
  let setup_needed = admin(&s.db).await?.is_none();
  Ok(Json(SessionView {
    username: session_user(&s, &headers).await?,
    setup_needed,
    setup_open: setup_needed && setup_open(&s),
  }))
}

/// 新建会话，返回带 Set-Cookie 的响应。
async fn start_session(
  state: &AppState,
  username: String,
) -> Result<Response, AppError> {
  let id = new_token();
  let hash = hash_token(&id);
  let now = now_ms();
  let expires = now + SESSION_TTL.as_millis() as i64;
  state
    .db
    .call(move |c| {
      c.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])
        .map_err(sql_err)?;
      c.execute(
        "INSERT INTO sessions (hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
        params![hash, now, expires],
      )
      .map_err(sql_err)
    })
    .await?;
  let cookie = format!(
    "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
    SESSION_TTL.as_secs()
  );
  Ok(
    (
      AppendHeaders([(header::SET_COOKIE, cookie)]),
      Json(SessionView {
        username: Some(username),
        setup_needed: false,
        setup_open: false,
      }),
    )
      .into_response(),
  )
}

/// `POST /api/setup`：首次设置管理员账号，设置完直接登录。
pub async fn setup(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  Json(req): Json<Credentials>,
) -> Result<Response, AppError> {
  let username = req.username.trim().to_lowercase();
  check_credentials(&username, &req.password)?;
  if admin(&s.db).await?.is_some() {
    return Err(
      ApiError::new(
        ErrorCode::AlreadyExists,
        "管理员账号已经设置过了",
      )
      .into(),
    );
  }
  if !setup_open(&s) {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "控制面启动已超过 30 分钟，不能在页面上设置管理员账号",
      )
      .with_hint("重启控制面后 30 分钟内设置，或在服务器上执行 docker exec -it wharf-core wharf-core reset-password")
      .into(),
    );
  }
  let hash = hash_password(&req.password)?;
  let name = username.clone();
  s.db
    .call(move |c| {
      // 两个人同时提交时只有第一个成功。
      c.execute(
        "INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, ?1, ?2, ?3)",
        params![name, hash, now_ms()],
      )
      .map_err(|_| {
        ApiError::new(ErrorCode::AlreadyExists, "管理员账号已经设置过了")
      })
    })
    .await?;
  tracing::info!("已在页面上设置管理员账号 {username}");
  start_session(&s, username).await
}

/// `POST /api/login`。
pub async fn login(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  headers: HeaderMap,
  Json(req): Json<Credentials>,
) -> Result<Response, AppError> {
  let key = client_key(&headers);
  if let Some(minutes) = locked(&key) {
    return Err(
      ApiError::new(
        ErrorCode::Unauthorized,
        format!("输错次数太多，{minutes} 分钟后再试"),
      )
      .into(),
    );
  }
  let username = req.username.trim().to_lowercase();
  let ok = match admin(&s.db).await? {
    Some((name, hash)) => {
      name == username && verify_password(&req.password, &hash)
    }
    None => false,
  };
  if !ok {
    record_failure(&key);
    // 拖慢猜密码。
    tokio::time::sleep(Duration::from_secs(1)).await;
    return Err(
      ApiError::new(ErrorCode::Unauthorized, "账号或密码不对").into(),
    );
  }
  FAILURES
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .remove(&key);
  start_session(&s, username).await
}

/// `POST /api/logout`：删掉这个浏览器的会话。
pub async fn logout(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  if let Some(id) = cookie_value(&headers) {
    let hash = hash_token(id);
    s.db
      .call(move |c| {
        c.execute(
          "DELETE FROM sessions WHERE hash = ?1",
          params![hash],
        )
        .map_err(sql_err)
      })
      .await?;
  }
  let cookie = format!(
    "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
  );
  Ok(
    (
      AppendHeaders([(header::SET_COOKIE, cookie)]),
      Json(serde_json::json!({})),
    )
      .into_response(),
  )
}

/// `wharf-core reset-password`：在服务器上重置管理员账号密码，所有页面会话退出。
pub fn reset_password(
  data_dir: &std::path::Path,
  username: Option<String>,
) -> anyhow::Result<()> {
  let conn = rusqlite::Connection::open(data_dir.join("wharf.db"))?;
  let current: Option<String> = conn
    .query_row("SELECT username FROM admin WHERE id = 1", [], |r| {
      r.get(0)
    })
    .optional()?;
  let username = username
    .or(current)
    .unwrap_or_else(|| "admin".to_string())
    .trim()
    .to_lowercase();
  let password =
    rpassword::prompt_password(format!("{username} 的新密码："))?;
  let again = rpassword::prompt_password("再输入一次：")?;
  anyhow::ensure!(password == again, "两次输入的密码不一样");
  check_credentials(&username, &password)
    .map_err(|e| anyhow::anyhow!(e.message))?;
  let hash = hash_password(&password)
    .map_err(|e| anyhow::anyhow!(e.message))?;
  set_admin(&conn, &username, &hash)
    .map_err(|e| anyhow::anyhow!(e.message))?;
  println!("已重置管理员 {username} 的密码，所有页面会话已退出");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn password_round_trip() {
    let hash = hash_password("correct horse").unwrap();
    assert!(verify_password("correct horse", &hash));
    assert!(!verify_password("wrong horse", &hash));
  }

  #[test]
  fn reads_session_cookie() {
    let mut h = HeaderMap::new();
    h.insert(
      header::COOKIE,
      "theme=dark; wharf_session=abc".parse().unwrap(),
    );
    assert_eq!(cookie_value(&h), Some("abc"));
  }

  #[test]
  fn locks_after_repeated_failures_per_client() {
    let mut h = HeaderMap::new();
    h.insert(
      "x-forwarded-for",
      "1.2.3.4, 203.0.113.9".parse().unwrap(),
    );
    let key = client_key(&h);
    assert_eq!(key, "203.0.113.9");
    for _ in 0..MAX_FAILURES - 1 {
      record_failure(&key);
    }
    assert_eq!(locked(&key), None);
    record_failure(&key);
    assert_eq!(locked(&key), Some(15));
    assert_eq!(locked("direct"), None);
  }
}
