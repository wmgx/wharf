//! 页面登录：管理员账号密码，登录后发 HttpOnly 会话 cookie。CLI 和 AI 仍用 API token。
//!
//! - 还没有管理员账号时，控制面启动时在数据目录生成一次性初始化码 `setup.code`（0600），
//!   页面设置管理员时必须填它，用掉即删（防止能访问页面的人抢先占走账号）；
//! - 忘记密码：`docker exec -it wharf-core wharf-core reset-password`；
//! - 密码用 argon2 存，会话只存 SHA-256，30 天过期；
//! - 管理员登录按来源 IP 和公网/内网区域分别限制失败次数。

use std::{net::IpAddr, sync::Arc, time::Duration};

use argon2::{
  Argon2,
  password_hash::{PasswordHasher, PasswordVerifier},
};
use axum::{
  Json,
  http::{HeaderMap, Method, header},
  response::{AppendHeaders, IntoResponse, Response},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  api::AppError,
  auth::{hash_token, new_token},
  db::{Db, now_ms, sql_err},
  lockout::{self, LockScope},
  state::AppState,
};

pub const COOKIE: &str = "wharf_session";
const SETUP_CODE: &str = "setup.code";
const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
pub(crate) fn client_key(
  peer: std::net::IpAddr,
  headers: &HeaderMap,
) -> String {
  crate::source_trust::client_key(peer, headers)
}

pub(crate) fn source(
  peer: std::net::IpAddr,
  headers: &HeaderMap,
) -> String {
  let addr = client_key(peer, headers);
  match headers
    .get(header::USER_AGENT)
    .and_then(|v| v.to_str().ok())
  {
    Some(agent) => {
      format!(
        "{addr} {}",
        agent.chars().take(120).collect::<String>()
      )
    }
    None => addr,
  }
}

/// 经网关走 HTTPS 时 cookie 加 `Secure`；直连 http 时加了浏览器会丢掉 cookie。
fn secure_attr(peer: IpAddr, headers: &HeaderMap) -> &'static str {
  if crate::source_trust::forwarded_proto(peer, headers)
    == Some("https")
  {
    "; Secure"
  } else {
    ""
  }
}

#[derive(Serialize)]
pub struct SessionView {
  /// 当前浏览器已登录时是账号名。
  username: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  totp_required: bool,
  /// 还没有管理员账号。
  setup_needed: bool,
  /// 现在可以在页面上设置管理员账号（凭初始化码）。
  setup_open: bool,
  /// 控制面公钥（hex），页面拼进 `wharf login --core-key` 和 agent 加入命令。公钥可以公开。
  #[serde(skip_serializing_if = "Option::is_none")]
  core_key: Option<String>,
}

#[derive(Deserialize)]
pub struct Credentials {
  username: String,
  password: String,
  #[serde(default)]
  code: Option<String>,
}

#[derive(Deserialize)]
pub struct SetupRequest {
  username: String,
  password: String,
  /// 数据目录里 `setup.code` 的内容。
  #[serde(default)]
  code: String,
}

/// 还没有管理员账号时生成初始化码文件（已有就沿用）。只记录路径，不打印内容。
pub async fn bootstrap_setup_code(
  db: &Db,
  data_dir: &std::path::Path,
) -> anyhow::Result<()> {
  let path = data_dir.join(SETUP_CODE);
  if admin(db)
    .await
    .map_err(|e| anyhow::anyhow!(e.message))?
    .is_some()
  {
    let _ = std::fs::remove_file(&path);
    return Ok(());
  }
  if !path.exists() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(&path)?;
    writeln!(file, "{}", new_token())?;
  }
  tracing::info!(
    "还没有管理员账号：页面初始化码保存在 {}，用 docker exec wharf-core cat {} 查看",
    path.display(),
    path.display()
  );
  Ok(())
}

/// 用户填的初始化码是否和文件里的一致（比较哈希，避免按字节提前返回）。
fn setup_code_ok(data_dir: &std::path::Path, code: &str) -> bool {
  let Ok(saved) = std::fs::read_to_string(data_dir.join(SETUP_CODE))
  else {
    return false;
  };
  let saved = saved.trim();
  !saved.is_empty() && hash_token(saved) == hash_token(code.trim())
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

static ARGON2_LIMIT: tokio::sync::Semaphore =
  tokio::sync::Semaphore::const_new(2);

async fn run_argon2<T: Send + 'static>(
  work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
  let permit = tokio::time::timeout(
    Duration::from_secs(3),
    ARGON2_LIMIT.acquire(),
  )
  .await
  .map_err(|_| {
    ApiError::new(ErrorCode::Busy, "登录验证繁忙，稍后再试")
  })?
  .map_err(|_| ApiError::internal("登录验证不可用"))?;
  tokio::task::spawn_blocking(move || {
    let _permit = permit;
    work()
  })
  .await
  .map_err(|_| ApiError::internal("登录验证失败"))
}

pub(crate) async fn verify_password_async(
  password: String,
  hash: String,
) -> Result<bool, ApiError> {
  run_argon2(move || verify_password(&password, &hash)).await
}

pub(crate) async fn hash_password_async(
  password: String,
) -> Result<String, ApiError> {
  run_argon2(move || hash_password(&password)).await?
}

pub(crate) async fn hash_basic_auth(
  value: String,
) -> Result<String, ApiError> {
  tokio::task::spawn_blocking(move || {
    crate::render::BasicAuth::hash_input(&value)
  })
  .await
  .map_err(|_| ApiError::internal("计算 Basic Auth 哈希失败"))?
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
  conn.execute("UPDATE admin SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = 1", []).map_err(sql_err)?;
  conn
    .execute("DELETE FROM recovery_codes", [])
    .map_err(sql_err)?;
  conn.execute("DELETE FROM sessions", []).map_err(sql_err)?;
  Ok(())
}

pub(crate) async fn admin(
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

pub(crate) fn cookie_value(headers: &HeaderMap) -> Option<&str> {
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
  session_user_with_activity(state, headers, true).await
}

pub(crate) async fn session_user_with_activity(
  state: &AppState,
  headers: &HeaderMap,
  track_activity: bool,
) -> Result<Option<String>, ApiError> {
  let Some(id) = cookie_value(headers) else {
    return Ok(None);
  };
  let hash = hash_token(id);
  state
    .db
    .call(move |c| {
      let now = now_ms();
      let user = c.query_row(
        "SELECT a.username FROM sessions s, admin a
         WHERE s.hash = ?1 AND s.expires_at > ?2 AND a.id = 1",
        params![hash, now],
        |r| r.get(0),
      )
      .optional()
      .map_err(sql_err)?;
      if track_activity && user.is_some() {
        let _ = c.execute("UPDATE sessions SET last_seen_at = ?2 WHERE hash = ?1 AND (last_seen_at IS NULL OR last_seen_at < ?2 - 60000)", params![hash, now]);
      }
      Ok(user)
    })
    .await
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
    totp_required: false,
    setup_open: setup_needed,
    core_key: Some(hex::encode(s.key.verifying_key().to_bytes())),
  }))
}

/// 新建会话，返回带 Set-Cookie 的响应。
async fn start_session(
  state: &AppState,
  peer: IpAddr,
  headers: &HeaderMap,
  username: String,
  source: String,
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
        "INSERT INTO sessions (hash, created_at, expires_at, source, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?2)",
        params![hash, now, expires, source],
      )
      .map_err(sql_err)
    })
    .await?;
  let cookie = format!(
    "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
    SESSION_TTL.as_secs(),
    secure_attr(peer, headers),
  );
  Ok(
    (
      AppendHeaders([(header::SET_COOKIE, cookie)]),
      Json(SessionView {
        username: Some(username),
        totp_required: false,
        setup_needed: false,
        setup_open: false,
        core_key: None,
      }),
    )
      .into_response(),
  )
}

/// `POST /api/setup`：首次设置管理员账号，设置完直接登录。
pub async fn setup(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
    std::net::SocketAddr,
  >,
  headers: HeaderMap,
  Json(req): Json<SetupRequest>,
) -> Result<Response, AppError> {
  crate::auth::require_same_origin(
    &Method::POST,
    Some(peer.ip()),
    &headers,
  )?;
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
  let key = client_key(peer.ip(), &headers);
  if let Some(minutes) = lockout::locked(LockScope::AdminLogin, &key)
  {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        format!("输错次数太多，{minutes} 分钟后再试"),
      )
      .into(),
    );
  }
  if !setup_code_ok(&s.data_dir, &req.code) {
    lockout::record_and_notify(
      &s,
      LockScope::AdminLogin,
      &key,
      Some("初始化管理员"),
    )
    .await;
    crate::audit::login_event(
      &s,
      "setup_failed",
      "未知用户",
      source(peer.ip(), &headers),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    return Err(
      ApiError::new(ErrorCode::Forbidden, "初始化码不对")
      .with_hint("在服务器上执行 docker exec wharf-core cat /var/lib/wharf-core/setup.code 查看；或执行 docker exec -it wharf-core wharf-core reset-password")
      .into(),
    );
  }
  let hash = hash_password_async(req.password).await?;
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
  lockout::clear(LockScope::AdminLogin, &key);
  let _ = std::fs::remove_file(s.data_dir.join(SETUP_CODE));
  tracing::info!("已在页面上设置管理员账号 {username}");
  crate::audit::login_event(
    &s,
    "setup",
    &username,
    source(peer.ip(), &headers),
  )
  .await;
  start_session(
    &s,
    peer.ip(),
    &headers,
    username,
    source(peer.ip(), &headers),
  )
  .await
}

/// `POST /api/login`。
pub async fn login(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
    std::net::SocketAddr,
  >,
  headers: HeaderMap,
  Json(req): Json<Credentials>,
) -> Result<Response, AppError> {
  crate::auth::require_same_origin(
    &Method::POST,
    Some(peer.ip()),
    &headers,
  )?;
  let key = client_key(peer.ip(), &headers);
  if let Some(minutes) = lockout::locked(LockScope::AdminLogin, &key)
  {
    return Err(
      ApiError::new(
        ErrorCode::Unauthorized,
        format!("输错次数太多，{minutes} 分钟后再试"),
      )
      .into(),
    );
  }
  let username = req.username.trim().to_lowercase();
  let account =
    admin(&s.db).await?.filter(|(name, _)| name == &username);
  let actor = if account.is_some() {
    username.as_str()
  } else {
    "未知用户"
  };
  let ok = match account {
    Some((_, hash)) => {
      verify_password_async(req.password, hash).await?
    }
    None => false,
  };
  if !ok {
    lockout::record_and_notify(&s, LockScope::AdminLogin, &key, None)
      .await;
    crate::audit::login_event(
      &s,
      "login_failed",
      actor,
      source(peer.ip(), &headers),
    )
    .await;
    // 拖慢猜密码。
    tokio::time::sleep(Duration::from_secs(1)).await;
    return Err(
      ApiError::new(ErrorCode::Unauthorized, "账号或密码不对").into(),
    );
  }
  let enabled = crate::totp::view(&s.db).await?.enabled;
  if enabled {
    let Some(code) = req.code.filter(|v| !v.trim().is_empty()) else {
      return Ok(
        Json(SessionView {
          username: None,
          totp_required: true,
          setup_needed: false,
          setup_open: false,
          core_key: None,
        })
        .into_response(),
      );
    };
    let result =
      s.db.call(move |c| crate::totp::verify(c, &code)).await?;
    match result {
      Some(recovery) => {
        if recovery {
          crate::totp::used(
            &s,
            &username,
            source(peer.ip(), &headers),
          )
          .await;
        }
      }
      None => {
        lockout::record_and_notify(
          &s,
          LockScope::AdminLogin,
          &key,
          None,
        )
        .await;
        crate::audit::login_event(
          &s,
          "login_failed",
          &username,
          source(peer.ip(), &headers),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        return Err(
          ApiError::new(ErrorCode::Unauthorized, "验证码不对").into(),
        );
      }
    }
  }
  lockout::clear(LockScope::AdminLogin, &key);
  crate::sessions::notify_new(&s, &key, &headers).await;
  crate::audit::login_event(
    &s,
    "login",
    &username,
    source(peer.ip(), &headers),
  )
  .await;
  start_session(
    &s,
    peer.ip(),
    &headers,
    username,
    source(peer.ip(), &headers),
  )
  .await
}

/// `POST /api/logout`：删掉这个浏览器的会话。
pub async fn logout(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
    std::net::SocketAddr,
  >,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  crate::auth::require_same_origin(
    &Method::POST,
    Some(peer.ip()),
    &headers,
  )?;
  if let Ok(Some(user)) = session_user(&s, &headers).await {
    crate::audit::login_event(
      &s,
      "logout",
      &user,
      source(peer.ip(), &headers),
    )
    .await;
  }
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
    "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
    secure_attr(peer.ip(), &headers)
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
  println!(
    "已重置管理员 {username} 的密码，两步验证已关闭，所有页面会话已退出"
  );
  Ok(())
}

pub fn require_human(
  auth: &crate::auth::Auth,
) -> Result<(), AppError> {
  if auth.human {
    Ok(())
  } else {
    Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "这个操作只能在页面上登录后进行",
      )
      .into(),
    )
  }
}

#[cfg(test)]
mod tests {
  #[tokio::test]
  async fn argon2_returns_busy_when_both_slots_are_taken() {
    let _lock = crate::rules::tests::TEST_LOCK.lock().await;
    let _permits = ARGON2_LIMIT.acquire_many(2).await.unwrap();
    let result = tokio::time::timeout(
      Duration::from_secs(5),
      verify_password_async("fixture-password".into(), String::new()),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code, ErrorCode::Busy);
  }

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
}
