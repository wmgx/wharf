//! API token：`Authorization: Bearer <token>`。数据库里只存 SHA-256。

use std::{path::Path, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};
use rusqlite::params;
use sha2::{Digest, Sha256};
use wharf_api_types::{ApiError, ErrorCode, view::TokenScope};

use crate::{
  api::AppError,
  db::{self, Db, now_ms, sql_err},
  state::AppState,
};

pub fn hash_token(token: &str) -> String {
  hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn new_token() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  format!("wh_{}", hex::encode(bytes))
}

pub fn scope_str(scope: TokenScope) -> &'static str {
  match scope {
    TokenScope::Read => "read",
    TokenScope::Plan => "plan",
    TokenScope::ApplySafe => "apply_safe",
    TokenScope::ApplyAll => "apply_all",
  }
}

pub fn parse_scope(s: &str) -> Option<TokenScope> {
  match s {
    "read" => Some(TokenScope::Read),
    "plan" => Some(TokenScope::Plan),
    "apply_safe" => Some(TokenScope::ApplySafe),
    "apply_all" => Some(TokenScope::ApplyAll),
    _ => None,
  }
}

pub fn insert_token(
  conn: &rusqlite::Connection,
  name: &str,
  scope: TokenScope,
  token: &str,
) -> Result<(), ApiError> {
  conn
    .execute(
      "INSERT INTO api_tokens (name, hash, scope, created_at) VALUES (?1, ?2, ?3, ?4)",
      params![name, hash_token(token), scope_str(scope), now_ms()],
    )
    .map_err(|e| match e {
      rusqlite::Error::SqliteFailure(f, _)
        if f.code == rusqlite::ErrorCode::ConstraintViolation =>
      {
        ApiError::new(ErrorCode::AlreadyExists, format!("token {name} 已存在"))
      }
      e => sql_err(e),
    })?;
  Ok(())
}

/// 第一次启动、还没有任何 token 时，生成管理员 token 写到文件里（0600）。
/// 只记录文件路径，不打印 token。
pub async fn bootstrap(
  db: &Db,
  data_dir: &Path,
) -> anyhow::Result<()> {
  let count = db.call(|c| db::token_count(c)).await?;
  if count > 0 {
    return Ok(());
  }
  let token = new_token();
  let path = data_dir.join("admin.token");
  {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .mode(0o600)
      .open(&path)?;
    writeln!(file, "{token}")?;
  }
  db.call(move |c| {
    insert_token(c, "admin", TokenScope::ApplyAll, &token)
  })
  .await?;
  tracing::info!(
    "已生成管理员 token（apply_all），保存在 {}。用它执行 wharf login",
    path.display()
  );
  Ok(())
}

/// 请求者的身份。
pub struct Auth {
  #[allow(dead_code)]
  pub name: String,
  pub scope: TokenScope,
}

impl Auth {
  pub fn require(&self, scope: TokenScope) -> Result<(), AppError> {
    if self.scope >= scope {
      Ok(())
    } else {
      Err(
        ApiError::new(
          ErrorCode::Forbidden,
          format!(
            "当前 token 的权限是 {}，这个操作需要 {}",
            scope_str(self.scope),
            scope_str(scope)
          ),
        )
        .into(),
      )
    }
  }
}

impl FromRequestParts<Arc<AppState>> for Auth {
  type Rejection = AppError;

  async fn from_request_parts(
    parts: &mut Parts,
    state: &Arc<AppState>,
  ) -> Result<Self, Self::Rejection> {
    let unauthorized = || {
      AppError::from(
        ApiError::new(
          ErrorCode::Unauthorized,
          "缺少或无效的 API token",
        )
        .with_hint("设置环境变量 WHARF_TOKEN，或执行 wharf login")
        .suggest("wharf login --url <控制面地址>"),
      )
    };
    let token = parts
      .headers
      .get(axum::http::header::AUTHORIZATION)
      .and_then(|v| v.to_str().ok())
      .and_then(|v| v.strip_prefix("Bearer "))
      .map(str::trim)
      .filter(|t| !t.is_empty())
      .ok_or_else(unauthorized)?;
    let hash = hash_token(token);
    let found = state
      .db
      .call(move |c| db::token_scope(c, &hash))
      .await
      .map_err(AppError::from)?;
    let (name, scope) = found.ok_or_else(unauthorized)?;
    Ok(Auth {
      name,
      scope: parse_scope(&scope).ok_or_else(unauthorized)?,
    })
  }
}
