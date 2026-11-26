//! API token：`Authorization: Bearer <token>`。数据库里只存 SHA-256。

use std::{
  collections::BTreeSet, net::IpAddr, path::Path, sync::Arc,
};

use axum::{
  extract::{ConnectInfo, FromRequestParts},
  http::{HeaderMap, Method, request::Parts},
};
use chrono::{DateTime, Utc};
use rusqlite::params;
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{Perm, TokenScope},
};

use crate::{
  api::AppError,
  db::{self, Db, TokenRow, now_ms, sql_err},
  source_trust,
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

/// 数据库里的权限：旧档位名（`apply_safe` 等）或逗号分隔的权限点。
pub fn encode_perms(perms: &[Perm]) -> String {
  let set: BTreeSet<Perm> =
    perms.iter().copied().chain([Perm::Read]).collect();
  set.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(",")
}

pub fn decode_perms(s: &str) -> Option<BTreeSet<Perm>> {
  let legacy = match s {
    "read" => Some(TokenScope::Read),
    "plan" => Some(TokenScope::Plan),
    "apply_safe" => Some(TokenScope::ApplySafe),
    "apply_all" => Some(TokenScope::ApplyAll),
    _ => None,
  };
  if let Some(scope) = legacy {
    return Some(Perm::of_scope(scope).into_iter().collect());
  }
  s.split(',').map(|p| Perm::parse(p.trim())).collect()
}

pub fn insert_token(
  conn: &rusqlite::Connection,
  name: &str,
  perms: &[Perm],
  token: &str,
) -> Result<(), ApiError> {
  conn
    .execute(
      "INSERT INTO api_tokens (name, hash, scope, created_at) VALUES (?1, ?2, ?3, ?4)",
      params![name, hash_token(token), encode_perms(perms), now_ms()],
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
  db.call(move |c| insert_token(c, "admin", &Perm::ALL, &token))
    .await?;
  tracing::info!(
    "已生成管理员 token（全部权限），保存在 {}。用它执行 wharf login",
    path.display()
  );
  Ok(())
}

/// 请求者的身份。
pub struct Auth {
  pub name: String,
  pub perms: BTreeSet<Perm>,
  pub expires_at: Option<DateTime<Utc>>,
  pub allowed_from: Vec<String>,
  pub services: Option<BTreeSet<String>>,
  /// 页面登录（人）。API token（CLI、AI）为 false。
  pub human: bool,
}

impl Auth {
  pub fn has(&self, perm: Perm) -> bool {
    self.perms.contains(&perm)
  }

  pub fn require(&self, perm: Perm) -> Result<(), AppError> {
    require_perm(&self.perms, perm).map_err(AppError::from)
  }
}

pub(crate) fn require_perm(
  perms: &BTreeSet<Perm>,
  perm: Perm,
) -> Result<(), ApiError> {
  if perms.contains(&perm) {
    return Ok(());
  }
  let have: Vec<&str> = perms.iter().map(|p| p.as_str()).collect();
  Err(
    ApiError::new(
      ErrorCode::Forbidden,
      format!(
        "当前 token 没有 {} 权限（有：{}）",
        perm.as_str(),
        have.join(",")
      ),
    )
    .with_hint("请用户在页面\u{201c}设置 → CLI 与 AI 接入\u{201d}换一个有这个权限的 token"),
  )
}

/// 推演接口校验调用者身份时也跳过使用时间的写入。
#[derive(Clone, Copy)]
pub(crate) struct SkipAuthActivity;

pub(crate) fn invalid_token() -> ApiError {
  ApiError::new(
    ErrorCode::Unauthorized,
    "没有登录，或 API token 无效",
  )
  .with_hint("设置环境变量 WHARF_TOKEN，或执行 wharf login")
  .suggest("wharf login --url <控制面地址>")
}

impl FromRequestParts<Arc<AppState>> for Auth {
  type Rejection = AppError;

  async fn from_request_parts(
    parts: &mut Parts,
    state: &Arc<AppState>,
  ) -> Result<Self, Self::Rejection> {
    let auth = authenticate(parts, state).await?;
    if let Some(slot) =
      parts.extensions.get::<crate::audit::AuditSlot>()
    {
      slot.set_actor(&auth.name);
    }
    Ok(auth)
  }
}

async fn authenticate(
  parts: &mut Parts,
  state: &Arc<AppState>,
) -> Result<Auth, AppError> {
  let rejected = |actor: &str, detail: &str| {
    if let Some(slot) =
      parts.extensions.get::<crate::audit::AuditSlot>()
    {
      slot.set_rejected(actor, detail);
    }
  };
  let unauthorized = || AppError::from(invalid_token());
  let track_activity =
    parts.extensions.get::<SkipAuthActivity>().is_none();
  let token = parts
    .headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .map(str::trim)
    .filter(|t| !t.is_empty());
  let peer = parts
    .extensions
    .get::<ConnectInfo<std::net::SocketAddr>>()
    .map(|c| c.0.ip());
  let Some(token) = token else {
    // 页面：账号密码登录后的会话 cookie，权限和管理员 token 一样。
    if crate::login::cookie_value(&parts.headers).is_none() {
      rejected("anonymous", "未登录");
      return Err(unauthorized());
    }
    require_same_origin(&parts.method, peer, &parts.headers)
      .inspect_err(|_| {
        rejected("session", "请求来源不一致");
      })?;
    let user = crate::login::session_user_with_activity(
      state,
      &parts.headers,
      track_activity,
    )
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| {
      rejected("session", "会话无效或已过期");
      unauthorized()
    })?;
    return Ok(Auth {
      name: format!("页面:{user}"),
      perms: Perm::ALL.into_iter().collect(),
      human: true,
      expires_at: None,
      allowed_from: vec![],
      services: None,
    });
  };
  // token 只能经 CLI 加密通道使用，防止在明文内网上被窃听；本机（如 docker exec 里的脚本）除外。
  let sealed = parts
    .extensions
    .get::<crate::cli_tunnel::Sealed>()
    .is_some();
  let local = peer.is_some_and(|ip| {
    source_trust::is_direct_local(ip, &parts.headers)
  });
  if !sealed && !local {
    rejected("anonymous", "明文令牌被拒绝");
    return Err(AppError::from(
      ApiError::new(
        ErrorCode::Unauthorized,
        "本机 wharf 太旧，不支持加密通道，控制面已拒绝明文 token",
      )
      .with_hint("在页面“设置 → CLI 与 AI 接入”按步骤更新 wharf 并重新 wharf login"),
    ));
  }
  let hash = hash_token(token);
  let found = state
    .db
    .call(move |c| db::token_scope(c, &hash, track_activity))
    .await
    .map_err(AppError::from)?;
  let row = found.ok_or_else(|| {
    rejected("anonymous", "无效访问令牌");
    unauthorized()
  })?;
  let address = peer
    .filter(|_| row.allowed_from.is_some())
    .map(|ip| crate::login::client_key(ip, &parts.headers));
  check_token(
    &row,
    Utc::now(),
    TokenPeer::Address {
      ip: address.as_deref().and_then(|raw| raw.parse().ok()),
      label: address.as_deref().unwrap_or("未知地址"),
    },
    &parts.method,
    parts.uri.path(),
  )
  .inspect_err(|e| rejected(&row.name, &e.message))?;
  Ok(Auth {
    name: row.name,
    perms: decode_perms(&row.perms).ok_or_else(unauthorized)?,
    human: false,
    expires_at: row.expires_at.map(db::to_time),
    allowed_from: scope_values(
      row.allowed_from.as_deref().unwrap_or_default(),
    )
    .collect(),
    services: row
      .services
      .as_deref()
      .map(|raw| scope_values(raw).collect()),
  })
}

#[derive(Clone, Copy)]
pub(crate) enum TokenPeer<'a> {
  // 保留 client_key 的原始文本，错误消息需要显示原地址。
  Address { ip: Option<IpAddr>, label: &'a str },
  AssumeAllowed,
}

/// 按顺序检查令牌的有效期、来源和服务范围。接口权限点由调用方检查。
pub(crate) fn check_token(
  row: &TokenRow,
  now: DateTime<Utc>,
  peer: TokenPeer<'_>,
  method: &Method,
  path: &str,
) -> Result<(), ApiError> {
  let name = &row.name;
  if let Some(time) =
    row.expires_at.map(db::to_time).filter(|time| *time <= now)
  {
    return Err(ApiError::new(
      ErrorCode::Unauthorized,
      format!("访问令牌 {name} 已在 {} 过期", time.format("%Y-%m-%d %H:%M UTC")),
    ).with_hint(format!("在页面\u{201c}设置 → CLI 与 AI 接入\u{201d}续期，或用有 admin 权限的令牌执行 wharf token set {name} --expires 30d")));
  }
  if let Some(raw) = &row.allowed_from {
    let allowed_from: Vec<_> = scope_values(raw).collect();
    if allowed_from.is_empty() {
      return Err(
        ApiError::new(
          ErrorCode::Forbidden,
          format!("访问令牌 {name} 的来源限制配置为空，已拒绝访问"),
        )
        .with_hint("请用管理员账号重新设置该令牌的来源限制"),
      );
    }
    if let TokenPeer::Address { ip, label } = peer
      && !ip.is_some_and(|ip| {
        crate::token_scope::ip_in_ranges(ip, &allowed_from)
      })
    {
      return Err(ApiError::new(
        ErrorCode::Forbidden,
        format!(
          "访问令牌 {name} 只允许从 {} 使用，这次请求来自 {}",
          allowed_from.join("、"),
          label
        ),
      ));
    }
  }
  if let Some(services) = row
    .services
    .as_deref()
    .map(|raw| scope_values(raw).collect())
    && !crate::token_scope::check_service_scope(
      &services, method, path,
    )
  {
    return Err(crate::token_scope::forbidden(name, &services, ""));
  }
  Ok(())
}

pub(crate) fn require_same_origin(
  method: &Method,
  peer: Option<IpAddr>,
  headers: &HeaderMap,
) -> Result<(), AppError> {
  if same_origin(method, peer, headers) {
    Ok(())
  } else {
    Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "请求来源和控制面地址不一致",
      )
      .into(),
    )
  }
}

pub(crate) fn same_origin(
  method: &Method,
  peer: Option<IpAddr>,
  headers: &HeaderMap,
) -> bool {
  same_origin_with(
    method,
    peer.is_some_and(source_trust::is_direct_proxy),
    headers,
  )
}

fn same_origin_with(
  method: &Method,
  trusted_proxy: bool,
  headers: &HeaderMap,
) -> bool {
  use source_trust::{
    authority, forwarded_host_with, forwarded_proto_with,
    single_header,
  };

  if !headers.contains_key("origin") {
    let websocket = headers.contains_key("sec-websocket-key")
      || headers
        .get_all("upgrade")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("websocket"));
    return matches!(
      *method,
      Method::GET | Method::HEAD | Method::OPTIONS
    ) && !websocket
      && (!headers.contains_key("sec-fetch-site")
        || matches!(
          single_header(headers, "sec-fetch-site"),
          Some("same-origin" | "none")
        ));
  }

  let scheme =
    if trusted_proxy && headers.contains_key("x-forwarded-proto") {
      let Some(scheme) = forwarded_proto_with(true, headers) else {
        return false;
      };
      scheme
    } else {
      "http"
    };
  let expected =
    if trusted_proxy && headers.contains_key("x-forwarded-host") {
      forwarded_host_with(true, headers)
    } else {
      single_header(headers, "host").and_then(authority)
    };
  let Some(expected) = expected else {
    return false;
  };
  let Some((origin_scheme, origin)) =
    single_header(headers, "origin")
      .and_then(|raw| raw.split_once("://"))
  else {
    return false;
  };
  let Some(origin) = authority(origin) else {
    return false;
  };
  let default_port = if scheme == "https" { 443 } else { 80 };
  origin_scheme.eq_ignore_ascii_case(scheme)
    && origin.host().eq_ignore_ascii_case(expected.host())
    && origin.port_u16().unwrap_or(default_port)
      == expected.port_u16().unwrap_or(default_port)
}

pub(crate) fn scope_values(
  raw: &str,
) -> impl Iterator<Item = String> + '_ {
  raw
    .split(',')
    .map(str::trim)
    .filter(|item| !item.is_empty())
    .map(str::to_string)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn origin_checks_scheme_proxy_and_required_headers() {
    let mut h = HeaderMap::new();
    h.insert("host", "wharf.example.test".parse().unwrap());
    h.insert(
      "x-forwarded-host",
      "evil.example.test".parse().unwrap(),
    );
    h.insert("origin", "https://evil.example.test".parse().unwrap());
    assert!(!same_origin_with(&Method::POST, false, &h));
    h.remove("x-forwarded-host");
    h.insert("x-forwarded-proto", "https".parse().unwrap());
    h.insert("origin", "http://wharf.example.test".parse().unwrap());
    assert!(!same_origin_with(&Method::POST, true, &h));
    h.insert(
      "origin",
      "https://WHARF.example.test:443".parse().unwrap(),
    );
    assert!(same_origin_with(&Method::POST, true, &h));
    h.remove("origin");
    assert!(!same_origin_with(&Method::POST, true, &h));
    assert!(same_origin_with(&Method::GET, true, &h));
    h.insert("upgrade", "WebSocket".parse().unwrap());
    assert!(!same_origin_with(&Method::GET, true, &h));
  }

  #[tokio::test]
  async fn forwarded_loopback_bearer_requires_sealed_channel() {
    let state = crate::rules::tests::test_state();
    state
      .db
      .call(|c| {
        insert_token(c, "fixture", &[Perm::Read], "fixture-token")
      })
      .await
      .unwrap();
    let (mut parts, ()) = axum::http::Request::get("/api/status")
      .header("authorization", "Bearer fixture-token")
      .header("x-forwarded-for", "malformed")
      .extension(ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
      ))
      .body(())
      .unwrap()
      .into_parts();
    assert_eq!(
      authenticate(&mut parts, &state).await.err().unwrap().0.code,
      ErrorCode::Unauthorized
    );
    parts.extensions.insert(crate::cli_tunnel::Sealed);
    assert!(authenticate(&mut parts, &state).await.is_ok());
    parts.extensions.remove::<crate::cli_tunnel::Sealed>();
    parts.headers.remove("x-forwarded-for");
    assert!(authenticate(&mut parts, &state).await.is_ok());
  }

  #[test]
  fn legacy_scopes_and_perm_lists() {
    let apply_safe = decode_perms("apply_safe").unwrap();
    assert!(apply_safe.contains(&Perm::Apply));
    assert!(!apply_safe.contains(&Perm::Confirm));
    assert_eq!(
      decode_perms("apply_all").unwrap(),
      Perm::ALL.into_iter().collect::<BTreeSet<_>>()
    );
    let ai = encode_perms(&[Perm::Plan, Perm::Exec]);
    assert_eq!(ai, "read,plan,exec");
    let back = decode_perms(&ai).unwrap();
    assert!(
      back.contains(&Perm::Exec) && !back.contains(&Perm::Admin)
    );
    assert!(decode_perms("read,nope").is_none());
  }
}
