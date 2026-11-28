//! 访问令牌的管理接口和设置校验。

use std::sync::Arc;

use axum::{
  Json,
  extract::{ConnectInfo, Path, State},
  http::HeaderMap,
};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode, validate_name,
  view::{CreatedToken, Perm, TokenScope, TokenSettings, TokenView},
};

use crate::{
  api::ApiResult,
  auth::{self, Auth},
  db::{TokenRow, now_ms, sql_err, to_time},
  state::AppState,
};

pub(crate) fn split_list(value: Option<String>) -> Vec<String> {
  value
    .filter(|v| !v.is_empty())
    .map(|v| v.split(',').map(str::to_string).collect())
    .unwrap_or_default()
}

fn normalize(
  mut settings: TokenSettings,
  current: Option<i64>,
) -> Result<TokenSettings, ApiError> {
  if let Some(expires) = settings.expires_at {
    let ms = expires.timestamp_millis();
    // 编辑时允许保留已有的到期时间，包括已经过期的令牌。
    if Some(ms) != current && ms <= now_ms() {
      return Err(ApiError::invalid("有效期必须晚于现在"));
    }
  }
  settings.normalize()?;
  Ok(settings)
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<TokenView>> {
  auth.require(Perm::Admin)?;
  let rows = s.db.call(|c| {
    let mut stmt = c.prepare(
      "SELECT name, scope, expires_at, allowed_from, services, created_at, last_used_at FROM api_tokens ORDER BY name",
    ).map_err(sql_err)?;
    let rows = stmt.query_map([], |r| {
      Ok((TokenRow::read(r)?, r.get::<_, i64>(5)?, r.get::<_, Option<i64>>(6)?))
    }).map_err(sql_err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
  }).await?;
  Ok(Json(
    rows
      .into_iter()
      .filter_map(|(row, created, used)| {
        Some(TokenView {
          name: row.name,
          perms: auth::decode_perms(&row.perms)?
            .into_iter()
            .collect(),
          expires_at: row.expires_at.map(to_time),
          allowed_from: split_list(row.allowed_from),
          services: split_list(row.services),
          created_at: to_time(created),
          last_used_at: used.map(to_time),
        })
      })
      .collect(),
  ))
}

/// 新建令牌：给权限点，或用旧档位作为预设。
#[derive(Deserialize)]
pub struct CreateToken {
  name: String,
  scope: Option<TokenScope>,
  perms: Option<Vec<Perm>>,
  expires_at: Option<DateTime<Utc>>,
  #[serde(default)]
  allowed_from: Vec<String>,
  #[serde(default)]
  services: Vec<String>,
}

pub async fn create(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<CreateToken>,
) -> ApiResult<CreatedToken> {
  auth.require(Perm::Admin)?;
  validate_name("令牌", &req.name)?;
  let perms = match (req.perms, req.scope) {
    (Some(p), None) => p,
    (None, Some(scope)) => Perm::of_scope(scope),
    _ => return Err(ApiError::invalid("perms 和 scope 要给且只给一个")
      .with_hint("perms 是权限点列表：read、plan、apply、confirm、exec、host、admin")
      .into()),
  };
  let settings = normalize(
    TokenSettings {
      perms,
      expires_at: req.expires_at,
      allowed_from: req.allowed_from,
      services: req.services,
    },
    None,
  )?;
  let token = auth::new_token();
  let (name, t, perms) =
    (req.name.clone(), token.clone(), settings.perms.clone());
  let stored = settings.clone();
  s.db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      auth::insert_token(&tx, &name, &perms, &t)?;
      save_settings(&tx, &name, &stored)?;
      tx.commit().map_err(sql_err)
    })
    .await?;
  crate::security_receipt::token_created(
    &s,
    &auth.name,
    &crate::login::client_key(peer.ip(), &headers),
    &req.name,
    &settings.perms,
  )
  .await;
  Ok(Json(CreatedToken {
    name: req.name,
    token,
    perms: settings.perms,
    expires_at: settings.expires_at,
    allowed_from: settings.allowed_from,
    services: settings.services,
  }))
}

fn save_settings(
  c: &rusqlite::Connection,
  name: &str,
  settings: &TokenSettings,
) -> Result<(), ApiError> {
  c.execute(
    "UPDATE api_tokens SET scope = ?2, expires_at = ?3, allowed_from = ?4, services = ?5 WHERE name = ?1",
    params![
      name,
      auth::encode_perms(&settings.perms),
      settings.expires_at.map(|v| v.timestamp_millis()),
      (!settings.allowed_from.is_empty()).then(|| settings.allowed_from.join(",")),
      (!settings.services.is_empty()).then(|| settings.services.join(",")),
    ],
  ).map_err(sql_err)?;
  Ok(())
}

pub async fn set(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(settings): Json<TokenSettings>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  s.db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let current: Option<i64> = tx
        .query_row(
          "SELECT expires_at FROM api_tokens WHERE name = ?1",
          [&name],
          |r| r.get(0),
        )
        .optional()
        .map_err(sql_err)?
        .ok_or_else(|| {
          ApiError::new(
            ErrorCode::NotFound,
            format!("访问令牌 {name} 不存在"),
          )
          .with_hint("执行 wharf token list")
        })?;
      save_settings(&tx, &name, &normalize(settings, current)?)?;
      tx.commit().map_err(sql_err)
    })
    .await?;
  Ok(Json(json!({"ok": true})))
}

pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let removed = s
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM api_tokens WHERE name = ?1",
        params![name],
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(Json(json!({"removed": removed > 0})))
}

pub async fn whoami(auth: Auth) -> ApiResult<Value> {
  let mut value = json!({
    "name": auth.name,
    "human": auth.human,
    "perms": auth.perms.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
    "build": wharf_api_types::BUILD,
    "version": env!("CARGO_PKG_VERSION"),
    "exec_v2": true,
  });
  if !auth.human {
    value["expires_at"] = json!(auth.expires_at);
    value["allowed_from"] = json!(auth.allowed_from);
    value["services"] = json!(auth.services.unwrap_or_default());
  }
  Ok(Json(value))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn creating_high_privilege_token_has_receipt() {
    use crate::{
      rules::tests::{
        TEST_LOCK, notice_titles, reset_memory, test_state,
      },
      security_receipt::tests::auth,
    };

    let _lock = TEST_LOCK.lock().await;
    reset_memory();
    let state = test_state();
    for (name, perm) in
      [("host-access", Perm::Host), ("admin-access", Perm::Admin)]
    {
      let result = create(
        State(state.clone()),
        auth(false),
        ConnectInfo("203.0.113.8:1234".parse().unwrap()),
        HeaderMap::new(),
        Json(CreateToken {
          name: name.into(),
          scope: None,
          perms: Some(vec![perm]),
          expires_at: None,
          allowed_from: vec![],
          services: vec![],
        }),
      )
      .await;
      assert!(result.is_ok());
    }
    assert_eq!(
      notice_titles(&state, "security_receipt").await,
      ["新建高权限令牌 host-access", "新建高权限令牌 admin-access"]
    );
  }

  #[test]
  fn normalizes_settings_and_rejects_invalid_range() {
    let mut settings = TokenSettings {
      perms: vec![Perm::Apply],
      expires_at: None,
      allowed_from: vec![
        " 203.0.113.7 ".into(),
        "203.0.113.7/32".into(),
        "fd7a:115c:a1e0::1/48".into(),
      ],
      services: vec!["new-service".into(), "new-service".into()],
    };
    let clean = normalize(settings.clone(), None).unwrap();
    assert_eq!(clean.perms, [Perm::Read, Perm::Apply]);
    assert_eq!(
      clean.allowed_from,
      ["203.0.113.7/32", "fd7a:115c:a1e0::/48"]
    );
    assert_eq!(clean.services, ["new-service"]);
    settings.allowed_from = vec!["203.0.113.7/33".into()];
    let error = normalize(settings, None).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert!(error.hint.is_some());
  }
}
