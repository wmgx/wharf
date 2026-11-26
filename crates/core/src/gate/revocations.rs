//! 网关只读吊销名单。回调密钥与续签凭据隔离，不授予访问站点或控制面的权限。

use std::{collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::State,
  http::{HeaderMap, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension};
use sha2::Sha256;
use wharf_api_types::{ApiError, ErrorCode};

use crate::{
  api::AppError,
  db::{self, Db, now_ms, sql_err},
  state::AppState,
};

use super::{
  cookie,
  credentials::{ACCESS_TTL, verify},
};

const SETTING: &str = "gate.revocations";
const CALLBACK_CONTEXT: &[u8] = b"wharf gate revocation callback v1";
type Cutoffs = BTreeMap<String, i64>;

fn callback_mac(seed: &[u8]) -> Hmac<Sha256> {
  let mut mac = Hmac::<Sha256>::new_from_slice(seed)
    .expect("HMAC 接受任意长度密钥");
  mac.update(CALLBACK_CONTEXT);
  mac
}

pub(crate) async fn config_key(db: &Db) -> Result<String, ApiError> {
  Ok(hex::encode(
    callback_mac(&super::rt_key(db).await?)
      .finalize()
      .into_bytes(),
  ))
}

pub(crate) fn poll_interval() -> Option<u32> {
  std::env::var("WHARF_GATE_REVOCATION_SECS")
    .ok()?
    .parse::<u32>()
    .ok()
    .filter(|seconds| *seconds > 0)
}

fn cutoffs(c: &Connection) -> Result<Cutoffs, ApiError> {
  db::setting(c, SETTING)?.map_or_else(
    || Ok(Cutoffs::new()),
    |raw| {
      serde_json::from_str(&raw)
        .map_err(|_| ApiError::internal("门禁吊销名单格式不对"))
    },
  )
}

fn save(c: &Connection, values: &Cutoffs) -> Result<(), ApiError> {
  if values.is_empty() {
    return db::set_setting(c, SETTING, None);
  }
  let raw = serde_json::to_string(values)
    .map_err(|_| ApiError::internal("无法保存门禁吊销名单"))?;
  db::set_setting(c, SETTING, Some(&raw))
}

fn active(values: &mut Cutoffs, now: i64) {
  values.retain(|_, time| *time > now - ACCESS_TTL);
}

fn admin_name(c: &Connection) -> Result<Option<String>, ApiError> {
  c.query_row("SELECT username FROM admin WHERE id = 1", [], |r| {
    r.get(0)
  })
  .optional()
  .map_err(sql_err)
}

fn record(c: &Connection, user: String) -> Result<(), ApiError> {
  let now = now_ms() / 1000;
  let mut values = cutoffs(c)?;
  active(&mut values, now);
  let cutoff = values.entry(user).or_insert(now);
  *cutoff = (*cutoff).max(now);
  save(c, &values)
}

pub(crate) fn sessions_removed(
  c: &Connection,
  removed: usize,
) -> Result<(), ApiError> {
  if removed > 0
    && let Some(user) = admin_name(c)?
  {
    record(c, user)?;
  }
  Ok(())
}

pub(crate) fn reset_admin(
  c: &Connection,
  name: &str,
  hash: &str,
) -> Result<(), ApiError> {
  let tx = c.unchecked_transaction().map_err(sql_err)?;
  if let Some(user) = admin_name(&tx)? {
    record(&tx, user)?;
  }
  crate::login::set_admin(&tx, name, hash)?;
  tx.commit().map_err(sql_err)
}

pub(crate) async fn cleanup(s: &AppState) -> Result<(), ApiError> {
  s.db
    .call(|c| {
      let mut values = cutoffs(c)?;
      let count = values.len();
      active(&mut values, now_ms() / 1000);
      if values.len() != count {
        save(c, &values)?;
      }
      Ok(())
    })
    .await
}

pub(crate) async fn list(
  State(s): State<Arc<AppState>>,
  headers: HeaderMap,
) -> Result<
  ([(header::HeaderName, &'static str); 1], Json<Cutoffs>),
  AppError,
> {
  let unauthorized =
    || ApiError::new(ErrorCode::Unauthorized, "需要网关回调凭据");
  let mut key = [0; 32];
  hex::decode_to_slice(
    headers
      .get("X-Wharf-Key")
      .map_or(&[][..], axum::http::HeaderValue::as_bytes),
    &mut key,
  )
  .map_err(|_| unauthorized())?;
  callback_mac(&super::rt_key(&s.db).await?)
    .verify_slice(&key)
    .map_err(|_| unauthorized())?;
  let values = s
    .db
    .call(|c| {
      let mut values = cutoffs(c)?;
      active(&mut values, now_ms() / 1000);
      Ok(values)
    })
    .await?;
  Ok(([(header::CACHE_CONTROL, "no-store")], Json(values)))
}

pub(super) async fn access_user(
  db: &Db,
  key: &SigningKey,
  headers: &HeaderMap,
  host: &str,
) -> Result<Option<String>, ApiError> {
  let now = now_ms() / 1000;
  let Some(token) = cookie(headers, "wharf_gate") else {
    return Ok(None);
  };
  let Some(user) = verify(key, token, host, now) else {
    return Ok(None);
  };
  // iat 已由上面的验签覆盖。旧 Cookie 的时间精度也是秒。
  let Some(issued) = token
    .split('.')
    .nth(1)
    .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
    .and_then(|p| {
      serde_json::from_slice::<serde_json::Value>(&p).ok()
    })
    .and_then(|claims| claims["iat"].as_i64())
  else {
    return Ok(None);
  };
  db.call(move |c| {
    let mut values = cutoffs(c)?;
    active(&mut values, now);
    Ok(
      values
        .get(&user)
        .is_none_or(|cutoff| issued > *cutoff)
        .then_some(user),
    )
  })
  .await
}
