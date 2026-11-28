//! 页面会话管理和新地址登录通知。
use crate::{
  api::AppError,
  auth::{Auth, hash_token},
  db::{now_ms, sql_err},
  login,
  state::AppState,
};
use axum::{
  Json,
  extract::{ConnectInfo, Path, State},
  http::HeaderMap,
};
use rusqlite::params;
use serde_json::{Value, json};
use std::{
  net::{IpAddr, SocketAddr},
  sync::Arc,
};
use wharf_api_types::{ApiError, ErrorCode, view::SessionRow};

fn current(headers: &HeaderMap) -> String {
  hash_token(login::cookie_value(headers).unwrap_or_default())
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  headers: HeaderMap,
) -> Result<Json<Vec<SessionRow>>, AppError> {
  login::require_human(&auth)?;
  let hash = current(&headers);
  Ok(Json(s.db.call(move |c| {
    let mut stmt = c.prepare("SELECT hash, created_at, last_seen_at, source FROM sessions WHERE expires_at > ?1 ORDER BY last_seen_at DESC").map_err(sql_err)?;
    stmt.query_map([now_ms()], |r| {
      let id: String = r.get(0)?;
      let source: Option<String> = r.get(3)?;
      let (addr, agent) = match source {
        Some(v) => { let (a, b) = v.split_once(' ').unwrap_or((&v, "")); (Some(a.to_string()), (!b.is_empty()).then(|| b.to_string())) },
        None => (None, None),
      };
      Ok(SessionRow { current: id == hash, id: id[..12].into(), created_at: r.get(1)?, last_seen_at: r.get(2)?, addr, agent })
    }).map_err(sql_err)?.collect::<Result<Vec<_>, _>>().map_err(sql_err)
  }).await?))
}

pub async fn revoke(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
  login::require_human(&auth)?;
  if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
    return Err(
      ApiError::invalid("会话编号必须是 12 位十六进制").into(),
    );
  }
  let id = id.to_ascii_lowercase();
  let hash = current(&headers);
  s.db
    .call(move |c| {
      let tx = c.unchecked_transaction().map_err(sql_err)?;
      let pattern = format!("{id}%");
      let count: i64 = tx
        .query_row(
          "SELECT COUNT(*) FROM sessions WHERE hash LIKE ?1",
          [&pattern],
          |r| r.get(0),
        )
        .map_err(sql_err)?;
      if count > 1 {
        return Err(ApiError::new(
          ErrorCode::Conflict,
          "会话编号不唯一",
        ));
      }
      if hash.starts_with(&id) {
        return Err(ApiError::invalid("当前设备请用右上角的退出"));
      }
      let removed = tx
        .execute(
          "DELETE FROM sessions WHERE hash LIKE ?1",
          [&pattern],
        )
        .map_err(sql_err)?;
      crate::gate::revocations::sessions_removed(&tx, removed)?;
      tx.commit().map_err(sql_err)
    })
    .await?;
  crate::audit::login_event(
    &s,
    "session_revoke",
    &auth.name,
    login::source(peer.ip(), &headers),
  )
  .await;
  Ok(Json(json!({})))
}

pub async fn revoke_others(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
  login::require_human(&auth)?;
  let hash = current(&headers);
  let removed = s
    .db
    .call(move |c| {
      let tx = c.unchecked_transaction().map_err(sql_err)?;
      let removed = tx
        .execute(
          "DELETE FROM sessions WHERE hash != ?1",
          params![hash],
        )
        .map_err(sql_err)?;
      crate::gate::revocations::sessions_removed(&tx, removed)?;
      tx.commit().map_err(sql_err)?;
      Ok(removed)
    })
    .await?;
  crate::audit::login_event(
    &s,
    "session_revoke_others",
    &auth.name,
    login::source(peer.ip(), &headers),
  )
  .await;
  Ok(Json(json!({"removed": removed})))
}

fn net_key(addr: &str) -> String {
  match addr.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
    Ok(IpAddr::V4(ip)) => {
      let b = ip.octets();
      format!("{}.{}.{}", b[0], b[1], b[2])
    }
    Ok(IpAddr::V6(ip)) => {
      let b = ip.segments();
      format!("{:x}:{:x}:{:x}", b[0], b[1], b[2])
    }
    Err(_) => addr.into(),
  }
}
fn is_new(history: &[String], addr: &str) -> bool {
  !history.is_empty()
    && !history.iter().any(|v| {
      net_key(v.split(' ').next().unwrap_or(v)) == net_key(addr)
    })
}

pub async fn notify_new(
  s: &AppState,
  addr: &str,
  headers: &HeaderMap,
) {
  let history = s.db.call(|c| {
    let mut stmt = c.prepare("SELECT source FROM audit_log WHERE kind = 'login' AND method IN ('login', 'setup') AND at >= ?1").map_err(sql_err)?;
    stmt.query_map([now_ms() - 90 * 24 * 3600 * 1000], |r| r.get::<_, Option<String>>(0)).map_err(sql_err)?.filter_map(|r| r.transpose()).collect::<Result<Vec<_>, _>>().map_err(sql_err)
  }).await;
  match history {
    Ok(history) if is_new(&history, addr) => {
      let agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect::<String>();
      crate::rules::notice(
        s,
        "login",
        None,
        None,
        false,
        crate::notify::Event {
          title: "从新的地址登录控制面".into(),
          body: format!("地址 {addr}\n{agent}"),
        },
      )
      .await;
    }
    Err(e) => tracing::warn!("检查新登录地址失败：{}", e.message),
    _ => {}
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn address_network() {
    assert_eq!(net_key("203.0.113.7"), "203.0.113");
    assert_eq!(net_key("2001:db8:1::7"), "2001:db8:1");
    assert_eq!(net_key("unknown"), "unknown");
  }
  #[test]
  fn known_network() {
    let history = vec!["203.0.113.7 Browser".into()];
    assert!(!is_new(&history, "203.0.113.99"));
    assert!(is_new(&history, "100.64.0.1"));
    assert!(!is_new(&[], "203.0.113.7"));
  }
}
