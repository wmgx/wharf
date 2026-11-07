//! 出口（p8）：一台服务器设置 `egress` 后，它的 agent 在内网地址上起 HTTP 代理。
//! 其他设置（控制面 `api_proxy`、服务器 `git_proxy`、`pull_proxy`）可以直接写这台的名字，
//! 在这里解析成带口令的地址。带口令的地址只在下发时用，计划、日志里只显示服务器名或 [mask] 后的地址。

use rusqlite::params;
use wharf_api_types::{ApiError, ErrorCode, agent::EGRESS_PORT};

use crate::{
  db::{now_ms, sql_err},
  snapshot::Snapshot,
  state::AppState,
};

/// 代理口令，Wharf 自动生成。
pub const TOKEN_SECRET: &str = "EGRESS_TOKEN";
/// 控制面设置：调厂商 API 用的出口。
pub const API_PROXY: &str = "api_proxy";

pub struct Exit {
  /// 带口令的代理地址。
  pub url: String,
}

/// 设置值是不是服务器名（不是 `http://` 地址）。
pub fn is_server(value: &str) -> bool {
  !value.contains("://")
}

/// 解析设置值。服务器名要存在、开了出口、有内网地址。
pub fn resolve(
  value: &str,
  snap: &Snapshot,
) -> Result<Exit, ApiError> {
  let value = value.trim();
  if !is_server(value) {
    return Ok(Exit {
      url: value.to_string(),
    });
  }
  let row = snap
    .world
    .servers
    .get(value)
    .ok_or_else(|| crate::world::server_not_found(value))?;
  if !row.settings.egress {
    return Err(
      ApiError::invalid(format!("服务器 {value} 没有开出口"))
        .with_hint(format!(
          "wharf server set {value} --egress true --apply"
        )),
    );
  }
  let ip = snap
    .net(&snap.world)
    .private
    .get(value)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::Conflict,
        format!("服务器 {value} 没有内网地址，出口用不了"),
      )
    })?;
  let token = snap.secrets.get(TOKEN_SECRET).ok_or_else(|| {
    ApiError::new(ErrorCode::Conflict, "出口口令还没生成").with_hint(
      format!(
        "先执行 wharf server set {value} --egress true --apply"
      ),
    )
  })?;
  Ok(Exit {
    url: format!("http://wharf:{token}@{ip}:{EGRESS_PORT}"),
  })
}

pub use wharf_api_types::agent::mask_url as mask;

/// 没有就生成口令，返回它。
pub async fn ensure_token(
  state: &AppState,
) -> Result<String, ApiError> {
  let fresh = crate::backup::random_hex();
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT OR IGNORE INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)",
        params![TOKEN_SECRET, fresh, now_ms()],
      )
      .map_err(sql_err)?;
      c.query_row(
        "SELECT value FROM secrets WHERE name = ?1",
        params![TOKEN_SECRET],
        |r| r.get(0),
      )
      .map_err(sql_err)
    })
    .await
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ApiProxy {
  /// 提供出口的服务器名或 `http://` 地址；空表示直连。
  #[serde(default)]
  pub api_proxy: Option<String>,
}

/// `GET /api/egress`：控制面调厂商 API 用的出口。地址里的口令不返回。
pub async fn get(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
) -> crate::api::ApiResult<ApiProxy> {
  auth.require(wharf_api_types::view::Perm::Read)?;
  let v = s.db.call(|c| crate::db::setting(c, API_PROXY)).await?;
  Ok(axum::Json(ApiProxy {
    api_proxy: v.map(|v| mask(&v)),
  }))
}

/// `PUT /api/egress`：设置控制面调厂商 API 用的出口，马上生效。
pub async fn put(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
  axum::Json(req): axum::Json<ApiProxy>,
) -> crate::api::ApiResult<ApiProxy> {
  auth.require(wharf_api_types::view::Perm::Admin)?;
  let value = req
    .api_proxy
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty());
  if let Some(v) = &value {
    if !is_server(v) && !v.starts_with("http://") {
      return Err(
        ApiError::invalid("要写服务器名或 http:// 地址").into(),
      );
    }
    let snap = crate::snapshot::load(&s.db).await?;
    resolve(v, &snap)?;
  }
  let saved = value.clone();
  s.db
    .call(move |c| {
      crate::db::set_setting(c, API_PROXY, saved.as_deref())
    })
    .await?;
  // 重新加载一次，让新设置马上生效。
  crate::snapshot::load(&s.db).await?;
  Ok(axum::Json(ApiProxy {
    api_proxy: value.map(|v| mask(&v)),
  }))
}

/// 计划步骤：按服务器设置开关这台的出口代理。
pub async fn apply(
  state: &AppState,
  server: &str,
  cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;
  let row = snap
    .world
    .servers
    .get(server)
    .ok_or_else(|| crate::world::server_not_found(server))?;
  let build = snap
    .agent(server)
    .and_then(|a| a.report.as_ref())
    .map(|r| r.build.as_str());
  if crate::agent_upgrade::outdated(build) {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("服务器 {server} 的 agent 版本太旧，不支持出口"),
      )
      .with_hint("运行 wharf upgrade"),
    );
  }
  let cfg = if row.settings.egress {
    let ip = snap
      .net(&snap.world)
      .private
      .get(server)
      .map(|a| a.ip.clone())
      .ok_or_else(|| {
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 没有内网地址，不能提供出口"),
        )
      })?;
    Some(wharf_api_types::agent::EgressConfig {
      bind: ip,
      port: EGRESS_PORT,
      token: ensure_token(state).await?,
    })
  } else {
    None
  };
  state
    .hub
    .call::<serde_json::Value>(
      server,
      wharf_api_types::agent::AgentOp::Egress(cfg),
      std::time::Duration::from_secs(30),
      None,
      cancel,
    )
    .await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn masks_credentials() {
    assert_eq!(
      mask("http://wharf:abc@100.64.0.1:8118"),
      "http://***@100.64.0.1:8118"
    );
    assert_eq!(
      mask("http://100.64.0.1:8118"),
      "http://100.64.0.1:8118"
    );
    assert!(is_server("s1") && !is_server("http://x"));
  }
}
