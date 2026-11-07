//! 出口（p8）。服务器设置里两项：
//!
//! - `egress`：这台提供出口，规则（全部 / 预置分组 / 自定义域名）决定经它出去的域名；
//! - `via`：这台经哪台的出口出去。它的 agent 在本机起分流代理，dockerd 拉镜像、
//!   构建、拉代码都指向本机代理（[local_url]），按出口的规则分流，出口连不上时直连。
//!
//! 控制面调厂商 API（Cloudflare、Tailscale）用控制面设置 [API_VIA]，按同一套规则分流。

use rusqlite::params;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, EgressConfig, EgressRoute, EgressServe},
  egress::{EgressSpec, LOCAL_PORT, SERVE_PORT},
  spec::ServerSettings,
};

use crate::{
  db::{now_ms, sql_err},
  snapshot::Snapshot,
  state::AppState,
};

/// 代理口令，Wharf 自动生成。
pub const TOKEN_SECRET: &str = "EGRESS_TOKEN";
/// 控制面设置：调厂商 API 经哪台的出口。
pub const API_VIA: &str = "egress.api_via";

/// 本机分流代理的地址（agent 和 dockerd 用宿主机网络，git 容器也是）。
pub fn local_url() -> String {
  format!("http://127.0.0.1:{LOCAL_PORT}")
}

/// 这台经哪台出口出去（空字符串当没设）。
pub fn via(s: &ServerSettings) -> Option<&str> {
  s.via.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

/// 经 `exit` 出去要用的东西：出口的 `内网地址:端口`、口令、规则。
pub fn route(
  exit: &str,
  snap: &Snapshot,
) -> Result<EgressRoute, ApiError> {
  let row = snap
    .world
    .servers
    .get(exit)
    .ok_or_else(|| crate::world::server_not_found(exit))?;
  let spec = row.settings.egress.as_ref().ok_or_else(|| {
    ApiError::invalid(format!("服务器 {exit} 没有开外网代理"))
      .with_hint(format!(
        "wharf server set {exit} --egress github,cloudflare --apply"
      ))
  })?;
  let ip = private_ip(exit, snap)?;
  let token =
    snap.secrets.get(TOKEN_SECRET).cloned().ok_or_else(|| {
      ApiError::new(ErrorCode::Conflict, "外网代理的口令还没生成")
        .with_hint(format!(
          "先执行 wharf apply，让 {exit} 开启外网代理"
        ))
    })?;
  Ok(EgressRoute {
    exit: format!("{ip}:{SERVE_PORT}"),
    token,
    all: spec.all,
    domains: spec.domains(),
  })
}

fn private_ip(
  server: &str,
  snap: &Snapshot,
) -> Result<String, ApiError> {
  snap
    .net(&snap.world)
    .private
    .get(server)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::Conflict,
        format!("服务器 {server} 没有内网地址，外网代理用不了"),
      )
    })
}

/// 设置是否自洽：规则写对，`via` 指向别的、提供出口的服务器。
pub fn validate(
  name: &str,
  s: &ServerSettings,
  servers: &std::collections::BTreeMap<
    String,
    crate::world::ServerRow,
  >,
) -> Result<(), ApiError> {
  if let Some(spec) = &s.egress {
    spec.validate().map_err(ApiError::invalid)?;
  }
  if s.egress.is_none()
    && let Some((user, _)) = servers
      .iter()
      .find(|(n, r)| *n != name && via(&r.settings) == Some(name))
  {
    return Err(
      ApiError::invalid(format!(
        "{user} 还在借 {name} 访问外网，不能关"
      ))
      .with_hint(format!(
        "先执行 wharf server set {user} --via \"\""
      )),
    );
  }
  if let Some(v) = via(s) {
    if v == name {
      return Err(ApiError::invalid("不能借自己访问外网"));
    }
    let ok =
      servers.get(v).is_some_and(|r| r.settings.egress.is_some());
    if !ok {
      return Err(
        ApiError::invalid(format!(
          "服务器 {v} 不存在或没有开外网代理"
        ))
        .with_hint(format!(
          "wharf server set {v} --egress github,cloudflare"
        )),
      );
    }
  }
  Ok(())
}

/// 下发给这台 agent 的出口配置（计划比较时也用，口令除外）。
pub fn config_for(
  server: &str,
  snap: &Snapshot,
  token: &str,
) -> Result<EgressConfig, ApiError> {
  let row = snap
    .world
    .servers
    .get(server)
    .ok_or_else(|| crate::world::server_not_found(server))?;
  let serve = match &row.settings.egress {
    Some(_) => Some(EgressServe {
      bind: private_ip(server, snap)?,
      token: token.to_string(),
    }),
    None => None,
  };
  let route = match via(&row.settings) {
    Some(exit) => Some(route(exit, snap)?),
    None => None,
  };
  Ok(EgressConfig { serve, route })
}

/// 计划用：这台出口相关的有效设置（自己的规则、经哪台、那台的规则）。
pub fn effective(
  server: &str,
  world: &crate::world::World,
) -> Option<(Option<EgressSpec>, Option<String>, Option<EgressSpec>)>
{
  let s = &world.servers.get(server)?.settings;
  let v = via(s).map(str::to_string);
  let exit_spec = v
    .as_ref()
    .and_then(|x| world.servers.get(x))
    .and_then(|r| r.settings.egress.clone());
  let e = (s.egress.clone(), v, exit_spec);
  (e != (None, None, None)).then_some(e)
}

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

/// 控制面加载快照后调用：按 [API_VIA] 设置厂商 API 的分流。出口配置不全时直连。
pub fn apply_api_route(via: Option<&str>, snap: &Snapshot) {
  let r = via
    .map(str::trim)
    .filter(|v| !v.is_empty())
    .and_then(|v| route(v, snap).ok());
  wharf_providers::http::set_route(r.map(|r| {
    wharf_providers::http::Route {
      proxy: format!("http://wharf:{}@{}", r.token, r.exit),
      all: r.all,
      domains: r.domains,
    }
  }));
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ApiVia {
  /// 提供出口的服务器名；空表示直连。
  #[serde(default)]
  pub via: Option<String>,
  /// 预置分组（只读，给页面用）。
  #[serde(default, skip_deserializing)]
  pub presets: Vec<serde_json::Value>,
}

fn presets() -> Vec<serde_json::Value> {
  wharf_api_types::egress::PRESETS
    .iter()
    .map(|(n, l, d)| serde_json::json!({ "name": n, "label": l, "domains": d }))
    .collect()
}

/// `GET /api/egress`：控制面调厂商 API 经哪台出口。
pub async fn get(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
) -> crate::api::ApiResult<ApiVia> {
  auth.require(wharf_api_types::view::Perm::Read)?;
  let via = s.db.call(|c| crate::db::setting(c, API_VIA)).await?;
  Ok(axum::Json(ApiVia {
    via,
    presets: presets(),
  }))
}

/// `PUT /api/egress`：设置控制面调厂商 API 经哪台出口，马上生效。
pub async fn put(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
  axum::Json(req): axum::Json<ApiVia>,
) -> crate::api::ApiResult<ApiVia> {
  auth.require(wharf_api_types::view::Perm::Admin)?;
  let via = req
    .via
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty());
  if let Some(v) = &via {
    let snap = crate::snapshot::load(&s.db).await?;
    route(v, &snap)?;
  }
  let saved = via.clone();
  s.db
    .call(move |c| {
      crate::db::set_setting(c, API_VIA, saved.as_deref())
    })
    .await?;
  // 重新加载一次，让新设置马上生效。
  crate::snapshot::load(&s.db).await?;
  Ok(axum::Json(ApiVia {
    via,
    presets: presets(),
  }))
}

/// 计划步骤：按设置让这台的 agent 起停出口、本地分流。
pub async fn apply(
  state: &AppState,
  server: &str,
  cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;
  let build = snap
    .agent(server)
    .and_then(|a| a.report.as_ref())
    .map(|r| r.build.as_str());
  if crate::agent_upgrade::outdated(build) {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("服务器 {server} 的 agent 版本太旧，不支持外网代理"),
      )
      .with_hint("运行 wharf upgrade"),
    );
  }
  let token = ensure_token(state).await?;
  // 口令刚生成时快照里还没有，重新加载。
  let snap = crate::snapshot::load(&state.db).await?;
  let cfg = config_for(server, &snap, &token)?;
  state
    .hub
    .call::<serde_json::Value>(
      server,
      AgentOp::Egress(cfg),
      std::time::Duration::from_secs(30),
      None,
      cancel,
    )
    .await?;
  Ok(())
}
