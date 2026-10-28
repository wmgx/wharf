//! 组网（design 2.10）：各机器怎么接入、谁能连谁。

use std::sync::Arc;

use axum::{Json, extract::State};
use chrono::TimeZone;
use wharf_api_types::{
  spec::NetworkMode,
  view::{NetworkServer, NetworkView, ReachView, TokenScope},
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db,
  link::{self, Pairs},
  snapshot::{self, Snapshot},
  state::AppState,
};

/// `GET /api/network`
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<NetworkView> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(view(&s, &snap).await?))
}

/// `POST /api/network/probe`：每台在线机器探测其余每台机器的内网地址。会让 agent 去连别的机器，需要 plan 权限。
pub async fn probe(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<NetworkView> {
  auth.require(TokenScope::Plan)?;
  let snap = probe_all(&s).await?;
  Ok(Json(view(&s, &snap).await?))
}

/// 每台在线机器探测其余每台机器的内网地址。后台定时跑，也可以在组网页手动触发。
pub async fn probe_all(
  s: &AppState,
) -> Result<Snapshot, wharf_api_types::ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let names: Vec<&String> = snap.world.servers.keys().collect();
  let pairs: Pairs = names
    .iter()
    .filter(|from| s.hub.is_online(from))
    .map(|from| {
      let to = names
        .iter()
        .filter(|to| *to != from)
        .map(|to| to.to_string())
        .collect();
      (from.to_string(), to)
    })
    .collect();
  link::probe_pairs(s, &net, pairs).await;
  Ok(snap)
}

async fn view(
  state: &AppState,
  snap: &Snapshot,
) -> Result<NetworkView, wharf_api_types::ApiError> {
  let servers = snap
    .world
    .servers
    .keys()
    .filter_map(|n| crate::views::server_view(state, snap, n))
    .map(|v| NetworkServer {
      mode: v
        .settings
        .network_mode
        .unwrap_or_else(|| NetworkMode::of(v.private_addr.as_ref())),
      configured: v.settings.network_mode.is_some(),
      private_ip: v.private_addr.map(|a| a.ip),
      public_ip: v.public_ip,
      online: v.online,
      name: v.name,
    })
    .collect();
  let known = snap.world.servers.clone();
  let reach = state
    .db
    .call(|c| db::reach_rows(c))
    .await?
    .into_iter()
    .filter(|(from, to, ..)| {
      known.contains_key(from) && known.contains_key(to)
    })
    .map(|(from, to, ok, at)| ReachView {
      from,
      to,
      ok,
      stale: at < db::now_ms() - db::REACH_TTL_MS,
      checked_at: chrono::Utc
        .timestamp_millis_opt(at)
        .single()
        .unwrap_or_default(),
    })
    .collect();
  Ok(NetworkView { servers, reach })
}
