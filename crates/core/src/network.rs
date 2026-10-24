//! 组网（design 2.10）：各机器怎么接入、谁能连谁。

use std::sync::Arc;

use axum::{Json, extract::State};
use chrono::TimeZone;
use wharf_api_types::view::{
  NetworkMode, NetworkServer, NetworkView, ReachView, TokenScope,
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

/// `POST /api/network/probe`：每台在线机器探测其余每台机器的内网地址。
pub async fn probe(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<NetworkView> {
  auth.require(TokenScope::Read)?;
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
  link::probe_pairs(&s, &net, pairs).await;
  Ok(Json(view(&s, &snap).await?))
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
      mode: NetworkMode::of(v.private_addr.as_ref()),
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
      checked_at: chrono::Utc
        .timestamp_millis_opt(at)
        .single()
        .unwrap_or_default(),
    })
    .collect();
  Ok(NetworkView { servers, reach })
}
