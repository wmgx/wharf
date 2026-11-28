//! 组网（design 2.10）：各机器怎么接入、谁能连谁。

use std::sync::Arc;

use axum::{Json, extract::State};
use chrono::TimeZone;
use wharf_api_types::{
  spec::NetworkMode,
  view::{NetworkServer, NetworkView, Perm, ReachView},
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
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(view(&s, &snap).await?))
}

/// `POST /api/network/probe`：每台在线机器探测其余每台机器的内网地址。会让 agent 去连别的机器，需要 plan 权限。
pub async fn probe(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<NetworkView> {
  auth.require(Perm::Plan)?;
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
  let (_, _, relays) = tokio::join!(
    link::probe_pairs(s, &net, pairs, link::ProbeMode::Persist),
    crate::tailnet_probe::probe_extra(s, &snap, &net),
    crate::tailnet_probe::refresh(s)
  );
  relays?;
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
      tailnet_ip: crate::tailnet_probe::address(snap, &v.name)
        .map(str::to_string),
      public_ip: v.public_ip,
      online: v.online,
      name: v.name,
    })
    .collect();
  let known = snap.world.servers.clone();
  let reach: Vec<_> = state
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
  let names: Vec<String> =
    snap.world.servers.keys().cloned().collect();
  let (links, relays) = crate::quality::view(&names);
  Ok(NetworkView {
    servers,
    tailnet_reach: crate::tailnet_probe::reach(snap, &reach),
    tailnet_relays: crate::tailnet_probe::relays(snap),
    reach,
    links,
    relays,
  })
}

#[tokio::test]
async fn network_probe_refreshes_relays() {
  use serde_json::json;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use wharf_api_types::{ApiError, agent::AgentOp};

  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    for (name, ip) in [("s1", "100.64.0.2"), ("s2", "100.64.0.3")] {
      db::apply_write(c, &db::Write::Upsert {
        kind:"server".into(), name:name.into(),
        spec:json!({"private_addr":{"ip":ip,"network":"tailscale"}}),
        meta:json!({}),
      })?;
    }
    Ok(())
  }).await.unwrap();
  let requests = Arc::new(AtomicUsize::new(0));
  for name in ["s1", "s2"] {
    let requests = requests.clone();
    state.hub.mock_agent(name, false, move |op| match op {
      AgentOp::HostExec(_) => {
        requests.fetch_add(1, Ordering::Relaxed);
        Err(ApiError::invalid("测试状态"))
      }
      AgentOp::Probe { targets } => {
        Ok(json!(vec![true; targets.len()]))
      }
      _ => panic!("意外的 agent 请求"),
    });
    state.hub.enable_mock_host_shell(name);
  }
  probe_all(&state).await.unwrap();
  assert_eq!(requests.load(Ordering::Relaxed), 2);
}
