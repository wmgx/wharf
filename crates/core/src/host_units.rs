//! 宿主机程序（只读接管）：列出宿主机上 systemd 跑的、自己装的程序；"接管"的那些每 5 分钟看一次，
//! 不在运行了进"需要注意"并推送，恢复再推送。不改它们的配置、不重启。
//!
//! 接管列表存在设置 `host_units.<服务器>`（JSON 数组），不走计划：只是盯着看。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};

use axum::{
  Json,
  extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, HostUnit},
  view::Perm,
};

use crate::{
  api::ApiResult, auth::Auth, db, snapshot, state::AppState,
  world::server_not_found,
};

const EVERY: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(90);

/// 服务器 → 接管了但没在运行的 (unit, 状态)。
static DOWN: Mutex<BTreeMap<String, Vec<(String, String)>>> =
  Mutex::new(BTreeMap::new());

fn key(server: &str) -> String {
  format!("host_units.{server}")
}

async fn watched(state: &AppState, server: &str) -> BTreeSet<String> {
  let k = key(server);
  state
    .db
    .call(move |c| db::setting(c, &k))
    .await
    .ok()
    .flatten()
    .and_then(|v| serde_json::from_str(&v).ok())
    .unwrap_or_default()
}

async fn fetch(
  state: &AppState,
  server: &str,
) -> Result<Vec<HostUnit>, ApiError> {
  state
    .hub
    .call(
      server,
      AgentOp::HostUnits,
      TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(150)).await;
    loop {
      if let Ok(snap) = snapshot::load(&state.db).await {
        for server in snap.world.servers.keys() {
          check(&state, server).await;
        }
      }
      tokio::time::sleep(EVERY).await;
    }
  });
}

async fn check(state: &AppState, server: &str) {
  let watch = watched(state, server).await;
  if watch.is_empty() || !state.hub.is_online(server) {
    if let Ok(mut d) = DOWN.lock() {
      d.remove(server);
    }
    return;
  }
  let Ok(units) = fetch(state, server).await else {
    return;
  };
  let mut down = Vec::new();
  for unit in &watch {
    let st = units
      .iter()
      .find(|u| &u.unit == unit)
      .map_or("没有在运行".to_string(), |u| u.state.clone());
    let ok = st == "running";
    if !ok {
      down.push((unit.clone(), st.clone()));
    }
    crate::rules::observe(
      state,
      "hostunit.running",
      &format!("{server}:{unit}"),
      f64::from(u8::from(ok)),
      &st,
    )
    .await;
  }
  if let Ok(mut d) = DOWN.lock() {
    d.insert(server.to_string(), down);
  }
}

/// 给"需要注意"。
pub fn problems() -> Vec<String> {
  DOWN
    .lock()
    .map(|d| {
      d.iter()
        .flat_map(|(s, v)| {
          v.iter().map(move |(u, st)| {
            format!("{s} 上的宿主机程序 {u} 不在运行（{st}）")
          })
        })
        .collect()
    })
    .unwrap_or_default()
}

#[derive(Serialize)]
pub struct HostUnitView {
  #[serde(flatten)]
  unit: HostUnit,
  watched: bool,
}

/// `GET /api/servers/{name}/host-units`：现场读一次（要几秒）。
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
) -> ApiResult<Vec<HostUnitView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let watch = watched(&s, &server).await;
  let units = fetch(&s, &server).await?;
  let mut out: Vec<HostUnitView> = units
    .into_iter()
    .map(|u| HostUnitView {
      watched: watch.contains(&u.unit),
      unit: u,
    })
    .collect();
  // 接管了但现在没列出来的（停了、被删了），也要能看到。
  for w in &watch {
    if !out.iter().any(|v| &v.unit.unit == w) {
      out.push(HostUnitView {
        unit: HostUnit {
          unit: w.clone(),
          state: "没有在运行".into(),
          ..Default::default()
        },
        watched: true,
      });
    }
  }
  Ok(Json(out))
}

#[derive(Deserialize)]
pub struct WatchBody {
  watch: bool,
}

/// `PUT /api/servers/{name}/host-units/{unit}/watch`：接管（只读盯着）或取消。
pub async fn set_watch(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((server, unit)): Path<(String, String)>,
  Json(body): Json<WatchBody>,
) -> ApiResult<serde_json::Value> {
  auth.require(Perm::Apply)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let mut watch = watched(&s, &server).await;
  if body.watch {
    watch.insert(unit.clone());
  } else {
    watch.remove(&unit);
  }
  let value = serde_json::to_string(&watch).unwrap_or_default();
  let k = key(&server);
  s.db
    .call(move |c| {
      db::set_setting(
        c,
        &k,
        (!value.is_empty() && value != "[]")
          .then_some(value.as_str()),
      )
    })
    .await?;
  check(&s, &server).await;
  Ok(Json(serde_json::json!({ "watched": watch })))
}

#[derive(Deserialize)]
pub struct LogsQuery {
  #[serde(default = "default_lines")]
  lines: u32,
}

fn default_lines() -> u32 {
  200
}

/// `GET /api/servers/{name}/host-units/{unit}/logs`
pub async fn logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((server, unit)): Path<(String, String)>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<String> {
  auth.require(Perm::Read)?;
  let text: String = s
    .hub
    .call(
      &server,
      AgentOp::HostUnitLogs {
        unit,
        lines: q.lines,
      },
      TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await?;
  Ok(Json(text))
}
