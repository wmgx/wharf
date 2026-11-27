//! 宿主机程序（只读接管）：列出宿主机上 systemd 跑的、自己装的程序；"接管"的那些每 5 分钟看一次，
//! 不在运行了进"需要注意"并推送，恢复再推送。不改它们的配置、不重启。
//!
//! 接管列表存在设置 `host_units.<服务器>`（JSON 数组），不走计划：只是盯着看。

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HostUnit},
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::{
  api::ApiResult, auth::Auth, db, snapshot, state::AppState,
  world::server_not_found,
};

const EVERY: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(90);

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
    return;
  }
  let Ok(units) = fetch(state, server).await else {
    return;
  };
  let current = watched(state, server).await;
  for unit in watch.intersection(&current) {
    let st = units
      .iter()
      .find(|u| &u.unit == unit)
      .map_or("没有在运行".to_string(), |u| u.state.clone());
    let ok = st == "running";
    crate::rules::observe(
      state,
      "hostunit.running",
      &format!("{server}:{unit}"),
      f64::from(u8::from(ok)),
      &st,
    )
    .await;
  }
}

pub fn issues() -> Vec<Issue> {
  crate::rules::firing_subjects("host_unit_down")
    .into_iter()
    .map(|(subject, title)| {
      let (alert, ack) =
        crate::rules::issue_alert("host_unit_down", &subject);
      let server = subject
        .split_once(':')
        .map_or(subject.as_str(), |(server, _)| server);
      Issue {
        code: "host_unit_down".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: server.into(),
        }),
        title,
        hint: None,
        ack,
        alert,
      }
    })
    .collect()
}

#[derive(Serialize)]
pub struct HostUnitView {
  #[serde(flatten)]
  unit: HostUnit,
  watched: bool,
}

impl HostUnitView {
  fn new(
    mut unit: HostUnit,
    watch: &BTreeSet<String>,
    log_values: &[String],
  ) -> Self {
    unit.command = crate::redact::redact_command(
      &wharf_api_types::mask_values(&unit.command, log_values),
    );
    Self {
      watched: watch.contains(&unit.unit),
      unit,
    }
  }
}

#[test]
fn host_unit_masks_registered_positional_secret() {
  let view = HostUnitView::new(
    HostUnit {
      command:
        "/usr/bin/example fixture-unit-key --token other-token".into(),
      ..Default::default()
    },
    &BTreeSet::new(),
    &["fixture-unit-key".into()],
  );
  assert_eq!(view.unit.command, "/usr/bin/example *** --token ***");
}

/// `GET /api/servers/{name}/host-units`：现场读一次（要几秒）。
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
) -> ApiResult<Vec<HostUnitView>> {
  let snap = snapshot::load(&s.db).await?;
  crate::host_access::require_with(
    &auth,
    crate::host_access::HostTarget::HostUnits { server: &server },
    snap.world.servers.get(&server).map(|r| &r.settings),
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let watch = watched(&s, &server).await;
  let units = fetch(&s, &server).await?;
  let mut out: Vec<HostUnitView> = units
    .into_iter()
    .map(|unit| HostUnitView::new(unit, &watch, &snap.log_values))
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
  let snap = snapshot::load(&s.db).await?;
  crate::host_access::require_with(
    &auth,
    crate::host_access::HostTarget::HostUnits { server: &server },
    snap.world.servers.get(&server).map(|r| &r.settings),
    crate::join::core_server_of(&snap).as_deref(),
  )?;
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
  if !body.watch {
    crate::rules::lifecycle::clear(
      &s,
      "host_unit_down",
      &format!("{server}:{unit}"),
    )
    .await;
  }
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
  let snap = snapshot::load(&s.db).await?;
  crate::host_access::require_with(
    &auth,
    crate::host_access::HostTarget::HostUnits { server: &server },
    snap.world.servers.get(&server).map(|r| &r.settings),
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  if !watched(&s, &server).await.contains(&unit)
    && !fetch(&s, &server).await?.iter().any(|u| u.unit == unit)
  {
    let message = format!(
      "unit {unit} 不在宿主机程序列表或已接管名单中，不能读取其日志"
    );
    let hint =
      "仅支持查看“宿主机程序”里列出的非系统服务日志，或先接管该程序";
    return Err(
      ApiError::new(ErrorCode::Forbidden, message)
        .with_hint(hint)
        .into(),
    );
  }
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
  Ok(Json(crate::log_redact::redact_text(&text)))
}
