//! 清理服务器上没在用的镜像和构建缓存，腾出磁盘。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, PruneRestoreResult},
  plan::ApplyResponse,
  view::Perm,
};

use crate::{
  api::ApiResult, auth::Auth, hub::ProgressFn, planner::Step,
  snapshot, state::AppState,
};

const PRUNE_TIMEOUT: Duration = Duration::from_secs(1200);

#[derive(serde::Deserialize, Default)]
pub struct PruneRequest {
  #[serde(default)]
  restore_days: Option<u32>,
}

/// `POST /api/servers/{name}/prune`
pub async fn prune_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  body: Option<Json<PruneRequest>>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Admin)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&name) {
    return Err(crate::world::server_not_found(&name).into());
  }
  if !s.hub.is_online(&name) {
    return Err(crate::hub::offline(&name).into());
  }
  let restore_days = body.and_then(|b| b.restore_days);
  if restore_days.is_some() {
    crate::backup::require_safe_backup(&s, &name)?;
  }
  Ok(Json(
    crate::apply::start_task_by(
      s.clone(),
      format!("清理 {name} 上没在用的镜像"),
      Step::Prune {
        server: name,
        restore_days,
      },
      Some(crate::apply::format_actor(&auth)),
    )
    .await?,
  ))
}

pub async fn prune(
  state: &AppState,
  server: &str,
  restore_days: Option<u32>,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let freed: String = state
    .hub
    .call(
      server,
      AgentOp::Prune,
      PRUNE_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  progress(freed);
  if let Some(older_than_days) = restore_days {
    let result: PruneRestoreResult = state
      .hub
      .call(
        server,
        AgentOp::PruneRestore { older_than_days },
        PRUNE_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await?;
    progress(format!(
      "清理 {} 份恢复保留，释放 {} 字节",
      result.removed, result.bytes
    ));
  }
  // 这里只刷新磁盘字段，避免把主动请求的完整上报当作普通报告入库。
  if let Some((conn, key)) = state.hub.connected_identity(server)
    && let Ok(report) = state
      .hub
      .call_bound::<wharf_api_types::agent::AgentReport>(
        (server, conn),
        AgentOp::Report,
        Duration::from_secs(15),
        None,
        cancel,
      )
      .await
    && state.hub.conn_id(server) == Some(conn)
  {
    let server = server.to_string();
    let values = serde_json::json!({ "disk": report.disk, "docker_disk": report.docker_disk });
    let _ = state.db.call(move |c| {
      c.execute(
        "UPDATE agents SET report = json_patch(report, ?1)
         WHERE server = ?2 AND public_key = ?3 AND report IS NOT NULL",
        rusqlite::params![values.to_string(), server, key],
      ).map_err(crate::db::sql_err)
    }).await;
  }
  Ok(())
}
