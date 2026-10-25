//! 清理服务器上没在用的镜像和构建缓存，腾出磁盘。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, agent::AgentOp, plan::ApplyResponse, view::TokenScope,
};

use crate::{
  api::ApiResult, auth::Auth, hub::ProgressFn, planner::Step,
  snapshot, state::AppState,
};

const PRUNE_TIMEOUT: Duration = Duration::from_secs(1200);

/// `POST /api/servers/{name}/prune`
pub async fn prune_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplyAll)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&name) {
    return Err(crate::world::server_not_found(&name).into());
  }
  if !s.hub.is_online(&name) {
    return Err(crate::hub::offline(&name).into());
  }
  Ok(Json(
    crate::apply::start_task(
      s.clone(),
      format!("清理 {name} 上没在用的镜像"),
      Step::Prune { server: name },
    )
    .await?,
  ))
}

pub async fn prune(
  state: &AppState,
  server: &str,
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
  // 让页面马上看到新的磁盘余量。
  if let Ok(report) = state
    .hub
    .call(
      server,
      AgentOp::Report,
      Duration::from_secs(15),
      None,
      cancel,
    )
    .await
  {
    crate::hub::touch(state, server, Some(report)).await;
  }
  Ok(())
}
