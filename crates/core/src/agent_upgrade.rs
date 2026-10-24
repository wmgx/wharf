//! 升级服务器上的 agent：让它拉和控制面同一构建号的镜像换掉自己，
//! 再等新 agent 连回来、上报的构建号对得上。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, BUILD, ErrorCode,
  agent::{AgentOp, UpgradeJob, UpgradeResult},
  plan::ApplyResponse,
  view::TokenScope,
};

use crate::{
  api::ApiResult, auth::Auth, hub::ProgressFn, planner::Step,
  snapshot, state::AppState,
};

/// 拉镜像要的时间。
const PULL_TIMEOUT: Duration = Duration::from_secs(600);
/// 接班容器最多等 60 秒新 agent 连上，失败再恢复旧的，这里多留一些。
const RECONNECT_WAIT: Duration = Duration::from_secs(150);
/// agent 连上后立刻上报，留够这么长时间再看构建号。
const FIRST_REPORT_WAIT: Duration = Duration::from_secs(15);

/// 本地构建的控制面没有构建号，不判断落后。
pub fn outdated(agent_build: Option<&str>) -> bool {
  BUILD != "dev" && agent_build != Some(BUILD)
}

/// `POST /api/servers/{name}/upgrade`
pub async fn upgrade_now(
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
      format!("升级 {name} 的 agent"),
      Step::AgentUpgrade { server: name },
    )
    .await?,
  ))
}

pub async fn upgrade(
  state: &AppState,
  server: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let row = snap.world.servers.get(server).ok_or_else(|| {
    ApiError::new(
      ErrorCode::PlanStale,
      format!("服务器 {server} 已不存在"),
    )
  })?;
  // 不带构建号的 agent 还不认识升级请求，发过去只会等到超时。
  if reported_build(state, server).await?.is_none() {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{server} 的 agent 版本太旧，不支持远程升级"),
      )
      .with_hint("在服务器上手动换一次 agent 镜像，之后就能用 wharf server upgrade"),
    );
  }
  let tag = (BUILD != "dev").then(|| format!("sha-{BUILD}"));
  let before = state.hub.conn_id(server);
  let result: UpgradeResult = state
    .hub
    .call(
      server,
      AgentOp::Upgrade(UpgradeJob {
        tag,
        pull: snapshot::pull_policy(row),
      }),
      PULL_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if !result.started {
    return Ok(());
  }
  progress("等新 agent 连回控制面".into());
  let deadline = tokio::time::Instant::now() + RECONNECT_WAIT;
  let mut new_conn_at = None;
  loop {
    tokio::select! {
      _ = cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
      _ = tokio::time::sleep(Duration::from_secs(3)) => {}
    }
    let now = state.hub.conn_id(server);
    if now.is_some() && now != before {
      let build = reported_build(state, server).await?;
      if BUILD == "dev" || build.as_deref() == Some(BUILD) {
        progress(format!(
          "新 agent 已上线，构建号 {}",
          build.unwrap_or_default()
        ));
        return Ok(());
      }
      // 新连接要等第一次上报才有构建号；过了这段时间还是旧的，
      // 就是接班容器已经把旧 agent 恢复回来了。
      let seen = *new_conn_at.get_or_insert_with(tokio::time::Instant::now);
      if build.is_some() && seen.elapsed() > FIRST_REPORT_WAIT {
        return Err(
          ApiError::new(
            ErrorCode::AgentFailed,
            format!("{server} 的新 agent 没有起来，已恢复旧 agent"),
          )
          .with_hint("在服务器上 docker logs wharf-agent-upgrade 查看原因"),
        );
      }
    }
    if tokio::time::Instant::now() > deadline {
      return Err(
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("{server} 的新 agent 没有连上控制面"),
        )
        .with_hint("接班容器会恢复旧 agent；在服务器上 docker logs wharf-agent 查看原因"),
      );
    }
  }
}

/// agent 连上后会立刻上报，上报里带构建号。
async fn reported_build(
  state: &AppState,
  server: &str,
) -> Result<Option<String>, ApiError> {
  let server = server.to_string();
  let agent =
    state.db.call(move |c| crate::db::agent(c, &server)).await?;
  Ok(
    agent
      .and_then(|a| a.report)
      .map(|r| r.build)
      .filter(|b| !b.is_empty()),
  )
}
