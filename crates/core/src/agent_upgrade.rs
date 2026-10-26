//! 升级服务器上的 agent：让它拉和控制面同一构建号的镜像换掉自己，
//! 再等新 agent 连回来、上报的构建号对得上。
//! 控制面自己也这样升级：由同机的 agent 起接班容器换掉控制面。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, BUILD, ErrorCode, VERSION,
  agent::{AgentOp, UpgradeJob, UpgradeResult, container_id},
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

/// 拉控制面镜像的时间，要短于 CLI 请求的超时（180 秒）。
const CORE_PULL_TIMEOUT: Duration = Duration::from_secs(150);
/// 控制面开始服务时打的日志，见 main.rs。
const CORE_READY: &str = " 监听 ";

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

/// `POST /api/servers/upgrade`：升级全部在线、版本落后的 agent。
/// 都是最新时 `run_id` 为空。
pub async fn upgrade_outdated(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Value> {
  auth.require(TokenScope::ApplyAll)?;
  Ok(Json(match start_outdated(&s).await? {
    Some(r) => json!({ "run_id": r.run_id }),
    None => json!({ "run_id": null }),
  }))
}

async fn start_outdated(
  s: &Arc<AppState>,
) -> Result<Option<ApplyResponse>, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let mut servers = Vec::new();
  for name in snap.world.servers.keys() {
    if s.hub.is_online(name)
      && outdated(reported_build(s, name).await?.as_deref())
    {
      servers.push(name.clone());
    }
  }
  if servers.is_empty() {
    return Ok(None);
  }
  let title = format!("升级 {} 的 agent", servers.join("、"));
  crate::apply::start_task(
    s.clone(),
    title,
    Step::AgentUpgrades { servers },
  )
  .await
  .map(Some)
}

/// 一台失败不影响其余的。
pub async fn upgrade_each(
  state: &AppState,
  servers: &[String],
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let mut failed = Vec::new();
  for server in servers {
    if cancel.is_cancelled() {
      return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
    }
    progress(format!("升级 {server}"));
    match upgrade(state, server, progress.clone(), cancel).await {
      Ok(()) => progress(format!("✓ {server}")),
      Err(e) => {
        progress(format!("✗ {server}：{}", e.message));
        failed.push(server.as_str());
      }
    }
  }
  if failed.is_empty() {
    Ok(())
  } else {
    Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{} 没有升级成功", failed.join("、")),
    ))
  }
}

/// 升级控制面时带上 `then_agents`：新控制面起来、agent 都连上后自己接着升级 agent。
const AGENTS_AFTER_KEY: &str = "upgrade.agents_after";
/// 新控制面启动后等 agent 重新连上的时间。
const AGENTS_AFTER_DELAY: Duration = Duration::from_secs(60);

/// 控制面启动时调用。
pub fn spawn_agents_after(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(AGENTS_AFTER_DELAY).await;
    let flagged = state
      .db
      .call(|c| {
        let v = crate::db::setting(c, AGENTS_AFTER_KEY)?;
        if v.is_some() {
          crate::db::set_setting(c, AGENTS_AFTER_KEY, None)?;
        }
        Ok(v)
      })
      .await;
    match flagged {
      // 升级失败时接班容器恢复的是旧控制面，构建号对不上就不升 agent。
      Ok(Some(from)) if from != BUILD => {
        if let Err(e) = start_outdated(&state).await {
          tracing::warn!("升级控制面后接着升级 agent 失败：{e}");
        }
      }
      Ok(_) => {}
      Err(e) => tracing::warn!("读取升级标记失败：{e}"),
    }
  });
}

#[derive(serde::Deserialize, Default)]
pub struct UpgradeCore {
  #[serde(default)]
  pub then_agents: bool,
}

/// `GET /api/version`
pub async fn version(auth: Auth) -> ApiResult<Value> {
  auth.require(TokenScope::Read)?;
  Ok(Json(json!({ "version": VERSION, "build": BUILD })))
}

/// `POST /api/upgrade`：让同机的 agent 拉最新的控制面镜像、起接班容器换掉控制面。
/// 回复之后控制面会重启；新控制面没起来时接班容器恢复旧的。
pub async fn upgrade_core(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  body: Option<Json<UpgradeCore>>,
) -> ApiResult<UpgradeResult> {
  auth.require(TokenScope::ApplyAll)?;
  let then_agents = body.is_some_and(|b| b.then_agents);
  let id = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| container_id(&m))
    .ok_or_else(|| {
      ApiError::invalid("控制面不在容器里运行，不能自动升级")
    })?;
  let snap = snapshot::load(&s.db).await?;
  let cancel = CancellationToken::new();
  for (name, row) in &snap.world.servers {
    // 旧 agent 不认识 container，会去升级它自己。
    if !s.hub.is_online(name)
      || outdated(reported_build(&s, name).await?.as_deref())
    {
      continue;
    }
    let job = UpgradeJob {
      tag: None,
      pull: snapshot::pull_policy(row),
      container: Some(id.clone()),
      ready: Some(CORE_READY.into()),
    };
    match s
      .hub
      .call::<UpgradeResult>(
        name,
        AgentOp::Upgrade(job),
        CORE_PULL_TIMEOUT,
        None,
        &cancel,
      )
      .await
    {
      Ok(r) => {
        // 记下旧构建号：新控制面起来后据此判断是不是真的换了。
        if then_agents && r.started {
          let from = BUILD.to_string();
          s.db
            .call(move |c| {
              crate::db::set_setting(c, AGENTS_AFTER_KEY, Some(&from))
            })
            .await?;
        }
        return Ok(Json(r));
      }
      Err(e) if e.code == ErrorCode::NotFound => continue,
      Err(e) => return Err(e.into()),
    }
  }
  Err(
    ApiError::new(
      ErrorCode::AgentFailed,
      "找不到和控制面在同一台机器上、在线且是最新版本的 agent",
    )
    .with_hint("先升级 agent：wharf server upgrade --all")
    .into(),
  )
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
        container: None,
        ready: None,
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
      let seen =
        *new_conn_at.get_or_insert_with(tokio::time::Instant::now);
      if build.is_some() && seen.elapsed() > FIRST_REPORT_WAIT {
        return Err(
          ApiError::new(
            ErrorCode::AgentFailed,
            format!("{server} 的新 agent 没有起来，已恢复旧 agent"),
          )
          .with_hint(
            "在服务器上 docker logs wharf-agent-upgrade 查看原因",
          ),
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
