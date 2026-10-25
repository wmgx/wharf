//! 部署后观察一会儿：容器起来马上又退出、反复重启、镜像自带的健康检查不通过，
//! 都算没起来。`up -d` 返回时容器只是"创建并启动了"，不代表能用。

use std::{collections::HashMap, time::Duration};

use wharf_api_types::{ApiError, ErrorCode, agent::ProjectState};

use crate::{docker::Docker, exec::Ctx};

/// 至少观察这么久。
const MIN_WATCH: Duration = Duration::from_secs(10);
/// 镜像自带健康检查时，最多等它这么久变成 healthy。
const MAX_WATCH: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_secs(2);

pub async fn watch(
  docker: &Docker,
  project: &str,
  ctx: &Ctx,
) -> Result<ProjectState, ApiError> {
  ctx.say("观察容器是否稳定运行");
  let start = tokio::time::Instant::now();
  let first = docker.one_status(project, ctx).await?;
  let restarts_before = restart_counts(docker, &first, ctx).await;
  loop {
    let state = docker.one_status(project, ctx).await?;
    if let Some(bad) = problem(&state) {
      return Err(failed(project, bad));
    }
    let restarts = restart_counts(docker, &state, ctx).await;
    let restarted: Vec<String> = state
      .containers
      .iter()
      .filter(|c| {
        restarts.get(&c.name).copied().unwrap_or(0)
          > restarts_before.get(&c.name).copied().unwrap_or(0)
      })
      .map(|c| format!("{} 退出后被重启", c.service))
      .collect();
    if !restarted.is_empty() {
      return Err(failed(project, restarted.join("，")));
    }
    let starting = state
      .containers
      .iter()
      .any(|c| c.health.as_deref() == Some("health: starting"));
    let elapsed = start.elapsed();
    if elapsed >= MIN_WATCH && !starting {
      ctx.say("容器运行正常");
      return Ok(state);
    }
    if elapsed >= MAX_WATCH {
      return Err(failed(
        project,
        format!("健康检查 {} 秒内没有通过", MAX_WATCH.as_secs()),
      ));
    }
    tokio::select! {
      _ = tokio::time::sleep(POLL) => {}
      _ = ctx.cancel.cancelled() => {
        return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
      }
    }
  }
}

/// 已经能下结论的问题：没有容器、容器退出、健康检查失败。
fn problem(state: &ProjectState) -> Option<String> {
  if state.containers.is_empty() {
    return Some("启动后没有容器".into());
  }
  let bad: Vec<String> = state
    .containers
    .iter()
    .filter_map(|c| {
      if c.health.as_deref() == Some("unhealthy") {
        Some(format!("{} 健康检查不通过", c.service))
      } else if c.state != "running" {
        Some(format!("{} {}（{}）", c.service, c.state, c.status))
      } else {
        None
      }
    })
    .collect();
  (!bad.is_empty()).then(|| bad.join("，"))
}

fn failed(project: &str, why: String) -> ApiError {
  ApiError::new(ErrorCode::AgentFailed, format!("{project} 没起来：{why}"))
    .suggest(format!("wharf service logs {project}"))
}

/// 容器名 → 重启次数。查不到时返回空，不影响判断其他条件。
async fn restart_counts(
  docker: &Docker,
  state: &ProjectState,
  ctx: &Ctx,
) -> HashMap<String, u64> {
  if state.containers.is_empty() {
    return HashMap::new();
  }
  let out = docker
    .cmd()
    .args(["inspect", "--format", "{{.Name}} {{.RestartCount}}"])
    .args(state.containers.iter().map(|c| c.name.clone()))
    .timeout(Duration::from_secs(15))
    .run(ctx)
    .await;
  let Ok(out) = out else { return HashMap::new() };
  out
    .stdout
    .lines()
    .filter_map(|l| {
      let (name, n) = l.trim().rsplit_once(' ')?;
      Some((name.trim_start_matches('/').to_string(), n.parse().ok()?))
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::agent::ContainerInfo;

  fn container(state: &str, health: Option<&str>) -> ContainerInfo {
    ContainerInfo {
      service: "app".into(),
      name: "app-app-1".into(),
      state: state.into(),
      status: String::new(),
      health: health.map(str::to_string),
      image: String::new(),
      foreign: false,
      working_dir: None,
    }
  }

  #[test]
  fn judges_containers() {
    let state = |c| ProjectState {
      project: "app".into(),
      hash: None,
      config_hash: None,
      containers: vec![c],
    };
    assert!(problem(&state(container("running", None))).is_none());
    assert!(
      problem(&state(container("running", Some("health: starting"))))
        .is_none()
    );
    assert!(problem(&state(container("exited", None))).is_some());
    assert!(
      problem(&state(container("running", Some("unhealthy")))).is_some()
    );
  }
}
