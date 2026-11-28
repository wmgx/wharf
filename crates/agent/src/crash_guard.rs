use std::{path::Path, time::Duration};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{CrashGuardOp, RestartPolicy},
  validate_name,
};

use crate::{docker::Docker, exec::Ctx};

pub(crate) async fn run(
  docker: &Docker,
  job: CrashGuardOp,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let (project, expected) = match &job {
    CrashGuardOp::Policies { service } => (service, None),
    CrashGuardOp::Disable { service, policies }
    | CrashGuardOp::Restore { service, policies } => {
      (service, Some(policies))
    }
  };
  validate_name("服务", project)?;
  let dir = docker.project_dir(project);
  let state = docker.one_status(project, ctx).await?;
  let refuse = || {
    ApiError::new(ErrorCode::Conflict, "容器身份或重启策略发生变化")
      .with_hint("查看服务的实时状态后重试")
  };
  if state.hash.is_none() || state.containers.is_empty() {
    return Err(refuse());
  }
  let mut policies = Vec::new();
  for container in state.containers {
    if container.foreign
      || container
        .working_dir
        .as_deref()
        .is_none_or(|dir_value| Path::new(dir_value) != dir)
    {
      return Err(refuse());
    }
    if container.is_completed_init() {
      continue;
    }
    let id = container.container_id.ok_or_else(refuse)?;
    let policy = container.restart_policy.ok_or_else(refuse)?;
    if !valid_id(&id) || !valid_policy(&policy) {
      return Err(refuse());
    }
    policies.push(RestartPolicy { id, policy });
  }
  if policies.is_empty() {
    return Err(refuse());
  }
  let Some(expected) = expected else {
    return Ok(json!(policies));
  };
  if expected.len() != policies.len()
    || expected.iter().any(|p| {
      !valid_policy(&p.policy)
        || policies.iter().filter(|c| c.id == p.id).count() != 1
    })
  {
    return Err(refuse());
  }
  let restore = matches!(job, CrashGuardOp::Restore { .. });
  for prior in expected {
    let actual = policies
      .iter()
      .find(|p| p.id == prior.id)
      .ok_or_else(refuse)?;
    if actual.policy != "no" && actual.policy != prior.policy {
      return Err(refuse());
    }
  }
  for prior in expected {
    let policy = if restore { &prior.policy } else { "no" };
    docker
      .cmd()
      .args(["update", "--restart", policy, "--", &prior.id])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("修改容器重启策略")?;
  }
  Ok(json!(true))
}

fn valid_id(id: &str) -> bool {
  id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_policy(policy: &str) -> bool {
  matches!(policy, "no" | "always" | "unless-stopped" | "on-failure")
    || policy
      .strip_prefix("on-failure:")
      .is_some_and(|retries| retries.parse::<u32>().is_ok())
}
