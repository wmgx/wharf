//! 服务的分层状态：期望、已应用、实际、健康、执行，再按优先级挑一句话给页面和 CLI。

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ContainerInfo, ProjectState},
  view::{
    Actual, Applied, Health, LastOp, OpStatus, ServiceStatus, Tone,
  },
};

pub struct Inputs<'a> {
  pub want_running: bool,
  pub desired_hash: Option<String>,
  pub applied: Option<&'a Applied>,
  /// 这台服务器的查询结果；`None` 表示没查。
  pub live: Option<&'a Result<&'a ProjectState, &'a ApiError>>,
  pub last_op: Option<&'a LastOp>,
}

pub fn service_status(i: Inputs<'_>) -> ServiceStatus {
  let (actual, actual_hash, containers) = match i.live {
    None => (Actual::Unknown, None, &[][..]),
    Some(Err(e)) if e.code == ErrorCode::AgentOffline => {
      (Actual::Offline, None, &[][..])
    }
    Some(Err(_)) => (Actual::Unknown, None, &[][..]),
    Some(Ok(p)) => {
      (actual_of(&p.containers), p.hash.clone(), &p.containers[..])
    }
  };
  let error = match i.live {
    Some(Err(e)) => Some(e.message.clone()),
    _ => None,
  };
  let health = health_of(containers);
  let (tone, summary) =
    summarize(&i, actual, actual_hash.as_deref(), health);
  ServiceStatus {
    want_running: i.want_running,
    desired_hash: i.desired_hash,
    applied: i.applied.cloned(),
    actual,
    actual_hash,
    health,
    last_op: i.last_op.cloned(),
    tone,
    summary,
    error,
  }
}

fn actual_of(containers: &[ContainerInfo]) -> Actual {
  let running =
    containers.iter().filter(|c| c.state == "running").count();
  if containers.is_empty() {
    Actual::Missing
  } else if running == containers.len() {
    Actual::Running
  } else if running == 0 {
    Actual::Stopped
  } else {
    Actual::Partial
  }
}

/// 有一个不健康就算不健康；没有任何容器配健康检查时是 `None`。
fn health_of(containers: &[ContainerInfo]) -> Health {
  let has = |h: &str| {
    containers.iter().any(|c| c.health.as_deref() == Some(h))
  };
  if has("unhealthy") {
    Health::Unhealthy
  } else if has("starting") {
    Health::Starting
  } else if has("healthy") {
    Health::Healthy
  } else {
    Health::None
  }
}

/// 优先级从高到低；越靠前越需要人管。
fn summarize(
  i: &Inputs<'_>,
  actual: Actual,
  actual_hash: Option<&str>,
  health: Health,
) -> (Tone, String) {
  let applied = i.applied.map(|a| a.hash.as_str());
  match (actual, i.last_op) {
    (Actual::Offline, _) => return (Tone::Bad, "服务器离线".into()),
    (Actual::Unknown, _) => return (Tone::Idle, "查不到现状".into()),
    (_, Some(op)) if op.status == OpStatus::Failed => {
      return (Tone::Bad, format!("{}失败", op.action));
    }
    (_, Some(op)) if op.status == OpStatus::Running => {
      return (Tone::Idle, format!("正在{}", op.action));
    }
    _ => {}
  }
  if !i.want_running {
    return match actual {
      Actual::Stopped | Actual::Missing => {
        (Tone::Idle, "已停止".into())
      }
      _ => (Tone::Warn, "应停止 · 还在运行".into()),
    };
  }
  match actual {
    Actual::Missing if applied.is_none() => {
      return (Tone::Bad, "未部署".into());
    }
    Actual::Missing => return (Tone::Bad, "容器不见了".into()),
    Actual::Stopped => return (Tone::Bad, "已停止".into()),
    Actual::Partial => return (Tone::Warn, "部分运行".into()),
    _ => {}
  }
  match health {
    Health::Unhealthy => {
      return (Tone::Bad, "运行中 · 不健康".into());
    }
    Health::Starting => return (Tone::Warn, "启动中".into()),
    _ => {}
  }
  if let Some(applied) = applied {
    if i.desired_hash.as_deref().is_some_and(|d| d != applied) {
      return (Tone::Warn, "配置有改动，未部署".into());
    }
    if actual_hash.is_some_and(|h| h != applied) {
      return (Tone::Warn, "和上次部署不一致".into());
    }
  }
  (Tone::Ok, "运行中".into())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn container(state: &str, health: Option<&str>) -> ContainerInfo {
    serde_json::from_value(serde_json::json!({
      "service": "web", "name": "web-1", "state": state, "status": "",
      "health": health, "image": "x",
    }))
    .unwrap()
  }

  #[test]
  fn summary_priority() {
    let applied = Applied {
      hash: "a".into(),
      at: Default::default(),
      digest: None,
      image: None,
      image_id: None,
      commit: None,
      git: None,
    };
    let failed = LastOp {
      action: "部署".into(),
      run_id: "r".into(),
      status: OpStatus::Failed,
      at: Default::default(),
      error: Some("拉取镜像失败".into()),
    };
    let up = ProjectState {
      hash: Some("a".into()),
      project: "web".into(),
      config_hash: None,
      containers: vec![container("running", None)],
    };
    let offline = ApiError::new(
      ErrorCode::AgentOffline,
      "服务器 x 的 agent 不在线",
    );
    let summary = |live: Result<&ProjectState, &ApiError>,
                   desired: &str,
                   op: Option<&LastOp>| {
      service_status(Inputs {
        want_running: true,
        desired_hash: Some(desired.into()),
        applied: Some(&applied),
        live: Some(&live),
        last_op: op,
      })
      .summary
    };
    assert_eq!(summary(Ok(&up), "a", None), "运行中");
    // 旧版本还在跑，也要显示部署失败。
    assert_eq!(summary(Ok(&up), "b", Some(&failed)), "部署失败");
    assert_eq!(summary(Ok(&up), "b", None), "配置有改动，未部署");
    assert_eq!(
      summary(Err(&offline), "a", Some(&failed)),
      "服务器离线"
    );
    let drifted = ProjectState {
      hash: Some("z".into()),
      ..up.clone()
    };
    assert_eq!(summary(Ok(&drifted), "a", None), "和上次部署不一致");
    let sick = ProjectState {
      containers: vec![container("running", Some("unhealthy"))],
      ..up.clone()
    };
    assert_eq!(summary(Ok(&sick), "a", None), "运行中 · 不健康");
  }
}
