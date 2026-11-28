//! 只记录这台服务器上纳管服务的 OOM 事件。

use wharf_api_types::view::{Issue, IssueLevel, IssueSubject};

use crate::{metrics, rules, snapshot, state::AppState};

pub async fn record_at(
  state: &AppState,
  server: &str,
  at: i64,
  oom: Option<Vec<String>>,
) {
  let Some(oom) = oom else { return };
  let snap = match snapshot::load(&state.db).await {
    Ok(snap) => snap,
    Err(e) => {
      tracing::warn!("记录 OOM 事件：读配置失败：{e}");
      return;
    }
  };
  for (name, row) in &snap.world.services {
    if row.spec.server != server || row.spec.stopped {
      continue;
    }
    if oom.contains(name) {
      metrics::event_at(state, at, "oom.kill", name, 1.0).await;
      let detail = row
        .spec
        .limits
        .as_ref()
        .and_then(|l| l.memory_mb)
        .map(|mb| format!("上限 {mb} MB"))
        .unwrap_or_else(|| "没有在 Wharf 里设内存上限".into());
      rules::observe_at(
        state,
        at,
        "container.oom",
        name,
        1.0,
        &detail,
      )
      .await;
    } else {
      rules::observe_at(state, at, "container.oom", name, 0.0, "")
        .await;
    }
  }
}

pub fn issues(world: &crate::world::World) -> Vec<Issue> {
  rules::firing_subjects("oom_killed")
    .into_iter()
    .filter(|(name, _)| crate::rules::lifecycle::running_service(world, name))
    .map(|(name, title)| {
      let (alert, ack) = rules::issue_alert("oom_killed", &name);
      Issue {
        code: "oom_killed".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: name.clone(),
        }),
        title,
        hint: Some(format!(
          "看时间线和内存曲线；内存确实不够就调大上限：wharf service limits {name} --memory <MB> --apply"
        )),
        ack,
        alert,
      }
    })
    .collect()
}
