//! 巡检：每分钟看一遍服务。配置要求运行、部署的就是当前配置，
//! 但容器退出了或者健康检查不通过，连续两次看到就自动重启。
//!
//! Docker 的 `unless-stopped` 会把崩溃的容器拉起来，但不管"健康检查不通过"
//! 和被手动停掉的容器，这里补上。每个服务一小时最多自动重启 3 次，
//! 再坏就是程序本身的问题，留给人看。

use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use wharf_api_types::{
  agent::ProjectState,
  plan::RunStatus,
  view::{Issue, IssueLevel, IssueSubject, OpStatus},
};

use crate::{
  apply, planner::Step, snapshot, state::AppState, views::cached_live,
};

const TICK: Duration = Duration::from_secs(60);
const FIRST_TICK: Duration = Duration::from_secs(90);
/// 连续看到几次才动手，避免撞上正在重启、正在部署的瞬间。
const STRIKES: u32 = 2;
const MAX_RESTARTS: usize = 3;
const WINDOW: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Record {
  strikes: u32,
  restarts: Vec<Instant>,
  /// 已经因为次数用完而放弃，只提醒一次。
  gave_up: bool,
  pending_run: Option<String>,
}

pub const AUTO_RESTART_TITLE: &str = "自动重启 ";
static GAVE_UP: Mutex<BTreeMap<String, String>> =
  Mutex::new(BTreeMap::new());
static CLEARED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub fn clear(service: &str) {
  CLEARED.lock().unwrap().insert(service.to_string());
  GAVE_UP.lock().unwrap().remove(service);
}

pub fn issues() -> Vec<Issue> {
  GAVE_UP
    .lock()
    .unwrap()
    .iter()
    .map(|(name, why)| Issue {
      code: "heal_gave_up".into(),
      level: IssueLevel::Fault,
      subject: Some(IssueSubject {
        kind: "service".into(),
        name: name.clone(),
      }),
      title: format!("服务 {name} 自动重启已放弃：{why}"),
      hint: Some(format!(
        "wharf service logs {name}；修好后重新部署或重启会自动清除"
      )),
    })
    .collect()
}

async fn notice(state: &AppState, name: &str, why: Option<&str>) {
  let event = if let Some(why) = why {
    crate::notify::Event {
      title: format!("服务 {name} 自动重启已放弃"),
      body: format!(
        "一小时内已自动重启 {MAX_RESTARTS} 次仍未恢复（{why}）。排查日志：wharf service logs {name}"
      ),
    }
  } else {
    crate::notify::Event {
      title: format!("服务 {name} 已恢复运行"),
      body: "容器已恢复正常，自动重启重新启用".into(),
    }
  };
  // Record 自己去重，删除/手动恢复后同名服务也可以发出新告警。
  crate::rules::notice(state, "heal", None, why.is_none(), event)
    .await;
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    let mut records: HashMap<String, Record> = HashMap::new();
    loop {
      if let Err(e) = tick(&state, &mut records).await {
        tracing::warn!("巡检失败：{e}");
      }
      tokio::time::sleep(TICK).await;
    }
  });
}

async fn tick(
  state: &Arc<AppState>,
  records: &mut HashMap<String, Record>,
) -> Result<(), wharf_api_types::ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let net = snap.net(&snap.world);
  let live = cached_live(state, &snap.world).await;
  for name in std::mem::take(&mut *CLEARED.lock().unwrap()) {
    records.remove(&name);
  }
  records.retain(|name, _| {
    snap
      .world
      .services
      .get(name)
      .is_some_and(|r| !r.spec.stopped)
  });
  GAVE_UP
    .lock()
    .unwrap()
    .retain(|name, _| records.contains_key(name));
  for (name, row) in &snap.world.services {
    if row.spec.stopped {
      continue;
    }
    let rec = records.entry(name.clone()).or_default();
    if let Some(id) = &rec.pending_run {
      if state.runs.get(id).is_some() {
        continue;
      }
      if let Ok(run) = apply::load_run(state, id).await {
        if matches!(
          run.status,
          RunStatus::Succeeded | RunStatus::Failed
        ) {
          rec.restarts.push(Instant::now());
        }
        if run.status == RunStatus::Succeeded {
          crate::metrics::event(state, "heal.restart", name, 1.0)
            .await;
        }
      }
      rec.pending_run = None;
    }
    let busy = state.is_service_busy(name)
      || snap
        .ops
        .get(name)
        .is_some_and(|op| op.status == OpStatus::Running);
    let observed = live.get(&row.spec.server);
    if !ready_to_observe(
      rec,
      busy,
      observed.is_some_and(Result::is_ok),
    ) {
      continue;
    }
    let Some(p) = observed
      .and_then(|o| o.as_ref().ok())
      .and_then(|projects| projects.get(name))
    else {
      rec.strikes = 0;
      continue;
    };
    let expected = snapshot::service_resolved(
      &snap.world,
      &net,
      name,
      &snap.render_values(&snap.world, name),
    )
    .ok()
    .map(|(_, h)| h);
    if p.hash.is_none()
      || p.hash != expected
      || p.containers.iter().all(|c| c.foreign)
    {
      rec.strikes = 0;
      continue;
    }
    let Some(why) = broken(p) else {
      rec.strikes = 0;
      if clear_give_up(name, rec) {
        notice(state, name, None).await;
      }
      continue;
    };
    rec.strikes = rec.strikes.saturating_add(1);
    if rec.strikes < STRIKES {
      continue;
    }
    rec.restarts.retain(|t| t.elapsed() < WINDOW);
    if rec.restarts.len() >= MAX_RESTARTS {
      if record_give_up(name, rec, &why) {
        notice(state, name, Some(&why)).await;
      }
      continue;
    }
    if let Ok(started) = apply::start_task(
      state.clone(),
      format!("{AUTO_RESTART_TITLE}{name}（{why}）"),
      Step::ServiceRestart {
        service: name.clone(),
      },
    )
    .await
    {
      rec.pending_run = Some(started.run_id);
      rec.strikes = 0;
    }
  }
  Ok(())
}

fn ready_to_observe(
  rec: &mut Record,
  busy: bool,
  observed: bool,
) -> bool {
  if busy {
    rec.strikes = 0;
  }
  !busy && observed
}

fn clear_give_up(name: &str, rec: &mut Record) -> bool {
  if !std::mem::take(&mut rec.gave_up) {
    return false;
  }
  GAVE_UP.lock().unwrap().remove(name);
  true
}

fn record_give_up(name: &str, rec: &mut Record, why: &str) -> bool {
  if rec.gave_up {
    return false;
  }
  tracing::warn!(
    "{name} 一小时内已自动重启 {MAX_RESTARTS} 次，不再重启：{why}"
  );
  rec.gave_up = true;
  GAVE_UP
    .lock()
    .unwrap()
    .insert(name.to_string(), why.to_string());
  true
}

/// 应该在运行却没在正常运行的原因。
fn broken(p: &ProjectState) -> Option<String> {
  if p.containers.is_empty() {
    return None;
  }
  let has_running = p.containers.iter().any(|c| c.is_running());
  let bad: Vec<String> = p
    .containers
    .iter()
    .filter(|c| !c.foreign && !(has_running && c.is_completed_init()))
    .filter_map(|c| {
      if c.health.as_deref() == Some("unhealthy") {
        Some(format!("{} 健康检查不通过", c.service))
      } else if c.state == "exited" || c.state == "dead" {
        Some(format!("{} 已退出", c.service))
      } else {
        None
      }
    })
    .collect();
  (!bad.is_empty()).then(|| bad.join("，"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn skips_busy_service_and_keeps_strikes_on_probe_err() {
    let mut rec = Record {
      strikes: 1,
      ..Default::default()
    };
    assert!(!ready_to_observe(&mut rec, false, false));
    assert_eq!(rec.strikes, 1);
    assert!(!ready_to_observe(&mut rec, true, true));
    assert_eq!(rec.strikes, 0);
  }

  #[test]
  fn gave_up_emits_issue_and_clears_on_recovery() {
    let name = "heal-fixture";
    let mut rec = Record::default();
    assert!(record_give_up(name, &mut rec, "退出"));
    assert!(!record_give_up(name, &mut rec, "退出"));
    let matching = || {
      issues().iter().any(|i| {
        i.code == "heal_gave_up"
          && i.subject.as_ref().is_some_and(|s| s.name == name)
      })
    };
    assert!(matching());
    assert!(clear_give_up(name, &mut rec));
    assert!(!matching());
    assert!(record_give_up(name, &mut rec, "退出"));
    clear(name);
    assert!(!matching());
    CLEARED.lock().unwrap().remove(name);
  }
}
