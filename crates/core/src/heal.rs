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
  ApiError,
  agent::ProjectState,
  plan::RunStatus,
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::{
  apply, db, planner::Step, snapshot, state::AppState,
  views::cached_live,
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

const NOTICE_PREFIX: &str = "notify.state.heal.";

pub(crate) fn reset_notice(
  conn: &rusqlite::Connection,
  service: &str,
) -> Result<(), ApiError> {
  db::set_setting(conn, &format!("{NOTICE_PREFIX}{service}"), None)
}

pub async fn clear(state: &AppState, service: &str) {
  let name = service.to_string();
  if let Err(e) = state.db.call(move |c| reset_notice(c, &name)).await
  {
    tracing::warn!("清理 {service} 的自愈通知状态失败：{e}");
  }
  forget(service);
}

pub(crate) fn forget(service: &str) {
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
      ack: None,
      alert: None,
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
  crate::rules::notice(
    state,
    "heal",
    Some(name),
    Some(&format!("heal.{name}")),
    why.is_none(),
    event,
  )
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
  if state.is_safe_mode() {
    return Ok(());
  }
  let snap = snapshot::load(&state.db).await?;
  let mut notices = state
    .db
    .call(|c| db::settings_with_prefix(c, NOTICE_PREFIX))
    .await?;
  let net = snap.net(&snap.world);
  let live = cached_live(state, &snap.world).await;
  for name in std::mem::take(&mut *CLEARED.lock().unwrap()) {
    records.remove(&name);
    notices.remove(&name);
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
    let busy = state.is_service_busy(name);
    let observed = snapshot::service_runtime_server(&snap, name)
      .and_then(|server| live.get(server));
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
    let expected = snapshot::service_hash(
      &snap.world,
      &net,
      name,
      &snap.render_values(&snap.world, name),
      p.hash.as_deref(),
    )
    .ok();
    if p.hash.is_none()
      || p.hash != expected
      || p.containers.iter().all(|c| c.foreign)
    {
      rec.strikes = 0;
      continue;
    }
    let was_notified = notices.get(name).is_some_and(|s| s == "fail");
    let Some(why) = broken(p) else {
      rec.strikes = 0;
      if p.all_running()
        && !p.containers.iter().any(|c| {
          c.is_running() && c.health.as_deref() == Some("starting")
        })
        && (clear_give_up(name, rec) || was_notified)
      {
        rec.restarts.clear();
        notice(state, name, None).await;
      }
      continue;
    };
    rec.strikes = rec.strikes.saturating_add(1);
    if rec.strikes < STRIKES {
      continue;
    }
    if restart_limit_reached(rec) || was_notified {
      if record_give_up(name, rec, &why) {
        notice(state, name, Some(&why)).await;
      }
      continue;
    }
    if let Ok(started) = apply::start_task_by(
      state.clone(),
      format!("{AUTO_RESTART_TITLE}{name}（{why}）"),
      Step::ServiceRestart {
        service: name.clone(),
      },
      Some("自动自愈".into()),
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

fn restart_limit_reached(rec: &mut Record) -> bool {
  rec.restarts.retain(|t| t.elapsed() < WINDOW);
  rec.gave_up || rec.restarts.len() >= MAX_RESTARTS
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
    .filter(|c| !(c.foreign || has_running && c.is_completed_init()))
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

  #[tokio::test]
  async fn backup_and_heal_share_service_lock_before_run_is_registered()
   {
    use crate::locks::LockSpec;
    use wharf_api_types::ErrorCode;

    let state = crate::rules::tests::test_state();
    let service = "app".to_string();
    let backup = state
      .locks
      .acquire(LockSpec::Backup(service.clone()), "备份")
      .unwrap();
    assert!(state.is_service_busy(&service));
    assert!(!state.is_service_busy("other"));
    let result = apply::start_task(
      state.clone(),
      AUTO_RESTART_TITLE.into(),
      Step::ServiceRestart {
        service: service.clone(),
      },
    )
    .await;
    assert_eq!(result.err().unwrap().code, ErrorCode::Busy);
    drop(backup);
    assert!(!state.is_service_busy(&service));

    let heal = state
      .locks
      .acquire(LockSpec::apply([service.clone()]), AUTO_RESTART_TITLE)
      .unwrap();
    assert!(state.is_service_busy(&service));
    let result = apply::start_task(
      state.clone(),
      "备份".into(),
      Step::Backup {
        service,
        options: Default::default(),
      },
    )
    .await;
    assert_eq!(result.err().unwrap().code, ErrorCode::Busy);
    drop(heal);
  }

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
  fn gave_up_stays_latched_after_restart_window_expires() {
    let mut rec = Record {
      gave_up: true,
      restarts: vec![Instant::now() - WINDOW; MAX_RESTARTS],
      ..Default::default()
    };
    assert!(restart_limit_reached(&mut rec));
    assert!(rec.restarts.is_empty());
    assert!(clear_give_up("heal-window-fixture", &mut rec));
    assert!(!restart_limit_reached(&mut rec));
  }

  #[tokio::test]
  async fn heal_notice_deduplicates_after_memory_loss_and_resets_on_clear()
   {
    let _lock = crate::rules::tests::TEST_LOCK.lock().await;
    crate::rules::tests::reset_memory();
    let state = crate::rules::tests::test_state();
    let name = "heal-notice-fixture";
    notice(&state, name, Some("退出")).await;
    // 新巡检进程没有上次的 Record，通知仍由持久化状态去重。
    notice(&state, name, Some("退出")).await;
    assert_eq!(
      crate::rules::tests::notice_titles(&state, "heal")
        .await
        .len(),
      1
    );
    notice(&state, name, None).await;
    notice(&state, name, Some("退出")).await;
    clear(&state, name).await;
    notice(&state, name, Some("退出")).await;
    assert_eq!(
      crate::rules::tests::notice_titles(&state, "heal").await,
      [
        format!("服务 {name} 自动重启已放弃"),
        format!("服务 {name} 已恢复运行"),
        format!("服务 {name} 自动重启已放弃"),
        format!("服务 {name} 自动重启已放弃"),
      ]
    );
    CLEARED.lock().unwrap().remove(name);
    crate::rules::tests::reset_memory();
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
    forget(name);
    assert!(!matching());
    CLEARED.lock().unwrap().remove(name);
  }
}
