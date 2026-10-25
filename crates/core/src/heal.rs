//! 巡检：每分钟看一遍服务。配置要求运行、部署的就是当前配置，
//! 但容器退出了或者健康检查不通过，连续两次看到就自动重启。
//!
//! Docker 的 `unless-stopped` 会把崩溃的容器拉起来，但不管"健康检查不通过"
//! 和被手动停掉的容器，这里补上。每个服务一小时最多自动重启 3 次，
//! 再坏就是程序本身的问题，留给人看。

use std::{
  collections::HashMap,
  sync::Arc,
  time::{Duration, Instant},
};

use wharf_api_types::agent::ProjectState;

use crate::{
  apply, planner::Step, snapshot, state::AppState, views::live_states,
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
  let live = live_states(state, &snap.world).await;
  records.retain(|name, _| snap.world.services.contains_key(name));
  for (name, row) in &snap.world.services {
    let observed = live
      .get(&row.spec.server)
      .and_then(|r| r.as_ref().ok())
      .and_then(|projects| projects.get(name));
    let expected =
      snapshot::service_resolved(&snap.world, &net, name, &snap.secrets)
        .ok()
        .map(|(_, h)| h);
    let why = observed.and_then(|p| {
      if row.spec.stopped || p.hash.is_none() || p.hash != expected {
        // 要求停止、不是 Wharf 部署的、和配置不一致（交给计划处理）都不管。
        return None;
      }
      broken(p)
    });
    let rec = records.entry(name.clone()).or_default();
    let Some(why) = why else {
      rec.strikes = 0;
      continue;
    };
    rec.strikes += 1;
    if rec.strikes < STRIKES {
      continue;
    }
    rec.restarts.retain(|t| t.elapsed() < WINDOW);
    if rec.restarts.len() >= MAX_RESTARTS {
      if !rec.gave_up {
        tracing::warn!(
          "{name} 一小时内已自动重启 {MAX_RESTARTS} 次，不再重启：{why}"
        );
        rec.gave_up = true;
      }
      continue;
    }
    // 有别的操作在执行（部署、备份、迁移）时 start_task 会拒绝，下一轮再看。
    let started = apply::start_task(
      state.clone(),
      format!("自动重启 {name}（{why}）"),
      Step::ServiceRestart {
        service: name.clone(),
      },
    )
    .await;
    if started.is_ok() {
      tracing::info!("自动重启 {name}：{why}");
      rec.strikes = 0;
      rec.gave_up = false;
      rec.restarts.push(Instant::now());
    }
  }
  Ok(())
}

/// 应该在运行却没在正常运行的原因。
fn broken(p: &ProjectState) -> Option<String> {
  if p.containers.is_empty() {
    return None;
  }
  let bad: Vec<String> = p
    .containers
    .iter()
    .filter(|c| !c.foreign)
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
