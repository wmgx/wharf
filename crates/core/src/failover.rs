//! 备用入口（P9）：路由设了 `backup_gateway` 时，两个网关都配好这个域名，DNS 指向主网关。
//!
//! 每分钟看一次主网关所在机器：连续 [SWITCH_MINUTES] 分钟离线（备用那台在线）就切到备用，
//! 主网关连续 [SWITCH_MINUTES] 分钟在线再切回。切换 = 改 DNS 记录（从计划里取出这个域名的
//! DNS 步骤单独执行）；切到 caddy 备用入口时顺带重启它，让它马上申请证书。
//!
//! 哪些域名在备用入口上存进设置 `failover.active`，控制面重启后接着用。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::AgentOp, plan::PlanRequest, spec::GatewayKind,
};

use crate::{db, notify, planner::Step, state::AppState};

const EVERY: Duration = Duration::from_secs(60);
const SWITCH_MINUTES: u32 = 5;
const SETTING: &str = "failover.active";

#[derive(Default)]
struct Memory {
  /// 切到备用入口的域名。
  active: BTreeSet<String>,
  /// 域名 → 主网关所在机器连续离线（切回时是连续在线）的分钟数。
  streak: BTreeMap<String, u32>,
  /// 切换了但 DNS 还没改成功的域名，下一轮重试。
  pending: BTreeSet<String>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Memory) -> T) -> T {
  let mut guard = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
  f(guard.get_or_insert_with(Memory::default))
}

/// 这个域名现在是否走备用入口。
pub fn active(host: &str) -> bool {
  with(|m| m.active.contains(host))
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    if let Ok(Some(v)) =
      state.db.call(|c| db::setting(c, SETTING)).await
      && let Ok(hosts) = serde_json::from_str::<BTreeSet<String>>(&v)
    {
      with(|m| m.active = hosts);
    }
    // 刚启动时 agent 还在陆续连回来，别误判离线。
    tokio::time::sleep(Duration::from_secs(180)).await;
    loop {
      if let Err(e) = round(&state).await {
        tracing::warn!("备用入口检查失败：{}", e.message);
      }
      tokio::time::sleep(EVERY).await;
    }
  });
}

async fn round(
  state: &Arc<AppState>,
) -> Result<(), wharf_api_types::ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;
  let world = &snap.world;
  let mut switches = Vec::new();
  with(|m| {
    // 去掉了备用入口的路由：切回主网关。
    let gone: Vec<String> = m
      .active
      .iter()
      .filter(|h| {
        world
          .routes
          .get(*h)
          .is_none_or(|r| r.spec.backup_gateway.is_none())
      })
      .cloned()
      .collect();
    for h in gone {
      m.active.remove(&h);
      m.pending.insert(h);
    }
    m.streak.retain(|h, _| world.routes.contains_key(h));
    for (host, route) in &world.routes {
      let Some(backup) = route.spec.backup_gateway.as_deref() else {
        continue;
      };
      let (Some(primary), Some(backup)) = (
        world
          .route_gateway(&route.spec)
          .and_then(|g| world.gateways.get(g)),
        world.gateways.get(backup),
      ) else {
        continue;
      };
      let primary_up = state.hub.is_online(&primary.spec.server);
      let on_backup = m.active.contains(host);
      // 在主网关上看离线，在备用上看恢复。
      let toward = if on_backup { primary_up } else { !primary_up };
      let n = m.streak.entry(host.clone()).or_default();
      *n = if toward { *n + 1 } else { 0 };
      let backup_up = state.hub.is_online(&backup.spec.server);
      if *n >= SWITCH_MINUTES && (on_backup || backup_up) {
        *n = 0;
        if on_backup {
          m.active.remove(host);
        } else {
          m.active.insert(host.clone());
        }
        m.pending.insert(host.clone());
        switches.push((
          host.clone(),
          !on_backup,
          primary.spec.server.clone(),
          route.spec.backup_gateway.clone().unwrap_or_default(),
        ));
      }
    }
  });
  if !switches.is_empty() {
    let hosts = with(|m| m.active.clone());
    let value = serde_json::to_string(&hosts).unwrap_or_default();
    state
      .db
      .call(move |c| db::set_setting(c, SETTING, Some(&value)))
      .await?;
  }
  for (host, to_backup, primary_server, backup) in &switches {
    let event = if *to_backup {
      notify::Event {
        title: format!("{host} 切到备用入口 {backup}"),
        body: format!(
          "主网关所在的 {primary_server} 已经 {SWITCH_MINUTES} 分钟离线，DNS 改指向备用入口 {backup}；{primary_server} 恢复后自动切回"
        ),
      }
    } else {
      notify::Event {
        title: format!("{host} 切回主网关"),
        body: format!(
          "{primary_server} 已经恢复 {SWITCH_MINUTES} 分钟，DNS 改回主网关"
        ),
      }
    };
    crate::rules::notice(state, "failover", None, !*to_backup, event)
      .await;
  }
  let pending: Vec<String> =
    with(|m| m.pending.iter().cloned().collect());
  for host in pending {
    match update_dns(state, &host).await {
      Ok(()) => with(|m| {
        m.pending.remove(&host);
      }),
      Err(e) => {
        tracing::warn!(
          "改 {host} 的 DNS 失败，下一轮重试：{}",
          e.message
        )
      }
    }
  }
  Ok(())
}

/// 从完整计划里取出这个域名的 DNS 步骤单独执行；不用改时什么也不做。
async fn update_dns(
  state: &Arc<AppState>,
  host: &str,
) -> Result<(), wharf_api_types::ApiError> {
  let planned =
    crate::planner::make_plan(state, PlanRequest::default()).await?;
  let step = planned.steps.into_iter().find_map(|s| match s.step {
    Step::DnsUpsert { ref hostname, .. } if hostname == host => {
      Some(s.step)
    }
    _ => None,
  });
  let Some(step) = step else {
    return Ok(());
  };
  crate::apply::start_task(
    state.clone(),
    format!("切换 {host} 的入口"),
    step,
  )
  .await?;
  if active(host) {
    restart_caddy_backup(state, host).await;
  }
  Ok(())
}

/// caddy 备用入口在 DNS 指过来之前拿不到证书，重启一下让它马上重新申请。
async fn restart_caddy_backup(state: &Arc<AppState>, host: &str) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let Some(name) = snap
    .world
    .routes
    .get(host)
    .and_then(|r| r.spec.backup_gateway.clone())
  else {
    return;
  };
  let Some(gw) = snap.world.gateways.get(&name) else {
    return;
  };
  if gw.spec.kind != GatewayKind::Caddy {
    return;
  }
  // 等 DNS 生效（记录 TTL 一般 1 到 5 分钟）。
  let state = state.clone();
  let server = gw.spec.server.clone();
  let project = crate::world::gateway_project(&name);
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(120)).await;
    let cancel = CancellationToken::new();
    for op in [
      AgentOp::ProjectStop {
        project: project.clone(),
      },
      AgentOp::ProjectStart {
        project: project.clone(),
      },
    ] {
      let r: Result<serde_json::Value, _> = state
        .hub
        .call(&server, op, Duration::from_secs(60), None, &cancel)
        .await;
      if let Err(e) = r {
        tracing::warn!("重启备用入口 {project} 失败：{}", e.message);
        return;
      }
    }
  });
}
