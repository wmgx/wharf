//! 备用入口（P9）：路由设了 `backup_gateway` 时，两个网关都配好这个域名，DNS 指向主网关。
//!
//! 每分钟看一次主网关所在机器：连续 [SWITCH_MINUTES] 分钟离线（备用那台在线）就切到备用，
//! 主网关连续 [SWITCH_MINUTES] 分钟在线再切回。切换 = 改 DNS 记录（从计划里取出这个域名的
//! DNS 步骤单独执行）；切到 caddy 备用入口时延迟热重载，促使它重新申请证书。
//!
//! 哪些域名在备用入口上存进设置 `failover.active`，控制面重启后接着用。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode, agent::AgentOp, plan::StepStatus,
  spec::GatewayKind,
};

use crate::{db, notify, state::AppState, world::World};

const EVERY: Duration = Duration::from_secs(60);
const SWITCH_MINUTES: u32 = 5;
const SETTING: &str = "failover.active";
const PENDING: &str = "failover.pending";

pub fn pending_view(
  host: &str,
) -> Option<wharf_api_types::view::FailoverPendingView> {
  with(|m| {
    m.pending.get(host).map(|p| {
      wharf_api_types::view::FailoverPendingView {
        target_backup: p.target_backup,
        attempts: p.attempts,
        last_error: p.last_error.clone(),
      }
    })
  })
}

pub fn load_active_from_conn(
  c: &rusqlite::Connection,
) -> Result<BTreeSet<String>, wharf_api_types::ApiError> {
  db::setting(c, SETTING)?.map_or_else(
    || Ok(BTreeSet::new()),
    |v| serde_json::from_str(&v).map_err(db::json_err),
  )
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Pending {
  target_backup: bool,
  primary_server: String,
  backup_gateway: String,
  attempts: u32,
  last_error: Option<String>,
  next_retry_ms: i64,
}

#[derive(Clone, Default)]
struct Memory {
  /// 切到备用入口的域名。
  active: BTreeSet<String>,
  /// 域名 → 主网关所在机器连续离线（切回时是连续在线）的分钟数。
  streak: BTreeMap<String, u32>,
  /// 切换了但 DNS 还没改成功的域名，下一轮重试。
  pending: BTreeMap<String, Pending>,
}

static RELOADS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
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
    loop {
      match state
        .db
        .call(|c| {
          Ok(Memory {
            active: load_active_from_conn(c)?,
            pending: db::setting(c, PENDING)?
              .map(|v| serde_json::from_str(&v))
              .transpose()
              .map_err(db::json_err)?
              .unwrap_or_default(),
            ..Memory::default()
          })
        })
        .await
      {
        Ok(memory) => {
          with(|m| *m = memory);
          break;
        }
        Err(e) => {
          tracing::warn!("读取主备切换状态失败：{}", e.message)
        }
      }
      tokio::time::sleep(EVERY).await;
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

async fn persist(
  state: &AppState,
  memory: &Memory,
) -> Result<(), ApiError> {
  let active =
    serde_json::to_string(&memory.active).map_err(db::json_err)?;
  let pending =
    serde_json::to_string(&memory.pending).map_err(db::json_err)?;
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      db::set_setting(&tx, SETTING, Some(&active))?;
      db::set_setting(&tx, PENDING, Some(&pending))?;
      tx.commit().map_err(db::sql_err)
    })
    .await?;
  with(|m| *m = memory.clone());
  Ok(())
}

fn observe(
  memory: &mut Memory,
  world: &World,
  online: impl Fn(&str) -> bool,
) -> bool {
  let before = memory.active.clone();
  let pending_count = memory.pending.len();
  memory.streak.retain(|h, _| world.routes.contains_key(h));
  memory.active.retain(|h| world.routes.contains_key(h));
  memory.pending.retain(|h, _| world.routes.contains_key(h));
  let mut changed = false;
  for (host, route) in &world.routes {
    let on_backup = memory.active.contains(host);
    let Some(primary) = world
      .route_gateway(&route.spec)
      .and_then(|g| world.gateways.get(g))
    else {
      continue;
    };
    let primary_server = &primary.spec.server;
    let backup =
      route.spec.backup_gateway.as_deref().unwrap_or_default();
    let target = if let Some(gw) = world.gateways.get(backup) {
      let toward = if on_backup {
        online(primary_server)
      } else {
        !online(primary_server)
      };
      let n = memory.streak.entry(host.clone()).or_default();
      *n = if toward { n.saturating_add(1) } else { 0 };
      if *n >= SWITCH_MINUTES
        && (on_backup || online(&gw.spec.server))
      {
        *n = 0;
        !on_backup
      } else {
        on_backup
      }
    } else {
      memory.streak.remove(host);
      false
    };
    let target_changed = memory.pending.get(host).is_some_and(|p| {
      p.primary_server != *primary_server
        || p.backup_gateway != backup
    });
    if target == on_backup && !target_changed {
      continue;
    }
    if target {
      memory.active.insert(host.clone());
    } else {
      memory.active.remove(host);
    }
    memory.pending.insert(
      host.clone(),
      Pending {
        target_backup: target,
        primary_server: primary_server.clone(),
        backup_gateway: backup.into(),
        attempts: 0,
        last_error: None,
        next_retry_ms: 0,
      },
    );
    changed = true;
  }
  changed
    || before != memory.active
    || pending_count != memory.pending.len()
}

async fn round(state: &Arc<AppState>) -> Result<(), ApiError> {
  let Ok(guard) = state
    .locks
    .acquire(crate::locks::LockSpec::apply([]), "主备切换")
  else {
    return Ok(());
  };
  let snap = crate::snapshot::load(&state.db).await?;
  let mut memory = with(|m| m.clone());
  if observe(&mut memory, &snap.world, |s| state.hub.is_online(s)) {
    persist(state, &memory).await?;
  } else {
    with(|m| m.streak.clone_from(&memory.streak));
  }
  let now = db::now_ms();
  let due = memory
    .pending
    .iter()
    .filter(|(_, p)| p.next_retry_ms <= now)
    .map(|(host, _)| host.clone())
    .collect::<BTreeSet<_>>();
  if due.is_empty() {
    return Ok(());
  }
  let mut results = BTreeMap::new();
  let mut hosts = Vec::new();
  let mut steps = Vec::new();
  for (host, planned) in
    crate::planner::plan_dns_for_hosts(&snap, &due).await
  {
    match planned {
      Ok(Some(step)) => {
        hosts.push(host);
        steps.push(step);
      }
      Ok(None) => {
        results.insert(host, Ok(()));
      }
      Err(e) => {
        results.insert(host, Err(e));
      }
    }
  }
  let guard = if steps.is_empty() {
    guard
  } else {
    let (done, guard) =
      crate::apply::run_batch_sync(state.clone(), steps, guard)
        .await?;
    for (host, step) in hosts.into_iter().zip(done) {
      results.insert(
        host,
        if step.status == StepStatus::Done {
          Ok(())
        } else {
          Err(step.error.unwrap_or_else(|| {
            ApiError::new(ErrorCode::Cancelled, "DNS 切换未执行")
          }))
        },
      );
    }
    guard
  };
  let mut notices = Vec::new();
  let mut reloads: BTreeMap<String, u32> = BTreeMap::new();
  for (host, result) in results {
    let Some(p) = memory.pending.get_mut(&host) else {
      continue;
    };
    match result {
      Ok(()) => {
        let p = memory.pending.remove(&host).expect("待切换域名");
        if p.target_backup
          && let Some(gw) = snap.world.gateways.get(&p.backup_gateway)
          && gw.spec.kind == GatewayKind::Caddy
        {
          let ttl = crate::world::effective_dns_ttl(
            &snap.world.routes[&host].spec,
            false,
          );
          let wait =
            reloads.entry(p.backup_gateway.clone()).or_default();
          *wait = (*wait).max(ttl.saturating_add(5).clamp(30, 120));
        }
        notices.push((
          host.clone(),
          "failover",
          !p.target_backup,
          notify::Event {
            title: if p.target_backup {
              format!("{host} 已切到备用入口 {}", p.backup_gateway)
            } else {
              format!("{host} 已切回主网关")
            },
            body: format!(
              "DNS 已更新，主网关所在服务器为 {}",
              p.primary_server
            ),
          },
        ));
      }
      Err(e) => {
        let message = crate::log_redact::redact_text(&e.message);
        p.attempts = p.attempts.saturating_add(1);
        p.next_retry_ms = now
          + match p.attempts {
            1 => 60_000,
            2 => 120_000,
            _ => 300_000,
          };
        p.last_error = Some(message.clone());
        notices.push((
          host.clone(),
          "failover_error",
          false,
          notify::Event {
            title: format!("{host} 的主备入口切换失败"),
            body: message,
          },
        ));
      }
    }
  }
  persist(state, &memory).await?;
  drop(guard);
  for (name, wait) in reloads {
    schedule_caddy_reload(state, &snap.world, name, wait);
  }
  for (host, kind, resolved, event) in notices {
    crate::rules::notice(state, kind, Some(&host), resolved, event)
      .await;
  }
  Ok(())
}

fn schedule_caddy_reload(
  state: &Arc<AppState>,
  world: &World,
  name: String,
  wait: u32,
) {
  let Some(gw) = world.gateways.get(&name) else {
    return;
  };
  if !RELOADS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(name.clone())
  {
    return;
  }
  let state = state.clone();
  let server = gw.spec.server.clone();
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(wait.into())).await;
    let result = state
      .hub
      .call::<serde_json::Value>(
        &server,
        AgentOp::GatewayReload {
          project: crate::world::gateway_project(&name),
        },
        Duration::from_secs(60),
        None,
        &CancellationToken::new(),
      )
      .await;
    if let Err(e) = result {
      tracing::warn!(
        "热重载备用入口 {name} 失败：{}。检查 agent 版本，必要时运行 wharf upgrade",
        e.message
      );
    }
    RELOADS
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .remove(&name);
  });
}
