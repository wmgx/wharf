//! 按网关可达性管理路由的备用入口和 DNS 切换。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};

use axum::{
  Extension, Json,
  extract::{Path, State},
};
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::AgentOp,
  plan::StepStatus,
  spec::GatewayKind,
  view::{
    FailoverHealthSnapshot, FailoverPinTarget, FailoverTarget, Perm,
    RouteFailoverRequest, RouteFailoverView,
  },
};

use crate::{
  api::ApiResult, auth::Auth, db, gateway_probe, notify, snapshot,
  state::AppState, world::World,
};

const EVERY: Duration = Duration::from_secs(60);
const SWITCH_MINUTES: u32 = 5;
const SETTING: &str = "failover.active";
const PENDING: &str = "failover.pending";
const PINNED: &str = "failover.pinned";

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
  #[serde(default)]
  reason: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct FailoverPin {
  target: FailoverPinTarget,
}

#[derive(Clone, Default)]
struct Memory {
  /// 切到备用入口的域名。
  active: BTreeSet<String>,
  /// 域名 → 连续满足切备或切回条件的轮数。
  streak: BTreeMap<String, u32>,
  /// 切换了但 DNS 还没改成功的域名，下一轮重试。
  pending: BTreeMap<String, Pending>,
  pinned: BTreeMap<String, FailoverPin>,
  health: BTreeMap<String, FailoverHealthSnapshot>,
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

fn load_memory(c: &rusqlite::Connection) -> Result<Memory, ApiError> {
  Ok(Memory {
    active: load_active_from_conn(c)?,
    pending: db::setting(c, PENDING)?
      .map(|v| serde_json::from_str(&v))
      .transpose()
      .map_err(db::json_err)?
      .unwrap_or_default(),
    pinned: db::setting(c, PINNED)?
      .map(|v| serde_json::from_str(&v))
      .transpose()
      .map_err(db::json_err)?
      .unwrap_or_default(),
    ..Memory::default()
  })
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    loop {
      let guard = state
        .locks
        .acquire(crate::locks::LockSpec::apply([]), "读取主备状态");
      if let Ok(guard) = guard {
        match state.db.call(|c| load_memory(c)).await {
          Ok(memory) => {
            with(|m| *m = memory);
            drop(guard);
            break;
          }
          Err(e) => {
            tracing::warn!("读取主备切换状态失败：{}", e.message)
          }
        }
      }
      tokio::time::sleep(EVERY).await;
    }
    // 刚启动时 agent 还在陆续连回来，别误判离线。
    tokio::time::sleep(Duration::from_secs(180)).await;
    let mut timer = tokio::time::interval(EVERY);
    timer.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      timer.tick().await;
      if let Err(e) = round(&state).await {
        tracing::warn!("备用入口检查失败：{}", e.message);
      }
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
  let pinned =
    serde_json::to_string(&memory.pinned).map_err(db::json_err)?;
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      db::set_setting(&tx, SETTING, Some(&active))?;
      db::set_setting(&tx, PENDING, Some(&pending))?;
      db::set_setting(&tx, PINNED, Some(&pinned))?;
      tx.commit().map_err(db::sql_err)
    })
    .await?;
  with(|m| *m = memory.clone());
  Ok(())
}

fn observe(
  memory: &mut Memory,
  world: &World,
  health: BTreeMap<String, FailoverHealthSnapshot>,
  managed_dns: impl Fn(&str) -> bool,
) -> bool {
  let before = memory.active.clone();
  let pending_count = memory.pending.len();
  let pinned_count = memory.pinned.len();
  let eligible =
    |host: &str| world.routes.contains_key(host) && managed_dns(host);
  memory.streak.retain(|h, _| eligible(h));
  memory.active.retain(|h| eligible(h));
  memory.pending.retain(|h, _| eligible(h));
  memory.pinned.retain(|h, _| {
    eligible(h) && world.routes[h].spec.backup_gateway.is_some()
  });
  memory.health = health;
  let mut changed = false;
  for (host, route) in &world.routes {
    if !managed_dns(host) {
      continue;
    }
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
    let assessed = memory.health.get(host);
    let target = if world.gateways.contains_key(backup) {
      if memory.pinned.contains_key(host)
        || route.spec.expires_at.is_some_and(|at| at <= db::now_ms())
      {
        memory.streak.remove(host);
        on_backup
      } else if let Some(assessed) = assessed {
        decide_failover(
          on_backup,
          (
            assessed.primary.as_ref().is_some_and(|p| p.ok),
            assessed.backup.as_ref().is_some_and(|p| p.ok),
          ),
          assessed.service_stopped,
          memory.streak.entry(host.clone()).or_default(),
          route.spec.failover_minutes.unwrap_or(SWITCH_MINUTES),
        )
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
        reason: if target {
          assessed
            .and_then(|h| h.primary.as_ref())
            .map(|p| p.detail.clone())
            .unwrap_or_default()
        } else {
          "主网关恢复可达".into()
        },
      },
    );
    changed = true;
  }
  changed
    || before != memory.active
    || pending_count != memory.pending.len()
    || pinned_count != memory.pinned.len()
}

fn decide_failover(
  on_backup: bool,
  (primary, backup): (bool, bool),
  blocked: bool,
  streak: &mut u32,
  threshold: u32,
) -> bool {
  let toward = !blocked
    && if on_backup {
      primary
    } else {
      !primary && backup
    };
  *streak = if toward { streak.saturating_add(1) } else { 0 };
  if *streak >= threshold {
    *streak = 0;
    !on_backup
  } else {
    on_backup
  }
}

async fn assess(
  state: &AppState,
  snap: &snapshot::Snapshot,
  memory: &Memory,
) -> BTreeMap<String, FailoverHealthSnapshot> {
  let world = &snap.world;
  let routes = world
    .routes
    .iter()
    .filter_map(|(host, route)| {
      let primary = world.route_gateway(&route.spec)?;
      let backup = route.spec.backup_gateway.as_deref()?;
      (snap.account_for(host).is_some()
        && route.spec.expires_at.is_none_or(|at| at > db::now_ms()))
      .then_some((host, &route.spec, primary, backup))
    })
    .collect::<Vec<_>>();
  if routes.is_empty() {
    return BTreeMap::new();
  }
  let net = &snap.net(world);
  let live = &crate::views::cached_live(state, world).await;
  let cancel = CancellationToken::new();
  let mut jobs = Vec::with_capacity(routes.len());
  for (host, route, primary, backup) in routes {
    let check_backup = !memory.active.contains(host)
      || memory.pending.get(host).is_some_and(|p| p.target_backup);
    jobs.push(assess_route(
      state,
      snap,
      net,
      live,
      (host, route, primary, backup),
      check_backup,
      &cancel,
    ));
  }
  let probes = futures_util::stream::iter(jobs).buffer_unordered(8);
  futures_util::pin_mut!(probes);
  let until = tokio::time::sleep(Duration::from_secs(42));
  tokio::pin!(until);
  let mut health = BTreeMap::new();
  loop {
    tokio::select! {
      next = probes.next() => match next {
        Some((host, entry)) => { health.insert(host, entry); }
        None => break,
      },
      _ = &mut until => break,
    }
  }
  cancel.cancel();
  health
}

async fn assess_route(
  state: &AppState,
  snap: &snapshot::Snapshot,
  net: &crate::render::Net,
  live: &crate::views::LiveMap,
  (host, route, primary, backup): (
    &str,
    &wharf_api_types::spec::RouteSpec,
    &str,
    &str,
  ),
  check_backup: bool,
  cancel: &CancellationToken,
) -> (String, FailoverHealthSnapshot) {
  let project = |server: &str, project: &str| {
    live.get(server)?.as_ref().ok()?.get(project)
  };
  let service_stopped =
    snap.world.services.get(&route.service).is_some_and(|svc| {
      svc.spec.stopped
        || (state.hub.is_online(&svc.spec.server)
          && project(&svc.spec.server, &route.service).is_some_and(
            |state| {
              !state
                .containers
                .iter()
                .any(|c| !c.foreign && c.is_running())
            },
          ))
    });
  let mut health = FailoverHealthSnapshot {
    at: db::now_ms(),
    service_stopped,
    ..Default::default()
  };
  if !service_stopped {
    let check = |name: &str| {
      snap.world.gateways.get(name).and_then(|gw| {
        project(&gw.spec.server, &crate::world::gateway_project(name))
      })
    };
    let main = gateway_probe::check_entry(
      state,
      snap,
      net,
      (host, route, primary),
      check(primary),
      cancel,
    )
    .await;
    if !main.ok && check_backup {
      let backup = gateway_probe::check_entry(
        state,
        snap,
        net,
        (host, route, backup),
        check(backup),
        cancel,
      )
      .await;
      health.backup = Some(backup.into());
    }
    health.primary = Some(main.into());
  }
  (host.into(), health)
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
  let health = assess(state, &snap, &memory).await;
  if observe(&mut memory, &snap.world, health, |host| {
    snap.account_for(host).is_some()
  }) {
    persist(state, &memory).await?;
  } else {
    with(|m| {
      m.streak.clone_from(&memory.streak);
      m.health.clone_from(&memory.health);
    });
  }
  let now = db::now_ms();
  let due = memory
    .pending
    .iter()
    .filter(|(host, p)| {
      if p.next_retry_ms > now {
        return false;
      }
      let route = &snap.world.routes[*host].spec;
      if route.expires_at.is_some_and(|at| at <= now) {
        return false;
      }
      if route.backup_gateway.is_none() {
        return true;
      }
      !memory.pinned.contains_key(*host)
        && memory.health.get(*host).is_some_and(|h| {
          !h.service_stopped
            && if p.target_backup {
              h.backup.as_ref().is_some_and(|p| p.ok)
            } else {
              h.primary.as_ref().is_some_and(|p| p.ok)
            }
        })
    })
    .map(|(host, _)| host.clone())
    .collect::<BTreeSet<_>>();
  if due.is_empty() {
    return Ok(());
  }
  let mut results = BTreeMap::new();
  let mut hosts = Vec::new();
  let mut steps = Vec::new();
  for (host, planned) in
    crate::planner::plan_dns_for_hosts(&snap, &due, None).await
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
    let (_, done, guard) =
      crate::apply::run_batch_sync(state.clone(), steps, guard, None)
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
          *wait = (*wait).max(caddy_reload_delay(ttl));
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
              "DNS 已更新，主网关所在服务器为 {}。{}",
              p.primary_server, p.reason
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
    if kind == "failover" {
      crate::notify::transition(state, &host, true).await;
      crate::rules::notice(
        state,
        kind,
        Some(&host),
        None,
        resolved,
        event,
      )
      .await;
    } else {
      crate::rules::notice(
        state,
        kind,
        Some(&host),
        Some(&host),
        resolved,
        event,
      )
      .await;
    }
  }
  Ok(())
}

pub fn pinned(host: &str) -> Option<FailoverPinTarget> {
  with(|m| m.pinned.get(host).map(|pin| pin.target))
}

fn targets<'a>(
  world: &'a World,
  host: &str,
) -> Result<
  (&'a wharf_api_types::spec::RouteSpec, &'a str, &'a str),
  ApiError,
> {
  let route = &world
    .routes
    .get(host)
    .ok_or_else(|| {
      ApiError::new(ErrorCode::NotFound, format!("没有路由 {host}"))
    })?
    .spec;
  let backup = route.backup_gateway.as_deref().ok_or_else(|| {
    ApiError::invalid(format!("路由 {host} 没有配置备用入口"))
      .with_hint("先配置备用入口后再切换")
      .suggest(format!(
        "wharf route add {host} --backup-gateway <网关> --apply"
      ))
  })?;
  let primary = world
    .route_gateway(route)
    .filter(|name| world.gateways.contains_key(*name))
    .ok_or_else(|| {
      ApiError::invalid("主网关不存在").suggest("wharf gateway list")
    })?;
  if !world.gateways.contains_key(backup) {
    return Err(
      ApiError::invalid("备用网关不存在")
        .suggest("wharf gateway list"),
    );
  }
  Ok((route, primary, backup))
}

fn status(
  world: &World,
  host: &str,
) -> Result<RouteFailoverView, ApiError> {
  let (_, primary, backup) = targets(world, host)?;
  let (on_backup, pinned, health) = with(|m| {
    (
      m.active.contains(host),
      m.pinned.get(host).map(|p| p.target),
      m.health.get(host).cloned(),
    )
  });
  Ok(RouteFailoverView {
    hostname: host.into(),
    primary_gateway: primary.into(),
    backup_gateway: backup.into(),
    on_backup,
    pinned,
    pending: pending_view(host),
    health,
    changed: false,
    run_id: None,
    verification: None,
  })
}

pub(crate) async fn status_api(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(host): Path<String>,
) -> ApiResult<RouteFailoverView> {
  auth.require(Perm::Read)?;
  let host = crate::world::normalize_hostname(&host)?;
  let snap = snapshot::load(&state.db).await?;
  crate::token_scope::require_route_by_host(
    &auth,
    &snap.world,
    &host,
  )?;
  Ok(Json(status(&snap.world, &host)?))
}

pub(crate) async fn manual_api(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<crate::audit::AuditSlot>,
  Path(host): Path<String>,
  Json(req): Json<RouteFailoverRequest>,
) -> ApiResult<RouteFailoverView> {
  auth.require(Perm::Apply)?;
  let host = crate::world::normalize_hostname(&host)?;
  let snap = snapshot::load(&state.db).await?;
  crate::token_scope::require_route_by_host(
    &auth,
    &snap.world,
    &host,
  )?;
  let reason = req
    .reason
    .as_deref()
    .map(crate::log_redact::redact_text)
    .unwrap_or_default();
  audit.set_detail(format!("{host} {:?} {reason}", req.target));
  // 客户端断开时仍要完成 DNS 与状态的提交。
  let response =
    tokio::spawn(
      async move { manual(&state, &host, req, &auth).await },
    )
    .await
    .map_err(|_| ApiError::internal("手动切换任务异常退出"))??;
  Ok(Json(response))
}

async fn manual(
  state: &Arc<AppState>,
  host: &str,
  req: RouteFailoverRequest,
  auth: &Auth,
) -> Result<RouteFailoverView, ApiError> {
  let guard = state
    .locks
    .acquire(crate::locks::LockSpec::apply([]), "手动切换入口")?;
  let snap = snapshot::load(&state.db).await?;
  let world = &snap.world;
  crate::token_scope::require_route_by_host(auth, world, host)?;
  let (route, primary, backup) = targets(world, host)?;
  if snap.account_for(host).is_none() {
    return Err(
      ApiError::invalid(format!(
        "没有厂商账号管理 {host}，无法切换 DNS"
      ))
      .suggest("wharf account list"),
    );
  }
  let mut memory = state.db.call(|c| load_memory(c)).await?;
  with(|m| {
    memory.streak.clone_from(&m.streak);
    memory.health.clone_from(&m.health);
  });
  if req.target == FailoverTarget::Auto {
    let changed = memory.pinned.remove(host).is_some();
    if changed {
      memory.streak.remove(host);
      persist(state, &memory).await?;
    }
    return Ok(RouteFailoverView {
      changed,
      ..status(world, host)?
    });
  }
  let want_backup = req.target == FailoverTarget::Backup;
  let target = if want_backup { backup } else { primary };
  let gw = &world.gateways[target].spec;
  let cancel = CancellationToken::new();
  let net = snap.net(world);
  let mut verification = None;
  if !req.force {
    let check = || {
      ApiError::new(
        ErrorCode::Conflict,
        format!("目标网关 {target} 未运行或配置未同步"),
      )
      .with_hint("先修复目标网关，或加 --force 强制切换")
    };
    let project = gateway_probe::current_project(
      state, &gw.server, target, &cancel,
    )
    .await
    .map_err(|_| check())?
    .filter(|p| p.all_running())
    .ok_or_else(check)?;
    let render = snapshot::gateway_render(world, &net, target)?;
    let applied = if gw.kind == GatewayKind::Caddy {
      project.config_hash.as_deref()
    } else {
      snap.tunnels.get(target).map(|t| t.config_hash.as_str())
    };
    if project.hash.as_deref() != Some(render.compose_hash.as_str())
      || !snapshot::gateway_config_matches(
        world,
        &net,
        target,
        &render,
        applied,
        project.acme_dns_url_hash.as_deref(),
      )
    {
      return Err(check());
    }
    if req.verify_before_dns {
      let result = gateway_probe::verify_before_dns(state, &snap, &net, (host, route, target), &cancel)
        .await.map_err(|e| e.with_hint("修好目标网关后重试；应急时可用 --no-verify 跳过预验，或用 --force 强制切换"))?;
      verification = Some(result.detail);
    }
  }
  let Some((_, planned)) = crate::planner::plan_dns_for_hosts(
    &snap,
    &BTreeSet::from([host.to_string()]),
    Some(target),
  )
  .await
  .pop() else {
    return Err(ApiError::internal("没有生成域名切换结果"));
  };
  let (run_id, guard) = if let Some(step) = planned? {
    let (run, mut done, guard) = crate::apply::run_batch_sync(
      state.clone(),
      vec![step],
      guard,
      Some((target, auth)),
    )
    .await?;
    let step = done.pop().expect("单域名 DNS 步骤");
    if step.status != StepStatus::Done {
      return Err(
        step
          .error
          .unwrap_or_else(|| {
            ApiError::new(ErrorCode::Cancelled, "DNS 切换未执行")
          })
          .suggest(format!("wharf run show {run}")),
      );
    }
    (Some(run), guard)
  } else {
    (None, guard)
  };
  let was_active = memory.active.contains(host);
  let was_pinned = memory.pinned.contains_key(host);
  let had_pending = memory.pending.remove(host).is_some();
  if want_backup {
    memory.active.insert(host.into());
    memory.pinned.insert(
      host.into(),
      FailoverPin {
        target: FailoverPinTarget::Backup,
      },
    );
  } else {
    memory.active.remove(host);
    memory.pinned.remove(host);
  }
  memory.streak.remove(host);
  let changed = run_id.is_some()
    || was_active != want_backup
    || was_pinned != want_backup
    || had_pending;
  if changed {
    persist(state, &memory).await?;
  } else {
    with(|m| {
      m.streak.remove(host);
    });
  }
  drop(guard);
  if run_id.is_some() || was_active != want_backup {
    if want_backup && gw.kind == GatewayKind::Caddy {
      let ttl = crate::world::effective_dns_ttl(route, false);
      schedule_caddy_reload(
        state,
        world,
        backup.into(),
        caddy_reload_delay(ttl),
      );
    }
    let action = if want_backup {
      "手动切到备用入口"
    } else {
      "手动切回主网关"
    };
    let reason = req
      .reason
      .as_deref()
      .map(crate::log_redact::redact_text)
      .unwrap_or_default();
    notify::transition(state, host, true).await;
    crate::rules::notice(
      state,
      "failover",
      Some(host),
      None,
      !want_backup,
      notify::Event {
        title: format!("{host} {action} {target}"),
        body: reason,
      },
    )
    .await;
  }
  Ok(RouteFailoverView {
    changed,
    run_id,
    verification,
    ..status(world, host)?
  })
}

fn caddy_reload_delay(ttl: u32) -> u32 {
  if ttl == 1 {
    120
  } else {
    ttl.saturating_add(5).clamp(30, 120)
  }
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

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use wharf_providers::{
    BoxFut, DnsProvider, DnsRecordSpec, Owner, ProviderError,
    RemoteRecord,
  };

  static WRITERS: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());
  static DNS: Mutex<(Option<RemoteRecord>, bool)> =
    Mutex::new((None, false));

  pub(crate) struct FixtureDns;

  impl DnsProvider for FixtureDns {
    fn validate(
      &self,
      _: &str,
      _: &DnsRecordSpec,
    ) -> Result<(), ProviderError> {
      Ok(())
    }

    fn list<'a>(
      &'a self,
      _: &'a str,
    ) -> BoxFut<'a, Vec<RemoteRecord>> {
      Box::pin(async {
        Ok(DNS.lock().unwrap().0.clone().into_iter().collect())
      })
    }

    fn upsert<'a>(
      &'a self,
      _: &'a str,
      spec: &'a DnsRecordSpec,
      owner: &'a Owner,
      _: Option<&'a RemoteRecord>,
    ) -> BoxFut<'a, RemoteRecord> {
      Box::pin(async move {
        let mut dns = DNS.lock().unwrap();
        if dns.1 {
          return Err(ProviderError::new(
            wharf_providers::error::code::TIMEOUT,
            "DNS 请求超时",
          ));
        }
        let record = RemoteRecord {
          remote_id: "r1".into(),
          scope: "zone".into(),
          canonical: spec.canonical(),
          marker: Some(owner.marker()),
        };
        dns.0 = Some(record.clone());
        Ok(record)
      })
    }

    fn delete<'a>(
      &'a self,
      _: &'a str,
      _: &'a str,
      _: Option<&'a Owner>,
    ) -> BoxFut<'a, ()> {
      unreachable!("切换单条同类型记录不需要删除")
    }
  }

  #[tokio::test]
  async fn manual_switch_pins_until_primary_and_dns_failure_keeps_state()
   {
    let _writers = WRITERS.lock().await;
    *DNS.lock().unwrap() = (None, false);
    let state = crate::rules::tests::test_state();
    let host = "manual.example.test";
    let mut world = World::default();
    for (name, server, ip) in [
      ("main", "s1", "203.0.113.1"),
      ("backup", "s2", "203.0.113.2"),
    ] {
      world.servers.insert(
        server.into(),
        crate::world::ServerRow {
          settings: serde_json::from_value(
            serde_json::json!({"public_ip":ip}),
          )
          .unwrap(),
          version: 1,
        },
      );
      world.gateways.insert(name.into(), crate::world::GatewayRow {
        spec: serde_json::from_value(serde_json::json!({"kind":"caddy","server":server,"tls":"off"})).unwrap(),
        version: 1,
      });
    }
    world.routes.insert(host.into(), crate::world::RouteRow {
      spec: serde_json::from_value(serde_json::json!({
        "hostname":host, "gateway":"main", "backup_gateway":"backup", "upstream":"127.0.0.1:8080", "failover_minutes":2
      })).unwrap(),
      id: "rt_manual".into(), version: 1,
    });
    let writes = world.writes_from(&World::default());
    state.db.call(move |c| {
      for write in writes {
        db::apply_write(c, &write)?;
      }
      c.execute("INSERT INTO accounts VALUES ('fixture','fixture-failover','','[\"example.test\"]','[]',0)", []).map_err(db::sql_err)?;
      Ok(())
    }).await.unwrap();

    let auth = crate::security_receipt::tests::auth(false);
    let switch = |target| {
      manual(
        &state,
        host,
        RouteFailoverRequest {
          target,
          force: true,
          verify_before_dns: true,
          reason: None,
        },
        &auth,
      )
    };
    let backup = switch(FailoverTarget::Backup).await.unwrap();
    assert!(backup.on_backup && backup.run_id.is_some());
    assert_eq!(backup.pinned, Some(FailoverPinTarget::Backup));
    assert_eq!(
      DNS.lock().unwrap().0.as_ref().unwrap().canonical["content"],
      "203.0.113.2"
    );
    assert!(
      switch(FailoverTarget::Backup)
        .await
        .unwrap()
        .run_id
        .is_none()
    );
    state.hub.mock_agent("s1", false, |op| Ok(match op {
      AgentOp::ProjectStatus { .. } => serde_json::json!([{
        "project":"wharf-gw-main","containers":[{"name":"main-1","service":"caddy","state":"running"}]
      }]),
      AgentOp::Probe { .. } => serde_json::json!([true]),
      _ => panic!("收到意外请求"),
    }));
    for _ in 0..10 {
      round(&state).await.unwrap();
    }
    assert!(active(host));

    DNS.lock().unwrap().1 = true;
    assert_eq!(
      switch(FailoverTarget::Primary).await.unwrap_err().code,
      ErrorCode::Provider
    );
    assert!(active(host));
    assert_eq!(pinned(host), Some(FailoverPinTarget::Backup));
    let mut scoped = crate::security_receipt::tests::auth(false);
    scoped.services = Some(BTreeSet::from(["other".into()]));
    let unauthorized = manual_api(
      State(state.clone()),
      scoped,
      Extension(crate::audit::AuditSlot::default()),
      Path(host.into()),
      Json(RouteFailoverRequest {
        target: FailoverTarget::Primary,
        force: true,
        verify_before_dns: true,
        reason: None,
      }),
    )
    .await;
    assert!(
      matches!(unauthorized, Err(crate::api::AppError(e)) if e.code == ErrorCode::Forbidden)
    );
    DNS.lock().unwrap().1 = false;
    let unlocked = switch(FailoverTarget::Auto).await.unwrap();
    assert!(
      unlocked.on_backup
        && unlocked.pinned.is_none()
        && unlocked.run_id.is_none()
    );
    assert!(
      switch(FailoverTarget::Backup)
        .await
        .unwrap()
        .run_id
        .is_none()
    );
    let primary = switch(FailoverTarget::Primary).await.unwrap();
    assert!(!primary.on_backup && primary.pinned.is_none());
    assert_eq!(
      DNS.lock().unwrap().0.as_ref().unwrap().canonical["content"],
      "203.0.113.1"
    );

    world.routes.get_mut(host).unwrap().spec.backup_gateway = None;
    assert_eq!(
      status(&world, host).unwrap_err().code,
      ErrorCode::InvalidInput
    );
  }

  #[tokio::test]
  async fn backup_gateway_reload_is_deduplicated_without_stop_start()
  {
    let state = crate::rules::tests::test_state();
    let (send, mut recv) = tokio::sync::mpsc::unbounded_channel();
    state.hub.mock_agent("s2", false, move |op| {
      assert!(matches!(op, AgentOp::GatewayReload { project } if project == "wharf-gw-reload-test"));
      send.send(()).unwrap();
      Ok(serde_json::Value::Null)
    });
    let mut w = World::default();
    w.gateways.insert(
      "reload-test".into(),
      crate::world::GatewayRow {
        spec: serde_json::from_str(
          r#"{"kind":"caddy","server":"s2"}"#,
        )
        .unwrap(),
        version: 1,
      },
    );
    schedule_caddy_reload(&state, &w, "reload-test".into(), 0);
    schedule_caddy_reload(&state, &w, "reload-test".into(), 0);
    tokio::time::timeout(Duration::from_secs(1), recv.recv())
      .await
      .unwrap()
      .unwrap();
    assert!(recv.try_recv().is_err());
  }

  #[test]
  fn incomplete_round_keeps_streak_and_external_dns_clears_failover()
  {
    let host = "external.example.net";
    let mut world = World::default();
    for (name, server) in [("edge", "s1"), ("backup", "s2")] {
      world.gateways.insert(
        name.into(),
        crate::world::GatewayRow {
          spec: serde_json::from_value(
            serde_json::json!({"kind":"caddy","server":server}),
          )
          .unwrap(),
          version: 1,
        },
      );
    }
    world.routes.insert(host.into(), crate::world::RouteRow {
      spec: serde_json::from_value(serde_json::json!({
        "hostname": host, "gateway":"edge", "backup_gateway":"backup", "upstream":"127.0.0.1:8080"
      })).unwrap(),
      id: "rt_fixture".into(),
      version: 1,
    });
    let mut memory = Memory::default();
    for _ in 0..SWITCH_MINUTES {
      assert!(!observe(&mut memory, &world, BTreeMap::new(), |_| {
        false
      }));
    }
    assert!(memory.active.is_empty() && memory.pending.is_empty());
    for round in 0..SWITCH_MINUTES {
      if round != 0 {
        assert!(!observe(
          &mut memory,
          &world,
          BTreeMap::new(),
          |_| true
        ));
        assert_eq!(memory.streak.get(host), Some(&round));
      }
      let health = FailoverHealthSnapshot {
        backup: Some(wharf_api_types::view::FailoverEntryHealth {
          ok: true,
          stage: "http".into(),
          detail: "HTTP 200".into(),
          status: Some(200),
        }),
        ..Default::default()
      };
      observe(
        &mut memory,
        &world,
        BTreeMap::from([(host.into(), health)]),
        |_| true,
      );
    }
    assert!(
      memory.active.contains(host)
        && memory.pending.contains_key(host)
    );
    assert!(observe(&mut memory, &world, BTreeMap::new(), |_| false));
    assert!(memory.active.is_empty() && memory.pending.is_empty());
  }

  #[test]
  fn reachability_requires_a_healthy_target_and_consecutive_rounds() {
    let mut streak = 0;
    for _ in 0..2 {
      assert!(!decide_failover(
        false,
        (false, false),
        false,
        &mut streak,
        2
      ));
      assert!(!decide_failover(
        false,
        (false, true),
        true,
        &mut streak,
        2
      ));
    }
    assert_eq!(streak, 0);
    assert!(!decide_failover(
      false,
      (false, true),
      false,
      &mut streak,
      2
    ));
    assert!(decide_failover(
      false,
      (false, true),
      false,
      &mut streak,
      2
    ));
    for _ in 0..10 {
      assert!(decide_failover(
        true,
        (true, true),
        true,
        &mut streak,
        2
      ));
    }
    assert_eq!(streak, 0);
    assert!(decide_failover(
      true,
      (true, false),
      false,
      &mut streak,
      2
    ));
    assert!(!decide_failover(
      true,
      (true, false),
      false,
      &mut streak,
      2
    ));
  }

  #[tokio::test]
  async fn foreign_running_container_does_not_keep_stopped_service_eligible()
   {
    let state = crate::rules::tests::test_state();
    state
      .hub
      .mock_agent("s1", false, |_| panic!("已停机服务不应探测"));
    let mut snap = snapshot::Snapshot::default();
    snap
      .world
      .apply_changes(&[serde_json::from_value(serde_json::json!({
        "op": "upsert_service", "name": "app",
        "spec": {"server": "s1", "source": {"image": "fixture:1"}}
      }))
      .unwrap()])
      .unwrap();
    let route = serde_json::from_value(serde_json::json!({
      "hostname": "a.example.test", "service": "app"
    }))
    .unwrap();
    let project = serde_json::from_value(serde_json::json!({
      "project": "app", "containers": [
        {"name":"app-1","service":"app","state":"exited"},
        {"name":"other-1","service":"app","state":"running","foreign":true}
      ]
    })).unwrap();
    let live = BTreeMap::from([(
      "s1".into(),
      Ok(BTreeMap::from([("app".into(), project)])),
    )]);
    let (_, health) = assess_route(
      &state,
      &snap,
      &snap.net(&snap.world),
      &live,
      ("a.example.test", &route, "gw1", "gw2"),
      true,
      &CancellationToken::new(),
    )
    .await;
    assert!(health.service_stopped);
    assert!(health.primary.is_none() && health.backup.is_none());
  }

  #[test]
  fn automatic_dns_ttl_uses_maximum_reload_delay() {
    assert_eq!(caddy_reload_delay(1), 120);
    assert_eq!(caddy_reload_delay(60), 65);
  }

  #[tokio::test]
  async fn removing_backup_persists_active_cleanup_and_retry() {
    let _writers = WRITERS.lock().await;
    let state = crate::rules::tests::test_state();
    let host = "removed-backup.example.test";
    let mut memory = Memory {
      active: BTreeSet::from([
        host.into(),
        "deleted.example.test".into(),
      ]),
      ..Memory::default()
    };
    let mut world = World::default();
    world.gateways.insert(
      "edge".into(),
      crate::world::GatewayRow {
        spec: serde_json::from_str(
          r#"{"kind":"caddy","server":"s1"}"#,
        )
        .unwrap(),
        version: 1,
      },
    );
    world.routes.insert(host.into(), crate::world::RouteRow {
      spec: serde_json::from_str(r#"{"hostname":"removed-backup.example.test","gateway":"edge","upstream":"127.0.0.1:8080"}"#).unwrap(),
      id: "rt_fixture".into(), version: 1,
    });
    assert!(observe(&mut memory, &world, BTreeMap::new(), |_| true));
    persist(&state, &memory).await.unwrap();
    state
      .db
      .call(move |c| {
        assert!(load_active_from_conn(c)?.is_empty());
        let pending: BTreeMap<String, Pending> =
          serde_json::from_str(&db::setting(c, PENDING)?.unwrap())
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[host].target_backup);
        Ok(())
      })
      .await
      .unwrap();
  }
}
