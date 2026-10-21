//! 执行计划。
//!
//! 语义（教训：Komodo 的执行接口返回"进行中"的 Update，容易被当成结果）：
//! - `POST /api/apply` 先在一个事务里检查版本、写入配置，然后立刻返回 `run_id`；
//! - 现实层的步骤在后台按顺序执行，`GET /api/runs/{id}` 查看进度和结果；
//! - 某一步失败就停止，后面的步骤标为 skipped。配置已经写入，
//!   再 `wharf plan` 可以看到剩下的差异；
//! - 每一步都有超时，可以随时 `wharf run cancel`。

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use tokio::sync::OwnedMutexGuard;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, GatewayApply, ProjectUp, ProjectUpResult},
  plan::{
    ApplyRequest, ApplyResponse, Plan, PlanStatus, Run, RunStatus,
    RunStep, StepStatus,
  },
  spec::{GatewayKind, ServiceSpec},
  view::TokenScope,
};
use wharf_providers::{Owner, RemoteRecord};

use crate::{
  db::{self, OwnedRecord, Write, json_err, now_ms, sql_err},
  hub::ProgressFn,
  planner::{RemoteRef, Step, StepPlan},
  render, snapshot,
  state::AppState,
  world::gateway_project,
};

const SERVICE_UP_TIMEOUT: Duration = Duration::from_secs(45 * 60);
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const SHORT_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// 每个步骤最多保留的日志行数。
const MAX_LOG_LINES: usize = 400;

struct ActiveRun {
  run: Arc<Mutex<Run>>,
  cancel: CancellationToken,
}

/// 进行中的执行记录。结束后只在数据库里。
#[derive(Default)]
pub struct Runs {
  active: Mutex<HashMap<String, ActiveRun>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
  m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Runs {
  pub fn get(&self, id: &str) -> Option<Run> {
    lock(&self.active).get(id).map(|a| lock(&a.run).clone())
  }

  pub fn cancel(&self, id: &str) -> bool {
    match lock(&self.active).get(id) {
      Some(a) => {
        a.cancel.cancel();
        true
      }
      None => false,
    }
  }
}

/// 控制面重启时，把上次没执行完的记录标为失败，不留下"一直在执行"。
pub async fn recover(state: &AppState) -> Result<(), ApiError> {
  let rows: Vec<(String, String)> = state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare("SELECT id, body FROM runs WHERE status = 'running'")
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  for (id, body) in rows {
    let mut run: Run =
      serde_json::from_str(&body).map_err(json_err)?;
    for step in &mut run.steps {
      if matches!(
        step.status,
        StepStatus::Running | StepStatus::Pending
      ) {
        step.status = StepStatus::Skipped;
        step.error = Some(ApiError::new(
          ErrorCode::Cancelled,
          "控制面重启，执行中断",
        ));
      }
    }
    run.status = RunStatus::Failed;
    run.finished_at = Some(Utc::now());
    persist(state, &run).await?;
    tracing::warn!("执行记录 {id} 因控制面重启而中断");
  }
  Ok(())
}

async fn persist(
  state: &AppState,
  run: &Run,
) -> Result<(), ApiError> {
  let id = run.run_id.clone();
  let status = serde_json::to_value(run.status)
    .ok()
    .and_then(|v| v.as_str().map(str::to_string))
    .unwrap_or_default();
  let body = serde_json::to_string(run).map_err(json_err)?;
  state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE runs SET status = ?1, body = ?2 WHERE id = ?3",
        params![status, body, id],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

pub async fn load_run(
  state: &AppState,
  id: &str,
) -> Result<Run, ApiError> {
  if let Some(run) = state.runs.get(id) {
    return Ok(run);
  }
  let id = id.to_string();
  let body: Option<String> = state
    .db
    .call({
      let id = id.clone();
      move |c| {
        c.query_row(
          "SELECT body FROM runs WHERE id = ?1",
          params![id],
          |r| r.get(0),
        )
        .optional()
        .map_err(sql_err)
      }
    })
    .await?;
  let body = body.ok_or_else(|| {
    ApiError::not_found(format!("执行记录 {id} 不存在"))
      .suggest("wharf run list")
  })?;
  serde_json::from_str(&body).map_err(json_err)
}

struct StoredPlan {
  plan: Plan,
  steps: Vec<StepPlan>,
  writes: Vec<Write>,
}

pub async fn load_plan(
  state: &AppState,
  id: &str,
) -> Result<Plan, ApiError> {
  Ok(stored_plan(state, id).await?.plan)
}

async fn stored_plan(
  state: &AppState,
  id: &str,
) -> Result<StoredPlan, ApiError> {
  let id = id.to_string();
  let row: Option<(String, String, String, String)> = state
    .db
    .call({
      let id = id.clone();
      move |c| {
        c.query_row(
          "SELECT status, body, steps, writes FROM plans WHERE id = ?1",
          params![id],
          |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(sql_err)
      }
    })
    .await?;
  let (status, body, steps, writes) = row.ok_or_else(|| {
    ApiError::not_found(format!("计划 {id} 不存在"))
      .with_hint("计划保留 7 天，过期后需要重新 plan")
      .suggest("wharf plan")
  })?;
  let mut plan: Plan =
    serde_json::from_str(&body).map_err(json_err)?;
  if status == "applied" {
    plan.status = PlanStatus::Applied;
  }
  Ok(StoredPlan {
    plan,
    steps: serde_json::from_str(&steps).map_err(json_err)?,
    writes: serde_json::from_str(&writes).map_err(json_err)?,
  })
}

pub async fn start(
  state: Arc<AppState>,
  req: ApplyRequest,
  scope: TokenScope,
) -> Result<ApplyResponse, ApiError> {
  let guard =
    state.apply_lock.clone().try_lock_owned().map_err(|_| {
      ApiError::new(ErrorCode::Busy, "已有一个 apply 在执行")
        .with_hint("等它结束，或者取消它")
        .suggest("wharf run list")
    })?;
  let stored = stored_plan(&state, &req.plan_id).await?;
  let plan = &stored.plan;
  let replan = "wharf plan".to_string();
  if plan.status == PlanStatus::Applied {
    return Err(
      ApiError::new(ErrorCode::PlanStale, "这个计划已经执行过了")
        .suggest(replan),
    );
  }
  if plan.expires_at < Utc::now() {
    return Err(
      ApiError::new(
        ErrorCode::PlanStale,
        "计划已过期，需要重新 plan",
      )
      .suggest(replan),
    );
  }
  let missing: Vec<&String> = plan
    .needs_confirm
    .iter()
    .filter(|a| !req.confirm.contains(a))
    .collect();
  if !missing.is_empty() {
    let flags: String =
      missing.iter().map(|a| format!(" --confirm {a}")).collect();
    let addresses: Vec<&str> =
      missing.iter().map(|s| s.as_str()).collect();
    return Err(
      ApiError::new(
        ErrorCode::ConfirmRequired,
        format!(
          "计划里有高风险项，需要确认：{}",
          addresses.join("、")
        ),
      )
      .with_hint("先看清楚 plan 里这些项的 reason，再确认")
      .suggest(format!("wharf apply {}{flags}", plan.plan_id)),
    );
  }
  if !plan.needs_confirm.is_empty() && scope < TokenScope::ApplyAll {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "计划里有高风险项，当前 token 只能执行安全的计划",
      )
      .with_hint(
        "请用户用 apply_all 权限的 token 执行，或者去掉高风险的修改",
      ),
    );
  }

  // 检查版本并写入配置，在一个事务里完成。
  let run_id = crate::world::new_id("r");
  let mut steps = Vec::new();
  let config_items: Vec<u32> = plan
    .items
    .iter()
    .filter(|i| i.layer == wharf_api_types::plan::Layer::Config)
    .map(|i| i.id)
    .collect();
  if !stored.writes.is_empty() {
    let now = Utc::now();
    steps.push(RunStep {
      items: config_items,
      title: "写入配置".into(),
      status: StepStatus::Done,
      log: vec![],
      error: None,
      started_at: Some(now),
      finished_at: Some(now),
    });
  }
  for s in &stored.steps {
    steps.push(RunStep {
      items: s.items.clone(),
      title: s.title.clone(),
      status: StepStatus::Pending,
      log: vec![],
      error: None,
      started_at: None,
      finished_at: None,
    });
  }
  let run = Run {
    run_id: run_id.clone(),
    plan_id: plan.plan_id.clone(),
    status: if stored.steps.is_empty() {
      RunStatus::Succeeded
    } else {
      RunStatus::Running
    },
    started_at: Utc::now(),
    finished_at: stored.steps.is_empty().then(Utc::now),
    steps,
  };
  {
    let base = plan.base_versions.clone();
    let writes = stored.writes.clone();
    let plan_id = plan.plan_id.clone();
    let run_body = serde_json::to_string(&run).map_err(json_err)?;
    let run_status = if run.status == RunStatus::Running {
      "running"
    } else {
      "succeeded"
    };
    let run_id = run_id.clone();
    state
      .db
      .call(move |c| {
        let tx = c.transaction().map_err(sql_err)?;
        let now_versions = db::versions(&tx)?;
        let stale: Vec<String> = base
          .keys()
          .chain(now_versions.keys())
          .filter(|k| base.get(*k) != now_versions.get(*k))
          .cloned()
          .collect::<std::collections::BTreeSet<_>>()
          .into_iter()
          .collect();
        if !stale.is_empty() {
          return Err(
            ApiError::new(
              ErrorCode::PlanStale,
              format!("plan 之后这些资源被修改过：{}", stale.join("、")),
            )
            .with_hint("重新 plan，确认新的差异后再 apply")
            .suggest("wharf plan"),
          );
        }
        for write in &writes {
          db::apply_write(&tx, write)?;
        }
        tx.execute(
          "UPDATE plans SET status = 'applied' WHERE id = ?1",
          params![plan_id],
        )
        .map_err(sql_err)?;
        tx.execute(
          "INSERT INTO runs (id, plan_id, status, body, started_at) VALUES (?1, ?2, ?3, ?4, ?5)",
          params![run_id, plan_id, run_status, run_body, now_ms()],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)
      })
      .await?;
  }

  if run.status == RunStatus::Running {
    let first_pending = run.steps.len() - stored.steps.len();
    let cancel = CancellationToken::new();
    let shared = Arc::new(Mutex::new(run));
    lock(&state.runs.active).insert(
      run_id.clone(),
      ActiveRun {
        run: shared.clone(),
        cancel: cancel.clone(),
      },
    );
    tokio::spawn(execute(
      state.clone(),
      shared,
      stored.steps,
      first_pending,
      cancel,
      guard,
    ));
  }
  Ok(ApplyResponse { run_id })
}

/// 不来自计划的执行（备份、恢复）：同样占用 apply 锁、有执行记录、可以取消。
pub async fn start_task(
  state: Arc<AppState>,
  title: String,
  step: Step,
) -> Result<ApplyResponse, ApiError> {
  let guard =
    state.apply_lock.clone().try_lock_owned().map_err(|_| {
      ApiError::new(ErrorCode::Busy, "已有一个 apply 在执行")
        .with_hint("等它结束再试")
        .suggest("wharf run list")
    })?;
  let run_id = crate::world::new_id("r");
  let run = Run {
    run_id: run_id.clone(),
    plan_id: String::new(),
    status: RunStatus::Running,
    started_at: Utc::now(),
    finished_at: None,
    steps: vec![RunStep {
      items: vec![],
      title: title.clone(),
      status: StepStatus::Pending,
      log: vec![],
      error: None,
      started_at: None,
      finished_at: None,
    }],
  };
  let body = serde_json::to_string(&run).map_err(json_err)?;
  {
    let run_id = run_id.clone();
    state
      .db
      .call(move |c| {
        c.execute(
          "INSERT INTO runs (id, plan_id, status, body, started_at) VALUES (?1, '', 'running', ?2, ?3)",
          params![run_id, body, now_ms()],
        )
        .map_err(sql_err)?;
        Ok(())
      })
      .await?;
  }
  let cancel = CancellationToken::new();
  let shared = Arc::new(Mutex::new(run));
  lock(&state.runs.active).insert(
    run_id.clone(),
    ActiveRun {
      run: shared.clone(),
      cancel: cancel.clone(),
    },
  );
  let steps = vec![StepPlan {
    items: vec![],
    title,
    step,
  }];
  tokio::spawn(execute(
    state.clone(),
    shared,
    steps,
    0,
    cancel,
    guard,
  ));
  Ok(ApplyResponse { run_id })
}

async fn execute(
  state: Arc<AppState>,
  run: Arc<Mutex<Run>>,
  steps: Vec<StepPlan>,
  offset: usize,
  cancel: CancellationToken,
  _guard: OwnedMutexGuard<()>,
) {
  let run_id = lock(&run).run_id.clone();
  let mut failed = false;
  for (i, step) in steps.iter().enumerate() {
    let index = offset + i;
    if failed || cancel.is_cancelled() {
      let mut r = lock(&run);
      r.steps[index].status = StepStatus::Skipped;
      continue;
    }
    {
      let mut r = lock(&run);
      r.steps[index].status = StepStatus::Running;
      r.steps[index].started_at = Some(Utc::now());
    }
    let snapshot_run = lock(&run).clone();
    let _ = persist(&state, &snapshot_run).await;
    let progress: ProgressFn = {
      let run = run.clone();
      Arc::new(move |line: String| {
        let mut r = lock(&run);
        let log = &mut r.steps[index].log;
        log.push(line);
        if log.len() > MAX_LOG_LINES {
          let drop = log.len() - MAX_LOG_LINES;
          log.drain(..drop);
        }
      })
    };
    tracing::info!("[{run_id}] {}", step.title);
    let result =
      run_step(&state, &run_id, &step.step, progress, &cancel).await;
    {
      let mut r = lock(&run);
      let s = &mut r.steps[index];
      s.finished_at = Some(Utc::now());
      match result {
        Ok(()) => s.status = StepStatus::Done,
        Err(e) => {
          tracing::warn!("[{run_id}] {} 失败：{e}", step.title);
          s.status = StepStatus::Failed;
          s.error = Some(e);
          failed = true;
        }
      }
    }
    let snapshot_run = lock(&run).clone();
    let _ = persist(&state, &snapshot_run).await;
  }
  let final_run = {
    let mut r = lock(&run);
    r.status = if cancel.is_cancelled() {
      RunStatus::Cancelled
    } else if failed {
      RunStatus::Failed
    } else {
      RunStatus::Succeeded
    };
    r.finished_at = Some(Utc::now());
    r.clone()
  };
  if let Err(e) = persist(&state, &final_run).await {
    tracing::error!("保存执行记录 {run_id} 失败：{e}");
  }
  lock(&state.runs.active).remove(&run_id);
  tracing::info!("[{run_id}] 结束：{:?}", final_run.status);
}

async fn run_step(
  state: &AppState,
  run_id: &str,
  step: &Step,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let world = &snap.world;
  let net = snap.net(world);
  match step {
    Step::EnsureDirs { server, dirs } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::EnsureDirs { dirs: dirs.clone() },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::VolumeSync { service, from, to } => {
      crate::migrate::volume_sync(
        state, &net, service, from, to, progress, cancel,
      )
      .await?;
    }
    Step::Backup { service } => {
      crate::backup::backup(state, run_id, service, progress, cancel)
        .await?;
    }
    Step::Restore { service, snapshot } => {
      crate::backup::restore(
        state, service, snapshot, progress, cancel,
      )
      .await?;
    }
    Step::ServiceUp { service } => {
      service_up(
        state, run_id, &snap, service, false, progress, cancel,
      )
      .await?;
    }
    Step::Rebuild { service } => {
      service_up(
        state, run_id, &snap, service, true, progress, cancel,
      )
      .await?;
    }
    Step::EdgeDeploy { app } => {
      crate::edge::deploy(state, &snap, app, &progress, cancel)
        .await?;
    }
    Step::EdgeAttach {
      hostname,
      app,
      takeover,
    } => {
      crate::edge::attach_domain(
        state, &snap, hostname, app, *takeover,
      )
      .await?;
    }
    Step::EdgeDetach { domain } => {
      crate::edge::detach_domain(state, &snap, domain).await?;
    }
    Step::EdgeRollback { app, version } => {
      crate::edge::rollback(state, &snap, app, version, &progress)
        .await?;
    }
    Step::ServiceDown { server, service } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: service.clone(),
          },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::GatewaySync { gateway } => {
      let gw = world.gateways.get(gateway).ok_or_else(|| {
        ApiError::new(
          ErrorCode::PlanStale,
          format!("网关 {gateway} 已不存在"),
        )
      })?;
      if gw.spec.kind == GatewayKind::CloudflareTunnel {
        return crate::tunnel::sync(
          state, &snap, gateway, progress, cancel,
        )
        .await;
      }
      let server = &gw.spec.server;
      let r = snapshot::gateway_render(world, &net, gateway)?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::GatewayApply(GatewayApply {
            up: ProjectUp {
              project: gateway_project(gateway),
              compose: r.compose,
              hash: r.compose_hash,
              pull: snapshot::pull_policy(&world.servers[server]),
            },
            caddyfile: r.config,
            caddyfile_hash: r.config_hash,
            image: render::gateway_image(&gw.spec),
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        &format!("网关 {gateway}"),
        &format!("wharf gateway logs {gateway}"),
      )?;
    }
    Step::GatewayDown { server, gateway } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: gateway_project(gateway),
          },
          SHORT_TIMEOUT,
          Some(progress.clone()),
          cancel,
        )
        .await?;
      // cloudflare_tunnel 网关：连接器停了之后删除它的隧道。
      crate::tunnel::destroy(
        state, &snap, gateway, &progress, cancel,
      )
      .await?;
    }
    Step::DnsUpsert {
      hostname,
      account,
      spec,
      existing,
      extra,
    } => {
      let route = world.routes.get(hostname).ok_or_else(|| {
        ApiError::new(
          ErrorCode::PlanStale,
          format!("路由 {hostname} 已不存在"),
        )
      })?;
      let account_row = find_account(&snap, account)?;
      let provider = snapshot::dns_provider(account_row)?;
      let owner = Owner {
        id: route.id.clone(),
      };
      let spec = match &spec.tunnel {
        Some(gateway) => {
          let t = snap.tunnels.get(gateway).ok_or_else(|| {
            ApiError::new(
              ErrorCode::PlanStale,
              format!("网关 {gateway} 的隧道还没有创建"),
            )
            .suggest("wharf plan")
          })?;
          crate::planner::DnsSpec {
            content: crate::planner::tunnel_target(&t.tunnel_id),
            ..spec.clone()
          }
        }
        None => spec.clone(),
      };
      let want = spec.to_provider();
      let existing_record = existing.as_ref().map(|r| RemoteRecord {
        remote_id: r.remote_id.clone(),
        scope: r.scope.clone(),
        canonical: serde_json::Value::Null,
        marker: None,
      });
      progress(format!(
        "{hostname} → {} {}",
        spec.record_type, spec.content
      ));
      let record = cancellable(
        cancel,
        snapshot::with_timeout(
          "写入 DNS 记录",
          provider.upsert(
            hostname,
            &want,
            &owner,
            existing_record.as_ref(),
          ),
        ),
      )
      .await?;
      add_owned(
        state,
        &route.id,
        hostname,
        account,
        &record.scope,
        &record.remote_id,
      )
      .await?;
      for r in extra {
        progress(format!("删除多余的记录 {}", r.remote_id));
        cancellable(
          cancel,
          snapshot::with_timeout(
            "删除 DNS 记录",
            provider.delete(&r.scope, &r.remote_id, None),
          ),
        )
        .await?;
        remove_owned(state, account, r).await?;
      }
    }
    Step::DnsDelete {
      hostname,
      account,
      remote,
      owner,
    } => {
      let account_row = find_account(&snap, account)?;
      let provider = snapshot::dns_provider(account_row)?;
      let owner = owner.as_ref().map(|id| Owner { id: id.clone() });
      progress(format!(
        "删除 {hostname} 的记录 {}",
        remote.remote_id
      ));
      cancellable(
        cancel,
        snapshot::with_timeout(
          "删除 DNS 记录",
          provider.delete(
            &remote.scope,
            &remote.remote_id,
            owner.as_ref(),
          ),
        ),
      )
      .await?;
      remove_owned(state, account, remote).await?;
    }
  }
  Ok(())
}

fn ensure_running(
  result: &ProjectUpResult,
  what: &str,
  logs: &str,
) -> Result<(), ApiError> {
  let bad: Vec<String> = result
    .containers
    .iter()
    .filter(|c| c.state != "running")
    .map(|c| format!("{} {}（{}）", c.service, c.state, c.status))
    .collect();
  if result.containers.is_empty() {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{what} 启动后没有容器"),
    ));
  }
  if !bad.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{what} 有容器没在运行：{}", bad.join("，")),
      )
      .suggest(logs),
    );
  }
  Ok(())
}

pub(crate) async fn cancellable<T>(
  cancel: &CancellationToken,
  fut: impl std::future::Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
  tokio::select! {
    r = fut => r,
    _ = cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
  }
}

fn find_account<'a>(
  snap: &'a snapshot::Snapshot,
  name: &str,
) -> Result<&'a db::AccountRow, ApiError> {
  snap
    .accounts
    .iter()
    .find(|a| a.name == name)
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::PlanStale,
        format!("厂商账号 {name} 已不存在"),
      )
    })
}

async fn add_owned(
  state: &AppState,
  route_id: &str,
  hostname: &str,
  account: &str,
  scope: &str,
  remote_id: &str,
) -> Result<(), ApiError> {
  let record = OwnedRecord {
    route_id: route_id.to_string(),
    hostname: hostname.to_string(),
    account: account.to_string(),
    scope: scope.to_string(),
    remote_id: remote_id.to_string(),
  };
  state.db.call(move |c| db::add_owned(c, &record)).await
}

async fn remove_owned(
  state: &AppState,
  account: &str,
  r: &RemoteRef,
) -> Result<(), ApiError> {
  let (account, scope, id) =
    (account.to_string(), r.scope.clone(), r.remote_id.clone());
  state
    .db
    .call(move |c| db::remove_owned(c, &account, &scope, &id))
    .await
}

/// 一次成功部署的内容，写进部署历史。
/// 部署一个服务：构建来源先构建镜像（`force` 时拉最新代码重新构建），再 `up`。
async fn service_up(
  state: &AppState,
  run_id: &str,
  snap: &snapshot::Snapshot,
  service: &str,
  force: bool,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let world = &snap.world;
  let net = snap.net(world);
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::new(
      ErrorCode::PlanStale,
      format!("服务 {service} 已不存在"),
    )
  })?;
  let server = &row.spec.server;
  let commit = crate::build::ensure_image(
    state, snap, service, force, &progress, cancel,
  )
  .await?;
  let (compose, hash) =
    snapshot::service_resolved(world, &net, service, &snap.secrets)?;
  let template = snapshot::service_template(world, &net, service)?;
  let result: ProjectUpResult = state
    .hub
    .call(
      server,
      AgentOp::ProjectUp(ProjectUp {
        project: service.to_string(),
        compose,
        hash: hash.clone(),
        pull: snapshot::pull_policy(&world.servers[server]),
      }),
      SERVICE_UP_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  for warning in &result.warnings {
    progress(format!("提醒：{warning}"));
  }
  record_deployment(
    state,
    Deployed {
      service,
      server,
      run_id,
      hash: &hash,
      template: &template,
      spec: &row.spec,
      commit: commit.as_deref(),
    },
    &result,
  )
  .await?;
  ensure_running(
    &result,
    service,
    &format!("wharf service logs {service}"),
  )
}

struct Deployed<'a> {
  service: &'a str,
  server: &'a str,
  run_id: &'a str,
  hash: &'a str,
  template: &'a str,
  spec: &'a ServiceSpec,
  /// 构建来源：实际构建的 git commit。
  commit: Option<&'a str>,
}

async fn record_deployment(
  state: &AppState,
  d: Deployed<'_>,
  result: &ProjectUpResult,
) -> Result<(), ApiError> {
  let images =
    serde_json::to_string(&result.images).map_err(json_err)?;
  let spec = serde_json::to_string(d.spec).map_err(json_err)?;
  let commit = d.commit.map(str::to_string);
  let values = (
    d.service.to_string(),
    d.server.to_string(),
    d.run_id.to_string(),
    d.hash.to_string(),
    d.template.to_string(),
  );
  state
    .db
    .call(move |c| {
      let (service, server, run_id, hash, compose) = values;
      c.execute(
        "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, spec, commit_sha)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![service, server, run_id, hash, compose, images, now_ms(), spec, commit],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

/// 最近的执行记录（不含日志）。
pub async fn list_runs(
  state: &AppState,
  limit: u32,
) -> Result<Vec<Run>, ApiError> {
  let bodies: Vec<String> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT body FROM runs ORDER BY started_at DESC LIMIT ?1",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![limit], |r| r.get(0))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  let mut runs = Vec::new();
  for body in bodies {
    let mut run: Run =
      serde_json::from_str(&body).map_err(json_err)?;
    if let Some(live) = state.runs.get(&run.run_id) {
      run = live;
    }
    for step in &mut run.steps {
      step.log.clear();
    }
    runs.push(run);
  }
  Ok(runs)
}
