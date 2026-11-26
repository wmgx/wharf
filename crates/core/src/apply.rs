//! 执行计划。
//!
//! 语义（教训：Komodo 的执行接口返回"进行中"的 Update，容易被当成结果）：
//! - `POST /api/apply` 先在一个事务里检查版本、写入配置，然后立刻返回 `run_id`；
//! - 现实层的步骤在后台按顺序执行，`GET /api/runs/{id}` 查看进度和结果；
//! - 某一步失败就停止，后面的步骤标为 skipped。配置已经写入，
//!   再 `wharf plan` 可以看到剩下的差异；
//! - 每一步都有超时，可以随时 `wharf run cancel`。

use std::{
  collections::{BTreeSet, HashMap},
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use tokio::sync::OwnedMutexGuard;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, GatewayApply, ProjectUp, ProjectUpResult, Retire,
    Retired, TRIAL_PROJECT_PREFIX,
  },
  plan::{
    ApplyRequest, ApplyResponse, Layer, Plan, PlanStatus, Run,
    RunStatus, RunStep, StepStatus,
  },
  spec::{GatewayKind, ServiceSpec, Source},
  view::{LastOp, OpStatus, Perm},
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

/// agent 那边 stop/start 本身限时 180 秒，这里多留一些。
const STOP_START_TIMEOUT: Duration = Duration::from_secs(200);
const SERVICE_UP_TIMEOUT: Duration = Duration::from_secs(70 * 60);
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const SHORT_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// 每个步骤最多保留的日志行数。
const MAX_LOG_LINES: usize = 400;

mod gateway;
#[path = "apply/run_scope.rs"]
mod run_scope;

use run_scope::{StoredRun, persist};
pub use run_scope::{
  list_runs, load_plan_for, load_run, load_run_for,
};

struct ActiveRun {
  scope_services: Option<Vec<String>>,
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

  /// 正在执行的那个：报"已有执行"时说清楚是谁、在做哪一步。
  pub fn busy_error(&self) -> ApiError {
    let active = lock(&self.active);
    let Some((id, a)) = active.iter().next() else {
      return ApiError::new(
        ErrorCode::Busy,
        "已有一个执行在进行，马上结束",
      )
      .with_hint("几秒后再试");
    };
    let run = lock(&a.run);
    let doing = run
      .steps
      .iter()
      .find(|s| s.status == StepStatus::Running)
      .or_else(|| run.steps.first())
      .map(|s| s.title.clone())
      .unwrap_or_default();
    let done = run
      .steps
      .iter()
      .filter(|s| {
        s.status != StepStatus::Running
          && s.status != StepStatus::Pending
      })
      .count();
    let secs = (chrono::Utc::now() - run.started_at).num_seconds();
    ApiError::new(
      ErrorCode::Busy,
      format!(
        "{id} 正在执行（{done}/{} 步，已 {secs} 秒）：{doing}",
        run.steps.len()
      ),
    )
    .with_hint("等它结束，或者取消它")
    .suggest(format!("wharf run cancel {id}"))
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
  state.db.call(|c| db::interrupt_service_ops(c)).await?;
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
    let mut stored: StoredRun =
      serde_json::from_str(&body).map_err(json_err)?;
    let run = &mut stored.run;
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
    persist(state, &stored.run, stored.scope_services.as_deref())
      .await?;
    tracing::warn!("执行记录 {id} 因控制面重启而中断");
  }
  Ok(())
}

#[derive(serde::Deserialize)]
struct StoredPlanBody {
  #[serde(flatten)]
  plan: Plan,
  // 旧计划没有引用清单，沿用生成时取所有账号的指纹。
  #[serde(default)]
  account_refs: Option<BTreeSet<String>>,
  #[serde(default)]
  route_effects: crate::token_scope::RouteEffects,
  #[serde(default)]
  host_requirements: Option<Vec<crate::host_access::HostRequirement>>,
}

struct StoredPlan {
  body: StoredPlanBody,
  steps: Vec<StepPlan>,
  writes: Vec<Write>,
}

pub async fn load_plan(
  state: &AppState,
  id: &str,
) -> Result<Plan, ApiError> {
  Ok(stored_plan(state, id).await?.body.plan)
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
  let mut body: StoredPlanBody =
    serde_json::from_str(&body).map_err(json_err)?;
  if status == "applied" {
    body.plan.status = PlanStatus::Applied;
  }
  Ok(StoredPlan {
    body,
    steps: serde_json::from_str(&steps).map_err(json_err)?,
    writes: serde_json::from_str(&writes).map_err(json_err)?,
  })
}

mod confirm;

pub async fn start(
  state: Arc<AppState>,
  req: ApplyRequest,
  perms: &std::collections::BTreeSet<Perm>,
  caller: Option<(&crate::auth::Auth, String)>,
) -> Result<ApplyResponse, ApiError> {
  let auth = caller.as_ref().map(|(auth, _)| *auth);
  let guard = state
    .apply_lock
    .clone()
    .try_lock_owned()
    .map_err(|_| state.runs.busy_error())?;
  let stored = stored_plan(&state, &req.plan_id).await?;
  let plan = &stored.body.plan;
  if let Some(auth) = auth {
    crate::token_scope::require_plan(
      auth,
      plan,
      &stored.body.route_effects,
    )?;
  }
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
  let human = auth.is_some_and(|auth| auth.human);
  let requirements = stored.body.host_requirements.as_deref();
  if requirements.is_none()
    || !human
      && (requirements.is_some_and(|reqs| !reqs.is_empty())
        || !plan.needs_host.is_empty()
        || plan.items.iter().any(|item| {
          item.needs_host() || item.address.starts_with("server/")
        }))
  {
    let snap = if requirements.is_some() {
      snapshot::load(&state.db).await?
    } else {
      snapshot::Snapshot::default()
    };
    let core_server =
      requirements.and_then(|_| crate::join::core_server_of(&snap));
    crate::host_access::require_plan_host(
      plan,
      &stored.steps,
      requirements,
      perms,
      human,
      &snap.world,
      core_server.as_deref(),
    )?;
  }
  if !perms.contains(&Perm::Admin)
    && plan.items.iter().any(|item| {
      if item.layer != Layer::Config
        || !item.address.starts_with("route/")
      {
        return false;
      }
      let before = item.before.as_ref().and_then(|v| v.get("sso"));
      let after = item.after.as_ref().and_then(|v| v.get("sso"));
      before != after
        && [before, after].into_iter().flatten().any(|s| {
          s.pointer("/login/script").is_some_and(|v| !v.is_null())
        })
    })
  {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "配置脚本代登录需要 admin 权限",
    ));
  }
  require_login_account(plan, perms.contains(&Perm::Admin))?;
  crate::caddy_validate::require_route_caddy(
    plan,
    perms.contains(&Perm::Admin),
  )?;
  confirm::require(
    &plan.plan_id,
    &plan.needs_confirm,
    &req.confirm,
    perms.contains(&Perm::Confirm),
  )?;

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
    let inputs = plan.inputs.clone();
    let account_refs = stored.body.account_refs;
    let replan_inputs = replan.clone();
    let writes = stored.writes.clone();
    let policy_plan = plan.clone();
    let admin = perms.contains(&Perm::Admin);
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
      .call_credentials(move |c, key| {
        let tx = c.transaction().map_err(sql_err)?;
        if let Some(i) = inputs
          && i != db::inputs(&tx, key, account_refs.as_ref())?
        {
          return Err(
            ApiError::new(
              ErrorCode::PlanStale,
              "plan 之后机器之间的连通性、密钥或机器地址变了，直连还是走隧道、渲染出的配置可能和计划不一样",
            )
            .suggest(replan_inputs),
          );
        }
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
        apply_writes(&tx, &policy_plan, &writes, admin)?;
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

  let actor =
    caller.map(crate::security_receipt::Actor::from_request);
  if run.status == RunStatus::Running {
    let first_pending = run.steps.len() - stored.steps.len();
    let cancel = CancellationToken::new();
    let shared = Arc::new(Mutex::new(run));
    lock(&state.runs.active).insert(
      run_id.clone(),
      ActiveRun {
        scope_services: None,
        run: shared.clone(),
        cancel: cancel.clone(),
      },
    );
    tokio::spawn(execute(
      state.clone(),
      shared,
      stored.steps,
      first_pending,
      actor.clone(),
      cancel,
      guard,
    ));
  }
  if !stored.writes.is_empty() {
    crate::security_receipt::committed_config(
      &state,
      actor.as_ref(),
      &plan.items,
    )
    .await;
  }
  for write in &stored.writes {
    if let db::Write::Delete { kind, name } = write
      && kind == crate::world::KIND_SERVICE
    {
      crate::rules::on_service_deleted(&state, name).await;
    }
  }
  crate::service_monitor::sync_watches(&state, None).await;
  Ok(ApplyResponse { run_id })
}

fn enables_login_account(plan: &Plan) -> bool {
  let enabled = |v: Option<&serde_json::Value>| {
    v.and_then(|v| v.pointer("/sso/login/use_account"))
      .and_then(serde_json::Value::as_bool)
      == Some(true)
  };
  plan.items.iter().any(|item| {
    item.layer == Layer::Config
      && item.address.starts_with("route/")
      && !enabled(item.before.as_ref())
      && enabled(item.after.as_ref())
  })
}

pub(crate) fn require_login_account(
  plan: &Plan,
  admin: bool,
) -> Result<(), ApiError> {
  if !admin && enables_login_account(plan) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "开启代登录使用应用账号需要 admin 权限",
    ));
  }
  Ok(())
}

fn apply_writes(
  tx: &rusqlite::Transaction<'_>,
  plan: &Plan,
  writes: &[crate::db::Write],
  admin: bool,
) -> Result<(), ApiError> {
  let current =
    crate::world::World::from_rows(db::all_resources(tx)?)?;
  crate::secret_policy::require_apply(plan, &current, admin)?;
  for write in writes {
    db::apply_write(tx, write)?;
  }
  let desired =
    crate::world::World::from_rows(db::all_resources(tx)?)?;
  desired.validate()?;
  crate::secret_policy::validate_accounts(
    &desired,
    &crate::app_accounts::account_links(tx)?,
  )
}

/// 不来自计划的执行（备份、恢复）：同样占用 apply 锁、有执行记录、可以取消。
pub async fn start_task(
  state: Arc<AppState>,
  title: String,
  step: Step,
) -> Result<ApplyResponse, ApiError> {
  let guard = state
    .apply_lock
    .clone()
    .try_lock_owned()
    .map_err(|_| state.runs.busy_error())?;
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
  let scope_services = Some(run_scope::step_services(&step));
  let body = run_scope::encode(&run, scope_services.as_deref())?;
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
      scope_services,
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
    None,
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
  actor: Option<crate::security_receipt::Actor>,
  cancel: CancellationToken,
  _guard: OwnedMutexGuard<()>,
) {
  let run_id = lock(&run).run_id.clone();
  let mut failed = false;
  let scope_services = lock(&state.runs.active)
    .get(&run_id)
    .and_then(|a| a.scope_services.clone());
  let scope_services = scope_services.as_deref();
  // 部署过服务就重新查一次版本，免得页面还按旧镜像提示升级。
  let mut deployed = false;
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
    let _ = persist(&state, &snapshot_run, scope_services).await;
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
    let started = std::time::Instant::now();
    let op = service_op(&step.step);
    if let Some((service, action)) = op {
      record_op(
        &state,
        service,
        action,
        &run_id,
        OpStatus::Running,
        None,
      )
      .await;
    }
    let result =
      run_step(&state, &run_id, &step.step, progress, &cancel).await;
    crate::security_receipt::completed_step(
      &state,
      actor.as_ref(),
      &step.step,
      &result,
    )
    .await;
    if let Some((service, action)) = op {
      let (status, error) = match &result {
        Ok(()) => (OpStatus::Succeeded, None),
        Err(e) => (OpStatus::Failed, Some(e.message.clone())),
      };
      deployed |= result.is_ok()
        && matches!(
          step.step,
          Step::ServiceUp { .. } | Step::Rebuild { .. }
        );
      record_op(&state, service, action, &run_id, status, error)
        .await;
    }
    crate::metrics::step_done(
      &state,
      &step.step,
      started.elapsed(),
      result.is_ok(),
    )
    .await;
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
    let _ = persist(&state, &snapshot_run, scope_services).await;
    crate::views::refresh_live_soon(state.clone());
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
  if let Err(e) = persist(&state, &final_run, scope_services).await {
    tracing::error!("保存执行记录 {run_id} 失败：{e}");
  }
  lock(&state.runs.active).remove(&run_id);
  tracing::info!("[{run_id}] 结束：{:?}", final_run.status);
  crate::dns_check::after_apply(
    state.clone(),
    &steps,
    &final_run.steps[offset..],
  );
  if deployed {
    tokio::spawn(
      async move { crate::updates::versions(&state).await },
    );
  }
}

/// 会改变服务现状的步骤，记进服务状态的"执行"一层。
fn service_op(step: &Step) -> Option<(&str, &'static str)> {
  match step {
    Step::ServiceUp { service, .. } => Some((service, "部署")),
    Step::Rebuild { service, .. } => Some((service, "重新构建")),
    Step::ServiceStop { service, .. } => Some((service, "停止")),
    Step::ServiceRestart { service, .. } => Some((service, "重启")),
    Step::VolumeSync { service, .. } => Some((service, "迁移数据")),
    Step::Restore { service, .. } => Some((service, "恢复")),
    Step::ServiceDown { service, .. } => Some((service, "删除")),
    _ => None,
  }
}

include!("apply/steps.rs");
include!("apply/service.rs");
