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
    Retired, SettleProbe, TRIAL_PROJECT_PREFIX,
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

/// 停止后最多补一次 docker stop，并复查现场。
const STOP_START_TIMEOUT: Duration = Duration::from_secs(330);
const PROJECT_DOWN_TIMEOUT: Duration = Duration::from_secs(210);
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
  pub fn is_service_busy(&self, service: &str) -> bool {
    lock(&self.active).values().any(|a| {
      a.scope_services
        .as_deref()
        .is_none_or(|names| names.iter().any(|n| n == service))
    })
  }

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
  #[serde(default)]
  base_instances: Option<std::collections::BTreeMap<String, String>>,
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
#[path = "apply/retry.rs"]
mod retry;

pub use retry::retry_run;

pub(crate) fn format_actor(auth: &crate::auth::Auth) -> String {
  if auth.human {
    format!("网页 ({})", auth.name)
  } else {
    format!("令牌 {}", auth.name)
  }
}

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

  if plan.status == PlanStatus::Applied {
    return Err(
      ApiError::new(ErrorCode::PlanStale, "这个计划已经执行过了")
        .suggest("wharf plan"),
    );
  }
  if plan.expires_at < Utc::now() {
    return Err(
      ApiError::new(
        ErrorCode::PlanStale,
        "计划已过期，需要重新 plan",
      )
      .suggest("wharf plan"),
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

  let skip = if req.skip_snapshot {
    crate::auth::require_perm(perms, Perm::Admin)?;
    Some(crate::security_receipt::Actor::from_request(
      caller.clone().ok_or_else(|| {
        ApiError::new(
          ErrorCode::Forbidden,
          "跳过热快照需要明确的管理员身份",
        )
      })?,
    ))
  } else {
    None
  };
  let reason =
    crate::db_snapshot::plan_trigger_reason(plan, &stored.steps);
  if reason.is_some() || skip.is_some() {
    let checked_plan = plan.clone();
    let refs = stored.body.account_refs.clone();
    let base_instances = stored.body.base_instances.clone();
    state
      .db
      .call_credentials(move |c, key| {
        require_fresh(
          c,
          key,
          &checked_plan,
          refs.as_ref(),
          base_instances.as_ref(),
        )
      })
      .await?;
    crate::db_snapshot::before(
      &state,
      crate::db_snapshot::Trigger::Apply,
      reason.unwrap_or_else(|| "执行计划".into()),
      Some(plan),
      skip.as_ref(),
    )
    .await?;
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
  let offset = steps.len();
  steps.extend(stored.steps.iter().map(pending_run_step));
  let run = Run {
    run_id: run_id.clone(),
    actor: auth.map(format_actor).or_else(|| Some("系统".into())),
    retry_of: None,
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
    let account_refs = stored.body.account_refs;
    let base_instances = stored.body.base_instances;
    let writes = stored.writes.clone();
    let step_plans = stored.steps.clone();
    let policy_plan = plan.clone();
    let admin = perms.contains(&Perm::Admin);
    let plan_id = plan.plan_id.clone();
    let run_body = serde_json::to_string(&run).map_err(json_err)?;
    let actor_name = run.actor.clone();
    let confirmed = req.confirm;
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
        require_fresh(
          &tx,
          key,
          &policy_plan,
          account_refs.as_ref(),
          base_instances.as_ref(),
        )?;
        apply_writes(&tx, &policy_plan, &writes, admin)?;
        crate::pending::stage(&tx, &run_id, &policy_plan, &writes, &step_plans)?;
        tx.execute(
          "UPDATE plans SET status = 'applied' WHERE id = ?1",
          params![plan_id],
        )
        .map_err(sql_err)?;
        let meta = retry::RetryMeta::capture(&tx, key, (step_plans, offset), account_refs, confirmed)?;
        let meta = serde_json::to_string(&meta).map_err(json_err)?;
        tx.execute(
          "INSERT INTO runs (id, plan_id, status, body, started_at, actor, retry_meta) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
          params![run_id, plan_id, run_status, run_body, now_ms(), actor_name, meta],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)
      })
      .await?;
    crate::log_redact::refresh(&state.db).await;
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
      crate::heal::forget(name);
      crate::rules::on_service_deleted(&state, name).await;
    }
  }
  crate::service_monitor::sync_watches(&state, None).await;
  Ok(ApplyResponse { run_id })
}

fn require_fresh(
  c: &rusqlite::Connection,
  key: &db::CredentialsKey,
  plan: &Plan,
  account_refs: Option<&BTreeSet<String>>,
  base_instances: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<(), ApiError> {
  if let Some(i) = &plan.inputs
    && *i != db::inputs(c, key, account_refs)?
  {
    return Err(ApiError::new(ErrorCode::PlanStale,
      "plan 之后机器之间的连通性、密钥或机器地址变了，直连还是走隧道、渲染出的配置可能和计划不一样")
      .suggest("wharf plan"));
  }
  if let Some(expected) = base_instances {
    check_base_instances(c, expected)?;
  }
  let base = &plan.base_versions;
  let now_versions = db::versions(c)?;
  let stale = base
    .keys()
    .chain(now_versions.keys())
    .filter(|k| base.get(*k) != now_versions.get(*k))
    .cloned()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();
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
  Ok(())
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

fn check_base_instances(
  c: &rusqlite::Connection,
  expected: &std::collections::BTreeMap<String, String>,
) -> Result<(), ApiError> {
  let actual = db::service_instances(c)?;
  let rebuilt: Vec<_> = expected
    .iter()
    .filter(|(name, id)| {
      actual.get(*name).is_some_and(|actual| actual != *id)
    })
    .map(|(name, _)| name.as_str())
    .collect();
  if !rebuilt.is_empty() {
    return Err(ApiError::new(ErrorCode::PlanStale,
      format!("plan 之后这些服务已被删除并重建：{}，旧计划不能作用到新服务", rebuilt.join("、")))
      .with_hint("重新 plan，确认新的差异后再 apply").suggest("wharf plan"));
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
    match write {
      Write::Delete { kind, name }
        if kind == crate::world::KIND_SERVICE =>
      {
        crate::heal::reset_notice(tx, name)?;
      }
      Write::Upsert {
        kind, name, spec, ..
      } if kind == crate::world::KIND_SERVICE
        && spec
          .get("stopped")
          .and_then(serde_json::Value::as_bool)
          == Some(true) =>
      {
        crate::heal::reset_notice(tx, name)?;
      }
      _ => {}
    }
    if let Write::Upsert { kind, name, .. } = write
      && kind == crate::world::KIND_SERVICE
      && !current.services.contains_key(name)
    {
      crate::pending::clear_service(tx, name, true)?;
      tx.execute("DELETE FROM cleanups WHERE service = ?1", [name])
        .map_err(sql_err)?;
    }
  }
  let desired =
    crate::world::World::from_rows(db::all_resources(tx)?)?;
  crate::secret_policy::validate_restrictions(
    &desired,
    &crate::secret_restrictions::load(tx)?,
  )?;
  desired.validate()?;
  crate::edge::validate_owners(&current, &desired)?;
  crate::secret_policy::validate_accounts(
    &desired,
    &crate::app_accounts::account_links(tx)?,
  )
}

/// 不来自计划的执行同样占用 apply 锁。
#[allow(dead_code)]
pub async fn start_task(
  state: Arc<AppState>,
  title: String,
  step: Step,
) -> Result<ApplyResponse, ApiError> {
  start_task_by(state, title, step, Some("系统".into())).await
}

pub async fn start_task_by(
  state: Arc<AppState>,
  title: String,
  step: Step,
  actor: Option<String>,
) -> Result<ApplyResponse, ApiError> {
  let guard = state
    .apply_lock
    .clone()
    .try_lock_owned()
    .map_err(|_| state.runs.busy_error())?;
  start_task_locked(state, title, step, actor, guard).await
}

pub(crate) async fn start_task_locked(
  state: Arc<AppState>,
  title: String,
  step: Step,
  actor: Option<String>,
  guard: OwnedMutexGuard<()>,
) -> Result<ApplyResponse, ApiError> {
  let scope = Some(run_scope::step_services(&step));
  let replayable = !matches!(
    &step,
    Step::CoreBackup { .. } | Step::CleanupData { .. }
  );
  let steps = vec![StepPlan {
    items: vec![],
    title,
    step,
  }];
  let run = Run {
    run_id: crate::world::new_id("r"),
    plan_id: String::new(),
    actor,
    retry_of: None,
    status: RunStatus::Running,
    started_at: Utc::now(),
    finished_at: None,
    steps: steps.iter().map(pending_run_step).collect(),
  };
  let run_id = run.run_id.clone();
  let stored = run.clone();
  let stored_steps = replayable.then(|| steps.clone());
  let scope_services = scope.clone();
  state
    .db
    .call_credentials(move |c, key| {
      let meta = stored_steps
        .map(|steps| {
          retry::RetryMeta::capture(c, key, (steps, 0), None, vec![])
        })
        .transpose()?;
      insert_task_run(
        c,
        &stored,
        scope_services.as_deref(),
        meta.as_ref(),
      )
    })
    .await?;
  spawn_run(state, run, scope, steps, guard);
  Ok(ApplyResponse { run_id })
}

fn pending_run_step(step: &StepPlan) -> RunStep {
  RunStep {
    items: step.items.clone(),
    title: step.title.clone(),
    status: StepStatus::Pending,
    log: vec![],
    error: None,
    started_at: None,
    finished_at: None,
  }
}

fn insert_task_run(
  c: &rusqlite::Connection,
  run: &Run,
  scope: Option<&[String]>,
  meta: Option<&retry::RetryMeta>,
) -> Result<(), ApiError> {
  let body = run_scope::encode(run, scope)?;
  let meta = meta
    .map(serde_json::to_string)
    .transpose()
    .map_err(json_err)?;
  c.execute(
    "INSERT INTO runs (id, plan_id, status, body, started_at, actor, retry_of, retry_meta) VALUES (?1, ?2, 'running', ?3, ?4, ?5, ?6, ?7)",
    params![run.run_id, run.plan_id, body, now_ms(), run.actor, run.retry_of, meta],
  ).map_err(sql_err)?;
  Ok(())
}

fn spawn_run(
  state: Arc<AppState>,
  run: Run,
  scope_services: Option<Vec<String>>,
  steps: Vec<StepPlan>,
  guard: OwnedMutexGuard<()>,
) {
  let run_id = run.run_id.clone();
  let cancel = CancellationToken::new();
  let shared = Arc::new(Mutex::new(run));
  lock(&state.runs.active).insert(
    run_id,
    ActiveRun {
      scope_services,
      run: shared.clone(),
      cancel: cancel.clone(),
    },
  );
  tokio::spawn(execute(state, shared, steps, 0, None, cancel, guard));
}

async fn execute(
  state: Arc<AppState>,
  run: Arc<Mutex<Run>>,
  steps: Vec<StepPlan>,
  offset: usize,
  actor: Option<crate::security_receipt::Actor>,
  cancel: CancellationToken,
  guard: OwnedMutexGuard<()>,
) {
  let mut guard = Some(guard);
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
        log.push(crate::log_redact::redact_text(&line));
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
    let result = if let Step::CleanupData {
      service,
      server,
      instance_id,
    } = &step.step
    {
      crate::jobs::cleanup_data(
        &state,
        (service, server, instance_id.as_deref()),
        progress,
        &cancel,
        guard.take().expect("清理任务必须先持有 apply 锁"),
      )
      .await
    } else {
      run_step(&state, &run_id, &step.step, progress, &cancel).await
    };
    let result = match result {
      Ok(()) => crate::pending::finish_step(&state, &step.step).await,
      Err(e) => Err(e),
    };
    crate::security_receipt::completed_step(
      &state,
      actor.as_ref(),
      &step.step,
      &result,
    )
    .await;
    if result.is_ok() {
      match &step.step {
        Step::ServiceUp { service, .. }
        | Step::Rebuild { service } => {
          crate::heal::clear(&state, service).await
        }
        Step::ServiceRestart { service }
          if !step
            .title
            .starts_with(crate::heal::AUTO_RESTART_TITLE) =>
        {
          crate::heal::clear(&state, service).await;
        }
        _ => {}
      }
    }
    if let Some((service, action)) = op {
      let (status, error) = match &result {
        Ok(()) => (OpStatus::Succeeded, None),
        Err(e) => (
          OpStatus::Failed,
          Some(crate::log_redact::redact_text(&e.message)),
        ),
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
          let e = crate::log_redact::redact_error(e);
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

/// 计划时的产物指纹和现在渲染的不一致：说明计划之后有东西变了，
/// 现在下发的和用户看过的不一样，重新 plan 再确认。
pub(crate) fn check_expect(
  expect: Option<&str>,
  current: &str,
  what: &str,
) -> Result<(), ApiError> {
  let Some(expect) = expect else {
    // 旧计划没有指纹，照常执行。
    return Ok(());
  };
  if expect == current {
    return Ok(());
  }
  Err(
    ApiError::new(
      ErrorCode::PlanStale,
      format!(
        "{what} 的配置在 plan 之后变了，现在下发的会和计划里看过的不一样"
      ),
    )
    .with_hint("重新 plan，确认新的差异后再 apply")
    .suggest("wharf plan"),
  )
}

/// 失败只记日志：状态显示不全不影响执行本身。
async fn record_op(
  state: &AppState,
  service: &str,
  action: &str,
  run_id: &str,
  status: OpStatus,
  error: Option<String>,
) {
  let service = service.to_string();
  let op = LastOp {
    action: action.to_string(),
    run_id: run_id.to_string(),
    status,
    at: Utc::now(),
    error,
  };
  let result = state
    .db
    .call(move |c| db::set_service_op(c, &service, &op))
    .await;
  if let Err(e) = result {
    tracing::warn!("记录服务操作失败：{e}");
  }
}

pub(crate) async fn run_step(
  state: &AppState,
  run_id: &str,
  step: &Step,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let mut snap = snapshot::load(&state.db).await?;
  if matches!(step, Step::LinkUp { .. } | Step::GatewaySync { .. }) {
    snap.reach =
      crate::link::probe(state, &snap.net(&snap.world), &snap.world)
        .await;
  }
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
    Step::VolumeSync {
      service,
      from,
      to,
      instance_id,
    } => {
      check_step_instance(world, service, instance_id.as_deref())?;
      crate::migrate::volume_sync(
        state,
        &net,
        service,
        (from, to),
        !world.services[service].spec.stopped,
        progress,
        cancel,
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
    Step::ServiceUp {
      service,
      expect,
      instance_id,
    } => {
      check_step_instance(world, service, instance_id.as_deref())?;
      let migration =
        snap.pending.migrations.get(service).filter(|m| {
          m.phase != crate::pending::MigratePhase::UpDone
            && world
              .services
              .get(service)
              .is_some_and(|row| row.spec.server == m.payload.to)
        });
      if migration.is_some_and(|m| {
        m.payload.has_managed_data
          && m.phase != crate::pending::MigratePhase::Synced
      }) {
        return Err(ApiError::new(
          ErrorCode::Conflict,
          "迁移数据尚未同步，先运行 wharf plan",
        ));
      }
      if let Err(e) = service_up(
        state,
        run_id,
        &snap,
        service,
        false,
        expect.as_deref(),
        progress.clone(),
        cancel,
      )
      .await
      {
        if let Some(m) =
          migration.filter(|m| m.payload.source_stopped)
        {
          let from = &m.payload.from;
          if crate::migrate::restart_source(
            state, from, service, &progress,
          )
          .await
          {
            crate::migrate::reset_after_restart(state, service)
              .await?;
            progress(format!(
              "迁移至 {} 失败，已恢复 {from} 上的 {service} 运行",
              m.payload.to
            ));
            return Err(e.with_hint(format!("源机已恢复运行；排查后可重试，或执行 wharf service move {service} --abort --apply 取消迁移")));
          }
          return Err(e.with_hint(format!("源机自动恢复失败，请先检查 {from} 并手动 wharf service start {service}")));
        }
        return Err(e);
      }
      if let Some(m) =
        migration.filter(|m| m.payload.has_managed_data)
      {
        progress(format!(
          "{} 上的 /srv/{service}/ 保留 7 天，之后自动删除",
          m.payload.from
        ));
      }
    }
    Step::Rebuild { service } => {
      crate::build::require_not_migrating(&snap, service)?;
      service_up(
        state, run_id, &snap, service, true, None, progress, cancel,
      )
      .await?;
    }
    Step::AgentUpgrade { server } => {
      crate::agent_upgrade::upgrade(state, server, progress, cancel)
        .await?;
    }
    Step::AgentUpgrades { servers } => {
      crate::agent_upgrade::upgrade_each(
        state, servers, progress, cancel,
      )
      .await?;
    }
    Step::ServiceStop { service } => {
      let server = service_server(&snap, service)?;
      project_stop_start(
        state, &server, service, false, &progress, cancel,
      )
      .await?;
    }
    Step::ServiceRestart { service } => {
      let server = service_server(&snap, service)?;
      project_stop_start(
        state, &server, service, false, &progress, cancel,
      )
      .await?;
      project_stop_start(
        state, &server, service, true, &progress, cancel,
      )
      .await?;
    }
    Step::CoreBackup { user_key } => {
      crate::core_backup::backup(
        state,
        run_id,
        user_key.as_ref(),
        progress,
        cancel,
      )
      .await?;
    }
    Step::DockerProxy { server } => {
      let settings = &world
        .servers
        .get(server)
        .ok_or_else(|| crate::world::server_not_found(server))?
        .settings;
      crate::docker_proxy::apply(
        state, server, settings, progress, cancel,
      )
      .await?;
    }
    Step::Baseline { server } => {
      let baseline = &world
        .servers
        .get(server)
        .ok_or_else(|| crate::world::server_not_found(server))?
        .settings
        .baseline;
      crate::baseline::apply(
        state, server, baseline, progress, cancel,
      )
      .await?;
    }
    Step::Egress { server } => {
      crate::egress::apply(state, server, cancel).await?;
    }
    Step::Prune { server } => {
      crate::prune::prune(state, server, progress, cancel).await?;
    }
    Step::EdgeDeploy { app } => {
      let key = crate::edge_plan::deployed_key(app);
      let fingerprint = world
        .edge_apps
        .get(app)
        .map(|a| crate::edge_plan::fingerprint(app, &a.spec));
      let k = key.clone();
      state
        .db
        .call(move |c| {
          db::set_setting(c, &k, Some(crate::edge_plan::DEPLOYING))
        })
        .await?;
      crate::edge::deploy(state, &snap, app, &progress, cancel)
        .await?;
      state
        .db
        .call(move |c| {
          db::set_setting(c, &key, fingerprint.as_deref())
        })
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
    Step::ServiceDown {
      server,
      service,
      purge_data,
      instance_id,
      has_relative_mounts,
    } => {
      service_down(
        state,
        &snap,
        (server, service),
        (*purge_data, instance_id.as_deref(), *has_relative_mounts),
        progress,
        cancel,
      )
      .await?;
    }
    Step::CleanupData { .. } => {
      return Err(ApiError::internal("清理只能由定时任务执行"));
    }
    Step::GatewaySync { gateway, expect } => {
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
      check_expect(
        expect.as_deref(),
        &r.fingerprint(),
        &format!("网关 {gateway}"),
      )?;
      let r =
        gateway::caddyfile_for_apply(state, world, &net, gateway, r)
          .await?;
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
              pull_missing_only: false,
              retire: None,
              rollback: false,
              pins: Default::default(),
              expected_images: Default::default(),
              no_start: false,
              trial: None,
              start_timeout_secs: None,
              readiness: None,
            },
            caddyfile: r.config,
            caddyfile_hash: r.config_hash,
            extra_files: r.extra_files,
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
        &[],
      )?;
    }
    Step::LinkUp { server, project } => {
      let p = crate::link::projects(world, &net)?
        .into_iter()
        .find(|p| &p.server == server && &p.project == project)
        .ok_or_else(|| {
          ApiError::new(
            ErrorCode::PlanStale,
            format!("{server} 上已经不需要 {project}"),
          )
          .suggest("wharf plan")
        })?;
      let client = project != crate::link::SERVER_PROJECT;
      if !client {
        crate::link_cert::require_gateway_agent(
          &state.hub, server, &p.gateway,
        )?;
      }
      let gateway = p.gateway;
      let (token, ca) = state
        .db
        .call_credentials({
          let gateway = gateway.clone();
          move |c, key| {
            let now = db::now_ms();
            let tx = c.transaction().map_err(db::sql_err)?;
            let token = db::ensure_scoped_secret(
              &tx,
              key,
              crate::link::TOKEN_PREFIX,
              &gateway,
              now,
            )?;
            let ca = if client {
              Some(crate::link_cert::ensure_ca(&tx, key, now)?.cert)
            } else {
              None
            };
            tx.commit().map_err(db::sql_err)?;
            Ok((token, ca))
          }
        })
        .await?;
      let mut secrets = snap.secrets.clone();
      secrets.insert(
        format!("{}{gateway}", crate::link::TOKEN_PREFIX),
        token,
      );
      if let Some(ca) = ca {
        secrets.insert(crate::link::CA_CERT_SECRET.into(), ca);
      }
      let p =
        crate::link::projects_with_secrets(world, &net, &secrets)?
          .into_iter()
          .find(|p| &p.server == server && &p.project == project)
          .ok_or_else(|| ApiError::internal("反向隧道配置丢失"))?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::ProjectUp(ProjectUp {
            project: project.clone(),
            compose: p.compose,
            hash: p.hash,
            pull: snapshot::pull_policy(&world.servers[server]),
            pull_missing_only: false,
            retire: None,
            rollback: false,
            pins: Default::default(),
            expected_images: Default::default(),
            no_start: false,
            trial: None,
            start_timeout_secs: None,
            readiness: None,
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        &format!("反向隧道 {project}"),
        &format!(
          "在 {server} 上 docker logs {project}-{}-1",
          if project == crate::link::SERVER_PROJECT {
            "frps"
          } else {
            "frpc"
          }
        ),
        &[],
      )?;
    }
    Step::TailscaleUp { server } => {
      let compose =
        crate::tailscale::deploy_compose(state, server).await?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::ProjectUp(ProjectUp {
            project: crate::tailscale::PROJECT.to_string(),
            compose,
            hash: crate::tailscale::hash(server),
            pull: snapshot::pull_policy(&world.servers[server]),
            pull_missing_only: false,
            retire: None,
            rollback: false,
            pins: Default::default(),
            expected_images: Default::default(),
            no_start: false,
            trial: None,
            start_timeout_secs: None,
            readiness: None,
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        "Tailscale",
        &format!(
          "在 {server} 上 docker logs {}-tailscale-1",
          crate::tailscale::PROJECT
        ),
        &[],
      )?;
    }
    Step::LinkDown { server, project } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: project.clone(),
            purge: false,
          },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::GatewayDown { server, gateway } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: gateway_project(gateway),
            purge: false,
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
      let owner_id = world.dns_owner(hostname).ok_or_else(|| {
        ApiError::new(
          ErrorCode::PlanStale,
          format!("域名 {hostname} 已经没有路由或边缘应用使用"),
        )
      })?;
      let account_row = find_account(&snap, account)?;
      let provider = snapshot::dns_provider(account_row)?;
      let owner = Owner { id: owner_id };
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
        &owner.id,
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

fn ensure_created(
  result: &ProjectUpResult,
  service: &str,
) -> Result<(), ApiError> {
  if result.containers.is_empty()
    || result.containers.iter().any(|c| c.state == "running")
  {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("服务 {service} 创建后没有容器或容器仍在运行"),
    ));
  }
  Ok(())
}

fn ensure_running(
  result: &ProjectUpResult,
  what: &str,
  logs: &str,
  expected: &[String],
) -> Result<(), ApiError> {
  let has_running = result.containers.iter().any(|c| c.is_running());
  let bad: Vec<String> = result
    .containers
    .iter()
    .filter(|c| !c.foreign && !c.is_healthy_state(has_running))
    .map(|c| format!("{} {}（{}）", c.service, c.state, c.status))
    .collect();
  if result.containers.iter().all(|c| c.foreign) {
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
  let missing =
    render::missing_components(expected, &result.containers);
  if !missing.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{what} 缺少组件：{}", missing.join("、")),
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

fn service_progress(
  values: Vec<String>,
  progress: ProgressFn,
) -> ProgressFn {
  Arc::new(move |line| {
    progress(crate::log_redact::redact_text_with(&line, &values))
  })
}

fn should_trial(
  spec: &ServiceSpec,
  rollback: bool,
  has_deployed: bool,
  has_trial_collision: bool,
) -> bool {
  rollback
    && !spec.stopped
    && !spec.ports.is_empty()
    && has_deployed
    && !has_trial_collision
}

/// 部署一个服务：构建来源先构建镜像（`force` 时重新构建），再 `up`。
#[allow(clippy::too_many_arguments)]
async fn service_up(
  state: &AppState,
  run_id: &str,
  snap: &snapshot::Snapshot,
  service: &str,
  force: bool,
  expect: Option<&str>,
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
  // 刚导入时本机已有的镜像不拉取，避免拉到新版本而重建容器。
  let pull_missing_only = row.import.is_some();
  if pull_missing_only {
    state.hub.require_safe_adopt(server)?;
  }
  let no_start = row.spec.stopped;
  if no_start && !pull_missing_only && !state.hub.supports_safe_migrate(server) {
    return Err(crate::hub::safe_migrate_required(server));
  }
  let (compose, hash) = snapshot::service_resolved(
    world,
    &net,
    service,
    &snap.render_values(world, service),
  )?;
  // 先比对指纹再构建：计划过期时不用白构建一次。
  check_expect(expect, &hash, &format!("服务 {service}"))?;
  let commit = crate::build::ensure_image(
    state, snap, service, force, &progress, cancel,
  )
  .await?;
  let template = snapshot::service_template(world, &net, service)?;
  // 导入的服务：agent 拉好镜像后停掉原来的容器，启动失败时由 agent 恢复。
  let retire = row
    .import
    .as_ref()
    .filter(|a| {
      a.project.is_some()
        || !a.containers.is_empty()
        || !a.expected_services.is_empty()
    })
    .map(|a| Retire {
      service: service.to_string(),
      project: a.project.clone(),
      containers: a.containers.clone(),
      rename_containers: a.rename_containers.clone(),
      expected_services: a.expected_services.clone(),
    });
  // 起不来时自动换回上一版：只对没有数据的服务做，新版本可能已经改了数据，
  // 旧版本不一定认。compose 来源看不出有没有数据，不做。
  let rollback = row.spec.volumes.is_empty()
    && retire.is_none()
    && !matches!(row.spec.source, Source::Compose { .. });
  // 先试跑再替换：和自动换回上一版的条件一样，另外要已经部署过、不是要保持停止的。
  let has_deployed = rollback
    && !row.spec.stopped
    && !row.spec.ports.is_empty()
    && has_deployment(state, service, &row.instance_id).await?;
  let trial = if should_trial(
    &row.spec,
    rollback,
    has_deployed,
    world
      .services
      .contains_key(&format!("{TRIAL_PROJECT_PREFIX}{service}")),
  ) {
    Some(snapshot::service_trial(
      world,
      &net,
      service,
      &snap.render_values(world, service),
    )?)
  } else {
    None
  };
  let values = crate::log_redact::service_values(&row.spec);
  let progress = service_progress(values.clone(), progress);
  let readiness = row
    .spec
    .monitor
    .as_ref()
    .filter(|_| !row.spec.stopped)
    .and_then(|m| {
      crate::monitor::url(row, m).ok().map(|url| SettleProbe {
        url,
        expect: m.expect,
        keyword: m.keyword.clone(),
      })
    });
  if (row.spec.start_timeout_secs.is_some() || readiness.is_some())
    && !state.hub.supports_runtime_v2(server)
  {
    progress(format!(
      "提醒：服务器 {server} 的 agent 版本较旧，自定义启动上限和就绪探活暂未生效，请运行 wharf upgrade 升级"
    ));
  }
  let result: ProjectUpResult = state
    .hub
    .call(
      server,
      AgentOp::ProjectUp(ProjectUp {
        project: service.to_string(),
        compose,
        hash: hash.clone(),
        pull: snapshot::pull_policy(&world.servers[server]),
        pull_missing_only,
        retire,
        rollback: rollback && !row.spec.stopped,
        pins: row.pins.clone(),
        expected_images: row
          .import
          .as_ref()
          .map(|a| a.expected_images.clone())
          .unwrap_or_default(),
        no_start,
        trial,
        start_timeout_secs: row.spec.start_timeout_secs,
        readiness,
      }),
      SERVICE_UP_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await
    .map_err(|mut e| {
      e.message =
        crate::log_redact::redact_text_with(&e.message, &values);
      e.hint = e.hint.map(|hint| {
        crate::log_redact::redact_text_with(&hint, &values)
      });
      e
    })?;
  let retired = result.retired.clone();
  for warning in &result.warnings {
    progress(format!("提醒：{warning}"));
  }
  let running = if no_start {
    ensure_created(&result, service)
  } else {
    ensure_running(
      &result,
      service,
      &format!("wharf service logs {service}"),
      &render::service_expected_components(service, &row.spec),
    )
  };
  if running.is_err() && !retired.is_empty() {
    restore(state, server, service, retired, &progress).await;
  }
  running?;
  if let Some(import) = row.import.clone() {
    let retired: Vec<String> = result
      .retired
      .iter()
      .map(|r| r.renamed.clone().unwrap_or_else(|| r.name.clone()))
      .collect();
    let (service, server) = (service.to_string(), server.to_string());
    state
      .db
      .call(move |c| {
        db::finish_import(c, &service, &server, &import, &retired)
      })
      .await?;
  }
  record_deployment(
    state,
    Deployed {
      service,
      instance_id: &row.instance_id,
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
  Ok(())
}

fn service_server(
  snap: &snapshot::Snapshot,
  service: &str,
) -> Result<String, ApiError> {
  snapshot::service_runtime_server(snap, service)
    .map(str::to_string)
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::PlanStale,
        format!("服务 {service} 已不存在"),
      )
    })
}

/// `docker compose stop` / `start`，容器不删除、不重建。
async fn project_stop_start(
  state: &AppState,
  server: &str,
  service: &str,
  start: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let op = if start {
    AgentOp::ProjectStart {
      project: service.to_string(),
    }
  } else {
    AgentOp::ProjectStop {
      project: service.to_string(),
    }
  };
  let done: bool = state
    .hub
    .call(
      server,
      op,
      STOP_START_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if !done {
    return Err(ApiError::new(
      ErrorCode::NotFound,
      format!("{server} 上还没有部署 {service}"),
    ));
  }
  Ok(())
}

/// 接管失败：删掉新起的 project，恢复原来的容器。不受取消影响。
async fn restore(
  state: &AppState,
  server: &str,
  service: &str,
  retired: Vec<Retired>,
  progress: &ProgressFn,
) {
  progress("部署失败，恢复原来的容器".into());
  let cancel = CancellationToken::new();
  let down = project_down(
    state,
    (server, service),
    false,
    true,
    progress.clone(),
    &cancel,
  )
  .await;
  if let Err(e) = down {
    progress(format!("删除新容器失败：{}", e.message));
  }
  let back: Result<serde_json::Value, ApiError> = state
    .hub
    .call(
      server,
      AgentOp::Unretire { items: retired },
      SHORT_TIMEOUT,
      Some(progress.clone()),
      &cancel,
    )
    .await;
  match back {
    Ok(_) => progress("已恢复原来的容器".into()),
    Err(e) => progress(format!(
      "恢复原来的容器失败，需要手动处理：{}",
      e.message
    )),
  }
}

fn check_step_instance(
  world: &crate::world::World,
  service: &str,
  expected: Option<&str>,
) -> Result<(), ApiError> {
  if let Some(expected) = expected
    && world.services.get(service).map(|r| r.instance_id.as_str())
      != Some(expected)
  {
    return Err(
      ApiError::new(
        ErrorCode::PlanStale,
        format!("服务 {service} 已被重建，中止旧步骤"),
      )
      .with_hint("重新运行 wharf plan")
      .suggest("wharf plan"),
    );
  }
  Ok(())
}

async fn service_down(
  state: &AppState,
  snap: &snapshot::Snapshot,
  (server, service): (&str, &str),
  (purge_data, instance_id, has_relative_mounts): (
    bool,
    Option<&str>,
    bool,
  ),
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let stale = |message| {
    ApiError::new(ErrorCode::PlanStale, message)
      .with_hint("运行 wharf plan 查看当前状态")
      .suggest("wharf plan")
  };
  if let Some(row) = snap.world.services.get(service) {
    if instance_id.is_some_and(|expected| row.instance_id != expected)
    {
      return Err(stale(format!(
        "服务 {service} 已被重建为新实例，拒绝执行旧删除步骤"
      )));
    }
    if row.spec.server == server {
      return Err(stale(format!(
        "服务 {service} 当前配置仍在 {server} 上，拒绝删除"
      )));
    }
  } else if let Some(expected) = instance_id
    && !snap.pending.service_deletes.iter().any(|p| {
      p.service == service
        && p.server == server
        && p.instance_id == expected
        && p.purge_data == purge_data
    })
  {
    return Err(stale(format!(
      "服务 {service} 在 {server} 上的删除已完成或取消"
    )));
  }
  project_down(
    state,
    (server, service),
    purge_data,
    has_relative_mounts,
    progress,
    cancel,
  )
  .await?;
  let (service, server, instance_id) = (
    service.to_string(),
    server.to_string(),
    instance_id.map(str::to_string),
  );
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      crate::pending::clear_delete(
        &tx,
        &service,
        &server,
        instance_id.as_deref(),
      )?;
      if crate::pending::load(&tx)?
        .migrations
        .get(&service)
        .is_some_and(|m| {
          m.phase == crate::pending::MigratePhase::UpDone
            && m.payload.from == server
        })
      {
        crate::pending::clear(&tx, "migrate", &service)?;
      }
      tx.commit().map_err(sql_err)
    })
    .await
}

async fn project_down(
  state: &AppState,
  (server, service): (&str, &str),
  purge: bool,
  require_safe_delete: bool,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let op = AgentOp::ProjectDown {
    project: service.to_string(),
    purge,
  };
  let _: serde_json::Value = if require_safe_delete {
    // 用同一条连接核对能力并发请求，防止重连时切到旧 agent。
    let conn = state.hub.safe_delete_conn_id(server)?;
    state
      .hub
      .call_bound(
        (server, conn),
        op,
        PROJECT_DOWN_TIMEOUT,
        Some(progress),
        cancel,
      )
      .await?
  } else {
    state
      .hub
      .call(server, op, PROJECT_DOWN_TIMEOUT, Some(progress), cancel)
      .await?
  };
  Ok(())
}

async fn has_deployment(
  state: &AppState,
  service: &str,
  instance_id: &str,
) -> Result<bool, ApiError> {
  let (service, instance_id) =
    (service.to_string(), instance_id.to_string());
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT 1 FROM deployments WHERE service = ?1 AND instance_id = ?2 AND started = 1 LIMIT 1",
        params![service, instance_id],
        |_| Ok(()),
      )
      .optional()
      .map(|r| r.is_some())
      .map_err(sql_err)
    })
    .await
}

struct Deployed<'a> {
  instance_id: &'a str,
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
  let mut images = result.images.clone();
  wharf_api_types::agent::normalize_image_digests(&mut images);
  let encoded_images =
    serde_json::to_string(&images).map_err(json_err)?;
  let spec = serde_json::to_string(d.spec).map_err(json_err)?;
  let commit = d.commit.map(str::to_string);
  let started = !d.spec.stopped;
  let instance_id = d.instance_id.to_string();
  // 记下实际跑起来的版本：导入（按本机已有的镜像启动）和每次部署之后，固定的版本都和正在跑的一致。
  let pinnable = crate::pins::images(&d.spec.source);
  let pins: std::collections::BTreeMap<&str, &str> = images
    .iter()
    .filter(|i| pinnable.contains(&i.image))
    .filter_map(|i| {
      let (_, digest) = i.digest.as_deref()?.split_once('@')?;
      Some((i.image.as_str(), digest))
    })
    .collect();
  let pins = (!pins.is_empty())
    .then(|| serde_json::to_string(&pins))
    .transpose()
    .map_err(json_err)?;
  let values = (
    d.service.to_string(),
    d.server.to_string(),
    d.run_id.to_string(),
    d.hash.to_string(),
    crate::log_redact::redact_text(d.template),
  );
  state
    .db
    .call(move |c| {
      let (service, server, run_id, hash, compose) = values;
      let tx = c.transaction().map_err(sql_err)?;
      tx.execute(
        "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, spec, commit_sha, instance_id, started)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![service, server, run_id, hash, compose, encoded_images, now_ms(), spec, commit, instance_id, started],
      )
      .map_err(sql_err)?;
      if let Some(pins) = pins {
        tx.execute(
          "UPDATE resources SET meta = json_set(COALESCE(meta, '{}'), '$.pins', json(?1))
           WHERE kind = 'service' AND name = ?2",
          params![pins, service],
        )
        .map_err(sql_err)?;
      }
      if let Some(m) = crate::pending::load(&tx)?.migrations.remove(&service)
        && m.payload.to == server && m.phase != crate::pending::MigratePhase::UpDone
      {
        if m.payload.has_managed_data {
          crate::jobs::schedule_cleanup(&tx, &service, &m.payload.from, Some(&instance_id))?;
        }
        crate::pending::update_migration(&tx, &service, |m| {
          m.phase = crate::pending::MigratePhase::UpDone;
          m.payload.source_stopped = false;
        })?;
      }
      tx.commit().map_err(sql_err)
    })
    .await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn crash_progress_redacts_inline_service_value() {
    let spec = serde_json::from_value::<ServiceSpec>(serde_json::json!({
      "server": "s1", "source": {"image": "fixture:1"}, "env": {"PASSWORD": "fixture-inline-value"},
    })).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let capture = lines.clone();
    let progress = service_progress(
      crate::log_redact::service_values(&spec),
      Arc::new(move |line| lock(&capture).push(line)),
    );
    progress("app 启动失败 fixture-inline-value".into());
    assert_eq!(&*lock(&lines), &["app 启动失败 ***"]);
  }

  #[test]
  fn no_port_service_skips_trial() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"image": "fixture:1"},
    }))
    .unwrap();
    assert!(!should_trial(&spec, true, true, false));
  }

  #[tokio::test]
  async fn stale_delete_plan_rejected_after_recreate_same_version() {
    use wharf_api_types::{plan::PlanRequest, spec::Change};
    let state = crate::rules::tests::test_state();
    let seed = |c: &rusqlite::Connection| {
      db::apply_write(
        c,
        &Write::Upsert {
          kind: "service".into(),
          name: "blog".into(),
          spec: serde_json::json!({"server":"s1","source":{"image":"fixture:1"}}),
          meta: serde_json::json!({}),
        },
      )
    };
    state
      .db
      .call(move |c| {
        db::apply_write(
          c,
          &Write::Upsert {
            kind: "server".into(),
            name: "s1".into(),
            spec: serde_json::json!({}),
            meta: serde_json::json!({}),
          },
        )?;
        seed(c)
      })
      .await
      .unwrap();
    let plan = crate::planner::make_plan(
      &state,
      PlanRequest {
        changes: vec![Change::RemoveService {
          name: "blog".into(),
          purge_data: true,
        }],
        ..Default::default()
      },
    )
    .await
    .unwrap();
    crate::planner::save(&state, &plan).await.unwrap();
    state
      .db
      .call(move |c| {
        db::apply_write(
          c,
          &Write::Delete {
            kind: "service".into(),
            name: "blog".into(),
          },
        )?;
        seed(c)
      })
      .await
      .unwrap();
    let result = start(
      state.clone(),
      ApplyRequest {
        plan_id: plan.plan.plan_id,
        confirm: vec!["service/blog".into()],
        skip_snapshot: false,
      },
      &BTreeSet::from([Perm::Admin, Perm::Confirm]),
      None,
    )
    .await;
    let error = result.err().unwrap();
    assert_eq!(error.code, ErrorCode::PlanStale);
    assert!(error.message.contains("已被删除并重建"));
    assert_eq!(
      snapshot::load(&state.db).await.unwrap().world.services["blog"]
        .version,
      1
    );
  }

  #[tokio::test]
  async fn old_agent_cannot_delete_relative_bind() {
    let state = crate::rules::tests::test_state();
    state
      .hub
      .mock_agent("s1", false, |_| panic!("不应发送删除请求"));
    let err = run_step(
      &state,
      "r1",
      &Step::ServiceDown {
        server: "s1".into(),
        service: "app".into(),
        purge_data: false,
        instance_id: None,
        has_relative_mounts: true,
      },
      Arc::new(|_| {}),
      &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
  }

  #[tokio::test]
  async fn offline_agent_is_reported_offline_for_relative_bind_delete()
   {
    let state = crate::rules::tests::test_state();
    let err = service_down(
      &state,
      &snapshot::Snapshot::default(),
      ("s1", "s1"),
      (false, None, true),
      Arc::new(|_| {}),
      &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::AgentOffline);
  }

  #[tokio::test]
  async fn takeover_rollback_does_not_send_project_down_to_old_agent()
  {
    let state = crate::rules::tests::test_state();
    let (sent, received) = tokio::sync::oneshot::channel();
    let mut sent = Some(sent);
    state.hub.mock_agent("s1", false, move |op| {
      assert!(
        matches!(op, AgentOp::Unretire { items } if items.len() == 1)
      );
      sent.take().unwrap().send(()).unwrap();
      Ok(serde_json::Value::Null)
    });
    let progress: ProgressFn = Arc::new(|_| {});
    restore(
      &state,
      "s1",
      "s1",
      vec![Retired {
        id: "s1".into(),
        name: "s1".into(),
        renamed: None,
        restart: "no".into(),
        was_running: true,
      }],
      &progress,
    )
    .await;
    received.await.unwrap();
  }

  #[test]
  fn old_plan_without_fingerprint_still_runs() {
    let step: Step = serde_json::from_str(
      r#"{"kind":"service_up","service":"web"}"#,
    )
    .unwrap();
    assert_eq!(
      step,
      Step::ServiceUp {
        instance_id: None,
        service: "web".into(),
        expect: None,
      }
    );
    let with = serde_json::to_string(&Step::ServiceUp {
      instance_id: None,
      service: "web".into(),
      expect: Some("h".into()),
    })
    .unwrap();
    assert!(with.contains(r#""expect":"h""#));
    let gateway: Step = serde_json::from_str(
      r#"{"kind":"gateway_sync","gateway":"gw"}"#,
    )
    .unwrap();
    assert_eq!(
      gateway,
      Step::GatewaySync {
        gateway: "gw".into(),
        expect: None,
      }
    );
  }

  #[test]
  fn fingerprint_mismatch_asks_for_a_new_plan() {
    assert!(check_expect(None, "x", "服务 web").is_ok());
    assert!(check_expect(Some("x"), "x", "服务 web").is_ok());
    let e = check_expect(Some("x"), "y", "服务 web").unwrap_err();
    assert_eq!(e.code, ErrorCode::PlanStale);
    assert_eq!(e.suggest, ["wharf plan"]);
  }

  #[test]
  fn api_token_cannot_apply_opening_host_exec() {
    let now = Utc::now();
    let plan = Plan {
      plan_id: "p1".into(),
      status: PlanStatus::Pending,
      created_at: now,
      expires_at: now,
      base_versions: Default::default(),
      inputs: None,
      items: vec![wharf_api_types::plan::PlanItem {
        id: 1,
        address: "server/s1".into(),
        layer: wharf_api_types::plan::Layer::Config,
        action: wharf_api_types::plan::Action::Update,
        before: Some(serde_json::json!({})),
        after: Some(serde_json::json!({"host_exec": true})),
        impacts: vec![],
        reason: "修改配置".into(),
        changes: vec![],
        host_access: vec![],
      }],
      warnings: vec![],
      needs_host: vec![],
      needs_confirm: vec![],
      suggest: vec![],
      note: None,
    };
    assert_eq!(
      crate::host_access::require_plan_host(
        &plan,
        &[],
        Some(&[]),
        &Perm::ALL.into_iter().collect(),
        false,
        &Default::default(),
        Some("core"),
      )
      .unwrap_err()
      .code,
      ErrorCode::Forbidden
    );
  }
}
