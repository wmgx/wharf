use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::*;
use crate::{
  auth::Auth,
  host_access::{self, HostTarget},
  pending::MigratePhase,
};

#[derive(Serialize, Deserialize)]
pub(super) struct RetryMeta {
  steps: Vec<StepPlan>,
  offset: usize,
  post_versions: BTreeMap<String, u64>,
  post_instances: BTreeMap<String, String>,
  inputs: String,
  account_refs: Option<BTreeSet<String>>,
  confirmed: Vec<String>,
}

impl RetryMeta {
  pub(super) fn capture(
    c: &rusqlite::Connection,
    key: &db::CredentialsKey,
    (steps, offset): (Vec<StepPlan>, usize),
    account_refs: Option<BTreeSet<String>>,
    confirmed: Vec<String>,
  ) -> Result<Self, ApiError> {
    Ok(Self {
      steps,
      offset,
      post_versions: db::versions(c)?,
      post_instances: db::service_instances(c)?,
      inputs: db::inputs(c, key, account_refs.as_ref())?,
      account_refs,
      confirmed,
    })
  }

  fn require_fresh(
    &self,
    c: &rusqlite::Connection,
    key: &db::CredentialsKey,
  ) -> Result<(), ApiError> {
    if self.post_versions != db::versions(c)?
      || self.post_instances != db::service_instances(c)?
      || self.inputs
        != db::inputs(c, key, self.account_refs.as_ref())?
    {
      return Err(
        ApiError::new(
          ErrorCode::PlanStale,
          "上次执行之后配置、密钥或连通性已经变化，不能直接续跑",
        )
        .with_hint(
          "运行 wharf plan 生成新计划，未完成的步骤会自动补出",
        )
        .suggest("wharf plan"),
      );
    }
    Ok(())
  }
}

fn require_retryable(run: &Run) -> Result<(), ApiError> {
  let id = &run.run_id;
  match run.status {
    RunStatus::Running => Err(ApiError::new(
      ErrorCode::Conflict,
      format!("执行记录 {id} 还在运行中，不能续跑"),
    )),
    RunStatus::Succeeded => Err(ApiError::invalid(format!(
      "执行记录 {id} 已经全部成功，无需续跑"
    ))),
    RunStatus::Failed | RunStatus::Cancelled => Ok(()),
  }
}

fn select_retry_steps(
  run: &Run,
  meta: &RetryMeta,
) -> Result<Vec<StepPlan>, ApiError> {
  require_retryable(run)?;
  let statuses = run
    .steps
    .get(meta.offset..)
    .filter(|steps| steps.len() == meta.steps.len())
    .ok_or_else(|| {
      ApiError::internal("续跑步骤与原执行记录不一致")
    })?;
  let remaining: Vec<_> = meta
    .steps
    .iter()
    .zip(statuses)
    .filter(|(_, step)| {
      matches!(step.status, StepStatus::Failed | StepStatus::Skipped)
    })
    .map(|(plan, _)| plan.clone())
    .collect();
  if remaining.is_empty() {
    return Err(ApiError::invalid(format!(
      "执行记录 {} 没有可续跑的失败或跳过步骤",
      run.run_id
    )));
  }
  Ok(remaining)
}

fn complete_migration_steps(
  steps: Vec<StepPlan>,
  snap: &snapshot::Snapshot,
) -> Vec<StepPlan> {
  let syncing: BTreeSet<_> = steps
    .iter()
    .filter_map(|s| match &s.step {
      Step::VolumeSync { service, .. } => Some(service.clone()),
      _ => None,
    })
    .collect();
  let mut remaining = Vec::new();
  for step in steps {
    if let Step::ServiceUp { service, .. } = &step.step
      && let Some(m) = snap.pending.migrations.get(service)
      && m.phase == MigratePhase::Pending
      && m.payload.has_managed_data
      && !syncing.contains(service)
    {
      let (from, to) = (&m.payload.from, &m.payload.to);
      remaining.push(StepPlan {
        items: step.items.clone(),
        title: format!("迁移 {service} 的数据 {from} → {to}"),
        step: Step::VolumeSync {
          service: service.clone(),
          from: from.clone(),
          to: to.clone(),
          instance_id: m.payload.instance_id.clone(),
        },
      });
    }
    remaining.push(step);
  }
  remaining
}

async fn require_retry_access(
  state: &AppState,
  auth: &Auth,
  original: &Run,
  steps: &[StepPlan],
  snap: &snapshot::Snapshot,
) -> Result<(), ApiError> {
  let core_server = crate::join::core_server_of(snap);
  if !original.plan_id.is_empty() {
    let stored = stored_plan(state, &original.plan_id).await?;
    let mut plan = stored.body.plan;
    let items: BTreeSet<_> =
      steps.iter().flat_map(|s| s.items.iter().copied()).collect();
    plan.items.retain(|item| {
      item.layer != Layer::Config && items.contains(&item.id)
    });
    let addresses: BTreeSet<_> =
      plan.items.iter().map(|item| item.address.clone()).collect();
    plan
      .needs_host
      .retain(|address| addresses.contains(address));
    let requirements =
      stored.body.host_requirements.map(|mut reqs| {
        reqs.retain(|req| addresses.contains(&req.address));
        reqs
      });
    host_access::require_plan_host(
      &plan,
      steps,
      requirements.as_deref(),
      &auth.perms,
      auth.human,
      &snap.world,
      core_server.as_deref(),
    )?;
  }
  for step in steps {
    match &step.step {
      Step::CoreBackup { .. } | Step::CleanupData { .. } => {
        return Err(ApiError::invalid("此任务不能续跑，请重新发起"));
      }
      Step::AgentUpgrade { .. }
      | Step::AgentUpgrades { .. }
      | Step::Prune { .. } => {
        auth.require(Perm::Admin).map_err(|e| e.0)?
      }
      Step::Restore { .. } => {
        auth.require(Perm::Confirm).map_err(|e| e.0)?
      }
      _ => {}
    }
    let deploy;
    let step = if let Step::Rebuild { service } = &step.step {
      deploy = Step::ServiceUp {
        service: service.clone(),
        instance_id: None,
        expect: None,
      };
      &deploy
    } else {
      &step.step
    };
    let target = HostTarget::PlanStep {
      step,
      current: &snap.world,
      desired: &snap.world,
    };
    let access = host_access::assess(target);
    let settings = access
      .server
      .as_ref()
      .and_then(|server| snap.world.servers.get(server))
      .map(|row| &row.settings);
    host_access::require_with(
      auth,
      target,
      settings,
      core_server.as_deref(),
    )
    .map_err(|e| e.0)?;
  }
  Ok(())
}

pub async fn retry_run(
  state: Arc<AppState>,
  auth: &Auth,
  id: &str,
  source: String,
) -> Result<ApplyResponse, ApiError> {
  auth.require(Perm::Apply).map_err(|e| e.0)?;
  let original = load_run_for(&state, auth, id).await?;
  require_retryable(&original)?;
  let guard = state
    .apply_lock
    .clone()
    .try_lock_owned()
    .map_err(|_| state.runs.busy_error())?;
  let (meta, scope_services) = {
    let id = id.to_string();
    state.db.call(move |c| {
      let row: Option<(String, Option<String>)> = c.query_row(
        "SELECT body,retry_meta FROM runs WHERE id=?1",
        [&id],
        |r| Ok((r.get(0)?,r.get(1)?)),
      ).optional().map_err(sql_err)?;
      let (body, meta) = row.ok_or_else(|| ApiError::not_found(format!("执行记录 {id} 不存在")))?;
      let stored: StoredRun = serde_json::from_str(&body).map_err(json_err)?;
      let other: Option<(String, String)> = c.query_row(
        "SELECT id,status FROM runs WHERE retry_of=?1 ORDER BY started_at DESC LIMIT 1",
        [&id], |r| Ok((r.get(0)?, r.get(1)?)),
      ).optional().map_err(sql_err)?;
      if let Some((other, status)) = other {
        let error = ApiError::new(ErrorCode::Conflict, format!("执行记录 {id} 已有续跑记录 {other}（{status}）"))
          .suggest(format!("wharf run show {other}"));
        return Err(if status == "failed" || status == "cancelled" {
          error.suggest(format!("wharf run retry {other}"))
        } else {
          error
        });
      }
      let meta = meta.ok_or_else(|| ApiError::invalid(format!("执行记录 {id} 没有可用的续跑信息"))
        .suggest("wharf plan"))?;
      Ok((serde_json::from_str::<RetryMeta>(&meta).map_err(json_err)?, stored.scope_services))
    }).await?
  };
  let steps = select_retry_steps(&original, &meta)?;
  let snap = snapshot::load(&state.db).await?;
  let steps = complete_migration_steps(steps, &snap);
  require_retry_access(&state, auth, &original, &steps, &snap)
    .await?;
  let run = Run {
    run_id: crate::world::new_id("r"),
    plan_id: original.plan_id.clone(),
    actor: Some(format_actor(auth)),
    retry_of: Some(id.to_string()),
    status: RunStatus::Running,
    started_at: Utc::now(),
    finished_at: None,
    steps: steps.iter().map(pending_run_step).collect(),
  };
  let run_id = run.run_id.clone();
  let stored_steps = steps.clone();
  let stored_run = run.clone();
  let scope = scope_services.clone();
  state
    .db
    .call_credentials(move |c, key| {
      meta.require_fresh(c, key)?;
      let next = RetryMeta {
        steps: stored_steps,
        offset: 0,
        ..meta
      };
      insert_task_run(c, &stored_run, scope.as_deref(), Some(&next))
    })
    .await?;
  let actor =
    crate::security_receipt::Actor::from_request((auth, source));
  spawn_run(state, run, scope_services, steps, Some(actor), guard);
  Ok(ApplyResponse { run_id })
}

#[test]
fn select_retry_steps_only_failed_and_skipped() {
  let steps: Vec<_> = ["a", "b", "c"]
    .into_iter()
    .map(|service| StepPlan {
      items: vec![],
      title: service.into(),
      step: Step::Rebuild {
        service: service.into(),
      },
    })
    .collect();
  let mut run = Run {
    run_id: "r1".into(),
    plan_id: "p1".into(),
    actor: None,
    retry_of: None,
    status: RunStatus::Failed,
    started_at: Utc::now(),
    finished_at: Some(Utc::now()),
    steps: steps.iter().map(pending_run_step).collect(),
  };
  run.steps[0].status = StepStatus::Done;
  run.steps[1].status = StepStatus::Failed;
  run.steps[2].status = StepStatus::Skipped;
  let meta = RetryMeta {
    steps,
    offset: 0,
    post_versions: BTreeMap::new(),
    post_instances: BTreeMap::new(),
    inputs: String::new(),
    account_refs: None,
    confirmed: vec![],
  };
  let selected = select_retry_steps(&run, &meta).unwrap();
  assert_eq!(
    selected
      .iter()
      .map(|s| s.title.as_str())
      .collect::<Vec<_>>(),
    ["b", "c"]
  );
}

#[tokio::test]
async fn run_retry_reruns_only_failed_and_skipped_and_rejects_stale()
{
  let state = crate::migrate::tests::seed_service(false).await;
  let auth = crate::host_access::tests::auth([Perm::Apply], false);
  let service = "notes".to_string();
  let restart = Step::ServiceRestart {
    service: service.clone(),
  };
  let steps: Vec<_> = [
    (restart.clone(), StepStatus::Done),
    (Step::ServiceStop { service }, StepStatus::Failed),
    (restart, StepStatus::Skipped),
  ]
  .into_iter()
  .map(|(step, status)| {
    (
      StepPlan {
        title: "操作".into(),
        items: vec![],
        step,
      },
      status,
    )
  })
  .collect();
  for id in ["r_first", "r_stale"] {
    let mut run = Run {
      run_id: id.into(),
      plan_id: String::new(),
      actor: None,
      retry_of: None,
      status: RunStatus::Failed,
      started_at: Utc::now(),
      finished_at: Some(Utc::now()),
      steps: vec![],
    };
    for (step, status) in &steps {
      let mut entry = pending_run_step(step);
      entry.status = *status;
      run.steps.push(entry);
    }
    let plans = steps.iter().map(|(s, _)| s.clone()).collect();
    let stored = run.clone();
    state
      .db
      .call_credentials(move |c, key| {
        let meta =
          RetryMeta::capture(c, key, (plans, 0), None, vec![])?;
        insert_task_run(c, &stored, None, Some(&meta))
      })
      .await
      .unwrap();
    persist(&state, &run, None).await.unwrap();
  }
  let calls = Arc::new(Mutex::new(vec![]));
  let recorded = calls.clone();
  state.hub.mock_agent("s2", false, move |op| {
    lock(&recorded).push(match op {
      AgentOp::ProjectStop { .. } => "stop",
      AgentOp::ProjectStart { .. } => "start",
      _ => panic!("意外请求"),
    });
    Ok(serde_json::json!(true))
  });
  let response =
    retry_run(state.clone(), &auth, "r_first", "测试".into())
      .await
      .unwrap();
  let run = tokio::time::timeout(Duration::from_secs(5), async {
    loop {
      let run = load_run(&state, &response.run_id).await.unwrap();
      if run.status != RunStatus::Running
        && state.apply_lock.try_lock().is_ok()
      {
        break run;
      }
      tokio::task::yield_now().await;
    }
  })
  .await
  .unwrap();
  assert_eq!(run.status, RunStatus::Succeeded);
  assert_eq!(run.retry_of.as_deref(), Some("r_first"));
  assert_eq!(run.actor.as_deref(), Some("令牌 test"));
  assert_eq!(*lock(&calls), ["stop", "stop", "start"]);
  state.db.call(|c| {
    c.execute("UPDATE resources SET version=version+1 WHERE kind='service' AND name='notes'", [])
      .map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  assert_eq!(
    retry_run(state, &auth, "r_stale", "测试".into())
      .await
      .unwrap_err()
      .code,
    ErrorCode::PlanStale
  );
}

#[tokio::test]
async fn retry_reinserts_volume_sync_after_source_restarts() {
  let state = crate::migrate::tests::seed_service(false).await;
  crate::migrate::tests::seed_migration(&state, "pending", false)
    .await;
  let snap = snapshot::load(&state.db).await.unwrap();
  let up = StepPlan {
    items: vec![1],
    title: "部署".into(),
    step: Step::ServiceUp {
      service: "notes".into(),
      instance_id: None,
      expect: None,
    },
  };
  let steps = complete_migration_steps(vec![up], &snap);
  assert!(
    matches!(&steps[0].step, Step::VolumeSync { from, to, .. } if from == "s1" && to == "s2")
  );
  assert!(matches!(steps[1].step, Step::ServiceUp { .. }));
}
