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
  #[serde(default)]
  verify_before_dns: Option<bool>,
}

impl RetryMeta {
  pub(super) fn capture(
    c: &rusqlite::Connection,
    key: &db::CredentialsKey,
    (steps, offset): (Vec<StepPlan>, usize),
    account_refs: Option<BTreeSet<String>>,
    confirmed: Vec<String>,
    verify_before_dns: Option<bool>,
  ) -> Result<Self, ApiError> {
    Ok(Self {
      steps,
      offset,
      post_versions: db::versions(c)?,
      post_instances: db::service_instances(c)?,
      inputs: db::inputs(c, key, account_refs.as_ref())?,
      account_refs,
      confirmed,
      verify_before_dns,
    })
  }

  fn require_fresh(
    &self,
    c: &rusqlite::Connection,
    key: &db::CredentialsKey,
    from_plan: bool,
  ) -> Result<(), ApiError> {
    let changed = if from_plan {
      !self.is_fresh(c, key)?
    } else {
      let instances = db::service_instances(c)?;
      self
        .steps
        .iter()
        .flat_map(|step| run_scope::step_services(&step.step))
        .any(|service| {
          let key = format!("service/{service}");
          self.post_instances.get(&key) != instances.get(&key)
        })
    };
    if changed {
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

  fn is_fresh(
    &self,
    c: &rusqlite::Connection,
    key: &db::CredentialsKey,
  ) -> Result<bool, ApiError> {
    Ok(
      self.post_versions == db::versions(c)?
        && self.post_instances == db::service_instances(c)?
        && self.inputs
          == db::inputs(c, key, self.account_refs.as_ref())?,
    )
  }
}

// 只把当前事务的变化计入续跑基线，保留之前发生的外部漂移。
pub(crate) fn record_changes<T>(
  c: &mut rusqlite::Connection,
  key: &db::CredentialsKey,
  run_id: &str,
  write: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let before: Option<String> = tx
    .query_row(
      "SELECT retry_meta FROM runs WHERE id = ?1 AND plan_id <> '' AND retry_meta IS NOT NULL",
      [run_id],
      |r| r.get(0),
    )
    .optional()
    .map_err(sql_err)?;
  let before = before
    .map(|raw| {
      serde_json::from_str::<RetryMeta>(&raw).map_err(json_err)
    })
    .transpose()?;
  let fresh = before
    .as_ref()
    .map(|meta| meta.is_fresh(&tx, key))
    .transpose()?
    .unwrap_or(false);
  let result = write(&tx)?;
  if let Some(mut meta) = before.filter(|_| fresh) {
    meta.post_versions = db::versions(&tx)?;
    meta.post_instances = db::service_instances(&tx)?;
    meta.inputs = db::inputs(&tx, key, meta.account_refs.as_ref())?;
    tx.execute(
      "UPDATE runs SET retry_meta = ?2 WHERE id = ?1",
      params![
        run_id,
        serde_json::to_string(&meta).map_err(json_err)?
      ],
    )
    .map_err(sql_err)?;
  }
  tx.commit().map_err(sql_err)?;
  Ok(result)
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
          bwlimit_kbps:
            wharf_api_types::resources::effective_bwlimit_kbps(
              None,
              &[from, to].map(|server| {
                snap
                  .world
                  .servers
                  .get(server)
                  .and_then(|row| row.settings.bg_bwlimit_kbps())
              }),
            ),
          explicit_bwlimit: false,
          shared_data: crate::shared_volumes::consumers_on(
            &snap.world,
            service,
            to,
          )
          .next()
          .is_some(),
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
  confirmed: &[String],
) -> Result<(), ApiError> {
  let core_server = crate::join::core_server_of(snap);
  if !original.plan_id.is_empty() {
    let stored = stored_plan(state, &original.plan_id).await?;
    let mut plan = stored.body.plan;
    let items: BTreeSet<_> =
      steps.iter().flat_map(|s| s.items.iter().copied()).collect();
    let needs_confirm: BTreeSet<_> = plan
      .items
      .iter()
      .filter(|item| item.needs_confirm())
      .filter(|item| {
        if items.contains(&item.id) {
          return true;
        }
        if item.layer == Layer::Config
          && let Some(host) = item.address.strip_prefix("route/")
          && let Some(route) = snap.world.routes.get(host)
        {
          let gateways = snap.world.route_gateways(&route.spec);
          return steps.iter().any(|s| match &s.step {
            Step::GatewaySync { gateway, .. } => gateways.contains(&gateway.as_str()),
            Step::DnsUpsert { hostname, .. } => hostname == host,
            _ => false,
          });
        }
        // 非托管卷的警告是独立计划项，关联到同步和目标机部署。
        item.layer == Layer::Volume
          && !stored.steps.iter().any(|s| s.items.contains(&item.id))
          && item.address.strip_prefix("service/").is_some_and(|name| {
            steps.iter().any(|s| {
              matches!(&s.step, Step::VolumeSync { service, .. } | Step::ServiceUp { service, .. } if service == name)
            })
          })
      })
      .map(|item| item.address.clone())
      .collect();
    confirm::require(
      &plan.plan_id,
      &needs_confirm.into_iter().collect::<Vec<_>>(),
      confirmed,
      auth.has(Perm::Confirm),
    )?;
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
      Step::BackupMove {
        is_core,
        replace_target,
        ..
      } => {
        if *is_core {
          auth.require(Perm::Admin).map_err(|e| e.0)?;
        }
        if *replace_target {
          auth.require(Perm::Confirm).map_err(|e| e.0)?;
        }
      }
      Step::CoreBackup { .. }
      | Step::CleanupData { .. }
      | Step::CleanupArchive { .. } => {
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
        refresh_files_from: None,
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
  let (meta, scope_services) = {
    let id = id.to_string();
    state
      .db
      .call(move |c| {
        let row: Option<(String, Option<String>)> = c
          .query_row(
            "SELECT body,retry_meta FROM runs WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
          )
          .optional()
          .map_err(sql_err)?;
        let (body, meta) = row.ok_or_else(|| {
          ApiError::not_found(format!("执行记录 {id} 不存在"))
        })?;
        let stored: StoredRun =
          serde_json::from_str(&body).map_err(json_err)?;
        let meta = meta.ok_or_else(|| {
          ApiError::invalid(format!(
            "执行记录 {id} 没有可用的续跑信息"
          ))
          .suggest("wharf plan")
        })?;
        Ok((
          serde_json::from_str::<RetryMeta>(&meta)
            .map_err(json_err)?,
          stored.scope_services,
        ))
      })
      .await?
  };
  let steps = select_retry_steps(&original, &meta)?;
  let guard = match steps.as_slice() {
    [step] if original.plan_id.is_empty() => {
      lock_task(&state, &step.step, "续跑").await?
    }
    _ => {
      let services = steps
        .iter()
        .flat_map(|p| run_scope::step_services(&p.step))
        .chain(scope_services.iter().flatten().cloned());
      state.locks.acquire(LockSpec::apply(services), "续跑")?
    }
  };
  let snap = snapshot::load(&state.db).await?;
  let steps = complete_migration_steps(steps, &snap);
  require_retry_access(
    &state,
    auth,
    &original,
    &steps,
    &snap,
    &meta.confirmed,
  )
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
  let verify = meta.verify_before_dns;
  let stored_steps = steps.clone();
  let stored_run = run.clone();
  let scope = scope_services.clone();
  let id = id.to_string();
  state
    .db
    .call_credentials(move |c, key| {
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
      meta.require_fresh(c, key, !stored_run.plan_id.is_empty())?;
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
  drop(spawn_run(
    state,
    run,
    scope_services,
    steps,
    (Some(actor), verify),
    guard,
  ));
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
    verify_before_dns: None,
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
  let mut scoped =
    crate::host_access::tests::auth([Perm::Apply], false);
  scoped.services = Some(BTreeSet::from(["notes".into()]));
  let service = "notes".to_string();
  let restart = Step::ServiceRestart {
    service: service.clone(),
    container: None,
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
  let calls = Arc::new(Mutex::new(vec![]));
  let recorded = calls.clone();
  state.hub.mock_agent("s2", false, move |op| {
    if matches!(op, AgentOp::ResolveImages(_)) {
      return Ok(serde_json::json!([{"image": "fixture:1", "digest": format!("sha256:{}", "a".repeat(64))}]));
    }
    if matches!(op, AgentOp::ProjectStatus { .. }) {
      return Ok(if lock(&recorded).contains(&"start") {
        serde_json::json!([{"project":"notes","containers":[{"name":"notes-1","service":"notes","state":"running"}]}])
      } else {
        serde_json::json!([])
      });
    }
    lock(&recorded).push(match op {
      AgentOp::ProjectStop { .. } => "stop",
      AgentOp::ProjectStart { .. } => "start",
      _ => panic!("意外请求"),
    });
    Ok(serde_json::json!(true))
  });
  let plan = crate::planner::make_plan(
    &state,
    wharf_api_types::plan::PlanRequest::default(),
  )
  .await
  .unwrap();
  crate::planner::save(&state, &plan).await.unwrap();
  for id in ["r_first", "r_stale"] {
    let mut run = Run {
      run_id: id.into(),
      plan_id: if id == "r_stale" {
        plan.plan.plan_id.clone()
      } else {
        String::new()
      },
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
          RetryMeta::capture(c, key, (plans, 0), None, vec![], None)?;
        insert_task_run(
          c,
          &stored,
          Some(&["notes".into()]),
          Some(&meta),
        )
      })
      .await
      .unwrap();
    persist(&state, &run, Some(&["notes".into()]))
      .await
      .unwrap();
  }
  let backup = state
    .locks
    .acquire(LockSpec::Backup("notes".into()), "备份")
    .unwrap();
  assert_eq!(
    retry_run(state.clone(), &scoped, "r_first", "测试".into())
      .await
      .unwrap_err()
      .code,
    ErrorCode::Busy
  );
  assert!(lock(&calls).is_empty());
  drop(backup);
  let response =
    retry_run(state.clone(), &scoped, "r_first", "测试".into())
      .await
      .unwrap();
  let run = tokio::time::timeout(Duration::from_secs(5), async {
    loop {
      let run = load_run(&state, &response.run_id).await.unwrap();
      if run.status != RunStatus::Running
        && state
          .locks
          .acquire(LockSpec::apply(["notes".into()]), "测试")
          .is_ok()
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
async fn retry_requires_confirm_only_for_remaining_risky_steps() {
  use wharf_api_types::{plan::PlanRequest, spec::Change};
  let state = crate::migrate::tests::seed_service(false).await;
  let mut plan = crate::planner::make_plan(
    &state,
    PlanRequest {
      changes: vec![Change::RemoveService {
        name: "notes".into(),
        purge_data: true,
      }],
      ..Default::default()
    },
  )
  .await
  .unwrap();
  let purge = plan
    .steps
    .iter()
    .find(|s| {
      matches!(
        s.step,
        Step::ServiceDown {
          purge_data: true,
          ..
        }
      )
    })
    .unwrap()
    .clone();
  let safe = StepPlan {
    items: vec![],
    title: "停止其他服务".into(),
    step: Step::ServiceStop {
      service: "other".into(),
    },
  };
  plan.steps = vec![purge, safe.clone()];
  crate::planner::save(&state, &plan).await.unwrap();
  let mut run = Run {
    run_id: "r_purge".into(),
    plan_id: plan.plan.plan_id,
    status: RunStatus::Failed,
    started_at: Utc::now(),
    finished_at: Some(Utc::now()),
    actor: None,
    retry_of: None,
    steps: plan.steps.iter().map(pending_run_step).collect(),
  };
  run.steps[0].status = StepStatus::Failed;
  run.steps[1].status = StepStatus::Skipped;
  let recorded = run.clone();
  let confirmed = plan.plan.needs_confirm;
  assert_eq!(confirmed, ["service/notes"]);
  let approved = confirmed.clone();
  let steps = plan.steps;
  state
    .db
    .call_credentials(move |c, key| {
      let meta =
        RetryMeta::capture(c, key, (steps, 0), None, approved, None)?;
      insert_task_run(c, &recorded, None, Some(&meta))
    })
    .await
    .unwrap();
  persist(&state, &run, None).await.unwrap();
  let auth = crate::host_access::tests::auth([Perm::Apply], false);
  assert_eq!(
    retry_run(state.clone(), &auth, &run.run_id, "测试".into())
      .await
      .unwrap_err()
      .code,
    ErrorCode::Forbidden,
  );
  let snap = snapshot::load(&state.db).await.unwrap();
  require_retry_access(
    &state,
    &auth,
    &run,
    &[safe],
    &snap,
    &confirmed,
  )
  .await
  .unwrap();
}

#[tokio::test]
async fn retry_baseline_tracks_run_writes_without_accepting_external_drift()
 {
  let state = crate::migrate::tests::seed_service(false).await;
  state
    .db
    .call_credentials(|c, key| {
      let run = Run {
        run_id: "r_import".into(),
        plan_id: "p_import".into(),
        status: RunStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        actor: None,
        retry_of: None,
        steps: vec![],
      };
      let load =
        |c: &rusqlite::Connection| -> Result<RetryMeta, ApiError> {
          let meta: String = c
            .query_row(
              "SELECT retry_meta FROM runs WHERE id=?1",
              [&run.run_id],
              |r| r.get(0),
            )
            .map_err(sql_err)?;
          serde_json::from_str(&meta).map_err(json_err)
        };
      let meta =
        RetryMeta::capture(c, key, (vec![], 0), None, vec![], None)?;
      insert_task_run(c, &run, None, Some(&meta))?;
      record_changes(c, key, &run.run_id, |tx| {
        db::finish_import(tx, "notes", "s2", &Default::default(), &[])
      })?;
      record_changes(c, key, &run.run_id, |tx| {
        db::ensure_secret(
          tx,
          key,
          crate::egress::TOKEN_SECRET,
          now_ms(),
        )
      })?;
      assert!(load(c)?.require_fresh(c, key, true).is_ok());
      db::set_reach(
        c,
        &[("s1".into(), "s2".into(), true)],
        now_ms(),
      )?;
      record_changes(c, key, &run.run_id, |tx| {
        db::ensure_scoped_secret(
          tx,
          key,
          crate::link::TOKEN_PREFIX,
          "gw",
          now_ms(),
        )
      })?;
      assert_eq!(
        load(c)?.require_fresh(c, key, true).unwrap_err().code,
        ErrorCode::PlanStale
      );
      Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn retry_reinserts_volume_sync_after_source_restarts() {
  let state = crate::migrate::tests::seed_service(false).await;
  crate::migrate::tests::seed_migration(&state, "pending", false)
    .await;
  let mut snap = snapshot::load(&state.db).await.unwrap();
  snap
    .world
    .servers
    .get_mut("s1")
    .unwrap()
    .settings
    .bg_bwlimit = Some("3M".into());
  snap
    .world
    .servers
    .get_mut("s2")
    .unwrap()
    .settings
    .bg_bwlimit = Some("10M".into());
  let up = StepPlan {
    items: vec![1],
    title: "部署".into(),
    step: Step::ServiceUp {
      service: "notes".into(),
      instance_id: None,
      expect: None,
      refresh_files_from: None,
    },
  };
  let steps = complete_migration_steps(vec![up], &snap);
  assert!(
    matches!(&steps[0].step, Step::VolumeSync { from, to, bwlimit_kbps: Some(3072), .. } if from == "s1" && to == "s2")
  );
  assert!(matches!(steps[1].step, Step::ServiceUp { .. }));
}
