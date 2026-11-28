use super::{
  ApiError, AppState, BTreeSet, ErrorCode, Plan, Run, Step, json_err,
  lock, sql_err, stored_plan,
};
use crate::{auth::Auth, token_scope};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct StoredRun {
  #[serde(flatten)]
  pub(super) run: Run,
  // 空列表代表非服务级任务，缺少字段代表没有记录归属的旧任务。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(super) scope_services: Option<Vec<String>>,
}

pub(super) fn encode(
  run: &Run,
  scope_services: Option<&[String]>,
) -> Result<String, ApiError> {
  serde_json::to_string(&StoredRun {
    run: run.clone(),
    scope_services: scope_services.map(<[String]>::to_vec),
  })
  .map_err(json_err)
}

pub(super) fn step_services(step: &Step) -> Vec<String> {
  match step {
    Step::Backup { service, .. }
    | Step::BackupMove {
      service,
      is_core: false,
      ..
    }
    | Step::Restore { service, .. }
    | Step::Rebuild { service }
    | Step::ServiceRestart { service, .. }
    | Step::ServiceStop { service }
    | Step::CrashStop { service, .. }
    | Step::ResumeProtected { service, .. }
    | Step::ServiceUp { service, .. }
    | Step::ServiceDown { service, .. }
    | Step::CleanupData { service, .. }
    | Step::VolumeSync { service, .. } => vec![service.clone()],
    Step::RenameService { job } => job.services.clone(),
    Step::CloneData { job } => {
      vec![job.source.clone(), job.target.clone()]
    }
    Step::AdoptData { job, .. } => vec![job.service.clone()],
    Step::CleanupArchive { entry, .. } => {
      entry.service.iter().cloned().collect()
    }
    _ => vec![],
  }
}

pub async fn load_plan_for(
  state: &AppState,
  auth: &Auth,
  id: &str,
) -> Result<Plan, ApiError> {
  let stored = match stored_plan(state, id).await {
    Err(error)
      if error.code == ErrorCode::NotFound
        && auth.services.is_some() =>
    {
      return Err(token_scope::forbidden(
        &auth.name,
        auth.services.as_ref().unwrap(),
        "",
      ));
    }
    result => result?,
  };
  if let Some(allowed) = &auth.services {
    token_scope::require_plan(
      auth,
      &stored.body.plan,
      &stored.body.route_effects,
    )
    .map_err(|_| token_scope::forbidden(&auth.name, allowed, ""))?;
  }
  Ok(stored.body.plan)
}

pub async fn list_plans(
  state: &AppState,
  auth: &Auth,
  pending: bool,
  limit: u32,
) -> Result<Vec<wharf_api_types::plan::PlanSummary>, ApiError> {
  use super::StoredPlanBody;
  use wharf_api_types::plan::{PlanStatus, PlanSummary};

  let services = auth.services.clone();
  let limit = limit.clamp(1, 100) as usize;
  let now = chrono::Utc::now();
  state.db.call(move |c| {
    let mut stmt = c.prepare(
      "SELECT status, body FROM plans WHERE NOT ?1 OR (status = 'pending' AND expires_at > ?2)
       ORDER BY created_at DESC, id DESC"
    ).map_err(sql_err)?;
    let mut rows = stmt.query(params![pending, now.timestamp_millis()]).map_err(sql_err)?;
    let mut summaries = Vec::new();
    while summaries.len() < limit {
      let Some(row) = rows.next().map_err(sql_err)? else { break };
      let status: String = row.get(0).map_err(sql_err)?;
      let body: String = row.get(1).map_err(sql_err)?;
      let Ok(StoredPlanBody { plan, route_effects, .. }) = serde_json::from_str(&body) else {
        tracing::warn!("跳过无法读取的旧计划");
        continue;
      };
      if services.as_ref().is_some_and(|services| plan.items.is_empty() || token_scope::check_plan_scope(services, &plan, &route_effects).is_err()) {
        continue;
      }
      let status = super::persisted_plan_status(&status, &plan, now);
      let mut seen = BTreeSet::new();
      let addresses = plan.items.iter().filter_map(|item| {
        seen.insert(&item.address).then_some(item.address.clone())
      }).take(20).collect();
      summaries.push(PlanSummary {
        plan_id: plan.plan_id, status, created_at: plan.created_at, expires_at: plan.expires_at,
        expires_in_secs: if status == PlanStatus::Pending { (plan.expires_at - now).num_seconds() } else { 0 },
        note: plan.note, item_count: plan.items.len(), needs_confirm: plan.needs_confirm, addresses,
      });
    }
    Ok(summaries)
  }).await
}

pub async fn run_in_scope(
  state: &AppState,
  services: &BTreeSet<String>,
  run: &Run,
  scope_services: Option<&[String]>,
) -> bool {
  if run.plan_id.is_empty() {
    return scope_services.is_some_and(|names| {
      !names.is_empty()
        && names.iter().all(|name| services.contains(name))
    });
  }
  stored_plan(state, &run.plan_id).await.is_ok_and(|stored| {
    token_scope::check_plan_scope(
      services,
      &stored.body.plan,
      &stored.body.route_effects,
    )
    .is_ok()
  })
}

pub async fn load_run(
  state: &AppState,
  id: &str,
) -> Result<Run, ApiError> {
  let mut run = load_stored_run(state, id).await?.run;
  crate::log_redact::redact_run(&mut run);
  Ok(run)
}

pub async fn load_run_for(
  state: &AppState,
  auth: &Auth,
  id: &str,
) -> Result<Run, ApiError> {
  let Some(allowed) = &auth.services else {
    return load_run(state, id).await;
  };
  let stored = match load_stored_run(state, id).await {
    Err(error) if error.code == ErrorCode::NotFound => {
      return Err(token_scope::forbidden(&auth.name, allowed, ""));
    }
    result => result?,
  };
  if !run_in_scope(
    state,
    allowed,
    &stored.run,
    stored.scope_services.as_deref(),
  )
  .await
  {
    return Err(token_scope::forbidden(&auth.name, allowed, ""));
  }
  let mut run = stored.run;
  crate::log_redact::redact_run(&mut run);
  Ok(run)
}

pub(super) async fn persist(
  state: &AppState,
  run: &Run,
  scope_services: Option<&[String]>,
) -> Result<(), ApiError> {
  let id = run.run_id.clone();
  let status = serde_json::to_value(run.status)
    .ok()
    .and_then(|v| v.as_str().map(str::to_string))
    .unwrap_or_default();
  let body = encode(run, scope_services)?;
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

async fn load_stored_run(
  state: &AppState,
  id: &str,
) -> Result<StoredRun, ApiError> {
  if let Some(active) = lock(&state.runs.active).get(id) {
    return Ok(StoredRun {
      run: lock(&active.run).clone(),
      scope_services: active.scope_services.clone(),
    });
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

/// 最近的执行记录（不含日志）。
pub async fn list_runs(
  state: &AppState,
  auth: &Auth,
  limit: u32,
  status: Option<wharf_api_types::plan::RunStatus>,
) -> Result<Vec<Run>, ApiError> {
  let status = status
    .map(serde_json::to_value)
    .transpose()
    .map_err(json_err)?;
  let status =
    status.and_then(|value| value.as_str().map(str::to_string));
  let bodies: Vec<String> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT body FROM runs WHERE (?2 IS NULL OR status = ?2) ORDER BY started_at DESC LIMIT ?1",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![limit, status], |r| r.get(0))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  let mut runs = Vec::new();
  for body in bodies {
    let stored: StoredRun =
      serde_json::from_str(&body).map_err(json_err)?;
    if let Some(allowed) = &auth.services
      && !run_in_scope(
        state,
        allowed,
        &stored.run,
        stored.scope_services.as_deref(),
      )
      .await
    {
      continue;
    }
    let mut run = stored.run;
    if let Some(live) = state.runs.get(&run.run_id) {
      run = live;
    }
    for step in &mut run.steps {
      step.log.clear();
    }
    crate::log_redact::redact_run(&mut run);
    runs.push(run);
  }
  Ok(runs)
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::plan::RunStatus;

  #[tokio::test]
  async fn list_runs_filters_failed_and_keeps_actor() {
    let state = crate::rules::tests::test_state();
    let auth = crate::host_access::tests::auth(
      [wharf_api_types::view::Perm::Read],
      false,
    );
    for (id, status, sql_status, at) in [
      ("r1", RunStatus::Failed, "failed", 1),
      ("r2", RunStatus::Succeeded, "succeeded", 2),
    ] {
      let run = Run {
        run_id: id.into(),
        plan_id: String::new(),
        status,
        actor: Some("令牌 fixture".into()),
        retry_of: None,
        started_at: chrono::Utc::now(),
        finished_at: None,
        steps: vec![],
      };
      let body = encode(&run, None).unwrap();
      state.db.call(move |c| {
        c.execute("INSERT INTO runs (id,plan_id,status,body,started_at) VALUES (?1,'',?2,?3,?4)",
          params![id, sql_status, body, at]).map_err(sql_err)?;
        Ok(())
      }).await.unwrap();
    }
    let found = list_runs(&state, &auth, 1, Some(RunStatus::Failed))
      .await
      .unwrap();
    assert_eq!(found[0].run_id, "r1");
    assert_eq!(found[0].actor.as_deref(), Some("令牌 fixture"));
  }

  #[tokio::test]
  async fn scoped_token_cannot_view_or_cancel_foreign_run() {
    let state = AppState {
      db: crate::db::Db::memory(),
      hub: Default::default(),
      key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]).into(),
      runs: Default::default(),
      locks: Default::default(),
      public_url: None,
      agent_image: String::new(),
      listen_port: 7700,
      data_dir: Default::default(),
      downloads: Default::default(),
      safe_mode: Default::default(),
      resumed_at: Default::default(),
      edge_syncing: Default::default(),
      cleanup_cache: Default::default(),
    };
    let mut auth = crate::host_access::tests::auth(
      [wharf_api_types::view::Perm::Apply],
      false,
    );
    auth.services = Some(BTreeSet::from(["blog".into()]));
    for (id, step, visible) in [
      (
        "foreign",
        Step::Rebuild {
          service: "other".into(),
        },
        false,
      ),
      (
        "global",
        Step::CoreBackup {
          options: Default::default(),
          user_key: None,
          target: None,
          owner_secret: None,
        },
        false,
      ),
      (
        "own",
        Step::Rebuild {
          service: "blog".into(),
        },
        true,
      ),
    ] {
      let run = Run {
        actor: None,
        retry_of: None,
        run_id: id.into(),
        plan_id: String::new(),
        status: RunStatus::Running,
        started_at: chrono::Utc::now(),
        finished_at: None,
        steps: vec![],
      };
      let services = step_services(&step);
      let body = encode(&run, Some(&services)).unwrap();
      state.db.call(move |c| {
        c.execute("INSERT INTO runs (id, plan_id, status, body, started_at) VALUES (?1, '', 'running', ?2, 1)",
          params![id, body]).map_err(sql_err)?;
        Ok(())
      }).await.unwrap();
      let result = load_run_for(&state, &auth, id).await;
      assert_eq!(result.is_ok(), visible);
      if !visible {
        assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
      }
    }
    assert_eq!(
      list_runs(&state, &auth, 20, None).await.unwrap()[0].run_id,
      "own"
    );
  }
}

#[tokio::test]
async fn plan_list_show_and_confirm_details() {
  use crate::rules::tests::test_state;
  use serde_json::json;

  let state = test_state();
  let now = chrono::Utc::now();
  let mut plan = serde_json::from_value::<Plan>(json!({
    "plan_id":"p_fixture", "status":"pending", "created_at":now, "expires_at": now + chrono::Duration::minutes(5),
    "base_versions":{}, "items":[{"id":1,"address":"service/app","layer":"config",
      "action":"delete","reason":"清理数据","impacts":["remove"]}],
    "needs_confirm":["service/app"],
  })).unwrap();
  state.db.call(move |c| {
    for (id, service, expires_at) in [
      ("p_fixture", "app", now + chrono::Duration::minutes(5)),
      ("p_other", "other", now + chrono::Duration::minutes(5)),
      ("p_expired", "app", now - chrono::Duration::minutes(5)),
    ] {
      plan.expires_at = expires_at;
      plan.plan_id = id.into();
      plan.items[0].address = format!("service/{service}");
      c.execute("INSERT INTO plans (id,status,body,steps,writes,created_at,expires_at)
        VALUES (?1,'pending',?2,'[]','[]',?3,?4)",
        params![id, serde_json::to_string(&plan).map_err(json_err)?, plan.created_at.timestamp_millis(), plan.expires_at.timestamp_millis()],
      ).map_err(sql_err)?;
    }
    Ok(())
  }).await.unwrap();
  let auth = Auth {
    name: "reader".into(),
    perms: [wharf_api_types::view::Perm::Read].into(),
    services: Some(["app".into()].into()),
    allowed_from: vec![],
    expires_at: None,
    human: false,
  };
  let plans = list_plans(&state, &auth, true, 1).await.unwrap();
  assert_eq!(plans[0].plan_id, "p_fixture");
  let mut plan =
    load_plan_for(&state, &auth, "p_fixture").await.unwrap();
  assert_eq!(plan.plan_id, "p_fixture");
  assert!(load_plan_for(&state, &auth, "p_other").await.is_err());
  plan.items[0].host_access.push("宿主机数据".into());
  let details = wharf_api_types::plan::confirm_details(
    &plan,
    &plan.needs_confirm.iter().collect::<Vec<_>>(),
  );
  assert_eq!(details["plan_id"], "p_fixture");
  assert_eq!(
    details["items"][0]["host_access"],
    json!(["宿主机数据"])
  );

  use wharf_api_types::plan::PlanStatus;
  let plans = list_plans(&state, &auth, false, 10).await.unwrap();
  let expired =
    plans.iter().find(|p| p.plan_id == "p_expired").unwrap();
  assert_eq!(expired.status, PlanStatus::Expired);
  let shown =
    load_plan_for(&state, &auth, "p_expired").await.unwrap();
  assert_eq!(shown.status, expired.status);
}
