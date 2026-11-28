use super::*;

use wharf_api_types::{
  agent::ProjectState,
  plan::RunStatus,
  spec::RestartSchedule,
  view::{RestartScheduleRun, RestartScheduleView},
};

#[derive(
  Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize,
)]
pub(crate) struct RestartIdentity {
  instance_id: String,
  revision: String,
}

type Candidate = (String, RestartSchedule, RestartIdentity, i64);

fn candidates(
  c: &rusqlite::Connection,
  name: Option<&str>,
) -> Result<Vec<Candidate>, ApiError> {
  let mut stmt = c.prepare(
    "SELECT name, json_extract(spec, '$.restart_schedule'),
            json_extract(meta, '$.instance_id'), json_extract(meta, '$.restart_revision'),
            json_extract(meta, '$.restart_since')
     FROM resources WHERE kind = 'service' AND (?1 IS NULL OR name = ?1)
       AND json_type(spec, '$.restart_schedule') = 'object'
       AND json_type(meta, '$.restart_revision') = 'text'",
  ).map_err(sql_err)?;
  let rows = stmt
    .query_map([name], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, String>(1)?,
        RestartIdentity {
          instance_id: r.get(2)?,
          revision: r.get(3)?,
        },
        r.get(4)?,
      ))
    })
    .map_err(sql_err)?;
  rows
    .map(|row| {
      let (name, spec, identity, since) = row.map_err(sql_err)?;
      Ok((
        name,
        serde_json::from_str(&spec).map_err(db::json_err)?,
        identity,
        since,
      ))
    })
    .collect()
}

impl RestartIdentity {
  fn key(&self) -> String {
    format!("@restart/{}/{}", self.instance_id, self.revision)
  }
}

pub(crate) fn validate(
  spec: &RestartSchedule,
) -> Result<Cron, ApiError> {
  let cron = Cron::parse(&spec.cron).map_err(|_| {
    ApiError::invalid("重启时间表须为五段 cron")
      .with_hint("例如 0 4 * * *")
  })?;
  if spec
    .catch_up_mins
    .is_some_and(|mins| !(1..=1440).contains(&mins))
  {
    return Err(ApiError::invalid(
      "重启补跑窗口须在 1 到 1440 分钟之间",
    ));
  }
  Ok(cron)
}

pub(crate) async fn show(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<RestartScheduleView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  Ok(Json(state.db.call(move |c| {
    let exists = c.query_row("SELECT EXISTS(SELECT 1 FROM resources WHERE kind='service' AND name=?1)",
      [&name], |row| row.get::<_, bool>(0)).map_err(sql_err)?;
    if !exists {
      return Err(crate::api::service_not_found(&name));
    }
    let Some((_, spec, identity, _)) = candidates(c, Some(&name))?.pop() else {
      return Ok(RestartScheduleView::default());
    };
    let cron = validate(&spec)?.with_offset(crate::config_api::offset(c)?);
    let last = c.query_row(
      "SELECT status, trigger, started_at, ended_at, COALESCE(output, '')
       FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT 1",
      [identity.key()],
      |r| {
        let output = r.get::<_, String>(4)?;
        let detail = serde_json::from_str::<serde_json::Value>(&output).ok();
        Ok(RestartScheduleRun {
          status: dec(&r.get::<_, String>(0)?),
          trigger: r.get(1)?,
          due_at: to_time(r.get(2)?),
          ended_at: r.get::<_, Option<i64>>(3)?.map(to_time),
          run_id: detail.as_ref().and_then(|v| v["run_id"].as_str()).map(str::to_owned),
          detail: detail.as_ref().and_then(|v| v["detail"].as_str()).map_or(output, str::to_owned),
        })
      },
    ).optional().map_err(sql_err)?;
    Ok(RestartScheduleView { spec: Some(spec), next_at: cron.next_after(Utc::now()), last })
  }).await?))
}

fn due_for(
  cron: &Cron,
  spec: &RestartSchedule,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
  resumed: DateTime<Utc>,
  since: i64,
) -> Option<(DateTime<Utc>, &'static str)> {
  let due = cron.prev_at_or_before(
    until,
    spec.catch_up_mins.unwrap_or_else(|| {
      (until - after).num_minutes().clamp(0, 1440) as u32
    }),
  )?;
  if due <= resumed || due.timestamp_millis() < since {
    return None;
  }
  if due > after {
    Some((due, "schedule"))
  } else {
    spec.catch_up_mins.map(|_| (due, "catch_up"))
  }
}

pub(super) async fn tick(
  state: &Arc<AppState>,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
  resumed: DateTime<Utc>,
  offset: chrono::FixedOffset,
) -> Result<(), ApiError> {
  let rows = state.db.call(|c| candidates(c, None)).await?;
  if rows.is_empty() {
    return Ok(());
  }
  let snap = snapshot::load(&state.db).await?;
  for (service, spec, identity, since) in rows {
    let cron = validate(&spec)?.with_offset(offset);
    let Some((due, trigger)) =
      due_for(&cron, &spec, after, until, resumed, since)
    else {
      continue;
    };
    let stopped = snap
      .world
      .services
      .get(&service)
      .is_some_and(|row| row.spec.stopped);
    if !stopped
      && spec.catch_up_mins.is_some()
      && exec_target(&snap, &service)
        .is_ok_and(|server| !state.hub.is_online(server))
    {
      continue;
    }
    let key = identity.key();
    let Some(guard) = RunGuard::acquire(&key) else {
      continue;
    };
    if scheduled_since(state, &key, due).await? {
      continue;
    }
    let state = state.clone();
    tokio::spawn(async move {
      if let Err(error) =
        execute(&state, &service, identity, due, trigger, guard).await
      {
        tracing::warn!("定时重启 {service}：{error}");
      }
    });
  }
  Ok(())
}

async fn execute(
  state: &Arc<AppState>,
  service: &str,
  identity: RestartIdentity,
  due: DateTime<Utc>,
  trigger: &str,
  _guard: RunGuard,
) -> Result<(), ApiError> {
  let title = format!("定时重启 {service}");
  let key = identity.key();
  let step = crate::planner::Step::ServiceRestart {
    service: service.into(),
    container: None,
    scheduled: Some(identity.clone()),
  };
  let guard = crate::apply::lock_task(state, &step, &title).await;
  if state.is_safe_mode() {
    return Ok(());
  }
  let name = service.to_string();
  let Some((_, spec, current, _)) = state
    .db
    .call(move |c| candidates(c, Some(&name)))
    .await?
    .pop()
  else {
    return Ok(());
  };
  if current.key() != key {
    return Ok(());
  }
  let snap = snapshot::load(&state.db).await?;
  let result = async {
    let guard =
      guard.map_err(|e| (TaskStatus::Skipped, e.message))?;
    let cancel = CancellationToken::new();
    ready(state, &snap, service, &identity, &cancel)
      .await
      .map_err(|error| {
        let status = if error.code == ErrorCode::Conflict
          && (error.hint.is_none()
            || (spec.skip_if_stopped
              && error.hint.as_deref().is_some_and(|s| {
                s.starts_with("检查 wharf service show")
              }))) {
          TaskStatus::Skipped
        } else {
          TaskStatus::Failed
        };
        (status, error.message)
      })?;
    Ok(guard)
  }
  .await;
  if let Err((status, detail)) = result.as_ref() {
    if spec.catch_up_mins.is_some()
      && *status == TaskStatus::Failed
      && exec_target(&snap, service)
        .is_ok_and(|server| !state.hub.is_online(server))
    {
      return Ok(());
    }
    let (id, _) = insert_run_at(
      state,
      &key,
      *status,
      trigger,
      due.timestamp_millis(),
      Some((service, Some(&identity.instance_id))),
      None,
    )
    .await?;
    finish(state, id, *status, None, detail, None, None).await;
    return Ok(());
  }
  let guard = result.expect("前面已处理不可运行的排程");
  let (id, _) = insert_run_at(
    state,
    &key,
    TaskStatus::Running,
    trigger,
    due.timestamp_millis(),
    Some((service, Some(&identity.instance_id))),
    None,
  )
  .await?;
  let (response, task) = match crate::apply::spawn_task(
    state.clone(),
    title,
    step,
    Some("定时重启".into()),
    guard,
  )
  .await
  {
    Ok(run) => run,
    Err(err) => {
      finish(
        state,
        id,
        TaskStatus::Failed,
        None,
        &err.message,
        None,
        None,
      )
      .await;
      return Ok(());
    }
  };
  let run_id = response.run_id;
  let output =
    serde_json::json!({"run_id": run_id, "detail": ""}).to_string();
  if let Err(error) = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE task_runs SET output = ?2 WHERE id = ?1",
        params![id, output],
      )
      .map(|_| ())
      .map_err(sql_err)
    })
    .await
  {
    tracing::warn!("关联定时重启执行记录失败：{error}");
  }
  let mut status = TaskStatus::Failed;
  let mut detail = "定时重启执行中断".to_string();
  if task.await.is_ok()
    && let Ok(run) = crate::apply::load_run(state, &run_id).await
  {
    status = match run.status {
      RunStatus::Succeeded => TaskStatus::Succeeded,
      RunStatus::Cancelled => TaskStatus::Cancelled,
      RunStatus::Failed | RunStatus::Running => TaskStatus::Failed,
    };
    detail = run
      .steps
      .iter()
      .find_map(|step| step.error.as_ref())
      .map_or_else(String::new, |error| error.message.clone());
  }
  let output =
    serde_json::json!({"run_id":run_id, "detail":detail}).to_string();
  finish(state, id, status, None, &output, None, None).await;
  Ok(())
}

pub(crate) async fn ready(
  state: &AppState,
  snap: &snapshot::Snapshot,
  name: &str,
  identity: &RestartIdentity,
  cancel: &CancellationToken,
) -> Result<String, ApiError> {
  if state.is_safe_mode() {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "安全模式暂停定时重启",
    ));
  }
  let service = name.to_string();
  let current = state
    .db
    .call(move |c| candidates(c, Some(&service)))
    .await?;
  let Some((_, spec, current, _)) = current
    .first()
    .filter(|(_, _, current, _)| current.key() == identity.key())
  else {
    return Err(ApiError::new(
      ErrorCode::PlanStale,
      "定时重启设置或服务实例已变更",
    ));
  };
  let row = snap
    .world
    .services
    .get(name)
    .filter(|row| row.instance_id == current.instance_id)
    .ok_or_else(|| {
      ApiError::new(ErrorCode::PlanStale, "定时重启服务实例已变更")
    })?;
  let stopped = || {
    let detail = if spec.skip_if_stopped {
      "跳过定时重启"
    } else {
      "本次定时重启未执行"
    };
    ApiError::new(
      ErrorCode::Conflict,
      format!("服务 {name} 已停止，{detail}"),
    )
    .with_hint(format!(
      "检查 wharf service show {name}，或启用 --skip-if-stopped true"
    ))
  };
  if row.spec.stopped {
    return Err(stopped());
  }
  let server = exec_target(snap, name)
    .map_err(|reason| ApiError::new(ErrorCode::Conflict, reason))?;
  let conn = state.hub.scheduled_restart_conn_id(server)?;
  let projects: Vec<ProjectState> = state
    .hub
    .call_bound(
      (server, conn),
      AgentOp::ProjectStatus {
        projects: vec![name.into()],
        include_links: false,
      },
      Duration::from_secs(6),
      None,
      cancel,
    )
    .await?;
  if !projects.iter().any(|p| {
    p.project == name
      && p.containers.iter().any(|c| !c.foreign && c.is_running())
  }) {
    return Err(stopped());
  }
  Ok(server.to_string())
}

#[test]
fn restart_due_does_not_catch_up_before_revision_or_resume() {
  let spec = RestartSchedule {
    cron: "0 * * * *".into(),
    skip_if_stopped: true,
    catch_up_mins: Some(5),
  };
  let cron = validate(&spec).unwrap();
  let at = |minute| {
    chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 1, 1, 1, minute, 0)
      .unwrap()
  };
  assert_eq!(
    due_for(
      &cron,
      &spec,
      at(1),
      at(3),
      DateTime::<Utc>::MIN_UTC,
      at(0).timestamp_millis()
    ),
    Some((at(0), "catch_up"))
  );
  assert_eq!(due_for(&cron, &spec, at(1), at(3), at(0), 0), None);
  assert_eq!(
    due_for(
      &cron,
      &spec,
      at(1),
      at(3),
      DateTime::<Utc>::MIN_UTC,
      at(1).timestamp_millis()
    ),
    None
  );
}
