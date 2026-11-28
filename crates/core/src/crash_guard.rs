use std::{
  collections::{BTreeMap, VecDeque},
  sync::Arc,
  time::Duration,
};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, CrashGuardOp, ProjectState, RestartPolicy},
  view::{CrashGuardView, Issue, IssueLevel, IssueSubject, Perm},
};

use crate::{
  api::ApiResult,
  apply,
  auth::Auth,
  db::{self, Write, json_err, sql_err},
  hub::ProgressFn,
  planner::Step,
  snapshot::{self, Snapshot},
  state::AppState,
  world::World,
};

pub(crate) const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS service_recovery(
  instance_id TEXT PRIMARY KEY, service TEXT NOT NULL, server TEXT NOT NULL,
  phase TEXT NOT NULL, payload TEXT NOT NULL, updated_at INTEGER NOT NULL
)";
const RPC: Duration = Duration::from_secs(45);
const WINDOW: i64 = 10 * 60_000;
const MAX_GAP: i64 = 2 * 60_000 + 15_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Evidence {
  pub instance: String,
  pub hash: String,
  pub container: String,
  pub count: u32,
  pub conn: u64,
  pub observed: i64,
  pub first: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Recovery {
  pub phase: String,
  pub evidence: Option<Evidence>,
  #[serde(default)]
  pub policies: Vec<RestartPolicy>,
  #[serde(default)]
  pub attempts: u8,
  pub run: String,
  #[serde(default)]
  pub lease: Option<crate::crash_guard::repair::Lease>,
}

pub(crate) mod repair;

pub(crate) fn load(
  c: &Connection,
  world: &World,
) -> Result<BTreeMap<String, Recovery>, ApiError> {
  let mut stmt = c.prepare("SELECT service,server,instance_id,payload FROM service_recovery").map_err(sql_err)?;
  let mut rows = stmt.query([]).map_err(sql_err)?;
  let mut out = BTreeMap::new();
  while let Some(row) = rows.next().map_err(sql_err)? {
    let name: String = row.get(0).map_err(sql_err)?;
    let server: String = row.get(1).map_err(sql_err)?;
    let instance: String = row.get(2).map_err(sql_err)?;
    if world.services.get(&name).is_some_and(|r| {
      r.instance_id == instance && r.spec.server == server
    }) {
      let raw: String = row.get(3).map_err(sql_err)?;
      out.insert(name, serde_json::from_str(&raw).map_err(json_err)?);
    }
  }
  Ok(out)
}

pub(crate) fn store(
  c: &Connection,
  service: &str,
  server: &str,
  instance: &str,
  value: &Recovery,
) -> Result<(), ApiError> {
  c.execute("INSERT INTO service_recovery(instance_id,service,server,phase,payload,updated_at)
     VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(instance_id) DO UPDATE SET phase=excluded.phase,payload=excluded.payload,updated_at=excluded.updated_at",
    params![instance,service,server,value.phase,serde_json::to_string(value).map_err(json_err)?,db::now_ms()],
  ).map_err(sql_err)?;
  Ok(())
}

pub(crate) fn read_raw(
  c: &Connection,
  name: &str,
) -> Result<Option<Recovery>, ApiError> {
  let raw: Option<String> = c.query_row(
    "SELECT recovery.payload FROM service_recovery recovery JOIN resources
       ON resources.kind='service' AND resources.name=recovery.service
      AND json_extract(resources.meta, '$.instance_id')=recovery.instance_id
     WHERE recovery.service=?1",
    [name],|r| r.get(0),
  ).optional().map_err(sql_err)?;
  raw
    .map(|raw| serde_json::from_str(&raw).map_err(json_err))
    .transpose()
}

fn blocker(name: &str) -> ApiError {
  ApiError::new(ErrorCode::Conflict,format!("服务 {name} 已保护停机或正在修复"))
    .with_hint(format!("运行 wharf service logs {name} 查看现场，或使用 wharf service repair {name}"))
}

pub(crate) fn require_idle(
  snap: &Snapshot,
  name: &str,
) -> Result<(), ApiError> {
  if snap.recovery.contains_key(name) {
    Err(blocker(name))
  } else {
    Ok(())
  }
}

pub(crate) fn check_plan(
  state: &AppState,
  snap: &Snapshot,
  desired: &World,
) -> Result<(), ApiError> {
  for (name, row) in &desired.services {
    if row.spec.crash_guard
      && snap
        .world
        .services
        .get(name)
        .is_none_or(|old| !old.spec.crash_guard)
    {
      state.hub.crash_guard_conn_id(&row.spec.server)?;
    }
  }
  for name in snap.recovery.keys() {
    let before = &snap.world.services[name];
    if desired.services.get(name).is_none_or(|after| {
      before != after
        && (!metadata_only(&before.spec, &after.spec)
          || before.pins != after.pins
          || before.commit != after.commit)
    }) {
      return Err(blocker(name));
    }
  }
  Ok(())
}

fn metadata_only(
  old: &wharf_api_types::spec::ServiceSpec,
  new: &wharf_api_types::spec::ServiceSpec,
) -> bool {
  let mut expected = old.clone();
  expected.crash_guard = new.crash_guard;
  expected.tags.clone_from(&new.tags);
  &expected == new
}

pub(crate) fn check_writes(
  c: &Connection,
  writes: &[Write],
) -> Result<(), ApiError> {
  for write in writes {
    let (name, value) = match write {
      Write::Delete { kind, name } if kind == "service" => {
        (name, None)
      }
      Write::Upsert {
        kind, name, spec, ..
      } if kind == "service" => (name, Some(spec)),
      _ => continue,
    };
    if read_raw(c, name)?.is_some() {
      let Some(value) = value else {
        return Err(blocker(name));
      };
      let old: String = c.query_row("SELECT spec FROM resources WHERE kind='service' AND name=?1",[name],|r| r.get(0)).map_err(sql_err)?;
      let old = serde_json::from_str(&old).map_err(json_err)?;
      let new =
        serde_json::from_value(value.clone()).map_err(json_err)?;
      if !metadata_only(&old, &new) {
        return Err(blocker(name));
      }
    }
  }
  Ok(())
}

pub async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<CrashGuardView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  let snap = snapshot::load_inner(&state.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| crate::api::service_not_found(&name))?;
  Ok(Json(CrashGuardView {
    enabled: row.spec.crash_guard,
    supported: state
      .hub
      .crash_guard_conn_id(&row.spec.server)
      .is_ok(),
    phase: snap.recovery.get(&name).map(|r| r.phase.clone()),
  }))
}

pub(crate) fn summary(phase: &str) -> Option<&'static str> {
  match phase {
    "protected" => Some("保护停机"),
    "repair" | "repair_starting" | "repair_cleanup" => Some("修复中"),
    "stopping" => Some("保护停机待确认"),
    "resuming" => Some("正在恢复"),
    _ => None,
  }
}

pub(crate) fn issues(snap: &Snapshot) -> Vec<Issue> {
  snap
    .recovery
    .iter()
    .filter_map(|(service, row)| {
      Some(Issue {
        code: "crash_guard".into(),
        ack: None,
        alert: None,
        level: if row.phase == "stopping" {
          IssueLevel::Fault
        } else {
          IssueLevel::Warn
        },
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: service.clone(),
        }),
        title: format!("{service}：{}", summary(&row.phase)?),
        hint: Some(format!("wharf service logs {service}")),
      })
    })
    .collect()
}

#[derive(Default)]
pub(crate) struct Observations {
  identity: Option<(String, String, u64)>,
  containers: BTreeMap<String, VecDeque<(i64, u32)>>,
}

impl Observations {
  pub(crate) fn clear(&mut self) {
    self.identity = None;
    self.containers.clear();
  }

  fn sample(
    &mut self,
    id: &str,
    at: i64,
    count: u32,
    restarting: bool,
  ) -> Option<i64> {
    let series = self.containers.entry(id.into()).or_default();
    if let Some(&(last, old)) = series.back() {
      if at == last {
        return None;
      }
      if at < last || at - last > MAX_GAP || count < old {
        series.clear();
      }
    }
    while series.front().is_some_and(|(first, _)| at - first > WINDOW)
    {
      series.pop_front();
    }
    let first = series
      .front()
      .filter(|(_, base)| {
        restarting && count.saturating_sub(*base) >= 5
      })
      .map(|(first, _)| *first);
    series.push_back((at, count));
    first
  }
}

pub(crate) async fn observe(
  state: &Arc<AppState>,
  snap: &Snapshot,
  name: &str,
  project: &ProjectState,
  observations: &mut Observations,
) {
  let row = &snap.world.services[name];
  let Ok(conn) = state.hub.crash_guard_conn_id(&row.spec.server)
  else {
    observations.clear();
    return;
  };
  let Some(hash) = project.hash.as_ref().filter(|hash| {
    snap.applied.get(name).is_some_and(|a| &a.hash == *hash)
      && !snap.recovery.contains_key(name)
      && !snap.pending.migrations.contains_key(name)
      && !snap.pending.adopt_data.contains_key(name)
      && !project.containers.iter().any(|c| c.foreign)
  }) else {
    observations.clear();
    return;
  };
  let identity = (row.instance_id.clone(), hash.clone(), conn);
  if observations.identity.as_ref() != Some(&identity) {
    observations.clear();
    observations.identity = Some(identity);
  }
  let mut seen = std::collections::BTreeSet::new();
  for c in &project.containers {
    let (Some(id), Some(count), Some(at)) =
      (&c.container_id, c.restart_count, c.restart_observed_at)
    else {
      continue;
    };
    if c.is_completed_init() || c.foreign {
      continue;
    }
    seen.insert(id.clone());
    if let Some(first) =
      observations.sample(id, at, count, c.is_restarting())
    {
      let evidence = Evidence {
        instance: row.instance_id.clone(),
        hash: hash.clone(),
        container: id.clone(),
        count,
        conn,
        observed: at,
        first,
      };
      kick(state, name, evidence).await;
      observations.clear();
      return;
    }
  }
  observations.containers.retain(|id, _| seen.contains(id));
}

async fn kick(state: &Arc<AppState>, name: &str, evidence: Evidence) {
  let _ = apply::start_task_by(
    state.clone(),
    format!("重启循环保护 {name}"),
    Step::CrashStop {
      service: name.into(),
      evidence,
    },
    Some("重启循环保护".into()),
  )
  .await;
}

pub(crate) async fn retry_stops(
  state: &Arc<AppState>,
  snap: &Snapshot,
) {
  for (name, row) in &snap.recovery {
    if row.phase == "stopping"
      && row.attempts < 3
      && !state.is_service_busy(name)
      && let Some(evidence) = &row.evidence
      && state
        .hub
        .crash_guard_conn_id(&snap.world.services[name].spec.server)
        .is_ok()
    {
      kick(state, name, evidence.clone()).await;
    }
  }
}

async fn project(
  state: &AppState,
  server: (&str, u64),
  name: &str,
  cancel: &CancellationToken,
) -> Result<ProjectState, ApiError> {
  let all: Vec<ProjectState> = state
    .hub
    .call_bound(
      server,
      AgentOp::ProjectStatus {
        projects: vec![name.into()],
        include_links: false,
      },
      RPC,
      None,
      cancel,
    )
    .await?;
  all
    .into_iter()
    .find(|p| p.project == name)
    .ok_or_else(|| blocker(name))
}

pub(crate) async fn stop(
  state: &AppState,
  snap: &Snapshot,
  run_id: &str,
  name: &str,
  evidence: &Evidence,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let row = snap
    .world
    .services
    .get(name)
    .filter(|row| row.instance_id == evidence.instance)
    .ok_or_else(|| blocker(name))?;
  let server = row.spec.server.as_str();
  let conn = state.hub.crash_guard_conn_id(server)?;
  let observed = project(state, (server, conn), name, cancel).await?;
  if observed.hash.as_deref() != Some(&evidence.hash)
    || observed.containers.is_empty()
    || observed.containers.iter().any(|c| c.foreign)
  {
    return Err(blocker(name));
  }
  let mut recovery = if let Some(r) = snap.recovery.get(name) {
    if r.phase == "protected" {
      return Ok(());
    }
    if r.phase != "stopping" || r.lease.is_some() {
      return Err(blocker(name));
    }
    r.clone()
  } else {
    if state.is_safe_mode()
      || !row.spec.crash_guard
      || row.spec.stopped
      || conn != evidence.conn
      || !observed.containers.iter().any(|c| {
        c.container_id.as_deref() == Some(&evidence.container)
          && c.is_restarting()
          && c
            .restart_count
            .is_some_and(|count| count >= evidence.count)
          && c
            .restart_observed_at
            .is_some_and(|at| at - evidence.first <= WINDOW)
      })
    {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        "重启循环证据已变化",
      ));
    }
    let policies: Vec<RestartPolicy> = state
      .hub
      .call_bound(
        (server, conn),
        AgentOp::CrashGuard(CrashGuardOp::Policies {
          service: name.into(),
        }),
        RPC,
        None,
        cancel,
      )
      .await?;
    Recovery {
      phase: "stopping".into(),
      evidence: Some(evidence.clone()),
      policies,
      attempts: 0,
      run: run_id.into(),
      lease: None,
    }
  };
  recovery.attempts = recovery.attempts.saturating_add(1);
  save(
    state,
    name,
    server,
    &row.instance_id,
    &recovery,
    Some(true),
    run_id,
  )
  .await?;
  policy(
    state,
    (server, conn),
    name,
    &recovery.policies,
    false,
    &progress,
    cancel,
  )
  .await?;
  if observed.containers.iter().any(|c| c.is_active()) {
    apply::project_stop_start_on(
      state,
      (server, Some(conn)),
      name,
      false,
      &progress,
      cancel,
    )
    .await?;
  }
  let verified = project(state, (server, conn), name, cancel).await?;
  if verified.containers.is_empty()
    || verified
      .containers
      .iter()
      .any(|c| c.is_active() || c.foreign)
  {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "服务仍有运行容器，保护停机未完成",
    ));
  }
  recovery.phase = "protected".into();
  save(
    state,
    name,
    server,
    &row.instance_id,
    &recovery,
    None,
    run_id,
  )
  .await?;
  crate::rules::notice(
    state,
    "crash_guard",
    Some(name),
    Some(&format!("crash_guard.{}", row.instance_id)),
    false,
    crate::notify::Event {
      title: format!("服务 {name} 已保护停机"),
      body: format!("运行 wharf service logs {name} 查看现场"),
    },
  )
  .await;
  Ok(())
}

async fn policy(
  state: &AppState,
  server: (&str, u64),
  name: &str,
  policies: &[RestartPolicy],
  restore: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let job = if restore {
    CrashGuardOp::Restore {
      service: name.into(),
      policies: policies.to_vec(),
    }
  } else {
    CrashGuardOp::Disable {
      service: name.into(),
      policies: policies.to_vec(),
    }
  };
  state
    .hub
    .call_bound::<bool>(
      server,
      AgentOp::CrashGuard(job),
      RPC,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  Ok(())
}

async fn save(
  state: &AppState,
  name: &str,
  server: &str,
  instance: &str,
  recovery: &Recovery,
  stopped: Option<bool>,
  run: &str,
) -> Result<(), ApiError> {
  let (name, server, instance, recovery, run) = (
    name.to_owned(),
    server.to_owned(),
    instance.to_owned(),
    recovery.clone(),
    run.to_owned(),
  );
  state.db.call_credentials(move |c,key| apply::record_retry_changes(c,key,&run,|tx| {
    store(tx,&name,&server,&instance,&recovery)?;
    if let Some(stopped) = stopped {
      tx.execute("UPDATE resources SET spec=json_set(spec,'$.stopped',json(CASE ?3 WHEN 1 THEN 'true' ELSE 'false' END)),version=version+1,updated_at=?4
        WHERE kind='service' AND name=?1 AND json_extract(meta,'$.instance_id')=?2 AND COALESCE(json_extract(spec,'$.stopped'),0) != ?3",
        params![name,instance,if stopped {1}else{0},db::now_ms()]).map_err(sql_err)?;
    }
    Ok(())
  })).await
}

pub(crate) async fn resume(
  state: &AppState,
  snap: &Snapshot,
  run: &str,
  name: &str,
  instance: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let row = snap
    .world
    .services
    .get(name)
    .filter(|r| r.instance_id == instance && r.spec.stopped)
    .ok_or_else(|| blocker(name))?;
  let server = row.spec.server.as_str();
  let conn = state.hub.crash_guard_conn_id(server)?;
  let mut recovery = snap
    .recovery
    .get(name)
    .filter(|r| {
      matches!(r.phase.as_str(), "protected" | "resuming")
        && r.lease.is_none()
    })
    .ok_or_else(|| blocker(name))?
    .clone();
  recovery.phase = "resuming".into();
  save(state, name, server, instance, &recovery, None, run).await?;
  let result = async {
    let live = project(state, (server, conn), name, cancel).await?;
    if live.hash.as_deref()
      != recovery.evidence.as_ref().map(|e| e.hash.as_str())
      || live.containers.is_empty()
      || live.containers.iter().any(|c| c.foreign)
    {
      return Err(blocker(name));
    }
    policy(
      state,
      (server, conn),
      name,
      &recovery.policies,
      true,
      &progress,
      cancel,
    )
    .await?;
    apply::project_stop_start_on(
      state,
      (server, Some(conn)),
      name,
      true,
      &progress,
      cancel,
    )
    .await?;
    let live = project(state, (server, conn), name, cancel).await?;
    if !live.all_running() {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "服务未恢复运行",
      ));
    }
    Ok(())
  }
  .await;
  if let Err(e) = result {
    let undo = CancellationToken::new();
    policy(
      state,
      (server, conn),
      name,
      &recovery.policies,
      false,
      &progress,
      &undo,
    )
    .await?;
    apply::project_stop_start_on(
      state,
      (server, Some(conn)),
      name,
      false,
      &progress,
      &undo,
    )
    .await?;
    recovery.phase = "protected".into();
    save(state, name, server, instance, &recovery, None, run).await?;
    return Err(e);
  }
  let (name, instance, run) =
    (name.to_owned(), instance.to_owned(), run.to_owned());
  state.db.call_credentials(move |c,key| apply::record_retry_changes(c,key,&run,|tx| {
    tx.execute("UPDATE resources SET spec=json_remove(spec,'$.stopped'),version=version+1,updated_at=?3
      WHERE kind='service' AND name=?1 AND json_extract(meta,'$.instance_id')=?2",
      params![name,instance,db::now_ms()]).map_err(sql_err)?;
    tx.execute("DELETE FROM service_recovery WHERE instance_id=?1",[instance]).map_err(sql_err)?;
    Ok(())
  })).await
}

#[test]
fn crash_window_requires_five_new_restarts_and_current_backoff() {
  let mut tracker = Observations::default();
  assert_eq!(tracker.sample("id", 1, 9, true), None);
  assert_eq!(tracker.sample("id", 60_001, 14, false), None);
  assert_eq!(tracker.sample("id", 120_001, 14, true), Some(1));
  assert_eq!(tracker.sample("new", 120_001, 14, true), None);
  assert_eq!(tracker.sample("id", WINDOW + MAX_GAP, 20, true), None);
}

pub(crate) async fn require_task_idle(
  state: &AppState,
  name: &str,
) -> Result<(), ApiError> {
  let name = name.to_owned();
  state
    .db
    .call(move |c| {
      if read_raw(c, &name)?.is_some() {
        return Err(blocker(&name));
      }
      Ok(())
    })
    .await
}

pub(crate) async fn require_data_writable(
  state: &AppState,
  name: &str,
) -> Result<(), ApiError> {
  let name = name.to_owned();
  state
    .db
    .call(move |c| {
      if read_raw(c, &name)?.is_some_and(|row| row.lease.is_some()) {
        return Err(blocker(&name));
      }
      Ok(())
    })
    .await
}
