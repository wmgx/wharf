//! 定时任务：控制面每 15 秒看一次到点的任务，下发给 agent 执行，记录结果，失败和恢复时通知。
//! 任务定义直接改。开启补跑的任务可在宽限期内补上最近一次计划。

use std::{
  collections::{BTreeMap, HashMap},
  sync::{Arc, LazyLock, Mutex, RwLock},
  time::Duration,
};

use axum::{
  Json,
  body::{Body, to_bytes},
  extract::{ConnectInfo, Path, Query, State},
  http::{Request, StatusCode},
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, HostExecJob, NODE_IMAGE, PYTHON_IMAGE, SHELL_IMAGE,
    ServiceDisk, TASK_DATA_PREFIX, TaskHow, TaskInput, TaskRunJob,
    TaskRunResult,
  },
  validate_name,
  view::{
    Issue, IssueLevel, IssueSubject, Perm, ScriptRuntime, TaskKind,
    TaskRunView, TaskSpec, TaskStatus, TaskView,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  cron::{Cron, minute_floor},
  db::{self, now_ms, sql_err, to_time},
  render, snapshot,
  state::AppState,
};

const TICK: Duration = Duration::from_secs(15);
const KEEP_RUNS: i64 = 50;
const HOST_MAX: u64 = 600;
const OTHER_MAX: u64 = 6 * 3600;

/// 正在跑的任务，同一个任务不并发。
static RUNNING: LazyLock<Mutex<HashMap<String, ActiveRun>>> =
  LazyLock::new(Default::default);

#[derive(Clone)]
struct ActiveRun {
  id: i64,
  cancel: CancellationToken,
}

static HOOKS: LazyLock<Mutex<crate::notify_keys::RequestLimit>> =
  LazyLock::new(Default::default);
static HOOK_FAILS: LazyLock<Mutex<crate::notify_keys::RequestLimit>> =
  LazyLock::new(Default::default);
static HOOK_INDEX: LazyLock<RwLock<HashMap<String, String>>> =
  LazyLock::new(Default::default);

fn task_token(spec: &TaskSpec) -> Option<&str> {
  match &spec.how {
    TaskKind::Ping { token, .. }
    | TaskKind::Script {
      hook: Some(token), ..
    } if !token.is_empty() => Some(token),
    _ => None,
  }
}

fn index_hooks(rows: &[(String, TaskSpec, i64)]) {
  let mut index = HashMap::new();
  for (name, spec, _) in rows {
    if spec.enabled
      && matches!(spec.how, TaskKind::Script { .. })
      && let Some(token) = task_token(spec)
    {
      index
        .entry(crate::auth::hash_token(token))
        .or_insert_with(|| name.clone());
    }
  }
  *HOOK_INDEX.write().unwrap_or_else(|e| e.into_inner()) = index;
}

pub async fn load_hooks(db: &crate::db::Db) -> Result<(), ApiError> {
  db.call(|c| {
    index_hooks(&load_rows(c)?);
    Ok(())
  })
  .await
}

fn validate_task_token(
  token: &str,
  old: Option<&str>,
  used: bool,
) -> Result<(), ApiError> {
  if old == Some(token) {
    return Ok(());
  }
  if token.len() < 24
    || used
    || !token
      .bytes()
      .all(|b| b.is_ascii_graphic() && !b"/?#".contains(&b))
  {
    return Err(
      ApiError::invalid(
        "口令至少需要 24 个字符，且不能和其他任务重复",
      )
      .with_hint("留空即可由 Wharf 自动生成随机口令"),
    );
  }
  Ok(())
}

struct RunGuard {
  name: String,
  cancel: CancellationToken,
}

impl RunGuard {
  fn acquire(name: &str) -> Option<Self> {
    let mut running =
      RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    let std::collections::hash_map::Entry::Vacant(slot) =
      running.entry(name.into())
    else {
      return None;
    };
    let cancel = CancellationToken::new();
    slot.insert(ActiveRun {
      id: 0,
      cancel: cancel.clone(),
    });
    Some(Self {
      name: name.into(),
      cancel,
    })
  }

  fn bind(&self, id: i64) {
    let mut running =
      RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    let run = running.get_mut(&self.name).expect("任务持有运行锁");
    run.id = id;
  }
}

impl Drop for RunGuard {
  fn drop(&mut self) {
    release(&self.name);
  }
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut checked = minute_floor(Utc::now());
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
      let now = minute_floor(Utc::now());
      if !state.is_safe_mode()
        && let Err(e) = tick(&state, checked, now).await
      {
        tracing::warn!("检查定时任务失败：{e}");
      }
      checked = now;
      tokio::time::sleep(TICK).await;
    }
  });
}

/// `(after, until]` 之间每一分钟到点的任务各跑一次。
async fn tick(
  state: &Arc<AppState>,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) -> Result<(), ApiError> {
  let resumed_at = state
    .resumed_at
    .get()
    .copied()
    .map(minute_floor)
    .unwrap_or(DateTime::<Utc>::MIN_UTC);
  let after = after.max(resumed_at);
  let rows = load(state).await?;
  let offset =
    state.db.call(|c| crate::config_api::offset(c)).await?;
  let snap = if rows.iter().any(|(_, spec, _)| {
    spec.enabled && matches!(spec.how, TaskKind::Exec { .. })
  }) {
    Some(snapshot::load(&state.db).await?)
  } else {
    None
  };
  for (name, spec, updated_at) in rows {
    if !spec.enabled || spec.schedule.is_empty() {
      continue;
    }
    let Ok(cron) = Cron::parse(&spec.schedule) else {
      continue;
    };
    let cron = cron.with_offset(offset);
    if let TaskKind::Ping { grace_mins, .. } = spec.how {
      if until > after {
        crate::ping::check_due(
          state,
          &name,
          &spec,
          &cron,
          grace_mins,
          after.max(
            resumed_at
              + chrono::Duration::minutes(i64::from(grace_mins)),
          ),
          until,
        )
        .await;
      }
      continue;
    }
    let stopped = snap
      .as_ref()
      .and_then(|snap| should_skip_stopped(&spec, &snap.world));
    let service =
      snap.as_ref().and_then(|snap| run_service(&spec, snap));
    let target = service
      .zip(snap.as_ref())
      .map_or(Ok(spec.server.as_str()), |((name, _), snap)| {
        exec_target(snap, name)
      });
    let online = target
      .as_ref()
      .is_ok_and(|server| state.hub.is_online(server));
    if until > after
      && cron.next_after(after).is_some_and(|t| t <= until)
    {
      if let Some(service) = stopped {
        record_skipped(
          state,
          &name,
          "schedule",
          service,
          snap.as_ref().expect("容器任务有快照"),
        )
        .await?;
        continue;
      }
      if spec.catch_up_mins.is_none() || online || target.is_err() {
        start(state, &name, spec, "schedule", None).await?;
        continue;
      }
    }
    let Some(window) = spec.catch_up_mins else {
      continue;
    };
    let grace = chrono::Duration::minutes(i64::from(window));
    if let Some(due) = cron.prev_at_or_before(until, window)
      && due > resumed_at
      && due.timestamp_millis() >= updated_at
      && (stopped.is_some() || online)
      && let Some(guard) = RunGuard::acquire(&name)
      && !scheduled_since(state, &name, due).await?
    {
      if let Some(service) = stopped {
        record_skipped(
          state,
          &name,
          "catch_up",
          service,
          snap.as_ref().expect("容器任务有快照"),
        )
        .await?;
      } else {
        start_with_guard(
          state,
          &name,
          spec,
          "catch_up",
          None,
          Some(guard),
          RunTaskRequest::default(),
        )
        .await?;
      }
      continue;
    }
    if until > after
      && let Some(due) =
        cron.next_after((after - grace).max(resumed_at))
      && due + grace <= until
      && due.timestamp_millis() >= updated_at
      && !scheduled_since(state, &name, due).await?
    {
      let server = match target {
        Ok(server) => server,
        Err(reason) => {
          let (id, _) = insert_run_at(
            state,
            &name,
            TaskStatus::Skipped,
            "catch_up",
            due.timestamp_millis(),
            service,
            None,
          )
          .await?;
          finish(
            state,
            id,
            TaskStatus::Skipped,
            None,
            &reason,
            None,
            None,
          )
          .await;
          continue;
        }
      };
      let output = format!(
        "错过计划时间 {}，在 {window} 分钟宽限内服务器 {} 未补跑",
        due.with_timezone(&offset).format("%H:%M"),
        server,
      );
      // 这条记录对应未执行的旧计划点，用实际写入时间会挡住后续补跑。
      let (id, _) = insert_run_at(
        state,
        &name,
        TaskStatus::Failed,
        "catch_up",
        due.timestamp_millis(),
        service,
        None,
      )
      .await?;
      finish(
        state,
        id,
        TaskStatus::Failed,
        None,
        &output,
        None,
        None,
      )
      .await;
      let state = state.clone();
      let server = server.to_string();
      tokio::spawn(async move {
        notify_result(
          &state,
          &name,
          id,
          TaskStatus::Failed,
          &output,
          Some(&server),
        )
        .await;
      });
    }
  }
  Ok(())
}

fn should_skip_stopped<'a>(
  spec: &'a TaskSpec,
  world: &crate::world::World,
) -> Option<&'a str> {
  if spec.skip_if_stopped
    && let TaskKind::Exec { service, .. } = &spec.how
    && world.services.get(service).is_some_and(|r| r.spec.stopped)
  {
    return Some(service);
  }
  None
}

async fn record_skipped(
  state: &AppState,
  name: &str,
  trigger: &str,
  service: &str,
  snap: &snapshot::Snapshot,
) -> Result<(), ApiError> {
  let instance = snap
    .world
    .services
    .get(service)
    .map(|row| row.instance_id.as_str());
  let id = insert_run(
    state,
    name,
    TaskStatus::Skipped,
    trigger,
    Some((service, instance)),
  )
  .await?;
  finish(
    state,
    id,
    TaskStatus::Skipped,
    None,
    &format!("服务 {service} 已停止，按 skip_if_stopped 跳过"),
    None,
    None,
  )
  .await;
  Ok(())
}

async fn scheduled_since(
  state: &AppState,
  name: &str,
  due: DateTime<Utc>,
) -> Result<bool, ApiError> {
  let name = name.to_string();
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_runs WHERE task = ?1
       AND trigger IN ('schedule', 'catch_up') AND started_at >= ?2)",
        params![name, due.timestamp_millis()],
        |r| r.get(0),
      )
      .map_err(sql_err)
    })
    .await
}

pub(crate) async fn load(
  state: &AppState,
) -> Result<Vec<(String, TaskSpec, i64)>, ApiError> {
  state.db.call(|c| load_rows(c)).await
}

pub(crate) fn load_rows(
  c: &rusqlite::Connection,
) -> Result<Vec<(String, TaskSpec, i64)>, ApiError> {
  let mut stmt = c
    .prepare("SELECT name, spec, updated_at FROM tasks ORDER BY name")
    .map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?))
    })
    .map_err(sql_err)?;
  let rows: Vec<(String, String, i64)> =
    rows.collect::<Result<_, _>>().map_err(sql_err)?;
  Ok(
    rows
      .into_iter()
      .filter_map(|(n, s, u)| {
        serde_json::from_str(&s).ok().map(|s| (n, s, u))
      })
      .collect(),
  )
}

async fn load_one_row(
  state: &AppState,
  name: &str,
) -> Result<Option<(String, TaskSpec, i64)>, ApiError> {
  let name = name.to_string();
  state
    .db
    .call(move |c| {
      let row: Option<(String, i64)> = c
        .query_row(
          "SELECT spec, updated_at FROM tasks WHERE name = ?1",
          [&name],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql_err)?;
      Ok(row.and_then(|(spec, updated)| {
        serde_json::from_str(&spec)
          .ok()
          .map(|spec| (name, spec, updated))
      }))
    })
    .await
}

async fn load_one(
  state: &AppState,
  name: &str,
) -> Result<TaskSpec, ApiError> {
  load_one_row(state, name)
    .await?
    .map(|(_, spec, _)| spec)
    .ok_or_else(|| {
      ApiError::not_found(format!("没有定时任务 {name}"))
        .with_hint("wharf task ls")
    })
}

pub(crate) async fn notification_server(
  state: &AppState,
  name: &str,
) -> Option<String> {
  let spec = load_one(state, name).await.ok()?;
  match spec.how {
    TaskKind::Exec { service, .. } => {
      let snap = snapshot::load_inner(&state.db).await.ok()?;
      exec_target(&snap, &service).ok().map(str::to_owned)
    }
    _ => Some(spec.server),
  }
}

/// 记一条运行记录并在后台执行，返回记录 id。上一次还没跑完时记为跳过。
async fn start(
  state: &Arc<AppState>,
  name: &str,
  spec: TaskSpec,
  trigger: &str,
  input: Option<TaskInput>,
) -> Result<(i64, bool), ApiError> {
  start_with_guard(
    state,
    name,
    spec,
    trigger,
    input,
    RunGuard::acquire(name),
    RunTaskRequest::default(),
  )
  .await
}

pub(crate) fn exec_target<'a>(
  snap: &'a snapshot::Snapshot,
  service: &str,
) -> Result<&'a str, String> {
  if !snap.world.services.contains_key(service) {
    return Err(format!("服务 {service} 已不存在，跳过本次执行"));
  }
  if let Some(migration) = snap.pending.migrations.get(service) {
    if migration.phase == crate::pending::MigratePhase::UpDone {
      return Ok(&migration.payload.to);
    }
    return Err(format!("服务 {service} 正在迁移中，跳过本次执行"));
  }
  snap
    .deployed
    .get(service)
    .map(String::as_str)
    .ok_or_else(|| format!("服务 {service} 尚未部署，跳过本次执行"))
}

fn run_service<'s>(
  spec: &'s TaskSpec,
  snap: &'s snapshot::Snapshot,
) -> Option<(&'s str, Option<&'s str>)> {
  let TaskKind::Exec { service, .. } = &spec.how else {
    return None;
  };
  Some((
    service,
    snap
      .world
      .services
      .get(service)
      .map(|row| row.instance_id.as_str()),
  ))
}

async fn start_with_guard(
  state: &Arc<AppState>,
  name: &str,
  spec: TaskSpec,
  trigger: &str,
  input: Option<TaskInput>,
  guard: Option<RunGuard>,
  mut request: RunTaskRequest,
) -> Result<(i64, bool), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let service = run_service(&spec, &snap);
  let target = service
    .map_or(Ok(spec.server.as_str()), |(name, _)| {
      exec_target(&snap, name)
    });
  if !request.env.is_empty()
    && service.is_some()
    && let Ok(server) = &target
  {
    request.conn = Some(
      state.hub.exec_v2_conn_id(server, "容器内任务临时 --env")?,
    );
  }
  let skip = if guard.is_none() {
    Some("上一次还没跑完".to_string())
  } else {
    target.as_ref().err().cloned()
  };
  let status = if skip.is_some() {
    TaskStatus::Skipped
  } else {
    TaskStatus::Running
  };
  let (id, guard) = insert_run_at(
    state,
    name,
    status,
    trigger,
    now_ms(),
    service,
    guard.filter(|_| skip.is_none()),
  )
  .await?;
  if let Some(reason) = skip {
    finish(state, id, TaskStatus::Skipped, None, &reason, None, None)
      .await;
    return Ok((id, true));
  }
  let server = target.expect("可执行任务已有目标").to_string();
  let mut spec = spec;
  spec.server = server;
  let guard = guard.expect("任务持有运行锁");
  let cancel = guard.cancel.clone();
  let state = state.clone();
  let name = name.to_string();
  tokio::spawn(async move {
    let (status, code, output, mem_peak, artifacts) = execute(
      &state,
      (id, &name),
      &spec,
      &snap,
      input,
      &request,
      &cancel,
    )
    .await;
    let (status, code, output) = if cancel.is_cancelled() {
      (TaskStatus::Cancelled, None, "已手动取消".into())
    } else {
      (status, code, output)
    };
    finish(&state, id, status, code, &output, mem_peak, artifacts)
      .await;
    drop(guard);
    notify_result(
      &state,
      &name,
      id,
      status,
      &output,
      Some(&spec.server),
    )
    .await;
  });
  Ok((id, false))
}

/// 任务失败和恢复时推送（任务开了通知时）。
pub(crate) async fn notify_result(
  state: &AppState,
  name: &str,
  run_id: i64,
  status: TaskStatus,
  output: &str,
  target: Option<&str>,
) {
  if state.is_safe_mode()
    || matches!(status, TaskStatus::Skipped | TaskStatus::Cancelled)
  {
    return;
  }
  let ok = status == TaskStatus::Succeeded;
  let task = name.to_string();
  let server = state.db.call(move |c| {
    let server = c.query_row(
      "SELECT json_extract(spec, '$.server'),
              COALESCE(json_extract(spec, '$.enabled'), 1)
                AND COALESCE(json_extract(spec, '$.notify'), 1)
       FROM tasks WHERE name = ?1
        AND EXISTS (SELECT 1 FROM task_runs WHERE id = ?2 AND task = ?1)",
      params![task, run_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
    ).optional().map_err(sql_err)?;
    let Some((server, notify)) = server else { return Ok(None) };
    let key = task_notice_key(&task);
    if !notify {
      db::set_setting(c, &key, None)?;
      return Ok(None);
    }
    Ok(crate::notify::transition_row(c, &key, ok)?.then_some(server))
  }).await;
  let Ok(Some(server)) = server else { return };
  let title = if ok {
    format!("定时任务 {name} 恢复正常")
  } else {
    format!("定时任务 {name} {}", status_text(status))
  };
  crate::rules::notice(
    state,
    "task",
    Some(name),
    None,
    ok,
    crate::notify::Event {
      title,
      body: format!(
        "服务器 {}\n{}",
        target.unwrap_or(&server),
        last_lines(output, 10)
      ),
    },
  )
  .await;
}

fn task_notice_key(name: &str) -> String {
  format!("notify.state.task.{name}")
}

fn release(name: &str) {
  if let Ok(mut r) = RUNNING.lock() {
    r.remove(name);
  }
}

fn status_text(s: TaskStatus) -> &'static str {
  match s {
    TaskStatus::Running => "运行中",
    TaskStatus::Succeeded => "成功",
    TaskStatus::Failed => "失败",
    TaskStatus::TimedOut => "超时",
    TaskStatus::Skipped => "跳过",
    TaskStatus::Cancelled => "已取消",
  }
}

fn last_lines(s: &str, n: usize) -> String {
  let lines: Vec<&str> = s.lines().collect();
  lines[lines.len().saturating_sub(n)..].join("\n")
}

/// 替换密钥、下发、把输出里的密钥值换成 `***`。
async fn execute(
  state: &Arc<AppState>,
  (run_id, name): (i64, &str),
  spec: &TaskSpec,
  snap: &snapshot::Snapshot,
  input: Option<TaskInput>,
  request: &RunTaskRequest,
  cancel: &CancellationToken,
) -> (
  TaskStatus,
  Option<i32>,
  String,
  Option<u64>,
  Option<artifacts::Stored>,
) {
  if let Err(e) = crate::secret_policy::validate_task_restrictions(
    name,
    &spec.how,
    &snap.secret_restrictions,
  ) {
    return (TaskStatus::Failed, None, e.message, None, None);
  }
  let secrets =
    crate::secret_policy::non_system_secrets(&snap.secrets);
  if let Err(e) = crate::secret_policy::validate_task_env(
    name,
    request.env.values().map(String::as_str),
    &snap.secret_restrictions,
  ) {
    return (TaskStatus::Failed, None, e.message, None, None);
  }
  let mut used = crate::secret_policy::redact_values(&secrets);
  used.extend(
    request
      .env
      .iter()
      .filter(|(key, _)| crate::redact::is_sensitive_env_key(key))
      .flat_map(|(_, value)| {
        let resolved = render::substitute(value, Some(&secrets)).ok();
        std::iter::once(value.clone()).chain(resolved)
      })
      .filter(|value| value.len() >= 6),
  );
  let redact = |s: String| {
    crate::log_redact::redact_text(&wharf_api_types::mask_values(
      &s, &used,
    ))
  };
  let result = run_on_agent(
    state,
    (run_id, name),
    spec,
    (snap, &secrets),
    input,
    request,
    cancel,
  )
  .await;
  match result {
    Ok(r) => {
      let status = if r.timed_out {
        TaskStatus::TimedOut
      } else if r.exit_code == Some(0) {
        TaskStatus::Succeeded
      } else {
        TaskStatus::Failed
      };
      let mut output = redact(r.output);
      if let Some(warning) = r.artifacts_warning {
        use std::fmt::Write;
        let _ = write!(output, "\n{}", redact(warning));
      }
      let artifacts =
        (!r.artifacts.is_empty()).then(|| artifacts::Stored {
          server: spec.server.clone(),
          files: r.artifacts,
          keep: spec.artifacts_keep.unwrap_or(5),
        });
      (status, r.exit_code, output, r.mem_peak, artifacts)
    }
    Err(e) => {
      let status = if e.code == ErrorCode::Cancelled {
        return (
          TaskStatus::Cancelled,
          None,
          "已手动取消".into(),
          None,
          None,
        );
      } else if e.code == ErrorCode::Timeout {
        TaskStatus::TimedOut
      } else {
        TaskStatus::Failed
      };
      (status, None, redact(e.message), None, None)
    }
  }
}

async fn run_on_agent(
  state: &Arc<AppState>,
  (run_id, name): (i64, &str),
  spec: &TaskSpec,
  (snap, secrets): (&snapshot::Snapshot, &BTreeMap<String, String>),
  input: Option<TaskInput>,
  request: &RunTaskRequest,
  cancel: &CancellationToken,
) -> Result<TaskRunResult, ApiError> {
  let texts = crate::missing_refs::task_texts(&spec.how)
    .filter(|(field, _)| {
      field
        .strip_prefix("env.")
        .is_none_or(|key| !request.env.contains_key(key))
    })
    .chain(
      request
        .env
        .iter()
        .map(|(key, value)| (format!("env.{key}"), value.as_str())),
    );
  crate::missing_refs::check_text(
    &format!("task/{name}"),
    texts,
    secrets,
  )?;
  let sub = |t: &str| render::substitute(t, Some(secrets));
  let env_with_overrides = |env: &BTreeMap<String, String>| {
    let mut merged = env.clone();
    merged.extend(request.env.clone());
    merged
      .into_iter()
      .map(|(k, v)| Ok((k, sub(&v)?)))
      .collect::<Result<_, ApiError>>()
  };
  let server = snap
    .world
    .servers
    .get(&spec.server)
    .ok_or_else(|| crate::world::server_not_found(&spec.server))?;
  let how = match &spec.how {
    TaskKind::Ping { .. } => {
      return Err(ApiError::invalid("外部报到任务由别处运行"));
    }
    TaskKind::Host { command } => {
      let job = HostExecJob {
        stream: false,
        command: sub(command)?,
        timeout_secs: spec.timeout_secs,
        cwd: "/root".into(),
      };
      let r = crate::shell::run_host_cancellable(
        state.clone(),
        &format!("task:{name}"),
        spec.server.clone(),
        job,
        Some(command),
        cancel.child_token(),
      )
      .await?;
      return Ok(TaskRunResult {
        artifacts: Vec::new(),
        artifacts_warning: None,
        result: None,
        mem_peak: None,
        exit_code: Some(r.exit_code),
        timed_out: false,
        output: format!("{}{}", r.stdout, r.stderr),
        duration_ms: r.duration_ms,
      });
    }
    TaskKind::Exec {
      service,
      container,
      command,
    } => TaskHow::Exec {
      project: service.clone(),
      service: container.clone(),
      command: sub(command)?,
      env: env_with_overrides(&BTreeMap::new())?,
      cancellable: true,
    },
    TaskKind::Script {
      runtime,
      code,
      deps,
      image,
      env,
      ..
    } => TaskHow::Script {
      image: image
        .clone()
        .unwrap_or_else(|| script_image(*runtime).to_string()),
      runtime: *runtime,
      code: code.clone(),
      deps: deps.clone(),
      mirrors: server.settings.build_env.clone(),
      env: env_with_overrides(env)?,
    },
    TaskKind::Container {
      image,
      command,
      env,
      mounts,
    } => TaskHow::Container {
      image: image.clone(),
      command: command.as_deref().map(&sub).transpose()?,
      env: env_with_overrides(env)?,
      mounts: mounts.clone(),
    },
  };
  let build = snap
    .agent(&spec.server)
    .and_then(|a| a.report.as_ref())
    .map(|r| r.build.as_str());
  if crate::agent_upgrade::outdated(build) {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "服务器 {} 的 agent 版本太旧，不支持定时任务",
          spec.server
        ),
      )
      .with_hint("运行 wharf upgrade"),
    );
  }
  let conn = if matches!(
    &how,
    TaskHow::Script { .. } | TaskHow::Container { .. }
  ) {
    state
      .hub
      .task_artifacts_conn_id(&spec.server)
      .ok()
      .filter(|id| request.conn.is_none_or(|bound| bound == *id))
  } else {
    None
  };
  let job = TaskRunJob {
    name: name.to_string(),
    how,
    input,
    network_host: false,
    out_dir: false,
    wait_for_deps: false,
    run_id: conn.map(|_| run_id),
    artifacts_max_bytes: conn.map(|_| {
      u64::from(spec.artifacts_max_mb.unwrap_or(50)) * 1024 * 1024
    }),
    artifacts_keep: conn.map(|_| spec.artifacts_keep.unwrap_or(5)),
    timeout_secs: spec.timeout_secs,
    pull: snapshot::pull_policy(server),
  };
  // 拉镜像的时间另算。
  let wait = Duration::from_secs(spec.timeout_secs + 15 * 60);
  let old_agent = matches!(&job.how, TaskHow::Script { .. })
    && !state.hub.supports_build_v2(&spec.server);
  let mut result: TaskRunResult = state
    .hub
    .call_optional_bound(
      &spec.server,
      request.conn.or(conn),
      AgentOp::TaskRun(job),
      wait,
      None,
      cancel,
    )
    .await?;
  if old_agent {
    result.output = format!(
      "{}\n{}",
      crate::build::old_agent_warning(&spec.server),
      result.output
    );
  }
  Ok(result)
}

pub(crate) fn script_image(runtime: ScriptRuntime) -> &'static str {
  match runtime {
    ScriptRuntime::Python => PYTHON_IMAGE,
    ScriptRuntime::Node => NODE_IMAGE,
    ScriptRuntime::Shell => SHELL_IMAGE,
  }
}

pub(crate) async fn insert_run(
  state: &AppState,
  name: &str,
  status: TaskStatus,
  trigger: &str,
  service: Option<(&str, Option<&str>)>,
) -> Result<i64, ApiError> {
  insert_run_at(state, name, status, trigger, now_ms(), service, None)
    .await
    .map(|(id, _)| id)
}

async fn insert_run_at(
  state: &AppState,
  name: &str,
  status: TaskStatus,
  trigger: &str,
  started_at: i64,
  service: Option<(&str, Option<&str>)>,
  guard: Option<RunGuard>,
) -> Result<(i64, Option<RunGuard>), ApiError> {
  let (name, trigger) = (name.to_string(), trigger.to_string());
  let status = enc(status);
  let (service, instance) = service.unzip();
  let (service, instance) = (
    service.map(str::to_string),
    instance.flatten().map(str::to_string),
  );
  state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      tx.execute(
        "INSERT INTO task_runs (task, status, trigger, started_at, service, service_instance_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![name, status, trigger, started_at, service, instance],
      )
      .map_err(sql_err)?;
      let id = tx.last_insert_rowid();
      tx.execute(
        "DELETE FROM task_runs WHERE task = ?1 AND id NOT IN (SELECT id FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT ?2)",
        params![name, KEEP_RUNS],
      )
      .map_err(sql_err)?;
      tx.commit().map_err(sql_err)?;
      // 数据库锁释放前绑定 ID，取消请求看到 running 时就能找到句柄。
      if let Some(guard) = &guard {
        guard.bind(id);
      }
      Ok((id, guard))
    })
    .await
}

pub(crate) async fn record_ping(
  state: &AppState,
  name: &str,
  token: &str,
  status: TaskStatus,
  trigger: &str,
  output: &str,
) -> Result<Option<i64>, ApiError> {
  let (name, token, trigger, output) = (
    name.to_string(),
    token.to_string(),
    trigger.to_string(),
    output.to_string(),
  );
  let status = enc(status);
  state.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    let at = now_ms();
    if tx.execute(
      "INSERT INTO task_runs (task, status, trigger, started_at, ended_at, output)
       SELECT name, ?3, ?4, ?5, ?5, ?6 FROM tasks
       WHERE name = ?1 AND json_extract(spec, '$.kind') = 'ping'
         AND json_extract(spec, '$.token') = ?2
         AND COALESCE(json_extract(spec, '$.enabled'), 1) = 1",
      params![name, token, status, trigger, at, output],
    ).map_err(sql_err)? == 0 {
      return Ok(None);
    }
    let id = tx.last_insert_rowid();
    tx.execute(
      "DELETE FROM task_runs WHERE task = ?1 AND id NOT IN (SELECT id FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT ?2)",
      params![name, KEEP_RUNS],
    ).map_err(sql_err)?;
    tx.commit().map_err(sql_err)?;
    Ok(Some(id))
  }).await
}

async fn finish(
  state: &AppState,
  id: i64,
  status: TaskStatus,
  code: Option<i32>,
  output: &str,
  mem_peak: Option<u64>,
  artifacts: Option<artifacts::Stored>,
) {
  let (status, output) = (enc(status), output.to_string());
  let r = state
    .db
    .call(move |c| {
      let manifest = artifacts.as_ref().map(serde_json::to_string).transpose().map_err(db::json_err)?;
      let tx = c.transaction().map_err(sql_err)?;
      let updated = tx.execute(
        "UPDATE task_runs SET status = ?2, exit_code = ?3, output = ?4, ended_at = ?5, mem_peak = ?6, artifacts = ?7 WHERE id = ?1",
        params![id, status, code, output, now_ms(), mem_peak, manifest],
      ).map_err(sql_err)?;
      if updated > 0
        && let Some(artifacts) = artifacts
      {
        tx.execute(
          "UPDATE task_runs SET artifacts = NULL
           WHERE id IN (
             SELECT id FROM task_runs WHERE task = (SELECT task FROM task_runs WHERE id = ?1)
             AND json_extract(artifacts, '$.server') = ?2
             ORDER BY id DESC LIMIT -1 OFFSET ?3
           )",
          params![id, artifacts.server, artifacts.keep],
        ).map_err(sql_err)?;
      }
      tx.commit().map_err(sql_err)
    })
    .await;
  if let Err(e) = r {
    tracing::warn!("记录定时任务结果失败：{e}");
  }
}

fn enc(s: TaskStatus) -> String {
  serde_json::to_value(s)
    .ok()
    .and_then(|v| v.as_str().map(String::from))
    .unwrap_or_default()
}

fn dec(s: &str) -> TaskStatus {
  serde_json::from_value(s.into()).unwrap_or(TaskStatus::Failed)
}

/// 最近一次（不算跳过和运行中）失败或超时的任务，给"需要注意"。
pub async fn issues(state: &AppState) -> Vec<Issue> {
  let rows = state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT t.name, r.status FROM tasks t JOIN task_runs r ON r.id = (
             SELECT id FROM task_runs WHERE task = t.name AND status NOT IN ('skipped', 'running', 'cancelled')
             ORDER BY id DESC LIMIT 1)
           WHERE r.status IN ('failed', 'timed_out')
             AND COALESCE(json_extract(t.spec, '$.enabled'), 1) = 1 ORDER BY t.name",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await
    .unwrap_or_default();
  rows
    .into_iter()
    .map(|(n, s)| Issue {
      code: "task_failed".into(),
      level: IssueLevel::Warn,
      title: format!("定时任务 {n} {}", status_text(dec(&s))),
      subject: Some(IssueSubject {
        kind: "task".into(),
        name: n,
      }),
      hint: None,
      ack: None,
      alert: None,
    })
    .collect()
}

/// 控制面启动时把上次没跑完的记录标成中断。
pub async fn recover(state: &AppState) -> Result<(), ApiError> {
  state
    .db
    .call(|c| {
      c.execute(
        "UPDATE task_runs SET status = 'failed', output = '控制面重启，执行中断', ended_at = ?1 WHERE status = 'running'",
        params![now_ms()],
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(())
}

pub(crate) fn validate_script(
  runtime: ScriptRuntime,
  code: &str,
  deps: &str,
  image: Option<&str>,
) -> Result<(), ApiError> {
  if deps.len() > 16 * 1024 {
    return Err(ApiError::invalid("依赖清单不能超过 16KB"));
  }
  if runtime == ScriptRuntime::Shell && !deps.trim().is_empty() {
    return Err(ApiError::invalid("shell 脚本不支持依赖清单"));
  }
  if code.trim().is_empty() {
    return Err(ApiError::invalid("脚本内容不能为空"));
  }
  if code.len() > 256 * 1024 {
    return Err(ApiError::invalid("脚本内容不能超过 256KB"));
  }
  if image.is_some_and(|s| s.trim().is_empty()) {
    return Err(ApiError::invalid("镜像不能为空"));
  }
  Ok(())
}

fn validate(
  name: &str,
  spec: &TaskSpec,
  snap: &snapshot::Snapshot,
) -> Result<(), ApiError> {
  validate_name("task", name)?;
  crate::secret_policy::validate_task(name, &spec.how)?;
  if !snap.world.servers.contains_key(&spec.server) {
    return Err(crate::world::server_not_found(&spec.server));
  }
  validate_schedule(spec)?;
  if spec.skip_if_stopped
    && !matches!(spec.how, TaskKind::Exec { .. })
  {
    return Err(ApiError::invalid(
      "skip_if_stopped 仅适用于容器内执行（--exec）任务",
    ));
  }
  if let Some(mins) = spec.catch_up_mins {
    if matches!(spec.how, TaskKind::Ping { .. })
      || spec.schedule.is_empty()
    {
      return Err(ApiError::invalid(
        "补跑只适用于由 Wharf 定时执行的任务",
      ));
    }
    if !(1..=1440).contains(&mins) {
      return Err(ApiError::invalid(
        "补跑宽限时间要在 1 到 1440 分钟之间",
      ));
    }
  }
  if spec
    .artifacts_max_mb
    .is_some_and(|size| !(1..=200).contains(&size))
    || spec
      .artifacts_keep
      .is_some_and(|keep| !(1..=20).contains(&keep))
  {
    return Err(ApiError::invalid(
      "产物大小上限须为 1 到 200 MiB，保留次数须为 1 到 20",
    ));
  }
  let max = match spec.how {
    TaskKind::Host { .. } => HOST_MAX,
    _ => OTHER_MAX,
  };
  if !(1..=max).contains(&spec.timeout_secs) {
    return Err(ApiError::invalid(format!(
      "超时要在 1 到 {max} 秒之间"
    )));
  }
  let blank = |s: &str| s.trim().is_empty();
  match &spec.how {
    TaskKind::Exec {
      service, command, ..
    } => {
      if !snap.world.services.contains_key(service) {
        return Err(
          ApiError::not_found(format!("没有服务 {service}"))
            .with_hint("wharf service list"),
        );
      }
      if blank(command) {
        return Err(ApiError::invalid("命令不能为空"));
      }
    }
    TaskKind::Script {
      code,
      image,
      deps,
      runtime,
      ..
    } => validate_script(*runtime, code, deps, image.as_deref())?,
    TaskKind::Container { image, mounts, .. } => {
      if blank(image) {
        return Err(ApiError::invalid("镜像不能为空"));
      }
      if let Some(m) = mounts
        .iter()
        .find(|m| !m.starts_with('/') || !m.contains(':'))
      {
        return Err(ApiError::invalid(format!(
          "挂载要写成 `/宿主机路径:/容器路径[:ro]`：{m}"
        )));
      }
    }
    TaskKind::Host { command } => {
      if blank(command) {
        return Err(ApiError::invalid("命令不能为空"));
      }
    }
    TaskKind::Ping { grace_mins, .. } => {
      if !(1..=7 * 24 * 60).contains(grace_mins) {
        return Err(ApiError::invalid(
          "宽限时间要在 1 分钟到 7 天之间",
        ));
      }
    }
  }
  Ok(())
}

pub(crate) fn need_perm(
  auth: &Auth,
  spec: &TaskSpec,
  world: &crate::world::World,
  core_server: Option<&str>,
) -> Result<(), crate::api::AppError> {
  let target = crate::host_access::HostTarget::Task(spec);
  if crate::host_access::assess(target).required {
    return crate::host_access::require_with(
      auth,
      target,
      world.servers.get(&spec.server).map(|row| &row.settings),
      core_server,
    );
  }
  auth.require(Perm::Apply)?;
  if matches!(
    spec.how,
    TaskKind::Script { .. }
      | TaskKind::Exec { .. }
      | TaskKind::Container { .. }
  ) {
    auth.require(Perm::Exec)?;
  }
  Ok(())
}

fn run_view(r: &rusqlite::Row) -> rusqlite::Result<TaskRunView> {
  Ok(TaskRunView {
    id: r.get(0)?,
    task: r.get(1)?,
    status: dec(&r.get::<_, String>(2)?),
    trigger: r.get(3)?,
    started_at: to_time(r.get(4)?),
    ended_at: r.get::<_, Option<i64>>(5)?.map(to_time),
    exit_code: r.get(6)?,
    output: crate::log_redact::redact_text(&r.get::<_, String>(7)?),
    mem_peak: r.get(8)?,
    service: r.get(9)?,
    artifacts: r
      .get::<_, Option<String>>(10)?
      .and_then(|raw| {
        serde_json::from_str::<artifacts::Stored>(&raw).ok()
      })
      .map(|s| s.files)
      .unwrap_or_default(),
  })
}

const RUN_COLS: &str = "id, task, status, trigger, started_at, ended_at, exit_code, output, mem_peak, service, artifacts";

/// `GET /api/tasks`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<TaskView>> {
  auth.require(Perm::Read)?;
  Ok(Json(build_views(&s, &auth, None, false).await?))
}

#[derive(Default, Deserialize)]
pub struct TaskQuery {
  #[serde(default)]
  reveal: bool,
}

pub(crate) mod artifacts;
#[path = "tasks/read.rs"]
mod read;
use read::build_views;

/// 单任务详情才测持久目录，失败不影响读取配置。
pub async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<TaskQuery>,
) -> ApiResult<TaskView> {
  auth.require(Perm::Read)?;
  let mut task = build_views(&s, &auth, Some(&name), q.reveal)
    .await?
    .pop()
    .ok_or_else(|| {
      if let Some(allowed) = &auth.services {
        crate::token_scope::forbidden(&auth.name, allowed, "")
      } else {
        ApiError::not_found(format!("没有定时任务 {name}"))
      }
    })?;
  if matches!(task.spec.how, TaskKind::Script { .. }) {
    let disks: Result<Vec<ServiceDisk>, _> = s
      .hub
      .call(
        &task.spec.server,
        AgentOp::DiskUsage {
          services: vec![format!("{TASK_DATA_PREFIX}{name}")],
        },
        Duration::from_secs(30),
        None,
        &CancellationToken::new(),
      )
      .await;
    task.data_bytes =
      disks.ok().and_then(|v| v.first().map(|d| d.data));
  }
  Ok(Json(task))
}

#[derive(Deserialize)]
pub struct PutTaskQuery {
  #[serde(default)]
  rotate_token: bool,
}

/// `PUT /api/tasks/{name}`：新建或修改。
pub async fn put(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(query): Query<PutTaskQuery>,
  Json(mut spec): Json<TaskSpec>,
) -> ApiResult<TaskSpec> {
  let snap = snapshot::load(&s.db).await?;
  if let TaskKind::Exec { service, .. } = &spec.how
    && let Some(server) =
      snapshot::service_runtime_server(&snap, service)
  {
    spec.server = server.to_string();
  }
  let core_server = crate::join::core_server_of(&snap);
  need_perm(&auth, &spec, &snap.world, core_server.as_deref())?;
  if let Ok(old) = load_one(&s, &name).await {
    need_perm(&auth, &old, &snap.world, core_server.as_deref())?;
  }
  validate(&name, &spec, &snap)?;
  let spec = s.db.call(move |c| {
    let mut spec = spec;
    crate::secret_policy::validate_task_restrictions(
      &name, &spec.how, &crate::secret_restrictions::load(c)?,
    )?;
    let rows = load_rows(c)?;
    let old = rows.iter().find(|(n, _, _)| n == &name).map(|(_, spec, _)| spec);
    if query.rotate_token {
      rotate_task_token(&mut spec.how)?;
    }
    if let TaskKind::Ping { token, .. } = &mut spec.how && token.is_empty() {
      *token = old.filter(|s| matches!(s.how, TaskKind::Ping { .. }))
        .and_then(task_token).map(str::to_string).unwrap_or_else(crate::auth::new_token);
    }
    if let TaskKind::Script { hook, .. } = &mut spec.how {
      let prior = old.filter(|s| matches!(s.how, TaskKind::Script { .. }))
        .and_then(task_token).map(str::to_string);
      *hook = next_hook(prior, hook.take());
    }
    if let Some(token) = task_token(&spec) {
      let used = rows.iter().any(|(n, other, _)| n != &name && task_token(other) == Some(token));
      validate_task_token(token, old.and_then(task_token), used)?;
    }
    let text = serde_json::to_string(&spec).map_err(crate::db::json_err)?;
    let tx = c.transaction().map_err(sql_err)?;
    tx.execute(
      "INSERT INTO tasks (name, spec, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)
       ON CONFLICT (name) DO UPDATE SET spec = excluded.spec, updated_at = excluded.updated_at",
      params![name, text, now_ms()],
    ).map_err(sql_err)?;
    if !spec.enabled || !spec.notify {
      crate::db::set_setting(&tx, &task_notice_key(&name), None)?;
    }
    tx.commit().map_err(sql_err)?;
    index_hooks(&load_rows(c)?);
    Ok(spec)
  }).await?;
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(spec))
}

#[derive(Deserialize)]
pub struct RemoveQuery {
  #[serde(default)]
  data: bool,
}

fn require_confirm_task_data(
  auth: &Auth,
  name: &str,
  spec: &TaskSpec,
  data: bool,
) -> Result<(), crate::api::AppError> {
  if data
    && matches!(spec.how, TaskKind::Script { .. })
    && !auth.has(Perm::Confirm)
  {
    let have = auth
      .perms
      .iter()
      .map(|p| p.as_str())
      .collect::<Vec<_>>()
      .join(",");
    return Err(ApiError::new(ErrorCode::Forbidden, format!("永久删除定时任务 {name} 的持久数据需要 confirm 权限（当前 token 有：{have}）"))
      .with_hint("请用户在页面上操作，或在页面“设置 → CLI 与 AI 接入”换一个有 confirm 权限的 token").into());
  }
  Ok(())
}

/// `DELETE /api/tasks/{name}`：连运行记录一起删。
pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RemoveQuery>,
) -> ApiResult<serde_json::Value> {
  let spec = load_one(&s, &name).await?;
  let snap = snapshot::load(&s.db).await?;
  need_perm(
    &auth,
    &spec,
    &snap.world,
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  require_confirm_task_data(&auth, &name, &spec, q.data)?;
  let _guard = RunGuard::acquire(&name).ok_or_else(|| {
    ApiError::new(ErrorCode::Busy, "任务仍在运行，结束后再删除")
  })?;
  let task_name = name.clone();
  let mut servers: std::collections::BTreeSet<String> = s.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    let servers = {
      let mut stmt = tx.prepare(
        "SELECT DISTINCT json_extract(artifacts, '$.server') FROM task_runs WHERE task = ?1 AND artifacts IS NOT NULL"
      ).map_err(sql_err)?;
      stmt.query_map([&name], |r| r.get(0)).and_then(Iterator::collect).map_err(sql_err)?
    };
    tx.execute("DELETE FROM tasks WHERE name = ?1", params![name]).map_err(sql_err)?;
    tx.execute("DELETE FROM task_runs WHERE task = ?1", params![name]).map_err(sql_err)?;
    crate::db::set_setting(&tx, &task_notice_key(&name), None)?;
    tx.commit().map_err(sql_err)?;
    index_hooks(&load_rows(c)?);
    Ok(servers)
  }).await?;
  servers.insert(spec.server.clone());
  artifacts::prune(&s, &task_name, &servers).await;
  crate::log_redact::refresh(&s.db).await;
  if q.data && matches!(spec.how, TaskKind::Script { .. }) {
    let result: wharf_api_types::agent::RemoveDataResult = s
      .hub
      .call(
        &spec.server,
        AgentOp::RemoveData {
          service: format!("{TASK_DATA_PREFIX}{task_name}"),
        },
        Duration::from_secs(30),
        None,
        &CancellationToken::new(),
      )
      .await?;
    if !result.removed {
      return Err(ApiError::new(ErrorCode::Conflict, format!("未能删除任务数据 /srv/{TASK_DATA_PREFIX}{task_name}：仍有容器挂载（{}）", result.blocked_by.join("、"))).into());
    }
  }
  Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunTaskRequest {
  #[serde(default)]
  env: BTreeMap<String, String>,
  #[serde(skip)]
  conn: Option<u64>,
}

fn validate_run_env(
  env: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  if env.len() > 64
    || env.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
      > 64 * 1024
  {
    return Err(ApiError::invalid(
      "临时环境变量最多 64 个、共 64 KiB",
    ));
  }
  for (key, value) in env {
    let mut bytes = key.bytes();
    if key.starts_with("WHARF_")
      || !bytes
        .next()
        .is_some_and(|b| b == b'_' || b.is_ascii_alphabetic())
      || !bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
    {
      return Err(ApiError::invalid(
        "临时环境变量名格式不正确，且不能以 WHARF_ 开头",
      ));
    }
    if value.len() > 16 * 1024 || value.contains('\0') {
      return Err(ApiError::invalid(
        "临时环境变量值最多 16 KiB，且不能包含 NUL",
      ));
    }
  }
  Ok(())
}

/// `POST /api/tasks/{name}/run`：立即运行，返回运行记录 id。
pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  body: Option<Json<RunTaskRequest>>,
) -> ApiResult<serde_json::Value> {
  let spec = load_one(&s, &name).await?;
  let snap = snapshot::load(&s.db).await?;
  need_perm(
    &auth,
    &spec,
    &snap.world,
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if matches!(spec.how, TaskKind::Ping { .. }) {
    return Err(
      ApiError::invalid(format!(
        "{name} 由外部运行，Wharf 不能替它跑"
      ))
      .with_hint("在运行它的机器上手动跑一次脚本")
      .into(),
    );
  }
  let request =
    body.map_or_else(RunTaskRequest::default, |body| body.0);
  if !request.env.is_empty() {
    if matches!(spec.how, TaskKind::Host { .. }) {
      return Err(
        ApiError::invalid("宿主机任务不支持临时 --env")
          .with_hint("将变量写进命令，或使用脚本/容器任务")
          .into(),
      );
    }
    validate_run_env(&request.env)?;
    crate::secret_policy::validate_task_env(
      &name,
      request.env.values().map(String::as_str),
      &snap.secret_restrictions,
    )?;
  }
  let (id, busy) = start_with_guard(
    &s,
    &name,
    spec,
    "manual",
    None,
    RunGuard::acquire(&name),
    request,
  )
  .await?;
  Ok(Json(
    serde_json::json!({ "id": id, "task": name, "status": if busy { "skipped" } else { "running" } }),
  ))
}

#[derive(Deserialize)]
pub struct RunsQuery {
  #[serde(default = "default_limit")]
  limit: i64,
}

fn default_limit() -> i64 {
  20
}

/// `GET /api/tasks/{name}/runs`
pub async fn runs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RunsQuery>,
) -> ApiResult<Vec<TaskRunView>> {
  check_run_scope(&s, &auth, &name).await?;
  let limit = q.limit.clamp(1, KEEP_RUNS);
  let visible = visible_services(&auth)?;
  let rows = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(&format!(
          "SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 AND (?3 IS NULL OR service IN (SELECT value FROM json_each(?3))) ORDER BY id DESC LIMIT ?2"
        ))
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![name, limit, visible], run_view)
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await?;
  Ok(Json(rows))
}

fn visible_services(auth: &Auth) -> Result<Option<String>, ApiError> {
  auth
    .services
    .as_ref()
    .map(serde_json::to_string)
    .transpose()
    .map_err(db::json_err)
}

async fn check_run_scope(
  s: &AppState,
  auth: &Auth,
  name: &str,
) -> Result<(), crate::api::AppError> {
  auth.require(Perm::Read)?;
  if let Some(allowed) = &auth.services {
    match load_one(s, name).await {
      Ok(spec) if matches!(&spec.how, TaskKind::Exec { service, .. } if allowed.contains(service)) =>
        {}
      Err(error) if error.code != ErrorCode::NotFound => {
        return Err(error.into());
      }
      _ => {
        return Err(
          crate::token_scope::forbidden(&auth.name, allowed, "")
            .into(),
        );
      }
    }
  }
  Ok(())
}

pub async fn run_detail(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((name, id)): Path<(String, i64)>,
) -> ApiResult<TaskRunView> {
  check_run_scope(&s, &auth, &name).await?;
  let visible = visible_services(&auth)?;
  Ok(Json(s.db.call(move |c| {
    c.query_row(
      &format!("SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 AND id = ?2 AND (?3 IS NULL OR service IN (SELECT value FROM json_each(?3)))"),
      params![name, id, visible], run_view,
    ).optional().map_err(sql_err)?.ok_or_else(|| {
      ApiError::not_found(format!("定时任务 {name} 没有运行记录 #{id}"))
        .with_hint(format!("只保留最近 50 条记录，查看列表：wharf task logs {name}"))
    })
  }).await?))
}

pub async fn cancel_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<i64>,
) -> ApiResult<serde_json::Value> {
  let (name, status): (String, String) = s
    .db
    .call(move |c| {
      c.query_row(
        "SELECT task, status FROM task_runs WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
      )
      .optional()
      .map_err(sql_err)?
      .ok_or_else(|| {
        ApiError::not_found(format!("没有运行记录 #{id}"))
      })
    })
    .await?;
  let spec = load_one(&s, &name).await?;
  let snap = snapshot::load(&s.db).await?;
  need_perm(
    &auth,
    &spec,
    &snap.world,
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if dec(&status) != TaskStatus::Running {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "运行记录 #{id} 已结束（{}），不能取消",
          status_text(dec(&status))
        ),
      )
      .into(),
    );
  }
  let active = RUNNING
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .get(&name)
    .filter(|run| run.id == id)
    .cloned();
  if let Some(run) = active {
    run.cancel.cancel();
  } else {
    s.db.call(move |c| {
      let changed = c.execute(
        "UPDATE task_runs SET status = 'cancelled', ended_at = ?2, output = '已手动取消' WHERE id = ?1 AND status = 'running'",
        params![id, now_ms()],
      ).map_err(sql_err)?;
      if changed == 0 {
        return Err(ApiError::new(ErrorCode::Conflict, format!("运行记录 #{id} 已结束")));
      }
      Ok(())
    }).await?;
  }
  Ok(Json(
    serde_json::json!({ "id": id, "task": name, "cancelled": true }),
  ))
}

fn validate_schedule(spec: &TaskSpec) -> Result<(), ApiError> {
  if spec.schedule.is_empty()
    && matches!(spec.how, TaskKind::Script { .. })
  {
    return Ok(());
  }
  Cron::parse(&spec.schedule).map(|_| ())
}

fn rotate_task_token(kind: &mut TaskKind) -> Result<(), ApiError> {
  let token = match kind {
    TaskKind::Ping { token, .. }
    | TaskKind::Script {
      hook: Some(token), ..
    } => token,
    _ => {
      return Err(ApiError::invalid(
        "只有开启了 --hook 的脚本任务或 --ping 外部报到任务支持轮换口令",
      ));
    }
  };
  *token = crate::auth::new_token();
  Ok(())
}

#[test]
fn task_disable_hook_and_rotate_token() {
  assert_eq!(next_hook(Some("fixture".into()), None), None);
  let mut kind = TaskKind::Ping {
    token: "fixture".into(),
    grace_mins: 5,
  };
  rotate_task_token(&mut kind).unwrap();
  assert!(
    matches!(kind, TaskKind::Ping { token, .. } if !token.is_empty() && token != "fixture")
  );
}

fn next_hook(
  old: Option<String>,
  new: Option<String>,
) -> Option<String> {
  new.map(|token| {
    if token.is_empty() {
      old
        .filter(|s| !s.is_empty())
        .unwrap_or_else(crate::auth::new_token)
    } else {
      token
    }
  })
}

/// 公开触发地址只按口令查找，不泄露任务是否存在。
pub async fn hook(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  request: Request<Body>,
) -> Result<Response, crate::api::AppError> {
  let source = crate::login::client_key(peer.ip(), request.headers());
  if HOOK_FAILS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .blocked(&source, 30)
  {
    return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
  }
  let hash = crate::auth::hash_token(&token);
  let name = HOOK_INDEX
    .read()
    .unwrap_or_else(|e| e.into_inner())
    .get(&hash)
    .cloned();
  let found = if let Some(name) = name {
    s.db
      .call(move |c| {
        let row: Option<String> = c
          .query_row(
            "SELECT spec FROM tasks WHERE name = ?1",
            [&name],
            |r| r.get(0),
          )
          .optional()
          .map_err(sql_err)?;
        Ok(
          row
            .and_then(|row| {
              serde_json::from_str::<TaskSpec>(&row).ok()
            })
            .map(|spec| (name, spec)),
        )
      })
      .await?
  } else {
    None
  };
  let Some((name, spec)) = found.filter(|(_, spec)| {
    spec.enabled && matches!(&spec.how, TaskKind::Script { hook: Some(t), .. } if !t.is_empty() && constant_time_eq(t, &token))
  }) else {
    let allowed = HOOK_FAILS.lock().unwrap_or_else(|e| e.into_inner()).record(&source, 30);
    return Ok(if allowed { StatusCode::NOT_FOUND } else { StatusCode::TOO_MANY_REQUESTS }.into_response());
  };
  let Some(guard) = RunGuard::acquire(&name) else {
    return Ok(StatusCode::CONFLICT.into_response());
  };
  if !HOOKS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .record(&hash, 30)
  {
    return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
  }
  let method = request.method().to_string();
  let query = request.uri().query().unwrap_or_default().to_string();
  let body = match to_bytes(request.into_body(), 1024 * 1024).await {
    Ok(body) => body,
    Err(_) => {
      return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
  };
  let input = TaskInput {
    method,
    query,
    body: STANDARD.encode(body),
  };
  let (id, _) = start_with_guard(
    &s,
    &name,
    spec,
    "hook",
    Some(input),
    Some(guard),
    RunTaskRequest::default(),
  )
  .await?;
  Ok(
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "run": id })))
      .into_response(),
  )
}

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
  let mut diff = a.len() ^ b.len();
  for (i, byte) in a.bytes().enumerate() {
    diff |=
      usize::from(byte ^ b.as_bytes().get(i).copied().unwrap_or(0));
  }
  diff == 0
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn exec_task_follows_migrated_service_and_skips_in_flight() {
    let world = crate::world::World::from_rows(vec![db::ResourceRow {
      kind: "service".into(), name: "web".into(),
      spec: serde_json::json!({"server":"s2","source":{"image":"nginx"}}),
      meta: serde_json::json!({}), version: 1,
    }]).unwrap();
    let mut snap = snapshot::Snapshot {
      world,
      ..Default::default()
    };
    snap.pending.migrations.insert(
      "web".into(),
      crate::pending::Migration {
        phase: crate::pending::MigratePhase::Synced,
        payload: serde_json::from_value(
          serde_json::json!({"service":"web","from":"s1","to":"s2"}),
        )
        .unwrap(),
      },
    );
    assert!(exec_target(&snap, "web").is_err());
    snap.pending.migrations.get_mut("web").unwrap().phase =
      crate::pending::MigratePhase::UpDone;
    assert_eq!(exec_target(&snap, "web"), Ok("s2"));
  }

  #[tokio::test]
  async fn rebind_exec_task_preserves_run_token_scope() {
    let state = crate::rules::tests::test_state();
    let task = serde_json::json!({"server":"s1","kind":"exec","service":"notes","command":"true","schedule":"0 4 * * *"}).to_string();
    state.db.call(move |c| {
      c.execute("INSERT INTO tasks (name,spec,created_at,updated_at) VALUES ('dump',?1,0,0)", [task]).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    insert_run(
      &state,
      "dump",
      TaskStatus::Failed,
      "manual",
      Some(("web", Some("old"))),
    )
    .await
    .unwrap();
    insert_run(
      &state,
      "dump",
      TaskStatus::Succeeded,
      "manual",
      Some(("notes", Some("new"))),
    )
    .await
    .unwrap();
    let mut auth =
      crate::host_access::tests::auth([Perm::Read], false);
    auth.services = Some(["notes".into()].into_iter().collect());
    let Json(rows) = runs(
      State(state.clone()),
      auth,
      Path("dump".into()),
      Query(RunsQuery { limit: 10 }),
    )
    .await
    .map_err(|error| error.0)
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].service.as_deref(), Some("notes"));
    let mut auth =
      crate::host_access::tests::auth([Perm::Read], false);
    auth.services = Some(["notes".into()].into_iter().collect());
    let denied = run_detail(
      State(state),
      auth,
      Path(("dump".into(), rows[0].id - 1)),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.0.code, ErrorCode::NotFound);
  }

  #[tokio::test]
  async fn quiet_task_clears_legacy_dedup_and_disabled_task_is_hidden()
   {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      let spec = serde_json::json!({"server":"s1","kind":"ping","notify":false}).to_string();
      c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES ('daily', ?1, 0, 0)", [spec]).map_err(sql_err)?;
      c.execute("INSERT INTO task_runs (id, task, status, trigger, started_at) VALUES (1,'daily','succeeded','ping',0)", []).map_err(sql_err)?;
      db::set_setting(c, &task_notice_key("daily"), Some("fail"))
    }).await.unwrap();
    notify_result(
      &state,
      "daily",
      1,
      TaskStatus::Succeeded,
      "",
      None,
    )
    .await;
    state.db.call(|c| {
      assert!(db::setting(c, &task_notice_key("daily"))?.is_none());
      c.execute("UPDATE tasks SET spec = json_set(spec, '$.enabled', json('false'))", []).map_err(sql_err)?;
      c.execute("UPDATE task_runs SET status = 'failed'", []).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    assert!(issues(&state).await.is_empty());
  }

  #[test]
  fn empty_schedule_only_for_script() {
    let mut spec: TaskSpec = serde_json::from_value(serde_json::json!({
      "server": "s1", "schedule": "", "kind": "script", "runtime": "shell", "code": "echo ok"
    })).unwrap();
    assert!(validate_schedule(&spec).is_ok());
    spec.how = TaskKind::Host {
      command: "echo ok".into(),
    };
    assert!(validate_schedule(&spec).is_err());
  }

  #[test]
  fn empty_hook_generates_and_preserves_token() {
    let token = next_hook(None, Some(String::new())).unwrap();
    assert!(!token.is_empty());
    assert_eq!(
      next_hook(Some(token.clone()), Some(String::new())),
      Some(token)
    );
    assert_eq!(next_hook(Some("old".into()), None), None);
  }
  fn task(fields: serde_json::Value) -> TaskSpec {
    let mut spec =
      serde_json::json!({"server":"s1","schedule":"* * * * *"});
    spec
      .as_object_mut()
      .unwrap()
      .extend(fields.as_object().unwrap().clone());
    serde_json::from_value(spec).unwrap()
  }

  #[test]
  fn host_and_mount_tasks_require_host_and_their_switch() {
    use crate::host_access::tests::auth;
    let host = auth([Perm::Host], false);
    for (fields, field, other) in [
      (
        serde_json::json!({"kind":"host","command":"true"}),
        "host_exec",
        "host_docker",
      ),
      (
        serde_json::json!({"kind":"container","image":"alpine","mounts":["/:/host"]}),
        "host_docker",
        "host_exec",
      ),
    ] {
      let spec = task(fields);
      let mut world = crate::world::World::default();
      let settings = |key: &str| {
        serde_json::from_value(serde_json::json!({(key): true}))
          .unwrap()
      };
      world.servers.insert(
        "s1".into(),
        crate::world::ServerRow {
          settings: settings(other),
          version: 1,
        },
      );
      let err =
        need_perm(&host, &spec, &world, Some("core")).unwrap_err().0;
      assert_eq!(err.code, ErrorCode::Forbidden);
      assert!(err.message.contains(field));
      world.servers.get_mut("s1").unwrap().settings = settings(field);
      assert!(need_perm(&host, &spec, &world, Some("core")).is_ok());
    }
  }

  #[test]
  fn script_exec_and_plain_container_tasks_require_exec() {
    use crate::host_access::tests::auth;
    let apply = auth([Perm::Read, Perm::Apply], false);
    let exec = auth([Perm::Read, Perm::Apply, Perm::Exec], false);
    for fields in [
      serde_json::json!({"kind":"script","runtime":"shell","code":"true"}),
      serde_json::json!({"kind":"exec","service":"app","command":"true"}),
      serde_json::json!({"kind":"container","image":"alpine"}),
    ] {
      let spec = task(fields);
      assert_eq!(
        need_perm(&apply, &spec, &Default::default(), None)
          .unwrap_err()
          .0
          .code,
        ErrorCode::Forbidden
      );
      assert!(
        need_perm(&exec, &spec, &Default::default(), None).is_ok()
      );
    }
    assert!(
      need_perm(
        &apply,
        &task(serde_json::json!({"kind":"ping"})),
        &Default::default(),
        None
      )
      .is_ok()
    );
  }

  #[test]
  fn delete_task_with_data_requires_confirm() {
    use crate::host_access::tests::auth;
    let apply = auth([Perm::Apply, Perm::Exec], false);
    let confirm =
      auth([Perm::Apply, Perm::Exec, Perm::Confirm], false);
    let spec = task(
      serde_json::json!({"kind":"script","runtime":"shell","code":"true"}),
    );
    let check = |auth, data| {
      need_perm(auth, &spec, &Default::default(), None).and_then(
        |()| require_confirm_task_data(auth, "script", &spec, data),
      )
    };
    assert_eq!(
      check(&apply, true).unwrap_err().0.code,
      ErrorCode::Forbidden
    );
    assert!(check(&confirm, true).is_ok());
    assert!(check(&apply, false).is_ok());
  }
}

#[test]
fn rejects_weak_and_reused_task_tokens() {
  assert!(validate_task_token("abc", None, false).is_err());
  assert!(validate_task_token("abc", Some("abc"), false).is_ok());
  assert!(validate_task_token(&"a".repeat(24), None, true).is_err());
  assert!(validate_task_token(&"a".repeat(24), None, false).is_ok());
  let mut limit = crate::notify_keys::RequestLimit::default();
  for _ in 0..30 {
    assert!(limit.record("203.0.113.1", 30));
  }
  assert!(limit.blocked("203.0.113.1", 30));
}

#[tokio::test]
async fn hook_rejects_unknown_tokens_before_reading_body() {
  let state = crate::rules::tests::test_state();
  let peer = ConnectInfo("203.0.113.15:12345".parse().unwrap());
  for index in 0..35 {
    let result = hook(
      State(state.clone()),
      Path("fixture-unknown".into()),
      peer,
      Request::new(Body::empty()),
    )
    .await;
    assert_eq!(
      result.ok().unwrap().status(),
      if index < 30 {
        StatusCode::NOT_FOUND
      } else {
        StatusCode::TOO_MANY_REQUESTS
      }
    );
  }
}

#[tokio::test]
async fn host_task_keeps_command_template_in_shell_log() {
  let state = crate::rules::tests::test_state();
  state
    .db
    .call(|c| {
      crate::db::apply_write(
        c,
        &crate::db::Write::Upsert {
          kind: "server".into(),
          name: "s1".into(),
          spec: serde_json::json!({}),
          meta: serde_json::json!({}),
        },
      )
    })
    .await
    .unwrap();
  let job = HostExecJob {
    stream: false,
    command: "curl https://api.example.test/fixture-secret".into(),
    timeout_secs: 1,
    cwd: "/".into(),
  };
  let template = "curl https://api.example.test/[[API_KEY]]";
  assert!(
    crate::shell::run_host_with_audit(
      state.clone(),
      "task:t1",
      "s1".into(),
      job,
      Some(template)
    )
    .await
    .is_err()
  );
  let command = state
    .db
    .call(|c| {
      c.query_row("SELECT command FROM shell_log", [], |row| {
        row.get::<_, String>(0)
      })
      .map_err(sql_err)
    })
    .await
    .unwrap();
  assert_eq!(command, template);
}

#[tokio::test]
async fn task_skips_when_service_stopped_and_catches_up_once_after_offline()
 {
  let state = crate::rules::tests::test_state();
  let now = minute_floor(Utc::now());
  let before = now - chrono::Duration::minutes(1);
  state.db.call(move |c| {
    for (kind, name, spec) in [
      ("server", "s1", serde_json::json!({})),
      ("server", "s2", serde_json::json!({})),
      ("service", "app", serde_json::json!({"server":"s1","source":{"image":"app:1"},"stopped":true})),
    ] {
      crate::db::apply_write(c, &crate::db::Write::Upsert { kind: kind.into(), name: name.into(), spec, meta: serde_json::json!({}) })?;
    }
    c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
      params!["skipped", serde_json::json!({
        "server":"s1","schedule":"* * * * *","kind":"exec","service":"app","command":"true","skip_if_stopped":true,
      }).to_string(), before.timestamp_millis()]).map_err(sql_err)?;
    c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
      params!["catchup", serde_json::json!({
        "server":"s1","schedule":"* * * * *","kind":"host","command":"true","catch_up_mins":120,"notify":false,
      }).to_string(), before.timestamp_millis()]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let expired = now - chrono::Duration::minutes(120);
  let (_, mut spec, _) = load(&state)
    .await
    .unwrap()
    .into_iter()
    .find(|(name, ..)| name == "skipped")
    .unwrap();
  let world = snapshot::load(&state.db).await.unwrap().world;
  assert_eq!(should_skip_stopped(&spec, &world), Some("app"));
  spec.skip_if_stopped = false;
  assert!(should_skip_stopped(&spec, &world).is_none());
  let local = expired
    .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());
  let expired_spec = serde_json::json!({
    "server":"s2","schedule":local.format("%M %H * * *").to_string(),
    "kind":"host","command":"true","catch_up_mins":120,"notify":false,
  })
  .to_string();
  state.db.call(move |c| {
    c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES ('expired', ?1, ?2, ?2)",
      params![expired_spec, expired.timestamp_millis()]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  tick(&state, before, now).await.unwrap();
  assert!(scheduled_since(&state, "skipped", now).await.unwrap());
  assert!(!scheduled_since(&state, "catchup", now).await.unwrap());
  state.hub.mock_agent("s1", false, |_| Ok(serde_json::json!({"output":"","exit_code":0,"timed_out":false})));
  tick(&state, now, now).await.unwrap();
  tick(&state, now, now).await.unwrap();
  state.db.call(|c| {
    let (count, trigger): (i64, String) = c.query_row(
      "SELECT COUNT(*), trigger FROM task_runs WHERE task = 'catchup'", [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(sql_err)?;
    assert_eq!((count, trigger.as_str()), (1, "catch_up"));
    let status: String = c.query_row("SELECT status FROM task_runs WHERE task = 'skipped'", [], |r| r.get(0)).map_err(sql_err)?;
    assert_eq!(status, "skipped");
    let expired: (i64, String) = c.query_row(
      "SELECT COUNT(*), status FROM task_runs WHERE task = 'expired'", [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(sql_err)?;
    assert_eq!(expired, (1, "failed".into()));
    Ok(())
  }).await.unwrap();
}

#[tokio::test]
async fn resume_skips_paused_due_times_without_skipping_future_runs()
{
  let state = crate::rules::tests::test_state();
  let resume =
    DateTime::parse_from_rfc3339("2026-11-20T10:20:00+08:00")
      .unwrap()
      .with_timezone(&Utc);
  state.resumed_at.set(resume).unwrap();
  state.db.call(|c| {
    c.execute_batch(
      "INSERT INTO tasks (name, spec, created_at, updated_at) VALUES
       ('online', '{\"server\":\"s1\",\"kind\":\"host\",\"command\":\"true\",\"schedule\":\"0 * * * *\",\"catch_up_mins\":60,\"notify\":false}', 0, 0),
       ('offline', '{\"server\":\"s2\",\"kind\":\"host\",\"command\":\"true\",\"schedule\":\"0 10 * * *\",\"catch_up_mins\":60,\"notify\":false}', 0, 0)",
    ).map_err(sql_err)
  }).await.unwrap();
  state.hub.mock_agent("s1", false, |_| Ok(serde_json::json!({"output":"","exit_code":0,"timed_out":false})));
  let minute = chrono::Duration::minutes(1);
  tick(&state, resume, resume + minute).await.unwrap();
  assert!(
    !scheduled_since(&state, "online", resume - minute * 20)
      .await
      .unwrap()
  );

  let next = resume + minute * 40;
  tick(&state, next - minute, next).await.unwrap();
  assert!(
    !scheduled_since(&state, "offline", resume - minute * 20)
      .await
      .unwrap()
  );
  assert!(scheduled_since(&state, "online", next).await.unwrap());
}

#[tokio::test]
async fn expired_exec_catch_up_skips_an_undeployed_service() {
  let state = crate::rules::tests::test_state();
  let at = DateTime::parse_from_rfc3339("2026-11-20T10:30:00+08:00")
    .unwrap()
    .with_timezone(&Utc);
  let due = at - chrono::Duration::minutes(30);
  state.db.call(|c| {
    db::apply_write(c, &db::Write::Upsert {
      kind: "service".into(), name: "web".into(),
      spec: serde_json::json!({"server":"s2","source":{"image":"app:1"}}),
      meta: serde_json::json!({}),
    })?;
    c.execute_batch(
      "INSERT INTO tasks (name, spec, created_at, updated_at) VALUES
       ('dump', '{\"server\":\"s1\",\"kind\":\"exec\",\"service\":\"web\",\"command\":\"true\",\"schedule\":\"0 10 * * *\",\"catch_up_mins\":30}', 0, 0)",
    ).map_err(sql_err)
  }).await.unwrap();
  let before = at - chrono::Duration::minutes(1);
  tick(&state, before, at).await.unwrap();
  tick(&state, before, at).await.unwrap();
  state.db.call(move |c| {
    let row: (i64, String, String, i64) = c.query_row(
      "SELECT COUNT(*), status, output, started_at FROM task_runs WHERE task = 'dump' AND trigger = 'catch_up'",
      [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).map_err(sql_err)?;
    assert_eq!(row, (
      1, "skipped".into(), "服务 web 尚未部署，跳过本次执行".into(),
      due.timestamp_millis(),
    ));
    Ok(())
  }).await.unwrap();
}

#[tokio::test]
async fn expired_schedule_does_not_hide_next_catch_up() {
  let state = crate::rules::tests::test_state();
  let next = minute_floor(Utc::now());
  let missed = next - chrono::Duration::minutes(1);
  state.db.call(move |c| {
    c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES ('overlap', ?1, ?2, ?2)",
      params![serde_json::json!({
        "server":"s1","schedule":"* * * * *","kind":"host","command":"true","catch_up_mins":1,"notify":false,
      }).to_string(), missed.timestamp_millis()]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();

  tick(&state, missed, next).await.unwrap();
  assert!(scheduled_since(&state, "overlap", missed).await.unwrap());
  assert!(!scheduled_since(&state, "overlap", next).await.unwrap());

  state.hub.mock_agent("s1", false, |_| Ok(serde_json::json!({"output":"","exit_code":0,"timed_out":false})));
  tick(&state, next, next).await.unwrap();
  tick(&state, next, next).await.unwrap();
  state.db.call(move |c| {
    let count: i64 = c.query_row(
      "SELECT count(*) FROM task_runs WHERE task = 'overlap' AND trigger = 'catch_up' AND started_at >= ?1",
      [next.timestamp_millis()], |r| r.get(0),
    ).map_err(sql_err)?;
    assert_eq!(count, 1);
    Ok(())
  }).await.unwrap();
}

#[cfg(test)]
#[tokio::test]
async fn task_is_cancellable_as_soon_as_run_record_is_visible() {
  use crate::host_access::tests::auth;
  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    c.execute("INSERT INTO tasks(name,spec,created_at,updated_at) VALUES ('cancel-fixture',?1,0,0)",
      [serde_json::json!({"server":"s1", "kind":"exec", "service":"app", "command":"true", "schedule":"0 4 * * *"}).to_string()]
    ).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let failed = insert_run(
    &state,
    "cancel-fixture",
    TaskStatus::Failed,
    "manual",
    None,
  )
  .await
  .unwrap();
  finish(
    &state,
    failed,
    TaskStatus::Failed,
    Some(1),
    "上次失败",
    None,
    None,
  )
  .await;
  let guard = RunGuard::acquire("cancel-fixture").unwrap();
  let token = guard.cancel.clone();
  let (id, _guard) = insert_run_at(
    &state,
    "cancel-fixture",
    TaskStatus::Running,
    "manual",
    now_ms(),
    None,
    Some(guard),
  )
  .await
  .unwrap();
  let permissions =
    || auth([Perm::Read, Perm::Apply, Perm::Exec], false);
  let Json(receipt) =
    cancel_run(State(state.clone()), permissions(), Path(id))
      .await
      .map_err(|error| error.0)
      .unwrap();
  assert_eq!(receipt["cancelled"], true);
  assert!(token.is_cancelled());
  finish(
    &state,
    id,
    TaskStatus::Cancelled,
    None,
    "已手动取消",
    None,
    None,
  )
  .await;
  assert_eq!(
    cancel_run(State(state.clone()), permissions(), Path(id))
      .await
      .unwrap_err()
      .0
      .code,
    ErrorCode::Conflict
  );
  assert_eq!(
    run_detail(
      State(state.clone()),
      permissions(),
      Path(("cancel-fixture".into(), failed))
    )
    .await
    .map_err(|error| error.0)
    .unwrap()
    .0
    .output,
    "上次失败"
  );
  assert!(
    issues(&state)
      .await
      .iter()
      .any(|issue| issue.title.contains("cancel-fixture"))
  );
}

#[cfg(test)]
#[test]
fn temporary_env_rejects_reserved_names_and_restricted_values() {
  assert!(
    validate_run_env(&BTreeMap::from([(
      "WHARF_METHOD".into(),
      "GET".into()
    )]))
    .is_err()
  );
  let restrictions = BTreeMap::from([(
    "PRIVATE_KEY".into(),
    ["svc".into()].into_iter().collect(),
  )]);
  for value in ["[[PRIVATE_KEY]]", "[[WHARF_INTERNAL]]"] {
    assert!(
      crate::secret_policy::validate_task_env(
        "fixture",
        [value].into_iter(),
        &restrictions
      )
      .is_err()
    );
  }
}

#[cfg(test)]
#[tokio::test]
async fn temporary_env_masks_only_long_values_without_persisting_settings()
 {
  use crate::host_access::tests::auth;
  use serde_json::json;
  let state = crate::rules::tests::test_state();
  let spec = json!({"server":"s1","schedule":"0 4 * * *","kind":"exec","service":"app","command":"echo ok","notify":false});
  let saved = spec.to_string();
  state.db.call(move |c| {
    db::apply_write(c, &db::Write::Upsert {
      kind: "server".into(), name: "s2".into(), spec: json!({}), meta: json!({}),
    })?;
    db::apply_write(c, &db::Write::Upsert {
      kind: "service".into(), name: "app".into(),
      spec: json!({"server":"s2","source":{"image":"alpine"}}),
      meta: json!({"instance_id":"fixture"}),
    })?;
    c.execute("INSERT INTO deployments(service,server,run_id,hash,compose,images,created_at,instance_id)
       SELECT 'app','s2','r1','h','{}','[]',0,json_extract(meta,'$.instance_id')
       FROM resources WHERE kind='service' AND name='app'", []).map_err(sql_err)?;
    c.execute("INSERT INTO tasks(name,spec,created_at,updated_at) VALUES ('env-fixture',?1,0,0)", [saved]).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let (sent, received) = tokio::sync::oneshot::channel();
  let mut sent = Some(sent);
  state.hub.mock_agent("s2", false, move |op| {
    let AgentOp::TaskRun(TaskRunJob { how: TaskHow::Exec { env, .. }, .. }) = op else {
      panic!("意外请求");
    };
    assert_eq!(env.get("AUTH_MODE").map(String::as_str), Some("1"));
    assert_eq!(env.get("AUTH_TOKEN").map(String::as_str), Some("fixture-long"));
    let _ = sent.take().unwrap().send(());
    Ok(json!({"output":"mode 1 fixture-long","exit_code":0,"timed_out":false,"duration_ms":0}))
  });
  let start = || {
    run_now(
      State(state.clone()),
      auth([Perm::Apply, Perm::Exec], false),
      Path("env-fixture".into()),
      Some(Json(RunTaskRequest {
        env: BTreeMap::from([
          ("AUTH_MODE".into(), "1".into()),
          ("AUTH_TOKEN".into(), "fixture-long".into()),
        ]),
        conn: None,
      })),
    )
  };
  assert_eq!(start().await.unwrap_err().0.code, ErrorCode::Conflict);
  state.hub.enable_mock_exec_v2("s2");
  let Json(receipt) = start().await.map_err(|error| error.0).unwrap();
  assert_eq!(receipt["status"], "running");
  tokio::time::timeout(Duration::from_secs(2), received)
    .await
    .unwrap()
    .unwrap();
  let id = receipt["id"].as_i64().unwrap();
  let output = tokio::time::timeout(Duration::from_secs(2), async {
    loop {
      let Json(run) = run_detail(
        State(state.clone()),
        auth([Perm::Read], false),
        Path(("env-fixture".into(), id)),
      )
      .await
      .map_err(|error| error.0)
      .unwrap();
      if run.status != TaskStatus::Running {
        break run.output;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .unwrap();
  assert_eq!(output, "mode 1 ***");
  let after = load_one(&state, "env-fixture").await.unwrap();
  assert_eq!(
    serde_json::to_value(after).unwrap(),
    serde_json::to_value(
      serde_json::from_value::<TaskSpec>(spec).unwrap()
    )
    .unwrap()
  );
}
