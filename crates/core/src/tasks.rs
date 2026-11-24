//! 定时任务：控制面每 30 秒看一次到点的任务，下发给 agent 执行，记录结果，失败和恢复时通知。
//! 任务定义直接改，不走计划（定义本身不改机器）。控制面停机期间错过的不补跑。

use std::{
  collections::{BTreeSet, HashMap},
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Json,
  body::{Body, to_bytes},
  extract::{Path, Query, State},
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
  db::{now_ms, sql_err, to_time},
  render, snapshot,
  state::AppState,
};

const TICK: Duration = Duration::from_secs(30);
const KEEP_RUNS: i64 = 50;
const HOST_MAX: u64 = 600;
const OTHER_MAX: u64 = 6 * 3600;

/// 正在跑的任务，同一个任务不并发。
static RUNNING: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static HOOKS: LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
  LazyLock::new(Default::default);

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut checked = minute_floor(Utc::now());
    loop {
      tokio::time::sleep(TICK).await;
      let now = minute_floor(Utc::now());
      if let Err(e) = tick(&state, checked, now).await {
        tracing::warn!("检查定时任务失败：{e}");
      }
      checked = now;
    }
  });
}

/// `(after, until]` 之间每一分钟到点的任务各跑一次。
async fn tick(
  state: &Arc<AppState>,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) -> Result<(), ApiError> {
  if until <= after {
    return Ok(());
  }
  for (name, spec, _) in load(state).await? {
    if !spec.enabled || spec.schedule.is_empty() {
      continue;
    }
    let Ok(cron) = Cron::parse(&spec.schedule) else {
      continue;
    };
    if let TaskKind::Ping { grace_mins, .. } = spec.how {
      crate::ping::check_due(
        state, &name, &spec, &cron, grace_mins, after, until,
      )
      .await;
      continue;
    }
    if cron.next_after(after).is_some_and(|t| t <= until) {
      let _ = start(state, &name, spec, "schedule", None).await;
    }
  }
  Ok(())
}

pub(crate) async fn load(
  state: &AppState,
) -> Result<Vec<(String, TaskSpec, i64)>, ApiError> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT name, spec, updated_at FROM tasks ORDER BY name",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| {
          Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get(2)?,
          ))
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
    })
    .await
}

async fn load_one(
  state: &AppState,
  name: &str,
) -> Result<TaskSpec, ApiError> {
  load(state)
    .await?
    .into_iter()
    .find(|(n, _, _)| n == name)
    .map(|(_, s, _)| s)
    .ok_or_else(|| {
      ApiError::not_found(format!("没有定时任务 {name}"))
        .with_hint("wharf task ls")
    })
}

/// 记一条运行记录并在后台执行，返回记录 id。上一次还没跑完时记为跳过。
async fn start(
  state: &Arc<AppState>,
  name: &str,
  spec: TaskSpec,
  trigger: &str,
  input: Option<TaskInput>,
) -> Result<(i64, bool), ApiError> {
  let busy = !RUNNING
    .lock()
    .map(|mut r| r.insert(name.to_string()))
    .unwrap_or(false);
  let status = if busy {
    TaskStatus::Skipped
  } else {
    TaskStatus::Running
  };
  let id = insert_run(state, name, status, trigger).await;
  let id = match id {
    Ok(id) => id,
    Err(e) => {
      if !busy {
        release(name);
      }
      return Err(e);
    }
  };
  if busy {
    finish(
      state,
      id,
      TaskStatus::Skipped,
      None,
      "上一次还没跑完",
      None,
    )
    .await;
    return Ok((id, true));
  }
  let state = state.clone();
  let name = name.to_string();
  tokio::spawn(async move {
    let (status, code, output, mem_peak) =
      execute(&state, &name, &spec, input).await;
    finish(&state, id, status, code, &output, mem_peak).await;
    release(&name);
    notify_result(&state, &name, &spec, status, &output).await;
  });
  Ok((id, false))
}

/// 任务失败和恢复时推送（任务开了通知时）。
pub(crate) async fn notify_result(
  state: &AppState,
  name: &str,
  spec: &TaskSpec,
  status: TaskStatus,
  output: &str,
) {
  if !spec.notify {
    return;
  }
  let ok = status == TaskStatus::Succeeded;
  let title = if ok {
    format!("定时任务 {name} 恢复正常")
  } else {
    format!("定时任务 {name} {}", status_text(status))
  };
  crate::rules::notice(
    state,
    "task",
    Some(name),
    Some(&format!("task.{name}")),
    ok,
    crate::notify::Event {
      title,
      body: format!(
        "服务器 {}\n{}",
        spec.server,
        last_lines(output, 10)
      ),
    },
  )
  .await;
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
  }
}

fn last_lines(s: &str, n: usize) -> String {
  let lines: Vec<&str> = s.lines().collect();
  lines[lines.len().saturating_sub(n)..].join("\n")
}

/// 替换密钥、下发、把输出里的密钥值换成 `***`。
async fn execute(
  state: &Arc<AppState>,
  name: &str,
  spec: &TaskSpec,
  input: Option<TaskInput>,
) -> (TaskStatus, Option<i32>, String, Option<u64>) {
  let snap = match snapshot::load(&state.db).await {
    Ok(s) => s,
    Err(e) => return (TaskStatus::Failed, None, e.message, None),
  };
  let secrets = &snap.secrets;
  let used: Vec<&String> = secrets
    .values()
    .filter(|v| v.len() >= 4 && spec_mentions(spec, secrets, v))
    .collect();
  let redact = |s: String| {
    used.iter().fold(s, |acc, v| acc.replace(v.as_str(), "***"))
  };
  let result = run_on_agent(state, name, spec, &snap, input).await;
  match result {
    Ok(r) => {
      let status = if r.timed_out {
        TaskStatus::TimedOut
      } else if r.exit_code == Some(0) {
        TaskStatus::Succeeded
      } else {
        TaskStatus::Failed
      };
      (status, r.exit_code, redact(r.output), r.mem_peak)
    }
    Err(e) => {
      let status = if e.code == ErrorCode::Timeout {
        TaskStatus::TimedOut
      } else {
        TaskStatus::Failed
      };
      (status, None, redact(e.message), None)
    }
  }
}

/// 任务里引用了这个密钥（按值判断，免得再解析一遍）。
fn spec_mentions(
  spec: &TaskSpec,
  secrets: &std::collections::BTreeMap<String, String>,
  value: &str,
) -> bool {
  let text = serde_json::to_string(&spec.how).unwrap_or_default();
  secrets
    .iter()
    .any(|(k, v)| v == value && text.contains(&format!("[[{k}]]")))
}

async fn run_on_agent(
  state: &Arc<AppState>,
  name: &str,
  spec: &TaskSpec,
  snap: &snapshot::Snapshot,
  input: Option<TaskInput>,
) -> Result<TaskRunResult, ApiError> {
  let sub = |t: &str| render::substitute(t, Some(&snap.secrets));
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
        command: sub(command)?,
        timeout_secs: spec.timeout_secs,
        cwd: "/root".into(),
      };
      let r = crate::shell::run_host(
        state.clone(),
        &format!("task:{name}"),
        spec.server.clone(),
        job,
      )
      .await?;
      return Ok(TaskRunResult {
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
      env: env
        .iter()
        .map(|(k, v)| Ok((k.clone(), sub(v)?)))
        .collect::<Result<_, ApiError>>()?,
    },
    TaskKind::Container {
      image,
      command,
      env,
      mounts,
    } => TaskHow::Container {
      image: image.clone(),
      command: command.as_deref().map(&sub).transpose()?,
      env: env
        .iter()
        .map(|(k, v)| Ok((k.clone(), sub(v)?)))
        .collect::<Result<_, ApiError>>()?,
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
  let job = TaskRunJob {
    name: name.to_string(),
    how,
    input,
    network_host: false,
    out_dir: false,
    wait_for_deps: false,
    timeout_secs: spec.timeout_secs,
    pull: snapshot::pull_policy(server),
  };
  // 拉镜像的时间另算。
  let wait = Duration::from_secs(spec.timeout_secs + 15 * 60);
  state
    .hub
    .call(
      &spec.server,
      AgentOp::TaskRun(job),
      wait,
      None,
      &CancellationToken::new(),
    )
    .await
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
) -> Result<i64, ApiError> {
  let (name, trigger) = (name.to_string(), trigger.to_string());
  let status = enc(status);
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO task_runs (task, status, trigger, started_at) VALUES (?1, ?2, ?3, ?4)",
        params![name, status, trigger, now_ms()],
      )
      .map_err(sql_err)?;
      let id = c.last_insert_rowid();
      c.execute(
        "DELETE FROM task_runs WHERE task = ?1 AND id <= ?2 - ?3",
        params![name, id, KEEP_RUNS],
      )
      .map_err(sql_err)?;
      Ok(id)
    })
    .await
}

pub(crate) async fn finish(
  state: &AppState,
  id: i64,
  status: TaskStatus,
  code: Option<i32>,
  output: &str,
  mem_peak: Option<u64>,
) {
  let (status, output) = (enc(status), output.to_string());
  let r = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE task_runs SET status = ?2, exit_code = ?3, output = ?4, ended_at = ?5, mem_peak = ?6 WHERE id = ?1",
        params![id, status, code, output, now_ms(), mem_peak],
      )
      .map_err(sql_err)
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
             SELECT id FROM task_runs WHERE task = t.name AND status NOT IN ('skipped', 'running')
             ORDER BY id DESC LIMIT 1)
           WHERE r.status IN ('failed', 'timed_out') ORDER BY t.name",
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
      alert: crate::rules::issue_target("task", &n),
      ack: None,
      code: "task_failed".into(),
      level: IssueLevel::Warn,
      title: format!("定时任务 {n} {}", status_text(dec(&s))),
      subject: Some(IssueSubject {
        kind: "task".into(),
        name: n,
      }),
      hint: None,
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
  if !snap.world.servers.contains_key(&spec.server) {
    return Err(crate::world::server_not_found(&spec.server));
  }
  validate_schedule(spec)?;
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
      let svc =
        snap.world.services.get(service).ok_or_else(|| {
          ApiError::not_found(format!("没有服务 {service}"))
            .with_hint("wharf service list")
        })?;
      if svc.spec.server != spec.server {
        return Err(ApiError::invalid(format!(
          "服务 {service} 在 {}，任务的服务器要一致",
          svc.spec.server
        )));
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

fn need_perm(
  auth: &Auth,
  spec: &TaskSpec,
) -> Result<(), crate::api::AppError> {
  auth.require(Perm::Apply)?;
  if matches!(spec.how, TaskKind::Host { .. }) {
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
    output: r.get(7)?,
    mem_peak: r.get(8)?,
  })
}

const RUN_COLS: &str = "id, task, status, trigger, started_at, ended_at, exit_code, output, mem_peak";

/// `GET /api/tasks`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<TaskView>> {
  auth.require(Perm::Read)?;
  let tasks = load(&s).await?;
  let base = crate::join::default_url(&s).await;
  let mut out = Vec::new();
  let now = Utc::now();
  for (name, spec, updated) in tasks {
    let n = name.clone();
    let last = s
      .db
      .call(move |c| {
        c.query_row(
          &format!("SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT 1"),
          params![n],
          run_view,
        )
        .optional()
        .map_err(sql_err)
      })
      .await?;
    let next_at = spec
      .enabled
      .then(|| Cron::parse(&spec.schedule).ok()?.next_after(now))
      .flatten();
    let ping_url = match (&spec.how, &base) {
      (TaskKind::Ping { token, .. }, Some(b)) => {
        Some(format!("{}/ping/{token}", b.trim_end_matches('/')))
      }
      _ => None,
    };
    let hook_url = match (&spec.how, &base) {
      (
        TaskKind::Script {
          hook: Some(token), ..
        },
        Some(b),
      ) => Some(format!("{}/hook/{token}", b.trim_end_matches('/'))),
      _ => None,
    };
    out.push(TaskView {
      data_bytes: None,
      name,
      spec,
      last,
      next_at,
      ping_url,
      hook_url,
      updated_at: to_time(updated),
    });
  }
  Ok(Json(out))
}

/// 单任务详情才测持久目录，失败不影响读取配置。
pub async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<TaskView> {
  let mut task = list(State(s.clone()), auth)
    .await?
    .0
    .into_iter()
    .find(|t| t.name == name)
    .ok_or_else(|| {
      ApiError::not_found(format!("没有定时任务 {name}"))
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

/// `PUT /api/tasks/{name}`：新建或修改。
pub async fn put(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(spec): Json<TaskSpec>,
) -> ApiResult<TaskSpec> {
  need_perm(&auth, &spec)?;
  if let Ok(old) = load_one(&s, &name).await {
    need_perm(&auth, &old)?;
  }
  let snap = snapshot::load(&s.db).await?;
  validate(&name, &spec, &snap)?;
  let mut spec = spec;
  if let TaskKind::Ping { token, .. } = &mut spec.how
    && token.is_empty()
  {
    // 修改时沿用原来的口令，脚本里的地址不用改。
    *token = match load_one(&s, &name).await.map(|o| o.how) {
      Ok(TaskKind::Ping { token: old, .. }) if !old.is_empty() => old,
      _ => crate::auth::new_token(),
    };
  }
  if let TaskKind::Script { hook, .. } = &mut spec.how {
    let old = match load_one(&s, &name).await.map(|o| o.how) {
      Ok(TaskKind::Script { hook, .. }) => hook,
      _ => None,
    };
    *hook = next_hook(old, hook.take());
  }
  let text = serde_json::to_string(&spec)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  s.db
    .call(move |c| {
      let now = now_ms();
      c.execute(
        "INSERT INTO tasks (name, spec, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT (name) DO UPDATE SET spec = excluded.spec, updated_at = excluded.updated_at",
        params![name, text, now],
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(Json(spec))
}

#[derive(Deserialize)]
pub struct RemoveQuery {
  #[serde(default)]
  data: bool,
}

/// `DELETE /api/tasks/{name}`：连运行记录一起删。
pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RemoveQuery>,
) -> ApiResult<serde_json::Value> {
  let spec = load_one(&s, &name).await?;
  need_perm(&auth, &spec)?;
  let task_name = name.clone();
  s.db
    .call(move |c| {
      c.execute("DELETE FROM tasks WHERE name = ?1", params![name])
        .map_err(sql_err)?;
      c.execute(
        "DELETE FROM task_runs WHERE task = ?1",
        params![name],
      )
      .map_err(sql_err)
    })
    .await?;
  if q.data && matches!(spec.how, TaskKind::Script { .. }) {
    let _: serde_json::Value = s
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
  }
  Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /api/tasks/{name}/run`：立即运行，返回运行记录 id。
pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<serde_json::Value> {
  let spec = load_one(&s, &name).await?;
  need_perm(&auth, &spec)?;
  if matches!(spec.how, TaskKind::Ping { .. }) {
    return Err(
      ApiError::invalid(format!(
        "{name} 由外部运行，Wharf 不能替它跑"
      ))
      .with_hint("在运行它的机器上手动跑一次脚本")
      .into(),
    );
  }
  let (id, _) = start(&s, &name, spec, "manual", None).await?;
  Ok(Json(serde_json::json!({ "id": id })))
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
  auth.require(Perm::Read)?;
  let limit = q.limit.clamp(1, KEEP_RUNS);
  let rows = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(&format!(
          "SELECT {RUN_COLS} FROM task_runs WHERE task = ?1 ORDER BY id DESC LIMIT ?2"
        ))
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![name, limit], run_view)
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await?;
  Ok(Json(rows))
}

fn validate_schedule(spec: &TaskSpec) -> Result<(), ApiError> {
  if spec.schedule.is_empty()
    && matches!(spec.how, TaskKind::Script { .. })
  {
    return Ok(());
  }
  Cron::parse(&spec.schedule).map(|_| ())
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
  request: Request<Body>,
) -> Result<Response, crate::api::AppError> {
  let found = load(&s).await?.into_iter().find(|(_, spec, _)| {
    spec.enabled && matches!(&spec.how, TaskKind::Script { hook: Some(t), .. } if !t.is_empty() && t == &token)
  });
  let Some((name, spec, _)) = found else {
    return Ok(StatusCode::NOT_FOUND.into_response());
  };
  {
    let mut counts = HOOKS.lock().unwrap_or_else(|e| e.into_inner());
    counts
      .retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60));
    let (count, _) =
      counts.entry(token).or_insert((0, Instant::now()));
    if *count >= 30 {
      return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    *count += 1;
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
  let (id, skipped) =
    start(&s, &name, spec, "hook", Some(input)).await?;
  Ok(if skipped {
    (
      StatusCode::CONFLICT,
      Json(serde_json::json!({ "error": "上一次还没跑完" })),
    )
      .into_response()
  } else {
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "run": id })))
      .into_response()
  })
}

#[cfg(test)]
mod tests {
  use super::*;

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
}
