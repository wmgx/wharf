//! 宿主机命令执行和审计查询。

use std::{path::Path, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path as AxumPath, Query, State},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HostExecJob, HostExecOutcome},
  view::{HostExecResponse, ShellLog, TokenScope},
};

use crate::{
  api::{ApiResult, AppError},
  auth::Auth,
  db::{Db, now_ms, sql_err, to_time},
  snapshot,
  state::AppState,
  world::server_not_found,
};

const DEFAULT_TIMEOUT: u64 = 30;
const MAX_TIMEOUT: u64 = 600;
const COMMAND_LIMIT: usize = 64 * 1024;
const CLEANUP_GRACE: u64 = 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
  command: String,
  timeout_secs: Option<u64>,
  cwd: Option<String>,
}

impl ExecRequest {
  fn job(self) -> Result<HostExecJob, ApiError> {
    if self.command.trim().is_empty() {
      return Err(ApiError::invalid("命令不能为空"));
    }
    if self.command.len() > COMMAND_LIMIT {
      return Err(ApiError::invalid("命令不能超过 64 KiB"));
    }
    if self.command.contains('\0') {
      return Err(ApiError::invalid("命令不能包含 NUL"));
    }
    let timeout_secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT);
    if !(1..=MAX_TIMEOUT).contains(&timeout_secs) {
      return Err(ApiError::invalid("超时必须在 1 到 600 秒之间"));
    }
    let cwd = self.cwd.unwrap_or_else(|| "/".into());
    if !Path::new(&cwd).is_absolute() || cwd.contains('\0') {
      return Err(ApiError::invalid(
        "工作目录必须是绝对路径且不能包含 NUL",
      ));
    }
    Ok(HostExecJob {
      command: self.command,
      timeout_secs,
      cwd,
    })
  }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
  fn drop(&mut self) {
    self.0.cancel();
  }
}

/// `POST /api/servers/{name}/exec`
pub async fn exec(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  AxumPath(name): AxumPath<String>,
  Json(req): Json<ExecRequest>,
) -> ApiResult<HostExecResponse> {
  auth.require(TokenScope::ApplyAll)?;
  let job = req.job()?;
  let snap = snapshot::load(&state.db).await?;
  let server = snap
    .world
    .servers
    .get(&name)
    .ok_or_else(|| server_not_found(&name))?;
  let audit_id =
    start(&state.db, &auth.name, &name, "exec", Some(&job.command))
      .await?;
  if !server.settings.host_exec {
    let error = ApiError::new(
      ErrorCode::Forbidden,
      "命令执行未开启，请到“服务器详情 → 设置”开启“命令执行”。",
    );
    finish(&state.db, audit_id, End::error(&error)).await;
    return Err(error.into());
  }

  let cancel = CancellationToken::new();
  let _cancel_on_drop = CancelOnDrop(cancel.clone());
  let task_state = state.clone();
  let timeout = job.timeout_secs;
  let task = tokio::spawn(async move {
    let outcome = task_state
      .hub
      .call::<HostExecOutcome>(
        &name,
        AgentOp::HostExec(job),
        Duration::from_secs(timeout + CLEANUP_GRACE),
        None,
        &cancel,
      )
      .await;
    match outcome {
      Ok(HostExecOutcome::Finished(result)) => {
        finish(
          &task_state.db,
          audit_id,
          End {
            exit_code: Some(result.exit_code),
            duration_ms: Some(result.duration_ms),
            output_bytes: Some(result.output_bytes),
            error: None,
          },
        )
        .await;
        Ok(HostExecResponse {
          exit_code: result.exit_code,
          stdout: result.stdout,
          stderr: result.stderr,
          truncated: result.truncated,
          duration_ms: result.duration_ms,
        })
      }
      Ok(HostExecOutcome::Failed(failure)) => {
        finish(
          &task_state.db,
          audit_id,
          End {
            exit_code: None,
            duration_ms: Some(failure.duration_ms),
            output_bytes: Some(failure.output_bytes),
            error: Some(error_text(&failure.error)),
          },
        )
        .await;
        Err(failure.error)
      }
      Err(error) => {
        finish(&task_state.db, audit_id, End::error(&error)).await;
        Err(error)
      }
    }
  });
  Ok(Json(task.await.map_err(|e| {
    AppError(ApiError::internal(e.to_string()))
  })??))
}

#[derive(Deserialize)]
pub struct LogQuery {
  server: Option<String>,
  #[serde(default = "default_limit")]
  limit: u32,
}

fn default_limit() -> u32 {
  50
}

/// `GET /api/shell-log`
pub async fn list(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(query): Query<LogQuery>,
) -> ApiResult<Vec<ShellLog>> {
  auth.require(TokenScope::Read)?;
  if !(1..=200).contains(&query.limit) {
    return Err(
      ApiError::invalid("limit 必须在 1 到 200 之间").into(),
    );
  }
  let rows = state
    .db
    .call(move |c| {
      query_logs(c, query.server.as_deref(), query.limit)
    })
    .await?;
  Ok(Json(rows))
}

pub(crate) async fn start(
  db: &Db,
  actor: &str,
  server: &str,
  kind: &str,
  command: Option<&str>,
) -> Result<i64, ApiError> {
  let actor = actor.to_string();
  let server = server.to_string();
  let kind = kind.to_string();
  let command = command.map(str::to_string);
  db.call(move |c| {
    c.execute(
      "INSERT INTO shell_log (at, actor, server, kind, command) VALUES (?1, ?2, ?3, ?4, ?5)",
      params![now_ms(), actor, server, kind, command],
    )
    .map_err(sql_err)?;
    Ok(c.last_insert_rowid())
  })
  .await
}

pub(crate) struct End {
  pub exit_code: Option<i32>,
  pub duration_ms: Option<u64>,
  pub output_bytes: Option<u64>,
  pub error: Option<String>,
}

impl End {
  pub fn error(error: &ApiError) -> Self {
    Self {
      exit_code: None,
      duration_ms: None,
      output_bytes: None,
      error: Some(error_text(error)),
    }
  }
}

pub(crate) async fn finish(db: &Db, id: i64, end: End) {
  let end = Arc::new(end);
  for attempt in 0..2 {
    let end = end.clone();
    let result = db
      .call(move |c| {
        c.execute(
          "UPDATE shell_log SET exit_code = ?1, duration_ms = ?2, output_bytes = ?3, error = ?4
           WHERE id = ?5 AND exit_code IS NULL AND duration_ms IS NULL AND output_bytes IS NULL AND error IS NULL",
          params![
            end.exit_code,
            end.duration_ms.map(|v| v as i64),
            end.output_bytes.map(|v| v as i64),
            end.error,
            id,
          ],
        )
        .map_err(sql_err)?;
        Ok(())
      })
      .await;
    if result.is_ok() {
      return;
    }
    if attempt == 0 {
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  }
  tracing::error!("结算 shell_log {id} 失败");
}

pub async fn recover(state: &AppState) -> Result<(), ApiError> {
  state
    .db
    .call(|c| {
      c.execute(
        "UPDATE shell_log SET error = 'core_restarted' WHERE exit_code IS NULL AND duration_ms IS NULL AND output_bytes IS NULL AND error IS NULL",
        [],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

fn error_text(error: &ApiError) -> String {
  format!("{}: {}", error.code.as_str(), error.message)
}

fn query_logs(
  c: &Connection,
  server: Option<&str>,
  limit: u32,
) -> Result<Vec<ShellLog>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT id, at, actor, server, kind, command, exit_code, duration_ms, output_bytes, error
       FROM shell_log WHERE (?1 IS NULL OR server = ?1) ORDER BY at DESC, id DESC LIMIT ?2",
    )
    .map_err(sql_err)?;
  let rows = stmt
    .query_map(params![server, limit], |r| {
      Ok(ShellLog {
        id: r.get(0)?,
        at: to_time(r.get(1)?),
        actor: r.get(2)?,
        server: r.get(3)?,
        kind: r.get(4)?,
        command: r.get(5)?,
        exit_code: r.get(6)?,
        duration_ms: r
          .get::<_, Option<i64>>(7)?
          .map(|v| v.max(0) as u64),
        output_bytes: r
          .get::<_, Option<i64>>(8)?
          .map(|v| v.max(0) as u64),
        error: r.get(9)?,
      })
    })
    .map_err(sql_err)?;
  rows.collect::<Result<_, _>>().map_err(sql_err)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn audit_starts_finishes_and_queries_one_row() {
    let db = Db::memory();
    let id = start(&db, "test", "s1", "exec", Some("printf ok"))
      .await
      .unwrap();
    finish(
      &db,
      id,
      End {
        exit_code: Some(7),
        duration_ms: Some(12),
        output_bytes: Some(2),
        error: None,
      },
    )
    .await;
    let rows =
      db.call(|c| query_logs(c, Some("s1"), 50)).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].command.as_deref(), Some("printf ok"));
    assert_eq!(rows[0].exit_code, Some(7));
  }
}
