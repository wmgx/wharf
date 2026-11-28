use std::{collections::BTreeSet, sync::Arc};

use axum::{
  Json,
  extract::{Path, Query, State},
  response::Response,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, FILE_CHUNK, TaskArtifact},
  view::{Perm, TaskArtifactsView, TaskKind},
};

use crate::{
  api::{ApiResult, AppError},
  auth::Auth,
  db::{sql_err, to_time},
  files_api,
  state::AppState,
};

#[derive(Deserialize, Serialize)]
pub(super) struct Stored {
  pub server: String,
  pub files: Vec<TaskArtifact>,
  #[serde(skip)]
  pub keep: u32,
}

#[derive(Deserialize)]
pub struct ListQuery {
  run: Option<i64>,
}

#[derive(Deserialize)]
pub struct DownloadQuery {
  path: String,
}

async fn fetch(
  s: &AppState,
  auth: &Auth,
  name: String,
  run: Option<i64>,
) -> Result<(TaskArtifactsView, Option<String>), AppError> {
  auth.require(Perm::Read)?;
  let spec = super::load_one(s, &name).await;
  if let Some(allowed) = &auth.services {
    match &spec {
      Ok(spec) if matches!(&spec.how, TaskKind::Exec { service, .. } if allowed.contains(service)) =>
        {}
      Err(error)
        if error.code != wharf_api_types::ErrorCode::NotFound =>
      {
        return Err(error.clone().into());
      }
      _ => {
        return Err(
          crate::token_scope::forbidden(&auth.name, allowed, "")
            .into(),
        );
      }
    }
  }
  let spec = spec?;
  let supports = matches!(
    spec.how,
    TaskKind::Script { .. } | TaskKind::Container { .. }
  );
  let visible = super::visible_services(auth)?;
  let row = s.db.call(move |c| {
    c.query_row(
      "SELECT id, started_at, status, artifacts FROM task_runs
       WHERE task = ?1 AND (?2 IS NULL OR id = ?2)
       AND (?3 IS NULL OR service IN (SELECT value FROM json_each(?3)))
       ORDER BY (artifacts IS NOT NULL) DESC, id DESC LIMIT 1",
      params![name, run, visible],
      |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)),
    ).optional().map_err(sql_err).map(|row| (name, row))
  }).await?;
  let (name, row) = row;
  if row.is_none() && run.is_some() {
    return Err(ApiError::not_found("找不到该任务的运行记录").into());
  }
  let (run_id, started_at, status, stored) =
    row.map_or((None, None, None, None), |(id, at, status, raw)| {
      (
        Some(id),
        Some(to_time(at)),
        Some(super::dec(&status)),
        raw.and_then(|s| serde_json::from_str::<Stored>(&s).ok()),
      )
    });
  let (server, artifacts) = stored.map_or((None, Vec::new()), |s| {
    (
      Some(s.server),
      if auth.services.is_none() {
        s.files
      } else {
        Vec::new()
      },
    )
  });
  let hint = if !supports {
    Some("仅脚本和容器任务自动收集 /out 产物".into())
  } else if artifacts.is_empty() {
    Some("这次运行没有保留产物".into())
  } else {
    None
  };
  let total_bytes = artifacts.iter().map(|f| f.size).sum();
  Ok((
    TaskArtifactsView {
      task: name,
      run_id,
      started_at,
      status,
      total_bytes,
      artifacts,
      hint,
    },
    server,
  ))
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<ListQuery>,
) -> ApiResult<TaskArtifactsView> {
  Ok(Json(fetch(&s, &auth, name, q.run).await?.0))
}

pub async fn download(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((task, run_id)): Path<(String, i64)>,
  Query(q): Query<DownloadQuery>,
) -> Result<Response, AppError> {
  let (view, server) =
    fetch(&s, &auth, task.clone(), Some(run_id)).await?;
  let artifact = view
    .artifacts
    .iter()
    .find(|f| f.path == q.path)
    .ok_or_else(|| ApiError::not_found("该运行没有这个产物"))?;
  let server = server
    .ok_or_else(|| ApiError::not_found("找不到产物所在服务器"))?;
  let conn = s.hub.task_artifacts_conn_id(&server)?;
  let path = q.path.clone();
  files_api::stream_download(
    &q.path,
    Some(artifact.size),
    move |offset, expect| {
      let state = Arc::clone(&s);
      let server = server.clone();
      let op = AgentOp::TaskArtifactRead {
        task: task.clone(),
        run_id,
        path: path.clone(),
        offset,
        len: FILE_CHUNK,
        expect,
      };
      async move {
        state
          .hub
          .call_bound(
            (&server, conn),
            op,
            files_api::CHUNK_TIMEOUT,
            None,
            &CancellationToken::new(),
          )
          .await
      }
    },
  )
  .await
}

pub(super) async fn prune(
  s: &AppState,
  task: &str,
  servers: &BTreeSet<String>,
) {
  for server in servers {
    if let Ok(conn) = s.hub.task_artifacts_conn_id(server) {
      let _ = s
        .hub
        .call_bound::<serde_json::Value>(
          (server, conn),
          AgentOp::TaskArtifactPrune {
            task: task.into(),
            keep_run_ids: Vec::new(),
          },
          std::time::Duration::from_secs(30),
          None,
          &CancellationToken::new(),
        )
        .await;
    }
  }
}

#[tokio::test]
async fn old_agent_is_rejected_before_artifact_dispatch() {
  let state = crate::rules::tests::test_state();
  state
    .hub
    .mock_agent("s1", false, |_| panic!("旧 agent 不应收到产物请求"));
  let error = state.hub.task_artifacts_conn_id("s1").unwrap_err();
  assert_eq!(error.code, wharf_api_types::ErrorCode::Conflict);
  assert!(error.hint.unwrap().contains("wharf upgrade"));
}

#[test]
fn existing_task_spec_does_not_serialize_artifact_defaults() {
  let raw = serde_json::json!({
    "server":"s1","schedule":"0 4 * * *","kind":"container","image":"app:1",
    "timeout_secs":600,"enabled":true,"notify":true
  });
  let task: wharf_api_types::view::TaskSpec =
    serde_json::from_value(raw.clone()).unwrap();
  assert_eq!(serde_json::to_value(task).unwrap(), raw);
}
