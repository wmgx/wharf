use std::{
  sync::Arc,
  time::{Duration, Instant},
};

use axum::{
  Extension, Json,
  extract::{Path, Query, State},
  response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, ServiceExecJob, ServiceExecOutcome},
  view::{HostExecResponse, Perm, ServiceExecResponse},
};

use crate::{
  api::{AppError, service_not_found},
  audit::AuditSlot,
  auth::Auth,
  exec_stream::{self, ExecQuery},
  hub::ProgressFn,
  shell::ExecRequest,
  snapshot,
  state::AppState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
  container: Option<String>,
  command: String,
  timeout_secs: Option<u64>,
  cwd: Option<String>,
}

pub async fn exec(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(slot): Extension<AuditSlot>,
  Path(service): Path<String>,
  Query(query): Query<ExecQuery>,
  Json(req): Json<Request>,
) -> Result<Response, AppError> {
  auth.require(Perm::Exec)?;
  crate::token_scope::require_service(&auth, &service)?;
  let snap = snapshot::load_inner(&state.db).await?;
  let row = snap
    .world
    .services
    .get(&service)
    .ok_or_else(|| service_not_found(&service))?;
  if row.spec.stopped {
    return Err(
      ApiError::invalid(format!(
        "服务 {service} 已停止，不能执行容器命令"
      ))
      .with_hint(format!("先启动：wharf service start {service}"))
      .into(),
    );
  }
  crate::service_container::validate(
    row,
    &service,
    req.container.as_deref(),
  )?;
  let server = snapshot::service_runtime_server(&snap, &service)
    .ok_or_else(|| service_not_found(&service))?
    .to_string();
  let conn = state.hub.exec_v2_conn_id(&server, "容器内命令执行")?;
  let cwd = req.cwd;
  let validated = ExecRequest {
    command: req.command,
    timeout_secs: req.timeout_secs,
    cwd: cwd.clone(),
  }
  .job()?;
  let mut values = crate::log_redact::service_values(&row.spec);
  crate::log_redact::add_encoded_values(&mut values);
  values.extend(snap.log_values.iter().cloned());
  let summary = exec_stream::redact(
    &crate::redact::redact_command(&validated.command),
    &values,
    false,
  )
  .chars()
  .take(500)
  .collect::<String>();
  let audit = slot
    .start_exec(
      &state,
      &auth.name,
      format!(
        "service={service} container={} command={summary}",
        req.container.as_deref().unwrap_or("自动选择"),
      ),
    )
    .await?;
  let run = Execution {
    state,
    conn,
    server: server.clone(),
    values: values.clone(),
    audit,
    job: ServiceExecJob {
      project: service.clone(),
      container: req.container,
      command: validated.command,
      timeout_secs: validated.timeout_secs,
      cwd,
      stream: query.stream,
    },
  };
  if query.stream {
    return Ok(exec_stream::response(
      values,
      move |progress, cancel| async move {
        run
          .execute(Some(progress), cancel)
          .await
          .map(|(c, r)| (Some(c), r))
      },
    ));
  }
  let cancel = CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  let (container, result) = tokio::spawn(run.execute(None, cancel))
    .await
    .map_err(|_| ApiError::internal("执行任务中断"))??;
  Ok(
    Json(ServiceExecResponse {
      service,
      server,
      container,
      exit_code: result.exit_code,
      stdout: result.stdout,
      stderr: result.stderr,
      truncated: result.truncated,
      duration_ms: result.duration_ms,
    })
    .into_response(),
  )
}

struct Execution {
  state: Arc<AppState>,
  conn: u64,
  server: String,
  job: ServiceExecJob,
  values: Vec<String>,
  audit: i64,
}

impl Execution {
  async fn execute(
    self,
    progress: Option<ProgressFn>,
    cancel: CancellationToken,
  ) -> Result<(String, HostExecResponse), ApiError> {
    let started = Instant::now();
    let timeout = Duration::from_secs(self.job.timeout_secs + 20);
    let result = self
      .state
      .hub
      .call_bound::<ServiceExecOutcome>(
        (&self.server, self.conn),
        AgentOp::ServiceExec(self.job),
        timeout,
        progress,
        &cancel,
      )
      .await;
    let clean = |text: &str, truncated| {
      exec_stream::redact(text, &self.values, truncated)
    };
    let (status, duration, detail, response) = match result {
      Ok(ServiceExecOutcome::Finished {
        container,
        result: r,
      }) => (
        200,
        r.duration_ms,
        format!(
          " resolved_container={container} exit_code={} output_bytes={}",
          r.exit_code, r.output_bytes
        ),
        Ok((
          container,
          HostExecResponse {
            exit_code: r.exit_code,
            stdout: clean(&r.stdout, r.truncated),
            stderr: clean(&r.stderr, r.truncated),
            truncated: r.truncated,
            duration_ms: r.duration_ms,
          },
        )),
      ),
      result => {
        let (mut e, duration, bytes) = match result {
          Ok(ServiceExecOutcome::Failed(f)) => {
            (f.error, f.duration_ms, f.output_bytes)
          }
          Err(e) => (e, started.elapsed().as_millis() as u64, 0),
          Ok(ServiceExecOutcome::Finished { .. }) => unreachable!(),
        };
        if cancel.is_cancelled() {
          e = ApiError::new(ErrorCode::Cancelled, "容器命令已取消");
        }
        e.message = clean(&e.message, false);
        e.hint = e.hint.map(|hint| clean(&hint, false));
        (
          e.code.http_status(),
          duration,
          format!(" error={} output_bytes={bytes}", e.code.as_str()),
          Err(e),
        )
      }
    };
    crate::audit::finish_exec(
      &self.state,
      self.audit,
      status,
      duration,
      detail,
    )
    .await?;
    response
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::db::{self, Write, sql_err};
  use axum::{
    body::{Body, to_bytes},
    http::Request,
  };
  use serde_json::json;
  use tower::ServiceExt;

  #[tokio::test]
  async fn service_exec_needs_only_scoped_exec_and_records_exit_code()
  {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      db::apply_write(c, &Write::Upsert {
        kind: "service".into(), name: "app".into(),
        spec: json!({"server":"s1","source":{"image":"alpine"},"env":{"API_TOKEN":"fixture-inline"}}),
        meta: json!({}),
      })?;
      crate::auth::insert_token(c, "exec-fixture", &[Perm::Exec], "fixture-exec")?;
      c.execute("UPDATE api_tokens SET services = 'app' WHERE name = 'exec-fixture'", [])
        .map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    state.hub.mock_agent("s1", false, |op| {
      assert!(matches!(&op, AgentOp::ServiceExec(job) if job.project == "app" && !job.stream));
      serde_json::to_value(ServiceExecOutcome::Finished {
        container: "app".into(),
        result: wharf_api_types::agent::HostExecResult {
          exit_code: 2, stdout: "fixture-inline\n".into(), stderr: String::new(),
          truncated: false, duration_ms: 1, output_bytes: 15,
        },
      }).map_err(|_| ApiError::internal("测试结果无法序列化"))
    });
    let router = crate::api::router(state.clone());
    let req = |name| {
      Request::builder()
        .method("POST")
        .uri(format!("/api/services/{name}/exec"))
        .header("authorization", "Bearer fixture-exec")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"command":"printf fixture-inline"}"#))
        .unwrap()
    };
    assert_eq!(
      router
        .clone()
        .oneshot(req("outside"))
        .await
        .unwrap()
        .status()
        .as_u16(),
      403
    );
    assert_eq!(
      router
        .clone()
        .oneshot(req("app"))
        .await
        .unwrap()
        .status()
        .as_u16(),
      409
    );
    state.hub.enable_mock_exec_v2("s1");
    let response = router.oneshot(req("app")).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    let result: ServiceExecResponse =
      serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.exit_code, 2);
    assert_eq!(result.stdout, "***\n");
    state.db.call(|c| {
      let detail: String = c.query_row(
        "SELECT detail FROM audit_log WHERE path = '/api/services/app/exec' AND status = 200", [], |r| r.get(0),
      ).map_err(sql_err)?;
      assert!(detail.contains("exit_code=2"));
      assert!(!detail.contains("fixture-inline"));
      Ok(())
    }).await.unwrap();
  }
}
