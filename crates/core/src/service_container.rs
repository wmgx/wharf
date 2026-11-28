use wharf_api_types::{
  ApiError, spec::Source, validate_container_name,
};

use crate::world::ServiceRow;

pub(crate) fn validate(
  row: &ServiceRow,
  name: &str,
  container: Option<&str>,
) -> Result<(), ApiError> {
  let Some(c) = container else {
    return Ok(());
  };
  validate_container_name(c)?;
  match &row.spec.source {
    Source::Compose {
      content: Some(yaml),
      ..
    } => {
      crate::render::compose_target(name, yaml, Some(c))?;
    }
    Source::Compose { content: None, .. } => {}
    _ if c != name => {
      return Err(
        ApiError::invalid(format!("服务 {name} 没有子容器 {c}"))
          .with_hint(format!(
            "去掉 --container，或传 --container {name}"
          )),
      );
    }
    _ => {}
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::{
    api,
    db::{self, Write},
    host_access::tests::auth,
  };
  use axum::extract::{Path, Query, RawQuery, State};
  use serde_json::json;
  use wharf_api_types::{ErrorCode, agent::AgentOp, view::Perm};

  #[tokio::test]
  async fn extra_logs_enforce_declarations_and_audit_only_file_reads()
  {
    use axum::{
      body::{Body, to_bytes},
      http::Request,
    };
    use tower::ServiceExt;

    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      db::apply_write(c, &Write::Upsert {
        kind: "service".into(), name: "stack".into(), meta: json!({}),
        spec: json!({"server":"s1","source":{"image":"fixture:1"},
          "volumes":[{"name":"logs","target":"/logs"}],"extra_logs":["logs/error.log"]}),
      })?;
      crate::auth::insert_token(c, "log-fixture", &[Perm::Read], "fixture-logs")?;
      Ok(())
    }).await.unwrap();
    state.hub.mock_agent("s1", false, |op| match op {
      AgentOp::Files(wharf_api_types::agent::FilesOp::ExtraLog {
        ..
      }) => Ok(json!({"path":"logs/error.log","size":19,"lines":3,
          "content":"before\nERROR\nafter\n","truncated":false})),
      AgentOp::Logs { .. } => Ok(json!("stdout")),
      _ => panic!("额外的 agent 操作"),
    });
    let request = |file: &str| {
      api::service_logs(
        State(state.clone()),
        auth([Perm::Read], false),
        Path("stack".into()),
        Query(
          serde_json::from_value(json!({"file":file,"grep":"ERROR"}))
            .unwrap(),
        ),
        RawQuery(Some("context=1".into())),
        axum::Extension(crate::audit::AuditSlot::default()),
      )
    };
    assert_eq!(
      request("logs/other.log").await.unwrap_err().0.code,
      ErrorCode::InvalidInput
    );
    assert_eq!(
      request("logs/error.log").await.unwrap_err().0.code,
      ErrorCode::Conflict
    );
    state.hub.enable_mock_extra_logs("s1");
    let router = crate::api::router(state.clone());
    for (query, expected) in [
      (
        "?file=logs%2Ferror.log&grep=ERROR&context=1",
        "before\nERROR\nafter\n",
      ),
      ("", "stdout"),
    ] {
      let request = Request::builder()
        .uri(format!("/api/services/stack/logs{query}"))
        .extension(crate::cli_tunnel::Sealed)
        .header("authorization", "Bearer fixture-logs")
        .body(Body::empty())
        .unwrap();
      let response = router.clone().oneshot(request).await.unwrap();
      assert_eq!(response.status().as_u16(), 200);
      let body = to_bytes(response.into_body(), 4096).await.unwrap();
      let result: serde_json::Value =
        serde_json::from_slice(&body).unwrap();
      assert_eq!(result["logs"], expected);
    }
    state
      .db
      .call(|c| {
        let mut rows = c
          .prepare(
            "SELECT actor, path, status, detail FROM audit_log",
          )
          .map_err(db::sql_err)?;
        let result = rows
          .query_map([], |r| {
            Ok((
              r.get::<_, String>(0)?,
              r.get::<_, String>(1)?,
              r.get::<_, u16>(2)?,
              r.get::<_, String>(3)?,
            ))
          })
          .map_err(db::sql_err)?
          .collect::<Result<Vec<_>, _>>()
          .map_err(db::sql_err)?;
        assert_eq!(
          result,
          [(
            "log-fixture".to_string(),
            "/api/services/stack/logs".to_string(),
            200,
            "logs stack:logs/error.log".to_string()
          )]
        );
        Ok(())
      })
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn child_logs_validate_name_and_bind_to_capable_agent() {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| db::apply_write(c, &Write::Upsert {
      kind: "service".into(), name: "stack".into(), meta: json!({}),
      spec: json!({"server":"s1","source":{"compose":{"content":"services: {web: {image: alpine}, db: {image: alpine}}"}}}),
    })).await.unwrap();
    state.hub.mock_agent("s1", false, |op| {
      let AgentOp::Logs {
        container, until, ..
      } = op
      else {
        unreachable!("应下发日志请求");
      };
      assert_eq!(container.as_deref(), Some("db"));
      Ok(json!(if until.is_some() {
        "截止前日志"
      } else {
        "db 日志"
      }))
    });
    let request = |c: &str, until: Option<&str>| {
      api::service_logs(
        State(state.clone()),
        auth([Perm::Read], false),
        Path("stack".into()),
        Query(
          serde_json::from_value(json!({"container":c})).unwrap(),
        ),
        RawQuery(until.map(str::to_owned)),
        axum::Extension(crate::audit::AuditSlot::default()),
      )
    };
    assert_eq!(
      request("db", None).await.unwrap_err().0.code,
      ErrorCode::Conflict
    );
    state.hub.enable_mock_exec_v2("s1");
    assert_eq!(
      request("db", None)
        .await
        .map_err(|error| error.0)
        .unwrap()
        .0["logs"],
      "db 日志"
    );
    assert_eq!(
      request("db", Some("until=1h")).await.unwrap_err().0.code,
      ErrorCode::Conflict
    );
    state.hub.enable_mock_files_v2("s1");
    assert_eq!(
      request("db", Some("until=1h"))
        .await
        .map_err(|error| error.0)
        .unwrap()
        .0["logs"],
      "截止前日志\n"
    );
    let error = request("redis", None).await.unwrap_err().0;
    assert_eq!(error.code, ErrorCode::InvalidInput);
    let hint = error.hint.unwrap();
    assert!(hint.contains("db") && hint.contains("web"));
  }
}
