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
  use axum::extract::{Path, Query, State};
  use serde_json::json;
  use wharf_api_types::{ErrorCode, agent::AgentOp, view::Perm};

  #[tokio::test]
  async fn child_logs_validate_name_and_bind_to_capable_agent() {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| db::apply_write(c, &Write::Upsert {
      kind: "service".into(), name: "stack".into(), meta: json!({}),
      spec: json!({"server":"s1","source":{"compose":{"content":"services: {web: {image: alpine}, db: {image: alpine}}"}}}),
    })).await.unwrap();
    state.hub.mock_agent("s1", false, |op| {
      assert!(matches!(op, AgentOp::Logs { container: Some(c), .. } if c == "db"));
      Ok(json!("db 日志"))
    });
    let request = |c: &str| {
      api::service_logs(
        State(state.clone()),
        auth([Perm::Read], false),
        Path("stack".into()),
        Query(
          serde_json::from_value(json!({"container":c})).unwrap(),
        ),
      )
    };
    assert_eq!(
      request("db").await.unwrap_err().0.code,
      ErrorCode::Conflict
    );
    state.hub.enable_mock_exec_v2("s1");
    assert_eq!(request("db").await.unwrap().0["logs"], "db 日志");
    let error = request("redis").await.unwrap_err().0;
    assert_eq!(error.code, ErrorCode::InvalidInput);
    let hint = error.hint.unwrap();
    assert!(hint.contains("db") && hint.contains("web"));
  }
}
