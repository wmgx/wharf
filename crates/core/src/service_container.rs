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
