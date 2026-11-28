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
  use super::*;
  use wharf_api_types::ErrorCode;

  #[tokio::test]
  async fn child_restart_requires_the_capability_on_current_connection()
   {
    let state = crate::rules::tests::test_state();
    state
      .hub
      .mock_agent("s1", false, |_| panic!("不应发送子容器操作"));
    assert_eq!(
      state
        .hub
        .exec_v2_conn_id("s1", "重启单个子容器")
        .unwrap_err()
        .code,
      ErrorCode::Conflict
    );
    state.hub.enable_mock_exec_v2("s1");
    assert!(
      state.hub.exec_v2_conn_id("s1", "重启单个子容器").is_ok()
    );
  }
}
