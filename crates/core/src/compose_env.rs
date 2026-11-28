use std::{
  borrow::Cow,
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::AgentOp,
  compose::{project_env_keys, valid_project_env_key},
  spec::{ServiceSpec, Source},
};

use crate::{hub::Hub, render::Net, world::World};

pub(crate) fn validate(
  spec: &ServiceSpec,
) -> Result<BTreeSet<String>, ApiError> {
  if !spec.compose_env {
    return Ok(BTreeSet::new());
  }
  let Source::Compose {
    content: Some(yaml),
    ..
  } = &spec.source
  else {
    return Err(ApiError::invalid("项目变量只用于 Compose 来源"));
  };
  if let Some(key) =
    spec.env.keys().find(|key| !valid_project_env_key(key))
  {
    return Err(ApiError::invalid(format!(
      "Compose 项目变量 {key} 名称不合法或被保留"
    )));
  }
  project_env_keys(&crate::render::parse_compose_template(yaml)?)
}

pub(crate) fn component_settings(
  spec: &ServiceSpec,
) -> Cow<'_, ServiceSpec> {
  if spec.compose_env
    && spec.container.is_none()
    && !spec.env.is_empty()
  {
    let mut spec = spec.clone();
    spec.env.clear();
    Cow::Owned(spec)
  } else {
    Cow::Borrowed(spec)
  }
}

pub(crate) fn inputs(
  world: &World,
  net: &Net,
  name: &str,
  values: &BTreeMap<String, String>,
) -> Result<Option<BTreeMap<String, String>>, ApiError> {
  let spec = &world.services[name].spec;
  if !spec.compose_env {
    return Ok(None);
  }
  let mut inputs = BTreeMap::new();
  for key in validate(spec)? {
    if let Some(text) = spec.env.get(&key) {
      let (text, substitutions) = crate::variables::prepare_file(
        world,
        net,
        name,
        text,
        Some(values),
      )?;
      let text = crate::refs::resolve(&text, name, world, net)?;
      let text = crate::render::project_env_value(&text, values)?;
      inputs.insert(key, substitutions.finish_text(&text, false));
    }
  }
  Ok(Some(inputs))
}

pub(crate) async fn preflight(
  hub: &Hub,
  world: &World,
  net: &Net,
  name: &str,
  values: &BTreeMap<String, String>,
  cancel: &CancellationToken,
) -> Result<u64, ApiError> {
  let server = &world.services[name].spec.server;
  let conn = hub.compose_env_conn_id(server)?;
  if let Some(project_env) = inputs(world, net, name, values)? {
    let (compose, _) =
      crate::snapshot::service_resolved(world, net, name, values)?;
    let _: serde_json::Value = hub
      .call_bound(
        (server, conn),
        AgentOp::ComposeEnvCheck {
          project: name.to_string(),
          compose,
          project_env,
        },
        Duration::from_secs(35),
        None,
        cancel,
      )
      .await?;
  }
  Ok(conn)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn validates_only_environment_values_and_collects_nested_inputs() {
    let yaml = r#"
services:
  a:
    image: alpine
    environment:
      VALUE: '${VAR:-${OTHER:?required}}'
      ESCAPED: '$$ABSENT'
  b:
    image: alpine
    environment: ['VALUE=$VAR']
"#;
    let spec = |yaml: &str| -> ServiceSpec {
      serde_json::from_value(serde_json::json!({"server": "s1",
        "source": {"compose": {"content": yaml}}, "compose_env": true})).unwrap()
    };
    assert_eq!(
      validate(&spec(yaml)).unwrap(),
      BTreeSet::from(["OTHER".into(), "VAR".into()])
    );
    assert!(
      validate(&spec(&yaml.replacen(
        "image: alpine",
        "image: '$VAR'",
        1
      )))
      .is_err()
    );
    assert!(
      validate(&spec(&format!("include: [other.yaml]\n{yaml}")))
        .is_err()
    );
  }
}
