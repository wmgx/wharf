use std::{collections::BTreeMap, time::Duration};

use serde_yaml_ng::{Mapping, Value};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::AgentOp,
  spec::{ServiceSpec, Source, named_network_name},
};

use crate::{hub::Hub, world::World};

fn conflict(server: &str, name: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 上的网络 {name} 与声明冲突"),
  )
  .with_hint("统一同机的 internal 设置，或换网络名")
}

pub(crate) fn validate_world(world: &World) -> Result<(), ApiError> {
  let mut declared = BTreeMap::new();
  for (name, row) in &world.services {
    let spec = &row.spec;
    for (network, attachment) in &spec.networks {
      wharf_api_types::validate_name("网络", network)?;
      let server = &spec.server;
      if declared
        .insert((server, network), attachment.internal)
        .is_some_and(|internal| internal != attachment.internal)
      {
        return Err(conflict(server, network));
      }
    }
    if internal(spec)
      && (spec.networks.len() != 1 || !spec.ports.is_empty())
    {
      return Err(internal_error(name));
    }
    if !spec.networks.is_empty()
      && let Source::Compose {
        content: Some(content),
        ..
      } = &spec.source
    {
      render_doc(
        name,
        spec,
        crate::render::parse_compose_template(content)?,
      )?;
    }
  }
  Ok(())
}

fn internal(spec: &ServiceSpec) -> bool {
  spec.networks.values().any(|network| network.internal)
}

fn internal_error(name: &str) -> ApiError {
  ApiError::invalid(format!(
    "服务 {name} 的 internal 网络不能和其他网络或发布端口一起使用"
  ))
  .with_hint(
    "只保留一个 internal 网络，并去掉发布端口；Compose 仅支持单组件",
  )
}

pub(crate) async fn preflight(
  hub: &Hub,
  spec: &ServiceSpec,
  cancel: &CancellationToken,
) -> Result<u64, ApiError> {
  let conn = hub.named_network_conn_id(&spec.server)?;
  if !spec.networks.is_empty() {
    let _: serde_json::Value = hub
      .call_bound(
        (&spec.server, conn),
        AgentOp::NamedNetworksCheck {
          networks: spec.networks.clone(),
        },
        Duration::from_secs(60),
        None,
        cancel,
      )
      .await?;
  }
  Ok(conn)
}

pub(crate) fn render(
  name: &str,
  spec: &ServiceSpec,
  text: String,
) -> Result<String, ApiError> {
  if spec.networks.is_empty() {
    return Ok(text);
  }
  let doc =
    render_doc(name, spec, crate::render::parse_compose(&text)?)?;
  serde_yaml_ng::to_string(&doc)
    .map_err(|_| ApiError::internal("无法渲染命名私网"))
}

fn render_doc(
  name: &str,
  spec: &ServiceSpec,
  mut doc: Value,
) -> Result<Value, ApiError> {
  let inner = internal(spec);
  let components = doc["services"]
    .as_mapping()
    .ok_or_else(|| ApiError::invalid("Compose 没有组件"))?;
  let target = match &spec.container {
    Some(target) if components.contains_key(target.as_str()) => {
      target.clone()
    }
    None if components.len() == 1 => components
      .keys()
      .next()
      .and_then(Value::as_str)
      .ok_or_else(|| ApiError::invalid("Compose 组件名不合法"))?
      .to_string(),
    _ => {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的命名网络需要指定 Compose 容器"
        ))
        .with_hint("用 --container 指定要加入网络的组件"),
      );
    }
  };
  let declared = |value: &Value| match value {
    Value::Mapping(v) => !v.is_empty(),
    Value::Sequence(v) => !v.is_empty(),
    Value::Null => false,
    _ => true,
  };
  if inner
    && (components.len() != 1
      || declared(&doc["networks"])
      || declared(&doc["services"][target.as_str()]["ports"])
      || declared(&doc["services"][target.as_str()]["networks"]))
  {
    return Err(internal_error(name));
  }
  let body = &mut doc["services"][target.as_str()];
  if !body["network_mode"].is_null()
    && body["network_mode"].as_str() != Some("default")
  {
    return Err(
      ApiError::invalid(format!(
        "服务 {name} 不能同时使用命名私网和 network_mode"
      ))
      .with_hint("移除 Compose 组件的 network_mode"),
    );
  }
  if let Some(map) = body.as_mapping_mut() {
    map.remove("network_mode");
  }
  let mut joined = match &body["networks"] {
    Value::Null => Mapping::new(),
    Value::Mapping(existing) => existing.clone(),
    Value::Sequence(existing) => existing
      .iter()
      .cloned()
      .map(|network| (network, Value::Null))
      .collect(),
    _ => {
      return Err(ApiError::invalid(
        "Compose 组件的 networks 格式不对",
      ));
    }
  };
  if !inner && joined.is_empty() {
    joined.insert(Value::String("default".into()), Value::Null);
  }
  let mut networks = match &doc["networks"] {
    Value::Null => Mapping::new(),
    Value::Mapping(existing) => existing.clone(),
    _ => {
      return Err(ApiError::invalid(
        "Compose 顶层的 networks 格式不对",
      ));
    }
  };
  for network in spec.networks.keys() {
    let key = Value::String(format!("wharf_named_{network}"));
    if networks.contains_key(&key) || joined.contains_key(&key) {
      return Err(conflict(&spec.server, network));
    }
    networks.insert(
      key.clone(),
      Value::Mapping(Mapping::from_iter([
        (Value::String("external".into()), Value::Bool(true)),
        (
          Value::String("name".into()),
          Value::String(named_network_name(network)),
        ),
      ])),
    );
    joined.insert(
      key,
      Value::Mapping(Mapping::from_iter([(
        Value::String("aliases".into()),
        Value::Sequence(vec![Value::String(name.into())]),
      )])),
    );
  }
  doc["services"][target.as_str()]["networks"] =
    Value::Mapping(joined);
  doc["networks"] = Value::Mapping(networks);
  Ok(doc)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn internal_network_is_shared_by_name_without_default() {
    let yaml = "services: {app: {image: alpine}}";
    let mut spec: ServiceSpec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"image": "alpine"}, "networks": {"lab": {"internal": true}},
    })).unwrap();
    let rendered = render("app", &spec, yaml.into()).unwrap();
    let doc = crate::render::parse_compose(&rendered).unwrap();
    assert_eq!(
      doc["networks"]["wharf_named_lab"]["name"].as_str(),
      Some("wharf-net-lab")
    );
    assert_eq!(
      doc["services"]["app"]["networks"]
        .as_mapping()
        .unwrap()
        .len(),
      1
    );
    assert!(
      render(
        "app",
        &spec,
        "services: {app: {image: alpine, ports: ['8080:80']}}".into()
      )
      .is_err()
    );
    spec.networks.get_mut("lab").unwrap().internal = false;
    let rendered = render("app", &spec, yaml.into()).unwrap();
    assert!(crate::render::parse_compose(&rendered).unwrap()["services"]["app"]["networks"].get("default").is_some());
  }
}
