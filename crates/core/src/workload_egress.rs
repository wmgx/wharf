use std::{collections::BTreeMap, time::Duration};

use serde_yaml_ng::{Mapping, Value};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::AgentOp,
  egress::{WORKLOAD_PROXY_HOST, workload_env},
  spec::ServiceSpec,
};

use crate::{
  hub::Hub,
  render::{self, Net},
  world::World,
};

pub(crate) fn no_exit(server: &str) -> ApiError {
  ApiError::invalid(format!("服务器 {server} 没有可用的分流出口"))
    .with_hint(format!(
      "先设置 wharf server set {server} --via <出口服务器>"
    ))
}

pub(crate) fn validate(
  world: &World,
  net: &Net,
  server: &str,
) -> Result<(), ApiError> {
  let exit = world
    .servers
    .get(server)
    .and_then(|row| crate::egress::via(&row.settings))
    .filter(|exit| {
      world
        .servers
        .get(*exit)
        .is_some_and(|row| row.settings.egress.is_some())
    })
    .ok_or_else(|| no_exit(server))?;
  if !net.private.contains_key(exit) {
    return Err(no_exit(server));
  }
  Ok(())
}

pub(crate) async fn preflight(
  hub: &Hub,
  server: &str,
  will_configure: bool,
  cancel: &CancellationToken,
) -> Result<u64, ApiError> {
  let id = hub.workload_egress_conn_id(server)?;
  if !will_configure {
    let running: bool = hub
      .call_bound(
        (server, id),
        AgentOp::WorkloadEgressStatus,
        Duration::from_secs(10),
        None,
        cancel,
      )
      .await?;
    if !running {
      return Err(no_exit(server));
    }
  }
  Ok(id)
}

pub(crate) fn bypass(net: &Net) -> String {
  let mut entries =
    String::from(crate::docker_proxy::internal_bypass());
  entries.push_str(",.local,.internal,.ts.net");
  for addr in net
    .private
    .values()
    .map(|addr| &addr.ip)
    .chain(net.lan_addrs.values().flatten())
    .chain(net.docker_subnets.values().flatten())
  {
    entries.push(',');
    entries.push_str(addr);
  }
  entries
}

fn bad_network(name: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务 {name} 的网络无法访问本机分流代理"),
  )
  .with_hint("换成可达的 bridge 网络或宿主机网络")
}

pub(crate) fn render(
  name: &str,
  spec: &ServiceSpec,
  net: &Net,
  text: String,
) -> Result<String, ApiError> {
  if !spec.use_egress {
    return Ok(text);
  }
  if spec.networks.values().any(|network| network.internal) {
    return Err(bad_network(name));
  }
  let component =
    render::compose_target(name, &text, spec.container.as_deref())?;
  let mut doc = render::parse_compose(&text)?;
  let selected = &mut doc["services"][component.as_str()];
  let host = match selected["network_mode"].as_str() {
    Some("host") => "127.0.0.1",
    None | Some("bridge" | "default") => WORKLOAD_PROXY_HOST,
    _ => return Err(bad_network(name)),
  };
  let mut env = BTreeMap::new();
  let mut existing = match &selected["environment"] {
    Value::Mapping(existing) => existing.clone(),
    Value::Sequence(items) => items
      .iter()
      .map(|item| {
        let item = item.as_str().ok_or_else(|| {
          ApiError::invalid("Compose environment 格式不对")
        })?;
        let (key, value) = item
          .split_once('=')
          .map_or((item, Value::Null), |(k, v)| {
            (k, Value::String(v.into()))
          });
        Ok((Value::String(key.into()), value))
      })
      .collect::<Result<Mapping, ApiError>>()?,
    Value::Null => Mapping::new(),
    _ => {
      return Err(ApiError::invalid("Compose environment 格式不对"));
    }
  };
  for (key, value) in &existing {
    if let Some(key) = key.as_str() {
      env.insert(
        key.to_string(),
        value.as_str().unwrap_or_default().to_string(),
      );
    }
  }
  workload_env(host, &bypass(net), &mut env)?;
  existing.retain(|key, _| {
    !key
      .as_str()
      .is_some_and(|key| key.eq_ignore_ascii_case("no_proxy"))
  });
  for key in [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
  ] {
    existing.insert(
      Value::String(key.into()),
      Value::String(env[key].clone()),
    );
  }
  selected["environment"] = Value::Mapping(existing);
  if host == WORKLOAD_PROXY_HOST {
    let value = &mut selected["extra_hosts"];
    let collision = [
      value.as_mapping().is_some_and(|m| {
        m.keys().any(|k| {
          k.as_str().is_some_and(|k| k.eq_ignore_ascii_case(host))
        })
      }),
      value.as_sequence().is_some_and(|seq| {
        seq.iter().any(|entry| {
          entry
            .as_str()
            .and_then(|s| s.split([':', '=']).next())
            .is_some_and(|key| key.eq_ignore_ascii_case(host))
        })
      }),
    ]
    .into_iter()
    .any(|v| v);
    if collision {
      return Err(ApiError::invalid("已有主机映射与 use_egress 冲突")
        .with_hint("移除 host.docker.internal 的自定义映射，或关闭 use_egress"));
    }
    match value {
      Value::Null => {
        *value = Value::Sequence(vec![Value::String(format!(
          "{host}=host-gateway"
        ))])
      }
      Value::Mapping(map) => {
        map.insert(
          Value::String(host.into()),
          Value::String("host-gateway".into()),
        );
      }
      Value::Sequence(seq) => {
        seq.push(Value::String(format!("{host}=host-gateway")))
      }
      _ => {
        return Err(ApiError::invalid(
          "Compose extra_hosts 格式不对",
        ));
      }
    }
  }
  serde_yaml_ng::to_string(&doc)
    .map_err(|_| ApiError::internal("无法渲染运行期代理"))
}

#[test]
fn proxy_is_opt_in_and_preserves_internal_bypass() {
  let mut spec: ServiceSpec =
    serde_json::from_value(serde_json::json!({
      "server":"s1", "source":{"image":"alpine"},
    }))
    .unwrap();
  let source = "services: {app: {image: alpine}}".to_string();
  let net = Net::default();
  assert_eq!(
    render("app", &spec, &net, source.clone()).unwrap(),
    source
  );
  spec.use_egress = true;
  let doc = render::parse_compose(
    &render("app", &spec, &net, source).unwrap(),
  )
  .unwrap();
  let env = &doc["services"]["app"]["environment"];
  assert_eq!(
    env["HTTP_PROXY"].as_str(),
    Some("http://host.docker.internal:8119")
  );
  assert!(
    env["NO_PROXY"].as_str().unwrap().contains("100.64.0.0/10")
  );
  let conflict = "services: {app: {image: alpine, environment: {HTTP_PROXY: fixture}}}";
  assert!(render("app", &spec, &net, conflict.into()).is_err());
}
