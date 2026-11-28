use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::{Path, State},
};
use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  references::{
    PublicRef, next_placeholder, parse_public_ref, placeholders,
  },
  spec::{ServiceSpec, Source, VarView},
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  render::Net,
  state::AppState,
  world::{ServiceRow, World},
};

pub(crate) fn validate(
  name: &str,
  value: &str,
) -> Result<(), ApiError> {
  if !wharf_api_types::references::valid_var_name(name) {
    return Err(
      ApiError::invalid(
        "变量名须以大写字母或下划线开头，最多 64 个字符",
      )
      .with_hint("变量名只能含大写字母、数字和下划线"),
    );
  }
  if value.len() > 4096 || value.contains('\0') {
    return Err(ApiError::invalid("变量值最多 4 KiB，且不能含 NUL"));
  }
  Ok(())
}

pub(crate) fn not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("变量 {name} 不存在"))
    .with_hint("先执行 wharf var set 设置变量")
}

pub(crate) fn require_global(auth: &Auth) -> Result<(), ApiError> {
  if let Some(services) = &auth.services {
    return Err(crate::token_scope::forbidden(
      &auth.name,
      services,
      "；变量管理需要全局令牌",
    ));
  }
  Ok(())
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<VarView>> {
  auth.require(Perm::Read)?;
  require_global(&auth)?;
  let world = s
    .db
    .call(|c| World::from_rows(crate::db::all_resources(c)?))
    .await?;
  Ok(Json(
    world
      .vars
      .into_iter()
      .map(|(name, row)| VarView {
        name,
        value: row.value,
      })
      .collect(),
  ))
}

pub async fn get(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<VarView> {
  auth.require(Perm::Read)?;
  require_global(&auth)?;
  let world = s
    .db
    .call(|c| World::from_rows(crate::db::all_resources(c)?))
    .await?;
  let row = world.vars.get(&name).ok_or_else(|| not_found(&name))?;
  Ok(Json(VarView {
    name,
    value: row.value.clone(),
  }))
}

pub(crate) fn validate_removals(
  current: &World,
  desired: &World,
) -> Result<(), ApiError> {
  for removed in current
    .vars
    .keys()
    .filter(|name| !desired.vars.contains_key(*name))
  {
    let uses = desired
      .services
      .iter()
      .flat_map(|(service, row)| {
        crate::missing_refs::service_texts(&row.spec).filter_map(
          move |(field, text)| {
            placeholders(text)
              .any(|raw| {
                parse_public_ref(raw, false)
                  == Some(PublicRef::Var(removed))
              })
              .then(|| format!("service/{service} {field}"))
          },
        )
      })
      .collect::<Vec<_>>();
    if !uses.is_empty() {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("变量 {removed} 仍在使用"),
        )
        .with_hint("先移除列出的引用")
        .with_details(serde_json::json!({"refs": uses})),
      );
    }
  }
  Ok(())
}

pub(crate) fn validate_self_conflicts(
  current: &World,
  desired: &World,
  secrets: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  for (name, row) in &desired.services {
    if !row.spec.self_refs
      || current
        .services
        .get(name)
        .is_some_and(|old| old.spec.self_refs)
    {
      continue;
    }
    for (_, text) in crate::missing_refs::service_texts(&row.spec) {
      for raw in placeholders(text) {
        if matches!(
          parse_public_ref(raw, true),
          Some(PublicRef::Own(..))
        ) && secrets.contains_key(raw)
        {
          return Err(
            ApiError::new(
              ErrorCode::Conflict,
              format!("服务 {name} 的自身引用 {raw} 与已有密钥重名"),
            )
            .with_hint("改用其他密钥名后再启用自身引用"),
          );
        }
      }
    }
  }
  Ok(())
}

fn resolve(
  world: &World,
  net: &Net,
  name: &str,
  row: &ServiceRow,
  raw: &str,
  reference: PublicRef<'_>,
) -> Result<String, ApiError> {
  let server = &row.spec.server;
  let value = match reference {
    PublicRef::Var(key) => {
      return world
        .vars
        .get(key)
        .map(|row| row.value.clone())
        .ok_or_else(|| {
          ApiError::invalid(format!("变量 {key} 不存在"))
            .with_hint("先设置变量或移除引用")
        });
    }
    PublicRef::Own("SELF_NAME", None) => Some(name.to_string()),
    PublicRef::Own("SELF_SERVER", None) => Some(server.clone()),
    PublicRef::Own("SELF_PRIVATE_IP", None) => {
      net.private.get(server).map(|addr| addr.ip.clone())
    }
    PublicRef::Own("SELF_PUBLIC_IP", None) => {
      net.public_ip.get(server).cloned()
    }
    PublicRef::Own("SELF_REGION", None) => world
      .servers
      .get(server)
      .and_then(|row| row.settings.region)
      .and_then(|region| serde_json::to_value(region).ok())
      .and_then(|value| value.as_str().map(str::to_string)),
    PublicRef::Own("SELF_DOMAIN", None) => {
      let mut hosts = world.routes.values().filter(|r| {
        r.spec.service == name && !r.spec.hostname.contains('*')
      });
      let host = hosts.next();
      host
        .filter(|_| hosts.next().is_none())
        .map(|r| r.spec.hostname.clone())
    }
    PublicRef::Own("SELF_PORT", port) => row
      .spec
      .find_port(port)
      .and_then(|port| row.host_ports.get(&port.name))
      .map(u16::to_string),
    PublicRef::Own(..) => None,
  };
  value.ok_or_else(|| {
    let ports = row
      .host_ports
      .keys()
      .cloned()
      .collect::<Vec<_>>()
      .join("、");
    ApiError::invalid(format!("服务 {name} 无法解析 {raw}"))
      .with_hint(format!(
        "检查地址、主域名及端口配置。可用端口：{ports}"
      ))
  })
}

fn replace(
  text: &str,
  mut visit: impl FnMut(&str) -> Result<Option<String>, ApiError>,
) -> Result<String, ApiError> {
  let mut rest = text;
  let mut result = String::with_capacity(text.len());
  while let Some((start, raw)) = next_placeholder(rest) {
    let end = start + raw.len() + 4;
    result.push_str(&rest[..start]);
    let replacement = visit(raw)?;
    result
      .push_str(replacement.as_deref().unwrap_or(&rest[start..end]));
    rest = &rest[end..];
  }
  result.push_str(rest);
  Ok(result)
}

#[derive(Default)]
pub(crate) struct Substitutions {
  prefix: String,
  values: Vec<String>,
}

impl Substitutions {
  fn new(
    text: &str,
    secrets: Option<&BTreeMap<String, String>>,
  ) -> Self {
    let mut prefix = format!(
      "WHARF_PUBLIC_REF_{}_",
      &crate::render::hash(text)[..16]
    );
    while text.contains(&prefix)
      || secrets
        .is_some_and(|map| map.values().any(|v| v.contains(&prefix)))
    {
      prefix.push('_');
    }
    Self {
      prefix,
      values: Vec::new(),
    }
  }

  fn insert(&mut self, value: String) -> String {
    let marker = format!("{}{}END", self.prefix, self.values.len());
    self.values.push(value);
    marker
  }

  pub(crate) fn finish_text(
    &self,
    text: &str,
    compose: bool,
  ) -> String {
    let mut rest = text;
    let mut result = String::with_capacity(text.len());
    if self.values.is_empty() {
      return text.to_string();
    }
    while let Some((before, marker)) = rest.split_once(&self.prefix) {
      let Some((id, after)) = marker.split_once("END") else {
        break;
      };
      result.push_str(before);
      if let Some(value) =
        id.parse::<usize>().ok().and_then(|i| self.values.get(i))
      {
        if compose {
          result.push_str(&value.replace('$', "$$"));
        } else {
          result.push_str(value);
        }
      } else {
        result.push_str(&self.prefix);
        result.push_str(id);
        result.push_str("END");
      }
      rest = after;
    }
    result.push_str(rest);
    result
  }

  pub(crate) fn finish_compose(
    &self,
    text: String,
  ) -> Result<String, ApiError> {
    if self.values.is_empty() {
      return Ok(text);
    }
    let mut doc = crate::render::parse_compose(&text)?;
    fn substitute_values(sub: &Substitutions, value: &mut Value) {
      match value {
        Value::String(s) => *s = sub.finish_text(s, true),
        Value::Sequence(values) => {
          for value in values {
            substitute_values(sub, value);
          }
        }
        Value::Mapping(values) => {
          for value in values.values_mut() {
            substitute_values(sub, value);
          }
        }
        _ => {}
      }
    }
    for (_, body) in
      doc["services"].as_mapping_mut().into_iter().flatten()
    {
      for key in [
        "command",
        "entrypoint",
        "working_dir",
        "hostname",
        "domainname",
        "stop_signal",
      ] {
        if let Some(value) = body.get_mut(key) {
          substitute_values(self, value);
        }
      }
      if let Some(test) = body
        .get_mut("healthcheck")
        .and_then(|value| value.get_mut("test"))
      {
        substitute_values(self, test);
      }
      match body.get_mut("environment") {
        Some(Value::Mapping(env)) => {
          for value in env.values_mut() {
            if let Value::String(s) = value {
              *s = self.finish_text(s, true);
            }
          }
        }
        Some(Value::Sequence(env)) => {
          for value in env {
            if let Value::String(s) = value
              && let Some((key, value)) = s.split_once('=')
            {
              *s = format!("{key}={}", self.finish_text(value, true));
            }
          }
        }
        _ => {}
      }
    }
    let out = serde_yaml_ng::to_string(&doc)
      .map_err(|_| ApiError::internal("无法渲染 Compose 变量"))?;
    if out.contains(&self.prefix) {
      // Compose 的结构由端口分配和宿主机权限先校验。
      return Err(
        ApiError::invalid(
          "Compose 变量和自身引用不能用于键名或部署结构",
        )
        .with_hint("将引用用于 environment 的值或容器命令参数"),
      );
    }
    Ok(out)
  }
}

pub(crate) fn prepare_spec<'a>(
  world: &World,
  net: &Net,
  name: &str,
  spec: &'a ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(Cow<'a, ServiceSpec>, Substitutions), ApiError> {
  let row = &world.services[name];
  let has_public = |text: &str| {
    placeholders(text)
      .any(|raw| parse_public_ref(raw, spec.self_refs).is_some())
  };
  if !spec.env.values().any(|text| has_public(text))
    && !matches!(&spec.source, Source::Compose {content: Some(text), ..} if has_public(text))
  {
    return Ok((Cow::Borrowed(spec), Substitutions::default()));
  }
  let mut substitutions = Substitutions::new(
    &serde_json::to_string(spec).map_err(crate::db::json_err)?,
    secrets,
  );
  let mut rewrite = |text: &str| {
    replace(text, |raw| {
      parse_public_ref(raw, spec.self_refs)
        .map(|r| {
          resolve(world, net, name, row, raw, r)
            .map(|v| substitutions.insert(v))
        })
        .transpose()
    })
  };
  let mut prepared = spec.clone();
  for value in prepared.env.values_mut() {
    *value = rewrite(value)?;
  }
  if let Source::Compose {
    content: Some(text),
    ..
  } = &mut prepared.source
  {
    *text = rewrite(text)?;
  }
  Ok((Cow::Owned(prepared), substitutions))
}

pub(crate) fn prepare_file(
  world: &World,
  net: &Net,
  name: &str,
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(String, Substitutions), ApiError> {
  let row = &world.services[name];
  if !placeholders(text)
    .any(|raw| parse_public_ref(raw, row.spec.self_refs).is_some())
  {
    return Ok((text.to_string(), Substitutions::default()));
  }
  let mut substitutions = Substitutions::new(text, secrets);
  let text = replace(text, |raw| {
    parse_public_ref(raw, row.spec.self_refs)
      .map(|r| {
        resolve(world, net, name, row, raw, r)
          .map(|v| substitutions.insert(v))
      })
      .transpose()
  })?;
  Ok((text, substitutions))
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use wharf_api_types::spec::{Change, PrivateAddr, PrivateNetwork};

  #[test]
  fn compose_command_expands_public_values_as_yaml_strings() {
    let mut world = World::default();
    let spec = json!({
      "op":"upsert_service", "name":"app", "spec":{
        "server":"s1", "self_refs": true, "source":{"compose":{"content":
          "services: {app: {image: alpine, command: ['[[SELF_NAME]]', '[[var:ARG]]']}}"
        }}
      }
    });
    world
      .apply_changes(&[
        Change::UpsertVar {
          name: "ARG".into(),
          value: "$HOME: [[SELF_NAME]]".into(),
        },
        serde_json::from_value(spec).unwrap(),
      ])
      .unwrap();
    let text = crate::snapshot::service_template(
      &world,
      &Net::default(),
      "app",
    )
    .unwrap();
    let doc = crate::render::parse_compose(&text).unwrap();
    let args = &doc["services"]["app"]["command"];
    assert_eq!(args[0].as_str(), Some("app"));
    assert_eq!(args[1].as_str(), Some("$$HOME: [[SELF_NAME]]"));
  }

  #[test]
  fn variables_are_literal_and_only_change_the_consumer() {
    let mut world = World::default();
    for server in ["s1", "s2"] {
      world.servers.insert(
        server.into(),
        crate::world::ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
    }
    let service = |name: &str, spec| {
      serde_json::from_value(json!({
        "op": "upsert_service", "name": name, "spec": spec,
      }))
      .unwrap()
    };
    world.apply_changes(&[
      Change::UpsertVar { name: "P23_TEXT".into(), value: "$ [[OTHER]] [[@b]]".into() },
      service("a", json!({"server": "s1", "source": {"image": "alpine"}, "self_refs": true,
        "env": {"VALUE": "[[var:P23_TEXT]]", "RUNNER": "[[SELF_SERVER]]", "ADDRESS": "[[SELF_PRIVATE_IP]]"}})),
      service("b", json!({"server": "s1", "source": {"image": "alpine"}})),
    ]).unwrap();
    let mut net = Net::default();
    for (server, ip) in [("s1", "100.64.0.1"), ("s2", "100.64.0.2")] {
      net.private.insert(
        server.into(),
        PrivateAddr {
          ip: ip.into(),
          network: PrivateNetwork::Tailscale,
        },
      );
    }
    let render = |w: &World, name: &str| {
      crate::snapshot::service_resolved(
        w,
        &net,
        name,
        &BTreeMap::new(),
      )
      .unwrap()
    };
    let (yaml, hash_a) = render(&world, "a");
    let (_, hash_b) = render(&world, "b");
    let env = &crate::render::parse_compose(&yaml).unwrap()["services"]
      ["a"]["environment"];
    assert_eq!(env["VALUE"].as_str(), Some("$$ [[OTHER]] [[@b]]"));
    assert_eq!(env["RUNNER"].as_str(), Some("s1"));
    let mut desired = world.clone();
    desired.vars.get_mut("P23_TEXT").unwrap().value =
      "changed".into();
    assert_ne!(render(&desired, "a").1, hash_a);
    assert_eq!(render(&desired, "b").1, hash_b);
    desired.services.get_mut("a").unwrap().spec.server = "s2".into();
    let doc =
      crate::render::parse_compose(&render(&desired, "a").0).unwrap();
    assert_eq!(
      doc["services"]["a"]["environment"]["ADDRESS"].as_str(),
      Some("100.64.0.2")
    );
    desired.vars.remove("P23_TEXT");
    assert_eq!(
      validate_removals(&world, &desired).unwrap_err().code,
      ErrorCode::Conflict
    );
  }
}
