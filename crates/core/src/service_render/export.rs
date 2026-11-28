use std::{collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::{Path, State},
};
use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  ApiError,
  references::{
    SecretMode, next_placeholder, parse_placeholder,
    parse_service_ref,
  },
  spec::Source,
  view::{Perm, ServiceComposeExport},
};

use crate::{
  api::ApiResult, auth::Auth, render, snapshot, state::AppState,
  world::ServiceRow,
};

pub async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ServiceComposeExport> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  let snap = snapshot::load(&state.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| crate::api::service_not_found(&name))?;
  export(&name, row, &snap.log_values)
    .map(Json)
    .map_err(Into::into)
}

fn unsupported(field: &str) -> ApiError {
  ApiError::invalid(format!("此配置无法安全导出（{field}）"))
    .with_hint("将密钥改成 Wharf 引用，或先提供可拉取镜像／外部文件")
}

fn identifier(s: &str) -> bool {
  !s.is_empty()
    && s.bytes().all(|b| {
      b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
    })
}

struct Export<'a> {
  reserved: String,
  result: ServiceComposeExport,
  secret_files: BTreeMap<String, (String, String)>,
  volumes: BTreeMap<String, String>,
  known: &'a [String],
}

impl Export<'_> {
  fn variable(&mut self, kind: &str) -> String {
    let mut n = self.result.variables.len() + 1;
    loop {
      let name = format!("EXPORT_VALUE_{n}");
      if !self.reserved.contains(&name)
        && !self.result.variables.contains_key(&name)
      {
        self.result.variables.insert(name.clone(), kind.into());
        return format!("${{{name}:?set {name}}}");
      }
      n += 1;
    }
  }

  fn file(&mut self, dir: &str, kind: &str) -> String {
    let path =
      format!("./{dir}/input-{}", self.result.files.len() + 1);
    self.result.files.insert(path.clone(), kind.into());
    path
  }

  fn scalar(
    &mut self,
    value: &str,
    field: &str,
    mounts: &mut BTreeMap<String, String>,
  ) -> Result<String, ApiError> {
    let mut out = String::new();
    let mut rest = value;
    while !rest.is_empty() {
      let reference = next_placeholder(rest);
      let dollar = rest.find('$');
      let next = reference
        .map(|(pos, _)| pos)
        .into_iter()
        .chain(dollar)
        .min();
      let end = next.unwrap_or(rest.len());
      let literal = &rest[..end];
      if !literal.is_empty() {
        if literal
          .chars()
          .all(|c| c.is_whitespace() || "=:;,.@/?&+-_".contains(c))
        {
          out.push_str(literal);
        } else {
          out.push_str(&self.variable(field));
        }
      }
      rest = &rest[end..];
      if rest.is_empty() {
        break;
      }
      if let Some((0, inner)) = next_placeholder(rest) {
        if parse_service_ref(inner).is_some() {
          out.push_str(&self.variable("service_ref"));
        } else {
          let p = parse_placeholder(inner, true)
            .map_err(|_| unsupported(field))?
            .ok_or_else(|| unsupported(field))?;
          let encoding = match p.mode {
            SecretMode::Plain => "plain",
            SecretMode::B64 => "b64",
            SecretMode::Json => "json",
            SecretMode::Url => "url",
            SecretMode::File => "file",
          };
          if p.mode == SecretMode::File {
            if !identifier(p.name) {
              return Err(unsupported(field));
            }
            let (path, target) =
              if let Some(entry) = self.secret_files.get(p.name) {
                entry.clone()
              } else {
                let path = self.file("secrets", "secret");
                let target =
                  format!("{}/{}", render::SECRET_FILE_DIR, p.name);
                self.secret_files.insert(
                  p.name.into(),
                  (path.clone(), target.clone()),
                );
                (path, target)
              };
            mounts.insert(target.clone(), path);
            out.push_str(&target);
          } else {
            out.push_str(&self.variable(encoding));
          }
        }
        rest = &rest[inner.len() + 4..];
      } else if let Some(after) = rest.strip_prefix("$$") {
        out.push_str("$$");
        rest = after;
      } else if let Some(after) = rest.strip_prefix("${") {
        let mut depth = 1;
        let end = after
          .char_indices()
          .find_map(|(offset, ch)| {
            if after[offset..].starts_with("${") {
              depth += 1;
            } else if ch == '}' {
              depth -= 1;
            }
            (depth == 0).then_some(offset)
          })
          .ok_or_else(|| unsupported(field))?;
        let expr = &after[..end];
        let name =
          expr.split([':', '-', '+', '?']).next().unwrap_or_default();
        let op = &expr[name.len()..];
        if !env_name(name)
          || (!op.is_empty()
            && !["-", ":-", "+", ":+", "?", ":?"]
              .iter()
              .any(|prefix| op.starts_with(prefix)))
          || next_placeholder(expr).is_some()
        {
          return Err(unsupported(field));
        }
        safe_tree(
          &Value::String(expr.to_owned()),
          field,
          self.known,
        )?;
        out.push_str(&rest[..end + 3]);
        rest = &after[end + 1..];
      } else {
        let after = &rest[1..];
        let end = after
          .bytes()
          .take_while(|&b| b.is_ascii_alphanumeric() || b == b'_')
          .count();
        if end == 0 || !env_name(&after[..end]) {
          return Err(unsupported(field));
        }
        out.push_str(&rest[..end + 1]);
        rest = &after[end..];
      }
    }
    Ok(out)
  }

  fn mount_source(&mut self, source: &str) -> String {
    if let Some(path) = self.volumes.get(source) {
      path.clone()
    } else if identifier(source) {
      source.into()
    } else {
      self.file("external", "bind")
    }
  }

  fn mount(&mut self, value: &mut Value) -> Result<(), ApiError> {
    if let Some(short) = value.as_str() {
      if short.starts_with('/') && !short.contains(':') {
        return safe_tree(value, "volumes", self.known);
      }
      let (head, tail) = short
        .rsplit_once(':')
        .ok_or_else(|| unsupported("volumes"))?;
      let (source, target, mode) = if tail.starts_with('/') {
        (head, tail, "")
      } else {
        let (source, target) = head
          .rsplit_once(':')
          .ok_or_else(|| unsupported("volumes"))?;
        if !tail.split(',').all(|v| {
          matches!(
            v,
            "ro"
              | "rw"
              | "z"
              | "Z"
              | "cached"
              | "delegated"
              | "consistent"
          )
        }) {
          return Err(unsupported("volumes.mode"));
        }
        (source, target, tail)
      };
      safe_target(target, self.known)?;
      let source = self.mount_source(source);
      *value = Value::String(if mode.is_empty() {
        format!("{source}:{target}")
      } else {
        format!("{source}:{target}:{mode}")
      });
      return Ok(());
    }
    let map = value
      .as_mapping_mut()
      .ok_or_else(|| unsupported("volumes"))?;
    let kind = map.get("type").and_then(Value::as_str).unwrap_or("");
    if !matches!(kind, "bind" | "volume" | "tmpfs")
      || map.keys().any(|key| {
        if kind == "tmpfs" && key.as_str() == Some("tmpfs") {
          return !map
            .get(key)
            .and_then(Value::as_mapping)
            .is_some_and(|options| {
              options.len() == 1
                && options
                  .get("size")
                  .and_then(Value::as_u64)
                  .is_some()
            });
        }
        !matches!(
          key.as_str(),
          Some("type" | "source" | "target" | "read_only")
        )
      })
    {
      return Err(unsupported("volumes"));
    }
    safe_target(
      map.get("target").and_then(Value::as_str).unwrap_or(""),
      self.known,
    )?;
    if let Some(source) = map.get_mut("source") {
      let path = source
        .as_str()
        .ok_or_else(|| unsupported("volumes.source"))?;
      *source = Value::String(self.mount_source(path));
    }
    safe_tree(value, "volumes", self.known)
  }
}

fn env_name(s: &str) -> bool {
  s.bytes()
    .next()
    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn safe_target(
  target: &str,
  known: &[String],
) -> Result<(), ApiError> {
  if !target.starts_with('/')
    || target.contains([':', '$', '\n', '\r', '\0'])
    || render::reserved_secret_mount(target)
  {
    return Err(unsupported("volumes.target"));
  }
  safe_tree(&Value::String(target.into()), "volumes.target", known)
}

fn safe_tree(
  value: &Value,
  field: &str,
  known: &[String],
) -> Result<(), ApiError> {
  match value {
    Value::String(value)
      if wharf_api_types::secret_detect::detect_secret_value(
        value,
      )
      .is_some()
        || known.iter().any(|secret| {
          !secret.is_empty() && value.contains(secret)
        }) =>
    {
      Err(unsupported(field))
    }
    Value::Sequence(values) => values
      .iter()
      .try_for_each(|value| safe_tree(value, field, known)),
    Value::Mapping(values) => {
      values.iter().try_for_each(|(key, value)| {
        safe_tree(key, field, known)?;
        safe_tree(value, field, known)
      })
    }
    Value::Tagged(_) => Err(unsupported(field)),
    _ => Ok(()),
  }
}

fn env_map(value: Value) -> Result<Mapping, ApiError> {
  match value {
    Value::Null => Ok(Mapping::new()),
    Value::Mapping(value) => Ok(value),
    Value::Sequence(list) => list
      .into_iter()
      .map(|value| {
        let item =
          value.as_str().ok_or_else(|| unsupported("environment"))?;
        let (key, value) = item
          .split_once('=')
          .map_or((item, Value::Null), |(k, v)| {
            (k, Value::String(v.into()))
          });
        Ok((Value::String(key.into()), value))
      })
      .collect(),
    _ => Err(unsupported("environment")),
  }
}

fn export(
  name: &str,
  row: &ServiceRow,
  stored_secrets: &[String],
) -> Result<ServiceComposeExport, ApiError> {
  let spec = &row.spec;
  let mut known = stored_secrets.to_vec();
  known.extend(crate::log_redact::service_values(spec));
  let template =
    serde_json::to_string(spec).map_err(|_| unsupported("source"))?;
  let mut ctx = Export {
    reserved: template,
    result: ServiceComposeExport {
      service: name.into(),
      compose: String::new(),
      variables: BTreeMap::new(),
      files: BTreeMap::new(),
      warnings: vec![],
    },
    secret_files: BTreeMap::new(),
    volumes: BTreeMap::new(),
    known: &known,
  };
  let mut settings = spec.clone();
  settings.env.clear();
  settings.files.clear();
  for v in &spec.volumes {
    if v.from_service.is_none() {
      if !identifier(&v.name) {
        return Err(unsupported("volumes.name"));
      }
      let path = format!("./data/{}", v.name);
      ctx.volumes.insert(
        render::volume_host_dir(name, v)
          .map_err(|_| unsupported("volumes"))?,
        path.clone(),
      );
      ctx.result.files.insert(path, "data".into());
    }
  }
  let is_compose = matches!(spec.source, Source::Compose { .. });
  let mut doc = match &spec.source {
    Source::Build(_) => return Err(unsupported("source.build")),
    Source::Compose {
      content: Some(content),
      ..
    } => {
      let parsed = render::parse_compose_template(content)
        .map_err(|_| unsupported("source.compose"))?;
      if parsed.get("include").is_some() {
        return Err(unsupported("include"));
      }
      let text = serde_yaml_ng::to_string(&parsed)
        .map_err(|_| unsupported("source.compose"))?;
      let text =
        render::compose_with_settings(name, &text, &settings)
          .map_err(|_| unsupported("source.compose"))?;
      render::parse_compose_template(&text)
        .map_err(|_| unsupported("source.compose"))?
    }
    Source::Compose { .. } => {
      return Err(unsupported("source.compose"));
    }
    Source::Image(_) => {
      let (text, _) = render::service_compose(
        name,
        &settings,
        &row.host_ports,
        &[],
        None,
      )
      .map_err(|_| unsupported("source.image"))?;
      render::parse_compose_template(&text)
        .map_err(|_| unsupported("source.image"))?
    }
  };
  let root =
    doc.as_mapping_mut().ok_or_else(|| unsupported("compose"))?;
  root.retain(|key, _| {
    !key
      .as_str()
      .is_some_and(|k| k.starts_with("x-") || k == "version")
  });
  for (key, value) in root.iter() {
    let key = key.as_str().ok_or_else(|| unsupported("compose"))?;
    match key {
      "services" => {}
      "name" if value.as_str().is_some_and(identifier) => {}
      "volumes" | "networks"
        if value.as_mapping().is_some_and(|map| {
          map.iter().all(|(k, v)| {
            k.as_str().is_some_and(identifier)
              && (v.is_null()
                || v.as_mapping().is_some_and(Mapping::is_empty))
          })
        }) => {}
      "include" => return Err(unsupported("include")),
      _ => return Err(unsupported("compose")),
    }
  }
  let services = root
    .get_mut("services")
    .and_then(Value::as_mapping_mut)
    .ok_or_else(|| unsupported("services"))?;
  if services.is_empty() {
    return Err(unsupported("services"));
  }
  let target = if spec.env.is_empty() && spec.files.is_empty() {
    None
  } else if is_compose {
    let content = serde_yaml_ng::to_string(&Value::Mapping(
      Mapping::from_iter([(
        Value::String("services".into()),
        Value::Mapping(services.clone()),
      )]),
    ))
    .map_err(|_| unsupported("services"))?;
    Some(
      render::compose_target(
        name,
        &content,
        spec.container.as_deref(),
      )
      .map_err(|_| unsupported("container"))?,
    )
  } else {
    Some(name.to_string())
  };
  for (component, body) in services {
    let component = component
      .as_str()
      .filter(|s| identifier(s))
      .ok_or_else(|| unsupported("services"))?;
    let body = body
      .as_mapping_mut()
      .ok_or_else(|| unsupported("services"))?;
    if !is_compose && let Some(mode) = spec.pull_policy {
      use wharf_api_types::spec::ImagePullMode;
      let policy = match mode {
        ImagePullMode::IfMissing => "missing",
        ImagePullMode::Never => "never",
        ImagePullMode::Always => "always",
      };
      body.insert("pull_policy".into(), Value::String(policy.into()));
    }
    let mut mounts = BTreeMap::new();
    let mut env =
      env_map(body.remove("environment").unwrap_or_default())?;
    if target.as_deref() == Some(component) {
      for (key, value) in &spec.env {
        env.insert(
          Value::String(key.clone()),
          Value::String(value.clone()),
        );
      }
      for file in &spec.files {
        safe_target(&file.path, &known)?;
        let path = ctx.file("config", "config");
        mounts.insert(file.path.clone(), path);
      }
    }
    env.remove("WHARF_HEARTBEAT_URL");
    for (key, value) in &mut env {
      let key = key
        .as_str()
        .filter(|key| env_name(key))
        .ok_or_else(|| unsupported("environment"))?;
      if !value.is_null() {
        let text = match value {
          Value::String(text) => text.clone(),
          Value::Bool(_) | Value::Number(_) => {
            serde_yaml_ng::to_string(value)
              .map_err(|_| unsupported("environment"))?
          }
          _ => return Err(unsupported("environment")),
        };
        if key == "TZ"
          && !is_compose
          && !spec.env.contains_key(key)
          && spec.timezone.is_some()
        {
          continue;
        }
        *value = Value::String(ctx.scalar(
          text.trim_end_matches('\n'),
          key,
          &mut mounts,
        )?);
      }
    }
    body.retain(|key, _| {
      !key.as_str().is_some_and(|key| key.starts_with("x-"))
    });
    for (key, value) in &mut *body {
      match key.as_str().unwrap_or_default() {
        "image" => {
          if !value.as_str().is_some_and(|s| {
            !s.is_empty()
              && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b"-._/:@".contains(&b)
              })
          }) || value.as_str().is_some_and(|s| {
            s.starts_with(wharf_api_types::agent::BUILD_IMAGE_PREFIX)
          }) {
            return Err(unsupported("image"));
          }
        }
        "command" | "entrypoint" => {
          let mut replace =
            |value: &mut Value| -> Result<(), ApiError> {
              let text = value
                .as_str()
                .ok_or_else(|| unsupported("command"))?;
              *value = Value::String(ctx.scalar(
                text,
                "command",
                &mut mounts,
              )?);
              Ok(())
            };
          match value {
            Value::Null => {}
            Value::Sequence(values) => {
              values.iter_mut().try_for_each(&mut replace)?
            }
            _ => replace(value)?,
          }
        }
        "volumes" => {
          for v in value
            .as_sequence_mut()
            .ok_or_else(|| unsupported("volumes"))?
          {
            ctx.mount(v)?;
          }
        }
        "labels" => match value {
          Value::Mapping(labels) => {
            labels.retain(|key, _| {
              !key.as_str().is_some_and(|s| s.starts_with("wharf."))
            });
            for item in labels.values_mut() {
              let text =
                item.as_str().ok_or_else(|| unsupported("labels"))?;
              *item = Value::String(ctx.scalar(
                text,
                "label",
                &mut mounts,
              )?);
            }
          }
          Value::Sequence(labels) => {
            labels.retain(|value| {
              !value.as_str().is_some_and(|s| s.starts_with("wharf."))
            });
            for item in labels {
              let text =
                item.as_str().ok_or_else(|| unsupported("labels"))?;
              let key = text.split('=').next().unwrap_or_default();
              if !identifier(key) {
                return Err(unsupported("labels"));
              }
              if let Some((key, text)) = text.split_once('=') {
                *item = Value::String(format!(
                  "{key}={}",
                  ctx.scalar(text, "label", &mut mounts)?
                ));
              }
            }
          }
          _ => return Err(unsupported("labels")),
        },
        "ports" => {
          for port in
            value.as_sequence().ok_or_else(|| unsupported("ports"))?
          {
            let allowed = match port {
              Value::String(s) => s.bytes().all(|b| {
                b.is_ascii_digit()
                  || b":.-/[]abcdefABCDEFtcpu".contains(&b)
              }),
              Value::Number(n) => {
                n.as_u64().is_some_and(|n| (1..=65535).contains(&n))
              }
              _ => false,
            };
            if !allowed {
              return Err(unsupported("ports"));
            }
          }
          if is_compose
            && !ctx
              .result
              .warnings
              .iter()
              .any(|s| s == "保留模板显式端口映射")
          {
            ctx.result.warnings.push("保留模板显式端口映射".into());
          }
        }
        "restart"
          if value.as_str().is_some_and(|s| {
            matches!(
              s,
              "no" | "always" | "unless-stopped" | "on-failure"
            ) || s
              .strip_prefix("on-failure:")
              .is_some_and(|s| s.parse::<u32>().is_ok())
          }) => {}
        "stop_signal"
          if value.as_str().is_some_and(|s| {
            wharf_api_types::compose::normalize_stop_signal(s).is_ok()
          }) => {}
        "pull_policy"
          if value.as_str().is_some_and(|s| {
            matches!(s, "always" | "missing" | "never")
          }) => {}
        "hostname" if value.as_str().is_some_and(identifier) => {}
        "pids_limit" if value.as_i64().is_some() => {}
        "cap_add" | "group_add"
          if value.as_sequence().is_some_and(|values| {
            values.iter().all(|v| {
              v.as_str().is_some_and(identifier)
                || v.as_u64().is_some()
            })
          }) => {}
        "ulimits"
          if value.as_mapping().is_some_and(|limits| {
            limits.iter().all(|(key, limit)| {
              key.as_str().is_some_and(identifier)
                && (limit.as_i64().is_some()
                  || limit.as_mapping().is_some_and(|pair| {
                    pair.len() == 2
                      && ["soft", "hard"].iter().all(|key| {
                        pair
                          .get(*key)
                          .and_then(Value::as_i64)
                          .is_some()
                      })
                  }))
            })
          }) => {}
        "logging"
          if value.as_mapping().is_some_and(|logging| {
            logging.len() == 2
              && logging.get("driver").and_then(Value::as_str)
                == Some("json-file")
              && logging
                .get("options")
                .and_then(Value::as_mapping)
                .is_some_and(|options| {
                  options.len() == 2
                    && ["max-size", "max-file"].iter().all(|key| {
                      options
                        .get(*key)
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.parse::<u64>().is_ok())
                    })
                })
          }) => {}
        "stop_grace_period" | "cpus" | "mem_limit" | "shm_size"
          if value.as_f64().is_some()
            || value.as_str().is_some_and(|s| {
              s.bytes().all(|b| {
                b.is_ascii_digit() || b".smhbkgtBKMG".contains(&b)
              })
            }) => {}
        "depends_on" | "networks"
          if value.as_sequence().is_some_and(|items| {
            items
              .iter()
              .all(|item| item.as_str().is_some_and(identifier))
          }) => {}
        "init" | "read_only" | "tty" | "stdin_open"
          if value.as_bool().is_some() => {}
        "extends" => return Err(unsupported("services.extends")),
        "build" => return Err(unsupported("services.build")),
        _ => return Err(unsupported("services")),
      }
    }
    if !env.is_empty() {
      body.insert("environment".into(), Value::Mapping(env));
    }
    if !mounts.is_empty() {
      let volumes = body
        .entry("volumes".into())
        .or_insert_with(|| Value::Sequence(vec![]));
      let volumes = volumes
        .as_sequence_mut()
        .ok_or_else(|| unsupported("volumes"))?;
      volumes.extend(mounts.into_iter().map(|(target, source)| {
        Value::String(format!("{source}:{target}:ro"))
      }));
    }
  }
  safe_tree(&doc, "compose", &known)?;
  ctx.result.compose = serde_yaml_ng::to_string(&doc)
    .map_err(|_| unsupported("compose"))?;
  if spec.init_cmd.is_some() {
    ctx
      .result
      .warnings
      .push("存在部署前初始化命令，需另行准备".into());
  }
  Ok(ctx.result)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn fixture(content: &str) -> ServiceRow {
    ServiceRow {
      frozen_defaults: Default::default(),
      instance_id: "fixture".into(),
      spec: serde_json::from_value(json!({
        "server":"s1", "source":{"compose":{"content":content}},
        "files":[{"path":"/etc/app.conf","content":"key=never-export-this"}]
      })).unwrap(),
      host_groups: Default::default(),
      host_ports: Default::default(),
      pins: Default::default(),
      import: None,
      commit: None,
      version: 1,
    }
  }

  #[test]
  fn compose_export_keeps_placeholders_and_never_returns_contents() {
    let row = fixture(
      r#"
services:
  web:
    image: alpine
    labels: ["wharf.service=web"]
    environment:
      PASS: '[[PASS]]'
      ENCODED: '[[url:PASS]],[[b64:PASS]],[[json:PASS]]'
      KEY: '[[FILE:KEY]]'
      DB: '[[@db.http:port]]'
      MODE: '${LOCAL_MODE:-production} $$'
      RAW: 'fixture-inline'
"#,
    );
    let view =
      export("app", &row, &["fixture-known".into()]).unwrap();
    let yaml: Value = serde_yaml_ng::from_str(&view.compose).unwrap();
    let web = &yaml["services"]["web"];
    assert_eq!(
      web["environment"]["MODE"].as_str(),
      Some("${LOCAL_MODE:-production} $$")
    );
    assert_eq!(view.files.len(), 2);
    assert_eq!(web["volumes"].as_sequence().unwrap().len(), 2);
    assert_eq!(view.variables.len(), 6);
    let json = serde_json::to_string(&view).unwrap();
    for text in [
      "never-export-this",
      "fixture-inline",
      "wharf.service",
      "[[@",
    ] {
      assert!(!json.contains(text));
    }
    assert!(
      export("app", &fixture("include: [external.yaml]"), &[])
        .unwrap_err()
        .message
        .contains("include")
    );
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
      let dir = tempfile::tempdir().unwrap();
      let compose = dir.path().join("compose.yaml");
      std::fs::write(&compose, &view.compose).unwrap();
      for file in view.files.keys() {
        let path = dir.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "fixture").unwrap();
      }
      let status = std::process::Command::new("docker")
        .args(["compose", "-f"])
        .arg(&compose)
        .args(["config", "--quiet"])
        .envs(view.variables.keys().map(|key| (key, "fixture")))
        .env("LOCAL_MODE", "fixture")
        .status()
        .unwrap();
      assert!(status.success());
    }
  }
}

#[cfg(test)]
#[test]
fn compose_export_carries_23_1_runtime_and_component_limits() {
  let row = |spec| ServiceRow {
    frozen_defaults: Default::default(),
    instance_id: "fixture".into(),
    spec: serde_json::from_value(spec).unwrap(),
    host_groups: Default::default(),
    host_ports: Default::default(),
    pins: Default::default(),
    import: None,
    commit: None,
    version: 1,
  };
  let image = row(serde_json::json!({
    "server":"s1", "source":{"image":"alpine"}, "command":["serve"],
    "init":true, "shm_size":67108864, "cap_add":["NET_BIND_SERVICE"],
    "ulimits":{"nofile":{"soft":64,"hard":128}}, "hostname":"worker",
    "group_add":["1000"], "tmpfs":{"/tmp":67108864}, "timezone":"Asia/Singapore",
    "log_max":{"max_bytes":10485760,"max_files":3}, "limits":{"pids":64}
  }));
  let yaml: Value = serde_yaml_ng::from_str(
    &export("app", &image, &[]).unwrap().compose,
  )
  .unwrap();
  let app = &yaml["services"]["app"];
  assert_eq!(app["shm_size"].as_u64(), Some(67108864));
  assert_eq!(
    app["environment"]["TZ"].as_str(),
    Some("Asia/Singapore")
  );
  assert_eq!(
    app["volumes"][0]["tmpfs"]["size"].as_u64(),
    Some(67108864)
  );
  assert_eq!(
    app["logging"]["options"]["max-file"].as_str(),
    Some("3")
  );
  assert_eq!(app["pids_limit"].as_u64(), Some(64));

  let compose = row(serde_json::json!({
    "server":"s1", "source":{"compose":{"content":"services:\n  web:\n    image: alpine\n"}},
    "pull_policy":"never", "container_limits":{"web":{"memory_mb":128,"pids":32}}
  }));
  let yaml: Value = serde_yaml_ng::from_str(
    &export("app", &compose, &[]).unwrap().compose,
  )
  .unwrap();
  assert_eq!(
    yaml["services"]["web"]["pull_policy"].as_str(),
    Some("never")
  );
  assert_eq!(
    yaml["services"]["web"]["mem_limit"].as_str(),
    Some("128m")
  );
  assert_eq!(
    yaml["services"]["web"]["pids_limit"].as_u64(),
    Some(32)
  );
}
