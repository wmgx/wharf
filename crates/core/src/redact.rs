use serde_yaml_ng::Value;
use wharf_api_types::view::{TaskKind, TaskSpec};

pub fn mask_url_token(prefix: &str, token: &str) -> String {
  format!("{prefix}{}…", token.chars().take(4).collect::<String>())
}

pub fn redact_task_spec(spec: &TaskSpec) -> TaskSpec {
  let mut spec = spec.clone();
  match &mut spec.how {
    TaskKind::Ping { token, .. }
    | TaskKind::Script {
      hook: Some(token), ..
    } => token.clear(),
    _ => {}
  }
  spec
}

const ENV_MARKERS: &[&str] = &[
  "TOKEN",
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "AUTH",
  "COOKIE",
  "CREDENTIAL",
  "DSN",
  "WEBHOOK",
];

pub fn is_sensitive_env_key(key: &str) -> bool {
  let key = key.to_ascii_uppercase();
  !matches!(
    key.as_str(),
    "PUBLIC_KEY"
      | "SSH_PUBLIC_KEY"
      | "KEY_PATH"
      | "LANG"
      | "PATH"
      | "TZ"
  ) && (ENV_MARKERS.iter().any(|part| key.contains(part))
    || ["PRIVATE_KEY", "API_KEY", "APIKEY"]
      .iter()
      .any(|part| key.contains(part))
    || key.ends_with("_KEY")
    || key.ends_with("_PASS"))
}

pub(crate) use wharf_api_types::secret_detect::url_credentials;

pub fn redact_compose_secrets(yaml: &str) -> (String, Vec<String>) {
  let Ok(mut root) = crate::render::parse_compose(yaml) else {
    return (String::new(), vec![]);
  };
  let mut keys = Vec::new();
  redact_compose_env(&mut root, &mut keys);
  keys.sort_unstable();
  keys.dedup();
  let output = if keys.is_empty() {
    yaml.to_string()
  } else {
    serde_yaml_ng::to_string(&root).unwrap_or_default()
  };
  (output, keys)
}

fn sensitive_compose_env(key: &str, value: &str) -> bool {
  is_sensitive_env_key(key)
    || url_credentials(value).next().is_some()
    || wharf_api_types::secret_detect::env_secret_reason(key, value)
      .is_some()
}

fn redact_compose_env(node: &mut Value, keys: &mut Vec<String>) {
  const MASK: &str = "[[请替换为密钥名]]";
  match node {
    Value::Mapping(map) => {
      match map.get_mut("environment") {
        Some(Value::Mapping(env)) => {
          for (key, value) in env.iter_mut() {
            if let Some(key) = key.as_str()
              && sensitive_compose_env(
                key,
                value.as_str().unwrap_or_default(),
              )
            {
              keys.push(key.to_string());
              *value = Value::String(MASK.into());
            }
          }
        }
        Some(Value::Sequence(env)) => {
          for item in env {
            if let Some(raw) = item.as_str() {
              let (key, value) =
                raw.split_once('=').unwrap_or((raw, ""));
              if sensitive_compose_env(key, value) {
                keys.push(key.to_string());
                *item = Value::String(format!("{key}={MASK}"));
              }
            }
          }
        }
        _ => {}
      }
      for value in map.values_mut() {
        redact_compose_env(value, keys);
      }
    }
    Value::Sequence(children) => {
      for child in children {
        redact_compose_env(child, keys);
      }
    }
    Value::Tagged(tag) => redact_compose_env(&mut tag.value, keys),
    _ => {}
  }
}

fn words(text: &str) -> Vec<(usize, &str)> {
  let mut result = Vec::new();
  let mut start = None;
  let mut quote = None;
  let mut escaped = false;
  for (index, c) in text.char_indices() {
    if !escaped
      && quote.is_none()
      && (c.is_whitespace() || matches!(c, ';' | '|' | '&'))
    {
      if let Some(start) = start.take() {
        result.push((start, &text[start..index]));
      }
      continue;
    }
    start.get_or_insert(index);
    if escaped {
      escaped = false;
    } else if c == '\\' && quote != Some('\'') {
      escaped = true;
    } else if quote == Some(c) {
      quote = None;
    } else if quote.is_none() && matches!(c, '\'' | '"') {
      quote = Some(c);
    }
  }
  if let Some(start) = start {
    result.push((start, &text[start..]));
  }
  result
}

fn redact_authorization(text: &str) -> String {
  let lower = text.to_ascii_lowercase();
  let mut output = text.to_string();
  let mut next = text.len();
  for (index, key) in lower
    .match_indices("authorization:")
    .collect::<Vec<_>>()
    .into_iter()
    .rev()
  {
    let value = text[index + key.len()..].trim_start();
    let delimiter = |c: char| {
      c.is_whitespace() || matches!(c, '\'' | '"' | ';' | '|')
    };
    let scheme_end = value.find(delimiter).unwrap_or(value.len());
    let known_scheme = matches!(
      value[..scheme_end].to_ascii_lowercase().as_str(),
      "bearer" | "basic" | "token"
    );
    let credential = if known_scheme {
      value[scheme_end..].trim_start()
    } else {
      value
    };
    let quoted = text[..index]
      .chars()
      .next_back()
      .filter(|c| matches!(*c, '\'' | '"'));
    let end = if let Some(quote) = quoted.filter(|_| !known_scheme) {
      credential.find(quote)
    } else {
      credential.find(delimiter)
    };
    let start = text.len() - credential.len();
    let end = (start + end.unwrap_or(credential.len())).min(next);
    if start < end {
      output.replace_range(start..end, "***");
      next = start;
    }
  }
  output
}

pub fn redact_command(cmd: &str) -> String {
  let mut output = cmd.to_string();
  for (start, end) in
    url_credentials(cmd).collect::<Vec<_>>().into_iter().rev()
  {
    output.replace_range(start..end, "***:***");
  }
  let cmd = redact_authorization(&output);
  let mut output = String::new();
  let mut end = 0;
  let mut previous = "";
  let mut mask_next = false;
  for (start, word) in words(&cmd) {
    output.push_str(&cmd[end..start]);
    let bare = word.trim_matches(['\'', '"']);
    let (key, value) = bare
      .split_once('=')
      .map_or((bare, None), |(k, v)| (k, Some(v)));
    let flag = key.trim_start_matches('-').to_ascii_lowercase();
    let sensitive = key.starts_with('-')
      && ([
        "token",
        "password",
        "passwd",
        "pass",
        "secret",
        "api-key",
        "apikey",
        "auth",
        "access-key",
        "private-key",
        "dsn",
        "webhook",
        "cookie",
      ]
      .iter()
      .any(|suffix| flag.ends_with(suffix))
        || (key == "-p"
          && matches!(
            previous.rsplit('/').next(),
            Some("mysql" | "redis-cli" | "pass")
          )));
    let env = !key.is_empty()
      && key.bytes().all(|c| {
        c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'
      })
      && (key.contains("KEY")
        || ENV_MARKERS.iter().any(|part| key.contains(part)));
    if mask_next && !bare.starts_with('-') {
      output.push_str("***");
    } else if value.is_some() && (sensitive || env) {
      output.push_str(key);
      output.push_str("=***");
    } else {
      output.push_str(word);
    }
    mask_next = sensitive && value.is_none();
    previous = bare;
    end = start + word.len();
  }
  output.push_str(&cmd[end..]);
  output
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use wharf_api_types::{ErrorCode, spec::ServiceSpec, view::Perm};

  #[test]
  fn import_preview_requires_host_and_redacts_sensitive_env() {
    use crate::host_access::{HostTarget, require_with, tests::auth};
    let auth = auth([Perm::Plan, Perm::Apply], false);
    assert_eq!(
      require_with(
        &auth,
        HostTarget::ImportPreview {
          server: "s1",
          target: "app"
        },
        None,
        Some("core"),
      )
      .unwrap_err()
      .0
      .code,
      ErrorCode::Forbidden
    );
    let (compose, keys) = redact_compose_secrets(
      "services:\n  app:\n    environment:\n      DATABASE_PASSWORD: s3cr3t\n      APP_PORT: \"8080\"\n      REDIS_URL: redis://user:pw@host:6379\n",
    );
    let root: Value = serde_yaml_ng::from_str(&compose).unwrap();
    let env = &root["services"]["app"]["environment"];
    assert_eq!(env["APP_PORT"].as_str(), Some("8080"));
    for key in ["DATABASE_PASSWORD", "REDIS_URL"] {
      assert_eq!(env[key].as_str(), Some("[[请替换为密钥名]]"));
    }
    assert_eq!(keys, ["DATABASE_PASSWORD", "REDIS_URL"]);
    assert!(
      !compose.contains("s3cr3t") && !compose.contains("user:pw")
    );
    let (list, keys) = redact_compose_secrets(
      "services: {app: {environment: ['API_KEY=example', 'LANG=C', 'QUEUE_URL=redis://u:p@queue']}}",
    );
    let root: Value = serde_yaml_ng::from_str(&list).unwrap();
    let env = root["services"]["app"]["environment"]
      .as_sequence()
      .unwrap();
    assert_eq!(
      env.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
      [
        "API_KEY=[[请替换为密钥名]]",
        "LANG=C",
        "QUEUE_URL=[[请替换为密钥名]]",
      ]
    );
    assert_eq!(keys, ["API_KEY", "QUEUE_URL"]);
  }

  #[test]
  fn read_only_redacts_task_tokens_and_rollback_heartbeat() {
    let auth = crate::host_access::tests::auth([Perm::Read], false);
    let ping: TaskSpec = serde_json::from_value(json!({"server":"s1","schedule":"","kind":"ping","token":"wh_secret_ping"})).unwrap();
    let script: TaskSpec = serde_json::from_value(json!({"server":"s1","schedule":"","kind":"script","runtime":"shell","code":"echo ok","hook":"wh_secret_hook"})).unwrap();
    assert!(
      matches!(redact_task_spec(&ping).how, TaskKind::Ping { token, .. } if token.is_empty())
    );
    assert!(
      matches!(redact_task_spec(&script).how, TaskKind::Script { hook: Some(token), .. } if token.is_empty())
    );
    for (spec, prefix, token) in [
      (&ping, "/ping/", "wh_secret_ping"),
      (&script, "/hook/", "wh_secret_hook"),
    ] {
      assert_eq!(
        crate::tasks::need_perm(
          &auth,
          spec,
          &Default::default(),
          Some("core")
        )
        .unwrap_err()
        .0
        .code,
        ErrorCode::Forbidden
      );
      assert_eq!(
        mask_url_token(prefix, token),
        format!("{prefix}wh_s…")
      );
    }
    let service: ServiceSpec = serde_json::from_value(json!({
      "server":"s1","source":{"image":"nginx:1"},
      "heartbeat":{"every_mins":10,"token":"wh_secret"}
    }))
    .unwrap();
    assert!(
      crate::service_monitor::heartbeat::redact(&service)
        .heartbeat
        .unwrap()
        .token
        .is_empty()
    );
  }
}
