use std::{
  cmp::Reverse,
  collections::BTreeMap,
  sync::{Arc, RwLock},
};

use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError,
  plan::Run,
  spec::{ServiceSpec, Source},
  view::{TaskKind, TaskSpec},
};

use crate::{
  db::{self, Db},
  redact, secret_policy,
  world::World,
};

static VALUES: RwLock<Option<Arc<Vec<String>>>> = RwLock::new(None);

fn prepare(values: &mut Vec<String>) {
  let escaped = values
    .iter()
    .filter_map(|value| {
      if !value.contains(['"', '\\', '\n', '\r', '\t']) {
        return None;
      }
      let encoded = serde_json::to_string(value).ok()?;
      Some(encoded[1..encoded.len() - 1].to_string())
    })
    .collect::<Vec<_>>();
  values.extend(escaped);
  values.retain(|value| value.len() >= 6);
  values.sort_unstable_by(|a, b| {
    (Reverse(a.len()), a).cmp(&(Reverse(b.len()), b))
  });
  values.dedup();
}

fn value(out: &mut Vec<String>, text: &str, sensitive: bool) {
  if text.contains("[[") || text.len() < 6 {
    return;
  }
  let mut credentials = false;
  for (start, end) in redact::url_credentials(text) {
    let userinfo = &text[start..end];
    out.push(userinfo.into());
    if let Some((_, password)) = userinfo.split_once(':') {
      out.push(password.into());
    }
    credentials = true;
  }
  if sensitive || credentials {
    out.push(text.into());
  }
}

pub fn service_values(spec: &ServiceSpec) -> Vec<String> {
  let mut out = Vec::new();
  if let Some(heartbeat) = &spec.heartbeat {
    out.push(heartbeat.token.clone());
  }
  for (key, text) in &spec.env {
    value(&mut out, text, redact::is_sensitive_env_key(key));
  }
  if let Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
    && let Ok(yaml) = serde_yaml_ng::from_str::<Value>(content)
    && let Some(services) =
      yaml.get("services").and_then(Value::as_mapping)
  {
    for service in services.values() {
      match service.get("environment") {
        Some(Value::Mapping(env)) => {
          for (key, item) in env {
            let Some(key) = key.as_str() else { continue };
            let sensitive = redact::is_sensitive_env_key(key);
            if let Some(text) = item.as_str() {
              value(&mut out, text, sensitive);
            } else if sensitive && let Some(n) = item.as_f64() {
              out.push(n.to_string());
            }
          }
        }
        Some(Value::Sequence(env)) => {
          for (key, text) in env
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|line| line.split_once('='))
          {
            value(&mut out, text, redact::is_sensitive_env_key(key));
          }
        }
        _ => {}
      }
    }
  }
  out
}

fn collect(
  secrets: &BTreeMap<String, String>,
  passwords: impl Iterator<Item = String>,
  accounts: &[db::AccountRow],
  world: &World,
  tasks: impl Iterator<Item = TaskSpec>,
) -> Vec<String> {
  let mut out = secret_policy::redact_values(secrets);
  for (name, text) in secrets {
    let token = if name.starts_with(crate::notify_keys::SECRET_PREFIX)
    {
      text.split_once("/notify/").map(|(_, token)| token)
    } else if name == crate::notify::FEISHU_WEBHOOK {
      text.rsplit_once('/').map(|(_, token)| token)
    } else {
      None
    };
    if let Some(token) = token
      .map(|t| t.split(['/', '?', '#']).next().unwrap_or_default())
      && token.len() >= 12
    {
      out.push(token.into());
    }
  }
  out.extend(passwords);
  out.extend(accounts.iter().map(|row| row.token.clone()));
  for service in world.services.values() {
    out.extend(service_values(&service.spec));
  }
  for server in world.servers.values() {
    let settings = &server.settings;
    for proxy in settings.pull_proxy.iter().chain(&settings.git_proxy)
    {
      value(&mut out, proxy, false);
    }
    for (key, text) in &settings.build_env {
      value(&mut out, text, redact::is_sensitive_env_key(key));
    }
    for mirror in settings
      .registry_mirrors
      .values()
      .flatten()
      .chain(&settings.github_mirror)
    {
      value(&mut out, mirror, false);
      let mirror =
        mirror.split_once("://").map_or(mirror.as_str(), |(_, m)| m);
      if let Some((_, path)) = mirror.split_once('/')
        && let Some(token) = path.split('/').next()
        && !token.contains("[[")
        && token.len() >= 12
      {
        out.push(token.into());
      }
    }
  }
  for task in tasks {
    if let TaskKind::Ping { token, .. }
    | TaskKind::Script {
      hook: Some(token), ..
    } = &task.how
    {
      out.push(token.clone());
    }
    if let TaskKind::Container { env, .. }
    | TaskKind::Script { env, .. } = &task.how
    {
      for (key, text) in env {
        value(&mut out, text, redact::is_sensitive_env_key(key));
      }
    }
  }
  prepare(&mut out);
  out
}

pub fn update(
  conn: &rusqlite::Connection,
  key: &db::CredentialsKey,
  world: &World,
  secrets: &BTreeMap<String, String>,
  accounts: &[db::AccountRow],
) -> Result<(), ApiError> {
  let passwords =
    db::service_values(conn, key, BTreeMap::new(), None)?
      .into_iter()
      .filter_map(|(name, value)| {
        name.ends_with(".password").then_some(value)
      });
  let tasks = crate::tasks::load_rows(conn)?;
  let values = collect(
    secrets,
    passwords,
    accounts,
    world,
    tasks.into_iter().map(|(_, spec, _)| spec),
  );
  *VALUES.write().unwrap_or_else(|e| e.into_inner()) =
    Some(Arc::new(values));
  Ok(())
}

pub async fn refresh(db: &Db) {
  let result = db
    .call_credentials(|conn, key| {
      let world = World::from_rows(db::all_resources(conn)?)?;
      let secrets = crate::oidc::with_client_secrets(
        &world,
        &db::secrets(conn, key)?,
      );
      update(conn, key, &world, &secrets, &db::accounts(conn)?)
    })
    .await;
  if result.is_err() {
    tracing::warn!("刷新日志打码清单失败");
  }
}

fn current() -> Option<Arc<Vec<String>>> {
  VALUES.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn redact_text(text: &str) -> String {
  if let Some(values) = current() {
    return values.iter().fold(text.to_string(), |text, value| {
      if text.contains(value) {
        text.replace(value, "***")
      } else {
        text
      }
    });
  }
  text.to_string()
}

pub fn redact_text_with(text: &str, extra: &[String]) -> String {
  if extra.is_empty() {
    return redact_text(text);
  }
  let mut values = extra.to_vec();
  prepare(&mut values);
  if let Some(current) = current() {
    values.extend(current.iter().cloned());
  }
  wharf_api_types::mask_values(text, &values)
}

pub fn redact_error(mut error: ApiError) -> ApiError {
  error.message = redact_text(&error.message);
  error.hint = error.hint.map(|hint| redact_text(&hint));
  error
}

pub fn redact_run(run: &mut Run) {
  for step in &mut run.steps {
    for line in &mut step.log {
      *line = redact_text(line);
    }
    step.error = step.error.take().map(redact_error);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redacts_registered_sources_and_preserves_public_values() {
    let secrets = BTreeMap::from([
      ("APP_KEY".into(), "fixture-app-key".into()),
      ("PEM".into(), "-----BEGIN PRIVATE KEY-----\nYWJjZGVmZw==\n-----END PRIVATE KEY-----".into()),
      (crate::link::CA_CERT_SECRET.into(), "fixture-public-cert".into()),
      ("SHORT".into(), "short".into()),
    ]);
    let raw = "fixture-app-key YWJjZGVmZw== fixture-public-cert short fixture-password fixture-inline fixture-heartbeat fixture-hook fixture-vendor";
    let mut world = World::default();
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1",
      "source": {"compose": {"content": "services: {app: {environment: {DB_PASSWORD: fixture-inline}}}"}},
      "heartbeat": {"every_mins": 10, "token":"fixture-heartbeat"}
    })).unwrap();
    world.services.insert(
      "app".into(),
      crate::world::ServiceRow {
        spec,
        host_ports: BTreeMap::new(),
        import: None,
        pins: BTreeMap::new(),
        commit: None,
        version: 1,
      },
    );
    let task = serde_json::from_value(serde_json::json!({
      "server":"s1","schedule":"","kind":"script","runtime":"shell","code":"echo ok","hook":"fixture-hook"
    })).unwrap();
    let account = db::AccountRow {
      name: "fixture".into(),
      kind: "cloudflare".into(),
      token: "fixture-vendor".into(),
      zones: vec![],
      warnings: vec![],
      updated_at: 0,
    };
    let values = collect(
      &secrets,
      ["fixture-password".to_string()].into_iter(),
      &[account],
      &world,
      [task].into_iter(),
    );
    let output = wharf_api_types::mask_values(raw, &values);
    assert_eq!(
      output,
      "*** *** fixture-public-cert short *** *** *** *** ***"
    );
    let found = crate::log_search::search(
      &output,
      &crate::log_search::Options {
        grep: Some("fixture-inline"),
        errors: false,
        max_line: 500,
        limit: 5,
      },
    );
    assert_eq!(found.matched, 0);
  }
}
