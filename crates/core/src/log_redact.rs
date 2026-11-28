use std::{
  cmp::Reverse,
  collections::BTreeMap,
  sync::{Arc, RwLock},
};

use base64::{Engine, engine::general_purpose::STANDARD};
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
  values.retain(|value| value.len() >= 6);
  add_encoded_values(values);
  values.sort_unstable_by(|a, b| {
    (Reverse(a.len()), a).cmp(&(Reverse(b.len()), b))
  });
  values.dedup();
}

pub(crate) fn add_encoded_values(values: &mut Vec<String>) {
  let mut escaped = Vec::new();
  for value in values.iter() {
    escaped.push(STANDARD.encode(value));
    if let std::borrow::Cow::Owned(encoded) =
      urlencoding::encode(value)
    {
      escaped.push(encoded);
    }
    if let Ok(json) = serde_json::to_string(value) {
      let json = &json[1..json.len() - 1];
      if json != value {
        escaped.push(json.to_string());
      }
      if json.contains(['<', '>', '&']) {
        escaped.push(
          json
            .replace('<', r"\u003c")
            .replace('>', r"\u003e")
            .replace('&', r"\u0026"),
        );
      }
    }
  }
  values.extend(escaped);
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
    out.extend(secret_policy::pem_body(text).map(str::to_string));
  }
}

pub fn service_values(spec: &ServiceSpec) -> Vec<String> {
  let mut out = Vec::new();
  if let Some(m) = &spec.monitor {
    for (key, text) in &m.headers {
      value(&mut out, text, crate::monitor::sensitive_header(key));
    }
  }
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
    && let Ok(yaml) = crate::render::parse_compose(content)
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
  previous: &BTreeMap<String, String>,
  passwords: impl Iterator<Item = String>,
  accounts: &[db::AccountRow],
  world: &World,
  tasks: impl Iterator<Item = TaskSpec>,
) -> Vec<String> {
  let mut out = secret_policy::redact_values(secrets);
  out.extend(secret_policy::redact_values(previous));
  for (name, text) in secrets.iter().chain(previous) {
    if secret_policy::describe(name).is_some_and(|meta| !meta.redact)
    {
      continue;
    }
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
) -> Result<Arc<Vec<String>>, ApiError> {
  let passwords =
    db::service_values(conn, key, BTreeMap::new(), None)?
      .into_iter()
      .filter_map(|(name, value)| {
        name.ends_with(".password").then_some(value)
      });
  let tasks = crate::tasks::load_rows(conn)?;
  let previous = db::previous_secrets(conn, key, db::now_ms())?;
  let values = Arc::new(collect(
    secrets,
    &previous,
    passwords,
    accounts,
    world,
    tasks.into_iter().map(|(_, spec, _)| spec),
  ));
  *VALUES.write().unwrap_or_else(|e| e.into_inner()) =
    Some(Arc::clone(&values));
  Ok(values)
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
  #[test]
  fn redacts_anchor_env_secret() {
    let spec = serde_json::from_value(serde_json::json!({
      "server":"s1", "source":{"compose":{"content":
        "x-base: &b {environment: {API_SECRET: fixture-anchor-value}}\nservices: {app: {<<: *b, image: nginx}}"
      }}
    })).unwrap();
    assert!(
      service_values(&spec).contains(&"fixture-anchor-value".into())
    );
  }

  use super::*;

  #[tokio::test]
  async fn expired_previous_secret_is_removed_from_redaction_and_cannot_rollback()
   {
    let db = Db::memory();
    db.call_credentials(|c, key| {
      let old = "fixture@old\n\"";
      let new = "fixture@new";
      let now = db::now_ms();
      let expires = now + 60_000;
      key.put_secret(c, "K1", old, now, false)?;
      key.rotate_secret(c, "K1", new, now, Some(expires), false)?;
      key.rotate_secret(c, "K1", new, now, Some(expires), false)?;
      let secrets = db::secrets(c, key)?;
      let masks = update(c, key, &World::default(), &secrets, &[])?;
      let json = serde_json::to_string(old).unwrap();
      let line = format!(
        "{old} {new} {} {} {}",
        STANDARD.encode(old),
        urlencoding::encode(old),
        &json[1..json.len() - 1]
      );
      assert_eq!(
        wharf_api_types::mask_values(&line, &masks),
        "*** *** *** *** ***"
      );
      assert_eq!(db::cleanup_expired_secret_prevs(c, expires)?, 1);
      assert_eq!(
        key.rollback_secret(c, "K1", expires).unwrap_err().code,
        wharf_api_types::ErrorCode::InvalidInput
      );
      assert!(
        !update(c, key, &World::default(), &secrets, &[])?
          .iter()
          .any(|value| value == old)
      );
      Ok(())
    })
    .await
    .unwrap();
  }

  #[test]
  fn masks_url_and_go_json_secret_encodings() {
    let mut values =
      vec!["p@ss/w#1?".into(), "a<&>\nbcd".into(), "<&>".into()];
    prepare(&mut values);
    assert_eq!(
      wharf_api_types::mask_values(
        r"p%40ss%2Fw%231%3F a\u003c\u0026\u003e\nbcd %3C%26%3E",
        &values,
      ),
      "*** *** %3C%26%3E"
    );
  }

  #[test]
  fn masks_base64_url_and_json_secret_encodings() {
    let value = "p@s#1\n\"\\";
    let input = r#"cEBzIzEKIlw= p%40s%231%0A%22%5C p@s#1\n\"\\"#;
    assert_eq!(
      redact_text_with(input, &[value.into()]),
      "*** *** ***"
    );
  }

  #[test]
  fn redacts_registered_sources_and_preserves_public_values() {
    let secrets = BTreeMap::from([
      ("APP_KEY".into(), "fixture-app-key".into()),
      ("PEM".into(), "\n-----BEGIN PRIVATE KEY----- \nYWJjZGVmZw==\n-----END PRIVATE KEY-----".into()),
      (crate::link::CA_CERT_SECRET.into(), "fixture-public-cert".into()),
      ("SHORT".into(), "short".into()),
    ]);
    let raw = "fixture-app-key   YWJjZGVmZw== fixture-public-cert short fixture-password fixture-inline fixture-heartbeat fixture-hook fixture-vendor   c2VydmljZQ==   dGFzay1rZXk=";
    let mut world = World::default();
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1",
      "source": {"compose": {"content": "services: {app: {environment: {DB_PASSWORD: fixture-inline}}}"}},
      "env": {"APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nc2VydmljZQ==\n-----END PRIVATE KEY-----"},
      "heartbeat": {"every_mins": 10, "token":"fixture-heartbeat"}
    })).unwrap();
    world.services.insert(
      "app".into(),
      crate::world::ServiceRow {
        instance_id: "svc_fixture".into(),
        spec,
        host_ports: BTreeMap::new(),
        import: None,
        pins: BTreeMap::new(),
        commit: None,
        version: 1,
      },
    );
    let task = serde_json::from_value(serde_json::json!({
      "server":"s1","schedule":"","kind":"script","runtime":"shell","code":"echo ok","hook":"fixture-hook",
      "env":{"TASK_PRIVATE_KEY":"-----BEGIN PRIVATE KEY-----\ndGFzay1rZXk=\n-----END PRIVATE KEY-----"}
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
      &BTreeMap::new(),
      ["fixture-password".to_string()].into_iter(),
      &[account],
      &world,
      [task].into_iter(),
    );
    let output = wharf_api_types::mask_values(raw, &values);
    assert_eq!(
      output,
      "***   *** fixture-public-cert short *** *** *** *** ***   ***   ***"
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
