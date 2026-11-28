//! 配置自查只读快照和期望状态。提醒只包含位置、规则和修复建议。

use wharf_api_types::secret_detect::{
  has_compose_var, is_placeholder_value, is_sensitive_env_key,
  known_format, private_key_header,
};

use std::collections::{BTreeMap, BTreeSet};

use serde_yaml_ng::{Mapping, Value};
use wharf_api_types::{
  plan::{Action, Layer, PlanItem},
  spec::{ServiceSpec, Source},
};

use crate::{
  docker_run::memory_mb,
  planner::{Step, StepPlan},
  render::Net,
  snapshot::Snapshot,
  world::{KIND_SERVICE, ServiceRow, World},
};

pub(crate) fn plan_warnings(
  snap: &Snapshot,
  desired: &World,
  items: &[PlanItem],
  steps: &[StepPlan],
) -> Vec<String> {
  let mut services = BTreeSet::new();
  let mut servers = BTreeSet::new();
  for item in items {
    let Some((KIND_SERVICE, name)) = item.address.split_once('/')
    else {
      continue;
    };
    let old = snap
      .world
      .services
      .get(name)
      .map(|s| s.spec.server.as_str());
    let new =
      desired.services.get(name).map(|s| s.spec.server.as_str());
    servers.extend(old.into_iter().chain(new));
    if item.layer == Layer::Config
      && matches!(item.action, Action::Create | Action::Update)
    {
      services.insert(name);
    }
  }
  for step in steps {
    match &step.step {
      Step::ServiceUp { service, .. } => {
        services.insert(service.as_str());
      }
      Step::VolumeSync {
        service, from, to, ..
      } => {
        services.insert(service.as_str());
        servers.extend([from.as_str(), to.as_str()]);
      }
      Step::ServiceDown { server, .. } => {
        servers.insert(server.as_str());
      }
      _ => {}
    }
  }
  warnings(
    snap,
    desired,
    services
      .into_iter()
      .filter_map(|name| desired.services.get_key_value(name)),
    servers.into_iter(),
  )
  .into_iter()
  .map(|(subject, detail)| format!("{subject} {detail}"))
  .collect()
}

pub(crate) fn scoped_warnings(
  snap: &Snapshot,
  services: &BTreeSet<String>,
  servers: &BTreeSet<String>,
) -> Vec<(String, String)> {
  warnings(
    snap,
    &snap.world,
    services
      .iter()
      .filter_map(|name| snap.world.services.get_key_value(name)),
    servers.iter().map(String::as_str),
  )
}

fn warnings<'a>(
  snap: &Snapshot,
  world: &World,
  services: impl Iterator<Item = (&'a String, &'a ServiceRow)>,
  servers: impl Iterator<Item = &'a str>,
) -> Vec<(String, String)> {
  let net = Net::derive(&world.servers, &snap.agents);
  let mut warnings = Vec::new();
  let secrets =
    crate::secret_policy::non_system_secrets(&snap.secrets);
  for (name, row) in services {
    let public = net.public_ip.contains_key(&row.spec.server);
    warnings.extend(
      service_warnings(&row.spec, public, &secrets)
        .into_iter()
        .chain(crate::shared_volumes::implicit_warnings(
          world, name, &row.spec,
        ))
        .map(|detail| (format!("服务 {name}"), detail)),
    );
  }
  for server in servers {
    let Some(metrics) = snap
      .agent(server)
      .and_then(|agent| agent.report.as_ref())
      .and_then(|report| report.metrics.as_deref())
    else {
      continue;
    };
    let services = world
      .services
      .values()
      .map(|row| &row.spec)
      .filter(|spec| spec.server == server);
    if let Some(detail) = memory_warning(services, metrics.mem_total)
    {
      warnings.push((format!("服务器 {server}"), detail));
    }
  }
  warnings
}

fn compose_services(spec: &ServiceSpec) -> Option<Mapping> {
  let Source::Compose {
    content: Some(content),
    ..
  } = &spec.source
  else {
    return None;
  };
  let mut compose = crate::render::parse_compose(content).ok()?;
  match std::mem::take(compose.get_mut("services")?) {
    Value::Mapping(services) => Some(services),
    _ => None,
  }
}

/// (绑定地址, 用于提示的端口)。没有指定宿主端口时显示容器端口。
fn published_port(port: &Value) -> Option<(&str, String)> {
  if let Some(raw) = port.as_str() {
    let mut parts = raw.rsplitn(3, ':');
    let target = parts.next()?.split('/').next()?;
    let published =
      parts.next().filter(|p| !p.is_empty()).unwrap_or(target);
    return Some((
      parts.next().unwrap_or_default(),
      published.to_string(),
    ));
  }
  if let Some(map) = port.as_mapping() {
    let host = map
      .get("host_ip")
      .and_then(Value::as_str)
      .unwrap_or_default();
    let published = map
      .get("published")
      .and_then(scalar_text)
      .filter(|s| !s.is_empty())
      .or_else(|| map.get("target").and_then(scalar_text))?;
    return Some((host, published));
  }
  port.as_u64().map(|target| ("", target.to_string()))
}

fn published_ports(
  container: &Value,
) -> impl Iterator<Item = (&str, String)> {
  container["ports"]
    .as_sequence()
    .into_iter()
    .flatten()
    .filter_map(published_port)
}

pub(crate) fn compose_allows_direct_access(compose: &Value) -> bool {
  compose["services"].as_mapping().is_some_and(|services| {
    services.values().any(|container| {
      container["network_mode"].as_str() == Some("host")
        || published_ports(container).any(|(host, _)| {
          !matches!(host, "127.0.0.1" | "::1" | "[::1]")
        })
    })
  })
}

fn uses_latest(image: &str) -> bool {
  let last = &image[image.rfind('/').map_or(0, |i| i + 1)..];
  !image.is_empty()
    && !image.contains('@')
    && !image.contains('$')
    && last.split_once(':').is_none_or(|(_, tag)| tag == "latest")
}

const LATEST: &str = "使用了 latest 镜像标签。Wharf 会固定 digest，但用 latest 看不出跑的是哪个版本，也查不到新版本";

fn service_warnings(
  spec: &ServiceSpec,
  public: bool,
  secrets: &BTreeMap<String, String>,
) -> Vec<String> {
  let mut warnings = Vec::new();
  if let Source::Image(image) = &spec.source
    && uses_latest(image)
  {
    warnings.push(format!("的镜像{LATEST}"));
  }
  for (key, value) in &spec.env {
    if let Some(detail) = env_secret(key, value, secrets) {
      warnings.push(format!("的 env 变量 {key} {detail}"));
    }
  }
  if let Some(m) = &spec.monitor {
    for (key, value) in &m.headers {
      let check_key = if crate::monitor::sensitive_header(key) {
        "ACCESS_TOKEN"
      } else {
        key
      };
      if let Some(detail) = env_secret(check_key, value, secrets) {
        warnings.push(format!("的监控请求头 {key} {detail}"));
      }
    }
  }
  if let Some(containers) = compose_services(spec) {
    for (name, container) in &containers {
      let Some(name) = name.as_str() else { continue };
      let restart = &container["restart"];
      if (restart.is_null()
        || restart.as_bool() == Some(false)
        || matches!(restart.as_str(), Some("no" | "false")))
        && container["deploy"]["restart_policy"].is_null()
      {
        warnings.push(format!("的 compose 容器 {name} 没设重启策略，机器重启或容器崩溃后不会自动拉起，可考虑设置 restart: unless-stopped"));
      }
      if container["image"].as_str().is_some_and(uses_latest) {
        warnings.push(format!("的 compose 容器 {name} {LATEST}"));
      }
      for (host, port) in published_ports(container) {
        if matches!(host, "" | "0.0.0.0" | "::" | "[::]") {
          let network = if public { "公网" } else { "局域网" };
          let port = if !port.is_empty()
            && port.bytes().all(|c| c.is_ascii_digit() || c == b'-')
          {
            format!("端口 {port} ")
          } else {
            "发布的端口".to_string()
          };
          warnings.push(format!("的 compose 容器 {name} 的{port}绑定所有地址，会暴露到{network}，可按需绑定回环或私网地址"));
        }
      }
      compose_env_warnings(
        &mut warnings,
        name,
        &container["environment"],
        secrets,
      );
    }
  }
  for file in &spec.files {
    if let Some(detail) = file_secret(&file.content, secrets) {
      warnings.push(format!("的文件 {} {detail}", file.path));
    }
  }
  warnings
}

fn scalar_text(value: &Value) -> Option<String> {
  match value {
    Value::String(s) => Some(s.clone()),
    Value::Number(n) => Some(n.to_string()),
    Value::Bool(b) => Some(b.to_string()),
    _ => None,
  }
}

fn compose_env_warnings(
  warnings: &mut Vec<String>,
  container: &str,
  env: &Value,
  secrets: &BTreeMap<String, String>,
) {
  let mut check = |key: &str, value: &str| {
    if let Some(detail) = env_secret(key, value, secrets) {
      warnings.push(format!(
        "的 compose 容器 {container} 的环境变量 {key} {detail}"
      ));
    }
  };
  if let Some(mapping) = env.as_mapping() {
    for (key, value) in mapping {
      if let (Some(key), Some(value)) =
        (key.as_str(), scalar_text(value))
      {
        check(key, &value);
      }
    }
  } else if let Some(entries) = env.as_sequence() {
    for (key, value) in
      entries.iter().filter_map(|e| e.as_str()?.split_once('='))
    {
      check(key, value);
    }
  }
}

fn memory_warning<'a>(
  services: impl Iterator<Item = &'a ServiceSpec>,
  total_bytes: u64,
) -> Option<String> {
  if total_bytes == 0 {
    return None;
  }
  let total = total_bytes as f64 / (1024.0 * 1024.0);
  let mut sum = 0.0;
  let mut unlimited = 0;
  for spec in services.filter(|spec| !spec.stopped) {
    let limit = service_memory(spec);
    sum += limit;
    unlimited += usize::from(limit == 0.0);
  }
  (sum > total).then(|| format!("上已设内存上限的服务合计 {sum} MB，超过机器内存 {total} MB（另有 {unlimited} 个服务没设上限）"))
}

fn service_memory(spec: &ServiceSpec) -> f64 {
  if let Some((bytes, _)) = compose_memory_limits(spec) {
    return bytes as f64 / (1 << 20) as f64;
  }
  f64::from(
    spec
      .limits
      .as_ref()
      .and_then(|l| l.memory_mb)
      .unwrap_or_default(),
  )
}

fn effective_component_memory(
  spec: &ServiceSpec,
  name: &Value,
  container: &Value,
  single: bool,
) -> Option<f64> {
  let name = name.as_str()?;
  spec
    .container_limits
    .get(name)
    .and_then(|limits| limits.memory_mb)
    .or_else(|| {
      (spec.container.as_deref() == Some(name)
        || (single && spec.container.is_none()))
      .then(|| {
        spec.limits.as_ref().and_then(|limits| limits.memory_mb)
      })
      .flatten()
    })
    .map(f64::from)
    .or_else(|| container_memory_mb(container))
}

fn container_memory_mb(container: &Value) -> Option<f64> {
  container["deploy"]["resources"]["limits"]
    .get("memory")
    .filter(|value| !value.is_null())
    .or_else(|| container.get("mem_limit"))
    .and_then(scalar_text)
    .as_deref()
    .and_then(memory_mb)
}

pub(crate) fn compose_memory_limits(
  spec: &ServiceSpec,
) -> Option<(u64, bool)> {
  let containers = compose_services(spec)?;
  let mut all_limited = !containers.is_empty();
  let mut bytes = 0_u64;
  for (name, container) in &containers {
    if let Some(mb) = effective_component_memory(
      spec,
      name,
      container,
      containers.len() == 1,
    )
    .filter(|&mb| mb > 0.0)
    {
      bytes = bytes.saturating_add((mb * (1 << 20) as f64) as u64);
    } else {
      all_limited = false;
    }
  }
  Some((bytes, all_limited))
}

fn has_reference_to(
  value: &str,
  known: Option<&BTreeMap<String, String>>,
) -> bool {
  has_compose_var(value)
    || crate::render::placeholders(value).any(|inner| {
      crate::render::parse_placeholder(inner, true)
        .ok()
        .flatten()
        .is_some_and(|p| {
          p.mode != crate::render::SecretMode::Plain
            || crate::render::account_ref(p.name).is_some()
            || known.is_none_or(|known| {
              known.contains_key(p.name)
                || value.trim() == format!("[[{inner}]]")
            })
        })
    })
}

fn env_secret(
  key: &str,
  value: &str,
  secrets: &BTreeMap<String, String>,
) -> Option<String> {
  let trimmed = value.trim();
  if url_has_password(trimmed, Some(secrets)) {
    return Some(move_to_vault("密码", "URL 内嵌密码"));
  }
  if has_reference_to(trimmed, Some(secrets))
    || is_placeholder_value(trimmed)
  {
    return None;
  }
  if let Some(name) = stored_secret(value, secrets) {
    return Some(reuse_secret(name));
  }
  if let Some(rule) = known_format(trimmed) {
    return Some(move_to_vault("密钥", rule));
  }
  (trimmed.chars().count() >= 6 && is_sensitive_env_key(key))
    .then(|| move_to_vault("密码", "敏感变量名"))
}

fn url_has_password(
  value: &str,
  known: Option<&BTreeMap<String, String>>,
) -> bool {
  let Some((scheme, tail)) = value.split_once("://") else {
    return false;
  };
  if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
    || !scheme.bytes().all(|c| {
      c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')
    })
  {
    return false;
  }
  let authority =
    tail.split(['/', '?', '#']).next().unwrap_or_default();
  let authority = authority
    .split_once("[[@")
    .map_or(authority, |(prefix, _)| prefix);
  authority.rsplit_once('@').is_some_and(|(userinfo, host)| {
    (!host.is_empty() || tail.contains("[[@"))
      && userinfo.split_once(':').is_some_and(|(_, password)| {
        !password.is_empty() && !has_reference_to(password, known)
      })
  })
}

fn stored_secret<'a>(
  value: &str,
  secrets: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
  if value.len() < 8 {
    return None;
  }
  secrets.iter().find_map(|(name, stored)| {
    (stored == value && !name.contains(value))
      .then_some(name.as_str())
  })
}

fn reuse_secret(name: &str) -> String {
  format!("直接写了密钥库里的明文值，建议直接改成 `[[{name}]]`")
}

fn move_to_vault(kind: &str, rule: &str) -> String {
  format!(
    "像是明文{kind}（{rule}），建议存成密钥：`wharf secret set <名>`，再改成 `[[<名>]]`"
  )
}

fn file_secret(
  content: &str,
  secrets: &BTreeMap<String, String>,
) -> Option<String> {
  if !has_reference_to(content, Some(secrets))
    && let Some(name) = stored_secret(content, secrets)
  {
    return Some(reuse_secret(name));
  }
  let mut rule = content
    .lines()
    .any(|line| {
      line
        .find("-----BEGIN ")
        .is_some_and(|start| private_key_header(&line[start..]))
    })
    .then_some("PEM 私钥格式");
  // shortcut: 按常见配置分隔符取值；需要识别带空格的字段时再按文件格式解析。
  for token in content.split(|c: char| {
    c.is_whitespace()
      || matches!(c, '\'' | '"' | ',' | ';' | '{' | '}')
  }) {
    for value in
      [Some(token), token.split_once('=').map(|(_, value)| value)]
        .into_iter()
        .flatten()
    {
      if url_has_password(value, Some(secrets)) {
        return Some(move_to_vault("密码", "URL 内嵌密码"));
      }
      if has_reference_to(value, Some(secrets)) {
        continue;
      }
      if let Some(name) = stored_secret(value, secrets) {
        return Some(reuse_secret(name));
      }
      if rule.is_none() {
        rule = known_format(value.trim_matches(['[', ']']));
      }
    }
  }
  rule.map(|rule| move_to_vault("密钥", rule))
}

#[cfg(test)]
mod tests {
  #[test]
  fn fake_brackets_do_not_bypass_secret_lint() {
    assert!(
      env_secret("API_TOKEN", "ab[[cd]]ef123456", &BTreeMap::new())
        .is_some()
    );
  }

  #[test]
  fn fake_brackets_do_not_hide_stored_secret_in_file() {
    let value = "ab[[cd]]ef123456";
    let secrets =
      BTreeMap::from([("API_TOKEN".into(), value.into())]);
    assert_eq!(
      file_secret(&format!("token={value}\n"), &secrets),
      Some(reuse_secret("API_TOKEN"))
    );
  }

  use serde_json::json;

  use super::*;

  fn compose(content: &str) -> ServiceSpec {
    serde_json::from_value(json!({
      "server": "s1",
      "source": {"compose": {"content": content}},
    }))
    .unwrap()
  }

  #[test]
  fn compose_warns_about_restart_latest_and_wildcard_port() {
    let spec = compose(
      r#"
services:
  web:
    image: nginx
    ports: ["8080:80", "127.0.0.1:9000:9000"]
  app:
    image: localhost:5000/app:1.2
    restart: unless-stopped
"#,
    );
    let warnings = service_warnings(&spec, true, &BTreeMap::new());
    assert_eq!(warnings.len(), 3);
    assert!(warnings[0].contains("没设重启策略"));
    assert!(warnings[1].contains("latest"));
    assert!(
      warnings[2].contains("8080")
        && warnings[2].contains("会暴露到公网")
    );
  }

  #[test]
  fn memory_adds_compose_and_service_limits() {
    let compose = compose(
      r#"
services:
  web:
    mem_limit: 512m
  worker:
    mem_limit: 128m
    deploy:
      resources:
        limits:
          memory: 1GiB
"#,
    );
    let image = serde_json::from_value(json!({
      "server": "s1",
      "source": {"image": "nginx:1"},
      "limits": {"memory_mb": 600},
    }))
    .unwrap();
    assert_eq!(
      memory_warning(
        [&compose, &image].into_iter(),
        2048 * 1024 * 1024
      )
      .as_deref(),
      Some(
        "上已设内存上限的服务合计 2136 MB，超过机器内存 2048 MB（另有 0 个服务没设上限）"
      )
    );
    assert_eq!(memory_mb("1g"), Some(1024.0));
    assert_eq!(memory_mb("1GiB"), Some(1024.0));
    assert_eq!(memory_mb("536870912"), Some(512.0));
    assert_eq!(memory_mb("512MB"), Some(512.0));
  }

  #[test]
  fn plaintext_secret_warnings_never_echo_values() {
    let spec = serde_json::from_value(json!({
      "server": "s1",
      "source": {"image": "app:1"},
      "monitor": {"headers": {"Authorization": "Bearer fixture-header-value"}},
    })).unwrap();
    let warnings = service_warnings(&spec, false, &BTreeMap::new());
    assert!(warnings.iter().any(|w| w.contains("Authorization")));
    assert!(
      !warnings.iter().any(|w| w.contains("fixture-header-value"))
    );
    let password = concat!("abc", "12345");
    let url_password = concat!("p4ss", "w0rd");
    let url = format!("postgres://u:{url_password}@db/x");
    let stored = concat!("ghp_", "fixture_for_lint_only");
    let vault = BTreeMap::from([("gh".into(), stored.into())]);
    for (key, value, expected) in [
      ("DB_PASSWORD", password, Some("敏感变量名")),
      ("DB_PASSWORD_FILE", "/run/secrets/x", None),
      ("API_TOKEN", "[[tok]]", None),
      ("PORT", "3000", None),
      ("DATABASE_URL", url.as_str(), Some("URL 内嵌密码")),
      ("GITHUB", stored, Some("[[gh]]")),
    ] {
      let warning = env_secret(key, value, &vault);
      assert_eq!(warning.is_some(), expected.is_some(), "{key}");
      assert!(
        !warning.as_deref().unwrap_or_default().contains(value),
        "{key}"
      );
      if let Some(expected) = expected {
        assert!(
          warning
            .as_deref()
            .is_some_and(|text| text.contains(expected)
              && !text.contains(url_password)),
          "{key}"
        );
      }
    }
  }
}

#[test]
fn service_ref_and_escaped_dollar_do_not_bypass_secret_lint() {
  let secrets =
    BTreeMap::from([("DB_PASS".into(), "fixture".into())]);
  assert!(
    env_secret(
      "DATABASE_URL",
      "postgres://u:fixture-pass@[[@db]]:5432/app",
      &secrets
    )
    .is_some()
  );
  assert!(env_secret("PASS", "Abc$$123", &secrets).is_some());
  assert!(
    env_secret(
      "DATABASE_URL",
      "postgres://u:[[DB_PASS]]@[[@db]]:5432/app",
      &secrets
    )
    .is_none()
  );
  assert!(env_secret("PASS", "${DB_PASS}", &secrets).is_none());
  assert_eq!(
    published_port(&serde_yaml_ng::from_str("target: 80").unwrap()),
    Some(("", "80".into()))
  );
}

#[test]
fn warns_on_stopped_service_config_update() {
  let mut snap = Snapshot::default();
  snap.world.services.insert("app".into(), ServiceRow {
    instance_id: "svc_fixture".into(), spec: serde_json::from_value(serde_json::json!({
      "server":"s1","source":{"image":"nginx:1"},"stopped":true,"env":{"PASS":"fixture-password"}
    })).unwrap(), host_ports:Default::default(), import:None, pins:Default::default(), commit:None, version:1,
  });
  let item: PlanItem = serde_json::from_value(serde_json::json!({
    "id":1,"address":"service/app","layer":"config","action":"update","reason":"测试",
  })).unwrap();
  assert!(
    plan_warnings(&snap, &snap.world, &[item], &[])
      .iter()
      .any(|w| w.contains("明文密码"))
  );
}
