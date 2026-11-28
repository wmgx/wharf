//! 计划和静态校验共用的引用检查。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use wharf_api_types::{
  ApiError,
  error::MissingRef,
  references::{
    SecretMode, account_ref, parse_placeholder, parse_service_ref,
    placeholders,
  },
  spec::{BuildSource, ServiceSpec, Source},
  view::TaskKind,
};

use crate::{snapshot::Snapshot, world::World};

pub(crate) fn service_texts(
  spec: &ServiceSpec,
) -> impl Iterator<Item = (String, &str)> {
  let compose = match &spec.source {
    Source::Compose { content, .. } => content.as_deref(),
    _ => None,
  };
  spec
    .env
    .iter()
    .map(|(k, v)| (format!("env.{k}"), v.as_str()))
    .chain(compose.map(|v| ("compose.content".into(), v)))
    .chain(
      spec
        .files
        .iter()
        .map(|f| (format!("file:{}", f.path), f.content.as_str())),
    )
}

pub(crate) fn service_secret_texts(
  spec: &ServiceSpec,
) -> impl Iterator<Item = (String, &str)> {
  service_texts(spec).chain(spec.monitor.iter().flat_map(|m| {
    m.headers
      .iter()
      .map(|(k, v)| (format!("monitor.headers.{k}"), v.as_str()))
  }))
}

pub(crate) fn task_texts(
  task: &TaskKind,
) -> impl Iterator<Item = (String, &str)> {
  let (command, env) = match task {
    TaskKind::Exec { command, .. } | TaskKind::Host { command } => {
      (Some(command.as_str()), None)
    }
    TaskKind::Container { command, env, .. } => {
      (command.as_deref(), Some(env))
    }
    TaskKind::Script { env, .. } => (None, Some(env)),
    TaskKind::Ping { .. } => (None, None),
  };
  command.map(|t| ("command".into(), t)).into_iter().chain(
    env
      .into_iter()
      .flatten()
      .map(|(k, v)| (format!("env.{k}"), v.as_str())),
  )
}

fn hit(kind: &str, target: &str, source: &str) -> MissingRef {
  let hint = match kind {
    "server" => format!("wharf server add {target}"),
    "gateway" => "wharf gateway list".into(),
    "account" => {
      format!("wharf sso account set {target} --user <用户名>")
    }
    "secret" => format!("wharf secret set {target} --generate"),
    "var" => format!("wharf var set {target} <值>"),
    _ => "wharf service list".into(),
  };
  MissingRef {
    kind: kind.into(),
    target: target.into(),
    source: source.into(),
    hint,
  }
}

pub(crate) fn error(
  mut missing: Vec<MissingRef>,
) -> Result<(), ApiError> {
  missing.sort();
  missing.dedup();
  if missing.is_empty() {
    return Ok(());
  }
  let total = missing.len();
  let mut message = format!("发现 {total} 处缺失的引用：");
  for item in missing.iter().take(20) {
    let kind = match item.kind.as_str() {
      "secret" => "密钥",
      "var" => "变量",
      "server" => "服务器",
      "gateway" => "网关",
      "account" => "应用账号",
      "port" => "端口",
      "volume" => "共享卷",
      "service_ref" => "服务引用",
      _ => "服务",
    };
    use std::fmt::Write;
    let _ = write!(
      message,
      "
- {kind} {}（{}）",
      item.target, item.source
    );
  }
  if total > 20 {
    use std::fmt::Write;
    let _ = write!(
      message,
      "
……另有 {} 处，完整列表见 details.missing",
      total - 20
    );
  }
  let mut counts = BTreeMap::new();
  for item in &missing {
    *counts.entry(&item.kind).or_insert(0) += 1;
  }
  let mut err = ApiError::invalid(message)
    .with_hint("补齐缺失对象或密钥后重新运行；批量导入密钥可用 wharf secret import");
  for suggest in missing
    .iter()
    .map(|item| &item.hint)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .take(5)
  {
    err = err.suggest(suggest);
  }
  Err(err.with_details(
    json!({ "total": total, "counts": counts, "missing": missing }),
  ))
}

pub(crate) fn check_text<'a>(
  source: &str,
  fields: impl IntoIterator<Item = (String, &'a str)>,
  secrets: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  error(
    fields
      .into_iter()
      .flat_map(|(field, text)| {
        placeholders(text).filter_map(move |p| {
          let p = parse_placeholder(p, false).ok().flatten()?;
          (!secrets.contains_key(p.name)).then(|| {
            hit("secret", p.name, &format!("{source} {field}"))
          })
        })
      })
      .collect(),
  )
}

pub(crate) fn collect_plan_missing(
  desired: &World,
  snap: &Snapshot,
) -> Vec<MissingRef> {
  let mut missing = Vec::new();
  let oidc = desired
    .routes
    .iter()
    .filter(|(_, r)| crate::oidc::route_is_oidc(&r.spec))
    .map(|(host, _)| crate::oidc::secret_name(host))
    .collect::<BTreeSet<_>>();
  let exists_secret = |name: &str| {
    snap.secrets.contains_key(name)
      || oidc.contains(name)
      || crate::secret_policy::is_system_secret(name)
  };
  let mut add =
    |kind: &str, target: &str, source: &str, exists: bool| {
      if !exists {
        missing.push(hit(kind, target, source));
      }
    };
  let port_exists = |service: &str, port: Option<&str>| {
    desired
      .services
      .get(service)
      .is_some_and(|s| s.spec.find_port(port).is_some())
  };
  let account_exists =
    |name: &str| snap.app_account_names.contains(name);
  for (name, row) in &desired.servers {
    if let Some(via) = &row.settings.via {
      add(
        "server",
        via,
        &format!("server/{name} via"),
        desired.servers.contains_key(via),
      );
    }
    for (field, text) in row
      .settings
      .registry_mirrors
      .values()
      .flatten()
      .map(|v| ("registry_mirrors", v))
      .chain(
        row
          .settings
          .github_mirror
          .iter()
          .map(|v| ("github_mirror", v)),
      )
    {
      for p in placeholders(text)
        .filter_map(|p| parse_placeholder(p, false).ok().flatten())
      {
        add(
          "secret",
          p.name,
          &format!("server/{name} {field}"),
          exists_secret(p.name),
        );
      }
    }
  }
  for (name, row) in &desired.services {
    let spec = &row.spec;
    let source = format!("service/{name}");
    add(
      "server",
      &spec.server,
      &source,
      desired.servers.contains_key(&spec.server),
    );
    if let Some(b) = &spec.backup {
      add(
        "server",
        &b.to,
        &format!("{source} backup.to"),
        desired.servers.contains_key(&b.to),
      );
    }
    for (field, text) in service_secret_texts(spec) {
      let at = format!("{source} {field}");
      for raw in placeholders(text) {
        if !field.starts_with("monitor.")
          && let Some(reference) =
            wharf_api_types::references::parse_public_ref(
              raw,
              spec.self_refs,
            )
        {
          if let wharf_api_types::references::PublicRef::Var(key) =
            reference
          {
            add("var", key, &at, desired.vars.contains_key(key));
          }
          continue;
        }
        if let Some(r) = parse_service_ref(raw)
          .filter(|_| !field.starts_with("monitor."))
        {
          if let Some(target) = desired.services.get(r.service) {
            let port = r.port.unwrap_or("<first>");
            let ok =
              r.port.map_or(!target.spec.ports.is_empty(), |p| {
                target.spec.ports.iter().any(|v| v.name == p)
              });
            add("port", &format!("{}.{port}", r.service), &at, ok);
          } else {
            add("service_ref", r.service, &at, false);
          }
        } else if let Ok(Some(p)) =
          parse_placeholder(raw, !field.starts_with("monitor."))
        {
          if let Some(account) = account_ref(p.name) {
            add("account", account, &at, account_exists(account));
          } else if p.mode != SecretMode::Plain
            || !field.starts_with("file:")
          {
            add("secret", p.name, &at, exists_secret(p.name));
          }
        }
      }
    }
    if let Source::Build(BuildSource { git: Some(git), .. }) =
      &spec.source
      && let Some(secret) = &git.token_secret
    {
      add(
        "secret",
        secret,
        &format!("{source} source.build.git.token_secret"),
        exists_secret(secret),
      );
    }
    for vol in &spec.volumes {
      if let Some(raw) = &vol.from_service
        && let Ok((owner, vol)) =
          crate::shared_volumes::parse_ref(raw)
      {
        let at = format!("{source} volume:{}", vol);
        if let Some(row) = desired.services.get(owner) {
          add(
            "volume",
            raw,
            &at,
            wharf_api_types::compose::owned_volumes(owner, &row.spec)
              .contains(vol),
          );
        } else {
          add("service", owner, &at, false);
        }
      }
    }
  }
  for (name, row) in &desired.edge_apps {
    let source = format!("edge/{name}");
    if let Some(server) = &row.spec.builder {
      add(
        "server",
        server,
        &format!("{source} builder"),
        desired.servers.contains_key(server),
      );
    }
    if let Some(secret) = row
      .spec
      .source
      .as_ref()
      .and_then(|s| s.git.as_ref())
      .and_then(|g| g.token_secret.as_deref())
    {
      add(
        "secret",
        secret,
        &format!("{source} source.git.token_secret"),
        exists_secret(secret),
      );
    }
  }
  for (name, row) in &desired.gateways {
    add(
      "server",
      &row.spec.server,
      &format!("gateway/{name}"),
      desired.servers.contains_key(&row.spec.server),
    );
    for rule in &row.spec.layer4 {
      if let Some(service) = &rule.service {
        let source = format!("gateway/{name} layer4:{}", rule.listen);
        if desired.services.contains_key(service) {
          add(
            "port",
            &format!(
              "{service}.{}",
              rule.port.as_deref().unwrap_or("<default>")
            ),
            &source,
            port_exists(service, rule.port.as_deref()),
          );
        } else {
          add("service", service, &source, false);
        }
      }
    }
  }
  for (name, row) in &desired.routes {
    let spec = &row.spec;
    let source = format!("route/{name}");
    let gateway = spec
      .gateway
      .as_deref()
      .or_else(|| desired.default_gateway());
    if let Some(gateway) = gateway {
      add(
        "gateway",
        gateway,
        &source,
        desired.gateways.contains_key(gateway),
      );
    } else {
      add("gateway", "<default>", &source, false);
    }
    if let Some(backup) = &spec.backup_gateway {
      add(
        "gateway",
        backup,
        &format!("{source} backup_gateway"),
        desired.gateways.contains_key(backup),
      );
    }
    let base = (!spec.service.is_empty()
      && spec.redirect.is_none()
      && spec.upstream.is_none())
    .then_some((
      spec.service.as_str(),
      spec.port.as_deref(),
      source.clone(),
    ));
    for (svc, port, at) in
      base.into_iter().chain(spec.paths.iter().filter_map(|p| {
        Some((
          p.service.as_deref()?,
          p.port.as_deref(),
          format!("{source} paths[{}]", p.path),
        ))
      }))
    {
      if desired.services.contains_key(svc) {
        add(
          "port",
          &format!("{svc}.{}", port.unwrap_or("<default>")),
          &at,
          port_exists(svc, port),
        );
      } else if !desired.edge_apps.contains_key(svc) {
        add("service", svc, &at, false);
      }
    }
    if let Some(login) =
      spec.sso.as_ref().and_then(|s| s.login.as_ref())
    {
      for secret in crate::sso_login::secret_refs(login) {
        add(
          "secret",
          &secret,
          &format!("{source} sso.login"),
          exists_secret(&secret),
        );
      }
    }
  }
  missing.sort();
  missing.dedup();
  missing
}

pub(crate) fn check_plan(
  desired: &World,
  snap: &Snapshot,
) -> Result<(), ApiError> {
  if desired == &snap.world {
    return Ok(());
  }
  let before = collect_plan_missing(&snap.world, snap)
    .into_iter()
    .collect::<BTreeSet<_>>();
  error(
    collect_plan_missing(desired, snap)
      .into_iter()
      .filter(|hit| !before.contains(hit))
      .collect(),
  )
}

pub(crate) fn scope_error(
  err: ApiError,
  allowed: Option<&BTreeSet<String>>,
  routes: &BTreeSet<String>,
) -> ApiError {
  let Some(allowed) = allowed else { return err };
  let Some(missing) =
    err.details.as_ref().and_then(|d| d.get("missing"))
  else {
    return err;
  };
  let Ok(mut missing) =
    serde_json::from_value::<Vec<MissingRef>>(missing.clone())
  else {
    return err;
  };
  let total = missing.len();
  missing.retain(|hit| {
    let owner =
      hit.source.split_whitespace().next().unwrap_or_default();
    owner
      .strip_prefix("service/")
      .is_some_and(|name| allowed.contains(name))
      || owner
        .strip_prefix("route/")
        .is_some_and(|name| routes.contains(name))
  });
  if missing.len() == total {
    return err;
  }
  error(missing).err().unwrap_or_else(|| {
    ApiError::invalid("改动导致其他资源引用缺失")
      .with_hint("使用不限服务的令牌查看完整引用")
  })
}

#[test]
fn plan_aggregates_missing_across_resources() {
  let snap = Snapshot::default();
  let fleet = serde_json::from_value(json!({
    "services": {"app": {
      "server": "s1", "source": {"image": "app:1"},
      "env": {"A": "[[K1]]", "B": "[[@redis]]"},
      "files": [{"path": "/etc/app.conf", "content": "[[routes]] [[url:K2]]"}]
    }},
    "routes": [{"hostname": "app.example.test", "service": "svc-x", "gateway": "gw-x"}]
  })).unwrap();
  let mut world = World::default();
  world.servers.insert(
    "s1".into(),
    crate::world::ServerRow {
      settings: Default::default(),
      version: 0,
    },
  );
  world.merge_with(&fleet).unwrap();
  let error = check_plan(&world, &snap).unwrap_err();
  assert_eq!(error.code, wharf_api_types::ErrorCode::InvalidInput);
  let details = error.details.unwrap();
  assert_eq!(details["total"], 5);
  assert_eq!(
    details["missing"]
      .as_array()
      .unwrap()
      .iter()
      .map(|r| r["target"].as_str().unwrap())
      .collect::<Vec<_>>(),
    ["gw-x", "K1", "K2", "svc-x", "redis"]
  );
}

#[test]
fn plan_precheck_accepts_compose_owned_volume() {
  let mut snap = Snapshot::default();
  let fleet = serde_json::from_value(json!({
    "services":{
      "photos":{"server":"s1","source":{"compose":{"content":"services: { photos: { image: app:1, volumes: ['/srv/photos/originals:/data'] } }"}}},
      "reader":{"server":"s1","source":{"image":"app:1"},"volumes":[{"name":"orig","target":"/orig","from_service":"photos:originals"}]}
    }
  })).unwrap();
  snap.world.servers.insert(
    "s1".into(),
    crate::world::ServerRow {
      settings: Default::default(),
      version: 0,
    },
  );
  snap.world.merge_with(&fleet).unwrap();
  check_plan(&snap.world, &snap).unwrap();
}
