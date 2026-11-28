//! 模板可引用的密钥与应用账号。

use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Layer, Plan},
  spec::{
    BuildSource, LoginSpec, RouteSpec, ServerSettings, ServiceSpec,
    Source,
  },
  view::TaskKind,
};

use crate::{
  render::{self, Placeholder, SecretMode},
  secret_restrictions::Restrictions,
  world::World,
};

const WHARF_PREFIX: &str = "WHARF_";
const ACME_PREFIX: &str = "ACME_DNS_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretMeta {
  pub label: &'static str,
  pub managed: bool,
  pub redact: bool,
}

pub fn describe(name: &str) -> Option<SecretMeta> {
  let (label, managed, redact) = match name {
    crate::link::CA_CERT_SECRET => ("机器互联", true, false),
    n if n.starts_with(crate::link::CERT_PREFIX) => {
      ("机器互联", true, false)
    }
    n if n.starts_with(crate::link::SECRET_PREFIX) => {
      ("机器互联", true, true)
    }
    crate::core_backup::OWNER_SECRET
    | "WHARF_CORE_BACKUP_HTTP_HASH" => ("控制面备份", true, false),
    n if n.starts_with("WHARF_CORE_BACKUP_") => {
      ("控制面备份", true, true)
    }
    "WHARF_BACKUP_HTTP_HASH" => ("备份", true, false),
    n if n.starts_with("WHARF_BACKUP_HTTP_HASH_") => {
      ("备份", true, false)
    }
    n if n.starts_with(crate::backup::SECRET_PREFIX) => {
      ("备份", true, true)
    }
    crate::render::TUNNEL_TOKEN_SECRET => ("隧道", true, true),
    n if n.starts_with(crate::acme_dns::SECRET_PREFIX)
      || n.starts_with(ACME_PREFIX) =>
    {
      ("DNS 证书验证", true, true)
    }
    n if n.starts_with(WHARF_PREFIX) => ("Wharf 内部", true, true),
    n if n.starts_with(crate::oidc::SECRET_PREFIX) => {
      ("OIDC", true, true)
    }
    n if n.starts_with(crate::notify_keys::SECRET_PREFIX) => {
      ("通知", true, true)
    }
    crate::egress::TOKEN_SECRET => ("外网代理", true, true),
    crate::tailscale::OAUTH_SECRET => ("Tailscale 组网", false, true),
    crate::notify::FEISHU_WEBHOOK | crate::notify::FEISHU_SECRET => {
      ("通知", false, true)
    }
    n if render::is_auth_secret(n) => ("登录保护", false, false),
    _ => return None,
  };
  Some(SecretMeta {
    label,
    managed,
    redact,
  })
}

pub fn system_label(name: &str) -> Option<&'static str> {
  // 通知 URL 由控制面管理，但业务服务仍可引用。
  if name.starts_with(crate::notify_keys::SECRET_PREFIX) {
    return None;
  }
  describe(name).map(|meta| meta.label)
}

pub fn is_system_secret(name: &str) -> bool {
  system_label(name).is_some()
}

pub fn is_managed_secret(name: &str) -> bool {
  describe(name).is_some_and(|meta| meta.managed)
}

pub fn redact_values(all: &BTreeMap<String, String>) -> Vec<String> {
  let mut values = BTreeSet::new();
  for (name, value) in all {
    if value.len() < 6
      || describe(name).is_some_and(|meta| !meta.redact)
    {
      continue;
    }
    values.insert(value.clone());
    values.extend(pem_body(value).map(str::to_string));
  }
  let mut values: Vec<_> = values.into_iter().collect();
  values.sort_by_key(|value| std::cmp::Reverse(value.len()));
  values
}

pub fn pem_body(value: &str) -> impl Iterator<Item = &str> {
  let pem = value.trim_start().lines().next().is_some_and(|line| {
    line.starts_with("-----BEGIN ")
      && line.trim_end().ends_with("PRIVATE KEY-----")
  });
  value.lines().map(str::trim).filter(move |line| {
    pem && line.len() >= 6 && !line.starts_with("-----")
  })
}

pub fn refuse_managed(name: &str) -> Result<(), ApiError> {
  if is_managed_secret(name) {
    return Err(ApiError::new(ErrorCode::Forbidden, format!("{name} 是 Wharf 内部保留密钥，不能直接修改或删除"))
      .with_hint("业务密钥请换一个不以 WHARF_、OIDC_、ACME_DNS_、NOTIFY_URL_ 开头的名字；隧道密钥用 wharf gateway rotate-link"));
  }
  Ok(())
}

pub fn reject_system_secret(
  name: &str,
  context: &str,
) -> Result<(), ApiError> {
  if let Some(label) = system_label(name) {
    return Err(ApiError::invalid(format!("{context} 不能引用系统密钥 {name}（属于{label}）"))
      .with_hint("WHARF_*、OIDC_*、ACME_DNS_* 等系统密钥只由 Wharf 内部使用；业务配置请单独创建普通密钥"));
  }
  Ok(())
}

pub fn non_system_secrets(
  all: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
  all
    .iter()
    .filter(|(name, _)| !is_system_secret(name))
    .map(|(name, value)| (name.clone(), value.clone()))
    .collect()
}

fn placeholders_checked(
  text: &str,
  allow_account: bool,
  allow_file: bool,
) -> impl Iterator<Item = Result<Placeholder<'_>, ApiError>> {
  render::placeholders(text).filter_map(move |inner| {
    render::parse_placeholder(inner, allow_account)
      .and_then(|p| {
        if !allow_file && let Some(p) = &p {
          render::reject_file(p)?;
        }
        Ok(p)
      })
      .transpose()
  })
}

fn service_templates(
  spec: &ServiceSpec,
) -> impl Iterator<Item = &str> {
  let compose = match &spec.source {
    Source::Compose { content, .. } => content.as_deref(),
    _ => None,
  };
  spec
    .env
    .values()
    .map(String::as_str)
    .chain(compose)
    .chain(spec.files.iter().map(|f| f.content.as_str()))
}

pub fn service_account_refs(
  spec: &ServiceSpec,
) -> impl Iterator<Item = (&str, &str)> {
  service_templates(spec)
    .flat_map(|text| {
      placeholders_checked(text, true, true).filter_map(Result::ok)
    })
    .map(|p| p.name)
    .filter_map(|name| Some((name, render::account_ref(name)?)))
}

fn git_token(spec: &ServiceSpec) -> Option<&str> {
  match &spec.source {
    Source::Build(BuildSource { git: Some(git), .. }) => {
      git.token_secret.as_deref()
    }
    _ => None,
  }
}

fn template_refs(spec: &ServiceSpec) -> impl Iterator<Item = &str> {
  service_templates(spec)
    .flat_map(|text| {
      placeholders_checked(text, true, true).filter_map(Result::ok)
    })
    .chain(
      spec
        .monitor
        .iter()
        .flat_map(|m| m.headers.values())
        .flat_map(|text| {
          placeholders_checked(text, false, false)
            .filter_map(Result::ok)
        }),
    )
    .map(|p| p.name)
    .filter(|name| render::account_ref(name).is_none())
}

pub fn service_uses_secret(spec: &ServiceSpec, name: &str) -> bool {
  template_refs(spec)
    .chain(git_token(spec))
    .any(|secret| secret == name)
}

pub fn service_renders_secret(
  spec: &ServiceSpec,
  name: &str,
) -> bool {
  template_refs(spec).any(|secret| secret == name)
}

pub fn other_secret_refs<'a>(
  world: &World,
  tasks: impl IntoIterator<Item = (&'a str, &'a TaskKind)>,
  name: &str,
) -> Vec<String> {
  let uses = |text: &str| {
    placeholders_checked(text, false, false)
      .filter_map(Result::ok)
      .any(|p| p.name == name)
  };
  let mut refs = Vec::new();
  for (server, row) in &world.servers {
    if mirror_templates(&row.settings).any(uses) {
      refs.push(format!("server:{server}"));
    }
  }
  for (host, row) in &world.routes {
    if route_login(&row.spec).is_some_and(|login| {
      crate::sso_login::secret_refs(login).contains(name)
    }) {
      refs.push(format!("sso:{host}"));
    }
  }
  for (app, row) in &world.edge_apps {
    if row
      .spec
      .source
      .as_ref()
      .and_then(|s| s.git.as_ref())
      .and_then(|git| git.token_secret.as_deref())
      == Some(name)
    {
      refs.push(format!("edge:{app}"));
    }
  }
  for (task, how) in tasks {
    let used = match how {
      TaskKind::Exec { command, .. } | TaskKind::Host { command } => {
        uses(command)
      }
      TaskKind::Container { command, env, .. } => {
        command.iter().chain(env.values()).any(|text| uses(text))
      }
      TaskKind::Script { env, .. } => {
        env.values().any(|text| uses(text))
      }
      TaskKind::Ping { .. } => false,
    };
    if used {
      refs.push(format!("task:{task}"));
    }
  }
  refs.sort_unstable();
  refs
}

fn mirror_templates(
  settings: &ServerSettings,
) -> impl Iterator<Item = &str> {
  settings
    .registry_mirrors
    .values()
    .flatten()
    .chain(&settings.github_mirror)
    .map(String::as_str)
}

pub fn validate_restrictions(
  world: &World,
  restrictions: &Restrictions,
) -> Result<(), ApiError> {
  for (name, allowed) in restrictions {
    if let Some((service, _)) =
      world.services.iter().find(|(service, row)| {
        !allowed.contains(*service)
          && service_uses_secret(&row.spec, name)
      })
    {
      return Err(restricted_error(
        name,
        allowed,
        &format!("服务 {service}"),
      ));
    }
    for (host, route) in &world.routes {
      if route_login(&route.spec).is_some_and(|login| {
        crate::sso_login::secret_refs(login).contains(name)
      }) {
        return Err(restricted_error(
          name,
          allowed,
          &format!("域名 {host} 的代登录"),
        ));
      }
    }
    for (app, row) in &world.edge_apps {
      if edge_git_token(&row.spec) == Some(name) {
        return Err(restricted_error(
          name,
          allowed,
          &format!("边缘应用 {app}"),
        ));
      }
    }
    for (server, row) in &world.servers {
      if mirror_templates(&row.settings)
        .flat_map(|text| placeholders_checked(text, false, true))
        .any(|p| matches!(p, Ok(p) if p.name == name))
      {
        return Err(restricted_error(
          name,
          allowed,
          &format!("服务器 {server} 的镜像源"),
        ));
      }
    }
  }
  Ok(())
}

fn restricted_error(
  name: &str,
  allowed: &BTreeSet<String>,
  context: &str,
) -> ApiError {
  let services = allowed
    .iter()
    .map(String::as_str)
    .collect::<Vec<_>>()
    .join("、");
  ApiError::invalid(format!(
    "{context}不能引用密钥 {name}，仅允许服务 {services} 引用"
  ))
}

fn edge_git_token(
  spec: &wharf_api_types::spec::EdgeAppSpec,
) -> Option<&str> {
  spec.source.as_ref()?.git.as_ref()?.token_secret.as_deref()
}

fn direct_refs<'a>(
  world: &'a World,
  service: &str,
) -> impl Iterator<Item = &'a str> {
  world
    .services
    .get(service)
    .into_iter()
    .flat_map(|r| template_refs(&r.spec).chain(git_token(&r.spec)))
}

fn owned_refs(world: &World, service: &str) -> BTreeSet<String> {
  direct_refs(world, service)
    .map(str::to_string)
    .chain(
      world
        .routes
        .values()
        .filter(|r| r.spec.service == service)
        .filter_map(|r| route_login(&r.spec))
        .flat_map(crate::sso_login::secret_refs),
    )
    .filter(|n| !is_system_secret(n))
    .collect()
}

fn route_login(route: &RouteSpec) -> Option<&LoginSpec> {
  route.sso.as_ref()?.login.as_ref()
}

fn oidc_names(world: &World, service: &str) -> BTreeSet<String> {
  world
    .routes
    .iter()
    .filter(|(_, row)| {
      row.spec.service == service
        && crate::oidc::route_is_oidc(&row.spec)
    })
    .map(|(host, _)| crate::oidc::secret_name(host))
    .collect()
}

pub fn service_secrets(
  world: &World,
  service: &str,
  all: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
  let mut names = owned_refs(world, service);
  names.extend(oidc_names(world, service));
  names
    .into_iter()
    .filter_map(|name| {
      let value = all.get(&name)?.clone();
      Some((name, value))
    })
    .collect()
}

pub fn login_secrets(
  world: &World,
  route: &RouteSpec,
  all: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
  let mut secrets = service_secrets(world, &route.service, all);
  secrets.retain(|name, _| {
    !is_system_secret(name) && login_owns(world, &route.service, name)
  });
  secrets
}

fn validate_login(
  world: &World,
  host: &str,
  route: &RouteSpec,
  login: &LoginSpec,
) -> Result<(), ApiError> {
  let context = format!("域名 {host} 的代登录");
  let service = &route.service;
  if let Some(script) = &login.script {
    for value in script.env.values() {
      crate::sso_login::env_refs(value)?;
    }
  }
  for name in crate::sso_login::secret_refs(login) {
    reject_system_secret(&name, &context)?;
    if !login_owns(world, service, &name) {
      return Err(
        ApiError::invalid(format!(
          "{context}引用了服务 {service} 未声明的密钥：{name}"
        ))
        .with_hint(format!(
          "先在服务 {service} 的配置中引用这个密钥，再配置代登录"
        )),
      );
    }
  }
  Ok(())
}

pub fn validate_world(world: &World) -> Result<(), ApiError> {
  for (name, row) in &world.services {
    let context = format!("服务 {name}");
    let oidc = oidc_names(world, name);
    if let Some(m) = &row.spec.monitor {
      for text in m.headers.values() {
        for p in placeholders_checked(text, false, false) {
          reject_system_secret(p?.name, &context)?;
        }
      }
    }
    for p in service_templates(&row.spec)
      .flat_map(|text| placeholders_checked(text, true, true))
    {
      let p = p?;
      if p.mode != SecretMode::Plain || !oidc.contains(p.name) {
        reject_system_secret(p.name, &context)?;
      }
    }
    if let Some(secret) = git_token(&row.spec) {
      reject_system_secret(secret, &context)?;
    }
  }
  for (name, app) in &world.edge_apps {
    if let Some(secret) = edge_git_token(&app.spec) {
      reject_system_secret(secret, &format!("边缘应用 {name}"))?;
    }
  }
  for (name, server) in &world.servers {
    for text in mirror_templates(&server.settings) {
      reject_templates(text, &format!("服务器 {name} 的镜像源"))?;
    }
  }
  for (name, row) in &world.gateways {
    if let Some(page) = &row.spec.error_page {
      validate_gateway_text(page, &format!("网关 {name} 的错误页"))?;
    }
    for upstream in
      row.spec.layer4.iter().filter_map(|f| f.upstream.as_deref())
    {
      validate_gateway_text(
        upstream,
        &format!("入口 {name} 的四层转发上游"),
      )?;
    }
  }
  for (host, row) in &world.routes {
    let spec = &row.spec;
    if let Some(login) = route_login(spec) {
      validate_login(world, host, spec, login)?;
    }
    if let Some(caddy) = &spec.caddy {
      validate_gateway_text(
        caddy,
        &format!("路由 {host}：自定义 Caddy 配置"),
      )?;
    }
    for upstream in spec
      .upstream
      .iter()
      .chain(spec.paths.iter().filter_map(|p| p.upstream.as_ref()))
    {
      validate_gateway_text(
        upstream,
        &format!("路由 {host} 的上游"),
      )?;
    }
  }
  Ok(())
}

fn validate_gateway_text(
  text: &str,
  context: &str,
) -> Result<(), ApiError> {
  if [
    render::ACME_DNS_KEY,
    render::ACME_DNS_URL,
    "[[WHARF_",
    "[[ACME_DNS_",
  ]
  .into_iter()
  .any(|pattern| text.contains(pattern))
  {
    return Err(
      ApiError::invalid(format!(
        "{context}里不能出现 Wharf 内部占位符"
      ))
      .with_hint("去掉 [[WHARF_*]] 和 [[ACME_DNS_*]] 后重试"),
    );
  }
  if let Some(p) = placeholders_checked(text, true, false).next() {
    let p = p?;
    reject_system_secret(p.name, context)?;
    return Err(
      ApiError::invalid(format!("{context}不能引用密钥 {}", p.name))
        .with_hint("在目标服务的配置中引用密钥"),
    );
  }
  Ok(())
}

fn reject_templates(
  text: &str,
  context: &str,
) -> Result<(), ApiError> {
  placeholders_checked(text, false, false)
    .try_for_each(|p| reject_system_secret(p?.name, context))
}

pub fn validate_task(
  name: &str,
  how: &TaskKind,
) -> Result<(), ApiError> {
  let context = format!("任务 {name}");
  task_templates(how)
    .into_iter()
    .try_for_each(|text| reject_templates(text, &context))
}

pub fn validate_task_restrictions(
  task: &str,
  how: &TaskKind,
  restrictions: &Restrictions,
) -> Result<(), ApiError> {
  validate_task_values(task, task_templates(how), restrictions)
}

pub(crate) fn validate_task_env<'a>(
  task: &str,
  values: impl Iterator<Item = &'a str> + Clone,
  restrictions: &Restrictions,
) -> Result<(), ApiError> {
  let context = format!("任务 {task}");
  for value in values.clone() {
    reject_templates(value, &context)?;
  }
  validate_task_values(task, values, restrictions)
}

fn validate_task_values<'a>(
  task: &str,
  values: impl IntoIterator<Item = &'a str>,
  restrictions: &Restrictions,
) -> Result<(), ApiError> {
  if restrictions.is_empty() {
    return Ok(());
  }
  for p in values
    .into_iter()
    .flat_map(|text| placeholders_checked(text, false, true))
    .filter_map(Result::ok)
  {
    let name = p.name;
    if let Some(allowed) = restrictions.get(name) {
      return Err(restricted_error(
        name,
        allowed,
        &format!("任务 {task}"),
      ));
    }
  }
  Ok(())
}

fn task_templates(how: &TaskKind) -> Vec<&str> {
  match how {
    TaskKind::Exec { command, .. } | TaskKind::Host { command } => {
      vec![command]
    }
    TaskKind::Container { command, env, .. } => command
      .iter()
      .chain(env.values())
      .map(String::as_str)
      .collect(),
    TaskKind::Script { env, .. } => {
      env.values().map(String::as_str).collect()
    }
    TaskKind::Ping { .. } => Vec::new(),
  }
}

pub fn validate_accounts(
  world: &World,
  links: &crate::app_accounts::AccountLinks,
) -> Result<(), ApiError> {
  for (service, row) in &world.services {
    for (_, account) in service_account_refs(&row.spec) {
      if !crate::app_accounts::linked_account(
        world, service, account, links,
      ) {
        return Err(ApiError::invalid(format!("服务 {service} 不能引用应用账号 {account}"))
          .with_hint(format!("只能引用已关联到该服务域名的应用账号；先用 wharf sso account link {account} <域名> 关联")));
      }
    }
  }
  Ok(())
}

fn other_users<'a>(
  world: &'a World,
  service: &'a str,
  name: &'a str,
) -> impl Iterator<Item = &'a String> {
  world.services.keys().filter(move |n| {
    n.as_str() != service && owned_refs(world, n).contains(name)
  })
}

fn login_owns(world: &World, service: &str, name: &str) -> bool {
  direct_refs(world, service).any(|r| r == name)
    || other_users(world, service, name).next().is_none()
}

fn borrowing(
  world: &World,
  service: &str,
  name: &str,
) -> Option<String> {
  if owned_refs(world, service).contains(name) {
    return None;
  }
  let others = other_users(world, service, name)
    .map(String::as_str)
    .collect::<Vec<_>>();
  (!others.is_empty()).then(|| others.join("、"))
}

fn borrowing_error(
  service: &str,
  name: &str,
  others: &str,
) -> ApiError {
  ApiError::new(ErrorCode::Forbidden, format!("服务 {service} 要引用的密钥 {name} 已经被服务 {others} 使用；跨服务共用密钥需要 admin 权限"))
    .with_hint("请用户在页面上执行，或给这个服务单独建一个密钥")
}

pub fn require_plan_git_secrets(
  current: &World,
  desired: &World,
  admin: bool,
) -> Result<(), ApiError> {
  if !admin {
    for (service, row) in &desired.services {
      if let Some(name) = git_token(&row.spec)
        && let Some(others) = borrowing(current, service, name)
      {
        return Err(borrowing_error(service, name, &others));
      }
    }
  }
  Ok(())
}

/// 返回新增引用已有他服密钥的 (服务, 密钥)。
pub fn borrows_other_service_secret(
  plan: &Plan,
  current_world: &World,
) -> Vec<(String, String)> {
  let mut borrowed = BTreeSet::new();
  for item in &plan.items {
    if item.layer != Layer::Config {
      continue;
    }
    let Some(after) = &item.after else {
      continue;
    };
    if let Some(service) = item.address.strip_prefix("service/")
      && let Ok(spec) =
        serde_json::from_value::<ServiceSpec>(after.clone())
    {
      for name in template_refs(&spec).chain(git_token(&spec)) {
        if !is_system_secret(name)
          && borrowing(current_world, service, name).is_some()
        {
          borrowed.insert((service.to_string(), name.to_string()));
        }
      }
    }
    if item.address.starts_with("route/")
      && let Ok(route) =
        serde_json::from_value::<RouteSpec>(after.clone())
      && let Some(login) = route_login(&route)
    {
      for name in crate::sso_login::secret_refs(login) {
        if !is_system_secret(&name)
          && borrowing(current_world, &route.service, &name).is_some()
        {
          borrowed.insert((route.service.clone(), name));
        }
      }
    }
  }
  borrowed.into_iter().collect()
}

pub fn require_apply(
  plan: &Plan,
  world: &World,
  admin: bool,
) -> Result<(), ApiError> {
  if !admin
    && let Some((service, name)) =
      borrows_other_service_secret(plan, world).into_iter().next()
    && let Some(others) = borrowing(world, &service, &name)
  {
    return Err(borrowing_error(&service, &name, &others));
  }
  Ok(())
}
