//! 引用、拓扑和搜索的只读查询。

use std::{collections::BTreeSet, sync::Arc};

use axum::{
  Json,
  extract::{Query, State},
};
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  references::{
    SecretMode, account_ref, parse_placeholder, parse_service_ref,
    placeholders,
  },
  spec::{BuildSource, RouteSpec, Source},
  view::{
    Perm, RefHit, RefReport, SearchHit, SearchResponse, TaskKind,
    TaskSpec, TreeView,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  missing_refs::{service_secret_texts, service_texts, task_texts},
  snapshot::{self, Snapshot},
  state::AppState,
  token_scope,
};

mod tree;

use tree::build_tree;

type Tasks = Vec<(String, TaskSpec, i64)>;

#[derive(Deserialize)]
pub struct RefQuery {
  target: String,
}

#[derive(Default, Deserialize)]
pub struct TreeQuery {
  target: Option<String>,
  server: Option<String>,
  service: Option<String>,
  route: Option<String>,
  gateway: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
  q: String,
  kind: Option<String>,
  limit: Option<usize>,
}

pub async fn refs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<RefQuery>,
) -> ApiResult<RefReport> {
  auth.require(Perm::Read)?;
  let (kind, name) = parse_target(&q.target)?;
  let snap = snapshot::load_inner(&s.db).await?;
  let tasks = s.db.call(|c| crate::tasks::load_rows(c)).await?;
  let mut report =
    collect_refs(&snap, &tasks, auth.services.as_ref(), kind, name);
  if auth.services.is_none()
    && matches!(kind, "server" | "service" | "route" | "gateway")
  {
    let name = report.name.clone();
    let hits = s.db.call(move |c| alert_refs(c, kind, &name)).await?;
    report.refs.extend(hits);
  }
  if auth.services.is_none() && kind == "route" {
    let host = report.name.clone();
    let gate_keys: Vec<String> = s.db.call(move |c| {
      let mut stmt = c.prepare(
        "SELECT name FROM gate_keys WHERE EXISTS (SELECT 1 FROM json_each(gate_keys.hosts) WHERE value = ?1) ORDER BY name"
      ).map_err(crate::db::sql_err)?;
      stmt.query_map([host], |r| r.get(0)).and_then(Iterator::collect).map_err(crate::db::sql_err)
    }).await?;
    report.refs.extend(gate_keys.into_iter().map(|name| RefHit {
      kind: "gate_key".into(),
      name,
      field: "hosts".into(),
      relation: "authorizes".into(),
      detail: None,
    }));
    report.refs.extend(
      snap
        .world
        .bookmarks
        .iter()
        .filter(|(_, b)| {
          reqwest::Url::parse(&b.spec.url).is_ok_and(|url| {
            url.host_str() == Some(report.name.as_str())
          })
        })
        .map(|(name, _)| RefHit {
          kind: "bookmark".into(),
          name: name.clone(),
          field: "url".into(),
          relation: "links_to".into(),
          detail: None,
        }),
    );
  }
  report.count = report.refs.len();
  report.refs.sort_by(|a, b| {
    (&a.kind, &a.name, &a.field).cmp(&(&b.kind, &b.name, &b.field))
  });
  Ok(Json(report))
}

fn alert_refs(
  c: &rusqlite::Connection,
  kind: &str,
  name: &str,
) -> Result<Vec<RefHit>, ApiError> {
  use crate::db::sql_err;
  let mut hits = Vec::new();
  let mut add = |name: String, field: &str| {
    hits.push(RefHit {
      kind: "alert".into(),
      name,
      field: field.into(),
      relation: "monitors".into(),
      detail: None,
    })
  };
  let mut stmt = c
    .prepare("SELECT name, service FROM alert_custom_rules")
    .map_err(sql_err)?;
  let custom = stmt
    .query_map([], |r| {
      Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })
    .and_then(Iterator::collect::<Result<Vec<_>, _>>)
    .map_err(sql_err)?;
  if kind == "service" {
    for (rule, _) in
      custom.iter().filter(|(_, service)| service == name)
    {
      add(rule.clone(), "custom.service");
    }
    let mut stmt = c
      .prepare(
        "SELECT rule FROM alert_service_overrides WHERE service = ?",
      )
      .map_err(sql_err)?;
    for row in
      stmt.query_map([name], |r| r.get(0)).map_err(sql_err)?
    {
      add(row.map_err(sql_err)?, "override.service");
    }
  }
  let mut stmt = c.prepare("SELECT id, source_rule, source_subject, target_rule, target_subject FROM alert_suppressions").map_err(sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, i64>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, Option<String>>(2)?,
        r.get::<_, String>(3)?,
        r.get::<_, Option<String>>(4)?,
      ))
    })
    .map_err(sql_err)?;
  for row in rows {
    let (id, source, a, target, b) = row.map_err(sql_err)?;
    for (rule, subject, field) in
      [(source, a, "source_subject"), (target, b, "target_subject")]
    {
      if let Some(subject) = subject
        && crate::rules::subject_resources(
          &rule,
          &subject,
          custom.iter().any(|(r, _)| r == &rule),
        )
        .into_iter()
        .any(|(resource, subject)| {
          resource == kind && subject == name
        })
      {
        add(format!("suppression/{id}"), field);
      }
    }
  }
  Ok(hits)
}

pub async fn tree(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<TreeQuery>,
) -> ApiResult<TreeView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load_inner(&s.db).await?;
  let live = crate::views::cached_live(&s, &snap.world).await;
  Ok(Json(build_tree(&snap, auth.services.as_ref(), &q, &live)?))
}

pub async fn search(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<SearchQuery>,
) -> ApiResult<SearchResponse> {
  auth.require(Perm::Read)?;
  if !(1..=128).contains(&q.q.trim().chars().count()) {
    return Err(
      ApiError::invalid("搜索关键词须为 1 到 128 个字符").into(),
    );
  }
  let snap = snapshot::load_inner(&s.db).await?;
  let tasks = s.db.call(|c| crate::tasks::load_rows(c)).await?;
  Ok(Json(search_snapshot(
    &snap,
    &tasks,
    auth.services.as_ref(),
    &q,
  )))
}

fn parse_target(
  target: &str,
) -> Result<(&'static str, &str), ApiError> {
  let (kind, name) = target
    .strip_prefix("path:")
    .map(|p| ("path", p))
    .or_else(|| target.split_once('/'))
    .filter(|(_, name)| !name.is_empty())
    .ok_or_else(|| {
      ApiError::invalid("引用目标应写成 类型/名称，例如 service/db")
    })?;
  let kind = match kind {
    "srv" | "server" => "server",
    "svc" | "service" => "service",
    "gw" | "gateway" => "gateway",
    "sec" | "secret" => "secret",
    "acc" | "account" => "account",
    "app_account" | "sso_account" => "app_account",
    "rt" | "route" => "route",
    "path" => "path",
    "var" => {
      return Err(
        ApiError::invalid("公共变量（var）尚未实现")
          .with_hint("使用 wharf refs secret/<名称> 查看密钥引用"),
      );
    }
    _ => return Err(ApiError::invalid("不支持的引用目标类型")),
  };
  Ok((kind, name))
}

fn visible(scope: Option<&BTreeSet<String>>, name: &str) -> bool {
  scope.is_none_or(|allowed| allowed.contains(name))
}

fn route_visible(
  scope: Option<&BTreeSet<String>>,
  route: &RouteSpec,
) -> bool {
  scope.is_none_or(|allowed| {
    token_scope::route_spec_in_scope(allowed, route)
  })
}

fn task_visible(
  scope: Option<&BTreeSet<String>>,
  how: &TaskKind,
) -> bool {
  scope.is_none_or(|allowed| matches!(how, TaskKind::Exec { service, .. } if allowed.contains(service)))
}

fn secret_matches(text: &str, name: &str) -> bool {
  placeholders(text).any(|p| {
    parse_placeholder(p, false)
      .ok()
      .flatten()
      .is_some_and(|p| p.name == name && p.mode != SecretMode::File)
  })
}

fn collect_refs(
  snap: &Snapshot,
  tasks: &Tasks,
  scope: Option<&BTreeSet<String>>,
  kind: &str,
  name: &str,
) -> RefReport {
  let world = &snap.world;
  let route_name = (kind == "route")
    .then(|| crate::world::normalize_hostname(name).ok())
    .flatten();
  let name = route_name.as_deref().unwrap_or(name);
  let mut hits = Vec::new();
  let mut add =
    |kind: &str, name: &str, field: &str, relation: &str| {
      hits.push(RefHit {
        kind: kind.into(),
        name: name.into(),
        field: field.into(),
        relation: relation.into(),
        detail: None,
      });
    };
  let hidden_secret = scope.is_some()
    && kind == "secret"
    && (crate::secret_policy::is_system_secret(name)
      || crate::secret_policy::is_managed_secret(name));
  for (service, row) in &world.services {
    if hidden_secret {
      break;
    }
    if !visible(scope, service) {
      continue;
    }
    let spec = &row.spec;
    match kind {
      "service" => {
        for (field, text) in service_texts(spec) {
          if placeholders(text)
            .filter_map(parse_service_ref)
            .any(|r| r.service == name)
          {
            add("service", service, &field, "service_ref");
          }
        }
        for v in &spec.volumes {
          if v
            .from_service
            .as_deref()
            .and_then(|raw| {
              crate::shared_volumes::parse_ref(raw).ok()
            })
            .is_some_and(|(owner, _)| owner == name)
          {
            add(
              "service",
              service,
              &format!("volume:{}", v.name),
              "shared_volume",
            );
          }
        }
      }
      "secret" | "app_account" => {
        for (field, text) in service_secret_texts(spec) {
          let used = placeholders(text)
            .filter_map(|p| {
              parse_placeholder(p, !field.starts_with("monitor."))
                .ok()
                .flatten()
            })
            .any(|p| {
              if kind == "secret" {
                p.name == name
                  && account_ref(p.name).is_none()
                  && (!field.starts_with("monitor.")
                    || p.mode != SecretMode::File)
              } else {
                account_ref(p.name) == Some(name)
              }
            });
          if used {
            add(
              "service",
              service,
              &field,
              if kind == "secret" {
                "uses_secret"
              } else {
                "uses_account"
              },
            );
          }
        }
        if kind == "secret"
          && let Source::Build(BuildSource { git: Some(git), .. }) =
            &spec.source
          && git.token_secret.as_deref() == Some(name)
        {
          add(
            "service",
            service,
            "source.build.git.token_secret",
            "uses_secret",
          );
        }
      }
      "server" => {
        if spec.server == name {
          add("service", service, "server", "hosts");
        }
        if spec.backup.as_ref().is_some_and(|b| b.to == name) {
          add("service", service, "backup.to", "backup_target");
        }
      }
      "path" => {
        for mount in crate::data::mounts(service, spec) {
          if mount.source == name || mount.target == name {
            add(
              "service",
              service,
              &format!("volume:{}", mount.target),
              "mount",
            );
          }
        }
      }
      _ => {}
    }
  }
  for (host, row) in &world.routes {
    if hidden_secret {
      break;
    }
    let spec = &row.spec;
    if !route_visible(scope, spec) {
      continue;
    }
    match kind {
      "service" => {
        if spec.service == name {
          add("route", host, "service", "route_target");
        }
        for path in &spec.paths {
          if path.service.as_deref() == Some(name) {
            add(
              "route",
              host,
              &format!("paths[{}]", path.path),
              "route_target",
            );
          }
        }
      }
      "gateway" => {
        let gateway = if scope.is_none() {
          world.route_gateway(spec)
        } else {
          spec.gateway.as_deref()
        };
        if gateway == Some(name) {
          add("route", host, "gateway", "route_gateway");
        }
        if spec.backup_gateway.as_deref() == Some(name) {
          add("route", host, "backup_gateway", "backup_gateway");
        }
      }
      "secret" => {
        if spec.auth && crate::render::route_auth_secret(host) == name
        {
          add("route", host, "auth", "uses_secret");
        }
        if spec
          .sso
          .as_ref()
          .and_then(|s| s.login.as_ref())
          .is_some_and(|login| {
            crate::sso_login::secret_refs(login).contains(name)
          })
        {
          add("route", host, "sso.login", "uses_secret");
        }
      }
      _ => {}
    }
  }
  for (task, spec, _) in tasks {
    if hidden_secret || !task_visible(scope, &spec.how) {
      continue;
    }
    match kind {
      "service" => {
        if matches!(&spec.how, TaskKind::Exec { service, .. } if service == name)
        {
          add("task", task, "exec.service", "runs_on");
        }
        for (field, text) in task_texts(&spec.how) {
          if placeholders(text)
            .filter_map(parse_service_ref)
            .any(|r| r.service == name)
            && visible(scope, name)
          {
            add("task", task, &field, "service_ref");
          }
        }
      }
      "server" if scope.is_none() => match &spec.how {
        TaskKind::Exec { service, .. }
          if crate::tasks::exec_target(snap, service).ok()
            == Some(name) =>
        {
          add("task", task, "exec.service", "runs_on");
        }
        TaskKind::Exec { .. } => {}
        _ if spec.server == name => {
          add("task", task, "server", "runs_on")
        }
        _ => {}
      },
      "secret" => {
        for (field, text) in task_texts(&spec.how) {
          if secret_matches(text, name) {
            add("task", task, &field, "uses_secret");
          }
        }
      }
      _ => {}
    }
  }
  if scope.is_none() {
    for (gateway, row) in &world.gateways {
      if kind == "server" && row.spec.server == name {
        add("gateway", gateway, "server", "hosts");
      }
      if kind == "account"
        && row.spec.account.as_deref() == Some(name)
      {
        add("gateway", gateway, "account", "uses_account");
      }
      if kind == "service" {
        for rule in &row.spec.layer4 {
          if rule.service.as_deref() == Some(name) {
            add(
              "gateway",
              gateway,
              &format!("layer4:{}", rule.listen),
              "route_target",
            );
          }
        }
      }
    }
    for (server, row) in &world.servers {
      if kind == "server" && row.settings.via.as_deref() == Some(name)
      {
        add("server", server, "via", "via");
      }
      if kind == "secret" {
        for (registry, values) in &row.settings.registry_mirrors {
          if values.iter().any(|v| secret_matches(v, name)) {
            add(
              "server",
              server,
              &format!("registry_mirrors.{registry}"),
              "uses_secret",
            );
          }
        }
        if row
          .settings
          .github_mirror
          .as_deref()
          .is_some_and(|v| secret_matches(v, name))
        {
          add("server", server, "github_mirror", "uses_secret");
        }
      }
    }
    for (app, row) in &world.edge_apps {
      let spec = &row.spec;
      if kind == "server" && spec.builder.as_deref() == Some(name) {
        add("edge", app, "builder", "runs_on");
      }
      if kind == "account" && spec.account == name {
        add("edge", app, "account", "uses_account");
      }
      if kind == "secret"
        && spec
          .source
          .as_ref()
          .and_then(|s| s.git.as_ref())
          .and_then(|g| g.token_secret.as_deref())
          == Some(name)
      {
        add("edge", app, "source.git.token_secret", "uses_secret");
      }
    }
    for (account, host) in &snap.account_links {
      if kind == "route" && host == name {
        add("app_account", account, "domains", "linked_domain");
      }
      if kind == "app_account" && account == name {
        add("route", host, "app_accounts", "uses_account");
      }
    }
    if kind == "secret"
      && let Some(services) = snap.secret_restrictions.get(name)
    {
      for service in services {
        add(
          "secret_restriction",
          service,
          "allowed_services",
          "allowed",
        );
      }
    }
  }
  hits.sort_by(|a, b| {
    (&a.kind, &a.name, &a.field).cmp(&(&b.kind, &b.name, &b.field))
  });
  hits.dedup_by(|a, b| {
    a.kind == b.kind
      && a.name == b.name
      && a.field == b.field
      && a.relation == b.relation
  });
  let discoverable = scope.is_none() || !hits.is_empty();
  let exists = match kind {
    "server" => discoverable && world.servers.contains_key(name),
    "service" => {
      (discoverable || visible(scope, name))
        && world.services.contains_key(name)
    }
    "gateway" => discoverable && world.gateways.contains_key(name),
    "route" => world
      .routes
      .get(name)
      .is_some_and(|row| route_visible(scope, &row.spec)),
    "secret" => {
      !hidden_secret
        && discoverable
        && snap.secrets.contains_key(name)
    }
    "account" => {
      scope.is_none() && snap.accounts.iter().any(|a| a.name == name)
    }
    "app_account" => {
      discoverable && snap.app_account_names.contains(name)
    }
    _ => !hits.is_empty(),
  };
  let removable = kind == "secret"
    && exists
    && scope.is_none()
    && hits.is_empty()
    && !crate::secret_policy::is_managed_secret(name)
    && !crate::secret_policy::is_system_secret(name);
  RefReport {
    kind: kind.into(),
    name: name.into(),
    exists,
    count: hits.len(),
    refs: hits,
    complete: scope.is_none(),
    removable,
  }
}

fn env_reference(text: &str) -> bool {
  text
    .strip_prefix("[[")
    .and_then(|s| s.strip_suffix("]]"))
    .is_some_and(|raw| {
      parse_placeholder(raw, true).is_ok_and(|p| p.is_some())
        || parse_service_ref(raw).is_some()
    })
}

fn search_snapshot(
  snap: &Snapshot,
  tasks: &Tasks,
  scope: Option<&BTreeSet<String>>,
  q: &SearchQuery,
) -> SearchResponse {
  let world = &snap.world;
  let needle = q.q.trim().to_lowercase();
  let limit = q.limit.unwrap_or(50).clamp(1, 200);
  let mut hits = Vec::new();
  let mut total = 0;
  let mut add = |kind: &str, name: &str, field: &str, text: &str| {
    if q.kind.as_deref().is_some_and(|k| k != kind) {
      return;
    }
    for line in text
      .lines()
      .filter(|line| !line.trim_start().starts_with("wharf-enc:v1:"))
    {
      let clean = if field.starts_with("env.")
        && line
          .split_once('=')
          .is_some_and(|(_, value)| env_reference(value))
      {
        crate::log_redact::redact_text_with(line, &snap.log_values)
      } else {
        crate::log_redact::redact_text_with(
          &crate::redact::redact_command(line),
          &snap.log_values,
        )
      };
      let text = clean.to_lowercase();
      if !text.contains(&needle) {
        continue;
      }
      total += 1;
      if hits.len() < limit {
        let start = text.find(&needle).unwrap_or(0);
        let offset = text[..start].chars().count().saturating_sub(24);
        hits.push(SearchHit {
          kind: kind.into(),
          name: name.into(),
          field: field.into(),
          match_text: clean.chars().skip(offset).take(120).collect(),
        });
      }
      break;
    }
  };
  let mut related = BTreeSet::new();
  for (service, row) in &world.services {
    if !visible(scope, service) {
      continue;
    }
    add("service", service, "name", service);
    if let Some(note) = snap.notes.get(service) {
      add("service", service, "note", note);
    }
    for port in &row.spec.ports {
      add(
        "service",
        service,
        "ports",
        &port.container.map_or_else(
          || port.name.clone(),
          |n| format!("{}={n}", port.name),
        ),
      );
    }
    for (field, text) in service_texts(&row.spec) {
      if let Some(key) = field.strip_prefix("env.") {
        let sensitive =
          wharf_api_types::secret_detect::is_sensitive_env_key(key)
            || crate::redact::is_sensitive_env_key(key)
            || wharf_api_types::secret_detect::detect_secret_value(
              text,
            )
            .is_some();
        let value = if sensitive && !env_reference(text) {
          "***"
        } else {
          text
        };
        add("service", service, &field, &format!("{key}={value}"));
      } else if let Some(path) = field.strip_prefix("file:") {
        add("service", service, &field, &format!("{path}\n{text}"));
      } else {
        add("service", service, &field, text);
      }
    }
    if scope.is_some() {
      related.extend(snap.secrets.keys().filter(|name| {
        crate::secret_policy::service_uses_secret(&row.spec, name)
      }));
    }
  }
  for (host, row) in &world.routes {
    if !route_visible(scope, &row.spec) {
      continue;
    }
    add("route", host, "hostname", host);
    if let Some(note) = snap.route_notes.get(host) {
      add("route", host, "note", note);
    }
    if scope.is_none()
      && let Some(caddy) = &row.spec.caddy
    {
      add("route", host, "caddy", caddy);
    }
  }
  for (name, spec, _) in tasks {
    if task_visible(scope, &spec.how) {
      add("task", name, "name", name);
      if let TaskKind::Script { code, .. } = &spec.how {
        add("task", name, "code", code);
      }
      if scope.is_some() {
        related.extend(snap.secrets.keys().filter(|name| {
          task_texts(&spec.how).any(|(_, t)| secret_matches(t, name))
        }));
      }
    }
  }
  for name in snap.secrets.keys() {
    if scope.is_none()
      || related.contains(name)
        && !crate::secret_policy::is_system_secret(name)
        && !crate::secret_policy::is_managed_secret(name)
    {
      add("secret", name, "name", name);
    }
  }
  if scope.is_none() {
    for name in world.servers.keys() {
      add("server", name, "name", name);
      if let Some(note) = snap.server_notes.get(name) {
        add("server", name, "note", note);
      }
    }
    for name in world.gateways.keys() {
      add("gateway", name, "name", name);
    }
    for (name, row) in &world.edge_apps {
      add("edge", name, "name", name);
      for domain in &row.spec.domains {
        add("edge", name, "domains", domain);
      }
    }
    for (id, row) in &world.bookmarks {
      add("bookmark", id, "title", &row.spec.title);
      add(
        "bookmark",
        id,
        "url",
        &crate::redact::redact_command(&row.spec.url),
      );
    }
  }
  SearchResponse { total, hits }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn seeded() -> Snapshot {
    let mut snap = Snapshot::default();
    for name in ["s1", "s2", "s3"] {
      snap.world.servers.insert(
        name.into(),
        crate::world::ServerRow {
          settings: Default::default(),
          version: 0,
        },
      );
    }
    let fleet = serde_json::from_value(json!({
      "services": {
        "db": {"server":"s3","source":{"image":"db:1"},"ports":[{"name":"http","container":80}],"volumes":[{"name":"data","target":"/data"}]},
        "api": {"server":"s3","source":{"image":"app:1"},"ports":[{"name":"http","container":80}],
          "backup":{"to":"s2"},"env":{"REDIS_HOST":"100.64.0.9","API_SECRET":"fixture-private-999"},
          "files":[{"path":"/etc/app.conf","content":"[[@db]]"}]},
        "worker": {"server":"s3","source":{"image":"app:1"},"volumes":[{"name":"data","target":"/data","from_service":"db:data"}]}
      },
      "gateways": {
        "edge": {"kind":"caddy","server":"s1","default":true},
        "cf": {"kind":"caddy","server":"s2"}
      },
      "routes": [{"hostname":"api.example.test","service":"api","gateway":"edge","backup_gateway":"cf"}]
    })).unwrap();
    snap.world.merge_with(&fleet).unwrap();
    snap.notes.insert(
      "api".into(),
      "公开备注\nwharf-enc:v1:fixture-cipher".into(),
    );
    snap
  }

  #[test]
  fn scoped_refs_hide_default_gateway_and_system_secrets_and_skip_invalid_refs()
   {
    let mut snap = seeded();
    let route = &mut snap
      .world
      .routes
      .get_mut("api.example.test")
      .unwrap()
      .spec;
    route.gateway = None;
    route.auth = true;
    let basic_auth =
      crate::render::route_auth_secret(&route.hostname);
    for name in [&basic_auth, "OIDC_SECRET_FIXTURE"] {
      snap
        .secrets
        .insert(name.to_string(), "fixture-value".into());
    }
    snap
      .world
      .services
      .get_mut("api")
      .unwrap()
      .spec
      .env
      .extend([
        ("PASSWORD".into(), "[[account.demo.password]]".into()),
        ("OIDC_KEY".into(), "[[OIDC_SECRET_FIXTURE]]".into()),
      ]);
    let tasks = vec![("fixture".into(), serde_json::from_value(json!({
      "server":"s3","schedule":"","kind":"exec","service":"api","command":"echo [[FILE:FOO]]"
    })).unwrap(), 0)];
    let scope = ["api".into()].into();
    for (kind, name) in [
      ("gateway", "edge"),
      ("secret", &basic_auth),
      ("secret", "OIDC_SECRET_FIXTURE"),
    ] {
      let report =
        collect_refs(&snap, &tasks, Some(&scope), kind, name);
      assert!(!report.exists);
      assert!(report.refs.is_empty());
    }
    for name in ["FOO", "account.demo.password"] {
      assert!(
        collect_refs(&snap, &tasks, None, "secret", name)
          .refs
          .is_empty()
      );
    }
  }

  #[test]
  fn server_refs_resolve_exec_target_after_service_migration() {
    let mut snap = seeded();
    snap.deployed.insert("api".into(), "s3".into());
    let tasks = vec![("moved".into(), serde_json::from_value(json!({
      "server":"s1","schedule":"","kind":"exec","service":"api","command":"true"
    })).unwrap(), 0)];
    assert!(
      collect_refs(&snap, &tasks, None, "server", "s3")
        .refs
        .iter()
        .any(|hit| hit.kind == "task")
    );
    assert!(
      !collect_refs(&snap, &tasks, None, "server", "s1")
        .refs
        .iter()
        .any(|hit| hit.kind == "task")
    );
  }

  #[test]
  fn search_matches_file_path_once_and_preserves_sensitive_env_reference()
   {
    let mut snap = seeded();
    let spec = &mut snap.world.services.get_mut("api").unwrap().spec;
    spec.files[0].content = "app.conf".into();
    spec
      .env
      .insert("DB_PASSWORD".into(), "[[MY_DB_PASS]]".into());
    let search = |q: &str| {
      search_snapshot(
        &snap,
        &vec![],
        None,
        &SearchQuery {
          q: q.into(),
          kind: Some("service".into()),
          limit: None,
        },
      )
    };
    assert_eq!(search("file").total, 0);
    assert_eq!(search("app.conf").total, 1);
    let hits = search("MY_DB_PASS");
    assert_eq!(hits.total, 1);
    assert_eq!(hits.hits[0].match_text, "DB_PASSWORD=[[MY_DB_PASS]]");
  }

  #[test]
  fn tree_normalizes_routes_and_disambiguates_gateway() {
    let mut snap = seeded();
    let edge = snap.world.services["api"].clone();
    snap.world.services.insert("edge".into(), edge);
    let lookup = |q| build_tree(&snap, None, &q, &Default::default());
    for q in [
      TreeQuery {
        target: Some("API.EXAMPLE.TEST".into()),
        ..Default::default()
      },
      TreeQuery {
        route: Some("api.example.test.".into()),
        ..Default::default()
      },
      TreeQuery {
        gateway: Some("edge".into()),
        ..Default::default()
      },
    ] {
      let view = lookup(q).unwrap();
      let route = &view.routes[0];
      assert_eq!(route.hostname, "api.example.test");
      let svc = route.service.as_ref().unwrap();
      assert_eq!(svc.state.as_deref(), Some("unknown"));
      assert_eq!(svc.dependency_details[0].kind, "service_ref");
      assert_eq!(
        svc.dependency_details[0].server.as_deref(),
        Some("s3")
      );
    }
    assert!(
      lookup(TreeQuery {
        target: Some("edge".into()),
        ..Default::default()
      })
      .is_err()
    );
  }

  #[test]
  fn refs_find_file_volume_and_route_with_scope() {
    let mut snap = seeded();
    snap
      .world
      .routes
      .get_mut("api.example.test")
      .unwrap()
      .spec
      .service = "db".into();
    let all = collect_refs(&snap, &vec![], None, "service", "db");
    assert_eq!(all.count, 3);
    let scope = ["api".into()].into();
    let scoped =
      collect_refs(&snap, &vec![], Some(&scope), "service", "db");
    assert_eq!(scoped.count, 1);
    assert_eq!(scoped.refs[0].field, "file:/etc/app.conf");
  }

  #[test]
  fn tree_includes_backup_dependencies_and_server_filter() {
    let snap = seeded();
    let all = build_tree(
      &snap,
      None,
      &TreeQuery::default(),
      &Default::default(),
    )
    .unwrap();
    let route = &all.routes[0];
    assert_eq!(route.gateway.as_ref().unwrap().name, "edge");
    assert_eq!(
      route.backup_gateway.as_ref().unwrap().server.as_deref(),
      Some("s2")
    );
    assert_eq!(route.link.as_deref(), Some("frp"));
    let service = route.service.as_ref().unwrap();
    assert_eq!(service.dependencies, ["db"]);
    assert_eq!(service.backup_to.as_deref(), Some("s2"));
    assert!(all.orphan_services.iter().any(|s| s.name == "db"));
    let filtered = build_tree(
      &snap,
      None,
      &TreeQuery {
        server: Some("s3".into()),
        ..Default::default()
      },
      &Default::default(),
    )
    .unwrap();
    assert_eq!(filtered.servers.len(), 1);
    assert_eq!(filtered.servers[0].name, "s3");
  }

  #[test]
  fn search_excludes_secret_values_and_sealed_notes() {
    let snap = seeded();
    let search = |q: &str| {
      search_snapshot(
        &snap,
        &vec![],
        None,
        &SearchQuery {
          q: q.into(),
          kind: None,
          limit: None,
        },
      )
    };
    assert_eq!(search("REDIS").hits[0].field, "env.REDIS_HOST");
    assert_eq!(search("fixture-private-999").total, 0);
    assert_eq!(search("fixture-cipher").total, 0);
  }
}

#[tokio::test]
async fn refs_include_alert_overrides_and_rule_aware_suppressions() {
  let db = crate::db::Db::memory();
  db.call(|c| {
    c.execute("INSERT INTO alert_service_overrides (rule, service) VALUES ('port_down','api')", []).map_err(crate::db::sql_err)?;
    c.execute("INSERT INTO alert_suppressions (source_rule, source_subject, target_rule, target_subject, created_at)
      VALUES ('host_unit_down','s1:db','port_down','api:http',0)", []).map_err(crate::db::sql_err)?;
    let hits = alert_refs(c, "service", "api")?;
    assert_eq!(hits.iter().map(|hit| hit.field.as_str()).collect::<Vec<_>>(), ["override.service", "target_subject"]);
    assert_eq!(alert_refs(c, "server", "s1")?[0].field, "source_subject");
    Ok(())
  }).await.unwrap();
}
