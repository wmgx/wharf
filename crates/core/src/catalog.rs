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
    account_ref, parse_placeholder, parse_service_ref, placeholders,
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
  Ok(Json(collect_refs(
    &snap,
    &tasks,
    auth.services.as_ref(),
    kind,
    name,
  )))
}

pub async fn tree(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<TreeQuery>,
) -> ApiResult<TreeView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load_inner(&s.db).await?;
  Ok(Json(build_tree(&snap, auth.services.as_ref(), &q)?))
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
    parse_placeholder(p, true)
      .ok()
      .flatten()
      .is_some_and(|p| p.name == name)
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
  for (service, row) in &world.services {
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
        if world.route_gateway(spec) == Some(name) {
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
    if !task_visible(scope, &spec.how) {
      continue;
    }
    match kind {
      "service" if matches!(&spec.how, TaskKind::Exec { service, .. } if service == name) => {
        add("task", task, "exec.service", "runs_on")
      }
      "server" if scope.is_none() && spec.server == name => {
        add("task", task, "server", "runs_on")
      }
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
    "secret" => discoverable && snap.secrets.contains_key(name),
    "account" => {
      scope.is_none() && snap.accounts.iter().any(|a| a.name == name)
    }
    "app_account" => {
      discoverable && snap.app_account_names.contains(name)
    }
    _ => !hits.is_empty(),
  };
  RefReport {
    kind: kind.into(),
    name: name.into(),
    exists,
    count: hits.len(),
    refs: hits,
    complete: scope.is_none(),
  }
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
      let clean =
        crate::log_redact::redact_text_with(line, &snap.log_values);
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
        &format!("{}={}", port.name, port.container),
      );
    }
    for (field, text) in service_texts(&row.spec) {
      if let Some(key) = field.strip_prefix("env.") {
        let value =
          if wharf_api_types::secret_detect::is_sensitive_env_key(key)
            || crate::redact::is_sensitive_env_key(key)
            || wharf_api_types::secret_detect::detect_secret_value(
              text,
            )
            .is_some()
          {
            "***"
          } else {
            text
          };
        add("service", service, &field, &format!("{key}={value}"));
      } else {
        add("service", service, &field, &field);
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
    let all = build_tree(&snap, None, &TreeQuery::default()).unwrap();
    let route = &all.routes[0];
    assert!(route.gateway.as_deref().unwrap().starts_with("edge"));
    assert!(
      route.backup_gateway.as_deref().unwrap().starts_with("cf")
    );
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
