//! 控制面静态一致性检查。

use std::{collections::BTreeSet, sync::Arc};

use axum::{
  Json,
  extract::{Query, State},
};
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  references::{parse_placeholder, placeholders},
  view::{
    LintFinding, LintReport, LintSeverity, LintSummary, Perm,
    TaskKind, TaskSpec,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db, lint,
  snapshot::{self, Snapshot},
  state::AppState,
};

#[derive(Default, Deserialize)]
pub struct LintQuery {
  severity: Option<LintSeverity>,
  category: Option<String>,
  service: Option<String>,
  #[serde(default)]
  strict: bool,
}

type Suppression =
  (i64, String, Option<String>, String, Option<String>);

#[derive(Default)]
struct Rows {
  tasks: Vec<(String, TaskSpec, i64)>,
  gate_hosts: Vec<(String, String)>,
  custom: Vec<(String, String)>,
  overrides: Vec<(String, String)>,
  suppressions: Vec<Suppression>,
}

pub async fn report(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<LintQuery>,
) -> ApiResult<LintReport> {
  auth.require(Perm::Read)?;
  if q
    .category
    .as_deref()
    .is_some_and(|c| !matches!(c, "config" | "consistency"))
  {
    return Err(
      ApiError::invalid("体检分类须为 config 或 consistency").into(),
    );
  }
  let snap = snapshot::load_inner(&s.db).await?;
  let global = auth.services.is_none() && q.service.is_none();
  let rows = s.db.call(move |c| {
    let mut rows = Rows { tasks: crate::tasks::load_rows(c)?, ..Default::default() };
    if global {
      let pairs = |sql| {
        let mut stmt = c.prepare(sql).map_err(db::sql_err)?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
          .and_then(Iterator::collect).map_err(db::sql_err)
      };
      rows.gate_hosts = pairs("SELECT gate_keys.name, j.value FROM gate_keys, json_each(gate_keys.hosts) j")?;
      rows.custom = pairs("SELECT name, service FROM alert_custom_rules")?;
      rows.overrides = pairs("SELECT rule, service FROM alert_service_overrides")?;
      let mut stmt = c.prepare("SELECT id, source_rule, source_subject, target_rule, target_subject FROM alert_suppressions").map_err(db::sql_err)?;
      rows.suppressions = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .and_then(Iterator::collect).map_err(db::sql_err)?;
    }
    Ok(rows)
  }).await?;
  Ok(Json(check_all(
    &snap,
    &rows,
    auth.services.as_ref(),
    &q,
    db::now_ms(),
  )))
}

fn check_all(
  snap: &Snapshot,
  rows: &Rows,
  scope: Option<&BTreeSet<String>>,
  q: &LintQuery,
  now: i64,
) -> LintReport {
  use LintSeverity::{Error, Info, Warning};
  let world = &snap.world;
  let global = scope.is_none() && q.service.is_none();
  let visible = |name: &str| {
    scope.is_none_or(|allowed| allowed.contains(name))
      && q.service.as_deref().is_none_or(|s| s == name)
  };
  let mut findings = Vec::new();
  let mut add = |id: &str,
                 severity,
                 subject: String,
                 message: String,
                 suggest: String| {
    findings.push(LintFinding {
      id: id.into(),
      category: "consistency".into(),
      severity,
      subject,
      message,
      suggest: vec![suggest],
    });
  };
  for (name, spec, _) in &rows.tasks {
    match &spec.how {
      TaskKind::Exec { service, .. } if visible(service) => {}
      TaskKind::Exec { .. } => continue,
      _ if global => {}
      _ => continue,
    }
    let subject = format!("task/{name}");
    let remove = format!("wharf task rm {name}");
    if !matches!(&spec.how, TaskKind::Exec { .. })
      && !world.servers.contains_key(&spec.server)
    {
      add(
        "dangling_task_server",
        Error,
        subject.clone(),
        "任务的服务器不存在".into(),
        remove.clone(),
      );
    }
    if let TaskKind::Exec {
      service, container, ..
    } = &spec.how
      && world.services.get(service).is_none_or(|r| {
        container.as_deref().is_some_and(|c| match &r.spec.source {
          wharf_api_types::spec::Source::Compose {
            content, ..
          } => content
            .as_deref()
            .and_then(|yaml| crate::render::parse_compose(yaml).ok())
            .is_some_and(|doc| {
              doc
                .get("services")
                .and_then(|svcs| svcs.get(c))
                .is_none()
            }),
          _ => c != service,
        })
      })
    {
      add(
        "dangling_task_service",
        Error,
        subject.clone(),
        "任务的服务或容器不存在".into(),
        remove,
      );
    }
    for reference in crate::missing_refs::task_texts(&spec.how)
      .flat_map(|(_, text)| placeholders(text))
      .filter_map(wharf_api_types::references::parse_service_ref)
      .filter(|r| visible(r.service))
    {
      if let Err(error) =
        crate::refs::validate_task_ref(name, world, &reference)
      {
        add(
          "dangling_task_service_ref",
          Error,
          subject.clone(),
          error.message,
          format!("wharf task show {name}"),
        );
      }
    }
    let names = crate::missing_refs::task_texts(&spec.how)
      .flat_map(|(_, text)| {
        placeholders(text).filter_map(|p| {
          parse_placeholder(p, false).ok().flatten().map(|p| p.name)
        })
      })
      .collect::<BTreeSet<_>>();
    for name in names {
      if !snap.secrets.contains_key(name)
        || crate::secret_policy::is_system_secret(name)
        || snap.secret_restrictions.contains_key(name)
      {
        add(
          "dangling_task_secret",
          Error,
          subject.clone(),
          format!("密钥 {name} 不存在或当前任务无权引用"),
          format!("wharf secret set {name}"),
        );
      }
    }
  }
  for item in crate::missing_refs::collect_plan_missing(world, snap) {
    let Some(name) = item
      .source
      .strip_prefix("service/")
      .and_then(|s| s.split_whitespace().next())
    else {
      continue;
    };
    if visible(name) {
      add(
        "dangling_service_ref",
        Error,
        format!("service/{name}"),
        format!("{} 缺少引用 {}", item.source, item.target),
        format!("wharf service show {name}"),
      );
    }
  }
  if global {
    let gated = |host: &str| {
      world
        .routes
        .get(host)
        .and_then(|r| r.spec.sso.as_ref())
        .is_some_and(|sso| sso.gated())
    };
    for (name, host) in &rows.gate_hosts {
      if !gated(host) {
        let hosts = rows
          .gate_hosts
          .iter()
          .filter(|(key, host)| key == name && gated(host))
          .map(|(_, host)| format!(" --host {host}"))
          .collect::<String>();
        let command = if hosts.is_empty() {
          format!("wharf gate key rm {name}")
        } else {
          format!("wharf gate key add {name}{hosts}")
        };
        add(
          "stale_gate_key_host",
          Warning,
          format!("gate_key/{name}"),
          format!("域名 {host} 已失效"),
          command,
        );
      }
    }
    for (account, host) in &snap.account_links {
      if !world.routes.contains_key(host) {
        add(
          "stale_app_account_domain",
          Warning,
          format!("app_account/{account}"),
          format!("关联域名 {host} 不存在"),
          format!("wharf sso account unlink {account} {host}"),
        );
      }
    }
    for name in &snap.app_account_names {
      let linked =
        snap.account_links.iter().any(|(account, host)| {
          account == name && world.routes.contains_key(host)
        });
      let referenced = world.services.values().any(|r| {
        crate::secret_policy::service_account_refs(&r.spec)
          .any(|(_, account)| account == name)
      });
      if !linked && !referenced {
        add(
          "orphan_app_account",
          Info,
          format!("app_account/{name}"),
          "账号没有域名或服务引用".into(),
          format!("wharf sso account rm {name}"),
        );
      }
    }
    for (rows, custom) in
      [(&rows.custom, true), (&rows.overrides, false)]
    {
      for (name, service) in rows {
        if !world.services.contains_key(service) {
          let cmd = if custom {
            format!("wharf alert custom rm {name}")
          } else {
            format!(
              "wharf alert set {name} --service {service} --reset"
            )
          };
          add(
            "stale_alert_rule",
            Warning,
            format!("alert/{name}"),
            format!("服务 {service} 不存在"),
            cmd,
          );
        }
      }
    }
    for (id, a_rule, a, b_rule, b) in &rows.suppressions {
      let missing = |rule: &str, subject: &str| {
        let custom = rows.custom.iter().any(|(name, _)| name == rule);
        crate::rules::subject_resources(rule, subject, custom)
          .into_iter()
          .any(|(kind, name)| match kind {
            "server" => !world.servers.contains_key(name),
            "service" => !world.services.contains_key(name),
            "route" => {
              !world.routes.contains_key(name)
                && world.edge_domain(name).is_none()
            }
            "gateway" => !world.gateways.contains_key(name),
            "task" => {
              !rows.tasks.iter().any(|(task, _, _)| task == name)
            }
            _ => false,
          })
      };
      if a.as_deref().is_some_and(|s| missing(a_rule, s))
        || b.as_deref().is_some_and(|s| missing(b_rule, s))
      {
        add(
          "stale_alert_suppression",
          Warning,
          format!("alert_suppression/{id}"),
          "抑制目标不存在".into(),
          format!("wharf alert suppress rm {id}"),
        );
      }
    }
    for (secret, allowed) in &snap.secret_restrictions {
      for service in allowed {
        if !world.services.contains_key(service) {
          add(
            "stale_secret_restriction",
            Warning,
            format!("secret/{secret}"),
            format!("允许列表中的服务 {service} 不存在"),
            format!(
              "wharf secret restrict {secret} --services <服务>"
            ),
          );
        }
      }
    }
    for (host, route) in &world.routes {
      if route.spec.expires_at.is_some_and(|at| at < now) {
        add(
          "expired_share_route",
          Info,
          format!("route/{host}"),
          "临时分享已过期".into(),
          format!("wharf route rm {host} --apply"),
        );
      }
    }
    let hosts = world
      .routes
      .keys()
      .chain(world.edge_apps.values().flat_map(|r| &r.spec.domains))
      .map(String::as_str)
      .collect::<BTreeSet<_>>();
    let is_in = |host: &str, root: &str| {
      host == root
        || host.strip_suffix(root).is_some_and(|p| p.ends_with('.'))
    };
    let roots = hosts
      .iter()
      .copied()
      .chain(hosts.iter().filter_map(|host| {
        let (_, parent) = host.split_once('.')?;
        let (label, suffix) = parent.rsplit_once('.')?;
        // 对可能是公共后缀的两层国家域名，只接受显式托管根域。
        (label.contains('.') || suffix.len() != 2).then_some(parent)
      }))
      .chain(world.gateways.values().flat_map(|r| {
        r.spec.wildcard.iter().map(|s| s.trim_start_matches("*."))
      }))
      .chain(
        snap
          .accounts
          .iter()
          .flat_map(|account| &account.zones)
          .map(String::as_str)
          .filter(|zone| hosts.iter().any(|host| is_in(host, zone))),
      )
      .collect::<BTreeSet<_>>();
    for (id, row) in &world.bookmarks {
      if let Ok(url) = reqwest::Url::parse(&row.spec.url)
        && let Some(host) = url.host_str()
        && !hosts.contains(host)
        && roots.iter().any(|root| is_in(host, root))
      {
        add(
          "dead_bookmark",
          Warning,
          format!("bookmark/{id}"),
          "集群内书签的域名没有路由".into(),
          format!("wharf bookmark rm {id}"),
        );
      }
    }
    for name in snap.secrets.keys() {
      if !crate::secret_policy::is_managed_secret(name)
        && !crate::secret_policy::is_system_secret(name)
        && !world.services.values().any(|r| {
          crate::secret_policy::service_uses_secret(&r.spec, name)
        })
        && crate::secret_policy::other_secret_refs(
          world,
          rows
            .tasks
            .iter()
            .map(|(name, spec, _)| (name.as_str(), &spec.how)),
          name,
        )
        .is_empty()
      {
        add(
          "orphan_secret",
          Info,
          format!("secret/{name}"),
          "密钥没有引用".into(),
          format!("wharf secret rm {name}"),
        );
      }
    }
  }

  let services = world
    .services
    .keys()
    .filter(|s| visible(s))
    .cloned()
    .collect();
  let servers = if global {
    world.servers.keys().cloned().collect()
  } else {
    BTreeSet::new()
  };
  for (subject, message) in
    lint::scoped_warnings(snap, &services, &servers)
  {
    let subject = if let Some(name) = subject.strip_prefix("服务 ")
    {
      format!("service/{name}")
    } else {
      format!("server/{}", subject.trim_start_matches("服务器 "))
    };
    let id = if message.contains("没设重启策略") {
      "compose_no_restart"
    } else if message.contains("绑定所有地址") {
      "compose_public_port"
    } else if message.contains("使用了 latest 镜像") {
      "image_latest"
    } else if message.contains("超过机器内存") {
      "server_mem_overcommit"
    } else if message.contains("直接挂载了服务") {
      "implicit_shared_volume"
    } else {
      "plaintext_secret"
    };
    let message =
      crate::log_redact::redact_text_with(&message, &snap.log_values);
    findings.push(LintFinding {
      id: id.into(),
      category: "config".into(),
      severity: Warning,
      subject,
      message,
      suggest: Vec::new(),
    });
  }
  findings
    .retain(|f| q.category.as_ref().is_none_or(|c| c == &f.category));
  findings.sort_by(|a, b| {
    (b.severity, &a.subject, &a.id, &a.message)
      .cmp(&(a.severity, &b.subject, &b.id, &b.message))
  });
  let mut summary = LintSummary::default();
  for f in &findings {
    match f.severity {
      Error => summary.error += 1,
      Warning => summary.warning += 1,
      Info => summary.info += 1,
    }
  }
  findings.retain(|f| q.severity.is_none_or(|s| f.severity >= s));
  LintReport {
    ok: summary.error == 0 && (!q.strict || summary.warning == 0),
    summary,
    findings,
  }
}

#[test]
fn lint_reports_stale_objects_without_matching_external_bookmark() {
  use serde_json::json;

  let mut snap = Snapshot::default();
  let fleet = serde_json::from_value(json!({
    "gateways": {"edge": {"kind":"caddy","server":"s1","wildcard":["example.test"]}},
    "bookmarks": {
      "dead": {"title":"dead","url":"https://missing.example.test"},
      "external": {"title":"external","url":"https://example.net"},
      "public-suffix": {"title":"external","url":"https://outside-fixture.co.uk"}
    },
    "routes": [{"hostname":"cluster-fixture.co.uk","upstream":"example.test:80"}]
  })).unwrap();
  snap.world.merge_with(&fleet).unwrap();
  snap.world.servers.insert(
    "s1".into(),
    crate::world::ServerRow {
      settings: Default::default(),
      version: 0,
    },
  );
  snap.app_account_names.insert("orphan".into());
  let task = serde_json::from_value(json!({"server":"s1","schedule":"","kind":"exec","service":"deleted","command":"true"})).unwrap();
  let rows = Rows {
    tasks: vec![("job".into(), task, 0)],
    gate_hosts: vec![("key".into(), "deleted.example.test".into())],
    custom: vec![("rule".into(), "deleted".into())],
    ..Default::default()
  };
  let report =
    check_all(&snap, &rows, None, &LintQuery::default(), 0);
  assert!(!report.ok);
  assert_eq!(report.summary.error, 1);
  assert_eq!(
    report
      .findings
      .iter()
      .map(|f| f.id.as_str())
      .collect::<BTreeSet<_>>(),
    [
      "dangling_task_service",
      "stale_gate_key_host",
      "orphan_app_account",
      "stale_alert_rule",
      "dead_bookmark"
    ]
    .into()
  );
  assert!(report.findings.iter().all(|f| !f.suggest.is_empty()
    && f.subject != "bookmark/external"
    && f.subject != "bookmark/public-suffix"));
}

#[test]
fn lint_validates_suppression_subjects_by_rule_and_keeps_strict_warnings()
 {
  use serde_json::json;
  let mut snap = Snapshot::default();
  for name in ["s1", "s2"] {
    snap.world.servers.insert(
      name.into(),
      crate::world::ServerRow {
        settings: Default::default(),
        version: 0,
      },
    );
  }
  let fleet = serde_json::from_value(json!({
    "services":{"api":{"server":"s1","source":{"image":"app:1"}}}
  }))
  .unwrap();
  snap.world.merge_with(&fleet).unwrap();
  let task = serde_json::from_value(json!({
    "server":"s1","schedule":"","kind":"host","command":"true"
  }))
  .unwrap();
  let rows = Rows {
    tasks: vec![("sync".into(), task, 0)],
    suppressions: vec![
      (
        1,
        "host_unit_down".into(),
        Some("s1:db".into()),
        "task".into(),
        Some("sync".into()),
      ),
      (
        2,
        "link_loss".into(),
        Some("s1>s2".into()),
        "port_down".into(),
        Some("api:http".into()),
      ),
      (
        3,
        "mem_forecast".into(),
        Some("服务器 s1".into()),
        "vendor_token_invalid".into(),
        Some("cloud".into()),
      ),
      (
        4,
        "server_offline".into(),
        Some("absent".into()),
        "task".into(),
        Some("sync".into()),
      ),
    ],
    ..Default::default()
  };
  let all = check_all(&snap, &rows, None, &LintQuery::default(), 0);
  let stale = all
    .findings
    .iter()
    .filter(|f| f.id == "stale_alert_suppression")
    .map(|f| f.subject.as_str())
    .collect::<Vec<_>>();
  assert_eq!(stale, ["alert_suppression/4"]);
  let strict = check_all(
    &snap,
    &rows,
    None,
    &LintQuery {
      strict: true,
      severity: Some(LintSeverity::Error),
      ..Default::default()
    },
    0,
  );
  assert!(!strict.ok);
  assert_eq!(strict.summary.warning, 1);
  assert!(strict.findings.is_empty());
}

#[test]
fn lint_exec_uses_actual_service_and_rejects_restricted_secrets() {
  use serde_json::json;
  let mut snap = Snapshot::default();
  snap.world.servers.insert(
    "s2".into(),
    crate::world::ServerRow {
      settings: Default::default(),
      version: 0,
    },
  );
  let fleet = serde_json::from_value(json!({
    "services":{"api":{"server":"s2","source":{"compose":{"content":"services: { worker: { image: app:1, restart: 'no', profiles: [batch] } }"}}}}
  })).unwrap();
  snap.world.merge_with(&fleet).unwrap();
  snap
    .secrets
    .insert("DB_PASS".into(), "fixture-value".into());
  snap
    .secret_restrictions
    .insert("DB_PASS".into(), ["api".into()].into());
  let task = serde_json::from_value(json!({
    "server":"s1","schedule":"","kind":"exec","service":"api","container":"worker","command":"echo [[DB_PASS]]"
  })).unwrap();
  let rows = Rows {
    tasks: vec![("sync".into(), task, 0)],
    ..Default::default()
  };
  let report =
    check_all(&snap, &rows, None, &LintQuery::default(), 0);
  let errors = report
    .findings
    .iter()
    .filter(|f| f.severity == LintSeverity::Error)
    .map(|f| f.id.as_str())
    .collect::<Vec<_>>();
  assert_eq!(errors, ["dangling_task_secret"]);
}

#[test]
fn lint_gate_key_retains_gated_hosts_and_finds_sibling_bookmark() {
  use serde_json::json;
  let mut snap = Snapshot::default();
  let fleet = serde_json::from_value(json!({
    "routes":[
      {"hostname":"live.example.test","upstream":"app.test:80","sso":{"mode":"gate"}},
      {"hostname":"public.example.test","upstream":"app.test:80","sso":{"mode":"oidc","public":true,"oidc":{"redirect_uris":["/callback"]}}}
    ],
    "bookmarks":{"dead":{"title":"dead","url":"https://gone.example.test"}}
  })).unwrap();
  snap.world.merge_with(&fleet).unwrap();
  let rows = Rows {
    gate_hosts: vec![
      ("mixed".into(), "live.example.test".into()),
      ("mixed".into(), "public.example.test".into()),
    ],
    ..Default::default()
  };
  let report =
    check_all(&snap, &rows, None, &LintQuery::default(), 0);
  let stale = report
    .findings
    .iter()
    .find(|f| f.id == "stale_gate_key_host")
    .unwrap();
  assert_eq!(
    stale.suggest,
    ["wharf gate key add mixed --host live.example.test"]
  );
  assert!(
    report.findings.iter().any(
      |f| f.id == "dead_bookmark" && f.subject == "bookmark/dead"
    )
  );
}
