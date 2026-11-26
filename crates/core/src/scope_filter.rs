//! 受限令牌（`--services`）的视图裁剪、对象归属校验与任务/执行记录作用域判定。

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  plan::{Plan, Run},
  spec::Fleet,
  view::{
    AlertsView, DataView, DoctorReport, Issue, SecretView, Status,
    TaskKind, TaskSpec,
  },
};

use crate::{
  auth::Auth,
  db::{json_err, sql_err},
  planner::Step,
  state::AppState,
  token_scope::{self, route_spec_in_scope},
  world::World,
};

#[derive(Serialize, Deserialize)]
pub struct StoredRun {
  #[serde(flatten)]
  pub run: Run,
  /// 非 plan 发起的 run（start_task）涉及的服务名；
  /// Some(vec) 表示只涉及这些服务（空 vec 表示全局/非服务级任务，受限令牌无权访问）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub scope_services: Option<Vec<String>>,
}

pub fn step_scope_services(step: &Step) -> Vec<String> {
  match step {
    Step::Backup { service }
    | Step::Restore { service, .. }
    | Step::Rebuild { service }
    | Step::ServiceRestart { service }
    | Step::ServiceStop { service }
    | Step::ServiceUp { service, .. }
    | Step::ServiceDown { service, .. }
    | Step::VolumeSync { service, .. } => vec![service.clone()],
    _ => vec![],
  }
}

pub fn task_in_scope(
  services: &BTreeSet<String>,
  spec: &TaskSpec,
) -> bool {
  matches!(&spec.how, TaskKind::Exec { service, .. } if services.contains(service))
}

pub fn require_task_scope(
  auth: &Auth,
  loaded: Result<TaskSpec, ApiError>,
) -> Result<TaskSpec, ApiError> {
  let Some(allowed) = &auth.services else {
    return loaded;
  };
  match loaded {
    Ok(spec) if task_in_scope(allowed, &spec) => Ok(spec),
    _ => Err(token_scope::forbidden(&auth.name, allowed, "")),
  }
}

pub fn check_task_reveal(
  auth: &Auth,
  spec: &TaskSpec,
  reveal: bool,
) -> Result<(), crate::api::AppError> {
  if reveal && let Err(e) = crate::tasks::need_perm(auth, spec) {
    return Err(
      ApiError::new(
        wharf_api_types::ErrorCode::Forbidden,
        "查看完整触发/报到地址需要对应执行权限",
      )
      .with_hint(e.0.message)
      .into(),
    );
  }
  Ok(())
}

pub fn alert_in_scope(
  services: &BTreeSet<String>,
  world: &World,
  custom_rule_service: Option<&str>,
  rule_id: &str,
  subject: Option<&str>,
) -> bool {
  if let Some(svc) = custom_rule_service {
    return services.contains(svc);
  }
  let Some(subj) = subject else {
    return false;
  };
  if let Some(svc) = crate::rules::service_of_subject(rule_id, subj) {
    return services.contains(svc);
  }
  if matches!(rule_id, "domain_down" | "cert_expiring") {
    return world
      .routes
      .get(subj)
      .is_some_and(|r| route_spec_in_scope(services, &r.spec));
  }
  false
}

fn issue_in_scope(
  services: &BTreeSet<String>,
  world: &World,
  issue: &Issue,
) -> bool {
  let Some(subj) = &issue.subject else {
    return false;
  };
  match subj.kind.as_str() {
    "service" => services.contains(&subj.name),
    "route" => world
      .routes
      .get(&subj.name)
      .is_some_and(|r| route_spec_in_scope(services, &r.spec)),
    _ => false,
  }
}

pub fn filter_status(
  services: &BTreeSet<String>,
  world: &World,
  status: &mut Status,
) {
  status.servers.clear();
  status.gateways.clear();
  status.edge_apps.clear();
  status.edge_unmanaged.clear();
  status.bookmarks.clear();
  status.services.retain(|s| services.contains(&s.name));
  status
    .routes
    .retain(|r| route_spec_in_scope(services, &r.spec));
  status.issues.retain(|i| issue_in_scope(services, world, i));
  status.problems = crate::views::problems_text(&status.issues);
  if let Some(u) = &mut status.updates {
    u.services.retain(|k, _| services.contains(k));
    u.pending = None;
  }
  if let Some(h) = &mut status.health {
    filter_doctor(services, world, h);
  }
}

pub fn filter_doctor(
  services: &BTreeSet<String>,
  world: &World,
  report: &mut DoctorReport,
) {
  report.servers.clear();
  report.vendors.clear();
  report.routes.retain(|r| {
    world
      .routes
      .get(&r.hostname)
      .is_some_and(|row| route_spec_in_scope(services, &row.spec))
  });
  report.config.retain(|c| {
    c.subject
      .strip_prefix("服务 ")
      .is_some_and(|n| services.contains(n))
      || c
        .subject
        .strip_prefix("路由 ")
        .and_then(|h| world.routes.get(h))
        .is_some_and(|r| route_spec_in_scope(services, &r.spec))
  });
}

pub fn filter_data(services: &BTreeSet<String>, data: &mut DataView) {
  data.services.retain(|s| services.contains(&s.name));
}

pub fn filter_export(services: &BTreeSet<String>, fleet: &mut Fleet) {
  fleet.bookmarks.clear();
  fleet.servers.clear();
  fleet.gateways.clear();
  fleet.edge_apps.clear();
  fleet.services.retain(|k, _| services.contains(k));
  fleet.routes.retain(|r| route_spec_in_scope(services, r));
}

pub fn filter_secrets(
  services: &BTreeSet<String>,
  list: &mut Vec<SecretView>,
) {
  list.retain_mut(|s| {
    if s.managed || s.system.is_some() {
      return false;
    }
    s.used_by.retain(|u| services.contains(u));
    !s.used_by.is_empty()
  });
}

pub fn filter_alerts(
  services: &BTreeSet<String>,
  world: &World,
  alerts: &mut AlertsView,
  history_subjects: &[(String, Option<String>)],
) {
  alerts.rules.retain(|r| {
    crate::rules::is_service_rule(&r.id)
      || matches!(r.id.as_str(), "domain_down" | "cert_expiring")
  });
  alerts.notices.clear();
  alerts.builtin_suppressions.clear();
  alerts.suppressions.clear();
  let custom_map: BTreeMap<String, String> = alerts
    .custom_rules
    .iter()
    .map(|r| (r.name.clone(), r.service.clone()))
    .collect();
  alerts
    .custom_rules
    .retain(|r| services.contains(&r.service));
  alerts
    .service_overrides
    .retain(|o| services.contains(&o.service));
  alerts.firing.retain(|f| {
    alert_in_scope(
      services,
      world,
      custom_map.get(&f.rule).map(String::as_str),
      &f.rule,
      Some(&f.subject),
    )
  });
  let mut idx = 0;
  alerts.history.retain(|h| {
    let keep =
      history_subjects.get(idx).is_some_and(|(rule, subj)| {
        rule == &h.source
          && alert_in_scope(
            services,
            world,
            custom_map.get(rule).map(String::as_str),
            rule,
            subj.as_deref(),
          )
      });
    idx += 1;
    keep
  });
}

pub async fn load_plan_for(
  state: &AppState,
  auth: &Auth,
  id: &str,
) -> Result<Plan, ApiError> {
  let stored = crate::apply::stored_plan(state, id).await?;
  token_scope::require_plan(
    auth,
    &stored.body.plan,
    &stored.body.route_effects,
  )?;
  Ok(stored.body.plan)
}

pub async fn run_in_scope(
  state: &AppState,
  services: &BTreeSet<String>,
  run: &Run,
  scope_services: Option<&[String]>,
) -> bool {
  if !run.plan_id.is_empty() {
    let Ok(stored) =
      crate::apply::stored_plan(state, &run.plan_id).await
    else {
      return false;
    };
    return token_scope::check_plan_scope(
      services,
      &stored.body.plan,
      &stored.body.route_effects,
    )
    .is_ok();
  }
  scope_services.is_some_and(|svcs| {
    !svcs.is_empty() && svcs.iter().all(|s| services.contains(s))
  })
}

async fn load_run_with_scope(
  state: &AppState,
  id: &str,
) -> Result<(Run, Option<Vec<String>>), ApiError> {
  if let Some(pair) = state.runs.get_with_scope(id) {
    return Ok(pair);
  }
  let id = id.to_string();
  let body: Option<String> = state
    .db
    .call({
      let id = id.clone();
      move |c| {
        c.query_row(
          "SELECT body FROM runs WHERE id = ?1",
          params![id],
          |r| r.get(0),
        )
        .optional()
        .map_err(sql_err)
      }
    })
    .await?;
  let body = body.ok_or_else(|| {
    ApiError::not_found(format!("执行记录 {id} 不存在"))
      .suggest("wharf run list")
  })?;
  let stored: StoredRun =
    serde_json::from_str(&body).map_err(json_err)?;
  Ok((stored.run, stored.scope_services))
}

pub async fn load_run_for(
  state: &AppState,
  auth: &Auth,
  id: &str,
) -> Result<Run, ApiError> {
  let (run, scope) = match load_run_with_scope(state, id).await {
    Ok(pair) => pair,
    Err(_) if auth.services.is_some() => {
      return Err(token_scope::forbidden(
        &auth.name,
        auth.services.as_ref().unwrap(),
        "",
      ));
    }
    Err(e) => return Err(e),
  };
  if let Some(allowed) = &auth.services
    && !run_in_scope(state, allowed, &run, scope.as_deref()).await
  {
    return Err(token_scope::forbidden(&auth.name, allowed, ""));
  }
  Ok(run)
}

pub async fn require_run_scope(
  state: &AppState,
  auth: &Auth,
  id: &str,
) -> Result<(), ApiError> {
  let Some(allowed) = &auth.services else {
    return Ok(());
  };
  let Ok((run, scope)) = load_run_with_scope(state, id).await else {
    return Err(token_scope::forbidden(&auth.name, allowed, ""));
  };
  if !run_in_scope(state, allowed, &run, scope.as_deref()).await {
    return Err(token_scope::forbidden(&auth.name, allowed, ""));
  }
  Ok(())
}

pub async fn list_runs_for(
  state: &AppState,
  auth: &Auth,
  limit: u32,
) -> Result<Vec<Run>, ApiError> {
  let Some(allowed) = &auth.services else {
    return crate::apply::list_runs(state, limit).await;
  };
  let fetch_limit = limit.max(200);
  let bodies: Vec<String> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT body FROM runs ORDER BY started_at DESC LIMIT ?1",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![fetch_limit], |r| r.get(0))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  let mut out = Vec::new();
  for body in bodies {
    if out.len() >= limit as usize {
      break;
    }
    let stored: StoredRun =
      serde_json::from_str(&body).map_err(json_err)?;
    let (mut run, scope) = state
      .runs
      .get_with_scope(&stored.run.run_id)
      .unwrap_or((stored.run, stored.scope_services));
    if !run_in_scope(state, allowed, &run, scope.as_deref()).await {
      continue;
    }
    for step in &mut run.steps {
      step.log.clear();
    }
    out.push(run);
  }
  Ok(out)
}

#[cfg(test)]
#[path = "scope_filter_tests.rs"]
mod tests;
