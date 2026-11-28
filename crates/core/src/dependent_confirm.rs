use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{
    Action, Dependent, DependentDisposition, Layer, Plan, PlanItem,
  },
};

use crate::{
  catalog::{dependent_visible, direct_dependents},
  db::{ResourceRow, Write},
  planner::{Step, StepPlan},
  state::AppState,
  world::World,
};

fn stale() -> ApiError {
  ApiError::new(ErrorCode::PlanStale, "停删服务的依赖影响已变更")
    .with_hint("重新生成并确认计划")
}

fn impacts(
  current: &World,
  desired: &World,
  name: &str,
) -> Vec<Dependent> {
  use DependentDisposition::*;
  let before = direct_dependents(current, name);
  let after = direct_dependents(desired, name);
  before
    .union(&after)
    .cloned()
    .map(|mut dep| {
      dep.disposition = if after.contains(&dep) {
        let stopping = dep
          .address
          .strip_prefix("service/")
          .and_then(|name| {
            desired.services.get(name).zip(current.services.get(name))
          })
          .is_some_and(|(new, old)| {
            new.spec.stopped && !old.spec.stopped
          });
        if stopping { Stopping } else { Retained }
      } else {
        let retained =
          dep.address.split_once('/').is_some_and(|(kind, name)| {
            match kind {
              "service" => desired.services.contains_key(name),
              "route" => desired.routes.contains_key(name),
              "gateway" => desired.gateways.contains_key(name),
              _ => false,
            }
          });
        if retained { Detached } else { Removed }
      };
      dep
    })
    .collect()
}

pub(crate) fn mark(
  current: &World,
  desired: &World,
  items: &mut [PlanItem],
  steps: &[StepPlan],
) {
  for item in items {
    let Some(name) = item.address.strip_prefix("service/") else {
      continue;
    };
    let remove = !desired.services.contains_key(name)
      && (item.action == Action::Delete || steps.iter().any(|step| {
        step.items.contains(&item.id)
          && matches!(&step.step, Step::ServiceDown { service, .. } if service == name)
      }));
    let stop = desired
      .services
      .get(name)
      .is_some_and(|row| row.spec.stopped)
      && ((item.layer == Layer::Config
        && current
          .services
          .get(name)
          .is_some_and(|row| !row.spec.stopped))
        || steps.iter().any(|step| {
          step.items.contains(&item.id)
            && matches!(&step.step, Step::ServiceStop { service }
            | Step::ServiceUp { service, .. } if service == name)
        }));
    if remove || stop {
      item.dependents = impacts(current, desired, name);
      item.stopping_service = stop;
    }
  }
}

pub(crate) fn project(
  plan: &mut Plan,
  scope: Option<&BTreeSet<String>>,
  routes: &BTreeSet<String>,
) {
  let Some(allowed) = scope else { return };
  for item in &mut plan.items {
    let count = item.dependents.len();
    item.dependents.retain(|dep| {
      dep
        .address
        .strip_prefix("service/")
        .is_some_and(|name| allowed.contains(name))
        || dep
          .address
          .strip_prefix("route/")
          .is_some_and(|name| routes.contains(name))
    });
    item.hidden_dependents += count - item.dependents.len();
  }
}

pub(crate) fn visible_routes(
  world: &World,
  plan: &Plan,
  allowed: &BTreeSet<String>,
) -> BTreeSet<String> {
  let mut routes = world
    .routes
    .keys()
    .filter(|host| {
      dependent_visible(world, allowed, &format!("route/{host}"))
    })
    .cloned()
    .collect::<BTreeSet<_>>();
  for item in &plan.items {
    if let Some(host) = item.address.strip_prefix("route/")
      && item.layer == Layer::Config
    {
      if crate::token_scope::route_in_scope(allowed, host, item) {
        routes.insert(host.into());
      } else {
        routes.remove(host);
      }
    }
  }
  routes
}

pub(crate) async fn check_apply(
  state: &AppState,
  plan: &Plan,
  steps: &[StepPlan],
  writes: &[Write],
) -> Result<(), ApiError> {
  if !plan
    .items
    .iter()
    .any(|item| item.address.starts_with("service/"))
  {
    return Ok(());
  }
  let changes = writes.to_vec();
  let (before, after) = state
    .db
    .call(move |c| {
      let rows = crate::db::all_resources(c)?;
      let mut after = rows
        .iter()
        .cloned()
        .map(|row| ((row.kind.clone(), row.name.clone()), row))
        .collect::<BTreeMap<_, _>>();
      for write in changes {
        match write {
          Write::Upsert {
            kind,
            name,
            spec,
            meta,
          } => {
            after.insert(
              (kind.clone(), name.clone()),
              ResourceRow {
                kind,
                name,
                spec,
                meta,
                version: 0,
              },
            );
          }
          Write::Delete { kind, name } => {
            after.remove(&(kind, name));
          }
        }
      }
      Ok((
        World::from_rows(rows)?,
        World::from_rows(after.into_values().collect())?,
      ))
    })
    .await?;
  let mut checked = plan.items.clone();
  for item in &mut checked {
    item.dependents.clear();
    item.stopping_service = false;
  }
  mark(&before, &after, &mut checked, steps);
  for (current, original) in checked.iter().zip(&plan.items) {
    if current.dependents != original.dependents
      || (current.stopping_service
        && !current.dependents.is_empty()
        && (!original.stopping_service
          || !plan.needs_confirm.contains(&original.address)))
    {
      return Err(stale());
    }
  }
  Ok(())
}

pub(crate) fn check_retry(
  world: &World,
  plan: &Plan,
  steps: &[StepPlan],
  instances: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  for step in steps {
    let (name, removing) = match &step.step {
      Step::ServiceStop { service } => (service, false),
      Step::ServiceDown { service, .. }
        if !world.services.contains_key(service) =>
      {
        (service, true)
      }
      Step::ServiceUp { service, .. }
        if world
          .services
          .get(service)
          .is_some_and(|row| row.spec.stopped) =>
      {
        (service, false)
      }
      _ => continue,
    };
    let deps = direct_dependents(world, name);
    if deps.is_empty() {
      continue;
    }
    let address = format!("service/{name}");
    let known = |address: &str| {
      address.strip_prefix("service/").is_none_or(|name| {
        world.services.get(name).is_some_and(|row| {
          instances.get(address) == Some(&row.instance_id)
        })
      })
    };
    if removing
      || !plan.needs_confirm.contains(&address)
      || !known(&address)
    {
      return Err(stale());
    }
    if deps.iter().any(|dep| {
      !known(&dep.address)
        || !plan.items.iter().any(|item| {
          step.items.contains(&item.id)
            && item.address == address
            && item.stopping_service
            && item.dependents.iter().any(|old| {
              old.address == dep.address
                && old.field == dep.field
                && old.kind == dep.kind
                && matches!(
                  old.disposition,
                  DependentDisposition::Retained
                    | DependentDisposition::Stopping
                )
            })
        })
    }) {
      return Err(stale());
    }
  }
  Ok(())
}

#[test]
fn retry_accepts_confirmed_consumer_created_in_same_plan() {
  use serde_json::json;
  let service = |name: &str, spec| ResourceRow {
    kind: "service".into(),
    name: name.into(),
    version: 1,
    spec,
    meta: json!({"instance_id": format!("fixture-{name}")}),
  };
  let db = json!({"server":"s1","source":{"image":"db:1"}});
  let before =
    World::from_rows(vec![service("db", db.clone())]).unwrap();
  let mut stopped = db;
  stopped["stopped"] = json!(true);
  let mut after = World::from_rows(vec![
    service("db", stopped),
    service(
      "app",
      json!({"server":"s1","source":{"image":"app:1"},
      "env":{"DB":"[[@db]]"}}),
    ),
  ])
  .unwrap();
  let mut plan: Plan = serde_json::from_value(json!({
    "plan_id":"p_test", "status":"applied","created_at":"2026-01-01T00:00:00Z",
    "expires_at":"2026-01-01T00:01:00Z","base_versions":{},"suggest":[],
    "needs_confirm":["service/db"],
    "items":[{"id":1,"address":"service/db","layer":"container","action":"update","reason":"停止"}],
  })).unwrap();
  let steps = [StepPlan {
    items: vec![1],
    title: "停止 db".into(),
    step: Step::ServiceStop {
      service: "db".into(),
    },
  }];
  mark(&before, &after, &mut plan.items, &steps);
  let committed_instances = after.service_instances();
  check_retry(&after, &plan, &steps, &committed_instances).unwrap();
  after.services.get_mut("app").unwrap().instance_id =
    "fixture-replacement".into();
  assert_eq!(
    check_retry(&after, &plan, &steps, &committed_instances)
      .unwrap_err()
      .code,
    ErrorCode::PlanStale,
  );
}

#[test]
fn stopping_requires_confirmation_and_hides_out_of_scope_dependents()
{
  let current = World::from_rows(vec![
    ResourceRow {
      kind: "service".into(), name: "db".into(), version: 1,
      spec: serde_json::json!({"server":"s1","source":{"image":"db:1"}}), meta: serde_json::json!({}),
    },
    ResourceRow {
      kind: "service".into(), name: "consumer".into(), version: 1,
      spec: serde_json::json!({"server":"s1","source":{"image":"app:1"},
        "env":{"DB":"[[@db]]"}, "wait_for":{"db":{"kind":"service","service":"db"}}}),
      meta: serde_json::json!({}),
    },
  ]).unwrap();
  let mut desired = current.clone();
  desired.services.get_mut("db").unwrap().spec.stopped = true;
  let mut plan: Plan = serde_json::from_value(serde_json::json!({
    "plan_id":"p_test", "status":"pending", "created_at":"2026-01-01T00:00:00Z",
    "expires_at":"2026-01-01T00:01:00Z", "base_versions":{}, "suggest":[],
    "items":[{"id":1,"address":"service/db","layer":"config","action":"update","reason":"停止"}],
  })).unwrap();
  mark(&current, &desired, &mut plan.items, &[]);
  assert!(plan.items[0].needs_confirm());
  assert_eq!(plan.items[0].dependents.len(), 2);
  project(
    &mut plan,
    Some(&BTreeSet::from(["db".into()])),
    &BTreeSet::new(),
  );
  assert!(plan.items[0].needs_confirm());
  assert_eq!(plan.items[0].hidden_dependents, 2);
  assert!(plan.items[0].dependents.is_empty());
}
