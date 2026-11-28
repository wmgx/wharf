use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  ApiError,
  plan::PlanRequest,
  spec::{Change, Limits, ServiceDefaults, ServiceSpec, Source},
};

use crate::{db, snapshot::Snapshot, world::World};

pub(crate) const KEY: &str = "defaults.global";
const DEFAULT_TIMEZONE: &str = "Asia/Shanghai";

pub(crate) fn load(
  c: &rusqlite::Connection,
) -> Result<ServiceDefaults, ApiError> {
  db::setting(c, KEY)?
    .map(|raw| serde_json::from_str(&raw).map_err(db::json_err))
    .transpose()
    .map(Option::unwrap_or_default)
}

pub(crate) fn validate(
  defaults: &ServiceDefaults,
) -> Result<(), ApiError> {
  let invalid = |field: &str, error: ApiError| {
    ApiError::invalid(format!("默认值 {field} 无效"))
      .with_hint(error.hint.unwrap_or(error.message))
  };
  if let Some(timezone) = &defaults.timezone {
    crate::config_api::validate_container_timezone(timezone)
      .map_err(|e| invalid("timezone", e))?;
  }
  if let Some(log) = &defaults.log_max {
    log.validate().map_err(|e| invalid("log_max", e))?;
  }
  for (field, value, flag) in [
    ("memory_mb", defaults.limits.memory_mb, "--unset-memory"),
    ("cpu_milli", defaults.limits.cpu_milli, "--unset-cpus"),
    ("pids", defaults.limits.pids, "--unset-pids"),
  ] {
    if value == Some(0) {
      return Err(
        ApiError::invalid(format!("默认值 {field} 无效"))
          .with_hint(format!("填写正数，或用 {flag} 清除此项")),
      );
    }
  }
  for (field, mut value) in [
    (
      "memory_mb",
      Limits {
        memory_mb: defaults.limits.memory_mb,
        ..Default::default()
      },
    ),
    (
      "cpu_milli",
      Limits {
        cpu_milli: defaults.limits.cpu_milli,
        ..Default::default()
      },
    ),
  ] {
    crate::world::validate_limits(&mut value)
      .map_err(|e| invalid(field, e))?;
  }
  Ok(())
}

fn fill(
  spec: &mut ServiceSpec,
  template: &ServiceDefaults,
) -> ServiceDefaults {
  if matches!(spec.source, Source::Compose { .. }) {
    return ServiceDefaults::default();
  }
  let limits = spec.limits.clone().unwrap_or_default();
  let inherited = ServiceDefaults {
    timezone: template.timezone.clone().filter(|_| {
      spec.timezone.is_none() && !spec.env.contains_key("TZ")
    }),
    log_max: template.log_max.filter(|_| spec.log_max.is_none()),
    limits: Limits {
      memory_mb: template
        .limits
        .memory_mb
        .filter(|_| limits.memory_mb.is_none()),
      cpu_milli: template
        .limits
        .cpu_milli
        .filter(|_| limits.cpu_milli.is_none()),
      pids: template.limits.pids.filter(|_| limits.pids.is_none()),
    },
  };
  if let Some(timezone) = &inherited.timezone {
    spec.timezone = Some(timezone.clone());
  }
  if let Some(log) = inherited.log_max {
    spec.log_max = Some(log);
  }
  if !inherited.limits.is_empty() {
    spec.limits = Some(Limits {
      memory_mb: limits.memory_mb.or(inherited.limits.memory_mb),
      cpu_milli: limits.cpu_milli.or(inherited.limits.cpu_milli),
      pids: limits.pids.or(inherited.limits.pids),
    });
  }
  inherited
}

pub(crate) fn matching(
  frozen: &ServiceDefaults,
  spec: &ServiceSpec,
) -> ServiceDefaults {
  if matches!(spec.source, Source::Compose { .. }) {
    return ServiceDefaults::default();
  }
  let limits = spec.limits.as_ref();
  ServiceDefaults {
    timezone: frozen.timezone.clone().filter(|tz| {
      Some(tz) == spec.timezone.as_ref()
        && !spec.env.contains_key("TZ")
    }),
    log_max: frozen.log_max.filter(|log| Some(*log) == spec.log_max),
    limits: Limits {
      memory_mb: frozen
        .limits
        .memory_mb
        .filter(|&n| limits.and_then(|l| l.memory_mb) == Some(n)),
      cpu_milli: frozen
        .limits
        .cpu_milli
        .filter(|&n| limits.and_then(|l| l.cpu_milli) == Some(n)),
      pids: frozen
        .limits
        .pids
        .filter(|&n| limits.and_then(|l| l.pids) == Some(n)),
    },
  }
}

pub(crate) fn prepare(
  request: &mut PlanRequest,
  snap: &Snapshot,
) -> BTreeMap<String, ServiceDefaults> {
  let current = &snap.world;
  let timezone = snap
    .container_timezone
    .as_deref()
    .unwrap_or(DEFAULT_TIMEZONE);
  let template = |server: &str,
                  updates: &BTreeMap<
    String,
    Option<ServiceDefaults>,
  >| {
    let local = match updates.get(server) {
      Some(local) => local.as_ref(),
      None => current
        .servers
        .get(server)
        .and_then(|s| s.settings.defaults.as_ref()),
    };
    let mut effective = local
      .cloned()
      .unwrap_or_default()
      .with_fallback(&snap.global_defaults);
    if matches!(effective.timezone.as_deref(), None | Some("default"))
    {
      effective.timezone = Some(timezone.into());
    }
    effective
  };
  let mut frozen = BTreeMap::new();
  if let Some(fleet) =
    request.fleet.as_mut().or(request.partial.as_mut())
  {
    let updates = fleet
      .servers
      .iter()
      .map(|(name, settings)| {
        (name.clone(), settings.defaults.clone())
      })
      .collect();
    for (name, spec) in &mut fleet.services {
      if request.no_defaults {
        frozen.insert(name.clone(), ServiceDefaults::default());
      } else if let Some(row) = current.services.get(name) {
        fill(spec, &row.frozen_defaults);
      } else {
        let effective = template(&spec.server, &updates);
        frozen.insert(name.clone(), fill(spec, &effective));
      }
    }
  } else {
    let updates = request
      .changes
      .iter()
      .filter_map(|change| match change {
        Change::UpdateServer { name, settings } => {
          Some((name.clone(), settings.defaults.clone()))
        }
        _ => None,
      })
      .collect();
    let mut existing: BTreeSet<_> =
      current.services.keys().cloned().collect();
    for change in &mut request.changes {
      match change {
        Change::UpsertService {
          name,
          spec,
          adopt,
          no_defaults,
          ..
        } => {
          let new = existing.insert(name.clone());
          if *no_defaults || adopt.is_some() {
            frozen.remove(name);
          } else if new {
            let effective = template(&spec.server, &updates);
            frozen.insert(name.clone(), fill(spec, &effective));
          }
        }
        Change::RemoveService { name, .. } => {
          existing.remove(name);
          frozen.remove(name);
        }
        _ => {}
      }
    }
  }
  frozen
}

pub(crate) fn finish(
  world: &mut World,
  snap: &Snapshot,
  frozen: BTreeMap<String, ServiceDefaults>,
) {
  let timezone = snap
    .container_timezone
    .as_deref()
    .unwrap_or(DEFAULT_TIMEZONE);
  for row in world.services.values_mut() {
    match row.spec.timezone.as_deref() {
      Some("default")
        if !matches!(row.spec.source, Source::Compose { .. }) =>
      {
        row.spec.timezone = Some(timezone.into())
      }
      Some("off") => row.spec.timezone = None,
      _ => {}
    }
  }
  for (name, values) in frozen {
    if let Some(row) = world.services.get_mut(&name) {
      row.frozen_defaults = matching(&values, &row.spec);
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Mutex};

  use axum::{
    Json,
    extract::{Path, State},
  };
  use serde_json::{Value, json};
  use wharf_api_types::{ErrorCode, agent::AgentOp, view::Perm};

  use super::*;
  use crate::{
    config_api,
    host_access::tests::auth,
    planner::{self, Planned, Step},
    state::AppState,
  };

  async fn patch(
    state: &Arc<AppState>,
    value: Value,
  ) -> crate::api::ApiResult<wharf_api_types::view::ConfigItemView>
  {
    config_api::set(
      State(state.clone()),
      auth([Perm::Admin], false),
      Path(KEY.into()),
      Json(value),
    )
    .await
    .map(|Json(item)| item)
    .map_err(|error| error.0)
  }

  fn write(plan: &Planned, service: &str) -> (Value, Value) {
    plan
      .writes
      .iter()
      .find_map(|write| match write {
        db::Write::Upsert {
          kind,
          name,
          spec,
          meta,
        } if kind == "service" && name == service => {
          Some((spec.clone(), meta.clone()))
        }
        _ => None,
      })
      .unwrap()
  }

  #[tokio::test]
  async fn defaults_freeze_new_service_and_keep_repeated_fleet_empty()
  {
    let state = crate::rules::tests::test_state();
    state
      .db
      .call(|c| {
        db::apply_write(
          c,
          &db::Write::Upsert {
            kind: "server".into(),
            name: "s1".into(),
            spec: json!({}),
            meta: json!({}),
          },
        )
      })
      .await
      .unwrap();
    patch(&state, json!({"timezone":"UTC","log_max":{"max_bytes":5242880,"max_files":2},
      "limits":{"memory_mb":128,"cpu_milli":300,"pids":64}})).await.unwrap();

    let live = Arc::new(Mutex::new(Vec::<Value>::new()));
    let observed = live.clone();
    state.hub.mock_agent("s1", false, move |op| match op {
      AgentOp::ProjectStatus { .. } => {
        Ok(json!(*observed.lock().unwrap()))
      }
      AgentOp::ResolveImages(job) => {
        Ok(json!(job.images.into_iter().map(|image| json!({
        "image":image,"digest":format!("sha256:{}", "a".repeat(64))
      })).collect::<Vec<_>>()))
      }
      _ => panic!("计划期间只能查询镜像和项目状态"),
    });
    let request: PlanRequest = serde_json::from_value(json!({"partial":{
      "servers":{"s1":{"defaults":{"limits":{"memory_mb":256}}}},
      "services":{"first":{"server":"s1","source":{"image":"fixture:1"},"limits":{"cpu_milli":500}}}
    }})).unwrap();
    let planned =
      planner::make_plan(&state, request.clone()).await.unwrap();
    let (first, meta) = write(&planned, "first");
    assert_eq!(
      first["limits"],
      json!({"memory_mb":256,"cpu_milli":500,"pids":64})
    );
    assert_eq!(first["timezone"], "UTC");
    assert_eq!(first["log_max"]["max_files"], 2);
    assert_eq!(
      meta["frozen_defaults"]["limits"],
      json!({"memory_mb":256,"pids":64})
    );
    let hash = planned
      .steps
      .iter()
      .find_map(|step| match &step.step {
        Step::ServiceUp {
          service, expect, ..
        } if service == "first" => expect.clone(),
        _ => None,
      })
      .unwrap();

    patch(
      &state,
      json!({"timezone":"Asia/Tokyo","limits":{"pids":null}}),
    )
    .await
    .unwrap();
    state
      .db
      .call(move |c| {
        for write in planned.writes {
          db::apply_write(c, &write)?;
        }
        Ok(())
      })
      .await
      .unwrap();
    *live.lock().unwrap() = vec![
      json!({"project":"first","hash":hash,
      "containers":[{"service":"first","name":"first-1","state":"running"}]}),
    ];
    let again = planner::make_plan(&state, request).await.unwrap();
    assert!(
      again.writes.is_empty()
        && again.steps.is_empty()
        && again.plan.items.is_empty()
    );

    let next: PlanRequest = serde_json::from_value(json!({"changes":[
      {"op":"upsert_service","name":"second","spec":{"server":"s1","source":{"image":"fixture:1"}}},
      {"op":"upsert_service","name":"opted-out","no_defaults":true,
        "spec":{"server":"s1","source":{"image":"fixture:1"},"limits":{"cpu_milli":500}}},
      {"op":"upsert_service","name":"explicit-tz",
        "spec":{"server":"s1","source":{"image":"fixture:1"},"env":{"TZ":""}}},
      {"op":"upsert_service","name":"raw","spec":{"server":"s1",
        "source":{"compose":{"content":"services: {raw: {image: fixture:1}}"}}}}
    ]})).unwrap();
    let plan = planner::make_plan(&state, next).await.unwrap();
    let (second, _) = write(&plan, "second");
    assert_eq!(second["timezone"], "Asia/Tokyo");
    assert_eq!(
      second["limits"],
      json!({"memory_mb":256,"cpu_milli":300})
    );
    let (opted_out, meta) = write(&plan, "opted-out");
    assert_eq!(opted_out["limits"], json!({"cpu_milli":500}));
    assert!(opted_out.get("timezone").is_none());
    assert!(meta.get("frozen_defaults").is_none());
    let (explicit, _) = write(&plan, "explicit-tz");
    assert_eq!(explicit["env"]["TZ"], "");
    assert!(explicit.get("timezone").is_none());
    let (raw, meta) = write(&plan, "raw");
    assert!(
      raw.get("limits").is_none() && raw.get("timezone").is_none()
    );
    assert!(meta.get("frozen_defaults").is_none());
  }

  #[tokio::test]
  async fn invalid_defaults_patch_keeps_saved_template() {
    let state = crate::rules::tests::test_state();
    let original = patch(
      &state,
      json!({"timezone":"UTC","limits":{"memory_mb":128,"pids":32}}),
    )
    .await
    .unwrap();
    let error = patch(&state, json!({"timezone":"Asia/Tokyo","limits":{"memory_mb":1,"pids":null}})).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.message, "默认值 memory_mb 无效");
    assert!(error.hint.unwrap().contains("32 MB"));
    let saved = state.db.call(|c| load(c)).await.unwrap();
    assert_eq!(json!(saved), original.value);
  }
}
