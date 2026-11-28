use serde_json::json;
use wharf_api_types::{
  plan::{Layer, PlanRequest},
  spec::Change,
};

use super::*;

pub(super) fn state() -> Arc<AppState> {
  Arc::new(AppState {
    db: crate::db::Db::memory(),
    hub: Default::default(),
    key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]).into(),
    runs: Default::default(),
    locks: Default::default(),
    public_url: Some("https://wharf.example.test".into()),
    agent_image: String::new(),
    listen_port: 7700,
    data_dir: Default::default(),
    downloads: Default::default(),
    edge_syncing: Default::default(),
  })
}

fn watch() -> LogWatch {
  LogWatch {
    id: "app:test:0".into(),
    project: "app".into(),
    spec: serde_json::from_value(
      json!({ "pattern": "ERROR", "min_count": 3 }),
    )
    .unwrap(),
  }
}

#[test]
fn log_window_counts_and_recovers() {
  let w = watch();
  let mut hits = Hits::default();
  let add = |hits: &mut Hits, at| {
    hits.add(
      LogHit {
        id: w.id.clone(),
        count: 1,
        at,
        lines: vec![],
      },
      at,
    )
  };
  add(&mut hits, MINUTE);
  add(&mut hits, 2 * MINUTE);
  assert_eq!(hits.value(&w, 2 * MINUTE), (-1.0, 2));
  add(&mut hits, 3 * MINUTE);
  assert_eq!(hits.value(&w, 3 * MINUTE), (0.0, 3));
  assert_eq!(hits.value(&w, 7 * MINUTE).1, 1);
  assert_eq!(hits.value(&w, 8 * MINUTE), (-f64::MAX, 0));
}

#[test]
fn invalid_regex_returns_validation_hint() {
  let mut spec: ServiceSpec = serde_json::from_value(json!({
    "source": { "image": "nginx" }, "server": "s1"
  }))
  .unwrap();
  let mut w = watch();
  w.spec.pattern = "(".into();
  w.spec.regex = true;
  spec.log_alerts.push(w.spec);
  assert!(validate(&spec, None).unwrap_err().hint.is_some());
}

#[test]
fn stopped_uses_last_finished_at_and_requires_it() {
  let now = 20 * DAY;
  let container = |days: Option<i64>| -> ContainerInfo {
    serde_json::from_value(json!({
      "service": "web", "name": "web-1", "state": "exited",
      "finished_at": days.and_then(|d| chrono::DateTime::from_timestamp_millis(now - d * DAY)),
    })).unwrap()
  };
  assert_eq!(
    stopped_issue("web", &[container(Some(8))], now)
      .unwrap()
      .level,
    IssueLevel::Info
  );
  assert!(
    stopped_issue(
      "web",
      &[container(Some(8)), container(Some(6))],
      now
    )
    .is_none()
  );
  assert!(
    stopped_issue("web", &[container(Some(8)), container(None)], now)
      .is_none()
  );
  assert!(stopped_issue("web", &[], now).is_none());
}

#[tokio::test]
async fn monitoring_only_plan_skips_deploy_but_heartbeat_changes_compose()
 {
  let state = state();
  let spec: ServiceSpec = serde_json::from_value(json!({
    "server": "s1", "source": { "image": "nginx:latest" },
    "ports": [{ "name": "web", "container": 80, "host": 8080 }]
  }))
  .unwrap();
  let mut world = World::default();
  world.servers.insert(
    "s1".into(),
    crate::world::ServerRow {
      settings: Default::default(),
      version: 1,
    },
  );
  world.services.insert(
    "app".into(),
    ServiceRow {
      instance_id: "svc_fixture".into(),
      spec: spec.clone(),
      host_ports: BTreeMap::from([("web".into(), 8080)]),
      import: None,
      pins: BTreeMap::from([(
        "nginx:latest".into(),
        format!("sha256:{}", "a".repeat(64)),
      )]),
      commit: None,
      version: 1,
    },
  );
  let writes = world.writes_from(&World::default());
  state
    .db
    .call(move |c| {
      for write in &writes {
        crate::db::apply_write(c, write)?;
      }
      Ok(())
    })
    .await
    .unwrap();
  let plan = |spec| {
    crate::planner::make_plan(
      &state,
      PlanRequest {
        changes: vec![Change::UpsertService {
          pins: None,
          commit: None,
          name: "app".into(),
          spec,
          adopt: None,
        }],
        ..PlanRequest::default()
      },
    )
  };
  for changed in [
    ServiceSpec {
      log_alerts: vec![watch().spec],
      ..spec.clone()
    },
    ServiceSpec {
      port_checks: BTreeMap::from([(
        "web".into(),
        PortCheckSpec::Off,
      )]),
      ..spec.clone()
    },
  ] {
    let result = plan(changed).await.unwrap();
    assert_eq!(result.plan.items.len(), 1);
    assert_eq!(result.plan.items[0].layer, Layer::Config);
    assert!(result.steps.is_empty());
  }
  let result = plan(ServiceSpec {
    heartbeat: Some(
      serde_json::from_value(json!({"every_mins": 10})).unwrap(),
    ),
    ..spec.clone()
  })
  .await
  .unwrap();
  assert!(result.steps.iter().any(|s| matches!(
    s.step,
    crate::planner::Step::ServiceUp { .. }
  )));
  let view = serde_json::to_string(&result.plan).unwrap();
  assert!(view.contains("WHARF_HEARTBEAT_URL"));
  assert!(!view.contains("/ping/wh_"));
  assert!(!view.contains("wharf.heartbeat"));
  let writes = result.writes;
  state
    .db
    .call(move |c| {
      for write in &writes {
        crate::db::apply_write(c, write)?;
      }
      Ok(())
    })
    .await
    .unwrap();

  let snap = crate::snapshot::load(&state.db).await.unwrap();
  let enabled = &snap.world.services["app"].spec;
  let previous = enabled.heartbeat.as_ref().unwrap();
  let compose = |spec: &ServiceSpec| {
    heartbeat::compose(
      "services:\n  app: {image: nginx}",
      spec,
      state.public_url.as_deref(),
      true,
    )
    .unwrap()
  };
  for (every_mins, grace_mins) in [(15, 5), (10, 7)] {
    let changed = ServiceSpec {
      heartbeat: Some(
        wharf_api_types::service_checks::HeartbeatSpec {
          every_mins,
          grace_mins,
          token: String::new(),
        },
      ),
      ..enabled.clone()
    };
    let result = plan(changed).await.unwrap();
    assert_eq!(result.plan.items.len(), 1);
    assert_eq!(result.plan.items[0].layer, Layer::Config);
    assert!(result.steps.is_empty());
    let [crate::db::Write::Upsert { spec, .. }] =
      result.writes.as_slice()
    else {
      panic!("expected a service config write")
    };
    let updated: ServiceSpec =
      serde_json::from_value(spec.clone()).unwrap();
    assert_eq!(
      updated.heartbeat.as_ref().unwrap().token,
      previous.token
    );
    assert_eq!(compose(enabled), compose(&updated));
  }

  let disabled = plan(spec).await.unwrap();
  assert!(disabled.steps.iter().any(|s| matches!(
    s.step,
    crate::planner::Step::ServiceUp { .. }
  )));
  assert!(
    !serde_json::to_string(&disabled.plan)
      .unwrap()
      .contains("WHARF_HEARTBEAT_URL")
  );
}

#[test]
fn previous_agent_report_and_service_spec_still_deserialize() {
  let report: wharf_api_types::agent::AgentReport = serde_json::from_value(json!({
    "version":"0.1.0", "hostname":"s1", "os":"linux", "arch":"arm", "data_dir":"/wharf"
  })).unwrap();
  assert!(report.log_hits.is_empty());
  let spec: ServiceSpec = serde_json::from_value(json!({
    "server": "s1", "source": { "image": "nginx" }
  }))
  .unwrap();
  assert!(
    spec.log_alerts.is_empty()
      && spec.port_checks.is_empty()
      && spec.heartbeat.is_none()
  );
}

#[test]
fn unchanged_legacy_check_survives_plan_validation() {
  let mut spec: ServiceSpec = serde_json::from_value(json!({
    "source":{"image":"nginx:1"},"server":"s1",
    "log_alerts":[{"pattern":"fixture","window_mins":1441}],
  }))
  .unwrap();
  let installed = spec.clone();
  assert!(validate(&installed, Some(&installed)).is_ok());
  spec.log_alerts[0].window_mins += 1;
  assert!(validate(&spec, Some(&installed)).is_err());
}

#[tokio::test]
async fn port_deployment_grace_stays_active_with_operation_silence_off()
 {
  let _guard = rules::tests::TEST_LOCK.lock().await;
  rules::tests::reset_memory();
  let state = state();
  let now = now_ms();
  let mut snap = Snapshot::default();
  snap.applied.insert(
    "web".into(),
    serde_json::from_value(json!({
      "hash": "fixture",
      "at": chrono::DateTime::from_timestamp_millis(now).unwrap(),
    }))
    .unwrap(),
  );
  state
    .db
    .call(|c| {
      crate::db::set_setting(
        c,
        "alerts.config",
        Some(r#"{"suppress_ops":{"enabled":false}}"#),
      )
    })
    .await
    .unwrap();
  rules::ensure_loaded(&state).await;
  let guard = state
    .locks
    .acquire(crate::locks::LockSpec::apply(["web".into()]), "部署")
    .unwrap();
  guard.silence_alerts(
    [rules::op_silence::Target::Service("web".into())].into(),
    "部署".into(),
  );
  assert!(!rules::op_silence::service_busy(&state, "web"));
  assert!(deploying(&snap, "web", now + MINUTE));
  assert!(!deploying(&snap, "web", now + 2 * MINUTE));
}
