use std::{collections::BTreeMap, time::Duration};

use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, ProjectState},
  net_probe::NetProbeKind,
  spec::{ServiceSpec, WaitCondition},
  view::{CheckStatus, OpStatus},
};

use crate::{
  planner::{Step, StepPlan},
  snapshot::{self, Snapshot},
  state::AppState,
  world::World,
};

pub(crate) fn require_agent(
  state: &AppState,
  server: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  if spec
    .wait_for
    .values()
    .any(|wait| !matches!(wait, WaitCondition::Service { .. }))
  {
    state.hub.supports_net_probe(server, false)?;
  }
  Ok(())
}

pub(crate) fn validate_steps(
  world: &World,
  steps: &[StepPlan],
) -> Result<(), ApiError> {
  for item in steps {
    let (service, moving) = match &item.step {
      Step::ServiceUp { service, .. }
      | Step::ServiceStart { service, .. } => (service, false),
      Step::VolumeSync { service, .. } => (service, true),
      _ => continue,
    };
    let spec = &world.services[service].spec;
    if spec.stopped {
      continue;
    }
    for dep in
      spec.wait_for.values().filter_map(WaitCondition::service)
    {
      if world.services.get(dep).is_some_and(|row| row.spec.stopped)
        || (moving && steps.iter().any(|step| {
          matches!(&step.step, Step::ServiceUp { service, .. } | Step::ServiceStart { service, .. } if service == dep)
        }))
      {
        return Err(ApiError::invalid(format!("本次计划无法先让服务 {dep} 就绪"))
          .with_hint("分开生成计划，先让依赖可用"));
      }
    }
  }
  Ok(())
}

pub(crate) async fn run(
  state: &AppState,
  world: &World,
  service: &str,
  server: &str,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let spec = &world
    .services
    .get(service)
    .ok_or_else(|| crate::api::service_not_found(service))?
    .spec;
  if spec.stopped || spec.wait_for.is_empty() {
    return Ok(());
  }
  require_agent(state, server, spec)?;
  let deadline = Instant::now()
    + Duration::from_secs(u64::from(
      spec.wait_for_timeout_secs.unwrap_or(120),
    ));
  let mut pending: BTreeMap<_, _> = spec
    .wait_for
    .keys()
    .map(|key| (key, String::from("尚未就绪")))
    .collect();
  let cancelled =
    || ApiError::new(ErrorCode::Cancelled, "已取消启动前等待");
  loop {
    let work = cancel.child_token();
    let _on_drop = work.clone().drop_guard();
    let snap = tokio::select! {
      biased;
      () = cancel.cancelled() => return Err(cancelled()),
      () = sleep_until(deadline) => break,
      snap = snapshot::load(&state.db) => snap?,
    };
    for (key, wait) in &spec.wait_for {
      let remaining =
        deadline.saturating_duration_since(Instant::now());
      let timeout = remaining.min(Duration::from_secs(5));
      let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(cancelled()),
        () = sleep_until(deadline) => break,
        result = check(state, &snap, service, server, wait, timeout, &work) => result,
      };
      match result {
        Ok((true, _)) => {
          pending.remove(key);
        }
        Ok((false, status)) => {
          pending.insert(key, status);
        }
        Err(e)
          if matches!(
            e.code,
            ErrorCode::InvalidInput | ErrorCode::Cancelled
          ) || (e.code == ErrorCode::Conflict
            && e.hint.is_some()) =>
        {
          return Err(e);
        }
        Err(e) => {
          pending
            .insert(key, crate::log_redact::redact_text(&e.message));
        }
      }
    }
    if cancel.is_cancelled() {
      return Err(cancelled());
    }
    if pending.is_empty() && Instant::now() < deadline {
      return Ok(());
    }
    if Instant::now() >= deadline {
      break;
    }
    tokio::select! {
      () = cancel.cancelled() => return Err(cancelled()),
      () = sleep_until(deadline.min(Instant::now() + Duration::from_secs(5))) => {}
    }
  }
  let missing = pending
    .into_iter()
    .map(|(key, status)| format!("{key}：{status}"))
    .collect::<Vec<_>>()
    .join("；");
  Err(ApiError::new(ErrorCode::Timeout, format!("服务 {service} 启动前等待超时，未就绪：{missing}"))
    .with_hint("用 wharf doctor --service 或 wharf server probe 检查依赖，修好后续跑"))
}

#[allow(clippy::too_many_arguments)]
async fn check(
  state: &AppState,
  snap: &Snapshot,
  service: &str,
  server: &str,
  wait: &WaitCondition,
  timeout: Duration,
  cancel: &CancellationToken,
) -> Result<(bool, String), ApiError> {
  match wait {
    WaitCondition::Service { service } => {
      service_ready(state, snap, service, timeout, cancel).await
    }
    WaitCondition::Dns { host } => {
      crate::net_probe::wait_probe(
        state,
        server,
        NetProbeKind::Dns,
        host.clone(),
        timeout,
        cancel,
      )
      .await
    }
    WaitCondition::Tcp { service: dep, port } => {
      let net = snap.net(&snap.world);
      let target = match crate::refs::probe_address(
        service,
        &snap.world,
        &net,
        dep,
        port,
      ) {
        Ok(target) => target,
        Err(e) => return Ok((false, e.message)),
      };
      crate::net_probe::wait_probe(
        state,
        server,
        NetProbeKind::Tcp,
        target,
        timeout,
        cancel,
      )
      .await
    }
  }
}

async fn service_ready(
  state: &AppState,
  snap: &Snapshot,
  service: &str,
  timeout: Duration,
  cancel: &CancellationToken,
) -> Result<(bool, String), ApiError> {
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| crate::api::service_not_found(service))?;
  if row.spec.stopped {
    return Ok((false, "已停止".into()));
  }
  let Some(server) = snapshot::service_runtime_server(snap, service)
    .filter(|server| *server == row.spec.server)
  else {
    return Ok((false, "迁移尚未就绪".into()));
  };
  if snap
    .ops
    .get(service)
    .is_some_and(|op| op.status == OpStatus::Running)
  {
    return Ok((false, "运行操作尚未完成".into()));
  }
  let net = snap.net(&snap.world);
  let project: Vec<ProjectState> = state
    .hub
    .call(
      server,
      AgentOp::ProjectStatus {
        projects: vec![service.into()],
        include_links: false,
      },
      timeout,
      None,
      cancel,
    )
    .await?;
  let live = BTreeMap::from([(
    server.into(),
    Ok(
      project
        .into_iter()
        .map(|p| (p.project.clone(), p))
        .collect(),
    ),
  )]);
  let Some(mut view) = crate::views::service_view(
    state,
    snap,
    &net,
    service,
    Some(&live),
    &Default::default(),
  ) else {
    return Ok((false, "还查不到现状".into()));
  };
  if view
    .status
    .as_ref()
    .is_none_or(|status| status.desired_hash.is_none())
  {
    return Ok((false, "还没有可比对的部署指纹".into()));
  }
  let refresh_observations =
    |view: &mut wharf_api_types::view::ServiceView| {
      view.monitor =
        crate::monitor::last_for(state, snap, service, row);
      view.port_checks =
        crate::service_monitor::port_views(state, snap, service, row);
    };
  refresh_observations(&mut view);
  if view.needs_service_probe() {
    if let Some(monitor) =
      crate::monitor::doctor_monitor(state, snap, service, row).await
      && monitor.status != CheckStatus::Ok
    {
      return Ok((false, monitor.detail));
    }
    if view.port_checks_supported != Some(false)
      && let Some(port) = crate::service_monitor::doctor_ports(
        state, snap, service, row,
      )
      .await
      .into_iter()
      .find(|check| check.status != CheckStatus::Ok)
    {
      return Ok((false, port.detail));
    }
    refresh_observations(&mut view);
  }
  Ok(view.service_ready())
}

#[tokio::test]
async fn wait_for_unready_service_observes_cancellation() {
  let state = crate::rules::tests::test_state();
  let world = World::from_rows(vec![crate::db::ResourceRow {
    kind: "service".into(),
    name: "app".into(),
    version: 1,
    spec: serde_json::json!({"server":"s1","source":{"image":"app:1"},
      "wait_for":{"db":{"kind":"service","service":"db"}}}),
    meta: serde_json::json!({}),
  }])
  .unwrap();
  let stop = CancellationToken::new();
  let cancel = stop.clone();
  let (result, ()) = tokio::join!(
    run(&state, &world, "app", "s1", &stop),
    async move {
      tokio::task::yield_now().await;
      cancel.cancel();
    }
  );
  assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
}

#[tokio::test]
async fn waits_until_health_tcp_and_dns_are_ready_with_stale_reach_failure()
 {
  use serde_json::json;
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };
  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    for (kind, name, spec, meta) in [
      ("server", "s1", json!({"private_addr":{"ip":"100.64.0.1","network":"tailscale"}}), json!({})),
      ("server", "s2", json!({"private_addr":{"ip":"100.64.0.2","network":"tailscale"}}), json!({})),
      ("service", "z-db", json!({"server":"s2","source":{"image":"db:1"},
        "ports":[{"name":"sql","container":5432,"host":22000}]}), json!({"host_ports":{"sql":22000}})),
      ("service", "a-app", json!({"server":"s1","source":{"image":"app:1"},
        "wait_for":{"service":{"kind":"service","service":"z-db"},
         "tcp":{"kind":"tcp","service":"z-db","port":"sql"},
         "dns":{"kind":"dns","host":"check.example.test"}}}), json!({})),
    ] {
      crate::db::apply_write(c, &crate::db::Write::Upsert { kind:kind.into(), name:name.into(), spec, meta })?;
    }
    crate::db::set_reach(c, &[("s1".into(), "s2".into(), false)], crate::db::now_ms())?;
    Ok(())
  }).await.unwrap();
  let snap = snapshot::load(&state.db).await.unwrap();
  let net = snap.net(&snap.world);
  let (_, hash) = snapshot::service_resolved(
    &snap.world,
    &net,
    "z-db",
    &Default::default(),
  )
  .unwrap();
  let rounds = Arc::new(AtomicUsize::new(0));
  let count = rounds.clone();
  state.hub.mock_agent("s2", false, move |op| match op {
    AgentOp::ProjectStatus { projects, .. } => {
      assert_eq!(projects, ["z-db"]);
      let health = if count.fetch_add(1, Ordering::SeqCst) == 0 { "starting" } else { "healthy" };
      Ok(json!([{"project":"z-db","hash":hash,"containers":[
        {"service":"z-db","name":"z-db-1","state":"running","health":health}]}]))
    }
    _ => panic!("等待目标只需提供运行状态"),
  });
  state.hub.mock_agent("s1", false, move |op| match op {
    AgentOp::NetProbe(job) if job.kind == NetProbeKind::Tcp => {
      assert_eq!(job.target, "100.64.0.2:22000");
      Ok(json!({"elapsed_ms":0,"tcp":{"remote_addr":job.target,"elapsed_ms":0}}))
    }
    AgentOp::NetProbe(job) => {
      assert_eq!(job.kind, NetProbeKind::Dns);
      assert_eq!(job.target, "check.example.test");
      Ok(json!({"elapsed_ms":0,"dns":{"ips":["203.0.113.1"],
        "elapsed_ms":0,"nameservers":[],"search":[]}}))
    }
    _ => panic!("等待前不允许启动项目或触发其他操作"),
  });
  state.hub.enable_mock_net_probe("s1");
  tokio::time::timeout(
    Duration::from_secs(15),
    run(
      &state,
      &snap.world,
      "a-app",
      "s1",
      &CancellationToken::new(),
    ),
  )
  .await
  .unwrap()
  .unwrap();
  assert_eq!(rounds.load(Ordering::SeqCst), 2);
}
