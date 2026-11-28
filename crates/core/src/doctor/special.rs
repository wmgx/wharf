use super::{
  DoctorScope, RouteChecks, check, container_of_service,
  gateway_check, link,
};
use crate::doctor_diagnose::{self, Target};
use wharf_api_types::{
  spec::LinkMode,
  view::{CheckStatus, DoctorCheck},
};

pub(super) async fn checks(
  ctx: &RouteChecks<'_>,
  scope: &DoctorScope,
) -> Vec<DoctorCheck> {
  match scope {
    DoctorScope::Service(name) => service(ctx, name).await,
    DoctorScope::Server(name) => server(ctx, name).await,
    _ => vec![],
  }
}

async fn service(
  ctx: &RouteChecks<'_>,
  name: &str,
) -> Vec<DoctorCheck> {
  let world = &ctx.snap.world;
  let row = &world.services[name];
  let container = container_of_service(world, ctx.live, name);
  let (mut containers, ports, monitor, forwards) = tokio::join!(
    diagnose_containers(ctx, [(name, container)]),
    crate::service_monitor::doctor_ports(ctx.s, name, row),
    crate::monitor::doctor_monitor(ctx.s, ctx.snap, name, row),
    layer4(ctx, name),
  );
  for c in &mut containers {
    c.subject = name.into();
  }
  containers.extend(ports);
  containers.extend(monitor);
  containers.extend(forwards);
  containers
}

async fn layer4(
  ctx: &RouteChecks<'_>,
  service: &str,
) -> Vec<DoctorCheck> {
  let world = &ctx.snap.world;
  let forwards = world.gateways.iter().flat_map(|(name, row)| {
    row
      .spec
      .layer4
      .iter()
      .filter(move |f| f.service.as_deref() == Some(service))
      .map(move |f| (name, &row.spec, f))
  });
  futures_util::future::join_all(forwards.map(
    |(name, gw, f)| async move {
      let gateway = gateway_check(ctx.live, name, &gw.server);
      let gw_label = format!("网关 {name} :{}", f.listen);
      let gateway = check(
        "layer4",
        service,
        gateway.status,
        format!("{gw_label}：{}", gateway.detail),
      );
      let upstream = if f.udp {
        check(
          "layer4",
          service,
          CheckStatus::Skip,
          format!("{gw_label}：UDP 四层转发暂不做 TCP 握手探测"),
        )
      } else {
        let port = world.service_port(service, f.port.as_deref());
        let cross = gw.server != world.services[service].spec.server;
        let result = port.and_then(|port| {
          if matches!(
            crate::link::choose(
              world,
              ctx.net,
              gw,
              service,
              port,
              LinkMode::Auto
            ),
            Ok(crate::link::Choice::Tunnel)
          ) {
            return None;
          }
          Some(crate::render::upstream(
            world,
            ctx.net,
            gw,
            service,
            port,
            LinkMode::Auto,
          ))
        });
        let (status, detail) = match result {
          Some(Ok(addr)) => {
            let (check, _) =
              link(ctx.s, &gw.server, &addr, cross).await;
            (check.status, check.detail)
          }
          Some(Err(e)) => (CheckStatus::Bad, e.message),
          None => (CheckStatus::Bad, "没找到可直连的四层上游".into()),
        };
        check(
          "layer4",
          service,
          status,
          format!("{gw_label}：{detail}"),
        )
      };
      [gateway, upstream]
    },
  ))
  .await
  .into_iter()
  .flatten()
  .collect()
}

async fn server(
  ctx: &RouteChecks<'_>,
  name: &str,
) -> Vec<DoctorCheck> {
  let world = &ctx.snap.world;
  let mut checks = vec![];
  if let Some(disk) = ctx
    .snap
    .agent(name)
    .and_then(|a| a.report.as_ref())
    .and_then(|r| r.disk)
  {
    let gib = 1u64 << 30;
    let status = if disk.free < disk.total / 10 || disk.free < 2 * gib
    {
      CheckStatus::Bad
    } else if disk.free < disk.total / 5 || disk.free < 5 * gib {
      CheckStatus::Warn
    } else {
      CheckStatus::Ok
    };
    checks.push(check(
      "disk",
      name,
      status,
      format!("剩余 {:.1} GiB", disk.free as f64 / gib as f64),
    ));
  }
  if let Some(ms) = crate::clock::offset_of(name) {
    checks.push(check(
      "clock",
      name,
      if ms.unsigned_abs() > 5000 {
        CheckStatus::Warn
      } else {
        CheckStatus::Ok
      },
      format!("时钟偏差 {ms} ms"),
    ));
  }
  if crate::exposure::has_public_reach(ctx.snap, name)
    && let Ok(view) = crate::exposure::view(ctx.s, name).await
    && view.checked_at.is_some()
  {
    let ports: Vec<_> = view
      .ports
      .iter()
      .filter(|p| !p.expected && !p.acked)
      .map(|p| format!("{}/{}", p.proto, p.port))
      .collect();
    let (status, detail) = if ports.is_empty() {
      (CheckStatus::Ok, "没有未确认的公网端口".into())
    } else {
      (
        CheckStatus::Warn,
        format!(
          "{}，执行 wharf server exposure {name} 查看",
          ports.join("、")
        ),
      )
    };
    checks.push(check("exposure", name, status, detail));
  }
  checks.extend(
    world
      .gateways
      .iter()
      .filter(|(_, g)| g.spec.server == name)
      .map(|(gw, _)| gateway_check(ctx.live, gw, name)),
  );
  checks.extend(tunnels(ctx, name).await);
  let services: Vec<_> = world
    .services
    .iter()
    .filter(|(_, row)| row.spec.server == name && !row.spec.stopped)
    .map(|(service, _)| {
      (
        service.as_str(),
        container_of_service(world, ctx.live, service),
      )
    })
    .collect();
  let count = services.len();
  let failed = services
    .into_iter()
    .filter(|(_, c)| c.status != CheckStatus::Ok);
  let findings = diagnose_containers(ctx, failed).await;
  if findings.is_empty() {
    checks.push(check(
      "container",
      name,
      CheckStatus::Ok,
      format!("本机 {count} 个运行中服务容器均正常"),
    ));
  } else {
    checks.extend(findings);
  }
  checks
}

async fn tunnels(
  ctx: &RouteChecks<'_>,
  server: &str,
) -> Vec<DoctorCheck> {
  let Ok(projects) = crate::link::projects(&ctx.snap.world, ctx.net)
  else {
    return vec![];
  };
  let names: Vec<_> = projects
    .into_iter()
    .filter(|p| p.server == server)
    .map(|p| p.project)
    .collect();
  if names.is_empty() {
    return vec![];
  }
  let states = crate::snapshot::project_status(
    &ctx.s.hub,
    server,
    names.clone(),
    super::PROBE_TIMEOUT,
  )
  .await;
  names
    .into_iter()
    .map(|name| {
      let (status, detail) = match &states {
        Ok(states)
          if states.get(&name).is_some_and(|p| p.all_running()) =>
        {
          (CheckStatus::Ok, "运行中")
        }
        Ok(_) => (CheckStatus::Bad, "容器未正常运行"),
        Err(_) => (CheckStatus::Skip, "查不到状态"),
      };
      check("link", name, status, detail)
    })
    .collect()
}

async fn diagnose_containers<'a>(
  ctx: &RouteChecks<'_>,
  containers: impl IntoIterator<Item = (&'a str, DoctorCheck)>,
) -> Vec<DoctorCheck> {
  let mut checks: Vec<_> = containers
    .into_iter()
    .map(|(service, check)| {
      let row = &ctx.snap.world.services[service];
      let targets =
        if !row.spec.stopped && check.status == CheckStatus::Bad {
          vec![Target {
            service: service.into(),
            server: row.spec.server.clone(),
            port: row.host_ports.values().next().copied(),
            local_loopback_ok: true,
            http_failed: false,
            link_unreachable: false,
            link_subject: None,
            container_subject: check.subject.clone(),
          }]
        } else {
          vec![]
        };
      (vec![check], targets)
    })
    .collect();
  doctor_diagnose::enrich(
    ctx.s,
    checks
      .iter_mut()
      .map(|(checks, targets)| (checks, std::mem::take(targets))),
  )
  .await;
  checks.into_iter().flat_map(|(checks, _)| checks).collect()
}
