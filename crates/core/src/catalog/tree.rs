use std::collections::BTreeSet;

use wharf_api_types::{
  ApiError,
  spec::{GatewayKind, GatewayTls},
  view::{
    TreeDependency, TreeGatewayNode, TreeRouteNode, TreeServerNode,
    TreeServiceNode, TreeView,
  },
};

use super::{TreeQuery, route_visible, visible};
use crate::snapshot::Snapshot;

pub(super) fn build_tree(
  snap: &Snapshot,
  scope: Option<&BTreeSet<String>>,
  q: &TreeQuery,
  live: &crate::views::LiveMap,
) -> Result<TreeView, ApiError> {
  let world = &snap.world;
  let mut server = q.server.as_deref();
  let mut service = q.service.as_deref();
  let explicit_route = q
    .route
    .as_deref()
    .map(crate::world::normalize_hostname)
    .transpose()?;
  let inferred_route = q
    .target
    .as_deref()
    .and_then(|name| crate::world::normalize_hostname(name).ok());
  let mut route = explicit_route.as_deref();
  let mut gateway = q.gateway.as_deref();
  let choices = [server, service, route, gateway]
    .into_iter()
    .flatten()
    .count();
  if choices > 1 || choices != 0 && q.target.is_some() {
    return Err(ApiError::invalid("树视图只能选一个目标"));
  }
  if let Some(target) = q.target.as_deref() {
    let mut found = 0;
    if world.services.contains_key(target) && visible(scope, target) {
      service = Some(target);
      found += 1;
    }
    if scope.is_none() && world.servers.contains_key(target) {
      server = Some(target);
      found += 1;
    }
    if let Some(host) = inferred_route.as_deref()
      && world
        .routes
        .get(host)
        .is_some_and(|r| route_visible(scope, &r.spec))
    {
      route = Some(host);
      found += 1;
    }
    if scope.is_none() && world.gateways.contains_key(target) {
      gateway = Some(target);
      found += 1;
    }
    match found {
      0 => return Err(ApiError::not_found("未找到树视图目标")),
      1 => {}
      _ => {
        return Err(ApiError::invalid("目标名称有重复").with_hint(
          "用 --server、--service、--route 或 --gateway 明确指定",
        ));
      }
    }
  }
  if server.is_some_and(|n| {
    scope.is_some() || !world.servers.contains_key(n)
  }) || service.is_some_and(|n| {
    !visible(scope, n) || !world.services.contains_key(n)
  }) || gateway.is_some_and(|n| {
    scope.is_some() || !world.gateways.contains_key(n)
  }) || route.is_some_and(|n| {
    !world
      .routes
      .get(n)
      .is_some_and(|r| route_visible(scope, &r.spec))
  }) {
    return Err(ApiError::not_found("未找到树视图目标"));
  }

  let net = snap.net(world);
  let node = |name: &str| {
    let row = world.services.get(name)?;
    let ports = row
      .spec
      .ports
      .iter()
      .map(|p| {
        (
          p.name.clone(),
          format!(
            "{}→{}",
            p.container
              .map_or_else(|| "-".into(), |port| port.to_string()),
            row.host_ports.get(&p.name).copied().unwrap_or_default()
          ),
        )
      })
      .collect();
    let mut deps = BTreeSet::new();
    for (_, text) in crate::missing_refs::service_texts(&row.spec) {
      deps.extend(
        wharf_api_types::references::placeholders(text)
          .filter_map(wharf_api_types::references::parse_service_ref)
          .map(|r| (r.service, "service_ref")),
      );
    }
    deps.extend(row.spec.volumes.iter().filter_map(|v| {
      let (owner, _) =
        crate::shared_volumes::parse_ref(v.from_service.as_deref()?)
          .ok()?;
      Some((owner, "shared_volume"))
    }));
    let dependency_details = deps
      .into_iter()
      .filter(|(n, _)| visible(scope, n))
      .map(|(n, kind)| TreeDependency {
        service: n.into(),
        server: scope
          .is_none()
          .then(|| {
            world.services.get(n).map(|row| row.spec.server.clone())
          })
          .flatten(),
        kind: kind.into(),
      })
      .collect();
    Some(TreeServiceNode {
      name: name.into(),
      server: scope.is_none().then(|| row.spec.server.clone()),
      ports,
      dependencies: crate::shared_volumes::uses(&row.spec)
        .into_iter()
        .filter(|n| visible(scope, n))
        .collect(),
      dependency_details,
      backup_to: scope
        .is_none()
        .then(|| row.spec.backup.as_ref().map(|b| b.to.clone()))
        .flatten(),
      stopped: row.spec.stopped,
      state: crate::snapshot::service_runtime_server(snap, name).map(
        |server| {
          crate::views::live_of(
            live,
            server,
            name,
            None,
            row.spec.stopped,
          )
          .state
        },
      ),
    })
  };
  let on_server = |name| {
    server.is_none_or(|s| {
      world
        .services
        .get(name)
        .is_some_and(|row| row.spec.server == s)
    })
  };
  let mut referenced = BTreeSet::new();
  let mut routes = Vec::new();
  for (host, row) in &world.routes {
    let spec = &row.spec;
    if !route_visible(scope, spec) || route.is_some_and(|r| r != host)
    {
      continue;
    }
    let main = world.route_gateway(spec);
    let backup = spec.backup_gateway.as_deref();
    if gateway.is_some_and(|g| Some(g) != main && Some(g) != backup) {
      continue;
    }
    let targets = std::iter::once(spec.service.as_str())
      .chain(spec.paths.iter().filter_map(|p| p.service.as_deref()))
      .filter(|n| !n.is_empty())
      .collect::<BTreeSet<_>>();
    if (server.is_some() || service.is_some())
      && !targets
        .iter()
        .any(|n| service.is_none_or(|s| s == *n) && on_server(*n))
      && !server.is_some_and(|s| {
        main.into_iter().chain(backup).any(|g| {
          world.gateways.get(g).is_some_and(|r| r.spec.server == s)
        })
      })
    {
      continue;
    }
    referenced.extend(targets.iter().copied());
    let active = world.live_gateway(host, spec);
    let active_spec =
      active.and_then(|g| world.gateways.get(g)).map(|g| &g.spec);
    let chain = active_spec.and_then(|g| {
      if g.kind == GatewayKind::CloudflareTunnel {
        return Some("tunnel");
      }
      let port = world.route_port(spec)?;
      match crate::link::choose(
        world,
        &net,
        g,
        &spec.service,
        port,
        spec.link,
      )
      .ok()?
      {
        crate::link::Choice::Local => Some("local"),
        crate::link::Choice::Direct(_) => Some("direct"),
        crate::link::Choice::Tunnel => Some("frp"),
      }
    });
    let gateway_node = |name: &str| TreeGatewayNode {
      name: name.to_string(),
      server: world.gateways.get(name).map(|g| g.spec.server.clone()),
    };
    routes.push(TreeRouteNode {
      hostname: host.clone(),
      https: active_spec.is_some_and(|g| {
        g.tls != GatewayTls::Off
          || g.kind == GatewayKind::CloudflareTunnel
      }),
      gate: spec.sso.is_some(),
      basic_auth: spec.auth,
      gateway: scope
        .is_none()
        .then(|| main.map(gateway_node))
        .flatten(),
      backup_gateway: scope
        .is_none()
        .then(|| backup.map(gateway_node))
        .flatten(),
      backup_active: scope.is_none()
        && backup.is_some()
        && crate::failover::active(host),
      link: scope
        .is_none()
        .then_some(chain)
        .flatten()
        .map(str::to_string),
      service: node(&spec.service),
      port: world.route_port(spec).map(str::to_string),
      target: scope
        .is_none()
        .then(|| {
          spec
            .redirect
            .as_ref()
            .or(spec.upstream.as_ref())
            .map(|url| crate::redact::redact_command(url))
        })
        .flatten(),
      path_services: targets
        .into_iter()
        .filter(|n| *n != spec.service)
        .filter_map(node)
        .collect(),
    });
  }
  let orphan_services = world
    .services
    .keys()
    .filter(|name| {
      visible(scope, name)
        && on_server(name.as_str())
        && service.is_none_or(|s| s == *name)
        && gateway.is_none()
        && route.is_none()
        && !referenced.contains(name.as_str())
    })
    .filter_map(|n| node(n))
    .collect();
  let servers = server
    .into_iter()
    .map(|n| TreeServerNode {
      name: n.into(),
      services: world
        .services
        .keys()
        .filter(|name| on_server(name.as_str()))
        .filter_map(|name| node(name))
        .collect(),
    })
    .collect();
  Ok(TreeView {
    routes,
    orphan_services,
    servers,
  })
}
