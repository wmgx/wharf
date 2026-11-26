//! 限定令牌的请求路径和计划范围。

use std::collections::{BTreeMap, BTreeSet};

use axum::http::Method;
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Action, Layer, Plan, PlanItem, PlanRequest},
  spec::{Change, RouteSpec},
};

use crate::{
  auth::Auth,
  planner::{Step, StepPlan},
  render::Net,
  world::World,
};

pub use wharf_api_types::token::ip_in_ranges;

pub type RouteEffects = BTreeMap<u32, Vec<String>>;

/// 仅在把这次改过的路由恢复后能复现正在运行的配置时，才把重载归给这些路由。
pub fn gateway_routes(
  items: &[PlanItem],
  current: &World,
  desired: &World,
  net: &Net,
  gateway: &str,
  applied_hash: &str,
) -> Vec<String> {
  let changed: Vec<_> = items
    .iter()
    .filter(|item| item.layer == Layer::Config)
    .filter_map(|item| item.address.strip_prefix("route/"))
    .filter(|host| {
      [current, desired].into_iter().any(|world| {
        world.routes.get(*host).is_some_and(|route| {
          world.route_gateways(&route.spec).contains(&gateway)
        })
      })
    })
    .collect();
  if changed.is_empty() {
    return vec![];
  }
  let mut reverted = desired.clone();
  for host in &changed {
    if let Some(route) = current.routes.get(*host) {
      reverted.routes.insert((*host).to_string(), route.clone());
    } else {
      reverted.routes.remove(*host);
    }
  }
  if crate::snapshot::gateway_render(&reverted, net, gateway)
    .is_ok_and(|rendered| rendered.config_hash == applied_hash)
  {
    changed
      .into_iter()
      .map(|host| format!("route/{host}"))
      .collect()
  } else {
    vec![]
  }
}

/// 删除解析时还要核对旧路由的所有权，避免把同名遗留记录算进来。
pub fn record_dns_routes(
  effects: &mut RouteEffects,
  steps: &[StepPlan],
  current: &World,
  desired: &World,
) {
  for step in steps {
    let host = match &step.step {
      Step::DnsUpsert { hostname, .. }
        if desired.routes.contains_key(hostname)
          && desired.edge_domain(hostname).is_none() =>
      {
        hostname
      }
      Step::DnsDelete {
        hostname,
        owner: Some(owner),
        ..
      } if !desired.routes.contains_key(hostname)
        && current
          .routes
          .get(hostname)
          .is_some_and(|r| &r.id == owner) =>
      {
        hostname
      }
      _ => continue,
    };
    for id in &step.items {
      effects.insert(*id, vec![format!("route/{host}")]);
    }
  }
}

fn contains_service(services: &BTreeSet<String>, raw: &str) -> bool {
  urlencoding::decode(raw)
    .is_ok_and(|name| services.contains(name.as_ref()))
}

pub fn check_service_scope(
  services: &BTreeSet<String>,
  method: &Method,
  path: &str,
) -> bool {
  if services.is_empty() {
    return false;
  }
  let path: Vec<_> = path.split('/').collect();
  match *method {
    Method::GET | Method::HEAD => match path.as_slice() {
      ["", "api", "whoami" | "version"]
      | ["", "api", "uploads", _] => true,
      ["", "api", "services", name, ..] => {
        contains_service(services, name)
      }
      [
        "",
        "api",
        "status" | "services" | "routes" | "data" | "alerts"
        | "doctor" | "report" | "export" | "runs" | "secrets"
        | "tasks",
      ]
      | ["", "api", "logs", "services"]
      | ["", "api", "metrics"]
      | ["", "api", "routes", _, "cert" | "dns-check"]
      | ["", "api", "tasks", _]
      | ["", "api", "tasks", _, "runs"]
      | ["", "api", "plans" | "runs", _] => true,
      _ => false,
    },
    _ => match path.as_slice() {
      ["", "api", "services", name, ..] => {
        contains_service(services, name)
      }
      ["", "api", "alerts", _, "services", name] => {
        *method == Method::PUT && contains_service(services, name)
      }
      ["", "api", "alerts", "ack" | "unack" | "custom"] => {
        *method == Method::POST
      }
      ["", "api", "alerts", "custom", _] => *method == Method::DELETE,
      ["", "api", "alerts", id] if *id != "options" => {
        *method == Method::PUT
      }
      ["", "api", "routes", _, "cert", "retry"]
      | ["", "api", "routes", _, "sso", "test"]
      | ["", "api", "plan" | "apply"]
      | ["", "api", "runs", _, "cancel"]
      | ["", "api", "convert", "docker-run"] => {
        *method == Method::POST
      }
      ["", "api", "routes", _, "note"] => *method == Method::PUT,
      ["", "api", "uploads", _] => {
        matches!(*method, Method::PUT | Method::POST)
      }
      _ => false,
    },
  }
}

pub fn forbidden(
  name: &str,
  services: &BTreeSet<String>,
  extra: &str,
) -> ApiError {
  let message = if services.is_empty() {
    format!(
      "访问令牌 {name} 的服务范围为空，不能执行任何服务操作{extra}"
    )
  } else {
    let names = services
      .iter()
      .map(String::as_str)
      .collect::<Vec<_>>()
      .join("、");
    format!("访问令牌 {name} 只能操作这些服务：{names}{extra}")
  };
  ApiError::new(ErrorCode::Forbidden, message)
    .with_hint("这个操作不属于名单里的服务；换一个不限服务的令牌，或在页面上操作")
}

pub fn require_service(
  auth: &Auth,
  service: &str,
) -> Result<(), ApiError> {
  if let Some(services) = &auth.services
    && !services.contains(service)
  {
    return Err(forbidden(&auth.name, services, ""));
  }
  Ok(())
}

pub fn require_route_by_host(
  auth: &Auth,
  world: &World,
  host: &str,
) -> Result<(), ApiError> {
  if let Some(services) = &auth.services
    && !world
      .routes
      .get(host)
      .is_some_and(|route| route_spec_in_scope(services, &route.spec))
  {
    return Err(forbidden(&auth.name, services, ""));
  }
  Ok(())
}

pub fn route_spec_in_scope(
  services: &BTreeSet<String>,
  route: &RouteSpec,
) -> bool {
  route.upstream.is_none()
    && route.redirect.is_none()
    && services.contains(&route.service)
    && route.paths.iter().all(|path| {
      path.upstream.is_none()
        && path
          .service
          .as_ref()
          .is_some_and(|name| services.contains(name))
    })
}

fn route_in_scope(
  services: &BTreeSet<String>,
  host: &str,
  item: &PlanItem,
) -> bool {
  let read_spec = |value: &Option<serde_json::Value>| {
    value
      .clone()
      .map(serde_json::from_value::<RouteSpec>)
      .transpose()
  };
  let (Ok(before), Ok(after)) =
    (read_spec(&item.before), read_spec(&item.after))
  else {
    return false;
  };
  if item.action != Action::Delete
    && crate::caddy_validate::route_caddy_changed(
      before.as_ref(),
      after.as_ref(),
    )
  {
    return false;
  }
  (before.is_some() || after.is_some())
    && [before, after].iter().flatten().all(|route| {
      route.hostname == host && route_spec_in_scope(services, route)
    })
}

pub fn check_plan_scope(
  services: &BTreeSet<String>,
  plan: &Plan,
  effects: &RouteEffects,
) -> Result<(), Vec<String>> {
  let routes: BTreeSet<_> = plan
    .items
    .iter()
    .filter(|item| item.layer == Layer::Config)
    .filter_map(|item| {
      let host = item.address.strip_prefix("route/")?;
      route_in_scope(services, host, item)
        .then_some(item.address.as_str())
    })
    .collect();
  let blocked: BTreeSet<_> = plan
    .items
    .iter()
    .filter(|item| {
      let Some((kind, name)) = item.address.split_once('/') else {
        return true;
      };
      let allowed = match kind {
        "service" => services.contains(name) && !item.needs_host(),
        "route" if item.layer == Layer::Config => {
          routes.contains(item.address.as_str())
        }
        "route" if item.layer == Layer::Dns => {
          effects.get(&item.id).is_some_and(|addresses| {
            addresses.as_slice() == [item.address.as_str()]
              && routes.contains(item.address.as_str())
          })
        }
        "gateway" if item.layer == Layer::Gateway => {
          effects.get(&item.id).is_some_and(|addresses| {
            !addresses.is_empty()
              && addresses.iter().all(|a| routes.contains(a.as_str()))
          })
        }
        _ => false,
      };
      !allowed
    })
    .map(|item| item.address.clone())
    .collect();
  if blocked.is_empty() {
    Ok(())
  } else {
    Err(blocked.into_iter().collect())
  }
}

pub fn require_plan_request(
  auth: &Auth,
  current: &World,
  req: &PlanRequest,
) -> Result<(), ApiError> {
  let Some(services) = &auth.services else {
    return Ok(());
  };
  if req.fleet.is_some() {
    return Err(forbidden(
      &auth.name,
      services,
      "；请求包含范围外的改动：fleet",
    ));
  }
  let mut blocked = BTreeSet::new();
  let route_allowed =
    |route: &RouteSpec| route_spec_in_scope(services, route);
  let upsert_route =
    |route: &RouteSpec| -> Result<Option<String>, ApiError> {
      let host = crate::world::normalize_hostname(&route.hostname)?;
      let before = current.routes.get(&host).map(|r| &r.spec);
      Ok(
        (!route_allowed(route)
          || before.is_some_and(|r| !route_allowed(r))
          || crate::caddy_validate::route_caddy_changed(
            before,
            Some(route),
          ))
        .then(|| format!("route/{host}")),
      )
    };
  if let Some(partial) = &req.partial {
    blocked
      .extend(partial.servers.keys().map(|n| format!("server/{n}")));
    blocked.extend(
      partial.gateways.keys().map(|n| format!("gateway/{n}")),
    );
    blocked
      .extend(partial.edge_apps.keys().map(|n| format!("edge/{n}")));
    blocked.extend(
      partial.bookmarks.keys().map(|n| format!("bookmark/{n}")),
    );
    blocked.extend(
      partial
        .services
        .keys()
        .filter(|n| !services.contains(*n))
        .map(|n| format!("service/{n}")),
    );
    for route in &partial.routes {
      blocked.extend(upsert_route(route)?);
    }
  }
  for change in &req.changes {
    let address = match change {
      Change::UpsertService { name, .. }
      | Change::RemoveService { name, .. }
      | Change::RefreshImages { name, .. }
      | Change::RetagImage { name, .. } => {
        (!services.contains(name)).then(|| format!("service/{name}"))
      }
      Change::UpdateServer { name, .. } => {
        Some(format!("server/{name}"))
      }
      Change::UpsertGateway { name, .. }
      | Change::RemoveGateway { name } => {
        Some(format!("gateway/{name}"))
      }
      Change::UpsertEdgeApp { name, .. }
      | Change::RemoveEdgeApp { name } => {
        Some(format!("edge/{name}"))
      }
      Change::UpsertBookmark { id, .. } => {
        Some(format!("bookmark/{}", id.as_deref().unwrap_or("new")))
      }
      Change::RemoveBookmark { id } => Some(format!("bookmark/{id}")),
      Change::UpsertRoute { spec } => upsert_route(spec)?,
      Change::RemoveRoute { hostname } => {
        let host = crate::world::normalize_hostname(hostname)?;
        current
          .routes
          .get(&host)
          .is_none_or(|r| !route_allowed(&r.spec))
          .then(|| format!("route/{host}"))
      }
    };
    blocked.extend(address);
  }
  if blocked.is_empty() {
    Ok(())
  } else {
    Err(forbidden(
      &auth.name,
      services,
      &format!(
        "；请求包含范围外的改动：{}",
        blocked.into_iter().collect::<Vec<_>>().join("、")
      ),
    ))
  }
}

pub fn require_plan(
  auth: &Auth,
  plan: &Plan,
  effects: &RouteEffects,
) -> Result<(), ApiError> {
  if let Some(services) = &auth.services {
    check_plan_scope(services, plan, effects).map_err(|blocked| {
      forbidden(
        &auth.name,
        services,
        &format!("；这个计划还会改：{}", blocked.join("、")),
      )
    })?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn scoped_token_get_rejects_other_services_and_cluster_endpoints() {
    let scope = BTreeSet::from(["blog".into()]);
    for path in [
      "/api/services/other/logs",
      "/api/services/other/files",
      "/api/core/logs",
      "/api/gateways/edge/config",
      "/api/servers/s1/agent-logs",
      "/api/audit",
      "/api/shell-log",
    ] {
      assert!(
        !check_service_scope(&scope, &Method::GET, path),
        "{path}"
      );
    }
  }

  #[test]
  fn empty_perms_and_empty_scope_fail_closed() {
    let mut settings = wharf_api_types::view::TokenSettings {
      perms: vec![],
      expires_at: None,
      allowed_from: vec![],
      services: vec![],
    };
    assert_eq!(
      settings.normalize().unwrap_err().code,
      ErrorCode::InvalidInput
    );
    for path in ["/api/services/blog", "/api/whoami"] {
      assert!(!check_service_scope(
        &BTreeSet::new(),
        &Method::GET,
        path
      ));
    }
  }

  #[test]
  fn scoped_token_rejects_other_service_alerts_and_foreign_routes() {
    let scope = BTreeSet::from(["blog".into()]);
    for path in
      ["/api/alerts/http_5xx/services/other", "/api/alerts/options"]
    {
      assert!(!check_service_scope(&scope, &Method::PUT, path));
    }
    crate::scope_filter::tests::rejects_foreign_alerts_and_routes();
  }

  #[test]
  fn scoped_token_allows_own_service_and_route_reads() {
    let scope = BTreeSet::from(["blog".into()]);
    for path in [
      "/api/status",
      "/api/services/blog",
      "/api/services/blog/logs",
      "/api/services/blog/files/download",
      "/api/routes/blog.example.com/cert",
      "/api/routes/blog.example.com/dns-check",
      "/api/metrics",
      "/api/alerts",
      "/api/export",
      "/api/whoami",
    ] {
      assert!(
        check_service_scope(&scope, &Method::GET, path),
        "{path}"
      );
    }
    crate::scope_filter::tests::allows_own_route();
  }

  #[test]
  fn scoped_token_allows_own_service_alerts_and_route_writes() {
    let scope = BTreeSet::from(["blog".into()]);
    for (method, path) in [
      (Method::PUT, "/api/alerts/http_5xx/services/blog"),
      (Method::POST, "/api/alerts/ack"),
      (Method::POST, "/api/alerts/unack"),
      (Method::POST, "/api/alerts/custom"),
      (Method::DELETE, "/api/alerts/custom/slow"),
      (Method::POST, "/api/routes/blog.example.com/cert/retry"),
      (Method::PUT, "/api/routes/blog.example.com/note"),
    ] {
      assert!(check_service_scope(&scope, &method, path), "{path}");
    }
    crate::scope_filter::tests::allows_own_alerts();
  }

  #[test]
  fn service_probe_respects_service_scope() {
    let services = BTreeSet::from(["blog".into()]);
    assert!(check_service_scope(
      &services,
      &Method::POST,
      "/api/services/blog/probe"
    ));
    assert!(!check_service_scope(
      &services,
      &Method::POST,
      "/api/services/other/probe"
    ));
  }

  #[test]
  fn matches_both_address_families() {
    for (range, inside, outside) in [
      ("100.64.0.0/10", "100.64.0.7", "203.0.113.7"),
      ("fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::7", "2001:db8::7"),
    ] {
      let ranges = [range.into()];
      assert!(ip_in_ranges(inside.parse().unwrap(), &ranges));
      assert!(!ip_in_ranges(outside.parse().unwrap(), &ranges));
    }
  }

  #[test]
  fn request_checks_encoded_names_and_host_terminal() {
    let services = BTreeSet::from(["blog".into()]);
    assert!(check_service_scope(
      &services,
      &Method::GET,
      "/api/services/%62log/connect"
    ));
    assert!(!check_service_scope(
      &services,
      &Method::GET,
      "/api/servers/s1/terminal"
    ));
  }

  #[test]
  fn scoped_token_cannot_read_access_logs() {
    let services = BTreeSet::from(["blog".into()]);
    for path in [
      "/api/gateways/edge/access-logs",
      "/api/routes/blog.example.com/access-logs",
    ] {
      assert!(!check_service_scope(&services, &Method::GET, path));
    }
  }

  #[test]
  fn scoped_token_cannot_probe_server() {
    assert!(!check_service_scope(
      &BTreeSet::from(["blog".into()]),
      &Method::POST,
      "/api/servers/aliyun/probe",
    ));
  }

  #[test]
  fn checks_route_targets_and_associated_dns() {
    let services = BTreeSet::from(["blog".into()]);
    let mut plan: Plan = serde_json::from_value(json!({
      "plan_id": "p", "status": "pending",
      "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z",
      "base_versions": {},
      "items": [
        {"id": 1, "address": "service/blog", "layer": "container", "action": "update", "reason": ""},
        {"id": 2, "address": "route/blog.example.com", "layer": "config", "action": "create", "reason": "",
         "after": {"hostname": "blog.example.com", "service": "blog"}},
        {"id": 3, "address": "route/blog.example.com", "layer": "dns", "action": "create", "reason": ""},
        {"id": 4, "address": "gateway/edge", "layer": "gateway", "action": "update", "reason": ""}
      ]
    })).unwrap();
    let effects = RouteEffects::from([
      (3, vec!["route/blog.example.com".into()]),
      (4, vec!["route/blog.example.com".into()]),
    ]);
    assert_eq!(check_plan_scope(&services, &plan, &effects), Ok(()));
    plan.items[1].action = Action::Update;
    plan.items[1].before = plan.items[1].after.clone();
    plan.items[1].before.as_mut().unwrap()["caddy"] =
      json!("respond 403");
    plan.items[1].after.as_mut().unwrap()["caddy"] =
      json!("respond 404");
    assert!(check_plan_scope(&services, &plan, &effects).is_err());
    plan.items[1].after.as_mut().unwrap()["caddy"] =
      json!("respond 403");
    plan.items[1].after.as_mut().unwrap()["rate_limit"] = json!(60);
    assert_eq!(check_plan_scope(&services, &plan, &effects), Ok(()));
    plan.items[1].after.as_mut().unwrap()["paths"] =
      json!([{"path": "/admin", "service": "halo"}]);
    assert_eq!(
      check_plan_scope(&services, &plan, &effects),
      Err(vec![
        "gateway/edge".into(),
        "route/blog.example.com".into()
      ])
    );
  }

  #[test]
  fn scoped_route_request_cannot_change_custom_caddy() {
    let host = "blog.example.com";
    let mut current = World::default();
    let spec: RouteSpec = serde_json::from_value(json!({
      "hostname": host, "service": "blog", "caddy": "respond 403"
    }))
    .unwrap();
    current.routes.insert(
      host.into(),
      crate::world::RouteRow {
        id: "r".into(),
        spec: spec.clone(),
        version: 1,
      },
    );
    let auth = Auth {
      name: "scoped".into(),
      perms: BTreeSet::from([wharf_api_types::view::Perm::Admin]),
      expires_at: None,
      allowed_from: vec![],
      services: Some(BTreeSet::from(["blog".into()])),
      human: false,
    };
    for caddy in [None, Some("respond 404"), Some("respond 403")] {
      let mut spec = spec.clone();
      spec.caddy = caddy.map(str::to_owned);
      spec.rate_limit = Some(60);
      for request in [
        PlanRequest {
          changes: vec![Change::UpsertRoute { spec: spec.clone() }],
          ..Default::default()
        },
        PlanRequest {
          partial: Some(wharf_api_types::spec::Fleet {
            routes: vec![spec.clone()],
            ..Default::default()
          }),
          ..Default::default()
        },
      ] {
        let result = require_plan_request(&auth, &current, &request);
        if caddy == Some("respond 403") {
          assert!(result.is_ok());
        } else {
          assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
        }
      }
    }
  }
}
