//! 期望状态的内存表示：从数据库读出来，叠加 plan 请求里的修改，再整体校验。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  spec::{
    Change, Fleet, GatewayKind, GatewaySpec, RouteSpec,
    ServerSettings, ServiceSpec, Source,
  },
  validate_name,
};

use crate::db::{ResourceRow, Write, json_err};

pub const KIND_SERVER: &str = "server";
pub const KIND_SERVICE: &str = "service";
pub const KIND_GATEWAY: &str = "gateway";
pub const KIND_ROUTE: &str = "route";

/// 网关的 compose project 名前缀，服务名不能用。
pub const GATEWAY_PROJECT_PREFIX: &str = "wharf-gw-";
/// 自动分配的宿主机端口范围。
pub const HOST_PORTS: std::ops::RangeInclusive<u16> = 20000..=29999;

#[derive(Debug, Clone, PartialEq)]
pub struct ServerRow {
  pub settings: ServerSettings,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceRow {
  pub spec: ServiceSpec,
  /// 端口名 → 宿主机端口。
  pub host_ports: BTreeMap<String, u16>,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayRow {
  pub spec: GatewaySpec,
  pub version: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteRow {
  pub id: String,
  pub spec: RouteSpec,
  pub version: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct World {
  pub servers: BTreeMap<String, ServerRow>,
  pub services: BTreeMap<String, ServiceRow>,
  pub gateways: BTreeMap<String, GatewayRow>,
  /// key 是 hostname。
  pub routes: BTreeMap<String, RouteRow>,
}

pub fn gateway_project(name: &str) -> String {
  format!("{GATEWAY_PROJECT_PREFIX}{name}")
}

pub fn new_id(prefix: &str) -> String {
  let mut bytes = [0u8; 6];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  format!("{prefix}_{}", hex::encode(bytes))
}

impl World {
  pub fn from_rows(rows: Vec<ResourceRow>) -> Result<Self, ApiError> {
    let mut world = World::default();
    for row in rows {
      let version = row.version;
      match row.kind.as_str() {
        KIND_SERVER => {
          world.servers.insert(
            row.name,
            ServerRow {
              settings: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_SERVICE => {
          world.services.insert(
            row.name,
            ServiceRow {
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              host_ports: serde_json::from_value(
                row.meta["host_ports"].clone(),
              )
              .unwrap_or_default(),
              version,
            },
          );
        }
        KIND_GATEWAY => {
          world.gateways.insert(
            row.name,
            GatewayRow {
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        KIND_ROUTE => {
          world.routes.insert(
            row.name,
            RouteRow {
              id: row.meta["id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
              spec: serde_json::from_value(row.spec)
                .map_err(json_err)?,
              version,
            },
          );
        }
        other => tracing::warn!("未知资源类型 {other}，忽略"),
      }
    }
    Ok(world)
  }

  /// 每个资源的版本，`kind/name` → version。
  pub fn versions(&self) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (name, r) in &self.servers {
      out.insert(format!("{KIND_SERVER}/{name}"), r.version);
    }
    for (name, r) in &self.services {
      out.insert(format!("{KIND_SERVICE}/{name}"), r.version);
    }
    for (name, r) in &self.gateways {
      out.insert(format!("{KIND_GATEWAY}/{name}"), r.version);
    }
    for (name, r) in &self.routes {
      out.insert(format!("{KIND_ROUTE}/{name}"), r.version);
    }
    out
  }

  /// 叠加局部修改。
  pub fn apply_changes(
    &mut self,
    changes: &[Change],
  ) -> Result<(), ApiError> {
    for change in changes {
      match change {
        Change::UpdateServer { name, settings } => {
          let server = self
            .servers
            .get_mut(name)
            .ok_or_else(|| server_not_found(name))?;
          server.settings = settings.clone();
        }
        Change::UpsertService { name, spec } => {
          validate_name("服务", name)?;
          let host_ports = self
            .services
            .get(name)
            .map(|s| s.host_ports.clone())
            .unwrap_or_default();
          let version =
            self.services.get(name).map(|s| s.version).unwrap_or(0);
          self.services.insert(
            name.clone(),
            ServiceRow {
              spec: spec.clone(),
              host_ports,
              version,
            },
          );
        }
        Change::RemoveService { name } => {
          if self.services.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("服务 {name} 不存在"))
                .suggest("wharf service list"),
            );
          }
        }
        Change::UpsertGateway { name, spec } => {
          validate_name("网关", name)?;
          let version =
            self.gateways.get(name).map(|g| g.version).unwrap_or(0);
          self.gateways.insert(
            name.clone(),
            GatewayRow {
              spec: spec.clone(),
              version,
            },
          );
        }
        Change::RemoveGateway { name } => {
          if self.gateways.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("网关 {name} 不存在"))
                .suggest("wharf gateway list"),
            );
          }
        }
        Change::UpsertRoute { spec } => {
          let mut spec = spec.clone();
          spec.hostname = normalize_hostname(&spec.hostname)?;
          let existing = self.routes.get(&spec.hostname);
          let id = existing
            .map(|r| r.id.clone())
            .unwrap_or_else(|| new_id("rt"));
          let version = existing.map(|r| r.version).unwrap_or(0);
          self.routes.insert(
            spec.hostname.clone(),
            RouteRow { id, spec, version },
          );
        }
        Change::RemoveRoute { hostname } => {
          let hostname = normalize_hostname(hostname)?;
          if self.routes.remove(&hostname).is_none() {
            return Err(
              ApiError::not_found(format!("路由 {hostname} 不存在"))
                .suggest("wharf route list"),
            );
          }
        }
      }
    }
    Ok(())
  }

  /// 用完整的意图文件替换期望状态。服务器只更新设置，不增删。
  pub fn replace_with(
    &mut self,
    fleet: &Fleet,
  ) -> Result<(), ApiError> {
    let mut changes = Vec::new();
    for (name, settings) in &fleet.servers {
      changes.push(Change::UpdateServer {
        name: name.clone(),
        settings: settings.clone(),
      });
    }
    let keep_services: BTreeSet<&String> =
      fleet.services.keys().collect();
    let keep_gateways: BTreeSet<&String> =
      fleet.gateways.keys().collect();
    let mut keep_routes = BTreeSet::new();
    for route in &fleet.routes {
      let hostname = normalize_hostname(&route.hostname)?;
      if !keep_routes.insert(hostname.clone()) {
        return Err(ApiError::invalid(format!(
          "意图文件里路由 {hostname} 出现了两次"
        )));
      }
    }
    self.services.retain(|name, _| keep_services.contains(name));
    self.gateways.retain(|name, _| keep_gateways.contains(name));
    self.routes.retain(|host, _| keep_routes.contains(host));
    for (name, spec) in &fleet.services {
      changes.push(Change::UpsertService {
        name: name.clone(),
        spec: spec.clone(),
      });
    }
    for (name, spec) in &fleet.gateways {
      changes.push(Change::UpsertGateway {
        name: name.clone(),
        spec: spec.clone(),
      });
    }
    for spec in &fleet.routes {
      changes.push(Change::UpsertRoute { spec: spec.clone() });
    }
    self.apply_changes(&changes)
  }

  pub fn default_gateway(&self) -> Option<&str> {
    self
      .gateways
      .iter()
      .find(|(_, g)| g.spec.default)
      .map(|(name, _)| name.as_str())
  }

  /// 路由实际使用的网关。
  pub fn route_gateway<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    route.gateway.as_deref().or_else(|| self.default_gateway())
  }

  /// 路由指向的端口名。
  pub fn route_port<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    let service = self.services.get(&route.service)?;
    match &route.port {
      Some(port) => Some(port.as_str()),
      None if service.spec.ports.len() == 1 => {
        Some(service.spec.ports[0].name.as_str())
      }
      None => None,
    }
  }

  /// 整体校验。`joined` 是已经完成 join 的服务器。
  pub fn validate(&self) -> Result<(), ApiError> {
    for (name, service) in &self.services {
      validate_service(self, name, &service.spec)?;
    }
    let defaults: Vec<&String> = self
      .gateways
      .iter()
      .filter(|(_, g)| g.spec.default)
      .map(|(n, _)| n)
      .collect();
    if defaults.len() > 1 {
      return Err(ApiError::invalid(format!(
        "默认网关只能有一个，现在有：{}",
        defaults
          .iter()
          .map(|s| s.as_str())
          .collect::<Vec<_>>()
          .join("、")
      )));
    }
    for (name, gateway) in &self.gateways {
      if !self.servers.contains_key(&gateway.spec.server) {
        return Err(server_not_found(&gateway.spec.server));
      }
      if gateway.spec.kind == GatewayKind::CloudflareTunnel {
        return Err(
          ApiError::new(
            wharf_api_types::ErrorCode::NotImplemented,
            format!("网关 {name}：cloudflare_tunnel 类型在 P3 实现"),
          )
          .with_hint("P1 先用 caddy 网关"),
        );
      }
      let http = gateway.spec.http_port.unwrap_or(80);
      let https = gateway.spec.https_port.unwrap_or(443);
      if http == https {
        return Err(ApiError::invalid(format!(
          "网关 {name} 的 http_port 和 https_port 不能相同"
        )));
      }
    }
    for (host, route) in &self.routes {
      let Some(service) = self.services.get(&route.spec.service)
      else {
        return Err(
          ApiError::invalid(format!(
            "路由 {host} 指向的服务 {} 不存在",
            route.spec.service
          ))
          .suggest("wharf service list"),
        );
      };
      match self.route_gateway(&route.spec) {
        None => {
          return Err(
            ApiError::invalid(format!(
              "路由 {host} 没有指定网关，也没有默认网关"
            ))
            .with_hint("先创建一个默认网关")
            .suggest(
              "wharf gateway add <name> --server <server> --default",
            ),
          );
        }
        Some(gw) if !self.gateways.contains_key(gw) => {
          return Err(
            ApiError::invalid(format!(
              "路由 {host} 的网关 {gw} 不存在"
            ))
            .suggest("wharf gateway list"),
          );
        }
        Some(_) => {}
      }
      let Some(port) = self.route_port(&route.spec) else {
        let names: Vec<&str> = service
          .spec
          .ports
          .iter()
          .map(|p| p.name.as_str())
          .collect();
        return Err(if names.is_empty() {
          ApiError::invalid(format!(
            "服务 {} 没有声明端口，路由 {host} 无处可去",
            route.spec.service
          ))
          .with_hint("给服务加上 --port，例如 --port http=80")
        } else {
          ApiError::invalid(format!(
            "服务 {} 有多个端口，路由 {host} 需要指定 --port（可选：{}）",
            route.spec.service,
            names.join("、")
          ))
        });
      };
      if !service.spec.ports.iter().any(|p| p.name == port) {
        return Err(ApiError::invalid(format!(
          "服务 {} 没有名为 {port} 的端口",
          route.spec.service
        )));
      }
      if route.spec.auth {
        return Err(
          ApiError::new(
            wharf_api_types::ErrorCode::NotImplemented,
            format!("路由 {host}：登录保护在 P3 实现"),
          )
          .with_hint("P1 先去掉 --auth"),
        );
      }
    }
    Ok(())
  }

  /// 为 image 来源的服务分配宿主机端口：保留已有分配，新端口从 20000 起取最小空闲值。
  /// 宿主机端口在同一台服务器上唯一。
  pub fn allocate_ports(&mut self) -> Result<(), ApiError> {
    let mut used: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let mut take = |server: &str, port: u16| {
      used.entry(server.to_string()).or_default().insert(port)
    };
    // 第一轮：固定端口（compose 来源、显式 host_port）和已有分配。
    let names: Vec<String> = self.services.keys().cloned().collect();
    let mut pending: Vec<(String, String)> = Vec::new();
    for name in &names {
      let service = &self.services[name];
      let server = service.spec.server.clone();
      let mut assigned = BTreeMap::new();
      for port in &service.spec.ports {
        let fixed = match service.spec.source {
          Source::Compose { .. } => Some(port.port),
          Source::Image(_) => port.host_port,
        };
        let chosen = fixed
          .or_else(|| service.host_ports.get(&port.name).copied());
        match chosen {
          Some(p) => {
            if !take(&server, p) {
              if fixed.is_some() {
                return Err(ApiError::invalid(format!(
                  "服务器 {server} 上宿主机端口 {p} 被多个服务使用（服务 {name}）"
                )));
              }
              pending.push((name.clone(), port.name.clone()));
            } else {
              assigned.insert(port.name.clone(), p);
            }
          }
          None => pending.push((name.clone(), port.name.clone())),
        }
      }
      self.services.get_mut(name).unwrap().host_ports = assigned;
    }
    for (name, port_name) in pending {
      let server = self.services[&name].spec.server.clone();
      let set = used.entry(server.clone()).or_default();
      let port = HOST_PORTS
        .clone()
        .find(|p| !set.contains(p))
        .ok_or_else(|| {
          ApiError::internal(format!(
            "服务器 {server} 上没有空闲端口了"
          ))
        })?;
      set.insert(port);
      self
        .services
        .get_mut(&name)
        .unwrap()
        .host_ports
        .insert(port_name, port);
    }
    Ok(())
  }

  /// 把期望状态和当前状态的差异转成数据库写入。
  pub fn writes_from(&self, current: &World) -> Vec<Write> {
    let mut out = Vec::new();
    diff_map(
      &current.servers,
      &self.servers,
      KIND_SERVER,
      |r| (to_json(&r.settings), json!({})),
      &mut out,
    );
    diff_map(
      &current.services,
      &self.services,
      KIND_SERVICE,
      |r| (to_json(&r.spec), json!({ "host_ports": r.host_ports })),
      &mut out,
    );
    diff_map(
      &current.gateways,
      &self.gateways,
      KIND_GATEWAY,
      |r| (to_json(&r.spec), json!({})),
      &mut out,
    );
    diff_map(
      &current.routes,
      &self.routes,
      KIND_ROUTE,
      |r| (to_json(&r.spec), json!({ "id": r.id })),
      &mut out,
    );
    out
  }
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
  serde_json::to_value(v).unwrap_or(Value::Null)
}

fn diff_map<T>(
  before: &BTreeMap<String, T>,
  after: &BTreeMap<String, T>,
  kind: &str,
  encode: impl Fn(&T) -> (Value, Value),
  out: &mut Vec<Write>,
) {
  for (name, row) in after {
    let (spec, meta) = encode(row);
    let changed = match before.get(name) {
      None => true,
      Some(old) => encode(old) != (spec.clone(), meta.clone()),
    };
    if changed {
      out.push(Write::Upsert {
        kind: kind.to_string(),
        name: name.clone(),
        spec,
        meta,
      });
    }
  }
  for name in before.keys() {
    if !after.contains_key(name) {
      out.push(Write::Delete {
        kind: kind.to_string(),
        name: name.clone(),
      });
    }
  }
}

pub fn server_not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("服务器 {name} 不存在"))
    .with_hint("先用 wharf server add 加入服务器")
    .suggest("wharf server list")
}

pub fn normalize_hostname(
  hostname: &str,
) -> Result<String, ApiError> {
  wharf_providers::validate::normalize_hostname(hostname)
    .map_err(|e| ApiError::invalid(e.message))
}

fn validate_service(
  world: &World,
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  validate_name("服务", name)?;
  if name.starts_with(GATEWAY_PROJECT_PREFIX) {
    return Err(ApiError::invalid(format!(
      "服务名不能以 {GATEWAY_PROJECT_PREFIX} 开头，它留给网关用"
    )));
  }
  if !world.servers.contains_key(&spec.server) {
    return Err(server_not_found(&spec.server));
  }
  match &spec.source {
    Source::Image(image) => {
      if image.trim().is_empty()
        || image.contains(char::is_whitespace)
      {
        return Err(ApiError::invalid(format!(
          "服务 {name} 的镜像名不合法"
        )));
      }
    }
    Source::Compose { content, file } => {
      let Some(content) = content else {
        return Err(
          ApiError::invalid(format!(
            "服务 {name} 的 compose 内容为空{}",
            file
              .as_ref()
              .map(|f| format!(
                "（file = {f} 需要由 CLI 读取后提交）"
              ))
              .unwrap_or_default()
          ))
          .with_hint("用 wharf CLI 提交，它会读取文件内容"),
        );
      };
      crate::render::check_compose(name, content)?;
      if !spec.env.is_empty() || !spec.volumes.is_empty() {
        return Err(ApiError::invalid(format!(
          "服务 {name}：compose 来源的环境变量和数据卷请直接写在 compose 文件里"
        )));
      }
    }
  }
  let mut port_names = BTreeSet::new();
  for port in &spec.ports {
    validate_name("端口", &port.name)?;
    if !port_names.insert(&port.name) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的端口名 {} 重复",
        port.name
      )));
    }
    if port.port == 0 {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的端口不能是 0"
      )));
    }
    if port.host_port.is_some()
      && matches!(spec.source, Source::Compose { .. })
    {
      return Err(ApiError::invalid(format!(
        "服务 {name}：compose 来源的 port 就是宿主机端口，不需要 host_port"
      )));
    }
  }
  let mut volume_names = BTreeSet::new();
  for volume in &spec.volumes {
    validate_name("数据卷", &volume.name)?;
    if !volume_names.insert(&volume.name) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的数据卷名 {} 重复",
        volume.name
      )));
    }
    if !volume.target.starts_with('/') || volume.target.contains(':')
    {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的数据卷 {} 的挂载点必须是容器内的绝对路径",
        volume.name
      )));
    }
  }
  for key in spec.env.keys() {
    let ok = !key.is_empty()
      && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
      && !key.as_bytes()[0].is_ascii_digit();
    if !ok {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的环境变量名 {key} 不合法"
      )));
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::spec::PortSpec;

  pub fn sample() -> World {
    let mut w = World::default();
    w.servers.insert(
      "node1".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    w
  }

  fn image_service(server: &str) -> ServiceSpec {
    ServiceSpec {
      server: server.into(),
      source: Source::Image("traefik/whoami".into()),
      ports: vec![PortSpec {
        name: "http".into(),
        port: 80,
        host_port: None,
      }],
      env: Default::default(),
      volumes: vec![],
    }
  }

  #[test]
  fn ports_are_stable_and_unique() {
    let mut w = sample();
    w.apply_changes(&[
      Change::UpsertService {
        name: "a".into(),
        spec: image_service("node1"),
      },
      Change::UpsertService {
        name: "b".into(),
        spec: image_service("node1"),
      },
    ])
    .unwrap();
    w.allocate_ports().unwrap();
    assert_eq!(w.services["a"].host_ports["http"], 20000);
    assert_eq!(w.services["b"].host_ports["http"], 20001);
    // 删除 a 之后 b 的端口不变。
    w.apply_changes(&[Change::RemoveService { name: "a".into() }])
      .unwrap();
    w.allocate_ports().unwrap();
    assert_eq!(w.services["b"].host_ports["http"], 20001);
  }

  #[test]
  fn route_needs_gateway_and_port() {
    let mut w = sample();
    w.apply_changes(&[
      Change::UpsertService {
        name: "who".into(),
        spec: image_service("node1"),
      },
      Change::UpsertRoute {
        spec: RouteSpec {
          hostname: "Who.EXAMPLE.com".into(),
          service: "who".into(),
          port: None,
          gateway: None,
          auth: false,
        },
      },
    ])
    .unwrap();
    assert!(w.routes.contains_key("who.example.com"));
    let err = w.validate().unwrap_err();
    assert!(err.message.contains("默认网关"), "{}", err.message);
    w.apply_changes(&[Change::UpsertGateway {
      name: "edge".into(),
      spec: GatewaySpec {
        kind: GatewayKind::Caddy,
        server: "node1".into(),
        default: true,
        http_port: None,
        https_port: None,
        email: None,
        image: None,
      },
    }])
    .unwrap();
    w.validate().unwrap();
  }

  #[test]
  fn unknown_server_is_rejected() {
    let mut w = sample();
    w.apply_changes(&[Change::UpsertService {
      name: "x".into(),
      spec: image_service("nowhere"),
    }])
    .unwrap();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code, wharf_api_types::ErrorCode::NotFound);
  }

  #[test]
  fn writes_only_include_changes() {
    let current = sample();
    let mut desired = current.clone();
    assert!(desired.writes_from(&current).is_empty());
    desired
      .apply_changes(&[Change::UpsertService {
        name: "x".into(),
        spec: image_service("node1"),
      }])
      .unwrap();
    desired.allocate_ports().unwrap();
    let writes = desired.writes_from(&current);
    assert_eq!(writes.len(), 1);
  }
}
