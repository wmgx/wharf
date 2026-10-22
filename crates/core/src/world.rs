//! 期望状态的内存表示：从数据库读出来，叠加 plan 请求里的修改，再整体校验。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  spec::{
    BuildSource, Change, EdgeAppSpec, Fleet, GatewayKind,
    GatewaySpec, GatewayTls, RouteSpec, ServerSettings, ServiceSpec,
    Source,
  },
  validate_name,
};

use crate::db::{ResourceRow, Write, json_err};

pub const KIND_SERVER: &str = "server";
pub const KIND_SERVICE: &str = "service";
pub const KIND_GATEWAY: &str = "gateway";
pub const KIND_ROUTE: &str = "route";
pub const KIND_EDGE: &str = "edge";

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
pub struct EdgeRow {
  pub spec: EdgeAppSpec,
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
  pub edge_apps: BTreeMap<String, EdgeRow>,
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
        KIND_EDGE => {
          world.edge_apps.insert(
            row.name,
            EdgeRow {
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
    for (name, r) in &self.edge_apps {
      out.insert(format!("{KIND_EDGE}/{name}"), r.version);
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
        Change::UpsertEdgeApp { name, spec } => {
          validate_name("边缘应用", name)?;
          let version =
            self.edge_apps.get(name).map(|r| r.version).unwrap_or(0);
          self.edge_apps.insert(
            name.clone(),
            EdgeRow {
              spec: spec.clone(),
              version,
            },
          );
        }
        Change::RemoveEdgeApp { name } => {
          if self.edge_apps.remove(name).is_none() {
            return Err(
              ApiError::not_found(format!("边缘应用 {name} 不存在"))
                .suggest("wharf edge list"),
            );
          }
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
    self
      .edge_apps
      .retain(|name, _| fleet.edge_apps.contains_key(name));
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
    for (name, spec) in &fleet.edge_apps {
      changes.push(Change::UpsertEdgeApp {
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

  /// 路由实际使用的网关。指向边缘应用的路由不经过网关。
  pub fn route_gateway<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    if self.edge_apps.contains_key(&route.service) {
      return None;
    }
    route.gateway.as_deref().or_else(|| self.default_gateway())
  }

  /// 路由的上游地址：直接写的地址，或按服务算出来的。
  pub fn route_upstream(
    &self,
    net: &crate::render::Net,
    gateway_server: &str,
    host: &str,
    route: &RouteSpec,
  ) -> Result<String, ApiError> {
    if let Some(up) = &route.upstream {
      return Ok(up.clone());
    }
    let port = self.route_port(route).ok_or_else(|| {
      ApiError::invalid(format!("路由 {host} 没有可用的端口"))
    })?;
    crate::render::upstream(
      self,
      net,
      gateway_server,
      &route.service,
      port,
    )
  }

  /// 路由指向的端口名。
  pub fn route_port<'a>(
    &'a self,
    route: &'a RouteSpec,
  ) -> Option<&'a str> {
    self.service_port(&route.service, route.port.as_deref())
  }

  /// 服务的端口名：指定了就用，只有一个端口时取它。
  pub fn service_port<'a>(
    &'a self,
    service: &str,
    port: Option<&'a str>,
  ) -> Option<&'a str> {
    let service = self.services.get(service)?;
    match port {
      Some(port) => Some(port),
      None if service.spec.ports.len() == 1 => {
        Some(service.spec.ports[0].name.as_str())
      }
      None => None,
    }
  }

  fn validate_paths(
    &self,
    host: &str,
    route: &RouteSpec,
  ) -> Result<(), ApiError> {
    if route.paths.is_empty() {
      return Ok(());
    }
    let bad =
      |m: String| Err(ApiError::invalid(format!("路由 {host}：{m}")));
    if let Some(gw) = self.route_gateway(route)
      && self
        .gateways
        .get(gw)
        .is_some_and(|g| g.spec.kind != GatewayKind::Caddy)
    {
      return bad("按路径转发只支持 caddy 网关".into());
    }
    let mut seen = BTreeSet::new();
    for p in &route.paths {
      let ok = p.path.starts_with('/')
        && !p.path.chars().any(|c| {
          c.is_whitespace() || matches!(c, '{' | '}' | '"' | '#')
        });
      if !ok {
        return bad(format!(
          "路径 {} 要以 / 开头，不能有空格和 {{}}\"#",
          p.path
        ));
      }
      if !seen.insert(p.path.as_str()) {
        return bad(format!("路径 {} 重复", p.path));
      }
      match (&p.service, &p.upstream) {
        (Some(service), None) => {
          if !self.services.contains_key(service) {
            return bad(format!(
              "路径 {} 指向的服务 {service} 不存在",
              p.path
            ));
          }
          let Some(port) =
            self.service_port(service, p.port.as_deref())
          else {
            return bad(format!(
              "路径 {} 要指定服务 {service} 的端口",
              p.path
            ));
          };
          if !self.services[service]
            .spec
            .ports
            .iter()
            .any(|x| x.name == port)
          {
            return bad(format!(
              "服务 {service} 没有名为 {port} 的端口"
            ));
          }
        }
        (None, Some(up)) => {
          if p.port.is_some() || !valid_upstream(up) {
            return bad(format!(
              "路径 {} 的上游 {up} 要写成 主机:端口，例如 127.0.0.1:8080",
              p.path
            ));
          }
        }
        _ => {
          return bad(format!(
            "路径 {} 要指定服务或上游（二选一）",
            p.path
          ));
        }
      }
    }
    Ok(())
  }

  fn check_route_gateway(
    &self,
    host: &str,
    route: &RouteSpec,
  ) -> Result<(), ApiError> {
    match self.route_gateway(route) {
      None => Err(
        ApiError::invalid(format!(
          "路由 {host} 没有指定网关，也没有默认网关"
        ))
        .with_hint("先创建一个默认网关")
        .suggest(
          "wharf gateway add <name> --server <server> --default",
        ),
      ),
      Some(gw) if !self.gateways.contains_key(gw) => Err(
        ApiError::invalid(format!("路由 {host} 的网关 {gw} 不存在"))
          .suggest("wharf gateway list"),
      ),
      Some(_) => Ok(()),
    }
  }

  /// 整体校验。`joined` 是已经完成 join 的服务器。
  pub fn validate(&self) -> Result<(), ApiError> {
    for (name, service) in &self.services {
      validate_service(self, name, &service.spec)?;
    }
    for (name, app) in &self.edge_apps {
      crate::edge::validate_app(self, name, &app.spec)?;
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
        let s = &gateway.spec;
        if s.account.is_none() {
          return Err(
            ApiError::invalid(format!(
              "网关 {name} 是 cloudflare_tunnel，要指定在哪个厂商账号下建隧道"
            ))
            .suggest("wharf account list"),
          );
        }
        if s.http_port.is_some()
          || s.https_port.is_some()
          || s.email.is_some()
          || s.tls != GatewayTls::Auto
        {
          return Err(ApiError::invalid(format!(
            "网关 {name}：http_port、https_port、email、tls 只适用于 caddy 网关"
          )));
        }
        continue;
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
      if self.edge_apps.contains_key(&route.spec.service) {
        crate::edge::validate_route(host, &route.spec)?;
        continue;
      }
      self.check_route_gateway(host, &route.spec)?;
      if let Some(up) = &route.spec.upstream {
        if !route.spec.service.is_empty() || route.spec.port.is_some()
        {
          return Err(ApiError::invalid(format!(
            "路由 {host}：服务和上游地址二选一"
          )));
        }
        if !valid_upstream(up) {
          return Err(ApiError::invalid(format!(
            "路由 {host} 的上游 {up} 要写成 主机:端口，例如 127.0.0.1:8080"
          )));
        }
        self.validate_paths(host, &route.spec)?;
        continue;
      }
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
      self.validate_paths(host, &route.spec)?;
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
          Source::Image(_) | Source::Build(_) => port.host_port,
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
    diff_map(
      &current.edge_apps,
      &self.edge_apps,
      KIND_EDGE,
      |r| (to_json(&r.spec), json!({})),
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

/// 代码来源（本机上传或 git）和相对路径的校验，服务和边缘应用共用。
/// `what` 例如"服务 api"。
pub fn check_code_source(
  what: &str,
  upload: Option<&String>,
  git: Option<&wharf_api_types::spec::GitSource>,
  paths: &[&Option<String>],
) -> Result<(), ApiError> {
  let bad = |m: &str| Err(ApiError::invalid(format!("{what} 的{m}")));
  match (upload, git) {
    (Some(sha), None) => {
      if sha.len() != 64
        || !sha.bytes().all(|c| c.is_ascii_hexdigit())
      {
        return bad("代码包 sha256 不合法");
      }
    }
    (None, Some(git)) => {
      let repo = git.repo.trim();
      if !repo.starts_with("https://")
        || repo.contains(char::is_whitespace)
        || repo.contains('@')
      {
        return Err(
          ApiError::invalid(format!(
            "{what} 的 git 仓库要写 https 地址，不要带账号密码"
          ))
          .with_hint(
            "私有仓库把 token 存成密钥，用 token_secret 引用",
          ),
        );
      }
      if git.reference.trim().is_empty()
        || git.reference.contains(char::is_whitespace)
        || git.reference.starts_with('-')
      {
        return bad("git ref 不合法");
      }
      if let Some(secret) = &git.token_secret
        && (secret.is_empty()
          || !secret
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_'))
      {
        return bad("token_secret 要写密钥名");
      }
    }
    _ => {
      return Err(ApiError::invalid(format!(
        "{what}：代码来源要给出 upload（本机目录）或 git 仓库，二选一"
      )));
    }
  }
  for p in paths.iter().copied().flatten() {
    let p = p.trim_start_matches("./");
    if p.is_empty()
      || p.starts_with('/')
      || p.split('/').any(|seg| seg == "..")
    {
      return bad(&format!("路径 {p} 不合法：要写代码里的相对路径"));
    }
  }
  Ok(())
}

/// 构建来源：代码来源二选一，路径只能是代码里的相对路径。
fn check_build(name: &str, b: &BuildSource) -> Result<(), ApiError> {
  let bad = |what: &str| {
    Err(ApiError::invalid(format!("服务 {name} 的{what}")))
  };
  check_code_source(
    &format!("服务 {name}"),
    b.upload.as_ref(),
    b.git.as_ref(),
    &[&b.path, &b.dockerfile],
  )?;
  if b.base.as_deref().is_some_and(|i| {
    i.trim().is_empty() || i.contains(char::is_whitespace)
  }) {
    return bad("基础镜像名不合法");
  }
  if b.start.as_deref().is_some_and(|s| s.trim().is_empty()) {
    return bad("启动命令为空");
  }
  if b.install.as_deref().is_some_and(|s| s.trim().is_empty()) {
    return bad("安装命令为空");
  }
  if let Some(t) = &b.template
    && !wharf_api_types::build::TEMPLATES
      .iter()
      .any(|(id, ..)| id == t)
  {
    return bad(&format!(
      "模板 {t} 不存在，可选：python、node、go、static"
    ));
  }
  if let Some(content) = &b.dockerfile_content {
    if content.trim().is_empty() {
      return bad("Dockerfile 内容为空");
    }
    if b.dockerfile.is_some()
      || b.template.is_some()
      || b.base.is_some()
      || b.start.is_some()
      || b.install.is_some()
    {
      return bad(
        "写了 Dockerfile 内容时，不再用 dockerfile、template、base、start、install",
      );
    }
  }
  Ok(())
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
  if name == crate::render::BACKUP_PROJECT {
    return Err(ApiError::invalid(format!(
      "服务名 {name} 留给备份服务用，换一个名字"
    )));
  }
  if !world.servers.contains_key(&spec.server) {
    return Err(server_not_found(&spec.server));
  }
  if let Some(backup) = &spec.backup {
    if !world.servers.contains_key(&backup.to) {
      return Err(server_not_found(&backup.to));
    }
    if backup.to == spec.server {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的备份要存到另一台服务器，不能是它所在的 {}",
        spec.server
      )));
    }
    if spec.volumes.is_empty()
      && !matches!(spec.source, Source::Compose { .. })
    {
      return Err(ApiError::invalid(format!(
        "服务 {name} 没有数据卷，不需要备份"
      )));
    }
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
    Source::Build(b) => check_build(name, b)?,
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

/// `主机:端口`，主机里不能有空白和 `/`。
fn valid_upstream(up: &str) -> bool {
  up.rsplit_once(':').is_some_and(|(h, port)| {
    !h.is_empty()
      && port.parse::<u16>().is_ok()
      && !h.chars().any(|c| c.is_whitespace() || c == '/')
  })
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
      backup: None,
      adopt: None,
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
          paths: vec![],
          upstream: None,
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
        tls: Default::default(),
        email: None,
        image: None,
        account: None,
      },
    }])
    .unwrap();
    w.validate().unwrap();
    // 直接指向地址：不需要服务，和服务二选一。
    let mut up = w.routes["who.example.com"].spec.clone();
    up.hostname = "core.example.com".into();
    up.service = String::new();
    up.upstream = Some("127.0.0.1:7700".into());
    w.apply_changes(&[Change::UpsertRoute { spec: up.clone() }])
      .unwrap();
    w.validate().unwrap();
    up.service = "who".into();
    w.apply_changes(&[Change::UpsertRoute { spec: up }])
      .unwrap();
    let err = w.validate().unwrap_err();
    assert!(err.message.contains("二选一"), "{}", err.message);
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
