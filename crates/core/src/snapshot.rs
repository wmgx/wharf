//! plan、apply、status 共用的数据快照和小工具。

use std::{collections::BTreeMap, time::Duration};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ProjectState, PullPolicy},
  spec::GatewayKind,
};
use wharf_providers::{
  Credentials, DnsProvider, ProviderError, error::code,
};

use crate::{
  db::{self, AccountRow, AgentRow, Db, OwnedRecord},
  render::{self, Net},
  world::{ServerRow, World},
};

/// 每次 `docker pull` 的超时。国内拉海外镜像慢，给足时间，但不会无限等。
pub const PULL_ATTEMPT_SECS: u64 = 600;

pub struct Snapshot {
  pub world: World,
  pub agents: Vec<AgentRow>,
  pub accounts: Vec<AccountRow>,
  pub owned: Vec<OwnedRecord>,
  pub secrets: BTreeMap<String, String>,
  /// 每个服务最近一次成功部署在哪台服务器上。和配置里的服务器不同，说明迁移还没完成。
  pub deployed: BTreeMap<String, String>,
  /// cloudflare_tunnel 网关已经创建的隧道。
  pub tunnels: BTreeMap<String, db::TunnelRow>,
}

pub async fn load(db: &Db) -> Result<Snapshot, ApiError> {
  db.call(|c| {
    Ok(Snapshot {
      world: World::from_rows(db::all_resources(c)?)?,
      agents: db::agents(c)?,
      accounts: db::accounts(c)?,
      owned: db::owned_records(c)?,
      secrets: db::secrets(c)?,
      deployed: db::deployed_servers(c)?,
      tunnels: db::tunnels(c)?,
    })
  })
  .await
}

impl Snapshot {
  pub fn agent(&self, server: &str) -> Option<&AgentRow> {
    self.agents.iter().find(|a| a.server == server)
  }

  pub fn net(&self, world: &World) -> Net {
    let mut net = Net {
      basic_auth: self
        .secrets
        .get(render::BASIC_AUTH_SECRET)
        .and_then(|v| render::BasicAuth::parse(v)),
      ..Net::default()
    };
    for (name, server) in &world.servers {
      let report = self.agent(name).and_then(|a| a.report.as_ref());
      if let Some(addr) = server
        .settings
        .private_addr
        .clone()
        .or_else(|| report.and_then(|r| r.private_addr.clone()))
      {
        net.private.insert(name.clone(), addr);
      }
      if let Some(r) = report {
        net.lan_ips.insert(name.clone(), r.lan_ips.clone());
      }
      if let Some(ip) = server
        .settings
        .public_ip
        .clone()
        .or_else(|| report.and_then(|r| r.public_ip.clone()))
      {
        net.public_ip.insert(name.clone(), ip);
      }
    }
    net
  }

  /// hostname 所属的厂商账号和 zone，取最长匹配。
  pub fn account_for(
    &self,
    hostname: &str,
  ) -> Option<(&AccountRow, String)> {
    self
      .accounts
      .iter()
      .filter_map(|a| {
        wharf_providers::match_zone(&a.zones, hostname)
          .map(|z| (a, z.to_string()))
      })
      .max_by_key(|(_, z)| z.len())
  }
}

pub fn pull_policy(server: &ServerRow) -> PullPolicy {
  PullPolicy {
    mirrors: server.settings.registry_mirrors.clone(),
    mirrors_only: server.settings.mirrors_only,
    attempt_timeout_secs: PULL_ATTEMPT_SECS,
  }
}

/// 服务实际要部署的内容（已替换密钥）和它的指纹。
pub fn service_resolved(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
) -> Result<(String, String), ApiError> {
  let row = world.services.get(name).ok_or_else(|| {
    ApiError::not_found(format!("服务 {name} 不存在"))
  })?;
  let resolved = render::service_compose(
    name,
    &row.spec,
    &row.host_ports,
    net.private.get(&row.spec.server).map(|a| a.ip.as_str()),
    Some(secrets),
  )?;
  let hash = render::hash(&resolved);
  Ok((resolved, hash))
}

pub fn service_template(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<String, ApiError> {
  let row = &world.services[name];
  render::service_compose(
    name,
    &row.spec,
    &row.host_ports,
    net.private.get(&row.spec.server).map(|a| a.ip.as_str()),
    None,
  )
}

/// 网关的 compose、Caddyfile，以及它承载的站点。
pub struct GatewayRender {
  /// cloudflare_tunnel 的 compose 里 token 是占位，执行时才替换。
  pub compose: String,
  pub compose_hash: String,
  /// caddy：Caddyfile；cloudflare_tunnel：入口规则（JSON）。
  pub config: String,
  pub config_hash: String,
  pub sites: Vec<render::Site>,
}

impl GatewayRender {
  /// 隧道的入口规则：`(hostname, http://上游)`。
  pub fn tunnel_rules(&self) -> Vec<(String, String)> {
    self
      .sites
      .iter()
      .map(|s| (s.hostname.clone(), format!("http://{}", s.upstream)))
      .collect()
  }
}

/// 给人看的网关配置：不带出登录保护的密码哈希。
pub fn redacted_config(config: &str, net: &Net) -> String {
  match &net.basic_auth {
    Some(a) => config.replace(&a.hash, "<bcrypt>"),
    None => config.to_string(),
  }
}

pub fn gateway_render(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<GatewayRender, ApiError> {
  let gateway = world.gateways.get(name).ok_or_else(|| {
    ApiError::not_found(format!("网关 {name} 不存在"))
  })?;
  let mut sites = Vec::new();
  for (host, route) in &world.routes {
    if world.route_gateway(&route.spec) != Some(name) {
      continue;
    }
    let port = world.route_port(&route.spec).ok_or_else(|| {
      ApiError::invalid(format!("路由 {host} 没有可用的端口"))
    })?;
    let tunnel = gateway.spec.kind == GatewayKind::CloudflareTunnel;
    if route.spec.auth && tunnel {
      return Err(ApiError::invalid(format!(
        "路由 {host}：cloudflare_tunnel 网关还不支持登录保护，换 caddy 网关或去掉 --auth"
      )));
    }
    if route.spec.auth && net.basic_auth.is_none() {
      return Err(
        ApiError::invalid(format!(
          "路由 {host} 开启了登录保护，但还没有设置账号"
        ))
        .with_hint(
          "值写成 用户名:密码，从标准输入读取，不会出现在命令行里",
        )
        .suggest(format!(
          "wharf secret set {}",
          render::BASIC_AUTH_SECRET
        )),
      );
    }
    sites.push(render::Site {
      auth: route.spec.auth,
      hostname: host.clone(),
      upstream: render::upstream(
        world,
        net,
        &gateway.spec.server,
        &route.spec.service,
        port,
      )?,
    });
  }
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  let (compose, config) = match gateway.spec.kind {
    GatewayKind::Caddy => (
      render::gateway_compose(name, &gateway.spec),
      render::caddyfile(
        name,
        &gateway.spec,
        &sites,
        net.basic_auth.as_ref(),
      ),
    ),
    GatewayKind::CloudflareTunnel => {
      let rules: Vec<serde_json::Value> = sites
        .iter()
        .map(|s| {
          serde_json::json!({
            "hostname": s.hostname,
            "service": format!("http://{}", s.upstream),
          })
        })
        .collect();
      (
        render::tunnel_compose(name, &gateway.spec),
        serde_json::to_string_pretty(&rules).unwrap_or_default(),
      )
    }
  };
  Ok(GatewayRender {
    compose_hash: render::hash(&compose),
    config_hash: render::hash(&config),
    compose,
    config,
    sites,
  })
}

/// 查询一台服务器上若干 project 的现状。
pub async fn project_status(
  hub: &crate::hub::Hub,
  server: &str,
  projects: Vec<String>,
  timeout: Duration,
) -> Result<BTreeMap<String, ProjectState>, ApiError> {
  let states: Vec<ProjectState> = hub
    .call(
      server,
      wharf_api_types::agent::AgentOp::ProjectStatus { projects },
      timeout,
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await?;
  Ok(states.into_iter().map(|s| (s.project.clone(), s)).collect())
}

pub fn provider_error(e: ProviderError) -> ApiError {
  e.log("dns");
  let hint = match e.code {
    code::AUTH_FAILED => Some(
      "检查 Cloudflare token 权限：Zone → DNS → Edit，Zone → Zone → Read",
    ),
    code::PROVIDER_REJECTED => Some(
      "检查 token 是否完整复制、是否已过期或被删除；DNS 记录冲突时到 Cloudflare 面板确认",
    ),
    code::ZONE_NOT_FOUND => {
      Some("执行 wharf account discover <account> 重新发现 zone")
    }
    code::RATE_LIMITED
    | code::PROVIDER_UNAVAILABLE
    | code::TIMEOUT => Some("稍后重试"),
    _ => None,
  };
  let mut err = ApiError::new(
    ErrorCode::Provider,
    format!("{}（{}）", e.message, e.code),
  );
  if let Some(hint) = hint {
    err = err.with_hint(hint);
  }
  err
}

pub fn dns_provider(
  account: &AccountRow,
) -> Result<Box<dyn DnsProvider>, ApiError> {
  let factory =
    wharf_providers::factory(&account.kind).ok_or_else(|| {
      ApiError::internal(format!("不支持的厂商类型 {}", account.kind))
    })?;
  (factory.build)(Credentials {
    name: account.name.clone(),
    token: account.token.clone(),
    zones: account.zones.clone(),
  })
  .map_err(provider_error)?
  .dns
  .ok_or_else(|| {
    ApiError::internal(format!("账号 {} 不支持 DNS", account.name))
  })
}

pub fn tunnel_provider(
  account: &AccountRow,
) -> Result<Box<dyn wharf_providers::TunnelProvider>, ApiError> {
  let factory =
    wharf_providers::factory(&account.kind).ok_or_else(|| {
      ApiError::internal(format!("不支持的厂商类型 {}", account.kind))
    })?;
  (factory.build)(Credentials {
    name: account.name.clone(),
    token: account.token.clone(),
    zones: account.zones.clone(),
  })
  .map_err(provider_error)?
  .tunnel
  .ok_or_else(|| {
    ApiError::invalid(format!("账号 {} 不支持隧道", account.name))
  })
}

/// 厂商调用的总超时（客户端自己也有单次请求超时）。
pub async fn with_timeout<T>(
  what: &str,
  fut: impl std::future::Future<Output = Result<T, ProviderError>>,
) -> Result<T, ApiError> {
  match tokio::time::timeout(Duration::from_secs(90), fut).await {
    Ok(result) => result.map_err(provider_error),
    Err(_) => Err(ApiError::new(
      ErrorCode::Timeout,
      format!("{what} 超过 90 秒没有完成"),
    )),
  }
}
