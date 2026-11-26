//! plan、apply、status 共用的数据快照和小工具。

use std::{collections::BTreeMap, time::Duration};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ProjectState, PullPolicy},
  spec::{GatewayKind, GatewayTls},
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
pub const PULL_ATTEMPT_SECS: u64 = 30 * 60;

#[derive(Default)]
pub struct Snapshot {
  pub world: World,
  pub sso_login: BTreeMap<String, String>,
  pub agents: Vec<AgentRow>,
  pub accounts: Vec<AccountRow>,
  pub app_account_defaults: BTreeMap<String, String>,
  pub owned: Vec<OwnedRecord>,
  pub secrets: BTreeMap<String, String>,
  pub account_links: crate::app_accounts::AccountLinks,
  pub service_values: BTreeMap<String, String>,
  /// 每个服务最近一次成功部署在哪台服务器上。和配置里的服务器不同，说明迁移还没完成。
  pub deployed: BTreeMap<String, String>,
  /// cloudflare_tunnel 网关已经创建的隧道。
  pub tunnels: BTreeMap<String, db::TunnelRow>,
  /// 已绑定到边缘应用的自定义域名。
  pub edge_domains: Vec<db::EdgeDomainRow>,
  /// 边缘应用的同步结果。
  pub edge_cache: BTreeMap<String, crate::edge_sync::AppCache>,
  /// 厂商账号里的 Workers / Pages（最近一次同步）。
  pub edge_accounts:
    BTreeMap<String, Vec<wharf_api_types::view::EdgeProjectView>>,
  /// 同步时间（毫秒），key 是 `app:<名字>` / `account:<账号>`。
  pub edge_checked: BTreeMap<String, i64>,
  /// 每个服务上次成功部署。
  pub applied: BTreeMap<String, wharf_api_types::view::Applied>,
  /// 导入记录（已完成的）。
  pub imports: BTreeMap<String, wharf_api_types::view::ImportRecord>,
  /// 每个服务最近一次操作。
  pub ops: BTreeMap<String, wharf_api_types::view::LastOp>,
  pub heartbeats:
    BTreeMap<String, crate::service_monitor::heartbeat::Reading>,
  /// 服务备注。
  pub notes: BTreeMap<String, String>,
  pub server_notes: BTreeMap<String, String>,
  pub route_notes: BTreeMap<String, String>,
  /// Wharf 记录的线上版本。
  pub edge_expected: BTreeMap<String, db::EdgeExpected>,
  /// 边缘应用上次发布成功的配置指纹（或"发布中"）。
  pub edge_deployed: BTreeMap<String, String>,
  /// 连通性探测结果。
  pub reach: db::Reach,
}

impl Snapshot {
  /// 解析同步结果。解析不了的旧数据当作没同步过。
  fn with_edge_cache(
    mut self,
    rows: BTreeMap<String, (String, i64)>,
  ) -> Self {
    for (key, (data, checked)) in rows {
      if let Some(app) = key.strip_prefix("app:") {
        if let Ok(c) = serde_json::from_str(&data) {
          self.edge_cache.insert(app.to_string(), c);
        }
      } else if let Some(account) = key.strip_prefix("account:")
        && let Ok(list) = serde_json::from_str(&data)
      {
        self.edge_accounts.insert(account.to_string(), list);
      }
      self.edge_checked.insert(key, checked);
    }
    self
  }
}

/// 最近一次加载的密钥：拉镜像策略里的 `[[NAME]]`（例如镜像源地址里的访问口令）用它替换。
/// 每个调用 [pull_policy] 的地方都是刚加载完快照，所以是新的。
static SECRETS: std::sync::RwLock<BTreeMap<String, String>> =
  std::sync::RwLock::new(BTreeMap::new());

fn with_secrets(text: &str) -> String {
  let secrets = SECRETS.read().unwrap_or_else(|e| e.into_inner());
  crate::render::substitute(text, Some(&secrets))
    .unwrap_or_else(|_| text.to_string())
}

pub async fn load(db: &Db) -> Result<Snapshot, ApiError> {
  let snap = load_inner(db).await?;
  *SECRETS.write().unwrap_or_else(|e| e.into_inner()) =
    crate::secret_policy::non_system_secrets(&snap.secrets);
  let api = db
    .call(|c| crate::db::setting(c, crate::egress::API_VIA))
    .await?;
  crate::egress::apply_api_route(api.as_deref(), &snap);
  crate::source_trust::refresh_core_proxies(
    &snap.world,
    &snap.net(&snap.world),
  );
  Ok(snap)
}

async fn load_inner(db: &Db) -> Result<Snapshot, ApiError> {
  db.call_credentials(|c, key| {
    let world = World::from_rows(db::all_resources(c)?)?;
    let secrets =
      crate::oidc::with_client_secrets(&world, &db::secrets(c, key)?);
    let service_values = db::service_values(
      c,
      key,
      secrets.clone(),
      Some(&render::service_account_refs(&world)),
    )?;
    Ok(
      Snapshot {
        world,
        agents: db::agents(c)?,
        accounts: db::accounts(c)?,
        app_account_defaults: crate::app_accounts::defaults(c)?,
        sso_login: db::settings_with_prefix(c, "sso.login.")?,
        owned: db::owned_records(c)?,
        secrets,
        service_values,
        account_links: crate::app_accounts::account_links(c)?,
        deployed: db::deployed_servers(c)?,
        applied: db::applied(c)?,
        ops: db::service_ops(c)?,
        heartbeats: crate::service_monitor::heartbeat::load(c)?,
        notes: db::service_notes(c)?,
        server_notes: crate::notes::resource_notes(
          c,
          crate::world::KIND_SERVER,
        )?,
        route_notes: crate::notes::resource_notes(
          c,
          crate::world::KIND_ROUTE,
        )?,
        imports: db::imports(c)?,
        tunnels: db::tunnels(c)?,
        edge_domains: db::edge_domains(c)?,
        edge_cache: BTreeMap::new(),
        edge_accounts: BTreeMap::new(),
        edge_checked: BTreeMap::new(),
        edge_expected: db::edge_expected(c)?,
        edge_deployed: db::settings_with_prefix(c, "edge.deployed.")?,
        reach: db::reach(c)?,
      }
      .with_edge_cache(db::edge_cache(c)?),
    )
  })
  .await
}

impl Snapshot {
  pub fn render_values(
    &self,
    world: &World,
    service: &str,
  ) -> BTreeMap<String, String> {
    let mut values = crate::secret_policy::service_secrets(
      world,
      service,
      &crate::oidc::with_client_secrets(world, &self.secrets),
    );
    if let Some(row) = world.services.get(service) {
      values.extend(
        crate::secret_policy::service_account_refs(&row.spec)
          .filter(|(_, account)| {
            crate::app_accounts::linked_account(
              world,
              service,
              account,
              &self.account_links,
            )
          })
          .filter_map(|(name, _)| {
            Some((
              name.to_string(),
              self.service_values.get(name)?.clone(),
            ))
          }),
      );
    }
    values
  }

  pub fn agent(&self, server: &str) -> Option<&AgentRow> {
    self.agents.iter().find(|a| a.server == server)
  }

  pub fn net(&self, world: &World) -> Net {
    let base = Net::derive(&world.servers, &self.agents);
    let (gate_public, gate_login) =
      crate::gate::render_context(world, &base);
    Net {
      gate_public,
      gate_login,
      heartbeat_url: crate::gate::public_url().map(str::to_string),
      basic_auth: self
        .secrets
        .iter()
        .filter(|(k, _)| render::is_auth_secret(k))
        .filter_map(|(k, v)| {
          Some((k.clone(), render::BasicAuth::parse(v)?))
        })
        .collect(),
      link_ca_cert: self
        .secrets
        .get(crate::link::CA_CERT_SECRET)
        .map(|cert| render::hash(cert)),
      link_token_hashes: self
        .secrets
        .iter()
        .filter_map(|(name, token)| {
          Some((
            name.strip_prefix(crate::link::TOKEN_PREFIX)?.to_string(),
            render::hash(token),
          ))
        })
        .collect(),
      link_certs: crate::link_cert::LinkCertState::from_secrets(
        &self.secrets,
      ),
      reach: self.reach.clone(),
      cloudflare_ips: crate::cloudflare_ips::cached_cidrs(),
      tailnet_ips: self
        .secrets
        .get(crate::tailscale::OAUTH_SECRET)
        .map(|credential| {
          crate::tailnet_ips::cached_cidrs(credential)
        })
        .unwrap_or_default(),
      ..base
    }
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

pub fn committed_pull_policy(
  current: &World,
  server: &str,
) -> PullPolicy {
  current.servers.get(server).map_or_else(
    || {
      pull_policy(&ServerRow {
        settings: Default::default(),
        version: 0,
      })
    },
    pull_policy,
  )
}

pub fn pull_policy(server: &ServerRow) -> PullPolicy {
  PullPolicy {
    mirrors: server
      .settings
      .registry_mirrors
      .iter()
      .map(|(k, v)| {
        (k.clone(), v.iter().map(|m| with_secrets(m)).collect())
      })
      .collect(),
    mirrors_only: server.settings.mirrors_only,
    attempt_timeout_secs: PULL_ATTEMPT_SECS,
    // 经出口时拉代码、构建都指向本机的分流代理。
    git_proxy: match crate::egress::via(&server.settings) {
      Some(_) => Some(crate::egress::local_url()),
      None => server.settings.git_proxy.clone(),
    },
    github_mirror: server
      .settings
      .github_mirror
      .as_deref()
      .map(with_secrets),
    registry_proxy: crate::docker_proxy::wanted(&server.settings)
      .map(|(proxy, _)| proxy),
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
    &net.bind_ips(&row.spec.server),
    Some(secrets),
  )?;
  let resolved = crate::service_monitor::heartbeat::compose(
    &resolved,
    &row.spec,
    net.heartbeat_url.as_deref(),
    true,
  )?;
  let resolved = crate::refs::resolve(&resolved, name, world, net)?;
  let resolved =
    with_files(world, net, name, &resolved, Some(secrets))?;
  let hash = render::hash(&resolved);
  Ok((resolved, hash))
}

pub fn service_trial(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
) -> Result<String, ApiError> {
  let row = world.services.get(name).ok_or_else(|| {
    ApiError::not_found(format!("服务 {name} 不存在"))
  })?;
  let trial = render::trial_compose(name, &row.spec, Some(secrets))?;
  let trial = crate::refs::resolve(&trial, name, world, net)?;
  with_files(world, net, name, &trial, Some(secrets))
}

/// 加上服务的配置文件，内容里的密钥和 `[[@服务]]` 先替换好。
fn with_files(
  world: &World,
  net: &Net,
  name: &str,
  compose: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  let spec = &world.services[name].spec;
  let files = spec
    .files
    .iter()
    .map(|f| {
      let content = render::file_content(&f.content, secrets);
      Ok((
        f.path.clone(),
        crate::refs::resolve(&content, name, world, net)?,
      ))
    })
    .collect::<Result<Vec<_>, ApiError>>()?;
  render::add_files(name, spec, compose, &files)
}

pub fn service_template(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<String, ApiError> {
  let row = &world.services[name];
  let text = render::service_compose(
    name,
    &row.spec,
    &row.host_ports,
    &net.bind_ips(&row.spec.server),
    None,
  )?;
  let text = crate::service_monitor::heartbeat::compose(
    &text,
    &row.spec,
    net.heartbeat_url.as_deref(),
    false,
  )?;
  let text = crate::refs::resolve(&text, name, world, net)?;
  with_files(world, net, name, &text, None)
}

mod gateway;
pub use gateway::{
  GatewayRender, gateway_render, gateway_render_with_fill,
  redacted_config,
};

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
      "检查 Cloudflare token 权限：Zone → DNS → Edit，Zone → Zone → Read；Workers / Pages 还要 Account → Workers Scripts → Edit、Account → Cloudflare Pages → Edit、Zone → Workers Routes → Edit",
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
  crate::external_status::failure(err, "Cloudflare")
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

pub fn edge_provider(
  account: &AccountRow,
) -> Result<Box<dyn wharf_providers::EdgeProvider>, ApiError> {
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
  .edge
  .ok_or_else(|| {
    ApiError::invalid(format!(
      "账号 {} 不支持 Workers / Pages",
      account.name
    ))
  })
}

/// 厂商调用的总超时（客户端自己也有单次请求超时）。
pub async fn with_timeout<T>(
  what: &str,
  fut: impl std::future::Future<Output = Result<T, ProviderError>>,
) -> Result<T, ApiError> {
  match tokio::time::timeout(Duration::from_secs(90), fut).await {
    Ok(result) => result.map_err(provider_error),
    Err(_) => Err(crate::external_status::failure(
      ApiError::new(
        ErrorCode::Timeout,
        format!("{what} 超过 90 秒没有完成"),
      ),
      "Cloudflare",
    )),
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::*;
  use crate::{
    render::Net,
    world::{ServerRow, ServiceRow, World},
  };

  fn world(host_port: u16) -> World {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1",
      "source": {"image": "nginx:1"},
      "ports": [{"name": "http", "container": 80}],
    }))
    .unwrap();
    let mut world = World::default();
    world.servers.insert(
      "s1".to_string(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    world.services.insert(
      "app".to_string(),
      ServiceRow {
        spec,
        host_ports: BTreeMap::from([("http".to_string(), host_port)]),
        import: None,
        pins: BTreeMap::new(),
        commit: None,
        version: 1,
      },
    );
    world
  }

  fn fingerprint(compose: &str, config: &str) -> String {
    GatewayRender {
      compose: compose.to_string(),
      compose_hash: render::hash(compose),
      config: config.to_string(),
      config_hash: render::hash(config),
      sites: Vec::new(),
      needs_acme_dns: false,
      needs_link_cert: false,
      extra_files: BTreeMap::new(),
    }
    .fingerprint()
  }

  #[test]
  fn service_hash_follows_the_rendered_compose() {
    let net = Net::default();
    let secrets = BTreeMap::new();
    let same = world(21000);
    let moved = world(21001);
    let hash = |w: &World| {
      service_resolved(w, &net, "app", &secrets).unwrap().1
    };
    assert_eq!(hash(&same), hash(&same));
    assert_ne!(hash(&same), hash(&moved));
  }

  #[test]
  fn references_follow_the_target_service() {
    use wharf_api_types::spec::{PrivateAddr, PrivateNetwork};
    let mut net = Net::default();
    for (s, ip) in [("s1", "100.64.0.1"), ("s2", "100.64.0.2")] {
      net.private.insert(
        s.to_string(),
        PrivateAddr {
          ip: ip.to_string(),
          network: PrivateNetwork::Tailscale,
        },
      );
    }
    let with_web = |db_server: &str| {
      let mut w = world(21000);
      w.servers.insert(
        "s2".to_string(),
        ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
      let mut web = w.services["app"].clone();
      web.spec.env.insert("DB".into(), "http://[[@app]]/".into());
      w.services.insert("web".to_string(), web);
      w.services.get_mut("app").unwrap().spec.server =
        db_server.into();
      w
    };
    let secrets = BTreeMap::new();
    let (here, _) =
      service_resolved(&with_web("s1"), &net, "web", &secrets)
        .unwrap();
    assert!(here.contains("http://100.64.0.1:21000/"));
    let (moved, _) =
      service_resolved(&with_web("s2"), &net, "web", &secrets)
        .unwrap();
    assert!(moved.contains("http://100.64.0.2:21000/"));

    let mut gone = with_web("s1");
    gone.services.remove("app");
    let err =
      service_resolved(&gone, &net, "web", &secrets).unwrap_err();
    assert!(err.message.contains("不存在"));
  }

  #[test]
  fn gateway_fingerprint_covers_both_payloads() {
    assert_eq!(fingerprint("a", "b"), fingerprint("a", "b"));
    assert_ne!(fingerprint("a", "b"), fingerprint("a2", "b"));
    assert_ne!(fingerprint("a", "b"), fingerprint("a", "b2"));
  }
  #[test]
  fn gate_core_uses_local_upstream() {
    let mut world = World::default();
    for (name, server) in [("edge", "s1"), ("other", "s2")] {
      world.gateways.insert(
        name.into(),
        crate::world::GatewayRow {
          version: 1,
          spec: serde_json::from_value(
            serde_json::json!({"kind":"caddy","server":server}),
          )
          .unwrap(),
        },
      );
    }
    for (host, gateway, sso) in [
      ("core.example.test", "edge", false),
      ("a.example.test", "edge", true),
      ("b.example.test", "other", true),
    ] {
      let spec=serde_json::from_value(serde_json::json!({"hostname":host,"gateway":gateway,"upstream":"127.0.0.1:7700","sso":if sso {Some(serde_json::json!({"mode":"gate"}))} else {None}})).unwrap();
      world.routes.insert(
        host.into(),
        crate::world::RouteRow {
          id: host.into(),
          version: 1,
          spec,
        },
      );
    }
    let net = Net {
      gate_login: Some("https://core.example.test".into()),
      gate_public: Some("public".into()),
      ..Default::default()
    };
    assert!(
      gateway_render(&world, &net, "edge")
        .unwrap()
        .config
        .contains("core http://127.0.0.1:7700")
    );
    assert!(
      gateway_render(&world, &net, "other")
        .unwrap()
        .config
        .contains("core https://core.example.test")
    );
  }
}
