//! plan、apply、status 共用的数据快照和小工具。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
  time::Duration,
};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ProjectState, PullPolicy},
  spec::{GatewayKind, GatewayTls},
  view::SsoLoginState,
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
  pub core_server: Option<String>,
  pub api_via: Option<String>,
  pub heartbeat_url: Option<String>,
  pub sso_login: BTreeMap<String, SsoLoginState>,
  pub log_values: Arc<Vec<String>>,
  pub agents: Vec<AgentRow>,
  pub accounts: Vec<AccountRow>,
  pub app_account_defaults: BTreeMap<String, String>,
  pub app_account_names: std::collections::BTreeSet<String>,
  pub owned: Vec<OwnedRecord>,
  pub secrets: BTreeMap<String, String>,
  pub secret_restrictions: crate::secret_restrictions::Restrictions,
  pub account_links: crate::app_accounts::AccountLinks,
  pub service_values: BTreeMap<String, String>,
  /// 每个服务最近一次成功部署在哪台服务器上。和配置里的服务器不同，说明迁移还没完成。
  pub deployed: BTreeMap<String, String>,
  pub pending: crate::pending::PendingState,
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

pub fn service_runtime_server<'a>(
  snap: &'a Snapshot,
  service: &str,
) -> Option<&'a str> {
  let row = snap.world.services.get(service)?;
  crate::report_guard::metric_owner_server(
    service,
    &snap.deployed,
    &snap.pending,
  )
  .or(Some(row.spec.server.as_str()))
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

#[tokio::test]
async fn snapshot_masks_legacy_errors_without_rewriting_rows() {
  let db = Db::memory();
  let sso =
    r#"{"at":1,"ok":false,"error":"login: fixture-legacy-key"}"#;
  db.call_credentials(move |c, key| {
    key.put_secret(c, "LEGACY_KEY", "fixture-legacy-key", 1, true)?;
    c.execute(
      "INSERT INTO service_ops (service, action, run_id, status, at, error)
       VALUES ('app', '部署', 'r1', 'failed', 1, 'pull: fixture-legacy-key')",
      [],
    )
    .map_err(db::sql_err)?;
    db::set_setting(c, "sso.login.app.example.test", Some(sso))
  })
  .await
  .unwrap();
  let snap = load_inner(&db).await.unwrap();
  assert_eq!(snap.ops["app"].error.as_deref(), Some("pull: ***"));
  assert_eq!(
    snap.sso_login["app.example.test"].error.as_deref(),
    Some("login: ***")
  );
  db.call(move |c| {
    assert_eq!(
      db::service_ops(c)?["app"].error.as_deref(),
      Some("pull: fixture-legacy-key")
    );
    let raw = db::setting(c, "sso.login.app.example.test")?;
    assert_eq!(raw.as_deref(), Some(sso));
    Ok(())
  })
  .await
  .unwrap();
}

/// 最近一次加载的密钥：拉镜像策略里的 `[[NAME]]`（例如镜像源地址里的访问口令）用它替换。
/// 每个调用 [pull_policy] 的地方都是刚加载完快照，所以是新的。
static SECRETS: std::sync::RwLock<BTreeMap<String, String>> =
  std::sync::RwLock::new(BTreeMap::new());

fn with_secrets(
  text: &str,
  secrets: &BTreeMap<String, String>,
) -> String {
  crate::render::substitute(text, Some(secrets))
    .unwrap_or_else(|_| text.to_string())
}

pub async fn load(db: &Db) -> Result<Snapshot, ApiError> {
  let snap = load_inner(db).await?;
  *SECRETS.write().unwrap_or_else(|e| e.into_inner()) =
    crate::secret_policy::non_system_secrets(&snap.secrets);
  crate::egress::apply_api_route(&snap);
  crate::source_trust::refresh_core_proxies(
    &snap.world,
    &snap.net(&snap.world),
  );
  Ok(snap)
}

pub(crate) async fn load_inner(
  db: &Db,
) -> Result<Snapshot, ApiError> {
  db.call_credentials(|c, key| {
    let world = World::from_rows(db::all_resources(c)?)?;
    let agents = db::agents(c)?;
    let core_server = crate::core_node::load_persisted(c)?
      .filter(|(server, key)| {
        world.servers.contains_key(server)
          && agents.iter().any(|a| {
            &a.server == server && a.public_key.as_ref() == Some(key)
          })
      })
      .map(|(server, _)| server);
    let secrets =
      crate::oidc::with_client_secrets(&world, &db::secrets(c, key)?);
    let service_values = db::service_values(
      c,
      key,
      secrets.clone(),
      Some(&render::service_account_refs(&world)),
    )?;
    let accounts = db::accounts(c)?;
    let log_values =
      crate::log_redact::update(c, key, &world, &secrets, &accounts)?;
    let redact =
      |text: &str| wharf_api_types::mask_values(text, &log_values);
    let sso_login = db::settings_with_prefix(c, "sso.login.")?
      .into_iter()
      .filter_map(|(host, value)| {
        let mut result: SsoLoginState =
          serde_json::from_str(&value).ok()?;
        result.error = result.error.as_deref().map(redact);
        Some((host, result))
      })
      .collect();
    let mut ops = db::service_ops(c)?;
    for op in ops.values_mut() {
      op.error = op.error.as_deref().map(redact);
    }
    Ok(
      Snapshot {
        world,
        agents,
        core_server,
        api_via: db::setting(c, crate::egress::API_VIA)?,
        heartbeat_url: db::setting(c, "core.heartbeat_url")?,
        accounts,
        app_account_defaults: crate::app_accounts::defaults(c)?,
        app_account_names: {
          let mut stmt = c
            .prepare("SELECT name FROM app_accounts")
            .map_err(db::sql_err)?;
          stmt
            .query_map([], |r| r.get(0))
            .and_then(Iterator::collect)
            .map_err(db::sql_err)?
        },
        sso_login,
        log_values,
        owned: db::owned_records(c)?,
        secrets,
        secret_restrictions: crate::secret_restrictions::load(c)?,
        service_values,
        account_links: crate::app_accounts::account_links(c)?,
        deployed: db::deployed_servers(c)?,
        pending: crate::pending::load(c)?,
        applied: db::applied(c)?,
        ops,
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
    let mut base = Net::derive(&world.servers, &self.agents);
    base.core_server = crate::core_node::server_of(self);
    base.core_listener = crate::gate::core_listener();
    base.acme_dns_url = base
      .core_listener
      .and_then(|(port, _)| {
        crate::join::default_url_with(
          world,
          &base,
          port,
          crate::gate::public_url(),
        )
      })
      .filter(|url| crate::caddy_validate::valid_public_url(url));
    let (gate_public, gate_login) =
      crate::gate::render_context(world, &base);
    Net {
      gate_public,
      gate_login,
      heartbeat_url: self.heartbeat_url.clone().or_else(|| {
        crate::service_monitor::heartbeat::base_url(
          world,
          &base,
          base.core_listener.map(|(port, _)| port),
          crate::gate::public_url(),
        )
      }),
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

  pub(crate) fn gateway_has_external_dns(
    &self,
    world: &World,
    gateway: &str,
  ) -> bool {
    world.routes.iter().any(|(host, r)| {
      world.route_gateways(&r.spec).contains(&gateway)
        && self.account_for(host).is_none()
    })
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
  let secrets = SECRETS.read().unwrap_or_else(|e| e.into_inner());
  pull_policy_with_secrets(server, &secrets)
}

fn pull_policy_with_secrets(
  server: &ServerRow,
  secrets: &BTreeMap<String, String>,
) -> PullPolicy {
  PullPolicy {
    mirrors: server
      .settings
      .registry_mirrors
      .iter()
      .map(|(k, v)| {
        (
          k.clone(),
          v.iter().map(|m| with_secrets(m, secrets)).collect(),
        )
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
      .map(|m| with_secrets(m, secrets)),
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
  resolve_service(world, net, name, secrets, false)
}

pub(crate) fn service_hash(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
  observed: Option<&str>,
) -> Result<String, ApiError> {
  let (_, hash) = service_resolved(world, net, name, secrets)?;
  if let Some(observed) = observed
    && observed != hash
    && net.private.values().any(|a| a.ip.contains(':'))
    && resolve_service(world, net, name, secrets, true)
      .is_ok_and(|(_, legacy)| legacy == observed)
  {
    // 旧指纹和现有内容完全一致时，保留已有部署。下次部署写入裸 IPv6。
    return Ok(observed.into());
  }
  Ok(hash)
}

fn resolve_service(
  world: &World,
  net: &Net,
  name: &str,
  secrets: &BTreeMap<String, String>,
  legacy: bool,
) -> Result<(String, String), ApiError> {
  let row = world.services.get(name).ok_or_else(|| {
    ApiError::not_found(format!("服务 {name} 不存在"))
  })?;
  let component = crate::compose_env::component_settings(&row.spec);
  let (spec, substitutions) = crate::variables::prepare_spec(
    world,
    net,
    name,
    &component,
    Some(secrets),
  )?;
  let (resolved, mounts) = render::service_compose(
    name,
    &spec,
    &row.host_ports,
    &net.bind_ips(&row.spec),
    Some(secrets),
  )?;
  let resolved = crate::service_monitor::heartbeat::compose(
    &resolved,
    &row.spec,
    net.heartbeat_url.as_deref(),
    true,
  )?;
  let resolved = crate::refs::resolve_with_host_style(
    &resolved, name, world, net, legacy,
  )?;
  let resolved = substitutions.finish_compose(resolved)?;
  let resolved = with_files(
    world,
    net,
    name,
    &resolved,
    mounts,
    Some(secrets),
    legacy,
  )?;
  crate::syntax_check::validate_rendered_compose(name, &resolved)?;
  let hash = match &row.spec.init_cmd {
    Some(command) => {
      let init = serde_json::json!([
        command,
        row.spec.init_timeout_secs.unwrap_or(300)
      ]);
      render::hash(&format!("{resolved}\n# wharf.init={init}"))
    }
    None => render::hash(&resolved),
  };
  let owners: BTreeMap<_, _> = row
    .spec
    .volumes
    .iter()
    .filter_map(|v| v.owner.as_ref().map(|owner| (&v.name, owner)))
    .collect();
  let hash = if owners.is_empty() {
    hash
  } else {
    let owners =
      serde_json::to_string(&owners).map_err(crate::db::json_err)?;
    render::hash(&format!("{hash}\n# wharf.volume_owners={owners}"))
  };
  let hash = if let Some(inputs) =
    crate::compose_env::inputs(world, net, name, secrets)?
  {
    let inputs =
      serde_json::to_string(&inputs).map_err(crate::db::json_err)?;
    render::hash(&format!("{hash}\n# wharf.project_env={inputs}"))
  } else {
    hash
  };
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
  let component = crate::compose_env::component_settings(&row.spec);
  let (spec, substitutions) = crate::variables::prepare_spec(
    world,
    net,
    name,
    &component,
    Some(secrets),
  )?;
  let (trial, mounts) =
    render::trial_compose(name, &spec, Some(secrets))?;
  let trial = crate::refs::resolve(&trial, name, world, net)?;
  let trial = substitutions.finish_compose(trial)?;
  with_files(world, net, name, &trial, mounts, Some(secrets), false)
}

pub(crate) fn render_config_file(
  world: &World,
  net: &Net,
  name: &str,
  file: &wharf_api_types::spec::FileSpec,
  secrets: Option<&BTreeMap<String, String>>,
  mounts: &mut BTreeSet<String>,
) -> Result<String, ApiError> {
  render_config_file_with_host_style(
    world, net, name, file, secrets, mounts, false,
  )
}

fn render_config_file_with_host_style(
  world: &World,
  net: &Net,
  name: &str,
  file: &wharf_api_types::spec::FileSpec,
  secrets: Option<&BTreeMap<String, String>>,
  mounts: &mut BTreeSet<String>,
  legacy: bool,
) -> Result<String, ApiError> {
  let (content, substitutions) = crate::variables::prepare_file(
    world,
    net,
    name,
    &file.content,
    secrets,
  )?;
  let content = render::file_content(&content, secrets, mounts)?;
  let content = crate::refs::resolve_with_host_style(
    &content, name, world, net, legacy,
  )?;
  Ok(substitutions.finish_text(&content, false))
}

/// 加上服务的配置文件，内容里的密钥和 `[[@服务]]` 先替换好。
pub(crate) fn with_files(
  world: &World,
  net: &Net,
  name: &str,
  compose: &str,
  mounts: render::SecretMounts,
  secrets: Option<&BTreeMap<String, String>>,
  legacy: bool,
) -> Result<String, ApiError> {
  let spec = &world.services[name].spec;
  let mut file_secrets = BTreeSet::new();
  let files = spec
    .files
    .iter()
    .map(|f| {
      let content = render_config_file_with_host_style(
        world,
        net,
        name,
        f,
        secrets,
        &mut file_secrets,
        legacy,
      )?;
      Ok((f.path.clone(), content))
    })
    .collect::<Result<Vec<_>, ApiError>>()?;
  render::add_files(
    name,
    spec,
    compose,
    &files,
    file_secrets,
    mounts,
    secrets,
  )
}

pub fn service_template(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<String, ApiError> {
  let row = &world.services[name];
  let component = crate::compose_env::component_settings(&row.spec);
  let (spec, substitutions) = crate::variables::prepare_spec(
    world, net, name, &component, None,
  )?;
  let (text, mounts) = render::service_compose(
    name,
    &spec,
    &row.host_ports,
    &net.bind_ips(&row.spec),
    None,
  )?;
  let text = crate::service_monitor::heartbeat::compose(
    &text,
    &row.spec,
    net.heartbeat_url.as_deref(),
    false,
  )?;
  let text = crate::refs::resolve(&text, name, world, net)?;
  let text = substitutions.finish_compose(text)?;
  with_files(world, net, name, &text, mounts, None, false)
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
  pub forwards: Vec<(bool, u16, String)>,
  pub needs_acme_dns: bool,
  pub needs_link_cert: bool,
  pub extra_files: BTreeMap<String, String>,
}

impl GatewayRender {
  /// 下发内容的指纹：compose 和配置各自的 hash 一起再算一次。
  pub fn fingerprint(&self) -> String {
    render::hash(&format!(
      "{} {}",
      self.compose_hash, self.config_hash
    ))
  }

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
  net
    .basic_auth
    .values()
    .fold(config.to_string(), |c, a| c.replace(&a.hash, "<bcrypt>"))
}

pub fn gateway_render(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<GatewayRender, ApiError> {
  gateway_render_with_fill(
    world,
    net,
    name,
    render::CaddyFill::default(),
  )
}

fn gate_core_direct(
  net: &Net,
  gateway_server: &str,
) -> Option<String> {
  let (port, loopback_only) = net.core_listener?;
  let core = net.core_server.as_ref()?;
  if gateway_server == core {
    return Some(format!("http://127.0.0.1:{port}"));
  }
  let ip = net
    .private
    .get(core)
    .filter(|addr| addr.network.encrypted())?;
  if loopback_only
    || net.reach.get(&(gateway_server.into(), core.clone()))
      != Some(&true)
  {
    return None;
  }
  let ip: std::net::IpAddr = ip.ip.parse().ok()?;
  Some(format!("http://{}", std::net::SocketAddr::new(ip, port)))
}

pub(crate) fn gateway_config_matches(
  world: &World,
  net: &Net,
  name: &str,
  rendered: &GatewayRender,
  applied: Option<&str>,
  observed_acme_dns: Option<&str>,
) -> bool {
  if let (Some(observed), Some(expected)) =
    (observed_acme_dns, &net.acme_dns_url)
    && rendered.needs_acme_dns
    && observed
      != render::hash(&format!(
        "{}/agent/acme-dns",
        expected.trim_end_matches('/')
      ))
  {
    return false;
  }
  if applied == Some(rendered.config_hash.as_str()) {
    return true;
  }
  // 旧指纹只忽略回调地址占位符，保留门禁回源等实际配置差异。
  if world.gateways[name].spec.kind != GatewayKind::Caddy
    || !rendered.needs_acme_dns
  {
    return false;
  }
  let legacy = Net {
    acme_dns_url: None,
    ..net.clone()
  };
  gateway_render(world, &legacy, name)
    .is_ok_and(|r| applied == Some(r.config_hash.as_str()))
}

pub fn gateway_render_with_fill(
  world: &World,
  net: &Net,
  name: &str,
  fill: render::CaddyFill<'_>,
) -> Result<GatewayRender, ApiError> {
  let gateway = world.gateways.get(name).ok_or_else(|| {
    ApiError::not_found(format!("网关 {name} 不存在"))
  })?;
  let mut sites = Vec::new();
  for (host, route) in &world.routes {
    if !world.route_gateways(&route.spec).contains(&name) {
      continue;
    }
    let protection = crate::entry_protection::SiteProtection::new(
      world,
      net,
      &gateway.spec,
      host,
      &route.spec,
    )?;
    if let Some(target) = &route.spec.redirect {
      sites.push(render::Site {
        protection,
        hostname: host.clone(),
        upstream: String::new(),
        auth: None,
        paths: Vec::new(),
        redirect: Some(target.clone()),
        ..Default::default()
      });
      continue;
    }
    let tunnel = gateway.spec.kind == GatewayKind::CloudflareTunnel;
    if route.spec.auth && tunnel {
      return Err(ApiError::invalid(format!(
        "路由 {host}：cloudflare_tunnel 网关还不支持登录保护，换 caddy 网关或去掉 --auth"
      )));
    }
    if route.spec.auth && net.auth_for(host).is_none() {
      return Err(
        ApiError::invalid(format!(
          "路由 {host} 开启了登录保护，但还没有设置账号"
        ))
        .with_hint(
          "值写成 用户名:密码，从标准输入读取，不会出现在命令行里",
        )
        .suggest(format!(
          "wharf secret set {}",
          render::route_auth_secret(host)
        )),
      );
    }
    if tunnel && !route.spec.paths.is_empty() {
      return Err(ApiError::invalid(format!(
        "路由 {host}：按路径转发只支持 caddy 网关"
      )));
    }
    let mut paths = Vec::new();
    for p in &route.spec.paths {
      let upstream = match (&p.service, &p.upstream) {
        (_, Some(up)) => up.clone(),
        (Some(svc), None) => {
          let port = world
            .service_port(svc, p.port.as_deref())
            .ok_or_else(|| {
              ApiError::invalid(format!(
                "路由 {host} 的路径 {} 没有可用的端口",
                p.path
              ))
            })?;
          render::upstream(
            world,
            net,
            &gateway.spec,
            svc,
            port,
            route.spec.link,
          )?
        }
        (None, None) => continue,
      };
      paths.push((p.path.clone(), upstream));
    }
    let gate = route
      .spec
      .sso
      .as_ref()
      .map(|sso| {
        let login = net
          .gate_login
          .as_ref()
          .filter(|u| u.starts_with("https://"))
          .ok_or_else(|| {
            ApiError::invalid("控制面还没有公网域名，开不了门禁")
              .with_hint("先给控制面加一个域名")
          })?;
        let url = reqwest::Url::parse(login).map_err(|_| {
          ApiError::invalid("控制面还没有公网域名，开不了门禁")
        })?;
        if url.host_str() == Some(host.as_str())
          || crate::gate::is_core_host(world, net, host)
        {
          return Err(ApiError::invalid(
            "控制面自己的域名不能开门禁",
          ));
        }
        let core = url
          .host_str()
          .and_then(|h| world.routes.get(h))
          .filter(|r| world.route_gateways(&r.spec).contains(&name))
          .map(|r| {
            world.route_upstream(
              net,
              &gateway.spec,
              &r.spec.hostname,
              &r.spec,
            )
          })
          .transpose()?
          .map(|u| format!("http://{u}"))
          .or_else(|| gate_core_direct(net, &gateway.spec.server))
          .unwrap_or_else(|| login.clone());
        Ok(render::Gate {
          public: sso.public,
          site_endpoints: crate::gate::site_endpoints(sso),
          app_login: sso.mode
            == wharf_api_types::spec::SsoMode::Login,
          user_header: (sso.mode
            == wharf_api_types::spec::SsoMode::Header)
            .then(|| {
              sso
                .header
                .clone()
                .unwrap_or_else(|| "Remote-User".into())
            }),
          trusted: if sso.trust_internal {
            crate::gate::trusted_ranges(net, &gateway.spec.server)
          } else {
            vec![]
          },
          login: login.clone(),
          core,
          skip_paths: sso.skip_paths.clone(),
          takeover: sso.login.as_ref().and_then(|login| {
            login.takeover.clone().map(|takeover| {
              (takeover, login.entry.as_deref().unwrap_or("/").into())
            })
          }),
        })
      })
      .transpose()?;
    sites.push(render::Site {
      protection,
      gate,
      wildcard: false,
      internal: route.spec.internal,
      internal_ranges: if route.spec.internal {
        crate::source_trust::internal_route_ranges(
          net,
          &gateway.spec.server,
        )
      } else {
        vec![]
      },
      expires_at: route.spec.expires_at,
      dns: (route.spec.internal
        && gateway.spec.tls == GatewayTls::Auto
        && !host.split_once('.').is_some_and(|(_, zone)| {
          gateway.spec.wildcard.iter().any(|z| z == zone)
        }))
      .then(|| host.clone()),
      rate_limit: route.spec.rate_limit,
      block_scanners: route.spec.block_scanners,
      custom: route
        .spec
        .caddy
        .clone()
        .filter(|c| !c.trim().is_empty()),
      redirect: None,
      paths,
      auth: route
        .spec
        .auth
        .then(|| net.auth_for(host).cloned())
        .flatten(),
      hostname: host.clone(),
      upstream: world.route_upstream(
        net,
        &gateway.spec,
        host,
        &route.spec,
      )?,
    });
  }
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  let mut needs_acme_dns = false;
  let needs_link_cert = gateway.spec.kind == GatewayKind::Caddy
    && crate::link::caddy_site(world, net, name, &gateway.spec)?;
  let mut forwards = Vec::new();
  let (compose, config) = match gateway.spec.kind {
    GatewayKind::Caddy => {
      for f in &gateway.spec.layer4 {
        let upstream = if let Some(up) = &f.upstream {
          up.clone()
        } else if let Some(svc) = &f.service {
          let port = world
            .service_port(svc, f.port.as_deref())
            .ok_or_else(|| {
              ApiError::invalid(format!(
                "入口 {name} 的四层转发 {}：找不到服务 {svc} 的端口",
                f.listen
              ))
            })?;
          let host = world.services[svc]
            .host_ports
            .get(port)
            .ok_or_else(|| {
              ApiError::internal(format!(
                "服务 {svc} 的端口 {port} 没有分配"
              ))
            })?;
          if world.services[svc].spec.server != gateway.spec.server
            && crate::link::service_port_bind(
              &world.services[svc],
              port,
            ) == crate::link::PortBind::LoopbackV4Only
          {
            return Err(ApiError::invalid(
              "四层转发不支持反向隧道，请把该端口绑定到内网地址",
            ));
          }
          match crate::link::choose(world, net, &gateway.spec, svc, port, wharf_api_types::spec::LinkMode::Auto)? {
            crate::link::Choice::Local => format!("127.0.0.1:{host}"),
            crate::link::Choice::Direct(ip) => format!("{ip}:{host}"),
            crate::link::Choice::Tunnel => return Err(ApiError::invalid(format!("入口 {name} 的四层转发 {}：入口所在机器连不到 {svc} 所在机器的内网地址，四层转发不支持反向隧道", f.listen)).with_hint(format!("让两台机器在同一个组网里，或者在 {svc} 所在的机器上建入口"))),
          }
        } else {
          return Err(ApiError::invalid(format!(
            "入口 {name} 的四层转发 {}：服务和上游二选一",
            f.listen
          )));
        };
        forwards.push((f.udp, f.listen, upstream));
      }
      forwards.sort_by_key(|(udp, listen, _)| (*udp, *listen));
      let mut caddy_sites = sites.clone();
      for zone in &gateway.spec.wildcard {
        caddy_sites.push(render::Site {
          hostname: format!("*.{zone}"),
          wildcard: true,
          dns: (gateway.spec.tls == GatewayTls::Auto)
            .then(|| zone.clone()),
          ..Default::default()
        });
      }
      needs_acme_dns = caddy_sites.iter().any(|s| s.dns.is_some());
      (
        render::gateway_compose(name, &gateway.spec),
        render::caddyfile_with_fill(
          name,
          &gateway.spec,
          &caddy_sites,
          &forwards,
          needs_link_cert,
          net.gate_public.as_deref(),
          &crate::source_trust::gateway_trusted_proxies(
            world,
            net,
            &gateway.spec,
            &net.cloudflare_ips,
          ),
          render::CaddyFill {
            acme_dns_url: net.acme_dns_url.as_deref(),
            ..fill
          },
        ),
      )
    }
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
        render::tunnel_compose(name, &gateway.spec, None),
        serde_json::to_string_pretty(&rules).unwrap_or_default(),
      )
    }
  };
  let config_hash = if needs_link_cert {
    let tag = match net.link_certs.get(name) {
      Some(cert)
        if !crate::link_cert::needs_renew(
          cert.expires_at,
          chrono::Utc::now(),
        ) =>
      {
        cert.fingerprint.as_str()
      }
      Some(_) => "renew",
      None => "pending",
    };
    crate::link_cert::config_hash(&config, tag)
  } else {
    render::hash(&config)
  };
  Ok(GatewayRender {
    compose_hash: render::hash(&compose),
    config_hash,
    compose,
    config,
    sites,
    forwards,
    needs_acme_dns,
    needs_link_cert,
    extra_files: BTreeMap::new(),
  })
}

/// 查询一台服务器上若干 project 的现状。
pub async fn project_status(
  hub: &crate::hub::Hub,
  server: &str,
  projects: Vec<String>,
  timeout: Duration,
) -> Result<BTreeMap<String, ProjectState>, ApiError> {
  project_status_with_links(hub, server, projects, timeout, false)
    .await
}

pub(crate) async fn project_status_with_links(
  hub: &crate::hub::Hub,
  server: &str,
  projects: Vec<String>,
  timeout: Duration,
  include_links: bool,
) -> Result<BTreeMap<String, ProjectState>, ApiError> {
  let states: Vec<ProjectState> = hub
    .call(
      server,
      wharf_api_types::agent::AgentOp::ProjectStatus {
        projects,
        include_links,
      },
      timeout,
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await?;
  Ok(states.into_iter().map(|s| (s.project.clone(), s)).collect())
}

pub(crate) async fn read_legacy_acme_dns_hash(
  hub: &crate::hub::Hub,
  server: &str,
  project: &str,
) -> Option<String> {
  use wharf_api_types::agent::{
    AgentOp, TaskHow, TaskRunJob, TaskRunResult,
  };
  // 只在 Caddy 容器内读取回调地址的指纹，避免传输完整配置。
  let result: TaskRunResult = hub
    .call(
      server,
      AgentOp::TaskRun(TaskRunJob {
        name: "gateway-acme-hash".into(),
        how: TaskHow::Exec {
          cancellable: false,
          env: BTreeMap::new(),
          project: project.into(),
          service: Some("caddy".into()),
          command: r#"url=$(awk '$1 == "server_url" && $2 ~ /\/agent\/acme-dns$/ {print $2; exit}' /etc/caddy/Caddyfile) && [ -n "$url" ] && printf '%s' "$url" | sha256sum"#.into(),
        },
        input: None,
        network_host: false,
        out_dir: false,
        wait_for_deps: false,
        run_id: None,
        artifacts_max_bytes: None,
        artifacts_keep: None,
        timeout_secs: 5,
        pull: PullPolicy {
          mirrors: BTreeMap::new(),
          mirrors_only: false,
          attempt_timeout_secs: PULL_ATTEMPT_SECS,
          git_proxy: None,
          github_mirror: None,
          registry_proxy: None,
        },
      }),
      Duration::from_secs(10),
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .ok()?;
  let hash = result.output.split_whitespace().next()?;
  (result.exit_code == Some(0)
    && hash.len() == 64
    && hash.bytes().all(|b| b.is_ascii_hexdigit()))
  .then(|| hash.to_string())
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
  #[cfg(test)]
  if account.kind == "fixture-failover" {
    return Ok(Box::new(crate::failover::tests::FixtureDns));
  }
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
        instance_id: "svc_fixture".into(),
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

  #[test]
  fn pull_policy_renders_encoded_mirror_credentials() {
    let server = ServerRow {
      settings: serde_json::from_value(serde_json::json!({
        "registry_mirrors": {"docker.io": ["https://registry.example.test/[[url:K]]/[[b64:K]]"]},
        "github_mirror": "https://git.example.test/[[json:K]]",
      })).unwrap(),
      version: 1,
    };
    let secrets =
      BTreeMap::from([("K".into(), "p@s#1\n\"\\".into())]);
    let pull = pull_policy_with_secrets(&server, &secrets);
    assert_eq!(
      pull.mirrors["docker.io"],
      [
        "https://registry.example.test/p%40s%231%0A%22%5C/cEBzIzEKIlw="
      ]
    );
    assert_eq!(
      pull.github_mirror.as_deref(),
      Some(r#"https://git.example.test/p@s#1\n\"\\"#)
    );
  }

  #[test]
  fn legacy_image_and_compose_bytes_and_hash_are_unchanged() {
    let mut w = world(21000);
    let secrets = BTreeMap::from([("KEY".into(), "ok123".into())]);
    let net = Net::default();
    w.services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("KEY".into(), "[[KEY]]".into());
    let legacy_image = concat!(
      "# 由 Wharf 生成，不要手改。\n",
      "name: app\nservices:\n  app:\n    image: nginx:1\n",
      "    restart: unless-stopped\n    environment:\n      KEY: ok123\n",
      "    ports:\n    - 127.0.0.1:21000:80\n",
      "    labels:\n      wharf.service: app\n",
    );
    assert_eq!(
      service_resolved(&w, &net, "app", &secrets).unwrap(),
      (legacy_image.to_string(), render::hash(legacy_image)),
    );

    let raw = "# 注释\nservices:\n  app:\n    image: nginx:1\n    environment:\n      KEY: [[KEY]] # 保留格式\n";
    let spec = &mut w.services.get_mut("app").unwrap().spec;
    spec.env.clear();
    spec.source = serde_json::from_value(
      serde_json::json!({"compose": {"content": raw}}),
    )
    .unwrap();
    let legacy_compose = raw.replace("[[KEY]]", "ok123");
    let legacy_hash = render::hash(&legacy_compose);
    assert_eq!(
      service_resolved(&w, &net, "app", &secrets).unwrap(),
      (legacy_compose, legacy_hash),
    );
  }

  #[test]
  fn stored_flow_compose_with_anchors_keeps_resolved_bytes_and_hash()
  {
    let mut w = world(21000);
    let raw = concat!(
      "# 注释和流式写法\n",
      "x-base: &b {image: nginx:1, environment: {PASS: \"[[json:K]]\"}}\n",
      "services: {app: {<<: *b}}\n",
    );
    w.services.get_mut("app").unwrap().spec.source =
      serde_json::from_value(
        serde_json::json!({"compose": {"content": raw}}),
      )
      .unwrap();
    let expected = raw.replace("[[json:K]]", r#"a\"b'c"#);
    assert_eq!(
      service_resolved(
        &w,
        &Net::default(),
        "app",
        &BTreeMap::from([("K".into(), "a\"b'c".into())])
      )
      .unwrap(),
      (expected.clone(), render::hash(&expected)),
    );
  }

  #[test]
  fn image_secret_file_is_private_to_resolved_compose_and_trial() {
    let mut w = world(21000);
    let spec = &mut w.services.get_mut("app").unwrap().spec;
    spec.source =
      wharf_api_types::spec::Source::Image("postgres:16".into());
    spec.env.insert(
      "POSTGRES_PASSWORD_FILE".into(),
      "[[FILE:PG_PASS]]".into(),
    );
    let secrets =
      BTreeMap::from([("PG_PASS".into(), "p$ss\"1[[@app]]".into())]);
    let net = Net::default();
    let (out, _) =
      service_resolved(&w, &net, "app", &secrets).unwrap();
    let trial = service_trial(&w, &net, "app", &secrets).unwrap();
    for out in [out, trial] {
      let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&out).unwrap();
      let app = &doc["services"]["app"];
      let mount = &app["configs"][0];
      let id = mount["source"].as_str().unwrap();
      let suffix = id.strip_prefix("wharf-secret-PG_PASS-").unwrap();
      assert_eq!(suffix.len(), 12);
      assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
      assert_eq!(doc["configs"][id]["content"], "p$$ss\"1[[@app]]");
      assert_eq!(mount["target"], "/run/wharf-secrets/PG_PASS");
      assert!(mount.get("mode").is_none());
      assert_eq!(
        app["environment"]["POSTGRES_PASSWORD_FILE"],
        "/run/wharf-secrets/PG_PASS"
      );
    }
    let template = service_template(&w, &net, "app").unwrap();
    assert!(template.contains("[[FILE:PG_PASS]]"));
    assert!(!template.contains("configs:"));
    assert!(!template.contains("p$ss"));
  }

  #[test]
  fn compose_secret_file_mounts_and_hash_follow_each_container() {
    let mut w = world(21000);
    let spec = &mut w.services.get_mut("app").unwrap().spec;
    let raw = concat!(
      "services:\n",
      "  db:\n    image: postgres:16\n    environment:\n      PASS_FILE: [[FILE:PG_PASS]]\n",
      "  app:\n    image: nginx:1\n    environment:\n      KEY_FILE: \"[[FILE:API_KEY]]\"\n",
    );
    spec.source = serde_json::from_value(
      serde_json::json!({"compose": {"content": raw}}),
    )
    .unwrap();
    let net = Net::default();
    let resolved = |db_key: &str| {
      let secrets = BTreeMap::from([
        ("PG_PASS".into(), db_key.into()),
        ("API_KEY".into(), "fixture-app".into()),
      ]);
      let (out, hash) =
        service_resolved(&w, &net, "app", &secrets).unwrap();
      (
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&out)
          .unwrap(),
        hash,
      )
    };
    let (before, hash) = resolved("fixture-before");
    let (after, new_hash) = resolved("fixture-after");
    assert_ne!(hash, new_hash);
    for (container, secret) in [("db", "PG_PASS"), ("app", "API_KEY")]
    {
      let body = &before["services"][container];
      let mounts = body["configs"].as_sequence().unwrap();
      assert_eq!(mounts.len(), 1);
      assert_eq!(
        mounts[0]["target"].as_str().unwrap(),
        format!("/run/wharf-secrets/{secret}")
      );
    }
    assert_ne!(
      before["services"]["db"]["configs"][0]["source"],
      after["services"]["db"]["configs"][0]["source"],
    );
    assert_eq!(before["services"]["app"], after["services"]["app"]);
  }

  #[test]
  fn compose_secret_file_checks_inherited_configs_and_each_reference()
  {
    let mut w = world(21000);
    let net = Net::default();
    let secrets =
      BTreeMap::from([("PG_PASS".into(), "fixture-value".into())]);
    let raw = concat!(
      "x-base: &base\n",
      "  environment:\n    PASS_FILE: [[FILE:PG_PASS]]\n",
      "  configs:\n    - source: fixture\n      target: /etc/fixture\n",
      "x-derived: &derived\n  <<: *base\n",
      "services:\n  app:\n    <<: *derived\n    image: nginx:1\n",
      "configs:\n  fixture:\n    content: fixture\n",
    );
    let mut resolve = |raw: &str| {
      w.services.get_mut("app").unwrap().spec.source =
        serde_json::from_value(
          serde_json::json!({"compose": {"content": raw}}),
        )
        .unwrap();
      service_resolved(&w, &net, "app", &secrets)
    };
    let (out, _) = resolve(raw).unwrap();
    let doc: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let mounts =
      doc["services"]["app"]["configs"].as_sequence().unwrap();
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0]["target"], "/etc/fixture");
    assert_eq!(mounts[1]["target"], "/run/wharf-secrets/PG_PASS");

    for alias in [
      "/run/wharf-secrets//PG_PASS",
      "/run/wharf-secrets/./PG_PASS",
      "/run/wharf-secrets/../wharf-secrets/PG_PASS",
    ] {
      let error =
        resolve(&raw.replace("/etc/fixture", alias)).unwrap_err();
      assert_eq!(
        error.message,
        "服务 app 的容器 app 已有重复的挂载目标 /run/wharf-secrets/PG_PASS",
      );
    }
    let orphan = format!("{raw}x-extra: [[FILE:PG_PASS]]\n");
    assert_eq!(
      resolve(&orphan).unwrap_err().message,
      "[[FILE:...]] 只能写在 services 下的容器配置里",
    );
  }

  #[test]
  fn service_volume_rejects_normalized_secret_directory() {
    let mut w = world(21000);
    w.services.get_mut("app").unwrap().spec.volumes.push(
      wharf_api_types::spec::VolumeSpec {
        from_service: None,
        owner: None,
        host_path: None,
        read_only: false,
        name: "data".into(),
        target: "/run/fixture/../wharf-secrets//PG_PASS".into(),
      },
    );
    assert!(
      w.validate()
        .unwrap_err()
        .message
        .contains(render::SECRET_FILE_DIR)
    );
  }

  #[test]
  fn config_file_secret_is_mounted_once_and_reserves_its_directory() {
    let mut w = world(21000);
    let spec = &mut w.services.get_mut("app").unwrap().spec;
    spec
      .env
      .insert("PASSWORD_FILE".into(), "[[FILE:DB_PASS]]".into());
    spec.files.push(wharf_api_types::spec::FileSpec {
      file: None,
      path: "/etc/app/conf.toml".into(),
      content: "pass_file = \"[[FILE:DB_PASS]]\"\n".into(),
      raw: false,
    });
    let net = Net::default();
    let secrets =
      BTreeMap::from([("DB_PASS".into(), "fixture-db".into())]);
    let (out, _) =
      service_resolved(&w, &net, "app", &secrets).unwrap();
    let doc: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let mounts =
      doc["services"]["app"]["configs"].as_sequence().unwrap();
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[1]["target"], "/run/wharf-secrets/DB_PASS");
    let id = mounts[0]["source"].as_str().unwrap();
    assert_eq!(
      doc["configs"][id]["content"],
      "pass_file = \"/run/wharf-secrets/DB_PASS\"\n"
    );
    w.services.get_mut("app").unwrap().spec.files[0].path =
      "/run/wharf-secrets/DB_PASS".into();
    let error = w.validate().unwrap_err();
    assert!(error.message.contains("/run/wharf-secrets/"));
    assert!(error.hint.unwrap().contains("换其他路径"));
  }

  fn fingerprint(compose: &str, config: &str) -> String {
    GatewayRender {
      compose: compose.to_string(),
      compose_hash: render::hash(compose),
      config: config.to_string(),
      config_hash: render::hash(config),
      sites: Vec::new(),
      forwards: Vec::new(),
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
  fn existing_ipv6_reference_keeps_its_deployed_hash() {
    let mut world = world(21000);
    world
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("APP_HOST".into(), "[[@app:host]]".into());
    let mut net = Net::default();
    net.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "2001:db8::1".into(),
        network: wharf_api_types::spec::PrivateNetwork::Overlay,
      },
    );
    let secrets = BTreeMap::new();
    let (_, legacy) =
      resolve_service(&world, &net, "app", &secrets, true).unwrap();
    let (_, new) =
      service_resolved(&world, &net, "app", &secrets).unwrap();
    assert_ne!(legacy, new);
    assert_eq!(
      service_hash(&world, &net, "app", &secrets, Some(&legacy))
        .unwrap(),
      legacy
    );
    assert_eq!(
      service_hash(&world, &net, "app", &secrets, None).unwrap(),
      new
    );
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
    let mut direct = Net {
      core_server: Some("s1".into()),
      core_listener: Some((7700, false)),
      ..net
    };
    direct.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "100.64.0.2".into(),
        network: wharf_api_types::spec::PrivateNetwork::Tailscale,
      },
    );
    direct.reach.insert(("s2".into(), "s1".into()), true);
    let upstream = |n: &Net| {
      gateway_render(&world, n, "other").unwrap().sites[0]
        .gate
        .as_ref()
        .unwrap()
        .core
        .clone()
    };
    assert_eq!(upstream(&direct), "http://100.64.0.2:7700");
    direct.core_listener = Some((7700, true));
    assert_eq!(upstream(&direct), "https://core.example.test");
    direct.core_listener = Some((7700, false));
    direct.reach.clear();
    assert_eq!(upstream(&direct), "https://core.example.test");
  }

  #[test]
  fn acme_callback_updates_fingerprint_without_drifting_legacy_hash()
  {
    let mut w = World::default();
    w.gateways.insert("edge".into(), crate::world::GatewayRow {
      spec: serde_json::from_value(serde_json::json!({"kind":"caddy","server":"s1","wildcard":["example.com"]})).unwrap(),
      version: 1,
    });
    let mut net = Net::default();
    let legacy = gateway_render(&w, &net, "edge").unwrap();
    net.acme_dns_url = Some("https://old.example.net".into());
    let before = gateway_render(&w, &net, "edge").unwrap();
    assert!(gateway_config_matches(
      &w,
      &net,
      "edge",
      &before,
      Some(&legacy.config_hash),
      Some(&render::hash("https://old.example.net/agent/acme-dns")),
    ));
    net.acme_dns_url = Some("https://new.example.net".into());
    let after = gateway_render(&w, &net, "edge").unwrap();
    assert!(
      after
        .config
        .contains("https://new.example.net/agent/acme-dns")
    );
    assert!(after.config.contains(render::ACME_DNS_KEY));
    assert!(!gateway_config_matches(
      &w,
      &net,
      "edge",
      &after,
      Some(&before.config_hash),
      None,
    ));
    assert!(!gateway_config_matches(
      &w,
      &net,
      "edge",
      &after,
      Some(&legacy.config_hash),
      Some(&render::hash("https://old.example.net/agent/acme-dns"))
    ));
    assert_eq!(before.compose_hash, after.compose_hash);
  }
}
