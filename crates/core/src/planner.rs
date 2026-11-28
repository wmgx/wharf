//! 生成计划：先算配置差异（期望 vs 数据库），再算现实差异（期望 vs 远端）。
//!
//! 计划里只存"要做什么"（[StepPlan]），apply 时从已提交的数据库重新渲染
//! 具体内容，所以密钥只在发给 agent 的那一刻才被替换进去。

use rusqlite::OptionalExtension;
use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::ProjectState,
  plan::{
    Action, Impact, Layer, Plan, PlanItem, PlanRequest, PlanStatus,
  },
  spec::{
    BuildSource, EdgeAppSpec, EdgeKind, GatewayKind, GatewayTls,
    NetworkMode, RouteSpec, Source,
  },
  view::DataKind,
};
use wharf_providers::{DnsRecordSpec, DnsRecordType, RemoteRecord};

use crate::{
  db::{self, Write},
  render::Net,
  snapshot::{self, Snapshot},
  state::AppState,
  world::{
    KIND_BOOKMARK, KIND_EDGE, KIND_GATEWAY, KIND_ROUTE, KIND_SERVER,
    KIND_SERVICE, World, gateway_project, new_id,
  },
};

/// 计划的有效期。
pub const PLAN_TTL_MINUTES: i64 = 60;
const STATUS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteRef {
  pub scope: String,
  pub remote_id: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub record_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSpec {
  pub record_type: String,
  pub content: String,
  pub proxied: bool,
  #[serde(default = "default_dns_ttl")]
  pub ttl: u32,
  /// 指向这个 cloudflare_tunnel 网关的隧道。隧道可能在同一次执行里才创建，
  /// 所以执行时按网关重新取隧道 id。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tunnel: Option<String>,
}

/// 隧道还没创建时计划里显示的 CNAME 目标。
const TUNNEL_PENDING: &str = "（隧道创建后确定）.cfargotunnel.com";

pub fn tunnel_target(id: &str) -> String {
  format!("{id}.cfargotunnel.com")
}

fn default_dns_ttl() -> u32 {
  1
}

impl DnsSpec {
  pub fn to_provider(&self) -> DnsRecordSpec {
    DnsRecordSpec {
      record_type: match self.record_type.as_str() {
        "AAAA" => DnsRecordType::AAAA,
        "CNAME" => DnsRecordType::CNAME,
        _ => DnsRecordType::A,
      },
      content: self.content.clone(),
      ttl: if self.proxied { 1 } else { self.ttl },
      proxied: self.proxied,
    }
  }
}

/// 可执行的步骤。按 [Step::order] 排序执行。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
  DnsDelete {
    hostname: String,
    account: String,
    remote: RemoteRef,
    /// 有值时只删带这个 route_id 标记的记录。
    owner: Option<String>,
  },
  EnsureDirs {
    server: String,
    dirs: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    after_sync: bool,
  },
  /// 迁移数据：先在服务运行时同步一遍，停掉旧服务器上的容器，再增量同步。
  VolumeSync {
    service: String,
    from: String,
    to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
  },
  ServiceUp {
    service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    /// 计划时渲染出的 compose 指纹，执行前重算比对；没有这个字段的旧计划不校验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<String>,
  },
  GatewaySync {
    gateway: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    after_dns: bool,
    /// 计划时渲染出的 compose 和配置的指纹，执行前重算比对。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<String>,
  },
  DnsUpsert {
    hostname: String,
    account: String,
    spec: DnsSpec,
    existing: Option<RemoteRef>,
    /// 接管时要删掉的多余记录。
    extra: Vec<RemoteRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_gateway: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    verify_target: bool,
  },
  GatewayDown {
    server: String,
    gateway: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    keep_tunnel: bool,
  },
  TunnelDelete {
    gateway: String,
    account: String,
    scope: String,
    tunnel_id: String,
  },
  /// 部署反向隧道的 frps 或 frpc（design 2.7.2）。
  LinkUp {
    server: String,
    project: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    hot_reload: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    after_dns: bool,
  },
  LinkDown {
    server: String,
    project: String,
  },
  /// 起 Wharf 管理的 Tailscale 容器并加入网络（design 2.10）。删除用 LinkDown。
  TailscaleUp {
    server: String,
  },
  /// 按服务器设置 `pull_proxy` 改 dockerd 的代理，有变化时重启 dockerd。
  DockerProxy {
    server: String,
  },
  /// 按服务器设置 `baseline` 纠正系统设置（机器基线）。
  Baseline {
    server: String,
  },
  /// 按服务器设置 `egress` 开关这台的出口代理。
  Egress {
    server: String,
  },
  /// 备份和恢复不来自计划，是单独发起的执行。
  Backup {
    service: String,
  },
  Restore {
    service: String,
    snapshot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
  },
  /// 构建来源：按固定的 commit 重新构建并部署（没固定过的拉最新代码）。单独发起，不来自计划。
  Rebuild {
    service: String,
  },
  ServiceDown {
    server: String,
    service: String,
    /// 连同数据目录和命名卷一起删。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    purge_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    has_relative_mounts: bool,
  },
  CleanupData {
    service: String,
    server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
  },
  /// 发布边缘应用的代码。
  EdgeDeploy {
    app: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
  },
  /// 把自定义域名绑定到边缘应用。`takeover`：覆盖已有的 DNS 记录（Workers）。
  EdgeAttach {
    hostname: String,
    app: String,
    takeover: bool,
  },
  /// 按记录解绑自定义域名。
  EdgeDetach {
    domain: db::EdgeDomainRow,
  },
  /// 升级服务器上的 agent。单独发起，不来自计划。
  AgentUpgrade {
    server: String,
  },
  /// 逐台升级 agent：一台失败不影响其余的，最后汇总报错。单独发起，不来自计划。
  AgentUpgrades {
    servers: Vec<String>,
  },
  /// 停止服务的容器（配置没变，不重建）。
  ServiceStop {
    service: String,
  },
  /// 重启服务的容器。单独发起，不来自计划。
  ServiceRestart {
    service: String,
  },
  /// 控制面自身备份。`user_key`：开启时输入的登录密码，加成仓库的恢复口令。
  CoreBackup {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_key: Option<wharf_api_types::agent::OneTimeSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_secret: Option<wharf_api_types::agent::OneTimeSecret>,
  },
  /// 清理服务器上没在用的镜像。单独发起，不来自计划。
  Prune {
    server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restore_days: Option<u32>,
  },
  /// 边缘应用回滚到厂商那边的旧版本。单独发起，不来自计划。
  EdgeRollback {
    app: String,
    version: String,
  },
}

impl Step {
  /// 删除 DNS → 建目录 → 迁移数据 → 起服务 → 网关 → 写 DNS → 下线网关 → 下线服务。
  ///
  /// 迁移时旧服务器上的容器在"下线服务"这一步才删除，网关切到新地址之前旧容器一直在。
  pub(crate) fn order(&self) -> u8 {
    match self {
      Self::DnsDelete { .. } | Self::EdgeDetach { .. } => 0,
      // 先换好拉镜像的路，后面起服务时就用上。
      Self::DockerProxy { .. } => 1,
      Self::Baseline { .. } => 1,
      Self::Egress { .. } => 1,
      Self::EnsureDirs { after_sync, .. } => {
        if *after_sync {
          2
        } else {
          1
        }
      }
      Self::VolumeSync { .. } => 2,
      Self::ServiceUp { .. }
      | Self::EdgeDeploy { .. }
      | Self::TailscaleUp { .. }
      | Self::ServiceStop { .. } => 3,
      Self::LinkUp { project, .. }
        if project == crate::link::SERVER_PROJECT =>
      {
        3
      }
      Self::GatewaySync {
        after_dns: true, ..
      } => 7,
      Self::GatewaySync { .. } => 4,
      Self::LinkUp {
        after_dns: true, ..
      } => 7,
      Self::LinkUp { .. } => 5,
      Self::DnsUpsert { .. } | Self::EdgeAttach { .. } => 6,
      Self::GatewayDown { .. }
      | Self::LinkDown { .. }
      | Self::TunnelDelete { .. } => 7,
      Self::ServiceDown { .. } => 8,
      Self::Backup { .. }
      | Self::Restore { .. }
      | Self::Rebuild { .. }
      | Self::AgentUpgrade { .. }
      | Self::AgentUpgrades { .. }
      | Self::Prune { .. }
      | Self::CoreBackup { .. }
      | Self::ServiceRestart { .. }
      | Self::CleanupData { .. }
      | Self::EdgeRollback { .. } => 9,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepPlan {
  pub items: Vec<u32>,
  pub title: String,
  pub step: Step,
}

/// 存进数据库的完整计划。
pub struct Planned {
  pub plan: Plan,
  pub base_instances: BTreeMap<String, String>,
  pub account_refs: BTreeSet<String>,
  pub host_requirements: Vec<crate::host_access::HostRequirement>,
  pub route_effects: crate::token_scope::RouteEffects,
  pub steps: Vec<StepPlan>,
  pub writes: Vec<Write>,
}

#[derive(Default)]
pub(crate) struct Builder {
  migration_mounts:
    BTreeMap<String, Vec<wharf_api_types::agent::ContainerMount>>,
  pub(crate) items: Vec<PlanItem>,
  steps: Vec<StepPlan>,
  route_effects: crate::token_scope::RouteEffects,
  pub(crate) warnings: Vec<String>,
  /// 这次计划查到的镜像 ID：服务 → 镜像 → `sha256:…`。
  image_ids: BTreeMap<String, BTreeMap<String, String>>,
  explicit_pins: BTreeSet<String>,
  /// 删除时连同数据一起删的服务。
  purge_data: BTreeSet<String>,
}

fn build_agent_warnings(
  state: &AppState,
  desired: &World,
  b: &mut Builder,
) -> Result<(), ApiError> {
  let mut warned = BTreeSet::new();
  for step in &b.steps {
    let Step::ServiceUp { service, .. } = &step.step else {
      continue;
    };
    let row = &desired.services[service];
    let Source::Build(build) = &row.spec.source else {
      continue;
    };
    let server = &row.spec.server;
    if state.hub.is_online(server)
      && !state.hub.supports_build_v2(server)
    {
      if build.git.as_ref().is_some_and(|g| g.user.is_some()) {
        return Err(crate::build::old_git_agent(server));
      }
      if warned.insert(server) {
        b.warnings.push(crate::build::old_agent_warning(server));
      }
    }
  }
  Ok(())
}

impl Builder {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn item(
    &mut self,
    address: String,
    layer: Layer,
    action: Action,
    before: Option<Value>,
    after: Option<Value>,
    impacts: Vec<Impact>,
    reason: impl Into<String>,
  ) -> u32 {
    let id = self.items.len() as u32 + 1;
    let changes = match (&before, &after) {
      (Some(b), Some(a)) => {
        wharf_api_types::plan::field_changes(b, a)
      }
      _ => vec![],
    };
    self.items.push(PlanItem {
      id,
      address,
      layer,
      action,
      before,
      after,
      impacts,
      reason: reason.into(),
      changes,
      host_access: vec![],
    });
    id
  }

  pub(crate) fn step(
    &mut self,
    items: Vec<u32>,
    title: impl Into<String>,
    step: Step,
  ) {
    self.steps.push(StepPlan {
      items,
      title: title.into(),
      step,
    });
  }
}

pub async fn make_plan(
  state: &AppState,
  req: PlanRequest,
) -> Result<Planned, ApiError> {
  make_plan_inner(
    state,
    req,
    snapshot::load(&state.db).await?,
    true,
    true,
  )
  .await
}

pub(crate) async fn pending_plan(
  state: &AppState,
) -> Result<Planned, ApiError> {
  make_plan_inner(
    state,
    PlanRequest::default(),
    snapshot::load(&state.db).await?,
    false,
    true,
  )
  .await
}

pub(crate) async fn require_plan_request(
  state: &AppState,
  auth: &crate::auth::Auth,
  req: &PlanRequest,
) -> Result<(), ApiError> {
  let current = state
    .db
    .call(|c| World::from_rows(db::all_resources(c)?))
    .await?;
  crate::token_scope::require_plan_request(auth, &current, req)
}

pub(crate) async fn make_plan_inner(
  state: &AppState,
  req: PlanRequest,
  mut snap: Snapshot,
  check_migrated_images: bool,
  admin: bool,
) -> Result<Planned, ApiError> {
  let current = snap.world.clone();
  let mut desired = current.clone();
  let given = usize::from(!req.changes.is_empty())
    + usize::from(req.fleet.is_some())
    + usize::from(req.partial.is_some());
  if given > 1 {
    return Err(ApiError::invalid(
      "changes、fleet、partial 只能给一个",
    ));
  }
  if let Some(fleet) = &req.fleet {
    desired.replace_with(fleet)?;
  } else if let Some(fleet) = &req.partial {
    desired.merge_with(fleet)?;
  } else {
    desired.apply_changes(&req.changes)?;
  }
  // 换了服务器的服务在新机器上重新分配宿主机端口，不和那里已有的服务抢。
  for (name, svc) in desired.services.iter_mut() {
    if current
      .services
      .get(name)
      .is_some_and(|c| c.spec.server != svc.spec.server)
    {
      svc.host_ports.clear();
    }
  }
  crate::service_monitor::heartbeat::prepare(
    state,
    &current,
    &mut desired,
  )?;
  desired.allocate_ports_with(&retiring_ports(
    &snap, &current, &desired,
  ))?;
  crate::secret_policy::validate_restrictions(
    &desired,
    &snap.secret_restrictions,
  )?;
  desired.validate()?;
  crate::link::validate_new_admin_port_bindings(&current, &desired)?;
  validate_changed_templates(&current, &desired)?;
  let mut warnings =
    crate::edge::validate_owners(&current, &desired)?;
  crate::secret_policy::validate_accounts(
    &desired,
    &snap.account_links,
  )?;
  crate::secret_policy::require_plan_git_secrets(
    &current, &desired, admin,
  )?;
  // 只改日志、端口监控或心跳时间时，计划只写配置，离线和现存漂移都不触发部署。
  if req.changes.iter().all(|c| {
    matches!(
      c,
      wharf_api_types::spec::Change::UpsertService {
        pins: None,
        commit: None,
        ..
      }
    )
  }) {
    let writes = desired.writes_from(&current);
    if !writes.is_empty()
      && writes.iter().all(|write| match write {
        Write::Upsert { kind, name, .. } if kind == KIND_SERVICE => {
          current
            .services
            .get(name)
            .zip(desired.services.get(name))
            .is_some_and(|(old, new)| {
              crate::service_monitor::config_only(old, new)
            })
        }
        _ => false,
      })
    {
      let mut b = Builder {
        warnings,
        ..Builder::default()
      };
      config_items(&mut b, &current, &desired, &writes);
      return Ok(finish_plan(
        &snap,
        &desired,
        b,
        writes,
        crate::render::service_account_refs(&desired),
        req.note.as_deref(),
      ));
    }
  }
  let mut refresh: BTreeSet<String> = req
    .changes
    .iter()
    .filter_map(|c| match c {
      wharf_api_types::spec::Change::RefreshImages {
        name,
        image,
      } => Some(crate::pins::refresh_key(name, image.as_deref())),
      _ => None,
    })
    .collect();
  let explicit_pins: BTreeSet<_> = req
    .changes
    .iter()
    .filter_map(|change| match change {
      wharf_api_types::spec::Change::UpsertService {
        name,
        pins: Some(_),
        ..
      } => Some(name.clone()),
      _ => None,
    })
    .collect();
  for name in &explicit_pins {
    if let Some(row) = desired.services.get(name) {
      refresh.extend(
        crate::pins::images(&row.spec.source)
          .into_iter()
          .filter(|image| !row.pins.contains_key(image))
          .map(|image| crate::pins::refresh_key(name, Some(&image))),
      );
    }
  }
  let started = std::time::Instant::now();
  let mut lap = started;
  let mut timing = Vec::new();
  let mut mark = |stage: &str| {
    timing.push(format!("{stage} {}ms", lap.elapsed().as_millis()));
    lap = std::time::Instant::now();
  };
  let resolved = crate::pins::resolve(
    state,
    &snap,
    &mut desired,
    &refresh,
    check_migrated_images,
  )
  .await?;
  warnings.extend(resolved.warnings);
  for name in &refresh {
    if let Some(why) = desired
      .services
      .get(name)
      .and_then(|r| crate::pins::unsupported(&r.spec.source))
    {
      warnings.push(format!("服务 {name} 没法检查更新：{why}"));
    }
  }
  if desired.routes.values().any(|r| r.spec.sso.is_some())
    && state
      .db
      .call(|c| {
        c.query_row(
          "SELECT totp_secret IS NOT NULL FROM admin WHERE id=1",
          [],
          |r| r.get::<_, bool>(0),
        )
        .optional()
        .map_err(crate::db::sql_err)
      })
      .await?
      != Some(true)
  {
    warnings.push("还没开两步验证，门禁只有密码一道".into());
  }
  crate::pins::resolve_commits(
    state,
    &snap,
    &mut desired,
    &refresh,
    &mut warnings,
  )
  .await?;
  mark("定版本");
  for (name, svc) in &desired.services {
    if let Source::Build(BuildSource {
      upload: Some(sha), ..
    }) = &svc.spec.source
      && !crate::uploads::exists(state, sha)
    {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的代码包还没有上传到控制面"
        ))
        .with_hint("用 wharf deploy <目录> 部署，CLI 会先上传代码"),
      );
    }
  }
  for (name, row) in &desired.servers {
    if row.settings.network_mode == Some(NetworkMode::Lan)
      && row.settings.private_addr.is_none()
    {
      return Err(
        ApiError::invalid(format!(
          "服务器 {name} 的接入方式是 lan，要指定内网地址"
        ))
        .suggest(format!(
          "wharf server set {name} --private-ip <ip>"
        )),
      );
    }
  }
  for (name, gw) in &desired.gateways {
    if let Some(account) = &gw.spec.account
      && !snap.accounts.iter().any(|a| &a.name == account)
    {
      return Err(
        ApiError::invalid(format!(
          "网关 {name} 的厂商账号 {account} 不存在"
        ))
        .suggest("wharf account list"),
      );
    }
  }

  for (host, route) in &desired.routes {
    if let Some(login) =
      route.spec.sso.as_ref().and_then(|s| s.login.as_ref())
    {
      if login.use_account
        && !snap.app_account_defaults.contains_key(host)
      {
        let error = crate::sso_login::missing_account(host);
        warnings.push(format!(
          "{}（{}）",
          error.message,
          error.hint.unwrap_or_default()
        ));
      }
      for name in crate::sso_login::secret_refs(login) {
        if !snap.secrets.contains_key(&name) {
          warnings
            .push(format!("密钥 {name} 还没有设置，代登录会失败"));
        }
      }
    }
  }
  let writes = desired.writes_from(&current);
  let mut b = Builder {
    image_ids: resolved.image_ids,
    explicit_pins,
    warnings,
    purge_data: req
      .changes
      .iter()
      .filter_map(|c| match c {
        wharf_api_types::spec::Change::RemoveService {
          name,
          purge_data: true,
        } => Some(name.clone()),
        _ => None,
      })
      .collect(),
    ..Builder::default()
  };
  config_items(&mut b, &current, &desired, &writes);
  b.migration_mounts = migration_mounts(
    state,
    &snap,
    &current,
    &desired,
    &mut b.warnings,
  )
  .await;

  for (host, route) in &desired.routes {
    let Some(sso) = route
      .spec
      .sso
      .as_ref()
      .filter(|s| s.mode == wharf_api_types::spec::SsoMode::Login)
    else {
      continue;
    };
    if current
      .routes
      .get(host)
      .and_then(|r| r.spec.sso.as_ref())
      .is_some_and(|s| {
        s.mode == wharf_api_types::spec::SsoMode::Login
      })
    {
      continue;
    }
    b.warnings.push(format!(
      "Wharf 会用保存的应用账号替每个过了门禁的人登录 {host}"
    ));
    let hostname = host.clone();
    let has_key = state.db.call(move |c| c.query_row("SELECT EXISTS(SELECT 1 FROM gate_keys, json_each(gate_keys.hosts) WHERE json_each.value=?1)", [hostname], |r| r.get::<_, bool>(0)).map_err(crate::db::sql_err)).await?;
    if !sso.skip_paths.is_empty() || sso.trust_internal || has_key {
      b.warnings.push(
        "不经过门禁的请求不会被代登录，会看到应用自己的登录页".into(),
      );
    }
  }
  let mut before_net = snap.net(&current);
  before_net.heartbeat_url.clone_from(&state.public_url);
  let mut net = snap.net(&desired);
  net.heartbeat_url.clone_from(&state.public_url);
  for (host, route) in &desired.routes {
    let Some(sso) = route
      .spec
      .sso
      .as_ref()
      .filter(|s| s.mode == wharf_api_types::spec::SsoMode::Header)
    else {
      continue;
    };
    if current
      .routes
      .get(host)
      .is_some_and(|r| r.spec.sso.as_ref() == Some(sso))
    {
      continue;
    }
    let header = sso.header.as_deref().unwrap_or("Remote-User");
    if let Some(service) = desired.services.get(&route.spec.service)
      && !net.bind_ips(&service.spec.server).is_empty()
      && match &service.spec.source {
        Source::Compose { content, .. } => {
          let compose = crate::render::parse_compose(
            content.as_deref().unwrap_or_default(),
          )?;
          crate::lint::compose_allows_direct_access(&compose)
        }
        _ => true,
      }
    {
      b.warnings.push(format!("{} 的端口能被同一个内网里的其他机器直接访问，绕过入口的请求可以自己填 {header} 冒充登录", route.spec.service));
    }
    let hostname = host.clone();
    let has_key = state.db.call(move |c| {
      c.query_row("SELECT EXISTS(SELECT 1 FROM gate_keys, json_each(gate_keys.hosts) WHERE json_each.value=?1)", [hostname], |r| r.get::<_, bool>(0)).map_err(crate::db::sql_err)
    }).await?;
    if !sso.skip_paths.is_empty() || sso.trust_internal || has_key {
      b.warnings.push(
        "不经过门禁的请求不带用户名，应用会把它们当成没登录".into(),
      );
    }
  }
  net.reach = crate::link::probe(state, &net, &desired).await;
  mark("探测互通");
  // 迁移要源机器把数据推到目标机器（design 2.10）。
  for (name, svc) in &desired.services {
    let to = &svc.spec.server;
    if let Some(from) = moved_from(&snap, &current, name, to)
      && current.services.get(name).is_some_and(|old| {
        crate::data::mounts(name, &old.spec)
          .iter()
          .any(|m| m.kind == DataKind::Managed)
      })
    {
      crate::link::require_reach(
        state,
        &net,
        from,
        to,
        "迁移数据",
        crate::link::ProbeMode::Plan,
      )
      .await?;
    }
  }
  let status = gather_status(
    state,
    &snap,
    (&current, &before_net),
    (&desired, &net),
    &mut b,
  )
  .await;
  mark("容器状态");
  let account_refs = crate::render::service_account_refs(&desired);
  if account_refs != crate::render::service_account_refs(&current) {
    let refs = account_refs.clone();
    let secrets = snap.secrets.clone();
    snap.service_values = state
      .db
      .call_credentials(move |c, key| {
        crate::db::service_values(c, key, secrets, Some(&refs))
      })
      .await?;
  }
  service_items(
    &mut b, &snap, &current, &desired, &net, &status, &writes,
  )?;
  build_agent_warnings(state, &desired, &mut b)?;
  let old_agents: BTreeSet<_> = b
    .steps
    .iter()
    .filter_map(|step| {
      let Step::ServiceUp { service, .. } = &step.step else {
        return None;
      };
      let row = desired.services.get(service)?;
      (matches!(row.spec.source, Source::Compose { .. })
        && row.import.is_none()
        && crate::apply::can_rollback_service(&row.spec)
        && state.hub.is_online(&row.spec.server)
        && !state.hub.supports_safe_rollback(&row.spec.server))
      .then_some(row.spec.server.as_str())
    })
    .collect();
  b.warnings.extend(
    old_agents
      .into_iter()
      .map(crate::apply::safe_rollback_warning),
  );
  leftover_items(&mut b, &snap, &current, &desired, &status);
  link_items(
    &mut b,
    &snap,
    &desired,
    (&before_net, &net),
    &status,
    &state.hub,
  )?;
  tailscale_items(&mut b, &snap, &desired, &status);
  egress_items(&mut b, &snap, &current, &desired);
  docker_proxy_items(&mut b, &snap, &current, &desired);
  baseline_items(&mut b, &snap, &current, &desired);
  gateway_items(
    &mut b,
    &snap,
    (&current, &before_net),
    (&desired, &net),
    &status,
    &state.hub,
  )?;
  // 带改动的计划只看受影响的域名；只检查漂移（没有改动）时看全部。
  let scope = (req.fleet.is_none()
    && (!req.changes.is_empty() || req.partial.is_some()))
  .then(|| {
    let mut affected =
      affected_hosts(&snap, &current, &before_net, &desired, &net);
    let cleanup_gateways: BTreeSet<_> = snap
      .pending
      .tunnel_deletes
      .iter()
      .map(|p| p.gateway.as_str())
      .chain(
        snap
          .pending
          .gateway_downs
          .iter()
          .map(|p| p.gateway.as_str()),
      )
      .collect();
    affected.extend(
      desired
        .routes
        .iter()
        .filter(|(host, r)| {
          desired
            .live_gateway(host, &r.spec)
            .is_some_and(|g| cleanup_gateways.contains(g))
        })
        .map(|(host, _)| host.clone()),
    );
    affected
  });
  dns_items(
    &mut b,
    &snap,
    &desired,
    &net,
    scope.as_ref(),
    true,
    None,
  )
  .await?;
  mark("DNS");
  crate::edge_plan::edge_items(
    state, &mut b, &snap, &current, &desired,
  )
  .await?;
  mark("边缘应用");
  crate::token_scope::record_dns_routes(
    &mut b.route_effects,
    &b.steps,
    &current,
    &desired,
  );
  tracing::info!(
    "生成计划用时 {}ms：{}",
    started.elapsed().as_millis(),
    timing.join("，")
  );

  Ok(finish_plan(
    &snap,
    &desired,
    b,
    writes,
    account_refs,
    req.note.as_deref(),
  ))
}

fn finish_plan(
  snap: &Snapshot,
  desired: &World,
  mut b: Builder,
  writes: Vec<Write>,
  account_refs: BTreeSet<String>,
  note: Option<&str>,
) -> Planned {
  b.warnings.extend(crate::lint::plan_warnings(
    snap, desired, &b.items, &b.steps,
  ));
  b.steps.sort_by_key(|s| s.step.order());
  // 同一次执行里要起 Tailscale：起来后机器地址会变，后面的服务和网关按新地址渲染，
  // 和计划时的指纹对不上是正常的，不校验。
  if b
    .steps
    .iter()
    .any(|s| matches!(s.step, Step::TailscaleUp { .. }))
  {
    for s in &mut b.steps {
      if let Step::ServiceUp { expect, .. }
      | Step::GatewaySync { expect, .. } = &mut s.step
      {
        *expect = None;
      }
    }
  }
  let (needs_host, host_requirements) = crate::host_access::mark_plan(
    &snap.world,
    desired,
    &mut b.items,
    &b.steps,
  );
  let plan_id = new_id("p");
  let mut needs_confirm: Vec<String> = b
    .items
    .iter()
    .filter(|i| i.needs_confirm())
    .map(|i| i.address.clone())
    .collect();
  needs_confirm.sort();
  needs_confirm.dedup();
  let suggest = if b.items.is_empty() {
    vec![]
  } else {
    let confirms: String = needs_confirm
      .iter()
      .map(|a| format!(" --confirm {a}"))
      .collect();
    vec![format!("wharf apply {plan_id}{confirms}")]
  };
  let now = Utc::now();
  let plan = Plan {
    plan_id,
    status: PlanStatus::Pending,
    created_at: now,
    expires_at: now + chrono::Duration::minutes(PLAN_TTL_MINUTES),
    base_versions: snap.world.versions(),
    inputs: Some(crate::db::inputs_fingerprint(
      &snap.reach,
      &snap.service_values,
      &snap.net(&snap.world).addresses(),
    )),
    items: b.items,
    warnings: b.warnings,
    needs_host,
    needs_confirm,
    suggest,
    note: note
      .map(str::trim)
      .filter(|n| !n.is_empty())
      .map(|n| n.chars().take(500).collect()),
  };
  Planned {
    plan,
    base_instances: snap.world.service_instances(),
    account_refs,
    host_requirements,
    route_effects: b.route_effects,
    steps: b.steps,
    writes,
  }
}

/// 服务实际在哪台服务器上：最近一次成功部署的位置，没部署过就看配置。
///
/// 迁移失败时配置已经写成新服务器，但容器和数据还在旧服务器上；
/// 按部署记录判断，重新 plan 时会再次迁移，而不是在新服务器上用不完整的数据启动。
fn running_on<'a>(
  snap: &'a Snapshot,
  current: &'a World,
  name: &str,
) -> Option<&'a str> {
  crate::snapshot::service_runtime_server(snap, name).or_else(|| {
    let configured = &current.services.get(name)?.spec.server;
    Some(snap.deployed.get(name).unwrap_or(configured))
  })
}

/// 服务要换服务器时，返回它现在所在的服务器。
fn moved_from<'a>(
  snap: &'a Snapshot,
  current: &'a World,
  name: &str,
  server: &str,
) -> Option<&'a str> {
  running_on(snap, current, name).filter(|old| *old != server)
}

fn to_json<T: Serialize>(v: &T) -> Value {
  serde_json::to_value(v).unwrap_or_default()
}

fn spec_json(world: &World, kind: &str, name: &str) -> Option<Value> {
  match kind {
    KIND_SERVER => {
      world.servers.get(name).map(|r| to_json(&r.settings))
    }
    KIND_SERVICE => world.services.get(name).map(|r| {
      let mut v =
        to_json(&crate::service_monitor::heartbeat::redact(&r.spec));
      v["host_ports"] = json!(r.host_ports);
      v
    }),
    KIND_GATEWAY => {
      world.gateways.get(name).map(|r| to_json(&r.spec))
    }
    KIND_ROUTE => world.routes.get(name).map(|r| to_json(&r.spec)),
    KIND_EDGE => world.edge_apps.get(name).map(|r| to_json(&r.spec)),
    KIND_BOOKMARK => {
      world.bookmarks.get(name).map(|r| to_json(&r.spec))
    }
    _ => None,
  }
}

mod route_impact;

fn config_items(
  b: &mut Builder,
  current: &World,
  desired: &World,
  writes: &[Write],
) {
  for write in writes {
    let (kind, name) = match write {
      Write::Upsert { kind, name, .. }
      | Write::Delete { kind, name } => {
        (kind.as_str(), name.as_str())
      }
    };
    let before = spec_json(current, kind, name);
    let after = spec_json(desired, kind, name);
    let action = match (&before, &after) {
      (None, _) => Action::Create,
      (_, None) => Action::Delete,
      _ => Action::Update,
    };
    let (risk, reason) = match (kind, action) {
      (KIND_BOOKMARK, action) => {
        let spec = if action == Action::Delete {
          &before
        } else {
          &after
        };
        let title = spec
          .as_ref()
          .and_then(|v| v["title"].as_str())
          .unwrap_or_default();
        let verb = match action {
          Action::Create => "新增",
          Action::Delete => "删除",
          _ => "修改",
        };
        (vec![], format!("{verb}书签 {title}"))
      }
      (KIND_SERVICE, Action::Delete) => {
        (vec![Impact::Remove], "删除服务（数据目录保留）".to_string())
      }
      (KIND_SERVICE, Action::Create)
        if desired
          .services
          .get(name)
          .and_then(|r| r.import.as_ref())
          .is_some() =>
      {
        let adopt = desired.services[name].import.as_ref();
        match adopt
          .and_then(|a| a.project.as_deref())
          .filter(|project| *project != name)
        {
          Some(project) => (
            vec![Impact::Restart],
            format!(
              "导入：停掉原来的 compose 项目 {project}，用新名字重新创建容器"
            ),
          ),
          None if adopt.is_some_and(|a| !a.containers.is_empty()) => {
            (
              vec![Impact::Restart],
              format!(
                "导入：原来的容器 {} 改名停掉（失败时恢复），重新创建",
                adopt
                  .map(|a| a.containers.join("、"))
                  .unwrap_or_default()
              ),
            )
          }
          None => (
            vec![],
            "导入：沿用同名 compose 项目，配置一致时不重建容器"
              .to_string(),
          ),
        }
      }
      (KIND_GATEWAY, Action::Delete) => (
        vec![Impact::Remove, Impact::Downtime],
        "删除网关".to_string(),
      ),
      (KIND_EDGE, Action::Delete) => {
        (vec![], "不再纳管（厂商那边的项目保留）".to_string())
      }
      (KIND_ROUTE, action) => route_impact::route_impact(
        current.routes.get(name).map(|r| &r.spec),
        desired.routes.get(name).map(|r| &r.spec),
        action,
      ),
      (_, Action::Create) => (vec![], "新增".to_string()),
      // 配置没变，只是记下固定的镜像版本（存在 meta 里）。
      (KIND_SERVICE, Action::Update) if before == after => {
        let old = &current.services[name];
        let new = &desired.services[name];
        let reason = if old.commit != new.commit
          && let Some(commit) = &new.commit
        {
          format!("切换代码版本到 {}", crate::pins::short(commit))
        } else if old.pins != new.pins
          && (b.explicit_pins.contains(name) || !old.pins.is_empty())
        {
          "切换固定镜像版本".into()
        } else if let Some(digest) = new.pins.values().next() {
          format!(
            "固定镜像版本 {}，不重建",
            crate::pins::short(digest)
          )
        } else {
          "更新内部记录，不重建".into()
        };
        (vec![], reason)
      }
      _ => (vec![], "修改配置".to_string()),
    };
    b.item(
      format!("{kind}/{name}"),
      Layer::Config,
      action,
      before,
      after,
      risk,
      reason,
    );
  }
}

type StatusMap =
  BTreeMap<String, Option<BTreeMap<String, ProjectState>>>;

/// 每台相关服务器查一次现状。查不到的服务器值为 `None`，并记一条提醒。
async fn gather_status(
  state: &AppState,
  snap: &Snapshot,
  (current, before_net): (&World, &Net),
  (desired, net): (&World, &Net),
  b: &mut Builder,
) -> StatusMap {
  let mut projects: BTreeMap<String, BTreeSet<String>> =
    BTreeMap::new();
  for (world, net) in [(current, before_net), (desired, net)] {
    for (name, s) in &world.services {
      projects
        .entry(s.spec.server.clone())
        .or_default()
        .insert(name.clone());
    }
    for (name, g) in &world.gateways {
      projects
        .entry(g.spec.server.clone())
        .or_default()
        .insert(gateway_project(name));
    }
    for p in crate::link::projects(world, net).unwrap_or_default() {
      projects.entry(p.server).or_default().insert(p.project);
    }
    for (name, server) in leftovers(&snap.deployed, current, desired)
    {
      projects
        .entry(server.to_string())
        .or_default()
        .insert(name.to_string());
    }
    for (name, row) in &world.servers {
      if row.settings.network_mode == Some(NetworkMode::Tailscale) {
        projects
          .entry(name.clone())
          .or_default()
          .insert(crate::tailscale::PROJECT.to_string());
      }
    }
  }
  for name in current.services.keys() {
    if let Some(server) = snap.deployed.get(name) {
      projects
        .entry(server.clone())
        .or_default()
        .insert(name.clone());
    }
  }
  for (name, migration) in &snap.pending.migrations {
    for server in [&migration.payload.from, &migration.payload.to] {
      projects
        .entry(server.clone())
        .or_default()
        .insert(name.clone());
    }
  }
  for pending in &snap.pending.service_deletes {
    projects
      .entry(pending.server.clone())
      .or_default()
      .insert(pending.service.clone());
  }
  for p in &snap.pending.gateway_downs {
    if state.hub.is_online(&p.server) {
      projects
        .entry(p.server.clone())
        .or_default()
        .insert(gateway_project(&p.gateway));
    }
  }
  let gateway_servers: BTreeSet<_> = current
    .gateways
    .values()
    .chain(desired.gateways.values())
    .filter(|g| g.spec.kind == GatewayKind::Caddy)
    .map(|g| &g.spec.server)
    .collect();
  for server in current.servers.keys().chain(desired.servers.keys()) {
    if state.hub.is_online(server) || projects.contains_key(server) {
      let candidates = projects.entry(server.clone()).or_default();
      candidates.insert(crate::link::SERVER_PROJECT.into());
      candidates.extend(
        gateway_servers
          .iter()
          .filter(|s| **s != server)
          .map(|s| crate::link::client_project(s)),
      );
    }
  }
  let futures =
    projects.into_iter().map(|(server, projects)| async move {
      let mut result = snapshot::project_status_with_links(
        &state.hub,
        &server,
        projects.into_iter().collect(),
        STATUS_TIMEOUT,
        state.hub.supports_safe_gateway(&server),
      )
      .await;
      if let Ok(states) = &mut result {
        let server = &server;
        futures_util::future::join_all(
          states
            .values_mut()
            .filter_map(|status| {
              let name = status.project.strip_prefix("wharf-gw-")?;
              (status.acme_dns_url_hash.is_none()
                && status.config_hash.is_some()
                && status.all_running()
                && [(current, before_net), (desired, net)]
                  .into_iter()
                  .any(|(world, net)| {
                    world
                      .gateways
                      .get(name)
                      .is_some_and(|g| g.spec.server == *server)
                      && snapshot::gateway_render(world, net, name)
                        .is_ok_and(|r| r.needs_acme_dns)
                  }))
              .then_some(status)
            })
            .map(|status| async move {
              status.acme_dns_url_hash =
                snapshot::read_legacy_acme_dns_hash(
                  &state.hub,
                  server,
                  &status.project,
                )
                .await;
            }),
        )
        .await;
      }
      (server, result)
    });
  let mut out = StatusMap::new();
  for (server, result) in
    futures_util::future::join_all(futures).await
  {
    match result {
      Ok(map) => {
        out.insert(server, Some(map));
      }
      Err(e) => {
        let joined =
          snap.agent(&server).is_some_and(|a| a.public_key.is_some());
        b.warnings.push(if joined {
          format!("无法读取服务器 {server} 的现状：{}", e.message)
        } else {
          format!("服务器 {server} 还没有完成 agent 加入，无法部署")
        });
        out.insert(server, None);
      }
    }
  }
  out
}

fn changed(writes: &[Write], kind: &str, name: &str) -> bool {
  writes.iter().any(|w| match w {
    Write::Upsert {
      kind: k, name: n, ..
    }
    | Write::Delete { kind: k, name: n } => k == kind && n == name,
  })
}

fn describe_containers(state: &ProjectState) -> String {
  let has_running = state.containers.iter().any(|c| c.is_running());
  state
    .containers
    .iter()
    .filter(|c| !c.foreign && !c.is_healthy_state(has_running))
    .map(|c| format!("{} {}", c.service, c.state))
    .collect::<Vec<_>>()
    .join("，")
}

fn validate_changed_templates(
  current: &World,
  desired: &World,
) -> Result<(), ApiError> {
  for (name, svc) in &desired.services {
    if let Source::Compose {
      content: Some(content),
      ..
    } = &svc.spec.source
      && current
        .services
        .get(name)
        .is_none_or(|old| old.spec.source != svc.spec.source)
    {
      crate::render::check_compose(name, content)?;
    }
  }
  for (name, route) in &desired.routes {
    if let Some(custom) = &route.spec.caddy
      && current
        .routes
        .get(name)
        .and_then(|old| old.spec.caddy.as_ref())
        != Some(custom)
    {
      crate::caddy_validate::check_custom_caddy(custom).map_err(
        |e| {
          ApiError::invalid(format!(
            "路由 {name}：自定义 Caddy 配置{e}"
          ))
          .with_hint("检查 Caddyfile 块括号、引号与指令参数")
        },
      )?;
    }
  }
  Ok(())
}

fn service_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
  writes: &[Write],
) -> Result<(), ApiError> {
  for (name, svc) in &desired.services {
    let old = current.services.get(name);
    if old.is_some_and(|old| {
      crate::service_monitor::config_only(old, svc)
    }) {
      continue;
    }
    let render_values = snap.render_values(desired, name);
    let service_changed = old.is_none_or(|old| old.spec != svc.spec);
    if service_changed
      && (!svc.spec.stopped
        || old.is_none_or(|old| old.spec.files != svc.spec.files))
    {
      crate::syntax_check::validate_service_files(
        desired,
        net,
        name,
        &render_values,
        &snap.log_values,
      )?;
    }
    let address = format!("{KIND_SERVICE}/{name}");
    let server = &svc.spec.server;
    let moved = moved_from(snap, current, name, server);
    let restarting_source = !svc.spec.stopped
      && snap.pending.migrations.get(name).is_some_and(|m| {
        m.phase != crate::pending::MigratePhase::UpDone
          && m.payload.from == *server
          && m.payload.source_stopped
      });
    if let Some(from) = moved {
      let synced =
        snap.pending.migrations.get(name).is_some_and(|m| {
          m.phase == crate::pending::MigratePhase::Synced
            && m.payload.to == *server
        });
      if !synced {
        move_items(b, snap, name, from, server, net);
      }
    }

    // 数据卷：新增的目录。迁移时新机器上要建全部目录。
    let old_dirs: BTreeSet<String> = current
      .services
      .get(name)
      .filter(|_| moved.is_none())
      .map(|s| {
        crate::render::service_dirs(name, &s.spec)
          .into_iter()
          .collect()
      })
      .unwrap_or_default();
    let pending_dirs =
      snap.pending.ensure_dirs.get(&format!("{name}@{server}"));
    let new_dirs: Vec<String> =
      crate::render::service_dirs(name, &svc.spec)
        .into_iter()
        .filter(|d| {
          !old_dirs.contains(d)
            || pending_dirs.is_some_and(|p| p.dirs.contains(d))
        })
        .collect();
    if !new_dirs.is_empty() {
      let id = b.item(
        address.clone(),
        Layer::Volume,
        Action::Create,
        None,
        Some(json!({ "dirs": new_dirs })),
        vec![],
        "创建数据目录",
      );
      b.step(
        vec![id],
        format!("在 {server} 上创建 {name} 的数据目录"),
        Step::EnsureDirs {
          server: server.clone(),
          dirs: new_dirs,
          after_sync: moved.is_some(),
        },
      );
    }

    let (_, hash) =
      snapshot::service_resolved(desired, net, name, &render_values)?;
    let template = snapshot::service_template(desired, net, name)?;
    let after =
      Some(json!({ "server": server, "compose": template }));
    let live = status
      .get(server)
      .and_then(|s| s.as_ref())
      .and_then(|p| p.get(name));
    let upgrade = crate::pins::change(
      snap.applied.get(name),
      &svc.pins,
      b.image_ids.get(name),
      b.explicit_pins.contains(name),
    )
    .map(|(image, old, new)| {
      let what = match &svc.spec.source {
        Source::Image(_) => String::new(),
        _ => format!(" {image}"),
      };
      format!(
        "更新镜像版本{what} {old} → {}",
        crate::pins::short(&new)
      )
    })
    .or_else(|| {
      crate::pins::commit_change(
        snap.applied.get(name),
        svc.commit.as_deref(),
      )
      .map(|(old, new)| {
        format!(
          "更新代码 {old} → {}，重新构建",
          crate::pins::short(&new)
        )
      })
    })
    .or_else(|| {
      (b.explicit_pins.contains(name)
        && crate::pins::images(&svc.spec.source)
          .iter()
          .any(|image| !svc.pins.contains_key(image)))
      .then(|| "按标签重新拉取未固定的镜像".into())
    });
    // 配置没变、只是要停下来：不重建，直接停。
    if moved.is_none()
      && svc.spec.stopped
      && !(upgrade.is_some()
        && (b.explicit_pins.contains(name)
          || current
            .services
            .get(name)
            .is_some_and(|old| old.commit != svc.commit)))
      && let Some(state) = live
      && state.hash.as_deref() == Some(hash.as_str())
    {
      if state.containers.iter().any(|c| !c.foreign && c.is_active())
      {
        let reason = if state
          .containers
          .iter()
          .any(|c| !c.foreign && c.is_restarting())
        {
          "停止服务（包含正在反复重启的容器）"
        } else {
          "停止服务"
        };
        let id = b.item(
          address.clone(),
          Layer::Container,
          Action::Update,
          Some(json!({ "containers": state.containers })),
          after,
          vec![Impact::Downtime],
          reason,
        );
        b.step(
          vec![id],
          format!("停止 {server} 上的 {name}"),
          Step::ServiceStop {
            service: name.clone(),
          },
        );
      }
      continue;
    }
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      None if changed(writes, KIND_SERVICE, name) => Some((
        Action::Update,
        vec![Impact::Restart],
        "无法读取现状，按新配置部署".to_string(),
        None,
      )),
      None => None,
      Some(projects) => match projects.get(name) {
        None => {
          Some((Action::Create, vec![], "部署新服务".into(), None))
        }
        Some(state)
          if state.hash.is_none() && state.containers.is_empty() =>
        {
          Some((Action::Create, vec![], "部署新服务".into(), None))
        }
        Some(state)
          if state.hash.as_deref() != Some(hash.as_str()) =>
        {
          let before = json!({ "hash": state.hash, "containers": state.containers });
          let adopting = svc.import.is_some();
          let reason: String = if state.hash.is_none() && adopting {
            "接管服务器上的同名 compose 项目，配置一致时不重建容器"
              .into()
          } else if state.hash.is_none() {
            "服务器上已有同名 project，但不是 Wharf 部署的，将被接管重建".into()
          } else {
            let (head, all) =
              if changed(writes, KIND_SERVICE, name) {
                ("配置变化", "配置变化，重建容器")
              } else {
                (
                  "漂移：服务器上的部署和配置不一致",
                  "漂移：服务器上的部署和配置不一致，重新部署",
                )
              };
            deployed_template(
              current,
              net,
              name,
              snap.applied.get(name),
            )
            .and_then(|old| changed_components(&old, &template))
            .map_or(all.to_string(), |(redo, keep)| {
              format!(
                "{head}，只重建 {}（{} 不变）",
                redo.join("、"),
                keep.join("、")
              )
            })
          };
          let risk = if state.hash.is_none() && !adopting {
            vec![Impact::Restart, Impact::Overwrite]
          } else {
            vec![Impact::Restart]
          };
          Some((
            Action::Update,
            risk,
            reason.to_string(),
            Some(before),
          ))
        }
        Some(_) if svc.spec.stopped && upgrade.is_some() => {
          upgrade.map(|reason| (Action::Update, vec![Impact::Restart], reason, None))
        }
        Some(state) => {
          let expected = crate::render::service_expected_components(
            name, &svc.spec,
          );
          let missing = crate::render::missing_components(
            &expected,
            &state.containers,
          );
          let running = state.all_running();
          if running && missing.is_empty() {
            upgrade.map(|reason| {
              (Action::Update, vec![Impact::Restart], reason, None)
            })
          } else {
            let mut before =
              json!({ "containers": state.containers });
            let reason = if missing.is_empty() {
              if changed(writes, KIND_SERVICE, name) {
                "启动服务".into()
              } else {
                format!(
                  "漂移：容器没在运行（{}）",
                  describe_containers(state)
                )
              }
            } else {
              before["missing_components"] = json!(missing);
              let missing = missing.join("、");
              if running {
                format!("漂移：缺少组件 {missing}，补建容器")
              } else {
                format!(
                  "漂移：容器没在运行（{}）；缺少组件 {missing}",
                  describe_containers(state)
                )
              }
            };
            Some((
              Action::Update,
              vec![Impact::Restart],
              reason,
              Some(before),
            ))
          }
        }
      },
    }.or_else(|| {
      let reason = if moved.is_some() {
        "在目标服务器部署服务"
      } else if restarting_source {
        "取消迁移，恢复源机服务"
      } else {
        return None;
      };
      Some((Action::Update, vec![Impact::Restart], reason.into(), None))
    });
    // 同名 compose 项目里混着别处起的容器：compose up 会把它们当成自己的删掉。导入时本来就要接管。
    let foreign: Vec<&str> = status
      .get(server)
      .and_then(|s| s.as_ref())
      .and_then(|p| p.get(name))
      .map(|s| {
        s.containers
          .iter()
          .filter(|c| c.foreign)
          .map(|c| c.name.as_str())
          .collect()
      })
      .unwrap_or_default();
    let decision = match decision {
      Some((action, _, _, before))
        if !foreign.is_empty() && svc.import.is_none() =>
      {
        Some((
          action,
          vec![Impact::Restart, Impact::Overwrite],
          format!(
            "{server} 上同名 compose 项目里有不是 Wharf 部署的容器（{}），部署会删除它们；要保留请先导入，或换个服务名",
            foreign.join("、")
          ),
          before,
        ))
      }
      d => d,
    };
    if let Some((action, mut risk, reason, before)) = decision {
      if !service_changed && !svc.spec.stopped {
        crate::syntax_check::validate_service_files(
          desired,
          net,
          name,
          &render_values,
          &snap.log_values,
        )?;
      }
      if !risk.contains(&Impact::Public)
        && crate::host_access::has_new_public_bind(
          current, name, &svc.spec,
        )
      {
        risk.push(Impact::Public);
      }
      let reason = if matches!(svc.spec.source, Source::Build(_)) {
        format!("{reason}（镜像不在 {server} 上时先构建）")
      } else {
        reason
      };
      let reason = if svc.spec.stopped {
        format!("{reason}，部署后保持停止")
      } else {
        reason
      };
      let id = b.item(
        address.clone(),
        Layer::Container,
        action,
        before,
        after,
        risk,
        reason,
      );
      b.step(
        vec![id],
        format!("在 {server} 上部署 {name}"),
        Step::ServiceUp {
          service: name.clone(),
          expect: Some(hash.clone()),
          instance_id: Some(svc.instance_id.clone()),
        },
      );
    }
  }
  for (name, svc) in &current.services {
    let migration = snap.pending.migrations.get(name);
    let desired_service = desired.services.get(name);
    let cleanup = migration.and_then(|m| {
      let target = &desired_service?.spec.server;
      if m.phase == crate::pending::MigratePhase::UpDone
        && m.payload.to == *target
      {
        return Some((m.payload.from.as_str(), false));
      }
      if m.phase != crate::pending::MigratePhase::UpDone
        && m.payload.from == *target
      {
        let exists = status
          .get(&m.payload.to)
          .and_then(Option::as_ref)
          .and_then(|projects| projects.get(name))
          .is_some_and(|s| {
            (s.hash.is_some() || !s.containers.is_empty())
              && s.containers.iter().all(|c| !c.foreign)
          });
        if exists {
          return Some((m.payload.to.as_str(), true));
        }
      }
      None
    });
    let old = cleanup
      .map(|(server, _)| server)
      .or_else(|| running_on(snap, current, name))
      .unwrap_or(&svc.spec.server);
    if desired
      .services
      .get(name)
      .is_some_and(|d| d.spec.server == old)
    {
      continue;
    }
    let has_relative_mounts =
      crate::data::has_relative_bind(&svc.spec)
        || snap
          .applied
          .get(name)
          .and_then(|applied| applied.spec.as_ref())
          .is_some_and(crate::data::has_relative_bind);
    // 迁移走的服务：旧服务器上的容器在网关切换之后删除，数据目录保留。
    if let Some(to) =
      desired.services.get(name).map(|d| &d.spec.server)
    {
      let server = &old.to_string();
      let id = b.item(
        format!("{KIND_SERVICE}/{name}"),
        Layer::Container,
        Action::Delete,
        Some(json!({ "server": server })),
        None,
        vec![],
        if cleanup.is_some_and(|(_, abort)| abort) {
          format!("取消迁移：服务保持在 {to}，删除 {server} 上的残留容器（数据目录保留）")
        } else {
          format!("迁移到 {to} 后删除 {server} 上的旧容器（数据目录保留）")
        },
      );
      b.step(
        vec![id],
        format!("删除 {server} 上的旧 {name}"),
        Step::ServiceDown {
          server: server.clone(),
          service: name.clone(),
          purge_data: false,
          instance_id: Some(svc.instance_id.clone()),
          has_relative_mounts,
        },
      );
      continue;
    }
    let server = old;
    let purge = b.purge_data.contains(name);
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      vec![Impact::Remove],
      "停止并删除容器",
    );
    for m in crate::data::mounts(name, &svc.spec) {
      let gone = purge
        && m.kind != wharf_api_types::view::DataKind::ExternalDir;
      b.warnings.push(if gone {
        format!(
          "服务 {name} 的{} 会被永久删除，不能恢复",
          crate::data::describe(&m)
        )
      } else {
        format!(
          "服务 {name} 的{} 会保留在 {server} 上，需要时手动删除",
          crate::data::describe(&m)
        )
      });
    }
    b.step(
      vec![id],
      if purge {
        format!("在 {server} 上删除 {name} 和它的数据")
      } else {
        format!("在 {server} 上删除 {name}")
      },
      Step::ServiceDown {
        server: server.to_string(),
        service: name.clone(),
        purge_data: purge,
        instance_id: Some(svc.instance_id.clone()),
        has_relative_mounts,
      },
    );
    let target = &svc.spec.server;
    if target != server
      && (purge
        || status
          .get(target)
          .and_then(Option::as_ref)
          .and_then(|projects| projects.get(name))
          .is_some_and(|s| {
            s.hash.is_some() || !s.containers.is_empty()
          }))
    {
      let id = b.item(
        format!("{KIND_SERVICE}/{name}"),
        Layer::Container,
        Action::Delete,
        Some(json!({ "server": target })),
        None,
        if purge {
          vec![Impact::Remove, Impact::DataLoss]
        } else {
          vec![Impact::Remove]
        },
        format!(
          "清理迁移未完成留在 {target} 上的残留容器{}",
          if purge { "和数据" } else { "" }
        ),
      );
      b.step(
        vec![id],
        format!("清理 {target} 上残留的 {name}"),
        Step::ServiceDown {
          server: target.clone(),
          service: name.clone(),
          purge_data: purge,
          instance_id: Some(svc.instance_id.clone()),
          has_relative_mounts,
        },
      );
    }
  }
  Ok(())
}

/// compose 里多个组件时，比较新旧模板逐个组件看：有的变了、有的没变时返回 (要重建的, 不变的)。
/// `docker compose up -d` 本来就只重建配置变了的组件，这里只是在计划里说清楚。
/// 服务器上现在跑的 compose：按上次部署的配置渲染；没有记录时退回当前配置。
/// 上次部署失败时新配置已经写进去了，拿当前配置比会看不出哪些容器要重建。
fn deployed_template(
  current: &World,
  net: &Net,
  name: &str,
  applied: Option<&wharf_api_types::view::Applied>,
) -> Option<String> {
  current.services.get(name)?;
  match applied.and_then(|a| a.spec.clone()) {
    Some(spec) => {
      let mut world = current.clone();
      world.services.get_mut(name)?.spec = spec;
      snapshot::service_template(&world, net, name).ok()
    }
    None => snapshot::service_template(current, net, name).ok(),
  }
}

fn changed_components(
  old: &str,
  new: &str,
) -> Option<(Vec<String>, Vec<String>)> {
  let parse =
    |t: &str| -> Option<BTreeMap<String, serde_yaml_ng::Value>> {
      let doc = crate::render::parse_compose(t).ok()?;
      let services = doc.get("services")?.as_mapping()?;
      Some(
        services
          .iter()
          .filter_map(|(k, v)| {
            Some((k.as_str()?.to_string(), v.clone()))
          })
          .collect(),
      )
    };
  let (old, new) = (parse(old)?, parse(new)?);
  if new.len() < 2 {
    return None;
  }
  let (redo, keep): (Vec<&String>, Vec<&String>) =
    new.keys().partition(|k| old.get(*k) != new.get(*k));
  (!redo.is_empty() && !keep.is_empty()).then(|| {
    (
      redo.into_iter().cloned().collect(),
      keep.into_iter().cloned().collect(),
    )
  })
}

/// 部署过、但配置里已经没有的服务：(服务, 最后部署在的服务器)。
/// 删除服务时配置先提交，删容器那步失败了，靠它在下次 plan 时接着清理。
fn leftovers<'a>(
  deployed: &'a BTreeMap<String, String>,
  current: &'a World,
  desired: &'a World,
) -> impl Iterator<Item = (&'a str, &'a str)> {
  deployed
    .iter()
    .filter(|(name, _)| {
      !current.services.contains_key(*name)
        && !desired.services.contains_key(*name)
    })
    .map(|(n, s)| (n.as_str(), s.as_str()))
}

/// 上次删除没做完：项目目录（Wharf 的部署指纹）还在。别人同名的项目没有指纹，不碰。
fn leftover_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  status: &StatusMap,
) {
  for p in &snap.pending.service_deletes {
    let (name, server) = (&p.service, &p.server);
    if current.services.get(name).is_some_and(|row| {
      row.instance_id != p.instance_id || row.spec.server == *server
    }) {
      continue;
    }
    let projects = status.get(server).and_then(Option::as_ref);
    let project = projects.and_then(|projects| projects.get(name));
    if !p.purge_data
      && project
        .is_some_and(|s| s.hash.is_none() && s.containers.is_empty())
    {
      continue;
    }
    if desired.services.get(name).is_some_and(|row| {
      row.instance_id != p.instance_id || row.spec.server == *server
    }) {
      b.warnings.push(format!("服务 {name} 的旧实例在 {server} 上曾有未完成的删除，新建同名服务后不会再自动清理旧数据，请按需手动检查"));
      continue;
    }
    if projects.is_none() {
      b.warnings.push(format!("上次删除服务 {name} 未完成，待服务器 {server} 上线后重新 plan 继续清理"));
      continue;
    }
    let (impacts, reason) = if p.purge_data {
      b.warnings.push(format!("服务 {name} 的目录 /srv/{name} 和命名卷会被永久删除，不能恢复"));
      (
        vec![Impact::Remove, Impact::DataLoss],
        "上次带清数据的删除未完成，继续删除残留容器及 /srv/ 下的服务目录和命名卷",
      )
    } else if project
      .is_some_and(|s| s.hash.is_some() || !s.containers.is_empty())
    {
      (
        vec![Impact::Remove],
        "上次删除没有完成，停止并删除留下的容器（数据目录保留）",
      )
    } else {
      continue;
    };
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      impacts,
      reason,
    );
    b.step(
      vec![id],
      format!("在 {server} 上继续删除 {name}"),
      Step::ServiceDown {
        server: server.clone(),
        service: name.clone(),
        purge_data: p.purge_data,
        instance_id: Some(p.instance_id.clone()),
        has_relative_mounts: p.has_relative_mounts,
      },
    );
  }
  for (name, server) in leftovers(&snap.deployed, current, desired) {
    if snap
      .pending
      .service_deletes
      .iter()
      .any(|p| p.service == name && p.server == server)
    {
      continue;
    }
    let Some(Some(projects)) = status.get(server) else {
      continue;
    };
    let Some(state) = projects.get(name).filter(|s| s.hash.is_some())
    else {
      continue;
    };
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(
        json!({ "server": server, "containers": state.containers }),
      ),
      None,
      vec![Impact::Remove],
      "上次删除没有完成，停止并删除留下的容器（数据目录保留）",
    );
    b.step(
      vec![id],
      format!("在 {server} 上删除 {name}"),
      Step::ServiceDown {
        server: server.to_string(),
        service: name.to_string(),
        purge_data: false,
        instance_id: None,
        // 老记录没有原配置，按可能有相对挂载处理。
        has_relative_mounts: true,
      },
    );
  }
}

async fn migration_mounts(
  state: &AppState,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  warnings: &mut Vec<String>,
) -> BTreeMap<String, Vec<wharf_api_types::agent::ContainerMount>> {
  let mut by_server: BTreeMap<&str, Vec<String>> = BTreeMap::new();
  for (name, row) in &desired.services {
    if let Some(from) =
      moved_from(snap, current, name, &row.spec.server)
    {
      by_server.entry(from).or_default().push(name.clone());
    }
  }
  let cancel = tokio_util::sync::CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  let mut out = BTreeMap::new();
  for (from, projects) in by_server {
    if !state.hub.supports_safe_migrate(from) {
      warnings.push(format!("源服务器 {from} 的 agent 版本较旧或离线，无法检查镜像自带的匿名卷，建议先 wharf upgrade"));
      continue;
    }
    let result = state.hub.call::<BTreeMap<String, Vec<wharf_api_types::agent::ContainerMount>>>(
      from, wharf_api_types::agent::AgentOp::ProjectMounts { projects },
      Duration::from_secs(15), None, &cancel,
    ).await;
    match result {
      Ok(mounts) => out.extend(mounts),
      Err(e) => warnings.push(format!(
        "无法检查源服务器 {from} 上未声明的卷：{}",
        e.message
      )),
    }
  }
  out
}

/// 迁移数据的计划项和步骤，以及相关提醒。
fn move_items(
  b: &mut Builder,
  snap: &Snapshot,
  name: &str,
  from: &str,
  to: &str,
  net: &Net,
) {
  let old = &snap.world.services[name];
  let source = snap
    .applied
    .get(name)
    .and_then(|a| a.spec.as_ref())
    .unwrap_or(&old.spec);
  let mounts = crate::data::mounts(name, source);
  let mut left: Vec<String> = mounts
    .iter()
    .filter(|m| m.kind != DataKind::Managed)
    .map(crate::data::describe)
    .collect();
  if let Some(actual) = b.migration_mounts.get(name) {
    left.extend(
      crate::data::undeclared_mounts(name, &mounts, actual)
        .iter()
        .map(|m| {
          let component = m
            .container
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(name);
          format!(
            "组件 {component} 的{}（挂载路径 {}，镜像自带或未声明）",
            crate::data::describe(m),
            m.target
          )
        }),
    );
  }
  left.sort();
  left.dedup();
  // 不归 Wharf 管的数据不会跟着走，新服务器上的服务看不到它们，要用户确认。
  if !left.is_empty() {
    b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Volume,
      Action::Update,
      None,
      None,
      vec![Impact::DataLoss],
      format!(
        "{} 不归 Wharf 管，不会迁移到 {to}：迁移后服务看不到这些数据",
        left.join("、")
      ),
    );
  }
  // 没有 Wharf 管理的数据：没有要搬的，新容器起来、网关切过去即可，不停服。
  let recorded = snap.pending.migrations.get(name).is_some_and(|m| {
    m.payload.has_managed_data && m.payload.from == from
  });
  if !recorded && !mounts.iter().any(|m| m.kind == DataKind::Managed)
  {
    return;
  }
  let id = b.item(
    format!("{KIND_SERVICE}/{name}"),
    Layer::Volume,
    Action::Update,
    Some(json!({ "server": from, "dir": format!("/srv/{name}/") })),
    Some(json!({ "server": to, "dir": format!("/srv/{name}/") })),
    vec![Impact::Downtime],
    format!("迁移 /srv/{name}/ 从 {from} 到 {to}：先同步一遍，再停掉旧容器做增量同步，这段时间服务不可用"),
  );
  b.step(
    vec![id],
    format!("迁移 {name} 的数据 {from} → {to}"),
    Step::VolumeSync {
      service: name.to_string(),
      from: from.to_string(),
      to: to.to_string(),
      instance_id: Some(old.instance_id.clone()),
    },
  );
  for (server, role) in [(from, "源"), (to, "目标")] {
    match net.private.get(server) {
      None => b.warnings.push(format!(
        "迁移 {name} 需要{role}服务器 {server} 的内网地址，执行时会失败：先 wharf server set {server} --private-ip <ip>"
      )),
      Some(addr) if !addr.network.encrypted() && role == "目标" => {
        b.warnings.push(format!(
          "迁移 {name} 的数据走内网直连 {from} → {to}，是明文"
        ))
      }
      _ => {}
    }
  }
  b.warnings.push(format!(
    "迁移后 {from} 上的 /srv/{name}/ 保留 7 天，之后自动删除（期间迁回 {from} 就不删）"
  ));
}

/// 网关上次应用的配置哈希：caddy 由 agent 上报，隧道的规则在厂商那边，记在控制面里。
fn applied_config<'a>(
  snap: &'a Snapshot,
  gateway: &str,
  kind: GatewayKind,
  state: &'a ProjectState,
) -> Option<&'a str> {
  match kind {
    GatewayKind::Caddy => state.config_hash.as_deref(),
    GatewayKind::CloudflareTunnel => {
      snap.tunnels.get(gateway).map(|t| t.config_hash.as_str())
    }
  }
}

/// 反向隧道的 frps / frpc：按路由算出该有哪些，和现状比对。
fn link_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  (before_net, net): (&Net, &Net),
  status: &StatusMap,
  hub: &crate::hub::Hub,
) -> Result<(), ApiError> {
  let before =
    crate::link::tunnels(&snap.world, before_net).unwrap_or_default();
  let after = crate::link::tunnels(desired, net)?;
  let want = crate::link::projects_for_servers(
    desired,
    net,
    &snap.secrets,
    |p| {
      hub.supports_frpc_reload(&p.server)
        && status.get(&p.server).and_then(Option::as_ref).is_some_and(
          |projects| {
            projects.get(&p.project).is_none_or(|s| {
              s.config_hash.is_some()
                || s.hash.as_deref() != Some(p.hash.as_str())
                || !s.all_running()
            })
          },
        )
    },
  )?;
  for p in &want {
    // 查不到现状的服务器已经单独提醒过。
    let Some(Some(projects)) = status.get(&p.server) else {
      continue;
    };
    let decision = match projects.get(&p.project) {
      Some(s) if !(s.hash.is_none() && s.containers.is_empty()) => {
        if s.hash.as_deref() != Some(p.hash.as_str()) {
          Some((
            Action::Update,
            vec![Impact::Restart],
            format!(
              "{}（配置变化，重建，经这条隧道的路由会断几秒）",
              p.summary
            ),
          ))
        } else if !s.all_running() {
          Some((
            Action::Update,
            vec![Impact::Restart],
            format!(
              "漂移：隧道容器没在运行（{}）",
              describe_containers(s)
            ),
          ))
        } else if p.reload.as_ref().is_some_and(|r| {
          s.config_hash.as_deref() != Some(r.config_hash.as_str())
        }) {
          Some((
            Action::Update,
            vec![],
            format!(
              "{}（热重载隧道配置，同机其他隧道不断开）",
              p.summary
            ),
          ))
        } else {
          None
        }
      }
      _ => Some((Action::Create, vec![], p.summary.clone())),
    };
    let Some((action, risk, reason)) = decision else {
      continue;
    };
    if p.project != crate::link::SERVER_PROJECT
      && hub.is_online(&p.server)
      && !hub.supports_frpc_reload(&p.server)
    {
      let server = &p.server;
      let warning = format!(
        "服务器 {server} 的 agent 版本较旧，修改隧道仍会重启 frpc；可执行 wharf server upgrade {server}"
      );
      if !b.warnings.contains(&warning) {
        b.warnings.push(warning);
      }
    }
    let id = b.item(
      format!("link/{}/{}", p.server, p.project),
      Layer::Gateway,
      action,
      None,
      Some(json!({ "server": p.server, "summary": p.summary })),
      risk,
      reason,
    );
    b.step(
      vec![id],
      format!("在 {} 上部署 {}", p.server, p.project),
      Step::LinkUp {
        server: p.server.clone(),
        project: p.project.clone(),
        hot_reload: p.reload.is_some(),
        after_dns: action == Action::Update
          && only_withdraws_tunnels(p, &before, &after),
      },
    );
  }
  for (server, projects) in status {
    for (project, state) in projects.iter().flatten() {
      if !crate::link::is_link_project(project)
        || (state.hash.is_none()
          && state.containers.iter().all(|c| c.foreign))
        || want
          .iter()
          .any(|p| p.server == *server && p.project == *project)
      {
        continue;
      }
      let id = b.item(
        format!("link/{server}/{project}"),
        Layer::Gateway,
        Action::Delete,
        Some(json!({ "server": server })),
        None,
        vec![Impact::Remove],
        "没有路由再用这条隧道，停止并删除",
      );
      b.step(
        vec![id],
        format!("在 {server} 上删除 {project}"),
        Step::LinkDown {
          server: server.clone(),
          project: project.clone(),
        },
      );
    }
  }
  Ok(())
}

/// 出口设置变了（自己的规则、经哪台、那台的规则）：让这台的 agent 重新起出口和本地分流。
/// 排在 dockerd 代理前面，那边要用本机的分流代理。
fn egress_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) {
  use crate::egress::effective;
  for server in desired.servers.keys() {
    let after = effective(server, desired);
    let before = effective(server, current);
    if after == before && !snap.pending.egresses.contains(server) {
      continue;
    }
    let show = |e: &Option<(
      Option<wharf_api_types::egress::EgressSpec>,
      Option<String>,
      Option<wharf_api_types::egress::EgressSpec>,
    )>| {
      e.as_ref().map(|(own, via, rules)| {
        json!({ "egress": own, "via": via, "via_rules": rules })
      })
    };
    let mut what = Vec::new();
    if let Some((own, via, _)) = &after {
      if let Some(o) = own {
        what.push(if o.all {
          "给其他机器当外网代理（所有网站）".to_string()
        } else {
          format!(
            "给其他机器当外网代理（{} 个域名）",
            o.domains().len()
          )
        });
      }
      if let Some(v) = via {
        what.push(format!(
          "访问外网借 {v}（只转发规则里的网站，{v} 不通时直连）"
        ));
      }
    }
    let reason = if what.is_empty() {
      format!("{server} 不再当外网代理或借道，相关请求改为直连")
    } else {
      format!("{server}：{}", what.join("；"))
    };
    let id = b.item(
      format!("egress/{server}"),
      Layer::Container,
      match (&before, &after) {
        _ if before == after => Action::Update,
        (None, _) => Action::Create,
        (_, None) => Action::Delete,
        _ => Action::Update,
      },
      show(&before),
      show(&after),
      vec![],
      reason,
    );
    b.step(
      vec![id],
      format!("更新 {server} 的外网代理"),
      Step::Egress {
        server: server.clone(),
      },
    );
  }
}

/// 机器基线：设置改了，或者最近一次检查有差异时，加一步纠正。
fn baseline_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) {
  for (server, row) in &desired.servers {
    let want = &row.settings.baseline;
    if want.is_empty() {
      continue;
    }
    let before =
      current.servers.get(server).map(|r| &r.settings.baseline);
    let drift = crate::baseline::drift(server);
    if before == Some(want)
      && drift.is_empty()
      && !snap.pending.baselines.contains(server)
    {
      continue;
    }
    let reason = if drift.is_empty() {
      "按新的基线检查并纠正系统设置".to_string()
    } else {
      drift.join("；")
    };
    let id = b.item(
      format!("baseline/{server}"),
      Layer::Container,
      Action::Update,
      before.map(|b| json!(b)),
      Some(json!(want)),
      vec![],
      reason,
    );
    b.step(
      vec![id],
      format!("纠正 {server} 的基线"),
      Step::Baseline {
        server: server.clone(),
      },
    );
  }
}

/// Wharf 管理的 Tailscale 容器：要的时候起，接入方式改掉之后删。
/// 拉镜像代理的设置（或它要直连的镜像源）变了：改 dockerd 配置。
fn docker_proxy_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
) {
  use crate::docker_proxy::wanted;
  for (server, row) in &desired.servers {
    let after = wanted(&row.settings);
    let before = current
      .servers
      .get(server)
      .and_then(|r| wanted(&r.settings));
    if after == before
      && !snap.pending.docker_proxies.contains(server)
    {
      continue;
    }
    let (mut reason, title) = match &after {
      Some((proxy, _)) => (
        format!(
          "拉镜像改走{}，镜像源和内网直连；重启 dockerd，开启 live-restore 后容器不停",
          shown(proxy)
        ),
        format!("在 {server} 上给 dockerd 配拉镜像代理"),
      ),
      None => (
        "去掉拉镜像代理，重启 dockerd（开启 live-restore，容器不停）"
          .to_string(),
        format!("在 {server} 上去掉 dockerd 的拉镜像代理"),
      ),
    };
    if after == before {
      reason = "上次拉镜像代理设置未完成，重新应用到 dockerd".into();
    }
    let id = b.item(
      format!("docker/{server}"),
      Layer::Container,
      if before == after {
        Action::Update
      } else if before.is_none() {
        Action::Create
      } else if after.is_none() {
        Action::Delete
      } else {
        Action::Update
      },
      before
        .map(|(p, n)| json!({ "proxy": shown(&p), "no_proxy": n })),
      after
        .map(|(p, n)| json!({ "proxy": shown(&p), "no_proxy": n })),
      vec![Impact::Restart],
      reason,
    );
    b.step(
      vec![id],
      title,
      Step::DockerProxy {
        server: server.clone(),
      },
    );
  }
}

/// 代理地址给人看的样子。
fn shown(value: &str) -> String {
  if value == crate::egress::local_url() {
    "本机分流代理（按借道规则）".into()
  } else {
    format!("代理 {value}")
  }
}

fn only_withdraws_tunnels(
  project: &crate::link::LinkProject,
  before: &[crate::link::Tunnel],
  after: &[crate::link::Tunnel],
) -> bool {
  let Some(gateway_server) =
    project.project.strip_prefix("wharf-link-")
  else {
    return false;
  };
  let belongs = |t: &&crate::link::Tunnel| {
    t.service_server == project.server
      && t.gateway_server == gateway_server
  };
  let old: Vec<_> = before.iter().filter(belongs).collect();
  let new: Vec<_> = after.iter().filter(belongs).collect();
  new.len() < old.len() && new.iter().all(|t| old.contains(t))
}

fn tailscale_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  status: &StatusMap,
) {
  use crate::tailscale::{self as ts, PROJECT};
  for server in desired.servers.keys() {
    // 查不到现状的服务器已经单独提醒过。
    let Some(Some(projects)) = status.get(server) else {
      continue;
    };
    let existing = projects
      .get(PROJECT)
      .filter(|s| !(s.hash.is_none() && s.containers.is_empty()));
    let address = format!("network/{server}/tailscale");
    if !ts::wanted(snap, desired, server, existing.is_some()) {
      if existing.is_some() {
        let id = b.item(
          address,
          Layer::Tunnel,
          Action::Delete,
          Some(json!({ "server": server })),
          None,
          vec![Impact::Remove],
          "接入方式不再是 tailscale，删除 Wharf 装的 Tailscale（机器会留在 Tailscale 后台，显示离线）",
        );
        b.step(
          vec![id],
          format!("在 {server} 上删除 Tailscale"),
          Step::LinkDown {
            server: server.clone(),
            project: PROJECT.to_string(),
          },
        );
      }
      continue;
    }
    let hash = ts::hash(server);
    let decision = match existing {
      None => Some((
        Action::Create,
        vec![],
        format!("没检测到 Tailscale，起容器并以 {} 加入", ts::TAG),
      )),
      Some(s) if s.hash.as_deref() != Some(hash.as_str()) => Some((
        Action::Update,
        vec![Impact::Restart],
        "Tailscale 容器配置变化，重建（不会重新加入）".to_string(),
      )),
      Some(s) if !s.all_running() => Some((
        Action::Update,
        vec![Impact::Restart],
        format!(
          "漂移：Tailscale 容器没在运行（{}）",
          describe_containers(s)
        ),
      )),
      Some(_) => None,
    };
    let Some((action, risk, reason)) = decision else {
      continue;
    };
    let id = b.item(
      address,
      Layer::Tunnel,
      action,
      None,
      Some(json!({ "server": server, "image": ts::IMAGE })),
      risk,
      reason,
    );
    b.step(
      vec![id],
      format!("在 {server} 上部署 Tailscale"),
      Step::TailscaleUp {
        server: server.clone(),
      },
    );
  }
}

fn gateway_items(
  b: &mut Builder,
  snap: &Snapshot,
  (current, before_net): (&World, &Net),
  (desired, net): (&World, &Net),
  status: &StatusMap,
  hub: &crate::hub::Hub,
) -> Result<(), ApiError> {
  for name in desired.gateways.keys() {
    let gw = &desired.gateways[name];
    if gw.spec.kind == GatewayKind::Caddy {
      for zone in &gw.spec.wildcard {
        if current
          .gateways
          .get(name)
          .is_some_and(|g| g.spec.wildcard.contains(zone))
        {
          continue;
        }
        if gw.spec.tls == GatewayTls::Auto
          && snap.account_for(zone).is_none()
        {
          return Err(ApiError::invalid(format!(
                        "入口 {name} 的泛域名证书 *.{zone}：没有厂商账号管理 {zone}"
                    ))
                    .suggest("wharf account list"));
        }
        b.warnings.push(format!("入口 {name} 开启 *.{zone} 的泛域名证书：这个入口上 {zone} 下一级的域名都改用这张证书，签出来之前（DNS 验证通常几十秒）这些域名的 HTTPS 打不开（验证记录由控制面写）"));
      }
    }
    if gw.spec.kind == GatewayKind::Caddy
      && gw.spec.tls == GatewayTls::Auto
    {
      for (host, route) in &desired.routes {
        if desired
          .route_gateways(&route.spec)
          .contains(&name.as_str())
          && route.spec.internal
          && !host.split_once('.').is_some_and(|(_, zone)| {
            gw.spec.wildcard.iter().any(|z| z == zone)
          })
          && snap.account_for(host).is_none()
        {
          b.warnings.push(format!("内网域名 {host} 的证书要用 DNS 验证签，但没有厂商账号管理它，证书签不出来"));
        }
      }
    }
    let server = &gw.spec.server;
    let project = gateway_project(name);
    let r = snapshot::gateway_render(desired, net, name)?;
    let online = hub.is_online(server);
    if r.needs_link_cert && online {
      crate::link_cert::require_gateway_agent(hub, server, name)?;
    }
    let after = Some(json!({
      "server": server,
      "sites": r.sites.iter().map(|s| json!({ "hostname": s.hostname, "upstream": s.upstream })).collect::<Vec<_>>(),
      "config": snapshot::redacted_config(&r.config, net),
    }));
    let tunnel_not_ready = gw.spec.kind
      == GatewayKind::CloudflareTunnel
      && crate::tunnel::ready(snap, name, &gw.spec).is_none();
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      _ if tunnel_not_ready => Some((
        Action::Update,
        vec![Impact::Restart],
        "在当前厂商账号下创建隧道并部署连接器".into(),
      )),
      // 查不到现状时，只有配置变了才计划（服务器离线已经单独提醒过）。
      None => {
        let migrating = snap
          .pending
          .gateway_downs
          .iter()
          .any(|p| p.gateway == *name && p.server != *server);
        let same = !migrating
          && current.gateways.get(name) == desired.gateways.get(name)
          && gateway_sites_same(
            current, before_net, desired, net, name,
          );
        (!same).then(|| {
          (
            Action::Update,
            vec![Impact::Restart],
            "无法读取现状，按新配置应用".to_string(),
          )
        })
      }
      Some(projects) => match projects.get(&project) {
        Some(s) if s.hash.is_none() && s.containers.is_empty() => {
          Some((Action::Create, vec![], "部署网关".to_string()))
        }
        None => {
          Some((Action::Create, vec![], "部署网关".to_string()))
        }
        Some(s)
          if s.hash.as_deref() != Some(r.compose_hash.as_str()) =>
        {
          Some((
            Action::Update,
            vec![Impact::Restart],
            "网关容器配置变化，重建".to_string(),
          ))
        }
        Some(s) if !s.all_running() => Some((
          Action::Update,
          vec![Impact::Restart],
          format!(
            "漂移：网关容器没在运行（{}）",
            describe_containers(s)
          ),
        )),
        Some(s)
          if !snapshot::gateway_config_matches(
            desired,
            net,
            name,
            &r,
            applied_config(snap, name, gw.spec.kind, s),
            s.acme_dns_url_hash.as_deref(),
          ) =>
        {
          Some((
            Action::Update,
            vec![],
            match gw.spec.kind {
              GatewayKind::Caddy if r.needs_link_cert => {
                let now = chrono::Utc::now();
                match net
                  .link_certs
                  .get(name)
                  .and_then(|cert| cert.expires_at)
                {
                  Some(at)
                    if crate::link_cert::needs_renew(
                      Some(at),
                      now,
                    ) =>
                  {
                    let days = crate::link_cert::days_left(at, now);
                    if days <= 0 {
                      "隧道叶证书已过期，续签并热重载配置".into()
                    } else {
                      format!(
                        "隧道叶证书将于 {days} 天后到期，续签并热重载配置"
                      )
                    }
                  }
                  _ if gateway_sites_same(
                    current, before_net, desired, net, name,
                  ) =>
                  {
                    "隧道证书变化，热重载配置".into()
                  }
                  _ => "路由变化，热重载配置".into(),
                }
              }
              GatewayKind::Caddy => {
                "路由或验证地址变化，热重载配置".into()
              }
              GatewayKind::CloudflareTunnel => {
                "路由变化，更新隧道入口规则".into()
              }
            },
          ))
        }
        Some(_) => None,
      },
    };
    if let Some((action, mut risk, reason)) = decision {
      if gw.spec.kind == GatewayKind::Caddy
        && online
        && action == Action::Update
        && risk.contains(&Impact::Restart)
        && !hub.supports_safe_rollback(server)
      {
        let warning = crate::apply::safe_rollback_warning(server);
        if !b.warnings.contains(&warning) {
          b.warnings.push(warning);
        }
      }
      if r.needs_link_cert && !online {
        b.warnings.push(format!("服务器 {server} 离线，无法确认网关 {name} 的 agent 能下发隧道证书"));
      }
      if gw.spec.kind == GatewayKind::Caddy {
        crate::caddy_validate::check_caddyfile(&r.config).map_err(
          |e| {
            ApiError::invalid(format!(
              "网关 {name} 渲染后的 Caddyfile 不合法（{e}）"
            ))
          },
        )?;
        for f in &gw.spec.layer4 {
          if current
            .gateways
            .get(name)
            .is_some_and(|g| g.spec.layer4.contains(f))
          {
            continue;
          }
          if !risk.contains(&Impact::Public) {
            risk.push(Impact::Public);
          }
          let protocol = if f.udp { "UDP" } else { "TCP" };
          let listen = f.listen;
          b.warnings.push(format!("入口 {name} 在 {server} 上对公网开放 {protocol} 端口 {listen}（四层转发，没有登录保护）；云厂商的安全组、机器的防火墙要自己放行"));
        }
      }
      let (layer, reason) = match gw.spec.kind {
        GatewayKind::Caddy => (Layer::Gateway, reason),
        GatewayKind::CloudflareTunnel
          if !snap.tunnels.contains_key(name) =>
        {
          (
            Layer::Tunnel,
            format!(
              "在账号 {} 下创建隧道 {}，部署 cloudflared",
              gw.spec.account.as_deref().unwrap_or_default(),
              crate::tunnel::tunnel_name(name)
            ),
          )
        }
        GatewayKind::CloudflareTunnel => (Layer::Tunnel, reason),
      };
      let routes = if gw.spec.kind == GatewayKind::Caddy
        && action == Action::Update
        && risk.is_empty()
        && current.gateways.get(name) == Some(gw)
        && let Some(applied) = status
          .get(server)
          .and_then(Option::as_ref)
          .and_then(|p| p.get(&project))
      {
        crate::token_scope::gateway_routes(
          &b.items, current, desired, net, name, applied,
        )
      } else {
        vec![]
      };
      let id = b.item(
        format!("{KIND_GATEWAY}/{name}"),
        layer,
        action,
        None,
        after,
        risk,
        reason,
      );
      if !routes.is_empty() {
        b.route_effects.insert(id, routes);
      }
      b.step(
        vec![id],
        format!("在 {server} 上应用网关 {name}"),
        Step::GatewaySync {
          gateway: name.clone(),
          after_dns: action == Action::Update
            && current.gateways.get(name) == Some(gw)
            && status
              .get(server)
              .and_then(Option::as_ref)
              .and_then(|p| p.get(&project))
              .is_some_and(|applied| {
                applied.all_running()
                  && applied.hash.as_deref()
                    == Some(r.compose_hash.as_str())
              })
            && snapshot::gateway_render(current, before_net, name)
              .is_ok_and(|before| {
                r.sites.len() < before.sites.len()
                  && r
                    .sites
                    .iter()
                    .all(|site| before.sites.contains(site))
              }),
          expect: (gw.spec.kind == GatewayKind::Caddy)
            .then(|| r.fingerprint()),
        },
      );
    }
  }
  gateway_cleanup_items(b, snap, current, desired, status);
  Ok(())
}

fn gateway_cleanup_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  status: &StatusMap,
) {
  let mut downs = BTreeMap::new();
  for p in &snap.pending.gateway_downs {
    let current_server = desired
      .gateways
      .get(&p.gateway)
      .map(|g| g.spec.server.as_str());
    if current_server != Some(p.server.as_str())
      && (!p.keep_tunnel
        || (desired.servers.contains_key(&p.server)
          && status.get(&p.server).is_some_and(Option::is_some)))
    {
      downs.insert((&p.gateway, &p.server), p.keep_tunnel);
    }
  }
  for (name, gw) in &current.gateways {
    let next = desired.gateways.get(name);
    if next.is_none_or(|g| g.spec.server != gw.spec.server) {
      downs.insert((name, &gw.spec.server), next.is_some());
    }
  }
  for ((name, server), keep_tunnel) in downs {
    let mut impacts = vec![Impact::Remove];
    if !keep_tunnel {
      impacts.push(Impact::Downtime);
    }
    let id = b.item(
      format!("{KIND_GATEWAY}/{name}"),
      Layer::Gateway,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      impacts,
      if keep_tunnel {
        "停止并删除旧机网关容器"
      } else {
        "停止并删除网关容器"
      },
    );
    b.step(
      vec![id],
      format!("在 {server} 上删除网关 {name}"),
      Step::GatewayDown {
        server: server.clone(),
        gateway: name.clone(),
        keep_tunnel,
      },
    );
  }

  let mut old_tunnels: BTreeMap<_, _> = snap
    .pending
    .tunnel_deletes
    .iter()
    .map(|p| ((p.account.clone(), p.tunnel_id.clone()), p.clone()))
    .collect();
  for (name, gw) in &desired.gateways {
    if gw.spec.kind == GatewayKind::CloudflareTunnel
      && let Some(old) = snap.tunnels.get(name)
      && Some(old.account.as_str()) != gw.spec.account.as_deref()
    {
      old_tunnels.insert(
        (old.account.clone(), old.tunnel_id.clone()),
        crate::pending::TunnelDeletePayload {
          gateway: name.clone(),
          account: old.account.clone(),
          scope: old.scope.clone(),
          tunnel_id: old.tunnel_id.clone(),
        },
      );
    }
  }
  for p in old_tunnels.into_values() {
    if snap.gateway_has_external_dns(desired, &p.gateway) {
      b.warnings.push(format!(
        "入口 {} 还有域名的 DNS 由外部管理，暂缓清理旧隧道",
        p.gateway
      ));
      continue;
    }
    if desired.gateways.get(&p.gateway).is_some_and(|g| {
      g.spec.account.as_deref() == Some(p.account.as_str())
    }) && snap
      .tunnels
      .get(&p.gateway)
      .is_some_and(|t| t.tunnel_id == p.tunnel_id)
    {
      continue;
    }
    let id = b.item(
      format!("{KIND_GATEWAY}/{}", p.gateway),
      Layer::Tunnel,
      Action::Delete,
      Some(json!({ "account": p.account, "tunnel_id": p.tunnel_id })),
      None,
      vec![Impact::Remove],
      "在新隧道和 DNS 生效后清理旧隧道",
    );
    b.step(
      vec![id],
      format!("删除旧账号 {} 下的隧道", p.account),
      Step::TunnelDelete {
        gateway: p.gateway,
        account: p.account,
        scope: p.scope,
        tunnel_id: p.tunnel_id,
      },
    );
  }
}

fn gateway_sites_same(
  current: &World,
  before_net: &Net,
  desired: &World,
  net: &Net,
  name: &str,
) -> bool {
  let a = snapshot::gateway_render(current, before_net, name).ok();
  let b = snapshot::gateway_render(desired, net, name).ok();
  matches!((a, b), (Some(a), Some(b)) if a.config_hash == b.config_hash)
}

/// 路由期望的 DNS 记录。
pub(crate) fn desired_record(
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  hostname: &str,
) -> Result<DnsSpec, ApiError> {
  desired_record_at(snap, desired, net, hostname, None)
}

pub(crate) fn desired_record_at(
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  hostname: &str,
  target: Option<&str>,
) -> Result<DnsSpec, ApiError> {
  let route = &desired.routes[hostname];
  let gateway = target
    .or_else(|| desired.live_gateway(hostname, &route.spec))
    .ok_or_else(|| {
      ApiError::invalid(format!("路由 {hostname} 没有网关"))
    })?;
  let gw = &desired.gateways[gateway].spec;
  if gw.kind == GatewayKind::CloudflareTunnel {
    return Ok(DnsSpec {
      record_type: "CNAME".into(),
      content: crate::tunnel::ready(snap, gateway, gw)
        .map(|t| tunnel_target(&t.tunnel_id))
        .unwrap_or_else(|| TUNNEL_PENDING.into()),
      proxied: true,
      ttl: 1,
      tunnel: Some(gateway.to_string()),
    });
  }
  let server = &gw.server;
  let ip = if route.spec.internal {
    net.private.get(server).map(|a| &a.ip).ok_or_else(|| {
      ApiError::invalid(format!("路由 {hostname} 只在内网访问，但入口 {gateway} 所在的 {server} 没有内网地址"))
        .with_hint("装好组网或手动指定内网地址")
        .suggest(format!("wharf server set {server} --private-ip <ip>"))
    })?
  } else {
    net.public_ip.get(server).ok_or_else(|| {
    ApiError::invalid(format!(
      "网关 {gateway} 所在的服务器 {server} 没有公网 IP，{hostname} 的 DNS 无处可指"
    ))
    .with_hint("agent 没探测到公网 IP 时，可以手动设置")
    .suggest(format!("wharf server set {server} --public-ip <ip>"))
  })?
  };
  let record_type = if ip.parse::<std::net::Ipv6Addr>().is_ok() {
    "AAAA"
  } else {
    "A"
  };
  Ok(DnsSpec {
    record_type: record_type.to_string(),
    content: ip.clone(),
    proxied: false,
    ttl: crate::world::effective_dns_ttl(&route.spec, false),
    tunnel: None,
  })
}

fn remote_ref(r: &RemoteRecord) -> RemoteRef {
  RemoteRef {
    scope: r.scope.clone(),
    remote_id: r.remote_id.clone(),
    record_type: r.canonical["type"].as_str().map(str::to_string),
  }
}

type DnsRemovals<'a> =
  BTreeMap<(String, String, String), &'a db::OwnedRecord>;

fn classify_dns_records<'a>(
  records: &'a [RemoteRecord],
  account: &str,
  owner_id: &str,
  deleting_owned: &mut DnsRemovals<'_>,
) -> (Vec<&'a RemoteRecord>, Vec<&'a RemoteRecord>, bool) {
  let owner = wharf_providers::Owner {
    id: owner_id.into(),
  };
  let marker = owner.marker();
  let (mut ours, mut foreign) = (Vec::new(), Vec::new());
  let mut handover = false;
  for record in records {
    if record.marker.as_deref() == Some(marker.as_str()) {
      ours.push(record);
      continue;
    }
    let key = (
      account.to_string(),
      record.scope.clone(),
      record.remote_id.clone(),
    );
    if deleting_owned.get(&key).is_some_and(|old| {
      record.marker.as_deref()
        == Some(
          wharf_providers::Owner {
            id: old.route_id.clone(),
          }
          .marker()
          .as_str(),
        )
    }) {
      handover = true;
      deleting_owned.remove(&key);
      ours.push(record);
    } else {
      foreign.push(record);
    }
  }
  (ours, foreign, handover)
}

fn prefer_dns_record(
  records: &mut [&RemoteRecord],
  canonical: &serde_json::Value,
) {
  let target = &canonical["type"];
  if let Some((index, _)) =
    records.iter().enumerate().max_by_key(|(index, r)| {
      let same_type = &r.canonical["type"] == target;
      let same_content =
        same_type && r.canonical["content"] == canonical["content"];
      (same_content, same_type, std::cmp::Reverse(*index))
    })
  {
    records.swap(0, index);
  }
}

/// 要写 DNS 的域名、记录所有者，Pages 域名还带上边缘应用。
type DnsTarget<'a> =
  (String, String, Option<(&'a str, &'a EdgeAppSpec)>);

fn retiring_ports(
  snap: &Snapshot,
  current: &World,
  desired: &World,
) -> BTreeMap<String, BTreeMap<u16, String>> {
  let mut reserved = BTreeMap::<String, BTreeMap<u16, String>>::new();
  for (name, old) in &current.services {
    let server =
      running_on(snap, current, name).unwrap_or(&old.spec.server);
    for (port, host) in &old.host_ports {
      if desired.services.get(name).is_none_or(|new| {
        new.spec.server != server
          || !new.spec.ports.iter().any(|p| {
            p.name == *port && p.host.unwrap_or(*host) == *host
          })
      }) {
        reserved
          .entry(server.to_string())
          .or_default()
          .insert(*host, name.clone());
      }
    }
  }
  reserved
}

/// 这次改动会让 DNS 期望值变化的域名：新增或改了的路由、指向变了的路由、改了的 Pages。
fn affected_hosts(
  snap: &Snapshot,
  current: &World,
  before_net: &Net,
  desired: &World,
  net: &Net,
) -> BTreeSet<String> {
  let mut out: BTreeSet<String> = desired
    .routes
    .iter()
    .filter(|(host, r)| {
      current.routes.get(*host).is_none_or(|c| c != *r)
        || desired_record(snap, current, before_net, host).ok()
          != desired_record(snap, desired, net, host).ok()
    })
    .map(|(h, _)| h.clone())
    .collect();
  for (name, app) in &desired.edge_apps {
    if current
      .edge_apps
      .get(name)
      .is_none_or(|c| c.spec != app.spec)
    {
      out.extend(app.spec.domains.iter().cloned());
    }
  }
  out
}

pub(crate) async fn plan_dns_for_hosts(
  snap: &Snapshot,
  hosts: &BTreeSet<String>,
  target: Option<&str>,
) -> Vec<(String, Result<Option<StepPlan>, ApiError>)> {
  let net = snap.net(&snap.world);
  futures_util::future::join_all(hosts.iter().map(|host| {
    let net = &net;
    async move {
      let result = async {
        if snap.account_for(host).is_none() {
          return Err(ApiError::invalid(format!(
            "没有厂商账号管理 {host} 的 DNS"
          )));
        }
        if desired_record_at(snap, &snap.world, net, host, target)?
          .content
          == TUNNEL_PENDING
        {
          return Err(
            ApiError::new(
              ErrorCode::PlanStale,
              format!("{host} 的目标隧道尚未就绪"),
            )
            .suggest("wharf plan"),
          );
        }
        let mut b = Builder::default();
        let hosts = BTreeSet::from([host.clone()]);
        dns_items(
          &mut b,
          snap,
          &snap.world,
          net,
          Some(&hosts),
          false,
          target,
        )
        .await?;
        if b.items.iter().any(|item| item.action == Action::Adopt) {
          return Err(
            ApiError::invalid(format!(
              "{host} 的 DNS 需要先确认接管"
            ))
            .suggest("wharf plan"),
          );
        }
        Ok(b.steps.pop().map(|mut step| {
          step.items.clear();
          step
        }))
      }
      .await;
      (host.clone(), result)
    }
  }))
  .await
}

fn dns_endpoint_changed(
  existing: &serde_json::Value,
  desired: &serde_json::Value,
) -> bool {
  ["type", "content", "proxied"]
    .iter()
    .any(|field| existing[*field] != desired[*field])
}

async fn dns_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  scope: Option<&BTreeSet<String>>,
  include_cleanup: bool,
  target_gateway: Option<&str>,
) -> Result<(), ApiError> {
  let in_scope = |h: &str| scope.is_none_or(|s| s.contains(h));
  let edge_ids: Vec<String> = desired
    .edge_apps
    .values()
    .flat_map(|a| {
      a.spec.domains.iter().map(|d| crate::world::edge_owner(d))
    })
    .collect();
  let live_ids: BTreeSet<&str> = desired
    .routes
    .values()
    .map(|r| r.id.as_str())
    .chain(edge_ids.iter().map(String::as_str))
    .collect();
  let mut deleting_owned: DnsRemovals<'_> = snap
    .owned
    .iter()
    .filter(|owned| {
      include_cleanup && !live_ids.contains(owned.route_id.as_str())
    })
    .map(|owned| {
      (
        (
          owned.account.clone(),
          owned.scope.clone(),
          owned.remote_id.clone(),
        ),
        owned,
      )
    })
    .collect();

  for (host, route) in &desired.routes {
    if !in_scope(host) {
      continue;
    }
    for warning in plaintext_hop(desired, net, &route.spec) {
      b.warnings.push(format!("路由 {host}：{warning}"));
    }
  }

  // 代理路由，加上 Pages 的自定义域名；Workers 的由厂商连同 DNS 一起管，见 edge_plan。
  let mut targets: Vec<DnsTarget> = desired
    .routes
    .iter()
    .filter(|(host, _)| in_scope(host))
    .map(|(host, r)| (host.clone(), r.id.clone(), None))
    .collect();
  for (name, app) in &desired.edge_apps {
    if app.spec.kind != EdgeKind::Pages {
      continue;
    }
    for d in app.spec.domains.iter().filter(|d| in_scope(d)) {
      targets.push((
        d.clone(),
        crate::world::edge_owner(d),
        Some((name.as_str(), &app.spec)),
      ));
    }
  }
  // 各域名的 DNS 记录并发读取：从国内逐个请求厂商 API 很慢。
  let mut fetched: BTreeMap<
    String,
    Result<Vec<RemoteRecord>, ApiError>,
  > = futures_util::future::join_all(targets.iter().filter_map(
    |(host, _, _)| {
      let (account, _) = snap.account_for(host)?;
      let provider = snapshot::dns_provider(account).ok()?;
      Some(async move {
        let records = snapshot::with_timeout(
          &format!("读取 {host} 的 DNS 记录"),
          provider.list(host),
        )
        .await;
        (host.clone(), records)
      })
    },
  ))
  .await
  .into_iter()
  .collect();
  for (host, owner_id, edge) in targets {
    let host = &host;
    let Some((account, _zone)) = snap.account_for(host) else {
      b.warnings.push(format!(
        "没有厂商账号管理 {host} 所在的域名，DNS 需要自己配置（或执行 wharf account add）"
      ));
      continue;
    };
    let spec = match edge {
      Some((name, app)) => {
        crate::edge_plan::pages_record(snap, name, app).await?
      }
      None => {
        desired_record_at(snap, desired, net, host, target_gateway)?
      }
    };
    let provider = snapshot::dns_provider(account)?;
    let want = spec.to_provider();
    if spec.content != TUNNEL_PENDING {
      provider
        .validate(host, &want)
        .map_err(snapshot::provider_error)?;
    }
    let records = match fetched.remove(host) {
      Some(records) => records?,
      None => {
        snapshot::with_timeout(
          &format!("读取 {host} 的 DNS 记录"),
          provider.list(host),
        )
        .await?
      }
    };
    let (mut ours, foreign, handover) = classify_dns_records(
      &records,
      &account.name,
      &owner_id,
      &mut deleting_owned,
    );
    let gateway_changed = target_gateway.is_none()
      && snap.world.routes.get(host).is_some_and(|old| {
        desired.routes.get(host).is_some_and(|new| {
          snap.world.live_gateway(host, &old.spec)
            != desired.live_gateway(host, &new.spec)
        })
      });
    let canonical = want.canonical();
    let address = format!("{KIND_ROUTE}/{host}");
    let after = Some(canonical.clone());
    let upsert = |existing: Option<&RemoteRecord>,
                  extra: Vec<RemoteRef>,
                  verify_target: bool| {
      Step::DnsUpsert {
        hostname: host.clone(),
        account: account.name.clone(),
        spec: spec.clone(),
        existing: existing.map(remote_ref),
        extra,
        expected_gateway: target_gateway
          .or_else(|| {
            desired
              .routes
              .get(host)
              .and_then(|r| desired.live_gateway(host, &r.spec))
          })
          .map(str::to_string),
        verify_target,
      }
    };
    let title = format!("写入 {host} 的 DNS 记录");
    if !foreign.is_empty() {
      let mut targets: Vec<&RemoteRecord> = ours.clone();
      targets.extend(foreign.iter().copied());
      prefer_dns_record(&mut targets, &canonical);
      let existing = targets[0];
      let extra =
        targets[1..].iter().map(|r| remote_ref(r)).collect();
      let id = b.item(
        address,
        Layer::Dns,
        Action::Adopt,
        Some(json!(
          foreign
            .iter()
            .map(|r| r.canonical.clone())
            .collect::<Vec<_>>()
        )),
        after,
        vec![Impact::Overwrite],
        format!(
          "{host} 已有 {} 条不是 Wharf 创建的记录，接管会覆盖{}",
          foreign.len(),
          if targets.len() > 1 {
            "并删除多余记录"
          } else {
            ""
          }
        ),
      );
      b.step(vec![id], title, upsert(Some(existing), extra, true));
      continue;
    }
    prefer_dns_record(&mut ours, &canonical);
    match ours.as_slice() {
      [] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Create,
          None,
          after,
          if edge.is_some() {
            vec![Impact::Public]
          } else {
            vec![]
          },
          if edge.is_some() {
            "新增边缘应用自定义域名的公网 DNS 记录".into()
          } else {
            format!("新建 {} 记录", spec.record_type)
          },
        );
        b.step(vec![id], title, upsert(None, vec![], true));
      }
      [only]
        if !handover
          && !gateway_changed
          && only.canonical == canonical => {}
      [first, rest @ ..] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Update,
          Some(first.canonical.clone()),
          after,
          vec![Impact::Restart],
          if handover {
            "移交 DNS 记录归属并更新内容".to_string()
          } else if first.canonical == canonical {
            "删除重复的记录".to_string()
          } else {
            "记录内容变化".to_string()
          },
        );
        let extra = rest.iter().map(|r| remote_ref(r)).collect();
        let verify_target =
          dns_endpoint_changed(&first.canonical, &canonical)
            || handover
            || gateway_changed;
        b.step(
          vec![id],
          title,
          upsert(Some(first), extra, verify_target),
        );
      }
    }
  }
  // 已删除路由留下的记录。
  for owned in deleting_owned.values() {
    let id = b.item(
      format!("{KIND_ROUTE}/{}", owned.hostname),
      Layer::Dns,
      Action::Delete,
      Some(json!({ "account": owned.account, "remote_id": owned.remote_id })),
      None,
      vec![Impact::Remove],
      "删除路由留下的 DNS 记录",
    );
    b.step(
      vec![id],
      format!("删除 {} 的 DNS 记录", owned.hostname),
      Step::DnsDelete {
        hostname: owned.hostname.clone(),
        account: owned.account.clone(),
        remote: RemoteRef {
          scope: owned.scope.clone(),
          remote_id: owned.remote_id.clone(),
          record_type: None,
        },
        owner: Some(owned.route_id.clone()),
      },
    );
  }

  Ok(())
}

/// 保存计划。
pub async fn save(
  state: &AppState,
  planned: &Planned,
) -> Result<(), ApiError> {
  let id = planned.plan.plan_id.clone();
  let mut body =
    serde_json::to_value(&planned.plan).map_err(db::json_err)?;
  body["base_instances"] = json!(&planned.base_instances);
  let dns_gateways: BTreeMap<_, _> = planned
    .steps
    .iter()
    .filter_map(|s| match &s.step {
      Step::DnsUpsert {
        hostname,
        expected_gateway: Some(gateway),
        ..
      } => Some((hostname, gateway)),
      _ => None,
    })
    .collect();
  body["dns_gateways"] = json!(dns_gateways);
  body["account_refs"] = json!(&planned.account_refs);
  body["host_access_checked"] = json!(true);
  body["host_requirements"] = json!(&planned.host_requirements);
  if !planned.route_effects.is_empty() {
    body["route_effects"] = json!(&planned.route_effects);
  }
  let body = body.to_string();
  let steps =
    serde_json::to_string(&planned.steps).map_err(db::json_err)?;
  let writes =
    serde_json::to_string(&planned.writes).map_err(db::json_err)?;
  let created = planned.plan.created_at.timestamp_millis();
  let expires = planned.plan.expires_at.timestamp_millis();
  state
    .db
    .call(move |c| {
      // 只保留最近的计划。
      c.execute(
        "DELETE FROM plans WHERE created_at < ?1",
        rusqlite::params![db::now_ms() - 7 * 24 * 3600 * 1000],
      )
      .map_err(db::sql_err)?;
      c.execute(
        "INSERT INTO plans (id, status, body, steps, writes, created_at, expires_at)
         VALUES (?1, 'pending', ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, body, steps, writes, created, expires],
      )
      .map_err(db::sql_err)?;
      Ok(())
    })
    .await
}

/// 网关跨机器访问服务、而服务所在机器的内网地址不加密时，返回提醒。
fn plaintext_hop(
  world: &World,
  net: &Net,
  route: &RouteSpec,
) -> Vec<String> {
  let Some(service) = world.services.get(&route.service) else {
    return vec![];
  };
  let server = &service.spec.server;
  let Some(addr) =
    net.private.get(server).filter(|a| !a.network.encrypted())
  else {
    return vec![];
  };
  let Some(port) =
    world.route_port(route).filter(|_| route.upstream.is_none())
  else {
    return vec![];
  };
  world
    .route_gateways(route)
    .into_iter()
    .filter_map(|name| {
      let gateway = &world.gateways.get(name)?.spec;
      let choice = crate::link::choose(
        world,
        net,
        gateway,
        &route.service,
        port,
        route.link,
      )
      .ok()?;
      matches!(choice, crate::link::Choice::Direct(_)).then(|| {
        format!(
          "网关（{}）到服务（{server}）这一段走内网直连 {}，是明文",
          gateway.server, addr.ip
        )
      })
    })
    .collect()
}

#[cfg(test)]
mod tests {
  #[tokio::test]
  async fn rollback_warning_skips_offline_server_and_new_gateway() {
    use wharf_api_types::spec::Change;

    let state = crate::rules::tests::test_state();
    let mut world = world();
    let gateway = Change::UpsertGateway {
      name: "edge".into(),
      spec: serde_json::from_value(
        json!({"kind":"caddy","server":"s1","tls":"off"}),
      )
      .unwrap(),
    };
    let spec = serde_json::from_value(json!({
      "server": "s1",
      "source": {"compose": {"content": format!(
        "services: {{app: {{image: 'app@sha256:{}'}}}}", "a".repeat(64)
      )}}
    }))
    .unwrap();
    let service = Change::UpsertService {
      name: "app".into(),
      spec,
      adopt: None,
      pins: None,
      commit: None,
    };
    let warning = crate::apply::safe_rollback_warning("s1");
    let planned = make_plan_inner(
      &state,
      PlanRequest {
        changes: vec![service, gateway.clone()],
        ..Default::default()
      },
      Snapshot {
        world: world.clone(),
        ..Default::default()
      },
      false,
      true,
    )
    .await
    .unwrap();
    assert!(
      planned
        .steps
        .iter()
        .any(|s| matches!(s.step, Step::ServiceUp { .. }))
    );
    assert!(
      planned
        .steps
        .iter()
        .any(|s| matches!(s.step, Step::GatewaySync { .. }))
    );
    assert!(!planned.plan.warnings.contains(&warning));

    world.services.clear();
    state.hub.mock_agent("s1", false, |op| match op {
      wharf_api_types::agent::AgentOp::ProjectStatus { .. } => {
        Ok(json!([]))
      }
      _ => panic!("意外的 agent 请求"),
    });
    let planned = make_plan_inner(
      &state,
      PlanRequest {
        changes: vec![gateway],
        ..Default::default()
      },
      Snapshot {
        world,
        ..Default::default()
      },
      false,
      true,
    )
    .await
    .unwrap();
    assert!(planned.plan.items.iter().any(|i| i.layer
      == Layer::Gateway
      && i.action == Action::Create));
    assert!(!planned.plan.warnings.contains(&warning));
  }

  #[test]
  fn explicit_rollback_from_empty_pins_reports_version_switch() {
    let current = world();
    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .pins
      .insert("nginx:1".into(), format!("sha256:{}", "a".repeat(64)));
    let writes = desired.writes_from(&current);
    let hash = hash_of(&current);
    let mut b = Builder {
      explicit_pins: BTreeSet::from(["app".into()]),
      ..Default::default()
    };
    config_items(&mut b, &current, &desired, &writes);
    service_items(
      &mut b,
      &Snapshot {
        world: current.clone(),
        applied: BTreeMap::from([(
          "app".into(),
          serde_json::from_value(json!({
            "hash": hash, "at": "2026-11-28T00:00:00Z",
            "image": "nginx:1", "image_id": "old-image"
          }))
          .unwrap(),
        )]),
        ..Default::default()
      },
      &current,
      &desired,
      &Net::default(),
      &live(Some(hash), vec![container("running")]),
      &writes,
    )
    .unwrap();
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::ServiceUp { .. }))
    );
    let config =
      b.items.iter().find(|i| i.layer == Layer::Config).unwrap();
    assert_eq!(config.reason, "切换固定镜像版本");
  }

  #[tokio::test]
  async fn plan_stops_and_updates_monitoring_with_legacy_jsonc() {
    let state = crate::rules::tests::test_state();
    let mut world = world();
    let app = world.services.get_mut("app").unwrap();
    app.pins.insert("nginx:1".into(), "sha256:fixture".into());
    app.spec.files = serde_json::from_value(json!([
      {"path":"/etc/app/config.json", "content":"{ // legacy\n\"value\": 1}"}
    ])).unwrap();
    let hash = hash_of(&world);
    state.hub.mock_agent("s1", false, move |op| match op {
      wharf_api_types::agent::AgentOp::ProjectStatus { .. } => Ok(json!([
        {"project":"app", "hash":hash, "containers":[container("running")]}
      ])),
      _ => panic!("意外的 agent 请求"),
    });
    let current = world.services["app"].spec.clone();
    let mut monitored = current.clone();
    monitored.log_alerts =
      serde_json::from_value(json!([{"pattern": "fixture-error"}]))
        .unwrap();
    for (spec, stop) in [
      (monitored, false),
      (
        wharf_api_types::spec::ServiceSpec {
          stopped: true,
          ..current
        },
        true,
      ),
    ] {
      let planned = make_plan_inner(
        &state,
        PlanRequest {
          changes: vec![
            wharf_api_types::spec::Change::UpsertService {
              pins: None,
              commit: None,
              name: "app".into(),
              spec,
              adopt: None,
            },
          ],
          ..Default::default()
        },
        Snapshot {
          world: world.clone(),
          ..Default::default()
        },
        false,
        true,
      )
      .await
      .unwrap();
      if stop {
        assert!(planned.steps.iter().any(|entry| matches!(
          entry.step,
          Step::ServiceStop { .. }
        )));
      } else {
        assert!(planned.steps.is_empty());
        assert_eq!(planned.plan.items[0].layer, Layer::Config);
      }
    }
  }

  #[tokio::test]
  async fn plan_rejects_broken_config_file_with_zero_side_effects() {
    let state = crate::rules::tests::test_state();
    let mut world = world();
    let app = world.services.get_mut("app").unwrap();
    app.pins.insert("nginx:1".into(), "sha256:fixture".into());
    app.spec.files = serde_json::from_value(json!([
      {"path":"/etc/app/config.json", "content":"{\"value\":\"[[S]]\"}"}
    ])).unwrap();
    let mut other = app.clone();
    other.instance_id = "svc_other".into();
    other.spec.files.clear();
    other.host_ports.insert("http".into(), 21001);
    world.services.insert("other".into(), other);
    let snap = |secret: &str| Snapshot {
      world: world.clone(),
      secrets: BTreeMap::from([("S".into(), secret.into())]),
      ..Default::default()
    };
    let hash = snapshot::service_resolved(
      &world,
      &Net::default(),
      "app",
      &snap("fixture\"value").render_values(&world, "app"),
    )
    .unwrap()
    .1;
    state.hub.mock_agent("s1", false, move |op| match op {
      wharf_api_types::agent::AgentOp::ProjectStatus { .. } => Ok(json!([
        {"project":"app", "hash":hash, "containers":[container("running")]}
      ])),
      _ => panic!("意外的 agent 请求"),
    });
    let spec = |name: &str, item| PlanRequest {
      changes: vec![wharf_api_types::spec::Change::UpsertService {
        pins: None,
        commit: None,
        name: name.into(),
        spec: item,
        adopt: None,
      }],
      ..Default::default()
    };
    let mut changed = world.services["app"].spec.clone();
    changed.env.insert("MODE".into(), "changed".into());
    let err = make_plan_inner(
      &state,
      spec("app", changed.clone()),
      snap("fixture\"value"),
      false,
      true,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.code, wharf_api_types::ErrorCode::InvalidInput);
    assert!(err.message.contains("/etc/app/config.json"));
    assert!(!err.message.contains("fixture"));
    let mut other = world.services["other"].spec.clone();
    other.env.insert("MODE".into(), "changed".into());
    let unrelated = make_plan_inner(
      &state,
      spec("other", other),
      snap("fixture\"value"),
      false,
      true,
    )
    .await
    .unwrap();
    assert!(
      unrelated
        .plan
        .items
        .iter()
        .all(|item| item.address != "service/app")
    );
    let drift = make_plan_inner(
      &state,
      PlanRequest::default(),
      snap("rotated\"value"),
      false,
      true,
    )
    .await
    .err()
    .unwrap();
    assert!(drift.message.contains("/etc/app/config.json"));
    changed.files[0].raw = true;
    assert!(
      make_plan_inner(
        &state,
        spec("app", changed),
        snap("fixture\"value"),
        false,
        true
      )
      .await
      .is_ok()
    );
    let count = state
      .db
      .call(|c| {
        c.query_row("SELECT COUNT(*) FROM plans", [], |r| {
          r.get::<_, i64>(0)
        })
        .map_err(db::sql_err)
      })
      .await
      .unwrap();
    assert_eq!(count, 0);
  }

  use super::*;

  #[tokio::test]
  async fn edge_plan_pins_commit_without_changing_configured_ref() {
    let state = crate::rules::tests::test_state();
    let sha = "0123456789012345678901234567890123456789";
    state.hub.mock_agent("s1", false, move |op| {
      let wharf_api_types::agent::AgentOp::ResolveCommit(job) = op else {
        panic!("只应查询 commit");
      };
      assert!(matches!(job.fetch, wharf_api_types::agent::BuildFetch::Git { reference, .. } if reference == "prod"));
      Ok(json!(sha))
    });
    state.hub.enable_mock_build_v2("s1");
    let mut current = world();
    let edge: EdgeAppSpec = serde_json::from_value(json!({
      "account":"edge", "kind":"pages", "builder":"s1",
      "source":{"git":{"repo":"https://example.test/site", "ref":"prod"}}
    })).unwrap();
    current.edge_apps.insert(
      "site".into(),
      crate::world::EdgeRow {
        spec: edge,
        version: 1,
      },
    );
    let mut desired = current.clone();
    desired
      .edge_apps
      .get_mut("site")
      .unwrap()
      .spec
      .source
      .as_mut()
      .unwrap()
      .build = Some("npm run build".into());
    let snap = Snapshot {
      world: current.clone(),
      ..Default::default()
    };
    let mut b = Builder::default();
    crate::edge_plan::edge_items(
      &state, &mut b, &snap, &current, &desired,
    )
    .await
    .unwrap();
    assert_eq!(
      b.items[0].after.as_ref().unwrap()["commit"],
      &sha[..12]
    );
    assert!(
      matches!(&b.steps[0].step, Step::EdgeDeploy { commit: Some(commit), .. } if commit == sha)
    );
    let git = desired.edge_apps["site"]
      .spec
      .source
      .as_ref()
      .unwrap()
      .git
      .as_ref()
      .unwrap();
    assert_eq!(git.reference, "prod");
    let fetch = crate::build::code_fetch(
      &state,
      &BTreeMap::new(),
      "边缘应用 site",
      None,
      Some(git),
      Some(sha.into()),
    )
    .unwrap();
    assert!(
      matches!(fetch, wharf_api_types::agent::BuildFetch::Git { reference, fallback_ref: Some(fallback), .. } if reference == sha && fallback == "prod")
    );
    let old: Step = serde_json::from_value(
      json!({"kind":"edge_deploy", "app":"site"}),
    )
    .unwrap();
    assert!(matches!(old, Step::EdgeDeploy { commit: None, .. }));
  }

  use crate::world::{RouteRow, ServerRow, ServiceRow};
  use wharf_api_types::{agent::ContainerInfo, spec::Limits};

  #[test]
  fn same_name_compose_import_has_no_config_restart_impact() {
    let current = world();
    let mut desired = current.clone();
    desired.services.get_mut("app").unwrap().import =
      crate::import::from_compose(
        "services: {web: {image: nginx:1}}",
        &[wharf_api_types::agent::ProjectContainerRaw {
          inspect: json!({
            "Config": {"Labels": {"com.docker.compose.service": "web"}},
            "State": {"Running": true}
          }),
          image_inspect: None,
          tag_image_id: None,
        }],
        "app",
        "app",
      )
      .unwrap()
      .adopt;
    let mut before = current;
    before.services.clear();
    let mut b = Builder::default();
    config_items(
      &mut b,
      &before,
      &desired,
      &desired.writes_from(&before),
    );
    let [item] = b.items.as_slice() else {
      panic!("expected one config item");
    };
    assert!(item.impacts.is_empty());
    assert!(item.reason.contains("沿用同名 compose 项目"));
  }

  fn gateway_fixture(
    kind: &str,
    server: &str,
  ) -> crate::world::GatewayRow {
    crate::world::GatewayRow {
      spec: serde_json::from_value(json!({
        "kind": kind, "server": server, "account": "cf1"
      }))
      .unwrap(),
      version: 1,
    }
  }

  fn route_fixture() -> RouteRow {
    RouteRow {
      id: "rt_fixture".into(),
      spec: serde_json::from_value(json!({
        "hostname": "a.example.com", "service": "app", "gateway": "edge"
      })).unwrap(),
      version: 1,
    }
  }

  #[test]
  fn ttl_only_keeps_default_dns_verification_off() {
    let existing =
      wharf_providers::dns_canonical("A", "203.0.113.1", 60, false);
    let ttl =
      wharf_providers::dns_canonical("A", "203.0.113.1", 120, false);
    let ip =
      wharf_providers::dns_canonical("A", "203.0.113.2", 120, false);
    assert!(!dns_endpoint_changed(&existing, &ttl));
    assert!(dns_endpoint_changed(&existing, &ip));
  }

  #[test]
  fn server_ip_change_affects_dns_and_respects_ttl() {
    let mut current = world();
    current
      .gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    current
      .routes
      .insert("a.example.com".into(), route_fixture());
    current.servers.get_mut("s1").unwrap().settings.public_ip =
      Some("203.0.113.10".into());
    let mut desired = current.clone();
    desired.servers.get_mut("s1").unwrap().settings.public_ip =
      Some("203.0.113.20".into());
    let snap = Snapshot::default();
    let before = snap.net(&current);
    let after = snap.net(&desired);
    let host = "a.example.com";
    assert!(
      affected_hosts(&snap, &current, &before, &desired, &after)
        .contains(host)
    );
    let dns = |w: &World| {
      desired_record(&snap, w, &after, host)
        .unwrap()
        .to_provider()
    };
    assert_eq!(dns(&desired).content, "203.0.113.20");
    assert_eq!(dns(&desired).ttl, 1);
    desired.routes.get_mut(host).unwrap().spec.backup_gateway =
      Some("backup".into());
    assert_eq!(dns(&desired).ttl, 60);
    desired.routes.get_mut(host).unwrap().spec.dns_ttl = Some(120);
    assert_eq!(dns(&desired).canonical()["ttl"], 120);
    desired.routes.get_mut(host).unwrap().spec.dns_ttl = Some(1);
    assert_eq!(dns(&desired).ttl, 1);
  }

  #[test]
  fn ownership_handover_consumes_old_dns_deletion_in_both_directions()
  {
    for (old, new) in [
      ("rt_fixture", "edge:a.example.com"),
      ("edge:a.example.com", "rt_fixture"),
    ] {
      let key =
        ("cf".to_string(), "zone".to_string(), "R1".to_string());
      let owned = db::OwnedRecord {
        route_id: old.into(),
        hostname: "a.example.com".into(),
        account: key.0.clone(),
        scope: key.1.clone(),
        remote_id: key.2.clone(),
      };
      let records = [RemoteRecord {
        remote_id: key.2.clone(),
        scope: key.1.clone(),
        canonical: json!({"type":"A"}),
        marker: Some(format!("wharf:{old}")),
      }];
      let mut deleting = DnsRemovals::from([(key, &owned)]);
      let (ours, foreign, handover) =
        classify_dns_records(&records, "cf", new, &mut deleting);
      assert_eq!(ours[0].remote_id, "R1");
      assert!(handover && deleting.is_empty() && foreign.is_empty());
    }
  }

  #[test]
  fn old_gateway_site_is_removed_after_dns() {
    let host = "a.example.com";
    let mut current = world();
    current
      .gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    current
      .gateways
      .insert("edge2".into(), gateway_fixture("caddy", "s1"));
    current.gateways.get_mut("edge2").unwrap().spec.http_port =
      Some(8080);
    current.routes.insert(host.into(), route_fixture());
    let mut desired = current.clone();
    desired.routes.get_mut(host).unwrap().spec.gateway =
      Some("edge2".into());
    let snap = Snapshot {
      world: current.clone(),
      ..Default::default()
    };
    let net = snap.net(&current);
    let before =
      snapshot::gateway_render(&current, &net, "edge").unwrap();
    let running: ProjectState = serde_json::from_value(json!({
      "project": "wharf-gw-edge",
      "hash": before.compose_hash,
      "config_hash": before.config_hash,
      "containers": [{"service":"caddy","name":"edge-1","state":"running"}]
    })).unwrap();
    let status = StatusMap::from([(
      "s1".into(),
      Some(BTreeMap::from([(running.project.clone(), running)])),
    )]);
    let mut b = Builder::default();
    gateway_items(
      &mut b,
      &snap,
      (&current, &net),
      (&desired, &net),
      &status,
      &crate::hub::Hub::default(),
    )
    .unwrap();
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::GatewaySync { gateway, after_dns: true, .. } if gateway == "edge")));
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::GatewaySync { gateway, after_dns: false, .. } if gateway == "edge2")));
  }

  #[test]
  fn gateway_move_and_account_change_cleanup_is_resumable() {
    let mut current = world();
    current.gateways.insert(
      "edge".into(),
      gateway_fixture("cloudflare_tunnel", "s1"),
    );
    current
      .gateways
      .insert("http".into(), gateway_fixture("caddy", "s1"));
    current
      .routes
      .insert("a.example.com".into(), route_fixture());
    let mut desired = current.clone();
    for row in desired.gateways.values_mut() {
      row.spec.server = "s2".into();
    }
    desired.services.get_mut("app").unwrap().spec.server =
      "s2".into();
    desired.gateways.get_mut("edge").unwrap().spec.account =
      Some("cf2".into());
    let mut snap = Snapshot::default();
    snap.accounts.push(db::AccountRow {
      name: "cf1".into(),
      kind: "cloudflare".into(),
      token: String::new(),
      zones: vec!["example.com".into()],
      warnings: vec![],
      updated_at: 0,
    });
    snap.tunnels.insert(
      "edge".into(),
      db::TunnelRow {
        account: "cf1".into(),
        scope: "scope".into(),
        tunnel_id: "old".into(),
        config_hash: "old".into(),
      },
    );
    let net = Net::default();
    let before =
      desired_record(&snap, &current, &net, "a.example.com").unwrap();
    let after =
      desired_record(&snap, &desired, &net, "a.example.com").unwrap();
    assert_eq!(before.content, "old.cfargotunnel.com");
    assert_eq!(after.content, TUNNEL_PENDING);
    let status =
      StatusMap::from([("s1".into(), Some(BTreeMap::new()))]);
    let mut b = Builder::default();
    gateway_items(
      &mut b,
      &snap,
      (&current, &net),
      (&desired, &net),
      &status,
      &crate::hub::Hub::default(),
    )
    .unwrap();
    for name in ["edge", "http"] {
      assert!(b.steps.iter().any(|s| matches!(&s.step,
        Step::GatewayDown { server, gateway, keep_tunnel: true } if server == "s1" && gateway == name
      ) && s.step.order() == 7));
    }
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::GatewaySync { gateway, .. } if gateway == "edge") && s.step.order() == 4));
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::TunnelDelete { account, tunnel_id, .. } if account == "cf1" && tunnel_id == "old")));
    snap.pending.gateway_downs.push(
      crate::pending::GatewayDownPayload {
        gateway: "edge".into(),
        server: "s1".into(),
        keep_tunnel: true,
      },
    );
    snap.pending.tunnel_deletes.push(
      crate::pending::TunnelDeletePayload {
        gateway: "edge".into(),
        account: "cf1".into(),
        scope: "scope".into(),
        tunnel_id: "old".into(),
      },
    );
    let tunnel = snap.tunnels.get_mut("edge").unwrap();
    tunnel.account = "cf2".into();
    tunnel.tunnel_id = "new".into();
    tunnel.config_hash.clear();
    let mut b = Builder::default();
    gateway_items(
      &mut b,
      &snap,
      (&desired, &net),
      (&desired, &net),
      &status,
      &crate::hub::Hub::default(),
    )
    .unwrap();
    assert!(b.steps.iter().any(|s| matches!(
      s.step,
      Step::GatewayDown {
        keep_tunnel: true,
        ..
      }
    )));
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::GatewaySync { gateway, .. } if gateway == "edge")));
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::TunnelDelete { tunnel_id, .. } if tunnel_id == "old")));
  }

  fn applied_gateway(
    rendered: snapshot::GatewayRender,
  ) -> ProjectState {
    ProjectState {
      project: gateway_project("edge"),
      hash: Some(rendered.compose_hash),
      config_hash: Some(rendered.config_hash),
      acme_dns_url_hash: None,
      containers: vec![container("running")],
    }
  }

  #[test]
  fn restored_gate_core_reach_plans_reload_and_marks_drift() {
    let mut snap = Snapshot {
      world: world(),
      ..Default::default()
    };
    snap
      .world
      .gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    let mut route = route_fixture();
    route.spec.sso =
      Some(serde_json::from_value(json!({"mode":"gate"})).unwrap());
    snap.world.routes.insert("a.example.com".into(), route);
    let world = &snap.world;
    let mut net = Net {
      core_server: Some("s2".into()),
      core_listener: Some((7700, false)),
      gate_login: Some("https://core.example.net".into()),
      gate_public: Some("public".into()),
      ..Default::default()
    };
    net.private.insert(
      "s2".into(),
      serde_json::from_value(json!({
        "ip":"100.64.0.2", "network":"tailscale"
      }))
      .unwrap(),
    );
    let project = gateway_project("edge");
    let applied = applied_gateway(
      snapshot::gateway_render(world, &net, "edge").unwrap(),
    );
    let states = BTreeMap::from([(project, applied)]);
    let status =
      StatusMap::from([("s1".into(), Some(states.clone()))]);
    let live = BTreeMap::from([("s1".into(), Ok(states))]);
    let before = net.clone();
    for reachable in [false, true] {
      net.reach.insert(("s1".into(), "s2".into()), reachable);
      let mut b = Builder::default();
      gateway_items(
        &mut b,
        &snap,
        (world, &before),
        (world, &net),
        &status,
        &crate::hub::Hub::default(),
      )
      .unwrap();
      assert_eq!(b.steps.len(), usize::from(reachable));
      let view =
        crate::views::gateway_view(&snap, &net, "edge", Some(&live))
          .unwrap();
      assert_eq!(view.live.unwrap().in_sync, Some(!reachable));
    }
  }

  #[test]
  fn dns_prefers_existing_target_address_over_provider_order() {
    let canonical =
      json!({"type":"A", "content":"203.0.113.10", "ttl":60});
    let records = [
      RemoteRecord {
        remote_id: "R1".into(),
        scope: "zone".into(),
        canonical: json!({"type":"AAAA", "content":"2001:db8::1"}),
        marker: None,
      },
      RemoteRecord {
        remote_id: "R2".into(),
        scope: "zone".into(),
        canonical: json!({"type":"A", "content":"203.0.113.10", "ttl":1}),
        marker: None,
      },
    ];
    let mut targets: Vec<_> = records.iter().collect();
    prefer_dns_record(&mut targets, &canonical);
    assert_eq!(targets[0].remote_id, "R2");
    assert_eq!(targets[1].remote_id, "R1");
  }

  #[tokio::test]
  async fn unready_tunnel_is_rescheduled_and_cannot_receive_dns() {
    let mut snap = Snapshot {
      world: world(),
      ..Default::default()
    };
    snap.world.gateways.insert(
      "edge".into(),
      gateway_fixture("cloudflare_tunnel", "s1"),
    );
    let host = "a.example.com";
    snap.world.routes.insert(host.into(), route_fixture());
    snap.accounts.push(db::AccountRow {
      name: "cf1".into(),
      kind: "cloudflare".into(),
      token: String::new(),
      zones: vec!["example.com".into()],
      warnings: vec![],
      updated_at: 0,
    });
    snap.tunnels.insert(
      "edge".into(),
      db::TunnelRow {
        account: "cf1".into(),
        scope: "zone".into(),
        tunnel_id: "new".into(),
        config_hash: String::new(),
      },
    );
    let world = &snap.world;
    let net = Net::default();
    let mut b = Builder::default();
    gateway_items(
      &mut b,
      &snap,
      (world, &net),
      (world, &net),
      &StatusMap::new(),
      &crate::hub::Hub::default(),
    )
    .unwrap();
    assert!(
      matches!(&b.steps[0].step, Step::GatewaySync { gateway, .. } if gateway == "edge")
    );
    let dns = desired_record(&snap, world, &net, host).unwrap();
    assert_eq!(dns.content, TUNNEL_PENDING);
    assert_eq!(
      crate::apply::resolve_dns_tunnel(&snap, &dns)
        .unwrap_err()
        .code,
      ErrorCode::PlanStale
    );
    let plans =
      plan_dns_for_hosts(&snap, &BTreeSet::from([host.into()]), None)
        .await;
    assert_eq!(
      plans[0].1.as_ref().unwrap_err().code,
      ErrorCode::PlanStale
    );
    snap.tunnels.get_mut("edge").unwrap().config_hash =
      "ready".into();
    assert_eq!(
      crate::apply::resolve_dns_tunnel(&snap, &dns)
        .unwrap()
        .content,
      "new.cfargotunnel.com"
    );
  }

  #[test]
  fn own_route_change_can_reload_legacy_dns_gateway() {
    let mut current = world();
    let mut edge = gateway_fixture("caddy", "s1");
    edge.spec.wildcard.push("example.com".into());
    current.gateways.insert("edge".into(), edge);
    let host = "a.example.com";
    current.routes.insert(host.into(), route_fixture());
    let applied = applied_gateway(
      snapshot::gateway_render(&current, &Net::default(), "edge")
        .unwrap(),
    );
    let mut desired = current.clone();
    desired.routes.remove(host);
    let net = Net {
      acme_dns_url: Some("https://core.example.net".into()),
      ..Default::default()
    };
    let mut b = Builder::default();
    config_items(
      &mut b,
      &current,
      &desired,
      &[Write::Delete {
        kind: KIND_ROUTE.into(),
        name: host.into(),
      }],
    );
    let status = StatusMap::from([(
      "s1".into(),
      Some(BTreeMap::from([(applied.project.clone(), applied)])),
    )]);
    let snap = Snapshot {
      accounts: vec![db::AccountRow {
        name: "cf1".into(),
        kind: "cloudflare".into(),
        token: String::new(),
        zones: vec!["example.com".into()],
        warnings: vec![],
        updated_at: 0,
      }],
      ..Default::default()
    };
    gateway_items(
      &mut b,
      &snap,
      (&current, &net),
      (&desired, &net),
      &status,
      &crate::hub::Hub::default(),
    )
    .unwrap();
    let item = b
      .items
      .iter()
      .find(|item| item.layer == Layer::Gateway)
      .unwrap();
    assert_eq!(b.route_effects[&item.id], [format!("route/{host}")]);
  }

  #[test]
  fn external_dns_keeps_old_tunnel_on_account_change() {
    let mut current = world();
    current.gateways.insert(
      "edge".into(),
      gateway_fixture("cloudflare_tunnel", "s1"),
    );
    current
      .gateways
      .insert("backup".into(), gateway_fixture("caddy", "s2"));
    let mut route = route_fixture();
    route.spec.gateway = Some("backup".into());
    route.spec.backup_gateway = Some("edge".into());
    current.routes.insert("external.example.net".into(), route);
    let mut desired = current.clone();
    desired.gateways.get_mut("edge").unwrap().spec.account =
      Some("cf2".into());
    let mut snap = Snapshot::default();
    snap.tunnels.insert(
      "edge".into(),
      db::TunnelRow {
        account: "cf1".into(),
        scope: "zone".into(),
        tunnel_id: "old".into(),
        config_hash: "ready".into(),
      },
    );
    let mut b = Builder::default();
    gateway_cleanup_items(
      &mut b,
      &snap,
      &current,
      &desired,
      &StatusMap::new(),
    );
    assert!(b.steps.is_empty());
    assert!(b.warnings[0].contains("外部管理"));
  }

  #[test]
  fn deleted_server_does_not_block_pending_tunnel_cleanup() {
    let mut snap = Snapshot::default();
    snap.pending.gateway_downs.push(
      crate::pending::GatewayDownPayload {
        gateway: "edge".into(),
        server: "s1".into(),
        keep_tunnel: false,
      },
    );
    snap.tunnels.insert(
      "edge".into(),
      db::TunnelRow {
        account: "cf1".into(),
        scope: "zone".into(),
        tunnel_id: "old".into(),
        config_hash: "ready".into(),
      },
    );
    let world = &snap.world;
    let mut b = Builder::default();
    gateway_cleanup_items(
      &mut b,
      &snap,
      world,
      world,
      &StatusMap::new(),
    );
    assert!(
      matches!(&b.steps[0].step, Step::GatewayDown { gateway, server, keep_tunnel: false } if gateway == "edge" && server == "s1")
    );
  }

  #[tokio::test]
  async fn old_agent_callback_probe_keeps_unchanged_gateway_and_detects_url_change()
   {
    use wharf_api_types::agent::{AgentOp, TaskHow};
    let state = crate::rules::tests::test_state();
    let mut world = world();
    let mut edge = gateway_fixture("caddy", "s1");
    edge.spec.wildcard.push("example.com".into());
    world.gateways.insert("edge".into(), edge);
    let snap = Snapshot::default();
    let mut net = Net::default();
    let applied = applied_gateway(
      snapshot::gateway_render(&world, &net, "edge").unwrap(),
    );
    let url = "https://old.example.net";
    state.hub.mock_agent("s1", false, move |op| {
      Ok(match op {
        AgentOp::ProjectStatus { .. } => json!([applied]),
        AgentOp::TaskRun(task) => {
          assert!(matches!(task.how, TaskHow::Exec { project, service: Some(service), .. } if project == "wharf-gw-edge" && service == "caddy"));
          json!({"output":format!("{}  -", crate::render::hash(&format!("{url}/agent/acme-dns"))), "exit_code":0, "timed_out":false, "duration_ms":0})
        }
        _ => panic!("计划期发了意外请求"),
      })
    });
    for (url, changes) in [(url, 0), ("https://new.example.net", 1)] {
      net.acme_dns_url = Some(url.into());
      let mut b = Builder::default();
      let status = gather_status(
        &state,
        &snap,
        (&world, &net),
        (&world, &net),
        &mut b,
      )
      .await;
      gateway_items(
        &mut b,
        &snap,
        (&world, &net),
        (&world, &net),
        &status,
        &state.hub,
      )
      .unwrap();
      assert_eq!(b.steps.len(), changes);
    }
  }

  #[test]
  fn stateless_migration_up_done_still_cleans_source_after_gateway() {
    let mut snap = Snapshot {
      world: world(),
      ..Snapshot::default()
    };
    snap.world.services.get_mut("app").unwrap().spec.server =
      "s2".into();
    snap.deployed.insert("app".into(), "s2".into());
    snap.pending.migrations.insert(
      "app".into(),
      crate::pending::Migration {
        phase: crate::pending::MigratePhase::UpDone,
        payload: serde_json::from_value(
          json!({"service":"app","from":"s1","to":"s2"}),
        )
        .unwrap(),
      },
    );
    let mut b = Builder::default();
    service_items(
      &mut b,
      &snap,
      &snap.world,
      &snap.world,
      &Net::default(),
      &StatusMap::new(),
      &[],
    )
    .unwrap();
    let down = b.steps.iter().find(|s| matches!(&s.step,
      Step::ServiceDown { server, purge_data: false, .. } if server == "s1"
    )).unwrap();
    assert!(
      down.step.order()
        > Step::GatewaySync {
          gateway: "edge".into(),
          after_dns: false,
          expect: None
        }
        .order()
    );
  }

  #[tokio::test]
  async fn existing_frpc_migrates_only_with_an_actual_change() {
    let mut current = world();
    current.servers.insert(
      "s2".into(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    current
      .gateways
      .insert("edge".into(), gateway_fixture("caddy", "s2"));
    let mut route = route_fixture();
    route.spec.link = wharf_api_types::spec::LinkMode::Tunnel;
    current.routes.insert("a.example.com".into(), route.clone());
    let net = Net {
      public_ip: BTreeMap::from([(
        "s2".into(),
        "203.0.113.2".into(),
      )]),
      ..Default::default()
    };
    let project = "wharf-link-s2";
    let running = |hot| {
      let rendered = crate::link::projects_for_servers(
        &current,
        &net,
        &BTreeMap::new(),
        |_| hot,
      )
      .unwrap()
      .into_iter()
      .find(|p| p.project == project)
      .unwrap();
      StatusMap::from([(
        "s1".into(),
        Some(BTreeMap::from([(
          project.into(),
          ProjectState {
            project: project.into(),
            hash: Some(rendered.hash),
            config_hash: rendered.reload.map(|r| r.config_hash),
            acme_dns_url_hash: None,
            containers: vec![container("running")],
          },
        )])),
      )])
    };
    let hub = crate::hub::Hub::default();
    hub.mock_agent("s1", false, |_| panic!("计划不可下发操作"));
    hub.enable_mock_failover_features("s1");
    let snap = Snapshot {
      world: current.clone(),
      ..Default::default()
    };
    let mut b = Builder::default();
    link_items(
      &mut b,
      &snap,
      &current,
      (&net, &net),
      &running(false),
      &hub,
    )
    .unwrap();
    assert!(b.steps.is_empty());

    let mut desired = current.clone();
    let mut service = desired.services["app"].clone();
    service.host_ports.insert("http".into(), 21001);
    desired.services.insert("app2".into(), service);
    route.spec.hostname = "b.example.com".into();
    route.spec.service = "app2".into();
    desired.routes.insert(route.spec.hostname.clone(), route);
    for already_migrated in [false, true] {
      let mut b = Builder::default();
      link_items(
        &mut b,
        &snap,
        &desired,
        (&net, &net),
        &running(already_migrated),
        &hub,
      )
      .unwrap();
      assert!(matches!(
        b.steps[0].step,
        Step::LinkUp {
          hot_reload: true,
          ..
        }
      ));
      assert_eq!(
        b.items[0].impacts.contains(&Impact::Restart),
        !already_migrated
      );
      assert!(
        !b.items[0]
          .after
          .as_ref()
          .unwrap()
          .to_string()
          .contains("webServer")
      );
    }
  }

  #[test]
  fn live_status_finds_unused_link_projects() {
    let world = world();
    let old = |project: &str| ProjectState {
      project: project.into(),
      hash: Some("existing".into()),
      config_hash: None,
      acme_dns_url_hash: None,
      containers: vec![],
    };
    let status = StatusMap::from([
      (
        "s1".into(),
        Some(BTreeMap::from([(
          "wharf-link".into(),
          old("wharf-link"),
        )])),
      ),
      (
        "s2".into(),
        Some(BTreeMap::from([(
          "wharf-link-s1".into(),
          old("wharf-link-s1"),
        )])),
      ),
    ]);
    let mut b = Builder::default();
    link_items(
      &mut b,
      &Snapshot::default(),
      &world,
      (&Net::default(), &Net::default()),
      &status,
      &crate::hub::Hub::default(),
    )
    .unwrap();
    assert_eq!(
      b.steps
        .into_iter()
        .map(|s| match s.step {
          Step::LinkDown { server, project } => (server, project),
          _ => panic!("应当清理旧隧道"),
        })
        .collect::<Vec<_>>(),
      [
        ("s1".into(), "wharf-link".into()),
        ("s2".into(), "wharf-link-s1".into())
      ]
    );
  }

  #[test]
  fn replacing_service_reserves_ports_until_the_old_one_stops() {
    let snap = Snapshot::default();
    let mut old = world();
    old
      .services
      .get_mut("app")
      .unwrap()
      .host_ports
      .insert("http".into(), 20000);
    let mut new = old.clone();
    let mut row = new.services.remove("app").unwrap();
    row.host_ports.clear();
    new.services.insert("next".into(), row);
    let reserved = retiring_ports(&snap, &old, &new);
    new.allocate_ports_with(&reserved).unwrap();
    assert_eq!(new.services["next"].host_ports["http"], 20001);
    new.services.get_mut("next").unwrap().spec.ports[0].host =
      Some(20000);
    assert!(
      new
        .allocate_ports_with(&reserved)
        .unwrap_err()
        .message
        .contains("仍被")
    );
  }

  #[tokio::test]
  async fn stale_dns_after_failover_rolls_back_apply_transaction() {
    let state = crate::rules::tests::test_state();
    let mut w = world();
    w.servers.insert("s2".into(), w.servers["s1"].clone());
    w.gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    w.gateways
      .insert("backup".into(), gateway_fixture("caddy", "s2"));
    let host = "dns-stale.example.test";
    let mut route = route_fixture();
    route.spec.hostname = host.into();
    route.spec.backup_gateway = Some("backup".into());
    w.routes.insert(host.into(), route);
    let seed = w.writes_from(&World::default());
    state
      .db
      .call(move |c| {
        for write in seed {
          db::apply_write(c, &write)?;
        }
        Ok(())
      })
      .await
      .unwrap();
    let snap = snapshot::load(&state.db).await.unwrap();
    let mut desired = snap.world.clone();
    desired.routes.get_mut(host).unwrap().spec.dns_ttl = Some(120);
    let mut b = Builder::default();
    b.step(
      vec![],
      "更新 DNS",
      Step::DnsUpsert {
        hostname: host.into(),
        account: "cf".into(),
        spec: DnsSpec {
          record_type: "A".into(),
          content: "203.0.113.1".into(),
          proxied: false,
          ttl: 120,
          tunnel: None,
        },
        existing: None,
        extra: vec![],
        expected_gateway: Some("edge".into()),
        verify_target: false,
      },
    );
    let p = finish_plan(
      &snap,
      &desired,
      b,
      desired.writes_from(&snap.world),
      BTreeSet::new(),
      None,
    );
    save(&state, &p).await.unwrap();
    state
      .db
      .call(move |c| {
        db::set_setting(
          c,
          "failover.active",
          Some(&json!([host]).to_string()),
        )
      })
      .await
      .unwrap();
    let err = crate::apply::start(
      state.clone(),
      wharf_api_types::plan::ApplyRequest {
        plan_id: p.plan.plan_id,
        confirm: vec![],
        verify_before_dns: None,
        skip_snapshot: false,
      },
      &wharf_api_types::view::Perm::ALL.into_iter().collect(),
      None,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.code, wharf_api_types::ErrorCode::PlanStale);
    assert!(
      snapshot::load(&state.db).await.unwrap().world.routes[host]
        .spec
        .dns_ttl
        .is_none()
    );
    let err = crate::apply::run_step(
      &state,
      "r1",
      &p.steps[0].step,
      std::sync::Arc::new(|_| {}),
      &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, wharf_api_types::ErrorCode::PlanStale);
  }

  #[test]
  fn lan_warning_checks_backup_gateway() {
    let mut w = world();
    w.gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    w.gateways
      .insert("backup".into(), gateway_fixture("caddy", "s2"));
    let mut route = route_fixture();
    route.spec.backup_gateway = Some("backup".into());
    let mut net = Net::default();
    net.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "100.64.0.1".into(),
        network: wharf_api_types::spec::PrivateNetwork::Lan,
      },
    );
    net.reach.insert(("s2".into(), "s1".into()), true);
    let warnings = plaintext_hop(&w, &net, &route.spec);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("s2"));
  }

  #[test]
  fn backup_gateway_validates_paths_and_ttl() {
    let mut w = world();
    w.servers.insert("s2".into(), w.servers["s1"].clone());
    w.gateways
      .insert("edge".into(), gateway_fixture("caddy", "s1"));
    w.gateways.insert(
      "backup".into(),
      gateway_fixture("cloudflare_tunnel", "s2"),
    );
    let mut route = route_fixture();
    route.spec.backup_gateway = Some("backup".into());
    route.spec.paths = serde_json::from_value(
      json!([{"path":"/api","upstream":"127.0.0.1:7701"}]),
    )
    .unwrap();
    w.routes.insert("a.example.com".into(), route);
    assert!(w.validate().unwrap_err().message.contains("按路径转发"));
    let spec = &mut w.routes.get_mut("a.example.com").unwrap().spec;
    spec.paths.clear();
    spec.dns_ttl = Some(30);
    assert!(w.validate().unwrap_err().message.contains("dns_ttl"));
    let spec = &mut w.routes.get_mut("a.example.com").unwrap().spec;
    spec.dns_ttl = Some(120);
    spec.backup_gateway = None;
    spec.gateway = Some("backup".into());
    assert!(w.validate().unwrap_err().message.contains("TTL 固定"));
  }

  #[test]
  fn internal_route_points_to_private_ip() {
    let snap = Snapshot::default();
    let mut w = world();
    w.gateways.insert(
      "edge".into(),
      crate::world::GatewayRow {
        spec: serde_json::from_value(
          json!({"kind":"caddy", "server":"s1"}),
        )
        .unwrap(),
        version: 1,
      },
    );
    w.routes.insert("i.example.com".into(), crate::world::RouteRow {
      id:"r1".into(), spec:serde_json::from_value(json!({"hostname":"i.example.com", "service":"app", "gateway":"edge"})).unwrap(), version:1,
    });
    let mut net = Net::default();
    net.public_ip.insert("s1".into(), "203.0.113.1".into());
    net.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "100.64.0.1".into(),
        network: wharf_api_types::spec::PrivateNetwork::Tailscale,
      },
    );
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap()
        .content,
      "203.0.113.1"
    );
    w.routes.get_mut("i.example.com").unwrap().spec.internal = true;
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap()
        .content,
      "100.64.0.1"
    );
    net.private.clear();
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap_err()
        .message,
      "路由 i.example.com 只在内网访问，但入口 edge 所在的 s1 没有内网地址"
    );
  }

  #[test]
  fn names_only_changed_components() {
    let old = "services:\n  web:\n    image: a\n  worker:\n    image: w:1\n  db:\n    image: pg\n";
    let new = "services:\n  web:\n    image: a\n  worker:\n    image: w:2\n  db:\n    image: pg\n";
    let (redo, keep) = changed_components(old, new).unwrap();
    assert_eq!(redo, vec!["worker"]);
    assert_eq!(keep, vec!["db", "web"]);
    assert!(changed_components(new, new).is_none());
  }

  #[test]
  fn cleans_up_unfinished_deletes() {
    let deployed = BTreeMap::from([
      ("half".to_string(), "s1".to_string()),
      ("done".to_string(), "s1".to_string()),
    ]);
    let state = |hash: Option<&str>| ProjectState {
      project: String::new(),
      hash: hash.map(str::to_string),
      config_hash: None,
      acme_dns_url_hash: None,
      containers: vec![],
    };
    let status = StatusMap::from([(
      "s1".to_string(),
      Some(BTreeMap::from([
        ("half".to_string(), state(Some("h"))),
        // 删干净了，或者是别人同名的项目：没有 Wharf 的指纹。
        ("done".to_string(), state(None)),
      ])),
    )]);
    let world = World::default();
    let mut b = Builder::default();
    let snap = Snapshot {
      deployed,
      ..Default::default()
    };
    leftover_items(&mut b, &snap, &world, &world, &status);
    let found: Vec<&str> =
      b.items.iter().map(|i| i.address.as_str()).collect();
    assert_eq!(found, ["service/half"]);
    assert!(b.items[0].needs_confirm());
  }

  #[tokio::test]
  async fn move_plan_warns_and_requires_confirm_for_image_anonymous_volume()
   {
    let state = crate::migrate::tests::seed_service(false).await;
    let mut snap = snapshot::load(&state.db).await.unwrap();
    snap
      .world
      .services
      .get_mut("notes")
      .unwrap()
      .spec
      .volumes
      .clear();
    use wharf_api_types::{agent::AgentOp, spec::Change};
    state.hub.mock_agent("s1", false, |op| {
      Ok(match op {
        AgentOp::ResolveImages(_) => json!([{"image": "fixture:1", "digest": format!("sha256:{}", "a".repeat(64))}]),
        AgentOp::ProjectStatus { .. } => json!([]),
        _ => panic!("计划期发了意外请求"),
      })
    });
    state.hub.mock_safe_migrate_agent("s2", |op, _| {
      Some(Ok(match op {
        AgentOp::ProjectStatus { .. } => json!([]),
        AgentOp::ProjectMounts { projects } => {
          assert_eq!(projects, ["notes"]);
          json!({"notes": [{"container": "notes-db-1", "service": "db",
            "kind": "volume", "source": "a".repeat(64), "target": "/var/lib/db"}]})
        }
        _ => panic!("计划期发了意外请求"),
      }))
    });
    let mut spec = snap.world.services["notes"].spec.clone();
    spec.server = "s1".into();
    let before = state
      .db
      .call(|c| {
        c.query_row("SELECT total_changes()", [], |r| {
          r.get::<_, i64>(0)
        })
        .map_err(db::sql_err)
      })
      .await
      .unwrap();
    let p = make_plan_inner(
      &state,
      PlanRequest {
        changes: vec![Change::UpsertService {
          pins: None,
          commit: None,
          name: "notes".into(),
          spec,
          adopt: None,
        }],
        ..PlanRequest::default()
      },
      snap,
      false,
      true,
    )
    .await
    .unwrap();
    assert_eq!(p.plan.needs_confirm, ["service/notes"]);
    assert!(
      p.plan
        .items
        .iter()
        .any(|item| item.impacts.contains(&Impact::DataLoss)
          && item.reason.contains("/var/lib/db"))
    );
    let after = state
      .db
      .call(|c| {
        c.query_row("SELECT total_changes()", [], |r| {
          r.get::<_, i64>(0)
        })
        .map_err(db::sql_err)
      })
      .await
      .unwrap();
    assert_eq!(before, after);
  }

  #[tokio::test]
  async fn failed_docker_proxy_egress_baseline_and_dirs_replanned() {
    let state = crate::migrate::tests::seed_service(false).await;
    let mut snap = snapshot::load(&state.db).await.unwrap();
    snap
      .world
      .servers
      .get_mut("s2")
      .unwrap()
      .settings
      .baseline
      .timezone = Some("Etc/UTC".into());
    for pending in [
      &mut snap.pending.docker_proxies,
      &mut snap.pending.egresses,
      &mut snap.pending.baselines,
    ] {
      pending.insert("s2".into());
    }
    snap.pending.ensure_dirs.insert(
      "notes@s2".into(),
      crate::pending::EnsureDirsPayload {
        service: "notes".into(),
        server: "s2".into(),
        dirs: vec!["/srv/notes/data".into()],
        instance_id: None,
      },
    );
    let world = &snap.world;
    let mut b = Builder::default();
    egress_items(&mut b, &snap, world, world);
    baseline_items(&mut b, &snap, world, world);
    docker_proxy_items(&mut b, &snap, world, world);
    service_items(
      &mut b,
      &snap,
      world,
      world,
      &Net::default(),
      &StatusMap::new(),
      &[],
    )
    .unwrap();
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::Egress { .. }))
    );
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::DockerProxy { .. }))
    );
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::Baseline { .. }))
    );
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::EnsureDirs { .. }))
    );
  }

  #[tokio::test]
  async fn abort_migration_skips_reverse_sync_and_cleans_target() {
    let state = crate::migrate::tests::seed_service(false).await;
    crate::migrate::tests::seed_migration(&state, "synced", true)
      .await;
    let snap = snapshot::load(&state.db).await.unwrap();
    let mut desired = snap.world.clone();
    desired.services.get_mut("notes").unwrap().spec.server =
      "s1".into();
    let status = StatusMap::from([(
      "s2".into(),
      Some(BTreeMap::from([(
        "notes".into(),
        ProjectState {
          project: "notes".into(),
          hash: Some("partial".into()),
          config_hash: None,
          acme_dns_url_hash: None,
          containers: vec![],
        },
      )])),
    )]);
    let mut b = Builder::default();
    service_items(
      &mut b,
      &snap,
      &snap.world,
      &desired,
      &Net::default(),
      &status,
      &[],
    )
    .unwrap();
    assert!(
      !b.steps
        .iter()
        .any(|s| matches!(s.step, Step::VolumeSync { .. }))
    );
    assert!(b.steps.iter().any(|s| matches!(&s.step, Step::ServiceDown { server, purge_data: false, .. } if server == "s2")));
    assert!(
      b.steps
        .iter()
        .any(|s| matches!(s.step, Step::ServiceUp { .. }))
    );
  }

  #[tokio::test]
  async fn plan_keeps_confirmed_non_purge_delete() {
    let state = crate::rules::tests::test_state();
    state
      .db
      .call(|c| {
        crate::pending::put_delete(
          c,
          ("", ""),
          &crate::pending::ServiceDeletePayload {
            service: "s1".into(),
            server: "s1".into(),
            instance_id: "svc_old".into(),
            purge_data: false,
            has_relative_mounts: true,
          },
        )
      })
      .await
      .unwrap();
    state.hub.mock_agent("s1", false, |op| match op {
      wharf_api_types::agent::AgentOp::ProjectStatus {
        projects,
        ..
      } => {
        assert_eq!(projects, ["s1"]);
        Ok(json!([{"project": "s1", "containers": []}]))
      }
      _ => panic!("意外的 agent 请求"),
    });
    let planned =
      make_plan(&state, PlanRequest::default()).await.unwrap();
    assert!(planned.plan.items.is_empty());
    assert!(planned.plan.warnings.is_empty());
    assert_eq!(
      state
        .db
        .call(|c| Ok(crate::pending::load(c)?.service_deletes.len()))
        .await
        .unwrap(),
      1
    );
  }

  #[test]
  fn delete_after_failed_move_targets_running_server() {
    let mut current = world();
    current.services.get_mut("app").unwrap().spec.server =
      "s2".into();
    let mut desired = current.clone();
    desired.services.clear();
    let snap = Snapshot {
      deployed: BTreeMap::from([("app".into(), "s1".into())]),
      ..Default::default()
    };
    let mut b = Builder {
      purge_data: BTreeSet::from(["app".into()]),
      ..Default::default()
    };
    service_items(
      &mut b,
      &snap,
      &current,
      &desired,
      &Net::default(),
      &StatusMap::new(),
      &desired.writes_from(&current),
    )
    .unwrap();
    let targets: Vec<_> = b
      .steps
      .iter()
      .filter_map(|step| match &step.step {
        Step::ServiceDown {
          server,
          purge_data: true,
          ..
        } => Some(server.as_str()),
        _ => None,
      })
      .collect();
    assert_eq!(targets, ["s1", "s2"]);
  }

  #[test]
  fn leftover_plan_preserves_purge_data_and_drops_on_recreate() {
    let snap = Snapshot {
      pending: crate::pending::PendingState {
        service_deletes: vec![crate::pending::ServiceDeletePayload {
          service: "app".into(),
          server: "s1".into(),
          instance_id: "svc_aaa".into(),
          purge_data: true,
          has_relative_mounts: true,
        }],
        ..Default::default()
      },
      ..Default::default()
    };
    let current = World::default();
    let status =
      StatusMap::from([("s1".into(), Some(BTreeMap::new()))]);
    let mut b = Builder::default();
    leftover_items(&mut b, &snap, &current, &current, &status);
    let planned =
      finish_plan(&snap, &current, b, vec![], BTreeSet::new(), None);
    assert_eq!(planned.plan.needs_confirm, ["service/app"]);
    assert!(matches!(&planned.steps[0].step, Step::ServiceDown {
      instance_id: Some(id), purge_data: true, has_relative_mounts: true, ..
    } if id == "svc_aaa"));
    let mut recreated = Builder::default();
    leftover_items(
      &mut recreated,
      &snap,
      &current,
      &world(),
      &status,
    );
    assert!(recreated.steps.is_empty());
    assert!(recreated.warnings[0].contains("新建同名服务"));
  }

  /// 一台 s1，一个 image 服务 app（nginx:1，端口 80）。
  fn world() -> World {
    let spec = serde_json::from_value(json!({
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
        host_ports: BTreeMap::from([("http".to_string(), 21000)]),
        import: None,
        pins: BTreeMap::new(),
        commit: None,
        version: 1,
      },
    );
    world
  }

  fn container(state: &str) -> ContainerInfo {
    ContainerInfo {
      service: "app".into(),
      name: "app-app-1".into(),
      state: state.into(),
      status: String::new(),
      health: None,
      image: String::new(),
      foreign: false,
      working_dir: None,
      finished_at: None,
      exit_code: None,
      restart_policy: None,
    }
  }

  /// s1 上 app 的现状。`hash` 为 None 表示不是 Wharf 部署的。
  fn live(
    hash: Option<String>,
    containers: Vec<ContainerInfo>,
  ) -> StatusMap {
    StatusMap::from([(
      "s1".to_string(),
      Some(BTreeMap::from([(
        "app".to_string(),
        ProjectState {
          project: "app".into(),
          hash,
          config_hash: None,
          acme_dns_url_hash: None,
          containers,
        },
      )])),
    )])
  }

  fn hash_of(w: &World) -> String {
    snapshot::service_resolved(
      w,
      &Net::default(),
      "app",
      &BTreeMap::new(),
    )
    .unwrap()
    .1
  }

  /// 跑一次 service_items，返回生成的计划项。
  fn plan(
    current: &World,
    desired: &World,
    status: &StatusMap,
  ) -> Builder {
    let mut b = Builder::default();
    let writes = desired.writes_from(current);
    service_items(
      &mut b,
      &Snapshot {
        world: current.clone(),
        ..Snapshot::default()
      },
      current,
      desired,
      &Net::default(),
      status,
      &writes,
    )
    .unwrap();
    b
  }

  #[test]
  fn stop_plans_for_restarting_container() {
    let mut world = world();
    world.services.get_mut("app").unwrap().spec.stopped = true;
    let b = plan(
      &world,
      &world,
      &live(Some(hash_of(&world)), vec![container("restarting")]),
    );
    assert!(matches!(b.steps[0].step, Step::ServiceStop { .. }));
    assert!(b.items[0].reason.contains("反复重启"));
  }

  #[test]
  fn missing_component_plans_up() {
    let mut world = world();
    let spec = &mut world.services.get_mut("app").unwrap().spec;
    spec.ports.clear();
    spec.source = Source::Compose {
      content: Some("services:\n  app: {image: fixture:1}\n  worker: {image: fixture:1}\n  init: {image: fixture:1, restart: \"no\"}\n".into()),
      file: None,
    };
    let b = plan(
      &world,
      &world,
      &live(Some(hash_of(&world)), vec![container("running")]),
    );
    assert!(matches!(b.steps[0].step, Step::ServiceUp { .. }));
    assert!(b.items[0].reason.contains("缺少组件 worker"));
    let worker = ContainerInfo {
      service: "worker".into(),
      ..container("running")
    };
    let complete =
      live(Some(hash_of(&world)), vec![container("running"), worker]);
    assert!(plan(&world, &world, &complete).items.is_empty());
  }

  #[test]
  fn no_change_no_item() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some(hash_of(&w)), vec![container("running")]),
    );
    assert!(b.items.is_empty());
  }

  #[test]
  fn new_service_creates() {
    let desired = world();
    let mut current = desired.clone();
    current.services.clear();
    let status =
      StatusMap::from([("s1".into(), Some(BTreeMap::new()))]);
    let b = plan(&current, &desired, &status);
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Create);
    assert!(b.items[0].impacts.is_empty());
    assert!(b.items[0].reason.contains("部署新服务"));
  }

  #[tokio::test]
  async fn rotating_file_and_encoded_secret_only_restarts_its_service()
   {
    let db = crate::db::Db::memory();
    let (old, new) = db
      .call_credentials(|c, key| {
        key.put_secret(c, "K1", "fixture-initial", 1, false)?;
        let old = crate::db::secrets(c, key)?;
        key.rotate_secret(
          c,
          "K1",
          "fixture-changed",
          2,
          Some(3),
          false,
        )?;
        Ok((old, crate::db::secrets(c, key)?))
      })
      .await
      .unwrap();
    let mut w = world();
    let idle = w.services["app"].clone();
    w.services.insert("idle".into(), idle);
    w.services.get_mut("app").unwrap().spec.env.extend([
      ("TOKEN".into(), "[[url:K1]]".into()),
      ("TOKEN_FILE".into(), "[[FILE:K1]]".into()),
    ]);
    let net = Net::default();
    let hash = |name| {
      snapshot::service_resolved(&w, &net, name, &old).unwrap().1
    };
    let mut status =
      live(Some(hash("app")), vec![container("running")]);
    status.get_mut("s1").unwrap().as_mut().unwrap().insert(
      "idle".into(),
      ProjectState {
        project: "idle".into(),
        hash: Some(hash("idle")),
        config_hash: None,
        acme_dns_url_hash: None,
        containers: vec![ContainerInfo {
          service: "idle".into(),
          ..container("running")
        }],
      },
    );
    for (secrets, expected) in
      [(old, vec![]), (new, vec!["service/app"])]
    {
      let mut builder = Builder::default();
      service_items(
        &mut builder,
        &Snapshot {
          world: w.clone(),
          secrets,
          ..Snapshot::default()
        },
        &w,
        &w,
        &net,
        &status,
        &[],
      )
      .unwrap();
      assert_eq!(
        builder
          .items
          .iter()
          .map(|item| item.address.as_str())
          .collect::<Vec<_>>(),
        expected
      );
    }
  }

  #[tokio::test]
  async fn basic_auth_rotation_and_rollback_restore_gateway_fingerprint()
   {
    let mut w = world();
    w.gateways.insert(
      "edge".into(),
      crate::world::GatewayRow {
        spec: serde_json::from_value(
          json!({"kind":"caddy","server":"s1","tls":"off"}),
        )
        .unwrap(),
        version: 1,
      },
    );
    w.routes.insert("a.example.test".into(), RouteRow {
      id: "r1".into(),
      spec: serde_json::from_value(json!({"hostname":"a.example.test","service":"app","gateway":"edge","auth":true})).unwrap(),
      version: 1,
    });
    let name = crate::render::route_auth_secret("a.example.test");
    let db = crate::db::Db::memory();
    let values = db
      .call_credentials(move |c, key| {
        let old = crate::render::BasicAuth::hash_input(
          "u1:fixture-original",
        )?;
        let new =
          crate::render::BasicAuth::hash_input("u1:fixture-changed")?;
        key.put_secret(c, &name, &old, 1, false)?;
        key.rotate_secret(c, &name, &new, 2, Some(10), false)?;
        key.rollback_secret(c, &name, 3)?;
        let actual = key.secret(c, &name)?.unwrap();
        assert!(actual == old);
        assert!(crate::db::previous_secrets(c, key, 3)?.is_empty());
        Ok((name, old, new, actual))
      })
      .await
      .unwrap();
    let net = |value: &str| {
      let mut net = Net::default();
      net.public_ip.insert("s1".into(), "203.0.113.1".into());
      net.basic_auth.insert(
        values.0.clone(),
        crate::render::BasicAuth::parse(value).unwrap(),
      );
      net
    };
    let before =
      snapshot::gateway_render(&w, &net(&values.1), "edge").unwrap();
    let project = gateway_project("edge");
    let status = StatusMap::from([(
      "s1".into(),
      Some(BTreeMap::from([(
        project.clone(),
        ProjectState {
          project,
          hash: Some(before.compose_hash),
          config_hash: Some(before.config_hash),
          acme_dns_url_hash: None,
          containers: vec![container("running")],
        },
      )])),
    )]);
    for (value, expected_steps) in [(&values.2, 1), (&values.3, 0)] {
      let mut builder = Builder::default();
      gateway_items(
        &mut builder,
        &Snapshot::default(),
        (&w, &net(&values.1)),
        (&w, &net(value)),
        &status,
        &crate::hub::Hub::default(),
      )
      .unwrap();
      assert_eq!(builder.steps.len(), expected_steps);
      for step in &builder.steps {
        assert!(
          matches!(&step.step, Step::GatewaySync { gateway, .. } if gateway == "edge")
        );
        assert!(builder.items[0].impacts.is_empty());
      }
    }
  }

  #[test]
  fn config_change_restarts() {
    let current = world();
    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&current)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("配置变化"));
  }

  #[test]
  fn plan_warns_only_for_service_being_redeployed() {
    let mut current = world();
    let changed_password = concat!("fixture", "-changed");
    let idle_password = concat!("fixture", "-idle");
    let app = current.services.get_mut("app").unwrap();
    app
      .spec
      .env
      .insert("DB_PASSWORD".into(), changed_password.into());
    let mut idle = app.clone();
    idle.host_ports.insert("http".into(), 21001);
    idle
      .spec
      .env
      .insert("DB_PASSWORD".into(), idle_password.into());
    current.services.insert("idle".into(), idle);

    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let mut status =
      live(Some(hash_of(&current)), vec![container("running")]);
    let (_, idle_hash) = snapshot::service_resolved(
      &current,
      &Net::default(),
      "idle",
      &BTreeMap::new(),
    )
    .unwrap();
    status.get_mut("s1").unwrap().as_mut().unwrap().insert(
      "idle".into(),
      ProjectState {
        project: "idle".into(),
        hash: Some(idle_hash),
        config_hash: None,
        acme_dns_url_hash: None,
        containers: vec![ContainerInfo {
          service: "idle".into(),
          ..container("running")
        }],
      },
    );
    let b = plan(&current, &desired, &status);
    let snap = Snapshot {
      world: current,
      ..Snapshot::default()
    };
    let planned =
      finish_plan(&snap, &desired, b, vec![], BTreeSet::new(), None);
    assert_eq!(planned.plan.items.len(), 1);
    assert_eq!(planned.plan.warnings.len(), 1);
    let warning = &planned.plan.warnings[0];
    assert!(warning.contains("服务 app 的 env 变量 DB_PASSWORD"));
    assert!(!warning.contains("服务 idle"));
    assert!(
      !warning.contains(changed_password)
        && !warning.contains(idle_password)
    );
  }

  #[test]
  fn drift_redeploys() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some("old".into()), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("漂移"));
  }

  #[test]
  fn changing_start_timeout_retries_failed_service_without_rebuilding_healthy_one()
   {
    let current = world();
    let mut desired = current.clone();
    let row = desired.services.get_mut("app").unwrap();
    row.spec.start_timeout_secs = Some(300);
    assert!(!crate::service_monitor::config_only(
      &current.services["app"],
      row
    ));

    let hash = hash_of(&current);
    assert_eq!(hash, hash_of(&desired));
    let failed = live(Some(hash.clone()), vec![container("exited")]);
    assert!(plan(&current, &desired, &failed).steps.iter()
      .any(|entry| matches!(&entry.step, Step::ServiceUp { service, .. } if service == "app")));
    let healthy = live(Some(hash), vec![container("running")]);
    assert!(plan(&current, &desired, &healthy).steps.is_empty());
  }

  #[test]
  fn stopped_container_is_drift() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some(hash_of(&w)), vec![container("exited")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("容器没在运行"));
  }

  #[test]
  fn stop_keeps_containers() {
    let current = world();
    let mut desired = current.clone();
    desired.services.get_mut("app").unwrap().spec.stopped = true;
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&desired)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Downtime]);
    assert!(b.items[0].reason.contains("停止服务"));
    assert!(matches!(b.steps[0].step, Step::ServiceStop { .. }));
  }

  #[test]
  fn unreachable_server() {
    let current = world();
    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let status = StatusMap::from([("s1".into(), None)]);
    let b = plan(&current, &desired, &status);
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("无法读取现状"));
    assert!(plan(&current, &current, &status).items.is_empty());
  }

  #[test]
  fn foreign_project_overwrites() {
    let desired = world();
    let mut current = desired.clone();
    current.services.clear();
    let b = plan(
      &current,
      &desired,
      &live(None, vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert!(b.items[0].impacts.contains(&Impact::Overwrite));
    assert!(b.items[0].needs_confirm());
  }

  #[test]
  fn foreign_container_warns() {
    let w = world();
    let mut c = container("running");
    c.foreign = true;
    let b = plan(&w, &w, &live(Some("old".into()), vec![c]));
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert!(b.items[0].impacts.contains(&Impact::Overwrite));
    assert!(b.items[0].reason.contains("会删除它们"));
  }

  #[test]
  fn remove_keeps_data() {
    let current = world();
    let mut desired = current.clone();
    desired.services.clear();
    let b = plan(&current, &desired, &StatusMap::new());
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Delete);
    assert_eq!(b.items[0].impacts, vec![Impact::Remove]);
    assert!(b.items[0].needs_confirm());
    assert!(matches!(
      b.steps[0].step,
      Step::ServiceDown {
        purge_data: false,
        ..
      }
    ));
  }

  #[test]
  fn limits_change_restarts() {
    let current = world();
    let mut desired = current.clone();
    desired.services.get_mut("app").unwrap().spec.limits =
      Some(Limits {
        memory_mb: Some(256),
        cpu_milli: None,
      });
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&current)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(hash_of(&current) != hash_of(&desired));
  }

  #[test]
  fn route_impacts() {
    let current = world();
    let mut desired = current.clone();
    desired.routes.insert(
      "a.example.com".into(),
      RouteRow {
        id: "a".into(),
        spec: serde_json::from_value(json!({
          "hostname": "a.example.com",
          "service": "app"
        }))
        .unwrap(),
        version: 1,
      },
    );
    desired.routes.insert(
      "b.example.com".into(),
      RouteRow {
        id: "b".into(),
        spec: serde_json::from_value(json!({
          "hostname": "b.example.com",
          "redirect": "https://a.example.com"
        }))
        .unwrap(),
        version: 1,
      },
    );
    let mut b = Builder::default();
    config_items(
      &mut b,
      &current,
      &desired,
      &desired.writes_from(&current),
    );
    let a = b
      .items
      .iter()
      .find(|i| i.address == "route/a.example.com")
      .unwrap();
    let redirect = b
      .items
      .iter()
      .find(|i| i.address == "route/b.example.com")
      .unwrap();
    assert!(a.impacts.contains(&Impact::Public));
    assert!(redirect.impacts.is_empty());
    assert!(redirect.reason.contains("新增跳转"));
  }
  #[test]
  fn removing_gate_requires_public_confirmation() {
    let mut current = world();
    current.routes.insert("a.example.com".into(),RouteRow{id:"a".into(),version:1,spec:serde_json::from_value(json!({"hostname":"a.example.com","service":"app","sso":{"mode":"gate"}})).unwrap()});
    let mut desired = current.clone();
    desired.routes.get_mut("a.example.com").unwrap().spec.sso = None;
    let mut b = Builder::default();
    config_items(
      &mut b,
      &current,
      &desired,
      &desired.writes_from(&current),
    );
    assert_eq!(b.items[0].impacts, vec![Impact::Public]);
    assert_eq!(b.items[0].reason, "去掉门禁后这个域名对公网开放");
  }
}
