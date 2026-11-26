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
  ApiError,
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
mod route_impact;

pub const PLAN_TTL_MINUTES: i64 = 60;
const STATUS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteRef {
  pub scope: String,
  pub remote_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSpec {
  pub record_type: String,
  pub content: String,
  pub proxied: bool,
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

impl DnsSpec {
  pub fn to_provider(&self) -> DnsRecordSpec {
    DnsRecordSpec {
      record_type: match self.record_type.as_str() {
        "AAAA" => DnsRecordType::AAAA,
        "CNAME" => DnsRecordType::CNAME,
        _ => DnsRecordType::A,
      },
      content: self.content.clone(),
      ttl: 1,
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
  },
  /// 迁移数据：先在服务运行时同步一遍，停掉旧服务器上的容器，再增量同步。
  VolumeSync {
    service: String,
    from: String,
    to: String,
  },
  ServiceUp {
    service: String,
    /// 计划时渲染出的 compose 指纹，执行前重算比对；没有这个字段的旧计划不校验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<String>,
  },
  GatewaySync {
    gateway: String,
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
  },
  GatewayDown {
    server: String,
    gateway: String,
  },
  /// 部署反向隧道的 frps 或 frpc（design 2.7.2）。
  LinkUp {
    server: String,
    project: String,
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
  },
  /// 发布边缘应用的代码。
  EdgeDeploy {
    app: String,
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
    user_key: Option<wharf_api_types::agent::OneTimeSecret>,
  },
  /// 清理服务器上没在用的镜像。单独发起，不来自计划。
  Prune {
    server: String,
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
      Self::EnsureDirs { .. } => 1,
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
      Self::GatewaySync { .. } => 4,
      Self::LinkUp { .. } => 5,
      Self::DnsUpsert { .. } | Self::EdgeAttach { .. } => 6,
      Self::GatewayDown { .. } | Self::LinkDown { .. } => 7,
      Self::ServiceDown { .. } => 8,
      Self::Backup { .. }
      | Self::Restore { .. }
      | Self::Rebuild { .. }
      | Self::AgentUpgrade { .. }
      | Self::AgentUpgrades { .. }
      | Self::Prune { .. }
      | Self::CoreBackup { .. }
      | Self::ServiceRestart { .. }
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
  pub account_refs: BTreeSet<String>,
  pub host_requirements: Vec<crate::host_access::HostRequirement>,
  pub route_effects: crate::token_scope::RouteEffects,
  pub steps: Vec<StepPlan>,
  pub writes: Vec<Write>,
}

#[derive(Default)]
pub(crate) struct Builder {
  pub(crate) items: Vec<PlanItem>,
  steps: Vec<StepPlan>,
  route_effects: crate::token_scope::RouteEffects,
  pub(crate) warnings: Vec<String>,
  /// 这次计划查到的镜像 ID：服务 → 镜像 → `sha256:…`。
  image_ids: BTreeMap<String, BTreeMap<String, String>>,
  /// 删除时连同数据一起删的服务。
  purge_data: BTreeSet<String>,
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
  desired.allocate_ports()?;
  desired.validate()?;
  crate::secret_policy::validate_accounts(
    &desired,
    &snap.account_links,
  )?;
  crate::secret_policy::require_plan_git_secrets(
    &current, &desired, admin,
  )?;
  // 只改日志、端口监控或心跳时间时，计划只写配置，离线和现存漂移都不触发部署。
  if req.changes.iter().all(|c| {
    matches!(c, wharf_api_types::spec::Change::UpsertService { .. })
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
      let mut b = Builder::default();
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
  let refresh: BTreeSet<String> = req
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
  let mut warnings = resolved.warnings;
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
          let compose: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(
              content.as_deref().unwrap_or_default(),
            )
            .map_err(|e| {
              ApiError::invalid(format!("compose 内容解析失败：{e}"))
            })?;
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
    if let Some(from) = moved_from(&snap, &current, name, to) {
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
  let status =
    gather_status(state, &snap, &current, &desired, &net, &mut b)
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
  leftover_items(&mut b, &snap.deployed, &current, &desired, &status);
  link_items(&mut b, &snap, &current, &desired, &net, &status)?;
  tailscale_items(&mut b, &snap, &desired, &status);
  egress_items(&mut b, &current, &desired);
  docker_proxy_items(&mut b, &current, &desired);
  baseline_items(&mut b, &current, &desired);
  gateway_items(
    &mut b, &snap, &current, &desired, &net, &status, &state.hub,
  )?;
  // 带改动的计划只看受影响的域名；只检查漂移（没有改动）时看全部。
  let scope = (req.fleet.is_none()
    && (!req.changes.is_empty() || req.partial.is_some()))
  .then(|| affected_hosts(&snap, &current, &desired, &net));
  dns_items(&mut b, &snap, &desired, &net, scope.as_ref()).await?;
  mark("DNS");
  crate::edge_plan::edge_items(&mut b, &snap, &current, &desired)
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

include!("planner/services.rs");
include!("planner/gateways.rs");
include!("planner/dns_and_saved_plans.rs");
