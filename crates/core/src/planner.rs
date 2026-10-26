//! 生成计划：先算配置差异（期望 vs 数据库），再算现实差异（期望 vs 远端）。
//!
//! 计划里只存"要做什么"（[StepPlan]），apply 时从已提交的数据库重新渲染
//! 具体内容，所以密钥只在发给 agent 的那一刻才被替换进去。

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
    Action, Layer, Plan, PlanItem, PlanRequest, PlanStatus, Risk,
  },
  spec::{
    BuildSource, EdgeAppSpec, EdgeKind, GatewayKind, NetworkMode,
    RouteSpec, Source,
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
    KIND_EDGE, KIND_GATEWAY, KIND_ROUTE, KIND_SERVER, KIND_SERVICE,
    World, gateway_project, new_id,
  },
};

/// 计划的有效期。
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
  },
  GatewaySync {
    gateway: String,
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
  /// 备份和恢复不来自计划，是单独发起的执行。
  Backup {
    service: String,
  },
  Restore {
    service: String,
    snapshot: String,
  },
  /// 构建来源：拉最新代码重新构建并部署。单独发起，不来自计划。
  Rebuild {
    service: String,
  },
  ServiceDown {
    server: String,
    service: String,
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
  fn order(&self) -> u8 {
    match self {
      Self::DnsDelete { .. } | Self::EdgeDetach { .. } => 0,
      Self::EnsureDirs { .. } => 1,
      Self::VolumeSync { .. } => 2,
      Self::ServiceUp { .. }
      | Self::EdgeDeploy { .. }
      | Self::LinkUp { .. }
      | Self::TailscaleUp { .. }
      | Self::ServiceStop { .. } => 3,
      Self::GatewaySync { .. } => 4,
      Self::DnsUpsert { .. } | Self::EdgeAttach { .. } => 5,
      Self::GatewayDown { .. } | Self::LinkDown { .. } => 6,
      Self::ServiceDown { .. } => 7,
      Self::Backup { .. }
      | Self::Restore { .. }
      | Self::Rebuild { .. }
      | Self::AgentUpgrade { .. }
      | Self::AgentUpgrades { .. }
      | Self::Prune { .. }
      | Self::CoreBackup { .. }
      | Self::ServiceRestart { .. }
      | Self::EdgeRollback { .. } => 8,
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
  pub steps: Vec<StepPlan>,
  pub writes: Vec<Write>,
}

#[derive(Default)]
pub(crate) struct Builder {
  items: Vec<PlanItem>,
  steps: Vec<StepPlan>,
  pub(crate) warnings: Vec<String>,
  /// 这次计划查到的镜像 ID：服务 → `sha256:…`。
  image_ids: BTreeMap<String, String>,
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
    risk: Risk,
    reason: impl Into<String>,
  ) -> u32 {
    let id = self.items.len() as u32 + 1;
    self.items.push(PlanItem {
      id,
      address,
      layer,
      action,
      before,
      after,
      risk,
      reason: reason.into(),
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
  let snap = snapshot::load(&state.db).await?;
  let current = snap.world.clone();
  let mut desired = current.clone();
  if let Some(fleet) = &req.fleet {
    if !req.changes.is_empty() {
      return Err(ApiError::invalid("changes 和 fleet 只能给一个"));
    }
    desired.replace_with(fleet)?;
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
  desired.allocate_ports()?;
  desired.validate()?;
  let refresh: BTreeSet<String> = req
    .changes
    .iter()
    .filter_map(|c| match c {
      wharf_api_types::spec::Change::RefreshImages { name } => {
        Some(name.clone())
      }
      _ => None,
    })
    .collect();
  let resolved = crate::pins::resolve(
    state,
    &snap.applied,
    &mut desired,
    &refresh,
  )
  .await?;
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

  let writes = desired.writes_from(&current);
  let mut b = Builder {
    image_ids: resolved.image_ids,
    warnings: resolved.warnings,
    ..Builder::default()
  };
  config_items(&mut b, &current, &desired, &writes);

  let mut net = snap.net(&desired);
  net.reach = crate::link::probe(state, &net, &desired).await;
  // 迁移要源机器把数据推到目标机器（design 2.10）。
  for (name, svc) in &desired.services {
    let to = &svc.spec.server;
    if let Some(from) = moved_from(&snap, &current, name, to) {
      crate::link::require_reach(state, &net, from, to, "迁移数据")
        .await?;
    }
  }
  let status =
    gather_status(state, &snap, &current, &desired, &net, &mut b)
      .await;
  service_items(
    &mut b, &snap, &current, &desired, &net, &status, &writes,
  )?;
  link_items(&mut b, &current, &desired, &net, &status)?;
  tailscale_items(&mut b, &snap, &desired, &status);
  gateway_items(&mut b, &snap, &current, &desired, &net, &status)?;
  dns_items(&mut b, &snap, &desired, &net).await?;
  crate::edge_plan::edge_items(&mut b, &snap, &current, &desired)
    .await?;

  b.steps.sort_by_key(|s| s.step.order());
  let plan_id = new_id("p");
  let mut needs_confirm: Vec<String> = b
    .items
    .iter()
    .filter(|i| i.risk.needs_confirm())
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
    base_versions: current.versions(),
    items: b.items,
    warnings: b.warnings,
    needs_confirm,
    suggest,
  };
  Ok(Planned {
    plan,
    steps: b.steps,
    writes,
  })
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
  let configured = &current.services.get(name)?.spec.server;
  Some(snap.deployed.get(name).unwrap_or(configured))
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
      let mut v = to_json(&r.spec);
      v["host_ports"] = json!(r.host_ports);
      v
    }),
    KIND_GATEWAY => {
      world.gateways.get(name).map(|r| to_json(&r.spec))
    }
    KIND_ROUTE => world.routes.get(name).map(|r| to_json(&r.spec)),
    KIND_EDGE => world.edge_apps.get(name).map(|r| to_json(&r.spec)),
    _ => None,
  }
}

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
      (KIND_SERVICE, Action::Delete) => {
        (Risk::Destructive, "删除服务（数据目录保留）".to_string())
      }
      (KIND_SERVICE, Action::Create)
        if desired
          .services
          .get(name)
          .and_then(|r| r.import.as_ref())
          .is_some() =>
      {
        let adopt = desired.services[name].import.as_ref();
        match adopt.and_then(|a| a.project.as_deref()) {
          Some(project) => (
            Risk::Disruptive,
            format!(
              "导入：停掉原来的 compose 项目 {project}，用新名字重新创建容器"
            ),
          ),
          None if adopt.is_some_and(|a| !a.containers.is_empty()) => {
            (
              Risk::Disruptive,
              format!(
                "导入：原来的容器 {} 改名停掉（失败时恢复），重新创建",
                adopt
                  .map(|a| a.containers.join("、"))
                  .unwrap_or_default()
              ),
            )
          }
          None => (
            Risk::Safe,
            "导入：沿用同名 compose 项目，配置一致时不重建容器"
              .to_string(),
          ),
        }
      }
      (KIND_GATEWAY, Action::Delete) => {
        (Risk::Disruptive, "删除网关".to_string())
      }
      (KIND_EDGE, Action::Delete) => {
        (Risk::Safe, "不再纳管（厂商那边的项目保留）".to_string())
      }
      (KIND_ROUTE, Action::Delete) => {
        (Risk::Disruptive, "删除路由，域名将无法访问".to_string())
      }
      (KIND_ROUTE, Action::Create) => {
        let route = desired.routes.get(name);
        let auth = route.is_some_and(|r| r.spec.auth);
        if auth {
          (Risk::Safe, "新增路由".to_string())
        } else {
          (
            Risk::ExposesPublic,
            "新增公网路由，未开启 auth".to_string(),
          )
        }
      }
      (_, Action::Create) => (Risk::Safe, "新增".to_string()),
      _ => (Risk::Safe, "修改配置".to_string()),
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
  current: &World,
  desired: &World,
  net: &Net,
  b: &mut Builder,
) -> StatusMap {
  let mut projects: BTreeMap<String, BTreeSet<String>> =
    BTreeMap::new();
  for world in [current, desired] {
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
    for (name, row) in &world.servers {
      if row.settings.network_mode == Some(NetworkMode::Tailscale) {
        projects
          .entry(name.clone())
          .or_default()
          .insert(crate::tailscale::PROJECT.to_string());
      }
    }
  }
  let futures =
    projects.into_iter().map(|(server, projects)| async move {
      let result = snapshot::project_status(
        &state.hub,
        &server,
        projects.into_iter().collect(),
        STATUS_TIMEOUT,
      )
      .await;
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
  state
    .containers
    .iter()
    .filter(|c| c.state != "running")
    .map(|c| format!("{} {}", c.service, c.state))
    .collect::<Vec<_>>()
    .join("，")
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
    let address = format!("{KIND_SERVICE}/{name}");
    let server = &svc.spec.server;
    let moved = moved_from(snap, current, name, server);
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
    let new_dirs: Vec<String> =
      crate::render::service_dirs(name, &svc.spec)
        .into_iter()
        .filter(|d| !old_dirs.contains(d))
        .collect();
    if !new_dirs.is_empty() {
      let id = b.item(
        address.clone(),
        Layer::Volume,
        Action::Create,
        None,
        Some(json!({ "dirs": new_dirs })),
        Risk::Safe,
        "创建数据目录",
      );
      b.step(
        vec![id],
        format!("在 {server} 上创建 {name} 的数据目录"),
        Step::EnsureDirs {
          server: server.clone(),
          dirs: new_dirs,
        },
      );
    }

    if let Some(from) = moved {
      move_items(b, current, name, from, server, net);
    }

    let (_, hash) =
      snapshot::service_resolved(desired, net, name, &snap.secrets)?;
    let template = snapshot::service_template(desired, net, name)?;
    let after =
      Some(json!({ "server": server, "compose": template }));
    let live = status
      .get(server)
      .and_then(|s| s.as_ref())
      .and_then(|p| p.get(name));
    // 配置没变、只是要停下来：不重建，直接停。
    if svc.spec.stopped
      && let Some(state) = live
      && state.hash.as_deref() == Some(hash.as_str())
    {
      if state.containers.iter().any(|c| c.state == "running") {
        let id = b.item(
          address.clone(),
          Layer::Container,
          Action::Update,
          Some(json!({ "containers": state.containers })),
          after,
          Risk::Disruptive,
          "停止服务",
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
    let upgrade = crate::pins::change(
      snap.applied.get(name),
      &svc.pins,
      b.image_ids.get(name).map(String::as_str),
    );
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      None if changed(writes, KIND_SERVICE, name) => Some((
        Action::Update,
        Risk::Disruptive,
        "无法读取现状，按新配置部署".to_string(),
        None,
      )),
      None => None,
      Some(projects) => match projects.get(name) {
        None => Some((
          Action::Create,
          Risk::Safe,
          "部署新服务".into(),
          None,
        )),
        Some(state)
          if state.hash.is_none() && state.containers.is_empty() =>
        {
          Some((
            Action::Create,
            Risk::Safe,
            "部署新服务".into(),
            None,
          ))
        }
        Some(state)
          if state.hash.as_deref() != Some(hash.as_str()) =>
        {
          let before = json!({ "hash": state.hash, "containers": state.containers });
          let adopting = svc.import.is_some();
          let reason = if state.hash.is_none() && adopting {
            "接管服务器上的同名 compose 项目，配置一致时不重建容器"
          } else if state.hash.is_none() {
            "服务器上已有同名 project，但不是 Wharf 部署的，将被接管重建"
          } else if changed(writes, KIND_SERVICE, name) {
            "配置变化，重建容器"
          } else {
            "漂移：服务器上的部署和配置不一致，重新部署"
          };
          let risk = if state.hash.is_none() && !adopting {
            Risk::Destructive
          } else {
            Risk::Disruptive
          };
          Some((
            Action::Update,
            risk,
            reason.to_string(),
            Some(before),
          ))
        }
        Some(state) if !state.all_running() => Some((
          Action::Update,
          Risk::Disruptive,
          if changed(writes, KIND_SERVICE, name) {
            "启动服务".to_string()
          } else {
            format!(
              "漂移：容器没在运行（{}）",
              describe_containers(state)
            )
          },
          Some(json!({ "containers": state.containers })),
        )),
        Some(_) => upgrade.map(|(old, new)| {
          (
            Action::Update,
            Risk::Disruptive,
            format!(
              "更新镜像版本 {old} → {}",
              crate::pins::short(&new)
            ),
            Some(json!({ "digest": old })),
          )
        }),
      },
    };
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
          Risk::Destructive,
          format!(
            "{server} 上同名 compose 项目里有不是 Wharf 部署的容器（{}），部署会删除它们；要保留请先导入，或换个服务名",
            foreign.join("、")
          ),
          before,
        ))
      }
      d => d,
    };
    if let Some((action, risk, reason, before)) = decision {
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
        },
      );
    }
  }
  for (name, svc) in &current.services {
    let old =
      running_on(snap, current, name).unwrap_or(&svc.spec.server);
    if desired
      .services
      .get(name)
      .is_some_and(|d| d.spec.server == old)
    {
      continue;
    }
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
        Risk::Disruptive,
        format!(
          "迁移到 {to} 后删除 {server} 上的旧容器（数据目录保留）"
        ),
      );
      b.step(
        vec![id],
        format!("删除 {server} 上的旧 {name}"),
        Step::ServiceDown {
          server: server.clone(),
          service: name.clone(),
        },
      );
      continue;
    }
    let server = &svc.spec.server;
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      Risk::Destructive,
      "停止并删除容器",
    );
    for m in crate::data::mounts(name, &svc.spec) {
      b.warnings.push(format!(
        "服务 {name} 的{} 会保留在 {server} 上，需要时手动删除",
        crate::data::describe(&m)
      ));
    }
    b.step(
      vec![id],
      format!("在 {server} 上删除 {name}"),
      Step::ServiceDown {
        server: server.clone(),
        service: name.clone(),
      },
    );
  }
  Ok(())
}

/// 迁移数据的计划项和步骤，以及相关提醒。
fn move_items(
  b: &mut Builder,
  current: &World,
  name: &str,
  from: &str,
  to: &str,
  net: &Net,
) {
  let old = &current.services[name];
  let mounts = crate::data::mounts(name, &old.spec);
  let left: Vec<String> = mounts
    .iter()
    .filter(|m| m.kind != DataKind::Managed)
    .map(crate::data::describe)
    .collect();
  // 不归 Wharf 管的数据不会跟着走，新服务器上的服务看不到它们，要用户确认。
  if !left.is_empty() {
    b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Volume,
      Action::Update,
      None,
      None,
      Risk::Destructive,
      format!(
        "{} 不归 Wharf 管，不会迁移到 {to}：迁移后服务看不到这些数据",
        left.join("、")
      ),
    );
  }
  // 没有 Wharf 管理的数据：没有要搬的，新容器起来、网关切过去即可，不停服。
  if !mounts.iter().any(|m| m.kind == DataKind::Managed) {
    return;
  }
  let id = b.item(
    format!("{KIND_SERVICE}/{name}"),
    Layer::Volume,
    Action::Update,
    Some(json!({ "server": from, "dir": format!("/srv/{name}/") })),
    Some(json!({ "server": to, "dir": format!("/srv/{name}/") })),
    Risk::Disruptive,
    format!("迁移 /srv/{name}/ 从 {from} 到 {to}：先同步一遍，再停掉旧容器做增量同步，这段时间服务不可用"),
  );
  b.step(
    vec![id],
    format!("迁移 {name} 的数据 {from} → {to}"),
    Step::VolumeSync {
      service: name.to_string(),
      from: from.to_string(),
      to: to.to_string(),
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
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
) -> Result<(), ApiError> {
  let want = crate::link::projects(desired, net)?;
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
            Risk::Disruptive,
            format!(
              "{}（配置变化，重建，经这条隧道的路由会断几秒）",
              p.summary
            ),
          ))
        } else if !s.all_running() {
          Some((
            Action::Update,
            Risk::Disruptive,
            format!(
              "漂移：隧道容器没在运行（{}）",
              describe_containers(s)
            ),
          ))
        } else {
          None
        }
      }
      _ => Some((Action::Create, Risk::Safe, p.summary.clone())),
    };
    let Some((action, risk, reason)) = decision else {
      continue;
    };
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
      },
    );
  }
  for p in crate::link::projects(current, net).unwrap_or_default() {
    if want
      .iter()
      .any(|w| w.server == p.server && w.project == p.project)
    {
      continue;
    }
    let exists = status
      .get(&p.server)
      .and_then(|s| s.as_ref())
      .and_then(|s| s.get(&p.project))
      .is_some_and(|s| !s.containers.is_empty());
    if !exists {
      continue;
    }
    let id = b.item(
      format!("link/{}/{}", p.server, p.project),
      Layer::Gateway,
      Action::Delete,
      Some(json!({ "server": p.server, "summary": p.summary })),
      None,
      Risk::Disruptive,
      "没有路由再用这条隧道，停止并删除",
    );
    b.step(
      vec![id],
      format!("在 {} 上删除 {}", p.server, p.project),
      Step::LinkDown {
        server: p.server.clone(),
        project: p.project,
      },
    );
  }
  Ok(())
}

/// Wharf 管理的 Tailscale 容器：要的时候起，接入方式改掉之后删。
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
          Risk::Disruptive,
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
        Risk::Safe,
        format!("没检测到 Tailscale，起容器并以 {} 加入", ts::TAG),
      )),
      Some(s) if s.hash.as_deref() != Some(hash.as_str()) => Some((
        Action::Update,
        Risk::Disruptive,
        "Tailscale 容器配置变化，重建（不会重新加入）".to_string(),
      )),
      Some(s) if !s.all_running() => Some((
        Action::Update,
        Risk::Disruptive,
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
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
) -> Result<(), ApiError> {
  for name in desired.gateways.keys() {
    let gw = &desired.gateways[name];
    let server = &gw.spec.server;
    let project = gateway_project(name);
    let r = snapshot::gateway_render(desired, net, name)?;
    let after = Some(json!({
      "server": server,
      "sites": r.sites.iter().map(|s| json!({ "hostname": s.hostname, "upstream": s.upstream })).collect::<Vec<_>>(),
      "config": snapshot::redacted_config(&r.config, net),
    }));
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      // 查不到现状时，只有配置变了才计划（服务器离线已经单独提醒过）。
      None => {
        let same = current.gateways.get(name)
          == desired.gateways.get(name)
          && gateway_sites_same(current, desired, net, name);
        (!same).then(|| {
          (
            Action::Update,
            Risk::Disruptive,
            "无法读取现状，按新配置应用".to_string(),
          )
        })
      }
      Some(projects) => match projects.get(&project) {
        Some(s) if s.hash.is_none() && s.containers.is_empty() => {
          Some((Action::Create, Risk::Safe, "部署网关".to_string()))
        }
        None => {
          Some((Action::Create, Risk::Safe, "部署网关".to_string()))
        }
        Some(s)
          if s.hash.as_deref() != Some(r.compose_hash.as_str()) =>
        {
          Some((
            Action::Update,
            Risk::Disruptive,
            "网关容器配置变化，重建".to_string(),
          ))
        }
        Some(s) if !s.all_running() => Some((
          Action::Update,
          Risk::Disruptive,
          format!(
            "漂移：网关容器没在运行（{}）",
            describe_containers(s)
          ),
        )),
        Some(s)
          if applied_config(snap, name, gw.spec.kind, s)
            != Some(r.config_hash.as_str()) =>
        {
          Some((
            Action::Update,
            Risk::Safe,
            match gw.spec.kind {
              GatewayKind::Caddy => "路由变化，热重载配置",
              GatewayKind::CloudflareTunnel => {
                "路由变化，更新隧道入口规则"
              }
            }
            .to_string(),
          ))
        }
        Some(_) => None,
      },
    };
    if let Some((action, risk, reason)) = decision {
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
      let id = b.item(
        format!("{KIND_GATEWAY}/{name}"),
        layer,
        action,
        None,
        after,
        risk,
        reason,
      );
      b.step(
        vec![id],
        format!("在 {server} 上应用网关 {name}"),
        Step::GatewaySync {
          gateway: name.clone(),
        },
      );
    }
  }
  for (name, gw) in &current.gateways {
    if desired.gateways.contains_key(name) {
      continue;
    }
    let server = &gw.spec.server;
    let id = b.item(
      format!("{KIND_GATEWAY}/{name}"),
      Layer::Gateway,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      Risk::Disruptive,
      "停止并删除网关容器",
    );
    b.step(
      vec![id],
      format!("在 {server} 上删除网关 {name}"),
      Step::GatewayDown {
        server: server.clone(),
        gateway: name.clone(),
      },
    );
  }
  Ok(())
}

fn gateway_sites_same(
  current: &World,
  desired: &World,
  net: &Net,
  name: &str,
) -> bool {
  let a = snapshot::gateway_render(current, net, name).ok();
  let b = snapshot::gateway_render(desired, net, name).ok();
  matches!((a, b), (Some(a), Some(b)) if a.config_hash == b.config_hash)
}

/// 路由期望的 DNS 记录。
fn desired_record(
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  hostname: &str,
) -> Result<DnsSpec, ApiError> {
  let route = &desired.routes[hostname];
  let gateway =
    desired.route_gateway(&route.spec).unwrap_or_default();
  let gw = &desired.gateways[gateway].spec;
  if gw.kind == GatewayKind::CloudflareTunnel {
    return Ok(DnsSpec {
      record_type: "CNAME".into(),
      content: snap
        .tunnels
        .get(gateway)
        .map(|t| tunnel_target(&t.tunnel_id))
        .unwrap_or_else(|| TUNNEL_PENDING.into()),
      proxied: true,
      tunnel: Some(gateway.to_string()),
    });
  }
  let server = &gw.server;
  let ip = net.public_ip.get(server).ok_or_else(|| {
    ApiError::invalid(format!(
      "网关 {gateway} 所在的服务器 {server} 没有公网 IP，{hostname} 的 DNS 无处可指"
    ))
    .with_hint("agent 没探测到公网 IP 时，可以手动设置")
    .suggest(format!("wharf server set {server} --public-ip <ip>"))
  })?;
  let record_type = if ip.parse::<std::net::Ipv6Addr>().is_ok() {
    "AAAA"
  } else {
    "A"
  };
  Ok(DnsSpec {
    record_type: record_type.to_string(),
    content: ip.clone(),
    proxied: false,
    tunnel: None,
  })
}

fn remote_ref(r: &RemoteRecord) -> RemoteRef {
  RemoteRef {
    scope: r.scope.clone(),
    remote_id: r.remote_id.clone(),
  }
}

/// 要写 DNS 的域名、记录所有者，Pages 域名还带上边缘应用。
type DnsTarget<'a> =
  (String, String, Option<(&'a str, &'a EdgeAppSpec)>);

async fn dns_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  net: &Net,
) -> Result<(), ApiError> {
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
  // 已删除路由留下的记录。
  for owned in &snap.owned {
    if live_ids.contains(owned.route_id.as_str()) {
      continue;
    }
    let id = b.item(
      format!("{KIND_ROUTE}/{}", owned.hostname),
      Layer::Dns,
      Action::Delete,
      Some(json!({ "account": owned.account, "remote_id": owned.remote_id })),
      None,
      Risk::Disruptive,
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
        },
        owner: Some(owned.route_id.clone()),
      },
    );
  }

  for (host, route) in &desired.routes {
    if let Some(warning) = plaintext_hop(desired, net, &route.spec) {
      b.warnings.push(format!("路由 {host}：{warning}"));
    }
  }

  // 代理路由，加上 Pages 的自定义域名；Workers 的由厂商连同 DNS 一起管，见 edge_plan。
  let mut targets: Vec<DnsTarget> = desired
    .routes
    .iter()
    .map(|(host, r)| (host.clone(), r.id.clone(), None))
    .collect();
  for (name, app) in &desired.edge_apps {
    if app.spec.kind != EdgeKind::Pages {
      continue;
    }
    for d in &app.spec.domains {
      targets.push((
        d.clone(),
        crate::world::edge_owner(d),
        Some((name.as_str(), &app.spec)),
      ));
    }
  }
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
      None => desired_record(snap, desired, net, host)?,
    };
    let provider = snapshot::dns_provider(account)?;
    let want = spec.to_provider();
    if spec.content != TUNNEL_PENDING {
      provider
        .validate(host, &want)
        .map_err(snapshot::provider_error)?;
    }
    let records = snapshot::with_timeout(
      &format!("读取 {host} 的 DNS 记录"),
      provider.list(host),
    )
    .await?;
    let owner = wharf_providers::Owner {
      id: owner_id.clone(),
    };
    let (ours, foreign): (Vec<&RemoteRecord>, Vec<&RemoteRecord>) =
      records.iter().partition(|r| provider.is_owned(r, &owner));
    let canonical = want.canonical();
    let address = format!("{KIND_ROUTE}/{host}");
    let after = Some(canonical.clone());
    let upsert = |existing: Option<&RemoteRecord>,
                  extra: Vec<RemoteRef>| {
      Step::DnsUpsert {
        hostname: host.clone(),
        account: account.name.clone(),
        spec: spec.clone(),
        existing: existing.map(remote_ref),
        extra,
      }
    };
    let title = format!("写入 {host} 的 DNS 记录");
    if !foreign.is_empty() {
      let mut targets: Vec<&RemoteRecord> = ours.clone();
      targets.extend(foreign.iter().copied());
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
        Risk::Destructive,
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
      b.step(vec![id], title, upsert(Some(existing), extra));
      continue;
    }
    match ours.as_slice() {
      [] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Create,
          None,
          after,
          Risk::Safe,
          format!("新建 {} 记录", spec.record_type),
        );
        b.step(vec![id], title, upsert(None, vec![]));
      }
      [only] if only.canonical == canonical => {}
      [first, rest @ ..] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Update,
          Some(first.canonical.clone()),
          after,
          Risk::Disruptive,
          if first.canonical == canonical {
            "删除重复的记录".to_string()
          } else {
            "记录内容变化".to_string()
          },
        );
        let extra = rest.iter().map(|r| remote_ref(r)).collect();
        b.step(vec![id], title, upsert(Some(first), extra));
      }
    }
  }
  Ok(())
}

/// 保存计划。
pub async fn save(
  state: &AppState,
  planned: &Planned,
) -> Result<(), ApiError> {
  let id = planned.plan.plan_id.clone();
  let body =
    serde_json::to_string(&planned.plan).map_err(db::json_err)?;
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
) -> Option<String> {
  let gateway = world.gateways.get(world.route_gateway(route)?)?;
  let server = &world.services.get(&route.service)?.spec.server;
  if &gateway.spec.server == server {
    return None;
  }
  let addr = net.private.get(server)?;
  (!addr.network.encrypted()).then(|| {
    format!(
      "网关（{}）到服务（{server}）这一段走内网直连 {}，是明文",
      gateway.spec.server, addr.ip
    )
  })
}
