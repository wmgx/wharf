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
  spec::RouteSpec,
};
use wharf_providers::{DnsRecordSpec, DnsRecordType, RemoteRecord};

use crate::{
  db::{self, Write},
  render::Net,
  snapshot::{self, Snapshot},
  state::AppState,
  world::{
    KIND_GATEWAY, KIND_ROUTE, KIND_SERVER, KIND_SERVICE, World,
    gateway_project, new_id,
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
  ServiceDown {
    server: String,
    service: String,
  },
}

impl Step {
  /// 删除 DNS → 建目录 → 起服务 → 网关 → 写 DNS → 下线网关 → 下线服务。
  fn order(&self) -> u8 {
    match self {
      Self::DnsDelete { .. } => 0,
      Self::EnsureDirs { .. } => 1,
      Self::ServiceUp { .. } => 2,
      Self::GatewaySync { .. } => 3,
      Self::DnsUpsert { .. } => 4,
      Self::GatewayDown { .. } => 5,
      Self::ServiceDown { .. } => 6,
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
struct Builder {
  items: Vec<PlanItem>,
  steps: Vec<StepPlan>,
  warnings: Vec<String>,
}

impl Builder {
  #[allow(clippy::too_many_arguments)]
  fn item(
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

  fn step(
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
  desired.allocate_ports()?;
  desired.validate()?;
  for (name, svc) in &desired.services {
    if let Some(old) = current.services.get(name)
      && old.spec.server != svc.spec.server
    {
      return Err(
        ApiError::new(
          wharf_api_types::ErrorCode::NotImplemented,
          format!(
            "服务 {name} 从 {} 换到 {}：迁移数据要用 wharf service move（P3）",
            old.spec.server, svc.spec.server
          ),
        )
        .with_hint("现在可以先删除服务再在新服务器上创建，数据目录需要自己搬"),
      );
    }
  }

  let writes = desired.writes_from(&current);
  let mut b = Builder::default();
  config_items(&mut b, &current, &desired, &writes);

  let net = snap.net(&desired);
  let status =
    gather_status(state, &snap, &current, &desired, &mut b).await;
  service_items(
    &mut b, &snap, &current, &desired, &net, &status, &writes,
  )?;
  gateway_items(&mut b, &current, &desired, &net, &status)?;
  dns_items(&mut b, &snap, &desired, &net).await?;

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
      (KIND_GATEWAY, Action::Delete) => {
        (Risk::Disruptive, "删除网关".to_string())
      }
      (KIND_ROUTE, Action::Delete) => {
        (Risk::Disruptive, "删除路由，域名将无法访问".to_string())
      }
      (KIND_ROUTE, Action::Create) => {
        let auth =
          desired.routes.get(name).is_some_and(|r| r.spec.auth);
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
    // 数据卷：新增的目录。
    let old_dirs: BTreeSet<String> = current
      .services
      .get(name)
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

    let (_, hash) =
      snapshot::service_resolved(desired, net, name, &snap.secrets)?;
    let template = snapshot::service_template(desired, net, name)?;
    let after =
      Some(json!({ "server": server, "compose": template }));
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
          let reason = if state.hash.is_none() {
            "服务器上已有同名 project，但不是 Wharf 部署的，将被接管重建"
          } else if changed(writes, KIND_SERVICE, name) {
            "配置变化，重建容器"
          } else {
            "漂移：服务器上的部署和配置不一致，重新部署"
          };
          let risk = if state.hash.is_none() {
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
          format!(
            "漂移：容器没在运行（{}）",
            describe_containers(state)
          ),
          Some(json!({ "containers": state.containers })),
        )),
        Some(_) => None,
      },
    };
    if let Some((action, risk, reason, before)) = decision {
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
    if desired.services.contains_key(name) {
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
    if !svc.spec.volumes.is_empty() {
      b.warnings.push(format!(
        "服务 {name} 的数据目录 /srv/{name}/ 会保留在 {server} 上，需要时手动删除"
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

fn gateway_items(
  b: &mut Builder,
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
      "caddyfile": r.caddyfile,
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
          if s.config_hash.as_deref()
            != Some(r.caddyfile_hash.as_str()) =>
        {
          Some((
            Action::Update,
            Risk::Safe,
            "路由变化，热重载配置".to_string(),
          ))
        }
        Some(_) => None,
      },
    };
    if let Some((action, risk, reason)) = decision {
      let id = b.item(
        format!("{KIND_GATEWAY}/{name}"),
        Layer::Gateway,
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
  matches!((a, b), (Some(a), Some(b)) if a.caddyfile_hash == b.caddyfile_hash)
}

/// 路由期望的 DNS 记录。
fn desired_record(
  desired: &World,
  net: &Net,
  hostname: &str,
) -> Result<DnsSpec, ApiError> {
  let route = &desired.routes[hostname];
  let gateway =
    desired.route_gateway(&route.spec).unwrap_or_default();
  let server = &desired.gateways[gateway].spec.server;
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
  })
}

fn remote_ref(r: &RemoteRecord) -> RemoteRef {
  RemoteRef {
    scope: r.scope.clone(),
    remote_id: r.remote_id.clone(),
  }
}

async fn dns_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  net: &Net,
) -> Result<(), ApiError> {
  let live_ids: BTreeSet<&str> =
    desired.routes.values().map(|r| r.id.as_str()).collect();
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

  for (host, route) in &desired.routes {
    let Some((account, _zone)) = snap.account_for(host) else {
      b.warnings.push(format!(
        "没有厂商账号管理 {host} 所在的域名，DNS 需要自己配置（或执行 wharf account add）"
      ));
      continue;
    };
    let spec = desired_record(desired, net, host)?;
    let provider = snapshot::dns_provider(account)?;
    let want = spec.to_provider();
    provider
      .validate(host, &want)
      .map_err(snapshot::provider_error)?;
    let records = snapshot::with_timeout(
      &format!("读取 {host} 的 DNS 记录"),
      provider.list(host),
    )
    .await?;
    let owner = wharf_providers::Owner {
      id: route.id.clone(),
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
