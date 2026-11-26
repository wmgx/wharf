//! 计划和直接接口共用的宿主机权限边界。

use std::{collections::BTreeSet, net::IpAddr};

use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Action, Impact, Layer, Plan, PlanItem},
  spec::{
    AdoptSpec, GatewayKind, GatewaySpec, ServerSettings, ServiceSpec,
    Source,
  },
  view::{TaskKind, TaskSpec},
};

use crate::{
  api::AppError,
  auth::Auth,
  planner::{Step, StepPlan},
  world::{
    KIND_GATEWAY, KIND_SERVER, KIND_SERVICE, ServiceRow, World,
    is_reserved_host_port,
  },
};

mod compose;
mod policy;

pub use policy::{
  HostCap, HostRequirement, MIGRATION, opened_switch,
  require_plan_host, require_with,
};

use compose::compose_host_reasons;
pub use compose::{has_new_public_bind, validate_service_ports};

#[cfg(test)]
pub(crate) use compose::compose_public_binds;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAccess {
  pub required: bool,
  pub human_only: bool,
  pub cap: Option<HostCap>,
  pub server: Option<String>,
  pub reasons: Vec<String>,
}

#[derive(Clone, Copy)]
pub enum HostTarget<'a> {
  PlanItem {
    item: &'a PlanItem,
    current: &'a World,
    desired: &'a World,
  },
  PlanStep {
    step: &'a Step,
    current: &'a World,
    desired: &'a World,
  },
  Task(&'a TaskSpec),
  HostExec {
    server: &'a str,
  },
  HostTerminal {
    server: &'a str,
  },
  HostDir {
    server: &'a str,
    action: &'static str,
  },
  HostApt {
    server: &'a str,
  },
  ImportPreview {
    server: &'a str,
    target: &'a str,
  },
  HostUnits {
    server: &'a str,
  },
  RemoveUnmanaged {
    server: &'a str,
    target: &'a str,
  },
}

pub fn assess(target: HostTarget<'_>) -> HostAccess {
  let human_only = matches!(target, HostTarget::HostTerminal { .. });
  use HostCap::{HostDocker, HostExec, HostSystem, HostTerminal};

  let (location, reasons) = match target {
    HostTarget::HostTerminal { server } => (
      Some((server, HostTerminal)),
      vec![format!("打开服务器 {server} 的宿主机终端")],
    ),
    HostTarget::HostExec { server } => (
      Some((server, HostExec)),
      vec![format!("在服务器 {server} 上执行宿主机命令")],
    ),
    HostTarget::HostDir { server, action } => (
      Some((server, HostExec)),
      vec![format!("在服务器 {server} 上{action}")],
    ),
    HostTarget::HostApt { server } => (
      Some((server, HostExec)),
      vec![format!("在服务器 {server} 上操作宿主机 apt 更新")],
    ),
    HostTarget::ImportPreview { server, target } => (
      Some((server, HostDocker)),
      vec![format!("读取服务器 {server} 上的容器配置 {target}")],
    ),
    HostTarget::HostUnits { server } => (
      Some((server, HostSystem)),
      vec![format!(
        "查看或管理服务器 {server} 上的宿主机 systemd 程序"
      )],
    ),
    HostTarget::RemoveUnmanaged { server, target } => (
      Some((server, HostDocker)),
      vec![format!("删除服务器 {server} 上的未纳管容器 {target}")],
    ),
    HostTarget::Task(spec) => match &spec.how {
      TaskKind::Host { .. } => (
        Some((spec.server.as_str(), HostExec)),
        vec!["在宿主机上执行命令".into()],
      ),
      TaskKind::Container { mounts, .. } if !mounts.is_empty() => (
        Some((spec.server.as_str(), HostDocker)),
        mounts
          .iter()
          .map(|m| format!("容器任务挂载了宿主机路径 {m}"))
          .collect(),
      ),
      _ => (None, vec![]),
    },
    HostTarget::PlanItem {
      item,
      current,
      desired,
    } => (
      item_location(item, desired),
      item_reasons(item, current, desired),
    ),
    HostTarget::PlanStep {
      step,
      current: _current,
      desired,
    } => match step {
      Step::ServiceUp { service, .. } => {
        desired.services.get(service).map_or((None, vec![]), |row| {
          (
            Some((row.spec.server.as_str(), HostDocker)),
            service_reasons(service, row, row.import.is_some()),
          )
        })
      }
      Step::Baseline { server }
      | Step::DockerProxy { server }
      | Step::Egress { server }
      | Step::TailscaleUp { server }
      | Step::LinkDown { server, .. } => (
        Some((server.as_str(), HostSystem)),
        step_reason(step).map(String::from).into_iter().collect(),
      ),
      _ => (None, vec![]),
    },
  };
  let location = location.filter(|_| !reasons.is_empty());
  HostAccess {
    required: !reasons.is_empty(),
    human_only,
    cap: location.map(|(_, cap)| cap),
    server: location.map(|(server, _)| server.to_owned()),
    reasons,
  }
}

fn item_location<'a>(
  item: &'a PlanItem,
  desired: &'a World,
) -> Option<(&'a str, HostCap)> {
  let (kind, name) = item.address.split_once('/')?;
  if host_address_reason(&item.address).is_some() {
    let server = if kind == "network" {
      name.strip_suffix("/tailscale")?
    } else {
      name
    };
    return Some((server, HostCap::HostSystem));
  }
  let server = match kind {
    KIND_SERVICE => &desired.services.get(name)?.spec.server,
    KIND_GATEWAY => &desired.gateways.get(name)?.spec.server,
    _ => return None,
  };
  Some((server, HostCap::HostDocker))
}

fn step_reason(step: &Step) -> Option<&'static str> {
  match step {
    Step::Baseline { .. } => Some("纠正服务器基线"),
    Step::DockerProxy { .. } => Some("修改 dockerd 拉镜像代理配置"),
    Step::Egress { .. } => Some("修改服务器外网代理"),
    Step::TailscaleUp { .. } => Some("启动宿主机 Tailscale 容器"),
    Step::LinkDown { project, .. }
      if project == crate::tailscale::PROJECT =>
    {
      Some("删除宿主机 Tailscale 容器")
    }
    _ => None,
  }
}

fn host_address_reason(address: &str) -> Option<&'static str> {
  let (kind, name) = address.split_once('/')?;
  match kind {
    KIND_SERVER => Some("修改服务器宿主机设置"),
    "baseline" => Some("纠正服务器基线"),
    "docker" => Some("修改 dockerd 拉镜像代理配置"),
    "egress" => Some("修改服务器外网代理"),
    "network" if name.ends_with("/tailscale") => {
      Some("管理宿主机 Tailscale 网络容器")
    }
    _ => None,
  }
}

fn item_reasons(
  item: &PlanItem,
  current: &World,
  desired: &World,
) -> Vec<String> {
  let Some((kind, name)) = item.address.split_once('/') else {
    return vec![];
  };
  if (kind != KIND_SERVER || item.layer == Layer::Config)
    && let Some(reason) = host_address_reason(&item.address)
  {
    return vec![reason.into()];
  }
  if item.action == Action::Delete {
    return vec![];
  }
  match kind {
    KIND_SERVICE => {
      let mut reasons =
        desired.services.get(name).map_or_else(Vec::new, |row| {
          service_reasons(
            name,
            row,
            row.import.is_some()
              && (item.layer == Layer::Container
                || current
                  .services
                  .get(name)
                  .and_then(|s| s.import.as_ref())
                  != row.import.as_ref()),
          )
        });
      if item.layer == Layer::Container
        && item.impacts.contains(&Impact::Overwrite)
      {
        reasons.push("覆盖接管宿主机上的未纳管容器".into());
      }
      reasons
    }
    KIND_GATEWAY if item.layer == Layer::Config => {
      let Some(gateway) = desired.gateways.get(name) else {
        return vec![];
      };
      let old = current.gateways.get(name);
      let mut reasons = Vec::new();
      if item.action == Action::Create
        && custom_gateway_image(&gateway.spec)
      {
        reasons.push("自定义网关镜像（网关以 host 网络运行）".into());
      }
      if item.action == Action::Update
        && old.map(|g| &g.spec.image) != Some(&gateway.spec.image)
      {
        reasons.push("修改网关镜像（网关以 host 网络运行）".into());
      }
      for f in &gateway.spec.layer4 {
        if let Some(up) = &f.upstream
          && is_host_local_upstream(up)
          && (item.action == Action::Create
            || !old.is_some_and(|g| g.spec.layer4.contains(f)))
        {
          reasons.push(format!(
            "四层转发 {} 的上游 {} 指向宿主机本地或保留端口",
            f.listen, up
          ));
        }
      }
      reasons
    }
    _ => vec![],
  }
}

fn compose(spec: &ServiceSpec) -> Option<&str> {
  match &spec.source {
    Source::Compose { content, .. } => content.as_deref(),
    _ => None,
  }
}

fn service_reasons(
  name: &str,
  row: &ServiceRow,
  adopting: bool,
) -> Vec<String> {
  let mut reasons = compose(&row.spec)
    .map_or_else(Vec::new, |content| {
      compose_host_reasons(name, content)
    });
  if adopting {
    reasons.push("接管宿主机上的未纳管容器".into());
  }
  reasons
}

fn custom_gateway_image(spec: &GatewaySpec) -> bool {
  spec.image.as_ref().is_some_and(|image| {
    image.trim()
      != match spec.kind {
        GatewayKind::Caddy => crate::render::DEFAULT_CADDY_IMAGE,
        GatewayKind::CloudflareTunnel => {
          crate::render::DEFAULT_CLOUDFLARED_IMAGE
        }
      }
  })
}

pub fn check_host_dir_settings(
  auth: &Auth,
  name: &str,
  settings: &ServerSettings,
) -> Result<(), ApiError> {
  if auth.human && !settings.host_terminal {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "没有开启宿主机访问，请到“服务器详情 → 设置”打开“允许从页面打开宿主机终端”。",
    ));
  }
  if !auth.human && !settings.host_exec {
    return Err(ApiError::new(ErrorCode::Forbidden, format!("服务器 {name} 没有开启宿主机命令执行，不能用 API token 访问宿主机目录、会话或执行 apt"))
      .with_hint("请在页面上操作，或到“服务器详情 → 设置”开启“宿主机命令执行”"));
  }
  Ok(())
}

pub fn mark_plan(
  current: &World,
  desired: &World,
  items: &mut [PlanItem],
  steps: &[StepPlan],
) -> (Vec<String>, Vec<HostRequirement>) {
  let mut addresses = BTreeSet::new();
  let mut requirements = Vec::new();
  for item in items {
    if item.layer == Layer::Config
      && let Some(name) = item.address.strip_prefix("gateway/")
      && layer4_changed(current, desired, name)
      && !item.impacts.contains(&Impact::Public)
    {
      item.impacts.push(Impact::Public);
    }
    let access = assess(HostTarget::PlanItem {
      item,
      current,
      desired,
    });
    let accesses = std::iter::once(access).chain(
      steps
        .iter()
        .filter(|s| s.items.contains(&item.id))
        .map(|s| {
          assess(HostTarget::PlanStep {
            step: &s.step,
            current,
            desired,
          })
        }),
    );
    for access in accesses {
      for reason in access.reasons {
        if !item.host_access.contains(&reason) {
          item.host_access.push(reason.clone());
        }
        if let (Some(server), Some(cap)) =
          (&access.server, access.cap)
        {
          let requirement = HostRequirement {
            address: item.address.clone(),
            server: server.clone(),
            cap,
            reason,
          };
          if !requirements.contains(&requirement) {
            requirements.push(requirement);
          }
        }
      }
    }
    if item.needs_host() {
      addresses.insert(item.address.clone());
    }
  }
  (addresses.into_iter().collect(), requirements)
}

// 旧计划的 ServiceUp 只有服务名，计划视图也可能脱敏。重新 plan 才能校验实际 Compose 和四层变更。
pub fn require_legacy_replan(
  plan: &Plan,
  steps: &[StepPlan],
) -> Result<(), ApiError> {
  if steps
    .iter()
    .any(|s| matches!(s.step, Step::ServiceUp { .. }))
    || plan.items.iter().any(|i| {
      i.action != Action::Delete
        && (i.address.starts_with("service/")
          || (i.layer == Layer::Config
            && i.address.starts_with("gateway/")))
    })
  {
    return Err(
      ApiError::new(
        ErrorCode::PlanStale,
        "计划生成于宿主机权限校验更新之前，需要重新 plan",
      )
      .suggest("wharf plan"),
    );
  }
  Ok(())
}

pub fn validate_adopt(
  world: &World,
  name: &str,
  old: Option<&ServiceRow>,
  adopt: Option<&AdoptSpec>,
) -> Result<(), ApiError> {
  let Some(adopt) = adopt else { return Ok(()) };
  if old.is_some_and(|row| row.import.as_ref() != Some(adopt)) {
    return Err(ApiError::invalid(format!(
      "服务 {name} 已存在，不能接管其他容器"
    )));
  }
  if let Some(project) = &adopt.project {
    if project.trim().is_empty() {
      return Err(ApiError::invalid("接管的项目名不能为空"));
    }
    if (project != name || !world.services.contains_key(project))
      && crate::import_api::managed(world, project)
    {
      return Err(ApiError::invalid(format!(
        "项目 {project} 属于 Wharf 管理，不能被服务 {name} 接管"
      )));
    }
  }
  for c in &adopt.containers {
    if c.trim().is_empty()
      || matches!(c.as_str(), "wharf-core" | "wharf-agent")
      || [
        "wharf-gw-",
        "wharf-link",
        "wharf-tailscale",
        "wharf-backup",
        wharf_api_types::agent::TASK_DATA_PREFIX,
        wharf_api_types::agent::TRIAL_PROJECT_PREFIX,
      ]
      .iter()
      .any(|prefix| c.starts_with(prefix))
    {
      return Err(ApiError::invalid(format!(
        "容器 {c} 属于 Wharf 系统组件，不能接管"
      )));
    }
  }
  Ok(())
}

fn layer4_changed(
  current: &World,
  desired: &World,
  name: &str,
) -> bool {
  // 删除一条转发和修改目标一样，走现有确认流程。
  let old = current
    .gateways
    .get(name)
    .map_or(&[][..], |g| g.spec.layer4.as_slice());
  desired
    .gateways
    .get(name)
    .is_some_and(|g| old != g.spec.layer4.as_slice())
}

fn upstream_host(up: &str) -> (&str, &str) {
  let (host, port) = up.rsplit_once(':').unwrap_or((up, ""));
  let host = host.trim_matches(['[', ']']);
  (host.trim_end_matches('.'), port)
}

pub fn is_metadata_upstream(up: &str) -> bool {
  let (host, _) = upstream_host(up);
  host.eq_ignore_ascii_case("metadata.google.internal")
    || host.eq_ignore_ascii_case("metadata")
    || host
      .split('%')
      .next()
      .and_then(|h| h.parse::<IpAddr>().ok())
      .is_some_and(|ip| match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => {
          ip.is_unicast_link_local()
            || ip.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]
        }
      })
}

pub fn is_host_local_upstream(up: &str) -> bool {
  let (host, port) = upstream_host(up);
  host.eq_ignore_ascii_case("localhost")
    || port.parse().is_ok_and(is_reserved_host_port)
    || host.parse::<IpAddr>().is_ok_and(|ip| {
      let ip = ip.to_canonical();
      ip.is_loopback() || ip.is_unspecified()
    })
}

#[cfg(test)]
pub(crate) mod tests;
