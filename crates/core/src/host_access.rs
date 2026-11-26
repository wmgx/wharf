//! 统一“触达宿主机”判定、接管校验、四层转发校验与 Admin 鉴权。

mod compose;
#[cfg(test)]
mod tests;

use std::{collections::BTreeSet, net::IpAddr};

use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Action, Impact, Layer, Plan, PlanItem},
  spec::{
    AdoptSpec, GatewayKind, GatewaySpec, Layer4Forward,
    ServerSettings, Source,
  },
  view::{Perm, TaskKind, TaskSpec},
};

use crate::{
  api::AppError,
  auth::Auth,
  planner::{Step, StepPlan},
  world::{
    GATEWAY_PROJECT_PREFIX, KIND_GATEWAY, KIND_SERVER, KIND_SERVICE,
    ServiceRow, World,
  },
};

pub use compose::{
  PublishedPort, compose_has_host_network, compose_host_reasons,
  compose_public_binds, compose_published_ports,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAccess {
  /// 是否触达宿主机（等价于 `!reasons.is_empty()`）。
  pub required: bool,
  /// 是否仅允许页面人工登录（`auth.human == true`），目前仅宿主机终端为 true。
  pub human_only: bool,
  /// 命中的具体原因（中文短语，用于 PlanItem.host_access 和报错文案）。
  pub reasons: Vec<String>,
}

impl HostAccess {
  fn from_reasons(reasons: Vec<String>, human_only: bool) -> Self {
    let mut uniq = Vec::new();
    push_unique(&mut uniq, reasons);
    Self {
      required: !uniq.is_empty(),
      human_only,
      reasons: uniq,
    }
  }
}

/// 统一判定输入：覆盖 plan/apply 和所有直接 API 入口。
pub enum HostTarget<'a> {
  PlanItem {
    item: &'a PlanItem,
    current: &'a World,
    desired: &'a World,
  },
  PlanStep {
    step: &'a Step,
    #[allow(dead_code)]
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
  RemoveUnmanaged {
    server: &'a str,
    target: &'a str,
  },
}

fn push_unique(
  dst: &mut Vec<String>,
  src: impl IntoIterator<Item = String>,
) {
  for r in src {
    if !dst.contains(&r) {
      dst.push(r);
    }
  }
}

fn format_perms(perms: &BTreeSet<Perm>) -> String {
  perms
    .iter()
    .map(|p| p.as_str())
    .collect::<Vec<_>>()
    .join(",")
}

/// 唯一判定函数：判断给定目标是否触达宿主机以及具体原因。
pub fn assess(target: HostTarget<'_>) -> HostAccess {
  match target {
    HostTarget::HostTerminal { server } => HostAccess::from_reasons(
      vec![format!("打开服务器 {server} 的宿主机终端")],
      true,
    ),
    HostTarget::HostExec { server } => HostAccess::from_reasons(
      vec![format!("在服务器 {server} 上执行宿主机命令")],
      false,
    ),
    HostTarget::HostDir { server, action } => {
      HostAccess::from_reasons(
        vec![format!("在服务器 {server} 上{action}")],
        false,
      )
    }
    HostTarget::HostApt { server } => HostAccess::from_reasons(
      vec![format!("在服务器 {server} 上操作宿主机 apt 更新")],
      false,
    ),
    HostTarget::RemoveUnmanaged { server, target } => {
      HostAccess::from_reasons(
        vec![format!("删除服务器 {server} 上的未纳管容器 {target}")],
        false,
      )
    }
    HostTarget::Task(spec) => {
      let reasons = match &spec.how {
        TaskKind::Host { .. } => vec!["在宿主机上执行命令".into()],
        TaskKind::Container { mounts, .. } if !mounts.is_empty() => {
          mounts
            .iter()
            .map(|m| format!("容器任务挂载了宿主机路径 {m}"))
            .collect()
        }
        _ => vec![],
      };
      HostAccess::from_reasons(reasons, false)
    }
    HostTarget::PlanItem {
      item,
      current,
      desired,
    } => HostAccess::from_reasons(
      assess_plan_item(item, current, desired),
      false,
    ),
    HostTarget::PlanStep { step, desired, .. } => {
      HostAccess::from_reasons(assess_plan_step(step, desired), false)
    }
  }
}

fn assess_plan_item(
  item: &PlanItem,
  current: &World,
  desired: &World,
) -> Vec<String> {
  let mut reasons = Vec::new();
  if let Some((kind, name)) = item.address.split_once('/') {
    match kind {
      KIND_SERVER => reasons.push("修改服务器宿主机设置".into()),
      "baseline" => reasons.push("纠正服务器基线".into()),
      "docker" => reasons.push("修改 dockerd 拉镜像代理配置".into()),
      "egress" => reasons.push("修改服务器外网代理".into()),
      "network" if name.ends_with("/tailscale") => {
        reasons.push("管理宿主机 Tailscale 网络容器".into());
      }
      KIND_SERVICE if item.action != Action::Delete => {
        if let Some(row) = desired.services.get(name) {
          if let Source::Compose {
            content: Some(content),
            ..
          } = &row.spec.source
          {
            reasons.extend(compose_host_reasons(name, content));
          }
          if row.import.is_some()
            && (current.services.get(name).is_none()
              || current
                .services
                .get(name)
                .and_then(|s| s.import.as_ref())
                != row.import.as_ref()
              || item.layer == Layer::Container)
          {
            reasons.push("接管宿主机上的未纳管容器".into());
          }
        }
        if item.layer == Layer::Container
          && item.impacts.contains(&Impact::Overwrite)
        {
          reasons.push("覆盖接管宿主机上的未纳管容器".into());
        }
      }
      KIND_GATEWAY if item.layer == Layer::Config => {
        let cur_gw = current.gateways.get(name).map(|g| &g.spec);
        let des_gw = desired.gateways.get(name).map(|g| &g.spec);
        if item.action == Action::Create
          && des_gw.is_some_and(custom_gateway_image)
        {
          reasons
            .push("自定义网关镜像（网关以 host 网络运行）".into());
        } else if item.action == Action::Update
          && cur_gw.map(|g| &g.image) != des_gw.map(|g| &g.image)
        {
          reasons.push("修改网关镜像（网关以 host 网络运行）".into());
        }
        if item.action != Action::Delete
          && let Some(gw) = des_gw
        {
          for f in &gw.layer4 {
            if let Some(up) = &f.upstream
              && is_host_local_upstream(up)
              && (item.action == Action::Create
                || layer4_changed(cur_gw, f))
            {
              reasons.push(format!(
                "四层转发 {} 的上游 {} 指向宿主机本地或保留端口",
                f.listen, up
              ));
            }
          }
        }
      }
      _ => {}
    }
  }
  reasons
}

fn assess_plan_step(step: &Step, desired: &World) -> Vec<String> {
  match step {
    Step::Baseline { .. } => vec!["纠正服务器基线".into()],
    Step::DockerProxy { .. } => {
      vec!["修改 dockerd 拉镜像代理配置".into()]
    }
    Step::Egress { .. } => vec!["修改服务器外网代理".into()],
    Step::TailscaleUp { .. } => {
      vec!["启动宿主机 Tailscale 容器".into()]
    }
    Step::LinkDown { project, .. }
      if project == crate::tailscale::PROJECT =>
    {
      vec!["删除宿主机 Tailscale 容器".into()]
    }
    Step::ServiceUp { service, .. } => {
      let mut reasons = Vec::new();
      if let Some(row) = desired.services.get(service) {
        if let Source::Compose {
          content: Some(content),
          ..
        } = &row.spec.source
        {
          reasons.extend(compose_host_reasons(service, content));
        }
        if row.import.is_some() {
          reasons.push("接管宿主机上的未纳管容器".into());
        }
      }
      reasons
    }
    _ => vec![],
  }
}

fn custom_gateway_image(spec: &GatewaySpec) -> bool {
  let Some(img) = spec.image.as_deref().map(str::trim) else {
    return false;
  };
  let default = match spec.kind {
    GatewayKind::Caddy => crate::render::DEFAULT_CADDY_IMAGE,
    GatewayKind::CloudflareTunnel => {
      crate::render::DEFAULT_CLOUDFLARED_IMAGE
    }
  };
  img != default
}

/// 四层转发是否是新增或改过目标（同端口换 service/port/upstream 也算变）。
pub fn layer4_changed(
  current: Option<&GatewaySpec>,
  forward: &Layer4Forward,
) -> bool {
  !current.is_some_and(|g| g.layer4.iter().any(|old| old == forward))
}

/// 直接接口统一鉴权：按 `assess(target)` 决定是否校验 `auth.human` 和 `Perm::Admin`。
pub fn require(
  auth: &Auth,
  target: HostTarget<'_>,
) -> Result<(), AppError> {
  let access = assess(target);
  if !access.required {
    return Ok(());
  }
  if access.human_only && !auth.human {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "宿主机终端只能在页面上由人登录后打开，不能用 API token 访问",
      )
      .with_hint(
        "请在浏览器登录 Wharf 页面，进入\u{201c}服务器详情 → 终端\u{201d}打开",
      )
      .into(),
    );
  }
  if !auth.has(Perm::Admin) {
    let have = format_perms(&auth.perms);
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        format!(
          "这个操作会触达宿主机（{}），需要 admin 权限（当前 token 有：{have}）",
          access.reasons.join("、")
        ),
      )
      .with_hint(
        "请用户在页面上操作，或在页面\u{201c}设置 → CLI 与 AI 接入\u{201d}换一个有 admin 权限的 token",
      )
      .into(),
    );
  }
  Ok(())
}

/// 宿主机目录/会话/apt 开关校验：页面人工会话查 `host_terminal`，API 令牌查 `host_exec`。
pub fn check_host_switch(
  auth: &Auth,
  server: &str,
  settings: &ServerSettings,
) -> Result<(), ApiError> {
  if auth.human {
    if !settings.host_terminal {
      return Err(ApiError::new(
        ErrorCode::Forbidden,
        "没有开启宿主机访问，请到\u{201c}服务器详情 → 设置\u{201d}打开\u{201c}允许从页面打开宿主机终端\u{201d}。",
      ));
    }
  } else if !settings.host_exec {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        format!(
          "服务器 {server} 没有开启宿主机命令执行，不能用 API token 访问宿主机目录、会话或执行 apt"
        ),
      )
      .with_hint(
        "请在页面上操作，或到\u{201c}服务器详情 → 设置\u{201d}开启\u{201c}宿主机命令执行\u{201d}",
      ),
    );
  }
  Ok(())
}

/// 在 `planner::finish_plan` 中调用：把 `HostTarget::PlanItem` 与 `HostTarget::PlanStep`
/// 的判定结果写入每个 `PlanItem.host_access`（去重保序），并返回排序去重后的 `needs_admin`。
pub fn mark_plan(
  current: &World,
  desired: &World,
  items: &mut [PlanItem],
  steps: &[StepPlan],
) -> Vec<String> {
  for item in items.iter_mut() {
    let access = assess(HostTarget::PlanItem {
      item,
      current,
      desired,
    });
    push_unique(&mut item.host_access, access.reasons);
  }
  for step_plan in steps {
    let access = assess(HostTarget::PlanStep {
      step: &step_plan.step,
      current,
      desired,
    });
    if !access.required {
      continue;
    }
    for &id in &step_plan.items {
      if let Some(item) = items.iter_mut().find(|i| i.id == id) {
        push_unique(&mut item.host_access, access.reasons.clone());
      }
    }
  }
  let mut needs_admin: Vec<String> = items
    .iter()
    .filter(|i| i.needs_admin())
    .map(|i| i.address.clone())
    .collect();
  needs_admin.sort();
  needs_admin.dedup();
  needs_admin
}

/// 在 `apply::start` 中调用：校验计划是否需要 `Perm::Admin`。
/// 检查 `plan.needs_admin` 与各 `item.host_access`，并对升级前留在库里的旧计划按 `steps` 兜底检查。
pub fn require_plan_admin(
  plan: &Plan,
  steps: &[StepPlan],
  perms: &BTreeSet<Perm>,
) -> Result<(), ApiError> {
  if perms.contains(&Perm::Admin) {
    return Ok(());
  }
  let mut details: Vec<String> = plan
    .items
    .iter()
    .filter(|item| !item.host_access.is_empty())
    .map(|item| {
      format!("{}：{}", item.address, item.host_access.join("、"))
    })
    .collect();
  if details.is_empty() && !plan.needs_admin.is_empty() {
    details.extend(plan.needs_admin.iter().cloned());
  }
  if details.is_empty() {
    // 兼容升级前已落库的旧计划：按地址前缀和宿主机步骤兜底。
    for item in &plan.items {
      let reason = match item.address.split_once('/') {
        Some((KIND_SERVER, _)) => Some("修改服务器宿主机设置"),
        Some(("baseline", _)) => Some("纠正服务器基线"),
        Some(("docker", _)) => Some("修改 dockerd 拉镜像代理配置"),
        Some(("egress", _)) => Some("修改服务器外网代理"),
        Some(("network", rest)) if rest.ends_with("/tailscale") => {
          Some("管理宿主机 Tailscale 网络容器")
        }
        _ => None,
      };
      if let Some(r) = reason {
        push_unique(&mut details, [format!("{}：{r}", item.address)]);
      }
    }
    for step_plan in steps {
      let reason = match &step_plan.step {
        Step::Baseline { .. } => Some("纠正服务器基线"),
        Step::DockerProxy { .. } => {
          Some("修改 dockerd 拉镜像代理配置")
        }
        Step::Egress { .. } => Some("修改服务器外网代理"),
        Step::TailscaleUp { .. } => Some("启动宿主机 Tailscale 容器"),
        Step::LinkDown { project, .. }
          if project == crate::tailscale::PROJECT =>
        {
          Some("删除宿主机 Tailscale 容器")
        }
        _ => None,
      };
      if let Some(r) = reason {
        push_unique(&mut details, [r.to_string()]);
      }
    }
  }
  if details.is_empty() {
    return Ok(());
  }
  let total = details.len();
  let summary = if total > 5 {
    format!("{} 等 {total} 项", details[..5].join("；"))
  } else {
    details.join("；")
  };
  let have = format_perms(perms);
  Err(
    ApiError::new(
      ErrorCode::Forbidden,
      format!(
        "计划里有触达宿主机的操作，需要 admin 权限（{summary}）；当前 token 有：{have}"
      ),
    )
    .with_hint(
      "请用户在页面上执行，或在页面\u{201c}设置 → CLI 与 AI 接入\u{201d}换一个有 admin 权限的 token",
    ),
  )
}

/// 校验服务接管（adopt）的所有权与合法性。
pub fn validate_adopt(
  world: &World,
  name: &str,
  old: Option<&ServiceRow>,
  adopt: Option<&AdoptSpec>,
) -> Result<(), ApiError> {
  if old.is_some()
    && adopt.is_some()
    && adopt != old.and_then(|s| s.import.as_ref())
  {
    return Err(ApiError::invalid(format!(
      "服务 {name} 已存在，不能接管其他容器"
    )));
  }
  let Some(adopt) = adopt else {
    return Ok(());
  };
  if let Some(project) = &adopt.project {
    if project.trim().is_empty() {
      return Err(ApiError::invalid(format!(
        "服务 {name} 接管的项目名不能为空"
      )));
    }
    if project != name && crate::import_api::managed(world, project) {
      return Err(ApiError::invalid(format!(
        "项目 {project} 属于 Wharf 管理，不能被服务 {name} 接管"
      )));
    }
  }
  for c in &adopt.containers {
    let trimmed = c.trim();
    let system = trimmed.is_empty()
      || trimmed == "wharf-core"
      || trimmed == "wharf-agent"
      || trimmed.starts_with(GATEWAY_PROJECT_PREFIX)
      || trimmed.starts_with("wharf-link")
      || trimmed.starts_with(crate::tailscale::PROJECT)
      || trimmed.starts_with(crate::render::BACKUP_PROJECT)
      || trimmed
        .starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
      || trimmed
        .starts_with(wharf_api_types::agent::TRIAL_PROJECT_PREFIX);
    if system {
      return Err(ApiError::invalid(format!(
        "容器 {c} 属于 Wharf 系统组件，不能接管"
      )));
    }
  }
  Ok(())
}

fn split_upstream(up: &str) -> Option<(&str, u16)> {
  let (host, port) = up.trim().rsplit_once(':')?;
  let port = port.parse::<u16>().ok()?;
  let host =
    host.trim().trim_start_matches('[').trim_end_matches(']');
  (!host.is_empty()).then_some((host, port))
}

/// 判断四层转发上游是否指向云元数据或链路本地地址。
pub fn is_metadata_upstream(up: &str) -> bool {
  let Some((host, _)) = split_upstream(up) else {
    return false;
  };
  if host.eq_ignore_ascii_case("metadata.google.internal")
    || host.eq_ignore_ascii_case("metadata")
  {
    return true;
  }
  let Ok(ip) = host.parse::<IpAddr>() else {
    return false;
  };
  match ip {
    IpAddr::V4(v4) => v4.is_link_local(),
    IpAddr::V6(v6) => {
      (v6.segments()[0] & 0xffc0) == 0xfe80
        || v6
          == std::net::Ipv6Addr::new(
            0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
          )
        || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
    }
  }
}

/// 判断四层转发上游是否指向宿主机本地回环/未指定地址或 Wharf 保留端口。
pub fn is_host_local_upstream(up: &str) -> bool {
  let Some((host, port)) = split_upstream(up) else {
    return false;
  };
  if crate::world::is_reserved_host_port(port) {
    return true;
  }
  if host.eq_ignore_ascii_case("localhost") {
    return true;
  }
  let Ok(ip) = host.parse::<IpAddr>() else {
    return false;
  };
  match ip {
    IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
    IpAddr::V6(v6) => {
      v6.is_loopback()
        || v6.is_unspecified()
        || v6
          .to_ipv4_mapped()
          .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
    }
  }
}
