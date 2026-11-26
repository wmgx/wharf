use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Layer, Plan},
  spec::ServerSettings,
  view::Perm,
};

use super::{
  HostTarget, assess, host_address_reason, require_legacy_replan,
  step_reason,
};
use crate::{
  api::AppError,
  auth::Auth,
  planner::StepPlan,
  world::{World, server_not_found},
};

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum HostCap {
  HostTerminal,
  HostExec,
  HostDocker,
  HostSystem,
}

impl HostCap {
  pub fn field(self) -> &'static str {
    match self {
      Self::HostTerminal => "host_terminal",
      Self::HostExec => "host_exec",
      Self::HostDocker => "host_docker",
      Self::HostSystem => "host_system",
    }
  }

  pub fn label(self) -> &'static str {
    match self {
      Self::HostTerminal => "宿主机终端",
      Self::HostExec => "宿主机命令",
      Self::HostDocker => "特权与未纳管容器",
      Self::HostSystem => "宿主机系统配置",
    }
  }

  pub fn enabled(self, s: &ServerSettings) -> bool {
    match self {
      Self::HostTerminal => s.host_terminal,
      Self::HostExec => s.host_exec,
      Self::HostDocker => s.host_docker,
      Self::HostSystem => s.host_system,
    }
  }
}

/// 随计划保存在 `plans.body` 中的结构化宿主机能力需求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRequirement {
  pub address: String,
  pub server: String,
  pub cap: HostCap,
  pub reason: String,
}

pub fn opened_switch(
  before: Option<&ServerSettings>,
  after: &ServerSettings,
) -> Option<&'static str> {
  [
    HostCap::HostTerminal,
    HostCap::HostExec,
    HostCap::HostDocker,
    HostCap::HostSystem,
  ]
  .into_iter()
  .find(|&cap| {
    cap.enabled(after) && !before.is_some_and(|s| cap.enabled(s))
  })
  .map(HostCap::label)
}

fn have(perms: &BTreeSet<Perm>) -> String {
  perms
    .iter()
    .map(|p| p.as_str())
    .collect::<Vec<_>>()
    .join(",")
}

fn require_core_admin(
  perms: &BTreeSet<Perm>,
  server: &str,
  core_server: Option<&str>,
  reason: &str,
) -> Result<(), ApiError> {
  if perms.contains(&Perm::Admin) {
    return Ok(());
  }
  match core_server {
    None => Err(ApiError::new(ErrorCode::Forbidden, format!("无法确认控制面所在服务器，为防止提权到控制面，触达宿主机的操作（{reason}）需要 admin 权限（当前 token 有：{}）", have(perms)))
      .with_hint("确认控制面与本机 agent 已上报相同网卡地址，或换一个同时有 host 和 admin 权限的 token")),
    Some(core) if core == server => Err(ApiError::new(ErrorCode::Forbidden, format!("服务器 {server} 是控制面所在机器，触达宿主机（{reason}）还需要 admin 权限（当前 token 有：{}）", have(perms)))
      .with_hint("请用户在页面上操作，或换一个同时有 host 和 admin 权限的 token")),
    Some(_) => Ok(()),
  }
}

fn require_enabled(
  cap: HostCap,
  server: &str,
  settings: Option<&ServerSettings>,
  reason: &str,
) -> Result<(), ApiError> {
  let settings = settings.ok_or_else(|| server_not_found(server))?;
  if !cap.enabled(settings) {
    return Err(ApiError::new(ErrorCode::Forbidden, format!("服务器 {server} 没有开启{}（{}），不能通过 API 令牌执行该操作（{reason}）", cap.label(), cap.field()))
      .with_hint(format!("请用户在页面“服务器详情 → {server} → 设置 → 权限”开启“{}”", cap.label())));
  }
  Ok(())
}

pub fn require_with(
  auth: &Auth,
  target: HostTarget<'_>,
  settings: Option<&ServerSettings>,
  core_server: Option<&str>,
) -> Result<(), AppError> {
  let access = assess(target);
  if access.human_only && !auth.human {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "宿主机终端只能在页面上由人登录后打开，不能用 API token 访问",
      )
      .with_hint(
        "请在浏览器登录 Wharf 页面，进入“服务器详情 → 终端”打开",
      )
      .into(),
    );
  }
  if !access.required || auth.human {
    return Ok(());
  }
  let reason = access.reasons.join("、");
  if !auth.has(Perm::Host) {
    return Err(ApiError::new(ErrorCode::Forbidden, format!("这个操作会触达宿主机（{reason}），需要 host 权限（当前 token 有：{}）", have(&auth.perms)))
      .with_hint("请用户在页面上操作，或在页面“设置 → CLI 与 AI 接入”换一个有 host 权限的 token").into());
  }
  let (Some(server), Some(cap)) = (access.server, access.cap) else {
    return Err(
      ApiError::internal("宿主机操作缺少目标服务器或能力").into(),
    );
  };
  require_core_admin(&auth.perms, &server, core_server, &reason)?;
  require_enabled(cap, &server, settings, &reason)?;
  Ok(())
}

pub fn require_plan_host(
  plan: &Plan,
  steps: &[StepPlan],
  requirements: Option<&[HostRequirement]>,
  perms: &BTreeSet<Perm>,
  human: bool,
  current: &World,
  core_server: Option<&str>,
) -> Result<(), ApiError> {
  let Some(reqs) = requirements else {
    if !plan.needs_host.is_empty()
      || plan.items.iter().any(|item| {
        item.needs_host()
          || host_address_reason(&item.address).is_some()
      })
      || steps.iter().any(|step| step_reason(&step.step).is_some())
    {
      return Err(
        ApiError::new(
          ErrorCode::PlanStale,
          "计划生成于宿主机权限校验更新之前，需要重新 plan",
        )
        .suggest("wharf plan"),
      );
    }
    return require_legacy_replan(plan, steps);
  };
  if human {
    return Ok(());
  }
  for item in &plan.items {
    if item.layer == Layer::Config
      && let Some(name) = item.address.strip_prefix("server/")
      && let Some(after) = &item.after
    {
      let after: ServerSettings =
        serde_json::from_value(after.clone())
          .map_err(crate::db::json_err)?;
      let before = current.servers.get(name).map(|row| &row.settings);
      if let Some(what) = opened_switch(before, &after) {
        return Err(ApiError::new(
          ErrorCode::Forbidden,
          format!("不能用 API token 打开 {name} 的{what}，只能关"),
        ));
      }
    }
  }
  if !(perms.contains(&Perm::Host) && perms.contains(&Perm::Admin))
    && let Some(address) = plan
      .needs_host
      .iter()
      .chain(
        plan
          .items
          .iter()
          .filter(|item| item.needs_host())
          .map(|item| &item.address),
      )
      .find(|&address| {
        !reqs.iter().any(|req| &req.address == address)
      })
  {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      format!(
        "计划项 {address} 触达宿主机但没能确定目标服务器，需要 host 和 admin 权限"
      ),
    ));
  }
  if reqs.is_empty() {
    return Ok(());
  }
  if !perms.contains(&Perm::Host) {
    let mut details: Vec<_> = reqs
      .iter()
      .take(5)
      .map(|req| format!("{}：{}", req.address, req.reason))
      .collect();
    if reqs.len() > 5 {
      details.push(format!("等 {} 项", reqs.len()));
    }
    return Err(ApiError::new(ErrorCode::Forbidden, format!("计划里有触达宿主机的操作，需要 host 权限（{}）；当前 token 有：{}", details.join("、"), have(perms)))
      .with_hint("请用户在页面上执行，或在页面“设置 → CLI 与 AI 接入”换一个有 host 权限的 token"));
  }
  for req in reqs {
    let reason = format!("{}：{}", req.address, req.reason);
    require_core_admin(perms, &req.server, core_server, &reason)?;
    let settings =
      current.servers.get(&req.server).map(|row| &row.settings);
    require_enabled(req.cap, &req.server, settings, &reason)?;
  }
  Ok(())
}

pub const MIGRATION: &str = r#"
UPDATE api_tokens
SET scope = trim(replace(',' || replace(scope, ' ', '') || ',', ',admin,', ',host,admin,'), ',')
WHERE (',' || replace(scope, ' ', '') || ',') LIKE '%,admin,%'
  AND (',' || replace(scope, ' ', '') || ',') NOT LIKE '%,host,%';

UPDATE resources
SET spec = json_set(COALESCE(NULLIF(spec, ''), '{}'), '$.host_docker', json('true'))
WHERE kind = 'server' AND json_type(spec, '$.host_docker') IS NULL;

UPDATE resources
SET spec = json_set(COALESCE(NULLIF(spec, ''), '{}'), '$.host_system', json('true'))
WHERE kind = 'server' AND json_type(spec, '$.host_system') IS NULL;
"#;
