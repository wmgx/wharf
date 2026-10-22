//! 边缘应用（Cloudflare Workers / Pages）：校验、发布、绑定自定义域名、回滚、状态缓存。
//!
//! - 单文件 Worker 由控制面直接调厂商接口上传（保留面板里的变量和绑定）；
//!   wrangler 项目和 Pages 交给一台服务器的 agent，在 node 容器里执行 wrangler；
//! - 回滚用厂商自己的版本，不在 Wharf 里另存；
//! - 不再纳管时不删除厂商那边的项目，只解绑 Wharf 绑定的域名。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, EdgeBuildJob, EdgeBuildResult, OneTimeSecret},
  spec::{EdgeAppSpec, EdgeKind, Region, RouteSpec},
  validate_name,
  view::EdgeVersionView,
};
use wharf_providers::WorkerScript;

use crate::{
  db::{self, AccountRow, EdgeDomainRow},
  hub::ProgressFn,
  snapshot::{self, Snapshot, with_timeout},
  state::AppState,
  world::{World, check_code_source, server_not_found},
};

/// wrangler 安装依赖、构建、上传都算在内。
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(40 * 60);

pub fn provider_kind(kind: EdgeKind) -> wharf_providers::EdgeKind {
  match kind {
    EdgeKind::Worker => wharf_providers::EdgeKind::Worker,
    EdgeKind::Pages => wharf_providers::EdgeKind::Pages,
  }
}

pub fn parse_kind(kind: &str) -> Option<EdgeKind> {
  match kind {
    "worker" => Some(EdgeKind::Worker),
    "pages" => Some(EdgeKind::Pages),
    _ => None,
  }
}

// VALIDATE

pub fn validate_app(
  world: &World,
  name: &str,
  spec: &EdgeAppSpec,
) -> Result<(), ApiError> {
  validate_name("边缘应用", name)?;
  if world.services.contains_key(name) {
    return Err(ApiError::invalid(format!(
      "名字 {name} 已经被服务使用，边缘应用和服务共用名字"
    )));
  }
  let project = spec.project_name(name);
  if project.is_empty()
    || project.len() > 63
    || !project.bytes().all(|c| {
      c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
    })
  {
    return Err(ApiError::invalid(format!(
      "边缘应用 {name} 的项目名 {project} 不合法：只能用小写字母、数字和 -"
    )));
  }
  if let Some(builder) = &spec.builder
    && !world.servers.contains_key(builder)
  {
    return Err(server_not_found(builder));
  }
  let Some(src) = &spec.source else {
    return Ok(());
  };
  let what = format!("边缘应用 {name}");
  check_code_source(
    &what,
    src.upload.as_ref(),
    src.git.as_ref(),
    &[&src.path, &src.script, &src.output],
  )?;
  match spec.kind {
    EdgeKind::Worker => {
      if src.build.is_some() || src.output.is_some() {
        return Err(ApiError::invalid(format!(
          "{what}：build、output 只用于 Pages"
        )));
      }
      if src.script.is_some() && src.git.is_some() {
        return Err(
          ApiError::invalid(format!(
            "{what}：单文件 Worker 要从本机上传"
          ))
          .with_hint("git 仓库请用 wrangler 项目（带 wrangler.toml），或用 wharf edge deploy --script 上传本机文件"),
        );
      }
    }
    EdgeKind::Pages => {
      if src.script.is_some() {
        return Err(ApiError::invalid(format!(
          "{what}：script 只用于 Worker"
        )));
      }
    }
  }
  if src.build.as_deref().is_some_and(|b| b.trim().is_empty()) {
    return Err(ApiError::invalid(format!("{what} 的构建命令为空")));
  }
  Ok(())
}

pub fn validate_route(
  host: &str,
  spec: &RouteSpec,
) -> Result<(), ApiError> {
  if spec.port.is_some()
    || spec.gateway.is_some()
    || !spec.paths.is_empty()
  {
    return Err(ApiError::invalid(format!(
      "路由 {host} 指向边缘应用，不经过网关，不能指定端口、网关或路径转发"
    )));
  }
  if spec.auth {
    return Err(ApiError::invalid(format!(
      "路由 {host}：边缘应用的域名暂不支持登录保护"
    )));
  }
  Ok(())
}

// HELPERS

pub fn account<'a>(
  snap: &'a Snapshot,
  name: &str,
) -> Result<&'a AccountRow, ApiError> {
  snap
    .accounts
    .iter()
    .find(|a| a.name == name)
    .ok_or_else(|| {
      ApiError::invalid(format!("厂商账号 {name} 不存在"))
        .suggest("wharf account list")
    })
}

fn app<'a>(
  snap: &'a Snapshot,
  name: &str,
) -> Result<&'a EdgeAppSpec, ApiError> {
  snap
    .world
    .edge_apps
    .get(name)
    .map(|r| &r.spec)
    .ok_or_else(|| edge_not_found(name))
}

pub fn edge_not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("边缘应用 {name} 不存在"))
    .suggest("wharf edge list")
}

/// 执行 wrangler 的服务器：指定的，或在线的海外服务器，或任一在线服务器。
fn builder(
  state: &AppState,
  snap: &Snapshot,
  spec: &EdgeAppSpec,
) -> Result<String, ApiError> {
  if let Some(b) = &spec.builder {
    return Ok(b.clone());
  }
  let online: Vec<&String> = snap
    .world
    .servers
    .keys()
    .filter(|s| state.hub.is_online(s))
    .collect();
  let overseas = online.iter().find(|s| {
    snap.world.servers[s.as_str()].settings.region
      == Some(Region::Overseas)
  });
  overseas
    .or(online.first())
    .map(|s| s.to_string())
    .ok_or_else(|| {
      ApiError::invalid("没有在线的服务器可以执行 wrangler")
        .with_hint("发布 Pages 和 wrangler 项目要在一台服务器上执行")
    })
}

/// 单文件脚本是不是 ES Module 格式。
fn is_module(content: &str) -> bool {
  content.contains("export default") || content.contains("export {")
}

// DEPLOY

/// 发布边缘应用的代码。`force`：git 来源也拉最新（发布本来就总是取最新）。
pub async fn deploy(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let spec = app(snap, name)?;
  let Some(src) = &spec.source else {
    return Err(
      ApiError::invalid(format!(
        "边缘应用 {name} 只纳管，没有代码来源"
      ))
      .suggest(format!("wharf edge deploy {name} --script <文件>")),
    );
  };
  let account = account(snap, &spec.account)?;
  let provider = snapshot::edge_provider(account)?;
  let project = spec.project_name(name);

  if let (EdgeKind::Worker, Some(script), Some(sha)) =
    (spec.kind, &src.script, &src.upload)
  {
    let path = match &src.path {
      Some(p) => format!("{}/{script}", p.trim_end_matches('/')),
      None => script.clone(),
    };
    let content = crate::uploads::read_file(state, sha, &path)?;
    let filename = path.rsplit('/').next().unwrap_or("worker.js");
    progress(format!(
      "上传 {filename} 到 Worker {project}（保留面板里的变量和绑定）"
    ));
    let script = WorkerScript {
      filename: filename.to_string(),
      modules: is_module(&content),
      content,
    };
    with_timeout(
      &format!("上传 Worker {project}"),
      provider.upload_worker(project, &script),
    )
    .await?;
    progress(format!("已发布 Worker {project}"));
  } else {
    let server = builder(state, snap, spec)?;
    let branch = match spec.kind {
      EdgeKind::Pages => {
        let p = with_timeout(
          &format!("准备 Pages 项目 {project}"),
          provider.ensure_pages(project),
        )
        .await?;
        p.production_branch
      }
      EdgeKind::Worker => None,
    };
    let account_id =
      with_timeout("读取 Cloudflare 账户", provider.account_id())
        .await?;
    let fetch = crate::build::code_fetch(
      state,
      snap,
      &format!("边缘应用 {name}"),
      src.upload.as_ref(),
      src.git.as_ref(),
      None,
    )?;
    let server_row = &snap.world.servers[&server];
    progress(format!("在 {server} 上执行 wrangler"));
    let result: EdgeBuildResult = state
      .hub
      .call(
        &server,
        AgentOp::EdgeBuild(Box::new(EdgeBuildJob {
          app: name.to_string(),
          kind: spec.kind,
          project: project.to_string(),
          fetch,
          path: src.path.clone(),
          build: src.build.clone(),
          output: src.output.clone(),
          branch,
          account_id,
          api_token: OneTimeSecret(account.token.clone()),
          build_env: server_row.settings.build_env.clone(),
          pull: snapshot::pull_policy(server_row),
        })),
        DEPLOY_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await?;
    if let Some(commit) = result.commit {
      progress(format!(
        "发布的 commit {}",
        &commit[..12.min(commit.len())]
      ));
    }
  }
  crate::edge_sync::after_change(state, name).await;
  Ok(())
}

// DOMAINS

pub async fn attach_domain(
  state: &AppState,
  snap: &Snapshot,
  hostname: &str,
  name: &str,
  takeover: bool,
) -> Result<(), ApiError> {
  let spec = app(snap, name)?;
  let account = account(snap, &spec.account)?;
  let provider = snapshot::edge_provider(account)?;
  let project = spec.project_name(name);
  with_timeout(
    &format!("绑定 {hostname}"),
    provider.attach_domain(
      provider_kind(spec.kind),
      project,
      hostname,
      takeover,
    ),
  )
  .await?;
  let row = EdgeDomainRow {
    hostname: hostname.to_string(),
    app: name.to_string(),
    account: account.name.clone(),
    kind: spec.kind.as_str().to_string(),
    project: project.to_string(),
  };
  state.db.call(move |c| db::put_edge_domain(c, &row)).await
}

pub async fn detach_domain(
  state: &AppState,
  snap: &Snapshot,
  row: &EdgeDomainRow,
) -> Result<(), ApiError> {
  let kind = parse_kind(&row.kind).ok_or_else(|| {
    ApiError::internal(format!("未知的边缘应用类型 {}", row.kind))
  })?;
  let account = account(snap, &row.account)?;
  let provider = snapshot::edge_provider(account)?;
  with_timeout(
    &format!("解绑 {}", row.hostname),
    provider.detach_domain(
      provider_kind(kind),
      &row.project,
      &row.hostname,
    ),
  )
  .await?;
  let host = row.hostname.clone();
  state
    .db
    .call(move |c| db::delete_edge_domain(c, &host))
    .await
}

// VERSIONS

pub async fn versions(
  snap: &Snapshot,
  name: &str,
) -> Result<Vec<EdgeVersionView>, ApiError> {
  let spec = app(snap, name)?;
  let provider =
    snapshot::edge_provider(account(snap, &spec.account)?)?;
  let list = with_timeout(
    &format!("读取 {name} 的版本"),
    provider
      .versions(provider_kind(spec.kind), spec.project_name(name)),
  )
  .await?;
  Ok(
    list
      .into_iter()
      .map(|v| EdgeVersionView {
        id: v.id,
        created_at: v.created_at,
        source: v.source,
        message: v.message,
        active: v.active,
        url: v.url,
      })
      .collect(),
  )
}

/// 回滚目标：指定的版本，或线上版本之后（更旧）的第一个。
pub fn rollback_target(
  versions: &[EdgeVersionView],
  to: Option<&str>,
) -> Result<String, ApiError> {
  if let Some(to) = to {
    let found = versions
      .iter()
      .find(|v| v.id == to || v.id.starts_with(to))
      .ok_or_else(|| {
        ApiError::not_found(format!("没有版本 {to}"))
          .suggest("wharf edge versions <名字>")
      })?;
    return Ok(found.id.clone());
  }
  let active = versions.iter().position(|v| v.active).unwrap_or(0);
  versions
    .get(active + 1)
    .map(|v| v.id.clone())
    .ok_or_else(|| ApiError::invalid("没有更早的版本可以回滚"))
}

pub async fn rollback(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
  version: &str,
  progress: &ProgressFn,
) -> Result<(), ApiError> {
  let spec = app(snap, name)?;
  let provider =
    snapshot::edge_provider(account(snap, &spec.account)?)?;
  progress(format!(
    "切换到版本 {}",
    &version[..8.min(version.len())]
  ));
  with_timeout(
    &format!("回滚 {name}"),
    provider.rollback(
      provider_kind(spec.kind),
      spec.project_name(name),
      version,
    ),
  )
  .await?;
  crate::edge_sync::after_change(state, name).await;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn v(id: &str, active: bool) -> EdgeVersionView {
    EdgeVersionView {
      id: id.into(),
      created_at: String::new(),
      source: None,
      message: None,
      active,
      url: None,
    }
  }

  #[test]
  fn rollback_goes_to_the_version_before_active() {
    let list = [v("c", false), v("b", true), v("a", false)];
    assert_eq!(rollback_target(&list, None).unwrap(), "a");
    assert_eq!(rollback_target(&list, Some("c")).unwrap(), "c");
    assert!(rollback_target(&[v("a", true)], None).is_err());
  }

  #[test]
  fn detects_module_workers() {
    assert!(is_module("export default { fetch() {} }"));
    assert!(!is_module("addEventListener('fetch', e => {})"));
  }
}
