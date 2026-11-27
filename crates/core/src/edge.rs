//! 边缘应用（Cloudflare Workers / Pages）：校验、发布、绑定自定义域名、回滚、状态缓存。
//!
//! - 单文件 Worker 由控制面直接调厂商接口上传（保留面板里的变量和绑定）；
//!   wrangler 项目和 Pages 交给一台服务器的 agent，在 node 容器里执行 wrangler；
//! - 回滚用厂商自己的版本，不在 Wharf 里另存；
//! - 不再纳管时不删除厂商那边的项目，只解绑 Wharf 绑定的域名。

use std::{collections::BTreeMap, time::Duration};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, EdgeBuildJob, EdgeBuildResult, OneTimeSecret},
  spec::{EdgeAppSpec, EdgeKind, Region},
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
  for d in &spec.domains {
    if world.routes.contains_key(d) {
      return Err(ApiError::invalid(format!(
        "域名 {d} 已经是路由，不能再绑定到边缘应用 {name}"
      )));
    }
    if let Some((other, _)) =
      world.edge_domain(d).filter(|(o, _)| *o != name)
    {
      return Err(ApiError::invalid(format!(
        "域名 {d} 已经绑定到边缘应用 {other}"
      )));
    }
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

/// 同一目标的每个应用在原配置里就指向这里，才算存量冲突。
pub fn validate_owners(
  current: &World,
  desired: &World,
) -> Result<Vec<String>, ApiError> {
  use crate::edge_sync::target;

  let mut owners = BTreeMap::<_, Vec<_>>::new();
  for (name, app) in &desired.edge_apps {
    owners
      .entry(target(name, &app.spec))
      .or_default()
      .push(name);
  }
  let mut legacy = 0;
  for (project, names) in owners {
    if names.len() < 2 {
      continue;
    }
    let existing = |name: &str| {
      current
        .edge_apps
        .get(name)
        .is_some_and(|app| target(name, &app.spec) == project)
    };
    if let Some(name) =
      names.iter().copied().find(|name| !existing(name))
    {
      if let Some(other) =
        names.iter().copied().find(|name| existing(name))
      {
        return Err(
          ApiError::invalid(format!(
            "边缘应用 {name} 和 {other} 都指向厂商项目 {project}"
          ))
          .with_hint(format!(
            "换一个 --project，或改用已有的应用名 {other}"
          )),
        );
      }
      return Err(
        ApiError::invalid(format!(
          "同一批里的 {name} 和 {} 都指向厂商项目 {project}",
          names[1]
        ))
        .with_hint("换一个 --project"),
      );
    }
    legacy += 1;
  }
  // 限定服务的令牌也能生成 plan，警告里不显示厂商和应用名。
  let mut warnings = Vec::new();
  if legacy != 0 {
    warnings
      .push(format!("已有 {legacy} 个厂商项目被多个边缘应用纳管"));
  }
  Ok(warnings)
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
pub(crate) fn builder(
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

/// .mjs / .cjs 显式选格式，.js 只识别明显的导出声明。
fn is_module(
  filename: &str,
  content: &str,
) -> Result<bool, ApiError> {
  if filename.ends_with(".mjs") {
    return Ok(true);
  }
  if filename.ends_with(".cjs") {
    return Ok(false);
  }
  let content = content.trim_start_matches('\u{feff}');
  let mut uncertain_context = false;
  let mut ambiguous = false;
  for line in content.split_inclusive('\n') {
    let mut inline = "";
    if line.trim_start().starts_with("//") {
      continue;
    }
    for statement in line.split_inclusive(';') {
      if let Some(after) =
        statement.trim_start().strip_prefix("export")
      {
        let tail = after.trim_start();
        let declaration = tail.starts_with(['{', '*'])
          || (after.starts_with(char::is_whitespace)
            && [
              "default", "const", "let", "var", "function", "class",
              "async",
            ]
            .iter()
            .any(|&keyword| {
              tail.strip_prefix(keyword).is_some_and(|rest| {
                rest.is_empty()
                  || rest.starts_with(char::is_whitespace)
                  || rest.starts_with(['{', '(', '[', '\'', '"'])
              })
            }));
        if declaration || tail.starts_with("/*") || tail.is_empty() {
          // 行首也可能处在多行模板字符串或注释里。只有明显的导出才自动选模块。
          if declaration
            && !uncertain_context
            && !inline.contains(['\'', '"', '/', '`', '\\'])
          {
            return Ok(true);
          }
          ambiguous = true;
        }
      }
      inline = &line[..inline.len() + statement.len()];
    }
    uncertain_context |=
      line.contains(['`', '\\']) || line.contains("/*");
  }
  if ambiguous {
    return Err(ApiError::invalid("无法确定单文件 Worker 的脚本格式")
      .with_hint("用 --script <文件.mjs> 指定 ES Module，或用 --script <文件.cjs> 指定旧式 Service Worker"));
  }
  Ok(false)
}

// DEPLOY

/// 发布边缘应用的代码。有计划固定的 commit 就按它构建。
pub async fn deploy(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
  commit: Option<String>,
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
      modules: is_module(filename, &content)?,
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
    if src.git.as_ref().is_some_and(|g| g.user.is_some()) {
      state.hub.require_build_v2(&server)?;
    }
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
      &crate::secret_policy::non_system_secrets(&snap.secrets),
      &format!("边缘应用 {name}"),
      src.upload.as_ref(),
      src.git.as_ref(),
      commit,
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
        last_deployed_at: v.last_deployed_at,
        source: v.source,
        message: v.message,
        active: v.active,
        url: v.url,
      })
      .collect(),
  )
}

/// 默认选最近一次承载过流量、现在已下线的版本。
pub fn rollback_target(
  name: &str,
  versions: &[EdgeVersionView],
  to: Option<&str>,
) -> Result<String, ApiError> {
  let list = format!("wharf edge versions {name}");
  if let Some(raw) = to {
    let to = raw.trim();
    if to.is_empty() {
      return Err(ApiError::invalid("版本号不能为空").suggest(list));
    }
    if let Some(exact) = versions.iter().find(|v| v.id == to) {
      return Ok(exact.id.clone());
    }
    let matches: Vec<_> =
      versions.iter().filter(|v| v.id.starts_with(to)).collect();
    return match matches.as_slice() {
      [] => Err(
        ApiError::not_found(format!("没有版本 {to}")).suggest(list),
      ),
      [v] => Ok(v.id.clone()),
      _ => Err(
        ApiError::invalid(format!(
          "前缀 {to} 匹配到多个版本（{}），请多写几位",
          matches.len()
        ))
        .suggest(list),
      ),
    };
  }
  if let Some(version) = versions
    .iter()
    .rev()
    .filter(|v| !v.active)
    .filter_map(|v| v.last_deployed_at.as_ref().map(|time| (time, v)))
    .max_by_key(|(time, _)| *time)
    .map(|(_, v)| v)
  {
    return Ok(version.id.clone());
  }
  let error = if versions.iter().filter(|v| v.active).count() > 1 {
    ApiError::invalid(
      "当前有多个线上灰度版本，没有更早的已上线版本可自动回滚",
    )
    .with_hint(format!("用 --to 指定目标版本，先运行 {list}"))
  } else if versions.iter().any(|v| !v.active) {
    ApiError::invalid("没有曾经上线过的旧版本可以自动回滚").with_hint(
      format!(
        "如需切换到未上线版本，请用 --to 明确指定；查看列表：{list}"
      ),
    )
  } else {
    ApiError::invalid("没有更早的版本可以回滚")
  };
  Err(error.suggest(list))
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
  let short: String = version.chars().take(8).collect();
  progress(format!("切换到版本 {short}"));
  let confirmed = with_timeout(
    &format!("回滚 {name}"),
    provider.rollback(
      provider_kind(spec.kind),
      spec.project_name(name),
      version,
    ),
  )
  .await?;
  complete_rollback(state, name, spec, confirmed, progress).await
}

async fn complete_rollback(
  state: &AppState,
  name: &str,
  spec: &EdgeAppSpec,
  confirmed: String,
  progress: &ProgressFn,
) -> Result<(), ApiError> {
  let short: String = confirmed.chars().take(8).collect();
  let expected = db::EdgeExpected {
    target: crate::edge_sync::target(name, spec),
    versions: confirmed,
  };
  let app = name.to_string();
  state.db.call(move |c| db::put_edge_expected(c, &app, &expected)).await.map_err(|e| {
    let accept = format!("wharf edge accept {name}");
    ApiError::internal(format!("远端 {name} 已切换到版本 {short}，但写入本地期望版本失败：{}", e.message))
      .with_hint(format!("运行 {accept} 将线上版本同步为期望版本")).suggest(accept)
  })?;
  if let Err(e) =
    crate::edge_sync::refresh_after_rollback(state, name).await
  {
    progress(format!(
      "提醒：远端回滚已生效并已记录期望版本，刷新线上状态失败（{}），稍后会自动同步",
      e.message
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn v(
    id: &str,
    active: bool,
    deployed: Option<&str>,
  ) -> EdgeVersionView {
    EdgeVersionView {
      id: id.into(),
      created_at: String::new(),
      last_deployed_at: deployed.map(str::to_string),
      source: None,
      message: None,
      active,
      url: None,
    }
  }

  #[test]
  fn rollback_target_picks_last_deployed_and_validates_prefix() {
    let list = [
      v("ab11", true, Some("t3")),
      v("ab22", true, Some("t3")),
      v("uploaded", false, None),
      v("earlier", false, Some("t1")),
      v("latest", false, Some("t2")),
    ];
    assert_eq!(rollback_target("w", &list, None).unwrap(), "latest");
    assert_eq!(
      rollback_target("w", &list, Some(" up ")).unwrap(),
      "uploaded"
    );
    assert_eq!(
      rollback_target("w", &list, Some("ab11")).unwrap(),
      "ab11"
    );
    for bad in [" ", "ab"] {
      assert_eq!(
        rollback_target("w", &list, Some(bad)).unwrap_err().code,
        wharf_api_types::ErrorCode::InvalidInput
      );
    }
    assert!(rollback_target("w", &list[..3], None).is_err());
  }

  #[tokio::test]
  async fn rollback_persists_expected_before_sync_readback() {
    let state = crate::rules::tests::test_state();
    let spec: EdgeAppSpec =
      serde_json::from_value(serde_json::json!({
        "kind":"worker", "account":"cf"
      }))
      .unwrap();
    let lines =
      std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = lines.clone();
    let progress: ProgressFn = std::sync::Arc::new(move |line| {
      output.lock().unwrap().push(line)
    });
    complete_rollback(
      &state,
      "w",
      &spec,
      "confirmed".into(),
      &progress,
    )
    .await
    .unwrap();
    assert!(lines.lock().unwrap()[0].contains("刷新线上状态失败"));
    let expected =
      state.db.call(|c| db::edge_expected(c)).await.unwrap();
    assert_eq!(expected["w"].versions, "confirmed");
  }

  #[test]
  fn detects_module_workers() {
    assert!(
      is_module("worker.js", "export default { fetch() {} }")
        .unwrap()
    );
    assert!(
      !is_module("worker.js", "addEventListener('fetch', e => {})")
        .unwrap()
    );
  }
}

#[cfg(test)]
mod module_tests {
  use super::is_module;

  #[test]
  fn recognizes_top_level_exports_only() {
    for src in [
      "export{h as default}",
      "export const x=1",
      "let x=1\nexport*from'./dep.js'",
      "function h(){};export{h as default}",
    ] {
      assert!(is_module("worker.js", src).unwrap(), "{src}");
    }
    for src in [
      "// export default\naddEventListener()",
      "const s=\"export default\";addEventListener()",
      "const s=/[;}export default]/",
      "let x=`a ${{v:`b ${1}`}} export default`",
    ] {
      assert!(!is_module("worker.js", src).unwrap(), "{src}");
    }
  }

  #[test]
  fn detects_exports_after_postfix_division_or_requires_explicit_format()
   {
    let script = "let i = 1; const x = i++ / 2; export default { fetch() { return new Response(String(x)); } };";
    let multiline = script.replace("; export", ";\nexport");
    assert!(is_module("worker.js", &multiline).unwrap());
    assert!(is_module("worker.js", script).is_err());
    assert!(is_module("worker.mjs", script).unwrap());
    let literal = "const text = `\nexport default {}\n`; addEventListener('fetch', f);";
    assert!(is_module("worker.js", literal).is_err());
    assert!(!is_module("worker.cjs", literal).unwrap());
  }
}
