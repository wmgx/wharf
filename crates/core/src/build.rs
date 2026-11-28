//! 构建来源的服务：部署前让服务所在的 agent 构建镜像。
//!
//! - 镜像名带构建配置的指纹，配置不变、镜像已在就跳过（普通部署、改环境变量）；
//! - "重新构建"（`force`）拉 ref 的最新代码；
//! - 不是 force 时，git 来源固定到上次部署的 commit（迁移到新机器时构建出同样的代码）。

use std::{path::Path, time::Duration};

use rusqlite::{OptionalExtension, params};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BuildFetch, BuildJob, BuildResult, OneTimeSecret,
    ResolveCommit,
  },
  build::{GIT_CREDENTIAL_HELPER, git_no_proxy},
  spec::{BuildSource, GitSource, ServiceSpec, Source},
};

use crate::{
  db::sql_err,
  hub::ProgressFn,
  render,
  snapshot::{self, Snapshot},
  state::AppState,
};

pub(crate) fn old_git_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!(
      "服务器 {server} 的 agent 版本旧，不支持自定义 Git 认证用户名"
    ),
  )
  .suggest("wharf upgrade")
}

pub(crate) fn old_agent_warning(server: &str) -> String {
  format!(
    "服务器 {server} 的 agent 版本旧，不包含子模块拉取、大锁文件、新模板与旧镜像回收修复，建议先运行 wharf upgrade"
  )
}

/// 计划只查 Git 引用。旧 agent 的查询可能拉镜像，因此在控制面做只读回退。
pub(crate) async fn plan_commit(
  state: &AppState,
  server: &str,
  job: ResolveCommit,
) -> Result<String, ApiError> {
  if let Some(conn) = state.hub.build_v2_conn_id(server) {
    return state
      .hub
      .call_bound(
        (server, conn),
        AgentOp::ResolveCommit(job),
        crate::pins::COMMIT_TIMEOUT,
        None,
        &Default::default(),
      )
      .await;
  }
  if !state.hub.is_online(server) {
    return Err(crate::hub::offline(server));
  }

  let BuildFetch::Git {
    repo,
    reference,
    token,
    user,
    ..
  } = &job.fetch
  else {
    return Err(ApiError::invalid("只有 git 来源能查 commit"));
  };
  if user.is_some() {
    return Err(old_git_agent(server));
  }
  if wharf_api_types::build::is_commit(reference) {
    return Ok(reference.to_ascii_lowercase());
  }
  let url = reqwest::Url::parse(repo)
    .map_err(|_| ApiError::invalid("Git 仓库地址不合法"))?;
  let mut args = vec!["-c", "http.followRedirects=initial"];
  let mut env = Vec::new();
  let config;
  let mirrored;
  let repo = if let Some(token) = token {
    let git_user = match url.host_str() {
      Some("bitbucket.org") => "x-token-auth",
      Some(host) if host.contains("gitlab") => "oauth2",
      _ => "x-access-token",
    };
    config = format!(
      "credential.{}/.helper={GIT_CREDENTIAL_HELPER}",
      url.origin().ascii_serialization()
    );
    args.extend(["-c", config.as_str()]);
    env.extend([
      ("GIT_USER", git_user),
      ("GIT_TOKEN", token.0.as_str()),
    ]);
    repo.as_str()
  } else if let Some((path, mirror)) = repo
    .strip_prefix("https://github.com/")
    .zip(job.pull.github_mirror.as_deref())
    && mirror.starts_with("https://")
  {
    mirrored = format!("{}/{path}", mirror.trim_end_matches('/'));
    mirrored.as_str()
  } else {
    repo.as_str()
  };
  let peeled = format!("{reference}^{{}}");
  args.extend(["ls-remote", "--", repo, reference, &peeled]);
  let mirror = job
    .pull
    .github_mirror
    .as_deref()
    .and_then(|mirror| reqwest::Url::parse(mirror).ok());
  let no_proxy =
    git_no_proxy(mirror.as_ref().and_then(reqwest::Url::host_str));
  env.extend([
    ("NO_PROXY", no_proxy.as_str()),
    ("no_proxy", no_proxy.as_str()),
  ]);
  let bytes =
    tokio::time::timeout(crate::pins::COMMIT_TIMEOUT, async {
      let proxy =
        reachable_git_proxy(job.pull.git_proxy.as_deref()).await;
      crate::secret_leak::git_with_env(
        Path::new("/"),
        proxy,
        &args,
        &env,
      )
      .await
    })
    .await
    .map_err(|_| {
      ApiError::new(ErrorCode::Timeout, "查询 Git 代码版本超时")
    })?
    .map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("控制面查询 Git 代码版本：{e}"),
      )
    })?;
  wharf_api_types::build::pick_commit(
    &String::from_utf8_lossy(&bytes),
    reference,
  )
  .ok_or_else(|| {
    ApiError::invalid(format!("仓库里没有分支或标签 {reference}"))
  })
}

/// 目标机的环回代理只在目标机上有效。其他代理从控制面探测，连不上走直连。
async fn reachable_git_proxy(proxy: Option<&str>) -> &str {
  let Some(proxy) = proxy.map(str::trim) else {
    return "";
  };
  let Ok(url) = reqwest::Url::parse(proxy) else {
    return "";
  };
  let Some(host) = url.host_str() else {
    return "";
  };
  let host = host.trim_matches(['[', ']']).trim_end_matches('.');
  let ip = host
    .parse::<std::net::IpAddr>()
    .ok()
    .map(|ip| ip.to_canonical());
  if host.eq_ignore_ascii_case("localhost")
    || host.to_ascii_lowercase().ends_with(".localhost")
    || ip.is_some_and(|ip| ip.is_loopback() || ip.is_unspecified())
  {
    return "";
  }
  let Some(port) = url.port_or_known_default() else {
    return "";
  };
  if tokio::time::timeout(
    Duration::from_secs(3),
    tokio::net::TcpStream::connect((host, port)),
  )
  .await
  .is_ok_and(|result| result.is_ok())
  {
    proxy
  } else {
    ""
  }
}

/// 拉代码、拉基础镜像、构建都算在内。
const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// 上次部署这个服务时构建的 commit，只在构建配置没变时有意义。
async fn last_commit(
  state: &AppState,
  service: &str,
  instance_id: &str,
  build: &BuildSource,
) -> Result<Option<String>, ApiError> {
  let s = service.to_string();
  let instance_id = instance_id.to_string();
  let row: Option<(Option<String>, String)> = state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT spec, commit_sha FROM deployments
         WHERE service = ?1 AND instance_id = ?2 AND commit_sha IS NOT NULL ORDER BY id DESC LIMIT 1",
        params![s, instance_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
      )
      .optional()
      .map_err(sql_err)
    })
    .await?;
  Ok(row.and_then(|(spec, commit)| {
    let spec: ServiceSpec = serde_json::from_str(&spec?).ok()?;
    match spec.source {
      Source::Build(b) if &b == build => Some(commit),
      _ => None,
    }
  }))
}

/// 告诉 agent 怎么取代码：本机上传的包（签发一次性下载口令）或 git 仓库。
/// `reference`：覆盖 git 的 ref（固定到某个 commit）。
pub fn code_fetch(
  state: &AppState,
  allowed_secrets: &std::collections::BTreeMap<String, String>,
  what: &str,
  upload: Option<&String>,
  git: Option<&GitSource>,
  reference: Option<String>,
) -> Result<BuildFetch, ApiError> {
  match (upload, git) {
    (Some(sha), _) => {
      if !crate::uploads::exists(state, sha) {
        return Err(
          ApiError::invalid(format!(
            "{what} 的代码包 {} 不在控制面上（可能已被清理）",
            &sha[..12]
          ))
          .with_hint(
            "重新执行 wharf deploy / wharf edge deploy 上传代码",
          ),
        );
      }
      Ok(BuildFetch::Upload {
        sha256: sha.clone(),
        token: OneTimeSecret(state.downloads.issue(sha)),
      })
    }
    (None, Some(git)) => {
      let token = match &git.token_secret {
        Some(name) => {
          crate::secret_policy::reject_system_secret(name, what)?;
          Some(OneTimeSecret(
            allowed_secrets.get(name).cloned().ok_or_else(|| {
              ApiError::invalid(format!("密钥 {name} 不存在"))
                .suggest(format!("wharf secret set {name}"))
            })?,
          ))
        }
        None => None,
      };
      Ok(BuildFetch::Git {
        repo: git.repo.clone(),
        fallback_ref: reference
          .as_ref()
          .filter(|r| {
            r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
          })
          .map(|_| git.reference.clone()),
        reference: reference.unwrap_or_else(|| git.reference.clone()),
        user: git.user.clone(),
        token,
      })
    }
    (None, None) => {
      Err(ApiError::invalid(format!("{what} 没有代码来源")))
    }
  }
}

/// 构建来源的服务确保镜像在服务器上，返回 git 来源实际构建的 commit。
/// 其他来源什么也不做。
pub async fn ensure_image(
  state: &AppState,
  snap: &Snapshot,
  service: &str,
  force: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<Option<String>, ApiError> {
  let row = &snap.world.services[service];
  let Source::Build(build) = &row.spec.source else {
    return Ok(None);
  };
  let server = &row.spec.server;
  let last =
    last_commit(state, service, &row.instance_id, build).await?;
  // 计划时固定的 commit 优先；没固定的（旧数据）沿用上次部署的，重新构建时拉最新。
  let pinned = row
    .commit
    .clone()
    .or_else(|| if force { None } else { last.clone() });
  // 镜像名只看构建配置，换了 commit 名字不变，要强制重新构建。
  let force = force
    || row.commit.as_deref().is_some_and(|expected| {
      last.as_deref().is_none_or(|sha| !sha.starts_with(expected))
    })
    || (build.git.is_some()
      && pinned.is_some()
      && !state.hub.supports_safe_migrate(server));
  if let (Some(commit), Some(_)) = (&pinned, &build.git) {
    progress(format!(
      "构建 commit {}",
      &commit[..commit.len().min(12)]
    ));
  }
  let fetch = code_fetch(
    state,
    &crate::secret_policy::service_secrets(
      &snap.world,
      service,
      &snap.secrets,
    ),
    &format!("服务 {service}"),
    build.upload.as_ref(),
    build.git.as_ref(),
    pinned.clone(),
  )?;
  let server_row = &snap.world.servers[server];
  let result: BuildResult = state
    .hub
    .call(
      server,
      AgentOp::Build(Box::new(BuildJob {
        expected_commit: build.git.as_ref().and(pinned.clone()),
        service: service.to_string(),
        image: render::build_image(service, build, &row.spec.ports),
        fetch,
        path: build.path.clone(),
        dockerfile: build.dockerfile.clone(),
        base: build.base.clone(),
        start: build.start.clone(),
        template: build.template.clone(),
        install: build.install.clone(),
        dockerfile_content: build.dockerfile_content.clone(),
        port: render::build_port(&row.spec.ports),
        build_env: server_row.settings.build_env.clone(),
        force,
        pull: snapshot::pull_policy(server_row),
      })),
      BUILD_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await
    .map_err(|e| {
      if e.code == ErrorCode::Timeout && e.hint.is_none() {
        e.with_hint("构建超过 60 分钟。国内机器可以给服务器配置 build_env（PIP_INDEX_URL、GOPROXY）")
      } else {
        e
      }
    })?;
  // 跳过构建时镜像还是上次那份代码。
  Ok(result.commit.or(pinned))
}

pub fn require_not_migrating(
  snap: &Snapshot,
  service: &str,
) -> Result<(), ApiError> {
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| crate::api::service_not_found(service))?;
  let from = snapshot::service_runtime_server(snap, service)
    .unwrap_or(&row.spec.server);
  let to = &row.spec.server;
  if from != to
    || snap.pending.migrations.get(service).is_some_and(|m| {
      m.phase != crate::pending::MigratePhase::UpDone
    })
  {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "服务 {service} 正在从 {from} 迁移到 {to}，不能直接重新构建"
        ),
      )
      .with_hint("先运行 wharf plan 完成迁移，或取消迁移后再重新构建")
      .suggest("wharf plan")
      .suggest(format!(
        "wharf service move {service} --abort --apply"
      )),
    );
  }
  Ok(())
}

/// `POST /api/services/{name}/rebuild`：按固定的 commit 重新构建并部署（没固定过的拉最新代码）。
pub async fn rebuild_now(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
  axum::extract::Path(name): axum::extract::Path<String>,
) -> crate::api::ApiResult<wharf_api_types::plan::ApplyResponse> {
  auth.require(wharf_api_types::view::Perm::Apply)?;
  let snap = snapshot::load(&s.db).await?;
  require_not_migrating(&snap, &name)?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| crate::api::service_not_found(&name))?;
  if !matches!(row.spec.source, Source::Build(_)) {
    return Err(
      ApiError::invalid(format!("服务 {name} 不是从代码构建的"))
        .with_hint("镜像来源用 wharf service deploy 更新")
        .into(),
    );
  }
  Ok(axum::Json(
    crate::apply::start_task_by(
      s.clone(),
      format!("重新构建 {name}"),
      crate::planner::Step::Rebuild { service: name },
      Some(crate::apply::format_actor(&auth)),
    )
    .await?,
  ))
}

/// `POST /api/services/{name}/restart`：重启容器，不改配置、不重建。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartRequest {
  #[serde(default)]
  container: Option<String>,
}

pub async fn restart_now(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
  axum::extract::Path(name): axum::extract::Path<String>,
  body: Option<axum::Json<RestartRequest>>,
) -> crate::api::ApiResult<wharf_api_types::plan::ApplyResponse> {
  auth.require(wharf_api_types::view::Perm::Apply)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| crate::api::service_not_found(&name))?;
  if row.spec.stopped {
    return Err(
      ApiError::invalid(format!("服务 {name} 已停止"))
        .with_hint(format!("先启动：wharf service start {name}"))
        .into(),
    );
  }
  let container = body.and_then(|body| body.0.container);
  crate::service_container::validate(
    row,
    &name,
    container.as_deref(),
  )?;
  let title = if let Some(c) = &container {
    let server = snapshot::service_runtime_server(&snap, &name)
      .ok_or_else(|| crate::api::service_not_found(&name))?;
    s.hub.exec_v2_conn_id(server, "重启单个子容器")?;
    format!("重启 {name}/{c}")
  } else {
    format!("重启 {name}")
  };
  Ok(axum::Json(
    crate::apply::start_task_by(
      s.clone(),
      title,
      crate::planner::Step::ServiceRestart {
        service: name,
        container,
      },
      Some(crate::apply::format_actor(&auth)),
    )
    .await?,
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn short_rollback_commit_reuses_matching_built_image() {
    let state = crate::rules::tests::test_state();
    let sha = "0123456789012345678901234567890123456789";
    let short = &sha[..7];
    let mut snap = Snapshot::default();
    snap.world.servers.insert(
      "s1".into(),
      crate::world::ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    let spec: ServiceSpec = serde_json::from_value(serde_json::json!({
      "server": "s1",
      "source": {"build": {"git": {"repo": "https://example.test/app", "ref": "main"}}}
    })).unwrap();
    let recorded_spec = serde_json::to_string(&spec).unwrap();
    state.db.call(move |c| {
      c.execute(
        "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, spec, commit_sha, instance_id, started)
         VALUES ('app', 's1', 'r1', 'h', '', '[]', 1, ?1, ?2, 'svc_fixture', 1)",
        params![recorded_spec, sha],
      ).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    snap.world.services.insert(
      "app".into(),
      crate::world::ServiceRow {
        host_groups: Default::default(),
        spec,
        instance_id: "svc_fixture".into(),
        host_ports: Default::default(),
        import: None,
        pins: Default::default(),
        commit: Some(short.into()),
        version: 1,
      },
    );
    snap
      .world
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "updated".into());
    state.hub.mock_safe_migrate_agent("s1", move |op, _| {
      let AgentOp::Build(job) = op else {
        panic!("意外的 agent 请求");
      };
      assert_eq!(job.expected_commit.as_deref(), Some(short));
      assert!(!job.force);
      Some(Ok(serde_json::json!({"skipped": true, "commit": sha})))
    });
    let progress: ProgressFn = std::sync::Arc::new(|_| {});
    assert_eq!(
      ensure_image(
        &state,
        &snap,
        "app",
        false,
        &progress,
        &CancellationToken::new()
      )
      .await
      .unwrap()
      .as_deref(),
      Some(sha)
    );
  }

  #[tokio::test]
  async fn legacy_plan_ignores_target_loopback_proxy_even_when_reachable()
   {
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    assert_eq!(reachable_git_proxy(Some(&proxy)).await, "");
    assert_eq!(
      reachable_git_proxy(Some("http://[::ffff:127.0.0.1]:8080"))
        .await,
      ""
    );
    assert_eq!(
      reachable_git_proxy(Some("http://127.0.0.1:0")).await,
      ""
    );
  }

  #[tokio::test]
  async fn plan_pin_on_legacy_agent_never_dispatches_docker_lookup() {
    let state = crate::rules::tests::test_state();
    state
      .hub
      .mock_agent("s1", false, |_| panic!("不应向旧 agent 发查询"));
    let sha = "0123456789012345678901234567890123456789";
    let job = ResolveCommit {
      service: "site".into(),
      fetch: BuildFetch::Git {
        repo: "https://example.test/site".into(),
        reference: sha.into(),
        token: None,
        user: None,
        fallback_ref: None,
      },
      pull: snapshot::committed_pull_policy(
        &Default::default(),
        "s1",
      ),
    };
    assert_eq!(plan_commit(&state, "s1", job).await.unwrap(), sha);
  }
}
