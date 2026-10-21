//! 构建来源的服务：部署前让服务所在的 agent 构建镜像。
//!
//! - 镜像名带构建配置的指纹，配置不变、镜像已在就跳过（普通部署、改环境变量）；
//! - "重新构建"（`force`）拉 ref 的最新代码；
//! - 不是 force 时，git 来源固定到上次部署的 commit（迁移到新机器时构建出同样的代码）。

use std::time::Duration;

use rusqlite::{OptionalExtension, params};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BuildFetch, BuildJob, BuildResult, OneTimeSecret,
  },
  spec::{BuildSource, GitSource, ServiceSpec, Source},
};

use crate::{
  db::sql_err,
  hub::ProgressFn,
  render,
  snapshot::{self, Snapshot},
  state::AppState,
};

/// 拉代码、拉基础镜像、构建都算在内。
const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// 上次部署这个服务时构建的 commit，只在构建配置没变时有意义。
async fn last_commit(
  state: &AppState,
  service: &str,
  build: &BuildSource,
) -> Result<Option<String>, ApiError> {
  let s = service.to_string();
  let row: Option<(Option<String>, String)> = state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT spec, commit_sha FROM deployments
         WHERE service = ?1 AND commit_sha IS NOT NULL ORDER BY id DESC LIMIT 1",
        params![s],
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
  snap: &Snapshot,
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
        Some(name) => Some(OneTimeSecret(
          snap.secrets.get(name).cloned().ok_or_else(|| {
            ApiError::invalid(format!("密钥 {name} 不存在"))
              .suggest(format!("wharf secret set {name}"))
          })?,
        )),
        None => None,
      };
      Ok(BuildFetch::Git {
        repo: git.repo.clone(),
        reference: reference.unwrap_or_else(|| git.reference.clone()),
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
  let pinned = if force {
    None
  } else {
    last_commit(state, service, build).await?
  };
  if let (Some(commit), Some(_)) = (&pinned, &build.git) {
    progress(format!("固定到上次部署的 commit {}", &commit[..12]));
  }
  let fetch = code_fetch(
    state,
    snap,
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
        service: service.to_string(),
        image: render::build_image(service, build, &row.spec.ports),
        fetch,
        path: build.path.clone(),
        dockerfile: build.dockerfile.clone(),
        base: build.base.clone(),
        start: build.start.clone(),
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
      if e.code == ErrorCode::Timeout {
        e.with_hint("构建超过 60 分钟。国内机器可以给服务器配置 build_env（PIP_INDEX_URL、GOPROXY）")
      } else {
        e
      }
    })?;
  // 跳过构建时镜像还是上次那份代码。
  Ok(result.commit.or(pinned))
}

/// `POST /api/services/{name}/rebuild`：拉最新代码重新构建并部署。
pub async fn rebuild_now(
  axum::extract::State(s): axum::extract::State<
    std::sync::Arc<AppState>,
  >,
  auth: crate::auth::Auth,
  axum::extract::Path(name): axum::extract::Path<String>,
) -> crate::api::ApiResult<wharf_api_types::plan::ApplyResponse> {
  auth.require(wharf_api_types::view::TokenScope::ApplySafe)?;
  let snap = snapshot::load(&s.db).await?;
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
    crate::apply::start_task(
      s.clone(),
      format!("重新构建 {name}"),
      crate::planner::Step::Rebuild { service: name },
    )
    .await?,
  ))
}
