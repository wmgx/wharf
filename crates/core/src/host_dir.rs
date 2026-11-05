//! 部署"服务器上的目录"：浏览宿主机目录、把目录打成代码包。
//! 和宿主机终端共用一个开关（服务器设置里的"允许打开宿主机终端"），要 exec 权限，打包记审计。
//! 打出的包和 CLI 上传的一样，填进 `BuildSource.upload`；来源目录记在设置 `pack.origin.<服务>`，
//! 服务详情据此提供"重新打包并发布"。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HostPackJob, HostSession, PackedUpload},
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db,
  shell::{End, finish, start},
  snapshot,
  state::AppState,
};

const LIST_TIMEOUT: Duration = Duration::from_secs(40);
const PACK_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub async fn check_server(
  s: &AppState,
  name: &str,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .servers
    .get(name)
    .ok_or_else(|| crate::world::server_not_found(name))?;
  if !row.settings.host_terminal {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "没有开启宿主机访问，请到\u{201c}服务器详情 → 设置\u{201d}打开\u{201c}允许从页面打开宿主机终端\u{201d}。",
    ));
  }
  if !s.hub.is_online(name) {
    return Err(crate::hub::offline(name));
  }
  Ok(())
}

#[derive(Deserialize)]
pub struct DirQuery {
  #[serde(default = "root")]
  path: String,
}

fn root() -> String {
  "/".into()
}

/// `GET /api/servers/{name}/dirs?path=`：列宿主机目录，目录名以 `/` 结尾。
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<DirQuery>,
) -> ApiResult<Vec<String>> {
  auth.require(Perm::Exec)?;
  check_server(&s, &name).await?;
  Ok(Json(
    s.hub
      .call(
        &name,
        AgentOp::HostListDir { path: q.path },
        LIST_TIMEOUT,
        None,
        &CancellationToken::new(),
      )
      .await?,
  ))
}

#[derive(Deserialize)]
pub struct PackRequest {
  path: String,
  /// 给哪个服务用：记下来源目录，以后可以"重新打包并发布"。
  #[serde(default)]
  service: Option<String>,
}

/// `POST /api/servers/{name}/pack`：把宿主机目录打成代码包，上传到控制面。
pub async fn pack(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<PackRequest>,
) -> ApiResult<PackedUpload> {
  auth.require(Perm::Exec)?;
  auth.require(Perm::Apply)?;
  check_server(&s, &name).await?;
  let audit =
    start(&s.db, &auth.name, &name, "pack", Some(&req.path)).await?;
  let started = std::time::Instant::now();
  let token = s.downloads.issue_upload();
  let result: Result<PackedUpload, ApiError> = s
    .hub
    .call(
      &name,
      AgentOp::HostPack(HostPackJob {
        path: req.path.clone(),
        token,
      }),
      PACK_TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await;
  match &result {
    Ok(p) => {
      finish(
        &s.db,
        audit,
        End {
          exit_code: Some(0),
          duration_ms: Some(started.elapsed().as_millis() as u64),
          output_bytes: Some(p.size),
          error: None,
        },
      )
      .await;
      if let Some(service) = req.service {
        let origin = serde_json::to_string(&Origin {
          server: name.clone(),
          path: req.path.clone(),
        })
        .unwrap_or_default();
        s.db
          .call(move |c| {
            db::set_setting(
              c,
              &format!("pack.origin.{service}"),
              Some(&origin),
            )
          })
          .await?;
      }
    }
    Err(e) => finish(&s.db, audit, End::error(e)).await,
  }
  Ok(Json(result?))
}

#[derive(Serialize, Deserialize)]
pub struct Origin {
  pub server: String,
  pub path: String,
}

/// `GET /api/services/{name}/origin`：代码包来自哪台服务器的哪个目录，没有时为 null。
pub async fn origin(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Option<Origin>> {
  auth.require(Perm::Read)?;
  let raw = s
    .db
    .call(move |c| db::setting(c, &format!("pack.origin.{name}")))
    .await?;
  Ok(Json(raw.and_then(|r| serde_json::from_str(&r).ok())))
}

const SESSION_TIMEOUT: Duration = Duration::from_secs(90);

/// `GET /api/servers/{name}/sessions`：宿主机上的 tmux 会话，终端页拿来列标签。
pub async fn sessions(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Vec<HostSession>> {
  auth.require(Perm::Exec)?;
  check_server(&s, &name).await?;
  Ok(Json(
    s.hub
      .call(
        &name,
        AgentOp::HostSessions,
        SESSION_TIMEOUT,
        None,
        &CancellationToken::new(),
      )
      .await?,
  ))
}

/// `DELETE /api/servers/{name}/sessions/{session}`：结束一个 tmux 会话，记审计。
pub async fn kill_session(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((name, session)): Path<(String, String)>,
) -> ApiResult<()> {
  auth.require(Perm::Exec)?;
  check_server(&s, &name).await?;
  let audit =
    start(&s.db, &auth.name, &name, "terminal.kill", Some(&session))
      .await?;
  let result: Result<(), ApiError> = s
    .hub
    .call(
      &name,
      AgentOp::HostSessionKill { session },
      SESSION_TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await;
  let end = match &result {
    Ok(()) => End {
      exit_code: Some(0),
      duration_ms: None,
      output_bytes: None,
      error: None,
    },
    Err(e) => End::error(e),
  };
  finish(&s.db, audit, end).await;
  Ok(Json(result?))
}

#[derive(Deserialize)]
pub struct RenameRequest {
  to: String,
}

/// `PUT /api/servers/{name}/sessions/{session}`：给 tmux 会话改名。
pub async fn rename_session(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((name, session)): Path<(String, String)>,
  Json(req): Json<RenameRequest>,
) -> ApiResult<()> {
  auth.require(Perm::Exec)?;
  check_server(&s, &name).await?;
  Ok(Json(
    s.hub
      .call(
        &name,
        AgentOp::HostSessionRename {
          session,
          to: req.to,
        },
        SESSION_TIMEOUT,
        None,
        &CancellationToken::new(),
      )
      .await?,
  ))
}
