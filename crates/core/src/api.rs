//! HTTP API。错误统一为 `{ code, message, hint, suggest }`。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
  Json, Router,
  extract::{Path, Query, State},
  http::{HeaderMap, StatusCode},
  response::{IntoResponse, Response},
  routing::{get, post, put},
};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::AgentOp,
  plan::{ApplyRequest, ApplyResponse, Plan, PlanRequest, Run},
  spec::Fleet,
  validate_name,
  view::{
    AccountView, CreatedToken, DataView, DeploymentView, GatewayView,
    JoinInfo, JoinRequest, JoinResponse, Perm, RouteView, SecretView,
    ServerView, ServiceView, Status, TokenScope, TokenView,
  },
};

use crate::{
  apply,
  auth::{self, Auth},
  db::{self, json_err, now_ms, sql_err, to_time},
  hub, planner, snapshot,
  state::AppState,
  views,
  world::{KIND_SERVER, gateway_project, server_not_found},
};

pub struct AppError(pub ApiError);

impl From<ApiError> for AppError {
  fn from(e: ApiError) -> Self {
    Self(e)
  }
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let status = StatusCode::from_u16(self.0.code.http_status())
      .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(self.0)).into_response()
  }
}

pub(crate) type ApiResult<T> = Result<Json<T>, AppError>;

pub fn router(state: Arc<AppState>) -> Router {
  Router::new()
    .route("/healthz", get(|| async { "ok" }))
    .route("/agent/ws", get(hub::agent_ws))
    .route("/agent/join", post(agent_join))
    .route("/join.sh", get(crate::join::script))
    .route("/cli.sh", get(crate::cli_dist::script))
    .route("/api/core/addresses", get(crate::join::addresses))
    .route("/api/session", get(crate::login::show))
    .route("/api/setup", post(crate::login::setup))
    .route("/api/login", post(crate::login::login))
    .route("/api/logout", post(crate::login::logout))
    .route(
      "/agent/uploads/{sha256}",
      get(crate::uploads::download)
        .put(crate::uploads::agent_put)
        .layer(axum::extract::DefaultBodyLimit::max(
          crate::uploads::MAX_UPLOAD,
        )),
    )
    .route(
      "/api/uploads/{sha256}",
      get(crate::uploads::show).put(crate::uploads::put).layer(
        axum::extract::DefaultBodyLimit::max(
          crate::uploads::MAX_UPLOAD,
        ),
      ),
    )
    .route("/api/status", get(status))
    .route("/api/version", get(crate::agent_upgrade::version))
    .route("/api/network", get(crate::network::show))
    .route("/api/data", get(data_overview))
    .route("/api/network/probe", post(crate::network::probe))
    .route("/api/upgrade", post(crate::agent_upgrade::upgrade_core))
    .route(
      "/api/core-backup",
      get(crate::core_backup::show).post(crate::core_backup::enable),
    )
    .route("/api/core-backup/run", post(crate::core_backup::run_now))
    .route("/api/doctor", get(crate::doctor::doctor))
    .route("/api/metrics", get(crate::metrics::query))
    .route("/api/metrics/usage", get(crate::metrics::usage))
    .route(
      "/api/core-backup/recovery-key",
      post(crate::core_backup::recovery_key),
    )
    .route("/api/servers", get(list_servers).post(add_server))
    .route(
      "/api/servers/upgrade",
      post(crate::agent_upgrade::upgrade_outdated),
    )
    .route(
      "/api/servers/{name}",
      get(show_server).delete(remove_server),
    )
    .route(
      "/api/servers/{name}/upgrade",
      post(crate::agent_upgrade::upgrade_now),
    )
    .route("/api/servers/{name}/prune", post(crate::prune::prune_now))
    .route(
      "/api/servers/{name}/baseline/check",
      post(crate::baseline::check_now),
    )
    .route("/api/servers/{name}/host", get(host_info))
    .route("/api/servers/{name}/dirs", get(crate::host_dir::list))
    .route("/api/servers/{name}/pack", post(crate::host_dir::pack))
    .route("/api/updates/check", post(crate::updates::check_now))
    .route(
      "/api/servers/{name}/apt",
      get(crate::apt::status).post(crate::apt::upgrade),
    )
    .route(
      "/api/servers/{name}/traffic",
      get(crate::traffic::traffic),
    )
    .route(
      "/api/servers/{name}/sessions",
      get(crate::host_dir::sessions),
    )
    .route(
      "/api/servers/{name}/sessions/{session}",
      axum::routing::delete(crate::host_dir::kill_session)
        .put(crate::host_dir::rename_session),
    )
    .route("/api/servers/{name}/exec", post(crate::shell::exec))
    .route(
      "/api/servers/{name}/terminal",
      get(crate::terminal::open_host),
    )
    .route("/api/shell-log", get(crate::shell::list))
    .route(
      "/api/servers/{name}/unmanaged",
      get(crate::import_api::unmanaged),
    )
    .route(
      "/api/servers/{name}/unmanaged/remove",
      post(crate::import_api::remove),
    )
    .route("/api/import", post(crate::import_api::preview))
    .route("/api/services", get(list_services))
    .route("/api/services/{name}", get(show_service))
    .route("/api/services/{name}/logs", get(service_logs))
    .route(
      "/api/services/{name}/logs/stream",
      get(crate::logs_stream::service),
    )
    .route(
      "/api/services/{name}/rollback",
      get(crate::rollback::target),
    )
    .route("/api/services/{name}/deployments", get(deployments))
    .route("/api/services/{name}/note", put(set_note))
    .route("/api/vault", get(show_vault).put(set_vault))
    .route(
      "/api/services/{name}/origin",
      get(crate::host_dir::origin),
    )
    .route(
      "/api/services/{name}/files",
      get(crate::files_api::list)
        .put(crate::files_api::upload)
        .layer(axum::extract::DefaultBodyLimit::max(
          crate::files_api::MAX_UPLOAD,
        )),
    )
    .route(
      "/api/services/{name}/files/download",
      get(crate::files_api::download),
    )
    .route(
      "/api/services/{name}/backups",
      get(crate::backup::list).post(crate::backup::run_now),
    )
    .route(
      "/api/services/{name}/restore",
      post(crate::backup::restore_now),
    )
    .route(
      "/api/services/{name}/rebuild",
      post(crate::build::rebuild_now),
    )
    .route(
      "/api/services/{name}/restart",
      post(crate::build::restart_now),
    )
    .route(
      "/api/services/{name}/terminal",
      get(crate::terminal::open),
    )
    .route("/api/gateways", get(list_gateways))
    .route("/api/gateways/{name}", get(show_gateway))
    .route("/api/gateways/{name}/config", get(gateway_config))
    .route("/api/gateways/{name}/logs", get(gateway_logs))
    .route(
      "/api/gateways/{name}/logs/stream",
      get(crate::logs_stream::gateway),
    )
    .route("/api/routes", get(list_routes))
    .route("/api/accounts", get(list_accounts).post(add_account))
    .route(
      "/api/accounts/{name}",
      axum::routing::delete(remove_account),
    )
    .route("/api/accounts/{name}/discover", post(rediscover_account))
    .route(
      "/api/accounts/{name}/edge",
      get(crate::edge_api::discover),
    )
    .route("/api/edge", get(crate::edge_api::list))
    .route("/api/edge/{name}", get(crate::edge_api::show))
    .route("/api/edge/{name}/script", get(crate::edge_api::script))
    .route(
      "/api/edge/{name}/versions",
      get(crate::edge_api::versions),
    )
    .route(
      "/api/edge/{name}/rollback",
      post(crate::edge_api::rollback),
    )
    .route(
      "/api/edge/{name}/redeploy",
      post(crate::edge_api::redeploy),
    )
    .route("/api/edge/{name}/accept", post(crate::edge_api::accept))
    .route("/api/secrets", get(list_secrets))
    .route("/api/notify/test", post(crate::notify::test))
    .route(
      "/api/egress",
      get(crate::egress::get).put(crate::egress::put),
    )
    .route("/api/tasks", get(crate::tasks::list))
    .route(
      "/api/tasks/{name}",
      put(crate::tasks::put).delete(crate::tasks::remove),
    )
    .route("/api/tasks/{name}/run", post(crate::tasks::run_now))
    .route("/api/tasks/{name}/runs", get(crate::tasks::runs))
    .route(
      "/api/secrets/{name}",
      put(set_secret).delete(remove_secret),
    )
    .route("/api/plan", post(make_plan))
    .route("/api/plans/{id}", get(show_plan))
    .route("/api/apply", post(apply_plan))
    .route("/api/runs", get(list_runs))
    .route("/api/runs/{id}", get(show_run))
    .route("/api/runs/{id}/cancel", post(cancel_run))
    .route("/api/export", get(export))
    .route("/api/tokens", get(list_tokens).post(create_token))
    .route("/api/tokens/{name}", axum::routing::delete(remove_token))
    .fallback(|uri: axum::http::Uri| async move {
      let path = uri.path();
      if path.starts_with("/api/") || path.starts_with("/agent/") {
        AppError(ApiError::not_found("没有这个接口")).into_response()
      } else {
        crate::web::serve(uri).await
      }
    })
    .layer(axum::middleware::from_fn(check_cli))
    .with_state(state)
}

/// 拦下太旧的 CLI。页面和控制面一起发布，不带这个头；更早的 CLI 也不带，放过。
async fn check_cli(
  req: axum::extract::Request,
  next: axum::middleware::Next,
) -> Response {
  let api = req
    .headers()
    .get(wharf_api_types::CLI_API_HEADER)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.parse::<u32>().ok());
  if let Some(api) = api
    && api < wharf_api_types::MIN_CLI_API
  {
    let host = req
      .headers()
      .get("host")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("<控制面地址>");
    let scheme = req
      .headers()
      .get("x-forwarded-proto")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("http");
    let base = format!("{scheme}://{host}");
    return AppError(
      ApiError::new(
        ErrorCode::InvalidInput,
        format!(
          "本机 wharf 太旧（接口版本 {api}，控制面至少要 {}）",
          wharf_api_types::MIN_CLI_API
        ),
      )
      .with_hint(format!(
        "更新后再试：curl -fsSL {base}/cli.sh | sh -s -- {base}"
      )),
    )
    .into_response();
  }
  let mut resp = next.run(req).await;
  resp.headers_mut().insert(
    wharf_api_types::BUILD_HEADER,
    axum::http::HeaderValue::from_static(wharf_api_types::BUILD),
  );
  resp
}

// STATUS

async fn status(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Status> {
  auth.require(Perm::Read)?;
  let status = views::status(&s).await?;
  // 刚导入、还没同步过的在后台同步，下一次轮询就有了。
  if let Ok(snap) = snapshot::load(&s.db).await {
    for a in status.edge_apps.iter().filter(|a| a.live.is_none()) {
      crate::edge_sync::sync_if_stale(&s, &snap, &a.name);
    }
  }
  Ok(Json(status))
}

/// 每个服务的数据在哪、备份有没有在跑。
async fn data_overview(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<DataView> {
  auth.require(Perm::Read)?;
  Ok(Json(crate::data::overview(&s).await?))
}

// SERVERS

async fn list_servers(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<ServerView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(
    snap
      .world
      .servers
      .keys()
      .filter_map(|n| views::server_view(&s, &snap, n))
      .collect(),
  ))
}

async fn show_server(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ServerView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(
    views::server_view(&s, &snap, &name)
      .ok_or_else(|| server_not_found(&name))?,
  ))
}

/// 宿主机的系统版本、待装更新、docker 和日志占用，现查。
async fn host_info(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<wharf_api_types::agent::HostInfo> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&name) {
    return Err(server_not_found(&name).into());
  }
  if !s.hub.is_online(&name) {
    return Err(crate::hub::offline(&name).into());
  }
  Ok(Json(
    s.hub
      .call(
        &name,
        AgentOp::HostInfo,
        Duration::from_secs(120),
        None,
        &tokio_util::sync::CancellationToken::new(),
      )
      .await?,
  ))
}

#[derive(Deserialize)]
struct AddServer {
  name: String,
  #[serde(default)]
  rejoin: bool,
  /// agent 连接控制面用的地址，不给时用启动配置或请求的 Host。
  #[serde(default)]
  core_url: Option<String>,
  /// agent 镜像，不给时用控制面的默认镜像。国内机器可以换成镜像站地址。
  #[serde(default)]
  agent_image: Option<String>,
}

const JOIN_TTL_HOURS: i64 = 24;

async fn add_server(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  headers: HeaderMap,
  Json(req): Json<AddServer>,
) -> ApiResult<JoinInfo> {
  auth.require(Perm::Admin)?;
  validate_name("服务器", &req.name)?;
  let image = match req.agent_image.as_deref().map(str::trim) {
    Some(i) if !i.is_empty() && i != s.agent_image => {
      Some(crate::join::check_image(i)?)
    }
    _ => None,
  };
  let core_url =
    match req.core_url.as_deref().filter(|u| !u.trim().is_empty()) {
      Some(u) => Some(crate::join::check_core_url(u)?),
      None => None,
    };
  let token = auth::new_token().replacen("wh_", "wj_", 1);
  let hash = auth::hash_token(&token);
  let expires = Utc::now() + chrono::Duration::hours(JOIN_TTL_HOURS);
  let name = req.name.clone();
  let rejoin = req.rejoin;
  let expires_ms = expires.timestamp_millis();
  s.db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let joined: Option<Option<String>> = tx
        .query_row(
          "SELECT public_key FROM agents WHERE server = ?1",
          params![name],
          |r| r.get(0),
        )
        .optional()
        .map_err(sql_err)?;
      if matches!(joined, Some(Some(_))) && !rejoin {
        return Err(
          ApiError::new(ErrorCode::AlreadyExists, format!("服务器 {name} 已经加入"))
            .with_hint("换机器或重装 agent 时用 --rejoin 生成新的加入命令，旧密钥会失效")
            .suggest(format!("wharf server add {name} --rejoin")),
        );
      }
      let exists: bool = tx
        .query_row(
          "SELECT 1 FROM resources WHERE kind = ?1 AND name = ?2",
          params![KIND_SERVER, name],
          |_| Ok(()),
        )
        .optional()
        .map_err(sql_err)?
        .is_some();
      if !exists {
        db::apply_write(
          &tx,
          &db::Write::Upsert {
            kind: KIND_SERVER.into(),
            name: name.clone(),
            spec: json!({}),
            meta: json!({}),
          },
        )?;
      }
      tx.execute(
        "INSERT INTO agents (server, join_token_hash, join_expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (server) DO UPDATE SET join_token_hash = excluded.join_token_hash,
           join_expires_at = excluded.join_expires_at",
        params![name, hash, expires_ms],
      )
      .map_err(sql_err)?;
      tx.commit().map_err(sql_err)
    })
    .await?;

  let core_url = match core_url {
    Some(u) => Some(u),
    None => crate::join::default_url(&s).await,
  };
  let core_url = core_url.unwrap_or_else(|| {
    let host = headers
      .get(axum::http::header::HOST)
      .and_then(|h| h.to_str().ok())
      .unwrap_or("127.0.0.1:7700");
    format!("http://{host}")
  });
  let commands = BTreeMap::from([
    (
      "script".to_string(),
      crate::join::script_command(
        &core_url,
        &token,
        image.as_deref(),
      ),
    ),
    (
      "docker".to_string(),
      format!(
        "docker run -d --name wharf-agent --restart unless-stopped --network host \
         -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/wharf:/var/lib/wharf -v /srv:/srv \
         -e WHARF_CORE_URL={core_url} -e WHARF_JOIN_TOKEN={token} {}",
        image.as_deref().unwrap_or(&s.agent_image)
      ),
    ),
    (
      "binary".to_string(),
      format!(
        "wharf-agent join {core_url} {token} && wharf-agent run"
      ),
    ),
  ]);
  Ok(Json(JoinInfo {
    server: req.name,
    join_token: token,
    expires_at: expires,
    commands,
    core_url,
  }))
}

async fn agent_join(
  State(s): State<Arc<AppState>>,
  Json(req): Json<JoinRequest>,
) -> ApiResult<JoinResponse> {
  let hash = auth::hash_token(req.join_token.trim());
  let key = req.public_key.clone();
  if hex::decode(&key).map(|b| b.len()).unwrap_or(0) != 32 {
    return Err(ApiError::invalid("公钥格式不对").into());
  }
  let server = s
    .db
    .call(move |c| {
      let found: Option<(String, i64)> = c
        .query_row(
          "SELECT server, join_expires_at FROM agents WHERE join_token_hash = ?1",
          params![hash],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql_err)?;
      let Some((server, expires)) = found else {
        return Err(
          ApiError::new(ErrorCode::Unauthorized, "加入凭据无效或已经用过")
            .with_hint("在控制面重新执行 wharf server add <name> --rejoin"),
        );
      };
      if expires < now_ms() {
        return Err(
          ApiError::new(ErrorCode::Unauthorized, "加入凭据已过期")
            .suggest(format!("wharf server add {server} --rejoin")),
        );
      }
      c.execute(
        "UPDATE agents SET public_key = ?1, join_token_hash = NULL, join_expires_at = NULL
         WHERE server = ?2",
        params![key, server],
      )
      .map_err(sql_err)?;
      Ok(server)
    })
    .await?;
  tracing::info!("服务器 {server} 完成加入");
  Ok(Json(JoinResponse {
    server,
    core_public_key: hex::encode(s.key.verifying_key().to_bytes()),
  }))
}

async fn remove_server(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&name) {
    return Err(server_not_found(&name).into());
  }
  let used: Vec<String> = snap
    .world
    .services
    .iter()
    .filter(|(_, r)| r.spec.server == name)
    .map(|(n, _)| format!("服务 {n}"))
    .chain(
      snap
        .world
        .gateways
        .iter()
        .filter(|(_, r)| r.spec.server == name)
        .map(|(n, _)| format!("网关 {n}")),
    )
    .collect();
  if !used.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("服务器 {name} 上还有：{}", used.join("、")),
      )
      .with_hint("先删除或迁走它们")
      .into(),
    );
  }
  s.db
    .call(move |c| {
      c.execute(
        "DELETE FROM resources WHERE kind = ?1 AND name = ?2",
        params![KIND_SERVER, name],
      )
      .map_err(sql_err)?;
      c.execute(
        "DELETE FROM agents WHERE server = ?1",
        params![name],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  Ok(Json(json!({ "removed": true })))
}

// SERVICES

async fn list_services(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<ServiceView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let live = views::cached_live(&s, &snap.world).await;
  Ok(Json(
    snap
      .world
      .services
      .keys()
      .filter_map(|n| {
        views::service_view(&snap, &net, n, Some(&live))
      })
      .collect(),
  ))
}

pub(crate) fn service_not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("服务 {name} 不存在"))
    .suggest("wharf service list")
}

#[derive(Deserialize)]
struct NoteRequest {
  note: String,
}

// 私密内容在浏览器里加密后以 base64 存进来，比原文长不少，所以放宽到 2 万字。
const NOTE_LIMIT: usize = 20000;

/// 备注私密内容的数据密钥，由浏览器用登录密码包好后存在这里；控制面只存不解。
const VAULT_KEY: &str = "note_vault";

#[derive(Deserialize)]
struct VaultRequest {
  vault: String,
}

async fn show_vault(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let vault = s.db.call(|c| crate::db::setting(c, VAULT_KEY)).await?;
  Ok(Json(json!({ "vault": vault })))
}

async fn set_vault(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<VaultRequest>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  if req.vault.len() > 2000 || !req.vault.starts_with('{') {
    return Err(ApiError::invalid("vault 格式不对").into());
  }
  s.db
    .call(move |c| {
      crate::db::set_setting(c, VAULT_KEY, Some(&req.vault))
    })
    .await?;
  Ok(Json(json!({ "ok": true })))
}

/// 改服务备注：不影响部署，直接保存，不走计划。传空字符串清除。
async fn set_note(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<NoteRequest>,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  let note = req.note.trim().to_string();
  if note.chars().count() > NOTE_LIMIT {
    return Err(
      ApiError::invalid(format!("备注最多 {NOTE_LIMIT} 个字")).into(),
    );
  }
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.services.contains_key(&name) {
    return Err(service_not_found(&name).into());
  }
  s.db
    .call(move |c| crate::db::set_service_note(c, &name, &note))
    .await?;
  Ok(Json(json!({ "ok": true })))
}

async fn show_service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ServiceView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let live = views::cached_live(&s, &snap.world).await;
  Ok(Json(
    views::service_view(&snap, &net, &name, Some(&live))
      .ok_or_else(|| service_not_found(&name))?,
  ))
}

#[derive(Deserialize)]
struct LogsQuery {
  #[serde(default = "default_tail")]
  tail: u32,
}

fn default_tail() -> u32 {
  200
}

async fn project_logs(
  s: &AppState,
  server: &str,
  project: String,
  tail: u32,
) -> Result<Json<Value>, AppError> {
  let logs: String = s
    .hub
    .call(
      server,
      AgentOp::Logs {
        project,
        tail,
        follow: false,
      },
      Duration::from_secs(40),
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await?;
  Ok(Json(json!({ "server": server, "logs": logs })))
}

async fn service_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  project_logs(&s, &row.spec.server, name.clone(), q.tail).await
}

async fn deployments(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Vec<DeploymentView>> {
  auth.require(Perm::Read)?;
  let rows = s
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT id, service, server, run_id, compose, images, created_at, spec, hash, commit_sha FROM deployments
           WHERE service = ?1 ORDER BY id DESC LIMIT 50",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![name], |r| {
          Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, Option<String>>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, Option<String>>(9)?,
          ))
        })
        .map_err(sql_err)?;
      rows.collect::<Result<Vec<_>, _>>().map_err(sql_err)
    })
    .await?;
  let mut out = Vec::new();
  for (
    id,
    service,
    server,
    run_id,
    compose,
    images,
    created,
    spec,
    hash,
    commit,
  ) in rows
  {
    out.push(DeploymentView {
      id,
      service,
      server,
      run_id,
      compose,
      images: serde_json::from_str(&images).map_err(json_err)?,
      spec: spec.and_then(|s| serde_json::from_str(&s).ok()),
      hash,
      created_at: to_time(created),
      commit,
    });
  }
  Ok(Json(out))
}

// GATEWAYS

async fn list_gateways(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<GatewayView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let live = views::cached_live(&s, &snap.world).await;
  Ok(Json(
    snap
      .world
      .gateways
      .keys()
      .filter_map(|n| {
        views::gateway_view(&snap, &net, n, Some(&live))
      })
      .collect(),
  ))
}

pub(crate) fn gateway_not_found(name: &str) -> ApiError {
  ApiError::not_found(format!("网关 {name} 不存在"))
    .suggest("wharf gateway list")
}

async fn show_gateway(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<GatewayView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let live = views::cached_live(&s, &snap.world).await;
  Ok(Json(
    views::gateway_view(&snap, &net, &name, Some(&live))
      .ok_or_else(|| gateway_not_found(&name))?,
  ))
}

async fn gateway_config(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.gateways.contains_key(&name) {
    return Err(gateway_not_found(&name).into());
  }
  let net = snap.net(&snap.world);
  let r = snapshot::gateway_render(&snap.world, &net, &name)?;
  let kind = snap.world.gateways[&name].spec.kind;
  Ok(Json(json!({
    "gateway": name,
    "kind": kind.as_str(),
    "config": snapshot::redacted_config(&r.config, &net),
    "compose": r.compose,
  })))
}

async fn gateway_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .gateways
    .get(&name)
    .ok_or_else(|| gateway_not_found(&name))?;
  project_logs(&s, &row.spec.server, gateway_project(&name), q.tail)
    .await
}

// ROUTES

async fn list_routes(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<RouteView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  Ok(Json(
    snap
      .world
      .routes
      .keys()
      .filter_map(|h| views::route_view(&snap, &net, h))
      .collect(),
  ))
}

// ACCOUNTS

fn mask(token: &str) -> String {
  let tail: String = token
    .chars()
    .rev()
    .take(4)
    .collect::<Vec<_>>()
    .into_iter()
    .rev()
    .collect();
  format!("…{tail}")
}

fn account_view(a: &db::AccountRow) -> AccountView {
  AccountView {
    name: a.name.clone(),
    kind: a.kind.clone(),
    token: mask(&a.token),
    zones: a.zones.clone(),
    warnings: a.warnings.clone(),
    updated_at: to_time(a.updated_at),
  }
}

async fn list_accounts(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<AccountView>> {
  auth.require(Perm::Read)?;
  let accounts = s.db.call(|c| db::accounts(c)).await?;
  Ok(Json(accounts.iter().map(account_view).collect()))
}

#[derive(Deserialize)]
struct AddAccount {
  name: String,
  #[serde(default = "default_kind")]
  kind: String,
  token: String,
}

fn default_kind() -> String {
  "cloudflare".into()
}

async fn discover(
  kind: &str,
  token: &str,
) -> Result<wharf_providers::Discovery, ApiError> {
  let factory = wharf_providers::factory(kind).ok_or_else(|| {
    ApiError::invalid(format!("不支持的厂商类型 {kind}"))
      .with_hint("P1 只支持 cloudflare")
  })?;
  snapshot::with_timeout(
    "发现 zone",
    (factory.discover)(token.to_string()),
  )
  .await
}

async fn save_account(
  s: &AppState,
  name: String,
  kind: String,
  token: String,
) -> Result<AccountView, ApiError> {
  let found = discover(&kind, &token).await?;
  let row = db::AccountRow {
    name,
    kind,
    token,
    zones: found.zones,
    warnings: found.warnings,
    updated_at: now_ms(),
  };
  let view = account_view(&row);
  s.db
    .call(move |c| {
      c.execute(
        "INSERT INTO accounts (name, kind, token, zones, warnings, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (name) DO UPDATE SET kind = excluded.kind, token = excluded.token,
           zones = excluded.zones, warnings = excluded.warnings, updated_at = excluded.updated_at",
        params![
          row.name,
          row.kind,
          row.token,
          serde_json::to_string(&row.zones).map_err(json_err)?,
          serde_json::to_string(&row.warnings).map_err(json_err)?,
          row.updated_at
        ],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  Ok(view)
}

async fn add_account(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AddAccount>,
) -> ApiResult<AccountView> {
  auth.require(Perm::Admin)?;
  validate_name("账号", &req.name)?;
  let token = req.token.trim().to_string();
  if token.is_empty() {
    return Err(ApiError::invalid("token 为空").into());
  }
  Ok(Json(save_account(&s, req.name, req.kind, token).await?))
}

async fn rediscover_account(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<AccountView> {
  auth.require(Perm::Admin)?;
  let accounts = s.db.call(|c| db::accounts(c)).await?;
  let account =
    accounts.into_iter().find(|a| a.name == name).ok_or_else(
      || ApiError::not_found(format!("账号 {name} 不存在")),
    )?;
  Ok(Json(
    save_account(&s, account.name, account.kind, account.token)
      .await?,
  ))
}

async fn remove_account(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  // 还有网关、隧道或 DNS 记录靠这个账号管理时，删了就没法再改它们。
  let snap = snapshot::load(&s.db).await?;
  let mut users: Vec<String> = snap
    .world
    .gateways
    .iter()
    .filter(|(_, g)| g.spec.account.as_deref() == Some(name.as_str()))
    .map(|(g, _)| format!("网关 {g}"))
    .collect();
  users.extend(
    snap
      .tunnels
      .iter()
      .filter(|(g, t)| {
        t.account == name && !snap.world.gateways.contains_key(*g)
      })
      .map(|(g, _)| format!("网关 {g} 留下的隧道")),
  );
  users.extend(
    snap
      .owned
      .iter()
      .filter(|r| r.account == name)
      .map(|r| format!("DNS 记录 {}", r.hostname)),
  );
  if !users.is_empty() {
    users.sort();
    users.dedup();
    return Err(
      ApiError::invalid(format!(
        "账号 {name} 还在使用：{}",
        users.join("、")
      ))
      .with_hint("先删除这些网关和域名（并执行计划），再删除账号")
      .into(),
    );
  }
  let removed = s
    .db
    .call(move |c| {
      c.execute("DELETE FROM accounts WHERE name = ?1", params![name])
        .map_err(sql_err)
    })
    .await?;
  Ok(Json(json!({ "removed": removed > 0 })))
}

// SECRETS

async fn list_secrets(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<SecretView>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let rows: Vec<(String, i64)> = s
    .db
    .call(|c| {
      let mut stmt = c
        .prepare("SELECT name, updated_at FROM secrets ORDER BY name")
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  Ok(Json(
    rows
      .into_iter()
      .map(|(name, at)| SecretView {
        used_by: secret_users(&snap.world, &name),
        managed: managed_secret(&name),
        system: system_secret(&name).map(str::to_string),
        name,
        updated_at: to_time(at),
      })
      .collect(),
  ))
}

/// Wharf 自己生成、自己用的密钥。改了或删了，旧备份就打不开了。
fn managed_secret(name: &str) -> bool {
  crate::backup::MANAGED_SECRETS.contains(&name)
    || name == crate::core_backup::OWNER_SECRET
    || name == crate::link::TOKEN_SECRET
    || name == crate::egress::TOKEN_SECRET
}

/// 系统功能用的密钥对应的功能名。
fn system_secret(name: &str) -> Option<&'static str> {
  match name {
    n if crate::backup::MANAGED_SECRETS.contains(&n) => Some("备份"),
    n if n == crate::core_backup::OWNER_SECRET => Some("控制面备份"),
    n if n == crate::link::TOKEN_SECRET => Some("机器互联"),
    n if n == crate::egress::TOKEN_SECRET => Some("外网代理"),
    n if n == crate::tailscale::OAUTH_SECRET => {
      Some("Tailscale 组网")
    }
    n if n == crate::render::BASIC_AUTH_SECRET => Some("网关登录"),
    n if n == crate::render::TUNNEL_TOKEN_SECRET => Some("隧道"),
    n if n == crate::notify::FEISHU_WEBHOOK
      || n == crate::notify::FEISHU_SECRET =>
    {
      Some("通知")
    }
    _ => None,
  }
}

fn secret_users(
  world: &crate::world::World,
  name: &str,
) -> Vec<String> {
  let system = system_secret(name);
  let reference = format!("[[{name}]]");
  let token = format!("\"token_secret\":\"{name}\"");
  system
    .map(str::to_string)
    .into_iter()
    .chain(world.services.iter().filter_map(|(service, row)| {
      let spec = serde_json::to_string(&row.spec).ok()?;
      (spec.contains(&reference) || spec.contains(&token))
        .then(|| service.clone())
    }))
    .collect()
}

fn refuse_managed(name: &str) -> Result<(), ApiError> {
  if managed_secret(name) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      format!(
        "{name} 是 Wharf 自己生成的，改了或删了旧备份就打不开了"
      ),
    ));
  }
  Ok(())
}

#[derive(Deserialize)]
struct SetSecret {
  value: String,
}

fn check_secret_name(name: &str) -> Result<(), ApiError> {
  let ok = !name.is_empty()
    && name.len() <= 64
    && name
      .bytes()
      .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
  if ok {
    Ok(())
  } else {
    Err(ApiError::invalid(format!(
      "密钥名 {name} 不合法，只能用字母、数字、_ 和 -"
    )))
  }
}

async fn set_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<SetSecret>,
) -> ApiResult<SecretView> {
  auth.require(Perm::Admin)?;
  check_secret_name(&name)?;
  refuse_managed(&name)?;
  let value = if name == crate::render::BASIC_AUTH_SECRET {
    crate::render::BasicAuth::hash_input(&req.value)?
  } else {
    req.value
  };
  let now = now_ms();
  let n = name.clone();
  s.db
    .call(move |c| {
      c.execute(
        "INSERT INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![n, value, now],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  Ok(Json(SecretView {
    used_by: vec![],
    managed: false,
    system: system_secret(&name).map(str::to_string),
    name,
    updated_at: to_time(now),
  }))
}

async fn remove_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  refuse_managed(&name)?;
  let removed = s
    .db
    .call(move |c| {
      c.execute("DELETE FROM secrets WHERE name = ?1", params![name])
        .map_err(sql_err)
    })
    .await?;
  Ok(Json(json!({ "removed": removed > 0 })))
}

// PLAN / APPLY / RUNS

async fn make_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<PlanRequest>,
) -> ApiResult<Plan> {
  auth.require(Perm::Plan)?;
  if !auth.human {
    guard_dangerous(&s, &req).await?;
  }
  let planned = planner::make_plan(&s, req).await?;
  planner::save(&s, &planned).await?;
  Ok(Json(planned.plan))
}

/// 宿主机终端、宿主机命令执行这类危险开关：API token（CLI、AI）只能关，打开要人在页面上操作。
async fn guard_dangerous(
  s: &AppState,
  req: &PlanRequest,
) -> Result<(), ApiError> {
  let snap = crate::snapshot::load(&s.db).await?;
  let wanted = req
    .changes
    .iter()
    .filter_map(|c| match c {
      wharf_api_types::spec::Change::UpdateServer {
        name,
        settings,
      } => Some((name, settings)),
      _ => None,
    })
    .chain(req.fleet.iter().flat_map(|f| f.servers.iter()));
  for (name, after) in wanted {
    let before = snap.world.servers.get(name).map(|r| &r.settings);
    let was =
      |f: fn(&wharf_api_types::spec::ServerSettings) -> bool| {
        before.is_some_and(f)
      };
    let opened = [
      (
        "宿主机终端",
        after.host_terminal && !was(|b| b.host_terminal),
      ),
      ("宿主机命令执行", after.host_exec && !was(|b| b.host_exec)),
    ];
    if let Some((what, _)) = opened.iter().find(|(_, o)| *o) {
      return Err(
        ApiError::new(
          ErrorCode::Forbidden,
          format!("不能用 API token 打开 {name} 的{what}，只能关"),
        )
        .with_hint(format!(
          "请用户在页面\u{201c}服务器详情 → {name} → 设置\u{201d}里打开"
        )),
      );
    }
  }
  Ok(())
}

async fn show_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Plan> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::load_plan(&s, &id).await?))
}

async fn apply_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<ApplyRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Apply)?;
  Ok(Json(apply::start(s.clone(), req, auth.perms).await?))
}

#[derive(Deserialize)]
struct RunsQuery {
  #[serde(default = "default_limit")]
  limit: u32,
}

fn default_limit() -> u32 {
  20
}

async fn list_runs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<RunsQuery>,
) -> ApiResult<Vec<Run>> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::list_runs(&s, q.limit.min(200)).await?))
}

async fn show_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Run> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::load_run(&s, &id).await?))
}

async fn cancel_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  if s.runs.cancel(&id) {
    Ok(Json(json!({ "cancelling": true })))
  } else {
    let run = apply::load_run(&s, &id).await?;
    Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("执行记录 {id} 已经结束（{:?}）", run.status),
      )
      .into(),
    )
  }
}

async fn export(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Fleet> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(views::export(&snap.world)))
}

// TOKENS

async fn list_tokens(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<TokenView>> {
  auth.require(Perm::Admin)?;
  let rows: Vec<(String, String, i64, Option<i64>)> = s
    .db
    .call(|c| {
      let mut stmt = c
        .prepare("SELECT name, scope, created_at, last_used_at FROM api_tokens ORDER BY name")
        .map_err(sql_err)?;
      let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  Ok(Json(
    rows
      .into_iter()
      .filter_map(|(name, scope, created, used)| {
        Some(TokenView {
          name,
          perms: auth::decode_perms(&scope)?.into_iter().collect(),
          created_at: to_time(created),
          last_used_at: used.map(to_time),
        })
      })
      .collect(),
  ))
}

/// 新建 token：给 `perms`（权限点），或给旧档位 `scope` 作为预设。
#[derive(Deserialize)]
struct CreateToken {
  name: String,
  #[serde(default)]
  scope: Option<TokenScope>,
  #[serde(default)]
  perms: Option<Vec<Perm>>,
}

async fn create_token(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<CreateToken>,
) -> ApiResult<CreatedToken> {
  auth.require(Perm::Admin)?;
  validate_name("token", &req.name)?;
  let token = auth::new_token();
  let perms = match (req.perms, req.scope) {
    (Some(p), None) => p,
    (None, Some(scope)) => Perm::of_scope(scope),
    _ => {
      return Err(
        wharf_api_types::ApiError::invalid("perms 和 scope 要给且只给一个")
          .with_hint("perms 是权限点列表：read、plan、apply、confirm、exec、admin")
          .into(),
      );
    }
  };
  let stored = auth::encode_perms(&perms);
  let (name, t, p) = (req.name.clone(), token.clone(), perms.clone());
  s.db
    .call(move |c| auth::insert_token(c, &name, &p, &t))
    .await?;
  Ok(Json(CreatedToken {
    name: req.name,
    perms: auth::decode_perms(&stored)
      .unwrap_or_default()
      .into_iter()
      .collect(),
    token,
  }))
}

async fn remove_token(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let removed = s
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM api_tokens WHERE name = ?1",
        params![name],
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(Json(json!({ "removed": removed > 0 })))
}
