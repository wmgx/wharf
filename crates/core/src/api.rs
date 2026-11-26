//! HTTP API。错误统一为 `{ code, message, hint, suggest }`。

use std::{
  collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration,
};

mod link;

use axum::{
  Extension, Json, Router,
  extract::{ConnectInfo, Path, Query, State},
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
    AccountView, DataView, DeploymentView, GatewayView, JoinInfo,
    JoinRequest, JoinResponse, Perm, RotateSecretResponse, RouteView,
    SecretView, ServerView, ServiceView, Status,
  },
};

use crate::secret_policy::{
  is_managed_secret as managed_secret, refuse_managed,
  system_label as system_secret,
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
    (status, Json(crate::log_redact::redact_error(self.0)))
      .into_response()
  }
}

pub(crate) type ApiResult<T> = Result<Json<T>, AppError>;

pub fn router(state: Arc<AppState>) -> Router {
  Router::new()
    .route("/gate/key", get(crate::gate::check_key))
    .route("/gate/revocations", get(crate::gate::revocations::list))
    .route(
      "/api/routes/{hostname}/sso/test",
      post(crate::scope_filter::test_route_sso),
    )
    .route(
      "/api/routes/{hostname}/cert",
      get(crate::cert_status::status),
    )
    .route(
      "/api/routes/{hostname}/cert/retry",
      post(crate::cert_status::retry),
    )
    .route("/api/sso/accounts", get(crate::app_accounts::list))
    .route(
      "/api/sso/accounts/{name}",
      get(crate::app_accounts::show)
        .put(crate::app_accounts::set)
        .delete(crate::app_accounts::remove),
    )
    .route(
      "/api/sso/accounts/{name}/password",
      post(crate::app_accounts::reveal),
    )
    .route(
      "/api/sso/accounts/{name}/domains/{host}",
      put(crate::app_accounts::link)
        .delete(crate::app_accounts::unlink),
    )
    .route("/api/gate/keys", get(crate::gate::list_keys))
    .route(
      "/api/gate/keys/{name}",
      axum::routing::put(crate::gate::put_key)
        .delete(crate::gate::remove_key),
    )
    .route(
      "/.well-known/openid-configuration",
      get(crate::oidc::discovery),
    )
    .route("/oidc/jwks", get(crate::oidc::jwks))
    .route("/oidc/authorize", get(crate::oidc::authorize))
    .route("/oidc/token", post(crate::oidc::token))
    .route(
      "/oidc/userinfo",
      get(crate::oidc::userinfo).post(crate::oidc::userinfo),
    )
    .route("/oidc/logout", get(crate::oidc::logout))
    .route("/api/oidc", get(crate::oidc::show))
    .route(
      "/api/oidc/settings",
      axum::routing::put(crate::oidc::settings),
    )
    .route(
      "/api/oidc/clients/{host}/secret",
      get(crate::oidc::secret),
    )
    .route("/gate/login", get(crate::gate::login))
    .route("/gate/refresh", axum::routing::any(crate::gate::refresh))
    .route("/gate/site/login", get(crate::gate::site_login))
    .route("/gate/site/gate", get(crate::gate::site_gate))
    .route("/gate/site/logout", get(crate::gate::site_logout))
    .route(
      "/gate/site/{*path}",
      get(|| async { StatusCode::NOT_FOUND }),
    )
    .route("/healthz", get(|| async { "ok" }))
    .route(
      "/ping/{token}",
      get(crate::ping::ok).post(crate::ping::ok),
    )
    .route(
      "/ping/{token}/fail",
      get(crate::ping::fail).post(crate::ping::fail),
    )
    .route("/notify/{token}", post(crate::notify_keys::send))
    .route(
      "/hook/{token}",
      get(crate::tasks::hook).post(crate::tasks::hook),
    )
    .route("/agent/ws", get(hub::agent_ws))
    .route(
      wharf_api_types::tunnel::TUNNEL_PATH,
      get(crate::cli_tunnel::open),
    )
    .route("/agent/join", post(agent_join))
    .route("/agent/acme-dns/update", post(crate::acme_dns::update))
    .route("/join.sh", get(crate::join::script))
    .route("/cli.sh", get(crate::cli_dist::script))
    .route("/skill.md", get(crate::cli_dist::skill))
    .route("/api/core/addresses", get(crate::join::addresses))
    .route("/api/session", get(crate::login::show))
    .route("/api/setup", post(crate::login::setup))
    .route("/api/login", post(crate::login::login))
    .route("/api/logout", post(crate::login::logout))
    .route("/api/sessions", get(crate::sessions::list))
    .route(
      "/api/sessions/{id}",
      axum::routing::delete(crate::sessions::revoke),
    )
    .route(
      "/api/sessions/revoke-others",
      post(crate::sessions::revoke_others),
    )
    .route("/api/totp", get(crate::totp::show))
    .route("/api/totp/begin", post(crate::totp::begin))
    .route("/api/totp/enable", post(crate::totp::enable))
    .route("/api/totp/disable", post(crate::totp::disable))
    .route("/api/totp/recovery", post(crate::totp::recovery))
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
    .route("/api/home/favicon", get(crate::favicon::get))
    .route("/api/version", get(crate::agent_upgrade::version))
    .route("/api/version/check", post(crate::agent_upgrade::check))
    .route("/api/network", get(crate::network::show))
    .route("/api/network/acl", get(crate::vendor_checks::acl))
    .route(
      "/api/routes/{host}/dns-check",
      get(crate::dns_check::show),
    )
    .route(
      "/api/external",
      get(crate::external_status::list)
        .post(crate::external_status::add),
    )
    .route(
      "/api/external/{name}",
      put(crate::external_status::set)
        .delete(crate::external_status::rm),
    )
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
    .route("/api/metrics/top", get(crate::resource_top::usage))
    .route("/api/metrics/images", get(crate::resource_top::images))
    .route("/api/report", get(crate::report::show))
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
    .route("/api/servers/{name}/probe", post(crate::net_probe::probe))
    .route("/api/servers/{name}/prune", post(crate::prune::prune_now))
    .route("/api/servers/{name}/note", put(crate::notes::server))
    .route("/api/servers/{name}/disk", get(crate::disk::show))
    .route("/api/servers/{name}/exposure", get(crate::exposure::show))
    .route(
      "/api/servers/{name}/exposure/refresh",
      post(crate::exposure::refresh_now),
    )
    .route(
      "/api/servers/{name}/exposure/ack",
      post(crate::exposure::ack),
    )
    .route(
      "/api/servers/{name}/host-units",
      get(crate::host_units::list),
    )
    .route(
      "/api/servers/{name}/host-units/{unit}/watch",
      axum::routing::put(crate::host_units::set_watch),
    )
    .route(
      "/api/servers/{name}/host-units/{unit}/logs",
      get(crate::host_units::logs),
    )
    .route(
      "/api/servers/{name}/disk/measure",
      post(crate::disk::measure_now),
    )
    .route(
      "/api/servers/{name}/baseline/check",
      post(crate::baseline::check_now),
    )
    .route("/api/servers/{name}/host", get(host_info))
    .route("/api/servers/{name}/dirs", get(crate::host_dir::list))
    .route("/api/servers/{name}/pack", post(crate::host_dir::pack))
    .route("/api/updates/check", post(crate::updates::check_now))
    .route("/api/updates/auto", post(auto_update_now))
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
      "/api/servers/{name}/unmanaged/ignore",
      post(crate::import_api::ignore),
    )
    .route(
      "/api/servers/{name}/unmanaged/remove",
      post(crate::import_api::remove),
    )
    .route("/api/import", post(crate::import_api::preview))
    .route(
      "/api/convert/docker-run",
      post(crate::docker_run::convert),
    )
    .route("/api/services", get(list_services))
    .route("/api/services/{name}", get(show_service))
    .route("/api/services/{name}/logs", get(service_logs))
    .route(
      "/api/services/{name}/probe",
      post(crate::net_probe::service_probe),
    )
    .route("/api/logs/services", get(multi_service_logs))
    .route(
      "/api/services/{name}/logs/stream",
      get(crate::logs_stream::service),
    )
    .route(
      "/api/services/{name}/rollback",
      get(crate::rollback::target),
    )
    .route("/api/services/{name}/deployments", get(deployments))
    .route(
      "/api/services/{name}/timeline",
      get(crate::timeline::show),
    )
    .route("/api/services/{name}/note", put(crate::notes::service))
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
    .route("/api/backups/migrate", post(crate::backup::migrate_all))
    .route(
      "/api/backups/cleanup-legacy",
      post(crate::backup::cleanup_legacy),
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
    .route("/api/services/{name}/connect", get(crate::connect::open))
    .route("/api/gateways", get(list_gateways))
    .route("/api/gateways/{name}", get(show_gateway))
    .route("/api/gateways/{name}/config", get(gateway_config))
    .route("/api/gateways/{name}/link/rotate", post(link::rotate))
    .route("/api/gateways/{name}/logs", get(gateway_logs))
    .route(
      "/api/gateways/{name}/access-logs",
      get(crate::access_logs::gateway),
    )
    .route("/api/servers/{name}/agent-logs", get(agent_logs))
    .route("/api/core/logs", get(core_logs))
    .route("/api/whoami", get(crate::tokens::whoami))
    .route(
      "/api/gateways/{name}/logs/stream",
      get(crate::logs_stream::gateway),
    )
    .route("/api/routes", get(list_routes))
    .route(
      "/api/routes/{host}/access-logs",
      get(crate::access_logs::route),
    )
    .route("/api/routes/{hostname}/note", put(crate::notes::route))
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
    .route("/api/notify/keys", get(crate::notify_keys::list))
    .route(
      "/api/notify/keys/{name}",
      post(crate::notify_keys::create)
        .delete(crate::notify_keys::remove),
    )
    .route("/api/alerts", get(crate::rules::list))
    .route("/api/alerts/options", put(crate::rules::set_options))
    .route("/api/alerts/ack", post(crate::rules::ack_api))
    .route("/api/alerts/unack", post(crate::rules::unack_api))
    .route(
      "/api/alerts/digest",
      get(crate::rules::digest_preview_api),
    )
    .route(
      "/api/alerts/suppress",
      get(crate::rules::suppress_list_api)
        .post(crate::rules::suppress_add_api),
    )
    .route(
      "/api/alerts/suppress/{id}",
      axum::routing::delete(crate::rules::suppress_rm_api),
    )
    .route("/api/alerts/custom", post(crate::rules::custom_add_api))
    .route(
      "/api/alerts/custom/{name}",
      axum::routing::delete(crate::rules::custom_rm_api),
    )
    .route(
      "/api/alerts/{id}/services/{service}",
      axum::routing::put(crate::rules::patch_service),
    )
    .route(
      "/api/alerts/{id}",
      axum::routing::put(crate::rules::patch),
    )
    .route(
      "/api/egress",
      get(crate::egress::get).put(crate::egress::put),
    )
    .route("/api/tasks", get(crate::tasks::list))
    .route(
      "/api/tasks/{name}",
      get(crate::tasks::get)
        .put(crate::tasks::put)
        .delete(crate::tasks::remove),
    )
    .route("/api/tasks/{name}/run", post(crate::tasks::run_now))
    .route("/api/tasks/{name}/runs", get(crate::tasks::runs))
    .route(
      "/api/secrets/{name}",
      put(set_secret).delete(remove_secret),
    )
    .route("/api/secrets/{name}/rotate", post(rotate_secret))
    .route("/api/secrets/{name}/rollback", post(rollback_secret))
    .route(
      "/api/secrets/{name}/previous",
      axum::routing::delete(clear_secret_previous),
    )
    .route(
      "/api/servers/{name}/rotate-key",
      post(crate::key_rotation::rotate_agent),
    )
    .route("/api/core/key", get(crate::key_rotation::show))
    .route("/api/core/key/rotate", post(crate::key_rotation::rotate))
    .route("/api/core/key/commit", post(crate::key_rotation::commit))
    .route(
      "/api/core/key/rollback",
      post(crate::key_rotation::rollback),
    )
    .route("/api/secrets/{name}/generate", post(generate_secret))
    .route("/api/secret-leak-check", post(crate::secret_leak::check))
    .route(
      "/api/secrets/{name}/restriction",
      put(crate::secret_restrictions::put),
    )
    .route("/api/plan", post(make_plan))
    .route("/api/plans/{id}", get(show_plan))
    .route("/api/apply", post(apply_plan))
    .route("/api/runs", get(list_runs))
    .route("/api/runs/{id}", get(show_run))
    .route("/api/runs/{id}/cancel", post(cancel_run))
    .route("/api/export", get(export))
    .route("/api/audit", get(crate::audit::list))
    .route(
      "/api/credentials/revoke-all",
      post(revoke_all_credentials),
    )
    .route(
      "/api/tokens",
      get(crate::tokens::list).post(crate::tokens::create),
    )
    .route(
      "/api/tokens/{name}",
      put(crate::tokens::set).delete(crate::tokens::remove),
    )
    .route(
      "/api/tokens/{name}/explain",
      get(crate::token_explain::get)
        .layer(axum::Extension(crate::auth::SkipAuthActivity)),
    )
    .fallback(|uri: axum::http::Uri| async move {
      let path = uri.path();
      if path.starts_with("/api/") || path.starts_with("/agent/") {
        AppError(ApiError::not_found("没有这个接口")).into_response()
      } else {
        crate::web::serve(uri).await
      }
    })
    .layer(axum::middleware::from_fn_with_state(
      state.clone(),
      crate::audit::layer,
    ))
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
    let scheme = crate::source_trust::request_proto(&req);
    let base = format!("{scheme}://{host}");
    let hint = if crate::join::allows_script_install(&base) {
      format!(
        "更新后再试：curl -fsSL {base}/cli.sh | sh -s -- {base}"
      )
    } else {
      "请经 HTTPS 访问控制面，或从 GitHub Releases 下载最新 wharf 并核对 SHA256SUMS 后替换".into()
    };
    return AppError(
      ApiError::new(
        ErrorCode::InvalidInput,
        format!(
          "本机 wharf 太旧（接口版本 {api}，控制面至少要 {}）",
          wharf_api_types::MIN_CLI_API
        ),
      )
      .with_hint(hint),
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
  let status = views::status(&s, auth.services.as_ref()).await?;
  // 刚导入、还没同步过的在后台同步，下一次轮询就有了。
  if !status.edge_apps.is_empty()
    && let Ok(snap) = snapshot::load(&s.db).await
  {
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
  let mut data = crate::data::overview(&s).await?;
  if let Some(allowed) = &auth.services {
    crate::scope_filter::filter_data(allowed, &mut data);
  }
  Ok(Json(data))
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
  let core_key = s.core_keys().public_key();
  let mut commands = BTreeMap::from([
    (
      "docker".to_string(),
      format!(
        "docker run -d --label wharf.system=agent --name wharf-agent --restart unless-stopped --network host \
         -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/wharf:/var/lib/wharf -v /srv:/srv \
         -e WHARF_CORE_URL={core_url} -e WHARF_JOIN_TOKEN={token} -e WHARF_CORE_KEY={core_key} {}",
        image.as_deref().unwrap_or(&s.agent_image)
      ),
    ),
    (
      "binary".to_string(),
      format!(
        "wharf-agent join {core_url} {token} --core-key {core_key} && wharf-agent run"
      ),
    ),
  ]);
  if crate::join::allows_script_install(&core_url) {
    commands.insert(
      "script".into(),
      crate::join::script_command(
        &core_url,
        &token,
        &core_key,
        image.as_deref(),
      ),
    );
  }
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
  sealed: Option<Extension<crate::cli_tunnel::Sealed>>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<JoinRequest>,
) -> ApiResult<JoinResponse> {
  if sealed.is_none()
    && !crate::source_trust::is_direct_local(peer.ip(), &headers)
  {
    return Err(
      ApiError::new(
        ErrorCode::Unauthorized,
        "控制面已拒绝明文提交加入凭据",
      )
      .with_hint(
        "先拉取最新的 wharf-agent 镜像，再用最新的加入命令重试",
      )
      .into(),
    );
  }
  let hash = auth::hash_token(req.join_token.trim());
  let key = req.public_key.clone();
  if hex::decode(&key).map(|b| b.len()).unwrap_or(0) != 32 {
    return Err(ApiError::invalid("公钥格式不对").into());
  }
  let _rotation = s.key.operation.try_lock().map_err(|_| {
    ApiError::new(
      ErrorCode::Conflict,
      "通信密钥正在切换，稍后可用原加入命令重试",
    )
  })?;
  let hub = s.clone();
  let server = s
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let found: Option<(String, i64)> = tx
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
      tx.execute(
        "UPDATE agents SET public_key = ?1, join_token_hash = NULL, join_expires_at = NULL,
           report = NULL, last_seen = NULL, next_public_key = NULL, next_key_expires_at = NULL, key_rotation = 0
         WHERE server = ?2",
        params![key, server],
      )
      .map_err(sql_err)?;
      crate::core_node::clear_if_server(&tx, &server)?;
      tx.commit().map_err(sql_err)?;
      hub.hub.disconnect(&server);
      Ok(server)
    })
    .await?;
  tracing::info!("服务器 {server} 完成加入");
  let keys = s.core_keys();
  Ok(Json(JoinResponse {
    server,
    core_public_key: keys.public_key(),
    previous_core_public_key: keys.previous_public_key(),
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
  let state = s.clone();
  s.db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      tx.execute(
        "DELETE FROM resources WHERE kind = ?1 AND name = ?2",
        params![KIND_SERVER, name],
      )
      .map_err(sql_err)?;
      tx.execute(
        "DELETE FROM agents WHERE server = ?1",
        params![name],
      )
      .map_err(sql_err)?;
      crate::core_node::clear_if_server(&tx, &name)?;
      tx.commit().map_err(sql_err)?;
      state.hub.disconnect(&name);
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
      .filter(|n| {
        auth
          .services
          .as_ref()
          .is_none_or(|allowed| allowed.contains(*n))
      })
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

#[derive(Default, Deserialize)]
struct ServiceQuery {
  #[serde(default)]
  reveal: bool,
}

async fn show_service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(query): Query<ServiceQuery>,
) -> ApiResult<ServiceView> {
  auth.require(Perm::Read)?;
  if query.reveal {
    auth.require(Perm::Apply)?;
  }
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let live = views::cached_live(&s, &snap.world).await;
  let mut view = views::service_view(&snap, &net, &name, Some(&live))
    .ok_or_else(|| service_not_found(&name))?;
  if query.reveal {
    view.heartbeat =
      crate::service_monitor::heartbeat::view(&snap, &name, true);
  }
  Ok(Json(view))
}

#[derive(Deserialize)]
pub(super) struct LogsQuery {
  #[serde(default = "default_tail")]
  pub(super) tail: u32,
  /// 只看这个时间之后的：`30m`、`2h`、`3d` 或 RFC 3339 时间。
  #[serde(default)]
  pub(super) since: Option<String>,
  /// 关键字，不分大小写。
  #[serde(default)]
  pub(super) grep: Option<String>,
  /// 只看报错，按内容去重计数。
  #[serde(default)]
  pub(super) errors: bool,
  /// 每行最多多少字符。
  #[serde(default)]
  pub(super) max_line: Option<usize>,
}

fn default_tail() -> u32 {
  200
}

async fn project_logs(
  s: &AppState,
  server: &str,
  project: String,
  q: &LogsQuery,
) -> Result<Json<Value>, AppError> {
  Ok(Json(
    fetch_logs(s, server, q, |tail, since| AgentOp::Logs {
      project: project.clone(),
      tail,
      follow: false,
      since,
    })
    .await?,
  ))
}

/// 取日志并按 `q` 筛选。`op` 由行数和时间范围生成 agent 操作。
async fn fetch_logs(
  s: &AppState,
  server: &str,
  q: &LogsQuery,
  op: impl Fn(u32, Option<String>) -> AgentOp,
) -> Result<Value, ApiError> {
  let since =
    match q.since.as_deref().filter(|v| !v.trim().is_empty()) {
      Some(v) => {
        Some(crate::log_search::since_arg(v).ok_or_else(|| {
          ApiError::invalid(format!("时间范围 {v} 看不懂")).with_hint(
            "写成 30m、2h、3d，或 2026-11-22T08:00:00+08:00",
          )
        })?)
      }
      None => None,
    };
  let grep = q.grep.as_deref().filter(|g| !g.trim().is_empty());
  let filtering = grep.is_some() || q.errors;
  let logs: String = s
    .hub
    .call(
      server,
      // 过滤时多拿一些再挑，最终条数由 tail 控制。
      op(if filtering { 5000 } else { q.tail }, since),
      Duration::from_secs(40),
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await?;
  let logs = crate::log_redact::redact_text(&logs);
  if !filtering && q.max_line.is_none() {
    return Ok(json!({ "server": server, "logs": logs }));
  }
  let found = crate::log_search::search(
    &logs,
    &crate::log_search::Options {
      grep,
      errors: q.errors,
      max_line: q.max_line.unwrap_or(500).max(20),
      limit: q.tail.max(1) as usize,
    },
  );
  let mut v = serde_json::to_value(found).unwrap_or_default();
  v["server"] = json!(server);
  Ok(v)
}

/// `GET /api/servers/{name}/agent-logs`：这台机器上 agent 自己的日志。
async fn agent_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&name) {
    return Err(crate::world::server_not_found(&name).into());
  }
  Ok(Json(
    fetch_logs(&s, &name, &q, |tail, since| AgentOp::ContainerLogs {
      container: "wharf-agent".into(),
      tail,
      since,
    })
    .await?,
  ))
}

/// `GET /api/core/logs`：控制面自己的日志。控制面按自己的容器 id 挨台问，
/// 和它在同一台机器上的 agent 能读到。
async fn core_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let id = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| wharf_api_types::agent::container_id(&m))
    .ok_or_else(|| {
      ApiError::invalid("控制面不在容器里运行，看不了它的日志")
        .with_hint("在控制面所在的机器上直接看进程的输出")
    })?;
  let snap = snapshot::load(&s.db).await?;
  for name in snap.world.servers.keys() {
    if !s.hub.is_online(name) {
      continue;
    }
    let found = fetch_logs(&s, name, &q, |tail, since| {
      AgentOp::ContainerLogs {
        container: id.clone(),
        tail,
        since,
      }
    })
    .await;
    match found {
      Ok(v) => return Ok(Json(v)),
      // 不在这台机器上：问下一台。
      Err(e) if matches!(e.code, ErrorCode::NotFound) => continue,
      Err(e) => return Err(e.into()),
    }
  }
  Err(
    ApiError::new(
      ErrorCode::AgentFailed,
      "找不到和控制面在同一台机器上、在线的 agent",
    )
    .with_hint("控制面所在机器的 agent 要在线，并且是最新版本：wharf server upgrade --all")
    .into(),
  )
}

async fn service_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let (server, project) =
    crate::multi_logs::service_target(&snap.world, &name)?;
  project_logs(&s, server, project, &q).await
}

async fn multi_service_logs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(services): Query<crate::multi_logs::Services>,
  Query(q): Query<LogsQuery>,
) -> ApiResult<Value> {
  auth.require(Perm::Read)?;
  Ok(Json(
    crate::multi_logs::fetch(&s, &auth, services, q).await?,
  ))
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
    let mut images: Vec<wharf_api_types::agent::ImageInfo> =
      serde_json::from_str(&images).map_err(json_err)?;
    wharf_api_types::agent::normalize_image_digests(&mut images);
    out.push(DeploymentView {
      id,
      service,
      server,
      run_id,
      compose: crate::log_redact::redact_text(&compose),
      images,
      spec: spec
        .and_then(|s| serde_json::from_str(&s).ok())
        .map(|spec| crate::service_monitor::heartbeat::redact(&spec)),
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
  project_logs(&s, &row.spec.server, gateway_project(&name), &q).await
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
      .iter()
      .filter(|(_, route)| {
        auth.services.as_ref().is_none_or(|allowed| {
          crate::token_scope::route_spec_in_scope(
            allowed,
            &route.spec,
          )
        })
      })
      .filter_map(|(h, _)| views::route_view(&snap, &net, h))
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
  crate::log_redact::refresh(&s.db).await;
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
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(json!({ "removed": removed > 0 })))
}

// SECRETS

async fn list_secrets(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<SecretView>> {
  auth.require(Perm::Read)?;
  let mut list = read_secret_views(&s).await?;
  if let Some(allowed) = &auth.services {
    crate::scope_filter::filter_secrets(allowed, &mut list);
  }
  Ok(Json(list))
}

async fn read_secret_views(
  s: &AppState,
) -> Result<Vec<SecretView>, ApiError> {
  s.db.call_credentials(|c, key| {
    let world = crate::world::World::from_rows(db::all_resources(c)?)?;
    let tasks = crate::tasks::load_rows(c)?;
    let previous = db::previous_secrets(c, key, now_ms())?;
    let values = db::secrets(c, key)?;
    let restrictions = crate::secret_restrictions::load(c)?;
    let mut stmt = c.prepare("SELECT name, updated_at, prev_expires_at FROM secrets ORDER BY name")
      .map_err(sql_err)?;
    let rows = stmt.query_map([], |r| {
      Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?))
    }).map_err(sql_err)?;
    rows.map(|row| {
      let (name, updated_at, prev_expires_at) = row.map_err(sql_err)?;
      let old = previous.get(&name);
      Ok(SecretView {
        allowed_services: restrictions.get(&name)
          .map(|allowed| allowed.iter().cloned().collect()),
        fingerprint: values.get(&name).map(|value| db::secret_fingerprint(value)),
        has_previous: old.is_some(),
        prev_expires_at: old.and(prev_expires_at).map(to_time),
        prev_fingerprint: old.map(|value| db::secret_fingerprint(value)),
        other_refs: crate::secret_policy::other_secret_refs(
          &world, tasks.iter().map(|(name, spec, _)| (name.as_str(), &spec.how)), &name,
        ),
        used_by: secret_users(&world, &name),
        managed: managed_secret(&name),
        system: system_secret(&name).map(str::to_string),
        name,
        updated_at: to_time(updated_at),
      })
    }).collect::<Result<Vec<_>, ApiError>>()
  }).await
}

fn secret_users(
  world: &crate::world::World,
  name: &str,
) -> Vec<String> {
  world
    .services
    .iter()
    .filter(|(_, row)| {
      crate::secret_policy::service_uses_secret(&row.spec, name)
    })
    .map(|(service, _)| service.clone())
    .collect()
}

#[derive(Deserialize)]
struct SetSecret {
  value: String,
  keep_days: Option<u16>,
}

pub(crate) fn check_secret_name(name: &str) -> Result<(), ApiError> {
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
  let response = write_secret(&s, name, req, true).await?;
  Ok(Json(response.secret))
}

async fn rotate_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<SetSecret>,
) -> ApiResult<RotateSecretResponse> {
  auth.require(Perm::Admin)?;
  Ok(Json(write_secret(&s, name, req, false).await?))
}

async fn write_secret(
  s: &AppState,
  name: String,
  req: SetSecret,
  create: bool,
) -> Result<RotateSecretResponse, AppError> {
  check_secret_name(&name)?;
  refuse_managed(&name)?;
  let keep_days =
    req.keep_days.unwrap_or(db::DEFAULT_SECRET_KEEP_DAYS);
  if keep_days > 30 {
    return Err(
      ApiError::invalid("保留天数须在 0 到 30 之间")
        .with_hint("0 表示不保留旧值，默认保留 7 天")
        .into(),
    );
  }
  let value = if crate::render::is_auth_secret(&name) {
    crate::login::hash_basic_auth(req.value).await?
  } else {
    req.value
  };
  let n = name.clone();
  s.db
    .call_credentials(move |c, key| {
      let now = now_ms();
      let until = (keep_days > 0)
        .then(|| now + i64::from(keep_days) * 86_400_000);
      key.rotate_secret(c, &n, &value, now, until, create)
    })
    .await?;
  crate::log_redact::refresh(&s.db).await;
  secret_rotation_response(s, name).await
}

async fn rollback_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<RotateSecretResponse> {
  auth.require(Perm::Admin)?;
  refuse_managed(&name)?;
  let n = name.clone();
  let result = s
    .db
    .call_credentials(move |c, key| {
      key.rollback_secret(c, &n, now_ms())
    })
    .await;
  crate::log_redact::refresh(&s.db).await;
  result?;
  Ok(Json(secret_rotation_response(&s, name).await?))
}

async fn clear_secret_previous(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  refuse_managed(&name)?;
  let cleared =
    s.db.call(move |c| db::clear_secret_prev(c, &name)).await?;
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(json!({ "cleared": cleared })))
}

async fn secret_rotation_response(
  s: &AppState,
  name: String,
) -> Result<RotateSecretResponse, AppError> {
  let secret = read_secret_view(s, &name).await?;
  let snap = snapshot::load(&s.db).await?;
  let affected_services: Vec<_> = snap
    .world
    .services
    .iter()
    .filter(|(_, row)| {
      crate::secret_policy::service_renders_secret(&row.spec, &name)
    })
    .map(|(service, _)| service.clone())
    .collect();
  let affected_gateways: Vec<_> = snap
    .world
    .routes
    .iter()
    .filter(|(host, row)| {
      row.spec.auth && crate::render::route_auth_secret(host) == name
    })
    .flat_map(|(_, row)| snap.world.route_gateways(&row.spec))
    .map(str::to_string)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect();
  let needs_plan =
    !affected_services.is_empty() || !affected_gateways.is_empty();
  Ok(RotateSecretResponse {
    other_refs: secret.other_refs.clone(),
    secret,
    needs_plan,
    affected_services,
    affected_gateways,
    suggest: needs_plan
      .then(|| "wharf plan".into())
      .into_iter()
      .collect(),
  })
}

async fn read_secret_view(
  s: &AppState,
  name: &str,
) -> Result<SecretView, ApiError> {
  read_secret_views(s)
    .await?
    .into_iter()
    .find(|v| v.name == name)
    .ok_or_else(|| ApiError::not_found(format!("密钥 {name} 不存在")))
}

async fn generate_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<SecretView> {
  auth.require(Perm::Admin)?;
  check_secret_name(&name)?;
  refuse_managed(&name)?;
  crate::secret_policy::reject_system_secret(&name, "随机生成")?;
  let now = now_ms();
  let n = name.clone();
  s.db
    .call_credentials(move |c, key| {
      store_generated_secret(c, key, &n, now)
    })
    .await?;
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(read_secret_view(&s, &name).await?))
}

fn store_generated_secret(
  c: &mut rusqlite::Connection,
  key: &db::CredentialsKey,
  name: &str,
  now: i64,
) -> Result<(), ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let exists: bool = tx
    .query_row(
      "SELECT EXISTS(SELECT 1 FROM secrets WHERE name = ?1)",
      [name],
      |r| r.get(0),
    )
    .map_err(sql_err)?;
  if exists {
    return Err(ApiError::invalid(format!("密钥 {name} 已存在")));
  }
  let mut bytes = [0; 32];
  getrandom::fill(&mut bytes)
    .map_err(|_| ApiError::internal("无法生成随机密钥"))?;
  key.put_secret(&tx, name, &hex::encode(bytes), now, false)?;
  tx.commit().map_err(sql_err)
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
  crate::log_redact::refresh(&s.db).await;
  Ok(Json(json!({ "removed": removed > 0 })))
}

#[derive(Deserialize)]
struct RevokeAllRequest {
  confirm: Option<String>,
}

async fn revoke_all_credentials(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<RevokeAllRequest>,
) -> Result<Response, AppError> {
  auth.require(Perm::Admin)?;
  if req.confirm.as_deref() != Some("revoke-all") {
    return Err(
      ApiError::invalid(
        r#"必须传入 confirm = "revoke-all" 以确认作废全部登录凭证"#,
      )
      .with_hint(
        "该操作会退出所有网页会话并作废全部 API 令牌和门禁凭证",
      )
      .into(),
    );
  }
  let revoked = s.db.call(revoke_credentials).await?;
  let source = crate::login::source(peer.ip(), &headers);
  crate::audit::login_event(
    &s,
    "credentials_revoke_all",
    &auth.name,
    source.clone(),
  )
  .await;
  crate::security_receipt::send(
    &s,
    &auth.name,
    &source,
    "已作废全部登录凭证（会话、令牌、门禁密钥）".into(),
  )
  .await;
  Ok((
    [(axum::http::header::SET_COOKIE, crate::login::expired_session_cookie(peer.ip(), &headers))],
    Json(json!({
      "revoked": revoked,
      "next": "网页请用管理员密码重新登录；CLI 请在页面重新生成令牌后执行 wharf login",
    })),
  ).into_response())
}

fn revoke_credentials(
  c: &mut rusqlite::Connection,
) -> Result<Value, ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  let sessions =
    tx.execute("DELETE FROM sessions", []).map_err(sql_err)?;
  let api_tokens =
    tx.execute("DELETE FROM api_tokens", []).map_err(sql_err)?;
  let gate_keys =
    tx.execute("DELETE FROM gate_keys", []).map_err(sql_err)?;
  let join_tokens = tx.execute(
    "UPDATE agents SET join_token_hash = NULL, join_expires_at = NULL WHERE join_token_hash IS NOT NULL",
    [],
  ).map_err(sql_err)?;
  crate::gate::revocations::record_all(&tx)?;
  crate::gate::revocations::rotate_refresh_seed(&tx)?;
  crate::oidc::rotate_refresh_seed(&tx)?;
  tx.commit().map_err(sql_err)?;
  crate::gate::clear_tickets();
  crate::oidc::clear_codes();
  Ok(
    json!({ "sessions": sessions, "api_tokens": api_tokens, "gate_keys": gate_keys, "join_tokens": join_tokens }),
  )
}

// PLAN / APPLY / RUNS

async fn auto_update_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<wharf_api_types::view::AutoUpdateResult>> {
  auth.require(Perm::Apply)?;
  Ok(Json(crate::auto_update::run(&s).await))
}

async fn make_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  axum::Extension(audit): axum::Extension<crate::audit::AuditSlot>,
  Json(req): Json<PlanRequest>,
) -> ApiResult<Plan> {
  auth.require(Perm::Plan)?;
  if let Err(error) =
    planner::require_plan_request(&s, &auth, &req).await
  {
    audit.skip_record();
    return Err(error.into());
  }
  if !auth.human {
    guard_dangerous(&s, &req).await?;
  }
  let snap = snapshot::load(&s.db).await?;
  if let Err(error) =
    crate::token_scope::require_plan_request(&auth, &snap.world, &req)
  {
    audit.skip_record();
    return Err(error.into());
  }
  let planned = planner::make_plan_inner(
    &s,
    req,
    snap,
    true,
    auth.has(Perm::Admin),
  )
  .await?;
  crate::token_scope::require_plan(
    &auth,
    &planned.plan,
    &planned.route_effects,
  )?;
  planner::save(&s, &planned).await?;
  let mut seen = std::collections::BTreeSet::new();
  let addresses = planned
    .plan
    .items
    .iter()
    .map(|item| item.address.as_str())
    .filter(|address| seen.insert(*address))
    .take(20)
    .collect::<Vec<_>>()
    .join(",");
  let note = planned
    .plan
    .note
    .as_deref()
    .map(|n| format!(" 备注：{n}"))
    .unwrap_or_default();
  audit.set_detail(format!(
    "plan={} {addresses}{note}",
    planned.plan.plan_id
  ));
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
    .chain(
      req
        .fleet
        .iter()
        .chain(&req.partial)
        .flat_map(|f| f.servers.iter()),
    );
  for (name, after) in wanted {
    let before = snap.world.servers.get(name).map(|r| &r.settings);
    if let Some(what) =
      crate::host_access::opened_switch(before, after)
    {
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
  Ok(Json(apply::load_plan_for(&s, &auth, &id).await?))
}

async fn apply_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  axum::Extension(audit): axum::Extension<crate::audit::AuditSlot>,
  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
    std::net::SocketAddr,
  >,
  headers: HeaderMap,
  Json(req): Json<ApplyRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Apply)?;
  let plan_id = req.plan_id.clone();
  // 计划备注跟着执行记下来，操作记录里看得到为什么做。
  let note = apply::load_plan(&s, &plan_id)
    .await
    .ok()
    .and_then(|p| p.note)
    .map(|n| format!(" 备注：{n}"))
    .unwrap_or_default();
  let source = crate::login::client_key(peer.ip(), &headers);
  let resp =
    apply::start(s.clone(), req, &auth.perms, Some((&auth, source)))
      .await?;
  audit
    .set_detail(format!("plan={plan_id} run={}{note}", resp.run_id));
  Ok(Json(resp))
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
  Ok(Json(apply::list_runs(&s, &auth, q.limit.min(200)).await?))
}

async fn show_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Run> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::load_run_for(&s, &auth, &id).await?))
}

async fn cancel_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  if auth.services.is_some() {
    apply::load_run_for(&s, &auth, &id).await?;
  }
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
  let mut fleet = views::export(&snap.world);
  if let Some(allowed) = &auth.services {
    crate::scope_filter::filter_export(allowed, &mut fleet);
  }
  Ok(Json(fleet))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn rotate_and_list_secret_views_show_only_allowed_references()
  {
    let s = crate::rules::tests::test_state();
    s.db.call_credentials(|c, key| {
      for (kind, name, spec) in [
        ("server", "s1", json!({"github_mirror":"https://example.test/[[b64:K1]]"})),
        ("service", "app-a", json!({
          "server": "s1", "source": {"image": "nginx:1"},
          "env": {"TOKEN_FILE": "[[FILE:K1]]", "TOKEN_URL": "[[url:K1]]"}
        })),
        ("service", "app-b", json!({"server": "s1", "source": {"image": "nginx:1"}, "env": {"TOKEN": "[[K2]]"}})),
      ] {
        db::apply_write(c, &db::Write::Upsert {
          kind: kind.into(), name: name.into(), spec, meta: json!({}),
        })?;
      }
      let task = json!({"server":"s1","schedule":"","kind":"host","command":"echo [[json:K1]]"});
      c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES ('t1', ?1, 0, 0)", [task.to_string()]).map_err(sql_err)?;
      key.put_secret(c, "K1", "fixture-before", 1, false)?;
      key.put_secret(c, "K2", "fixture-unrelated", 1, false)
    }).await.unwrap();
    let auth =
      |services: Option<std::collections::BTreeSet<String>>| Auth {
        name: "fixture".into(),
        perms: [Perm::Read, Perm::Admin].into(),
        expires_at: None,
        allowed_from: vec![],
        services,
        human: false,
      };
    let Json(rotated) = rotate_secret(
      State(s.clone()),
      auth(None),
      Path("K1".into()),
      Json(SetSecret {
        value: "fixture-after".into(),
        keep_days: None,
      }),
    )
    .await
    .map_err(|e| e.0)
    .unwrap();
    assert!(rotated.needs_plan && rotated.secret.has_previous);
    assert_eq!(rotated.affected_services, ["app-a"]);
    let view = serde_json::to_string(&rotated).unwrap();
    assert!(
      !view.contains("fixture-before")
        && !view.contains("fixture-after")
    );
    let Json(all) = list_secrets(State(s.clone()), auth(None))
      .await
      .map_err(|e| e.0)
      .unwrap();
    assert_eq!(all[0].used_by, ["app-a"]);
    assert_eq!(all[0].other_refs, ["server:s1", "task:t1"]);
    let Json(filtered) =
      list_secrets(State(s), auth(Some(["app-a".into()].into())))
        .await
        .map_err(|e| e.0)
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "K1");
    assert_eq!(filtered[0].used_by, ["app-a"]);
    assert!(filtered[0].other_refs.is_empty());
  }

  #[test]
  fn encoded_and_file_secret_users_follow_service_scope() {
    let mut world = crate::world::World::default();
    for (name, reference) in [("a", "[[url:S]]"), ("b", "[[FILE:S]]")]
    {
      world.services.insert(name.into(), crate::world::ServiceRow {
        spec: serde_json::from_value(json!({
          "server": "s1", "source": {"image": "nginx:1"}, "env": {"KEY": reference}
        })).unwrap(),
        host_ports: Default::default(),
        import: None,
        pins: Default::default(),
        commit: None,
        version: 1,
      });
    }
    let used_by = secret_users(&world, "S");
    assert_eq!(used_by, ["a", "b"]);
    let mut rows = vec![SecretView {
      fingerprint: None,
      has_previous: false,
      prev_expires_at: None,
      prev_fingerprint: None,
      other_refs: vec!["task:t1".into()],
      allowed_services: Some(vec!["a".into(), "b".into()]),
      name: "S".into(),
      used_by,
      managed: false,
      system: None,
      updated_at: to_time(0),
    }];
    crate::scope_filter::filter_secrets(
      &["b".into()].into(),
      &mut rows,
    );
    assert_eq!(rows[0].used_by, ["b"]);
    assert_eq!(rows[0].allowed_services.as_ref().unwrap(), &["b"]);
    assert!(rows[0].other_refs.is_empty());
  }

  fn rotation_admin(human: bool) -> Auth {
    Auth {
      name: "admin".into(),
      perms: [Perm::Admin].into(),
      expires_at: None,
      allowed_from: vec![],
      services: None,
      human,
    }
  }

  async fn rotate_core_for_test(
    s: &Arc<AppState>,
    human: bool,
  ) -> ApiResult<wharf_api_types::view::CoreKeyView> {
    crate::key_rotation::rotate(
      State(s.clone()),
      rotation_admin(human),
      ConnectInfo("203.0.113.1:3000".parse().unwrap()),
      HeaderMap::new(),
      Json(serde_json::from_value(json!({})).unwrap()),
    )
    .await
  }

  #[tokio::test]
  async fn legacy_agent_is_online_but_key_rotation_requires_capability()
   {
    let s = crate::rules::tests::test_state();
    s.db.call(|c| {
      c.execute("INSERT INTO agents (server, public_key) VALUES ('s1', 'fixture-public')", []).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    s.hub.mock_agent("s1", false, |_| {
      panic!("不应向旧 agent 下发密钥操作")
    });
    assert!(s.hub.is_online("s1"));
    let error = crate::key_rotation::rotate_agent(
      State(s.clone()),
      rotation_admin(true),
      ConnectInfo("203.0.113.1:3000".parse().unwrap()),
      HeaderMap::new(),
      Path("s1".into()),
    )
    .await
    .err()
    .unwrap()
    .0;
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.hint.unwrap().contains("upgrade"));
    assert_eq!(
      rotate_core_for_test(&s, true).await.err().unwrap().0.code,
      ErrorCode::Conflict
    );
    assert!(s.hub.is_online("s1"));
  }

  #[tokio::test]
  async fn core_rotation_requires_current_cli_to_confirm_config_writable()
   {
    let s = crate::rules::tests::test_state();
    let error =
      rotate_core_for_test(&s, false).await.err().unwrap().0;
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.hint.unwrap().contains("config.toml"));
  }

  #[tokio::test]
  async fn core_rotation_aborts_on_prepare_failure_and_all_agents_keep_trusting_old_key()
   {
    use ed25519_dalek::{Signature, Verifier};
    use std::sync::Mutex;
    let dir = tempfile::tempdir().unwrap();
    let mut s = crate::rules::tests::test_state();
    Arc::get_mut(&mut s).unwrap().data_dir = dir.path().into();
    let old = s.core_keys().verifying_key();
    let old_public = hex::encode(old.to_bytes());
    s.db
      .call(|c| {
        c.execute_batch(
          "INSERT INTO agents (server, public_key, key_rotation)
        VALUES ('s1', 'fixture-one', 1), ('s2', 'fixture-two', 1);",
        )
        .map_err(sql_err)
      })
      .await
      .unwrap();
    let configurations = ["s1", "s2"].map(|name| {
      let config = Arc::new(Mutex::new((old_public.clone(), None)));
      let persisted = config.clone();
      s.hub.mock_rotation_agent(name, move |op| {
        let AgentOp::TrustCoreKey(job) = op else {
          panic!("应下发控制面公钥")
        };
        assert!(!job.reconnect);
        let fail = name == "s2" && job.alt.is_some();
        *persisted.lock().unwrap() = (job.current, job.alt);
        if fail {
          return Err(ApiError::internal("测试：推送应答丢失"));
        }
        Ok(Value::Null)
      });
      config
    });
    assert_eq!(
      rotate_core_for_test(&s, true).await.err().unwrap().0.code,
      ErrorCode::Conflict
    );
    assert!(!dir.path().join("core.key.next").exists());
    let payload = b"fixture-handshake";
    let (signature, alt) = s.core_keys().sign(payload);
    assert!(alt.is_none());
    let bytes: [u8; 64] =
      hex::decode(signature).unwrap().try_into().unwrap();
    for config in &configurations {
      assert_eq!(*config.lock().unwrap(), (old_public.clone(), None));
      assert!(
        old.verify(payload, &Signature::from_bytes(&bytes)).is_ok()
      );
    }
    assert!(s.hub.is_online("s1") && s.hub.is_online("s2"));
  }

  #[tokio::test(start_paused = true)]
  async fn core_rotation_reports_reconnect_timeout_after_switch_and_sends_receipt()
   {
    use crate::rules::tests::{
      TEST_LOCK, notice_titles, reset_memory,
    };

    let _guard = TEST_LOCK.lock().await;
    reset_memory();
    let dir = tempfile::tempdir().unwrap();
    let mut s = crate::rules::tests::test_state();
    Arc::get_mut(&mut s).unwrap().data_dir = dir.path().into();
    let old = s.core_keys().verifying_key();
    s.db.call(|c| {
      c.execute(
        "INSERT INTO agents (server, public_key, key_rotation) VALUES ('s1', 'fixture-public', 1)",
        [],
      ).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    s.hub.mock_rotation_agent("s1", |op| {
      assert!(matches!(op, AgentOp::TrustCoreKey(_)));
      Ok(Value::Null)
    });

    let Json(view) = rotate_core_for_test(&s, true)
      .await
      .map_err(|e| e.0)
      .unwrap();
    assert_eq!(view.pending_agents, ["s1"]);
    assert_ne!(s.core_keys().verifying_key(), old);
    assert_eq!(view.public_key, s.core_keys().public_key());
    assert!(view.previous_expires_at.is_some());
    assert_eq!(
      notice_titles(&s, "security_receipt").await,
      ["在线轮换控制面公钥"]
    );
  }

  #[tokio::test]
  async fn core_rotation_dual_signatures_then_rollback_and_commit() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let _guard = crate::rules::tests::TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut s = crate::rules::tests::test_state();
    Arc::get_mut(&mut s).unwrap().data_dir = dir.path().into();
    let old = s.core_keys().verifying_key();
    let verify = |key: VerifyingKey| {
      let payload = wharf_api_types::tunnel::tunnel_payload(
        "nonce", "core-kx", "peer-kx",
      );
      let (signature, alt) = s.core_keys().sign(&payload);
      [signature].into_iter().chain(alt).any(|signature| {
        let bytes: [u8; 64] =
          hex::decode(signature).unwrap().try_into().unwrap();
        key.verify(&payload, &Signature::from_bytes(&bytes)).is_ok()
      })
    };
    let Json(first) = rotate_core_for_test(&s, true)
      .await
      .map_err(|e| e.0)
      .unwrap();
    let new = s.core_keys().verifying_key();
    assert!(first.previous_expires_at.is_some());
    assert!(verify(old) && verify(new));
    let Json(rolled_back) = crate::key_rotation::rollback(
      State(s.clone()),
      rotation_admin(true),
    )
    .await
    .map_err(|e| e.0)
    .unwrap();
    assert!(rolled_back.previous_expires_at.is_none());
    assert!(verify(old) && !verify(new));
    let Json(second) = rotate_core_for_test(&s, true)
      .await
      .map_err(|e| e.0)
      .unwrap();
    let new = s.core_keys().verifying_key();
    assert!(second.previous_expires_at.is_some());
    assert!(verify(old) && verify(new));
    let Json(committed) = crate::key_rotation::commit(
      State(s.clone()),
      rotation_admin(true),
    )
    .await
    .map_err(|e| e.0)
    .unwrap();
    assert!(committed.previous_expires_at.is_none());
    assert!(!verify(old) && verify(new));
    assert!(!dir.path().join("core.key.prev").exists());
  }

  #[tokio::test]
  async fn revoke_all_revokes_login_only_and_preserves_gateway_callback()
   {
    let _guard = crate::rules::tests::TEST_LOCK.lock().await;
    crate::rules::tests::reset_memory();
    let s = crate::rules::tests::test_state();
    let (refresh_before, oidc_before) = s.db.call_credentials(|c, key| {
      crate::login::set_admin(c, "admin", "fixture-hash")?;
      c.execute_batch(
        "INSERT INTO sessions (hash, created_at, expires_at) VALUES ('h1', 0, 1), ('h2', 0, 1);
         INSERT INTO api_tokens (name, hash, scope, created_at) VALUES ('t1', 'h1', 'read', 0), ('t2', 'h2', 'read', 0);
         INSERT INTO gate_keys (name, hash, hosts, created_at) VALUES ('g1', 'h1', '[]', 0);
         INSERT INTO agents (server, public_key, join_token_hash, join_expires_at) VALUES ('s1', NULL, 'h1', 1), ('s2', 'joined', NULL, NULL);
         INSERT INTO notify_keys (name, hash, created_at) VALUES ('n1', 'h1', 0);"
      ).map_err(sql_err)?;
      key.put_secret(c, "K1", "fixture-value", 0, false)?;
      key.put_secret(c, "NOTIFY_URL_n1", "fixture-url", 0, false)?;
      Ok((db::setting(c, "gate.rt_key")?, hex::encode(crate::gate::seed(c, "oidc.refresh_key")?)))
    }).await.unwrap();
    assert!(refresh_before.is_none());
    let callback =
      crate::gate::revocations::config_key(&s.db).await.unwrap();
    let seed =
      s.db.call(|c| db::setting(c, "gate.rt_key")).await.unwrap();
    assert!(crate::gate::fixture_ticket(true));
    assert!(crate::oidc::fixture_code(true));
    let response = revoke_all_credentials(
      State(s.clone()),
      Auth {
        name: "admin".into(),
        perms: [Perm::Admin].into(),
        expires_at: None,
        allowed_from: vec![],
        services: None,
        human: true,
      },
      ConnectInfo("203.0.113.1:3000".parse().unwrap()),
      HeaderMap::new(),
      Json(RevokeAllRequest {
        confirm: Some("revoke-all".into()),
      }),
    )
    .await
    .map_err(|e| e.0)
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
      .await
      .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
      value["revoked"],
      json!({"sessions": 2, "api_tokens": 2, "gate_keys": 1, "join_tokens": 1})
    );
    assert!(!crate::gate::fixture_ticket(false));
    assert!(!crate::oidc::fixture_code(false));
    assert!(
      callback
        == crate::gate::revocations::config_key(&s.db).await.unwrap()
    );
    s.db.call(move |c| {
      assert!(db::setting(c, "gate.revocation_seed")? == seed);
      assert!(db::setting(c, "gate.rt_key")? != seed);
      assert!(db::setting(c, "oidc.refresh_key")? != Some(oidc_before));
      let cutoff: Value = serde_json::from_str(&db::setting(c, "gate.revocations")?.unwrap()).unwrap();
      assert!((now_ms() / 1000 - 5..=now_ms() / 1000).contains(&cutoff["admin"].as_i64().unwrap()));
      let still_present: (i64, i64, i64, i64) = c.query_row(
        "SELECT (SELECT COUNT(*) FROM agents WHERE public_key IS NOT NULL),
                (SELECT COUNT(*) FROM secrets), (SELECT COUNT(*) FROM notify_keys),
                (SELECT COUNT(*) FROM agents WHERE join_token_hash IS NOT NULL OR join_expires_at IS NOT NULL)", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
      ).map_err(sql_err)?;
      assert_eq!(still_present, (1, 2, 1, 0));
      Ok(())
    }).await.unwrap();
    assert_eq!(
      crate::rules::tests::notice_titles(&s, "security_receipt")
        .await
        .len(),
      1
    );
  }

  #[tokio::test]
  async fn generates_and_stores_encrypted_secret() {
    db::Db::memory()
      .call_credentials(|c, key| {
        store_generated_secret(c, key, "APP_KEY", 1)?;
        let value = key.secret(c, "APP_KEY")?.unwrap();
        let stored: String = c
          .query_row(
            "SELECT value FROM secrets WHERE name = 'APP_KEY'",
            [],
            |row| row.get(0),
          )
          .map_err(sql_err)?;
        assert!(stored != value);
        assert_eq!(hex::decode(value).unwrap().len(), 32);
        Ok(())
      })
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn generating_an_existing_secret_preserves_its_value() {
    db::Db::memory()
      .call_credentials(|c, key| {
        key.put_secret(c, "APP_KEY", "fixture-original", 1, true)?;
        key.rotate_secret(
          c,
          "APP_KEY",
          "fixture-current",
          2,
          Some(100),
          false,
        )?;
        let err =
          store_generated_secret(c, key, "APP_KEY", 3).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(
          key.secret(c, "APP_KEY")?.as_deref(),
          Some("fixture-current")
        );
        assert_eq!(
          db::previous_secrets(c, key, 3)?["APP_KEY"],
          "fixture-original"
        );
        Ok(())
      })
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn agent_join_rejects_plaintext_non_local_and_accepts_sealed()
  {
    let state = crate::rules::tests::test_state();
    for (peer, forwarded, sealed, allowed) in [
      ("203.0.113.5:4000", false, false, false),
      ("127.0.0.1:4000", true, false, false),
      ("203.0.113.5:4000", false, true, true),
      ("127.0.0.1:4000", false, false, true),
    ] {
      let token = auth::new_token();
      let hash = auth::hash_token(&token);
      state.db.call(move |c| {
        c.execute("INSERT OR REPLACE INTO agents (server, join_token_hash, join_expires_at) VALUES ('s1', ?1, ?2)", params![hash, now_ms() + 60_000])
          .map_err(sql_err)?;
        Ok(())
      }).await.unwrap();
      let mut headers = HeaderMap::new();
      if forwarded {
        headers
          .insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
      }
      let key = state.core_keys().public_key();
      let result = agent_join(
        State(state.clone()),
        sealed.then_some(Extension(crate::cli_tunnel::Sealed)),
        ConnectInfo(peer.parse().unwrap()),
        headers,
        Json(JoinRequest {
          join_token: token,
          public_key: key,
        }),
      )
      .await;
      if allowed {
        assert!(result.is_ok());
      } else {
        let Err(error) = result else {
          panic!("明文加入被放行")
        };
        assert_eq!(error.0.code, ErrorCode::Unauthorized);
      }
      let consumed = state.db.call(|c| c.query_row("SELECT join_token_hash IS NULL FROM agents WHERE server = 's1'",
        [], |r| r.get::<_, bool>(0)).map_err(sql_err)).await.unwrap();
      assert_eq!(consumed, allowed);
    }
  }
}
