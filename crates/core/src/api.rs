//! HTTP API。错误统一为 `{ code, message, hint, suggest }`。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

mod link;

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
    AccountView, DataView, DeploymentView, GatewayView, JoinInfo,
    JoinRequest, JoinResponse, Perm, RouteView, SecretView,
    ServerView, ServiceView, Status,
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
    (status, Json(self.0)).into_response()
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
    .route("/api/plan", post(make_plan))
    .route("/api/plans/{id}", get(show_plan))
    .route("/api/apply", post(apply_plan))
    .route("/api/runs", get(list_runs))
    .route("/api/runs/{id}", get(show_run))
    .route("/api/runs/{id}/cancel", post(cancel_run))
    .route("/api/export", get(export))
    .route("/api/audit", get(crate::audit::list))
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

include!("api/resources.rs");
include!("api/accounts_and_runs.rs");
