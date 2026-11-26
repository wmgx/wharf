use super::*;

// SERVICES

pub(super) async fn list_services(
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
pub(super) struct VaultRequest {
  vault: String,
}

pub(super) async fn show_vault(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  let vault = s.db.call(|c| crate::db::setting(c, VAULT_KEY)).await?;
  Ok(Json(json!({ "vault": vault })))
}

pub(super) async fn set_vault(
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
pub(super) struct ServiceQuery {
  #[serde(default)]
  reveal: bool,
}

pub(super) async fn show_service(
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
pub(crate) struct LogsQuery {
  #[serde(default = "default_tail")]
  pub(crate) tail: u32,
  /// 只看这个时间之后的：`30m`、`2h`、`3d` 或 RFC 3339 时间。
  #[serde(default)]
  pub(crate) since: Option<String>,
  /// 关键字，不分大小写。
  #[serde(default)]
  pub(crate) grep: Option<String>,
  /// 只看报错，按内容去重计数。
  #[serde(default)]
  pub(crate) errors: bool,
  /// 每行最多多少字符。
  #[serde(default)]
  pub(crate) max_line: Option<usize>,
}

fn default_tail() -> u32 {
  200
}

pub(super) async fn project_logs(
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
pub(super) async fn fetch_logs(
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
pub(super) async fn agent_logs(
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
pub(super) async fn core_logs(
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

pub(super) async fn service_logs(
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

pub(super) async fn multi_service_logs(
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

pub(super) async fn deployments(
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

pub(super) async fn list_gateways(
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

pub(super) async fn show_gateway(
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

pub(super) async fn gateway_config(
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

pub(super) async fn gateway_logs(
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

pub(super) async fn list_routes(
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
