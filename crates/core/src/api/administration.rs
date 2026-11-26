use super::*;

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

pub(super) async fn list_accounts(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<AccountView>> {
  auth.require(Perm::Read)?;
  let accounts = s.db.call(|c| db::accounts(c)).await?;
  Ok(Json(accounts.iter().map(account_view).collect()))
}

#[derive(Deserialize)]
pub(super) struct AddAccount {
  name: String,
  #[serde(default = "default_kind")]
  kind: String,
  token: String,
}

fn default_kind() -> String {
  "cloudflare".into()
}

pub(super) async fn discover(
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

pub(super) async fn save_account(
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

pub(super) async fn add_account(
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

pub(super) async fn rediscover_account(
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

pub(super) async fn remove_account(
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

pub(super) async fn list_secrets(
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
  let mut list = rows
    .into_iter()
    .map(|(name, at)| SecretView {
      used_by: secret_users(&snap.world, &name),
      managed: managed_secret(&name),
      system: system_secret(&name).map(str::to_string),
      name,
      updated_at: to_time(at),
    })
    .collect();
  if let Some(allowed) = &auth.services {
    crate::scope_filter::filter_secrets(allowed, &mut list);
  }
  Ok(Json(list))
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

#[derive(Deserialize)]
pub(super) struct SetSecret {
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

pub(super) async fn set_secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<SetSecret>,
) -> ApiResult<SecretView> {
  auth.require(Perm::Admin)?;
  check_secret_name(&name)?;
  refuse_managed(&name)?;
  let value = if crate::render::is_auth_secret(&name) {
    crate::login::hash_basic_auth(req.value).await?
  } else {
    req.value
  };
  let now = now_ms();
  let n = name.clone();
  s.db
    .call_credentials(move |c, key| {
      key.put_secret(c, &n, &value, now, true)
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

pub(super) async fn remove_secret(
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

pub(super) async fn auto_update_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<wharf_api_types::view::AutoUpdateResult>> {
  auth.require(Perm::Apply)?;
  Ok(Json(crate::auto_update::run(&s).await))
}

pub(super) async fn make_plan(
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
pub(super) async fn guard_dangerous(
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

pub(super) async fn show_plan(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Plan> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::load_plan_for(&s, &auth, &id).await?))
}

pub(super) async fn apply_plan(
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
pub(super) struct RunsQuery {
  #[serde(default = "default_limit")]
  limit: u32,
}

fn default_limit() -> u32 {
  20
}

pub(super) async fn list_runs(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<RunsQuery>,
) -> ApiResult<Vec<Run>> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::list_runs(&s, &auth, q.limit.min(200)).await?))
}

pub(super) async fn show_run(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
) -> ApiResult<Run> {
  auth.require(Perm::Read)?;
  Ok(Json(apply::load_run_for(&s, &auth, &id).await?))
}

pub(super) async fn cancel_run(
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

pub(super) async fn export(
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
