//! 边缘应用的接口：列表、详情、发现厂商账号里的项目、拉脚本、版本、回滚、重新发布。
//! 新增、修改、取消纳管走计划（`UpsertEdgeApp` / `RemoveEdgeApp`）。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, Query, State},
};
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  plan::ApplyResponse,
  spec::EdgeKind,
  view::{
    EdgeAppView, EdgeProjectView, EdgeScript, EdgeVersionView,
    TokenScope,
  },
};

use crate::{
  api::ApiResult,
  apply::start_task,
  auth::Auth,
  edge::{self, edge_not_found},
  edge_sync,
  planner::Step,
  snapshot::{self, Snapshot, with_timeout},
  state::AppState,
  views,
};

#[derive(Deserialize, Default)]
pub struct SyncQuery {
  /// 先同步再返回（CLI 和页面上的"同步"按钮用）；不给时读控制面里存的。
  #[serde(default, deserialize_with = "flag")]
  sync: bool,
}

/// `?sync=1`、`?sync=true` 都算。
fn flag<'de, D: serde::Deserializer<'de>>(
  d: D,
) -> Result<bool, D::Error> {
  let v = String::deserialize(d)?;
  Ok(matches!(v.as_str(), "1" | "true" | "yes"))
}

/// `GET /api/edge`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<EdgeAppView>> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  for name in snap.world.edge_apps.keys() {
    edge_sync::sync_if_stale(&s, &snap, name);
  }
  Ok(Json(
    snap
      .world
      .edge_apps
      .keys()
      .filter_map(|n| views::edge_view(&snap, n))
      .collect(),
  ))
}

/// 同步（`sync` 或从没同步过时）后重新读快照，否则读到的旧了就后台同步。
async fn synced(
  s: &Arc<AppState>,
  name: &str,
  sync: bool,
) -> Result<Snapshot, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.edge_apps.contains_key(name) {
    return Err(edge_not_found(name));
  }
  if sync || !snap.edge_cache.contains_key(name) {
    edge_sync::sync_app(s, &snap, name, false).await?;
    return snapshot::load(&s.db).await;
  }
  edge_sync::sync_if_stale(s, &snap, name);
  Ok(snap)
}

/// `GET /api/edge/{name}`
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<SyncQuery>,
) -> ApiResult<EdgeAppView> {
  auth.require(TokenScope::Read)?;
  let snap = synced(&s, &name, q.sync).await?;
  Ok(Json(
    views::edge_view(&snap, &name)
      .ok_or_else(|| edge_not_found(&name))?,
  ))
}

/// `GET /api/accounts/{name}/edge`：账号里的 Workers 和 Pages 项目，标出已导入的。
pub async fn discover(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(account): Path<String>,
  Query(q): Query<SyncQuery>,
) -> ApiResult<Vec<EdgeProjectView>> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  edge::account(&snap, &account)?;
  let mut list = match snap.edge_accounts.get(&account) {
    Some(list) if !q.sync => list.clone(),
    _ => edge_sync::sync_account(&s, &snap, &account).await?,
  };
  edge_sync::mark_managed(&snap, &mut list);
  Ok(Json(list))
}

/// `POST /api/edge/{name}/accept`：以线上为准，把现在的线上版本记为 Wharf 期望的版本。
pub async fn accept(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<EdgeAppView> {
  auth.require(TokenScope::ApplySafe)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.edge_apps.contains_key(&name) {
    return Err(edge_not_found(&name).into());
  }
  edge_sync::sync_app(&s, &snap, &name, true).await?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(
    views::edge_view(&snap, &name)
      .ok_or_else(|| edge_not_found(&name))?,
  ))
}

/// `GET /api/edge/{name}/script`：下载 Worker 线上的脚本（只支持单文件）。
pub async fn script(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<EdgeScript> {
  auth.require(TokenScope::Plan)?;
  let snap = snapshot::load(&s.db).await?;
  let spec = &snap
    .world
    .edge_apps
    .get(&name)
    .ok_or_else(|| edge_not_found(&name))?
    .spec;
  if spec.kind != EdgeKind::Worker {
    return Err(
      ApiError::invalid(format!(
        "{name} 是 Pages，没有单个脚本可以下载"
      ))
      .into(),
    );
  }
  let provider =
    snapshot::edge_provider(edge::account(&snap, &spec.account)?)?;
  let script = with_timeout(
    &format!("下载 {name} 的脚本"),
    provider.download_worker(spec.project_name(&name)),
  )
  .await?;
  Ok(Json(EdgeScript {
    filename: script.filename,
    content: script.content,
    modules: script.modules,
  }))
}

/// `GET /api/edge/{name}/versions`：厂商那边的版本，新的在前。
pub async fn versions(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<SyncQuery>,
) -> ApiResult<Vec<EdgeVersionView>> {
  auth.require(TokenScope::Read)?;
  let snap = synced(&s, &name, q.sync).await?;
  Ok(Json(
    snap
      .edge_cache
      .get(&name)
      .map(|c| c.versions.clone())
      .unwrap_or_default(),
  ))
}

#[derive(Deserialize, Default)]
pub struct RollbackRequest {
  /// 版本 id（可以只写前几位），不写就是上一个版本。
  #[serde(default)]
  version: Option<String>,
}

/// `POST /api/edge/{name}/rollback`
pub async fn rollback(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<RollbackRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplySafe)?;
  let snap = snapshot::load(&s.db).await?;
  let list = edge::versions(&snap, &name).await?;
  let version = edge::rollback_target(&list, req.version.as_deref())?;
  Ok(Json(
    start_task(
      s.clone(),
      format!("回滚 {name} 到 {}", &version[..8.min(version.len())]),
      Step::EdgeRollback { app: name, version },
    )
    .await?,
  ))
}

/// `POST /api/edge/{name}/redeploy`：按现在的代码来源再发布一次（git 来源取最新）。
pub async fn redeploy(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplySafe)?;
  let snap = snapshot::load(&s.db).await?;
  let app = snap
    .world
    .edge_apps
    .get(&name)
    .ok_or_else(|| edge_not_found(&name))?;
  if app.spec.source.is_none() {
    return Err(
      ApiError::invalid(format!(
        "边缘应用 {name} 只纳管，没有代码来源"
      ))
      .suggest(format!("wharf edge deploy {name} --script <文件>"))
      .into(),
    );
  }
  Ok(Json(
    start_task(
      s.clone(),
      format!("重新发布 {name}"),
      Step::EdgeDeploy { app: name },
    )
    .await?,
  ))
}
