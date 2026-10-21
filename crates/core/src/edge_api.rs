//! 边缘应用的接口：列表、详情、发现厂商账号里的项目、拉脚本、版本、回滚、重新发布。
//! 新增、修改、取消纳管走计划（`UpsertEdgeApp` / `RemoveEdgeApp`）。

use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, State},
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
  planner::Step,
  snapshot::{self, with_timeout},
  state::AppState,
  views,
};

/// `GET /api/edge`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<EdgeAppView>> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(
    snap
      .world
      .edge_apps
      .keys()
      .filter_map(|n| views::edge_view(&s, &snap, n))
      .collect(),
  ))
}

/// `GET /api/edge/{name}`：先实时读一次厂商那边的现状。
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<EdgeAppView> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.edge_apps.contains_key(&name) {
    return Err(edge_not_found(&name).into());
  }
  edge::refresh(&s, &snap, &name).await;
  Ok(Json(
    views::edge_view(&s, &snap, &name)
      .ok_or_else(|| edge_not_found(&name))?,
  ))
}

/// `GET /api/accounts/{name}/edge`：账号里的 Workers 和 Pages 项目，标出已导入的。
pub async fn discover(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(account): Path<String>,
) -> ApiResult<Vec<EdgeProjectView>> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let provider =
    snapshot::edge_provider(edge::account(&snap, &account)?)?;
  let list =
    with_timeout("读取 Workers / Pages 项目", provider.list())
      .await?;
  Ok(Json(
    list
      .into_iter()
      .map(|(kind, p)| {
        let kind = match kind {
          wharf_providers::EdgeKind::Worker => EdgeKind::Worker,
          wharf_providers::EdgeKind::Pages => EdgeKind::Pages,
        };
        let managed_as = snap
          .world
          .edge_apps
          .iter()
          .find(|(n, r)| {
            r.spec.account == account
              && r.spec.kind == kind
              && r.spec.project_name(n) == p.name
          })
          .map(|(n, _)| n.clone());
        EdgeProjectView {
          kind,
          project: p.name,
          url: p.url,
          modified_at: p.modified_at,
          managed_as,
        }
      })
      .collect(),
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
) -> ApiResult<Vec<EdgeVersionView>> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(edge::versions(&snap, &name).await?))
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
