use crate::{
  api::ApiResult,
  audit::AuditSlot,
  auth::Auth,
  db::{self, sql_err},
  jobs::{CLEANUP_POLICY_KEY, cleanup_policy},
  locks::LockSpec,
  snapshot::{self, Snapshot},
  state::AppState,
};
use axum::{
  Extension, Json,
  extract::{Query, State},
  http::StatusCode,
  response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
  time::Duration,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentCleanupEntry, AgentOp, CleanupDeleteRequest,
    CleanupDeleteResult,
    CleanupKind::{self, *},
  },
  view::{
    CleanupSkippedServer, DataCleanupActionResult,
    DataCleanupExecRequest, DataCleanupItem, DataCleanupPolicy,
    DataCleanupResult, DataCleanupView, Issue, IssueLevel,
    IssueSubject, Perm,
  },
};

pub type CleanupCache =
  std::sync::RwLock<BTreeMap<String, Vec<AgentCleanupEntry>>>;

mod inventory;
pub(crate) use inventory::migration_block;
use inventory::{
  Candidate, Listing, Record, active_resource, cleanup_block,
  desired_links, inventory, is_archive, list, mount_reason,
  obsolete_migration,
};

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Filters {
  server: Option<String>,
  service: Option<String>,
  kind: Option<CleanupKind>,
  expired_only: bool,
}

fn machine_item(item: &DataCleanupItem) -> bool {
  item.is_core
    || item.service.is_none()
    || matches!(item.kind, OrphanTaskData | OrphanCaddy | OrphanFrpc)
    || item.service.as_ref().is_some_and(|s| {
      s.starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
    })
}

fn eligible_scope(auth: &Auth, item: &DataCleanupItem) -> bool {
  auth.services.as_ref().is_none_or(|allowed| {
    !machine_item(item)
      && item.service.as_ref().is_some_and(|s| allowed.contains(s))
  })
}

fn matches_filter(item: &DataCleanupItem, filters: &Filters) -> bool {
  filters
    .service
    .as_ref()
    .is_none_or(|svc| item.service.as_ref() == Some(svc))
    && filters.kind.is_none_or(|kind| item.kind == kind)
    && (!filters.expired_only || item.expired)
}

fn update_cache(
  state: &AppState,
  items: &[Candidate],
  skipped: &[CleanupSkippedServer],
) {
  let mut cache = state
    .cleanup_cache
    .write()
    .unwrap_or_else(|e| e.into_inner());
  cache.retain(|server, _| {
    skipped.iter().any(|skip| &skip.server == server)
  });
  for item in items.iter().filter(|i| is_archive(i.item.kind)) {
    cache
      .entry(item.item.server.clone())
      .or_default()
      .push(item.agent.clone());
  }
}

pub async fn refresh_cache(state: &AppState) -> Result<(), ApiError> {
  let listing = list(
    state,
    &Filters::default(),
    false,
    &CancellationToken::new(),
  )
  .await?;
  update_cache(state, &listing.items, &listing.skipped);
  auto_expire_archives(state, listing.items).await
}

pub async fn overview(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(filters): Query<Filters>,
) -> ApiResult<DataCleanupView> {
  auth.require(Perm::Read)?;
  if let Some(svc) = &filters.service {
    crate::token_scope::require_service(&auth, svc)?;
  }
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let Listing {
    policy,
    items,
    mut skipped,
    mut warnings,
    mut reclaimable,
  } = list(&state, &filters, true, &cancel).await?;
  if auth.services.is_none() && filters.server.is_none() {
    update_cache(&state, &items, &skipped);
  }
  let mut items: Vec<_> = items
    .into_iter()
    .map(|c| c.item)
    .filter(|item| {
      eligible_scope(&auth, item) && matches_filter(item, &filters)
    })
    .collect();
  if auth.services.is_some() {
    skipped
      .retain(|s| items.iter().any(|item| item.server == s.server));
    warnings.clear();
    reclaimable = None;
    for item in &mut items {
      if item.blocked {
        item.blocked_reason = Some("资源仍在使用或归属已变化".into());
      }
    }
  }
  Ok(Json(DataCleanupView {
    policy,
    total_items: items.len(),
    expired_items: items.iter().filter(|i| i.expired).count(),
    blocked_items: items.iter().filter(|i| i.blocked).count(),
    total_bytes: total_bytes(items.iter()),
    expired_bytes: total_bytes(items.iter().filter(|i| i.expired)),
    prune_reclaimable_bytes: reclaimable,
    items,
    skipped_servers: skipped,
    warnings,
    hint: Some(
      "用 --id <ID>、--expired 或 --all 配合 --apply 申请确认".into(),
    ),
  }))
}

fn total_bytes<'a>(
  items: impl Iterator<Item = &'a DataCleanupItem>,
) -> u64 {
  items.fold(0u64, |sum, item| {
    sum.saturating_add(item.size_bytes.unwrap_or(0))
  })
}

pub async fn policy(
  State(state): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<DataCleanupPolicy> {
  auth.require(Perm::Read)?;
  Ok(Json(state.db.call(|c| cleanup_policy(c)).await?))
}

#[derive(Deserialize)]
pub struct PolicyPatch {
  #[serde(default)]
  auto_expire: Option<bool>,
  #[serde(default)]
  keep_days: Option<u32>,
}

pub async fn set_policy(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Json(patch): Json<PolicyPatch>,
) -> ApiResult<DataCleanupPolicy> {
  auth.require(Perm::Admin)?;
  if patch
    .keep_days
    .is_some_and(|days| !(1..=365).contains(&days))
  {
    return Err(
      ApiError::invalid("保留天数必须在 1 到 365 之间").into(),
    );
  }
  Ok(Json(
    state
      .db
      .call(move |c| {
        let mut policy = cleanup_policy(c)?;
        policy.keep_days =
          patch.keep_days.unwrap_or(policy.keep_days);
        policy.auto_expire =
          patch.auto_expire.unwrap_or(policy.auto_expire);
        db::set_setting(
          c,
          CLEANUP_POLICY_KEY,
          Some(
            &serde_json::to_string(&policy).map_err(db::json_err)?,
          ),
        )?;
        Ok(policy)
      })
      .await?,
  ))
}

fn confirm(
  req: &DataCleanupExecRequest,
  selected: &[Candidate],
) -> Result<(), ApiError> {
  let mut items: Vec<_> = selected
    .iter()
    .map(|c| &c.item)
    .filter(|i| !i.blocked)
    .collect();
  items.sort_unstable_by(|a, b| a.id.cmp(&b.id));
  let ids: Vec<_> =
    items.iter().map(|item| item.id.as_str()).collect();
  let suffix = match ids.as_slice() {
    [] => return Ok(()),
    [id] => id.to_string(),
    _ => format!(
      "batch-{}",
      &hex::encode(Sha256::digest(ids.join("|")))[..8]
    ),
  };
  let expected = format!("data-cleanup/{suffix}");
  if req.confirm.as_deref() == Some(expected.as_str()) {
    return Ok(());
  }
  let bytes = total_bytes(items.iter().copied());
  Err(ApiError::new(ErrorCode::ConfirmRequired, format!("即将永久删除 {} 项数据或孤儿资源（约 {bytes} 字节），需要显式确认", items.len()))
    .with_hint(format!("核对清单后追加 --confirm {expected}"))
    .with_details(json!({ "confirm": expected, "count": items.len(), "total_bytes": bytes, "items": items })))
}

pub async fn execute_http(
  state: State<Arc<AppState>>,
  auth: Auth,
  audit: Extension<AuditSlot>,
  req: Json<DataCleanupExecRequest>,
) -> Response {
  match execute(state, auth, audit, req).await {
    Err(e) if e.0.code == ErrorCode::ConfirmRequired => {
      let mut response = e.into_response();
      *response.status_mut() = StatusCode::CONFLICT;
      response
    }
    result => result.into_response(),
  }
}

async fn execute(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<DataCleanupExecRequest>,
) -> ApiResult<DataCleanupResult> {
  auth.require(Perm::Apply)?;
  auth.require(Perm::Confirm)?;
  if u8::from(!req.ids.is_empty())
    + u8::from(req.expired_only)
    + u8::from(req.all)
    != 1
    || (req.include_unlabeled && !req.all)
  {
    return Err(
      ApiError::invalid(
        "请选择一种清理范围：--id、--expired 或 --all",
      )
      .into(),
    );
  }
  if let Some(svc) = &req.service {
    crate::token_scope::require_service(&auth, svc)?;
  }
  let denied = || {
    auth.services.as_ref().map_or_else(
      || {
        ApiError::new(ErrorCode::Forbidden, "清理目标不在权限范围内")
      },
      |allowed| {
        crate::token_scope::forbidden(&auth.name, allowed, "")
      },
    )
  };
  if auth.services.is_some()
    && (req.include_unlabeled
      || matches!(
        req.kind,
        Some(OrphanTaskData | OrphanCaddy | OrphanFrpc)
      ))
  {
    return Err(denied().into());
  }
  let filters = Filters {
    server: req.server.clone(),
    service: req.service.clone(),
    kind: req.kind,
    expired_only: req.expired_only,
  };
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let listing = list(&state, &filters, true, &cancel).await?;
  let ids: BTreeSet<_> = req.ids.iter().map(String::as_str).collect();
  let selected: Vec<_> = listing
    .items
    .into_iter()
    .filter(|c| {
      let item = &c.item;
      eligible_scope(&auth, item)
        && matches_filter(item, &filters)
        && (ids.is_empty() || ids.contains(item.id.as_str()))
        && (!item.unlabeled
          || req.include_unlabeled
          || !ids.is_empty())
    })
    .collect();
  if !ids.is_empty() && ids.len() != selected.len() {
    if auth.services.is_some() {
      return Err(denied().into());
    }
    return Err(
      ApiError::not_found("清理项不存在或已失效")
        .with_hint("重新运行 wharf data cleanup 查看清单")
        .into(),
    );
  }
  for c in &selected {
    if machine_item(&c.item) || c.item.unlabeled {
      auth.require(Perm::Admin)?;
    }
  }
  if selected.len() == 1 && !selected[0].item.blocked {
    state.hub.require_data_cleanup(&selected[0].item.server)?;
  }
  confirm(&req, &selected)?;
  let mut result = DataCleanupResult {
    deleted: 0,
    skipped: 0,
    blocked: 0,
    failed: 0,
    freed_bytes: 0,
    results: vec![],
    warnings: if auth.services.is_none() {
      listing.warnings
    } else {
      vec![]
    },
  };
  for c in selected {
    let action = delete_candidate(&state, &c, &cancel).await;
    let item = c.item;
    let (status, freed_bytes, reason) = match action {
      Ok(res) if res.removed => {
        result.deleted += 1;
        ("deleted", res.freed_bytes, None)
      }
      Ok(res) => {
        result.blocked += 1;
        (
          "blocked",
          0,
          res.detail.or_else(|| mount_reason(&res.blocked_by)),
        )
      }
      Err(e) if e.code == ErrorCode::Busy => {
        result.skipped += 1;
        ("skipped", 0, Some(e.message))
      }
      Err(e) => {
        result.failed += 1;
        (
          "failed",
          0,
          Some(crate::log_redact::redact_error(e).message),
        )
      }
    };
    result.freed_bytes =
      result.freed_bytes.saturating_add(freed_bytes);
    let reason = if auth.services.is_some() && status == "blocked" {
      Some("资源仍在使用或归属已变化".into())
    } else {
      reason
    };
    result.results.push(DataCleanupActionResult {
      id: item.id,
      kind: item.kind,
      server: item.server,
      service: item.service,
      display: item.display,
      status: status.into(),
      freed_bytes,
      reason,
    });
    audit.require_record(format!("data_cleanup deleted={} blocked={} skipped={} failed={} freed_bytes={} items=[{}]",
      result.deleted, result.blocked, result.skipped, result.failed, result.freed_bytes,
      result.results.iter().map(|r| format!("{}:{}", r.id, r.status)).collect::<Vec<_>>().join(",")));
  }
  Ok(Json(result))
}

async fn finish_record(
  state: &AppState,
  c: &Candidate,
  blocked: Option<String>,
) -> Result<(), ApiError> {
  let item = &c.item;
  let Some(record) = c.record.clone() else {
    return Ok(());
  };
  let service = item.service.clone().unwrap_or_default();
  let server = item.server.clone();
  state.db.call(move |c| {
    match record {
      Record::Migration { due, created, instance, .. } => {
        if let Some(reason) = blocked {
          c.execute("UPDATE cleanups SET blocked_reason = ?6 WHERE service = ?1 AND server = ?2 AND due_at = ?3 AND created_at IS ?4 AND instance_id IS ?5",
            params![service, server, due, created, instance, reason]).map_err(sql_err)?;
        } else {
          c.execute("DELETE FROM cleanups WHERE service = ?1 AND server = ?2 AND due_at = ?3 AND created_at IS ?4 AND instance_id IS ?5",
            params![service, server, due, created, instance]).map_err(sql_err)?;
        }
      }
      Record::Retired { key, value, .. } if blocked.is_none() => {
        c.execute("DELETE FROM settings WHERE key = ?1 AND value = ?2", params![key, value]).map_err(sql_err)?;
      }
      Record::Retired { .. } => {}
    }
    Ok(())
  }).await
}

async fn delete_candidate(
  state: &AppState,
  c: &Candidate,
  cancel: &CancellationToken,
) -> Result<CleanupDeleteResult, ApiError> {
  let item = &c.item;
  let block = |detail| CleanupDeleteResult {
    removed: false,
    freed_bytes: 0,
    blocked_by: vec![],
    detail: Some(detail),
  };
  let obsolete = item.kind == MigrateOldData
    && item.blocked_reason.as_deref().is_some_and(|r| {
      matches!(r, "服务已同名重建" | "服务已回到该服务器")
    });
  if item.blocked && !obsolete && c.record.is_none() {
    return Ok(block(
      item.blocked_reason.clone().unwrap_or_default(),
    ));
  }
  // 共享卷消费者也可能由其他服务的 apply 创建，整批 apply 必须串行。
  let _guard =
    state.locks.acquire(LockSpec::Global, "清理遗留数据")?;
  let snap = snapshot::load_inner(&state.db).await?;
  let inv = state.db.call(inventory).await?;
  let record = inv.records.get(&(
    item.server.clone(),
    item.kind,
    item.service.clone().unwrap_or_default(),
  ));
  if record != c.record.as_ref()
    || active_resource(
      &snap,
      &inv,
      &item.server,
      &c.agent,
      &desired_links(&snap),
    )
  {
    return Ok(block("资源归属已发生变化".into()));
  }
  if item.kind == MigrateOldData
    && let Some(reason) = obsolete_migration(&snap, item)
  {
    finish_record(state, c, None).await?;
    return Ok(block(reason.into()));
  }
  if let Some(reason) = cleanup_block(&snap, &inv, item) {
    finish_record(state, c, Some(reason.clone())).await?;
    return Ok(block(reason));
  }
  if item.blocked {
    return Ok(block(
      item.blocked_reason.clone().unwrap_or_default(),
    ));
  }
  let conn = state.hub.require_data_cleanup(&item.server)?;
  let response: CleanupDeleteResult = state
    .hub
    .call_bound(
      (&item.server, conn),
      AgentOp::CleanupDelete(CleanupDeleteRequest {
        kind: item.kind,
        target: item.target.clone(),
        service: item.service.clone(),
        is_core: item.is_core,
        extra_project: c.agent.extra_project.clone(),
      }),
      Duration::from_secs(1800),
      None,
      cancel,
    )
    .await?;
  if response.removed {
    finish_record(state, c, None).await?;
    if let Some(entries) = state
      .cleanup_cache
      .write()
      .unwrap_or_else(|e| e.into_inner())
      .get_mut(&item.server)
    {
      entries
        .retain(|e| e.kind != item.kind || e.target != item.target);
    }
  } else if let Some(reason) = response
    .detail
    .clone()
    .or_else(|| mount_reason(&response.blocked_by))
  {
    finish_record(state, c, Some(reason)).await?;
  }
  Ok(response)
}

pub async fn issues(
  state: &AppState,
  snap: &Snapshot,
) -> Result<Vec<Issue>, ApiError> {
  let inv = state.db.call(inventory).await?;
  let mut grouped = BTreeMap::<(_, _), (usize, u64, bool)>::new();
  let mut add = |mut c: Candidate| {
    c.update_block(snap, &inv);
    let item = c.item;
    if item.expired {
      let subject = if item.is_core || item.service.is_none() {
        ("server", item.server)
      } else {
        ("service", item.service.unwrap_or_default())
      };
      let group = grouped.entry(subject).or_default();
      group.0 += 1;
      group.1 = group.1.saturating_add(item.size_bytes.unwrap_or(0));
      group.2 |= item.blocked;
    }
  };
  for ((server, kind, svc), record) in &inv.records {
    add(Candidate::from_record(
      server,
      *kind,
      svc,
      record,
      inv.policy.keep_days,
      None,
    ));
  }
  for (server, entries) in state
    .cleanup_cache
    .read()
    .unwrap_or_else(|e| e.into_inner())
    .iter()
  {
    for entry in entries {
      add(Candidate::new(
        server,
        entry.clone(),
        None,
        inv.policy.keep_days,
      ));
    }
  }
  Ok(grouped.into_iter().map(|((kind, name), (count, bytes, blocked))| Issue {
    code: "stale_cleanup_data".into(), level: IssueLevel::Warn,
    title: format!("{name} 有 {count} 项超期留底（约 {bytes} 字节）{}", if blocked { "，存在清理阻拦" } else { "" }),
    subject: Some(IssueSubject { kind: kind.into(), name }),
    hint: Some("wharf data cleanup 查看清单，wharf data cleanup --expired --apply 清理到期项".into()),
    ack: None, alert: None,
  }).collect())
}

async fn auto_expire_archives(
  state: &AppState,
  items: Vec<Candidate>,
) -> Result<(), ApiError> {
  if !crate::jobs::auto_cleanup_enabled(state).await? {
    return Ok(());
  }
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  for c in items.into_iter().filter(|c| {
    c.item.expired
      && !c.item.blocked
      && matches!(c.item.kind, MigrateTargetBackup | RestoreBackup)
  }) {
    if !crate::jobs::auto_cleanup_enabled(state).await? {
      break;
    }
    let policy = state.db.call(|c| cleanup_policy(c)).await?;
    if let Some(created) = c.item.created_at
      && created + chrono::Duration::days(i64::from(policy.keep_days))
        > chrono::Utc::now()
    {
      continue;
    }
    match delete_candidate(state, &c, &cancel).await {
      Ok(result) if result.removed => {
        crate::audit::insert(
          state,
          wharf_api_types::view::AuditEntry {
            id: 0,
            at: db::now_ms(),
            kind: "cleanup".into(),
            actor: "到期清理".into(),
            method: "DELETE".into(),
            path: "/api/data/cleanup".into(),
            status: Some(200),
            duration_ms: None,
            detail: Some(format!(
              "data_cleanup deleted=1 freed_bytes={} items=[{}]",
              result.freed_bytes, c.item.id
            )),
            source: None,
          },
        )
        .await?;
      }
      Err(e)
        if !matches!(
          e.code,
          ErrorCode::Busy | ErrorCode::AgentOffline
        ) =>
      {
        tracing::warn!("留底清理失败：{e}")
      }
      _ => {}
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests;
