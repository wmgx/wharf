use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BACKUP_ROOT, CORE_BACKUP_ROOT, ResticAction, ResticRepo,
    Snapshot, SyncKind,
  },
  view::{BackupMovePreview, BackupMoveStatus, Perm},
};

use crate::{
  api::ApiResult,
  apply,
  auth::Auth,
  backup, core_backup,
  db::{self, json_err, now_ms, sql_err},
  hub::ProgressFn,
  link::{self, ProbeMode},
  locks::{LockSpec, OpLockGuard},
  pending,
  planner::Step,
  snapshot::{self, Snapshot as WorldSnapshot},
  state::AppState,
};

pub(crate) const KIND: &str = "backup_move";
const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingMove {
  #[serde(default)]
  is_core: bool,
  #[serde(flatten)]
  pub status: BackupMoveStatus,
  #[serde(default)]
  target_prepared: bool,
  #[serde(default)]
  instance: Option<String>,
  started_at: i64,
}

#[derive(Deserialize)]
pub struct BackupMoveRequest {
  #[serde(default)]
  to: Option<String>,
  #[serde(default)]
  from: Option<String>,
  #[serde(default)]
  dry_run: bool,
  #[serde(default)]
  abort: bool,
  #[serde(default)]
  confirm: Option<String>,
}

#[derive(Clone)]
struct Move {
  service: String,
  is_core: bool,
  from: String,
  to: String,
}

impl Move {
  fn kind(&self) -> SyncKind {
    if self.is_core {
      SyncKind::CoreBackupRepo
    } else {
      SyncKind::BackupRepo
    }
  }

  fn repo_path(&self) -> String {
    let root = if self.is_core {
      CORE_BACKUP_ROOT
    } else {
      BACKUP_ROOT
    };
    format!("{root}/{}", self.service)
  }

  fn confirm(&self) -> String {
    format!("backup-move/{}", self.service)
  }

  fn matches(&self, p: &PendingMove) -> bool {
    p.status.from == self.from && p.status.to == self.to
  }

  fn save(
    &self,
    run_id: &str,
    p: &PendingMove,
    c: &rusqlite::Connection,
  ) -> Result<(), ApiError> {
    let payload = serde_json::to_string(p).map_err(json_err)?;
    c.execute(
      "INSERT INTO pending_steps (kind,target_key,run_id,plan_id,phase,payload,updated_at)
       VALUES (?1,?2,?3,'',?4,?5,?6)
       ON CONFLICT(kind,target_key) DO UPDATE SET run_id=excluded.run_id,
       phase=excluded.phase,payload=excluded.payload,updated_at=excluded.updated_at",
      params![KIND, self.service, run_id, p.status.phase, payload, now_ms()],
    ).map_err(sql_err)?;
    Ok(())
  }

  async fn repo<T: serde::de::DeserializeOwned>(
    &self,
    s: &AppState,
    snap: &WorldSnapshot,
    server: &str,
    key: &str,
    action: ResticAction,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    let repo = if self.is_core {
      ResticRepo::LocalCore
    } else {
      ResticRepo::Local
    };
    s.hub
      .call(
        server,
        backup::job(snap, server, &self.service, repo, key, action),
        backup::LIST_TIMEOUT,
        None,
        cancel,
      )
      .await
  }

  fn current_pending(
    &self,
    snap: &WorldSnapshot,
  ) -> Result<Option<PendingMove>, ApiError> {
    let p = snap.pending.backup_moves.get(&self.service);
    if let Some(p) = p {
      if !self.matches(p) || self.is_core != p.is_core {
        return Err(ApiError::new(ErrorCode::Conflict, format!(
          "存在未完成的备份仓库迁移（{} → {}）", p.status.from, p.status.to,
        )).with_hint("续传请传相同 --from 和 --to，或加 --abort 清除旧进度后重来"));
      }
      if !self.is_core
        && p.instance.as_ref()
          != snap
            .world
            .services
            .get(&self.service)
            .map(|r| &r.instance_id)
      {
        return Err(
          ApiError::new(ErrorCode::Conflict, "服务实例已变更")
            .with_hint("先运行 wharf backup move --abort 清除旧进度"),
        );
      }
    }
    Ok(p.cloned())
  }

  async fn location(
    &self,
    s: &AppState,
    snap: &WorldSnapshot,
    mode: ProbeMode,
    cancel: &CancellationToken,
  ) -> Result<backup::Where, ApiError> {
    if self.from == self.to {
      return Err(ApiError::invalid("源备份机与目标备份机相同"));
    }
    let server = if self.is_core {
      match mode {
        ProbeMode::Plan => crate::core_node::server_of(snap)
          .ok_or_else(|| {
            ApiError::not_found("尚未确认控制面所在服务器")
          })?,
        ProbeMode::Persist => {
          crate::core_node::require_verified(s, cancel).await?.server
        }
      }
    } else {
      let row =
        snap.world.services.get(&self.service).ok_or_else(|| {
          crate::api::service_not_found(&self.service)
        })?;
      snapshot::service_runtime_server(snap, &self.service)
        .unwrap_or(&row.spec.server)
        .into()
    };
    if server == self.to {
      return Err(ApiError::invalid(
        "备份目标不能是被备份数据所在的服务器",
      ));
    }
    let net = snap.net(&snap.world);
    for host in [&self.from, &self.to] {
      if !snap.world.servers.contains_key(host) {
        return Err(crate::world::server_not_found(host));
      }
      backup::require_safe_backup(s, host)?;
      backup::require_isolation(s, host)?;
      if !s.hub.supports_backup_move(host) {
        return Err(old_agent(host));
      }
      if !net.private.contains_key(host) {
        return Err(ApiError::invalid(format!(
          "备份服务器 {host} 没有内网地址"
        )));
      }
    }
    tokio::select! {
      result = link::require_reach(s, &net, &self.from, &self.to, "迁移备份仓库", mode) => result?,
      _ = cancel.cancelled() => return Err(cancelled()),
    }
    Ok(backup::Where {
      server,
      target: self.to.clone(),
      target_ip: net.private[&self.to].ip.clone(),
    })
  }

  async fn source(
    &self,
    s: &AppState,
    snap: &WorldSnapshot,
    cancel: &CancellationToken,
  ) -> Result<(String, Vec<Snapshot>), ApiError> {
    let (primary, fallback) = if self.is_core {
      (
        s.db
          .call_credentials(|c, key| {
            key.secret(c, core_backup::KEY_SECRET)
          })
          .await?,
        None,
      )
    } else {
      backup::repository_secrets(s, &self.service).await?
    };
    let allowed_fallback = fallback.is_some() && fallback != primary;
    let mut choices = primary.into_iter().chain(fallback);
    let mut key = choices
      .next()
      .ok_or_else(|| ApiError::not_found("找不到源仓库凭据"))?;
    let mut result: Result<Vec<Snapshot>, _> = self
      .repo(
        s,
        snap,
        &self.from,
        &key,
        ResticAction::Snapshots,
        cancel,
      )
      .await;
    if allowed_fallback
      && matches!(&result, Err(e) if e.code == ErrorCode::Forbidden)
      && let Some(fallback) = choices.next()
    {
      key = fallback;
      result = self
        .repo(
          s,
          snap,
          &self.from,
          &key,
          ResticAction::Snapshots,
          cancel,
        )
        .await;
    }
    let snapshots = result?;
    if snapshots.is_empty() {
      let exists: bool = self
        .repo(
          s,
          snap,
          &self.from,
          "",
          ResticAction::RepoNonempty,
          cancel,
        )
        .await?;
      return Err(if exists {
        ApiError::invalid(format!(
          "源备份机 {} 的仓库没有任何快照",
          self.from
        ))
        .with_hint(
          "可使用 wharf backup enable/core --to 修改备份目标",
        )
      } else {
        ApiError::not_found(format!(
          "源备份机 {} 上没有找到 {} 的备份仓库",
          self.from, self.service
        ))
      });
    }
    Ok((key, snapshots))
  }

  async fn preview(
    &self,
    s: &AppState,
    snap: &WorldSnapshot,
    key: &str,
    snapshots: usize,
    pending: Option<&PendingMove>,
    cancel: &CancellationToken,
  ) -> Result<BackupMovePreview, ApiError> {
    let needs_confirm = if pending.is_some_and(|p| p.target_prepared)
    {
      false
    } else {
      self
        .repo(
          s,
          snap,
          &self.to,
          "",
          ResticAction::RepoNonempty,
          cancel,
        )
        .await?
    };
    let target_existing_snapshots = if needs_confirm {
      let result: Result<Vec<Snapshot>, _> = self
        .repo(s, snap, &self.to, key, ResticAction::Snapshots, cancel)
        .await;
      match result {
        Ok(items) => items.len(),
        Err(e)
          if matches!(
            e.code,
            ErrorCode::Forbidden | ErrorCode::AgentFailed
          ) =>
        {
          0
        }
        Err(e) => return Err(e),
      }
    } else {
      0
    };
    Ok(BackupMovePreview {
      service: self.service.clone(), is_core: self.is_core,
      from: self.from.clone(), to: self.to.clone(), source_snapshots: snapshots,
      target_existing_snapshots, resuming: pending.is_some(), needs_confirm,
      confirm: needs_confirm.then(|| self.confirm()),
      old_repo_path: self.repo_path(),
      hint: needs_confirm.then(|| format!(
        "目标机 {} 已有仓库数据，确认后将先归档到 .wharf-backup-archive 再同步", self.to,
      )),
    })
  }
}

pub(crate) fn old_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，不支持备份仓库迁移"),
  )
  .suggest("wharf upgrade")
}

pub(crate) fn lock(
  s: &AppState,
  service: &str,
  is_core: bool,
) -> Result<OpLockGuard, ApiError> {
  let spec = if is_core {
    LockSpec::CoreBackup
  } else {
    LockSpec::Backup(service.into())
  };
  s.locks.acquire(spec, "迁移备份仓库")
}

fn cancelled() -> ApiError {
  ApiError::new(ErrorCode::Cancelled, "已取消")
}

pub(crate) fn require_idle(
  snap: &WorldSnapshot,
  service: &str,
) -> Result<(), ApiError> {
  if let Some(p) = snap.pending.backup_moves.get(service) {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "{service} 有未完成的备份仓库迁移（{} → {}）",
          p.status.from, p.status.to
        ),
      )
      .with_hint(
        "续传迁移，或运行 wharf backup move --abort 清除旧进度",
      ),
    );
  }
  Ok(())
}

pub async fn service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  Json(req): Json<BackupMoveRequest>,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  crate::token_scope::require_service(&auth, &service)?;
  if service == core_backup::REPO {
    return Err(
      ApiError::invalid("控制面仓库请使用 backup move --core").into(),
    );
  }
  start(s, &auth, service, false, req).await
}

pub async fn core(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<BackupMoveRequest>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  start(s, &auth, core_backup::REPO.into(), true, req).await
}

async fn start(
  s: Arc<AppState>,
  auth: &Auth,
  service: String,
  is_core: bool,
  req: BackupMoveRequest,
) -> ApiResult<Value> {
  let guard = lock(&s, &service, is_core)?;
  if req.abort {
    if req.dry_run {
      return Err(
        ApiError::invalid("--abort 与 --dry-run 不能同时使用").into(),
      );
    }
    let name = service.clone();
    s.db.call(move |c| pending::clear(c, KIND, &name)).await?;
    return Ok(Json(json!({"aborted": true, "service": service})));
  }
  let to = req.to.ok_or_else(|| ApiError::invalid("请指定 --to"))?;
  let snap = snapshot::load(&s.db).await?;
  let pending = snap.pending.backup_moves.get(&service);
  let from =
    match req.from.or_else(|| pending.map(|p| p.status.from.clone()))
    {
      Some(from) => from,
      None if is_core => s
        .db
        .call(|c| core_backup::target(c))
        .await?
        .ok_or_else(|| ApiError::invalid("还没有开启控制面备份"))?,
      None => {
        if !snap.world.services.contains_key(&service) {
          return Err(crate::api::service_not_found(&service).into());
        }
        backup::restore_target(&s, &snap, &service, None).await?
      }
    };
  let movement = Move {
    service,
    is_core,
    from,
    to,
  };
  let pending = movement.current_pending(&snap)?;
  guard.reserve_backup_target(movement.from.clone())?;
  guard.reserve_backup_target(movement.to.clone())?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  movement
    .location(&s, &snap, ProbeMode::Plan, &cancel)
    .await?;
  let (key, snapshots) = movement.source(&s, &snap, &cancel).await?;
  let preview = movement
    .preview(
      &s,
      &snap,
      &key,
      snapshots.len(),
      pending.as_ref(),
      &cancel,
    )
    .await?;
  if req.dry_run {
    return Ok(Json(
      serde_json::to_value(preview).map_err(json_err)?,
    ));
  }
  let replace_target =
    req.confirm.as_deref() == Some(movement.confirm().as_str());
  if preview.needs_confirm && !replace_target {
    let command = if is_core { "--core" } else { &movement.service };
    return Err(
      ApiError::new(
        ErrorCode::ConfirmRequired,
        "目标机已有备份仓库数据",
      )
      .with_hint(preview.hint.unwrap_or_default())
      .suggest(format!(
        "wharf backup move {command} --from {} --to {} --confirm {}",
        movement.from,
        movement.to,
        movement.confirm()
      ))
      .with_details(json!(preview))
      .into(),
    );
  }
  if replace_target {
    auth.require(Perm::Confirm)?;
  }
  let result = apply::start_task_locked(
    s,
    format!("迁移 {} 的备份仓库", movement.service),
    Step::BackupMove {
      service: movement.service,
      is_core,
      from: movement.from,
      to: movement.to,
      replace_target,
    },
    Some(apply::format_actor(auth)),
    guard,
  )
  .await?;
  Ok(Json(serde_json::to_value(result).map_err(json_err)?))
}

async fn save(
  s: &AppState,
  movement: &Move,
  run_id: &str,
  p: &PendingMove,
) -> Result<(), ApiError> {
  let (movement, run_id, p) =
    (movement.clone(), run_id.to_owned(), p.clone());
  s.db.call(move |c| movement.save(&run_id, &p, c)).await
}

pub(crate) async fn execute(
  s: &AppState,
  snap: &WorldSnapshot,
  run_id: &str,
  step: &Step,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let Step::BackupMove {
    service,
    is_core,
    from,
    to,
    replace_target,
  } = step
  else {
    unreachable!("只执行仓库迁移步骤");
  };
  let movement = Move {
    service: service.clone(),
    is_core: *is_core,
    from: from.clone(),
    to: to.clone(),
  };
  let old = movement.current_pending(snap)?;
  let w = movement
    .location(s, snap, ProbeMode::Persist, cancel)
    .await?;
  let (mut key, snapshots) = movement.source(s, snap, cancel).await?;
  if !old.as_ref().is_some_and(|p| p.target_prepared)
    && !*replace_target
  {
    let occupied: bool = movement
      .repo(s, snap, to, "", ResticAction::RepoNonempty, cancel)
      .await?;
    if occupied {
      return Err(
        ApiError::new(
          ErrorCode::ConfirmRequired,
          "目标机已有备份仓库数据",
        )
        .with_hint(format!(
          "请重跑并指定 --confirm {}",
          movement.confirm()
        )),
      );
    }
  }
  if !*is_core {
    let service_key =
      backup::ensure_service_creds(s, service).await?.key;
    if service_key != key {
      backup::ensure_repo_has_service_key(
        s,
        snap,
        (from, service),
        &service_key,
        cancel,
      )
      .await?;
      key = service_key;
    }
  }
  let mut p = old.unwrap_or_else(|| PendingMove {
    is_core: *is_core,
    status: BackupMoveStatus {
      from: from.clone(),
      to: to.clone(),
      phase: "syncing".into(),
      source_snapshots: snapshots.len(),
      target_archive: None,
    },
    target_prepared: false,
    instance: snap
      .world
      .services
      .get(service)
      .map(|r| r.instance_id.clone()),
    started_at: now_ms(),
  });
  save(s, &movement, run_id, &p).await?;
  if p.status.phase == "syncing" {
    sync::run(
      s,
      snap,
      &movement,
      run_id,
      &mut p,
      *replace_target,
      progress,
      cancel,
    )
    .await?;
  }
  let ids = |items: Vec<Snapshot>| {
    items.into_iter().map(|s| s.id).collect::<BTreeSet<_>>()
  };
  let dst = ids(
    movement
      .repo(s, snap, to, &key, ResticAction::Snapshots, cancel)
      .await?,
  );
  let src = ids(
    movement
      .repo(s, snap, from, &key, ResticAction::Snapshots, cancel)
      .await?,
  );
  if dst != src || dst.is_empty() {
    p.status.phase = "syncing".into();
    save(s, &movement, run_id, &p).await?;
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "迁移后快照校验不一致：源机 {} 份，新机 {} 份，未切换配置",
          src.len(),
          dst.len(),
        ),
      )
      .with_hint("重新运行同一条 wharf backup move 命令增量续传"),
    );
  }
  p.status.phase = "verified".into();
  p.status.source_snapshots = src.len();
  save(s, &movement, run_id, &p).await?;
  if *is_core {
    core_backup::deploy_move_target(s, snap, &w, progress, cancel)
      .await?;
  } else {
    backup::ensure_server(
      s,
      snap,
      &w,
      Some(service),
      progress,
      cancel,
    )
    .await?;
  }
  if cancel.is_cancelled() {
    return Err(cancelled());
  }
  let moved = movement.clone();
  let id = run_id.to_owned();
  let count = src.len();
  s.db.call(move |c| finish(c, &moved, &id, count)).await?;
  progress(format!(
    "已将 {service} 备份仓库迁至 {to}（{count} 份快照一致）；{from} 上的旧仓库已保留，可用 wharf data cleanup 查看和清理"
  ));
  Ok(())
}

fn finish(
  c: &mut rusqlite::Connection,
  m: &Move,
  run_id: &str,
  snapshot_count: usize,
) -> Result<(), ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  if m.is_core {
    core_backup::switch_move_target(&tx, &m.from, &m.to)?;
  } else {
    let count = tx.execute(
      "UPDATE resources SET spec=json_set(spec,'$.backup',
       json_set(COALESCE(json_extract(spec,'$.backup'),'{}'),'$.to',?2)),
       version=version+1, updated_at=?3 WHERE kind='service' AND name=?1",
       params![m.service, m.to, now_ms()],
    ).map_err(sql_err)?;
    if count != 1 {
      return Err(crate::api::service_not_found(&m.service));
    }
  }
  tx.execute(
    "INSERT INTO backups (service, server, target, run_id, ok, body, created_at)
     SELECT service, server, ?3, ?4, ok, body, created_at
     FROM backups WHERE service=?1 AND target=?2 AND ok=1 ORDER BY created_at DESC,id DESC LIMIT 1",
    params![m.service, m.from, m.to, run_id],
  ).map_err(sql_err)?;
  let now = now_ms();
  let retired = json!({
    "service": m.service, "is_core": m.is_core, "server": m.from,
    "moved_to": m.to, "path": m.repo_path(), "snapshot_count": snapshot_count,
    "moved_at": now, "expires_at": now + RETENTION_MS,
  });
  let setting =
    |host: &str| format!("backup_move.retired.{}@{host}", m.service);
  db::set_setting(
    &tx,
    &setting(&m.from),
    Some(&retired.to_string()),
  )?;
  db::set_setting(&tx, &setting(&m.to), None)?;
  pending::clear(&tx, KIND, &m.service)?;
  tx.commit().map_err(sql_err)?;
  Ok(())
}

mod sync;

#[cfg(test)]
mod tests;
