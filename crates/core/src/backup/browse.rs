use axum::{
  body::{Body, Bytes},
  http::header,
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use wharf_api_types::{
  agent::FileChunk,
  backup::{
    BackupDiffView, BackupExtractMeta, BackupKeepResult,
    BackupLsView, EXTRACT_CHUNK, EXTRACT_LIMIT,
    normalize_snapshot_rel,
  },
};

use super::*;

fn latest() -> String {
  "latest".into()
}

#[derive(Deserialize)]
pub struct BrowseQuery {
  #[serde(default = "latest")]
  snapshot: String,
  #[serde(default)]
  from: Option<String>,
  #[serde(default)]
  path: String,
  #[serde(default)]
  base: Option<String>,
  #[serde(default)]
  recursive: bool,
  #[serde(default)]
  limit: u32,
}

async fn local<T: serde::de::DeserializeOwned>(
  state: &AppState,
  snap: &Snap,
  target: &str,
  service: &str,
  action: ResticAction,
  cancel: &CancellationToken,
) -> Result<T, ApiError> {
  if !state.hub.supports_backup_v2(target) {
    return Err(old_backup_v2(target));
  }
  let (key, legacy) = repository_secrets(state, service).await?;
  let key = key
    .as_deref()
    .or(legacy.as_deref())
    .ok_or_else(|| ApiError::not_found("没有业务备份仓库口令"))?;
  let result = local_call(
    state,
    snap,
    (target, service),
    key,
    action.clone(),
    cancel,
  )
  .await;
  if let Some(legacy) = legacy.as_deref().filter(|p| *p != key)
    && matches!(&result, Err(e) if e.code == ErrorCode::Forbidden)
  {
    return local_call(
      state,
      snap,
      (target, service),
      legacy,
      action,
      cancel,
    )
    .await;
  }
  result
}

pub async fn ls(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  Query(q): Query<BrowseQuery>,
) -> ApiResult<BackupLsView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &service)?;
  let snap = snapshot::load(&s.db).await?;
  let target =
    restore_target(&s, &snap, &service, q.from.as_deref()).await?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let mut result: BackupLsView = local(
    &s,
    &snap,
    &target,
    &service,
    ResticAction::Ls {
      snapshot: q.snapshot,
      path: q.path,
      recursive: q.recursive,
      limit: q.limit,
    },
    &cancel,
  )
  .await?;
  result.target = target;
  Ok(Json(result))
}

pub async fn diff(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  Query(q): Query<BrowseQuery>,
) -> ApiResult<BackupDiffView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &service)?;
  let snap = snapshot::load(&s.db).await?;
  let target =
    restore_target(&s, &snap, &service, q.from.as_deref()).await?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  if let Some(base) = q.base {
    return Ok(Json(
      local(
        &s,
        &snap,
        &target,
        &service,
        ResticAction::DiffSnapshots {
          base,
          target: q.snapshot,
          limit: q.limit,
        },
        &cancel,
      )
      .await?,
    ));
  }

  let w = location(&snap, &service, target);
  if w.target_ip.is_empty() {
    return Err(ApiError::invalid("备份服务器没有内网地址").into());
  }
  if !s.hub.supports_backup_v2(&w.server) {
    return Err(old_backup_v2(&w.server).into());
  }
  let (key, legacy) = repository_secrets(&s, &service).await?;
  let username = service.clone();
  let http = s
    .db
    .call_credentials(move |c, master| {
      let key = db::scoped_secret_name(HTTP_PREFIX, &username)?;
      Ok((
        master.secret(c, &key)?,
        master.secret(c, LEGACY_HTTP_SECRET)?,
      ))
    })
    .await?;
  let action = ResticAction::DiffLocal {
    snapshot: q.snapshot,
    excludes: snap.world.services[&service]
      .spec
      .backup
      .as_ref()
      .map(|p| p.exclude.clone())
      .unwrap_or_default(),
    limit: q.limit,
  };
  let call = |login, http, key| {
    s.hub.call(
      &w.server,
      job(
        &snap,
        &w.server,
        &service,
        rest_repo(&w.target_ip, REST_SERVER_PORT, login, http),
        key,
        action.clone(),
      ),
      LIST_TIMEOUT,
      None,
      &cancel,
    )
  };
  let result: Result<BackupDiffView, ApiError> =
    match (key.as_deref(), http.0.as_deref()) {
      (Some(key), Some(password)) => {
        call(&service, password, key).await
      }
      _ => {
        Err(ApiError::new(ErrorCode::Forbidden, "没有当前仓库凭证"))
      }
    };
  if matches!(&result, Err(e) if matches!(e.code, ErrorCode::Forbidden | ErrorCode::AgentFailed))
    && let (Some(key), Some(http)) =
      (legacy.as_deref(), http.1.as_deref())
  {
    return Ok(Json(call("wharf", http, key).await?));
  }
  Ok(Json(result?))
}

#[derive(Deserialize)]
pub struct KeepRequest {
  snapshot: String,
  #[serde(default)]
  keep: bool,
  #[serde(default)]
  note: Option<String>,
  #[serde(default)]
  clear_note: bool,
  #[serde(default)]
  target: Option<String>,
}

pub async fn keep(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  Json(req): Json<KeepRequest>,
) -> ApiResult<BackupKeepResult> {
  auth.require(Perm::Apply)?;
  crate::token_scope::require_service(&auth, &service)?;
  wharf_api_types::backup::validate_snapshot_id(&req.snapshot)?;
  if let Some(note) = &req.note {
    wharf_api_types::backup::validate_note(note)?;
    if req.clear_note {
      return Err(
        ApiError::invalid("设置备注和清除备注不能同时使用").into(),
      );
    }
  }
  let guard = s.locks.acquire(
    crate::locks::LockSpec::Backup(service.clone()),
    "修改快照留底",
  )?;
  let snap = snapshot::load(&s.db).await?;
  let target =
    restore_target(&s, &snap, &service, req.target.as_deref())
      .await?;
  guard.reserve_backup_target(target.clone())?;
  if !s.hub.supports_backup_v2(&target) {
    return Err(old_backup_v2(&target).into());
  }
  if req.keep {
    guard_kept(&s, &service).await?;
  }
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let (old_snapshot, snapshot) = local(
    &s,
    &snap,
    &target,
    &service,
    ResticAction::Tag {
      snapshot: req.snapshot,
      keep: req.keep,
      note: req.note,
      clear_note: req.clear_note,
    },
    &cancel,
  )
  .await?;
  Ok(Json(BackupKeepResult {
    service,
    target,
    old_snapshot,
    snapshot,
  }))
}

struct Extract {
  state: Arc<AppState>,
  target: String,
  service: String,
  meta: BackupExtractMeta,
}

impl Extract {
  fn job(&self, action: ResticAction) -> AgentOp {
    AgentOp::Restic(ResticJob {
      service: self.service.clone(),
      repo: ResticRepo::Local,
      password: OneTimeSecret(String::new()),
      pull: wharf_api_types::agent::PullPolicy {
        mirrors: Default::default(),
        mirrors_only: false,
        attempt_timeout_secs: snapshot::PULL_ATTEMPT_SECS,
        git_proxy: None,
        github_mirror: None,
        registry_proxy: None,
      },
      action,
      core_marker: None,
    })
  }

  async fn read(&self, offset: u64) -> Result<Bytes, ApiError> {
    let cancel = CancellationToken::new();
    let _cancel = cancel.clone().drop_guard();
    let len =
      (self.meta.size - offset).min(u64::from(EXTRACT_CHUNK)) as u32;
    let chunk: FileChunk = self
      .state
      .hub
      .call(
        &self.target,
        self.job(ResticAction::ExtractRead {
          token: self.meta.token.clone(),
          offset,
          len,
        }),
        Duration::from_secs(30),
        None,
        &cancel,
      )
      .await?;
    let bytes = STANDARD
      .decode(chunk.data)
      .map_err(|_| ApiError::internal("无效的备份文件分块"))?;
    if chunk.size != self.meta.size || bytes.len() != len as usize {
      return Err(ApiError::internal("备份文件分块大小不一致"));
    }
    Ok(Bytes::from(bytes))
  }
}

impl Drop for Extract {
  fn drop(&mut self) {
    let state = self.state.clone();
    let target = self.target.clone();
    let job = self.job(ResticAction::ExtractClose {
      token: self.meta.token.clone(),
    });
    tokio::spawn(async move {
      let _: Result<serde_json::Value, _> = state
        .hub
        .call(
          &target,
          job,
          Duration::from_secs(10),
          None,
          &CancellationToken::new(),
        )
        .await;
    });
  }
}

pub async fn extract(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  Query(q): Query<BrowseQuery>,
) -> Result<Response, crate::api::AppError> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &service)?;
  let path = normalize_snapshot_rel(&q.path)?;
  if path.is_empty() {
    return Err(ApiError::invalid("请指定快照中的普通文件").into());
  }
  let snap = snapshot::load(&s.db).await?;
  let target =
    restore_target(&s, &snap, &service, q.from.as_deref()).await?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let meta = local(
    &s,
    &snap,
    &target,
    &service,
    ResticAction::ExtractPrepare {
      snapshot: q.snapshot,
      path: path.to_owned(),
      max_bytes: EXTRACT_LIMIT,
    },
    &cancel,
  )
  .await?;
  let transfer = Extract {
    state: s,
    target,
    service,
    meta,
  };
  let meta = &transfer.meta;
  if meta.size > EXTRACT_LIMIT
    || meta.mode > 0o777
    || meta.sha256.len() != 64
    || !meta.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    || meta.snapshot.len() != 64
    || !meta.snapshot.bytes().all(|b| b.is_ascii_hexdigit())
  {
    return Err(ApiError::internal("备份文件元数据无效").into());
  }
  let headers = [
    (
      header::CONTENT_TYPE.as_str(),
      "application/octet-stream".into(),
    ),
    (header::CONTENT_LENGTH.as_str(), meta.size.to_string()),
    (
      header::CONTENT_DISPOSITION.as_str(),
      format!(
        "attachment; filename*=UTF-8''{}",
        urlencoding::encode(&meta.name)
      ),
    ),
    ("x-wharf-file-mode", format!("{:04o}", meta.mode)),
    ("x-wharf-file-sha256", meta.sha256.clone()),
    ("x-wharf-snapshot", meta.snapshot.clone()),
  ];
  let stream = futures_util::stream::unfold(
    Some((transfer, 0)),
    |state| async move {
      let (transfer, offset) = state?;
      if offset >= transfer.meta.size {
        return None;
      }
      match transfer.read(offset).await {
        Ok(bytes) => {
          let next = offset + bytes.len() as u64;
          Some((Ok(bytes), Some((transfer, next))))
        }
        Err(_) => {
          Some((Err(std::io::Error::other("备份文件传输中断")), None))
        }
      }
    },
  );
  Ok((headers, Body::from_stream(stream)).into_response())
}
