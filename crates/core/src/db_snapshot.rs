use std::{
  fs::{self, File, Metadata, OpenOptions},
  io::{self, Read, Write},
  os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
  },
  path::{Path, PathBuf},
  sync::Arc,
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{Path as ApiPath, State},
};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Impact, Plan},
  view::{
    AuditEntry, CoreSnapshotsView, DbSnapshotInfo, Perm,
    SNAPSHOT_RESTORE_HINT,
  },
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, Db},
  planner::{Step, StepPlan},
  security_receipt::Actor,
  state::AppState,
};

const MAX_COUNT: usize = 10;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MIN_FREE_AFTER_BYTES: u64 = MAX_TOTAL_BYTES;
pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub enum Trigger {
  Upgrade,
  Apply,
  Restore,
  CleanupLegacy,
  PreRestore,
  Manual,
}

impl Trigger {
  fn name(self) -> &'static str {
    match self {
      Self::Upgrade => "upgrade",
      Self::Apply => "apply",
      Self::Restore => "restore",
      Self::CleanupLegacy => "cleanup_legacy",
      Self::PreRestore => "pre_restore",
      Self::Manual => "manual",
    }
  }
}

fn risky_item(impacts: &[Impact]) -> bool {
  impacts
    .iter()
    .any(|impact| matches!(impact, Impact::DataLoss | Impact::Remove))
}

pub fn plan_trigger_reason(
  plan: &Plan,
  steps: &[StepPlan],
) -> Option<String> {
  (!plan.needs_confirm.is_empty()
    || plan.items.iter().any(|i| risky_item(&i.impacts))
    || steps.iter().any(|s| {
      matches!(
        s.step,
        Step::VolumeSync { .. }
          | Step::AdoptData { .. }
          | Step::ServiceDown {
            purge_data: true,
            ..
          }
      )
    }))
  .then(|| "高危计划执行前".into())
}

fn conflict(message: impl Into<String>) -> ApiError {
  ApiError::new(ErrorCode::Conflict, message)
    .with_hint("清理控制面磁盘或用 wharf core snapshot rm <id> 删除旧快照。整机灾备使用 wharf backup core")
    .suggest("wharf core snapshot list")
}

fn io_error(error: io::Error) -> ApiError {
  conflict(format!("本机热快照文件操作失败：{}", error.kind()))
}

fn timed_out() -> ApiError {
  conflict("本机热快照创建超时，已中止操作")
}

fn metadata(
  path: &Path,
  directory: bool,
) -> Result<Option<Metadata>, ApiError> {
  match fs::symlink_metadata(path) {
    Ok(m)
      if (directory && m.is_dir()) || (!directory && m.is_file()) =>
    {
      Ok(Some(m))
    }
    Ok(_) => Err(ApiError::invalid(
      "快照路径必须是普通文件或目录，不接受符号链接",
    )),
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
    Err(e) => Err(io_error(e)),
  }
}

fn directory(data_dir: &Path) -> Result<PathBuf, ApiError> {
  let dir = data_dir.join("snapshots");
  if metadata(&dir, true)?.is_none() {
    fs::DirBuilder::new()
      .mode(0o700)
      .create(&dir)
      .map_err(io_error)?;
  }
  fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
    .map_err(io_error)?;
  Ok(dir)
}

fn validate_id(id: &str) -> Result<(), ApiError> {
  if id.is_empty()
    || id.len() > 80
    || !id
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
  {
    return Err(ApiError::invalid("快照 ID 格式不对"));
  }
  Ok(())
}

fn entry(
  dir: &Path,
  id: &str,
  allow_bad_sidecar: bool,
) -> Result<DbSnapshotInfo, ApiError> {
  validate_id(id)?;
  let db = metadata(&dir.join(format!("{id}.db")), false)?
    .ok_or_else(|| ApiError::not_found("快照不存在"))?;
  let sidecar = dir.join(format!("{id}.json"));
  if metadata(&sidecar, false)?.is_some() {
    let parsed = serde_json::from_reader::<_, DbSnapshotInfo>(
      File::open(sidecar).map_err(io_error)?,
    )
    .map_err(|_| conflict("快照元数据格式不对"))
    .and_then(|mut info| {
      if info.id != id {
        return Err(conflict("快照元数据的 ID 不匹配"));
      }
      info.size_bytes = db.len();
      Ok(info)
    });
    match parsed {
      Ok(info) => return Ok(info),
      Err(error) if allow_bad_sidecar => {
        tracing::warn!(id, "{}", error.message);
      }
      Err(error) => return Err(error),
    }
  }
  let created_at = id
    .get(..16)
    .and_then(|date| {
      NaiveDateTime::parse_from_str(date, "%Y%m%d-%H%M%SZ").ok()
    })
    .map(|date| date.and_utc())
    .or_else(|| db.modified().ok().map(DateTime::<Utc>::from))
    .unwrap_or_default();
  Ok(DbSnapshotInfo {
    id: id.into(),
    created_at,
    trigger: id
      .get(17..)
      .and_then(|s| s.rsplit_once('-'))
      .map_or("", |(s, _)| s)
      .into(),
    size_bytes: db.len(),
    ..Default::default()
  })
}

fn entries(dir: &Path) -> Result<Vec<DbSnapshotInfo>, ApiError> {
  let mut entries = Vec::new();
  for file in fs::read_dir(dir).map_err(io_error)? {
    let file = file.map_err(io_error)?;
    if let Some(id) = file
      .file_name()
      .to_str()
      .and_then(|n| n.strip_suffix(".db"))
      && validate_id(id).is_ok()
    {
      match entry(dir, id, true) {
        Ok(entry) => entries.push(entry),
        Err(error) if error.code == ErrorCode::NotFound => {}
        Err(error) if error.code == ErrorCode::InvalidInput => {
          tracing::warn!(id, "{}", error.message);
        }
        Err(error) => return Err(error),
      }
    }
  }
  entries.sort_unstable_by(|a, b| {
    (b.created_at, &b.id).cmp(&(a.created_at, &a.id))
  });
  Ok(entries)
}

fn remove(dir: &Path, id: &str) -> Result<(), ApiError> {
  validate_id(id)?;
  let db = dir.join(format!("{id}.db"));
  let json = dir.join(format!("{id}.json"));
  if metadata(&db, false)?.is_none() {
    return Err(ApiError::not_found("快照不存在"));
  }
  let sidecar = metadata(&json, false)?.is_some();
  fs::remove_file(db).map_err(io_error)?;
  if sidecar {
    fs::remove_file(json).map_err(io_error)?;
  }
  sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<(), ApiError> {
  File::open(dir).and_then(|f| f.sync_all()).map_err(io_error)
}

fn bytes(entries: &[DbSnapshotInfo]) -> u64 {
  entries.iter().map(|e| e.size_bytes).sum()
}

fn latest_upgrade(entries: &[DbSnapshotInfo]) -> Option<&str> {
  entries
    .iter()
    .find(|e| e.trigger == "upgrade")
    .map(|e| e.id.as_str())
}

// 输入按创建时间倒序。
fn plan_pruning(
  entries: &[DbSnapshotInfo],
  now: DateTime<Utc>,
  keep_id: Option<&str>,
) -> Vec<String> {
  let latest = entries.first().map(|e| e.id.as_str());
  let upgrade = latest_upgrade(entries);
  let mut count = entries.len();
  let mut size = bytes(entries);
  let mut remove = Vec::new();
  for e in entries.iter().rev() {
    let id = Some(e.id.as_str());
    if id == keep_id || id == latest || id == upgrade {
      continue;
    }
    if now - e.created_at > chrono::TimeDelta::days(14)
      || count > MAX_COUNT
      || size > MAX_TOTAL_BYTES
    {
      count -= 1;
      size -= e.size_bytes;
      remove.push(e.id.clone());
    }
  }
  if size > MAX_TOTAL_BYTES
    && let Some(id) = upgrade
    && Some(id) != keep_id
  {
    remove.push(id.to_string());
  }
  remove
}

fn space_pruning(
  entries: &[DbSnapshotInfo],
  mut needed: u64,
  keep_id: Option<&str>,
) -> Option<Vec<String>> {
  let mut remove = Vec::new();
  let upgrade = latest_upgrade(entries);
  for e in entries.iter().skip(1).rev() {
    if needed == 0 {
      break;
    }
    if Some(e.id.as_str()) != upgrade
      && Some(e.id.as_str()) != keep_id
    {
      needed = needed.saturating_sub(e.size_bytes);
      remove.push(e.id.clone());
    }
  }
  (needed == 0).then_some(remove)
}

fn prune(dir: &Path, keep_id: Option<&str>) -> Result<(), ApiError> {
  for id in plan_pruning(&entries(dir)?, Utc::now(), keep_id) {
    remove(dir, &id)?;
  }
  Ok(())
}

fn prune_after_create(dir: &Path, keep_id: &str) {
  if let Err(e) = prune(dir, Some(keep_id)) {
    tracing::warn!("裁剪本机热快照失败：{}", e.message);
  }
}

fn clean_temp(dir: &Path) -> Result<(), ApiError> {
  for file in fs::read_dir(dir).map_err(io_error)? {
    let file = file.map_err(io_error)?;
    if file.file_name().as_encoded_bytes().starts_with(b".tmp-")
      && let Some(m) = metadata(&file.path(), false)?
      && m
        .modified()
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|d| d > Duration::from_secs(3600))
    {
      fs::remove_file(file.path()).map_err(io_error)?;
    }
  }
  Ok(())
}

pub(crate) fn free_bytes(dir: &Path) -> Result<u64, ApiError> {
  let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
    .map_err(|_| ApiError::invalid("数据目录路径无效"))?;
  let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
  // statvfs 成功时填满结构体。
  if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
    return Err(io_error(io::Error::last_os_error()));
  }
  let stat = unsafe { stat.assume_init() };
  let free = u128::from(stat.f_bavail) * u128::from(stat.f_frsize);
  Ok(free.try_into().unwrap_or(u64::MAX))
}

fn preflight(
  data_dir: &Path,
  dir: &Path,
  keep_id: Option<&str>,
) -> Result<(), ApiError> {
  let required = ["wharf.db", "wharf.db-wal"]
    .into_iter()
    .try_fold(0_u64, |sum, name| {
      Ok::<_, ApiError>(sum.saturating_add(
        metadata(&data_dir.join(name), false)?.map_or(0, |m| m.len()),
      ))
    })?
    .saturating_mul(2)
    .saturating_add(MIN_FREE_AFTER_BYTES);
  let mut free = free_bytes(dir)?;
  if free < required {
    clean_temp(dir)?;
    free = free_bytes(dir)?;
  }
  let ids = space_pruning(
    &entries(dir)?,
    required.saturating_sub(free),
    keep_id,
  )
  .ok_or_else(|| {
    conflict(format!(
      "磁盘剩余 {} MiB，留热快照至少需要 {} MiB",
      free / (1024 * 1024),
      required.div_ceil(1024 * 1024)
    ))
  })?;
  for id in ids {
    remove(dir, &id)?;
  }
  Ok(())
}

pub(crate) fn hash(path: &Path) -> Result<String, ApiError> {
  let mut digest = Sha256::new();
  let mut file = File::open(path).map_err(io_error)?;
  let mut buf = [0; 16384];
  loop {
    let n = file.read(&mut buf).map_err(io_error)?;
    if n == 0 {
      break;
    }
    digest.update(&buf[..n]);
  }
  Ok(hex::encode(digest.finalize()))
}

fn fingerprint(data_dir: &Path) -> Result<String, ApiError> {
  let path = data_dir.join(db::CREDENTIALS_KEY_FILE);
  let key = fs::read(path).map_err(io_error)?;
  if key.len() != 32 {
    return Err(conflict("主密钥文件格式不对"));
  }
  Ok(hex::encode(&Sha256::digest(key)[..4]))
}

fn private_file(path: &Path) -> Result<File, ApiError> {
  OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(path)
    .map_err(io_error)
}

fn write_snapshot(
  c: &Connection,
  data_dir: &Path,
  dir: &Path,
  mut info: DbSnapshotInfo,
  keep_id: Option<&str>,
  cancelled: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<DbSnapshotInfo, ApiError> {
  let mut salt = [0; 2];
  getrandom::fill(&mut salt).map_err(|_| conflict("随机数不可用"))?;
  info.created_at = Utc::now();
  info.id = format!(
    "{}-{}-{}",
    info.created_at.format("%Y%m%d-%H%M%SZ"),
    info.trigger,
    hex::encode(salt)
  );
  let db_tmp = dir.join(format!(".tmp-{}.db", info.id));
  let json_tmp = dir.join(format!(".tmp-{}.json", info.id));
  let db_final = dir.join(format!("{}.db", info.id));
  let json_final = dir.join(format!("{}.json", info.id));
  for path in [&db_tmp, &json_tmp, &db_final, &json_final] {
    if metadata(path, false)?.is_some() {
      return Err(conflict("快照 ID 已存在，请重试"));
    }
  }
  info.key_fingerprint = fingerprint(data_dir)?;
  preflight(data_dir, dir, keep_id)?;
  let cancelled = Arc::new(cancelled);
  let mut published = false;
  let mut published_json = false;
  let result = (|| {
    let check = cancelled.clone();
    vacuum_into(c, &db_tmp, move || check())?;
    fs::set_permissions(&db_tmp, fs::Permissions::from_mode(0o600))
      .map_err(io_error)?;
    let file = File::open(&db_tmp).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    info.size_bytes = file.metadata().map_err(io_error)?.len();
    info.schema_version = schema_version(c)?;
    info.sha256 = hash(&db_tmp)?;
    let mut file = private_file(&json_tmp)?;
    serde_json::to_writer(&mut file, &info)
      .map_err(|_| conflict("写入快照元数据失败"))?;
    file
      .flush()
      .and_then(|()| file.sync_all())
      .map_err(io_error)?;
    if cancelled() {
      return Err(timed_out());
    }
    fs::rename(&db_tmp, &db_final).map_err(io_error)?;
    published = true;
    fs::rename(&json_tmp, &json_final).map_err(io_error)?;
    published_json = true;
    sync_dir(dir)?;
    Ok(info)
  })();
  if result.is_err() {
    for path in [&db_tmp, &json_tmp] {
      let _ = fs::remove_file(path);
    }
    if published {
      let _ = fs::remove_file(db_final);
    }
    if published_json {
      let _ = fs::remove_file(json_final);
    }
  }
  result
}

pub(crate) fn vacuum_into(
  c: &Connection,
  path: &Path,
  cancelled: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<(), ApiError> {
  let cancelled = Arc::new(cancelled);
  if cancelled() {
    return Err(timed_out());
  }
  let path = path
    .to_str()
    .ok_or_else(|| ApiError::invalid("快照路径必须是 UTF-8"))?;
  let check = cancelled.clone();
  c.progress_handler(1000, Some(move || check()));
  let vacuum = c.execute("VACUUM INTO ?1", [path]);
  c.progress_handler(0, None::<fn() -> bool>);
  if cancelled() {
    return Err(timed_out());
  }
  vacuum.map_err(|_| conflict("SQLite 无法导出本机热快照"))?;
  Ok(())
}

pub(crate) fn schema_version(
  c: &Connection,
) -> Result<usize, ApiError> {
  c.pragma_query_value(None, "user_version", |r| r.get(0))
    .map_err(|_| conflict("读取 SQLite schema 版本失败"))
}

async fn create(
  db: &Db,
  data_dir: &Path,
  info: DbSnapshotInfo,
) -> Result<DbSnapshotInfo, ApiError> {
  let data_dir = data_dir.to_path_buf();
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let started = Instant::now();
  let job = db.call(move |c| {
    if cancel.is_cancelled() {
      return Err(timed_out());
    }
    let dir = directory(&data_dir)?;
    let info =
      write_snapshot(c, &data_dir, &dir, info, None, move || {
        cancel.is_cancelled() || started.elapsed() >= TIMEOUT
      })?;
    prune_after_create(&dir, &info.id);
    Ok(info)
  });
  tokio::time::timeout(TIMEOUT, job)
    .await
    .map_err(|_| timed_out())?
    .map_err(|e| {
      if e.code == ErrorCode::Conflict {
        e
      } else {
        conflict(e.message)
      }
    })
}

fn info(trigger: Trigger, reason: String) -> DbSnapshotInfo {
  DbSnapshotInfo {
    trigger: trigger.name().into(),
    reason,
    build: wharf_api_types::BUILD.into(),
    ..Default::default()
  }
}

pub fn api_actor(
  auth: &Auth,
  peer: Option<
    axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>,
  >,
  headers: &axum::http::HeaderMap,
) -> Actor {
  let source = peer.map_or_else(
    || "API".into(),
    |axum::Extension(axum::extract::ConnectInfo(addr))| {
      crate::login::client_key(addr.ip(), headers)
    },
  );
  Actor::from_request((auth, source))
}

pub async fn before(
  s: &AppState,
  trigger: Trigger,
  reason: String,
  plan: Option<&Plan>,
  skip: Option<&Actor>,
) -> Result<Option<DbSnapshotInfo>, ApiError> {
  if let Some(actor) = skip {
    let detail = format!("跳过数据库热快照执行 {reason}");
    crate::audit::insert(
      s,
      AuditEntry {
        id: 0,
        at: db::now_ms(),
        kind: "api".into(),
        actor: actor.name.clone(),
        method: "snapshot_skip".into(),
        path: trigger.name().into(),
        status: None,
        duration_ms: None,
        detail: Some(detail.clone()),
        source: Some(actor.source.clone()),
      },
    )
    .await?;
    crate::security_receipt::send(
      s,
      &actor.name,
      &actor.source,
      detail,
    )
    .await;
    return Ok(None);
  }
  let mut info = info(trigger, reason);
  if let Some(plan) = plan {
    info.plan_id = Some(plan.plan_id.clone());
    info.addresses = plan
      .items
      .iter()
      .map(|i| i.address.clone())
      .collect::<std::collections::BTreeSet<_>>()
      .into_iter()
      .collect();
  }
  create(&s.db, &s.data_dir, info)
    .await
    .map(Some)
    .map_err(|error| {
      let hint = error.hint.as_deref().unwrap_or_default();
      let hint =
        format!("{hint}。紧急情况下 Admin 可显式加 --skip-snapshot");
      error.with_hint(hint)
    })
}

pub async fn cleanup(s: &AppState) -> Result<(), ApiError> {
  let Ok(_guard) = s.locks.acquire(
    crate::locks::LockSpec::CoreMaintenance,
    "维护控制面热快照",
  ) else {
    return Ok(());
  };
  let data_dir = s.data_dir.clone();
  s.db
    .call(move |_| {
      let dir = directory(&data_dir)?;
      clean_temp(&dir)?;
      prune(&dir, None)
    })
    .await
}

fn view(dir: &Path) -> Result<CoreSnapshotsView, ApiError> {
  let mut snapshots = entries(dir)?;
  for info in &mut snapshots {
    info.reason = crate::log_redact::redact_text(&info.reason);
  }
  Ok(CoreSnapshotsView {
    dir_bytes: bytes(&snapshots),
    max_count: MAX_COUNT,
    max_total_bytes: MAX_TOTAL_BYTES,
    min_free_after_bytes: MIN_FREE_AFTER_BYTES,
    snapshots,
    restore_hint: SNAPSHOT_RESTORE_HINT.into(),
  })
}

pub async fn list_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreSnapshotsView> {
  auth.require(Perm::Admin)?;
  let data_dir = s.data_dir.clone();
  Ok(Json(
    s.db.call(move |_| view(&directory(&data_dir)?)).await?,
  ))
}

#[derive(Deserialize)]
pub struct CreateRequest {
  reason: Option<String>,
}

pub async fn create_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<CreateRequest>,
) -> ApiResult<DbSnapshotInfo> {
  auth.require(Perm::Admin)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::CoreMaintenance,
    "维护控制面热快照",
  )?;
  let reason = crate::log_redact::redact_text(
    req.reason.as_deref().unwrap_or("手动留底"),
  );
  if reason.len() > 1024 {
    return Err(
      ApiError::invalid("快照原因不能超过 1024 字节").into(),
    );
  }
  Ok(Json(
    create(&s.db, &s.data_dir, info(Trigger::Manual, reason)).await?,
  ))
}

pub async fn delete_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ApiPath(id): ApiPath<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  validate_id(&id)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::CoreMaintenance,
    "维护控制面热快照",
  )?;
  let data_dir = s.data_dir.clone();
  Ok(Json(
    s.db
      .call(move |_| {
        remove(&directory(&data_dir)?, &id)?;
        Ok(json!({ "removed": true, "id": id }))
      })
      .await?,
  ))
}

mod offline;
pub(crate) use offline::lock_sqlite;
pub use offline::{OfflineCommand, offline, process_lock};

#[cfg(test)]
mod tests;
