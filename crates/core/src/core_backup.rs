//! 控制面自身备份（design 2.11）：数据库、控制面密钥、管理员 token，
//! 每天用 restic 推到另一台服务器的 rest-server（独立于业务备份）。
//!
//! - 数据库用 `VACUUM INTO` 做一致的快照，和密钥一起放到 [CORE_BACKUP_DIR]，
//!   同机的 agent 备份这个目录（目录里的标记确认是哪台机器）；
//! - 仓库有两把口令：控制面保存的备份口令（定时备份用），和管理员的登录密码
//!   （开启时输入，控制面只存它的哈希，拿不到明文）。控制面整个丢了，
//!   用登录密码就能从备份服务器恢复；
//! - 备份服务器的 htpasswd 也加上管理员账号（bcrypt），恢复时用登录密码访问。

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use axum::{
  Extension, Json,
  extract::{ConnectInfo, State},
  http::{HeaderMap, header},
  response::{AppendHeaders, IntoResponse, Response},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BackupSummary, CORE_BACKUP_DIR, CORE_REST_SERVER_PORT,
    OneTimeSecret, ResticAction, ResticKeyInfo,
  },
  plan::ApplyResponse,
  view::{BackupRecord, Issue, IssueLevel, Perm},
};

use crate::{
  api::{ApiResult, AppError},
  apply,
  audit::{self, AuditSlot},
  auth::Auth,
  backup::{self, Where},
  core_node::VerifiedCore,
  db::{self, now_ms, sql_err},
  hub::ProgressFn,
  lockout::{self, LockScope},
  login,
  planner::Step,
  render, snapshot,
  state::AppState,
};

/// 备份服务器 htpasswd 里管理员那一行：`用户名:bcrypt(登录密码)`。
pub const OWNER_SECRET: &str = "WHARF_CORE_BACKUP_OWNER";
/// 仓库名，也是备份记录里的服务名。
pub const REPO: &str = "wharf-core";
pub const KEY_SECRET: &str = "WHARF_CORE_BACKUP_KEY";
pub const HTTP_SECRET: &str = "WHARF_CORE_BACKUP_HTTP";
pub const HTTP_HASH_SECRET: &str = "WHARF_CORE_BACKUP_HTTP_HASH";
pub const HTTP_USER: &str = "wharf-core";
const REPO_SETTING: &str = "core_backup.repo";
const REPO_VERSION: &str = "7711";
const USER_KEY_TARGET: &str = "core_backup.user_key_target";
pub(crate) const TO: &str = "core_backup.to";
/// 登录密码那把钥匙的 id，换密码时删掉旧的。
const USER_KEY: &str = "core_backup.user_key";
/// 加钥匙时管理员的密码哈希。和现在的不一样说明改过密码，要重新输入一次。
const KEY_FOR: &str = "core_backup.key_for";

#[derive(Serialize)]
pub struct CoreBackupView {
  /// 备份到哪台服务器，没开启时没有。
  #[serde(skip_serializing_if = "Option::is_none")]
  pub to: Option<String>,
  /// 登录密码那把钥匙是不是当前的密码。
  pub user_key_current: bool,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub repo_empty: bool,
  pub records: Vec<BackupRecord>,
  /// 控制面整个丢了时，在新机器上执行的恢复命令。
  #[serde(skip_serializing_if = "Option::is_none")]
  pub restore_command: Option<String>,
}

pub fn target(
  c: &rusqlite::Connection,
) -> Result<Option<String>, ApiError> {
  db::setting(c, TO)
}

#[derive(Deserialize)]
pub struct PasswordRequest {
  pub password: String,
}

#[derive(Serialize)]
pub struct RecoveryKey {
  pub filename: String,
  pub text: String,
}

#[derive(Deserialize)]
pub struct EnableRequest {
  pub to: String,
  pub password: String,
}

/// `GET /api/core-backup`
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreBackupView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let records = crate::backup::records(&s, REPO, 10).await?;
  let (to, user_key_current, admin) = s
    .db
    .call(|c| {
      let to = db::setting(c, TO)?;
      let admin: Option<(String, String)> = c
        .query_row(
          "SELECT username, password_hash FROM admin WHERE id = 1",
          [],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
      let user_key_current = user_key_current(
        c,
        to.as_deref(),
        admin.as_ref().map(|a| a.1.as_str()),
      )?;
      Ok((to, user_key_current, admin))
    })
    .await?;
  let restore_command = to.as_ref().and_then(|to| {
    let ip = snap.net(&snap.world).private.get(to)?.ip.clone();
    let user = admin.as_ref().map(|a| a.0.clone())?;
    Some(restore_command(&ip, &user))
  });
  let history = crate::data::history(&s.db).await?;
  let repo_empty = to.as_ref().is_some_and(|target| {
    let last_ok = history
      .get(&(REPO.into(), target.clone()))
      .and_then(|h| h.ok);
    crate::data::repo_verified_empty(&s, &snap, target, REPO, last_ok)
  });
  Ok(Json(CoreBackupView {
    user_key_current,
    repo_empty,
    to,
    records,
    restore_command,
  }))
}

fn user_key_current(
  c: &rusqlite::Connection,
  target: Option<&str>,
  admin_hash: Option<&str>,
) -> Result<bool, ApiError> {
  Ok(
    target.is_some()
      && admin_hash.is_some()
      && db::setting(c, REPO_SETTING)?.as_deref()
        == Some(REPO_VERSION)
      && db::setting(c, USER_KEY_TARGET)?.as_deref() == target
      && db::setting(c, USER_KEY)?.is_some()
      && db::setting(c, KEY_FOR)?.as_deref() == admin_hash,
  )
}

pub(crate) async fn require_recovery_ready(
  state: &AppState,
) -> Result<(), ApiError> {
  state
    .db
    .call_credentials(|c, key| {
      if let Some(target) = db::setting(c, TO)? {
        let hash = c
          .query_row(
            "SELECT password_hash FROM admin WHERE id = 1",
            [],
            |r| r.get::<_, String>(0),
          )
          .map_err(sql_err)?;
        if key.secret(c, KEY_SECRET)?.is_none()
          || !user_key_current(c, Some(&target), Some(&hash))?
        {
          return Err(
            ApiError::new(
              ErrorCode::Conflict,
              "请先同步控制面备份的恢复口令",
            )
            .with_hint(format!(
              "运行 wharf backup core --to {target}"
            )),
          );
        }
      }
      Ok(())
    })
    .await
}

fn password_source(
  peer: SocketAddr,
  headers: &HeaderMap,
) -> Result<String, ApiError> {
  let key = login::client_key(peer.ip(), headers);
  if let Some(minutes) = lockout::locked(LockScope::AdminLogin, &key)
  {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      format!("输错次数太多，{minutes} 分钟后再试"),
    ));
  }
  Ok(key)
}

async fn verify_backup_password(
  s: &AppState,
  auth: &Auth,
  audit: &AuditSlot,
  key: &str,
  source: String,
  password: String,
  hash: String,
) -> Result<(), ApiError> {
  if login::verify_password_async(password, hash).await? {
    lockout::clear(LockScope::AdminLogin, key);
    return Ok(());
  }
  lockout::record_and_notify(
    s,
    LockScope::AdminLogin,
    key,
    Some("控制面备份"),
  )
  .await;
  audit::login_event(s, "login_failed", &auth.name, source).await;
  audit.set_detail("控制面备份登录密码校验失败".into());
  tokio::time::sleep(Duration::from_secs(1)).await;
  Err(ApiError::new(ErrorCode::Forbidden, "登录密码不对"))
}

/// `POST /api/core-backup`：开启（或换备份服务器、改过密码后重新输入），并立刻备份一次。
pub async fn enable(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<EnableRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Admin)?;
  let key = password_source(peer, &headers)?;
  check_data_dir(&s)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&req.to) {
    return Err(crate::world::server_not_found(&req.to).into());
  }
  if !snap.net(&snap.world).private.contains_key(&req.to) {
    return Err(
      ApiError::invalid(format!(
        "{} 没有内网地址，不能做备份服务器",
        req.to
      ))
      .into(),
    );
  }
  let (username, hash) = login::admin(&s.db)
    .await?
    .ok_or_else(|| sql_err(rusqlite::Error::QueryReturnedNoRows))?;
  if matches!(username.as_str(), "wharf" | HTTP_USER)
    || username == "."
    || username.contains("..")
    || username.contains('/')
  {
    return Err(ApiError::invalid(format!(
      "管理员账号叫 {username}，不能用于控制面备份账号，请先改个名"
    )).with_hint("在控制面服务器执行 docker exec -it wharf-core wharf-core reset-password <新用户名>").into());
  }
  verify_backup_password(
    &s,
    &auth,
    &audit,
    &key,
    login::source(peer.ip(), &headers),
    req.password.clone(),
    hash,
  )
  .await?;
  let guard = s
    .locks
    .acquire(crate::locks::LockSpec::CoreBackup, "备份控制面")?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let core_server = match crate::core_node::server_of(&snap) {
    Some(server) => server,
    None => {
      crate::core_node::require_verified(&s, &cancel)
        .await?
        .server
    }
  };
  reject_self_target(&core_server, &req.to)?;
  for server in [&core_server, &req.to] {
    backup::require_isolation(&s, server)?;
    backup::require_safe_backup(&s, server)?;
  }
  let password = req.password.clone();
  let owner = tokio::task::spawn_blocking(move || {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
  })
  .await
  .map_err(|_| ApiError::internal("计算哈希失败"))?
  .map_err(|e| ApiError::internal(format!("计算哈希失败：{e}")))?;
  let owner = format!("{username}:{owner}");
  Ok(Json(
    apply::start_task_locked(
      s.clone(),
      "备份控制面".into(),
      Step::CoreBackup {
        user_key: Some(OneTimeSecret(req.password)),
        target: Some(req.to),
        owner_secret: Some(OneTimeSecret(owner)),
      },
      Some(crate::apply::format_actor(&auth)),
      guard,
    )
    .await?,
  ))
}

/// `POST /api/core-backup/recovery-key`：后备的恢复密钥（备份口令和备份服务器账号）。
/// 登录密码忘了也能恢复控制面。下载前要重新输入登录密码。
pub async fn recovery_key(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<PasswordRequest>,
) -> Result<Response, AppError> {
  auth.require(Perm::Admin)?;
  login::require_human(&auth)?;
  let key = password_source(peer, &headers)?;
  let (_, hash) = login::admin(&s.db)
    .await?
    .ok_or_else(|| sql_err(rusqlite::Error::QueryReturnedNoRows))?;
  verify_backup_password(
    &s,
    &auth,
    &audit,
    &key,
    login::source(peer.ip(), &headers),
    req.password,
    hash,
  )
  .await?;
  let snap = snapshot::load(&s.db).await?;
  let to = s.db.call(|c| db::setting(c, TO)).await?;
  let net = snap.net(&snap.world);
  let target =
    to.as_ref().and_then(|t| net.private.get(t)).map(|a| {
      if a.ip.contains(':') {
        format!("[{}]:{CORE_REST_SERVER_PORT}", a.ip)
      } else {
        format!("{}:{CORE_REST_SERVER_PORT}", a.ip)
      }
    });
  let creds = ensure_creds(&s).await?;
  tracing::info!("已下载恢复密钥");
  let image = wharf_api_types::agent::RESTIC_IMAGE;
  let user = HTTP_USER;
  let mut text = format!(
    "# Wharf 恢复密钥：能打开控制面备份，收好，别放在被备份的机器上。\n\
RESTIC_PASSWORD={key}\n\
RESTIC_REST_USERNAME={user}\n\
RESTIC_REST_PASSWORD={http}\n",
    key = creds.key,
    http = creds.http,
  );
  if let Some(target) = target {
    text.push_str(&format!(
      "\n# 控制面备份在 {to}（{target}）的仓库 {REPO}。\n\
# 恢复控制面（新机器先加入同一个内网，把本文件存成 wharf-recovery.env）：\n\
docker run --rm --label wharf.temp=1 --network host --env-file wharf-recovery.env -v /var/lib/wharf-core:/restore \\\n  \
{image} -r rest:http://{target}/{REPO} restore latest:{CORE_BACKUP_DIR} --target /restore\n",
      to = to.unwrap_or_default(),
    ));
  }
  audit.require_record("下载了控制面恢复密钥".into());
  crate::security_receipt::send(
    &s,
    &auth.name,
    &key,
    "下载控制面恢复密钥".into(),
  )
  .await;
  Ok(
    (
      AppendHeaders([(header::CACHE_CONTROL, "no-store")]),
      Json(RecoveryKey {
        filename: "wharf-recovery.env".into(),
        text,
      }),
    )
      .into_response(),
  )
}

/// `POST /api/core-backup/run`
pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Apply)?;
  Ok(Json(
    apply::start_task_by(
      s.clone(),
      "备份控制面".into(),
      Step::CoreBackup {
        user_key: None,
        target: None,
        owner_secret: None,
      },
      Some(crate::apply::format_actor(&auth)),
    )
    .await?,
  ))
}

/// 控制面数据目录必须是 [CORE_BACKUP_DIR] 的上一级，agent 才找得到。
fn check_data_dir(s: &AppState) -> Result<(), ApiError> {
  let expected = Path::new(CORE_BACKUP_DIR).parent();
  if expected != Some(s.data_dir.as_path()) {
    return Err(ApiError::invalid(format!(
      "控制面数据目录是 {}，不是 {}，不能自动备份",
      s.data_dir.display(),
      expected
        .map(|p| p.display().to_string())
        .unwrap_or_default()
    )));
  }
  Ok(())
}

fn reject_self_target(
  server: &str,
  target: &str,
) -> Result<(), ApiError> {
  if server == target {
    return Err(ApiError::invalid(format!(
      "控制面所在机器 {target} 不能同时作为控制面备份目标"
    )));
  }
  Ok(())
}

pub async fn backup(
  state: &AppState,
  run_id: &str,
  user_key: Option<&OneTimeSecret>,
  change: (Option<&str>, Option<&OneTimeSecret>),
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  backup_impl(state, run_id, user_key, change, progress, cancel, true)
    .await
}

async fn backup_impl(
  state: &AppState,
  run_id: &str,
  user_key: Option<&OneTimeSecret>,
  (target, owner): (Option<&str>, Option<&OneTimeSecret>),
  progress: ProgressFn,
  cancel: &CancellationToken,
  require_standard_dir: bool,
) -> Result<(), ApiError> {
  let (to, old_target) =
    state.db.call(|c| db::setting(c, TO)).await.map(|old| {
      (target.map(str::to_string).or_else(|| old.clone()), old)
    })?;
  let to = to.ok_or_else(|| ApiError::invalid("还没有开启控制面备份")
    .with_hint("本机快速回退用 wharf core snapshot，整机异地灾备用 wharf backup core")
    .suggest("wharf backup core --to <server>"))?;
  let mut w = Where {
    server: String::new(),
    target: to,
    target_ip: String::new(),
  };
  let result: Result<_, ApiError> = async {
    if require_standard_dir {
      check_data_dir(state)?;
    }
    let snap = snapshot::load(&state.db).await?;
    w.server = crate::core_node::server_of(&snap).unwrap_or_default();
    w.target_ip = target_ip(&snap, &w.target)?;
    let core =
      crate::core_node::require_verified(state, cancel).await?;
    w.server.clone_from(&core.server);
    reject_self_target(&w.server, &w.target)?;
    backup::require_safe_backup(state, &w.server)?;
    backup::require_safe_backup(state, &w.target)?;
    let mut creds = ensure_creds(state).await?;
    // 同一个目标的旧登录凭据保留到新快照与新钥匙准备好。
    if old_target.as_deref() != Some(&w.target) {
      creds.owner = owner.map(|owner| owner.0.clone());
    }
    ensure_core_server(state, &snap, &w, &creds, &progress, cancel)
      .await?;
    let dir = staging_path(&state.data_dir);
    let (marker, _stage) = stage(state, &dir).await?;
    progress("已生成数据库快照".into());
    let summary: BackupSummary = run_repo(
      state,
      &snap,
      &w,
      &creds,
      &core,
      ResticAction::Backup {
        host: w.server.clone(),
      },
      Some(&marker),
      &progress,
      cancel,
    )
    .await?;
    Ok((summary, snap, core, creds))
  }
  .await;
  let recorded = result
    .as_ref()
    .map(|(summary, _, _, _)| summary.clone())
    .map_err(Clone::clone);
  if !matches!(&recorded, Err(e) if e.code == ErrorCode::Cancelled) {
    backup::record(state, run_id, REPO, &w, &recorded).await?;
  }
  let (_, snap, core, mut creds) = result?;
  let old_owner = creds.owner.clone();
  if let Some(owner) = owner {
    creds.owner = Some(owner.0.clone());
  }
  finish_backup(
    state,
    &snap,
    &w,
    &creds,
    &core,
    user_key,
    old_target.as_deref() == Some(&w.target),
    old_owner,
    &progress,
    cancel,
  )
  .await
}

fn target_ip(
  snap: &snapshot::Snapshot,
  to: &str,
) -> Result<String, ApiError> {
  snap
    .net(&snap.world)
    .private
    .get(to)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::invalid(format!("备份服务器 {to} 没有内网地址"))
    })
}

pub async fn unlock(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  body: Option<Json<backup::UnlockRequest>>,
) -> ApiResult<()> {
  auth.require(Perm::Admin)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::CoreBackup,
    "解锁控制面备份仓库",
  )?;
  let target = s
    .db
    .call(|c| db::setting(c, TO))
    .await?
    .ok_or_else(|| ApiError::invalid("还没有开启控制面备份"))?;
  let snap = snapshot::load(&s.db).await?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let core = crate::core_node::require_verified(&s, &cancel).await?;
  backup::require_safe_backup(&s, &core.server)?;
  let w = Where {
    server: core.server.clone(),
    target_ip: target_ip(&snap, &target)?,
    target,
  };
  let creds = ensure_creds(&s).await?;
  let progress: ProgressFn = Arc::new(|_| {});
  run_repo::<serde_json::Value>(
    &s,
    &snap,
    &w,
    &creds,
    &core,
    ResticAction::Unlock {
      remove_all: !body.is_some_and(|b| b.stale_only),
    },
    None,
    &progress,
    &cancel,
  )
  .await?;
  Ok(Json(()))
}

pub async fn issues(db: &db::Db) -> Result<Vec<Issue>, ApiError> {
  db.call(|c| {
    let Some(target) = db::setting(c, TO)? else { return Ok(Vec::new()); };
    let hash: Option<String> = c.query_row("SELECT password_hash FROM admin WHERE id = 1", [], |r| r.get(0)).optional().map_err(sql_err)?;
    if user_key_current(c, Some(&target), hash.as_deref())? { return Ok(Vec::new()); }
    Ok(vec![Issue {
      code: "core_backup_key_stale".into(),
      level: IssueLevel::Warn,
      subject: None,
      ack: None,
      alert: None,
      title: "控制面备份的登录密码恢复口令已失效".into(),
      hint: Some(format!("重新输入当前登录密码同步恢复口令：wharf backup core --to {target}")),
    }])
  }).await
}

#[derive(Clone)]
struct CoreCreds {
  key: String,
  http: String,
  http_hash: String,
  owner: Option<String>,
}

async fn ensure_creds(
  state: &AppState,
) -> Result<CoreCreds, ApiError> {
  let (http, http_hash) = backup::ensure_http_pair(
    state,
    HTTP_SECRET.into(),
    HTTP_HASH_SECRET.into(),
  )
  .await?;
  let (key, owner) = state
    .db
    .call_credentials(|c, master| {
      Ok((
        db::ensure_secret(c, master, KEY_SECRET, now_ms())?,
        master.secret(c, OWNER_SECRET)?,
      ))
    })
    .await?;
  Ok(CoreCreds {
    key,
    http,
    http_hash,
    owner,
  })
}

async fn ensure_core_server(
  state: &AppState,
  snap: &snapshot::Snapshot,
  w: &Where,
  creds: &CoreCreds,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  backup::require_isolation(state, &w.server)?;
  backup::require_isolation(state, &w.target)?;
  let mut htpasswd = format!("{HTTP_USER}:{}\n", creds.http_hash);
  if let Some(owner) = &creds.owner
    && owner
      .split_once(':')
      .is_some_and(|(user, _)| user != HTTP_USER)
  {
    htpasswd.push_str(owner);
    htpasswd.push('\n');
  }
  let compose =
    render::core_backup_server_compose(&w.target_ip, &htpasswd);
  backup::deploy_server(
    state,
    snap,
    w,
    (render::CORE_BACKUP_PROJECT, compose),
    progress,
    cancel,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn finish_backup(
  state: &AppState,
  snap: &snapshot::Snapshot,
  w: &Where,
  creds: &CoreCreds,
  core: &VerifiedCore,
  user_key: Option<&OneTimeSecret>,
  same_target: bool,
  old_owner: Option<String>,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  if let Some(password) = user_key {
    let (_, hash) = login::admin(&state.db)
      .await?
      .ok_or_else(|| sql_err(rusqlite::Error::QueryReturnedNoRows))?;
    let changed = || {
      ApiError::new(
        ErrorCode::Conflict,
        "登录密码已变更，请重新设置控制面备份",
      )
    };
    if !login::verify_password_async(password.0.clone(), hash.clone())
      .await?
    {
      return Err(changed());
    }
    let keys: Vec<ResticKeyInfo> = run_repo(
      state,
      snap,
      w,
      creds,
      core,
      ResticAction::ListKeys,
      None,
      progress,
      cancel,
    )
    .await?;
    let id: String = run_repo(
      state,
      snap,
      w,
      creds,
      core,
      ResticAction::AddKey {
        new_password: password.clone(),
      },
      None,
      progress,
      cancel,
    )
    .await?;
    let owner_changed = old_owner != creds.owner;
    let configure: Result<_, ApiError> = async {
      if owner_changed {
        ensure_core_server(state, snap, w, creds, progress, cancel)
          .await?;
      }
      let target = w.target.clone();
      let owner = creds.owner.clone();
      let new_id = id.clone();
      state
        .db
        .call_credentials(move |c, key| {
          let tx = c.transaction().map_err(sql_err)?;
          let matches = tx
            .query_row(
              "SELECT password_hash = ?1 FROM admin WHERE id = 1",
              [&hash],
              |r| r.get::<_, bool>(0),
            )
            .optional()
            .map_err(sql_err)?
            .unwrap_or(false);
          if !matches {
            return Err(changed());
          }
          let old = db::setting(&tx, USER_KEY)?;
          db::set_setting(&tx, TO, Some(&target))?;
          if let Some(owner) = owner {
            key.put_secret(
              &tx,
              OWNER_SECRET,
              &owner,
              now_ms(),
              true,
            )?;
          }
          db::set_setting(&tx, REPO_SETTING, Some(REPO_VERSION))?;
          db::set_setting(&tx, USER_KEY, Some(&new_id))?;
          db::set_setting(&tx, KEY_FOR, Some(&hash))?;
          db::set_setting(&tx, USER_KEY_TARGET, Some(&target))?;
          tx.commit().map_err(sql_err)?;
          Ok(old)
        })
        .await
    }
    .await;
    let old = match configure {
      Ok(old) => old,
      Err(error) => {
        if owner_changed && same_target {
          let previous = CoreCreds {
            owner: old_owner,
            ..creds.clone()
          };
          let rolled_back = ensure_core_server(
            state,
            snap,
            w,
            &previous,
            progress,
            &CancellationToken::new(),
          )
          .await;
          if let Err(rollback) = rolled_back {
            return Err(error.with_hint(format!(
              "恢复旧备份服务器配置失败：{}",
              rollback.message
            )));
          }
        }
        return Err(error);
      }
    };
    // 配置先提交，数据库写失败时旧钥匙仍可用。
    if same_target
      && let Some(old) = old
      && old != id
      && keys.iter().any(|k| !k.current && k.id == old)
      && let Err(e) = run_repo::<serde_json::Value>(
        state,
        snap,
        w,
        creds,
        core,
        ResticAction::RemoveKey { id: old },
        None,
        progress,
        &CancellationToken::new(),
      )
      .await
    {
      progress(format!("提醒：删除旧恢复口令失败：{}", e.message));
    }
    progress("已把登录密码设为恢复口令".into());
  } else {
    state
      .db
      .call(|c| db::set_setting(c, REPO_SETTING, Some(REPO_VERSION)))
      .await?;
  }
  // 清理旧快照失败不影响这次备份的结果。
  let pruned = run_repo::<serde_json::Value>(
    state,
    snap,
    w,
    creds,
    core,
    ResticAction::Prune,
    None,
    progress,
    cancel,
  )
  .await;
  if let Err(e) = pruned {
    progress(format!("提醒：清理旧快照失败：{}", e.message));
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_repo<T: serde::de::DeserializeOwned>(
  state: &AppState,
  snap: &snapshot::Snapshot,
  w: &Where,
  creds: &CoreCreds,
  core: &VerifiedCore,
  action: ResticAction,
  marker: Option<&str>,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<T, ApiError> {
  let mut job = backup::job(
    snap,
    &core.server,
    REPO,
    backup::rest_repo(
      &w.target_ip,
      CORE_REST_SERVER_PORT,
      HTTP_USER,
      &creds.http,
    ),
    &creds.key,
    action,
  );
  if let AgentOp::Restic(j) = &mut job {
    j.core_marker = marker.map(str::to_string);
  }
  core
    .call(
      state,
      job,
      backup::RESTIC_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await
}

struct StagedCoreDir(std::path::PathBuf);

impl Drop for StagedCoreDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn staging_path(data_dir: &Path) -> std::path::PathBuf {
  data_dir
    .join(Path::new(CORE_BACKUP_DIR).file_name().expect("备份目录名"))
}

pub fn cleanup_staged(data_dir: &Path) {
  let _ = std::fs::remove_dir_all(staging_path(data_dir));
}

/// 把数据库快照、控制面密钥、加密主密钥、管理员 token 放进 [CORE_BACKUP_DIR]，返回标记。
async fn stage(
  state: &AppState,
  dir: &Path,
) -> Result<(String, StagedCoreDir), ApiError> {
  use std::os::unix::fs::DirBuilderExt;
  use std::os::unix::fs::PermissionsExt;
  match std::fs::remove_dir_all(dir) {
    Ok(()) => {}
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
    Err(e) => {
      return Err(ApiError::internal(format!(
        "清理备份暂存目录失败：{e}"
      )));
    }
  }
  std::fs::DirBuilder::new().mode(0o700).create(dir).map_err(
    |e| ApiError::internal(format!("创建 {}：{e}", dir.display())),
  )?;
  let guard = StagedCoreDir(dir.to_path_buf());
  let _rotation = state.key.operation.lock().await;
  let db_copy = dir.join("wharf.db").display().to_string();
  state
    .db
    .call(move |c| {
      c.execute("VACUUM INTO ?1", params![db_copy])
        .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  std::fs::set_permissions(
    dir.join("wharf.db"),
    std::fs::Permissions::from_mode(0o600),
  )
  .map_err(|e| {
    ApiError::internal(format!(
      "收紧备份数据库权限失败：{}",
      e.kind()
    ))
  })?;
  for name in ["core.key", "core.key.prev", "admin.token"] {
    let from = state.data_dir.join(name);
    if from.exists() {
      std::fs::copy(&from, dir.join(name)).map_err(|e| {
        ApiError::internal(format!("复制 {}：{e}", from.display()))
      })?;
    }
  }
  let key = db::CREDENTIALS_KEY_FILE;
  std::fs::copy(state.data_dir.join(key), dir.join(key)).map_err(
    |e| ApiError::internal(format!("备份主密钥 {key} 失败：{e}")),
  )?;
  let marker = backup::random_hex();
  std::fs::write(dir.join(".marker"), &marker)
    .map_err(|e| ApiError::internal(format!("写标记：{e}")))?;
  Ok((marker, guard))
}

/// 新机器上恢复：先让它加入同一个内网，再执行这条命令，按提示输入两次登录密码。
fn restore_command(ip: &str, user: &str) -> String {
  let image = wharf_api_types::agent::RESTIC_IMAGE;
  let ip = if ip.contains(':') {
    format!("[{ip}]")
  } else {
    ip.to_string()
  };
  format!(
    "read -rsp '登录密码：' P && echo && docker run --rm --label wharf.temp=1 --network host -v /var/lib/wharf-core:/restore \
-e RESTIC_REST_USERNAME={user} -e RESTIC_REST_PASSWORD=\"$P\" -e RESTIC_PASSWORD=\"$P\" \
{image} -r rest:http://{ip}:{CORE_REST_SERVER_PORT}/{REPO} restore latest:{CORE_BACKUP_DIR} --target /restore"
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn prepare_failure_records_row_and_preserves_old_config() {
    let state = crate::rules::tests::test_state();
    crate::backup::tests::seed_servers(&state).await;
    state
      .db
      .call(|c| db::set_setting(c, TO, Some("s1")))
      .await
      .unwrap();
    assert_eq!(
      reject_self_target("s1", "s1").unwrap_err().code,
      ErrorCode::InvalidInput
    );
    assert!(
      backup_impl(
        &state,
        "r1",
        None,
        (Some("s2"), None),
        Arc::new(|_| {}),
        &CancellationToken::new(),
        false
      )
      .await
      .is_err()
    );
    let records = backup::records(&state, REPO, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target, "s2");
    assert!(!records[0].ok);
    assert_eq!(
      state
        .db
        .call(|c| db::setting(c, TO))
        .await
        .unwrap()
        .as_deref(),
      Some("s1")
    );
  }

  #[tokio::test]
  async fn stale_user_key_emits_issue_and_stage_drop_cleans_dir() {
    let state = crate::rules::tests::test_state();
    state
      .db
      .call(|c| db::set_setting(c, TO, Some("s2")))
      .await
      .unwrap();
    assert_eq!(
      issues(&state.db).await.unwrap()[0].code,
      "core_backup_key_stale"
    );

    let root = tempfile::tempdir().unwrap();
    let dir = staging_path(root.path());
    std::fs::create_dir(&dir).unwrap();
    drop(StagedCoreDir(dir.clone()));
    assert!(!dir.exists());
    std::fs::create_dir(&dir).unwrap();
    cleanup_staged(root.path());
    assert!(!dir.exists());
  }

  #[tokio::test]
  async fn recovery_requires_human_and_enable_password_failures_lock()
  {
    use crate::{
      rules::tests::{TEST_LOCK, test_state},
      security_receipt::tests::auth,
    };

    let _lock = TEST_LOCK.lock().await;
    let mut state = test_state();
    Arc::get_mut(&mut state).unwrap().data_dir =
      Path::new(CORE_BACKUP_DIR).parent().unwrap().into();
    let password = "fixture-password";
    state.db.call(move |c| {
      login::set_admin(c, "operator", &login::hash_password(password)?)?;
      db::apply_write(c, &db::Write::Upsert {
        kind: "server".into(), name: "s2".into(),
        spec: serde_json::json!({"private_addr": {"ip": "100.64.0.2", "network": "lan"}}),
        meta: serde_json::json!({}),
      })
    }).await.unwrap();
    let peer: SocketAddr = "127.0.0.24:12345".parse().unwrap();
    let token_peer: SocketAddr = "127.0.0.25:12345".parse().unwrap();
    let recover = |human, password: &str| {
      recovery_key(
        State(state.clone()),
        auth(human),
        ConnectInfo(peer),
        HeaderMap::new(),
        Extension(AuditSlot::default()),
        Json(PasswordRequest {
          password: password.into(),
        }),
      )
    };
    let enable_backup = |human, peer| {
      enable(
        State(state.clone()),
        auth(human),
        ConnectInfo(peer),
        HeaderMap::new(),
        Extension(AuditSlot::default()),
        Json(EnableRequest {
          to: "s2".into(),
          password: "fixture-wrong".into(),
        }),
      )
    };
    assert_eq!(
      recover(false, password).await.err().unwrap().0.code,
      ErrorCode::Forbidden
    );
    let error =
      enable_backup(false, token_peer).await.err().unwrap().0;
    assert_eq!(error.code, ErrorCode::Forbidden);
    assert_eq!(error.message, "登录密码不对");
    for _ in 0..5 {
      let error = enable_backup(true, peer).await.err().unwrap().0;
      assert_eq!(error.code, ErrorCode::Forbidden);
      assert_eq!(error.message, "登录密码不对");
    }

    let error = recover(true, password).await.err().unwrap().0;
    assert_eq!(error.code, ErrorCode::Forbidden);
    assert!(error.message.contains("分钟后再试"));
    let count: u32 = state.db.call(move |c| c.query_row(
      "SELECT count(*) FROM audit_log WHERE method = 'login_failed' AND source = ?1",
      [peer.ip().to_string()], |r| r.get(0),
    ).map_err(sql_err)).await.unwrap();
    assert_eq!(count, 5);
    lockout::clear(LockScope::AdminLogin, &peer.ip().to_string());
    lockout::clear(
      LockScope::AdminLogin,
      &token_peer.ip().to_string(),
    );
  }

  #[tokio::test]
  async fn core_backup_never_sends_secrets_to_target() {
    use crate::{
      backup::tests::seed_servers,
      rules::tests::{TEST_LOCK, test_state},
    };
    use serde_json::json;
    use wharf_api_types::agent::{CoreHostProbeResult, ResticRepo};

    let _lock = TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state();
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.data_dir = dir.path().into();
    inner.db = db::Db::open(&dir.path().join("wharf.db")).unwrap();
    seed_servers(&state).await;
    let login_password = backup::random_hex();
    let logged_in = login_password.clone();
    state
      .db
      .call_credentials(move |c, key| {
      c.execute("INSERT INTO agents (server, public_key) VALUES ('s1', 's1')", []).map_err(sql_err)?;
        login::set_admin(
          c,
          "operator",
          &login::hash_password(&logged_in)?,
        )?;
        db::set_setting(c, TO, Some("s2"))?;
        db::set_setting(c, USER_KEY, Some("abcd"))?;
        let owner_hash =
          bcrypt::hash(logged_in, bcrypt::DEFAULT_COST)
            .map_err(|_| ApiError::internal("测试哈希失败"))?;
        key.put_secret(
          c,
          OWNER_SECRET,
          &format!("operator:{owner_hash}"),
          now_ms(),
          false,
        )
      })
      .await
      .unwrap();
    let creds = ensure_creds(&state).await.unwrap();
    let target_key = creds.key.clone();
    let target_http = creds.http.clone();
    let target_password = login_password.clone();
    let owner = creds.owner.unwrap().replace('$', "$$");
    let http_hash = creds.http_hash.replace('$', "$$");
    state.hub.mock_agent_with_backup(
      "s2",
      false,
      true,
      false,
      move |op| match op {
        AgentOp::ProjectStatus { projects } => {
          assert_eq!(projects, [render::CORE_BACKUP_PROJECT]);
          Ok(json!([]))
        }
        AgentOp::ProjectUp(project) => {
          assert_eq!(project.project, render::CORE_BACKUP_PROJECT);
          assert!(
            project
              .compose
              .contains(&format!("{HTTP_USER}:{http_hash}"))
          );
          assert!(project.compose.contains(&owner));
          for secret in [&target_key, &target_http, &target_password]
          {
            assert!(!project.compose.contains(secret));
          }
          Ok(json!({"containers": [{"name": "rest-server", "service": "rest-server", "state": "running", "image": "fixture:1"}], "images": []}))
        }
        _ => panic!("备份目标机收到了容器部署以外的任务"),
      },
    );
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_source = seen.clone();
    let expected_password = login_password.clone();
    state.hub.mock_agent_with_backup("s1", false, true, true, move |op| {
      match op {
        AgentOp::ProbeCoreHost(probe) => {
          let token = std::fs::read_to_string(
            Path::new(&probe.data_dir).join(".core-probe").join(probe.challenge_id)
          ).unwrap();
          Ok(serde_json::to_value(CoreHostProbeResult { token }).unwrap())
        }
        AgentOp::Restic(job) => {
          let ResticRepo::Rest { host, port, user, password } = job.repo
            else { panic!("控制面必须使用远程仓库") };
          assert_eq!(job.service, REPO);
          assert_eq!((host.as_str(), port, user.as_str()), ("100.64.0.2", 7711, HTTP_USER));
          assert!(password.0 == creds.http && job.password.0 == creds.key);
          let mut seen = seen_source.lock().unwrap();
          match job.action {
            ResticAction::Backup { .. } => {
              assert!(job.core_marker.is_some());
              seen.push("backup");
              Ok(json!({"snapshot_id": "a1", "files": 1, "added_bytes": 500, "bytes": 500}))
            }
            ResticAction::ListKeys => {
              seen.push("list");
              Ok(json!([{"id": "a1", "current": true}, {"id": "abcd", "current": false}]))
            }
            ResticAction::AddKey { new_password } => {
              assert!(new_password.0 == expected_password);
              seen.push("add");
              Ok(json!("cafe"))
            }
            ResticAction::RemoveKey { id } => {
              assert_eq!(id, "abcd");
              seen.push("remove");
              Ok(serde_json::Value::Null)
            }
            ResticAction::Unlock { remove_all: true } => {
              seen.push("unlock");
              Ok(serde_json::Value::Null)
            }
            ResticAction::Prune => {
              seen.push("prune");
              Ok(serde_json::Value::Null)
            }
            _ => panic!("意外备份任务"),
          }
        }
        _ => panic!("意外任务"),
      }
    });
    state.hub.mock_safe_backup_agent("s1");
    state.hub.mock_safe_backup_agent("s2");
    backup_impl(
      &state,
      "r1",
      Some(&OneTimeSecret(login_password)),
      (None, None),
      Arc::new(|_| {}),
      &CancellationToken::new(),
      false,
    )
    .await
    .unwrap();
    assert_eq!(
      *seen.lock().unwrap(),
      ["backup", "list", "add", "remove", "prune"]
    );
    let _ = unlock(
      State(state.clone()),
      crate::security_receipt::tests::auth(true),
      None,
    )
    .await
    .map_err(|e| e.0)
    .unwrap();
    assert_eq!(seen.lock().unwrap().last(), Some(&"unlock"));
    require_recovery_ready(&state).await.unwrap();
  }

  #[test]
  fn core_backup_compose_uses_shared_repo_without_append_only() {
    let compose = render::core_backup_server_compose(
      "100.64.0.2",
      "wharf-core:$2b$12$hash-a\noperator:$2b$12$hash-b\n",
    );
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&compose).unwrap();
    assert_eq!(
      yaml["name"].as_str(),
      Some(render::CORE_BACKUP_PROJECT)
    );
    let service = &yaml["services"]["rest-server"];
    let cmd = service["command"].as_sequence().unwrap();
    assert!(
      cmd
        .iter()
        .any(|arg| arg.as_str() == Some("100.64.0.2:7711"))
    );
    assert!(!cmd.iter().any(|arg| matches!(
      arg.as_str(),
      Some("--private-repos" | "--append-only")
    )));
    let volumes = service["volumes"].as_sequence().unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(
      volumes[0].as_str(),
      Some("/srv/wharf-backup-core:/data")
    );
    let restore = restore_command("100.64.0.2", "operator");
    assert!(restore.contains("RESTIC_REST_USERNAME=operator"));
    assert!(restore.contains("7711/wharf-core restore"));
    assert!(!restore.contains("--no-lock"));
  }

  #[tokio::test]
  async fn core_backup_enable_rejects_reserved_admin_name() {
    use crate::{
      backup::tests::seed_servers, rules::tests::test_state,
      security_receipt::tests::auth,
    };

    let mut state = test_state();
    Arc::get_mut(&mut state).unwrap().data_dir =
      Path::new(CORE_BACKUP_DIR).parent().unwrap().into();
    seed_servers(&state).await;
    state
      .db
      .call(|c| login::set_admin(c, HTTP_USER, "h1"))
      .await
      .unwrap();
    let err = enable(
      State(state),
      auth(true),
      ConnectInfo("203.0.113.3:12345".parse().unwrap()),
      HeaderMap::new(),
      Extension(AuditSlot::default()),
      Json(EnableRequest {
        to: "s2".into(),
        password: backup::random_hex(),
      }),
    )
    .await
    .err()
    .unwrap()
    .0;
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("管理员账号"));
  }

  #[tokio::test]
  async fn legacy_core_user_key_settings_survive_without_becoming_current()
   {
    use crate::{
      backup::tests::seed_servers, rules::tests::test_state,
      security_receipt::tests::auth,
    };
    let state = test_state();
    seed_servers(&state).await;
    state
      .db
      .call(|c| {
        login::set_admin(c, "operator", "h1")?;
        db::set_setting(c, TO, Some("s2"))?;
        db::set_setting(c, USER_KEY, Some("k1"))?;
        db::set_setting(c, KEY_FOR, Some("h1"))
      })
      .await
      .unwrap();
    for initialized in [false, true] {
      if initialized {
        state
          .db
          .call(|c| {
            db::set_setting(c, REPO_SETTING, Some(REPO_VERSION))
          })
          .await
          .unwrap();
      }
      let view = show(State(state.clone()), auth(true))
        .await
        .map_err(|e| e.0)
        .unwrap()
        .0;
      assert_eq!(view.to.as_deref(), Some("s2"));
      assert!(!view.user_key_current);
      state
        .db
        .call(|c| {
          assert_eq!(
            db::setting(c, USER_KEY)?.as_deref(),
            Some("k1")
          );
          assert_eq!(db::setting(c, KEY_FOR)?.as_deref(), Some("h1"));
          Ok(())
        })
        .await
        .unwrap();
    }
  }
}
