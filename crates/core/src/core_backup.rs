//! 控制面自身备份（design 2.11）：数据库、控制面密钥、管理员 token，
//! 每天用 restic 推到另一台服务器的 rest-server（和服务备份同一个）。
//!
//! - 数据库用 `VACUUM INTO` 做一致的快照，和密钥一起放到 [CORE_BACKUP_DIR]，
//!   同机的 agent 备份这个目录（目录里的标记确认是哪台机器）；
//! - 仓库有两把口令：控制面保存的备份口令（定时备份用），和管理员的登录密码
//!   （开启时输入，控制面只存它的哈希，拿不到明文）。控制面整个丢了，
//!   用登录密码就能从备份服务器恢复；
//! - 备份服务器的 htpasswd 也加上管理员账号（bcrypt），恢复时用登录密码访问。

use std::{path::Path, sync::Arc};

use axum::{Json, extract::State};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BackupSummary, CORE_BACKUP_DIR, OneTimeSecret,
    REST_SERVER_PORT, ResticAction, ResticRepo,
  },
  plan::ApplyResponse,
  view::{BackupRecord, TokenScope},
};

use crate::{
  api::ApiResult,
  apply,
  auth::Auth,
  backup::{self, Where},
  db::{self, now_ms, sql_err},
  hub::ProgressFn,
  planner::Step,
  snapshot,
  state::AppState,
};

/// 备份服务器 htpasswd 里管理员那一行：`用户名:bcrypt(登录密码)`。
pub const OWNER_SECRET: &str = "WHARF_CORE_BACKUP_OWNER";
/// 仓库名，也是备份记录里的服务名。
pub const REPO: &str = "wharf-core";
const TO: &str = "core_backup.to";
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
  pub records: Vec<BackupRecord>,
  /// 控制面整个丢了时，在新机器上执行的恢复命令。
  #[serde(skip_serializing_if = "Option::is_none")]
  pub restore_command: Option<String>,
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
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let records = crate::backup::records(&s, REPO, 10).await?;
  let (to, key_for, admin) = s
    .db
    .call(|c| {
      let admin: Option<(String, String)> = c
        .query_row(
          "SELECT username, password_hash FROM admin WHERE id = 1",
          [],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
      Ok((db::setting(c, TO)?, db::setting(c, KEY_FOR)?, admin))
    })
    .await?;
  let restore_command = to.as_ref().and_then(|to| {
    let ip = snap.net(&snap.world).private.get(to)?.ip.clone();
    let user = admin.as_ref().map(|a| a.0.clone())?;
    Some(restore_command(&ip, &user))
  });
  Ok(Json(CoreBackupView {
    user_key_current: key_for.is_some()
      && key_for == admin.map(|a| a.1),
    to,
    records,
    restore_command,
  }))
}

/// `POST /api/core-backup`：开启（或换备份服务器、改过密码后重新输入），并立刻备份一次。
pub async fn enable(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<EnableRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplyAll)?;
  check_data_dir(&s)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&req.to) {
    return Err(crate::world::server_not_found(&req.to).into());
  }
  if !snap.net(&snap.world).private.contains_key(&req.to) {
    return Err(
      ApiError::invalid(format!("{} 没有内网地址，不能做备份服务器", req.to))
        .into(),
    );
  }
  let (username, hash): (String, String) = s
    .db
    .call(|c| {
      c.query_row(
        "SELECT username, password_hash FROM admin WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
      )
      .map_err(sql_err)
    })
    .await?;
  // 备份服务器上 wharf 这个账号已经给控制面用了。
  if username == "wharf" {
    return Err(
      ApiError::invalid("管理员账号叫 wharf，和备份服务器的内部账号重名，先改个名")
        .into(),
    );
  }
  if !crate::login::verify_password(&req.password, &hash) {
    return Err(
      ApiError::new(ErrorCode::Unauthorized, "登录密码不对").into(),
    );
  }
  let owner = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
    .map_err(|e| ApiError::internal(format!("计算哈希失败：{e}")))?;
  let owner = format!("{username}:{owner}");
  let to = req.to.clone();
  s.db
    .call(move |c| {
      db::set_setting(c, TO, Some(&to))?;
      c.execute(
        "INSERT INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![OWNER_SECRET, owner, now_ms()],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  Ok(Json(
    apply::start_task(
      s.clone(),
      "备份控制面".into(),
      Step::CoreBackup {
        user_key: Some(OneTimeSecret(req.password)),
      },
    )
    .await?,
  ))
}

/// `POST /api/core-backup/recovery-key`：后备的恢复密钥（备份口令和备份服务器账号）。
/// 登录密码忘了也能恢复；服务备份也用同一个口令。要重新输入登录密码。
pub async fn recovery_key(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<PasswordRequest>,
) -> ApiResult<RecoveryKey> {
  auth.require(TokenScope::ApplyAll)?;
  let hash: String = s
    .db
    .call(|c| {
      c.query_row("SELECT password_hash FROM admin WHERE id = 1", [], |r| {
        r.get(0)
      })
      .map_err(sql_err)
    })
    .await?;
  if !crate::login::verify_password(&req.password, &hash) {
    return Err(
      ApiError::new(ErrorCode::Unauthorized, "登录密码不对").into(),
    );
  }
  let snap = snapshot::load(&s.db).await?;
  let to = s.db.call(|c| db::setting(c, TO)).await?;
  let net = snap.net(&snap.world);
  let target = to
    .as_ref()
    .and_then(|t| net.private.get(t))
    .map(|a| format!("{}:{REST_SERVER_PORT}", a.ip));
  let creds = backup::credentials(&s).await?;
  tracing::info!("已下载恢复密钥");
  let image = wharf_api_types::agent::RESTIC_IMAGE;
  let user = backup::HTTP_USER;
  let mut text = format!(
    "# Wharf 恢复密钥：能打开所有备份，收好，别放在被备份的机器上。\n\
RESTIC_PASSWORD={key}\n\
RESTIC_REST_USERNAME={user}\n\
RESTIC_REST_PASSWORD={http}\n",
    key = creds.key,
    http = creds.http,
  );
  if let Some(target) = target {
    text.push_str(&format!(
      "\n# 控制面备份在 {to}（{target}）的仓库 {REPO}；服务备份的仓库名是服务名。\n\
# 恢复控制面（新机器先加入同一个内网，把本文件存成 wharf-recovery.env）：\n\
docker run --rm --network host --env-file wharf-recovery.env -v /var/lib/wharf-core:/restore \\\n  \
{image} -r rest:http://{target}/{REPO} restore latest:{CORE_BACKUP_DIR} --target /restore\n",
      to = to.unwrap_or_default(),
    ));
  }
  Ok(Json(RecoveryKey {
    filename: "wharf-recovery.env".into(),
    text,
  }))
}

/// `POST /api/core-backup/run`
pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplySafe)?;
  Ok(Json(
    apply::start_task(
      s.clone(),
      "备份控制面".into(),
      Step::CoreBackup { user_key: None },
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
      expected.map(|p| p.display().to_string()).unwrap_or_default()
    )));
  }
  Ok(())
}

pub fn enabled(c: &rusqlite::Connection) -> Result<bool, ApiError> {
  Ok(db::setting(c, TO)?.is_some())
}

pub async fn backup(
  state: &AppState,
  run_id: &str,
  user_key: Option<&OneTimeSecret>,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  check_data_dir(state)?;
  let to = state
    .db
    .call(|c| db::setting(c, TO))
    .await?
    .ok_or_else(|| {
      ApiError::invalid("还没有开启控制面备份")
        .suggest("wharf backup core --to <server>")
    })?;
  let snap = snapshot::load(&state.db).await?;
  let target_ip = snap
    .net(&snap.world)
    .private
    .get(&to)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::invalid(format!("备份服务器 {to} 没有内网地址"))
    })?;
  let creds = backup::credentials(state).await?;
  let mut w = Where {
    server: String::new(),
    target: to.clone(),
    target_ip,
  };
  backup::ensure_server(state, &snap, &w, &creds, &progress, cancel)
    .await?;
  let marker = stage(state).await?;
  progress("已生成数据库快照".into());

  // 不知道控制面在哪台机器上：问每台在线的 agent，目录里的标记对得上的就是。
  let mut result: Result<BackupSummary, ApiError> = Err(ApiError::new(
    ErrorCode::NotFound,
    format!("找不到控制面所在的机器（控制面不能和备份服务器 {to} 是同一台）"),
  ));
  for server in snap.world.servers.keys() {
    if *server == to || !state.hub.is_online(server) {
      continue;
    }
    let job = core_job(&snap, server, &w, &creds, &marker, ResticAction::Backup {
      host: server.clone(),
    });
    match state
      .hub
      .call(server, job, backup::RESTIC_TIMEOUT, Some(progress.clone()), cancel)
      .await
    {
      Err(e) if e.code == ErrorCode::NotFound => continue,
      r => {
        w.server = server.clone();
        result = r;
        break;
      }
    }
  }
  let _ = std::fs::remove_dir_all(CORE_BACKUP_DIR);
  backup::record(state, run_id, REPO, &w, &result).await?;
  result?;

  if let Some(password) = user_key {
    add_user_key(state, &snap, &w, &creds, password, &progress, cancel)
      .await?;
  }
  // 清理旧快照失败不影响这次备份的结果。
  let pruned = state
    .hub
    .call::<serde_json::Value>(
      &w.target,
      local_job(&snap, &w.target, &creds, ResticAction::Prune),
      backup::RESTIC_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await;
  if let Err(e) = pruned {
    progress(format!("提醒：清理旧快照失败：{}", e.message));
  }
  Ok(())
}

/// 加上登录密码这把钥匙，删掉之前的那把。在控制面所在的机器上经 rest-server 加。
async fn add_user_key(
  state: &AppState,
  snap: &snapshot::Snapshot,
  w: &Where,
  creds: &backup::Creds,
  password: &OneTimeSecret,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let job = backup::job(
    snap,
    &w.server,
    REPO,
    backup::rest_repo(w, creds),
    creds,
    ResticAction::AddKey {
      new_password: password.clone(),
    },
  );
  let id: String = state
    .hub
    .call(&w.server, job, backup::RESTIC_TIMEOUT, Some(progress.clone()), cancel)
    .await?;
  let old = state.db.call(|c| db::setting(c, USER_KEY)).await?;
  if let Some(old) = old.filter(|o| *o != id) {
    let removed = state
      .hub
      .call::<serde_json::Value>(
        &w.target,
        local_job(snap, &w.target, creds, ResticAction::RemoveKey { id: old }),
        backup::RESTIC_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await;
    if let Err(e) = removed {
      progress(format!("提醒：删除旧口令失败：{}", e.message));
    }
  }
  state
    .db
    .call(move |c| {
      let hash: String = c
        .query_row("SELECT password_hash FROM admin WHERE id = 1", [], |r| {
          r.get(0)
        })
        .map_err(sql_err)?;
      db::set_setting(c, USER_KEY, Some(&id))?;
      db::set_setting(c, KEY_FOR, Some(&hash))
    })
    .await?;
  progress("已把登录密码设为恢复口令".into());
  Ok(())
}

fn core_job(
  snap: &snapshot::Snapshot,
  server: &str,
  w: &Where,
  creds: &backup::Creds,
  marker: &str,
  action: ResticAction,
) -> AgentOp {
  let mut job =
    backup::job(snap, server, REPO, backup::rest_repo(w, creds), creds, action);
  if let AgentOp::Restic(j) = &mut job {
    j.core_marker = Some(marker.to_string());
  }
  job
}

fn local_job(
  snap: &snapshot::Snapshot,
  target: &str,
  creds: &backup::Creds,
  action: ResticAction,
) -> AgentOp {
  backup::job(snap, target, REPO, ResticRepo::Local, creds, action)
}

/// 把数据库快照、控制面密钥、管理员 token 放进 [CORE_BACKUP_DIR]，返回标记。
async fn stage(state: &AppState) -> Result<String, ApiError> {
  let dir = Path::new(CORE_BACKUP_DIR);
  let _ = std::fs::remove_dir_all(dir);
  std::fs::create_dir_all(dir).map_err(|e| {
    ApiError::internal(format!("创建 {}：{e}", dir.display()))
  })?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
  }
  let db_copy = dir.join("wharf.db").display().to_string();
  state
    .db
    .call(move |c| {
      c.execute("VACUUM INTO ?1", params![db_copy]).map_err(sql_err)?;
      Ok(())
    })
    .await?;
  for name in ["core.key", "admin.token"] {
    let from = state.data_dir.join(name);
    if from.exists() {
      std::fs::copy(&from, dir.join(name)).map_err(|e| {
        ApiError::internal(format!("复制 {}：{e}", from.display()))
      })?;
    }
  }
  let marker = backup::random_hex();
  std::fs::write(dir.join(".marker"), &marker)
    .map_err(|e| ApiError::internal(format!("写标记：{e}")))?;
  Ok(marker)
}

/// 新机器上恢复：先让它加入同一个内网，再执行这条命令，按提示输入两次登录密码。
fn restore_command(ip: &str, user: &str) -> String {
  let image = wharf_api_types::agent::RESTIC_IMAGE;
  format!(
    "read -rsp '登录密码：' P && echo && docker run --rm --network host -v /var/lib/wharf-core:/restore \
-e RESTIC_REST_USERNAME={user} -e RESTIC_REST_PASSWORD=\"$P\" -e RESTIC_PASSWORD=\"$P\" \
{image} -r rest:http://{ip}:{REST_SERVER_PORT}/{REPO} restore latest:{CORE_BACKUP_DIR} --target /restore"
  )
}

/// 定时备份用：上次成功是什么时候。
pub fn last_ok(c: &rusqlite::Connection) -> Result<Option<i64>, ApiError> {
  c.query_row(
    "SELECT MAX(created_at) FROM backups WHERE service = ?1 AND ok",
    params![REPO],
    |r| r.get(0),
  )
  .map_err(sql_err)
}
