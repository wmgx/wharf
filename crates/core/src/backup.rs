//! 备份和恢复：服务的 `/srv/<service>/` 用 restic 备份到另一台服务器。
//!
//! - 备份服务器上跑 rest-server（只听内网地址、要账号、只能追加），
//!   第一次备份时自动部署，之后配置不变就不动它；
//! - 流程是"停止、备份、启动"（参考 offen/docker-volume-backup），数据库类服务也能得到一致的快照；
//!   备份失败也会把服务启动回来；
//! - 旧快照在备份服务器本机清理：保留最近 7 天、4 周、6 个月各一份；
//! - 仓库口令和 rest-server 账号由控制面生成，存在密钥里，不经过对话、不打印。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::params;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BackupSummary, OneTimeSecret, ProjectUp,
    ProjectUpResult, REST_SERVER_PORT, ResticAction, ResticJob,
    ResticRepo, Snapshot,
  },
  plan::ApplyResponse,
  view::{BackupRecord, BackupsView, RestoreRequest, TokenScope},
};

use crate::{
  api::{ApiResult, service_not_found},
  apply,
  auth::Auth,
  db::{json_err, now_ms, sql_err, to_time},
  hub::ProgressFn,
  planner::Step,
  render::{self, BACKUP_PROJECT},
  snapshot::{self, Snapshot as Snap},
  state::AppState,
};

const KEY_SECRET: &str = "WHARF_BACKUP_KEY";
const HTTP_SECRET: &str = "WHARF_BACKUP_HTTP";
const HTTP_HASH_SECRET: &str = "WHARF_BACKUP_HTTP_HASH";
const HTTP_USER: &str = "wharf";

const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RESTIC_TIMEOUT: Duration = Duration::from_secs(6 * 3600);
const SERVER_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const LIST_TIMEOUT: Duration = Duration::from_secs(3 * 60);

struct Creds {
  key: String,
  http: String,
  http_hash: String,
}

pub(crate) fn random_hex() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

/// 取备份口令，没有就生成。已有的不覆盖（INSERT OR IGNORE），并发时也只有一份。
async fn credentials(state: &AppState) -> Result<Creds, ApiError> {
  let key = random_hex();
  let http = random_hex();
  let http_hash = bcrypt::hash(&http, bcrypt::DEFAULT_COST)
    .map_err(|e| ApiError::internal(format!("计算哈希失败：{e}")))?;
  state
    .db
    .call(move |c| {
      let now = now_ms();
      for (name, value) in [
        (KEY_SECRET, key),
        (HTTP_SECRET, http),
        (HTTP_HASH_SECRET, http_hash),
      ] {
        c.execute(
          "INSERT OR IGNORE INTO secrets (name, value, updated_at) VALUES (?1, ?2, ?3)",
          params![name, value, now],
        )
        .map_err(sql_err)?;
      }
      let secrets = crate::db::secrets(c)?;
      let get = |n: &str| secrets.get(n).cloned().unwrap_or_default();
      Ok(Creds {
        key: get(KEY_SECRET),
        http: get(HTTP_SECRET),
        http_hash: get(HTTP_HASH_SECRET),
      })
    })
    .await
}

/// 一次备份或恢复要用到的位置信息。
struct Where {
  /// 数据所在的服务器（最近一次部署的位置）。
  server: String,
  /// 备份服务器。
  target: String,
  target_ip: String,
}

fn locate(snap: &Snap, service: &str) -> Result<Where, ApiError> {
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| service_not_found(service))?;
  let target =
    row.spec.backup.as_ref().map(|b| b.to.clone()).ok_or_else(
      || {
        ApiError::invalid(format!("服务 {service} 没有开启备份"))
          .suggest(format!(
            "wharf backup enable {service} --to <server>"
          ))
      },
    )?;
  let server = snap
    .deployed
    .get(service)
    .cloned()
    .unwrap_or_else(|| row.spec.server.clone());
  if server == target {
    return Err(ApiError::invalid(format!(
      "服务 {service} 现在就在备份服务器 {target} 上，换一台备份服务器"
    )));
  }
  let net = snap.net(&snap.world);
  let target_ip =
    net.private.get(&target).map(|a| a.ip.clone()).ok_or_else(
      || {
        ApiError::invalid(format!("备份服务器 {target} 没有内网地址"))
          .suggest(format!(
            "wharf server set {target} --private-ip <ip>"
          ))
      },
    )?;
  Ok(Where {
    server,
    target,
    target_ip,
  })
}

fn job(
  snap: &Snap,
  server: &str,
  service: &str,
  repo: ResticRepo,
  creds: &Creds,
  action: ResticAction,
) -> AgentOp {
  AgentOp::Restic(ResticJob {
    service: service.to_string(),
    repo,
    password: OneTimeSecret(creds.key.clone()),
    action,
    pull: snap
      .world
      .servers
      .get(server)
      .map(snapshot::pull_policy)
      .unwrap_or(wharf_api_types::agent::PullPolicy {
        mirrors: Default::default(),
        mirrors_only: false,
        attempt_timeout_secs: snapshot::PULL_ATTEMPT_SECS,
      }),
  })
}

fn rest_repo(w: &Where, creds: &Creds) -> ResticRepo {
  ResticRepo::Rest {
    host: w.target_ip.clone(),
    port: REST_SERVER_PORT,
    user: HTTP_USER.to_string(),
    password: OneTimeSecret(creds.http.clone()),
  }
}

/// 备份服务器上的 rest-server 配置没变且在运行时什么也不做。
async fn ensure_server(
  state: &AppState,
  snap: &Snap,
  w: &Where,
  creds: &Creds,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let compose = render::backup_server_compose(
    &w.target_ip,
    &format!("{HTTP_USER}:{}", creds.http_hash),
  );
  let hash = render::hash(&compose);
  let states = snapshot::project_status(
    &state.hub,
    &w.target,
    vec![BACKUP_PROJECT.to_string()],
    LIST_TIMEOUT,
  )
  .await?;
  if states.get(BACKUP_PROJECT).is_some_and(|s| {
    s.hash.as_deref() == Some(hash.as_str()) && s.all_running()
  }) {
    return Ok(());
  }
  progress(format!("在 {} 上部署备份服务（rest-server）", w.target));
  let result: ProjectUpResult = state
    .hub
    .call(
      &w.target,
      AgentOp::ProjectUp(ProjectUp {
        project: BACKUP_PROJECT.to_string(),
        compose,
        hash,
        pull: snapshot::pull_policy(&snap.world.servers[&w.target]),
        pull_missing_only: false,
        retire: None,
        rollback: false,
      }),
      SERVER_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if result.containers.iter().any(|c| c.state != "running") {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{} 上的备份服务没有运行起来", w.target),
    ));
  }
  // rest-server 刚起来时端口可能还没开始监听。
  tokio::time::sleep(Duration::from_secs(2)).await;
  Ok(())
}

/// 停止服务；返回是否真的停了（没部署过就不用停，也不用再启动）。
async fn stop(
  state: &AppState,
  w: &Where,
  service: &str,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<bool, ApiError> {
  progress(format!("停止 {} 上的 {service}", w.server));
  state
    .hub
    .call(
      &w.server,
      AgentOp::ProjectStop {
        project: service.to_string(),
      },
      STOP_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await
}

/// 无论成功、失败还是取消都要启动回来，所以用新的令牌。
async fn start(
  state: &AppState,
  w: &Where,
  service: &str,
  progress: &ProgressFn,
) -> Result<(), ApiError> {
  progress(format!("启动 {} 上的 {service}", w.server));
  state
    .hub
    .call::<bool>(
      &w.server,
      AgentOp::ProjectStart {
        project: service.to_string(),
      },
      STOP_TIMEOUT,
      Some(progress.clone()),
      &CancellationToken::new(),
    )
    .await
    .map(|_| ())
    .map_err(|e| {
      e.with_hint(format!(
        "服务没能启动，手动处理：wharf service deploy {service}"
      ))
    })
}

pub async fn backup(
  state: &AppState,
  run_id: &str,
  service: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let w = locate(&snap, service)?;
  crate::link::require_reach(
    state,
    &snap.net(&snap.world),
    &w.server,
    &w.target,
    "备份到这台机器",
  )
  .await?;
  let creds = credentials(state).await?;
  let result = async {
    ensure_server(state, &snap, &w, &creds, &progress, cancel)
      .await?;
    let stopped = stop(state, &w, service, &progress, cancel).await?;
    let backed: Result<BackupSummary, ApiError> = state
      .hub
      .call(
        &w.server,
        job(
          &snap,
          &w.server,
          service,
          rest_repo(&w, &creds),
          &creds,
          ResticAction::Backup {
            host: w.server.clone(),
          },
        ),
        RESTIC_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await;
    let started = if stopped {
      start(state, &w, service, &progress).await
    } else {
      Ok(())
    };
    let summary = backed?;
    started?;
    Ok(summary)
  }
  .await;
  record(state, run_id, service, &w, &result).await?;
  result?;

  // 清理旧快照失败不影响这次备份的结果。
  let pruned = state
    .hub
    .call::<serde_json::Value>(
      &w.target,
      job(
        &snap,
        &w.target,
        service,
        ResticRepo::Local,
        &creds,
        ResticAction::Prune,
      ),
      RESTIC_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await;
  if let Err(e) = pruned {
    progress(format!("提醒：清理旧快照失败：{}", e.message));
  }
  Ok(())
}

pub async fn restore(
  state: &AppState,
  service: &str,
  snapshot_id: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let w = locate(&snap, service)?;
  crate::link::require_reach(
    state,
    &snap.net(&snap.world),
    &w.server,
    &w.target,
    "备份到这台机器",
  )
  .await?;
  let creds = credentials(state).await?;
  ensure_server(state, &snap, &w, &creds, &progress, cancel).await?;
  let stopped = stop(state, &w, service, &progress, cancel).await?;
  let restored = state
    .hub
    .call::<serde_json::Value>(
      &w.server,
      job(
        &snap,
        &w.server,
        service,
        rest_repo(&w, &creds),
        &creds,
        ResticAction::Restore {
          snapshot: snapshot_id.to_string(),
        },
      ),
      RESTIC_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await;
  let started = if stopped {
    start(state, &w, service, &progress).await
  } else {
    Ok(())
  };
  restored?;
  started
}

async fn record(
  state: &AppState,
  run_id: &str,
  service: &str,
  w: &Where,
  result: &Result<BackupSummary, ApiError>,
) -> Result<(), ApiError> {
  let (ok, body) = match result {
    Ok(s) => (true, serde_json::to_string(s).map_err(json_err)?),
    Err(e) => {
      (false, serde_json::to_string(&e.message).map_err(json_err)?)
    }
  };
  let values = (
    service.to_string(),
    w.server.clone(),
    w.target.clone(),
    run_id.to_string(),
  );
  state
    .db
    .call(move |c| {
      let (service, server, target, run_id) = values;
      c.execute(
        "INSERT INTO backups (service, server, target, run_id, ok, body, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![service, server, target, run_id, ok, body, now_ms()],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await
}

pub async fn records(
  state: &AppState,
  service: &str,
  limit: u32,
) -> Result<Vec<BackupRecord>, ApiError> {
  let service = service.to_string();
  let rows: Vec<(i64, String, String, String, bool, String, i64)> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare(
          "SELECT id, server, target, run_id, ok, body, created_at FROM backups
           WHERE service = ?1 ORDER BY id DESC LIMIT ?2",
        )
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![service, limit], |r| {
          Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
          ))
        })
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  Ok(
    rows
      .into_iter()
      .map(|(id, server, target, run_id, ok, body, at)| {
        BackupRecord {
          id,
          server,
          target,
          run_id,
          ok,
          summary: ok
            .then(|| serde_json::from_str(&body).ok())
            .flatten(),
          error: (!ok)
            .then(|| serde_json::from_str(&body).unwrap_or(body)),
          created_at: to_time(at),
        }
      })
      .collect(),
  )
}

// ---- 接口 ----

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<BackupsView> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  let target = row.spec.backup.as_ref().map(|b| b.to.clone());
  let records = records(&s, &name, 20).await?;
  // 快照在备份服务器本机读，服务所在的机器离线也能看到。
  let mut snapshots = vec![];
  let mut snapshots_error = None;
  if let Some(target) =
    target.as_ref().or(records.first().map(|r| &r.target))
  {
    let creds = credentials(&s).await?;
    let listed = s
      .hub
      .call::<Vec<Snapshot>>(
        target,
        job(
          &snap,
          target,
          &name,
          ResticRepo::Local,
          &creds,
          ResticAction::Snapshots,
        ),
        LIST_TIMEOUT,
        None,
        &CancellationToken::new(),
      )
      .await;
    match listed {
      Ok(list) => snapshots = list,
      Err(e) => snapshots_error = Some(e.message),
    }
  }
  Ok(Json(BackupsView {
    service: name,
    target,
    records,
    snapshots,
    snapshots_error,
  }))
}

pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplySafe)?;
  let snap = snapshot::load(&s.db).await?;
  locate(&snap, &name)?;
  Ok(Json(
    apply::start_task(
      s.clone(),
      format!("备份 {name}"),
      Step::Backup { service: name },
    )
    .await?,
  ))
}

pub async fn restore_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<RestoreRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(TokenScope::ApplyAll)?;
  let address = format!("service/{name}");
  if req.confirm != address {
    return Err(
      ApiError::new(
        ErrorCode::ConfirmRequired,
        format!("恢复会覆盖 {name} 现在的数据，需要确认 {address}"),
      )
      .with_hint("原来的数据会改名保留在 /srv/.wharf-restore/ 下")
      .suggest(format!(
        "wharf backup restore {name} --snapshot {} --confirm {address}",
        req.snapshot
      ))
      .into(),
    );
  }
  let snap = snapshot::load(&s.db).await?;
  locate(&snap, &name)?;
  Ok(Json(
    apply::start_task(
      s.clone(),
      format!("恢复 {name} 到快照 {}", req.snapshot),
      Step::Restore {
        service: name,
        snapshot: req.snapshot,
      },
    )
    .await?,
  ))
}
