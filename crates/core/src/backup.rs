//! 备份和恢复：服务的 `/srv/<service>/` 用 restic 备份到另一台服务器。
//!
//! - 备份服务器上跑 rest-server（只听内网地址、要账号、只能追加），
//!   第一次备份时自动部署，之后配置不变就不动它；
//! - 流程是"停止、备份、启动"（参考 offen/docker-volume-backup），数据库类服务也能得到一致的快照；
//!   备份失败也会把服务启动回来；
//! - 旧快照在备份服务器本机清理：保留最近 7 天、4 周、6 个月各一份；
//! - 仓库口令和 rest-server 账号由控制面生成，存在密钥里，不经过对话、不打印。

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BackupSummary, OneTimeSecret, ProjectUp,
    ProjectUpResult, REST_SERVER_PORT, ResticAction, ResticJob,
    ResticKeyInfo, ResticPreflight, ResticPreflightMode,
    ResticPreflightResult, ResticRepo, Snapshot, StoppedContainers,
  },
  plan::ApplyResponse,
  view::{BackupRecord, BackupsView, Perm, RestoreRequest},
};

use crate::{
  api::{ApiResult, service_not_found},
  apply,
  auth::Auth,
  db::{self, json_err, now_ms, sql_err, to_time},
  hub::ProgressFn,
  planner::Step,
  render::{self, BACKUP_PROJECT},
  snapshot::{self, Snapshot as Snap},
  state::AppState,
};

const LEGACY_KEY_SECRET: &str = "WHARF_BACKUP_KEY";
const LEGACY_HTTP_SECRET: &str = "WHARF_BACKUP_HTTP";
const LEGACY_HTTP_HASH_SECRET: &str = "WHARF_BACKUP_HTTP_HASH";
pub const SECRET_PREFIX: &str = "WHARF_BACKUP_";
const KEY_PREFIX: &str = "WHARF_BACKUP_KEY_";
pub const HTTP_PREFIX: &str = "WHARF_BACKUP_HTTP_";
pub const HTTP_HASH_PREFIX: &str = "WHARF_BACKUP_HTTP_HASH_";

const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const RESTIC_TIMEOUT: Duration =
  Duration::from_secs(6 * 3600);
const SERVER_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const LIST_TIMEOUT: Duration = Duration::from_secs(3 * 60);

struct ServiceCreds {
  key: String,
  http: String,
}

pub(crate) fn random_hex() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

async fn ensure_service_creds(
  state: &AppState,
  service: &str,
) -> Result<ServiceCreds, ApiError> {
  let (http, _) = service_http_pair(state, service).await?;
  let service = service.to_string();
  let key = state
    .db
    .call_credentials(move |c, master| {
      db::ensure_scoped_secret(
        c,
        master,
        KEY_PREFIX,
        &service,
        now_ms(),
      )
    })
    .await?;
  Ok(ServiceCreds { key, http })
}

async fn service_http_pair(
  state: &AppState,
  service: &str,
) -> Result<(String, String), ApiError> {
  ensure_http_pair(
    state,
    db::scoped_secret_name(HTTP_PREFIX, service)?,
    db::scoped_secret_name(HTTP_HASH_PREFIX, service)?,
  )
  .await
}

pub(crate) async fn ensure_http_pair(
  state: &AppState,
  http_name: String,
  hash_name: String,
) -> Result<(String, String), ApiError> {
  loop {
    let (http, hash) = {
      let (http_name, hash_name) =
        (http_name.clone(), hash_name.clone());
      state
        .db
        .call_credentials(move |c, key| {
          Ok((key.secret(c, &http_name)?, key.secret(c, &hash_name)?))
        })
        .await?
    };
    if let (Some(http), Some(hash)) = (&http, hash) {
      return Ok((http.clone(), hash));
    }
    let candidate = http.clone().unwrap_or_else(random_hex);
    let hash = {
      let candidate = candidate.clone();
      tokio::task::spawn_blocking(move || {
        bcrypt::hash(candidate, bcrypt::DEFAULT_COST)
      })
      .await
      .map_err(|_| ApiError::internal("计算哈希失败"))?
      .map_err(|e| ApiError::internal(format!("计算哈希失败：{e}")))?
    };
    let (http_name, hash_name) =
      (http_name.clone(), hash_name.clone());
    let pair = state
      .db
      .call_credentials(move |c, key| {
        let tx = c.transaction().map_err(sql_err)?;
        if key.secret(&tx, &http_name)? != http {
          return Ok(None);
        }
        if http.is_some()
          && let Some(existing) = key.secret(&tx, &hash_name)?
        {
          return Ok(Some((candidate, existing)));
        }
        let now = now_ms();
        key.put_secret(&tx, &http_name, &candidate, now, false)?;
        key.put_secret(&tx, &hash_name, &hash, now, true)?;
        tx.commit().map_err(sql_err)?;
        Ok(Some((candidate, hash)))
      })
      .await?;
    if let Some(pair) = pair {
      return Ok(pair);
    }
  }
}

/// 一次备份或恢复要用到的位置信息。
pub(crate) struct Where {
  /// 数据所在的服务器（最近一次部署的位置）。
  pub(crate) server: String,
  /// 备份服务器。
  pub(crate) target: String,
  pub(crate) target_ip: String,
}

fn service_target(
  snap: &Snap,
  service: &str,
) -> Result<String, ApiError> {
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| service_not_found(service))?;
  row
    .spec
    .backup
    .as_ref()
    .map(|b| b.to.clone())
    .ok_or_else(|| {
      ApiError::invalid(format!("服务 {service} 没有开启备份"))
        .suggest(format!(
          "wharf backup enable {service} --to <server>"
        ))
    })
}

async fn resolve_target(
  state: &AppState,
  snap: &Snap,
  service: &str,
  explicit: Option<&str>,
) -> Result<Option<String>, ApiError> {
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| service_not_found(service))?;
  if let Some(target) = explicit {
    if !snap.world.servers.contains_key(target) {
      return Err(crate::world::server_not_found(target));
    }
    return Ok(Some(target.to_string()));
  }
  if let Some(b) = &row.spec.backup {
    return Ok(Some(b.to.clone()));
  }
  let service = service.to_string();
  state.db.call(move |c| {
    c.query_row(
      "SELECT target FROM backups WHERE service = ?1 ORDER BY ok DESC, id DESC LIMIT 1",
      [service], |r| r.get(0),
    ).optional().map_err(sql_err)
  }).await
}

fn missing_target(service: &str) -> ApiError {
  ApiError::invalid(format!(
    "服务 {service} 没有开启备份，也没有历史备份记录"
  ))
  .with_hint("若快照在其他备份服务器上，可传 --from <server> 指定")
}

fn location(snap: &Snap, service: &str, target: String) -> Where {
  let server = snapshot::service_runtime_server(snap, service)
    .unwrap_or(&snap.world.services[service].spec.server)
    .to_string();
  let target_ip = snap
    .net(&snap.world)
    .private
    .get(&target)
    .map(|a| a.ip.clone())
    .unwrap_or_default();
  Where {
    server,
    target,
    target_ip,
  }
}

async fn check_location(
  state: &AppState,
  snap: &Snap,
  w: &Where,
  service: &str,
) -> Result<(), ApiError> {
  if w.server == w.target {
    return Err(ApiError::invalid(format!(
      "服务 {service} 现在就在备份服务器 {} 上，换一台备份服务器",
      w.target
    )));
  }
  if w.target_ip.is_empty() {
    return Err(
      ApiError::invalid(format!(
        "备份服务器 {} 没有内网地址",
        w.target
      ))
      .suggest(format!(
        "wharf server set {} --private-ip <ip>",
        w.target
      )),
    );
  }
  require_safe_backup(state, &w.server)?;
  require_safe_backup(state, &w.target)?;
  crate::link::require_reach(
    state,
    &snap.net(&snap.world),
    &w.server,
    &w.target,
    "连接备份服务器",
    crate::link::ProbeMode::Persist,
  )
  .await
}

pub(crate) fn job(
  snap: &Snap,
  server: &str,
  service: &str,
  repo: ResticRepo,
  key: &str,
  action: ResticAction,
) -> AgentOp {
  AgentOp::Restic(ResticJob {
    service: service.to_string(),
    repo,
    password: OneTimeSecret(key.to_string()),
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
        git_proxy: None,
        github_mirror: None,
        registry_proxy: None,
      }),
    core_marker: None,
  })
}

pub(crate) fn rest_repo(
  target_ip: &str,
  port: u16,
  user: &str,
  http: &str,
) -> ResticRepo {
  ResticRepo::Rest {
    host: target_ip.into(),
    port,
    user: user.into(),
    password: OneTimeSecret(http.into()),
  }
}

pub(crate) fn require_isolation(
  state: &AppState,
  server: &str,
) -> Result<(), ApiError> {
  if !state.hub.is_online(server) {
    return Err(crate::hub::offline(server));
  }
  if !state.hub.supports_backup_isolation(server) {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      format!("服务器 {server} 的 agent 版本旧，请先升级 agent 再执行隔离备份"),
    ).with_hint(format!("运行 wharf server upgrade {server}")));
  }
  Ok(())
}

pub(crate) fn old_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，无法安全备份或恢复"),
  )
  .with_hint("运行 wharf upgrade 升级 agent")
}

pub(crate) fn require_safe_backup(
  state: &AppState,
  server: &str,
) -> Result<(), ApiError> {
  if !state.hub.is_online(server) {
    return Err(crate::hub::offline(server));
  }
  if !state.hub.supports_safe_backup(server) {
    return Err(old_agent(server));
  }
  Ok(())
}

async fn target_htpasswd(
  state: &AppState,
  snap: &Snap,
  target: &str,
  extra_service: Option<&str>,
) -> Result<String, ApiError> {
  let mut htpasswd = String::new();
  for (service, row) in &snap.world.services {
    if extra_service == Some(service.as_str())
      || row
        .spec
        .backup
        .as_ref()
        .is_some_and(|backup| backup.to == target)
    {
      let (_, hash) = service_http_pair(state, service).await?;
      htpasswd.push_str(&format!("{service}:{hash}\n"));
    }
  }
  Ok(htpasswd)
}

async fn ensure_server(
  state: &AppState,
  snap: &Snap,
  w: &Where,
  extra_service: Option<&str>,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  require_isolation(state, &w.target)?;
  let htpasswd =
    target_htpasswd(state, snap, &w.target, extra_service).await?;
  let compose =
    render::backup_server_compose(&w.target_ip, &htpasswd);
  deploy_server(
    state,
    snap,
    w,
    (BACKUP_PROJECT, compose),
    progress,
    cancel,
  )
  .await
}

/// 备份服务器上的 rest-server 配置没变且在运行时什么也不做。
pub(crate) async fn deploy_server(
  state: &AppState,
  snap: &Snap,
  w: &Where,
  (project, compose): (&str, String),
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let hash = render::hash(&compose);
  let states: Vec<wharf_api_types::agent::ProjectState> = state
    .hub
    .call(
      &w.target,
      AgentOp::ProjectStatus {
        projects: vec![project.into()],
      },
      LIST_TIMEOUT,
      None,
      cancel,
    )
    .await?;
  if states.iter().any(|s| {
    s.project == project
      && s.hash.as_deref() == Some(hash.as_str())
      && s.all_running()
  }) {
    return Ok(());
  }
  progress(format!("在 {} 上部署备份服务（rest-server）", w.target));
  let result: ProjectUpResult = state
    .hub
    .call(
      &w.target,
      AgentOp::ProjectUp(ProjectUp {
        project: project.to_string(),
        compose,
        hash,
        pull: snapshot::pull_policy(&snap.world.servers[&w.target]),
        pull_missing_only: false,
        retire: None,
        rollback: false,
        pins: Default::default(),
        expected_images: Default::default(),
        no_start: false,
        trial: None,
        start_timeout_secs: None,
        readiness: None,
      }),
      SERVER_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if result.containers.is_empty()
    || result.containers.iter().any(|c| c.state != "running")
  {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{} 上的备份服务没有运行起来", w.target),
    ));
  }
  // rest-server 刚起来时端口可能还没开始监听。
  tokio::select! {
    () = cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
    () = tokio::time::sleep(Duration::from_secs(2)) => Ok(()),
  }
}

/// 停服后只启动本次停掉的容器。
async fn stop(
  state: &AppState,
  w: &Where,
  service: &str,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<StoppedContainers, ApiError> {
  if cancel.is_cancelled() {
    return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
  }
  progress(format!("停止 {} 上的 {service}", w.server));
  // 等到 agent 返回停服结果，取消传输时仍能知道需要启动哪些容器。
  state
    .hub
    .call(
      &w.server,
      AgentOp::ServiceStopForData {
        project: service.to_string(),
      },
      STOP_TIMEOUT,
      Some(progress.clone()),
      &CancellationToken::new(),
    )
    .await
}

async fn start(
  state: &AppState,
  w: &Where,
  service: &str,
  stopped: StoppedContainers,
  should_start: bool,
  progress: &ProgressFn,
) -> Result<(), ApiError> {
  if !should_start || stopped.containers.is_empty() {
    return Ok(());
  }
  progress(format!("启动 {} 上的 {service}", w.server));
  state
    .hub
    .call::<bool>(
      &w.server,
      AgentOp::ProjectStart {
        project: service.to_string(),
        containers: stopped.containers,
      },
      STOP_TIMEOUT,
      Some(progress.clone()),
      &CancellationToken::new(),
    )
    .await?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
  state: &AppState,
  snap: &Snap,
  w: &Where,
  service: &str,
  creds: &ServiceCreds,
  mode: ResticPreflightMode,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<ResticPreflightResult, ApiError> {
  let backup = matches!(&mode, ResticPreflightMode::Backup);
  let managed_mounts =
    crate::data::mounts(service, &snap.world.services[service].spec)
      .into_iter()
      .filter(|m| m.kind == wharf_api_types::view::DataKind::Managed)
      .map(|m| m.source)
      .collect();
  let result: ResticPreflightResult = state
    .hub
    .call(
      &w.server,
      job(
        snap,
        &w.server,
        service,
        rest_repo(
          &w.target_ip,
          REST_SERVER_PORT,
          service,
          &creds.http,
        ),
        &creds.key,
        ResticAction::Preflight(ResticPreflight {
          mode,
          managed_mounts,
        }),
      ),
      SERVER_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if result.is_mountpoint && !backup {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("/srv/{service} 本身是独立挂载点"),
      )
      .with_hint(format!(
        "把数据盘改挂到 /srv/{service}/data 子目录后重试"
      )),
    );
  }
  if !result.conflicting_users.is_empty() {
    let users = result
      .conflicting_users
      .iter()
      .map(|u| {
        format!(
          "{}（容器 {}，挂载 {}）",
          u.project.as_deref().unwrap_or(&u.container),
          u.container,
          u.source
        )
      })
      .collect::<Vec<_>>()
      .join("、");
    let hint = if backup {
      "先停止共用该目录的服务，或将对方挂载改为只读（:ro）"
    } else {
      "先停止共用该目录的容器再恢复"
    };
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("无法安全操作 /srv/{service}，其他活动挂载：{users}"),
      )
      .with_hint(hint),
    );
  }
  for m in &result.escaped_mounts {
    progress(format!(
      "快照只包含软链：{} -> {}",
      m.source, m.resolved
    ));
  }
  Ok(result)
}

pub async fn backup(
  state: &AppState,
  run_id: &str,
  service: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let w = location(&snap, service, service_target(&snap, service)?);
  let mut started = Ok(());
  let result = async {
    check_location(state, &snap, &w, service).await?;
    let creds = ensure_service_creds(state, service).await?;
    ensure_server(state, &snap, &w, None, &progress, cancel).await?;
    ensure_repo_has_service_key(
      state,
      &snap,
      (&w.target, service),
      &creds.key,
      cancel,
    )
    .await?;
    let check = preflight(
      state,
      &snap,
      &w,
      service,
      &creds,
      ResticPreflightMode::Backup,
      &progress,
      cancel,
    )
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
          rest_repo(
            &w.target_ip,
            REST_SERVER_PORT,
            service,
            &creds.http,
          ),
          &creds.key,
          ResticAction::Backup {
            host: w.server.clone(),
          },
        ),
        RESTIC_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await;
    started = start(
      state,
      &w,
      service,
      stopped,
      !snap.world.services[service].spec.stopped,
      &progress,
    )
    .await;
    backed.map(|mut summary| {
      summary.escaped_mounts = check.escaped_mounts;
      (summary, creds)
    })
  }
  .await;
  // 快照写入成功与重启结果分别记录。
  let record_result = result
    .as_ref()
    .map(|(summary, _)| summary.clone())
    .map_err(Clone::clone);
  if !matches!(&record_result, Err(e) if e.code == ErrorCode::Cancelled)
  {
    record(state, run_id, service, &w, &record_result).await?;
  }
  let (_, creds) = match result {
    Ok(result) => result,
    Err(err) => {
      return combine_restart(Err(err), started, service, &progress);
    }
  };
  let pruned = local_call::<serde_json::Value>(
    state,
    &snap,
    (&w.target, service),
    &creds.key,
    ResticAction::Prune,
    cancel,
  )
  .await;
  if let Err(e) = pruned {
    progress(format!("提醒：清理旧快照失败：{e}"));
  }
  crate::rules::notice(
    state,
    "backup",
    Some(&format!("backup.{service}.restart")),
    started.is_ok(),
    crate::notify::Event {
      title: if started.is_ok() {
        format!("服务 {service} 备份后启动恢复正常")
      } else {
        format!("服务 {service} 备份已完成，但重启失败")
      },
      body: started
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default(),
    },
  )
  .await;
  started.map_err(|e| e.with_hint(format!("数据快照已写入目标仓库，请手动拉起服务：wharf service deploy {service}")))
}

fn combine_restart(
  result: Result<(), ApiError>,
  started: Result<(), ApiError>,
  service: &str,
  progress: &ProgressFn,
) -> Result<(), ApiError> {
  match (result, started) {
    (Ok(()), Ok(())) => Ok(()),
    (Err(e), Ok(())) => Err(e),
    (result, Err(restart)) => {
      let msg = format!(
        "重启失败：{restart}。请手动拉起服务：wharf service deploy {service}"
      );
      progress(msg.clone());
      Err(result.err().unwrap_or(restart).with_hint(msg))
    }
  }
}

pub async fn restore(
  state: &AppState,
  service: &str,
  snapshot_id: &str,
  target: Option<&str>,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let target = resolve_target(state, &snap, service, target)
    .await?
    .ok_or_else(|| missing_target(service))?;
  let w = location(&snap, service, target);
  check_location(state, &snap, &w, service).await?;
  let creds = ensure_service_creds(state, service).await?;
  ensure_server(state, &snap, &w, Some(service), &progress, cancel)
    .await?;
  ensure_repo_has_service_key(
    state,
    &snap,
    (&w.target, service),
    &creds.key,
    cancel,
  )
  .await?;
  preflight(
    state,
    &snap,
    &w,
    service,
    &creds,
    ResticPreflightMode::Restore {
      snapshot: snapshot_id.to_string(),
    },
    &progress,
    cancel,
  )
  .await?;
  let stopped = stop(state, &w, service, &progress, cancel).await?;
  let restored = state
    .hub
    .call::<serde_json::Value>(
      &w.server,
      job(
        &snap,
        &w.server,
        service,
        rest_repo(
          &w.target_ip,
          REST_SERVER_PORT,
          service,
          &creds.http,
        ),
        &creds.key,
        ResticAction::Restore {
          snapshot: snapshot_id.to_string(),
        },
      ),
      RESTIC_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await;
  let started = start(
    state,
    &w,
    service,
    stopped,
    !snap.world.services[service].spec.stopped,
    &progress,
  )
  .await;
  combine_restart(restored.map(|_| ()), started, service, &progress)
}

pub(crate) async fn record(
  state: &AppState,
  run_id: &str,
  service: &str,
  w: &Where,
  result: &Result<BackupSummary, ApiError>,
) -> Result<(), ApiError> {
  if let Ok(s) = result {
    crate::metrics::event(
      state,
      "backup.added",
      service,
      s.added_bytes as f64,
    )
    .await;
  }
  crate::rules::notice(
    state,
    "backup",
    Some(&format!("backup.{service}")),
    result.is_ok(),
    crate::notify::Event {
      title: match result {
        Ok(_) => format!("服务 {service} 的备份恢复正常"),
        Err(_) => format!("服务 {service} 备份失败"),
      },
      body: match result {
        Ok(_) => format!("备份到 {}", w.target),
        Err(e) => format!("备份到 {}：{e}", w.target),
      },
    },
  )
  .await;
  let (ok, body) = match result {
    Ok(s) => (true, serde_json::to_string(s).map_err(json_err)?),
    Err(e) => (
      false,
      serde_json::to_string(&crate::log_redact::redact_text(
        &e.to_string(),
      ))
      .map_err(json_err)?,
    ),
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
          error: (!ok).then(|| {
            let error: String =
              serde_json::from_str(&body).unwrap_or(body);
            crate::log_redact::redact_text(&error)
          }),
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
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let target = resolve_target(&s, &snap, &name, None).await?;
  let records = records(&s, &name, 20).await?;
  let mut snapshots = vec![];
  let mut snapshots_error = None;
  if let Some(target) = target.as_ref() {
    let (key, legacy) = repository_secrets(&s, &name).await?;
    let cancel = CancellationToken::new();
    let _cancel = cancel.clone().drop_guard();
    let has_key = key.is_some();
    let mut listed: Result<Vec<Snapshot>, ApiError> = Ok(vec![]);
    if let Some(key) = key {
      listed = local_call(
        &s,
        &snap,
        (target, &name),
        &key,
        ResticAction::Snapshots,
        &cancel,
      )
      .await;
    }
    if let Some(legacy) = legacy
      && (!has_key
        || matches!(&listed, Err(e) if e.code == ErrorCode::Forbidden
        || (e.code == ErrorCode::AgentFailed && !s.hub.supports_backup_isolation(target))))
    {
      listed = local_call(
        &s,
        &snap,
        (target, &name),
        &legacy,
        ResticAction::Snapshots,
        &cancel,
      )
      .await;
    }
    match listed {
      Ok(list) => snapshots = list,
      Err(e) => {
        snapshots_error =
          Some(crate::log_redact::redact_text(&e.to_string()));
      }
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

async fn repository_secrets(
  state: &AppState,
  service: &str,
) -> Result<(Option<String>, Option<String>), ApiError> {
  let name = db::scoped_secret_name(KEY_PREFIX, service)?;
  state
    .db
    .call_credentials(move |c, key| {
      Ok((key.secret(c, &name)?, key.secret(c, LEGACY_KEY_SECRET)?))
    })
    .await
}

async fn local_call<T: serde::de::DeserializeOwned>(
  state: &AppState,
  snap: &Snap,
  (target, service): (&str, &str),
  key: &str,
  action: ResticAction,
  cancel: &CancellationToken,
) -> Result<T, ApiError> {
  let timeout = if matches!(action, ResticAction::Prune) {
    RESTIC_TIMEOUT
  } else {
    LIST_TIMEOUT
  };
  state
    .hub
    .call(
      target,
      job(snap, target, service, ResticRepo::Local, key, action),
      timeout,
      None,
      cancel,
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum MigrationStatus {
  Migrated,
  AlreadyOk,
  NoRepo,
  SkippedOffline,
  Failed,
}

async fn ensure_repo_has_service_key(
  state: &AppState,
  snap: &Snap,
  repo: (&str, &str),
  service_key: &str,
  cancel: &CancellationToken,
) -> Result<MigrationStatus, ApiError> {
  let (_, legacy) = repository_secrets(state, repo.1).await?;
  let list = |key: &str| {
    let op = job(
      snap,
      repo.0,
      repo.1,
      ResticRepo::Local,
      key,
      ResticAction::ListKeys,
    );
    state.hub.call::<Vec<ResticKeyInfo>>(
      repo.0,
      op,
      LIST_TIMEOUT,
      None,
      cancel,
    )
  };
  match list(service_key).await {
    Ok(keys) => {
      return Ok(if keys.is_empty() {
        MigrationStatus::NoRepo
      } else {
        MigrationStatus::AlreadyOk
      });
    }
    Err(e) if e.code == ErrorCode::Forbidden && legacy.is_some() => {}
    Err(e) => return Err(e),
  }
  let legacy = legacy.expect("已确认存在旧备份口令");
  if list(&legacy).await?.is_empty() {
    return Ok(MigrationStatus::NoRepo);
  }
  local_call::<String>(
    state,
    snap,
    repo,
    &legacy,
    ResticAction::AddKey {
      new_password: OneTimeSecret(service_key.to_string()),
    },
    cancel,
  )
  .await?;
  if list(service_key).await?.is_empty() {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "加钥匙后找不到备份仓库",
    ));
  }
  Ok(MigrationStatus::Migrated)
}

/// 历史目标也可能还有仓库，清理前必须逐个确认。
async fn repositories(
  state: &AppState,
  snap: &Snap,
) -> Result<BTreeSet<(String, String)>, ApiError> {
  let mut repos = state.db.call(|c| {
    let mut stmt = c.prepare("SELECT DISTINCT target, service FROM backups WHERE service <> ?1")
      .map_err(sql_err)?;
    let rows = stmt.query_map([crate::core_backup::REPO], |r| Ok((r.get(0)?, r.get(1)?)))
      .map_err(sql_err)?;
    rows.collect::<Result<BTreeSet<_>, _>>().map_err(sql_err)
  }).await?;
  for (service, row) in &snap.world.services {
    if let Some(backup) = &row.spec.backup
      && service != crate::core_backup::REPO
    {
      repos.insert((backup.to.clone(), service.clone()));
    }
  }
  Ok(repos)
}

#[derive(Serialize)]
pub struct MigrateReport {
  repositories: Vec<MigrationResult>,
}

#[derive(Serialize)]
struct MigrationResult {
  target: String,
  service: String,
  status: MigrationStatus,
  #[serde(skip_serializing_if = "Option::is_none")]
  error: Option<ApiError>,
}

pub async fn migrate_all(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<MigrateReport> {
  auth.require(Perm::Admin)?;
  let _lock = s
    .locks
    .acquire(crate::locks::LockSpec::Global, "维护业务备份仓库")?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let snap = snapshot::load(&s.db).await?;
  let mut results = Vec::new();
  for (target, service) in repositories(&s, &snap).await? {
    let outcome = async {
      require_isolation(&s, &target)?;
      let creds = ensure_service_creds(&s, &service).await?;
      ensure_repo_has_service_key(
        &s,
        &snap,
        (&target, &service),
        &creds.key,
        &cancel,
      )
      .await
    }
    .await;
    let (status, error) = match outcome {
      Ok(status) => (status, None),
      Err(e) if e.code == ErrorCode::AgentOffline => {
        (MigrationStatus::SkippedOffline, Some(e))
      }
      Err(e) => (MigrationStatus::Failed, Some(e)),
    };
    results.push(MigrationResult {
      target,
      service,
      status,
      error: error.map(crate::log_redact::redact_error),
    });
  }
  Ok(Json(MigrateReport {
    repositories: results,
  }))
}

#[derive(Deserialize, Serialize)]
pub struct CleanupRequest {
  #[serde(default)]
  confirm: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  skip_snapshot: bool,
}

#[derive(Serialize)]
pub struct CleanupReport {
  removed_keys: usize,
  deleted_secrets: usize,
}

pub async fn cleanup_legacy(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  peer: Option<
    axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>,
  >,
  headers: axum::http::HeaderMap,
  Json(req): Json<CleanupRequest>,
) -> ApiResult<CleanupReport> {
  auth.require(Perm::Admin)?;
  auth.require(Perm::Confirm)?;
  if req.confirm.as_deref() != Some("backup/legacy") {
    return Err(ApiError::new(
      ErrorCode::ConfirmRequired,
      "清理旧全局备份口令后无法再回退用 WHARF_BACKUP_KEY 解密旧仓库，需要确认 backup/legacy",
    ).with_hint("先确认 wharf backup core 和各服务的历史快照均已验证可读")
      .suggest("wharf backup cleanup-legacy --confirm backup/legacy")
      .into());
  }
  let _lock = s
    .locks
    .acquire(crate::locks::LockSpec::Global, "维护业务备份仓库")?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let legacy = s
    .db
    .call_credentials(|c, key| key.secret(c, LEGACY_KEY_SECRET))
    .await?;
  let skip = req
    .skip_snapshot
    .then(|| crate::db_snapshot::api_actor(&auth, peer, &headers));
  let mut removals = Vec::new();
  let snap = if let Some(legacy) = &legacy {
    crate::core_backup::require_recovery_ready(&s).await?;
    let snap = snapshot::load(&s.db).await?;
    for (target, service) in repositories(&s, &snap).await? {
      require_isolation(&s, &target)?;
      let repo = (target.as_str(), service.as_str());
      let key = repository_secrets(&s, &service).await?.0;
      // 尚无新口令时仍要用旧口令确认该机器是否真的没有仓库。
      let keys: Vec<ResticKeyInfo> = local_call(
        &s,
        &snap,
        repo,
        key.as_deref().unwrap_or(legacy),
        ResticAction::ListKeys,
        &cancel,
      )
      .await?;
      if keys.is_empty() {
        continue;
      }
      let key = key.ok_or_else(|| {
        ApiError::new(
          ErrorCode::Conflict,
          format!(
            "服务器 {target} 上的 {service} 仓库还没有服务专属口令"
          ),
        )
        .with_hint("运行 wharf backup migrate")
      })?;
      let current = current_key(&keys)?;
      let old_keys: Vec<ResticKeyInfo> = match local_call(
        &s,
        &snap,
        repo,
        legacy,
        ResticAction::ListKeys,
        &cancel,
      )
      .await
      {
        Ok(keys) => keys,
        Err(e) if e.code == ErrorCode::Forbidden => continue,
        Err(e) => return Err(e.into()),
      };
      let old = current_key(&old_keys)?;
      if old == current {
        return Err(
          ApiError::new(
            ErrorCode::Conflict,
            format!("{service} 的旧钥匙仍在使用"),
          )
          .into(),
        );
      }
      removals.push((target, service, key, old.to_string()));
    }
    Some(snap)
  } else {
    None
  };
  crate::db_snapshot::before(
    &s,
    crate::db_snapshot::Trigger::CleanupLegacy,
    "清理旧全局备份口令".into(),
    None,
    skip.as_ref(),
  )
  .await?;
  if let (Some(legacy), Some(snap)) = (&legacy, snap) {
    for (target, service, key, id) in &removals {
      let repo = (target.as_str(), service.as_str());
      local_call::<serde_json::Value>(
        &s,
        &snap,
        repo,
        key,
        ResticAction::RemoveKey { id: id.clone() },
        &cancel,
      )
      .await?;
      let checked: Result<Vec<ResticKeyInfo>, _> = local_call(
        &s,
        &snap,
        repo,
        legacy,
        ResticAction::ListKeys,
        &cancel,
      )
      .await;
      match checked {
        Err(e) if e.code == ErrorCode::Forbidden => {}
        Err(e) => return Err(e.into()),
        Ok(_) => return Err(ApiError::new(
          ErrorCode::Conflict, format!("服务器 {target} 上的 {service} 仓库尚未确认移除旧口令，请重试"),
        ).into()),
      }
    }
  }
  let deleted_secrets = s
    .db
    .call(|c| {
      c.execute(
        "DELETE FROM secrets WHERE name IN (?1, ?2, ?3)",
        [
          LEGACY_KEY_SECRET,
          LEGACY_HTTP_SECRET,
          LEGACY_HTTP_HASH_SECRET,
        ],
      )
      .map_err(sql_err)
    })
    .await?;
  Ok(Json(CleanupReport {
    removed_keys: removals.len(),
    deleted_secrets,
  }))
}

fn current_key(keys: &[ResticKeyInfo]) -> Result<&str, ApiError> {
  keys
    .iter()
    .find(|k| k.current)
    .map(|k| k.id.as_str())
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::AgentFailed,
        "找不到仓库当前使用的钥匙",
      )
    })
}

#[derive(Deserialize, Default)]
pub struct UnlockRequest {
  #[serde(default)]
  pub stale_only: bool,
}

pub async fn unlock(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(service): Path<String>,
  body: Option<Json<UnlockRequest>>,
) -> ApiResult<()> {
  auth.require(Perm::Apply)?;
  crate::token_scope::require_service(&auth, &service)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::Backup(service.clone()),
    "解锁备份仓库",
  )?;
  let snap = snapshot::load(&s.db).await?;
  let target = resolve_target(&s, &snap, &service, None)
    .await?
    .ok_or_else(|| missing_target(&service))?;
  require_safe_backup(&s, &target)?;
  let (key, legacy) = repository_secrets(&s, &service).await?;
  let action = ResticAction::Unlock {
    remove_all: !body.is_some_and(|b| b.stale_only),
  };
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let result = if let Some(key) = key {
    local_call::<serde_json::Value>(
      &s,
      &snap,
      (&target, &service),
      &key,
      action.clone(),
      &cancel,
    )
    .await
  } else {
    Err(ApiError::new(ErrorCode::Forbidden, "没有当前仓库口令"))
  };
  if let Some(legacy) = legacy
    && matches!(&result, Err(e) if e.code == ErrorCode::Forbidden)
  {
    local_call::<serde_json::Value>(
      &s,
      &snap,
      (&target, &service),
      &legacy,
      action,
      &cancel,
    )
    .await?;
  } else {
    result?;
  }
  Ok(Json(()))
}

pub async fn run_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Apply)?;
  let snap = snapshot::load(&s.db).await?;
  crate::token_scope::require_service(&auth, &name)?;
  service_target(&snap, &name)?;
  Ok(Json(
    apply::start_task_by(
      s.clone(),
      format!("备份 {name}"),
      Step::Backup { service: name },
      Some(crate::apply::format_actor(&auth)),
    )
    .await?,
  ))
}

pub async fn restore_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  peer: Option<
    axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>,
  >,
  headers: axum::http::HeaderMap,
  Json(req): Json<RestoreRequest>,
) -> ApiResult<ApplyResponse> {
  auth.require(Perm::Confirm)?;
  if req.skip_snapshot {
    auth.require(Perm::Admin)?;
  }
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
  crate::token_scope::require_service(&auth, &name)?;
  let guard = s.locks.acquire(
    crate::locks::LockSpec::apply([name.clone()]),
    "恢复服务数据",
  )?;
  let snap = snapshot::load(&s.db).await?;
  let target =
    resolve_target(&s, &snap, &name, req.target.as_deref())
      .await?
      .ok_or_else(|| missing_target(&name))?;
  let skip = req
    .skip_snapshot
    .then(|| crate::db_snapshot::api_actor(&auth, peer, &headers));
  crate::db_snapshot::before(
    &s,
    crate::db_snapshot::Trigger::Restore,
    format!("恢复 {address}"),
    None,
    skip.as_ref(),
  )
  .await?;
  Ok(Json(
    apply::start_task_locked(
      s.clone(),
      format!("恢复 {name} 到快照 {}", req.snapshot),
      Step::Restore {
        service: name,
        snapshot: req.snapshot,
        target: Some(target),
      },
      Some(crate::apply::format_actor(&auth)),
      guard,
    )
    .await?,
  ))
}

#[cfg(test)]
#[path = "backup_isolation_tests.rs"]
pub(crate) mod tests;
