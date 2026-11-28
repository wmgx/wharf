//! agent 连接中心：握手认证、请求分发、超时和取消。
//!
//! 每个请求都有超时；超时、取消或连接断开时，等待方立刻拿到错误，
//! 并给 agent 发 `Cancel`。不会出现"一直在忙"的状态。

use std::{
  collections::HashMap,
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  time::Duration,
};

use axum::{
  extract::{
    State, WebSocketUpgrade,
    ws::{Message, WebSocket},
  },
  response::Response,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rusqlite::params;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode, PROTOCOL,
  agent::{
    AgentMsg, AgentOp, AgentReport, BufferedSample, CoreMsg,
    TerminalInput, auth_payload, auth_payload_v2,
  },
  seal::{KeyShare, Opener, Role, Sealer},
};

use crate::{
  db::{now_ms, sql_err},
  state::AppState,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 控制面在 agent 超时之后再多等一会儿，让 agent 有机会报告超时原因。
const GRACE: Duration = Duration::from_secs(15);

pub type ProgressFn = Arc<dyn Fn(String) + Send + Sync>;

struct Pending {
  done: oneshot::Sender<Result<Value, ApiError>>,
  progress: Option<ProgressFn>,
}

#[derive(Clone)]
struct Conn {
  conn_id: u64,
  public_key: String,
  core_probe: bool,
  key_rotation: bool,
  authenticated_core: Option<String>,
  tx: mpsc::Sender<CoreMsg>,
  pending: Arc<Mutex<HashMap<u64, Pending>>>,
  closed: CancellationToken,
  /// 最近一次 ping 的往返延迟，毫秒。
  rtt_ms: Arc<AtomicU64>,
  host_shell: bool,
  runtime_v2: bool,
  monitor_v2: bool,
  task_artifacts: bool,
  backfill: bool,
  forward: bool,
  service_checks: bool,
  container_diagnosis: bool,
  access_logs: bool,
  net_probe: bool,
  container_probe: bool,
  ssh_logins: bool,
  gateway_extra_files: bool,
  backup_isolation: bool,
  safe_delete: bool,
  named_networks_v1: bool,
  compose_env_v2: bool,
  safe_host_bind_v2: bool,
  project_files_v2: bool,
  workload_egress_v1: bool,
  service_runtime_opts: bool,
  live_limits_update: bool,
  task_resource_limits: bool,
  data_cleanup: bool,
  exec_v2: bool,
  files_v2: bool,
  extra_logs_v1: bool,
  shared_volumes: bool,
  safe_gateway: bool,
  gateway_probe: bool,
  frpc_reload: bool,
  safe_adopt: bool,
  safe_migrate: bool,
  migrate_v2: bool,
  service_copy: bool,
  crash_guard: bool,
  service_repair: bool,
  data_ops: bool,
  safe_backup: bool,
  backup_move: bool,
  backup_v2: bool,
  build_v2: bool,
  deploy_v2: bool,
  safe_rollback: bool,
  /// 协议版本不一致：连接放行，但只接受升级相关的请求，好让它升上来。
  upgrade_only: bool,
}

fn check_data_cleanup(
  server: &str,
  conn: &Conn,
) -> Result<(), ApiError> {
  if conn.upgrade_only || !conn.data_cleanup {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!(
          "服务器 {server} 的 agent 版本旧，不支持数据与孤儿资源清理"
        ),
      )
      .with_hint("先运行 wharf upgrade 升级 agent 后重试")
      .suggest("wharf upgrade"),
    );
  }
  Ok(())
}

impl Conn {
  fn deliver_reply(&self, msg: AgentMsg) {
    match msg {
      AgentMsg::Progress { id, line } => {
        let progress = lock(&self.pending)
          .get(&id)
          .and_then(|p| p.progress.clone());
        if let Some(progress) = progress {
          progress(line);
        }
      }
      AgentMsg::Response { id, result } => {
        if let Some(pending) = lock(&self.pending).remove(&id) {
          let _ = pending.done.send(result);
        }
      }
      _ => {}
    }
  }

  fn require_deploy_v2(
    &self,
    server: &str,
    what: &str,
  ) -> Result<(), ApiError> {
    if self.upgrade_only || !self.deploy_v2 {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 版本较旧，不支持{what}"),
        )
        .with_hint("先运行 wharf upgrade 升级 agent 后重试")
        .suggest("wharf upgrade"),
      );
    }
    Ok(())
  }

  fn check_net_probe(
    &self,
    server: &str,
    container: bool,
  ) -> Result<(), ApiError> {
    if self.upgrade_only
      || !self.net_probe
      || (container && !self.container_probe)
    {
      return Err(crate::net_probe::unsupported(server, container));
    }
    Ok(())
  }
}

struct InFlight<'a> {
  conn: &'a Conn,
  id: u64,
}

impl Drop for InFlight<'_> {
  fn drop(&mut self) {
    if lock(&self.conn.pending).remove(&self.id).is_some()
      && self
        .conn
        .tx
        .try_send(CoreMsg::Cancel { id: self.id })
        .is_err()
    {
      self.conn.closed.cancel();
    }
  }
}

#[derive(Default)]
pub struct Hub {
  report_rate: crate::report_guard::RateGate,
  conns: Mutex<HashMap<String, Conn>>,
  next_id: AtomicU64,
  next_conn: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
  m.lock().unwrap_or_else(|p| p.into_inner())
}

fn safe_adopt_required(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!(
      "服务器 {server} 的 agent 版本旧，无法安全导入或接管容器"
    ),
  )
  .with_hint("先运行 wharf upgrade 升级 agent 后重试")
  .suggest("wharf upgrade")
}

pub fn old_workload_egress_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 不支持服务或任务分流代理"),
  )
  .with_hint("运行 wharf upgrade，升级后重新生成计划")
}

fn old_project_files_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 不支持项目文件和目录属主"),
  )
  .with_hint("运行 wharf upgrade，升级后重新生成计划")
}

fn old_host_bind_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 不支持安全外部挂载"),
  )
  .with_hint("运行 wharf upgrade，升级后重新生成计划")
}

fn old_compose_env_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 不支持 Compose 项目变量"),
  )
  .with_hint("运行 wharf upgrade，升级后重新生成计划")
}

fn old_network_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 不支持命名私网"),
  )
  .with_hint("运行 wharf upgrade，升级后重新生成计划")
}

pub(crate) fn offline(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::AgentOffline,
    format!("服务器 {server} 的 agent 不在线"),
  )
  .with_hint("确认这台机器上 wharf-agent 在运行，并且能访问控制面")
  .suggest(format!("wharf server show {server}"))
}

impl Hub {
  pub fn core_probe_servers(&self) -> (Vec<String>, bool) {
    let conns = lock(&self.conns);
    let capable = conns
      .iter()
      .filter(|(_, c)| c.core_probe && !c.closed.is_cancelled())
      .map(|(name, _)| name.clone())
      .collect();
    let legacy = conns
      .values()
      .any(|c| !c.core_probe && !c.closed.is_cancelled());
    (capable, legacy)
  }

  pub fn connected_identity(
    &self,
    server: &str,
  ) -> Option<(u64, String)> {
    lock(&self.conns)
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .map(|c| (c.conn_id, c.public_key.clone()))
  }

  pub fn key_connection(&self, server: &str) -> Option<(u64, bool)> {
    lock(&self.conns)
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .map(|c| (c.conn_id, c.key_rotation))
  }

  pub fn rotation_agents(&self) -> Vec<(String, u64)> {
    lock(&self.conns)
      .iter()
      .filter(|(_, c)| c.key_rotation && !c.closed.is_cancelled())
      .map(|(server, c)| (server.clone(), c.conn_id))
      .collect()
  }

  pub fn uses_core_key(
    &self,
    server: &str,
    previous_conn: Option<u64>,
    public: &str,
  ) -> bool {
    lock(&self.conns).get(server).is_some_and(|c| {
      c.key_rotation
        && !c.closed.is_cancelled()
        && Some(c.conn_id) != previous_conn
        && c.authenticated_core.as_deref() == Some(public)
    })
  }

  pub fn core_probe_identity(
    &self,
    server: &str,
  ) -> Option<(u64, String)> {
    lock(&self.conns)
      .get(server)
      .filter(|c| c.core_probe && !c.closed.is_cancelled())
      .map(|c| (c.conn_id, c.public_key.clone()))
  }

  pub fn disconnect(&self, server: &str) {
    if let Some(conn) = lock(&self.conns).remove(server) {
      conn.closed.cancel();
    }
  }

  pub fn is_online(&self, server: &str) -> bool {
    lock(&self.conns).contains_key(server)
  }

  pub fn ssh_login_servers(&self) -> Vec<String> {
    lock(&self.conns)
      .iter()
      .filter(|(_, conn)| !conn.upgrade_only && conn.ssh_logins)
      .map(|(server, _)| server.clone())
      .collect()
  }

  pub fn supports_host_shell(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|conn| conn.host_shell)
  }

  pub fn supports_runtime_v2(&self, server: &str) -> bool {
    self.runtime_v2_conn_id(server).is_ok()
  }

  pub(crate) fn runtime_v2_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.runtime_v2 {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 版本较旧，不支持该功能"),
        )
        .with_hint("运行 wharf upgrade 升级 agent"),
      );
    }
    Ok(conn.conn_id)
  }

  pub fn supports_service_checks(&self, server: &str) -> bool {
    self.service_checks_support(server) == Some(true)
  }

  pub(crate) fn service_checks_support(
    &self,
    server: &str,
  ) -> Option<bool> {
    lock(&self.conns)
      .get(server)
      .filter(|c| !c.closed.is_cancelled() && !c.upgrade_only)
      .map(|c| c.service_checks)
  }

  pub fn supports_container_diagnosis(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.container_diagnosis)
  }

  pub(crate) fn require_safe_adopt(
    &self,
    server: &str,
  ) -> Result<(), ApiError> {
    let conns = lock(&self.conns);
    let c = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if c.upgrade_only || !c.safe_adopt {
      return Err(safe_adopt_required(server));
    }
    Ok(())
  }

  pub(crate) fn require_data_ops(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.data_ops {
      return Err(data_ops_required(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn service_repair_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.service_repair {
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "agent 不支持服务修复")
          .with_hint(format!(
            "运行 wharf server upgrade {server} 后重试"
          )),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn crash_guard_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.crash_guard {
      return Err(
        ApiError::new(
          ErrorCode::AgentFailed,
          "agent 不支持重启循环保护",
        )
        .with_hint(format!(
          "运行 wharf server upgrade {server} 后重试"
        )),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn service_copy_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.service_copy {
      return Err(
        ApiError::new(
          ErrorCode::AgentFailed,
          format!("服务器 {server} 的 agent 不支持服务复制"),
        )
        .with_hint(format!(
          "运行 wharf server upgrade {server} 后重试"
        )),
      );
    }
    Ok(conn.conn_id)
  }

  pub fn supports_migrate_v2(&self, server: &str) -> bool {
    self.require_migrate_v2(server).is_ok()
  }

  pub(crate) fn require_migrate_v2(
    &self,
    server: &str,
  ) -> Result<(), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.migrate_v2 {
      return Err(migrate_v2_required(server));
    }
    Ok(())
  }

  pub fn supports_safe_migrate(&self, server: &str) -> bool {
    self.require_safe_migrate(server).is_ok()
  }

  pub(crate) fn require_safe_migrate(
    &self,
    server: &str,
  ) -> Result<(), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.safe_migrate {
      return Err(safe_migrate_required(server));
    }
    Ok(())
  }

  pub fn supports_backup_move(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.backup_move)
  }

  pub fn supports_backup_v2(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.backup_v2)
  }

  pub fn supports_safe_backup(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.safe_backup)
  }

  pub fn supports_build_v2(&self, server: &str) -> bool {
    self.build_v2_conn_id(server).is_some()
  }

  pub(crate) fn require_build_v2(
    &self,
    server: &str,
  ) -> Result<(), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.build_v2 {
      return Err(crate::build::old_git_agent(server));
    }
    Ok(())
  }

  pub(crate) fn build_v2_conn_id(&self, server: &str) -> Option<u64> {
    lock(&self.conns)
      .get(server)
      .filter(|c| {
        !c.closed.is_cancelled() && !c.upgrade_only && c.build_v2
      })
      .map(|c| c.conn_id)
  }

  pub fn supports_safe_rollback(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.safe_rollback)
  }

  pub fn supports_gateway_probe(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.gateway_probe)
  }

  pub fn supports_frpc_reload(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.frpc_reload)
  }

  pub fn supports_backfill(&self, server: &str) -> bool {
    lock(&self.conns).get(server).is_some_and(|c| {
      !c.closed.is_cancelled() && !c.upgrade_only && c.backfill
    })
  }

  pub(crate) fn task_limits_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.task_resource_limits {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持任务资源上限"),
        )
        .with_hint("运行 wharf upgrade 后重新运行任务")
        .suggest("wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn task_artifacts_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.task_artifacts {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!(
            "服务器 {server} 的 agent 版本旧，不支持定时任务产物读取"
          ),
        )
        .with_hint("先升级 agent：wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub fn supports_monitor_v2(&self, server: &str) -> bool {
    lock(&self.conns).get(server).is_some_and(|c| {
      !c.closed.is_cancelled() && !c.upgrade_only && c.monitor_v2
    })
  }

  pub(crate) fn scheduled_restart_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.safe_gateway {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持定时温和重启"),
        )
        .with_hint("运行 wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub fn supports_safe_gateway(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.safe_gateway)
  }

  pub fn supports_data_cleanup(&self, server: &str) -> bool {
    self.require_data_cleanup(server).is_ok()
  }

  pub(crate) fn require_data_cleanup(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    check_data_cleanup(server, conn)?;
    Ok(conn.conn_id)
  }

  pub fn supports_safe_delete(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.safe_delete)
  }

  pub fn supports_backup_isolation(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.backup_isolation)
  }

  pub fn gateway_extra_files(&self, server: &str) -> Option<bool> {
    lock(&self.conns)
      .get(server)
      .map(|c| !c.upgrade_only && c.gateway_extra_files)
  }

  pub fn supports_net_probe(
    &self,
    server: &str,
    container: bool,
  ) -> Result<(), ApiError> {
    self.net_probe_conn_id(server, container).map(|_| ())
  }

  pub(crate) fn net_probe_conn_id(
    &self,
    server: &str,
    container: bool,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    conn.check_net_probe(server, container)?;
    Ok(conn.conn_id)
  }

  pub fn log_watches(
    &self,
    server: &str,
    watches: Vec<wharf_api_types::service_checks::LogWatch>,
  ) {
    if let Some(conn) = lock(&self.conns).get(server)
      && !conn.upgrade_only
      && conn.tx.try_send(CoreMsg::LogWatches { watches }).is_err()
    {
      conn.closed.cancel();
    }
  }

  /// 当前连接的编号，每次重连都会变。不在线时是 `None`。
  pub fn conn_id(&self, server: &str) -> Option<u64> {
    lock(&self.conns).get(server).map(|c| c.conn_id)
  }

  /// 控制面到 agent 的往返延迟。还没测到时是 `None`。
  pub fn rtt_ms(&self, server: &str) -> Option<u32> {
    let conns = lock(&self.conns);
    let ms = conns.get(server)?.rtt_ms.load(Ordering::Relaxed);
    (ms != u64::MAX).then_some(ms as u32)
  }

  /// 发一个请求并等待结果。
  pub async fn call<T: DeserializeOwned>(
    &self,
    server: &str,
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    self
      .call_as(self.new_id(), server, op, timeout, progress, cancel)
      .await
  }

  /// 请求编号。要在请求进行中给它发输入（终端）时，先拿编号再 [Self::call_as]。
  pub fn new_id(&self) -> u64 {
    self.next_id.fetch_add(1, Ordering::Relaxed) + 1
  }

  /// 给进行中的请求发输入。连接已断开时什么也不做。
  pub async fn input(
    &self,
    server: &str,
    id: u64,
    input: TerminalInput,
  ) -> bool {
    let conn = lock(&self.conns).get(server).cloned();
    let Some(conn) = conn else {
      return false;
    };
    tokio::time::timeout(
      Duration::from_secs(1),
      conn.tx.send(CoreMsg::Input { id, input }),
    )
    .await
    .is_ok_and(|result| result.is_ok())
  }

  pub async fn call_as<T: DeserializeOwned>(
    &self,
    id: u64,
    server: &str,
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    let conn = lock(&self.conns)
      .get(server)
      .cloned()
      .ok_or_else(|| offline(server))?;
    Self::call_conn(
      id,
      server,
      conn,
      op,
      timeout,
      (progress, None),
      cancel,
    )
    .await
  }

  pub async fn call_bound<T: DeserializeOwned>(
    &self,
    (server, conn_id): (&str, u64),
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    let conn = lock(&self.conns)
      .get(server)
      .filter(|c| c.conn_id == conn_id && !c.closed.is_cancelled())
      .cloned()
      .ok_or_else(|| offline(server))?;
    Self::call_conn(
      self.new_id(),
      server,
      conn,
      op,
      timeout,
      (progress, None),
      cancel,
    )
    .await
  }

  pub fn supports_deploy_v2(&self, server: &str) -> bool {
    self.deploy_v2_conn_id(server, "").is_ok()
  }

  pub(crate) fn deploy_v2_conn_id(
    &self,
    server: &str,
    what: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    conn.require_deploy_v2(server, what)?;
    Ok(conn.conn_id)
  }

  pub(crate) fn shared_volumes_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.shared_volumes {
      return Err(shared_volumes_required(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn supports_shared_volumes(&self, server: &str) -> bool {
    self.shared_volumes_conn_id(server).is_ok()
  }

  pub(crate) fn exec_v2_conn_id(
    &self,
    server: &str,
    feature: &str,
  ) -> Result<u64, ApiError> {
    self.exec_connection(server).and_then(|(id, supported)| {
      if supported {
        Ok(id)
      } else {
        Err(
          ApiError::new(
            ErrorCode::Conflict,
            format!(
              "服务器 {server} 的 agent 版本旧，不支持{feature}"
            ),
          )
          .with_hint("先升级 agent：wharf upgrade"),
        )
      }
    })
  }

  pub(crate) fn host_exec_connection(
    &self,
    server: &str,
  ) -> Result<(u64, bool), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if !conn.host_shell || conn.upgrade_only {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持宿主机命令"),
        )
        .with_hint("先升级 agent：wharf upgrade"),
      );
    }
    Ok((conn.conn_id, conn.exec_v2))
  }

  fn exec_connection(
    &self,
    server: &str,
  ) -> Result<(u64, bool), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|c| !c.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    Ok((conn.conn_id, !conn.upgrade_only && conn.exec_v2))
  }

  pub(crate) async fn call_optional_bound<T: DeserializeOwned>(
    &self,
    server: &str,
    conn: Option<u64>,
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    if let Some(conn) = conn {
      self
        .call_bound((server, conn), op, timeout, progress, cancel)
        .await
    } else {
      self.call(server, op, timeout, progress, cancel).await
    }
  }

  pub(crate) fn workload_egress_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.workload_egress_v1 {
      return Err(old_workload_egress_agent(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn project_files_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.project_files_v2 {
      return Err(old_project_files_agent(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn host_bind_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.safe_host_bind_v2 {
      return Err(old_host_bind_agent(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn compose_env_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.compose_env_v2 {
      return Err(old_compose_env_agent(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn named_network_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.named_networks_v1 {
      return Err(old_network_agent(server));
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn live_limits_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.live_limits_update {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持原地更新资源上限"),
        )
        .with_hint("运行 wharf upgrade 后重新 plan")
        .suggest("wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn runtime_options_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.service_runtime_opts {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持运行参数"),
        )
        .with_hint("运行 wharf upgrade 后重新 plan")
        .suggest("wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn safe_delete_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.safe_delete {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!(
            "服务器 {server} 的 agent 版本旧，无法安全删除项目"
          ),
        )
        .with_hint("先运行 wharf upgrade 升级 agent 后重试")
        .suggest("wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn files_v2_conn_id(
    &self,
    server: &str,
    feature: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.files_v2 {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 版本旧，不支持{feature}"),
        )
        .with_hint("先运行 wharf upgrade 升级 agent 后重试")
        .suggest("wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) fn extra_logs_conn_id(
    &self,
    server: &str,
  ) -> Result<u64, ApiError> {
    let conns = lock(&self.conns);
    let conn = conns
      .get(server)
      .filter(|conn| !conn.closed.is_cancelled())
      .ok_or_else(|| offline(server))?;
    if conn.upgrade_only || !conn.files_v2 || !conn.extra_logs_v1 {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持文件日志"),
        )
        .with_hint("运行 wharf upgrade"),
      );
    }
    Ok(conn.conn_id)
  }

  pub(crate) async fn dispatch_cleanup(
    &self,
    server: &str,
    service: &str,
    progress: ProgressFn,
    cancel: &CancellationToken,
    guard: crate::locks::OpLockGuard,
  ) -> Result<wharf_api_types::agent::RemoveDataResult, ApiError> {
    let conn = lock(&self.conns)
      .get(server)
      .cloned()
      .ok_or_else(|| offline(server))?;
    Self::call_conn(
      self.new_id(),
      server,
      conn,
      AgentOp::RemoveData {
        service: service.to_string(),
      },
      Duration::from_secs(30 * 60),
      (Some(progress), Some((guard, service.to_string()))),
      cancel,
    )
    .await
  }

  async fn call_conn<T: DeserializeOwned>(
    id: u64,
    server: &str,
    conn: Conn,
    mut op: AgentOp,
    timeout: Duration,
    (progress, dispatch_guard): (
      Option<ProgressFn>,
      Option<(crate::locks::OpLockGuard, String)>,
    ),
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    if matches!(
      &op,
      AgentOp::CleanupScan(_) | AgentOp::CleanupDelete(_)
    ) {
      check_data_cleanup(server, &conn)?;
    }
    if !conn.monitor_v2
      && match &op {
        AgentOp::HttpCheck(job) => !job.headers.is_empty(),
        AgentOp::ComposeEnvCheck { .. } => true,
        AgentOp::ProjectUp(up) => {
          up.readiness.as_ref().is_some_and(|p| !p.headers.is_empty())
        }
        _ => false,
      }
    {
      return Err(crate::monitor::old_agent(server));
    }
    if let AgentOp::ProjectUp(up) = &op {
      if up.init.is_some() {
        conn.require_deploy_v2(server, "部署前初始化")?;
      } else if wharf_api_types::compose::parse_compose_max_grace_secs(
        &up.compose,
      ) > 150
      {
        conn
          .require_deploy_v2(server, "超过 150 秒的优雅停机超时")?;
      }
    }
    if (matches!(&op, AgentOp::ImportRead(_))
      || matches!(&op, AgentOp::ProjectUp(up) if up.pull_missing_only))
      && (conn.upgrade_only || !conn.safe_adopt)
    {
      return Err(safe_adopt_required(server));
    }
    if (matches!(&op, AgentOp::SyncServe(job) if job.kind.is_service_data())
      || matches!(&op, AgentOp::SyncPush(job) if job.kind.is_service_data())
      || matches!(&op, AgentOp::ProjectMounts { .. })
      || matches!(&op, AgentOp::ProjectUp(up) if up.no_start && !up.pull_missing_only))
      && (conn.upgrade_only || !conn.safe_migrate)
    {
      return Err(safe_migrate_required(server));
    }
    if matches!(
      &op,
      AgentOp::AdoptDataInspect(_)
        | AgentOp::AdoptDataCopy(_)
        | AgentOp::DataManifest { .. }
        | AgentOp::DataSqliteSnap { .. }
        | AgentOp::DataSqliteRead { .. }
        | AgentOp::DataSqliteClose { .. }
        | AgentOp::Files(
          wharf_api_types::agent::FilesOp::DataMkdir { .. }
            | wharf_api_types::agent::FilesOp::Remove { .. }
            | wharf_api_types::agent::FilesOp::AbortWrite { .. }
            | wharf_api_types::agent::FilesOp::DataWrite { .. }
        )
    ) && (conn.upgrade_only || !conn.data_ops)
    {
      return Err(data_ops_required(server));
    }
    if matches!(&op, AgentOp::ServiceRepair(_))
      && (conn.upgrade_only || !conn.service_repair)
    {
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "agent 不支持服务修复")
          .with_hint(format!(
            "运行 wharf server upgrade {server} 后重试"
          )),
      );
    }
    if matches!(&op, AgentOp::CrashGuard(_))
      && (conn.upgrade_only || !conn.crash_guard)
    {
      return Err(
        ApiError::new(
          ErrorCode::AgentFailed,
          "agent 不支持重启循环保护",
        )
        .with_hint(format!(
          "运行 wharf server upgrade {server} 后重试"
        )),
      );
    }
    if (matches!(&op, AgentOp::ServiceCopy(_))
      || matches!(&op, AgentOp::SyncServe(job) if job.kind == wharf_api_types::agent::SyncKind::CloneData)
      || matches!(&op, AgentOp::SyncPush(job) if job.kind == wharf_api_types::agent::SyncKind::CloneSource))
      && (conn.upgrade_only || !conn.service_copy)
    {
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "agent 不支持服务复制")
          .with_hint(format!(
            "运行 wharf server upgrade {server} 后重试"
          )),
      );
    }
    if (matches!(&op, AgentOp::DirSpace { .. })
      || matches!(&op, AgentOp::SyncPush(p) if p.bwlimit_kbps.is_some())
      || matches!(&op, AgentOp::Restic(j) if j.bwlimit_kbps.is_some()))
      && (conn.upgrade_only || !conn.migrate_v2)
    {
      return Err(migrate_v2_required(server));
    }
    if let AgentOp::Build(job) = &mut op
      && job.expected_commit.is_some()
      && !conn.safe_migrate
    {
      job.force = true;
    }
    if (matches!(&op, AgentOp::GatewayProbe(_))
      && !conn.gateway_probe)
      || (matches!(&op, AgentOp::LinkApply(_)) && !conn.frpc_reload)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 不支持该操作"),
        )
        .suggest(format!("wharf server upgrade {server}")),
      );
    }
    let requires_exec_v2 = match &op {
      AgentOp::ServiceExec(_) => true,
      AgentOp::HostExec(job) => job.stream,
      AgentOp::Logs { container, .. }
      | AgentOp::ProjectRestart { container, .. } => {
        container.is_some()
      }
      AgentOp::TaskRun(job) => {
        matches!(&job.how, wharf_api_types::agent::TaskHow::Exec { env, .. } if !env.is_empty())
      }
      _ => false,
    };
    if requires_exec_v2 && (conn.upgrade_only || !conn.exec_v2) {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 版本旧"),
        )
        .with_hint("先升级 agent：wharf upgrade"),
      );
    }
    let cancel_grace = match &op {
      AgentOp::HostExec(_)
      | AgentOp::ServiceExec(_)
      | AgentOp::TaskRun(_) => Some(Duration::from_secs(15)),
      AgentOp::LinkApply(_) => Some(Duration::from_secs(90)),
      AgentOp::ServiceStopForData { .. } => {
        Some(Duration::from_secs(250))
      }
      AgentOp::Restic(job)
        if matches!(
          job.action,
          wharf_api_types::agent::ResticAction::Backup { .. }
            | wharf_api_types::agent::ResticAction::Restore { .. }
            | wharf_api_types::agent::ResticAction::Prune
            | wharf_api_types::agent::ResticAction::PruneV2 { .. }
        ) =>
      {
        Some(Duration::from_secs(45))
      }
      _ => None,
    };
    if matches!(
      &op,
      AgentOp::ProjectDown { purge: true, .. }
        | AgentOp::BindMountUsers(_)
    ) && (conn.upgrade_only || !conn.shared_volumes)
    {
      return Err(shared_volumes_required(server));
    }
    use wharf_api_types::agent::{ResticAction, ResticRepo};
    let needs_backup_move = match &op {
      AgentOp::SyncServe(job) => !job.kind.is_service_data(),
      AgentOp::SyncPush(job) => !job.kind.is_service_data(),
      AgentOp::Restic(job) => {
        matches!(job.repo, ResticRepo::LocalCore)
          || matches!(job.action, ResticAction::RepoNonempty)
      }
      _ => false,
    };
    if needs_backup_move && (conn.upgrade_only || !conn.backup_move) {
      return Err(crate::backup_move::old_agent(server));
    }
    if let AgentOp::Restic(job) = &op
      && job.action.needs_backup_v2()
      && (conn.upgrade_only || !conn.backup_v2)
    {
      return Err(crate::backup::old_backup_v2(server));
    }
    let needs_safe_backup = match &op {
      AgentOp::ServiceStopForData { .. }
      | AgentOp::PruneRestore { .. } => true,
      AgentOp::ProjectStart { containers, .. } => {
        !containers.is_empty()
      }
      AgentOp::Restic(job) => matches!(
        job.action,
        wharf_api_types::agent::ResticAction::Preflight(_)
          | wharf_api_types::agent::ResticAction::Unlock { .. }
          | wharf_api_types::agent::ResticAction::Backup { .. }
          | wharf_api_types::agent::ResticAction::Restore { .. }
      ),
      _ => false,
    };
    if needs_safe_backup && (conn.upgrade_only || !conn.safe_backup) {
      return Err(crate::backup::old_agent(server));
    }
    use wharf_api_types::agent::{BuildFetch, TaskHow};
    let fetch = match &op {
      AgentOp::Build(job) => Some(&job.fetch),
      AgentOp::EdgeBuild(job) => Some(&job.fetch),
      AgentOp::ResolveCommit(job) => Some(&job.fetch),
      _ => None,
    };
    if !conn.build_v2 {
      if matches!(fetch, Some(BuildFetch::Git { user: Some(_), .. }))
      {
        return Err(crate::build::old_git_agent(server));
      }
      if (matches!(&op, AgentOp::Build(_) | AgentOp::EdgeBuild(_))
        || matches!(&op, AgentOp::TaskRun(job) if matches!(&job.how, TaskHow::Script { .. })))
        && let Some(progress) = &progress
      {
        progress(crate::build::old_agent_warning(server));
      }
    }
    let workload_egress = match &op {
      AgentOp::WorkloadEgressStatus => true,
      AgentOp::ProjectUp(up) => up.workload_egress,
      AgentOp::TaskRun(job) => job.workload_no_proxy.is_some(),
      AgentOp::HostExec(job) => job.workload_no_proxy.is_some(),
      _ => false,
    };
    if workload_egress
      && (conn.upgrade_only || !conn.workload_egress_v1)
    {
      return Err(old_workload_egress_agent(server));
    }
    if matches!(&op, AgentOp::ProjectUp(up) if !up.volume_owners.is_empty() || !up.project_files.is_empty())
      && (conn.upgrade_only || !conn.project_files_v2)
    {
      return Err(old_project_files_agent(server));
    }
    if (matches!(&op, AgentOp::HostBindCheck { .. })
      || matches!(&op, AgentOp::ProjectUp(up) if !up.host_binds.is_empty()))
      && (conn.upgrade_only || !conn.safe_host_bind_v2)
    {
      return Err(old_host_bind_agent(server));
    }
    if (matches!(&op, AgentOp::ComposeEnvCheck { .. })
      || matches!(&op, AgentOp::ProjectUp(up) if up.project_env.is_some()))
      && (conn.upgrade_only || !conn.compose_env_v2)
    {
      return Err(old_compose_env_agent(server));
    }
    if (matches!(&op, AgentOp::NamedNetworksCheck { .. })
      || matches!(&op, AgentOp::ProjectUp(up) if !up.networks.is_empty()))
      && (conn.upgrade_only || !conn.named_networks_v1)
    {
      return Err(old_network_agent(server));
    }
    if matches!(&op, AgentOp::RemoveData { .. })
      && (conn.upgrade_only || !conn.safe_delete)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!(
            "服务器 {server} 的 agent 版本旧，无法安全清理数据"
          ),
        )
        .with_hint("先运行 wharf upgrade 升级 agent 后重试")
        .suggest("wharf upgrade"),
      );
    }
    if matches!(
      &op,
      AgentOp::RotateAgentKey(_) | AgentOp::TrustCoreKey(_)
    ) && !conn.key_rotation
    {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        "agent 不支持在线轮换密钥",
      ));
    }
    if matches!(&op, AgentOp::ProbeCoreHost(_)) && !conn.core_probe {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        "agent 不支持控制面同机校验",
      ));
    }
    if matches!(&op, AgentOp::SshLogins) && !conn.ssh_logins {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        "agent 不支持采集 SSH 登录",
      ));
    }
    if let AgentOp::NetProbe(job) = &op {
      conn.check_net_probe(server, job.container.is_some())?;
    }
    if matches!(&op, AgentOp::AccessLogs(_))
      && (conn.upgrade_only || !conn.access_logs)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          "网关所在机器的 agent 版本旧，不支持访问日志",
        )
        .with_hint("运行 wharf upgrade"),
      );
    }
    if matches!(
      &op,
      AgentOp::Restic(job) if matches!(job.action, wharf_api_types::agent::ResticAction::ListKeys)
    ) && (conn.upgrade_only || !conn.backup_isolation)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!(
            "服务器 {server} 的 agent 版本旧，不支持备份密钥管理"
          ),
        )
        .with_hint("运行 wharf upgrade"),
      );
    }
    if let AgentOp::ProjectUp(job) = &op
      && matches!(
        job.project.as_str(),
        crate::render::BACKUP_PROJECT
          | crate::render::CORE_BACKUP_PROJECT
      )
      && (conn.upgrade_only || !conn.backup_isolation)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 版本旧，不支持隔离备份"),
        )
        .with_hint("运行 wharf upgrade"),
      );
    }
    if conn.upgrade_only
      && !matches!(&op, AgentOp::Upgrade(_) | AgentOp::UpgradeLog)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 协议版本和控制面不一致，只能升级"),
        )
        .with_hint("运行 wharf upgrade 把 agent 升到和控制面一致"),
      );
    }
    if matches!(
      &op,
      AgentOp::HostTerminal { .. } | AgentOp::HostExec(_)
    ) && !conn.host_shell
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 还不支持宿主机终端"),
        )
        .with_hint("请先运行 wharf upgrade"),
      );
    }
    if matches!(&op, AgentOp::Forward(_)) && !conn.forward {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务器 {server} 的 agent 还不支持端口转发"),
        )
        .with_hint("请先运行 wharf upgrade"),
      );
    }
    if matches!(&op, AgentOp::DiagnoseContainer { .. })
      && !conn.container_diagnosis
    {
      return Err(ApiError::new(
        ErrorCode::Conflict,
        "agent 版本旧，升级后能看到原因（wharf upgrade）",
      ));
    }
    let (done, mut rx) = oneshot::channel();
    lock(&conn.pending).insert(id, Pending { done, progress });
    let _in_flight = InFlight { conn: &conn, id };
    let activating_key = matches!(
      &op,
      AgentOp::RotateAgentKey(job)
        if matches!(job.phase, wharf_api_types::agent::KeyRotatePhase::Activate)
    );
    let sent = tokio::select! {
      biased;
      _ = cancel.cancelled() => {
        lock(&conn.pending).remove(&id);
        return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
      },
      sent = tokio::time::timeout(
      Duration::from_secs(5),
      conn.tx.send(CoreMsg::Request {
        id,
        timeout_ms: timeout.as_millis() as u64,
        op,
      }),
      ) => sent,
    };
    if let Some((guard, service)) = &dispatch_guard {
      guard.release_apply(service);
    }
    if !matches!(sent, Ok(Ok(()))) {
      lock(&conn.pending).remove(&id);
      return Err(offline(server));
    }
    let abort = |code: ErrorCode, message: String| {
      lock(&conn.pending).remove(&id);
      if conn.tx.try_send(CoreMsg::Cancel { id }).is_err() {
        conn.closed.cancel();
      }
      ApiError::new(code, message)
    };
    let result = tokio::select! {
      result = &mut rx => result.unwrap_or_else(|_| Err(offline(server))),
      _ = conn.closed.cancelled() => Err(offline(server)),
      _ = tokio::time::sleep(timeout + cancel_grace.unwrap_or(GRACE)) => Err(abort(
        ErrorCode::Timeout,
        format!("服务器 {server} 超过 {} 秒没有响应", timeout.as_secs()),
      )),
      _ = cancel.cancelled() => {
        if let Some(grace) = cancel_grace {
          // 数据操作先等 agent 收尾。停服已成功时仍需返回原容器列表。
          if conn.tx.try_send(CoreMsg::Cancel { id }).is_err() {
            conn.closed.cancel();
          }
          tokio::select! {
            result = &mut rx => result.unwrap_or_else(|_| Err(offline(server))),
            _ = conn.closed.cancelled() => Err(offline(server)),
            _ = tokio::time::sleep(grace) => Err(abort(ErrorCode::Timeout, "未收到 agent 收尾确认".into())),
          }
        } else {
          Err(abort(ErrorCode::Cancelled, "已取消".into()))
        }
      },
    };
    let value = result.map_err(|e| {
      // 请求已发出，断线不能证明 agent 没有切换密钥。
      if activating_key && e.code == ErrorCode::AgentOffline {
        return ApiError::new(
          ErrorCode::Timeout,
          "未收到 agent 密钥切换确认",
        );
      }
      crate::external_status::agent_failure(e, server)
    })?;
    serde_json::from_value(value).map_err(|e| {
      ApiError::internal(format!("agent 返回的数据无法解析：{e}"))
    })
  }

  fn register(&self, server: &str, conn: Conn) {
    if let Some(old) =
      lock(&self.conns).insert(server.to_string(), conn)
    {
      // 同一台服务器重复连接：旧连接作废。
      old.closed.cancel();
    }
  }

  fn unregister(&self, server: &str, conn: &Conn) {
    let mut conns = lock(&self.conns);
    if conns.get(server).is_some_and(|c| c.conn_id == conn.conn_id) {
      conns.remove(server);
    }
    drop(conns);
    for (_, pending) in lock(&conn.pending).drain() {
      let _ = pending.done.send(Err(offline(server)));
    }
  }
}

pub async fn agent_ws(
  State(state): State<Arc<AppState>>,
  ws: WebSocketUpgrade,
) -> Response {
  ws.max_message_size(crate::report_guard::MAX_WS_MESSAGE_BYTES)
    .on_upgrade(move |socket| async move {
      if let Err(e) = handle_socket(state, socket).await {
        tracing::warn!("agent 连接结束：{e}");
      }
    })
}

fn random_nonce() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

fn decode_key(hex_key: &str) -> Option<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
  VerifyingKey::from_bytes(&bytes).ok()
}

fn decode_sig(hex_sig: &str) -> Option<Signature> {
  let bytes: [u8; 64] = hex::decode(hex_sig).ok()?.try_into().ok()?;
  Some(Signature::from_bytes(&bytes))
}

async fn recv_text(socket: &mut WebSocket) -> anyhow::Result<String> {
  loop {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
      .await
      .map_err(|_| anyhow::anyhow!("握手超时"))?
      .ok_or_else(|| anyhow::anyhow!("连接关闭"))??;
    match msg {
      Message::Text(text) => return Ok(text.to_string()),
      Message::Close(_) => anyhow::bail!("连接关闭"),
      _ => continue,
    }
  }
}

async fn send_msg(
  socket: &mut WebSocket,
  msg: &CoreMsg,
) -> anyhow::Result<()> {
  tokio::time::timeout(
    SOCKET_WRITE_TIMEOUT,
    socket.send(Message::text(serde_json::to_string(msg)?)),
  )
  .await
  .map_err(|_| anyhow::anyhow!("发送 WebSocket 消息超时"))??;
  Ok(())
}

/// 协议版本是否兼容。旧 agent（含不发这个字段的 0）只能明文连接，只接受升级请求。
fn protocol_ok(agent: u32) -> bool {
  agent == PROTOCOL
}

/// 握手之后的收发：新 agent 全部加密；旧 agent 明文，只用于下发升级。
enum Wire {
  Plain,
  Sealed(Sealer, Opener),
}

impl Wire {
  fn encode(&mut self, msg: &CoreMsg) -> anyhow::Result<Message> {
    let text = serde_json::to_string(msg)?;
    Ok(match self {
      Wire::Plain => Message::text(text),
      Wire::Sealed(tx, _) => {
        Message::binary(tx.seal(text.as_bytes()))
      }
    })
  }

  /// `Ok(None)`：不是这种通道该收的帧，忽略。解密失败返回错误，调用方断开。
  fn decode(
    &mut self,
    msg: Message,
  ) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(match (self, msg) {
      (Wire::Plain, Message::Text(t)) => Some(t.as_bytes().to_vec()),
      (Wire::Sealed(_, rx), Message::Binary(b)) => Some(rx.open(&b)?),
      _ => None,
    })
  }
}

async fn handle_socket(
  state: Arc<AppState>,
  mut socket: WebSocket,
) -> anyhow::Result<()> {
  let nonce = random_nonce();
  send_msg(
    &mut socket,
    &CoreMsg::Challenge {
      nonce: nonce.clone(),
    },
  )
  .await?;
  let hello: AgentMsg =
    serde_json::from_str(&recv_text(&mut socket).await?)?;
  let AgentMsg::Hello {
    server,
    public_key,
    signature,
    nonce: agent_nonce,
    kx: agent_kx,
    version,
    protocol,
    host_shell,
    runtime_v2,
    monitor_v2,
    task_artifacts,
    backfill,
    forward,
    service_checks,
    container_diagnosis,
    access_logs,
    net_probe,
    container_probe,
    ssh_logins,
    gateway_extra_files,
    core_probe,
    backup_isolation,
    safe_delete,
    named_networks_v1,
    compose_env_v2,
    safe_host_bind_v2,
    project_files_v2,
    workload_egress_v1,
    service_runtime_opts,
    live_limits_update,
    task_resource_limits,
    data_cleanup,
    exec_v2,
    files_v2,
    extra_logs_v1,
    shared_volumes,
    safe_gateway,
    gateway_probe,
    frpc_reload,
    safe_adopt,
    safe_migrate,
    migrate_v2,
    service_copy,
    crash_guard,
    service_repair,
    data_ops,
    safe_backup,
    backup_move,
    backup_v2,
    build_v2,
    deploy_v2,
    safe_rollback,
    key_rotation,
  } = hello
  else {
    anyhow::bail!("agent 没有先发 hello");
  };
  // 协议不一致也放行（认证照做），只接受升级请求，否则 agent 永远收不到升级指令。
  // 协议版本对但没交换密钥：不是正常 agent，拒绝。
  if protocol_ok(protocol) && agent_kx.is_none() {
    anyhow::bail!("服务器 {server} 的 agent 没有交换会话密钥");
  }
  let upgrade_only = !protocol_ok(protocol) || agent_kx.is_none();
  let key_rotation = key_rotation && !upgrade_only;
  if upgrade_only {
    tracing::warn!(
      "服务器 {server} 的 agent 协议版本 {protocol}，控制面要求 {PROTOCOL}：只接受升级请求，请运行 wharf upgrade"
    );
  }
  let registered = {
    let server = server.clone();
    let public = public_key.clone();
    state
      .db
      .call(move |c| {
        crate::key_rotation::accepts_agent(
          c,
          &server,
          &public,
          key_rotation,
        )
      })
      .await?
  };
  let verified = registered
    && decode_key(&public_key)
      .zip(decode_sig(&signature))
      .is_some_and(|(key, sig)| {
        key
          .verify(
            &match &agent_kx {
              Some(kx) => {
                auth_payload_v2("agent", &server, &nonce, kx)
              }
              None => auth_payload("agent", &server, &nonce),
            },
            &sig,
          )
          .is_ok()
      });
  if !verified {
    let _ = tokio::time::timeout(
      SOCKET_WRITE_TIMEOUT,
      socket.send(Message::Close(Some(axum::extract::ws::CloseFrame {
        code: 4001,
        reason: "认证失败：服务器未加入或密钥不匹配，请重新 wharf server add".into(),
      }))),
    )
    .await;
    anyhow::bail!("服务器 {server} 认证失败");
  }
  let keys = state.core_keys();
  let (welcome, mut wire) = match &agent_kx {
    Some(akx) => {
      let share = KeyShare::generate();
      let kx = share.public.clone();
      let (signature, alt_signature) = keys.sign(&auth_payload_v2(
        "core",
        &server,
        &agent_nonce,
        &format!("{kx},{akx}"),
      ));
      let (tx, rx) = share
        .finish(akx, &format!("{nonce}{agent_nonce}"), Role::Core)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
      (
        CoreMsg::Welcome {
          backfill: !upgrade_only,
          signature,
          alt_signature: if key_rotation {
            alt_signature
          } else {
            None
          },
          confirm_key: key_rotation,
          kx: Some(kx),
        },
        Wire::Sealed(tx, rx),
      )
    }
    None => {
      let (signature, _) =
        keys.sign(&auth_payload("core", &server, &agent_nonce));
      (
        CoreMsg::Welcome {
          backfill: !upgrade_only,
          signature,
          alt_signature: None,
          confirm_key: false,
          kx: None,
        },
        Wire::Plain,
      )
    }
  };
  send_msg(&mut socket, &welcome).await?;

  // 第一个加密帧证明 agent 已验过 Welcome，之后才能提升注册公钥。
  let (authenticated_core, trusted_primary, trusted_alt) =
    if key_rotation {
      let (public, primary, alt) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
          while let Some(msg) = socket.recv().await.transpose()? {
            if let Some(text) = wire.decode(msg)? {
              if let AgentMsg::KeyReady {
                core_public_key,
                trusted_primary,
                trusted_alt,
              } = serde_json::from_slice(&text)?
              {
                return anyhow::Ok((
                  core_public_key,
                  trusted_primary,
                  trusted_alt,
                ));
              }
              break;
            }
          }
          anyhow::bail!("agent 未确认加密握手");
        })
        .await??;
      anyhow::ensure!(
        public == keys.public_key()
          || keys.previous_public_key().as_deref() == Some(&public),
        "agent 确认了未知的控制面公钥"
      );
      (Some(public), primary, alt)
    } else {
      (None, None, None)
    };

  let (tx, mut rx) = mpsc::channel(4096);
  let conn = Conn {
    conn_id: state.hub.next_conn.fetch_add(1, Ordering::Relaxed),
    public_key,
    core_probe: core_probe && !upgrade_only,
    key_rotation,
    authenticated_core,
    tx,
    pending: Default::default(),
    closed: CancellationToken::new(),
    rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
    host_shell,
    runtime_v2,
    monitor_v2,
    task_artifacts,
    backfill,
    forward,
    service_checks,
    container_diagnosis,
    access_logs,
    net_probe,
    container_probe,
    ssh_logins,
    gateway_extra_files,
    backup_isolation,
    safe_delete,
    named_networks_v1,
    compose_env_v2,
    safe_host_bind_v2,
    project_files_v2,
    workload_egress_v1,
    service_runtime_opts,
    live_limits_update,
    task_resource_limits,
    data_cleanup,
    exec_v2,
    files_v2,
    extra_logs_v1,
    shared_volumes,
    safe_gateway,
    gateway_probe,
    frpc_reload,
    safe_adopt,
    safe_migrate,
    migrate_v2,
    service_copy,
    crash_guard,
    service_repair,
    data_ops,
    safe_backup,
    backup_move,
    backup_v2,
    build_v2,
    deploy_v2,
    safe_rollback,
    upgrade_only,
  };
  let state_on_db = state.clone();
  let socket_server = server.clone();
  let socket_conn = conn.clone();
  state
    .db
    .call(move |c| {
      crate::key_rotation::register_agent_key(
        c,
        &socket_server,
        &socket_conn.public_key,
        key_rotation,
      )?;
      state_on_db.hub.register(&socket_server, socket_conn);
      Ok(())
    })
    .await?;
  if key_rotation {
    let ack = wire.encode(&CoreMsg::KeyAccepted)?;
    if !matches!(
      tokio::time::timeout(SOCKET_WRITE_TIMEOUT, socket.send(ack))
        .await,
      Ok(Ok(()))
    ) {
      conn.closed.cancel();
      state.hub.unregister(&server, &conn);
      anyhow::bail!("发送握手确认失败");
    }
    tokio::spawn(crate::key_rotation::sync_agent(
      state.clone(),
      server.clone(),
      conn.conn_id,
      trusted_primary,
      trusted_alt,
    ));
  }
  if conn.core_probe {
    crate::core_node::spawn_probe_on_connect(
      state.clone(),
      server.clone(),
      conn.conn_id,
      conn.closed.clone(),
    );
  }
  tracing::info!("服务器 {server} 上线（agent {version}）");
  let seen = server.clone();
  state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE agents SET last_seen = ?1 WHERE server = ?2",
        params![now_ms(), seen],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  crate::service_monitor::sync_watches(&state, Some(&server)).await;

  let (mut sink, mut stream) = socket.split();
  let mut ping = tokio::time::interval(PING_EVERY);
  let mut last_recv = tokio::time::Instant::now();
  let mut ping_sent: Option<tokio::time::Instant> = None;
  let reports = Arc::new(ReportSlot::default());
  let mut backfill_open = conn.backfill && !conn.upgrade_only;
  let report_task = tokio::spawn(report_worker(
    state.clone(),
    server.clone(),
    conn.clone(),
    reports.clone(),
  ));
  let result: anyhow::Result<()> = loop {
    tokio::select! {
      biased;
      _ = conn.closed.cancelled() => break Ok(()),
      out = rx.recv() => {
        let Some(out) = out else { break Ok(()) };
        match tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(wire.encode(&out)?)).await {
          Ok(Ok(())) => {}
          Ok(Err(e)) => break Err(e.into()),
          Err(_) => break Err(anyhow::anyhow!("发送 WebSocket 消息超时")),
        }
      }
      _ = ping.tick() => {
        // agent 每 30 秒上报一次，再加上 pong，正常连接不会这么久没消息。
        if last_recv.elapsed() > IDLE_TIMEOUT {
          break Err(anyhow::anyhow!("{} 秒没有收到消息", IDLE_TIMEOUT.as_secs()));
        }
        match tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(Message::Ping(Default::default()))).await {
          Ok(Ok(())) => {}
          Ok(Err(e)) => break Err(e.into()),
          Err(_) => break Err(anyhow::anyhow!("发送 WebSocket ping 超时")),
        }
        ping_sent = Some(tokio::time::Instant::now());
      }
      incoming = stream.next() => {
        let msg = match incoming {
          None => break Ok(()),
          Some(Err(e)) => break Err(e.into()),
          Some(Ok(msg)) => msg,
        };
        last_recv = tokio::time::Instant::now();
        let text = match msg {
          Message::Close(_) => break Ok(()),
          Message::Pong(_) => {
            if let Some(sent) = ping_sent.take() {
              conn.rtt_ms.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            continue;
          }
          msg => match wire.decode(msg) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(e) => break Err(e),
          },
        };
        match serde_json::from_slice::<AgentMsg>(&text) {
          Ok(AgentMsg::Backfill { mut samples, dropped })
            if std::mem::take(&mut backfill_open) && state.hub.supports_backfill(&server) =>
          {
            samples.truncate(20);
            reports.push_backfill(now_ms(), samples, dropped);
          }
          Ok(AgentMsg::Backfill { .. }) => {
            tracing::debug!("忽略服务器 {server} 的重复或不支持的断连补传");
          }
          Ok(AgentMsg::Report(mut report)) => {
            backfill_open = false;
            use crate::report_guard::RateDecision::*;
            match state.hub.report_rate.check(&server, conn.conn_id, report.metrics.is_some(), std::time::Instant::now()) {
              DropAll => continue,
              AcceptNoMetrics => report.metrics = None,
              AcceptAll => {}
            }
            let mut hits = std::mem::take(&mut report.log_hits);
            crate::report_guard::sanitize_log_hits(&mut hits);
            if !conn.closed.is_cancelled() {
              crate::service_monitor::report(&server, hits);
            }
            reports.push(now_ms(), *report);
          }
          Ok(msg @ (AgentMsg::Progress { .. } | AgentMsg::Response { .. })) => {
            conn.deliver_reply(msg);
          }
          Ok(AgentMsg::Hello { .. } | AgentMsg::KeyReady { .. }) => {}
          Err(e) => tracing::debug!("无法解析 {server} 的消息：{:?}", e.classify()),
        }
      }
    }
  };
  conn.closed.cancel();
  report_task.abort();
  state.hub.unregister(&server, &conn);
  tracing::info!("服务器 {server} 离线");
  result
}

#[derive(Default)]
struct ReportSlot {
  latest: Mutex<Option<(i64, AgentReport)>>,
  backfill: Mutex<Option<(i64, Vec<BufferedSample>, u32)>>,
  ready: tokio::sync::Notify,
}

impl ReportSlot {
  fn push(&self, received: i64, report: AgentReport) {
    *lock(&self.latest) = Some((received, report));
    self.ready.notify_one();
  }

  fn push_backfill(
    &self,
    received: i64,
    samples: Vec<BufferedSample>,
    dropped: u32,
  ) {
    *lock(&self.backfill) = Some((received, samples, dropped));
    self.ready.notify_one();
  }

  async fn next(&self) -> IncomingReport {
    loop {
      if let Some((received, samples, dropped)) =
        lock(&self.backfill).take()
      {
        return IncomingReport::Backfill(received, samples, dropped);
      }
      if let Some((at, report)) = lock(&self.latest).take() {
        return IncomingReport::Live(at, Box::new(report));
      }
      self.ready.notified().await;
    }
  }
}

enum IncomingReport {
  Backfill(i64, Vec<BufferedSample>, u32),
  Live(i64, Box<AgentReport>),
}

async fn ingest_backfill(
  state: &Arc<AppState>,
  server: &str,
  public_key: &str,
  now: i64,
  mut samples: Vec<BufferedSample>,
  alerts: &crate::rules::resources::ReportQueue,
) -> Result<usize, ApiError> {
  let (name, key) = (server.to_string(), public_key.to_string());
  let (world, deployed, pending, mut last) = state.db.call(move |c| {
    if !crate::db::agents(c)?.iter().any(|a| a.server == name && a.public_key.as_deref() == Some(key.as_str())) {
      return Err(ApiError::not_found("agent 已取消注册"));
    }
    let world = crate::world::World::from_rows(crate::db::all_resources(c)?)?;
    let deployed = crate::db::deployed_servers(c)?;
    let last = c.query_row(
      "SELECT MAX(at) FROM points WHERE subject = ?1 AND name = 'host.net_rx'",
      [&name], |r| r.get::<_, Option<i64>>(0),
    ).map_err(sql_err)?.unwrap_or(i64::MIN);
    Ok((world, deployed, crate::pending::load(c)?, last))
  }).await?;
  samples.retain(|s| {
    // 后续实时报告可能在同一毫秒收到，补传只能排在它之前。
    (now - 20 * 60_000..now).contains(&s.at_ms)
  });
  samples.sort_by_key(|s| s.at_ms);
  let settings =
    crate::rules::resources::settings(state, server).await;
  let mut applied = 0;
  for sample in samples {
    let at = sample.at_ms;
    if at <= last {
      continue;
    }
    last = at;
    let mut hits = sample.log_hits;
    crate::report_guard::sanitize_log_hits(&mut hits);
    crate::service_monitor::report_at(server, at, hits);
    if let Some(mut m) = sample.metrics {
      crate::report_guard::sanitize_metrics(&mut m);
      crate::report_guard::filter_owned_metrics(
        server, &mut m, &world, &deployed, &pending,
      );
      let oom = m.oom.take();
      let hosts = std::mem::take(&mut m.hosts);
      if !hosts.is_empty() {
        crate::http_stats::record_at(state, server, at, hosts).await;
      }
      crate::metrics::record_report_at(state, server, at, &m).await;
      if let Some((_, limits)) = &settings {
        alerts.push_backfill((at, m, limits.clone(), None)).await;
      }
      crate::oom::record_at(state, server, at, oom).await;
    }
    applied += 1;
  }
  Ok(applied)
}

async fn report_worker(
  state: Arc<AppState>,
  server: String,
  conn: Conn,
  reports: Arc<ReportSlot>,
) {
  let mut agent_memory = None;
  let alerts = crate::rules::resources::report_queue(
    state.clone(),
    server.clone(),
    conn.closed.clone(),
  );
  let process = async {
    loop {
      let (received, report) = match reports.next().await {
        IncomingReport::Live(at, report) => (at, *report),
        IncomingReport::Backfill(received, samples, dropped) => {
          match ingest_backfill(
            &state,
            &server,
            &conn.public_key,
            received,
            samples,
            &alerts,
          )
          .await
          {
            Ok(applied) if applied > 0 || dropped > 0 => {
              tracing::info!(
                "服务器 {server} 补传 {applied} 条断连采样（淘汰 {dropped} 条）"
              )
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
              "服务器 {server} 补传失败：{}",
              e.message
            ),
          }
          continue;
        }
      };
      let mut report = match crate::report_guard::record_report(
        &state.db,
        &server,
        &conn.public_key,
        report,
      )
      .await
      {
        Ok(report) => report,
        Err(e) => {
          tracing::warn!("校验服务器 {server} 上报失败：{e}");
          continue;
        }
      };
      let agent_ms = report.time_ms;
      crate::clock::record(&state, &server, agent_ms).await;
      let settings =
        crate::rules::resources::settings(&state, &server).await;
      if !conn.upgrade_only
        && let Some(bytes) = settings.as_ref().map(|s| s.0)
        && agent_memory != Some(bytes)
        && conn.tx.try_send(CoreMsg::AgentMemory { bytes }).is_ok()
      {
        agent_memory = Some(bytes);
      }
      if let Some(m) = report.metrics.as_mut() {
        let oom = m.oom.take();
        let hosts = std::mem::take(&mut m.hosts);
        if !hosts.is_empty() {
          crate::http_stats::record_at(
            &state, &server, received, hosts,
          )
          .await;
        }
        crate::metrics::record_report_at(
          &state, &server, received, m,
        )
        .await;
        if let Some((wanted, limits)) = settings {
          let limit = report
            .agent_memory
            .as_ref()
            .and_then(|m| m.limit)
            .filter(|_| wanted > 0);
          alerts.push((received, m.as_ref().clone(), limits, limit));
        }
        crate::oom::record_at(&state, &server, received, oom).await;
      }
    }
  };
  tokio::select! {
    _ = conn.closed.cancelled() => {},
    _ = process => {},
  }
}

fn shared_volumes_required(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!(
      "服务器 {server} 的 agent 版本较旧，缺少共享挂载占用检查"
    ),
  )
  .with_hint("请先运行 wharf upgrade 升级 agent，再重试")
  .suggest("wharf upgrade")
}

#[cfg(test)]
mod tests;

fn data_ops_required(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，不支持数据收编或推拉"),
  )
  .with_hint("先升级 agent：wharf upgrade")
}

fn migrate_v2_required(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，不支持迁移预检或限速"),
  )
  .with_hint("先升级 agent：wharf upgrade")
}

pub(crate) fn safe_migrate_required(server: &str) -> ApiError {
  ApiError::new(ErrorCode::Conflict, format!("服务器 {server} 的 agent 版本旧，无法安全同步数据或更新停机服务"))
    .with_hint("先运行 wharf upgrade 升级 agent 后重试")
    .suggest("wharf upgrade")
}
