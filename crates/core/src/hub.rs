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
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rusqlite::params;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode, PROTOCOL,
  agent::{
    AgentMsg, AgentOp, CoreMsg, TerminalInput, auth_payload,
    auth_payload_v2,
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
  tx: mpsc::Sender<CoreMsg>,
  pending: Arc<Mutex<HashMap<u64, Pending>>>,
  closed: CancellationToken,
  /// 最近一次 ping 的往返延迟，毫秒。
  rtt_ms: Arc<AtomicU64>,
  host_shell: bool,
  forward: bool,
  service_checks: bool,
  container_diagnosis: bool,
  access_logs: bool,
  net_probe: bool,
  container_probe: bool,
  ssh_logins: bool,
  /// 协议版本不一致：连接放行，但只接受升级相关的请求，好让它升上来。
  upgrade_only: bool,
}

impl Conn {
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

pub fn offline(server: &str) -> ApiError {
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

  pub fn supports_service_checks(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.service_checks)
  }

  pub fn supports_container_diagnosis(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|c| !c.upgrade_only && c.container_diagnosis)
  }

  pub fn supports_net_probe(
    &self,
    server: &str,
    container: bool,
  ) -> Result<(), ApiError> {
    let conns = lock(&self.conns);
    let conn = conns.get(server).ok_or_else(|| offline(server))?;
    conn.check_net_probe(server, container)
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
    Self::call_conn(id, server, conn, op, timeout, progress, cancel)
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
      progress,
      cancel,
    )
    .await
  }

  async fn call_conn<T: DeserializeOwned>(
    id: u64,
    server: &str,
    conn: Conn,
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
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
    let (done, rx) = oneshot::channel();
    lock(&conn.pending).insert(id, Pending { done, progress });
    let _in_flight = InFlight { conn: &conn, id };
    let sent = tokio::time::timeout(
      Duration::from_secs(5),
      conn.tx.send(CoreMsg::Request {
        id,
        timeout_ms: timeout.as_millis() as u64,
        op,
      }),
    )
    .await;
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
      result = rx => result.unwrap_or_else(|_| Err(offline(server))),
      _ = conn.closed.cancelled() => Err(offline(server)),
      _ = tokio::time::sleep(timeout + GRACE) => Err(abort(
        ErrorCode::Timeout,
        format!("服务器 {server} 超过 {} 秒没有响应", timeout.as_secs()),
      )),
      _ = cancel.cancelled() => Err(abort(
        ErrorCode::Cancelled,
        "已取消".to_string(),
      )),
    };
    let value = result.map_err(|e| {
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

mod socket;
pub use socket::agent_ws;

#[cfg(test)]
mod tests;
