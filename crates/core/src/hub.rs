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
  key_rotation: bool,
  authenticated_core: Option<String>,
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
  gateway_extra_files: bool,
  backup_isolation: bool,
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
  let keys = state.key.read();
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
  let authenticated_core = if key_rotation {
    let public = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
      while let Some(msg) = socket.recv().await.transpose()? {
        if let Some(text) = wire.decode(msg)? {
          if let AgentMsg::KeyReady { core_public_key } =
            serde_json::from_slice(&text)?
          {
            return anyhow::Ok(core_public_key);
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
    Some(public)
  } else {
    None
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
    forward,
    service_checks,
    container_diagnosis,
    access_logs,
    net_probe,
    container_probe,
    ssh_logins,
    gateway_extra_files,
    backup_isolation,
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
    if conn.authenticated_core.as_deref()
      != Some(keys.public_key().as_str())
    {
      tokio::spawn(crate::key_rotation::sync_agent(
        state.clone(),
        server.clone(),
        conn.conn_id,
      ));
    }
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
  let mut agent_memory = None;
  let alerts = crate::rules::resources::report_queue(
    state.clone(),
    server.clone(),
    conn.closed.clone(),
  );
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
          Ok(AgentMsg::Report(mut report)) => {
            use crate::report_guard::RateDecision::*;
            match state.hub.report_rate.check(&server, conn.conn_id, report.metrics.is_some(), std::time::Instant::now()) {
              DropAll => continue,
              AcceptNoMetrics => report.metrics = None,
              AcceptAll => {}
            }
            let mut report = match crate::report_guard::record_report(&state.db, &server, &conn.public_key, *report).await {
              Ok(report) if !conn.closed.is_cancelled() => report,
              Ok(_) => continue,
              Err(e) => {
                tracing::warn!("校验服务器 {server} 上报失败：{e}");
                continue;
              }
            };
            crate::service_monitor::report(&server, std::mem::take(&mut report.log_hits));
            let received = now_ms();
            let agent_ms = report.time_ms;
            crate::clock::record(&state, &server, agent_ms).await;
            let settings = crate::rules::resources::settings(&state, &server).await;
            if !conn.upgrade_only && let Some(bytes) = settings.as_ref().map(|s| s.0)
              && agent_memory != Some(bytes)
              && conn.tx.try_send(CoreMsg::AgentMemory { bytes }).is_ok()
            {
              agent_memory = Some(bytes);
            }
            if let Some(m) = report.metrics.as_mut() {
              let oom = m.oom.take();
              let hosts = std::mem::take(&mut m.hosts);
              if !hosts.is_empty() {
                tokio::spawn(crate::http_stats::record(state.clone(), server.clone(), hosts));
              }
              crate::metrics::record_report(&state, &server, m).await;
              if let Some((wanted, limits)) = settings {
                let limit = report.agent_memory.as_ref().and_then(|m| m.limit).filter(|_| wanted > 0);
                let _ = alerts.try_send((received, m.as_ref().clone(), limits, limit));
              }
              let state = state.clone();
              let server = server.clone();
              tokio::spawn(async move {
                crate::oom::record(&state, &server, oom).await;
              });
            }
          }
          Ok(AgentMsg::Progress { id, line }) => {
            let progress = lock(&conn.pending).get(&id).and_then(|p| p.progress.clone());
            if let Some(progress) = progress {
              progress(line);
            }
          }
          Ok(AgentMsg::Response { id, result }) => {
            if let Some(pending) = lock(&conn.pending).remove(&id) {
              let _ = pending.done.send(result);
            }
          }
          Ok(AgentMsg::Hello { .. } | AgentMsg::KeyReady { .. }) => {}
          Err(e) => tracing::debug!("无法解析 {server} 的消息：{:?}", e.classify()),
        }
      }
    }
  };
  conn.closed.cancel();
  state.hub.unregister(&server, &conn);
  tracing::info!("服务器 {server} 离线");
  result
}

#[cfg(test)]
mod tests;
