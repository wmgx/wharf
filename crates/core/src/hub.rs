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
  agent::{AgentMsg, AgentOp, CoreMsg, TerminalInput, auth_payload},
};

use crate::{
  db::{now_ms, sql_err},
  state::AppState,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
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
  tx: mpsc::Sender<CoreMsg>,
  pending: Arc<Mutex<HashMap<u64, Pending>>>,
  closed: CancellationToken,
  /// 最近一次 ping 的往返延迟，毫秒。
  rtt_ms: Arc<AtomicU64>,
  host_shell: bool,
}

#[derive(Default)]
pub struct Hub {
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
  pub fn is_online(&self, server: &str) -> bool {
    lock(&self.conns).contains_key(server)
  }

  pub fn supports_host_shell(&self, server: &str) -> bool {
    lock(&self.conns)
      .get(server)
      .is_some_and(|conn| conn.host_shell)
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
    let (done, rx) = oneshot::channel();
    lock(&conn.pending).insert(id, Pending { done, progress });
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
      _ = tokio::time::sleep(timeout + GRACE) => Err(abort(
        ErrorCode::Timeout,
        format!("服务器 {server} 超过 {} 秒没有响应", timeout.as_secs()),
      )),
      _ = cancel.cancelled() => Err(abort(
        ErrorCode::Cancelled,
        "已取消".to_string(),
      )),
    };
    let value = result?;
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
  ws.on_upgrade(move |socket| async move {
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
  socket
    .send(Message::text(serde_json::to_string(msg)?))
    .await?;
  Ok(())
}

/// 协议版本是否兼容：0 是旧 agent（不发这个字段），必须放行；其余版本必须相等。
fn protocol_ok(agent: u32) -> bool {
  agent == 0 || agent == PROTOCOL
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
    version,
    protocol,
    host_shell,
  } = hello
  else {
    anyhow::bail!("agent 没有先发 hello");
  };
  if !protocol_ok(protocol) {
    let reason = format!(
      "agent 协议版本 {protocol}，控制面要求 {PROTOCOL}，请运行 wharf upgrade"
    );
    tracing::warn!("服务器 {server} 拒绝连接：{reason}");
    let _ = socket
      .send(Message::Close(Some(axum::extract::ws::CloseFrame {
        code: 4002,
        reason: reason.clone().into(),
      })))
      .await;
    anyhow::bail!("{reason}");
  }
  let registered = {
    let server = server.clone();
    state
      .db
      .call(move |c| crate::db::agent(c, &server))
      .await
      .map_err(|e| anyhow::anyhow!("{e}"))?
      .and_then(|a| a.public_key)
  };
  let verified = registered.as_deref() == Some(public_key.as_str())
    && decode_key(&public_key)
      .zip(decode_sig(&signature))
      .is_some_and(|(key, sig)| {
        key
          .verify(&auth_payload("agent", &server, &nonce), &sig)
          .is_ok()
      });
  if !verified {
    let _ = socket
      .send(Message::Close(Some(axum::extract::ws::CloseFrame {
        code: 4001,
        reason: "认证失败：服务器未加入或密钥不匹配，请重新 wharf server add".into(),
      })))
      .await;
    anyhow::bail!("服务器 {server} 认证失败");
  }
  if protocol == 0 {
    // 线上旧 agent 不发这个字段。不能拒绝，否则控制面一升级所有 agent 都连不上。
    tracing::warn!(
      "服务器 {server} 的 agent 没有上报协议版本（旧版本），按兼容处理，建议运行 wharf upgrade"
    );
  }
  let welcome =
    state.key.sign(&auth_payload("core", &server, &agent_nonce));
  send_msg(
    &mut socket,
    &CoreMsg::Welcome {
      signature: hex::encode(welcome.to_bytes()),
    },
  )
  .await?;

  let (tx, mut rx) = mpsc::channel(4096);
  let conn = Conn {
    conn_id: state.hub.next_conn.fetch_add(1, Ordering::Relaxed),
    tx,
    pending: Default::default(),
    closed: CancellationToken::new(),
    rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
    host_shell,
  };
  state.hub.register(&server, conn.clone());
  tracing::info!("服务器 {server} 上线（agent {version}）");
  touch(&state, &server, None).await;

  let (mut sink, mut stream) = socket.split();
  let mut ping = tokio::time::interval(PING_EVERY);
  let mut last_recv = tokio::time::Instant::now();
  let mut ping_sent: Option<tokio::time::Instant> = None;
  let result: anyhow::Result<()> = loop {
    tokio::select! {
      _ = conn.closed.cancelled() => break Ok(()),
      out = rx.recv() => {
        let Some(out) = out else { break Ok(()) };
        if let Err(e) = sink.send(Message::text(serde_json::to_string(&out)?)).await {
          break Err(e.into());
        }
      }
      _ = ping.tick() => {
        // agent 每 30 秒上报一次，再加上 pong，正常连接不会这么久没消息。
        if last_recv.elapsed() > IDLE_TIMEOUT {
          break Err(anyhow::anyhow!("{} 秒没有收到消息", IDLE_TIMEOUT.as_secs()));
        }
        if let Err(e) = sink.send(Message::Ping(Default::default())).await {
          break Err(e.into());
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
          Message::Text(text) => text,
          Message::Close(_) => break Ok(()),
          Message::Pong(_) => {
            if let Some(sent) = ping_sent.take() {
              conn.rtt_ms.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            continue;
          }
          _ => continue,
        };
        match serde_json::from_str::<AgentMsg>(&text) {
          Ok(AgentMsg::Report(mut report)) => {
            if let Some(m) = report.metrics.take() {
              crate::metrics::record_report(&state, &server, *m).await;
            }
            touch(&state, &server, Some(report)).await
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
          Ok(AgentMsg::Hello { .. }) => {}
          Err(e) => tracing::warn!("无法解析 {server} 的消息：{e}"),
        }
      }
    }
  };
  state.hub.unregister(&server, &conn);
  tracing::info!("服务器 {server} 离线");
  result
}

/// 记录最后在线时间和上报内容。
pub(crate) async fn touch(
  state: &AppState,
  server: &str,
  report: Option<wharf_api_types::agent::AgentReport>,
) {
  let server = server.to_string();
  let report = report.and_then(|r| serde_json::to_string(&r).ok());
  let result = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE agents SET last_seen = ?1, report = COALESCE(?2, report) WHERE server = ?3",
        params![now_ms(), report, server],
      )
      .map_err(sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录 agent 状态失败：{e}");
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn protocol_gate() {
    // 旧 agent 不发 protocol 字段，控制面升级后必须还能连上
    assert!(protocol_ok(0));
    assert!(protocol_ok(PROTOCOL));
    assert!(!protocol_ok(PROTOCOL + 1));
    assert!(!protocol_ok(u32::MAX));
  }

  #[test]
  fn old_hello_has_no_host_shell_capability() {
    let hello: AgentMsg = serde_json::from_value(serde_json::json!({
      "type": "hello",
      "server": "s1",
      "public_key": "k",
      "signature": "s",
      "nonce": "n",
      "version": "0.1.0",
      "protocol": 1
    }))
    .unwrap();
    let AgentMsg::Hello { host_shell, .. } = hello else {
      panic!("不是 hello");
    };
    assert!(!host_shell);
  }
}
