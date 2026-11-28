//! 和控制面的 websocket 连接：握手、断线重连、请求分发、心跳。

use std::{
  collections::HashMap,
  path::Path,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};

use anyhow::{Context, anyhow, bail};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentMsg, AgentOp, BufferedSample, CoreMsg, TerminalInput,
    auth_payload_v2,
  },
  seal::{KeyShare, Role},
};

use crate::{
  backfill::{BackfillBuffer, unix_ms},
  exec::Ctx,
  identity::{self, Joined},
  ops::Ops,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const REPORT_EVERY: Duration = Duration::from_secs(30);
/// 这么久没收到控制面任何消息（包括 ping）就认为连接已死。
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug)]
struct AuthenticationFailed;

impl std::fmt::Display for AuthenticationFailed {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("控制面握手认证失败")
  }
}

impl std::error::Error for AuthenticationFailed {}

fn handle_auth_failure(
  data_dir: &Path,
  failures: &mut u8,
) -> anyhow::Result<bool> {
  if !identity::has_previous_key(data_dir) {
    *failures = 0;
    return Ok(false);
  }
  *failures = failures.saturating_add(1);
  if *failures < 3 {
    return Ok(false);
  }
  identity::rollback_key(data_dir)?;
  *failures = 0;
  Ok(true)
}

pub async fn run_forever(ops: Arc<Ops>) -> ! {
  let mut backoff = 1u64;
  let mut auth_failures = 0;
  let cursors = crate::log_watches::CursorStore::load(&ops.data_dir);
  tokio::spawn({
    let cursors = cursors.clone();
    async move {
      loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        cursors.save();
      }
    }
  });
  let hits = crate::log_watches::Hits::default();
  let cancel = CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  let mut watches = crate::log_watches::Watches::new(
    ops.docker.clone(),
    cancel.clone(),
    hits.clone(),
    cursors.clone(),
  );
  let telemetry = Arc::new(Telemetry {
    online: AtomicBool::new(false),
    buffer: Mutex::new(BackfillBuffer::default()),
    hits,
  });
  tokio::spawn(sample_offline(
    ops.clone(),
    telemetry.clone(),
    cancel,
  ));
  loop {
    let result = async {
      let joined = Joined::load(&ops.data_dir)?
        .context("agent 没有加入控制面")?;
      let key = identity::load_key(&ops.data_dir)?;
      session(&joined, &key, ops.clone(), &mut watches, &telemetry)
        .await
    }
    .await;
    cursors.save();
    match result {
      Ok(true) => {
        backoff = 1;
        auth_failures = 0;
        continue;
      }
      Ok(false) => {
        tracing::warn!("与控制面的连接断开");
        backoff = 1;
        auth_failures = 0;
      }
      Err(e) => {
        tracing::warn!("连接控制面失败：{e:#}");
        if e.is::<AuthenticationFailed>() {
          match handle_auth_failure(&ops.data_dir, &mut auth_failures)
          {
            Ok(true) => {
              tracing::warn!(
                "新 agent 密钥连续 3 次认证失败，已恢复旧密钥"
              );
              backoff = 1;
              continue;
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("恢复旧 agent 密钥失败：{e}"),
          }
        } else {
          auth_failures = 0;
        }
      }
    }
    let jitter = (std::process::id() as u64 + backoff) % 3;
    tokio::time::sleep(Duration::from_secs(backoff + jitter)).await;
    backoff = (backoff * 2).min(30);
  }
}

struct Telemetry {
  online: AtomicBool,
  buffer: Mutex<BackfillBuffer>,
  hits: crate::log_watches::Hits,
}

struct Online<'a>(&'a AtomicBool);

impl Drop for Online<'_> {
  fn drop(&mut self) {
    self.0.store(false, Ordering::Release);
  }
}

async fn sample_offline(
  ops: Arc<Ops>,
  telemetry: Arc<Telemetry>,
  cancel: CancellationToken,
) {
  let ctx = Ctx {
    cancel: cancel.clone(),
    progress: None,
  };
  let mut tick = tokio::time::interval(Duration::from_secs(60));
  tick
    .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  tick.tick().await;
  loop {
    tokio::select! {
      _ = cancel.cancelled() => break,
      _ = tick.tick() => {}
    }
    if telemetry.online.load(Ordering::Acquire) {
      continue;
    }
    let mut buffer = telemetry.buffer.lock().await;
    if telemetry.online.load(Ordering::Acquire) {
      continue;
    }
    let metrics = ops.reporter.metrics(&ctx).await;
    let log_hits =
      std::mem::take(&mut *telemetry.hits.lock().unwrap())
        .into_values()
        .collect();
    let at_ms = unix_ms();
    buffer.push(
      BufferedSample {
        at_ms,
        metrics,
        log_hits,
      },
      at_ms,
    );
  }
}

fn random_nonce() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

type HandshakeSocket = tokio_tungstenite::WebSocketStream<
  tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn handshake(
  joined: &Joined,
  key: &SigningKey,
  data_dir: &Path,
) -> anyhow::Result<(
  HandshakeSocket,
  wharf_api_types::seal::Sealer,
  wharf_api_types::seal::Opener,
  bool,
)> {
  let url = joined.ws_url();
  let (mut ws, _) = tokio::time::timeout(
    HANDSHAKE_TIMEOUT,
    tokio_tungstenite::connect_async(&url),
  )
  .await
  .context("连接超时")?
  .with_context(|| format!("连接 {url}"))?;

  // 握手
  let challenge = next_core_msg(&mut ws).await?;
  let CoreMsg::Challenge { nonce } = challenge else {
    bail!("控制面没有先发 challenge");
  };
  let my_nonce = random_nonce();
  let share = KeyShare::generate();
  let my_kx = share.public.clone();
  let hello = AgentMsg::Hello {
    server: joined.server.clone(),
    public_key: hex::encode(key.verifying_key().to_bytes()),
    signature: hex::encode(
      key
        .sign(&auth_payload_v2(
          "agent",
          &joined.server,
          &nonce,
          &my_kx,
        ))
        .to_bytes(),
    ),
    nonce: my_nonce.clone(),
    kx: Some(my_kx.clone()),
    version: wharf_api_types::VERSION.to_string(),
    protocol: wharf_api_types::PROTOCOL,
    host_shell: true,
    runtime_v2: true,
    monitor_v2: true,
    task_artifacts: true,
    backfill: true,
    forward: true,
    service_checks: true,
    container_diagnosis: true,
    ssh_logins: true,
    gateway_extra_files: true,
    core_probe: true,
    backup_isolation: true,
    safe_delete: true,
    data_cleanup: true,
    exec_v2: true,
    shared_volumes: true,
    safe_gateway: true,
    gateway_probe: true,
    frpc_reload: true,
    safe_adopt: true,
    safe_migrate: true,
    migrate_v2: true,
    service_copy: true,
    crash_guard: true,
    service_repair: true,
    data_ops: true,
    safe_backup: true,
    backup_move: true,
    backup_v2: true,
    build_v2: true,
    deploy_v2: true,
    safe_rollback: true,
    key_rotation: true,
    access_logs: true,
    net_probe: true,
    container_probe: true,
    files_v2: true,
  };
  tokio::time::timeout(
    SOCKET_WRITE_TIMEOUT,
    ws.send(Message::text(serde_json::to_string(&hello)?)),
  )
  .await
  .context("发送 hello 超时")??;
  let CoreMsg::Welcome {
    signature,
    alt_signature,
    confirm_key,
    backfill,
    kx,
  } = next_core_msg(&mut ws).await?
  else {
    return Err(AuthenticationFailed.into());
  };
  let core_kx = kx.ok_or(AuthenticationFailed)?;
  let core_public_key = joined
    .verify_core(
      &auth_payload_v2(
        "core",
        &joined.server,
        &my_nonce,
        &format!("{core_kx},{my_kx}"),
      ),
      &signature,
      alt_signature.as_deref(),
    )
    .ok_or(AuthenticationFailed)?;
  let (mut sealer, mut opener) = share
    .finish(&core_kx, &format!("{nonce}{my_nonce}"), Role::Agent)
    .map_err(|_| AuthenticationFailed)?;
  if confirm_key {
    let ready = serde_json::to_vec(&AgentMsg::KeyReady {
      core_public_key,
      trusted_primary: Some(joined.core_public_key.clone()),
      trusted_alt: joined.core_public_key_alt.clone(),
    })?;
    tokio::time::timeout(
      SOCKET_WRITE_TIMEOUT,
      ws.send(Message::binary(sealer.seal(&ready))),
    )
    .await
    .context("发送握手确认超时")??;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
      while let Some(frame) = ws.next().await.transpose()? {
        match frame {
          Message::Binary(data) => {
            let plain =
              opener.open(&data).map_err(|_| AuthenticationFailed)?;
            if matches!(
              serde_json::from_slice(&plain)?,
              CoreMsg::KeyAccepted
            ) {
              return anyhow::Ok(());
            }
            return Err(AuthenticationFailed.into());
          }
          Message::Close(Some(frame))
            if u16::from(frame.code) == 4001 =>
          {
            return Err(AuthenticationFailed.into());
          }
          Message::Close(_) => break,
          _ => {}
        }
      }
      bail!("连接在等待密钥确认期间关闭");
    })
    .await
    .context("等待密钥确认超时")??;
    if let Err(e) = identity::confirm_key(data_dir) {
      tracing::warn!("清理已确认的旧身份密钥失败：{e}");
    }
  } else if identity::has_previous_key(data_dir) {
    return Err(AuthenticationFailed.into());
  }
  Ok((ws, sealer, opener, backfill))
}

async fn session(
  joined: &Joined,
  key: &SigningKey,
  ops: Arc<Ops>,
  watches: &mut crate::log_watches::Watches,
  telemetry: &Telemetry,
) -> anyhow::Result<bool> {
  let (ws, mut sealer, mut opener, backfill) =
    handshake(joined, key, &ops.data_dir).await?;
  let _online = Online(&telemetry.online);
  telemetry.online.store(true, Ordering::Release);
  let (mut sink, mut stream) = ws.split();
  {
    let mut buffer = telemetry.buffer.lock().await;
    if backfill {
      let (samples, dropped) = buffer.peek_all(unix_ms());
      if !samples.is_empty() || dropped > 0 {
        let plain = serde_json::to_vec(&AgentMsg::Backfill {
          samples,
          dropped,
        })?;
        tokio::time::timeout(
          SOCKET_WRITE_TIMEOUT,
          sink.send(Message::binary(sealer.seal(&plain))),
        )
        .await
        .context("发送断连采样超时")??;
      }
    }
    buffer.clear();
  }
  let hits = telemetry.hits.clone();
  let url = joined.ws_url();
  tracing::info!(
    "已连接控制面 {url}，服务器名 {}（通道已加密）",
    joined.server
  );

  let (mut outbound, tx, progress_tx, data_mux) =
    crate::outbound::Outbound::new();
  let session_cancel = CancellationToken::new();
  let reconnect_after = Arc::new(AtomicU64::new(0));
  let writer = {
    let reconnect_after = reconnect_after.clone();
    let cancel = session_cancel.clone();
    tokio::spawn(async move {
      while let Some(msg) = tokio::select! {
        _ = cancel.cancelled() => None,
        msg = outbound.recv() => msg,
      } {
        let reconnect = matches!(&msg, AgentMsg::Response { id, .. }
          if *id == reconnect_after.load(Ordering::Acquire));
        let Ok(text) = serde_json::to_string(&msg) else {
          continue;
        };
        if !matches!(
          tokio::time::timeout(
            SOCKET_WRITE_TIMEOUT,
            sink.send(Message::binary(sealer.seal(text.as_bytes()))),
          )
          .await,
          Ok(Ok(()))
        ) {
          break;
        }
        if reconnect {
          let _ =
            tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.close())
              .await;
          break;
        }
      }
      cancel.cancel();
    })
  };
  let (memory_tx, memory_rx) = watch::channel(None);
  let (memory_status, memory_report) = watch::channel(None);
  tokio::spawn(crate::agent_memory::configure(
    ops.docker.clone(),
    memory_rx,
    memory_status,
    session_cancel.clone(),
  ));
  let reporter = {
    let tx = tx.clone();
    let ops = ops.clone();
    let cancel = session_cancel.clone();
    tokio::spawn(async move {
      let mut refresh = true;
      // 每两次上报（一分钟）带一次资源采样。
      let mut sample = true;
      let ctx = Ctx {
        cancel: cancel.clone(),
        progress: None,
      };
      let mut tick = tokio::time::interval(REPORT_EVERY);
      tick.set_missed_tick_behavior(
        tokio::time::MissedTickBehavior::Skip,
      );
      loop {
        tokio::select! {
          _ = tick.tick() => {}
          _ = cancel.cancelled() => break,
        }
        let mut report = tokio::select! {
          _ = cancel.cancelled() => break,
          report = ops.reporter.report(refresh) => report,
        };
        refresh = false;
        if sample {
          report.metrics =
            ops.reporter.metrics(&ctx).await.map(Box::new);
        }
        sample = !sample;
        report.agent_memory = memory_report.borrow().clone();
        report.time_ms = Some(chrono::Utc::now().timestamp_millis());
        let permit = tokio::select! {
          _ = cancel.cancelled() => break,
          permit = tx.reserve() => match permit { Ok(permit) => permit, Err(_) => break },
        };
        report.log_hits = std::mem::take(&mut *hits.lock().unwrap())
          .into_values()
          .collect();
        permit.send(AgentMsg::Report(Box::new(report)));
      }
    })
  };

  let running: Arc<Mutex<HashMap<u64, CancellationToken>>> =
    Default::default();
  // 进行中的终端：控制面转来的输入送到这里。
  let inputs: Arc<Mutex<HashMap<u64, mpsc::Sender<TerminalInput>>>> =
    Default::default();
  let result = loop {
    let msg = tokio::select! {
      msg = tokio::time::timeout(IDLE_TIMEOUT, stream.next()) => msg,
      _ = session_cancel.cancelled() => break Ok(()),
    };
    let msg = match msg {
      Err(_) => {
        break Err(anyhow!(
          "{} 秒没有收到控制面消息",
          IDLE_TIMEOUT.as_secs()
        ));
      }
      Ok(None) => break Ok(()),
      Ok(Some(Err(e))) => break Err(e.into()),
      Ok(Some(Ok(msg))) => msg,
    };
    let frame = match msg {
      Message::Binary(frame) => frame,
      Message::Close(_) => break Ok(()),
      _ => continue,
    };
    let text = match opener.open(&frame) {
      Ok(text) => text,
      Err(e) => break Err(anyhow!("{e}")),
    };
    let msg: CoreMsg = match serde_json::from_slice(&text) {
      Ok(msg) => msg,
      Err(e) => {
        tracing::warn!("无法解析控制面消息：{e}");
        continue;
      }
    };
    match msg {
      CoreMsg::LogWatches { watches: full } => watches.replace(full),
      CoreMsg::AgentMemory { bytes } => {
        memory_tx.send_replace(Some(bytes));
      }
      CoreMsg::Request { id, op, .. }
        if matches!(
          &op,
          AgentOp::RotateAgentKey(_) | AgentOp::TrustCoreKey(_)
        ) =>
      {
        let result =
          ops.rotate_identity(op).map(|(value, reconnect)| {
            if reconnect {
              reconnect_after.store(id, Ordering::Release);
            }
            value
          });
        if tx.send(AgentMsg::Response { id, result }).await.is_err() {
          break Ok(());
        }
      }
      CoreMsg::Request { id, timeout_ms, op } => {
        // 先占服务锁，再接收后续部署或迁移请求。
        let removal = if let AgentOp::RemoveData { service } = &op {
          match ops.reserve_removal(service) {
            Ok(guard) => Some(guard),
            Err(error) => {
              if tx
                .send(AgentMsg::Response {
                  id,
                  result: Err(error),
                })
                .await
                .is_err()
              {
                break Ok(());
              }
              continue;
            }
          }
        } else {
          None
        };
        let cancel = session_cancel.child_token();
        running.lock().await.insert(id, cancel.clone());
        let input = if matches!(
          op,
          AgentOp::Terminal(_)
            | AgentOp::HostTerminal { .. }
            | AgentOp::Forward(_)
        ) {
          // 转发的输入是数据块，多留些余量。
          let cap = if matches!(op, AgentOp::Forward(_)) {
            64
          } else {
            256
          };
          let (itx, irx) = mpsc::channel(cap);
          inputs.lock().await.insert(id, itx);
          Some(irx)
        } else {
          None
        };
        let tx = tx.clone();
        let ops = ops.clone();
        let running = running.clone();
        let inputs = inputs.clone();
        let data = match &op {
          AgentOp::Forward(_) => {
            Some(Arc::new(data_mux.register(id, 32)))
          }
          // 这两帧是迁移握手，接收方等它才开始同步。
          AgentOp::SyncServe(_) => {
            Some(Arc::new(data_mux.register(id, 2)))
          }
          AgentOp::Terminal(_) | AgentOp::HostTerminal { .. } => {
            Some(Arc::new(data_mux.register(id, 64)))
          }
          _ => None,
        };
        let log = data.is_none().then(|| {
          crate::outbound::ProgressLog::new(progress_tx.clone(), id)
        });
        let session = session_cancel.clone();
        tokio::spawn(async move {
          let progress = if let Some(log) = &log {
            Some(log.callback())
          } else if !matches!(&op, AgentOp::Forward(_)) {
            let data = data.clone().unwrap();
            let cancel = cancel.clone();
            Some(Arc::new(move |line| {
              if data.try_send(line).is_err() {
                cancel.cancel();
              }
            }) as crate::exec::Progress)
          } else {
            None
          };
          let ctx = Ctx {
            cancel: cancel.clone(),
            progress,
          };
          let timeout = Duration::from_millis(timeout_ms.max(1000));
          let deadline = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
              tokio::time::sleep(timeout).await;
              cancel.cancel();
              true
            })
          };
          let result = match (op, input) {
            (AgentOp::Terminal(job), Some(input)) => {
              crate::terminal::run(&ops.docker, &job, &ctx, input)
                .await
            }
            (
              AgentOp::HostTerminal { size, session },
              Some(input),
            ) => {
              ops
                .host_shell
                .terminal(size, session, &ctx, input)
                .await
            }
            (AgentOp::Forward(job), Some(input)) => {
              crate::forward::run(
                &ops.docker,
                &job,
                &ctx,
                input,
                data.as_deref().unwrap(),
              )
              .await
            }
            (op, _) => ops.handle(op, &ctx).await,
          };
          drop(removal);
          inputs.lock().await.remove(&id);
          let timed_out = deadline.is_finished();
          deadline.abort();
          let result = match result {
            Err(e) if e.code == ErrorCode::Cancelled && timed_out => {
              Err(ApiError::new(
                ErrorCode::Timeout,
                format!(
                  "请求超过 {} 秒未完成，已终止",
                  timeout.as_secs()
                ),
              ))
            }
            other => other,
          };
          drop(ctx);
          if let Some(log) = log {
            tokio::select! {
              _ = session.cancelled() => {}
              _ = log.finish() => {}
            }
          }
          if let Some(data) = data {
            tokio::select! {
              _ = cancel.cancelled() => {}
              _ = data.finish() => {}
            }
          }
          running.lock().await.remove(&id);
          let _ = tx.send(AgentMsg::Response { id, result }).await;
        });
      }
      CoreMsg::Cancel { id } => {
        if let Some(cancel) = running.lock().await.get(&id) {
          cancel.cancel();
        }
      }
      CoreMsg::Input { id, input } => {
        let rejected = inputs
          .lock()
          .await
          .get(&id)
          .is_some_and(|itx| itx.try_send(input).is_err());
        if rejected
          && let Some(cancel) = running.lock().await.get(&id)
        {
          cancel.cancel();
        }
      }
      CoreMsg::Challenge { .. }
      | CoreMsg::Welcome { .. }
      | CoreMsg::KeyAccepted => {}
    }
  };
  // 断线时取消全部进行中的请求，不留下"一直在忙"的操作。
  session_cancel.cancel();
  reporter.abort();
  let _ = reporter.await;
  drop(tx);
  let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
  result.map(|()| reconnect_after.load(Ordering::Acquire) != 0)
}

async fn next_core_msg<S>(stream: &mut S) -> anyhow::Result<CoreMsg>
where
  S: StreamExt<
      Item = Result<Message, tokio_tungstenite::tungstenite::Error>,
    > + Unpin,
{
  loop {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.next())
      .await
      .context("握手超时")?
      .ok_or_else(|| anyhow!("连接被关闭"))??;
    match msg {
      Message::Text(text) => return Ok(serde_json::from_str(&text)?),
      Message::Close(Some(frame))
        if u16::from(frame.code) == 4001 =>
      {
        return Err(AuthenticationFailed.into());
      }
      Message::Close(frame) => bail!(
        "控制面关闭了连接：{}",
        frame.map(|f| f.reason.to_string()).unwrap_or_default()
      ),
      _ => continue,
    }
  }
}

#[cfg(test)]
mod rotation_tests {
  use super::*;
  use ed25519_dalek::Verifier;
  use wharf_api_types::agent::{
    KeyRotatePhase, RotateAgentKeyJob, RotateAgentKeyResult,
  };

  #[tokio::test]
  async fn rejected_new_agent_key_rolls_back_and_reconnects_with_old_key()
   {
    let dir = tempfile::tempdir().unwrap();
    let old = identity::load_or_create_key(dir.path())
      .unwrap()
      .verifying_key();
    let (prepared, _) = identity::rotate_key(
      dir.path(),
      RotateAgentKeyJob {
        phase: KeyRotatePhase::Prepare,
        expected_public_key: None,
      },
    )
    .unwrap();
    let prepared: RotateAgentKeyResult =
      serde_json::from_value(prepared).unwrap();
    identity::rotate_key(
      dir.path(),
      RotateAgentKeyJob {
        phase: KeyRotatePhase::Activate,
        expected_public_key: Some(prepared.public_key),
      },
    )
    .unwrap();
    let core = SigningKey::from_bytes(&[42; 32]);
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let joined = Joined {
      core_url: format!("http://{}", listener.local_addr().unwrap()),
      server: "s1".into(),
      core_public_key: hex::encode(core.verifying_key().to_bytes()),
      core_public_key_alt: None,
    };
    let server = tokio::spawn(async move {
      for attempt in 0..4 {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws =
          tokio_tungstenite::accept_async(tcp).await.unwrap();
        let nonce = random_nonce();
        ws.send(Message::text(
          serde_json::to_string(&CoreMsg::Challenge {
            nonce: nonce.clone(),
          })
          .unwrap(),
        ))
        .await
        .unwrap();
        let hello = ws.next().await.unwrap().unwrap();
        let AgentMsg::Hello {
          server,
          public_key,
          signature,
          nonce: agent_nonce,
          kx: Some(agent_kx),
          ..
        } = serde_json::from_str(hello.to_text().unwrap()).unwrap()
        else {
          panic!("缺少握手消息")
        };
        let public = identity::parse_public_key(&public_key).unwrap();
        public
          .verify(
            &auth_payload_v2("agent", &server, &nonce, &agent_kx),
            &identity::parse_signature(&signature).unwrap(),
          )
          .unwrap();
        if attempt < 3 {
          assert_ne!(public, old);
          ws.close(Some(
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
              code: 4001u16.into(),
              reason: "认证失败".into(),
            },
          ))
          .await
          .unwrap();
        } else {
          assert_eq!(public, old);
          let share = KeyShare::generate();
          let signature = core.sign(&auth_payload_v2(
            "core",
            &server,
            &agent_nonce,
            &format!("{},{agent_kx}", share.public),
          ));
          ws.send(Message::text(
            serde_json::to_string(&CoreMsg::Welcome {
              signature: hex::encode(signature.to_bytes()),
              alt_signature: None,
              confirm_key: false,
              backfill: false,
              kx: Some(share.public),
            })
            .unwrap(),
          ))
          .await
          .unwrap();
        }
      }
    });
    let mut failures = 0;
    for attempt in 0..3 {
      let key = identity::load_key(dir.path()).unwrap();
      let result = handshake(&joined, &key, dir.path()).await;
      assert!(
        result.err().is_some_and(|e| e.is::<AuthenticationFailed>())
      );
      assert_eq!(
        handle_auth_failure(dir.path(), &mut failures).unwrap(),
        attempt == 2
      );
    }
    let key = identity::load_key(dir.path()).unwrap();
    assert_eq!(key.verifying_key(), old);
    assert!(handshake(&joined, &key, dir.path()).await.is_ok());
    server.await.unwrap();
  }
}
