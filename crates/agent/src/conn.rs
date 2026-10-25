//! 和控制面的 websocket 连接：握手、断线重连、请求分发、心跳。

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, anyhow, bail};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentMsg, AgentOp, CoreMsg, TerminalInput, auth_payload},
};

use crate::{
  exec::Ctx,
  identity::{Joined, parse_signature},
  ops::Ops,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const REPORT_EVERY: Duration = Duration::from_secs(30);
/// 这么久没收到控制面任何消息（包括 ping）就认为连接已死。
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn run_forever(
  joined: Joined,
  key: SigningKey,
  ops: Arc<Ops>,
) -> ! {
  let mut backoff = 1u64;
  loop {
    match session(&joined, &key, ops.clone()).await {
      Ok(()) => {
        tracing::warn!("与控制面的连接断开");
        backoff = 1;
      }
      Err(e) => tracing::warn!("连接控制面失败：{e:#}"),
    }
    let jitter = (std::process::id() as u64 + backoff) % 3;
    tokio::time::sleep(Duration::from_secs(backoff + jitter)).await;
    backoff = (backoff * 2).min(30);
  }
}

fn random_nonce() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

async fn session(
  joined: &Joined,
  key: &SigningKey,
  ops: Arc<Ops>,
) -> anyhow::Result<()> {
  let url = joined.ws_url();
  let (ws, _) = tokio::time::timeout(
    HANDSHAKE_TIMEOUT,
    tokio_tungstenite::connect_async(&url),
  )
  .await
  .context("连接超时")?
  .with_context(|| format!("连接 {url}"))?;
  let (mut sink, mut stream) = ws.split();

  // 握手
  let challenge = next_core_msg(&mut stream).await?;
  let CoreMsg::Challenge { nonce } = challenge else {
    bail!("控制面没有先发 challenge");
  };
  let my_nonce = random_nonce();
  let hello = AgentMsg::Hello {
    server: joined.server.clone(),
    public_key: hex::encode(key.verifying_key().to_bytes()),
    signature: hex::encode(
      key
        .sign(&auth_payload("agent", &joined.server, &nonce))
        .to_bytes(),
    ),
    nonce: my_nonce.clone(),
    version: wharf_api_types::VERSION.to_string(),
  };
  sink
    .send(Message::text(serde_json::to_string(&hello)?))
    .await?;
  let CoreMsg::Welcome { signature } =
    next_core_msg(&mut stream).await?
  else {
    bail!("控制面拒绝了连接");
  };
  joined
    .core_key()?
    .verify(
      &auth_payload("core", &joined.server, &my_nonce),
      &parse_signature(&signature)?,
    )
    .map_err(|_| anyhow!("控制面签名不对，可能连到了假的控制面"))?;
  tracing::info!("已连接控制面 {url}，服务器名 {}", joined.server);

  // 所有出站消息走一个通道，由写任务统一发送。
  let (tx, mut rx) = mpsc::unbounded_channel::<AgentMsg>();
  let session_cancel = CancellationToken::new();
  let writer = {
    let cancel = session_cancel.clone();
    tokio::spawn(async move {
      while let Some(msg) = rx.recv().await {
        let Ok(text) = serde_json::to_string(&msg) else {
          continue;
        };
        if sink.send(Message::text(text)).await.is_err() {
          break;
        }
      }
      cancel.cancel();
    })
  };
  let reporter = {
    let tx = tx.clone();
    let ops = ops.clone();
    let cancel = session_cancel.clone();
    tokio::spawn(async move {
      let mut refresh = true;
      loop {
        let report = ops.reporter.report(refresh).await;
        refresh = false;
        if tx.send(AgentMsg::Report(report)).is_err() {
          break;
        }
        tokio::select! {
          _ = tokio::time::sleep(REPORT_EVERY) => {}
          _ = cancel.cancelled() => break,
        }
      }
    })
  };

  let running: Arc<Mutex<HashMap<u64, CancellationToken>>> =
    Default::default();
  // 进行中的终端：控制面转来的输入送到这里。
  let inputs: Arc<
    Mutex<HashMap<u64, mpsc::UnboundedSender<TerminalInput>>>,
  > = Default::default();
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
    let text = match msg {
      Message::Text(text) => text,
      Message::Close(_) => break Ok(()),
      _ => continue,
    };
    let msg: CoreMsg = match serde_json::from_str(&text) {
      Ok(msg) => msg,
      Err(e) => {
        tracing::warn!("无法解析控制面消息：{e}");
        continue;
      }
    };
    match msg {
      CoreMsg::Request { id, timeout_ms, op } => {
        let cancel = session_cancel.child_token();
        running.lock().await.insert(id, cancel.clone());
        let input = if matches!(op, AgentOp::Terminal(_)) {
          let (itx, irx) = mpsc::unbounded_channel();
          inputs.lock().await.insert(id, itx);
          Some(irx)
        } else {
          None
        };
        let tx = tx.clone();
        let ops = ops.clone();
        let running = running.clone();
        let inputs = inputs.clone();
        tokio::spawn(async move {
          let progress_tx = tx.clone();
          let ctx = Ctx {
            cancel: cancel.clone(),
            progress: Some(Arc::new(move |line| {
              let _ =
                progress_tx.send(AgentMsg::Progress { id, line });
            })),
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
            (op, _) => ops.handle(op, &ctx).await,
          };
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
          running.lock().await.remove(&id);
          let _ = tx.send(AgentMsg::Response { id, result });
        });
      }
      CoreMsg::Cancel { id } => {
        if let Some(cancel) = running.lock().await.get(&id) {
          cancel.cancel();
        }
      }
      CoreMsg::Input { id, input } => {
        if let Some(itx) = inputs.lock().await.get(&id) {
          let _ = itx.send(input);
        }
      }
      CoreMsg::Challenge { .. } | CoreMsg::Welcome { .. } => {}
    }
  };
  // 断线时取消全部进行中的请求，不留下"一直在忙"的操作。
  session_cancel.cancel();
  reporter.abort();
  drop(tx);
  let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
  result
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
      Message::Close(frame) => bail!(
        "控制面关闭了连接：{}",
        frame.map(|f| f.reason.to_string()).unwrap_or_default()
      ),
      _ => continue,
    }
  }
}
