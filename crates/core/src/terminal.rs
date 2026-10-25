//! 容器终端：浏览器 ⇄ WebSocket ⇄ 控制面 ⇄ agent ⇄ `docker exec -it`。
//!
//! 浏览器发 JSON `{data?, cols?, rows?}`（data 是键盘输入的文本），
//! 控制面回二进制帧（终端原始输出）。shell 退出时发一条文本帧再关闭。
//! 浏览器断开时取消请求，agent 杀掉 docker exec。

use std::{sync::Arc, time::Duration};

use axum::{
  extract::{
    Path, Query, State, WebSocketUpgrade,
    ws::{Message, WebSocket},
  },
  response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, TerminalInput, TerminalJob, TerminalSize},
  view::TokenScope,
};

use crate::{
  api::{AppError, service_not_found},
  auth::Auth,
  hub::ProgressFn,
  snapshot,
  state::AppState,
};

/// 一次终端最长开这么久。
const SESSION_MAX: Duration = Duration::from_secs(4 * 60 * 60);
/// 浏览器读得慢时最多积压的输出块，超过就丢弃。
const BACKLOG: usize = 4096;

#[derive(Deserialize)]
pub struct OpenQuery {
  #[serde(default = "default_cols")]
  cols: u16,
  #[serde(default = "default_rows")]
  rows: u16,
  /// compose 里的服务名，不填时用第一个在运行的容器。
  service: Option<String>,
}

fn default_cols() -> u16 {
  100
}

fn default_rows() -> u16 {
  30
}

#[derive(Deserialize)]
struct ClientMsg {
  data: Option<String>,
  cols: Option<u16>,
  rows: Option<u16>,
}

/// `GET /api/services/{name}/terminal`（WebSocket）
pub async fn open(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<OpenQuery>,
  ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
  // 能在容器里执行任意命令，和执行全部操作同一权限。
  auth.require(TokenScope::ApplyAll)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  if !s.hub.is_online(&row.spec.server) {
    return Err(crate::hub::offline(&row.spec.server).into());
  }
  let server = row.spec.server.clone();
  let job = TerminalJob {
    project: name,
    service: q.service,
    size: TerminalSize {
      cols: q.cols,
      rows: q.rows,
    },
  };
  Ok(ws.on_upgrade(move |socket| session(s, server, job, socket)))
}

async fn session(
  state: Arc<AppState>,
  server: String,
  job: TerminalJob,
  mut socket: WebSocket,
) {
  let id = state.hub.new_id();
  let cancel = CancellationToken::new();
  let (out_tx, mut out_rx) = mpsc::channel::<String>(BACKLOG);
  let progress: ProgressFn = Arc::new(move |chunk| {
    let _ = out_tx.try_send(chunk);
  });
  let call = {
    let state = state.clone();
    let server = server.clone();
    let cancel = cancel.clone();
    tokio::spawn(async move {
      state
        .hub
        .call_as::<i32>(
          id,
          &server,
          AgentOp::Terminal(job),
          SESSION_MAX,
          Some(progress),
          &cancel,
        )
        .await
    })
  };
  tokio::pin!(call);
  let end = loop {
    tokio::select! {
      chunk = out_rx.recv() => {
        let Some(chunk) = chunk else { continue };
        let Ok(bytes) = STANDARD.decode(chunk) else { continue };
        if socket.send(Message::Binary(bytes.into())).await.is_err() {
          break None;
        }
      }
      msg = socket.recv() => match msg {
        Some(Ok(Message::Text(text))) => {
          let Ok(m) = serde_json::from_str::<ClientMsg>(&text) else { continue };
          let size = m.cols.zip(m.rows).map(|(cols, rows)| TerminalSize { cols, rows });
          state.hub.input(&server, id, TerminalInput {
            data: m.data.map(|d| STANDARD.encode(d)),
            size,
          });
        }
        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break None,
        Some(Ok(_)) => {}
      },
      result = &mut call => break Some(result),
    }
  };
  match end {
    // 浏览器关了：取消请求，agent 那边杀掉 docker exec。
    None => cancel.cancel(),
    Some(result) => {
      // 把还没发出去的输出送完。
      while let Ok(chunk) = out_rx.try_recv() {
        if let Ok(bytes) = STANDARD.decode(chunk) {
          let _ = socket.send(Message::Binary(bytes.into())).await;
        }
      }
      let line = match result {
        Ok(Ok(code)) => format!("\r\n[已退出，退出码 {code}]\r\n"),
        Ok(Err(e)) => format!("\r\n[终端出错：{}]\r\n", message(&e)),
        Err(_) => "\r\n[终端出错]\r\n".to_string(),
      };
      let _ = socket.send(Message::Text(line.into())).await;
      let _ = socket.send(Message::Close(None)).await;
    }
  }
}

fn message(e: &ApiError) -> String {
  match &e.hint {
    Some(h) => format!("{}（{h}）", e.message),
    None => e.message.clone(),
  }
}
