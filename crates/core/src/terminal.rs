//! 容器终端：浏览器 ⇄ WebSocket ⇄ 控制面 ⇄ agent ⇄ `docker exec -it`。
//!
//! 浏览器发 JSON `{data?, cols?, rows?}`（data 是键盘输入的文本），
//! 控制面回二进制帧（终端原始输出）。shell 退出时发一条文本帧再关闭。
//! 浏览器断开时取消请求，agent 杀掉 docker exec。

use std::{
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::{Duration, Instant},
};

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
  ApiError, ErrorCode,
  agent::{AgentOp, TerminalInput, TerminalJob, TerminalSize},
  view::TokenScope,
};

use crate::{
  api::{AppError, service_not_found},
  auth::Auth,
  hub::ProgressFn,
  shell::{End, finish, start},
  snapshot,
  state::AppState,
};

/// 一次终端最长开这么久。
const SESSION_MAX: Duration = Duration::from_secs(4 * 60 * 60);
/// 浏览器读得慢时最多积压的输出块，超过就关闭会话。
const BACKLOG: usize = 4096;
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_WAIT: Duration = Duration::from_secs(20);

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
  Ok(ws.on_upgrade(move |socket| {
    session(s, server, Target::Service(job), socket, None)
  }))
}

/// `GET /api/servers/{name}/terminal`（WebSocket）
pub async fn open_host(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<OpenQuery>,
  ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
  auth.require(TokenScope::ApplyAll)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .servers
    .get(&name)
    .ok_or_else(|| crate::world::server_not_found(&name))?;
  let audit_id =
    start(&s.db, &auth.name, &name, "terminal", None).await?;
  if !row.settings.host_terminal {
    let error = ApiError::new(
      ErrorCode::Forbidden,
      "宿主机终端未开启，请到“服务器详情 → 设置”开启“宿主机终端”。",
    );
    finish(&s.db, audit_id, End::error(&error)).await;
    return Err(error.into());
  }
  if !s.hub.is_online(&name) {
    let error = crate::hub::offline(&name);
    finish(&s.db, audit_id, End::error(&error)).await;
    return Err(error.into());
  }
  if !s.hub.supports_host_shell(&name) {
    let error = ApiError::new(
      ErrorCode::Conflict,
      format!("服务器 {name} 的 agent 还不支持宿主机终端"),
    )
    .with_hint("请先运行 wharf upgrade");
    finish(&s.db, audit_id, End::error(&error)).await;
    return Err(error.into());
  }
  let size = TerminalSize {
    cols: q.cols,
    rows: q.rows,
  };
  Ok(ws.on_upgrade(move |socket| {
    session(s, name, Target::Host(size), socket, Some(audit_id))
  }))
}

enum Target {
  Service(TerminalJob),
  Host(TerminalSize),
}

async fn session(
  state: Arc<AppState>,
  server: String,
  target: Target,
  mut socket: WebSocket,
  audit_id: Option<i64>,
) {
  let started = Instant::now();
  let id = state.hub.new_id();
  let cancel = CancellationToken::new();
  let (out_tx, mut out_rx) = mpsc::channel::<String>(BACKLOG);
  let output_bytes = Arc::new(AtomicU64::new(0));
  let overflow = Arc::new(AtomicBool::new(false));
  let progress_cancel = cancel.clone();
  let progress_bytes = output_bytes.clone();
  let progress_overflow = overflow.clone();
  let progress: ProgressFn = Arc::new(move |chunk| {
    if let Ok(bytes) = STANDARD.decode(&chunk) {
      progress_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
    if out_tx.try_send(chunk).is_err() {
      progress_overflow.store(true, Ordering::Relaxed);
      progress_cancel.cancel();
    }
  });
  let call = {
    let state = state.clone();
    let server = server.clone();
    let cancel = cancel.clone();
    tokio::spawn(async move {
      let op = match target {
        Target::Service(job) => AgentOp::Terminal(job),
        Target::Host(size) => AgentOp::HostTerminal { size },
      };
      state
        .hub
        .call_as::<i32>(
          id,
          &server,
          op,
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
        if !send(&mut socket, Message::Binary(bytes.into())).await {
          break None;
        }
      }
      msg = socket.recv() => match msg {
        Some(Ok(Message::Text(text))) => {
          let Ok(m) = serde_json::from_str::<ClientMsg>(&text) else { continue };
          let size = m.cols.zip(m.rows).map(|(cols, rows)| TerminalSize { cols, rows });
          if !state.hub.input(&server, id, TerminalInput {
            data: m.data.map(|d| STANDARD.encode(d)),
            size,
          }).await {
            break None;
          }
        }
        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break None,
        Some(Ok(_)) => {}
      },
      result = &mut call => break Some(result),
    }
  };
  let client_open = end.is_some();
  let result = match end {
    Some(result) => Some(result),
    // 浏览器关了：取消请求，等 agent 清理完成后再结算审计。
    None => {
      cancel.cancel();
      tokio::time::timeout(CLEANUP_WAIT, &mut call).await.ok()
    }
  };
  if client_open {
    // 把还没发出去的输出送完。
    while let Ok(chunk) = out_rx.try_recv() {
      if let Ok(bytes) = STANDARD.decode(chunk)
        && !send(&mut socket, Message::Binary(bytes.into())).await
      {
        break;
      }
    }
    let line = match &result {
      Some(Ok(Ok(code))) => {
        format!("\r\n[已退出，退出码 {code}]\r\n")
      }
      Some(Ok(Err(_))) if overflow.load(Ordering::Relaxed) => {
        "\r\n[终端输出过快，已断开]\r\n".to_string()
      }
      Some(Ok(Err(e))) => {
        format!("\r\n[终端出错：{}]\r\n", message(e))
      }
      Some(Err(_)) | None => "\r\n[终端出错]\r\n".to_string(),
    };
    let _ = send(&mut socket, Message::Text(line.into())).await;
    let _ = send(&mut socket, Message::Close(None)).await;
  }
  if let Some(audit_id) = audit_id {
    let end = match result {
      Some(Ok(Ok(code))) => End {
        exit_code: Some(code),
        duration_ms: Some(started.elapsed().as_millis() as u64),
        output_bytes: Some(output_bytes.load(Ordering::Relaxed)),
        error: None,
      },
      Some(Ok(Err(_))) if overflow.load(Ordering::Relaxed) => End {
        exit_code: None,
        duration_ms: Some(started.elapsed().as_millis() as u64),
        output_bytes: Some(output_bytes.load(Ordering::Relaxed)),
        error: Some("backpressure".into()),
      },
      Some(Ok(Err(error))) => End {
        exit_code: None,
        duration_ms: Some(started.elapsed().as_millis() as u64),
        output_bytes: Some(output_bytes.load(Ordering::Relaxed)),
        error: Some(format!(
          "{}: {}",
          error.code.as_str(),
          error.message
        )),
      },
      Some(Err(_)) | None => End {
        exit_code: None,
        duration_ms: None,
        output_bytes: Some(output_bytes.load(Ordering::Relaxed)),
        error: Some("cleanup_timeout".into()),
      },
    };
    finish(&state.db, audit_id, end).await;
  }
}

async fn send(socket: &mut WebSocket, message: Message) -> bool {
  tokio::time::timeout(SOCKET_WRITE_TIMEOUT, socket.send(message))
    .await
    .is_ok_and(|result| result.is_ok())
}

fn message(e: &ApiError) -> String {
  match &e.hint {
    Some(h) => format!("{}（{h}）", e.message),
    None => e.message.clone(),
  }
}
