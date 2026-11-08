//! 端口转发（`wharf connect` 的中转路径）：CLI ⇄ WebSocket ⇄ 控制面 ⇄ agent ⇄ 服务端口。
//!
//! 一条 WebSocket 对应一条 TCP 连接，双向都是二进制帧。CLI 发空帧表示自己不再发送（半关闭）。
//! agent 连上目标前不读 CLI 的数据，连不上时发一条文本帧说明原因再关闭。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

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
  agent::{AgentOp, ForwardJob, TerminalInput},
  spec::ServiceSpec,
  view::Perm,
};

use crate::{
  api::{AppError, service_not_found},
  auth::Auth,
  hub::ProgressFn,
  snapshot,
  state::AppState,
};

/// 一条转发连接最长开这么久。
const SESSION_MAX: Duration = Duration::from_secs(12 * 60 * 60);
const BACKLOG: usize = 4096;
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
pub struct ConnectQuery {
  /// 端口名、容器端口或宿主机端口；只有一个端口时可以不填。
  port: Option<String>,
  /// compose 里的组件名，连没有声明的容器端口时用。
  component: Option<String>,
}

/// `GET /api/services/{name}/connect`（WebSocket）
pub async fn open(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<ConnectQuery>,
  ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
  // 能直连服务的任意端口（数据库等），和执行全部操作同一权限。
  auth.require(Perm::Exec)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  let job = target(
    &name,
    &row.spec,
    &row.host_ports,
    q.port.as_deref(),
    q.component,
  )?;
  if !s.hub.is_online(&row.spec.server) {
    return Err(crate::hub::offline(&row.spec.server).into());
  }
  let server = row.spec.server.clone();
  Ok(ws.on_upgrade(move |socket| session(s, server, job, socket)))
}

/// 声明过的端口走宿主机端口（agent 在宿主机网络里），其余数字当作容器端口。
fn target(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  port: Option<&str>,
  component: Option<String>,
) -> Result<ForwardJob, ApiError> {
  if let Some(p) = spec.find_port(port) {
    if let Some(host) = host_ports.get(&p.name).copied().or(p.host) {
      return Ok(ForwardJob {
        project: None,
        service: None,
        port: host,
      });
    }
    if let Some(container) = p.container {
      return Ok(ForwardJob {
        project: Some(name.to_string()),
        service: component,
        port: container,
      });
    }
  }
  if let Some(n) = port.and_then(|p| p.parse::<u16>().ok()) {
    return Ok(ForwardJob {
      project: Some(name.to_string()),
      service: component,
      port: n,
    });
  }
  let names: Vec<&str> =
    spec.ports.iter().map(|p| p.name.as_str()).collect();
  let message = match port {
    Some(p) => format!("服务 {name} 没有端口 {p}"),
    None if names.is_empty() => format!("服务 {name} 没有声明端口"),
    None => format!("服务 {name} 有多个端口：{}", names.join("、")),
  };
  Err(
    ApiError::invalid(message)
      .with_hint("用 --port 指定端口名或容器端口"),
  )
}

async fn session(
  state: Arc<AppState>,
  server: String,
  job: ForwardJob,
  mut socket: WebSocket,
) {
  let id = state.hub.new_id();
  let cancel = CancellationToken::new();
  let (out_tx, mut out_rx) = mpsc::channel::<String>(BACKLOG);
  let progress_cancel = cancel.clone();
  let progress: ProgressFn = Arc::new(move |chunk| {
    if out_tx.try_send(chunk).is_err() {
      progress_cancel.cancel();
    }
  });
  let call = {
    let state = state.clone();
    let server = server.clone();
    let cancel = cancel.clone();
    tokio::spawn(async move {
      state
        .hub
        .call_as::<u64>(
          id,
          &server,
          AgentOp::Forward(job),
          SESSION_MAX,
          Some(progress),
          &cancel,
        )
        .await
    })
  };
  tokio::pin!(call);
  let mut ready = false;
  let end = loop {
    tokio::select! {
      chunk = out_rx.recv() => {
        let Some(chunk) = chunk else { continue };
        if chunk.is_empty() {
          ready = true;
          continue;
        }
        let Ok(bytes) = STANDARD.decode(chunk) else { continue };
        if !send(&mut socket, Message::Binary(bytes.into())).await {
          break None;
        }
      }
      msg = socket.recv(), if ready => match msg {
        Some(Ok(Message::Binary(data))) => {
          if !state.hub.input(&server, id, TerminalInput {
            data: Some(STANDARD.encode(&data)),
            size: None,
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
  let Some(result) = end else {
    cancel.cancel();
    return;
  };
  while let Ok(chunk) = out_rx.try_recv() {
    if let Ok(bytes) = STANDARD.decode(chunk)
      && !bytes.is_empty()
      && !send(&mut socket, Message::Binary(bytes.into())).await
    {
      return;
    }
  }
  if let Ok(Err(e)) = result {
    let text = match &e.hint {
      Some(h) => format!("{}（{h}）", e.message),
      None => e.message.clone(),
    };
    let _ = send(&mut socket, Message::Text(text.into())).await;
  }
  let _ = send(&mut socket, Message::Close(None)).await;
}

async fn send(socket: &mut WebSocket, message: Message) -> bool {
  tokio::time::timeout(SOCKET_WRITE_TIMEOUT, socket.send(message))
    .await
    .is_ok_and(|result| result.is_ok())
}

#[cfg(test)]
mod tests {
  use wharf_api_types::spec::{PortSpec, Source};

  use super::*;

  #[test]
  fn declared_port_uses_host_port_else_container() {
    let spec = ServiceSpec {
      server: "s1".into(),
      source: Source::Image("postgres:16".into()),
      ports: vec![PortSpec {
        name: "pg".into(),
        container: Some(5432),
        host: None,
      }],
      env: Default::default(),
      volumes: vec![],
      backup: None,
      stopped: false,
      monitor: None,
    };
    let hp = BTreeMap::from([("pg".to_string(), 20001)]);
    let j = target("db", &spec, &hp, None, None).unwrap();
    assert_eq!((j.project, j.port), (None, 20001));
    let j = target("db", &spec, &hp, Some("6379"), None).unwrap();
    assert_eq!((j.project.as_deref(), j.port), (Some("db"), 6379));
    assert!(target("db", &spec, &hp, Some("x"), None).is_err());
  }
}
