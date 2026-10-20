//! 日志流：页面打开日志面板时，持续把新日志推给浏览器。
//!
//! 返回纯文本分块响应，一行一条。浏览器断开时响应体被丢弃，
//! 取消令牌随之触发，agent 那边的 `docker compose logs -f` 会被杀掉。

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
  body::Body,
  extract::{Path, Query, State},
  http::header,
  response::{IntoResponse, Response},
};
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{agent::AgentOp, view::TokenScope};

use crate::{
  api::{AppError, gateway_not_found, service_not_found},
  auth::Auth,
  hub::ProgressFn,
  snapshot,
  state::AppState,
  world::gateway_project,
};

/// 和 agent 的跟随上限一致，再留一点余量。
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(30 * 60 + 30);
/// 浏览器读得慢时最多积压的行数，超过就丢弃。
const BACKLOG: usize = 2000;

#[derive(Deserialize)]
pub struct FollowQuery {
  #[serde(default = "default_tail")]
  tail: u32,
}

fn default_tail() -> u32 {
  200
}

pub async fn service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<FollowQuery>,
) -> Result<Response, AppError> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| service_not_found(&name))?;
  Ok(follow(s.clone(), row.spec.server.clone(), name, q.tail))
}

pub async fn gateway(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<FollowQuery>,
) -> Result<Response, AppError> {
  auth.require(TokenScope::Read)?;
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .gateways
    .get(&name)
    .ok_or_else(|| gateway_not_found(&name))?;
  Ok(follow(
    s.clone(),
    row.spec.server.clone(),
    gateway_project(&name),
    q.tail,
  ))
}

fn follow(
  state: Arc<AppState>,
  server: String,
  project: String,
  tail: u32,
) -> Response {
  let (tx, rx) = mpsc::channel::<String>(BACKLOG);
  let cancel = CancellationToken::new();
  let guard = cancel.clone().drop_guard();
  let line_tx = tx.clone();
  let progress: ProgressFn = Arc::new(move |line| {
    let _ = line_tx.try_send(line);
  });
  tokio::spawn(async move {
    let result = state
      .hub
      .call::<String>(
        &server,
        AgentOp::Logs {
          project,
          tail,
          follow: true,
        },
        FOLLOW_TIMEOUT,
        Some(progress),
        &cancel,
      )
      .await;
    if let Err(e) = result
      && !cancel.is_cancelled()
    {
      let _ =
        tx.send(format!("[wharf] 日志流中断：{}", e.message)).await;
    }
  });
  // guard 跟着响应体走：浏览器断开 → 流被丢弃 → 取消。
  let body =
    stream::unfold((rx, guard), |(mut rx, guard)| async move {
      let line = rx.recv().await?;
      Some((Ok::<_, Infallible>(format!("{line}\n")), (rx, guard)))
    });
  (
    [
      (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
      (header::CACHE_CONTROL, "no-cache"),
      (header::HeaderName::from_static("x-accel-buffering"), "no"),
    ],
    Body::from_stream(body),
  )
    .into_response()
}
