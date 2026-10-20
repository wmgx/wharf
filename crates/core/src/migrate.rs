//! 迁移服务的数据：`/srv/<service>/` 从一台服务器搬到另一台，走内网地址。
//!
//! 1. 目标机器起 rsync 接收端（一次性口令，只接受源机器的地址）；
//! 2. 源机器在服务运行时推送一遍，传完大部分数据；
//! 3. 停掉源机器上的容器，再增量推送一遍；
//! 4. 关掉接收端。之后由普通的步骤在新机器上起服务、切网关、删旧容器。
//!
//! 第 3 步之后失败时把源机器上的容器重新启动，不让服务一直停着。

use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use serde::Deserialize;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, OneTimeSecret, SYNC_READY, SyncPush, SyncServe},
};

use crate::{hub::ProgressFn, render::Net, state::AppState};

const SERVE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
const PUSH_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Deserialize)]
struct Pushed {
  synced: bool,
}

fn private_ip(net: &Net, server: &str) -> Result<String, ApiError> {
  net
    .private
    .get(server)
    .map(|a| a.ip.clone())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务器 {server} 没有内网地址，迁移数据走不通"
      ))
      .suggest(format!("wharf server set {server} --private-ip <ip>"))
    })
}

fn one_time_password() -> OneTimeSecret {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  OneTimeSecret(hex::encode(bytes))
}

pub async fn volume_sync(
  state: &AppState,
  net: &Net,
  service: &str,
  from: &str,
  to: &str,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let source_ip = private_ip(net, from)?;
  let target_ip = private_ip(net, to)?;
  let password = one_time_password();

  // 接收端跟着这个子令牌走：结束（成功或失败）时取消它，agent 就会关掉 rsync。
  let serve_cancel = cancel.child_token();
  let (ready_tx, ready_rx) = oneshot::channel::<u16>();
  let ready_tx = Arc::new(Mutex::new(Some(ready_tx)));
  let serve_progress: ProgressFn = {
    let progress = progress.clone();
    let to = to.to_string();
    Arc::new(move |line: String| {
      if let Some(port) =
        line.strip_prefix(SYNC_READY).and_then(|p| p.parse().ok())
      {
        if let Some(tx) =
          ready_tx.lock().unwrap_or_else(|p| p.into_inner()).take()
        {
          let _ = tx.send(port);
        }
        progress(format!("{to} 上的接收端已就绪"));
      } else {
        progress(format!("[{to}] {line}"));
      }
    })
  };
  let serve = state.hub.call::<serde_json::Value>(
    to,
    AgentOp::SyncServe(SyncServe {
      service: service.to_string(),
      bind: target_ip.clone(),
      allow: source_ip,
      password: password.clone(),
    }),
    SERVE_TIMEOUT,
    Some(serve_progress),
    &serve_cancel,
  );

  let work = async {
    let port = tokio::select! {
      port = ready_rx => port.map_err(|_| ApiError::new(
        ErrorCode::AgentFailed,
        format!("{to} 上的 rsync 接收端没有启动"),
      ))?,
      _ = tokio::time::sleep(READY_TIMEOUT) => return Err(ApiError::new(
        ErrorCode::Timeout,
        format!("{to} 上的 rsync 接收端 {} 秒内没有就绪", READY_TIMEOUT.as_secs()),
      )),
      _ = cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
    };
    let push = || {
      AgentOp::SyncPush(SyncPush {
        service: service.to_string(),
        host: target_ip.clone(),
        port,
        password: password.clone(),
      })
    };

    progress("第一遍同步（服务继续运行）".into());
    let first: Pushed = state
      .hub
      .call(
        from,
        push(),
        PUSH_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await?;
    if !first.synced {
      return Ok(());
    }

    progress(format!("停止 {from} 上的 {service}"));
    state
      .hub
      .call::<serde_json::Value>(
        from,
        AgentOp::ProjectStop {
          project: service.to_string(),
        },
        STOP_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await?;

    progress("增量同步（服务已停止）".into());
    let second = state
      .hub
      .call::<Pushed>(
        from,
        push(),
        PUSH_TIMEOUT,
        Some(progress.clone()),
        cancel,
      )
      .await;
    if let Err(e) = second {
      restart_source(state, from, service, &progress).await;
      return Err(e);
    }
    Ok(())
  };
  // 接收端和推送同时进行；推送结束（成功或失败）就关掉接收端。
  let work = async {
    let r = work.await;
    serve_cancel.cancel();
    r
  };
  let (result, served) = tokio::join!(work, serve);
  match (result, served) {
    // 接收端没起来时，就绪等待只会说"没有启动"，用接收端自己的错误更清楚。
    (Err(_), Err(e)) if e.code != ErrorCode::Cancelled => Err(e),
    (Err(e), _) => Err(e),
    (Ok(()), _) => {
      crate::jobs::schedule_cleanup(state, service, from).await?;
      progress(format!(
        "{from} 上的 /srv/{service}/ 保留 7 天，之后自动删除"
      ));
      Ok(())
    }
  }
}

/// 增量同步失败时，把旧服务器上停掉的容器拉起来。用新的令牌，取消执行时也要做。
async fn restart_source(
  state: &AppState,
  server: &str,
  service: &str,
  progress: &ProgressFn,
) {
  progress(format!("迁移失败，重新启动 {server} 上的 {service}"));
  let result = state
    .hub
    .call::<serde_json::Value>(
      server,
      AgentOp::ProjectStart {
        project: service.to_string(),
      },
      STOP_TIMEOUT,
      Some(progress.clone()),
      &CancellationToken::new(),
    )
    .await;
  if let Err(e) = result {
    progress(format!(
      "重新启动失败：{}，需要手动处理：wharf service deploy {service}",
      e.message
    ));
  }
}
