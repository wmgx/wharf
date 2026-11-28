use std::sync::Mutex;

use tokio::sync::oneshot;
use wharf_api_types::agent::{
  OneTimeSecret, SYNC_BACKUP, SYNC_READY, SyncPass, SyncPush,
  SyncServe,
};

use super::*;

const PUSH_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const SERVE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
  s: &AppState,
  snap: &WorldSnapshot,
  movement: &Move,
  run_id: &str,
  p: &mut PendingMove,
  replace_target: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let net = snap.net(&snap.world);
  let bind = net.private[&movement.to].ip.clone();
  let allow = net.private[&movement.from].ip.clone();
  let mut random = [0; 24];
  getrandom::fill(&mut random)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  let password = OneTimeSecret(hex::encode(random));
  let (tx, rx) = oneshot::channel();
  let signal = Mutex::new((Some(tx), None));
  let serve_progress: ProgressFn = Arc::new(move |line| {
    let mut state = signal.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(path) = line.strip_prefix(SYNC_BACKUP) {
      state.1 = Some(path.to_owned());
    } else if let Some(port) = line
      .strip_prefix(SYNC_READY)
      .and_then(|p| p.parse::<u16>().ok())
      && let Some(tx) = state.0.take()
    {
      let _ = tx.send((port, state.1.take()));
    }
  });
  let serve_cancel = cancel.child_token();
  let _stop = serve_cancel.clone().drop_guard();
  let work_cancel = cancel.child_token();
  let serve_op = AgentOp::SyncServe(SyncServe {
    service: movement.service.clone(),
    bind: bind.clone(),
    allow,
    password: password.clone(),
    preserve_existing: !p.target_prepared && replace_target,
    require_empty: !p.target_prepared && !replace_target,
    kind: movement.kind(),
  });
  let serve = async {
    let result = s
      .hub
      .call::<Value>(
        &movement.to,
        serve_op,
        SERVE_TIMEOUT,
        Some(serve_progress),
        &serve_cancel,
      )
      .await;
    if !serve_cancel.is_cancelled() {
      work_cancel.cancel();
    }
    result
  };
  let transfer = async {
    let (port, archive) = tokio::select! {
      ready = rx => ready.map_err(|_| ApiError::new(ErrorCode::AgentFailed, "目标接收端没有启动"))?,
      _ = work_cancel.cancelled() => return Err(cancelled()),
      _ = tokio::time::sleep(Duration::from_secs(45)) => {
        return Err(ApiError::new(ErrorCode::Timeout, "等待目标接收端超时"));
      }
    };
    p.target_prepared = true;
    if archive.is_some() {
      p.status.target_archive = archive;
    }
    save(s, movement, run_id, p).await?;
    let result: Value = s
      .hub
      .call(
        &movement.from,
        AgentOp::SyncPush(SyncPush {
          service: movement.service.clone(),
          host: bind,
          port,
          password,
          pass: SyncPass::Final,
          kind: movement.kind(),
          bwlimit_kbps: None,
        }),
        PUSH_TIMEOUT,
        Some(progress.clone()),
        &work_cancel,
      )
      .await?;
    if result["synced"].as_bool() != Some(true) {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "备份仓库未完成同步",
      ));
    }
    Ok(())
  };
  let work = async {
    let result = transfer.await;
    serve_cancel.cancel();
    result
  };
  let (serve, work) = tokio::join!(serve, work);
  if let Err(e) = serve
    && e.code != ErrorCode::Cancelled
  {
    return Err(e);
  }
  work
}
