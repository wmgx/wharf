use crate::{apply::Runs, db::Db, hub::Hub};

pub struct AppState {
  pub db: Db,
  pub hub: Hub,
  /// 控制面的签名密钥，agent 用它确认连上的是真的控制面。
  pub key: crate::key_rotation::CoreKeyRing,
  pub runs: Runs,
  pub locks: crate::locks::OpLocks,
  /// agent 连接控制面用的地址，写进 join 命令。不设置时用请求的 Host。
  pub public_url: Option<String>,
  /// join 命令里 agent 容器的镜像。
  pub agent_image: String,
  /// 监听端口，列控制面候选地址时用。
  pub listen_port: u16,
  /// 数据目录，上传的代码包放在它下面的 `uploads/`。
  pub data_dir: std::path::PathBuf,
  pub downloads: crate::uploads::Downloads,
  pub safe_mode: std::sync::atomic::AtomicBool,
  /// 正在后台同步的边缘应用。
  pub edge_syncing: crate::edge_sync::Syncing,
}

impl AppState {
  pub fn is_safe_mode(&self) -> bool {
    self.safe_mode.load(std::sync::atomic::Ordering::Acquire)
  }

  pub fn is_service_busy(&self, service: &str) -> bool {
    self.locks.is_service_busy(service)
  }
}

use std::sync::{Arc, atomic::Ordering};

use axum::{Extension, Json, extract::State};
use wharf_api_types::view::{CoreSafeModeView, Perm};

use crate::{api::ApiResult, audit::AuditSlot, auth::Auth};

fn safe_mode_view(
  s: &AppState,
  resumed: Option<bool>,
) -> CoreSafeModeView {
  let safe_mode = s.is_safe_mode();
  CoreSafeModeView {
    safe_mode,
    resumed,
    paused: if safe_mode {
      ["自动清理", "自动备份", "自愈", "主备切换", "自动更新", "定时任务", "告警外发"]
        .map(String::from)
        .to_vec()
    } else {
      Vec::new()
    },
    hint: resumed.filter(|r| *r).map(|_| "如果使用 WHARF_SAFE_MODE 启动，请移除该环境变量，避免重启后再次进入安全接管模式".into()),
  }
}

pub async fn safe_mode(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreSafeModeView> {
  auth.require(Perm::Read)?;
  Ok(Json(safe_mode_view(&s, None)))
}

pub async fn resume(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
) -> ApiResult<CoreSafeModeView> {
  auth.require(Perm::Admin)?;
  audit.set_detail("解除安全接管模式".into());
  let resumed = s.safe_mode.swap(false, Ordering::AcqRel);
  Ok(Json(safe_mode_view(&s, Some(resumed))))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    rules::tests::test_state, security_receipt::tests::auth,
  };

  #[tokio::test]
  async fn safe_mode_status_pauses_and_admin_resumes() {
    let s = test_state();
    s.safe_mode.store(true, Ordering::Release);
    let status = crate::views::status(&s, None).await.unwrap();
    assert!(status.safe_mode);
    assert!(
      crate::notify::send(
        &s,
        &crate::notify::Event {
          title: String::new(),
          body: String::new()
        }
      )
      .await
      .is_err_and(|e| e.code == wharf_api_types::ErrorCode::Conflict)
    );
    assert_eq!(status.issues[0].code, "core_safe_mode");
    let mut reader = auth(false);
    reader.perms = [Perm::Read].into_iter().collect();
    assert!(
      resume(
        State(s.clone()),
        reader,
        Extension(AuditSlot::default())
      )
      .await
      .is_err()
    );
    let view = resume(
      State(s.clone()),
      auth(true),
      Extension(AuditSlot::default()),
    )
    .await
    .map_err(|e| e.0)
    .unwrap()
    .0;
    assert_eq!(view.resumed, Some(true));
    assert!(!s.is_safe_mode());
  }
}
