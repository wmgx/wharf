use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::{apply::Runs, db::Db, hub::Hub};

pub struct AppState {
  pub db: Db,
  pub hub: Hub,
  /// 控制面的签名密钥，agent 用它确认连上的是真的控制面。
  pub key: SigningKey,
  pub runs: Runs,
  /// 同一时间只有一个 apply 在执行。
  pub apply_lock: Arc<tokio::sync::Mutex<()>>,
  /// agent 连接控制面用的地址，写进 join 命令。不设置时用请求的 Host。
  pub public_url: Option<String>,
  /// join 命令里 agent 容器的镜像。
  pub agent_image: String,
}
