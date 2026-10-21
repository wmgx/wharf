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
  /// 数据目录，上传的代码包放在它下面的 `uploads/`。
  pub data_dir: std::path::PathBuf,
  pub downloads: crate::uploads::Downloads,
  /// 启动时间：没有管理员账号时，启动后 30 分钟内可以在页面上设置。
  pub started: std::time::Instant,
  /// 正在后台同步的边缘应用。
  pub edge_syncing: crate::edge_sync::Syncing,
}
