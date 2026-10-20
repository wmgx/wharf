//! wharf-core：控制面。API、plan/apply、agent 连接，数据在一个 SQLite 文件里。

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use ed25519_dalek::SigningKey;

mod api;
mod apply;
mod auth;
mod db;
mod hub;
mod logs_stream;
mod planner;
mod render;
mod rollback;
mod snapshot;
mod state;
mod views;
mod web;
mod world;

#[derive(Parser)]
#[command(name = "wharf-core", version, about = "Wharf 控制面")]
struct Cli {
  #[arg(long, env = "WHARF_LISTEN", default_value = "0.0.0.0:7700")]
  listen: SocketAddr,
  /// 数据目录：数据库、控制面密钥、首次启动生成的管理员 token。
  #[arg(long, env = "WHARF_DATA_DIR", default_value = "./data")]
  data_dir: PathBuf,
  /// agent 连接控制面用的地址，例如 `http://100.x.y.z:7700`。
  /// 不设置时用 CLI 请求里的 Host。
  #[arg(long, env = "WHARF_PUBLIC_URL")]
  public_url: Option<String>,
  /// `wharf server add` 给出的 docker 命令里用的 agent 镜像。
  #[arg(
    long,
    env = "WHARF_AGENT_IMAGE",
    default_value = "ghcr.io/wmgx/wharf-agent:latest"
  )]
  agent_image: String,
}

fn load_or_create_key(
  path: &std::path::Path,
) -> anyhow::Result<SigningKey> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  if let Ok(text) = std::fs::read_to_string(path) {
    let seed: [u8; 32] = hex::decode(text.trim())
      .ok()
      .and_then(|b| b.try_into().ok())
      .with_context(|| format!("{} 格式不对", path.display()))?;
    return Ok(SigningKey::from_bytes(&seed));
  }
  let mut seed = [0u8; 32];
  getrandom::fill(&mut seed)
    .map_err(|e| anyhow::anyhow!("随机数不可用：{e}"))?;
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(path)
    .with_context(|| format!("写入 {}", path.display()))?;
  file.write_all(hex::encode(seed).as_bytes())?;
  Ok(SigningKey::from_bytes(&seed))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into()),
    )
    .init();
  let cli = Cli::parse();
  std::fs::create_dir_all(&cli.data_dir)
    .with_context(|| format!("创建 {}", cli.data_dir.display()))?;
  let db = db::Db::open(&cli.data_dir.join("wharf.db"))?;
  let key = load_or_create_key(&cli.data_dir.join("core.key"))?;
  auth::bootstrap(&db, &cli.data_dir).await?;

  let state = Arc::new(state::AppState {
    db,
    hub: Default::default(),
    key,
    runs: Default::default(),
    apply_lock: Default::default(),
    public_url: cli
      .public_url
      .map(|u| u.trim_end_matches('/').to_string()),
    agent_image: cli.agent_image,
  });
  apply::recover(&state).await?;

  let listener = tokio::net::TcpListener::bind(cli.listen)
    .await
    .with_context(|| format!("监听 {}", cli.listen))?;
  tracing::info!(
    "wharf-core {} 监听 {}",
    wharf_api_types::VERSION,
    cli.listen
  );
  axum::serve(listener, api::router(state))
    .with_graceful_shutdown(async {
      let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
  Ok(())
}
