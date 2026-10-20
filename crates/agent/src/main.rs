//! wharf-agent：每台服务器一个，主动连接控制面。
//!
//! ```text
//! wharf-agent join http://100.101.102.103:7700 <join_token>   # 只需一次
//! wharf-agent run
//! ```
//! 容器里运行时，可以直接 `run` 并设置 `WHARF_CORE_URL`、`WHARF_JOIN_TOKEN`，
//! 第一次启动会自动加入。

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

mod conn;
mod docker;
mod exec;
mod identity;
mod ops;
mod report;

#[derive(Parser)]
#[command(name = "wharf-agent", version, about = "Wharf agent")]
struct Cli {
  /// 存放密钥、compose 文件的目录。容器里运行时要以相同路径挂载宿主机目录。
  #[arg(
    long,
    env = "WHARF_DATA_DIR",
    default_value = "/var/lib/wharf",
    global = true
  )]
  data_dir: PathBuf,
  #[arg(
    long,
    env = "WHARF_DOCKER",
    default_value = "docker",
    global = true
  )]
  docker: String,
  /// 覆盖自动探测的 Tailscale IP。
  #[arg(long, env = "WHARF_TAILSCALE_IP", global = true)]
  tailscale_ip: Option<String>,
  /// 覆盖自动探测的公网 IP。
  #[arg(long, env = "WHARF_PUBLIC_IP", global = true)]
  public_ip: Option<String>,
  #[command(subcommand)]
  command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
  /// 用一次性凭据加入控制面（`wharf server add` 会给出完整命令）。
  Join {
    core_url: String,
    join_token: String,
  },
  /// 连接控制面并处理请求（默认）。
  Run {
    /// 还没加入时，用它和 `--join-token` 自动加入。
    #[arg(long, env = "WHARF_CORE_URL")]
    core_url: Option<String>,
    #[arg(long, env = "WHARF_JOIN_TOKEN", hide_env_values = true)]
    join_token: Option<String>,
  },
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

  let command = cli.command.unwrap_or(Command::Run {
    core_url: std::env::var("WHARF_CORE_URL").ok(),
    join_token: std::env::var("WHARF_JOIN_TOKEN").ok(),
  });
  let joined = match command {
    Command::Join {
      core_url,
      join_token,
    } => {
      let joined =
        identity::join(&cli.data_dir, &core_url, &join_token).await?;
      println!(
        "已加入 {}，服务器名 {}。现在运行：wharf-agent run",
        joined.core_url, joined.server
      );
      return Ok(());
    }
    Command::Run {
      core_url,
      join_token,
    } => match identity::Joined::load(&cli.data_dir)? {
      Some(joined) => joined,
      None => match (core_url, join_token) {
        (Some(url), Some(token)) if !token.is_empty() => {
          identity::join(&cli.data_dir, &url, &token).await?
        }
        _ => bail!(
          "还没有加入控制面。先在控制面执行 `wharf server add <name>`，再按提示运行 join"
        ),
      },
    },
  };

  let key = identity::load_or_create_key(&cli.data_dir)?;
  let docker = docker::Docker {
    bin: cli.docker,
    data_dir: cli.data_dir,
  };
  let reporter = report::Reporter::new(
    docker.clone(),
    cli.tailscale_ip,
    cli.public_ip,
  );
  let ops = Arc::new(ops::Ops::new(docker, reporter));
  conn::run_forever(joined, key, ops).await
}
