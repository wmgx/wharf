//! `wharf`：Wharf 的命令行，给 AI 用。
//!
//! - 所有命令都支持 `--json`，输出结构稳定；
//! - 修改类命令只生成计划，`wharf apply <plan_id>` 才执行；加 `--apply` 可以一步完成；
//! - 错误统一为 `{ code, message, hint, suggest }`；
//! - 退出码：0 成功，1 出错，2 需要确认，3 计划已过期，4 执行部分失败。

use clap::{Args, Parser, Subcommand};

mod client;
mod commands;
mod fleet;
mod print;

#[derive(Parser)]
#[command(
  name = "wharf",
  version,
  about = "Wharf：多服务器管理（服务器、服务、网关、路由）"
)]
pub struct Cli {
  /// 输出 JSON（给程序和 AI 用）。
  #[arg(long, global = true)]
  pub json: bool,
  /// 控制面地址，默认读 `~/.config/wharf/config.toml`。
  #[arg(long, env = "WHARF_URL", global = true)]
  pub url: Option<String>,
  /// API token，默认读配置文件。
  #[arg(
    long,
    env = "WHARF_TOKEN",
    global = true,
    hide_env_values = true
  )]
  pub token: Option<String>,
  #[command(subcommand)]
  pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
  /// 保存控制面地址和 token（token 从标准输入读取，不回显）。
  Login {
    #[arg(long)]
    url: String,
  },
  /// 总览：服务器、服务、网关、路由的状态。
  Status,
  /// 服务器。
  #[command(subcommand)]
  Server(ServerCmd),
  /// 服务（一个服务就是一个 compose project）。
  #[command(subcommand)]
  Service(ServiceCmd),
  /// 网关。
  #[command(subcommand)]
  Gateway(GatewayCmd),
  /// 路由（域名）。
  #[command(subcommand)]
  Route(RouteCmd),
  /// 厂商账号（Cloudflare）。
  #[command(subcommand)]
  Account(AccountCmd),
  /// 密钥。服务的环境变量里用 `[[NAME]]` 引用。
  #[command(subcommand)]
  Secret(SecretCmd),
  /// 生成计划。不带参数时只检查漂移；`-f` 时以意图文件为完整期望状态。
  Plan {
    #[arg(short = 'f', long)]
    file: Option<std::path::PathBuf>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 执行计划。
  Apply {
    plan_id: String,
    /// 确认高风险项，可以多次使用。
    #[arg(long)]
    confirm: Vec<String>,
    /// 不等待执行结束，只返回 run_id。
    #[arg(long)]
    no_wait: bool,
  },
  /// 执行记录。
  #[command(subcommand)]
  Run(RunCmd),
  /// 导出当前期望状态为 TOML 意图文件。
  Export {
    #[arg(short = 'o', long)]
    output: Option<std::path::PathBuf>,
  },
  /// 输出字段说明（JSON Schema），不需要连接控制面。
  Schema {
    /// fleet、service、gateway、route、server、change、plan、run、status、error。不填则列出全部。
    resource: Option<String>,
  },
  /// API token。
  #[command(subcommand)]
  Token(TokenCmd),
}

/// 修改类命令共用：生成计划后是否直接执行。
#[derive(Args, Clone, Default)]
pub struct ApplyFlags {
  /// 生成计划后直接执行并等待结束。有高风险项时仍需要 `--confirm`。
  #[arg(long)]
  pub apply: bool,
  /// 和 `--apply` 一起用：确认高风险项。
  #[arg(long)]
  pub confirm: Vec<String>,
}

#[derive(Subcommand)]
pub enum ServerCmd {
  List,
  Show {
    name: String,
  },
  /// 登记服务器并给出 agent 加入命令。
  Add {
    name: String,
    /// 已加入的服务器重新生成加入命令（换机器、重装 agent 时）。
    #[arg(long)]
    rejoin: bool,
  },
  /// 修改服务器设置。
  Set {
    name: String,
    #[arg(long, value_parser = ["cn", "overseas"])]
    region: Option<String>,
    /// 覆盖 agent 探测的公网 IP；传空字符串清除。
    #[arg(long)]
    public_ip: Option<String>,
    /// 镜像源，例如 `docker.io=docker.1ms.run,docker.m.daocloud.io`，可以多次使用。
    #[arg(long)]
    mirror: Vec<String>,
    /// 清空全部镜像源。
    #[arg(long)]
    clear_mirrors: bool,
    /// 有镜像源时不再尝试原地址。
    #[arg(long)]
    mirrors_only: Option<bool>,
    /// 手动指定内网地址（没有组网工具、机器之间内网直通时用）；传空字符串恢复自动检测。
    #[arg(long)]
    private_ip: Option<String>,
    /// 内网地址所在网络：lan（普通内网，明文）或 overlay（WireGuard 等加密组网）。
    #[arg(long, default_value = "lan", value_parser = ["lan", "overlay"])]
    network: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除服务器（上面不能还有服务和网关）。
  Rm {
    name: String,
  },
}

#[derive(Subcommand)]
pub enum ServiceCmd {
  List,
  Show {
    name: String,
  },
  Logs {
    name: String,
    #[arg(long, default_value_t = 200)]
    tail: u32,
    /// 持续输出新日志，Ctrl-C 结束。
    #[arg(short, long)]
    follow: bool,
  },
  /// 部署历史。
  History {
    name: String,
  },
  /// 回滚到之前的一次部署（默认是上一个不同的版本）。
  /// image 来源会固定到当时的镜像 digest。
  Rollback {
    name: String,
    /// 部署记录 id，见 `wharf service history`。
    #[arg(long)]
    to: Option<i64>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 新建或更新服务。已存在的服务只修改给出的参数。
  Deploy {
    name: String,
    /// 镜像，例如 `traefik/whoami`。
    #[arg(long, conflicts_with = "compose")]
    image: Option<String>,
    /// compose 文件路径。
    #[arg(long)]
    compose: Option<std::path::PathBuf>,
    /// 运行在哪台服务器上。只有一台服务器时可以不填。
    #[arg(long)]
    server: Option<String>,
    /// 端口：`名字=容器端口` 或 `名字=容器端口:宿主机端口`，可以多次使用。
    /// compose 来源写 `名字=宿主机端口`。给出后替换全部端口。
    #[arg(long)]
    port: Vec<String>,
    /// 环境变量 `KEY=VALUE`，值里可以用 `[[SECRET]]`。可以多次使用。
    #[arg(long)]
    env: Vec<String>,
    /// 删除环境变量。
    #[arg(long)]
    unset_env: Vec<String>,
    /// 数据卷 `名字:/容器内路径`，宿主机目录是 /srv/<服务>/<名字>。可以多次使用。
    #[arg(long)]
    volume: Vec<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 迁移到另一台服务器：同步 /srv/<服务>/ 的数据，在新服务器上启动，
  /// 网关改指新地址后删除旧容器，域名不变。旧服务器上的数据目录保留。
  Move {
    name: String,
    #[arg(long)]
    to: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除服务（数据目录保留）。
  Rm {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

#[derive(Subcommand)]
pub enum GatewayCmd {
  List,
  Show {
    name: String,
  },
  /// 查看生成的 Caddyfile 和 compose。
  Config {
    name: String,
  },
  Logs {
    name: String,
    #[arg(long, default_value_t = 200)]
    tail: u32,
  },
  /// 在某台服务器上新建网关。
  Add {
    name: String,
    #[arg(long)]
    server: String,
    #[arg(long, default_value = "caddy", value_parser = ["caddy"])]
    kind: String,
    /// 设为默认入口。
    #[arg(long)]
    default: bool,
    #[arg(long)]
    http_port: Option<u16>,
    #[arg(long)]
    https_port: Option<u16>,
    #[arg(long)]
    email: Option<String>,
    /// caddy 镜像，默认 caddy:2。
    #[arg(long)]
    image: Option<String>,
    /// 证书方式：auto（公网签证书）、internal（自签）、off（只走 HTTP，内网用）。
    #[arg(long, default_value = "auto", value_parser = ["auto", "internal", "off"])]
    tls: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  Rm {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

#[derive(Subcommand)]
pub enum RouteCmd {
  List,
  /// 新增或修改路由。
  Add {
    hostname: String,
    #[arg(long)]
    service: String,
    /// 端口名，服务只有一个端口时可以不填。
    #[arg(long)]
    port: Option<String>,
    /// 网关，不填用默认网关。
    #[arg(long)]
    gateway: Option<String>,
    /// 登录保护：访问时要输入账号密码。账号用 `wharf secret set BASIC_AUTH` 设置。
    #[arg(long)]
    auth: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  Rm {
    hostname: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

#[derive(Subcommand)]
pub enum AccountCmd {
  List,
  /// 添加账号，token 从标准输入读取，然后自动发现 zone。
  Add {
    name: String,
    #[arg(long, default_value = "cloudflare", value_parser = ["cloudflare"])]
    kind: String,
  },
  /// 重新发现 zone。
  Discover {
    name: String,
  },
  Rm {
    name: String,
  },
}

#[derive(Subcommand)]
pub enum SecretCmd {
  List,
  /// 设置密钥，值从标准输入读取。
  /// `BASIC_AUTH` 是登录保护的账号，值写成 `用户名:密码`，只保存哈希。
  Set {
    name: String,
  },
  Rm {
    name: String,
  },
}

#[derive(Subcommand)]
pub enum RunCmd {
  List {
    #[arg(long, default_value_t = 20)]
    limit: u32,
  },
  Show {
    run_id: String,
  },
  /// 等待执行结束。
  Wait {
    run_id: String,
  },
  Cancel {
    run_id: String,
  },
}

#[derive(Subcommand)]
pub enum TokenCmd {
  List,
  /// 新建 token（只显示这一次）。AI 默认用 apply_safe。
  Create {
    name: String,
    #[arg(long, value_parser = ["read", "plan", "apply_safe", "apply_all"])]
    scope: String,
  },
  Rm {
    name: String,
  },
}

#[tokio::main]
async fn main() {
  let cli = Cli::parse();
  let as_json = cli.json;
  let code = match commands::run(cli).await {
    Ok(()) => 0,
    Err(client::CliError::Exit(code)) => code,
    Err(client::CliError::Api(e)) => {
      print::error(&e, as_json);
      e.code.exit_code()
    }
  };
  std::process::exit(code);
}
