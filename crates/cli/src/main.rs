//! `wharf`：Wharf 的命令行，给 AI 用。
//!
//! - 所有命令都支持 `--json`，输出结构稳定；
//! - 修改类命令只生成计划，`wharf apply <plan_id>` 才执行；加 `--apply` 可以一步完成；
//! - 错误统一为 `{ code, message, hint, suggest }`；
//! - 退出码：0 成功，1 出错，2 需要确认，3 计划已过期，4 执行部分失败。

use clap::{Args, Parser, Subcommand};

mod client;
mod commands;
mod deploy;
mod edge;
mod fleet;
mod gh;
mod pack;
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
  /// 部署本机代码目录：打包上传，在服务器上构建并运行。
  /// Python、Go 自动识别，有 Dockerfile 就用。再次执行就是发布新版本。
  Deploy {
    /// 代码目录，默认当前目录。
    #[arg(default_value = ".")]
    dir: std::path::PathBuf,
    /// 服务名，默认取目录名。
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    server: Option<String>,
    /// 端口 `名字=容器端口`，不给时 Python 用 8000、Go 用 8080。
    #[arg(long)]
    port: Vec<String>,
    #[arg(long)]
    env: Vec<String>,
    #[command(flatten)]
    build: BuildOpts,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 升级 Wharf：控制面换成最新镜像，再把各服务器的 agent 升到同一版本。
  Upgrade,
  /// 只读诊断：沿每个域名逐层检查（解析 → HTTPS → 网关 → 网关连上游 → 容器）。
  /// 有不通的项时退出码为 1。
  Doctor {
    /// 只查这个域名。
    hostname: Option<String>,
  },
  /// 组网：各服务器怎么接入（tailscale / lan / public）、谁能连谁的内网地址。
  Network {
    /// 先让每台在线服务器探测其余服务器，再显示结果。
    #[arg(long)]
    probe: bool,
  },
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
  /// 边缘应用（Cloudflare Workers / Pages）：导入、发布、版本和回滚。
  #[command(subcommand)]
  Edge(edge::EdgeCmd),
  /// 密钥。服务的环境变量里用 `[[NAME]]` 引用。
  #[command(subcommand)]
  Secret(SecretCmd),
  /// 备份：服务的 /srv/<服务>/ 每天用 restic 备份到另一台服务器。
  #[command(subcommand)]
  Backup(BackupCmd),
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

/// 从代码构建：本机目录或 git 仓库，加上构建选项。
#[derive(Args, Clone, Default)]
pub struct BuildArgs {
  /// 本机代码目录：打包上传，在服务器上构建（Python、Go 自动识别，有 Dockerfile 就用）。
  #[arg(long)]
  pub dir: Option<std::path::PathBuf>,
  /// git 仓库（https 地址），在服务器上拉代码构建。
  #[arg(long)]
  pub git: Option<String>,
  /// git 的分支、标签或 commit，默认 main。
  #[arg(long = "ref")]
  pub git_ref: Option<String>,
  /// 私有仓库：保存访问 token 的密钥名（先 `wharf secret set`）。
  /// GitHub 私有仓库不给时，用本机 gh 的登录存进密钥 GITHUB_TOKEN。
  #[arg(long)]
  pub git_token_secret: Option<String>,
  #[command(flatten)]
  pub opts: BuildOpts,
}

/// 怎么构建：代码里的 Dockerfile、Wharf 里保存的 Dockerfile，或内置模板。
#[derive(Args, Clone, Default)]
pub struct BuildOpts {
  /// 代码里的子目录，作为构建目录。
  #[arg(long)]
  pub path: Option<String>,
  /// 代码里的 Dockerfile 路径（相对构建目录）。不给时有 Dockerfile 就用，没有就用模板。
  #[arg(long)]
  pub dockerfile: Option<String>,
  /// 本机的 Dockerfile 文件，内容存进 Wharf（代码里不用放 Dockerfile）。
  #[arg(long, conflicts_with_all = ["dockerfile", "template", "base", "start", "start_file", "install"])]
  pub dockerfile_file: Option<std::path::PathBuf>,
  /// 内置模板，`auto` 表示按文件识别。
  #[arg(long, value_parser = ["auto", "python", "node", "go", "static"])]
  pub template: Option<String>,
  /// 内置模板的基础镜像，例如 `python:3.12-slim`。
  #[arg(long)]
  pub base: Option<String>,
  /// 覆盖内置模板安装依赖的命令（Python、Node），例如 `npm ci && npm run build`。
  #[arg(long)]
  pub install: Option<String>,
  /// 内置模板的启动命令，监听端口用 `$PORT`，例如 `python run.py`。
  #[arg(long, conflicts_with = "start_file")]
  pub start: Option<String>,
  /// 启动脚本文件（多行 shell），内容存进 Wharf。
  #[arg(long)]
  pub start_file: Option<std::path::PathBuf>,
  /// 只打印会用的 Dockerfile，不部署（只支持本机目录）。
  #[arg(long)]
  pub print_dockerfile: bool,
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
    /// agent 连接控制面用的地址，例如 https://wharf.example.com。不给时用控制面的启动配置。
    #[arg(long)]
    core_url: Option<String>,
    /// agent 镜像，国内机器可以换成镜像站地址。
    #[arg(long)]
    agent_image: Option<String>,
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
    /// 接入方式：tailscale（没装时由 Wharf 装 Tailscale 容器并加入）、lan（要 --private-ip）、
    /// public（不用内网地址，网关一律走反向隧道）、auto（按检测到的地址推断）。
    #[arg(long, value_parser = ["tailscale", "lan", "public", "auto"])]
    mode: Option<String>,
    /// 构建时传给内置模板的参数 `KEY=VALUE`（国内机器配 PIP_INDEX_URL、GOPROXY），可以多次使用。
    #[arg(long)]
    build_env: Vec<String>,
    /// 清空构建参数。
    #[arg(long)]
    clear_build_env: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除服务器（上面不能还有服务和网关）。
  Rm {
    name: String,
  },
  /// 升级 agent 到和控制面相同的版本：拉新镜像，换掉 agent 容器，新 agent 连不上就恢复旧的。
  Upgrade {
    /// 服务器名；不给时用 `--all`。
    name: Option<String>,
    /// 升级全部版本落后的在线服务器，一台接一台。
    #[arg(long, conflicts_with = "name")]
    all: bool,
  },
  /// 删除没有容器在用的镜像和构建缓存，腾出磁盘。
  Prune {
    name: String,
  },
}

#[derive(Subcommand)]
// 只在启动时解析一次，变体大小无所谓。
#[allow(clippy::large_enum_variant)]
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
  /// 停止：容器保留但不运行，之后部署也保持停止。生成计划。
  Stop {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 启动之前停止的服务。生成计划。
  Start {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 重启容器，不改配置、不重建。
  Restart {
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
  /// 列出服务器上还没纳管的容器（compose 项目或 `docker run` 起的容器）。
  Discover {
    server: String,
  },
  /// 把服务器上已有的 compose 项目或容器导入成服务。
  Import {
    server: String,
    /// compose 项目名。
    #[arg(
      long,
      conflicts_with = "container",
      required_unless_present = "container"
    )]
    project: Option<String>,
    /// `docker run` 起的容器名。
    #[arg(long)]
    container: Option<String>,
    /// 服务名，不填时由项目名或容器名得出。和原 compose 项目同名时不重建容器。
    #[arg(long)]
    name: Option<String>,
    /// 打印转换出的 compose（可能含明文的环境变量）。
    #[arg(long)]
    print: bool,
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
    build: BuildArgs,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 从代码构建的服务：拉最新代码（本机目录用上次上传的）重新构建并部署。
  Rebuild {
    name: String,
    /// 只发起，不等结束。
    #[arg(long)]
    no_wait: bool,
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
    /// caddy：服务器要有公网 IP 和 80/443；cloudflare_tunnel：走 Cloudflare 隧道，不用开端口。
    #[arg(long, default_value = "caddy", value_parser = ["caddy", "cloudflare_tunnel"])]
    kind: String,
    /// cloudflare_tunnel：在哪个厂商账号下建隧道，只有一个账号时可以不填。
    #[arg(long)]
    account: Option<String>,
    /// 设为默认入口。
    #[arg(long)]
    default: bool,
    #[arg(long)]
    http_port: Option<u16>,
    #[arg(long)]
    https_port: Option<u16>,
    #[arg(long)]
    email: Option<String>,
    /// 镜像：caddy 默认 caddy:2，cloudflare_tunnel 默认 cloudflare/cloudflared。
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
    /// 服务或边缘应用（Workers / Pages）的名字。
    #[arg(
      long,
      required_unless_present = "upstream",
      conflicts_with = "upstream"
    )]
    service: Option<String>,
    /// 不归 Wharf 管的上游，写网关所在机器能访问到的 主机:端口，例如 127.0.0.1:7700。
    #[arg(long)]
    upstream: Option<String>,
    /// 端口名，服务只有一个端口时可以不填。
    #[arg(long)]
    port: Option<String>,
    /// 网关，不填用默认网关。
    #[arg(long)]
    gateway: Option<String>,
    /// 登录保护：访问时要输入账号密码。账号用 `wharf secret set BASIC_AUTH` 设置。
    #[arg(long)]
    auth: bool,
    /// 按路径转发，可以多次给：`/ws=服务[:端口名]` 或 `/ws=127.0.0.1:17891`（不归 Wharf 管的上游）。
    /// `/api/*` 匹配前缀。只支持 caddy 网关。
    #[arg(long = "path", value_name = "PATH=TARGET")]
    paths: Vec<String>,
    /// 总是走反向隧道。不给时自动选：同机、能直连内网地址就直连，否则走隧道。
    #[arg(long)]
    tunnel: bool,
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
pub enum BackupCmd {
  /// 开启每天自动备份（先停服务、备份、再启动，通常几秒）。
  Enable {
    service: String,
    /// 备份存到哪台服务器，不能是服务所在的服务器。
    #[arg(long)]
    to: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 关闭自动备份。已有的快照保留在备份服务器上。
  Disable {
    service: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 立即备份一次并等待结束。
  Run {
    service: String,
    /// 不等待执行结束，只返回 run_id。
    #[arg(long)]
    no_wait: bool,
  },
  /// 备份记录和快照。
  List { service: String },
  /// 控制面自身备份（数据库和密钥）。不带参数时查看状态和恢复命令。
  /// `--to` 开启或换备份服务器，会要求输入登录密码：它会成为恢复口令。
  Core {
    #[arg(long, conflicts_with = "run")]
    to: Option<String>,
    /// 立即备份一次。
    #[arg(long)]
    run: bool,
  },
  /// 恢复快照：停服务、恢复数据、启动。原来的数据改名保留在 /srv/.wharf-restore/ 下。
  Restore {
    service: String,
    /// 快照 id（见 `wharf backup list`），默认最新的。
    #[arg(long, default_value = "latest")]
    snapshot: String,
    /// 必须写 `service/<名称>`：恢复会覆盖现有数据。
    #[arg(long)]
    confirm: Option<String>,
    #[arg(long)]
    no_wait: bool,
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
