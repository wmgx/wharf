//! `wharf`：Wharf 的命令行，给 AI 用。
//!
//! - 所有命令都支持 `--json`，输出结构稳定；
//! - 修改类命令只生成计划，`wharf apply <plan_id>` 才执行；加 `--apply` 可以一步完成；
//! - 错误统一为 `{ code, message, hint, suggest }`；
//! - 退出码：0 成功，1 出错，2 需要确认，3 计划已过期，4 执行部分失败。

use clap::{Args, Parser, Subcommand};

mod audit;
mod client;
mod commands;
mod connect;
mod deploy;
mod edge;
mod fleet;
mod gh;
mod pack;
mod print;
mod task;
mod tunnel;

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
    /// 控制面公钥（页面“设置 → CLI 与 AI 接入”里的登录命令带着）。之后只认这个公钥，防中间人。
    #[arg(long, env = "WHARF_CORE_KEY")]
    core_key: String,
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
  /// 出口：控制面调厂商 API（Cloudflare、Tailscale）经哪台出口，以及预置分组。
  /// 不带参数时显示现状。
  Egress {
    #[command(subcommand)]
    cmd: Option<EgressCmd>,
  },
  /// 通知：发一条测试消息。渠道用密钥配置，飞书群机器人设 NOTIFY_FEISHU_WEBHOOK
  /// （开了签名校验再设 NOTIFY_FEISHU_SECRET）。
  #[command(subcommand)]
  Notify(NotifyCmd),
  /// 只读诊断：沿每个域名逐层检查（解析 → HTTPS → 网关 → 网关连上游 → 容器）。
  /// 有不通的项时退出码为 1。
  Doctor {
    /// 只查这个域名。
    hostname: Option<String>,
  },
  /// 打点：服务器或服务的资源曲线（host.* / svc.*），以及部署、备份耗时等事件。
  Metrics {
    /// 服务器名或服务名。
    subject: String,
    /// 只看这些，逗号分隔，例如 host.cpu,host.mem。
    #[arg(long)]
    names: Option<String>,
    #[arg(long, default_value = "24h", value_parser = ["1h", "24h", "7d", "30d"])]
    range: String,
  },
  /// 数据：每个服务的挂载和备份情况。
  Data,
  /// 按服务名在本机开一个端口连到服务（数据库客户端等用）。
  /// 能直连组网或局域网地址就直连，否则经控制面中转。
  Connect {
    service: String,
    /// 端口名、容器端口或宿主机端口；服务只有一个端口时可以不填。
    #[arg(long)]
    port: Option<String>,
    /// compose 里的组件名，连没有发布的容器端口时用。
    #[arg(long)]
    component: Option<String>,
    /// 本机端口，默认用服务的端口号，被占用时随机。
    #[arg(long)]
    local: Option<u16>,
    /// 多久后自动断开，例如 30m、2h。
    #[arg(long, default_value = "2h", value_parser = connect::parse_ttl)]
    ttl: std::time::Duration,
    /// 不探测直连，直接经控制面中转。
    #[arg(long)]
    relay: bool,
  },
  /// 在宿主机执行一次非交互 shell 命令。
  Exec {
    server: String,
    #[arg(long)]
    timeout: Option<u64>,
    #[arg(long)]
    cwd: Option<String>,
    /// 完整 shell 命令；写在 `--` 后并用本地 shell 引号保护。
    #[arg(last = true, required = true)]
    command: String,
  },
  /// 操作记录和登录记录：谁在什么时候做了什么。
  Audit {
    /// 只看这个发起人（令牌名，或 页面:<用户名>）。
    #[arg(long)]
    actor: Option<String>,
    /// 只看一类：api 或 login。
    #[arg(long, value_parser = ["api", "login"])]
    kind: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: u32,
  },
  /// 宿主机终端和命令执行审计。
  ShellLog {
    #[arg(long)]
    server: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: u32,
  },
  /// 组网：各服务器怎么接入（tailscale / lan / public）、谁能连谁的内网地址。
  Network {
    /// 先让每台在线服务器探测其余服务器，再显示结果。
    #[arg(long)]
    probe: bool,
  },
  /// 告警规则和事件通知：开关、阈值、连续次数、静默。
  #[command(subcommand)]
  Alert(AlertCmd),
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
  /// 定时任务：按 cron（北京时间）在服务容器里、一次性容器里或宿主机上执行命令。
  /// 改动直接生效，不走计划。
  #[command(subcommand)]
  Task(task::TaskCmd),
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
#[allow(clippy::large_enum_variant)] // 命令行参数，只解析一次
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
    /// 额外绑定的局域网地址（私有网段），可以多次使用；服务端口也绑到这些地址上。
    /// 可选地址见 `wharf server show <name>` 里 agent 上报的 lan_ips。
    #[arg(long)]
    lan_ip: Vec<String>,
    /// 清空额外绑定的局域网地址。
    #[arg(long)]
    clear_lan_ips: bool,
    /// 构建时传给内置模板的参数 `KEY=VALUE`（国内机器配 PIP_INDEX_URL、GOPROXY），可以多次使用。
    #[arg(long)]
    build_env: Vec<String>,
    /// 清空构建参数。
    #[arg(long)]
    clear_build_env: bool,
    /// 拉代码时用的 HTTP 代理，例如 `http://100.x.x.x:8118`；传空字符串清除。设了 `--via` 时不用它。
    #[arg(long)]
    git_proxy: Option<String>,
    /// 拉镜像时 dockerd 用的 HTTP 代理，例如 `http://100.x.x.x:8118`；镜像源和内网直连。
    /// apply 时改宿主机的 daemon.json 并重启 dockerd（开启 live-restore，容器不停）；传空字符串清除。
    /// 设了 `--via` 时不用它。
    pull_proxy: Option<String>,
    /// 这台提供出口，以及经它出去的规则：`all`（除内网外全部），或逗号分隔的预置分组和域名，
    /// 例如 `github,cloudflare,*.example.com`（分组见 `wharf egress presets`）；`off` 关闭。
    #[arg(long)]
    egress: Option<String>,
    /// 经哪台的出口出去：本机起分流代理，拉镜像、构建、拉代码按那台的规则分流，出口连不上时直连；
    /// 传空字符串清除。
    #[arg(long)]
    via: Option<String>,
    /// 代替 `https://github.com/` 拉代码的地址，例如 `https://gh.example.com/[[MIRROR_TOKEN]]`；
    /// 可以引用密钥；传空字符串清除。
    #[arg(long)]
    github_mirror: Option<String>,
    /// 是否允许从页面打开宿主机终端。用 token 只能关（false），打开要在页面上操作。
    #[arg(long)]
    host_terminal: Option<bool>,
    /// 是否允许通过 API 在宿主机执行命令。用 token 只能关（false），打开要在页面上操作。
    #[arg(long)]
    host_exec: Option<bool>,
    /// 每月流量额度（GB），只用于显示用了多少；0 清除。
    #[arg(long)]
    traffic_quota_gb: Option<u32>,
    /// 流量每月几号重置（1 到 28，北京时间）；0 清除（按 1 号）。
    #[arg(long)]
    traffic_reset_day: Option<u8>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除服务器（上面不能还有服务和网关）。
  Rm {
    name: String,
  },
  /// 机器基线：不带设置参数时立即检查并列出差异；带参数时修改基线，--apply 时纠正。
  /// 有差异时只加 --apply 也会纠正。不管 ssh 和防火墙。
  Baseline {
    name: String,
    /// 时区，例如 Asia/Shanghai；传空字符串不再管。
    #[arg(long)]
    timezone: Option<String>,
    /// 没有 swap 时建一个这么大的 /swapfile（GB）；0 不再管。
    #[arg(long)]
    swap_gb: Option<u32>,
    /// 内核参数 `KEY=VALUE`，例如 net.ipv4.tcp_congestion_control=bbr，可以多次使用；值为空不再管。
    #[arg(long)]
    sysctl: Vec<String>,
    /// 容器日志轮转：单个文件上限和保留个数，例如 `20m:3`；传空字符串不再管。
    #[arg(long)]
    docker_log: Option<String>,
    /// journald 日志总上限，例如 500M；传空字符串不再管。
    #[arg(long)]
    journal_max: Option<String>,
    /// 自动安装安全更新：on、off，或 none 不再管。
    #[arg(long, value_parser = ["on", "off", "none"])]
    security_updates: Option<String>,
    /// 从另一台服务器复制整份基线。
    #[arg(long)]
    copy_from: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
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
  /// 宿主机信息：系统版本、待装更新、docker 和日志占用。
  Host {
    name: String,
  },
}

#[derive(Subcommand)]
// 只在启动时解析一次，变体大小无所谓。
#[allow(clippy::large_enum_variant)]
pub enum ServiceCmd {
  /// 服务的时间线：部署、备份、任务、自动重启、告警、操作记录。
  Timeline {
    name: String,
    #[arg(long, default_value_t = 50)]
    limit: u32,
    /// 只看这个毫秒时间戳之前的（上一页返回的 next_before）。
    #[arg(long)]
    before: Option<i64>,
  },
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
  /// 设置备注（给人看的说明，不影响部署，直接保存）。传空字符串清除。
  Note {
    name: String,
    note: String,
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
  /// 检查更新：image 来源重新查镜像标签现在的版本，git 构建来源重新查分支现在的 commit，
  /// 有新版本时计划里会更新。平时改配置不会换版本。
  Update {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
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
    /// compose 来源只有宿主机端口，写 `名字=:宿主机端口`。给出后替换全部端口。
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
  /// 从代码构建的服务：按固定的 commit 重新构建并部署（本机目录用上次上传的）。
  /// 要换成最新代码用 `wharf service update`。
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
    /// 连同数据一起删：/srv/<服务> 目录和 compose 声明的命名卷，不能恢复。外部目录不动。
    #[arg(long)]
    purge_data: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 自定义监控：服务所在机器每分钟请求 `http://127.0.0.1:<端口><路径>`，连续 3 次不正常推送。
  /// 例：`wharf service monitor blog --path /health --keyword ok --apply`；`--off` 关闭。
  Monitor {
    name: String,
    /// 请求路径，默认 `/`。
    #[arg(long)]
    path: Option<String>,
    /// 端口名，默认第一个端口。
    #[arg(long)]
    port: Option<String>,
    /// 期望的状态码；不写时 2xx、3xx 都算正常。
    #[arg(long)]
    expect: Option<u16>,
    /// 应答里必须包含的文字。
    #[arg(long)]
    keyword: Option<String>,
    /// 关闭监控。
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 资源上限。例：`wharf service limits blog --memory 512 --cpus 0.5 --apply`；`--off` 去掉全部上限。
  Limits {
    name: String,
    /// 内存上限，单位 MB；给 0 去掉这一项。
    #[arg(long)]
    memory: Option<u32>,
    /// CPU 上限，单位核，可以是小数；给 0 去掉这一项。
    #[arg(long)]
    cpus: Option<f64>,
    /// 去掉全部上限。
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

#[derive(Subcommand)]
pub enum AlertCmd {
  /// 告警里附带服务最近的日志：`wharf alert options --include-logs on`。
  Options {
    #[arg(long, value_parser = ["on", "off"])]
    include_logs: String,
  },
  /// 规则、事件通知、正在触发的告警、最近的推送。
  List,
  /// 改一条规则或事件通知（id 见 list）。只改给了的选项。
  Set {
    id: String,
    /// 打开
    #[arg(long, conflicts_with = "off")]
    on: bool,
    /// 关闭
    #[arg(long)]
    off: bool,
    #[arg(long)]
    threshold: Option<f64>,
    /// 连续多少次（窗口规则是窗口里多少次）才触发。
    #[arg(long = "for")]
    for_n: Option<u32>,
    /// 静默多少分钟，0 取消。
    #[arg(long)]
    mute: Option<u32>,
    /// 恢复默认值。
    #[arg(long)]
    reset: bool,
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
    /// 镜像：caddy 默认 Wharf 自建的 wharf-caddy，cloudflare_tunnel 默认 cloudflare/cloudflared。
    #[arg(long)]
    image: Option<String>,
    /// 证书方式：auto（公网签证书）、internal（自签）、off（只走 HTTP，内网用）。
    #[arg(long, default_value = "auto", value_parser = ["auto", "internal", "off"])]
    tls: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 错误页：网关连不上服务时（502、503、504）显示的页面。
  /// 例：`wharf gateway error-page edge --file 502.html --apply`；`--default` 换回内置页。
  ErrorPage {
    name: String,
    /// HTML 文件；`-` 从标准输入读。
    #[arg(long, conflicts_with = "default", required_unless_present = "default")]
    file: Option<String>,
    /// 换回内置的默认页。
    #[arg(long)]
    default: bool,
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
      required_unless_present_any = ["upstream", "redirect"],
      conflicts_with_all = ["upstream", "redirect"]
    )]
    service: Option<String>,
    /// 不归 Wharf 管的上游，写网关所在机器能访问到的 主机:端口，例如 127.0.0.1:7700。
    #[arg(long)]
    upstream: Option<String>,
    /// 只做跳转：整个域名 301 到这个网址，保留路径和参数，例如 https://a.com。只支持 caddy 网关。
    #[arg(long, conflicts_with = "upstream")]
    redirect: Option<String>,
    /// 端口名，服务只有一个端口时可以不填。
    #[arg(long)]
    port: Option<String>,
    /// 网关，不填用默认网关。
    #[arg(long)]
    gateway: Option<String>,
    /// 备用入口：另一台机器上的网关。主网关那台连续离线 5 分钟，DNS 自动切到它，恢复后切回。
    #[arg(long)]
    backup_gateway: Option<String>,
    /// 登录保护：访问时要输入账号密码。账号用 `wharf secret set BASIC_AUTH_<域名，. 换成 _>` 设置。
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
  /// `BASIC_AUTH_<域名，. 换成 _>` 是这个域名的登录保护账号，值写成 `用户名:密码`，只保存哈希。
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
  /// 新建 token（只显示这一次）。给 AI 常用 `--perms plan,apply,exec`。
  Create {
    name: String,
    /// 权限点，逗号分隔：read、plan、apply、confirm、exec、admin（read 总是带上）。
    #[arg(
      long,
      conflicts_with = "scope",
      required_unless_present = "scope"
    )]
    perms: Option<String>,
    /// 旧档位预设：read、plan、apply_safe、apply_all。
    #[arg(long, value_parser = ["read", "plan", "apply_safe", "apply_all"])]
    scope: Option<String>,
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

#[derive(Subcommand)]
pub enum NotifyCmd {
  /// 给所有已配置的渠道发一条测试消息。
  Test,
}

#[derive(Subcommand)]
pub enum EgressCmd {
  /// 设置控制面调厂商 API 经哪台出口（按那台的规则分流）；空字符串直连。
  Api { server: String },
  /// 列出预置分组和包含的域名。
  Presets,
}
