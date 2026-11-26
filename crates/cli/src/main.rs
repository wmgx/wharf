//! `wharf`：Wharf 的命令行，给 AI 用。
//!
//! - 所有命令都支持 `--json`，输出结构稳定；
//! - 修改类命令只生成计划，`wharf apply <plan_id>` 才执行；加 `--apply` 可以一步完成；
//! - 错误统一为 `{ code, message, hint, suggest }`；
//! - 退出码：0 成功，1 出错，2 需要确认，3 计划已过期，4 执行部分失败。

use clap::{Args, Parser, Subcommand};

mod access_logs;
mod alert;
mod audit;
mod bookmark;
mod client;
mod commands;
mod connect;
mod deploy;
mod describe;
mod edge;
mod external;
mod files;
mod fleet;
mod gh;
mod note;
mod pack;
mod preview;
mod print;
mod probe;
mod report;
mod selfcmd;
mod server;
mod service_checks;
mod task;
mod token;
mod top;
mod tunnel;
mod view;
mod wait;

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
  /// 只输出这些字段，逗号分隔，`a.b` 取嵌套字段，列表按每一项取；隐含 `--json`。
  /// 例：`wharf service list --fields name,status.summary`。
  #[arg(long, global = true)]
  pub fields: Option<String>,
  /// 列表分页：每页多少项；隐含 `--json`。总数写在标准错误里。
  /// 例：`wharf service list --page-size 20 --page 2`。
  #[arg(long, global = true)]
  pub page_size: Option<usize>,
  /// 第几页，从 1 开始，和 `--page-size` 一起用。
  #[arg(
    long,
    global = true,
    default_value_t = 1,
    requires = "page_size"
  )]
  pub page: usize,
  /// 只输出和上次执行同一条命令相比变了的地方（`path`、`before`、`after`）；隐含 `--json`。
  /// 第一次执行时整份输出算一条变化。上次的结果存在本机缓存目录里。
  #[arg(long, global = true)]
  pub changed: bool,
  /// 这次操作的原因，记进操作记录（`wharf audit` 和页面上看得到）。
  /// 例：`wharf service restart blog --reason "内存泄漏，先重启"`。
  #[arg(long, global = true)]
  pub reason: Option<String>,
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
pub enum SsoCmd {
  #[command(
    long_about = "实际登录一次应用并检查结果。开启 use_account 时，用 wharf sso account set 保存账号，再用 wharf sso account link <名称> <域名> --default 设为默认。用 wharf route sso <域名> --mode login --file <文件> --apply 应用代登录配置，再运行 wharf sso test <域名>。"
  )]
  Test { hostname: String },
  /// Wharf 当 OIDC 身份提供方的信息：issuer、发现地址、各应用的 client_id 和密钥引用。
  #[command(
    long_about = "给了域名就只看这个应用。接入步骤：先 wharf route sso <域名> --mode oidc --redirect <回调路径> --apply；再把这里输出的 issuer、client_id、secret_ref 写进服务环境变量（secret_ref 原样写，例如 [[OIDC_BLOG_EXAMPLE_COM]]，部署时自动换成密钥），重新部署服务。很多应用要求邮箱，没设时用 wharf sso email <邮箱> 设置。"
  )]
  Oidc { hostname: Option<String> },
  /// 设置发给应用的邮箱；--clear 清除。
  Email {
    #[arg(required_unless_present = "clear")]
    email: Option<String>,
    #[arg(long, conflicts_with = "email")]
    clear: bool,
  },
  /// 管理应用账号和关联域名。
  #[command(subcommand)]
  Account(AppAccountCmd),
}

#[derive(Subcommand)]
pub enum AppAccountCmd {
  /// 列出应用账号。
  List,
  /// 新建或更新应用账号，密码从标准输入读取，不回显。
  Set {
    name: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    note: Option<String>,
    /// 保留现有密码，跳过密码输入，仅适用于已有账号。
    #[arg(long)]
    keep_password: bool,
  },
  /// 查看应用账号。
  Show {
    name: String,
    /// 显示密码，会记一条操作记录。
    #[arg(long)]
    reveal: bool,
  },
  /// 删除应用账号。
  Rm { name: String },
  /// 关联域名。
  Link {
    name: String,
    hostname: String,
    /// 设为该域名的默认账号。
    #[arg(long)]
    default: bool,
  },
  /// 取消关联域名。
  Unlink { name: String, hostname: String },
}

#[derive(Subcommand)]
pub enum Command {
  /// 统一登录：应用账号、代登录测试、OIDC 信息和邮箱。
  #[command(subcommand)]
  Sso(SsoCmd),
  /// 保存控制面地址和 token（token 从标准输入读取，不回显）。
  Login {
    #[arg(long)]
    url: String,
    /// 控制面公钥（页面“设置 → CLI 与 AI 接入”里的登录命令带着）。之后只认这个公钥，防中间人。
    #[arg(long, env = "WHARF_CORE_KEY")]
    core_key: String,
    /// 从文件读取 token。
    #[arg(long, conflicts_with = "token_cmd")]
    token_file: Option<String>,
    /// 执行命令，从标准输出首行读取 token。
    #[arg(long, conflicts_with = "token_file")]
    token_cmd: Option<String>,
  },
  /// 总览：服务器、服务、网关、路由的状态。
  Status,
  /// 全局资源或镜像排行。server usage 看单台用量均值，server disk 看目录和卷，server host 看整机概况。
  Top(top::TopArgs),
  /// 周期指标和告警摘要报告（默认对比近 7 天与上一个 7 天）。
  Report(report::ReportArgs),
  /// 部署本机代码目录：打包上传，在服务器上构建并运行。
  /// Python、Node、Go、静态站点自动识别，有 Dockerfile 就用。再次执行就是发布新版本。
  Deploy {
    /// 代码目录，默认当前目录。
    #[arg(default_value = ".")]
    dir: std::path::PathBuf,
    /// 服务名，默认取目录名。
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    server: Option<String>,
    /// 端口 `名字=容器端口`，不给时 Python 用 8000、Node 用 3000，其余用 8080。
    #[arg(long)]
    port: Vec<String>,
    #[arg(long)]
    env: Vec<String>,
    #[command(flatten)]
    build: BuildOpts,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 升级 Wharf：控制面换成最新镜像，再把各服务器的 agent 升到同一版本，最后把本机 CLI 也换成同一版本。
  Upgrade,
  /// 把本机 CLI 换成和控制面同一构建的版本，顺带更新已装的 Skill。
  SelfUpdate,
  /// 当前用的是哪个 token、有哪些权限、连的哪个控制面，以及 CLI 和控制面的版本。
  Whoami,
  /// 控制面自己：日志。
  #[command(subcommand)]
  Core(CoreCmd),
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
    #[arg(long, default_value = "24h", value_parser = ["1h", "24h", "7d", "14d", "30d"])]
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
  /// 临时分享：给服务生成一个随机子域名，到期后自动失效。用入口上的泛域名证书，不用等签证书。
  /// 例：`wharf share blog --ttl 2h --apply`。查看用 `wharf route list`，删除用 `wharf route rm`。
  Share {
    name: String,
    /// 多久后失效，例如 30m、2h、1d，最长 7d。
    #[arg(long)]
    ttl: String,
    /// 端口名，服务只有一个端口时可以不填。
    #[arg(long)]
    port: Option<String>,
    /// 入口，不填用默认入口。
    #[arg(long)]
    gateway: Option<String>,
    /// 入口开了多个泛域名证书时选一个 zone。
    #[arg(long)]
    zone: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
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
    #[command(subcommand)]
    action: Option<external::NetworkCmd>,
  },
  /// 外部服务状态。
  #[command(subcommand)]
  External(external::ExternalCmd),
  /// 告警规则、事件通知、确认、每日汇总和抑制。
  #[command(subcommand)]
  Alert(alert::AlertCmd),
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
  /// 门禁访问凭证。
  #[command(subcommand)]
  Gate(GateCmd),
  /// 厂商账号（Cloudflare）。
  #[command(subcommand)]
  Account(AccountCmd),
  /// 边缘应用（Cloudflare Workers / Pages）：导入、发布、版本和回滚。
  #[command(subcommand)]
  Edge(edge::EdgeCmd),
  /// 首页书签。
  #[command(subcommand)]
  Bookmark(bookmark::BookmarkCmd),
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
  /// 生成计划。不带参数时只检查漂移；`-f` 时以意图文件为完整期望状态，
  /// 加 `--partial` 时只新建或修改文件里写到的对象，其余不动。
  /// 例：`wharf export --service blog -o blog.toml` 改完后 `wharf plan -f blog.toml --partial`。
  Plan {
    #[arg(short = 'f', long)]
    file: Option<std::path::PathBuf>,
    /// 文件是局部的：没写到的服务、网关、路由保持原样，不会被删除。
    #[arg(long, requires = "file")]
    partial: bool,
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
  /// 导出当前期望状态为 TOML 意图文件。给了 `--service` 时只导出这些服务和指向它们的域名，
  /// 改完用 `wharf plan -f <文件> --partial` 交回。
  Export {
    #[arg(short = 'o', long)]
    output: Option<std::path::PathBuf>,
    /// 只导出这个服务（连同它的域名），可以多次使用。
    #[arg(long)]
    service: Vec<String>,
  },
  /// 不连控制面，检查意图文件写得对不对：格式、拼错的字段、名字、域名重复、compose 语法、文件内的引用。
  /// 机器、账号这些要控制面才知道的，用 `wharf plan -f` 检查。
  Validate { file: std::path::PathBuf },
  /// 输出字段说明（JSON Schema），不需要连接控制面。
  Schema {
    /// fleet、service、gateway、route、server、change、plan、run、status、error。不填则列出全部。
    resource: Option<String>,
  },
  /// API token。
  #[command(subcommand)]
  Token(TokenCmd),
  /// 等到某件事发生再返回：服务正常运行、域名各层都通、“需要注意”清空。每 5 秒查一次，超时退出码 1。
  #[command(subcommand)]
  Wait(WaitCmd),
  /// 全部命令和参数的机器可读说明（JSON），不需要连接控制面。给了前缀只列这一组，例如 `wharf commands service`。
  #[command(visible_alias = "describe")]
  Commands {
    prefix: Vec<String>,
    /// 只看这一版和本机上次用的版本相比，命令和参数有哪些增删改。
    #[arg(long)]
    changes: bool,
  },
}

#[derive(Subcommand)]
pub enum CoreCmd {
  /// 查看控制面的候选地址。
  Addresses,
  /// 立即检查控制面有没有新构建。
  Check,

  /// 控制面自己的日志。例：`wharf core logs --since 1h --errors`。
  Logs(LogArgs),
}

/// 看日志的公共参数。
#[derive(Args, Clone)]
pub struct LogArgs {
  /// 最多输出多少行（`--errors` 时是多少种报错）。
  #[arg(long, default_value_t = 200)]
  pub tail: u32,
  /// 只看这段时间内的：30m、2h、3d，或 RFC 3339 时间。
  #[arg(long)]
  pub since: Option<String>,
  /// 只看含这个关键字的行，不分大小写。筛选时在最近 5000 行里找。
  #[arg(long)]
  pub grep: Option<String>,
  /// 只看报错，同一种报错合成一条，带次数和首末时间。
  #[arg(long)]
  pub errors: bool,
  /// 每行最多多少字符，超出截断（筛选时默认 500）。
  #[arg(long)]
  pub max_line: Option<usize>,
}

#[derive(Subcommand)]
pub enum WaitCmd {
  /// 服务按配置在运行、健康检查通过（没配就不看），而且容器是当前配置；停止的服务等到它停下。
  /// 例：`wharf wait service blog --timeout 5m`。
  Service {
    name: String,
    /// 最多等多久：90s、10m、1h。
    #[arg(long, default_value = "10m")]
    timeout: String,
  },
  /// 域名从解析到容器各层都通（和 `wharf doctor <域名>` 一样的检查）。
  Route {
    hostname: String,
    #[arg(long, default_value = "10m")]
    timeout: String,
  },
  /// “需要注意”里没有事了；给了 `--subject` 只看这一个对象（名字或 `service/blog` 这种写法）。
  Clear {
    #[arg(long)]
    subject: Option<String>,
    #[arg(long, default_value = "10m")]
    timeout: String,
  },
}

/// 从代码构建：本机目录或 git 仓库，加上构建选项。
#[derive(Args, Clone, Default)]
pub struct BuildArgs {
  /// 本机代码目录：打包上传，在服务器上构建（Python、Node、Go、静态站点自动识别，有 Dockerfile 就用）。
  #[arg(long)]
  pub dir: Option<std::path::PathBuf>,
  /// git 仓库（https 地址），在服务器上拉代码构建。
  #[arg(long)]
  pub git: Option<String>,
  /// git 的分支、标签或 commit，默认 main。
  #[arg(long = "ref")]
  pub git_ref: Option<String>,
  /// 私有仓库：保存访问 token 的密钥名（先 `wharf secret set`）。
  /// GitHub 私有仓库不给时，沿用控制面已有的 GITHUB_TOKEN。
  #[arg(long)]
  pub git_token_secret: Option<String>,
  /// 用本机 gh 的登录写入或覆盖控制面 GITHUB_TOKEN。
  #[arg(long, requires = "git", conflicts_with = "git_token_secret")]
  pub sync_gh_token: bool,
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

// 修改类命令共用：生成计划后是否直接执行。
// 用普通注释：文档注释会被 clap 当成没写说明的子命令（例如 `rm`）的说明。
#[derive(Args, Clone, Default)]
pub struct ApplyFlags {
  /// 生成计划后直接执行并等待结束。有高风险项时仍需要 `--confirm`。
  #[arg(long)]
  pub apply: bool,
  /// 和 `--apply` 一起用：确认高风险项。
  #[arg(long)]
  pub confirm: Vec<String>,
  /// 计划备注，随计划保存，执行时记进操作记录。
  #[arg(long)]
  pub note: Option<String>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // 命令行参数，只解析一次
pub enum ServerCmd {
  /// 从指定服务器探测一个目标。只返回响应头和诊断结果，禁止探测云元数据地址。
  Probe(probe::ServerProbeArgs),
  /// 查看最近一次系统更新的状态，或开始安装更新。
  Apt {
    name: String,
    /// 开始安装系统更新。
    #[arg(long)]
    apply: bool,
  },
  /// 列出宿主机目录。
  Dirs {
    name: String,
    #[arg(default_value = "/")]
    path: String,
  },
  /// 把宿主机目录打包并上传到控制面。
  Pack {
    name: String,
    path: String,
    /// 为这个服务记住代码来源目录。
    #[arg(long)]
    service: Option<String>,
  },
  /// 查看或管理宿主机终端会话。
  Sessions {
    name: String,
    /// 结束指定会话。
    #[arg(long, conflicts_with = "rename")]
    end: Option<String>,
    /// 给会话改名，依次传旧名和新名。
    #[arg(long, num_args = 2, value_names = ["旧名", "新名"])]
    rename: Option<Vec<String>>,
  },
  /// 查看宿主机程序。
  HostUnits {
    name: String,
  },
  /// 查看一个宿主机程序的日志。
  HostLogs {
    name: String,
    unit: String,
    #[arg(long, default_value_t = 200)]
    lines: u32,
  },
  /// 监视一个宿主机程序。
  WatchUnit {
    name: String,
    unit: String,
    /// 取消监视。
    #[arg(long)]
    off: bool,
  },
  /// 查看单台服务器的服务、网关和 agent 最近 10 分钟平均资源用量。
  Usage {
    name: String,
  },
  /// 查看服务器本周期的流量。
  Traffic {
    name: String,
  },

  /// 设置服务器备注，直接生效。
  Note {
    name: String,
    #[command(flatten)]
    args: note::NoteArgs,
  },
  /// 本机监听端口和容器风险。
  Exposure {
    name: String,
    #[arg(long)]
    refresh: bool,
    #[arg(long, conflicts_with = "unack")]
    ack: Option<String>,
    #[arg(long)]
    unack: Option<String>,
  },
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
    #[arg(long)]
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
    /// 是否允许通过 API 操作特权与未纳管容器。用 token 只能关（false），打开要在页面上操作。
    #[arg(long)]
    host_docker: Option<bool>,
    /// 是否允许通过 API 操作宿主机系统配置。用 token 只能关（false），打开要在页面上操作。
    #[arg(long)]
    host_system: Option<bool>,
    /// 每月流量额度（GB），只用于显示用了多少；0 清除。
    #[arg(long)]
    traffic_quota_gb: Option<u32>,
    /// 流量每月几号重置（1 到 28，北京时间）；0 清除（按 1 号）。
    #[arg(long)]
    traffic_reset_day: Option<u8>,
    /// 服务器续费日（YYYY-MM-DD，北京时间）；传空字符串清除。
    #[arg(long)]
    renew_at: Option<String>,
    /// agent 内存上限，例如 256M、1G 或 none（不限）。默认 256 MiB，应用时无需重启 agent。
    #[arg(long, value_parser = top::parse_agent_memory)]
    agent_memory: Option<String>,
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
  /// 磁盘占用排行：每个服务的数据目录、容器日志、数据卷（每天测一次），从大到小。
  /// 镜像、构建缓存和系统日志看 `wharf server host`。
  Disk {
    name: String,
    /// 现在就测一次（要遍历文件，可能要几分钟）。
    #[arg(long)]
    measure: bool,
  },
  /// 这台机器上 agent 自己的日志。例：`wharf server logs home --errors`。
  Logs {
    name: String,
    #[command(flatten)]
    logs: LogArgs,
  },
}

#[derive(Subcommand)]
// 只在启动时解析一次，变体大小无所谓。
#[allow(clippy::large_enum_variant)]
pub enum ServiceCmd {
  /// 从服务容器的网络探测一个目标。
  Probe(probe::ServiceProbeArgs),
  /// 查看服务的代码包来自哪台服务器的哪个目录。
  Origin {
    name: String,
  },
  /// 删除未纳管的容器或 Compose 项目。
  UnmanagedRemove {
    server: String,
    #[arg(
      long,
      required_unless_present = "container",
      conflicts_with = "container"
    )]
    project: Option<String>,
    #[arg(long)]
    container: Option<String>,
    /// 同时删除具名数据卷。
    #[arg(long)]
    volumes: bool,
  },

  /// 忽略未纳管容器的通知和待处理提示，用 --undo 取消忽略。
  UnmanagedIgnore {
    server: String,
    #[arg(
      long,
      required_unless_present = "container",
      conflicts_with = "container"
    )]
    project: Option<String>,
    #[arg(long)]
    container: Option<String>,
    #[arg(long)]
    undo: bool,
  },
  /// 列出、添加或删除日志关键字告警。--off 关闭全部。
  LogAlert {
    name: String,
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
    #[command(subcommand)]
    action: Option<service_checks::LogAlertCmd>,
  },
  /// 设置宿主机端口探测。默认检查 TCP，UDP 需要提供 DNS 或自定义报文。
  PortCheck(service_checks::PortArgs),
  /// 设置服务心跳。启停时重新部署以添加或移除 WHARF_HEARTBEAT_URL。
  Heartbeat {
    name: String,
    /// 报到间隔，例如 10m。
    #[arg(long, required_unless_present_any = ["off", "grace"], conflicts_with = "off", value_parser = service_checks::minutes)]
    every: Option<u32>,
    /// 宽限，默认 5 分钟。心跳已开启时可以单独调整。
    #[arg(long, conflicts_with = "off", value_parser = service_checks::minutes)]
    grace: Option<u32>,
    /// 关闭心跳。
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },

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
    /// 显示完整的心跳报到地址。
    #[arg(long)]
    reveal: bool,
  },
  /// 看日志。可以给多个服务，按时间合在一起看。支持按时间、关键字筛和用 `--errors` 合并同类报错。
  /// 例：`wharf service logs blog --since 2h --errors`、`wharf service logs blog --grep timeout --tail 50`。
  Logs {
    /// 服务名，可给 1～10 个。
    #[arg(required = true, num_args = 1..=10)]
    names: Vec<String>,
    /// 最多输出多少行（`--errors` 时是多少种报错）。
    #[arg(long, default_value_t = 200)]
    tail: u32,
    /// 持续输出单个服务的新日志，Ctrl-C 结束。不能与时间范围、关键字、报错筛选或行长限制同用。
    #[arg(short, long, conflicts_with_all = ["since", "grep", "errors", "max_line"])]
    follow: bool,
    /// 只看这段时间内的：30m、2h、3d，或 RFC 3339 时间。
    #[arg(long)]
    since: Option<String>,
    /// 只看含这个关键字的行，不分大小写。单服务筛选时在最近 5000 行里找。
    #[arg(long)]
    grep: Option<String>,
    /// 只看报错（error、exception、panic、failed 等），同一种报错只是 id、耗时不同的合成一条，带次数和首末时间。
    #[arg(long)]
    errors: bool,
    /// 每行最多多少字符，超出截断（筛选时默认 500）。
    #[arg(long)]
    max_line: Option<usize>,
  },
  /// 列出服务数据目录（`/srv/<服务>/`）里的文件。例：`wharf service files blog config`。
  Files {
    name: String,
    /// 数据目录下的相对路径，不给是根目录。
    #[arg(default_value = "")]
    path: String,
  },
  /// 从服务数据目录下载一个文件。例：`wharf service download blog config/app.ini -o app.ini`。
  Download {
    name: String,
    /// 数据目录下的相对路径。
    path: String,
    /// 存到哪里，不给时用文件名存在当前目录；`-` 输出到标准输出。
    #[arg(short, long)]
    output: Option<String>,
  },
  /// 上传一个本机文件到服务数据目录，已有的会被覆盖（最大 100 MB）。需要 exec 权限。
  /// 例：`wharf service upload blog ./app.ini config/app.ini`。
  Upload {
    name: String,
    /// 本机文件。
    local: std::path::PathBuf,
    /// 数据目录下的相对路径。
    path: String,
  },
  /// 部署历史。
  History {
    name: String,
  },
  /// 设置备注，直接生效。
  Note {
    name: String,
    #[command(flatten)]
    args: note::NoteArgs,
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
  /// 检查更新：镜像（image 来源和 compose 里的镜像）重新查标签现在的版本，git 构建来源重新查分支现在的 commit，
  /// 有新版本时计划里会更新。平时改配置不会换版本。不会换标签，换标签用 `wharf service retag`。
  Update {
    name: String,
    /// 只检查这一个镜像，和 compose 里写的一字不差；不填检查全部镜像。
    /// 例：`wharf service update halo --image mysql:8.0.36`。
    #[arg(long)]
    image: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 把服务里的镜像换成另一个标签（例如升级大版本），compose 来源只改对应的 `image:` 行。生成计划。
  /// 例：`wharf service retag halo registry.fit2cloud.com/halo/halo:2.20 2.21 --apply`。
  /// 更高版本的标签在 `wharf status` 的“需要注意”和更新提醒里能看到。
  Retag {
    name: String,
    /// 现在写的镜像，和 compose 里的一字不差。
    image: String,
    tag: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 有新版本时每天自动更新；--off 关闭。生成计划。
  AutoUpdate {
    name: String,
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 现在跑一轮自动更新，不受每天更新时间限制。
  AutoUpdateRun,
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
    /// 照着一条 `docker run` 命令新建：端口、环境变量、数据卷、资源上限一起转过来，
    /// 用了镜像来源表达不了的参数时转成 compose 来源。没转换的参数会列出来。
    /// 例：`wharf service deploy app --from-run 'docker run -d -p 8080:80 -v data:/data nginx'`。
    #[arg(long, conflicts_with_all = ["image", "compose", "compose_url"])]
    from_run: Option<String>,
    /// 从网址取 compose 文件（在本机下载，GitHub 的网页链接自动换成原始文件）。
    #[arg(long, conflicts_with_all = ["image", "compose"])]
    compose_url: Option<String>,
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
    /// 用本机 gh 的登录写入或覆盖控制面 GITHUB_TOKEN。
    #[arg(long)]
    sync_gh_token: bool,
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
  /// 配置文件：内容存在 Wharf 里，部署时放进容器（只读），跟着部署历史和回滚走。
  /// 内容里可以用 `[[密钥名]]`、`[[@服务]]`。只给服务名时列出全部；给了路径不带参数时打印内容。
  /// 例：`wharf service file app /etc/app/config.yaml --file ./config.yaml --apply`。
  File {
    name: String,
    /// 容器内的绝对路径。
    path: Option<String>,
    /// 从本地文件读内容，`-` 表示标准输入。生成计划。
    #[arg(long, requires = "path", conflicts_with = "rm")]
    file: Option<String>,
    /// 去掉这个配置文件。生成计划。
    #[arg(long, requires = "path")]
    rm: bool,
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
  /// 轮换网关反向隧道的凭据。省略 --link-token 和 --cert 时同时轮换两者。
  RotateLink {
    name: String,
    /// 轮换反向隧道的认证密钥。
    #[arg(long)]
    link_token: bool,
    /// 轮换反向隧道的叶证书。
    #[arg(long)]
    cert: bool,
    /// 兼容旧调用。高风险项仍需逐项传入 --confirm <地址>。
    #[arg(long = "yes", requires = "apply")]
    _yes: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 查看网关容器日志，或加 --access 查看 HTTP 访问日志。
  #[command(group(
    clap::ArgGroup::new("access_filters")
      .args(["host", "status", "path", "method"])
      .multiple(true)
      .requires("access")
  ))]
  Logs(access_logs::GatewayArgs),
  /// 在某台服务器上新建网关。修改已有网关时只改给出的参数。
  Add {
    name: String,
    /// 新建时必填。
    #[arg(long)]
    server: Option<String>,
    /// caddy（默认）：服务器要有公网 IP 和 80/443；cloudflare_tunnel：走 Cloudflare 隧道，不用开端口。
    #[arg(long, value_parser = ["caddy", "cloudflare_tunnel"])]
    kind: Option<String>,
    /// cloudflare_tunnel：在哪个厂商账号下建隧道，只有一个账号时可以不填。
    #[arg(long)]
    account: Option<String>,
    /// 设为默认入口，原来的默认入口在同一个计划里取消。
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
    /// 证书方式：auto（默认，公网签证书）、internal（自签）、off（只走 HTTP，内网用）。
    #[arg(long, value_parser = ["auto", "internal", "off"])]
    tls: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 错误页：网关连不上服务时（502、503、504）显示的页面。
  /// 例：`wharf gateway error-page edge --file 502.html --apply`；`--default` 换回内置页。
  ErrorPage {
    name: String,
    /// HTML 文件；`-` 从标准输入读。
    #[arg(
      long,
      conflicts_with = "default",
      required_unless_present = "default"
    )]
    file: Option<String>,
    /// 换回内置的默认页。
    #[arg(long)]
    default: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 泛域名证书：给 *.<zone> 签一张证书，DNS 验证记录由控制面写。
  /// 例：`wharf gateway wildcard edge --zone example.com --apply`；`--off` 关闭。
  Wildcard {
    name: String,
    #[arg(long)]
    zone: String,
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 配置可信上游代理。不带修改参数时查看当前配置。
  TrustedProxies {
    name: String,
    /// 信任 Cloudflare 官方回源网段。
    #[arg(long)]
    cloudflare: Option<bool>,
    /// 信任集群网关和组网服务器的实际地址。
    #[arg(long)]
    cluster: Option<bool>,
    /// 追加自定义 IP 或 CIDR，可多次使用。
    #[arg(long)]
    add: Vec<String>,
    /// 移除自定义 IP 或 CIDR，可多次使用。
    #[arg(long)]
    rm: Vec<String>,
    /// 清空可信代理配置。
    #[arg(long, conflicts_with_all = ["cloudflare", "cluster", "add", "rm"])]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 查看或修改 Caddy 的连接超时和热重载宽限。
  Timeouts(commands::entry_protection::TimeoutsArgs),
  /// 四层转发：入口监听公网 TCP 或 UDP 端口，转给服务。--rm 删除。
  Forward {
    name: String,
    #[arg(long)]
    listen: u16,
    #[arg(long)]
    udp: bool,
    #[arg(long, conflicts_with = "upstream")]
    service: Option<String>,
    #[arg(long)]
    port: Option<String>,
    #[arg(long)]
    upstream: Option<String>,
    #[arg(long, conflicts_with_all = ["service", "upstream", "port"])]
    rm: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除网关。生成计划。
  Rm {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

#[derive(Subcommand)]
pub enum RouteCmd {
  List,
  /// 按域名看访问日志。例：wharf route logs blog.example.com --status 5xx --since 1h。
  Logs(access_logs::RouteArgs),
  /// 向三个公共 DNS 检查 A 和 AAAA 是否生效。
  DnsCheck {
    hostname: String,
  },
  /// 设置域名备注，直接生效。
  Note {
    host: String,
    #[command(flatten)]
    args: note::NoteArgs,
  },
  /// 新增或修改路由。修改已有域名时只改给出的参数。
  #[command(visible_alias = "set")]
  Add {
    hostname: String,
    /// 服务或边缘应用（Workers / Pages）的名字。
    #[arg(long, conflicts_with_all = ["upstream", "redirect"])]
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
    /// 传空字符串清除。
    #[arg(long)]
    backup_gateway: Option<String>,
    /// 登录保护：访问时要输入账号密码。账号用 `wharf secret set BASIC_AUTH_<域名，. 换成 _>` 设置。
    #[arg(long, conflicts_with = "no_auth")]
    auth: bool,
    /// 关闭登录保护。
    #[arg(long)]
    no_auth: bool,
    /// 按路径转发，可以多次给：`/ws=服务[:端口名]` 或 `/ws=127.0.0.1:17891`（不归 Wharf 管的上游）。
    /// `/api/*` 匹配前缀。只支持 caddy 网关。给出后替换全部路径转发。
    #[arg(
      long = "path",
      value_name = "PATH=TARGET",
      conflicts_with = "no_paths"
    )]
    paths: Vec<String>,
    /// 清空全部路径转发。
    #[arg(long)]
    no_paths: bool,
    /// 总是走反向隧道。不给时自动选：同机、能直连内网地址就直连，否则走隧道。
    #[arg(long, conflicts_with = "no_tunnel")]
    tunnel: bool,
    /// 恢复自动选走法。
    #[arg(long)]
    no_tunnel: bool,
    /// 只在内网访问：DNS 指向入口所在机器的内网地址，入口只放行内网来源，证书用 DNS 验证签。
    #[arg(long, conflicts_with = "no_internal")]
    internal: bool,
    /// 恢复公网访问。
    #[arg(long)]
    no_internal: bool,
    #[command(flatten)]
    protection: commands::entry_protection::RouteProtectionArgs,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 域名门禁；不给 --mode 时显示当前配置。
  Sso {
    name: String,
    /// gate 只挡门；header 传用户名；login 代登录；oidc 让应用用 Wharf 账号登录（应用要支持 OIDC）。
    #[arg(long, value_parser = ["gate", "header", "login", "oidc", "off"])]
    mode: Option<String>,
    /// oidc 方式的回调地址，可写多次：本域名路径（如 /login/generic_oauth）或手机 app 的自定义协议。
    #[arg(long = "redirect", requires = "mode")]
    redirect: Vec<String>,
    #[arg(long = "skip", requires = "mode")]
    skip: Vec<String>,
    #[arg(
      long,
      requires = "mode",
      conflicts_with = "no_trust_internal"
    )]
    trust_internal: bool,
    #[arg(long, requires = "mode")]
    no_trust_internal: bool,
    #[arg(long, requires = "mode")]
    header: Option<String>,
    /// 代登录的 YAML 或 JSON 文件，steps 或 script 二选一。- 从标准输入读。entry 指定代登录后跳到的路径，例如 /ghost/。
    #[arg(long, requires = "mode")]
    file: Option<String>,
    /// 公开站点（如博客）：不加门禁，访客照常访问。login 方式由主人打开 https://<域名>/_wharf/login 代登录进后台；oidc 方式由应用自己决定哪里要登录。只能配 login 或 oidc。
    #[arg(long, requires = "mode")]
    public: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 防护：按来源 IP 限速、拦截常见扫描。例：`wharf route guard a.example.com --rate 600 --block --apply`。
  Guard {
    name: String,
    /// 每个来源 IP 每分钟最多多少次请求，超过返回 429。
    #[arg(long, conflicts_with = "no_rate")]
    rate: Option<u32>,
    /// 关闭限速。
    #[arg(long)]
    no_rate: bool,
    /// 拦截常见扫描路径和扫描器，返回 404。
    #[arg(long, conflicts_with = "no_block")]
    block: bool,
    /// 关闭拦截。
    #[arg(long)]
    no_block: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 证书申请状态：申请中、失败原因和下次自动重试的时间。`--retry` 让入口立刻重新申请。
  Cert {
    name: String,
    /// 让入口立刻重新申请（强制热重载入口，配置不变）。同一个入口 1 分钟内只能一次。
    #[arg(long)]
    retry: bool,
  },
  /// 自定义 Caddy 配置：原样插进网关里这个域名的站点块，Caddy 能做的都能写（按路径拦截、加响应头等）。
  /// 网关下发前会用 Caddy 校验，写错了不会生效。不给参数时显示现在的配置。
  /// 例：`printf '@admin path /admin/*\nrespond @admin 403\n' | wharf route caddy a.example.com --file - --apply`。
  Caddy {
    name: String,
    /// 配置文件；`-` 从标准输入读。给出后替换整段。
    #[arg(long, conflicts_with = "off")]
    file: Option<String>,
    /// 去掉自定义配置。
    #[arg(long)]
    off: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 删除路由（域名）。生成计划。
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
  List {
    #[arg(long)]
    detail: bool,
  },
  /// 从标准输入读入新值并保留旧值。
  Rotate {
    name: String,
    #[arg(long)]
    keep_days: Option<u16>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  Rollback {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  ClearOld {
    name: String,
  },
  /// 设置密钥，值从标准输入读取。
  /// `BASIC_AUTH_<域名，. 换成 _>` 是这个域名的登录保护账号，值写成 `用户名:密码`，只保存哈希。
  Set {
    name: String,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
  Rm {
    name: String,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
}

#[derive(Subcommand)]
pub enum BackupCmd {
  /// 给历史业务仓库加上服务专属口令。
  Migrate,
  /// 验证业务仓库的新口令后，摘除并清理旧全局口令。
  CleanupLegacy {
    #[arg(long)]
    confirm: Option<String>,
  },
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
  /// 只读推演，不会真的发出被推演的请求或修改数据。
  Explain {
    name: String,
    /// 要推演的服务。
    #[arg(long)]
    service: Option<String>,
    /// 假设请求来自这个 IP 地址。
    #[arg(long)]
    from: Option<String>,
    /// 要推演的 HTTP 方法，例如 GET。
    #[arg(long, requires = "path")]
    method: Option<String>,
    /// 要推演的请求路径，以 /api/ 开头。
    #[arg(long, requires = "method")]
    path: Option<String>,
  },
  /// 新建 token（只显示这一次）。给 AI 常用 `--perms plan,apply,exec`。
  Create {
    name: String,
    /// 权限点，逗号分隔：read、plan、apply、confirm、exec、host、admin（read 总是带上）。
    #[arg(
      long,
      conflicts_with = "scope",
      required_unless_present = "scope"
    )]
    perms: Option<String>,
    /// 旧档位预设：read、plan、apply_safe、apply_all。
    #[arg(long, value_parser = ["read", "plan", "apply_safe", "apply_all"])]
    scope: Option<String>,
    /// 有效期，例如 30m、12h、7d 或 2026-12-31。
    #[arg(long)]
    expires: Option<String>,
    /// 允许的来源地址或网段，逗号分隔。
    #[arg(long)]
    from: Option<String>,
    /// 允许操作的服务，逗号分隔。
    #[arg(long)]
    services: Option<String>,
  },
  /// 修改访问令牌的权限和限制。
  Set {
    name: String,
    /// 权限点，逗号分隔。
    #[arg(long)]
    perms: Option<String>,
    /// 有效期，例如 30m、12h、7d、2026-12-31，或用 never 清除。
    #[arg(long)]
    expires: Option<String>,
    /// 允许的来源地址或网段，逗号分隔，或用 any 清除。
    #[arg(long)]
    from: Option<String>,
    /// 允许操作的服务，逗号分隔，或用 all 清除。
    #[arg(long)]
    services: Option<String>,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
  Rm {
    name: String,
  },
}

#[tokio::main]
async fn main() {
  let mut cli = Cli::parse();
  if let Some(fields) = &cli.fields {
    print::set_fields(fields);
    cli.json = true;
  }
  if cli.page_size.is_some() || cli.changed {
    cli.json = true;
  }
  if let Some(reason) = &cli.reason {
    let _ = client::REASON.set(reason.clone());
  }
  let key: Vec<String> = std::env::args()
    .skip(1)
    .filter(|a| a != "--changed")
    .collect();
  view::set(
    cli.page_size.map(|size| (size, cli.page)),
    cli.changed.then_some(key.as_slice()),
  );
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
  /// 通知地址：给自己的服务和脚本发通知用，`POST <地址>`，正文就是消息，
  /// 或者发 JSON `{"title": "...", "text": "..."}`。每个凭证每分钟最多 20 条。
  #[command(subcommand)]
  Key(NotifyKeyCmd),
}

#[derive(Subcommand)]
pub enum NotifyKeyCmd {
  /// 新建（同名已有时换新地址，旧地址失效）。地址存进密钥 `NOTIFY_URL_<名字>`，
  /// 服务的环境变量里写 `[[NOTIFY_URL_<名字>]]` 引用。
  Add {
    name: String,
    /// 把地址打印出来（地址就是凭证，给 Wharf 以外的脚本用时才需要）。
    #[arg(long)]
    show: bool,
  },
  List,
  /// 删除，地址立即失效，对应的密钥一起删。
  Rm {
    name: String,
  },
}

#[derive(Subcommand)]
pub enum EgressCmd {
  /// 设置控制面调厂商 API 经哪台出口（按那台的规则分流）；空字符串直连。
  Api { server: String },
  /// 列出预置分组和包含的域名。
  Presets,
}

#[derive(Subcommand)]
pub enum GateCmd {
  #[command(subcommand)]
  Key(GateKeyCmd),
}
#[derive(Subcommand)]
pub enum GateKeyCmd {
  Add {
    name: String,
    #[arg(long = "host", required = true)]
    hosts: Vec<String>,
  },
  List,
  Rm {
    name: String,
  },
}
