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
  /// 轮换网关的反向隧道密钥或证书。
  RotateLink {
    name: String,
    #[arg(long)]
    token: bool,
    #[arg(long)]
    cert: bool,
    /// 确认执行 --apply 请求的操作。
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
  List,
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
