//! 期望配置。字段与设计文档第 2 节一一对应。
//!
//! 资源名不放在 spec 里，由外层的 key（fleet.toml 的表名、API 路径）给出，
//! 这样意图文件里不会出现"名字写了两遍还不一致"的问题。

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Region {
  Cn,
  Overseas,
}

/// 服务器上可以由用户修改的设置。IP 由 agent 上报，这里只是覆盖值。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ServerSettings {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub task_limits: Option<Limits>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub region: Option<Region>,
  /// 覆盖 agent 探测到的公网 IP。caddy 网关的 DNS 记录指向它。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub public_ip: Option<String>,
  /// 拉镜像时的镜像源，按顺序尝试，最后才尝试原地址。
  /// 例如 `{ "docker.io" = ["docker.1ms.run"], "ghcr.io" = ["ghcr.nju.edu.cn"] }`。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub registry_mirrors: BTreeMap<String, Vec<String>>,
  /// 是否跳过原地址（例如国内机器访问不了 Docker Hub，直连只会白等）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub mirrors_only: bool,
  /// 覆盖 agent 探测到的内网地址。没有组网工具、直接走内网时用它。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub private_addr: Option<PrivateAddr>,
  /// 额外绑定的局域网地址（只能是 10/8、172.16/12、192.168/16）。镜像和代码来源服务的端口
  /// 除了 127.0.0.1 和内网地址，也绑到这些地址上，在同一局域网里可以直接访问。
  /// 机器之间互相访问仍走内网地址，不受影响。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub lan_addrs: Vec<String>,
  /// 构建时传给内置模板的参数，例如 `PIP_INDEX_URL`、`GOPROXY`（国内机器配镜像源）。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub build_env: BTreeMap<String, String>,
  /// 拉代码、查 commit 时用的 HTTP 代理，例如 `http://<海外机器内网地址>:<端口>`。
  /// 设了 `via` 时不用它。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git_proxy: Option<String>,
  /// 这台提供出口：agent 在内网地址上起 HTTP 代理（要口令），规则决定哪些域名经它出去。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub egress: Option<crate::egress::EgressSpec>,
  /// 经哪台的出口出去（那台要设了 `egress`）：本机 agent 起分流代理，
  /// dockerd 拉镜像、构建、拉代码都经它，按出口的规则分流，出口连不上时直连。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub via: Option<String>,
  /// 拉镜像时 dockerd 用的 HTTP 代理，例如 `http://<海外机器内网地址>:<端口>`。设了 `via` 时不用它。
  /// 写进宿主机的 /etc/docker/daemon.json；镜像源和内网地址直连，其余仓库（ghcr 等）走代理。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pull_proxy: Option<String>,
  /// 代替 `https://github.com/` 拉代码的地址，例如 `https://github.<域名>/[[MIRROR_TOKEN]]`
  /// （wharf 的 mirror 服务）。可以用 `[[NAME]]` 引用密钥。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub github_mirror: Option<String>,
  /// 接入方式（design 2.10）。不填按检测到的地址推断。`tailscale` 且没检测到 Tailscale 时
  /// 由 Wharf 装 Tailscale 容器并加入；`public` 不用内网地址，网关到这台一律走反向隧道。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub network_mode: Option<NetworkMode>,
  /// 允许从页面打开宿主机 root 终端。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub host_terminal: bool,
  /// 允许通过 API 在宿主机执行命令。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub host_exec: bool,
  /// 允许通过 API 部署特权/host 网络/越界挂载容器、挂载宿主机路径的容器任务、操作未纳管容器，以及修改网关镜像和本地四层转发。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub host_docker: bool,
  /// 允许通过 API 修改服务器宿主机设置、纠正基线、配置 dockerd 代理/外网代理/Tailscale，以及查看监视宿主机 systemd 程序。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub host_system: bool,
  /// 每月流量额度（GB），用于显示本期用了多少，用到 80% 时提醒（阈值在告警规则里改）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub traffic_quota_gb: Option<u32>,
  /// 流量每月几号重置（1 到 28，按北京时间），不填是 1 号。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub traffic_reset_day: Option<u8>,
  /// 服务器续费日（`YYYY-MM-DD`，北京时间）。只用来提醒，不影响任何部署。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub renew_at: Option<String>,
  /// 机器基线：系统设置的期望值，agent 定时检查差异，apply 时纠正。
  #[serde(default, skip_serializing_if = "Baseline::is_empty")]
  pub baseline: Baseline,
  /// agent 内存上限，例如 256M、1G，none 为不限，缺省为 256 MiB。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub agent_memory: Option<String>,
  /// 后台传输限速，例如 3M 或 500K。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub bg_bwlimit: Option<String>,
}

/// 机器基线（P9）。字段不填就不管；去掉某项只是不再管，不会改回去。
/// 不含 ssh 和防火墙：配错会把自己锁在机器外面。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Baseline {
  /// 时区，例如 `Asia/Shanghai`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub timezone: Option<String>,
  /// 没有 swap 时建一个这么大的 /swapfile（GB）；已有 swap 不改。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub swap_gb: Option<u32>,
  /// 内核参数，写进 /etc/sysctl.d/90-wharf.conf，例如 `net.ipv4.tcp_congestion_control = bbr`。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub sysctl: BTreeMap<String, String>,
  /// 容器日志轮转：单个文件上限，例如 `20m`。写进 daemon.json，只对新建的容器生效。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub docker_log_size: Option<String>,
  /// 容器日志轮转：保留几个文件，默认 3。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub docker_log_files: Option<u32>,
  /// journald 日志总上限，例如 `500M`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub journal_max: Option<String>,
  /// 自动安装安全更新（unattended-upgrades，只支持 apt 系统）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub security_updates: Option<bool>,
}

impl Baseline {
  pub fn is_empty(&self) -> bool {
    self == &Self::default()
  }
}

/// 机器的接入方式（design 2.10）。不指定时按检测到的地址推断：有 Tailscale 地址是 `tailscale`，
/// 有别的内网地址是 `lan`，都没有是 `public`（只能经公网和反向隧道）。
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
  Tailscale,
  Lan,
  Public,
}

impl NetworkMode {
  pub fn of(addr: Option<&PrivateAddr>) -> Self {
    match addr.map(|a| a.network) {
      Some(PrivateNetwork::Tailscale) => Self::Tailscale,
      Some(_) => Self::Lan,
      None => Self::Public,
    }
  }
}

/// 服务器之间互相访问用的地址：网关跨机器访问服务时连它，
/// 服务端口除了 127.0.0.1 也只绑定它。
///
/// Wharf 不负责打洞，组网交给专门的工具；这里只记地址在哪个网络、
/// 网络本身是否加密。
#[derive(
  Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct PrivateAddr {
  pub ip: String,
  pub network: PrivateNetwork,
}

/// 内网地址所在的网络。
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrivateNetwork {
  /// Tailscale 或 Headscale（同一个客户端），agent 自动检测。加密。
  Tailscale,
  /// 其他加密组网：WireGuard、ZeroTier、Netbird 等，手动指定。
  Overlay,
  /// 普通内网直连（公司内网、云厂商 VPC、家里局域网）。明文。
  Lan,
}

impl PrivateNetwork {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Tailscale => "tailscale",
      Self::Overlay => "overlay",
      Self::Lan => "lan",
    }
  }

  /// 网络本身是否加密。不加密时，跨机器的流量是明文。
  pub fn encrypted(self) -> bool {
    self != Self::Lan
  }
}

/// 服务来源，三选一。git 来源在 P4。
///
/// 意图文件里写作 `source = { image = "traefik/whoami" }` 或
/// `source = { compose = { file = "blog.yaml" } }`。
#[allow(clippy::large_enum_variant)]
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Source {
  /// 单个镜像，系统自动生成只有一个服务的 compose。
  Image(String),
  /// 完整的 compose 文件内容。CLI 和意图文件也可以写 `file = "路径"`，
  /// 由 CLI 读出内容后再提交。
  Compose {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
  },
  /// 从代码构建镜像（在服务所在的服务器上 `docker build`），其余和 image 来源一样。
  Build(BuildSource),
}

/// 代码来源：本机目录（CLI 打包上传）或 git 仓库，二选一。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct BuildSource {
  /// CLI 上传到控制面的代码包（tar.gz）的 sha256。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upload: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git: Option<GitSource>,
  /// 代码里的子目录，作为构建目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  /// Dockerfile 路径（相对构建目录）。不填时有 `Dockerfile` 就用，没有就按语言用内置模板。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile: Option<String>,
  /// 内置模板的基础镜像，例如 `python:3.12-slim`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub base: Option<String>,
  /// 内置模板的启动命令，例如 `uvicorn main:app --host 0.0.0.0 --port $PORT`。
  /// 可以多行（启动脚本），用 `sh -c` 执行。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start: Option<String>,
  /// 内置模板：`python` / `node` / `go` / `static`，不填时按文件识别。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub template: Option<String>,
  /// 覆盖内置模板安装依赖的命令（Python、Node），例如 `npm ci && npm run build`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub install: Option<String>,
  /// 存在 Wharf 里的 Dockerfile 内容，优先于代码里的 Dockerfile 和模板。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile_content: Option<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct GitSource {
  /// https 地址，例如 `https://github.com/owner/repo`。
  pub repo: String,
  /// 分支、标签或 commit。
  #[serde(rename = "ref")]
  pub reference: String,
  /// 私有仓库：保存访问 token 的密钥名（`wharf secret set`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token_secret: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub user: Option<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct PortSpec {
  /// 端口名，路由用它指定目标端口，例如 `http`。
  pub name: String,
  /// 容器内端口。image / build 来源必填；compose 来源不填（映射写在 compose 里）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<u16>,
  /// 宿主机端口。compose 来源必填（compose 里已经发布的端口）；
  /// image / build 来源选填，不填由系统从 20000 起自动分配。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub host: Option<u16>,
  /// UDP 端口，只能用于四层转发，不能给域名用。默认 TCP。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub udp: bool,
}

/// 目录挂载：宿主机 `/srv/<service>/<name>/` 挂到容器内 `target`。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct VolumeSpec {
  /// 本地卷名。共享卷省略时取拥有者的卷名。
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub name: String,
  pub target: String,
  /// 同机拥有者的托管卷，格式为 <服务名>:<卷名>。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub from_service: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub read_only: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub host_path: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub owner: Option<String>,
}

pub fn parse_uid_gid(raw: &str) -> Option<(u32, u32)> {
  let (uid, gid) = raw.split_once(':')?;
  let parse = |id: &str| {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
      return None;
    }
    id.parse::<u32>().ok().filter(|id| *id != u32::MAX)
  };
  Some((parse(uid)?, parse(gid)?))
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ServiceSpec {
  /// 运行在哪台服务器上。
  pub server: String,
  pub source: Source,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ports: Vec<PortSpec>,
  /// 环境变量。值里可以用 `[[SECRET_NAME]]` 引用密钥；compose 来源加到 `container` 指定的容器上，
  /// compose 文件内容也会做同样的替换。
  /// 也可以用 `[[@服务]]` 引用别的服务，部署时换成它的 `内网地址:宿主机端口`；
  /// `[[@服务.端口名]]` 指定端口，末尾加 `:host` / `:port` 只取地址或端口。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub env: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub volumes: Vec<VolumeSpec>,
  /// 每天自动备份 `/srv/<服务>/` 到另一台服务器（restic）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub backup: Option<BackupSpec>,
  /// 停止：容器保留但不运行，部署后也保持停止。不影响 compose，也就不会重建容器。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub stopped: bool,
  /// 自定义监控：服务所在机器的 agent 每分钟从本机请求一次，连续 3 次不正常推送。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub monitor: Option<MonitorSpec>,
  /// 启动等待上限（秒），缺省 120。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start_timeout_secs: Option<u32>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub log_alerts: Vec<crate::service_checks::LogAlertSpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub port_checks:
    BTreeMap<String, crate::service_checks::PortCheckSpec>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub heartbeat: Option<crate::service_checks::HeartbeatSpec>,
  /// 资源上限，不填不限。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub limits: Option<Limits>,
  /// 自动更新：每天检查一次，有新版本就自动更新。只支持没有数据卷的服务（compose 来源看 compose 里有没有挂载）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub auto_update: bool,
  /// 镜像和构建版本的更新忽略规则。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub update_ignore: Vec<UpdateIgnoreSpec>,
  /// compose 来源：环境变量、资源上限和配置文件加在哪个容器上。只有一个容器时不用填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
  /// 配置文件：内容存在 Wharf 里，部署时放进容器（只读，属主 root），跟着部署历史和回滚走。
  /// 应用自己改写的内容下次部署会被覆盖。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub files: Vec<FileSpec>,
  /// 容器优雅停机等待秒数（1 到 600），缺省用 Docker 默认。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub stop_grace_secs: Option<u32>,
  /// 容器停机信号，缺省用镜像默认。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub stop_signal: Option<String>,
  /// 部署前在临时容器内执行的初始化命令。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub init_cmd: Option<String>,
  /// 初始化超时秒数（10 到 1800），缺省 300 秒。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub init_timeout_secs: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub command: Option<Vec<String>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub shm_size: Option<u64>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub cap_add: Vec<String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub ulimits: BTreeMap<String, Ulimit>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub init: Option<bool>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub group_add: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub hostname: Option<String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub tmpfs: BTreeMap<String, u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub timezone: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pull_policy: Option<ImagePullMode>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub log_max: Option<LogMax>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub container_limits: BTreeMap<String, Limits>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub lan: Option<bool>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub extra_hosts: BTreeMap<String, std::net::IpAddr>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub self_refs: bool,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub networks: BTreeMap<String, NetworkAttachment>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub compose_env: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub user: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub use_egress: bool,
}

#[derive(
  Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct NetworkAttachment {
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub internal: bool,
}

pub fn named_network_name(name: &str) -> String {
  format!("wharf-net-{name}")
}

#[derive(
  Debug,
  Clone,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
  JsonSchema,
)]
pub struct UpdateIgnoreSpec {
  /// 镜像仓库名、完整镜像标签，或 *。
  pub image: String,
  pub scope: UpdateIgnoreScope,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UpdateIgnoreScope {
  All,
  Major,
}

pub fn image_repo(image: &str) -> &str {
  let image = image.split_once('@').map_or(image, |(repo, _)| repo);
  let segment = image.rfind('/').map_or(0, |i| i + 1);
  image[segment..]
    .find(':')
    .map_or(image, |i| &image[..segment + i])
}

/// 一个配置文件。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct FileSpec {
  /// 容器内的绝对路径，例如 `/etc/app/config.yaml`。
  pub path: String,
  /// 文本内容，最大 64 KB。可以用 `[[密钥名]]` 和 `[[@服务]]`，部署时替换。
  #[serde(default)]
  pub content: String,
  /// 意图文件中的外置配置路径。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub file: Option<String>,
  /// 跳过 plan 阶段的配置文件语法预检。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub raw: bool,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub init_only: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mode: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub owner: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub on_change: Option<String>,
}

impl FileSpec {
  pub fn managed_dir(&self) -> bool {
    self.init_only
      || self
        .on_change
        .as_deref()
        .is_some_and(|value| value != "recreate")
  }

  pub fn needs_agent(&self) -> bool {
    self.managed_dir() || self.mode.is_some() || self.owner.is_some()
  }
}

pub fn parse_file_mode(mode: &str) -> Option<u32> {
  (mode.len() == 4 && mode.starts_with('0'))
    .then(|| u32::from_str_radix(mode, 8).ok())
    .flatten()
}

pub const HOST_GROUPS: &[&str] = &["video", "render", "dialout"];

impl ServiceSpec {
  pub fn host_groups(&self) -> impl Iterator<Item = &str> {
    self
      .group_add
      .iter()
      .filter_map(|group| group.strip_prefix("host:"))
  }

  pub fn image_runtime_fields(
    &self,
  ) -> impl Iterator<Item = &'static str> {
    [
      ("command", self.command.is_some()),
      ("shm_size", self.shm_size.is_some()),
      ("cap_add", !self.cap_add.is_empty()),
      ("ulimits", !self.ulimits.is_empty()),
      ("init", self.init.is_some()),
      ("group_add", !self.group_add.is_empty()),
      ("hostname", self.hostname.is_some()),
      ("tmpfs", !self.tmpfs.is_empty()),
      ("timezone", self.timezone.is_some()),
      ("log_max", self.log_max.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
  }

  pub fn uses_runtime_options(&self) -> bool {
    self.image_runtime_fields().next().is_some()
      || self.pull_policy.is_some()
      || !self.container_limits.is_empty()
      || self
        .limits
        .as_ref()
        .is_some_and(|limits| limits.pids.is_some())
  }

  /// 按端口名、容器端口或宿主机端口找声明过的端口。`arg` 为空时只有一个端口就用它。
  pub fn find_port(&self, arg: Option<&str>) -> Option<&PortSpec> {
    let Some(arg) = arg else {
      return match self.ports.as_slice() {
        [only] => Some(only),
        _ => None,
      };
    };
    if let Some(p) = self.ports.iter().find(|p| p.name == arg) {
      return Some(p);
    }
    let n: u16 = arg.parse().ok()?;
    self
      .ports
      .iter()
      .find(|p| p.container == Some(n) || p.host == Some(n))
  }
}

/// 自定义监控：`http://127.0.0.1:<宿主机端口><path>`。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct MonitorSpec {
  /// 自定义请求头，值支持密钥引用。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub headers: BTreeMap<String, String>,
  /// 检查间隔（秒），缺省 60。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub interval_secs: Option<u32>,
  /// 单轮失败后的重试次数。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retries: Option<u8>,
  /// 请求路径，默认 `/`。
  #[serde(default = "default_monitor_path")]
  pub path: String,
  /// 端口名，默认第一个端口。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 期望的状态码；不写时 2xx、3xx 都算正常。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expect: Option<u16>,
  /// 响应里必须包含的文字（只看前 64KB）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub keyword: Option<String>,
}

/// 资源上限。compose 来源加在 `container` 指定的容器上。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Limits {
  /// 内存上限，单位 MB。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub memory_mb: Option<u32>,
  /// CPU 上限，单位是千分之一核，500 表示 0.5 核。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cpu_milli: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pids: Option<u32>,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
pub struct Ulimit {
  pub soft: i64,
  pub hard: i64,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
pub struct LogMax {
  pub max_bytes: u64,
  pub max_files: u32,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ImagePullMode {
  IfMissing,
  Never,
  Always,
}

impl Limits {
  pub fn is_empty(&self) -> bool {
    self.memory_mb.is_none()
      && self.cpu_milli.is_none()
      && self.pids.is_none()
  }

  pub fn normalize(&mut self) {
    self.memory_mb = self.memory_mb.filter(|n| *n != 0);
    self.cpu_milli = self.cpu_milli.filter(|n| *n != 0);
    self.pids = self.pids.filter(|n| *n != 0);
  }
}

impl Default for MonitorSpec {
  fn default() -> Self {
    Self {
      path: default_monitor_path(),
      port: None,
      expect: None,
      keyword: None,
      headers: BTreeMap::new(),
      interval_secs: None,
      retries: None,
    }
  }
}

fn default_monitor_path() -> String {
  "/".into()
}

/// 导入前容器是怎么跑的。和服务同名的 compose 项目不需要接管，Wharf 直接沿用。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct AdoptSpec {
  /// 原来的 compose 项目名（和服务名不同时）：停掉它的容器。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  /// 原来 `docker run` 起的容器：改名为 `<名字>-wharf-old` 并停掉，留着回退用。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub rename_containers: Vec<String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub expected_images: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub initial_pins: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub expected_services: Vec<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct BackupSpec {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub exclude: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retention: Option<crate::backup::BackupRetention>,
  /// 备份存到哪台服务器，不能是服务所在的服务器。
  pub to: String,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GatewayKind {
  Caddy,
  /// Wharf 在厂商账号下创建隧道，服务器上跑 cloudflared，不需要公网 IP 和开放端口。
  CloudflareTunnel,
}

impl GatewayKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Caddy => "caddy",
      Self::CloudflareTunnel => "cloudflare_tunnel",
    }
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct GatewaySpec {
  pub kind: GatewayKind,
  /// 网关跑在哪台服务器上。
  pub server: String,
  /// 默认入口：添加路由时不选网关就用它。最多一个。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub default: bool,
  /// caddy：HTTP 端口，默认 80。改端口只用于测试，签证书需要 80。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub http_port: Option<u16>,
  /// caddy：HTTPS 端口，默认 443。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub https_port: Option<u16>,
  /// caddy：ACME 账号邮箱，可选。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub email: Option<String>,
  /// caddy：镜像，默认 Wharf 自建的 wharf-caddy。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image: Option<String>,
  /// caddy：证书方式，默认 `auto`（公网签证书）。
  #[serde(default, skip_serializing_if = "GatewayTls::is_auto")]
  pub tls: GatewayTls,
  /// cloudflare_tunnel：在哪个厂商账号下建隧道（`wharf account list`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub account: Option<String>,
  /// caddy：网关连不上服务时（502、503、504）显示的 HTML。不填用内置的默认页。
  /// 内容里可以写 `{err.status_code}`，显示时换成状态码。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_page: Option<String>,
  /// caddy：签一张 *.<zone>，这个入口上 zone 下一级的域名都用它。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub wildcard: Vec<String>,
  /// caddy：四层转发，只经过入口所在机器，服务自己的端口不对公网开放。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub layer4: Vec<Layer4Forward>,
  /// caddy：可信上游代理（Cloudflare 官方网段、集群网关/组网地址、自定义 CIDR）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub trusted_proxies:
    Option<crate::trusted_proxies::TrustedProxiesSpec>,
  /// caddy：读取请求头的超时（秒），默认 10。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub read_header_timeout: Option<u32>,
  /// caddy：连接空闲超时（秒），默认 120。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub idle_timeout: Option<u32>,
  /// caddy：重载时等待正在处理的请求（秒），默认 10。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub grace_period: Option<u32>,
}

/// 在入口机器上监听 TCP 或 UDP，原样转给服务。服务和上游二选一。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Layer4Forward {
  pub listen: u16,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub udp: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
}

/// 网关的证书方式。
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GatewayTls {
  /// 自动向 Let's Encrypt 等申请证书，需要公网可达的域名。
  #[default]
  Auto,
  /// Caddy 自签证书，浏览器会提示不受信任。用于内网。
  Internal,
  /// 只走 HTTP，不用证书。用于内网演示。
  Off,
}

impl GatewayTls {
  pub fn is_auto(&self) -> bool {
    *self == Self::Auto
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct RouteSpec {
  /// 例如 `blog.example.com`。
  pub hostname: String,
  /// 目标服务。和 `upstream`、`redirect` 三选一。边缘应用的域名写在边缘应用的 `domains` 里。
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub service: String,
  /// 不归 Wharf 管的上游，写网关所在机器能访问到的 `主机:端口`，例如 `127.0.0.1:7700`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
  /// 目标端口名。服务只有一个端口时可以不填；边缘应用不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 入口网关。不填则用默认网关；边缘应用的域名不经过网关，不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub gateway: Option<String>,
  /// 备用入口：主入口持续不可达且备用可达时切换 DNS，主入口持续恢复后切回。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub backup_gateway: Option<String>,
  /// 自动切备和切回所需的连续异常或恢复分钟数，默认 5 分钟。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub failover_minutes: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dns_ttl: Option<u32>,
  /// 门禁。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub sso: Option<SsoSpec>,
  /// 登录保护（P3）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub auth: bool,
  /// 按路径转发到别的上游，其余路径仍到 `service`。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub paths: Vec<PathRoute>,
  /// 自定义 Caddy 配置：原样插进网关里这个域名的站点块，例如按路径拦截、加响应头。
  /// 网关下发前会用 Caddy 校验，写错了不会生效。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub caddy: Option<String>,
  /// 意图文件中的外置 Caddy 片段路径。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub caddy_file: Option<String>,
  /// 网关到服务的走法。不填为自动：同机、能直连内网地址就直连，否则走反向隧道。
  #[serde(default, skip_serializing_if = "LinkMode::is_auto")]
  pub link: LinkMode,
  /// 跳转：整个域名 301 到这个网址，保留路径和参数，例如 `https://a.com`。
  /// 和 `service`、`upstream` 三选一。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub redirect: Option<String>,
  /// 限速：同一个来源 IP 每分钟最多这么多次请求，超过的返回 429。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rate_limit: Option<u32>,
  /// 拦截常见扫描：请求命中扫描路径或扫描器的 UA 时直接返回 404，不转给服务。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub block_scanners: bool,
  /// 只在内网访问：DNS 指向入口所在机器的内网地址，证书用 DNS 验证签，入口只放行内网来源。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub internal: bool,
  /// 仅向组网内来源开放控制面页面。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub core_mesh_only: bool,
  /// 只接受 Cloudflare 官方网段的直连请求。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub cf_origin_only: bool,
  /// 临时分享：到这个时间（毫秒时间戳）以后，网关直接断开这个域名的请求；路由和 DNS 记录留着，等人删除。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expires_at: Option<i64>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct SsoSpec {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub login: Option<LoginSpec>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub header: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub trust_internal: bool,
  pub mode: SsoMode,
  /// 不过门禁的路径前缀。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub skip_paths: Vec<String>,
  /// 公开站点：不加门禁，所有人都能访问。login 方式只提供 `/_wharf/login`
  /// 入口，主人从入口登录 Wharf 后代登录进应用；oidc 方式由应用自己决定哪里要登录。
  /// 只能和 login、oidc 方式一起用。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub public: bool,
  /// oidc 方式：应用用 Wharf 账号登录（Wharf 当 OIDC 身份提供方）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub oidc: Option<OidcClientSpec>,
}
/// OIDC 客户端。client_id 就是域名，密钥由 Wharf 生成，
/// 服务环境变量里用 `[[OIDC_<域名大写，. 和 - 换成 _>]]` 引用。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct OidcClientSpec {
  /// 登录完成后的回调地址。`/` 开头的是本域名下的路径；
  /// 也可以写本域名的完整 https 地址，或手机 app 的自定义协议（如 `app.immich:///oauth-callback`）。
  pub redirect_uris: Vec<String>,
}
impl SsoSpec {
  /// 网关是否挡住没登录的访问。
  pub fn gated(&self) -> bool {
    !self.public
  }
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SsoMode {
  Gate,
  Header,
  Login,
  Oidc,
}

/// 网关到服务的走法偏好。
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
  #[default]
  Auto,
  /// 总是走反向隧道，不经过组网。
  Tunnel,
}

impl LinkMode {
  pub fn is_auto(&self) -> bool {
    *self == Self::Auto
  }
}

/// 路由里的一条路径转发。`service` 和 `upstream` 二选一。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct PathRoute {
  /// Caddy 的路径匹配：`/ws` 只匹配这个路径，`/api/*` 匹配前缀。
  pub path: String,
  /// 目标服务。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service: Option<String>,
  /// 目标端口名，服务只有一个端口时可以不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 不归 Wharf 管的上游，例如网关所在机器上的 `127.0.0.1:17891`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
}

/// 边缘应用的种类。
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
  /// Cloudflare Workers。
  Worker,
  /// Cloudflare Pages。
  Pages,
}

impl EdgeKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Worker => "worker",
      Self::Pages => "pages",
    }
  }
}

/// 边缘应用的代码来源。和服务的构建来源一样，代码来自本机目录上传或 git。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct EdgeSource {
  /// 本机目录上传到控制面的代码包 sha256（`wharf edge deploy` 自动填）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upload: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git: Option<GitSource>,
  /// 代码里的子目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  /// worker：单文件脚本（相对代码目录）。直接调用厂商接口上传，
  /// 保留面板里配置的变量和绑定。不填时按 wrangler 项目发布。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub script: Option<String>,
  /// pages：构建命令，例如 `npm run build`。不填就是静态目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub build: Option<String>,
  /// pages：要发布的目录（相对代码目录）。不填时有构建命令用 `dist`，否则用代码目录本身。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub output: Option<String>,
}

/// 边缘应用：Cloudflare Workers / Pages。没有端口、数据卷、迁移、备份。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct EdgeAppSpec {
  /// 厂商账号。
  pub account: String,
  pub kind: EdgeKind,
  /// 厂商那边的脚本名 / 项目名。不填时等于边缘应用的名字。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  /// 不填表示只纳管：Wharf 显示状态、管域名、回滚，不发布代码。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub source: Option<EdgeSource>,
  /// 在哪台服务器上执行 wrangler（构建 Pages、发布 wrangler 项目）。不填时自动选，优先海外。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub builder: Option<String>,
  /// 绑定的自定义域名，不经过网关。Worker 的 DNS 由 Cloudflare 管；Pages 由 Wharf 写 CNAME。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub domains: Vec<String>,
}

impl EdgeAppSpec {
  /// 厂商那边的名字。
  pub fn project_name<'a>(&'a self, name: &'a str) -> &'a str {
    self.project.as_deref().unwrap_or(name)
  }
}

/// 首页上的一条书签：不归 Wharf 管的地址。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct BookmarkSpec {
  pub title: String,
  /// 只允许 http:// 或 https://。
  pub url: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub group: Option<String>,
  #[serde(default)]
  pub order: i32,
}

/// 意图文件 fleet.toml 的全部内容。plan 时作为完整期望状态：
/// 文件里没有的服务、网关、路由会被计划删除。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Fleet {
  /// 服务器设置。服务器本身通过 `wharf server add` 加入，不在这里创建或删除。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub servers: BTreeMap<String, ServerSettings>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub services: BTreeMap<String, ServiceSpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub gateways: BTreeMap<String, GatewaySpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub edge_apps: BTreeMap<String, EdgeAppSpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub bookmarks: BTreeMap<String, BookmarkSpec>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub routes: Vec<RouteSpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub vars: BTreeMap<String, String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct VarView {
  pub name: String,
  pub value: String,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct MigrateOptions {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub bwlimit: Option<String>,
}

/// 对期望状态的局部修改。CLI 的 `service deploy`、`route add` 等命令都生成它。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // 一次计划只有几个，装箱改动面太大
pub enum Change {
  UpsertVar {
    name: String,
    value: String,
  },
  RemoveVar {
    name: String,
  },
  /// id 为空时新建，否则修改已有书签。
  UpsertBookmark {
    id: Option<String>,
    spec: BookmarkSpec,
  },
  RemoveBookmark {
    id: String,
  },
  /// 服务器必须已经 `wharf server add` 过。
  UpdateServer {
    name: String,
    settings: ServerSettings,
  },
  UpsertService {
    name: String,
    spec: ServiceSpec,
    /// 导入时接管的现有容器：第一次部署前停掉它们，失败时恢复。部署成功后记进导入记录，不再起作用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adopt: Option<AdoptSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pins: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migrate: Option<MigrateOptions>,
  },
  AdoptData {
    service: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<crate::adopt_data::AdoptMountSpec>,
  },
  RemoveService {
    name: String,
    /// 连同数据一起删：`/srv/<服务>` 目录和 compose 声明的命名卷。外部目录不动。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    purge_data: bool,
  },
  /// 检查更新：重新查镜像标签（image 来源）或分支（git 构建来源）现在对应的版本，有新版本时计划里会更新。
  RefreshImages {
    name: String,
    /// 只检查这一个镜像（compose 里写的名字）；不填检查服务里的全部镜像。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image: Option<String>,
  },
  /// 把服务里的镜像换成同一仓库的另一个标签（image 来源改镜像，compose 来源改 `image:` 那一行），
  /// 计划时查新标签的版本。例：`halo/halo:2.20` 换成 `2.21`。
  RetagImage {
    name: String,
    /// 现在写的镜像，和 compose 里的一字不差。
    image: String,
    tag: String,
  },
  UpsertGateway {
    name: String,
    spec: GatewaySpec,
  },
  RemoveGateway {
    name: String,
  },
  UpsertRoute {
    spec: RouteSpec,
  },
  RemoveRoute {
    hostname: String,
  },
  UpsertEdgeApp {
    name: String,
    spec: EdgeAppSpec,
  },
  ImportEdgeApp {
    name: String,
    spec: EdgeAppSpec,
  },
  /// 只是不再纳管，不删除厂商那边的 Worker / Pages 项目。
  RemoveEdgeApp {
    name: String,
  },
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LoginSpec {
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub use_account: bool,
  #[serde(default)]
  pub steps: Vec<LoginStep>,
  #[serde(default)]
  pub write: Vec<LoginWrite>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub script: Option<LoginScript>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub check: Option<LoginStep>,
  #[serde(default = "login_ttl")]
  pub ttl_hours: u16,
  /// 代登录完成后跳到的路径，例如后台 `/ghost/`；不填就是 `/`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub entry: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub takeover: Option<LoginTakeover>,
}
fn login_ttl() -> u16 {
  24
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LoginTakeover {
  pub paths: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub skip_query: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rd_param: Option<String>,
  #[serde(default = "native_minutes")]
  pub native_minutes: u16,
}
fn native_minutes() -> u16 {
  10
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct LoginScript {
  pub runtime: crate::view::ScriptRuntime,
  pub code: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image: Option<String>,
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub deps: String,
  #[serde(default = "script_timeout")]
  pub timeout_secs: u64,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub env: BTreeMap<String, String>,
}
fn script_timeout() -> u64 {
  30
}
fn login_method() -> String {
  "GET".into()
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LoginStep {
  #[serde(default = "login_method")]
  pub method: String,
  pub path: String,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub headers: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub form: Option<BTreeMap<String, String>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub json: Option<serde_json::Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub body: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expect: Option<Vec<u16>>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub extract: Vec<Extract>,
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum Extract {
  Json { name: String, path: String },
  Body { name: String, between: [String; 2] },
  Header { name: String, header: String },
  Cookie { name: String, cookie: String },
}
impl Extract {
  pub fn name(&self) -> &str {
    match self {
      Self::Json { name, .. }
      | Self::Body { name, .. }
      | Self::Header { name, .. }
      | Self::Cookie { name, .. } => name,
    }
  }
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LoginWrite {
  Cookies(AllCookies),
  Cookie {
    name: String,
    value: String,
    #[serde(default = "cookie_http_only")]
    http_only: bool,
  },
  LocalStorage {
    key: String,
    value: String,
  },
  SessionStorage {
    key: String,
    value: String,
  },
}
fn cookie_http_only() -> bool {
  true
}
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AllCookies {
  All,
}
