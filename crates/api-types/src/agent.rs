//! 控制面和 agent 之间的 websocket 协议。握手是 JSON 文本帧，之后是加密的二进制帧。
//!
//! 握手（双向认证 + 交换临时密钥，不依赖 TLS）：
//! 1. agent 连上 `/agent/ws`，控制面发 [CoreMsg::Challenge]；
//! 2. agent 回 [AgentMsg::Hello]：自己的 nonce、临时公钥 `kx`，
//!    以及对 [auth_payload_v2]（含 challenge nonce 和 `kx`）的签名；
//! 3. 控制面验证 agent 公钥，回 [CoreMsg::Welcome]：自己的临时公钥 `kx`，
//!    以及对 agent nonce 和双方临时公钥的签名；
//! 4. agent 用 join 时记下的控制面公钥验证，双方用临时密钥派生会话密钥（[crate::seal]），
//!    之后每条消息都是一个加密的二进制帧，内容仍是 JSON。
//!
//! 旧 agent（协议版本低于 [crate::PROTOCOL]）不发 `kx`，按旧握手认证、明文通信，只接受升级请求。
//!
//! 请求：控制面发 [CoreMsg::Request]，agent 执行中可以发任意条
//! [AgentMsg::Progress]，最后发一条 [AgentMsg::Response]。
//! 控制面可以随时发 [CoreMsg::Cancel]；连接断开时 agent 取消全部请求。

use std::collections::BTreeMap;

pub use crate::resources::{AgentMemory, LocalImage};
use schemars::JsonSchema;

use serde::{Deserialize, Serialize};

use crate::{ApiError, spec::PrivateAddr};

pub use crate::net_probe::{NetProbeJob, NetProbeResult};

mod payloads;
pub use payloads::*;

/// 被签名的内容。`role` 是 `agent` 或 `core`，防止把一方的签名拿去冒充另一方。
pub fn auth_payload(
  role: &str,
  server: &str,
  nonce: &str,
) -> Vec<u8> {
  format!("wharf-auth-v1|{role}|{server}|{nonce}").into_bytes()
}

/// 带临时公钥的签名内容。`keys`：agent 签自己的临时公钥；控制面签 `控制面临时公钥,agent 临时公钥`。
pub fn auth_payload_v2(
  role: &str,
  server: &str,
  nonce: &str,
  keys: &str,
) -> Vec<u8> {
  format!("wharf-auth-v2|{role}|{server}|{nonce}|{keys}").into_bytes()
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreMsg {
  Challenge {
    nonce: String,
  },
  /// `signature`：控制面对 `auth_payload_v2("core", server, agent_nonce, "<kx>,<agent kx>")` 的签名；
  /// 旧 agent 收到的是对 `auth_payload("core", server, agent_nonce)` 的签名，没有 `kx`。
  Welcome {
    signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alt_signature: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    confirm_key: bool,
    /// 控制面的临时 X25519 公钥，hex。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kx: Option<String>,
  },
  KeyAccepted,
  AgentMemory {
    bytes: u64,
  },
  LogWatches {
    watches: Vec<crate::service_checks::LogWatch>,
  },
  Request {
    id: u64,
    timeout_ms: u64,
    op: AgentOp,
  },
  Cancel {
    id: u64,
  },
  /// 发给进行中的 [AgentOp::Terminal]、[AgentOp::HostTerminal] 或 [AgentOp::Forward]：输入字节或窗口大小变化。
  Input {
    id: u64,
    #[serde(flatten)]
    input: TerminalInput,
  },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TerminalInput {
  /// 输入的字节，base64。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub data: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub size: Option<TerminalSize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TerminalSize {
  pub cols: u16,
  pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
  Hello {
    server: String,
    public_key: String,
    /// 对 `auth_payload_v2("agent", server, challenge_nonce, kx)` 的签名（旧 agent 是 `auth_payload`）。
    signature: String,
    nonce: String,
    /// agent 的临时 X25519 公钥，hex。旧 agent 没有。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kx: Option<String>,
    version: String,
    /// 协议版本，见 [crate::PROTOCOL]。旧 agent 不发这个字段，反序列化成 0。
    #[serde(default)]
    protocol: u32,
    /// 是否支持宿主机终端和命令执行。旧 agent 缺省为不支持。
    #[serde(default)]
    host_shell: bool,
    #[serde(default)]
    runtime_v2: bool,
    /// 是否支持 [AgentOp::Forward]。旧 agent 缺省为不支持。
    #[serde(default)]
    forward: bool,
    #[serde(default)]
    service_checks: bool,
    #[serde(default)]
    container_diagnosis: bool,
    #[serde(default)]
    access_logs: bool,
    #[serde(default)]
    net_probe: bool,
    #[serde(default)]
    container_probe: bool,
    #[serde(default)]
    ssh_logins: bool,
    #[serde(default)]
    gateway_extra_files: bool,
    #[serde(default)]
    core_probe: bool,
    #[serde(default)]
    backup_isolation: bool,
    #[serde(default)]
    safe_delete: bool,
    #[serde(default)]
    shared_volumes: bool,
    #[serde(default)]
    safe_adopt: bool,
    #[serde(default)]
    safe_migrate: bool,
    #[serde(default)]
    safe_backup: bool,
    #[serde(default)]
    key_rotation: bool,
  },
  KeyReady {
    core_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_primary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_alt: Option<String>,
  },
  Report(Box<AgentReport>),
  Progress {
    id: u64,
    line: String,
  },
  Response {
    id: u64,
    result: Result<serde_json::Value, ApiError>,
  },
}

/// agent 定期上报的机器信息。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct AgentReport {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub backup_repos: Option<std::collections::BTreeMap<String, u32>>,
  pub version: String,
  pub hostname: String,
  pub os: String,
  pub arch: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub docker_version: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compose_version: Option<String>,
  /// 检测到的组网地址（目前只检测 Tailscale / Headscale）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub private_addr: Option<PrivateAddr>,
  /// 其余网卡的 IPv4 地址（不含回环和 docker 网桥），
  /// 没有组网工具时作为内网地址的候选。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub lan_ips: Vec<String>,
  /// 探测到的公网出口 IP。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub public_ip: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub egress_info: Option<crate::external::EgressInfo>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub docker_quota: Option<crate::external::DockerQuota>,
  /// agent 存放 compose 文件的目录。
  pub data_dir: String,
  /// 构建号，见 [crate::BUILD]。旧版本 agent 没有。
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub build: String,
  /// `data_dir` 所在磁盘的容量。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub disk: Option<Disk>,
  /// Docker 镜像和容器所在磁盘的容量，和 `disk` 不是同一块盘时才有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub docker_disk: Option<Disk>,
  /// 最近一次检查 agent 容器内存上限的结果。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub agent_memory: Option<AgentMemory>,
  /// 资源采样，每分钟一次。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub metrics: Option<Box<Metrics>>,
  /// agent 发送上报时的 Unix 毫秒时间，旧版本没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub time_ms: Option<i64>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub log_hits: Vec<crate::service_checks::LogHit>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub host_subnets: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub docker_subnets: Vec<DockerSubnet>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct DockerSubnet {
  pub name: String,
  pub subnet: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerDiagnosis {
  pub name: String,
  pub running: bool,
  pub restarting: bool,
  pub exit_code: i32,
  pub oom_killed: bool,
  pub started_at: String,
  pub restart_count: u64,
  pub network_mode: String,
  /// 本次查询命中的宿主机端口到容器 TCP 端口的映射。
  pub ports: BTreeMap<u16, u16>,
  /// None 表示读取失败或容器未运行。
  pub listeners: Option<Vec<std::net::SocketAddr>>,
  pub user: Option<ContainerUser>,
  pub mounts: Vec<BindMountDiagnosis>,
  pub log_keywords: Vec<ContainerLogKeyword>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ContainerUser {
  pub uid: u32,
  /// 退出容器只配了数字 UID 时，镜像内的主组可能未知。
  pub gid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BindMountDiagnosis {
  pub source: String,
  /// None 表示未检查。
  pub permissions: Option<DirectoryPermissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirectoryPermissions {
  pub uid: u32,
  pub gid: u32,
  pub mode: u32,
  pub writable: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerLogKeyword {
  PermissionDenied,
  Eacces,
  ReadOnlyFileSystem,
  ExecFormatError,
}

/// 一次资源采样。速率是和上一次采样相比的平均值。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Metrics {
  /// 整机 CPU 使用率，0 到 100。
  pub cpu: f32,
  pub mem_used: u64,
  pub mem_total: u64,
  /// 字节每秒，不含回环、docker 网桥和组网网卡。
  pub net_rx: u64,
  pub net_tx: u64,
  pub disk_used: u64,
  pub disk_total: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub inode_used: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub inode_total: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub agent_cpu: Option<f32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub agent_mem: Option<u64>,
  /// compose project 名到它的容器合计。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub projects: BTreeMap<String, ProjectMetrics>,
  /// 本机 Caddy 网关上一段时间各域名的请求统计。旧 agent 没有。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub hosts: BTreeMap<String, HostTraffic>,
  /// 上次上报以来因内存超限被杀过容器的 compose project 名。
  /// 旧 agent 没有这个字段；新 agent 每次都带，没有就是空列表。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub oom: Option<Vec<String>>,
}

/// 一个域名在上报间隔内经网关的请求（只算转发到上游的）。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct HostTraffic {
  pub reqs: u64,
  /// 5xx 的个数。
  pub errors: u64,
  /// 这段统计的秒数。
  pub secs: f32,
  pub p50_ms: f32,
  pub p95_ms: f32,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ProjectMetrics {
  /// 占整机 CPU 的百分比，0 到 100。
  pub cpu: f32,
  pub mem: u64,
  pub net_rx: u64,
  pub net_tx: u64,
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
pub struct Disk {
  pub total: u64,
  pub free: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentOp {
  RotateAgentKey(RotateAgentKeyJob),
  TrustCoreKey(TrustCoreKeyJob),
  /// 结果是 Vec<LocalImage>。
  ListImages,
  /// 立刻回一份最新的 [AgentReport]。
  Report,
  /// 结果是 `Vec<ResolvedImage>`。
  ResolveImages(ResolveImages),
  /// 查 git 分支或标签现在指向的 commit（`git ls-remote`，不下载代码），结果是 40 位 commit。
  ResolveCommit(ResolveCommit),
  /// 读取若干 compose project 的现状，结果是 `Vec<ProjectState>`。
  ProjectStatus {
    projects: Vec<String>,
  },
  /// 只读诊断指定宿主机端口，结果是 Vec<ContainerDiagnosis>。
  DiagnoseContainer {
    project: String,
    ports: Vec<u16>,
  },
  /// 创建目录（数据卷）。已存在不报错。
  EnsureDirs {
    dirs: Vec<String>,
  },
  /// 写入 compose、拉镜像、`up -d`。结果是 [ProjectUpResult]。
  ProjectUp(ProjectUp),
  ProjectMounts {
    projects: Vec<String>,
  },
  /// `down` 并删除 project 目录。数据目录保留；`purge` 时连同 `/srv/<project>` 和 compose 声明的命名卷一起删。
  ProjectDown {
    project: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    purge: bool,
  },
  /// 最近的日志，结果是字符串。`follow` 时持续把新日志作为进度推送，
  /// 直到被取消或超时，结果是空字符串。
  Logs {
    project: String,
    tail: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    follow: bool,
    /// 只要这个时间之后的：`30m`、`2h`，或 RFC 3339 时间。旧 agent 不认识，会忽略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<String>,
  },
  PreviousLogs {
    project: String,
    #[serde(default)]
    index: u32,
    #[serde(default)]
    tail: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    list: bool,
  },
  /// 校验并应用网关配置，失败自动回滚。结果是 [ProjectUpResult]。
  GatewayApply(GatewayApply),
  /// 结果是 [crate::access_logs::AccessLogsResult]。
  AccessLogs(crate::access_logs::AccessLogsRequest),
  /// 配置不变，强制热重载网关（`caddy reload --force`），让还没签下来的证书立刻重新申请。
  /// 旧 agent 不认识，会忽略，调用方等到超时。
  GatewayReload {
    project: String,
  },
  /// `docker compose stop`：停止容器但不删除。project 不存在时什么也不做。
  ProjectStop {
    project: String,
  },
  /// `docker compose start`：启动已停止的容器。
  ProjectStart {
    project: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    containers: Vec<String>,
  },
  ServiceStopForData {
    project: String,
  },
  PruneRestore {
    older_than_days: u32,
  },
  /// 迁移的接收端：在内网地址上临时起一个 rsync 服务，写入 `/srv/<service>/`。
  /// 就绪后推送一条进度 `ready <port>`，之后一直运行，直到请求被取消。
  SyncServe(SyncServe),
  /// 迁移的发送端：把本机 `/srv/<service>/` 推送到另一台机器的 [AgentOp::SyncServe]。
  SyncPush(SyncPush),
  /// 删除迁移后留在旧服务器上的 `/srv/<service>/`。这台机器上还部署着这个服务时拒绝。
  RemoveData {
    service: String,
  },
  BindMountUsers(BindMountQuery),
  Restic(ResticJob),
  ProbeCoreHost(CoreHostProbe),
  /// 取代码、`docker build`，结果是 [BuildResult]。镜像已存在且不是 `force` 时跳过。
  Build(Box<BuildJob>),
  /// 取代码，在 node 容器里执行 wrangler 发布 Worker / Pages，结果是 [EdgeBuildResult]。
  EdgeBuild(Box<EdgeBuildJob>),
  /// 列出本机的全部容器（不含 agent 自己），结果是 `Vec<FoundContainer>`。
  Discover,
  /// 宿主机上 systemd 跑的、自己装的程序（只读），结果是 `Vec<HostUnit>`。
  HostUnits,
  /// 结果是 [ExposureReport]。
  Exposure,
  /// 宿主机程序最近的日志（journalctl -u），结果是字符串。
  HostUnitLogs {
    unit: String,
    lines: u32,
  },
  /// Wharf 自己的容器（agent、控制面）最近的日志，标准输出和标准错误按时间合在一起，结果是字符串。
  /// 这台机器上没有这个容器时报 NotFound。旧 agent 不认识。
  ContainerLogs {
    container: String,
    tail: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<String>,
  },
  /// 测各服务的占用：`/srv/<服务>`、容器日志、挂载的命名卷。要遍历文件，结果是 `Vec<ServiceDisk>`。
  DiskUsage {
    services: Vec<String>,
  },
  /// 删除没纳管的容器（`docker rm -f`）；`volumes` 时连同它们的具名数据卷一起删，别的容器还在用的不删。
  RemoveContainers {
    containers: Vec<String>,
    #[serde(default)]
    volumes: bool,
  },
  /// 读取要导入的 compose 项目或容器的配置，结果是 [ImportRaw]。
  ImportRead(ImportTarget),
  /// 恢复 [ProjectUp::retire] 停掉的容器。
  Unretire {
    items: Vec<Retired>,
  },
  /// 从本机去连别的服务器的探测端口，结果是 `Vec<bool>`（和 `targets` 一一对应）。
  Probe {
    targets: Vec<ProbeTarget>,
  },
  /// 从本机发一次 HTTP GET（自定义监控），结果是 [HttpCheckResult]。
  HttpCheck(HttpCheck),
  PortChecks {
    checks: Vec<crate::service_checks::PortCheck>,
  },
  /// 代登录请求，不记录请求和应答内容。
  HttpFetch(HttpFetch),
  NetProbe(NetProbeJob),
  /// 链路质量：对每个目标连 `count` 次，结果是 `Vec<LinkSample>`（和 `targets` 一一对应）。
  Quality {
    targets: Vec<ProbeTarget>,
    count: u8,
  },
  /// 升级 agent 自己（或 `container` 指定的同机容器，例如控制面）：
  /// 拉新镜像，起一个接班容器换掉当前容器，结果是 [UpgradeResult]。
  /// 回复之后连接会断开，新 agent 重新连上才算完成。
  Upgrade(UpgradeJob),
  /// 只拉镜像并比较容器的镜像 ID。结果是 [UpgradePreparation]。
  UpgradePrepare(UpgradeJob),
  /// 删除没有容器在用的镜像和构建缓存，结果是字符串（释放了多少）。
  Prune,
  /// 在 project 的容器里开一个 shell。输出作为进度推送（base64），
  /// 输入经 [CoreMsg::Input] 送进来；shell 退出时结束，结果是退出码。
  Terminal(TerminalJob),
  /// 在宿主机命名空间里开一个 root shell。输入输出与 [AgentOp::Terminal] 相同。
  HostTerminal {
    size: TerminalSize,
    /// 接上哪个 tmux 会话；不填是默认会话 `wharf`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<String>,
  },
  /// 转发一条 TCP 连接：连上目标后，收到的字节作为进度（base64）推回，
  /// 经 [CoreMsg::Input] 送进来的字节写给目标。任一方关闭就结束，结果是转发的字节数。
  Forward(ForwardJob),
  /// 宿主机上的 tmux 会话列表，结果是 `Vec<HostSession>`。没装 tmux 时是空列表。
  HostSessions,
  /// 结束宿主机上的一个 tmux 会话，里面跑着的程序会一起结束。
  HostSessionKill {
    session: String,
  },
  /// 给宿主机上的 tmux 会话改名。
  HostSessionRename {
    session: String,
    to: String,
  },
  /// 在宿主机命名空间里执行一次命令。结果是 [HostExecOutcome]。
  HostExec(HostExecJob),
  /// 定时任务：在服务容器里执行命令，或跑一次性容器。结果是 [TaskRunResult]。
  TaskRun(TaskRunJob),
  /// 入口服务器上仍在使用的代登录目录和运行容器。
  SsoCleanup {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    runners: Vec<String>,
  },
  /// 设置这台机器的出口：提供出口、本地分流，两部分都可以没有。
  /// 配置存在 agent 数据目录，重启后自动恢复。
  Egress(EgressConfig),
  /// 读宿主机的系统版本、待装更新、docker 和日志占用，结果是 [HostInfo]。只读。
  HostInfo,
  /// 近 30 天 sshd 成功登录，结果是采样时间和登录记录。
  SshLogins,
  /// 上一次升级接班容器的最后几十行日志，升级失败时控制面拿来显示原因。结果是字符串。
  UpgradeLog,
  /// 服务数据目录 `/srv/<service>/` 里的文件：列目录、分块读、分块写。
  Files(FilesOp),
  /// 列宿主机上的一个目录（只读挂载宿主机根目录），结果是 `Vec<String>`，目录名以 `/` 结尾。
  HostListDir {
    path: String,
  },
  /// 把宿主机上的目录按 `.gitignore` 打成代码包，用一次性口令上传到控制面，
  /// 结果是 [PackedUpload]。
  HostPack(HostPackJob),
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct HostPackJob {
  /// 宿主机上的绝对路径。
  pub path: String,
  /// 上传口令，只能用一次。
  pub token: String,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct PackedUpload {
  pub sha256: String,
  pub size: u64,
  pub files: usize,
}

/// 路径都相对于 `/srv/<service>/`，不能跳出去（含符号链接）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FilesOp {
  /// 结果是 `Vec<FileEntry>`。
  List { service: String, path: String },
  /// 结果是 [FileChunk]。
  Read {
    service: String,
    path: String,
    offset: u64,
    len: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<FileVersion>,
  },
  /// 写进临时文件，`last` 时换成正式文件（保留原文件或所在目录的属主）。
  /// `offset` 为 0 时从头写。结果为空。
  Write {
    service: String,
    path: String,
    offset: u64,
    /// base64。
    data: String,
    last: bool,
  },
}

/// 分块传输的块大小：base64 后远小于 websocket 单帧上限。
pub const FILE_CHUNK: u32 = 4 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileEntry {
  pub name: String,
  pub dir: bool,
  /// 符号链接（不跟进）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub link: bool,
  pub size: u64,
  /// 修改时间，毫秒。
  pub modified: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVersion {
  pub dev: u64,
  pub ino: u64,
  pub size: u64,
  pub mtime_secs: i64,
  pub mtime_nanos: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoveDataResult {
  #[serde(default)]
  pub removed: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub blocked_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
  /// base64。
  pub data: String,
  /// 文件总大小。
  pub size: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub version: Option<FileVersion>,
}

/// 服务器详情页的宿主机信息，打开页面时现查。
#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct HostInfo {
  /// `/etc/os-release` 的 PRETTY_NAME。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub os: Option<String>,
  pub kernel: String,
  pub uptime_secs: u64,
  pub mem_total: u64,
  pub mem_available: u64,
  /// 1、5、15 分钟负载。
  pub load: [f64; 3],
  pub cpus: u32,
  /// 按上次 `apt update` 的结果算的待装更新；不是 apt 系统时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub updates: Option<Vec<PackageUpdate>>,
  pub reboot_required: bool,
  /// `docker system df` 的每一行。
  pub docker: Vec<DockerUsage>,
  /// 容器日志（json-file）合计字节数。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container_logs: Option<u64>,
  /// systemd journal 字节数。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub journal: Option<u64>,
  /// `/var/log` 合计字节数（含 journal）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub var_log: Option<u64>,
  /// 近 30 天 sshd 的成功登录，最多 20 条，新的在前；读不到 journal 时为空。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ssh_logins: Vec<SshLogin>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct SshLogin {
  pub at: chrono::DateTime<chrono::Utc>,
  pub user: String,
  pub from: String,
  /// 认证方式，例如 publickey、password。
  pub method: String,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct PackageUpdate {
  pub name: String,
  pub from: String,
  pub to: String,
  /// 来自安全更新源。
  pub security: bool,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct DockerUsage {
  /// Images / Containers / Local Volumes / Build Cache。
  pub kind: String,
  pub total: String,
  pub active: String,
  pub size: String,
  pub reclaimable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalJob {
  pub project: String,
  /// compose 里的服务名，不填时用第一个在运行的容器。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service: Option<String>,
  pub size: TerminalSize,
}

/// 转发目标。`project` 为空时连宿主机 `127.0.0.1:port`，
/// 否则连该 compose 项目里在运行的容器的 `容器地址:port`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardJob {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  /// compose 里的服务名，不填时用第一个在运行的容器。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service: Option<String>,
  pub port: u16,
}

/// 宿主机上的一个 tmux 会话。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSession {
  pub name: String,
  /// 现在有几个终端连着它。
  pub attached: u32,
  /// 创建时间，unix 秒。
  pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostExecJob {
  pub command: String,
  pub timeout_secs: u64,
  pub cwd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HostExecOutcome {
  Finished(HostExecResult),
  Failed(HostExecFailure),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostExecResult {
  pub exit_code: i32,
  pub stdout: String,
  pub stderr: String,
  pub truncated: bool,
  pub duration_ms: u64,
  /// stdout 和 stderr 实际读到的原始字节数，包含截掉的部分。
  pub output_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostExecFailure {
  pub error: ApiError,
  pub duration_ms: u64,
  pub output_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeJob {
  /// 镜像标签，例如 `sha-0b45a47`。不填时重新拉当前镜像。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tag: Option<String>,
  pub pull: PullPolicy,
  /// 要换掉的容器 id，不填是 agent 自己。不在这台机器上时回复 NotFound。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
  /// 新容器日志里出现这段文字才算起来了，不填是 agent 连上控制面的日志。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub ready: Option<String>,
  /// 使用已经拉取的镜像，标签变化时拒绝执行。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expected_image: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpgradePreparation {
  pub image: String,
  /// 当前容器已经使用该镜像时为空。
  pub image_id: Option<String>,
}

/// 从 `/proc/self/mountinfo` 认出当前所在的容器 id：
/// `/etc/hostname` 之类的挂载来自 `.../containers/<id>/`。
pub fn container_id(mountinfo: &str) -> Option<String> {
  mountinfo.lines().find_map(|line| {
    let rest =
      &line[line.find("/containers/")? + "/containers/".len()..];
    let id: String =
      rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (id.len() == 64).then_some(id)
  })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResult {
  /// 新镜像。
  pub image: String,
  /// `false`：已经是这个镜像，没有换容器。
  pub started: bool,
}

/// 探测目标：连上 `addr` 后对方要回 `wharf <server>`。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ProbeTarget {
  pub server: String,
  /// `ip:端口`。
  pub addr: String,
  /// 只看 TCP 能不能连上，不要求对方是 agent 的探测端口（诊断网关到上游用）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub plain: bool,
}

/// 一个目标的链路质量采样。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LinkSample {
  pub sent: u8,
  /// 连上并且对方回了正确名字的次数。
  pub ok: u8,
  /// 成功那几次 TCP 建连的平均耗时（毫秒），一次都没成功时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub avg_ms: Option<f64>,
}

/// agent 的探测端口：连上后回一行 `wharf <服务器名>`。
pub const PROBE_PORT: u16 = 7701;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotatePhase {
  Prepare,
  Activate,
  Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateAgentKeyJob {
  pub phase: KeyRotatePhase,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expected_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateAgentKeyResult {
  pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCoreKeyJob {
  pub current: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub alt: Option<String>,
  #[serde(default)]
  pub reconnect: bool,
}
