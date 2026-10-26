//! 控制面和 agent 之间的 websocket 协议。消息都是 JSON 文本帧。
//!
//! 握手（双向认证，传输加密依赖服务器之间的网络）：
//! 1. agent 连上 `/agent/ws`，控制面发 [CoreMsg::Challenge]；
//! 2. agent 回 [AgentMsg::Hello]：对 [auth_payload] 的签名，以及自己的 nonce；
//! 3. 控制面验证 agent 公钥，回 [CoreMsg::Welcome]：对 agent nonce 的签名；
//! 4. agent 用 join 时记下的控制面公钥验证，之后开始上报和处理请求。
//!
//! 请求：控制面发 [CoreMsg::Request]，agent 执行中可以发任意条
//! [AgentMsg::Progress]，最后发一条 [AgentMsg::Response]。
//! 控制面可以随时发 [CoreMsg::Cancel]；连接断开时 agent 取消全部请求。

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiError, spec::PrivateAddr};

/// 被签名的内容。`role` 是 `agent` 或 `core`，防止把一方的签名拿去冒充另一方。
pub fn auth_payload(
  role: &str,
  server: &str,
  nonce: &str,
) -> Vec<u8> {
  format!("wharf-auth-v1|{role}|{server}|{nonce}").into_bytes()
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreMsg {
  Challenge {
    nonce: String,
  },
  /// `signature`：控制面对 `auth_payload("core", server, agent_nonce)` 的签名。
  Welcome {
    signature: String,
  },
  Request {
    id: u64,
    timeout_ms: u64,
    op: AgentOp,
  },
  Cancel {
    id: u64,
  },
  /// 发给进行中的 [AgentOp::Terminal]：键盘输入或窗口大小变化。
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
    /// 对 `auth_payload("agent", server, challenge_nonce)` 的签名。
    signature: String,
    nonce: String,
    version: String,
  },
  Report(AgentReport),
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
  /// agent 存放 compose 文件的目录。
  pub data_dir: String,
  /// 构建号，见 [crate::BUILD]。旧版本 agent 没有。
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub build: String,
  /// `data_dir` 所在磁盘的容量。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub disk: Option<Disk>,
  /// 资源采样，每分钟一次（其余上报没有）。控制面存进曲线后不再保留。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub metrics: Option<Box<Metrics>>,
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
  /// compose project 名到它的容器合计。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub projects: BTreeMap<String, ProjectMetrics>,
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
  /// 创建目录（数据卷）。已存在不报错。
  EnsureDirs {
    dirs: Vec<String>,
  },
  /// 写入 compose、拉镜像、`up -d`。结果是 [ProjectUpResult]。
  ProjectUp(ProjectUp),
  /// `down` 并删除 project 目录。数据目录保留。
  ProjectDown {
    project: String,
  },
  /// 最近的日志，结果是字符串。`follow` 时持续把新日志作为进度推送，
  /// 直到被取消或超时，结果是空字符串。
  Logs {
    project: String,
    tail: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    follow: bool,
  },
  /// 校验并应用网关配置，失败自动回滚。结果是 [ProjectUpResult]。
  GatewayApply(GatewayApply),
  /// `docker compose stop`：停止容器但不删除。project 不存在时什么也不做。
  ProjectStop {
    project: String,
  },
  /// `docker compose start`：启动已停止的容器。
  ProjectStart {
    project: String,
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
  Restic(ResticJob),
  /// 取代码、`docker build`，结果是 [BuildResult]。镜像已存在且不是 `force` 时跳过。
  Build(Box<BuildJob>),
  /// 取代码，在 node 容器里执行 wrangler 发布 Worker / Pages，结果是 [EdgeBuildResult]。
  EdgeBuild(Box<EdgeBuildJob>),
  /// 列出本机的全部容器（不含 agent 自己），结果是 `Vec<FoundContainer>`。
  Discover,
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
  /// 升级 agent 自己（或 `container` 指定的同机容器，例如控制面）：
  /// 拉新镜像，起一个接班容器换掉当前容器，结果是 [UpgradeResult]。
  /// 回复之后连接会断开，新 agent 重新连上才算完成。
  Upgrade(UpgradeJob),
  /// 删除没有容器在用的镜像和构建缓存，结果是字符串（释放了多少）。
  Prune,
  /// 在 project 的容器里开一个 shell。输出作为进度推送（base64），
  /// 输入经 [CoreMsg::Input] 送进来；shell 退出时结束，结果是退出码。
  Terminal(TerminalJob),
  /// 读宿主机的系统版本、待装更新、docker 和日志占用，结果是 [HostInfo]。只读。
  HostInfo,
  /// 服务数据目录 `/srv/<service>/` 里的文件：列目录、分块读、分块写。
  Files(FilesOp),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
  /// base64。
  pub data: String,
  /// 文件总大小。
  pub size: u64,
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

/// agent 的探测端口：连上后回一行 `wharf <服务器名>`。
pub const PROBE_PORT: u16 = 7701;

/// 服务器上的一个容器。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct FoundContainer {
  pub name: String,
  pub image: String,
  pub state: String,
  #[serde(default)]
  pub status: String,
  /// 例如 `0.0.0.0:8080->80/tcp`。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ports: Vec<String>,
  /// 所属的 compose 项目，`docker run` 起的为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
}

/// 导入哪个：compose 项目或单个容器，二选一。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTarget {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
}

/// 原样读出的配置，由控制面转换成服务。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportRaw {
  /// compose 项目：`docker compose config` 的输出（相对路径、`.env` 已解析）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compose: Option<String>,
  /// 单个容器：`docker inspect` 的结果。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub inspect: Option<serde_json::Value>,
  /// 单个容器的镜像：`docker image inspect` 的结果，用来去掉镜像自带的默认值。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image_inspect: Option<serde_json::Value>,
  /// 读取时的提醒，例如 compose 里引用了没有设置的变量。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retire {
  /// 接管后的服务名（也是新的 compose 项目名），属于它的容器不动。
  pub service: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<String>,
}

/// 被停掉的一个容器，恢复时用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retired {
  pub id: String,
  pub name: String,
  /// 改名后的名字（单个容器）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub renamed: Option<String>,
  /// 原来的重启策略。
  pub restart: String,
  pub was_running: bool,
}

/// 一次性口令。Debug 输出时隐藏，防止被打进日志。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OneTimeSecret(pub String);

impl std::fmt::Debug for OneTimeSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("***")
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncServe {
  pub service: String,
  /// 监听的内网地址。
  pub bind: String,
  /// 只接受这个地址（发送端的内网地址）的连接。
  pub allow: String,
  pub password: OneTimeSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPush {
  pub service: String,
  pub host: String,
  pub port: u16,
  pub password: OneTimeSecret,
}

/// restic 操作，在 restic 容器里执行。结果见 [ResticAction] 各项说明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResticJob {
  pub service: String,
  pub repo: ResticRepo,
  /// 仓库加密口令。
  pub password: OneTimeSecret,
  pub action: ResticAction,
  /// 本机没有 restic 镜像时怎么拉。
  pub pull: PullPolicy,
  /// 控制面自身备份：备份 [CORE_BACKUP_DIR] 而不是 `/srv/<service>/`。
  /// 目录里的 `.marker` 要和这个值一样，不一样（不是控制面所在的机器）回复 NotFound。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub core_marker: Option<String>,
}

/// 控制面把要备份的数据库快照和密钥放在这里，宿主机和容器里路径相同。
pub const CORE_BACKUP_DIR: &str = "/var/lib/wharf-core/backup";

/// restic 和 rest-server 的镜像，控制面和 agent 共用。
pub const RESTIC_IMAGE: &str = "restic/restic:0.18.1";
/// git 克隆在这个镜像的容器里做，服务器不用装 git。
pub const GIT_IMAGE: &str = "alpine/git:v2.49.1";
/// 构建出的镜像都在这个名字下，只在本机，不拉取。
pub const BUILD_IMAGE_PREFIX: &str = "wharf-build/";
/// 执行 wrangler 的镜像。
pub const NODE_IMAGE: &str = "node:22-bookworm-slim";
/// 项目里没装 wrangler 时用这个版本。
pub const WRANGLER_VERSION: &str = "4.148.0";
pub const REST_SERVER_IMAGE: &str = "restic/rest-server:0.14.0";
/// rest-server 在备份服务器内网地址上监听的端口。
pub const REST_SERVER_PORT: u16 = 7710;
/// rest-server 的数据目录，每个服务一个仓库 `<目录>/<服务>`。
pub const BACKUP_ROOT: &str = "/srv/wharf-backup";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResticRepo {
  /// 另一台服务器上的 rest-server：`http://<host>:<port>/<service>`。
  Rest {
    host: String,
    port: u16,
    user: String,
    password: OneTimeSecret,
  },
  /// 本机上 rest-server 的数据目录 `/srv/wharf-backup/<service>`，用来清理旧快照。
  Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResticAction {
  /// 备份 `/srv/<service>/`，仓库不存在时先初始化。结果是 [BackupSummary]。
  Backup { host: String },
  /// 列出快照，结果是 `Vec<Snapshot>`。
  Snapshots,
  /// 恢复快照到 `/srv/<service>/`，原来的目录改名保留。结果是保留目录的路径。
  Restore { snapshot: String },
  /// 按保留策略删除旧快照并回收空间。
  Prune,
  /// 给仓库加一把口令，结果是新钥匙的 id。
  AddKey { new_password: OneTimeSecret },
  /// 删掉一把口令。rest-server 只能追加，要在备份服务器本机（`Local`）做。
  RemoveKey { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupSummary {
  pub snapshot_id: String,
  pub files: u64,
  pub bytes: u64,
  /// 这次新增到仓库的字节数（去重后）。
  pub added_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Snapshot {
  pub id: String,
  pub short_id: String,
  pub time: chrono::DateTime<chrono::Utc>,
  pub hostname: String,
  #[serde(default)]
  pub paths: Vec<String>,
}

/// [AgentOp::SyncServe] 就绪时的进度行前缀。
pub const SYNC_READY: &str = "ready ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullPolicy {
  /// 例如 `{ "docker.io": ["docker.1ms.run"] }`。
  pub mirrors: BTreeMap<String, Vec<String>>,
  pub mirrors_only: bool,
  /// 每次 `docker pull` 的超时。
  pub attempt_timeout_secs: u64,
  /// 拉代码、查 commit 时用的 HTTP 代理（服务器设置 `git_proxy`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git_proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUp {
  pub project: String,
  /// 已经替换过密钥的 compose 内容，agent 以 0600 写入磁盘。
  pub compose: String,
  /// 控制面算出的指纹，agent 原样保存，用于漂移判断。
  pub hash: String,
  pub pull: PullPolicy,
  /// 本机已有的镜像不再拉取（刚导入的服务，避免拉到新版本而重建容器）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub pull_missing_only: bool,
  /// 导入时接管的原容器：镜像拉好之后、启动之前停掉，启动失败时恢复。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retire: Option<Retire>,
  /// 启动后没稳定运行时，换回上一版 compose（没有数据卷的服务才这样做）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub rollback: bool,
  /// 计划时固定的版本：镜像（compose 里写的名字）→ `sha256:…`。按 digest 拉取后打回原来的标签，
  /// compose 不用改；本地已经是这个 digest 就不拉。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub pins: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveCommit {
  pub service: String,
  /// 只能是 `BuildFetch::Git`。
  pub fetch: BuildFetch,
  pub pull: PullPolicy,
}

/// 查镜像标签当前对应的 digest：只读 registry 的清单，不拉镜像。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveImages {
  pub images: Vec<String>,
  pub pull: PullPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedImage {
  pub image: String,
  /// `sha256:…`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub digest: Option<String>,
  /// 这台机器平台对应的镜像 ID（`sha256:…`），和 `docker image inspect` 的 Id 相同。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub config: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayApply {
  pub up: ProjectUp,
  /// 写到 project 目录下 `conf/Caddyfile`。
  pub caddyfile: String,
  pub caddyfile_hash: String,
  /// 用来跑 `caddy validate` 的镜像，和 compose 里的一致。
  pub image: String,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ContainerInfo {
  /// compose 里的服务名。
  pub service: String,
  pub name: String,
  /// `running`、`exited`、`restarting` 等。
  pub state: String,
  #[serde(default)]
  pub status: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub health: Option<String>,
  #[serde(default)]
  pub image: String,
  /// 同名 compose 项目里不是 Wharf 部署的容器（compose 工作目录不是 Wharf 的项目目录）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub foreign: bool,
  /// compose 的工作目录，只在 agent 内部用来判断 `foreign`。
  #[serde(skip)]
  pub working_dir: Option<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ProjectState {
  pub project: String,
  /// 上次 `ProjectUp` 保存的指纹。没有部署过时为空。
  #[serde(default)]
  pub hash: Option<String>,
  /// 网关配置的指纹。
  #[serde(default)]
  pub config_hash: Option<String>,
  pub containers: Vec<ContainerInfo>,
}

impl ProjectState {
  /// 部署过，且所有容器都在运行。
  pub fn all_running(&self) -> bool {
    !self.containers.is_empty()
      && self.containers.iter().all(|c| c.state == "running")
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ImageInfo {
  pub image: String,
  #[serde(default)]
  pub id: String,
  /// `repo@sha256:…`，本地构建的镜像没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUpResult {
  pub containers: Vec<ContainerInfo>,
  pub images: Vec<ImageInfo>,
  #[serde(default)]
  pub warnings: Vec<String>,
  /// 这次停掉的原容器，容器起来后又退出时控制面用它恢复。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub retired: Vec<Retired>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJob {
  pub service: String,
  /// 构建出的镜像，`wharf-build/<服务>:<指纹>`。
  pub image: String,
  pub fetch: BuildFetch,
  /// 代码里的子目录，作为构建目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub base: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub template: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub install: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile_content: Option<String>,
  /// 内置模板里的 `$PORT`。
  pub port: u16,
  /// 作为 `--build-arg` 传入（镜像源等）。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub build_env: BTreeMap<String, String>,
  /// 镜像已存在也重新构建。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub force: bool,
  pub pull: PullPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeBuildJob {
  /// 边缘应用名，用于容器名和日志。
  pub app: String,
  pub kind: crate::spec::EdgeKind,
  /// 厂商那边的脚本名 / 项目名。
  pub project: String,
  pub fetch: BuildFetch,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  /// pages：构建命令。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub build: Option<String>,
  /// pages：发布目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub output: Option<String>,
  /// pages：生产分支，发布到它才算正式版本。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub branch: Option<String>,
  pub account_id: String,
  /// 厂商 API token，以环境变量传给 wrangler。
  pub api_token: OneTimeSecret,
  /// 作为环境变量传入（NPM_CONFIG_REGISTRY 等）。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub build_env: BTreeMap<String, String>,
  pub pull: PullPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeBuildResult {
  /// git 来源实际发布的 commit。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildFetch {
  /// 从控制面下载 CLI 上传的代码包：`GET <控制面>/agent/uploads/<sha256>`，
  /// 带一次性口令。
  Upload {
    sha256: String,
    token: OneTimeSecret,
  },
  Git {
    repo: String,
    reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<OneTimeSecret>,
  },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildResult {
  /// 镜像已存在，没有重新构建。
  #[serde(default)]
  pub skipped: bool,
  /// git 来源实际构建的 commit。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub commit: Option<String>,
}
