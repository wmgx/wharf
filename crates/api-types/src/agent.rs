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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentOp {
  /// 立刻回一份最新的 [AgentReport]。
  Report,
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
}

/// 一次性口令。Debug 输出时隐藏，防止被打进日志。
#[derive(Clone, Serialize, Deserialize)]
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
}

/// restic 和 rest-server 的镜像，控制面和 agent 共用。
pub const RESTIC_IMAGE: &str = "restic/restic:0.18.1";
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUp {
  pub project: String,
  /// 已经替换过密钥的 compose 内容，agent 以 0600 写入磁盘。
  pub compose: String,
  /// 控制面算出的指纹，agent 原样保存，用于漂移判断。
  pub hash: String,
  pub pull: PullPolicy,
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
}
