//! Agent 操作的请求参数和返回值。

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedSample {
  pub at_ms: i64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub metrics: Option<super::Metrics>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub log_hits: Vec<crate::service_checks::LogHit>,
}

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
  /// 挂载的具名数据卷（不含宿主机目录和匿名卷）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub volumes: Vec<String>,
}

/// 宿主机上 systemd 跑的一个程序。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct HostUnit {
  /// unit 名，例如 `api.service`。
  pub unit: String,
  #[serde(default)]
  pub description: String,
  /// 启动命令。
  #[serde(default)]
  pub command: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub working_dir: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub user: Option<String>,
  /// unit 文件位置。
  #[serde(default)]
  pub unit_file: String,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub env_files: Vec<String>,
  /// running、exited、failed 等。
  #[serde(default)]
  pub state: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub since: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub memory: Option<u64>,
  /// 监听的地址，例如 `127.0.0.1:8080`。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub listens: Vec<String>,
  /// 宿主机上的 Caddy、nginx、cloudflared 配置里转发到这些端口的域名。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub domains: Vec<String>,
  /// 是网关本身（Caddy、nginx、cloudflared），它的 domains 是它承载的全部域名。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub gateway: bool,
  /// 配置文件：网关的配置、环境文件。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub configs: Vec<String>,
}

/// 一个服务的磁盘占用（字节）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceDisk {
  pub service: String,
  /// `/srv/<服务>` 目录。
  pub data: u64,
  /// 容器的 json 日志（含轮转出来的）。
  pub logs: u64,
  /// 挂载的命名卷：卷名 → 大小。
  #[serde(default)]
  pub volumes: std::collections::BTreeMap<String, u64>,
}

/// [super::AgentOp::RemoveContainers] 的结果。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemovedContainers {
  pub containers: Vec<String>,
  /// 删掉的数据卷。
  #[serde(default)]
  pub volumes: Vec<String>,
  /// 还有别的容器在用、没删的数据卷。
  #[serde(default)]
  pub kept_volumes: Vec<String>,
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
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<ProjectContainerRaw>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tag_image_id: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub config_files: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub env_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectContainerRaw {
  pub inspect: serde_json::Value,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image_inspect: Option<serde_json::Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tag_image_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retire {
  /// 接管后的服务名（也是新的 compose 项目名），属于它的容器不动。
  pub service: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub rename_containers: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub expected_services: Vec<String>,
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
  #[serde(default)]
  pub preserve_existing: bool,
}

#[derive(
  Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SyncPass {
  Live,
  #[default]
  Final,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPush {
  pub service: String,
  pub host: String,
  pub port: u16,
  pub password: OneTimeSecret,
  #[serde(default)]
  pub pass: SyncPass,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub bwlimit_kbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSpaceInfo {
  pub fs_avail_bytes: u64,
  pub fs_total_bytes: u64,
  #[serde(default)]
  pub data_bytes: Option<u64>,
  #[serde(default)]
  pub existing_bytes: u64,
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
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub bwlimit_kbps: Option<u32>,
}

/// 控制面把要备份的数据库快照和密钥放在这里，宿主机和容器里路径相同。
pub const CORE_BACKUP_DIR: &str = "/var/lib/wharf-core/backup";

/// restic 和 rest-server 的镜像，控制面和 agent 共用。
pub const RESTIC_IMAGE: &str = "restic/restic:0.18.1";
/// git 克隆在这个镜像的容器里做，服务器不用装 git。
pub const GIT_IMAGE: &str = "alpine/git:v2.49.1";
/// 构建出的镜像都在这个名字下，只在本机，不拉取。
pub const BUILD_IMAGE_PREFIX: &str = "wharf-build/";
pub const TRIAL_PROJECT_PREFIX: &str = "wharf-try-";
/// 执行 wrangler 的镜像。
pub const NODE_IMAGE: &str = "node:22-bookworm-slim";
pub const PYTHON_IMAGE: &str = "python:3.13-slim";
pub const SHELL_IMAGE: &str = "alpine:3.22";
/// 项目里没装 wrangler 时用这个版本。
pub const WRANGLER_VERSION: &str = "4.148.0";
pub const REST_SERVER_IMAGE: &str = "restic/rest-server:0.14.0";
/// rest-server 在备份服务器内网地址上监听的端口。
pub const REST_SERVER_PORT: u16 = 7710;
pub const CORE_REST_SERVER_PORT: u16 = 7711;
pub const CORE_BACKUP_ROOT: &str = "/srv/wharf-backup-core";
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
  Backup {
    host: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    excludes: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    keep: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
  },
  /// 列出快照，结果是 `Vec<Snapshot>`。
  Snapshots,
  /// 恢复快照到 `/srv/<service>/`，原来的目录改名保留。结果是保留目录的路径。
  Restore {
    snapshot: String,
  },
  /// 按保留策略删除旧快照并回收空间。
  Prune,
  PruneV2 {
    daily: u16,
    weekly: u16,
    monthly: u16,
    #[serde(default)]
    keep_tag: Option<String>,
    #[serde(default)]
    protect_before: Option<chrono::DateTime<chrono::Utc>>,
  },
  Ls {
    snapshot: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    limit: u32,
  },
  ExtractPrepare {
    snapshot: String,
    path: String,
    max_bytes: u64,
  },
  ExtractRead {
    token: String,
    offset: u64,
    len: u32,
  },
  ExtractClose {
    token: String,
  },
  DiffLocal {
    snapshot: String,
    #[serde(default)]
    excludes: Vec<String>,
    limit: u32,
  },
  DiffSnapshots {
    base: String,
    target: String,
    limit: u32,
  },
  Tag {
    snapshot: String,
    keep: bool,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    clear_note: bool,
  },
  /// 给仓库加一把口令，结果是新钥匙的 id。
  AddKey {
    new_password: OneTimeSecret,
  },
  /// 列出仓库钥匙。仓库不存在时返回空的 `Vec<ResticKeyInfo>`。
  ListKeys,
  /// 删掉一把口令。业务备份只能在备份服务器本机执行。
  RemoveKey {
    id: String,
  },
  Preflight(ResticPreflight),
  Unlock {
    #[serde(default)]
    remove_all: bool,
  },
}

impl ResticAction {
  pub fn needs_backup_v2(&self) -> bool {
    match self {
      Self::Backup {
        excludes,
        keep,
        note,
        ..
      } => !excludes.is_empty() || *keep || note.is_some(),
      Self::PruneV2 { .. }
      | Self::Tag { .. }
      | Self::Ls { .. }
      | Self::ExtractPrepare { .. }
      | Self::ExtractRead { .. }
      | Self::ExtractClose { .. }
      | Self::DiffLocal { .. }
      | Self::DiffSnapshots { .. } => true,
      _ => false,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResticKeyInfo {
  pub id: String,
  #[serde(default)]
  pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupSummary {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub escaped_mounts: Vec<EscapedMount>,
  pub snapshot_id: String,
  pub files: u64,
  pub bytes: u64,
  /// 这次新增到仓库的字节数（去重后）。
  pub added_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Snapshot {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub keep: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
  pub id: String,
  pub short_id: String,
  pub time: chrono::DateTime<chrono::Utc>,
  pub hostname: String,
  #[serde(default)]
  pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResticPreflight {
  pub mode: ResticPreflightMode,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub managed_mounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResticPreflightMode {
  Backup,
  Restore { snapshot: String },
}

#[derive(
  Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct EscapedMount {
  pub source: String,
  pub resolved: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMountUser {
  pub container: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  pub source: String,
  pub rw: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResticPreflightResult {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub escaped_mounts: Vec<EscapedMount>,
  #[serde(default)]
  pub is_mountpoint: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub conflicting_users: Vec<BindMountUser>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoppedContainers {
  pub containers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PruneRestoreResult {
  pub removed: usize,
  pub bytes: u64,
}

/// [super::AgentOp::SyncServe] 就绪时的进度行前缀。
pub const SYNC_READY: &str = "ready ";
pub const SYNC_BACKUP: &str = "WHARF_SYNC_BACKUP:";

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
  /// 代替 `https://github.com/` 的地址（服务器设置 `github_mirror`，已替换密钥）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub github_mirror: Option<String>,
  /// 查镜像版本时访问原仓库用的 HTTP 代理，和 dockerd 拉镜像用的一样（经出口时是本机的分流代理）。
  /// 镜像源总是直连。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub registry_proxy: Option<String>,
}

impl PullPolicy {
  /// 把镜像源和 GitHub 镜像地址里主机名后面的路径（可能是访问口令）换成 `***`，
  /// 用于日志和报错。
  pub fn redact(&self, text: &str) -> String {
    let addrs = self
      .mirrors
      .values()
      .flatten()
      .chain(self.github_mirror.iter());
    let text = addrs
      .fold(text.to_string(), |acc, addr| redact_addr(&acc, addr));
    match self.git_proxy.as_deref() {
      Some(p) if p.contains('@') => text.replace(p, &mask_url(p)),
      _ => text,
    }
  }
}

/// 去掉地址里的用户名和密码：`http://u:p@h:1` → `http://***@h:1`。
pub fn mask_url(url: &str) -> String {
  match (url.split_once("://"), url.rfind('@')) {
    (Some((scheme, _)), Some(at)) => {
      format!("{scheme}://***@{}", &url[at + 1..])
    }
    _ => url.to_string(),
  }
}

/// 把 `text` 里出现的 `addr`（形如 `host/口令` 或 `https://host/口令`）的路径部分换成 `***`。
pub fn redact_addr(text: &str, addr: &str) -> String {
  let bare = addr.split_once("://").map_or(addr, |(_, r)| r);
  match bare.trim_end_matches('/').split_once('/') {
    Some((host, path)) if !path.is_empty() => {
      text.replace(&format!("{host}/{path}"), &format!("{host}/***"))
    }
    _ => text.to_string(),
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMount {
  pub container: String,
  pub service: String,
  pub kind: String,
  pub source: String,
  pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitRun {
  pub service: String,
  pub command: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUp {
  pub project: String,
  /// 已经替换过密钥的 compose 内容，agent 以 0600 写入磁盘。
  pub compose: String,
  /// 控制面算出的指纹，agent 原样保存，用于漂移判断。
  pub hash: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start_timeout_secs: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub readiness: Option<SettleProbe>,
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
  /// 试跑用的 compose（已替换密钥）：正式替换之前先用它起一个不发布端口的容器，
  /// 稳定运行了才动线上的容器。旧版本 agent 不认识这个字段，直接部署。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub trial: Option<String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub expected_images: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub no_start: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub init: Option<InitRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveCommit {
  pub service: String,
  /// 只能是 `BuildFetch::Git`。
  pub fetch: BuildFetch,
  pub pull: PullPolicy,
}

/// 查镜像标签当前对应的 digest 和平台，不拉镜像层。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveImages {
  pub images: Vec<String>,
  pub pull: PullPolicy,
  /// 顺便列出仓库里更高版本的标签。旧版本 agent 不认识这个字段，不返回。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub tags: bool,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ResolvedImage {
  pub image: String,
  /// `sha256:…`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub digest: Option<String>,
  /// 这台机器平台对应的镜像 ID（`sha256:…`），和 `docker image inspect` 的 Id 相同。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub config: Option<String>,
  /// 镜像支持的平台，例如 `linux/amd64`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub platforms: Option<Vec<String>>,
  /// 目标 agent 的平台，例如 `linux/arm64`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub host_platform: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  /// `tags` 时：同一大版本里最高的标签，和跨大版本最高的标签（没有就不列）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub newer_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayApply {
  pub up: ProjectUp,
  /// 写到 project 目录下 `conf/Caddyfile`。
  pub caddyfile: String,
  pub caddyfile_hash: String,
  /// 随 Caddyfile 下发的受控文件。旧控制面缺省为空。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub extra_files: BTreeMap<String, String>,
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
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub exit_code: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub restart_policy: Option<String>,
}

impl ContainerInfo {
  pub fn is_active(&self) -> bool {
    matches!(self.state.as_str(), "running" | "restarting" | "paused")
  }

  pub fn is_restarting(&self) -> bool {
    self.state == "restarting"
  }

  pub fn is_running(&self) -> bool {
    !self.foreign && self.state == "running"
  }

  pub fn is_completed_init(&self) -> bool {
    self.state == "exited"
      && self.exit_code == Some(0)
      && matches!(self.restart_policy.as_deref(), Some("" | "no"))
  }

  pub fn is_healthy_state(&self, has_running: bool) -> bool {
    self.state == "running"
      || (has_running && self.is_completed_init())
  }
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
  /// 只上报 DNS-01 回调地址的指纹，不上报 Caddyfile。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub acme_dns_url_hash: Option<String>,
  /// 管理端口只用于保持同机已有 frpc 的分配。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub frpc_admin_port: Option<u16>,
  pub containers: Vec<ContainerInfo>,
}

impl ProjectState {
  /// 自有容器中至少一个在运行，其余可以是已完成的初始化容器。
  pub fn all_running(&self) -> bool {
    self.containers.iter().any(ContainerInfo::is_running)
      && self
        .containers
        .iter()
        .filter(|c| !c.foreign)
        .all(|c| c.is_healthy_state(true))
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
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expected_commit: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback_ref: Option<String>,
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redact_hides_mirror_paths() {
    let policy = PullPolicy {
      mirrors: BTreeMap::from([(
        "docker.io".into(),
        vec![
          "hub.example.com/secret123".into(),
          "docker.1ms.run".into(),
        ],
      )]),
      mirrors_only: false,
      attempt_timeout_secs: 60,
      git_proxy: None,
      github_mirror: Some("https://gh.example.com/secret123/".into()),
      registry_proxy: None,
    };
    let text = "docker pull hub.example.com/secret123/library/busybox:1 失败；\
      fatal: unable to access 'https://gh.example.com/secret123/o/r/'；docker.1ms.run/x";
    let out = policy.redact(text);
    assert!(!out.contains("secret123"), "{out}");
    assert!(out.contains("hub.example.com/***/library/busybox:1"));
    assert!(out.contains("https://gh.example.com/***/o/r/"));
    assert!(out.contains("docker.1ms.run/x"));
  }
}

pub const TASK_DATA_PREFIX: &str = "wharf-task-";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunJob {
  /// 任务名，一次性容器叫 `wharf-task-<任务名>`。
  pub name: String,
  pub how: TaskHow,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub input: Option<TaskInput>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub network_host: bool,
  /// 代登录脚本使用常驻容器，通过 WHARF_OUT 回传结果。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub out_dir: bool,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub wait_for_deps: bool,
  pub timeout_secs: u64,
  pub pull: PullPolicy,
}

pub fn sso_runner_name(
  runtime: crate::view::ScriptRuntime,
  image: &str,
) -> String {
  use crate::view::ScriptRuntime;
  use sha2::{Digest, Sha256};

  let runtime = match runtime {
    ScriptRuntime::Python => "python",
    ScriptRuntime::Node => "node",
    ScriptRuntime::Shell => "shell",
  };
  let hash = hex::encode(Sha256::digest(image));
  format!("wharf-sso-runner-{runtime}-{}", &hash[..12])
}

/// 网址触发带来的请求，请求体使用 base64。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInput {
  pub method: String,
  pub query: String,
  pub body: String,
}

/// 命令里的密钥已经替换好，脚本正文保持原样。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskHow {
  Script {
    image: String,
    runtime: crate::view::ScriptRuntime,
    code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    deps: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    mirrors: BTreeMap<String, String>,
    env: BTreeMap<String, String>,
  },
  /// 在 compose 项目 `project` 的容器里执行；`service` 是 compose 服务名，只有一个容器时可以不填。
  Exec {
    project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    /// 任务执行才准备容器内取消句柄。只读探测不写容器文件。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    cancellable: bool,
  },
  /// `docker run --rm`；有 `command` 时用 `sh -c` 代替镜像的入口。
  Container {
    image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    /// `宿主机路径:容器路径[:ro]`。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<String>,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunResult {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub result: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mem_peak: Option<u64>,
  /// 超时被杀掉时没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub exit_code: Option<i32>,
  pub timed_out: bool,
  /// stdout 和 stderr 合起来的最后一段。
  pub output: String,
  pub duration_ms: u64,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize,
)]
pub struct EgressConfig {
  /// 提供出口：在内网地址 `bind` 上起代理，要口令。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub serve: Option<EgressServe>,
  /// 本地分流：在 127.0.0.1 和 docker 网桥地址上起代理，命中规则的转给出口。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub route: Option<EgressRoute>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressServe {
  pub bind: String,
  pub token: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressRoute {
  /// 出口的 `内网地址:端口`。
  pub exit: String,
  pub token: String,
  pub all: bool,
  /// 已展开的域名清单。
  pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrevLogMeta {
  pub index: u32,
  pub at: i64,
  pub reason: String,
  pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrevLogOutput {
  pub index: u32,
  pub at: i64,
  pub reason: String,
  pub available: u32,
  pub logs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleProbe {
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub headers: BTreeMap<String, String>,
  pub url: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expect: Option<u16>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub keyword: Option<String>,
}

pub fn judge_http_check(
  expect: Option<u16>,
  keyword: Option<&str>,
  r: &HttpCheckResult,
) -> (bool, String) {
  let Some(code) = r.status else {
    return (
      false,
      r.error.clone().unwrap_or_else(|| "没有应答".into()),
    );
  };
  let code_ok = match expect {
    Some(e) => code == e,
    None => (200..400).contains(&code),
  };
  if !code_ok {
    let want =
      expect.map_or("2xx 或 3xx".to_string(), |e| e.to_string());
    return (false, format!("HTTP {code}，期望 {want}"));
  }
  if r.found == Some(false) {
    let k = keyword.unwrap_or_default();
    return (
      false,
      format!("HTTP {code}，但应答里没有\u{201c}{k}\u{201d}"),
    );
  }
  (true, format!("HTTP {code} · {} ms", r.ms))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCheck {
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub headers: BTreeMap<String, String>,
  pub url: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub keyword: Option<String>,
  pub timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpCheckResult {
  /// 拿到应答时的状态码。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub status: Option<u16>,
  pub ms: u64,
  /// 设了关键字时：应答里有没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub found: Option<bool>,
  /// 连不上、超时等。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ExposureReport {
  pub listens: Vec<Listen>,
  pub containers: Vec<ContainerRisk>,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Listen {
  pub proto: String,
  pub addr: String,
  pub port: u16,
  pub process: String,
  pub container: Option<String>,
  pub project: Option<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ContainerRisk {
  pub name: String,
  pub project: Option<String>,
  pub risks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFetch {
  pub url: String,
  pub method: String,
  pub headers: Vec<(String, String)>,
  pub body: Option<String>,
  pub timeout_secs: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpFetchResult {
  pub status: Option<u16>,
  pub headers: Vec<(String, String)>,
  pub body: String,
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreHostProbe {
  pub challenge_id: String,
  pub data_dir: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CoreHostProbeResult {
  pub token: String,
}

/// 用原镜像仓库名和校验后的摘要消除镜像源路径。
pub fn normalize_image_digest(
  image: &str,
  raw: &str,
) -> Option<String> {
  let (_, digest) = raw.rsplit_once('@')?;
  let hex = digest.strip_prefix("sha256:")?;
  if hex.len() != 64
    || !hex
      .bytes()
      .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
  {
    return None;
  }
  let name = image.split_once('@').map_or(image, |(name, _)| name);
  let tag_start = name.rfind('/').map_or(0, |i| i + 1);
  let name = name
    .rfind(':')
    .filter(|i| *i >= tag_start)
    .map_or(name, |i| &name[..i]);
  (!name.is_empty()).then(|| format!("{name}@{digest}"))
}

pub fn normalize_image_digests(images: &mut [ImageInfo]) {
  for image in images {
    image.digest = image
      .digest
      .as_deref()
      .and_then(|d| normalize_image_digest(&image.image, d));
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProbeJob {
  pub hostname: String,
  pub path: String,
  pub tls: bool,
  #[serde(default)]
  pub allow_pending_cert: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub gate_cookie: Option<OneTimeSecret>,
  pub http_port: u16,
  pub https_port: u16,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
  #[serde(default)]
  pub upstream_only: bool,
  #[serde(default = "default_gateway_probe_timeout")]
  pub timeout_secs: u16,
}

fn default_gateway_probe_timeout() -> u16 {
  5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProbeResult {
  pub ok: bool,
  pub stage: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub status: Option<u16>,
  #[serde(default)]
  pub cert_pending: bool,
  pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkApply {
  pub up: ProjectUp,
  pub config: String,
  pub config_hash: String,
  #[serde(default)]
  pub extra_files: BTreeMap<String, String>,
  pub image: String,
}

#[test]
fn foreign_running_container_does_not_make_project_running() {
  let project: ProjectState = serde_json::from_value(serde_json::json!({
    "project":"app","containers":[{"service":"app","name":"app-1","state":"running","foreign":true}]
  })).unwrap();
  assert!(!project.all_running());
}

/// 查询 /srv 下数据路径的 Docker bind 挂载者。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMountQuery {
  pub path: String,
  #[serde(default)]
  pub running_only: bool,
  #[serde(default)]
  pub writable_only: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub exclude_projects: Vec<String>,
}
