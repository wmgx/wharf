//! API 返回的视图。字段只增不改，AI 可以依赖它们。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
  agent::{AgentReport, ContainerInfo},
  spec::{
    EdgeAppSpec, EdgeKind, GatewaySpec, PrivateAddr, RouteSpec,
    ServerSettings, ServiceSpec,
  },
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerView {
  pub name: String,
  pub settings: ServerSettings,
  /// agent 是否已经加入（完成过 join）。
  pub joined: bool,
  pub online: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_seen: Option<DateTime<Utc>>,
  /// agent 最近一次上报。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub report: Option<AgentReport>,
  /// 实际使用的公网 IP：设置里的覆盖值，否则是 agent 探测值。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub public_ip: Option<String>,
  /// 实际使用的内网地址：设置里的覆盖值，否则是 agent 检测到的组网地址。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub private_addr: Option<PrivateAddr>,
  /// 控制面到 agent 的往返延迟（websocket ping），毫秒。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rtt_ms: Option<u32>,
  pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceView {
  pub name: String,
  pub spec: ServiceSpec,
  /// 端口名到宿主机端口。
  pub host_ports: BTreeMap<String, u16>,
  /// 服务之间互相访问用的地址（内网地址:宿主机端口），例如 `100.101.102.103:20001`。
  pub addresses: BTreeMap<String, String>,
  pub version: u64,
  /// 实时状态，查不到时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub live: Option<LiveState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LiveState {
  /// `running`、`partial`、`stopped`、`missing`、`unknown`。
  pub state: String,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<ContainerInfo>,
  /// 现状是否和控制面里的配置一致。`false` 时执行 `wharf plan` 可以看到差异。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub in_sync: Option<bool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GatewayView {
  pub name: String,
  pub spec: GatewaySpec,
  /// 承载的路由 hostname。
  pub routes: Vec<String>,
  pub version: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub live: Option<LiveState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouteView {
  pub id: String,
  pub spec: RouteSpec,
  /// 实际使用的网关（spec 里没填时是默认网关）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub gateway: Option<String>,
  /// 网关转发到的上游地址。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
  pub url: String,
  pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EdgeAppView {
  pub name: String,
  pub spec: EdgeAppSpec,
  pub version: u64,
  /// 厂商那边的现状（后台同步后存在控制面），还没同步过时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub live: Option<EdgeLive>,
  /// 和 Wharf 记录的不一致时的说明，例如线上版本被别处改过、项目被删了。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub drift: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EdgeLive {
  /// 厂商那边是否存在这个 Worker / Pages 项目。
  pub exists: bool,
  /// 默认访问地址，例如 `https://x.y.workers.dev`、`https://x.pages.dev`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub url: Option<String>,
  /// 最近一次发布。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub deployed_at: Option<String>,
  /// 最近一次发布的来源，例如 `wrangler`、`dashboard`、`api`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub deployed_by: Option<String>,
  /// 读取失败时的原因。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  pub checked_at: DateTime<Utc>,
}

/// 厂商账号下自动发现的 Worker / Pages 项目。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EdgeProjectView {
  /// 所在的厂商账号。
  #[serde(default)]
  pub account: String,
  pub kind: EdgeKind,
  pub project: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub url: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub modified_at: Option<String>,
  /// 已经导入时是边缘应用的名字。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub managed_as: Option<String>,
}

/// 边缘应用的一个版本（Workers 的 version / Pages 的 deployment）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EdgeVersionView {
  pub id: String,
  pub created_at: String,
  /// `wrangler`、`dashboard`、`api` 等。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub source: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub message: Option<String>,
  /// 正在线上的版本。
  pub active: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub url: Option<String>,
}

/// `wharf edge pull`：Worker 当前线上的脚本。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EdgeScript {
  /// 文件名，例如 `worker.js`。
  pub filename: String,
  pub content: String,
  /// ES Module 格式（`export default`）还是旧的 Service Worker 格式。
  pub modules: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AccountView {
  pub name: String,
  pub kind: String,
  /// 脱敏后的 token，例如 `abcd…wxyz`。
  pub token: String,
  /// 自动发现的 zone。
  pub zones: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
  pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretView {
  pub name: String,
  pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentView {
  pub id: i64,
  pub service: String,
  pub server: String,
  pub run_id: String,
  /// 渲染后的 compose（密钥未替换）。
  pub compose: String,
  pub images: Vec<crate::agent::ImageInfo>,
  /// 部署时的服务配置。早于记录这一项的部署没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub spec: Option<ServiceSpec>,
  pub hash: String,
  pub created_at: DateTime<Utc>,
}

/// 回滚到某次部署时要提交的服务配置。image 来源会固定到当时的镜像 digest。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RollbackTarget {
  pub service: String,
  pub deployment_id: i64,
  pub deployed_at: DateTime<Utc>,
  pub spec: ServiceSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Status {
  pub servers: Vec<ServerView>,
  pub services: Vec<ServiceView>,
  #[serde(default)]
  pub edge_apps: Vec<EdgeAppView>,
  /// 厂商账号里还没纳管的 Workers / Pages（来自最近一次同步）。
  #[serde(default)]
  pub edge_unmanaged: Vec<EdgeProjectView>,
  pub gateways: Vec<GatewayView>,
  pub routes: Vec<RouteView>,
  /// 需要注意的问题，例如服务器离线、服务没在运行。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub problems: Vec<String>,
}

/// `wharf server add` 的返回：在目标机器上执行 `join` 里的任一命令即可加入。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JoinInfo {
  pub server: String,
  /// 一次性加入凭据，24 小时内有效，用过即失效。
  pub join_token: String,
  pub expires_at: DateTime<Utc>,
  /// 例如 `{ "script": "curl ... | sh ...", "docker": "docker run ...", "binary": "wharf-agent join ..." }`。
  pub commands: BTreeMap<String, String>,
  /// 命令里 agent 连接控制面用的地址。
  #[serde(default)]
  pub core_url: String,
}

/// 控制面能被 agent 访问到的地址。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoreAddresses {
  /// 控制面所在的服务器（网卡地址和 agent 上报的地址比对得到），找不到时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server: Option<String>,
  pub port: u16,
  pub addresses: Vec<CoreAddress>,
  /// 控制面默认的 agent 镜像。
  #[serde(default)]
  pub agent_image: String,
}

/// 控制面的一个候选地址，加服务器时选一个给 agent 连。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoreAddress {
  pub url: String,
  /// route（经网关开放的域名）、configured（启动时配置的地址）、public、tailscale、lan。
  pub kind: String,
  /// 走这个地址时 agent 和控制面之间是明文。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub plaintext: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JoinRequest {
  pub join_token: String,
  /// agent 的 ed25519 公钥，hex。
  pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JoinResponse {
  pub server: String,
  /// 控制面的 ed25519 公钥，hex。agent 用它确认连上的是真的控制面。
  pub core_public_key: String,
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
pub enum TokenScope {
  Read,
  Plan,
  /// 可以执行只含 safe 和 disruptive 项的计划。AI 默认用它。
  ApplySafe,
  /// 全部权限，包括确认高风险项、管理服务器和账号。
  ApplyAll,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TokenView {
  pub name: String,
  pub scope: TokenScope,
  pub created_at: DateTime<Utc>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreatedToken {
  pub name: String,
  pub scope: TokenScope,
  /// 只返回这一次。
  pub token: String,
}

/// 一次备份的记录（成功或失败）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupRecord {
  pub id: i64,
  /// 数据所在的服务器。
  pub server: String,
  /// 备份存到的服务器。
  pub target: String,
  pub run_id: String,
  pub ok: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub summary: Option<crate::agent::BackupSummary>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  pub created_at: DateTime<Utc>,
}

/// `GET /api/services/{name}/backups`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupsView {
  pub service: String,
  /// 没开启备份时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub target: Option<String>,
  /// 最近的备份记录，新的在前。
  pub records: Vec<BackupRecord>,
  /// 备份服务器上的快照，新的在前。
  pub snapshots: Vec<crate::agent::Snapshot>,
  /// 读取快照失败的原因（例如备份服务器离线）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub snapshots_error: Option<String>,
}

/// `POST /api/services/{name}/restore`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RestoreRequest {
  /// 快照 id，或 `latest`。
  pub snapshot: String,
  /// 必须是 `service/<名称>`：恢复会覆盖现有数据。
  pub confirm: String,
}
