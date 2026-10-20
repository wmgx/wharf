//! API 返回的视图。字段只增不改，AI 可以依赖它们。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
  agent::{AgentReport, ContainerInfo},
  spec::{
    GatewaySpec, PrivateAddr, RouteSpec, ServerSettings, ServiceSpec,
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
  /// 例如 `{ "docker": "docker run ...", "binary": "wharf-agent join ..." }`。
  pub commands: BTreeMap<String, String>,
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
