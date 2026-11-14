//! API 返回的视图。字段只增不改，AI 可以依赖它们。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
  agent::{AgentReport, ContainerInfo},
  spec::{
    BookmarkSpec, EdgeAppSpec, EdgeKind, GatewaySpec, NetworkMode, PrivateAddr,
    RouteSpec, ServerSettings, ServiceSpec,
  },
};

/// `GET /api/network`：各机器怎么接入、谁能连谁。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NetworkView {
  pub servers: Vec<NetworkServer>,
  /// 探测过的方向，没探测过的不在里面。
  pub reach: Vec<ReachView>,
  /// 最近一轮链路质量（每 5 分钟测一次，控制面重启后要等下一轮）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub links: Vec<LinkView>,
  /// 直连差、经第三台中转两段都好的方向。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub relays: Vec<RelayHint>,
}

/// 一个方向的链路质量。历史曲线：`GET /api/metrics?subject=<from>><to>&names=link.ms,link.loss`。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LinkView {
  pub from: String,
  pub to: String,
  /// TCP 建连平均耗时（毫秒），全部失败时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub ms: Option<f64>,
  /// 丢包率，0 到 100。
  pub loss: f64,
  pub at: DateTime<Utc>,
}

/// 中转建议：`from` → `via` → `to` 比直连好。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RelayHint {
  pub from: String,
  pub to: String,
  pub via: String,
  /// 直连丢包率。
  pub direct_loss: f64,
  /// 经中转两段合计的丢包率。
  pub via_loss: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NetworkServer {
  pub name: String,
  pub mode: NetworkMode,
  /// 接入方式是在设置里指定的（否则是按检测到的地址推断）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub configured: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub private_ip: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub public_ip: Option<String>,
  pub online: bool,
}

/// `from` 所在机器能不能连到 `to` 的内网地址。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReachView {
  pub from: String,
  pub to: String,
  pub ok: bool,
  pub checked_at: DateTime<Utc>,
  /// 超过一天没重新探测，结果不作数。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerView {
  pub name: String,
  pub settings: ServerSettings,
  /// agent 是否已经加入（完成过 join）。
  pub joined: bool,
  pub online: bool,
  /// 当前连接的 agent 支持宿主机终端和命令执行。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub host_shell: bool,
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
  /// agent 的构建号和控制面不一致，可以 `wharf server upgrade`。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub agent_outdated: bool,
  pub version: u64,
  /// 最近一次检查和基线不一样的项（每 6 小时检查一次）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub baseline_drift: Vec<String>,
  /// 按近 7 天趋势预计几天后磁盘写满；数据不足或没在增长时没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub disk_days_left: Option<f64>,
  /// 和控制面的时间差（毫秒，agent 比控制面快为正）。旧 agent 没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub clock_offset_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HostExecResponse {
  pub exit_code: i32,
  pub stdout: String,
  pub stderr: String,
  pub truncated: bool,
  pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ShellLog {
  pub id: i64,
  pub at: DateTime<Utc>,
  pub actor: String,
  pub server: String,
  pub kind: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub command: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub exit_code: Option<i32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub duration_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub output_bytes: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceView {
  pub name: String,
  pub spec: ServiceSpec,
  /// 端口名到宿主机端口。
  pub host_ports: BTreeMap<String, u16>,
  /// 服务之间互相访问用的地址（内网地址:宿主机端口），例如 `100.101.102.103:20001`。
  pub addresses: BTreeMap<String, String>,
  /// 局域网地址：端口名 → 各个局域网地址:宿主机端口（服务器设置了 lan_addrs 时才有）。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub lan_addresses: BTreeMap<String, Vec<String>>,
  /// 备注：给人看的说明，不影响部署。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
  pub version: u64,
  /// 容器现状，查不到时为空；状态看 `status`。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<crate::agent::ContainerInfo>,
  /// 服务挂载的数据和归属，从配置里算出来。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub data: Vec<DataMount>,
  /// 从服务器上已有的容器导入时的记录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub import: Option<ImportRecord>,
  /// 分层状态；只读配置、不查现状时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub status: Option<ServiceStatus>,
  /// 自定义监控的最近一次结果；没配监控或还没检查过时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub monitor: Option<MonitorView>,
  /// 用 `[[@服务]]` 引用了哪些服务。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub uses: Vec<String>,
  /// 被哪些服务引用。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub used_by: Vec<String>,
}

/// 服务的分层状态：期望、已应用、实际、健康、执行，加上按优先级挑出的一句话。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ServiceStatus {
  /// 期望：按配置应该在运行（`stopped` 时为 false）。
  pub want_running: bool,
  /// 期望：当前配置生成的 compose 哈希；缺密钥等算不出时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub desired_hash: Option<String>,
  /// 已应用：上次成功部署。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub applied: Option<Applied>,
  /// 实际：容器现状。
  pub actual: Actual,
  /// 实际：容器上标记的哈希。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub actual_hash: Option<String>,
  pub health: Health,
  /// 执行：最近一次和这个服务有关的部署、启停、重启、迁移、恢复。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_op: Option<LastOp>,
  pub tone: Tone,
  /// 一句话，例如"运行中"、"部署失败"、"服务器离线"。
  pub summary: String,
  /// 查不到现状时的原因。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  /// 最后一次成功查到这台服务器现状的时间；服务器离线时就是"多久前看到的"。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub observed_at: Option<DateTime<Utc>>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Applied {
  pub hash: String,
  pub at: DateTime<Utc>,
  /// image 来源实际部署的镜像 digest（`sha256:…`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub digest: Option<String>,
  /// 部署时的镜像（compose 里写的名字）和镜像 ID。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image_id: Option<String>,
  /// git 构建来源实际构建的 commit，和当时的 `仓库#分支`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub commit: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git: Option<String>,
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
pub enum Actual {
  Running,
  /// 有的容器在运行，有的没有。
  Partial,
  Stopped,
  /// 服务器上没有这个服务的容器。
  Missing,
  /// 服务器的 agent 不在线。
  Offline,
  /// agent 在线但查询失败。
  Unknown,
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
pub enum Health {
  Healthy,
  Unhealthy,
  Starting,
  /// 没配健康检查。
  None,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct LastOp {
  /// 部署、重启、停止、迁移数据、恢复。
  pub action: String,
  pub run_id: String,
  pub status: OpStatus,
  pub at: DateTime<Utc>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
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
pub enum OpStatus {
  Running,
  Succeeded,
  Failed,
}

/// 页面上的颜色。
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
pub enum Tone {
  Ok,
  Warn,
  Bad,
  Idle,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct ImportRecord {
  pub server: String,
  /// 原来的 compose 项目。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  /// 原来 `docker run` 起的容器。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub containers: Vec<String>,
  /// 被停掉留着回退用的旧容器（改名后的名字）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub retired: Vec<String>,
  /// 第一次部署成功的时间；还没部署时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub done_at: Option<DateTime<Utc>>,
}

/// 数据归属：决定迁移、备份、删除时动不动它。
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
pub enum DataKind {
  /// `/srv/<服务>/` 下：迁移时同步、每天备份、迁走后旧机器上的 7 天后删除。
  Managed,
  /// 其他宿主机目录：Wharf 不迁移、不备份、不删除。
  ExternalDir,
  /// docker 命名卷或匿名卷：Wharf 不迁移、不备份、不删除。
  NamedVolume,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct DataMount {
  pub kind: DataKind,
  /// 宿主机路径或卷名；匿名卷为空。
  pub source: String,
  /// 容器内路径。
  pub target: String,
  /// compose 里的服务名；image / build 来源为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
}

/// 一个服务的数据备份状态。
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
pub enum DataStatus {
  /// 开了备份，最近 48 小时内成功过。
  Ok,
  /// 开了备份，最近 48 小时内没有成功（包括从没成功、最近一次失败）。
  Stale,
  /// 有 Wharf 管的目录，但没开备份。
  Off,
  /// 开了备份，但还有不归 Wharf 管的数据，备份盖不到。
  Uncovered,
  /// 没有任何挂载。
  None,
}

/// `GET /api/data`：每个服务的数据在哪、备份有没有在跑。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DataView {
  pub services: Vec<ServiceData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceData {
  pub name: String,
  /// 数据所在的服务器。
  pub server: String,
  /// 备份存到哪台服务器，没开备份时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub target: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_ok: Option<DateTime<Utc>>,
  /// 只在这个时间比最近成功晚时才有，也就是最近一次尝试失败了。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_failed: Option<DateTime<Utc>>,
  pub mounts: Vec<DataMount>,
  pub status: DataStatus,
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
  /// 最近一次域名体检的 HTTP(S) 结果和连续失败次数；还没检查过时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub probe: Option<ProbeView>,
  /// 主网关那台离线，DNS 现在指向备用入口（`gateway` 是备用网关）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub on_backup: bool,
}

/// 自定义监控的最近一次结果。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MonitorView {
  pub ok: bool,
  /// 例如 `HTTP 200 · 12 ms`、`HTTP 502，期望 2xx 或 3xx`。
  pub detail: String,
  /// 毫秒时间戳。
  pub at: i64,
  #[serde(default)]
  pub fails: u32,
}

/// 域名探测结果。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeView {
  pub ok: bool,
  /// 例如 `HTTP 200`、`15 秒没有应答`。
  pub detail: String,
  pub ms: u64,
  /// 毫秒时间戳。
  pub at: i64,
  /// 连续失败次数。
  #[serde(default)]
  pub fails: u32,
  /// https 证书还剩几天。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cert_days: Option<i64>,
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
  /// 用到它的服务和系统功能。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub used_by: Vec<String>,
  /// Wharf 自己生成的，不能改也不能删。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub managed: bool,
  /// 系统功能用的（网关登录、组网、通知等）：在对应功能里改，不算应用密钥。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub system: Option<String>,
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
  /// git 来源时部署的 commit。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub commit: Option<String>,
}

/// 回滚到某次部署时要提交的服务配置。image 来源会固定到当时的镜像 digest。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RollbackTarget {
  pub service: String,
  pub deployment_id: i64,
  pub deployed_at: DateTime<Utc>,
  pub spec: ServiceSpec,
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
pub enum IssueLevel {
  /// 现在就不能用。
  Fault,
  /// 能用，但要看一眼。
  Warn,
  /// 可以做的事：有新版本、有没执行完的改动。
  Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IssueSubject {
  /// server、service、gateway、edge、task、route。
  pub kind: String,
  pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Issue {
  /// 这是哪一类问题，页面按它决定给什么按钮。取值见下表。
  pub code: String,
  pub level: IssueLevel,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub subject: Option<IssueSubject>,
  /// 给人看的一句话。
  pub title: String,
  /// 只给命令行看的补充（怎么用命令处理）。页面不显示。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Status {
  #[serde(default)]
  pub bookmarks: Vec<BookmarkView>,
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
  #[serde(default)]
  pub issues: Vec<Issue>,
  /// 最近一次域名检查（后台每 5 分钟），控制面刚启动时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub health: Option<DoctorReport>,
  /// 后台检查的新版本和未执行的改动，控制面刚启动时为空。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub updates: Option<UpdatesView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkView {
  pub id: String,
  pub spec: BookmarkSpec,
  pub version: u64,
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
/// 旧的权限档位，现在只作为新建 token 时的预设，见 [`Perm::of_scope`]。
pub enum TokenScope {
  Read,
  Plan,
  /// 可以执行只含 safe 和 disruptive 项的计划。AI 默认用它。
  ApplySafe,
  /// 全部权限，包括确认高风险项、管理服务器和账号。
  ApplyAll,
}

/// 权限点。token 持有一组；页面登录的会话有全部权限。
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Hash,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Perm {
  /// 查看一切（不含密钥明文）。
  Read,
  /// 生成计划、探测网络、预览导入。
  Plan,
  /// 执行不含高风险项的计划、上传代码包、触发备份、重新发布边缘应用。
  Apply,
  /// 确认高风险项（删数据、覆盖、公开）、从备份恢复。
  Confirm,
  /// 宿主机命令执行、宿主机和容器终端、改服务文件。
  Exec,
  /// 管理服务器、账号、密钥、token，升级 Wharf，改宿主机访问开关。
  Admin,
}

impl Perm {
  pub const ALL: [Perm; 6] = [
    Perm::Read,
    Perm::Plan,
    Perm::Apply,
    Perm::Confirm,
    Perm::Exec,
    Perm::Admin,
  ];

  pub fn as_str(self) -> &'static str {
    match self {
      Perm::Read => "read",
      Perm::Plan => "plan",
      Perm::Apply => "apply",
      Perm::Confirm => "confirm",
      Perm::Exec => "exec",
      Perm::Admin => "admin",
    }
  }

  pub fn parse(s: &str) -> Option<Perm> {
    Perm::ALL.into_iter().find(|p| p.as_str() == s)
  }

  /// 旧档位对应的一组权限点。
  pub fn of_scope(scope: TokenScope) -> Vec<Perm> {
    let n = match scope {
      TokenScope::Read => 1,
      TokenScope::Plan => 2,
      TokenScope::ApplySafe => 3,
      TokenScope::ApplyAll => 6,
    };
    Perm::ALL[..n].to_vec()
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TokenView {
  pub name: String,
  pub perms: Vec<Perm>,
  pub created_at: DateTime<Utc>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreatedToken {
  pub name: String,
  pub perms: Vec<Perm>,
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

/// `GET /api/servers/{name}/unmanaged`：服务器上还没纳管的一组容器，
/// 是一个 compose 项目或一个 `docker run` 起的容器。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Unmanaged {
  pub server: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
  pub containers: Vec<crate::agent::FoundContainer>,
  /// 导入时默认的服务名。
  pub name: String,
}

/// `POST /api/import`：compose 项目和容器二选一。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportRequest {
  pub server: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub container: Option<String>,
  /// 服务名，不填时由项目名或容器名得出。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
}

/// 导入预览：用 `upsert_service` 提交即可。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportPreview {
  pub name: String,
  pub spec: ServiceSpec,
  /// 提交 `UpsertService` 时原样带上。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub adopt: Option<crate::spec::AdoptSpec>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
}

/// `wharf doctor` 的结果：沿每个域名的访问链路逐层检查。只读。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DoctorReport {
  pub checked_at: DateTime<Utc>,
  pub servers: Vec<DoctorCheck>,
  pub routes: Vec<RouteDiagnosis>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouteDiagnosis {
  pub hostname: String,
  pub url: String,
  /// 按访问顺序：域名解析 → HTTPS → 网关 → 网关到上游 → 容器。
  pub checks: Vec<DoctorCheck>,
  /// HTTPS 证书到期时间，连不上或不是 HTTPS 时没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cert_expires: Option<DateTime<Utc>>,
  /// 这个域名的注册到期时间（后台用 RDAP 查，查不到没有）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub domain_expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DoctorCheck {
  /// 哪一层，例如 `dns`、`https`、`gateway`、`link`、`container`、`agent`。
  pub layer: String,
  /// 检查对象，例如 `server1 上的网关 edge`。
  pub subject: String,
  pub status: CheckStatus,
  pub detail: String,
  pub at: DateTime<Utc>,
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
pub enum CheckStatus {
  Ok,
  Warn,
  Bad,
  /// 前面一层已经不通，或这一层不适用。
  Skip,
}

/// 后台检查：镜像标签、代码分支有没有比固定版本新的（每 6 小时），
/// 现在的配置和机器上的现状差几项（每 10 分钟算一次计划，不保存）。
#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdatesView {
  /// 服务 → 版本检查结果，只有 image 和 git 构建来源的服务。
  #[serde(default)]
  pub services: BTreeMap<String, VersionCheck>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pending: Option<PendingCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionCheck {
  pub at: DateTime<Utc>,
  /// 仓库里有比固定版本新的。
  pub newer: bool,
  /// 查到的最新版本（镜像 digest 或 commit）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub latest: Option<String>,
  /// 这次没查到时的原因，`newer` 沿用上一次的结果。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PendingCheck {
  pub at: DateTime<Utc>,
  /// 计划项的地址，例如 `service/whoami`。
  #[serde(default)]
  pub items: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

/// 定时任务。名字全局唯一。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskSpec {
  pub server: String,
  /// 5 段 cron（分 时 日 月 周），北京时间。
  pub schedule: String,
  #[serde(flatten)]
  pub how: TaskKind,
  /// 超时秒数，默认 600；宿主机命令最长 600，其他最长 6 小时。
  #[serde(default = "default_task_timeout")]
  pub timeout_secs: u64,
  #[serde(default = "yes")]
  pub enabled: bool,
  /// 失败和恢复时发通知。
  #[serde(default = "yes")]
  pub notify: bool,
}

fn default_task_timeout() -> u64 {
  600
}

fn yes() -> bool {
  true
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskKind {
  /// 在服务的容器里执行命令。
  Exec {
    service: String,
    /// compose 服务名，服务只有一个容器时不用填。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    container: Option<String>,
    command: String,
  },
  /// 一次性容器，跑完删除。
  Container {
    image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<String>,
  },
  /// 宿主机命令，要服务器开了"命令执行"。
  Host { command: String },
  /// 外部报到：Wharf 不执行，由别处（cron、systemd timer、脚本）跑完后请求报到地址。
  /// `schedule` 是预期的运行时间，过了 `grace_mins` 分钟还没报到就记一次失败并通知。
  Ping {
    /// 报到地址里的口令，新建时自动生成。
    #[serde(default)]
    token: String,
    #[serde(default = "default_grace")]
    grace_mins: u32,
  },
}

fn default_grace() -> u32 {
  60
}

#[derive(
  Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
  Running,
  Succeeded,
  Failed,
  TimedOut,
  /// 上一次还没跑完。
  Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskRunView {
  pub id: i64,
  pub task: String,
  pub status: TaskStatus,
  /// 定时触发还是手动（`manual`）。
  pub trigger: String,
  pub started_at: DateTime<Utc>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub ended_at: Option<DateTime<Utc>>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub exit_code: Option<i32>,
  /// 输出的最后 16 KB，密钥值已换成 `***`；出错时是错误信息。
  pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskView {
  pub name: String,
  pub spec: TaskSpec,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub last: Option<TaskRunView>,
  /// 下次运行时间；停用时没有。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub next_at: Option<DateTime<Utc>>,
  /// 外部报到任务的报到地址：成功请求它，失败请求它加 `/fail`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub ping_url: Option<String>,
  pub updated_at: DateTime<Utc>,
}

/// `GET /api/alerts`：告警规则、事件通知的开关，正在触发的告警和最近的推送。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AlertsView {
  pub rules: Vec<AlertRuleView>,
  pub notices: Vec<NoticeView>,
  pub firing: Vec<FiringView>,
  /// 最近的推送（新的在前，保留 7 天）。
  pub history: Vec<AlertHistoryView>,
  /// 触发的告警里附带服务最近的日志。
  #[serde(default)]
  pub include_logs: bool,
}

/// 一条告警规则：对一个指标的每个对象，最近 `for_n` 个点都满足 `比较 阈值` 时触发。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AlertRuleView {
  pub id: String,
  pub name: String,
  /// 指标名，例如 `server.online`。
  pub metric: String,
  /// 人能读的条件，例如"在线 < 1 连续 3 次（每分钟一次）"。
  pub condition: String,
  /// `<`、`>`、`>=`。
  pub op: String,
  pub threshold: f64,
  pub for_n: u32,
  /// 阈值是不是有意义可改（`online < 1` 这种就不让改）。
  pub threshold_editable: bool,
  pub enabled: bool,
  /// 静默到这个时间（毫秒），期间照常判断但不推送。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub muted_until: Option<i64>,
  /// 和内置默认值不同。
  pub customized: bool,
}

/// 一类事件通知：发生就推，没有阈值。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NoticeView {
  pub id: String,
  pub name: String,
  pub enabled: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub muted_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FiringView {
  pub rule: String,
  pub subject: String,
  pub title: String,
  /// 开始触发的时间（毫秒）。
  pub since: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AlertHistoryView {
  pub at: i64,
  /// 规则或事件通知的 id。
  pub source: String,
  pub title: String,
  /// true 是恢复。
  pub ok: bool,
  /// 没发出去的原因：关了、静默中、没有渠道、发送失败。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub skipped: Option<String>,
}

/// `PUT /api/alerts/{id}`：只改给了的字段。`reset` 恢复默认值。
#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct AlertPatch {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub enabled: Option<bool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub threshold: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub for_n: Option<u32>,
  /// 静默多少分钟，0 取消静默。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mute_minutes: Option<u32>,
  #[serde(default)]
  pub reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AlertOptions {
  pub include_logs: bool,
}

/// 一条操作记录或登录记录。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditEntry {
  pub id: i64,
  pub at: i64,
  pub kind: String,
  pub actor: String,
  pub method: String,
  pub path: String,
  pub status: Option<u16>,
  pub duration_ms: Option<i64>,
  pub detail: Option<String>,
  pub source: Option<String>,
}

/// 服务时间线上的一条。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TimelineItem {
  pub at: i64,
  /// deploy / backup / task / heal / alert / op
  pub kind: String,
  pub title: String,
  /// 成功还是失败；没有这个概念的（自动重启）为空。
  pub ok: Option<bool>,
  /// 只有 op 有：谁做的。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Timeline {
  pub items: Vec<TimelineItem>,
  /// 还有更早的记录时，下一页用它作 `before`。
  pub next_before: Option<i64>,
}
