// 和 crates/api-types 对应的类型，只写页面用到的字段。

export type PrivateNetwork = "tailscale" | "overlay" | "lan";

export interface CoreAddress {
  url: string;
  kind: "route" | "configured" | "public" | "tailscale" | "lan" | string;
  plaintext?: boolean;
}

export interface CoreAddresses {
  /** 控制面所在的服务器。 */
  server?: string;
  port: number;
  addresses: CoreAddress[];
  /** 控制面默认的 agent 镜像。 */
  agent_image: string;
}

export interface JoinInfo {
  server: string;
  join_token: string;
  expires_at: string;
  commands: Record<string, string>;
  core_url: string;
}

export interface PrivateAddr {
  ip: string;
  network: PrivateNetwork;
}

export interface AgentReport {
  version: string;
  hostname: string;
  os: string;
  arch: string;
  docker_version?: string;
  compose_version?: string;
  build?: string;
  lan_ips?: string[];
  disk?: { total: number; free: number };
}

export interface ServerView {
  name: string;
  settings: Record<string, unknown> & {
    host_terminal: boolean;
    host_exec: boolean;
  };
  joined: boolean;
  online: boolean;
  host_shell: boolean;
  last_seen?: string;
  report?: AgentReport;
  public_ip?: string;
  private_addr?: PrivateAddr;
  rtt_ms?: number;
  agent_outdated?: boolean;
}

export interface BuildSource {
  /** 本机目录上传的代码包 sha256。 */
  upload?: string;
  git?: { repo: string; ref: string; token_secret?: string };
  path?: string;
  dockerfile?: string;
  base?: string;
  start?: string;
  template?: string;
  install?: string;
  dockerfile_content?: string;
}

export type Source =
  | { image: string }
  | { compose: { content?: string; file?: string } }
  | { build: BuildSource };

export interface PortSpec {
  name: string;
  /** 容器内端口。image / build 来源必填，compose 来源不填。 */
  container?: number;
  /** 宿主机端口。compose 来源必填；其余来源不填时自动分配。 */
  host?: number;
}

export interface VolumeSpec {
  name: string;
  target: string;
}

export interface ServiceSpec {
  server: string;
  source: Source;
  ports?: PortSpec[];
  env?: Record<string, string>;
  volumes?: VolumeSpec[];
  /** 每天自动备份到另一台服务器。 */
  backup?: { to: string };
  /** 停止：容器保留但不运行。 */
  stopped?: boolean;
}

export interface FoundContainer {
  name: string;
  image: string;
  state: string;
  status: string;
  ports?: string[];
  project?: string;
}

/** 服务器上没纳管的一个 compose 项目或单个容器。 */
export interface Unmanaged {
  server: string;
  project?: string;
  container?: string;
  containers: FoundContainer[];
  name: string;
}

/** 导入时接管的现有容器：提交 upsert_service 时原样带上。 */
export interface AdoptSpec {
  project?: string;
  containers?: string[];
}

export interface ImportRecord {
  server: string;
  project?: string;
  containers?: string[];
  /** 被停掉留着回退用的旧容器。 */
  retired?: string[];
  /** 第一次部署成功的时间；还没部署时为空。 */
  done_at?: string;
}

export interface ImportPreview {
  name: string;
  spec: ServiceSpec;
  adopt?: AdoptSpec;
  warnings?: string[];
}

export interface ContainerInfo {
  service: string;
  name: string;
  state: string;
  status: string;
  health?: string;
  image: string;
}

export interface LiveState {
  state: "running" | "stopped" | "partial" | "missing" | "unknown" | string;
  containers?: ContainerInfo[];
  in_sync?: boolean | null;
  error?: string;
}

export interface ServiceView {
  name: string;
  spec: ServiceSpec;
  host_ports: Record<string, number>;
  addresses: Record<string, string>;
  version: number;
  containers?: ContainerInfo[];
  data?: DataMount[];
  status?: ServiceStatus;
  import?: ImportRecord;
}

export type GatewayTls = "auto" | "internal" | "off";

export interface GatewaySpec {
  kind: "caddy" | "cloudflare_tunnel";
  server: string;
  default?: boolean;
  http_port?: number;
  https_port?: number;
  email?: string;
  image?: string;
  tls?: GatewayTls;
  /** cloudflare_tunnel：在哪个厂商账号下建隧道。 */
  account?: string;
}

export interface GatewayView {
  name: string;
  spec: GatewaySpec;
  routes: string[];
  version: number;
  live?: LiveState;
}

export interface RouteSpec {
  hostname: string;
  /** 和 upstream 二选一，指向地址时为空。 */
  service?: string;
  /** 不归 Wharf 管的上游，例如 127.0.0.1:7700。 */
  upstream?: string;
  port?: string;
  gateway?: string;
  auth?: boolean;
  /** 网关到服务的走法：不填为自动，tunnel 总是走反向隧道。 */
  link?: "auto" | "tunnel";
  /** 按路径转发，service 和 upstream 二选一。 */
  paths?: { path: string; service?: string; port?: string; upstream?: string }[];
}

export interface RouteView {
  id: string;
  spec: RouteSpec;
  gateway?: string;
  upstream?: string;
  url: string;
}

export type EdgeKind = "worker" | "pages";

export interface EdgeSource {
  upload?: string;
  git?: { repo: string; ref: string; token_secret?: string };
  path?: string;
  /** 单文件 Worker 的脚本文件名。 */
  script?: string;
  /** Pages 的构建命令。 */
  build?: string;
  output?: string;
}

export interface EdgeAppSpec {
  account: string;
  kind: EdgeKind;
  /** 厂商那边的项目名，和名字相同时不写。 */
  project?: string;
  source?: EdgeSource;
  builder?: string;
  /** 绑定的自定义域名，不经过网关。 */
  domains?: string[];
}

export interface EdgeLive {
  exists: boolean;
  url?: string;
  deployed_at?: string;
  deployed_by?: string;
  error?: string;
  checked_at: string;
}

export interface EdgeAppView {
  name: string;
  spec: EdgeAppSpec;
  version: number;
  live?: EdgeLive;
  /** 和 Wharf 记录的不一致时的说明。 */
  drift?: string;
}

export interface EdgeProjectView {
  account: string;
  kind: EdgeKind;
  project: string;
  url?: string;
  modified_at?: string;
  managed_as?: string;
}

export interface EdgeVersionView {
  id: string;
  created_at: string;
  source?: string;
  message?: string;
  active: boolean;
  url?: string;
}

export interface Status {
  servers: ServerView[];
  services: ServiceView[];
  edge_apps?: EdgeAppView[];
  /** 厂商账号里还没纳管的 Workers / Pages。 */
  edge_unmanaged?: EdgeProjectView[];
  gateways: GatewayView[];
  routes: RouteView[];
  problems?: string[];
}

export interface AccountView {
  name: string;
  kind: string;
  /** 打码后的 token，例如 `abcd…wxyz`。 */
  token: string;
  zones: string[];
  warnings?: string[];
  updated_at: string;
}

export type Change =
  | { op: "update_server"; name: string; settings: Record<string, unknown> }
  | { op: "upsert_service"; name: string; spec: ServiceSpec; adopt?: AdoptSpec }
  | { op: "remove_service"; name: string }
  | { op: "refresh_images"; name: string }
  | { op: "upsert_gateway"; name: string; spec: GatewaySpec }
  | { op: "remove_gateway"; name: string }
  | { op: "upsert_route"; spec: RouteSpec }
  | { op: "remove_route"; hostname: string }
  | { op: "upsert_edge_app"; name: string; spec: EdgeAppSpec }
  | { op: "remove_edge_app"; name: string };

export type Impact = "restart" | "downtime" | "remove" | "data_loss" | "overwrite" | "public";

export interface PlanItem {
  id: number;
  address: string;
  layer: string;
  action: "create" | "update" | "delete" | "adopt";
  before?: unknown;
  after?: unknown;
  impacts?: Impact[];
  reason: string;
}

export interface Plan {
  plan_id: string;
  expires_at: string;
  items: PlanItem[];
  warnings?: string[];
  needs_confirm?: string[];
  suggest?: string[];
}

export type StepStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface ApiErrorBody {
  code: string;
  message: string;
  hint?: string;
  suggest?: string[];
}

export interface RunStep {
  title: string;
  status: StepStatus;
  /** 没有日志时后端省略这个字段。 */
  log?: string[];
  error?: ApiErrorBody;
}

export interface Run {
  run_id: string;
  status: "running" | "succeeded" | "failed" | "cancelled";
  steps: RunStep[];
}

export interface ImageInfo {
  image: string;
  id: string;
  digest?: string;
}

export interface DeploymentView {
  id: number;
  server: string;
  run_id: string;
  compose: string;
  images: ImageInfo[];
  spec?: ServiceSpec;
  hash: string;
  created_at: string;
}

export interface RollbackTarget {
  deployment_id: number;
  deployed_at: string;
  spec: ServiceSpec;
}

export interface BackupSummary {
  snapshot_id: string;
  files: number;
  bytes: number;
  added_bytes: number;
}

export interface BackupRecord {
  id: number;
  server: string;
  target: string;
  run_id: string;
  ok: boolean;
  summary?: BackupSummary;
  error?: string;
  created_at: string;
}

export interface Snapshot {
  id: string;
  short_id: string;
  time: string;
  hostname: string;
  paths?: string[];
}

export interface BackupsView {
  service: string;
  target?: string;
  records: BackupRecord[];
  snapshots: Snapshot[];
  snapshots_error?: string;
}

export type NetworkMode = "tailscale" | "lan" | "public";

export interface NetworkView {
  servers: { name: string; mode: NetworkMode; configured?: boolean; private_ip?: string; public_ip?: string; online: boolean }[];
  reach: { from: string; to: string; ok: boolean; checked_at: string; stale?: boolean }[];
}

export interface SecretView {
  name: string;
  updated_at: string;
  used_by?: string[];
  managed?: boolean;
}

export type TokenScope = "read" | "plan" | "apply_safe" | "apply_all";

export interface TokenView {
  name: string;
  scope: TokenScope;
  created_at: string;
  last_used_at?: string;
}

export interface CreatedToken {
  name: string;
  scope: TokenScope;
  token: string;
}

export interface CoreBackupView {
  to?: string;
  user_key_current: boolean;
  records: BackupRecord[];
  restore_command?: string;
}

export interface PackageUpdate {
  name: string;
  from: string;
  to: string;
  security: boolean;
}

export interface DockerUsage {
  kind: string;
  total: string;
  active: string;
  size: string;
  reclaimable: string;
}

/** 服务器详情页的宿主机信息，现查。 */
export interface HostInfo {
  os?: string;
  kernel: string;
  uptime_secs: number;
  mem_total: number;
  mem_available: number;
  load: [number, number, number];
  cpus: number;
  /** 不是 apt 系统时没有。 */
  updates?: PackageUpdate[];
  reboot_required: boolean;
  docker: DockerUsage[];
  container_logs?: number;
  journal?: number;
  var_log?: number;
}

export interface FileEntry {
  name: string;
  dir: boolean;
  link?: boolean;
  size: number;
  /** 毫秒。 */
  modified: number;
}

/** 数据归属：只有 managed 会被迁移、备份。 */
export type DataKind = "managed" | "external_dir" | "named_volume";

export interface DataMount {
  kind: DataKind;
  /** 宿主机路径或卷名；匿名卷为空。 */
  source: string;
  target: string;
  container?: string;
}

/** 一个服务的备份状态。stale：开了备份但 48 小时没成功过。 */
export type DataStatus = "ok" | "stale" | "off" | "uncovered" | "none";

export interface ServiceData {
  name: string;
  /** 数据所在的服务器。 */
  server: string;
  /** 没开备份时为空。 */
  target?: string;
  last_ok?: string;
  /** 只在这个时间比最近成功晚时才有。 */
  last_failed?: string;
  mounts: DataMount[];
  status: DataStatus;
}

export interface DataView {
  services: ServiceData[];
}

/** 分层状态：期望、已应用、实际、健康、执行，summary 是按优先级挑出的一句话。 */
export interface ServiceStatus {
  want_running: boolean;
  desired_hash?: string;
  applied?: { hash: string; at: string };
  actual: "running" | "partial" | "stopped" | "missing" | "offline" | "unknown";
  actual_hash?: string;
  health: "healthy" | "unhealthy" | "starting" | "none";
  last_op?: { action: string; run_id: string; status: "running" | "succeeded" | "failed"; at: string; error?: string };
  tone: "ok" | "warn" | "bad" | "idle";
  summary: string;
  error?: string;
}
