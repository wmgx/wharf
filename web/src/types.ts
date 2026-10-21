// 和 crates/api-types 对应的类型，只写页面用到的字段。

export type PrivateNetwork = "tailscale" | "overlay" | "lan";

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
  lan_ips?: string[];
}

export interface ServerView {
  name: string;
  joined: boolean;
  online: boolean;
  last_seen?: string;
  report?: AgentReport;
  public_ip?: string;
  private_addr?: PrivateAddr;
  rtt_ms?: number;
}

export interface BuildSource {
  /** 本机目录上传的代码包 sha256。 */
  upload?: string;
  git?: { repo: string; ref: string; token_secret?: string };
  path?: string;
  dockerfile?: string;
  base?: string;
  start?: string;
}

export type Source =
  | { image: string }
  | { compose: { content?: string; file?: string } }
  | { build: BuildSource };

export interface PortSpec {
  name: string;
  port: number;
  host_port?: number;
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
  live?: LiveState;
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
  service: string;
  port?: string;
  gateway?: string;
  auth?: boolean;
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
}

export interface EdgeProjectView {
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
  | { op: "upsert_service"; name: string; spec: ServiceSpec }
  | { op: "remove_service"; name: string }
  | { op: "upsert_gateway"; name: string; spec: GatewaySpec }
  | { op: "remove_gateway"; name: string }
  | { op: "upsert_route"; spec: RouteSpec }
  | { op: "remove_route"; hostname: string }
  | { op: "upsert_edge_app"; name: string; spec: EdgeAppSpec }
  | { op: "remove_edge_app"; name: string };

export type Risk = "safe" | "disruptive" | "destructive" | "exposes_public";

export interface PlanItem {
  id: number;
  address: string;
  layer: string;
  action: "create" | "update" | "delete" | "adopt";
  before?: unknown;
  after?: unknown;
  risk: Risk;
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
