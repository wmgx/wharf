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
  docker_disk?: { total: number; free: number };
}

export interface ServerView {
  name: string;
  settings: Record<string, unknown> & {
    host_terminal: boolean;
    host_exec: boolean;
    egress?: EgressSpec;
    via?: string;
    renew_at?: string;
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
  baseline_drift?: string[];
  disk_days_left?: number;
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
  /** 自定义监控。 */
  monitor?: MonitorSpec;
  /** 资源上限：内存 MB、CPU 千分之一核。 */
  limits?: { memory_mb?: number; cpu_milli?: number };
}

export interface MonitorSpec {
  path: string;
  port?: string;
  expect?: number;
  keyword?: string;
}

export interface MonitorView {
  ok: boolean;
  detail: string;
  at: number;
  fails: number;
}

export interface FoundContainer {
  name: string;
  image: string;
  state: string;
  status: string;
  ports?: string[];
  project?: string;
  /** 挂载的具名数据卷。 */
  volumes?: string[];
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
  monitor?: MonitorView;
  uses?: string[];
  used_by?: string[];
  name: string;
  spec: ServiceSpec;
  host_ports: Record<string, number>;
  addresses: Record<string, string>;
  /** 局域网地址：端口名 → 各局域网地址:宿主机端口。 */
  lan_addresses?: Record<string, string[]>;
  /** 备注，不影响部署。 */
  note?: string;
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
  error_page?: string;
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
  /** 和 upstream、redirect 三选一，指向地址或跳转时为空。 */
  service?: string;
  /** 不归 Wharf 管的上游，例如 127.0.0.1:7700。 */
  upstream?: string;
  /** 只做跳转：整个域名 301 到这个网址。和 service、upstream 三选一。 */
  redirect?: string;
  port?: string;
  gateway?: string;
  /** 另一台机器上的网关：主网关那台离线 5 分钟后 DNS 自动切过去。 */
  backup_gateway?: string;
  auth?: boolean;
  /** 网关到服务的走法：不填为自动，tunnel 总是走反向隧道。 */
  link?: "auto" | "tunnel";
  /** 按路径转发，service 和 upstream 二选一。 */
  paths?: {
    path: string;
    service?: string;
    port?: string;
    upstream?: string;
  }[];
}

export interface RouteView {
  id: string;
  spec: RouteSpec;
  gateway?: string;
  upstream?: string;
  url: string;
  probe?: ProbeView;
  on_backup?: boolean;
}

/** 域名探测（控制面每 5 分钟一次）。 */
export interface ProbeView {
  ok: boolean;
  detail: string;
  ms: number;
  at: number;
  fails: number;
  cert_days?: number;
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

export type IssueLevel = "fault" | "warn" | "info";
export interface IssueSubject { kind: string; name: string }
export interface Issue {
  code: string;
  level: IssueLevel;
  subject?: IssueSubject;
  title: string;
  hint?: string;
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
  issues: Issue[];
  /** 最近一次域名检查，控制面刚启动时没有。 */
  health?: DoctorReport;
  /** 后台检查的新版本（6 小时）和未执行的改动（10 分钟）。 */
  updates?: UpdatesView;
}

export interface VersionCheck {
  at: string;
  newer: boolean;
  latest?: string;
  error?: string;
}

export interface UpdatesView {
  services: Record<string, VersionCheck>;
  pending?: { at: string; items: string[]; error?: string };
}

export type CheckStatus = "ok" | "warn" | "bad" | "skip";

export interface DoctorCheck {
  layer: string;
  subject: string;
  status: CheckStatus;
  detail: string;
  at: string;
}

export interface RouteDiagnosis {
  hostname: string;
  url: string;
  checks: DoctorCheck[];
  /** HTTPS 证书到期时间，连不上或不是 HTTPS 时没有。 */
  cert_expires?: string;
  domain_expires?: string;
}

export interface DoctorReport {
  checked_at: string;
  servers: DoctorCheck[];
  routes: RouteDiagnosis[];
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
  | { op: "remove_service"; name: string; purge_data?: boolean }
  | { op: "refresh_images"; name: string }
  | { op: "upsert_gateway"; name: string; spec: GatewaySpec }
  | { op: "remove_gateway"; name: string }
  | { op: "upsert_route"; spec: RouteSpec }
  | { op: "remove_route"; hostname: string }
  | { op: "upsert_edge_app"; name: string; spec: EdgeAppSpec }
  | { op: "remove_edge_app"; name: string };

export type Impact =
  "restart" | "downtime" | "remove" | "data_loss" | "overwrite" | "public";

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
  plan_id?: string;
  status: "running" | "succeeded" | "failed" | "cancelled";
  started_at?: string;
  finished_at?: string;
  steps: RunStep[];
}

/** 宿主机终端和命令执行的审计记录。 */
export interface ShellLog {
  id: number;
  at: string;
  actor: string;
  server: string;
  kind: string;
  command?: string;
  exit_code?: number;
  duration_ms?: number;
  output_bytes?: number;
  error?: string;
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
  commit?: string;
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
  servers: {
    name: string;
    mode: NetworkMode;
    configured?: boolean;
    private_ip?: string;
    public_ip?: string;
    online: boolean;
  }[];
  reach: {
    from: string;
    to: string;
    ok: boolean;
    checked_at: string;
    stale?: boolean;
  }[];
  links?: { from: string; to: string; ms?: number; loss: number; at: string }[];
  relays?: { from: string; to: string; via: string; direct_loss: number; via_loss: number }[];
}

export interface SecretView {
  name: string;
  updated_at: string;
  used_by?: string[];
  managed?: boolean;
  /** 系统功能用的，在对应功能里改。 */
  system?: string;
}

export type Perm = "read" | "plan" | "apply" | "confirm" | "exec" | "admin";

export interface TokenView {
  name: string;
  perms: Perm[];
  created_at: string;
  last_used_at?: string;
}

export interface CreatedToken {
  name: string;
  perms: Perm[];
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
  ssh_logins?: SshLogin[];
}

export interface SshLogin {
  at: string;
  user: string;
  from: string;
  method: string;
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
  last_op?: {
    action: string;
    run_id: string;
    status: "running" | "succeeded" | "failed";
    at: string;
    error?: string;
  };
  tone: "ok" | "warn" | "bad" | "idle";
  summary: string;
  error?: string;
  observed_at?: string;
}

export type TaskKind =
  | { kind: "exec"; service: string; container?: string; command: string }
  | {
      kind: "container";
      image: string;
      command?: string;
      env?: Record<string, string>;
      mounts?: string[];
    }
  | { kind: "host"; command: string }
  | { kind: "ping"; token?: string; grace_mins: number };

export type TaskSpec = TaskKind & {
  server: string;
  schedule: string;
  timeout_secs: number;
  enabled: boolean;
  notify: boolean;
};

export type TaskStatus =
  "running" | "succeeded" | "failed" | "timed_out" | "skipped";

export interface TaskRunView {
  id: number;
  task: string;
  status: TaskStatus;
  trigger: string;
  started_at: string;
  ended_at?: string;
  exit_code?: number;
  output: string;
}

export interface TaskView {
  name: string;
  spec: TaskSpec;
  last?: TaskRunView;
  next_at?: string;
  /** 外部报到任务的报到地址。 */
  ping_url?: string;
  updated_at: string;
}

/** 出口规则：全部走，或预置分组加自定义域名。 */
export type EgressSpec = {
  all?: boolean;
  presets?: string[];
  domains?: string[];
};
export type EgressPreset = { name: string; label: string; domains: string[] };

export interface AlertRuleView {
  id: string;
  name: string;
  metric: string;
  condition: string;
  op: string;
  threshold: number;
  for_n: number;
  threshold_editable: boolean;
  enabled: boolean;
  muted_until?: number;
  customized: boolean;
}

export interface NoticeView {
  id: string;
  name: string;
  enabled: boolean;
  muted_until?: number;
}

export interface AlertsView {
  include_logs?: boolean;
  rules: AlertRuleView[];
  notices: NoticeView[];
  firing: { rule: string; subject: string; title: string; since: number }[];
  history: { at: number; source: string; title: string; ok: boolean; skipped?: string }[];
}

export interface AlertPatch {
  enabled?: boolean;
  threshold?: number;
  for_n?: number;
  mute_minutes?: number;
  reset?: boolean;
}

export interface AuditEntry {
  id: number;
  at: number;
  kind: string;
  actor: string;
  method: string;
  path: string;
  status?: number;
  duration_ms?: number;
  detail?: string;
  source?: string;
}

export interface TimelineItem {
  at: number;
  kind: string;
  title: string;
  ok: boolean | null;
  actor?: string;
}

export interface Timeline {
  items: TimelineItem[];
  next_before: number | null;
}
