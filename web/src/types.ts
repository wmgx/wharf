// 和 crates/api-types 对应的类型，只写页面用到的字段。

import type * as Gen from "./types.gen";
export type { AclView, ExternalStatus, Limits, UsageRow } from "./types.gen";

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

export interface AgentReport extends Pick<Gen.AgentReport, "public_ip" | "egress_info" | "docker_quota"> {
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

export interface ServerView extends Pick<Gen.ServerView, "key_fingerprint" | "key_rotation"> {
  note?: string;
  name: string;
  settings: Record<string, unknown> & {
    host_terminal: boolean;
    host_exec: boolean;
    host_docker?: boolean;
    host_system?: boolean;
    egress?: EgressSpec;
    via?: string;
    renew_at?: string;
    agent_memory?: string | null;
    registry_mirrors?: Gen.ServerSettings["registry_mirrors"];
  };
  agent?: Gen.AgentUsage;
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
  clock_offset_ms?: number;
}

export type BuildSource = Gen.BuildSource;

export type Source = Gen.Source;

export type PortSpec = Gen.PortSpec;

export type VolumeSpec = Gen.VolumeSpec;

export type ServiceDraft = Gen.ServiceDraft;

export type ServiceSpec = Gen.ServiceSpec;

export type MonitorSpec = Gen.MonitorSpec;

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
  ignored?: boolean;
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
  risks?: string[];
  monitor?: MonitorView;
  log_alerts?: Gen.LogAlertView[];
  port_checks?: Record<string, boolean>;
  heartbeat?: Gen.HeartbeatView;
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
  wildcard?: string[];
  layer4?: Gen.Layer4Forward[];
  trusted_proxies?: Gen.TrustedProxiesSpec;
  read_header_timeout?: number;
  idle_timeout?: number;
  grace_period?: number;
}

export interface GatewayView {
  name: string;
  spec: GatewaySpec;
  routes: string[];
  version: number;
  live?: LiveState;
}

export interface RouteSpec {
  sso?: Gen.SsoSpec;
  rate_limit?: number;
  block_scanners?: boolean;
  core_mesh_only?: boolean;
  cf_origin_only?: boolean;
  internal?: boolean;
  expires_at?: number;
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
  /** 自定义 Caddy 配置，原样插进网关里这个域名的站点块。 */
  caddy?: string;
}

export interface RouteView {
  core?: boolean;
  note?: string;
  sso_login?: Gen.SsoLoginState;
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
  last_deployed_at?: string;
  id: string;
  created_at: string;
  source?: string;
  message?: string;
  active: boolean;
  url?: string;
}

export type IssueLevel = Gen.IssueLevel;
export type IssueSubject = Gen.IssueSubject;
export type Issue = Gen.Issue;

export interface Status {
  safe_mode?: boolean;
  bookmarks: BookmarkView[];
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

export type VersionCheck = Gen.VersionCheck;

export type UpdatesView = Gen.UpdatesView;

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

export interface BookmarkSpec {
  title: string;
  url: string;
  group?: string;
  order: number;
}

export interface BookmarkView {
  id: string;
  spec: BookmarkSpec;
  version: number;
}

export type Change =
  | { op: "upsert_bookmark"; id?: string; spec: BookmarkSpec }
  | { op: "remove_bookmark"; id: string }
  | { op: "update_server"; name: string; settings: Record<string, unknown> }
  | { op: "upsert_service"; name: string; spec: ServiceSpec; adopt?: AdoptSpec; pins?: Record<string, string>; commit?: string }
  | { op: "remove_service"; name: string; purge_data?: boolean }
  | { op: "refresh_images"; name: string; image?: string }
  | { op: "retag_image"; name: string; image: string; tag: string }
  | { op: "upsert_gateway"; name: string; spec: GatewaySpec }
  | { op: "remove_gateway"; name: string }
  | { op: "upsert_route"; spec: RouteSpec }
  | { op: "remove_route"; hostname: string }
  | { op: "upsert_edge_app"; name: string; spec: EdgeAppSpec }
  | { op: "import_edge_app"; name: string; spec: EdgeAppSpec }
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
  changes?: Gen.FieldChange[];
  host_access?: string[];
}

export interface Plan {
  plan_id: string;
  expires_at: string;
  items: PlanItem[];
  warnings?: string[];
  needs_host?: string[];
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
  started?: boolean;
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
  pins?: Record<string, string>;
  commit?: string;
  warnings?: string[];
  deployment_id: number;
  deployed_at: string;
  spec: ServiceSpec;
}

export interface BackupSummary {
  snapshot_id: string;
  files: number;
  bytes: number;
  added_bytes: number;
  escaped_mounts?: Gen.EscapedMount[];
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
  tags?: string[];
  keep?: boolean;
  note?: string | null;
  id: string;
  short_id: string;
  time: string;
  hostname: string;
  paths?: string[];
}

export interface BackupsView {
  exclude?: string[];
  retention?: Gen.BackupRetention | null;
  service: string;
  target?: string;
  snapshot_target?: string;
  records: BackupRecord[];
  snapshots: Snapshot[];
  snapshots_error?: string;
}

export type NetworkMode = "tailscale" | "lan" | "public";

export interface NetworkView extends Pick<Gen.NetworkView, "tailnet_reach" | "tailnet_relays"> {
  servers: {
    name: string;
    mode: NetworkMode;
    configured?: boolean;
    private_ip?: string;
    tailnet_ip?: Gen.NetworkServer["tailnet_ip"];
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

export type SecretView = Gen.SecretView;

export type Perm = Gen.Perm;
export type TokenView = Gen.TokenView;
export type CreatedToken = Gen.CreatedToken;
export type TokenSettings = Gen.TokenSettings;

export interface CoreBackupView {
  retention?: Gen.BackupRetention | null;
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
export type DataKind = Gen.DataKind;

export interface DataMount {
  kind: DataKind;
  from_service?: string | null;
  read_only?: boolean;
  resolved?: string;
  /** 宿主机路径或卷名；匿名卷为空。 */
  source: string;
  target: string;
  container?: string;
}

/** 一个服务的备份状态。stale：开了备份但 48 小时没成功过。 */
export type DataStatus = "ok" | "stale" | "off" | "uncovered" | "none";

export interface ServiceData {
  repo_empty?: boolean;
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
  recovery?: Gen.ServiceStatus["recovery"];
  want_running: boolean;
  desired_hash?: string;
  applied?: { hash: string; at: string };
  actual: Gen.Actual;
  missing_components?: Gen.ServiceStatus["missing_components"];
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

export type ScriptRuntime = "python" | "node" | "shell";

export type TaskKind =
  | { kind: "exec"; service: string; container?: string; command: string }
  | {
      kind: "container";
      image: string;
      command?: string;
      env?: Record<string, string>;
      mounts?: string[];
    }
  | { kind: "script"; runtime: ScriptRuntime; code: string; deps?: string; image?: string; env?: Record<string, string>; hook?: string }
  | { kind: "host"; command: string }
  | { kind: "ping"; token?: string; grace_mins: number };

export type TaskSpec = TaskKind & {
  server: string;
  schedule: string;
  timeout_secs: number;
  enabled: boolean;
  notify: boolean;
  skip_if_stopped?: boolean;
  catch_up_mins?: number;
  limits?: Gen.TaskSpec["limits"];
  inherit_server_limits?: Gen.TaskSpec["inherit_server_limits"];
};

export type TaskStatus =
  "running" | "succeeded" | "failed" | "timed_out" | "skipped" | "cancelled";

export interface TaskRunView {
  service?: string;
  mem_peak?: number;
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
  target_server?: string;
  migrating?: boolean;
  data_bytes?: number;
  name: string;
  spec: TaskSpec;
  last?: TaskRunView;
  next_at?: string;
  /** 外部报到任务的报到地址。 */
  ping_url?: string;
  hook_url?: string;
  updated_at: string;
}

/** 出口规则：全部走，或预置分组加自定义域名。 */
export type EgressSpec = {
  all?: boolean;
  presets?: string[];
  domains?: string[];
};
export type EgressPreset = { name: string; label: string; domains: string[] };

export type AlertLevel = Gen.AlertLevel;
export type AlertAckView = Gen.AlertAckView;
export type AlertTarget = Gen.AlertTarget;
export type BuiltinSuppressionView = Gen.BuiltinSuppressionView;
export type AlertSuppressionView = Gen.AlertSuppressionView;
export type ServiceAlertOverrideView = Gen.ServiceAlertOverrideView;
export type CustomAlertRuleView = Gen.CustomAlertRuleView;

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
  level: AlertLevel;
  muted_until?: number | null;
  customized: boolean;
}

export interface NoticeView {
  id: string;
  name: string;
  enabled: boolean;
  level: AlertLevel;
  muted_until?: number | null;
  customized?: boolean;
}

export interface AlertsView {
  include_logs?: boolean;
  rules: AlertRuleView[];
  notices: NoticeView[];
  firing: { rule: string; subject: string; title: string; since: number; ack?: AlertAckView | null }[];
  history: { at: number; source: string; title: string; ok: boolean; skipped?: string | null }[];
  builtin_suppressions?: BuiltinSuppressionView[];
  suppressions?: AlertSuppressionView[];
  service_overrides?: ServiceAlertOverrideView[];
  custom_rules?: CustomAlertRuleView[];
}

export interface AlertPatch {
  enabled?: boolean;
  threshold?: number;
  for_n?: number;
  level?: AlertLevel;
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

export type TimelineItem = Gen.TimelineItem;

export type Timeline = Gen.Timeline;
export type GateKeyView = Gen.GateKeyView;
export type GateKeyRequest = Gen.GateKeyRequest;
