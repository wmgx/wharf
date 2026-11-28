// 自动生成，不要手改。
// 重新生成：cargo run -q -p wharf-cli -- schema web | node web/scripts/gen-types.mjs > web/src/types.gen.ts

export interface AccessLogEntry {
  client_ip: string;
  duration_ms: number;
  host: string;
  method: string;
  path: string;
  query: string;
  size: number;
  status: number;
  ts: string;
}

export interface AccessLogsResult {
  entries: AccessLogEntry[];
  matched: number;
  missing: boolean;
  scanned_files: number;
  scanned_lines: number;
  skipped: number;
  truncated: boolean;
  warnings?: string[];
}

export interface AccountView {
  kind: string;
  name: string;
  /**
   * 脱敏后的 token，例如 `abcd…wxyz`。
   */
  token: string;
  updated_at: string;
  warnings?: string[];
  /**
   * 自动发现的 zone。
   */
  zones: string[];
}

export interface AclView {
  acls: number;
  grants: number;
  groups: Record<string, string[]>;
  hint?: string | null;
  modified_at?: string | null;
  raw?: string | null;
  status: string;
  tagOwners: Record<string, string[]>;
}

export type Action = "create" | "update" | "delete" | "adopt";

export type Actual = "running" | "restarting" | "stopped" | "partial" | "missing" | "offline" | "unknown";

export interface AdoptMountSpec {
  rename_only?: boolean;
  source: string | null;
  target: string | null;
  volume_name: string | null;
}

/**
 * 导入前容器是怎么跑的。和服务同名的 compose 项目不需要接管，Wharf 直接沿用。
 */
export interface AdoptSpec {
  /**
   * 原来 `docker run` 起的容器：改名为 `<名字>-wharf-old` 并停掉，留着回退用。
   */
  containers?: string[];
  expected_images?: Record<string, string>;
  expected_services?: string[];
  initial_pins?: Record<string, string>;
  /**
   * 原来的 compose 项目名（和服务名不同时）：停掉它的容器。
   */
  project?: string | null;
  rename_containers?: string[];
}

export interface AgentMemory {
  error?: string | null;
  /**
   * Docker 实际上限，0 表示不限。
   */
  limit?: number | null;
}

/**
 * agent 定期上报的机器信息。
 */
export interface AgentReport {
  /**
   * 最近一次检查 agent 容器内存上限的结果。
   */
  agent_memory?: AgentMemory | null;
  arch: string;
  backup_repos?: Record<string, number> | null;
  /**
   * 构建号，见 [crate::BUILD]。旧版本 agent 没有。
   */
  build?: string;
  compose_version?: string | null;
  /**
   * agent 存放 compose 文件的目录。
   */
  data_dir: string;
  /**
   * `data_dir` 所在磁盘的容量。
   */
  disk?: Disk | null;
  /**
   * Docker 镜像和容器所在磁盘的容量，和 `disk` 不是同一块盘时才有。
   */
  docker_disk?: Disk | null;
  docker_quota?: DockerQuota | null;
  docker_subnets?: DockerSubnet[];
  docker_version?: string | null;
  egress_info?: EgressInfo | null;
  host_subnets?: string[];
  hostname: string;
  /**
   * 其余网卡的 IPv4 地址（不含回环和 docker 网桥），
   * 没有组网工具时作为内网地址的候选。
   */
  lan_ips?: string[];
  log_hits?: LogHit[];
  /**
   * 资源采样，每分钟一次。
   */
  metrics?: Metrics | null;
  os: string;
  /**
   * 检测到的组网地址（目前只检测 Tailscale / Headscale）。
   */
  private_addr?: PrivateAddr | null;
  /**
   * 探测到的公网出口 IP。
   */
  public_ip?: string | null;
  /**
   * agent 发送上报时的 Unix 毫秒时间，旧版本没有。
   */
  time_ms?: number | null;
  version: string;
}

export interface AgentUsage {
  configured_limit: number;
  cpu: number | null;
  limit_error: string | null;
  mem: number | null;
  memory_limit: number | null;
  memory_pct: number | null;
}

export interface AlertAckView {
  at: number;
  by: string;
  note?: string | null;
}

export interface AlertHistoryView {
  at: number;
  /**
   * true 是恢复。
   */
  ok: boolean;
  /**
   * 没发出去的原因：关了、静默中、没有渠道、发送失败。
   */
  skipped?: string | null;
  /**
   * 规则或事件通知的 id。
   */
  source: string;
  title: string;
}

export type AlertLevel = "urgent" | "digest";

/**
 * `PUT /api/alerts/{id}`：只改给了的字段。`reset` 恢复默认值。
 */
export interface AlertPatch {
  enabled?: boolean | null;
  for_n?: number | null;
  level?: AlertLevel | null;
  /**
   * 静默多少分钟，0 取消静默。
   */
  mute_minutes?: number | null;
  reset: boolean;
  threshold?: number | null;
}

/**
 * 单条告警规则在周期内的触发次数对比。
 */
export interface AlertReport {
  change_pct?: number | null;
  current: number;
  name: string;
  previous?: number | null;
  rule: string;
}

export interface AlertRuleDefaults {
  enabled: boolean;
  for_n: number;
  level: AlertLevel;
  threshold: number;
}

/**
 * 一条告警规则：对一个指标的每个对象，最近 `for_n` 个点都满足 `比较 阈值` 时触发。
 */
export interface AlertRuleView {
  /**
   * 人能读的条件，例如"在线 < 1 连续 3 次（每分钟一次）"。
   */
  condition: string;
  /**
   * 和内置默认值不同。
   */
  customized: boolean;
  defaults?: AlertRuleDefaults | null;
  enabled: boolean;
  for_n: number;
  id: string;
  level: AlertLevel;
  /**
   * 指标名，例如 `server.online`。
   */
  metric: string;
  /**
   * 静默到这个时间（毫秒），期间照常判断但不推送。
   */
  muted_until?: number | null;
  name: string;
  /**
   * `<`、`>`、`>=`。
   */
  op: string;
  threshold: number;
  /**
   * 阈值是不是有意义可改（`online < 1` 这种就不让改）。
   */
  threshold_editable: boolean;
}

export interface AlertSuppressionView {
  created_at: number;
  id: number;
  source_rule: string;
  source_subject?: string | null;
  target_rule: string;
  target_subject?: string | null;
}

export interface AlertTarget {
  rule: string;
  subject: string;
}

/**
 * `GET /api/alerts`：告警规则、事件通知的开关，正在触发的告警和最近的推送。
 */
export interface AlertsView {
  builtin_suppressions: BuiltinSuppressionView[];
  custom_rules: CustomAlertRuleView[];
  firing: FiringView[];
  /**
   * 最近的推送（新的在前，保留 14 天）。
   */
  history: AlertHistoryView[];
  /**
   * 触发的告警里附带服务最近的日志。
   */
  include_logs: boolean;
  notices: NoticeView[];
  rules: AlertRuleView[];
  service_overrides: ServiceAlertOverrideView[];
  suppressions: AlertSuppressionView[];
}

export type AllCookies = "all";

/**
 * 统一错误格式。`message` 可以直接给用户看，不含 token 和厂商原始响应。
 */
export interface ApiError {
  code: ErrorCode;
  details?: unknown;
  /**
   * 怎么解决。
   */
  hint?: string | null;
  message: string;
  /**
   * 可以直接执行的下一步命令。
   */
  suggest?: string[];
  upstream?: Upstream | null;
}

export interface AppAccountDomain {
  exists: boolean;
  hostname: string;
  is_default: boolean;
}

export interface AppAccountView {
  domains: AppAccountDomain[];
  name: string;
  note: string;
  updated_at: string;
  username: string;
}

export interface Applied {
  at: string;
  /**
   * git 构建来源实际构建的 commit，和当时的 `仓库#分支`。
   */
  commit?: string | null;
  /**
   * image 来源实际部署的镜像 digest（`sha256:…`）。
   */
  digest?: string | null;
  /**
   * 部署时 compose 里每个镜像的 digest 和镜像 ID：镜像（compose 里写的名字）→ `sha256:…`。
   */
  digests?: Record<string, string>;
  git?: string | null;
  hash: string;
  /**
   * 部署时的镜像（compose 里写的名字）和镜像 ID。
   */
  image?: string | null;
  image_id?: string | null;
  image_ids?: Record<string, string>;
}

export interface ApplyRequest {
  /**
   * 确认高风险项的地址。
   */
  confirm?: string[];
  plan_id: string;
  skip_snapshot?: boolean;
  verify_before_dns?: boolean | null;
}

/**
 * 一条操作记录或登录记录。
 */
export interface AuditEntry {
  actor: string;
  at: number;
  detail: string | null;
  duration_ms: number | null;
  id: number;
  kind: string;
  method: string;
  path: string;
  source: string | null;
  status: number | null;
}

export interface BackupMoveStatus {
  from: string;
  phase: string;
  source_snapshots: number;
  target_archive?: string | null;
  to: string;
}

/**
 * 一次备份的记录（成功或失败）。
 */
export interface BackupRecord {
  created_at: string;
  error?: string | null;
  id: number;
  ok: boolean;
  run_id: string;
  /**
   * 数据所在的服务器。
   */
  server: string;
  summary?: BackupSummary | null;
  /**
   * 备份存到的服务器。
   */
  target: string;
}

export interface BackupRetention {
  daily: number;
  monthly: number;
  weekly: number;
}

export interface BackupSpec {
  exclude?: string[];
  retention?: BackupRetention | null;
  /**
   * 备份存到哪台服务器，不能是服务所在的服务器。
   */
  to: string;
}

export interface BackupSummary {
  /**
   * 这次新增到仓库的字节数（去重后）。
   */
  added_bytes: number;
  bytes: number;
  escaped_mounts?: EscapedMount[];
  files: number;
  snapshot_id: string;
}

/**
 * `GET /api/services/{name}/backups`
 */
export interface BackupsView {
  exclude?: string[];
  pending_move?: BackupMoveStatus | null;
  /**
   * 最近的备份记录，新的在前。
   */
  records: BackupRecord[];
  retention?: BackupRetention | null;
  service: string;
  /**
   * 列出快照时使用的备份服务器，关闭自动备份后可来自历史记录。
   */
  snapshot_target?: string | null;
  /**
   * 备份服务器上的快照，新的在前。
   */
  snapshots: Snapshot[];
  /**
   * 读取快照失败的原因（例如备份服务器离线）。
   */
  snapshots_error?: string | null;
  /**
   * 没开启备份时为空。
   */
  target?: string | null;
}

/**
 * 机器基线（P9）。字段不填就不管；去掉某项只是不再管，不会改回去。
 * 不含 ssh 和防火墙：配错会把自己锁在机器外面。
 */
export interface Baseline {
  /**
   * 容器日志轮转：保留几个文件，默认 3。
   */
  docker_log_files?: number | null;
  /**
   * 容器日志轮转：单个文件上限，例如 `20m`。写进 daemon.json，只对新建的容器生效。
   */
  docker_log_size?: string | null;
  /**
   * journald 日志总上限，例如 `500M`。
   */
  journal_max?: string | null;
  /**
   * 自动安装安全更新（unattended-upgrades，只支持 apt 系统）。
   */
  security_updates?: boolean | null;
  /**
   * 没有 swap 时建一个这么大的 /swapfile（GB）；已有 swap 不改。
   */
  swap_gb?: number | null;
  /**
   * 内核参数，写进 /etc/sysctl.d/90-wharf.conf，例如 `net.ipv4.tcp_congestion_control = bbr`。
   */
  sysctl?: Record<string, string>;
  /**
   * 时区，例如 `Asia/Shanghai`。
   */
  timezone?: string | null;
}

/**
 * 首页上的一条书签：不归 Wharf 管的地址。
 */
export interface BookmarkSpec {
  group?: string | null;
  order: number;
  title: string;
  /**
   * 只允许 http:// 或 https://。
   */
  url: string;
}

export interface BookmarkView {
  id: string;
  spec: BookmarkSpec;
  version: number;
}

/**
 * 代码来源：本机目录（CLI 打包上传）或 git 仓库，二选一。
 */
export interface BuildSource {
  /**
   * 内置模板的基础镜像，例如 `python:3.12-slim`。
   */
  base?: string | null;
  /**
   * Dockerfile 路径（相对构建目录）。不填时有 `Dockerfile` 就用，没有就按语言用内置模板。
   */
  dockerfile?: string | null;
  /**
   * 存在 Wharf 里的 Dockerfile 内容，优先于代码里的 Dockerfile 和模板。
   */
  dockerfile_content?: string | null;
  git?: GitSource | null;
  /**
   * 覆盖内置模板安装依赖的命令（Python、Node），例如 `npm ci && npm run build`。
   */
  install?: string | null;
  /**
   * 代码里的子目录，作为构建目录。
   */
  path?: string | null;
  /**
   * 内置模板的启动命令，例如 `uvicorn main:app --host 0.0.0.0 --port $PORT`。
   * 可以多行（启动脚本），用 `sh -c` 执行。
   */
  start?: string | null;
  /**
   * 内置模板：`python` / `node` / `go` / `static`，不填时按文件识别。
   */
  template?: string | null;
  /**
   * CLI 上传到控制面的代码包（tar.gz）的 sha256。
   */
  upload?: string | null;
}

export interface BuiltinSuppressionView {
  enabled: boolean;
  id: string;
  name: string;
}

/**
 * 证书申请状态，从网关最近的日志里读出来。
 */
export type CertState = "ok" | "obtaining" | "failed" | "unknown";

export interface CertStatus {
  /**
   * 这一轮已经失败了几次。
   */
  attempts: number;
  /**
   * 最近一次失败的原始报错（截断）。
   */
  error?: string | null;
  /**
   * 失败的时间（毫秒）。
   */
  failed_at?: number | null;
  gateway: string;
  hostname: string;
  /**
   * 网关下次自动重试的时间（毫秒）。
   */
  next_retry_at?: number | null;
  /**
   * 最近一次失败的原因，说人话。
   */
  reason?: string | null;
  /**
   * 这一轮开始申请的时间（毫秒）。
   */
  since?: number | null;
  state: CertState;
}

/**
 * 对期望状态的局部修改。CLI 的 `service deploy`、`route add` 等命令都生成它。
 */
export type Change = {
  id: string | null;
  op: "upsert_bookmark";
  spec: BookmarkSpec;
} | {
  id: string;
  op: "remove_bookmark";
} | {
  name: string;
  op: "update_server";
  settings: ServerSettings;
} | {
  /**
   * 导入时接管的现有容器：第一次部署前停掉它们，失败时恢复。部署成功后记进导入记录，不再起作用。
   */
  adopt?: AdoptSpec | null;
  commit?: string | null;
  migrate?: MigrateOptions | null;
  name: string;
  op: "upsert_service";
  pins?: Record<string, string> | null;
  spec: ServiceSpec;
} | {
  mounts?: AdoptMountSpec[];
  op: "adopt_data";
  service: string;
} | {
  name: string;
  op: "remove_service";
  /**
   * 连同数据一起删：`/srv/<服务>` 目录和 compose 声明的命名卷。外部目录不动。
   */
  purge_data?: boolean;
} | {
  /**
   * 只检查这一个镜像（compose 里写的名字）；不填检查服务里的全部镜像。
   */
  image?: string | null;
  name: string;
  op: "refresh_images";
} | {
  /**
   * 现在写的镜像，和 compose 里的一字不差。
   */
  image: string;
  name: string;
  op: "retag_image";
  tag: string;
} | {
  name: string;
  op: "upsert_gateway";
  spec: GatewaySpec;
} | {
  name: string;
  op: "remove_gateway";
} | {
  op: "upsert_route";
  spec: RouteSpec;
} | {
  hostname: string;
  op: "remove_route";
} | {
  name: string;
  op: "upsert_edge_app";
  spec: EdgeAppSpec;
} | {
  name: string;
  op: "import_edge_app";
  spec: EdgeAppSpec;
} | {
  name: string;
  op: "remove_edge_app";
};

export type CheckStatus = "ok" | "warn" | "bad" | "skip";

export type CleanupKind = "migrate_old_data" | "migrate_target_backup" | "restore_backup" | "backup_move_retired" | "backup_move_archive" | "orphan_service_data" | "orphan_task_data" | "orphan_backup_repo" | "orphan_container" | "orphan_volume" | "orphan_network" | "orphan_image" | "orphan_caddy" | "orphan_frpc";

export interface CleanupSkippedServer {
  hint?: string | null;
  reason: string;
  server: string;
}

export interface ContainerInfo {
  exit_code?: number | null;
  finished_at?: string | null;
  /**
   * 同名 compose 项目里不是 Wharf 部署的容器（compose 工作目录不是 Wharf 的项目目录）。
   */
  foreign?: boolean;
  health?: string | null;
  image: string;
  name: string;
  restart_policy?: string | null;
  /**
   * compose 里的服务名。
   */
  service: string;
  /**
   * `running`、`exited`、`restarting` 等。
   */
  state: string;
  status: string;
}

export interface ContainerProbeInfo {
  component: string | null;
  helper: boolean;
  name: string;
  network_mode: string;
  proxy_env: string[];
}

/**
 * 控制面的一个候选地址，加服务器时选一个给 agent 连。
 */
export interface CoreAddress {
  /**
   * route（经网关开放的域名）、configured（启动时配置的地址）、public、tailscale、lan。
   */
  kind: string;
  /**
   * 走这个地址时 agent 和控制面之间是明文。
   */
  plaintext?: boolean;
  url: string;
}

/**
 * 控制面能被 agent 访问到的地址。
 */
export interface CoreAddresses {
  addresses: CoreAddress[];
  /**
   * 控制面默认的 agent 镜像。
   */
  agent_image: string;
  port: number;
  /**
   * 控制面所在的服务器（网卡地址和 agent 上报的地址比对得到），找不到时为空。
   */
  server?: string | null;
}

export interface CoreKeyView {
  fingerprint: string;
  pending_agents?: string[];
  previous_expires_at?: string | null;
  public_key: string;
}

export interface CoreSnapshotsView {
  dir_bytes: number;
  max_count: number;
  max_total_bytes: number;
  min_free_after_bytes: number;
  restore_hint: string;
  snapshots: DbSnapshotInfo[];
}

export interface CreatedToken {
  allowed_from: string[];
  expires_at: string | null;
  name: string;
  perms: Perm[];
  services: string[];
  /**
   * 只返回这一次。
   */
  token: string;
}

/**
 * 用户自定义的按服务告警规则。
 */
export interface CustomAlertRuleView {
  /**
   * 人能读的条件，例如 `req.p95 > 500 ms 连续 3 次（每分钟一次）`。
   */
  condition: string;
  created_at: number;
  enabled: boolean;
  for_n: number;
  level: AlertLevel;
  /**
   * 指标名：`svc.cpu`、`svc.mem`（MB）、`svc.mem_pct`、`req.err`、`req.p95`。
   */
  metric: string;
  muted_until?: number | null;
  name: string;
  /**
   * `>` 或 `<`。
   */
  op: string;
  service: string;
  threshold: number;
}

export interface DataCleanupActionResult {
  display: string;
  freed_bytes: number;
  id: string;
  kind: CleanupKind;
  reason?: string | null;
  server: string;
  service?: string | null;
  /**
   * `"deleted"` | `"skipped"` | `"blocked"` | `"failed"`
   */
  status: string;
}

export interface DataCleanupExecRequest {
  /**
   * 清理筛选范围内的全部未阻塞项（仍默认跳过 unlabeled 卷，除非 include_unlabeled = true）。
   */
  all: boolean;
  /**
   * 确认串：单选为 `data-cleanup/<id>`；批量为 `data-cleanup/batch-<8位hex>`。
   */
  confirm: string | null;
  /**
   * 仅清理已到期项（expires_at <= now；不含无到期时间的孤儿项与 unlabeled 卷）。
   */
  expired_only: boolean;
  /**
   * 显式按 ID 删除（与 expired_only / all 互斥）。
   */
  ids: string[];
  include_unlabeled: boolean;
  kind: CleanupKind | null;
  server: string | null;
  service: string | null;
}

export interface DataCleanupItem {
  /**
   * 是否被在用容器、共享卷或实例变化阻拦，阻拦时禁止删除。
   */
  blocked: boolean;
  blocked_reason?: string | null;
  created_at?: string | null;
  detail?: string | null;
  display: string;
  expired: boolean;
  expires_at?: string | null;
  /**
   * 稳定短 ID（如 `cln_a1b2c3d4e5f6`，由 `kind + server + target` 算 SHA-256 前 12 位），供 `--id` 精准删除。
   */
  id: string;
  /**
   * 绑定服务实例 ID（主要来自 `cleanups` 表）。
   */
  instance_id?: string | null;
  is_core?: boolean;
  kind: CleanupKind;
  server: string;
  server_status?: string | null;
  service?: string | null;
  size_bytes?: number | null;
  size_estimated?: boolean;
  /**
   * 中文来源描述（如 `"迁移旧机目录"`、`"恢复前留底"`、`"换备份机旧仓库"`、`"孤儿服务数据"`、`"Caddy 残留"` 等）。
   */
  source: string;
  target: string;
  /**
   * 无 compose project 标签的悬空卷，默认批量不纳入。
   */
  unlabeled?: boolean;
}

export interface DataCleanupPolicy {
  /**
   * 是否启用到期自动清理（默认 false，拍板 1 选 A）。
   */
  auto_expire: boolean;
  /**
   * 迁移/恢复/换备份机留底默认保留天数（1..=365，默认 7）。
   */
  keep_days: number;
}

export interface DataCleanupResult {
  blocked: number;
  deleted: number;
  failed: number;
  freed_bytes: number;
  results: DataCleanupActionResult[];
  skipped: number;
  warnings?: string[];
}

export interface DataCleanupView {
  blocked_items: number;
  expired_bytes: number;
  expired_items: number;
  hint?: string | null;
  items: DataCleanupItem[];
  policy: DataCleanupPolicy;
  /**
   * 各在线服务器 `AgentReport.docker_disk` 汇总的可回收通用镜像/构建缓存字节（仅提示用，归 `wharf server prune`）。
   */
  prune_reclaimable_bytes?: number | null;
  skipped_servers?: CleanupSkippedServer[];
  total_bytes: number;
  total_items: number;
  warnings?: string[];
}

/**
 * 数据归属：决定迁移、备份、删除时动不动它。
 */
export type DataKind = "managed" | "shared" | "external_dir" | "named_volume";

export interface DataMount {
  /**
   * compose 里的服务名；image / build 来源为空。
   */
  container?: string | null;
  from_service?: string | null;
  kind: DataKind;
  read_only?: boolean;
  resolved?: string | null;
  /**
   * 宿主机路径或卷名；匿名卷为空。
   */
  source: string;
  /**
   * 容器内路径。
   */
  target: string;
}

/**
 * 一个服务的数据备份状态。
 */
export type DataStatus = "ok" | "stale" | "off" | "uncovered" | "none";

/**
 * `GET /api/data`：每个服务的数据在哪、备份有没有在跑。
 */
export interface DataView {
  services: ServiceData[];
}

export interface DbSnapshotInfo {
  addresses?: string[];
  build: string;
  created_at: string;
  id: string;
  key_fingerprint: string;
  plan_id?: string | null;
  reason: string;
  schema_version: number;
  sha256: string;
  size_bytes: number;
  trigger: string;
}

export interface DeploymentView {
  /**
   * git 来源时部署的 commit。
   */
  commit?: string | null;
  /**
   * 渲染后的 compose（密钥未替换）。
   */
  compose: string;
  created_at: string;
  hash: string;
  id: number;
  images: ImageInfo[];
  run_id: string;
  server: string;
  service: string;
  /**
   * 部署时的服务配置。早于记录这一项的部署没有。
   */
  spec?: ServiceSpec | null;
  /**
   * 容器是否启动并通过运行校验。
   */
  started: boolean;
}

export interface Disk {
  free: number;
  total: number;
}

export interface DnsCheck {
  effective: boolean;
  expected: string;
  hostname: string;
  resolvers: DnsResolver[];
}

export interface DnsResolver {
  a: string[] | null;
  aaaa: string[] | null;
  elapsed_ms: number;
  resolver: string;
  verdict: DnsVerdict;
}

export type DnsVerdict = "matches" | "mismatch" | "unavailable";

export interface DockerQuota {
  checked_at: string;
  /**
   * 查询失败时的简短原因；查到额度时为空。
   */
  error?: string | null;
  limit?: number | null;
  remaining?: number | null;
  window_secs?: number | null;
}

/**
 * `POST /api/convert/docker-run` 的请求：一条 `docker run` 命令。
 */
export interface DockerRunRequest {
  command: string;
  /**
   * 服务名，不填时取命令里的 `--name` 或镜像名。compose 来源里的数据目录按它写。
   */
  name?: string | null;
}

export interface DockerSubnet {
  name: string;
  subnet: string;
}

export interface DockerUsage {
  active: string;
  /**
   * Images / Containers / Local Volumes / Build Cache。
   */
  kind: string;
  reclaimable: string;
  size: string;
  total: string;
}

export interface DoctorCheck {
  at: string;
  detail: string;
  /**
   * 哪一层，例如 `dns`、`https`、`gateway`、`link`、`container`、`agent`。
   */
  layer: string;
  status: CheckStatus;
  /**
   * 检查对象，例如 `server1 上的网关 edge`。
   */
  subject: string;
}

/**
 * `wharf doctor` 的结果：沿每个域名的访问链路逐层检查。只读。
 */
export interface DoctorReport {
  checked_at: string;
  checks?: DoctorCheck[];
  config?: DoctorCheck[];
  routes: RouteDiagnosis[];
  servers: DoctorCheck[];
  vendors?: DoctorCheck[];
}

/**
 * 边缘应用：Cloudflare Workers / Pages。没有端口、数据卷、迁移、备份。
 */
export interface EdgeAppSpec {
  /**
   * 厂商账号。
   */
  account: string;
  /**
   * 在哪台服务器上执行 wrangler（构建 Pages、发布 wrangler 项目）。不填时自动选，优先海外。
   */
  builder?: string | null;
  /**
   * 绑定的自定义域名，不经过网关。Worker 的 DNS 由 Cloudflare 管；Pages 由 Wharf 写 CNAME。
   */
  domains?: string[];
  kind: EdgeKind;
  /**
   * 厂商那边的脚本名 / 项目名。不填时等于边缘应用的名字。
   */
  project?: string | null;
  /**
   * 不填表示只纳管：Wharf 显示状态、管域名、回滚，不发布代码。
   */
  source?: EdgeSource | null;
}

export interface EdgeAppView {
  /**
   * 和 Wharf 记录的不一致时的说明，例如线上版本被别处改过、项目被删了。
   */
  drift?: string | null;
  /**
   * 厂商那边的现状（后台同步后存在控制面），还没同步过时为空。
   */
  live?: EdgeLive | null;
  name: string;
  spec: EdgeAppSpec;
  version: number;
}

/**
 * 边缘应用的种类。
 */
export type EdgeKind = "worker" | "pages";

export interface EdgeLive {
  checked_at: string;
  /**
   * 最近一次发布。
   */
  deployed_at?: string | null;
  /**
   * 最近一次发布的来源，例如 `wrangler`、`dashboard`、`api`。
   */
  deployed_by?: string | null;
  /**
   * 读取失败时的原因。
   */
  error?: string | null;
  /**
   * 厂商那边是否存在这个 Worker / Pages 项目。
   */
  exists: boolean;
  /**
   * 默认访问地址，例如 `https://x.y.workers.dev`、`https://x.pages.dev`。
   */
  url?: string | null;
}

/**
 * 厂商账号下自动发现的 Worker / Pages 项目。
 */
export interface EdgeProjectView {
  /**
   * 所在的厂商账号。
   */
  account: string;
  kind: EdgeKind;
  /**
   * 已经导入时是边缘应用的名字。
   */
  managed_as?: string | null;
  modified_at?: string | null;
  project: string;
  url?: string | null;
}

/**
 * 边缘应用的代码来源。和服务的构建来源一样，代码来自本机目录上传或 git。
 */
export interface EdgeSource {
  /**
   * pages：构建命令，例如 `npm run build`。不填就是静态目录。
   */
  build?: string | null;
  git?: GitSource | null;
  /**
   * pages：要发布的目录（相对代码目录）。不填时有构建命令用 `dist`，否则用代码目录本身。
   */
  output?: string | null;
  /**
   * 代码里的子目录。
   */
  path?: string | null;
  /**
   * worker：单文件脚本（相对代码目录）。直接调用厂商接口上传，
   * 保留面板里配置的变量和绑定。不填时按 wrangler 项目发布。
   */
  script?: string | null;
  /**
   * 本机目录上传到控制面的代码包 sha256（`wharf edge deploy` 自动填）。
   */
  upload?: string | null;
}

/**
 * 边缘应用的一个版本（Workers 的 version / Pages 的 deployment）。
 */
export interface EdgeVersionView {
  /**
   * 正在线上的版本。
   */
  active: boolean;
  created_at: string;
  id: string;
  last_deployed_at?: string | null;
  message?: string | null;
  /**
   * `wrangler`、`dashboard`、`api` 等。
   */
  source?: string | null;
  url?: string | null;
}

export interface EgressInfo {
  asn: string | null;
  city: string | null;
  country: string | null;
  ipv4: string | null;
  ipv6: string | null;
  operator: string | null;
}

/**
 * 服务器设置 `egress`：这台提供出口，以及经它出去的规则。
 */
export interface EgressSpec {
  /**
   * `true`：除内网外全部经出口；`false`：只有命中预置分组和自定义域名的经出口。
   */
  all: boolean;
  /**
   * 自定义域名：`example.com` 只匹配它自己，`*.example.com` 匹配所有子域名（不含自己）。
   */
  domains?: string[];
  /**
   * 预置分组，见 [PRESETS]。
   */
  presets?: string[];
}

/**
 * 稳定的错误码。AI 和页面可以按它分支处理。
 */
export type ErrorCode = "InvalidInput" | "NotFound" | "AlreadyExists" | "Conflict" | "Unauthorized" | "Forbidden" | "PasswordRequired" | "AgentOffline" | "Timeout" | "Cancelled" | "NotImplemented" | "Internal" | "PlanStale" | "ConfirmRequired" | "Busy" | "AgentFailed" | "Provider";

export interface EscapedMount {
  resolved: string;
  source: string;
}

export type ExplainVerdict = "allow" | "deny" | "depends";

export interface ExposureView {
  checked_at: number | null;
  outdated: boolean;
  ports: PortRow[];
  risks: RiskRow[];
}

export interface ExternalIncident {
  name: string;
  url: string;
}

export interface ExternalStatus {
  checked_at: string | null;
  description: string;
  enabled: boolean;
  incidents: ExternalIncident[];
  indicator: string | null;
  name: string;
  url: string;
}

export type Extract = {
  from: "json";
  name: string;
  path: string;
} | {
  between: string[];
  from: "body";
  name: string;
} | {
  from: "header";
  header: string;
  name: string;
} | {
  cookie: string;
  from: "cookie";
  name: string;
};

export interface ExtractedSecretItem {
  action: string;
  component?: string | null;
  env_key: string;
  reason: string;
  secret_name: string;
}

export interface FailoverEntryHealth {
  detail: string;
  ok: boolean;
  stage: string;
  status?: number | null;
}

export interface FailoverHealthSnapshot {
  at: number;
  backup?: FailoverEntryHealth | null;
  primary?: FailoverEntryHealth | null;
  service_stopped?: boolean;
}

export interface FailoverPendingView {
  attempts: number;
  last_error?: string | null;
  target_backup: boolean;
}

export type FailoverPinTarget = "backup";

export type FailoverTarget = "primary" | "backup" | "auto";

/**
 * 配置里改动的一个字段。
 */
export interface FieldChange {
  after?: unknown;
  /**
   * 没有这个字段时为空。
   */
  before?: unknown;
  /**
   * 多行文本（比如 compose）按行对比：`-` 删掉的行，`+` 新增的行，
   * 空格开头是上下文，`…` 表示省略了没变的行。
   */
  lines?: string[];
  /**
   * 字段路径，例如 `env.TZ`、`source.compose.content`。
   */
  path: string;
}

export interface FileEntry {
  dir: boolean;
  /**
   * 符号链接（不跟进）。
   */
  link?: boolean;
  /**
   * 修改时间，毫秒。
   */
  modified: number;
  name: string;
  size: number;
}

/**
 * 一个配置文件。
 */
export interface FileSpec {
  /**
   * 文本内容，最大 64 KB。可以用 `[[密钥名]]` 和 `[[@服务]]`，部署时替换。
   */
  content: string;
  /**
   * 意图文件中的外置配置路径。
   */
  file?: string | null;
  /**
   * 容器内的绝对路径，例如 `/etc/app/config.yaml`。
   */
  path: string;
  /**
   * 跳过 plan 阶段的配置文件语法预检。
   */
  raw?: boolean;
}

export interface FiringView {
  ack?: AlertAckView | null;
  rule: string;
  /**
   * 开始触发的时间（毫秒）。
   */
  since: number;
  subject: string;
  title: string;
}

/**
 * 服务器上的一个容器。
 */
export interface FoundContainer {
  image: string;
  name: string;
  /**
   * 例如 `0.0.0.0:8080->80/tcp`。
   */
  ports?: string[];
  /**
   * 所属的 compose 项目，`docker run` 起的为空。
   */
  project?: string | null;
  state: string;
  status: string;
  /**
   * 挂载的具名数据卷（不含宿主机目录和匿名卷）。
   */
  volumes?: string[];
}

export interface GateKeyRequest {
  hosts: string[];
}

/**
 * 门禁访问凭证；列表不包含明文或哈希。
 */
export interface GateKeyView {
  created_at: number;
  hosts: string[];
  last_used_at: number | null;
  name: string;
}

export type GatewayKind = "caddy" | "cloudflare_tunnel";

export interface GatewaySpec {
  /**
   * cloudflare_tunnel：在哪个厂商账号下建隧道（`wharf account list`）。
   */
  account?: string | null;
  /**
   * 默认入口：添加路由时不选网关就用它。最多一个。
   */
  default?: boolean;
  /**
   * caddy：ACME 账号邮箱，可选。
   */
  email?: string | null;
  /**
   * caddy：网关连不上服务时（502、503、504）显示的 HTML。不填用内置的默认页。
   * 内容里可以写 `{err.status_code}`，显示时换成状态码。
   */
  error_page?: string | null;
  /**
   * caddy：重载时等待正在处理的请求（秒），默认 10。
   */
  grace_period?: number | null;
  /**
   * caddy：HTTP 端口，默认 80。改端口只用于测试，签证书需要 80。
   */
  http_port?: number | null;
  /**
   * caddy：HTTPS 端口，默认 443。
   */
  https_port?: number | null;
  /**
   * caddy：连接空闲超时（秒），默认 120。
   */
  idle_timeout?: number | null;
  /**
   * caddy：镜像，默认 Wharf 自建的 wharf-caddy。
   */
  image?: string | null;
  kind: GatewayKind;
  /**
   * caddy：四层转发，只经过入口所在机器，服务自己的端口不对公网开放。
   */
  layer4?: Layer4Forward[];
  /**
   * caddy：读取请求头的超时（秒），默认 10。
   */
  read_header_timeout?: number | null;
  /**
   * 网关跑在哪台服务器上。
   */
  server: string;
  /**
   * caddy：证书方式，默认 `auto`（公网签证书）。
   */
  tls?: GatewayTls;
  /**
   * caddy：可信上游代理（Cloudflare 官方网段、集群网关/组网地址、自定义 CIDR）。
   */
  trusted_proxies?: TrustedProxiesSpec | null;
  /**
   * caddy：签一张 *.<zone>，这个入口上 zone 下一级的域名都用它。
   */
  wildcard?: string[];
}

/**
 * 网关的证书方式。
 */
export type GatewayTls = "auto" | "internal" | "off";

export interface GatewayView {
  gate_core?: string | null;
  live?: LiveState | null;
  name: string;
  omitted?: Record<string, number>;
  /**
   * 承载的路由 hostname。
   */
  routes: string[];
  spec: GatewaySpec;
  version: number;
}

export interface GitSource {
  /**
   * 分支、标签或 commit。
   */
  ref: string;
  /**
   * https 地址，例如 `https://github.com/owner/repo`。
   */
  repo: string;
  /**
   * 私有仓库：保存访问 token 的密钥名（`wharf secret set`）。
   */
  token_secret?: string | null;
  user?: string | null;
}

export type Health = "healthy" | "unhealthy" | "starting" | "none";

export interface HeartbeatReportView {
  at: number;
  ok: boolean;
  output: string;
}

export interface HeartbeatSpec {
  every_mins: number;
  grace_mins: number;
  rotate?: boolean;
  /**
   * 已按目标容器配置；旧心跳保留原来的全容器注入。
   */
  targeted?: boolean;
  token?: string;
}

export interface HeartbeatView {
  last_at: number | null;
  status: string;
  url: string;
}

/**
 * 服务器详情页的宿主机信息，打开页面时现查。
 */
export interface HostInfo {
  /**
   * 容器日志（json-file）合计字节数。
   */
  container_logs?: number | null;
  cpus: number;
  /**
   * `docker system df` 的每一行。
   */
  docker: DockerUsage[];
  /**
   * systemd journal 字节数。
   */
  journal?: number | null;
  kernel: string;
  /**
   * 1、5、15 分钟负载。
   */
  load: number[];
  mem_available: number;
  mem_total: number;
  /**
   * `/etc/os-release` 的 PRETTY_NAME。
   */
  os?: string | null;
  reboot_required: boolean;
  /**
   * 近 30 天 sshd 的成功登录，最多 20 条，新的在前；读不到 journal 时为空。
   */
  ssh_logins?: SshLogin[];
  /**
   * 按上次 `apt update` 的结果算的待装更新；不是 apt 系统时为空。
   */
  updates?: PackageUpdate[] | null;
  uptime_secs: number;
  /**
   * `/var/log` 合计字节数（含 journal）。
   */
  var_log?: number | null;
}

/**
 * 一个域名在上报间隔内经网关的请求（只算转发到上游的）。
 */
export interface HostTraffic {
  /**
   * 5xx 的个数。
   */
  errors: number;
  p50_ms: number;
  p95_ms: number;
  reqs: number;
  /**
   * 这段统计的秒数。
   */
  secs: number;
}

export interface ImageInfo {
  /**
   * `repo@sha256:…`，本地构建的镜像没有。
   */
  digest?: string | null;
  id: string;
  image: string;
}

export type ImagePullMode = "if_missing" | "never" | "always";

export interface ImageRow {
  id: string;
  image: string;
  server: string;
  size: number;
  used_by: string[];
}

export interface ImageVersionCheck {
  error?: string | null;
  latest?: string | null;
  newer: boolean;
}

export interface ImagesView {
  errors: Record<string, string>;
  rows: ImageRow[];
  unused: Record<string, number>;
}

/**
 * 计划项会造成的影响，一项可以有多个。
 */
export type Impact = "restart" | "downtime" | "remove" | "data_loss" | "overwrite" | "public" | "privilege";

/**
 * 导入预览：用 `upsert_service` 提交即可。
 */
export interface ImportPreview {
  /**
   * 提交 `UpsertService` 时原样带上。
   */
  adopt?: AdoptSpec | null;
  extracted_secrets?: ExtractedSecretItem[];
  name: string;
  secrets_committed?: boolean;
  spec: ServiceSpec;
  warnings?: string[];
}

export interface ImportRecord {
  /**
   * 原来 `docker run` 起的容器。
   */
  containers?: string[];
  /**
   * 第一次部署成功的时间；还没部署时为空。
   */
  done_at?: string | null;
  /**
   * 原来的 compose 项目。
   */
  project?: string | null;
  /**
   * 被停掉留着回退用的旧容器（改名后的名字）。
   */
  retired?: string[];
  server: string;
}

export interface Issue {
  ack?: AlertAckView | null;
  alert?: AlertTarget | null;
  /**
   * 这是哪一类问题，页面按它决定给什么按钮。取值见下表。
   * oom_killed：服务的容器因内存超限被杀。
   * recovery_low：恢复码少于 3 个。
   * exposed_port：未确认的对公网监听端口。
   * log_keyword、port_down、heartbeat_late：服务监控触发（Fault）。
   * service_stopped_long、unmanaged_container：长期停止和未纳管容器（Info）。
   */
  code: string;
  /**
   * 只给命令行看的补充（怎么用命令处理）。页面不显示。
   */
  hint?: string | null;
  level: IssueLevel;
  subject?: IssueSubject | null;
  /**
   * 给人看的一句话。
   */
  title: string;
}

export type IssueLevel = "fault" | "warn" | "info";

export interface IssueSubject {
  /**
   * server、service、gateway、edge、task、route。
   */
  kind: string;
  name: string;
}

/**
 * `wharf server add` 的返回：在目标机器上执行 `join` 里的任一命令即可加入。
 */
export interface JoinInfo {
  /**
   * 例如 `{ "script": "curl ... | sh ...", "docker": "docker run ...", "binary": "wharf-agent join ..." }`。
   */
  commands: Record<string, string>;
  /**
   * 命令里 agent 连接控制面用的地址。
   */
  core_url: string;
  expires_at: string;
  /**
   * 一次性加入凭据，24 小时内有效，用过即失效。
   */
  join_token: string;
  server: string;
}

export interface LastOp {
  /**
   * 部署、重启、停止、迁移数据、恢复。
   */
  action: string;
  at: string;
  error?: string | null;
  run_id: string;
  status: OpStatus;
}

export type Layer = "volume" | "container" | "gateway" | "dns" | "tunnel" | "config" | "edge";

/**
 * 在入口机器上监听 TCP 或 UDP，原样转给服务。服务和上游二选一。
 */
export interface Layer4Forward {
  listen: number;
  port?: string | null;
  service?: string | null;
  udp?: boolean;
  upstream?: string | null;
}

/**
 * 资源上限。compose 来源加在 `container` 指定的容器上。
 */
export interface Limits {
  /**
   * CPU 上限，单位是千分之一核，500 表示 0.5 核。
   */
  cpu_milli?: number | null;
  /**
   * 内存上限，单位 MB。
   */
  memory_mb?: number | null;
  pids?: number | null;
}

/**
 * 网关到服务的走法偏好。
 */
export type LinkMode = "auto" | "tunnel";

/**
 * 一个方向的链路质量。历史曲线：`GET /api/metrics?subject=<from>><to>&names=link.ms,link.loss`。
 */
export interface LinkView {
  at: string;
  from: string;
  /**
   * 丢包率，0 到 100。
   */
  loss: number;
  /**
   * TCP 建连平均耗时（毫秒），全部失败时为空。
   */
  ms?: number | null;
  to: string;
}

export interface LiveState {
  containers?: ContainerInfo[];
  error?: string | null;
  /**
   * 现状是否和控制面里的配置一致。`false` 时执行 `wharf plan` 可以看到差异。
   */
  in_sync?: boolean | null;
  /**
   * `running`、`partial`、`stopped`、`missing`、`unknown`。
   */
  state: string;
}

export interface LogAlertSpec {
  container?: string | null;
  min_count: number;
  pattern: string;
  regex: boolean;
  window_mins: number;
}

export interface LogAlertView {
  firing: boolean;
  last_hit: number | null;
  pattern: string;
}

export interface LogHit {
  at: number;
  count: number;
  id: string;
  lines: string[];
}

export interface LogMax {
  max_bytes: number;
  max_files: number;
}

export interface LoginScript {
  code: string;
  deps?: string;
  env?: Record<string, string>;
  image?: string | null;
  runtime: ScriptRuntime;
  timeout_secs: number;
}

export interface LoginSpec {
  check?: LoginStep | null;
  /**
   * 代登录完成后跳到的路径，例如后台 `/ghost/`；不填就是 `/`。
   */
  entry?: string | null;
  script?: LoginScript | null;
  steps: LoginStep[];
  takeover?: LoginTakeover | null;
  ttl_hours: number;
  use_account?: boolean;
  write: LoginWrite[];
}

export interface LoginStep {
  body?: string | null;
  expect?: number[] | null;
  extract?: Extract[];
  form?: Record<string, string> | null;
  headers?: Record<string, string>;
  json?: unknown;
  method: string;
  path: string;
}

export interface LoginTakeover {
  native_minutes: number;
  paths: string[];
  rd_param?: string | null;
  skip_query?: string[];
}

export type LoginWrite = {
  cookies: AllCookies;
} | {
  cookie: {
  http_only: boolean;
  name: string;
  value: string;
};
} | {
  local_storage: {
  key: string;
  value: string;
};
} | {
  session_storage: {
  key: string;
  value: string;
};
};

/**
 * 单个指标的本期值、上期值与环比变化百分比。
 */
export interface MetricDelta {
  /**
   * 相对上期的变化百分比（正数增加，负数减少）；上期无数据或上期为 0 且本期非 0 时为空。
   */
  change_pct?: number | null;
  current?: number | null;
  previous?: number | null;
}

/**
 * 一次资源采样。速率是和上一次采样相比的平均值。
 */
export interface Metrics {
  agent_cpu?: number | null;
  agent_mem?: number | null;
  /**
   * 整机 CPU 使用率，0 到 100。
   */
  cpu: number;
  disk_total: number;
  disk_used: number;
  /**
   * 本机 Caddy 网关上一段时间各域名的请求统计。旧 agent 没有。
   */
  hosts?: Record<string, HostTraffic>;
  inode_total?: number | null;
  inode_used?: number | null;
  mem_total: number;
  mem_used: number;
  /**
   * 字节每秒，不含回环、docker 网桥和组网网卡。
   */
  net_rx: number;
  net_rx_bytes?: number | null;
  net_tx: number;
  net_tx_bytes?: number | null;
  /**
   * 上次上报以来因内存超限被杀过容器的 compose project 名。
   * 旧 agent 没有这个字段；新 agent 每次都带，没有就是空列表。
   */
  oom?: string[] | null;
  /**
   * compose project 名到它的容器合计。
   */
  projects?: Record<string, ProjectMetrics>;
}

export interface MigrateOptions {
  bwlimit?: string | null;
}

export interface MigrationView {
  from: string;
  phase: string;
  to: string;
}

/**
 * 自定义监控：`http://127.0.0.1:<宿主机端口><path>`。
 */
export interface MonitorSpec {
  /**
   * 期望的状态码；不写时 2xx、3xx 都算正常。
   */
  expect?: number | null;
  /**
   * 自定义请求头，值支持密钥引用。
   */
  headers?: Record<string, string>;
  /**
   * 检查间隔（秒），缺省 60。
   */
  interval_secs?: number | null;
  /**
   * 响应里必须包含的文字（只看前 64KB）。
   */
  keyword?: string | null;
  /**
   * 请求路径，默认 `/`。
   */
  path: string;
  /**
   * 端口名，默认第一个端口。
   */
  port?: string | null;
  /**
   * 单轮失败后的重试次数。
   */
  retries?: number | null;
}

/**
 * 自定义监控的最近一次结果。
 */
export interface MonitorView {
  /**
   * 毫秒时间戳。
   */
  at: number;
  /**
   * 例如 `HTTP 200 · 12 ms`、`HTTP 502，期望 2xx 或 3xx`。
   */
  detail: string;
  fails: number;
  ok: boolean;
}

export interface NetProbeCertificate {
  days_left: number;
  issuer: string | null;
  not_after: string;
  san: string[];
  subject_cn: string | null;
}

export interface NetProbeDns {
  elapsed_ms: number;
  ips: string[];
  nameservers: string[];
  resolved_by_egress?: boolean;
  search: string[];
}

export interface NetProbeError {
  kind: NetProbeErrorKind;
  message: string;
}

export type NetProbeErrorKind = "dns_failed" | "blocked" | "refused" | "timeout" | "unreachable" | "tls" | "other" | "cancelled";

export interface NetProbeHttp {
  egress: boolean;
  headers: Record<string, string>;
  status: number;
}

export type NetProbeKind = "tcp" | "http" | "dns";

export interface NetProbeReport {
  certificate: NetProbeCertificate | null;
  container?: ContainerProbeInfo | null;
  dns: NetProbeDns | null;
  elapsed_ms: number;
  error: NetProbeError | null;
  hint: string | null;
  http: NetProbeHttp | null;
  kind: NetProbeKind;
  ok: boolean;
  reachable: boolean;
  server: string;
  target: string;
  tcp: NetProbeTcp | null;
  tls: NetProbeTls | null;
}

export interface NetProbeRequest {
  component?: string | null;
  egress?: boolean | null;
  kind?: NetProbeKind | null;
  target: string;
  timeout_secs?: number | null;
}

export interface NetProbeTcp {
  elapsed_ms: number;
  remote_addr: string;
}

export interface NetProbeTls {
  verified: boolean;
  verify_error: string | null;
}

/**
 * 机器的接入方式（design 2.10）。不指定时按检测到的地址推断：有 Tailscale 地址是 `tailscale`，
 * 有别的内网地址是 `lan`，都没有是 `public`（只能经公网和反向隧道）。
 */
export type NetworkMode = "tailscale" | "lan" | "public";

export interface NetworkServer {
  /**
   * 接入方式是在设置里指定的（否则是按检测到的地址推断）。
   */
  configured?: boolean;
  mode: NetworkMode;
  name: string;
  online: boolean;
  private_ip?: string | null;
  public_ip?: string | null;
  tailnet_ip?: string | null;
}

/**
 * `GET /api/network`：各机器怎么接入、谁能连谁。
 */
export interface NetworkView {
  /**
   * 最近一轮链路质量（每 5 分钟测一次，控制面重启后要等下一轮）。
   */
  links?: LinkView[];
  /**
   * 探测过的方向，没探测过的不在里面。
   */
  reach: ReachView[];
  /**
   * 直连差、经第三台中转两段都好的方向。
   */
  relays?: RelayHint[];
  servers: NetworkServer[];
  tailnet_reach?: ReachView[];
  tailnet_relays?: TailnetRelay[];
}

export interface NewerTag {
  /**
   * compose 里写的镜像，例如 `halo/halo:2.20`。
   */
  image: string;
  /**
   * 换了大版本（第一位数字变了），通常有不兼容的改动。
   */
  major?: boolean;
  /**
   * 更高版本的标签，例如 `2.21`。
   */
  tag: string;
}

/**
 * 一类事件通知：发生就推，没有阈值。
 */
export interface NoticeView {
  customized: boolean;
  default_level?: AlertLevel | null;
  enabled: boolean;
  id: string;
  level: AlertLevel;
  muted_until?: number | null;
  name: string;
}

/**
 * OIDC 客户端。client_id 就是域名，密钥由 Wharf 生成，
 * 服务环境变量里用 `[[OIDC_<域名大写，. 和 - 换成 _>]]` 引用。
 */
export interface OidcClientSpec {
  /**
   * 登录完成后的回调地址。`/` 开头的是本域名下的路径；
   * 也可以写本域名的完整 https 地址，或手机 app 的自定义协议（如 `app.immich:///oauth-callback`）。
   */
  redirect_uris: string[];
}

export interface OidcClientView {
  client_id: string;
  public: boolean;
  redirect_uris: string[];
  /**
   * 服务环境变量里引用密钥的写法，例如 `[[OIDC_BLOG_EXAMPLE_COM]]`。
   */
  secret_ref: string;
}

export interface OidcSecretView {
  client_id: string;
  client_secret: string;
}

export interface OidcSettingsRequest {
  email: string | null;
}

/**
 * Wharf 作为 OIDC 身份提供方的信息；不含任何密钥值。
 */
export interface OidcView {
  clients: OidcClientView[];
  discovery: string | null;
  /**
   * 发给应用的邮箱；很多应用要求有邮箱。
   */
  email: string | null;
  /**
   * 控制面没有对外 https 地址时为空，OIDC 不可用。
   */
  issuer: string | null;
  username: string;
}

export type OpStatus = "running" | "succeeded" | "failed";

export interface PackageUpdate {
  from: string;
  name: string;
  /**
   * 来自安全更新源。
   */
  security: boolean;
  to: string;
}

/**
 * 路由里的一条路径转发。`service` 和 `upstream` 二选一。
 */
export interface PathRoute {
  /**
   * Caddy 的路径匹配：`/ws` 只匹配这个路径，`/api/*` 匹配前缀。
   */
  path: string;
  /**
   * 目标端口名，服务只有一个端口时可以不填。
   */
  port?: string | null;
  /**
   * 目标服务。
   */
  service?: string | null;
  /**
   * 不归 Wharf 管的上游，例如网关所在机器上的 `127.0.0.1:17891`。
   */
  upstream?: string | null;
}

export interface PendingCheck {
  at: string;
  error?: string | null;
  /**
   * 计划项的地址，例如 `service/whoami`。
   */
  items: string[];
}

/**
 * 权限点。token 持有一组；页面登录的会话有全部权限。
 */
export type Perm = "read" | "plan" | "apply" | "confirm" | "exec" | "host" | "admin";

export interface Plan {
  /**
   * plan 时读到的资源版本。apply 时任何一个变了都拒绝执行。
   */
  base_versions: Record<string, number>;
  created_at: string;
  /**
   * 过期后不能 apply，需要重新 plan。
   */
  expires_at: string;
  /**
   * plan 时连通性结果和密钥的指纹：直连还是走隧道、渲染出的配置都取决于它们，
   * apply 时变了就拒绝执行。旧计划没有这个字段，不检查。
   */
  inputs?: string | null;
  items: PlanItem[];
  /**
   * 需要 `--confirm` 的地址。
   */
  needs_confirm?: string[];
  /**
   * 触达宿主机、apply 时需要 `host` 权限且目标服务器开启对应开关的地址。
   */
  needs_host?: string[];
  /**
   * 生成计划时写的备注。
   */
  note?: string | null;
  plan_id: string;
  status: PlanStatus;
  /**
   * 建议的下一步命令。
   */
  suggest?: string[];
  /**
   * 不阻止 apply 的提醒，例如某台服务器离线，查不到现状。
   */
  warnings?: string[];
}

export interface PlanItem {
  action: Action;
  /**
   * 例如 `service/whoami`、`route/who.example.com`。
   */
  address: string;
  after: unknown;
  before: unknown;
  /**
   * 修改时具体改了哪些字段，由 `before`、`after` 算出。旧计划里没有。
   */
  changes?: FieldChange[];
  /**
   * 触达宿主机的原因；非空时 apply 阶段需要 host 权限且目标服务器开启对应开关。旧计划里没有。
   */
  host_access?: string[];
  id: number;
  /**
   * 旧计划里没有这个字段（当时是单个 `risk`），读出来为空。
   */
  impacts: Impact[];
  layer: Layer;
  reason: string;
}

export type PlanStatus = "pending" | "applied" | "expired";

export interface PlanSummary {
  addresses?: string[];
  created_at: string;
  expires_at: string;
  expires_in_secs: number;
  item_count: number;
  needs_confirm?: string[];
  note?: string | null;
  plan_id: string;
  status: PlanStatus;
}

export type PortCheckSpec = {
  kind: "off";
} | {
  domain: string;
  kind: "dns";
} | {
  expect: string;
  kind: "custom";
  send: string;
};

export interface PortRow {
  acked: boolean;
  addr: string;
  expected: boolean;
  family?: string | null;
  name: string;
  owner: string;
  port: number;
  proto: string;
}

export interface PortSpec {
  /**
   * 容器内端口。image / build 来源必填；compose 来源不填（映射写在 compose 里）。
   */
  container?: number | null;
  /**
   * 宿主机端口。compose 来源必填（compose 里已经发布的端口）；
   * image / build 来源选填，不填由系统从 20000 起自动分配。
   */
  host?: number | null;
  /**
   * 端口名，路由用它指定目标端口，例如 `http`。
   */
  name: string;
  /**
   * UDP 端口，只能用于四层转发，不能给域名用。默认 TCP。
   */
  udp?: boolean;
}

/**
 * 服务器之间互相访问用的地址：网关跨机器访问服务时连它，
 * 服务端口除了 127.0.0.1 也只绑定它。
 * 
 * Wharf 不负责打洞，组网交给专门的工具；这里只记地址在哪个网络、
 * 网络本身是否加密。
 */
export interface PrivateAddr {
  ip: string;
  network: PrivateNetwork;
}

/**
 * 内网地址所在的网络。
 */
export type PrivateNetwork = "tailscale" | "overlay" | "lan";

/**
 * 域名探测结果。
 */
export interface ProbeView {
  /**
   * 毫秒时间戳。
   */
  at: number;
  /**
   * https 证书还剩几天。
   */
  cert_days?: number | null;
  /**
   * 例如 `HTTP 200`、`15 秒没有应答`。
   */
  detail: string;
  /**
   * 连续失败次数。
   */
  fails: number;
  ms: number;
  ok: boolean;
}

export interface ProjectMetrics {
  /**
   * 占整机 CPU 的百分比，0 到 100。
   */
  cpu: number;
  mem: number;
  net_rx: number;
  net_tx: number;
}

/**
 * `from` 所在机器能不能连到 `to` 的内网地址。
 */
export interface ReachView {
  checked_at: string;
  from: string;
  ok: boolean;
  /**
   * 超过一天没重新探测，结果不作数。
   */
  stale?: boolean;
  to: string;
}

export type Region = "cn" | "overseas";

/**
 * 中转建议：`from` → `via` → `to` 比直连好。
 */
export interface RelayHint {
  /**
   * 直连丢包率。
   */
  direct_loss: number;
  from: string;
  to: string;
  via: string;
  /**
   * 经中转两段合计的丢包率。
   */
  via_loss: number;
}

/**
 * 报告实际覆盖的时间范围。
 */
export interface ReportCoverage {
  earliest_at?: number | null;
  has_current: boolean;
  has_previous: boolean;
  latest_at?: number | null;
  period_end: number;
  period_start: number;
  previous_end: number;
  /**
   * 上期实际覆盖的时间比例（0.0～1.0），按 `earliest_at` 到 `previous_end` 计算。
   */
  previous_ratio: number;
  previous_start: number;
}

/**
 * `GET /api/report` 的返回结构。
 */
export interface ReportView {
  alerts: AlertReport[];
  coverage: ReportCoverage;
  days: number;
  servers: ServerReport[];
  services: ServiceReport[];
  summary: string[];
}

export interface ResolvedImage {
  /**
   * 这台机器平台对应的镜像 ID（`sha256:…`），和 `docker image inspect` 的 Id 相同。
   */
  config?: string | null;
  /**
   * `sha256:…`。
   */
  digest?: string | null;
  error?: string | null;
  /**
   * 目标 agent 的平台，例如 `linux/arm64`。
   */
  host_platform?: string | null;
  image: string;
  /**
   * `tags` 时：同一大版本里最高的标签，和跨大版本最高的标签（没有就不列）。
   */
  newer_tags?: string[];
  /**
   * 镜像支持的平台，例如 `linux/amd64`。
   */
  platforms?: string[] | null;
}

/**
 * `POST /api/services/{name}/restore`
 */
export interface RestoreRequest {
  /**
   * 必须是 `service/<名称>`：恢复会覆盖现有数据。
   */
  confirm: string;
  skip_snapshot?: boolean;
  /**
   * 快照 id，或 `latest`。
   */
  snapshot: string;
  target?: string | null;
}

export interface RiskRow {
  container: string;
  own: boolean;
  project: string | null;
  risks: string[];
  service: string | null;
}

/**
 * 回滚到某次部署时要提交的服务配置和版本。
 */
export interface RollbackTarget {
  commit?: string | null;
  deployed_at: string;
  deployment_id: number;
  pins?: Record<string, string> | null;
  service: string;
  spec: ServiceSpec;
  warnings?: string[];
}

export interface RouteDiagnosis {
  /**
   * HTTPS 证书到期时间，连不上或不是 HTTPS 时没有。
   */
  cert_expires?: string | null;
  /**
   * 按访问顺序：域名解析 → HTTPS → 网关 → 网关到上游 → 容器。
   */
  checks: DoctorCheck[];
  /**
   * 这个域名的注册到期时间（后台用 RDAP 查，查不到没有）。
   */
  domain_expires?: string | null;
  edge_app?: string | null;
  hostname: string;
  url: string;
}

export interface RouteFailoverRequest {
  force: boolean;
  reason?: string | null;
  target: FailoverTarget;
  verify_before_dns: boolean;
}

export interface RouteFailoverView {
  backup_gateway: string;
  changed: boolean;
  health?: FailoverHealthSnapshot | null;
  hostname: string;
  on_backup: boolean;
  pending?: FailoverPendingView | null;
  pinned: FailoverPinTarget | null;
  primary_gateway: string;
  run_id?: string | null;
  verification?: string | null;
}

export interface RouteSpec {
  /**
   * 登录保护（P3）。
   */
  auth?: boolean;
  /**
   * 备用入口：主入口持续不可达且备用可达时切换 DNS，主入口持续恢复后切回。
   */
  backup_gateway?: string | null;
  /**
   * 拦截常见扫描：请求命中扫描路径或扫描器的 UA 时直接返回 404，不转给服务。只支持 caddy 网关。
   */
  block_scanners?: boolean;
  /**
   * 自定义 Caddy 配置：原样插进网关里这个域名的站点块，例如按路径拦截、加响应头。
   * 网关下发前会用 Caddy 校验，写错了不会生效。只支持 caddy 网关。
   */
  caddy?: string | null;
  /**
   * 意图文件中的外置 Caddy 片段路径。
   */
  caddy_file?: string | null;
  /**
   * 只接受 Cloudflare 官方网段的直连请求。
   */
  cf_origin_only?: boolean;
  /**
   * 仅向组网内来源开放控制面页面。
   */
  core_mesh_only?: boolean;
  dns_ttl?: number | null;
  /**
   * 临时分享：到这个时间（毫秒时间戳）以后，网关直接断开这个域名的请求；路由和 DNS 记录留着，等人删除。
   */
  expires_at?: number | null;
  /**
   * 自动切备和切回所需的连续异常或恢复分钟数，默认 5 分钟。
   */
  failover_minutes?: number | null;
  /**
   * 入口网关。不填则用默认网关；边缘应用的域名不经过网关，不填。
   */
  gateway?: string | null;
  /**
   * 例如 `blog.example.com`。
   */
  hostname: string;
  /**
   * 只在内网访问：DNS 指向入口所在机器的内网地址，证书用 DNS 验证签，入口只放行内网来源。只支持 caddy 网关。
   */
  internal?: boolean;
  /**
   * 网关到服务的走法。不填为自动：同机、能直连内网地址就直连，否则走反向隧道。
   */
  link?: LinkMode;
  /**
   * 按路径转发到别的上游，其余路径仍到 `service`。只支持 caddy 网关。
   */
  paths?: PathRoute[];
  /**
   * 目标端口名。服务只有一个端口时可以不填；边缘应用不填。
   */
  port?: string | null;
  /**
   * 限速：同一个来源 IP 每分钟最多这么多次请求，超过的返回 429。只支持 caddy 网关。
   */
  rate_limit?: number | null;
  /**
   * 跳转：整个域名 301 到这个网址，保留路径和参数，例如 `https://a.com`。
   * 和 `service`、`upstream` 三选一。只支持 caddy 网关。
   */
  redirect?: string | null;
  /**
   * 目标服务。和 `upstream`、`redirect` 三选一。边缘应用的域名写在边缘应用的 `domains` 里。
   */
  service?: string;
  /**
   * 门禁。
   */
  sso?: SsoSpec | null;
  /**
   * 不归 Wharf 管的上游，写网关所在机器能访问到的 `主机:端口`，例如 `127.0.0.1:7700`。
   */
  upstream?: string | null;
}

export interface RouteView {
  core?: boolean;
  failover_pending?: FailoverPendingView | null;
  failover_pinned?: FailoverPinTarget | null;
  /**
   * 实际使用的网关（spec 里没填时是默认网关）。
   */
  gateway?: string | null;
  has_sealed_note?: boolean;
  id: string;
  note?: string | null;
  omitted?: Record<string, number>;
  /**
   * 当前生效入口是备用网关。
   */
  on_backup?: boolean;
  /**
   * 最近一次域名体检的 HTTP(S) 结果和连续失败次数；还没检查过时为空。
   */
  probe?: ProbeView | null;
  spec: RouteSpec;
  sso_login?: SsoLoginState | null;
  /**
   * 网关转发到的上游地址。
   */
  upstream?: string | null;
  url: string;
  version: number;
}

/**
 * 一次执行记录。
 */
export interface Run {
  actor?: string | null;
  finished_at?: string | null;
  plan_id: string;
  retry_of?: string | null;
  run_id: string;
  started_at: string;
  status: RunStatus;
  steps: RunStep[];
}

export type RunStatus = "running" | "succeeded" | "cancelled" | "failed";

export interface RunStep {
  error?: ApiError | null;
  finished_at?: string | null;
  /**
   * 对应的计划项 id。一个步骤可能完成多个计划项，例如配置写入。
   */
  items: number[];
  log?: string[];
  /**
   * 本步骤收到的日志总行数。
   */
  log_lines?: number;
  /**
   * 摘要日志只保留尾部；完整日志可另行读取。
   */
  log_truncated?: boolean;
  started_at?: string | null;
  status: StepStatus;
  title: string;
}

export type ScriptRuntime = "python" | "node" | "shell";

export interface SecretView {
  /**
   * 允许引用的服务。
   */
  allowed_services?: string[] | null;
  /**
   * 当前值的 8 位 SHA-256 指纹。
   */
  fingerprint?: string | null;
  /**
   * 是否保留了可回退的旧值。
   */
  has_previous?: boolean;
  /**
   * Wharf 自己生成的，不能改也不能删。
   */
  managed?: boolean;
  name: string;
  /**
   * 非服务引用方。
   */
  other_refs?: string[];
  prev_expires_at?: string | null;
  prev_fingerprint?: string | null;
  /**
   * 系统功能用的（网关登录、组网、通知等）：在对应功能里改，不算应用密钥。
   */
  system?: string | null;
  updated_at: string;
  /**
   * 用到它的服务。
   */
  used_by?: string[];
}

/**
 * 单台服务器的周期指标。
 */
export interface ServerReport {
  /**
   * CPU 均值（%）。
   */
  cpu_avg: MetricDelta;
  /**
   * CPU 峰值（%）。
   */
  cpu_peak: MetricDelta;
  /**
   * 周期内磁盘用量变化（字节，末值减初值）。
   */
  disk_change: MetricDelta;
  /**
   * 本期最新磁盘总量（字节）。
   */
  disk_total?: number | null;
  /**
   * 本期最新磁盘已用（字节）。
   */
  disk_used?: number | null;
  /**
   * 内存均值（字节）。
   */
  mem_avg: MetricDelta;
  /**
   * 内存峰值（字节）。
   */
  mem_peak: MetricDelta;
  /**
   * 整机内存容量（字节），用于判断峰值是否接近上限。
   */
  mem_total?: number | null;
  name: string;
  /**
   * 周期内网络接收总量（字节）。
   */
  net_rx_bytes: MetricDelta;
  /**
   * 周期内网络发送总量（字节）。
   */
  net_tx_bytes: MetricDelta;
  /**
   * 该对象的上期覆盖比例（0.0～1.0）。
   */
  previous_ratio?: number | null;
}

/**
 * 服务器上可以由用户修改的设置。IP 由 agent 上报，这里只是覆盖值。
 */
export interface ServerSettings {
  /**
   * agent 内存上限，例如 256M、1G，none 为不限，缺省为 256 MiB。
   */
  agent_memory?: string | null;
  /**
   * 机器基线：系统设置的期望值，agent 定时检查差异，apply 时纠正。
   */
  baseline?: Baseline;
  /**
   * 后台传输限速，例如 3M 或 500K。
   */
  bg_bwlimit?: string | null;
  /**
   * 构建时传给内置模板的参数，例如 `PIP_INDEX_URL`、`GOPROXY`（国内机器配镜像源）。
   */
  build_env?: Record<string, string>;
  /**
   * 这台提供出口：agent 在内网地址上起 HTTP 代理（要口令），规则决定哪些域名经它出去。
   */
  egress?: EgressSpec | null;
  /**
   * 拉代码、查 commit 时用的 HTTP 代理，例如 `http://<海外机器内网地址>:<端口>`。
   * 设了 `via` 时不用它。
   */
  git_proxy?: string | null;
  /**
   * 代替 `https://github.com/` 拉代码的地址，例如 `https://github.<域名>/[[MIRROR_TOKEN]]`
   * （wharf 的 mirror 服务）。可以用 `[[NAME]]` 引用密钥。
   */
  github_mirror?: string | null;
  /**
   * 允许通过 API 部署特权/host 网络/越界挂载容器、挂载宿主机路径的容器任务、操作未纳管容器，以及修改网关镜像和本地四层转发。
   */
  host_docker?: boolean;
  /**
   * 允许通过 API 在宿主机执行命令。
   */
  host_exec?: boolean;
  /**
   * 允许通过 API 修改服务器宿主机设置、纠正基线、配置 dockerd 代理/外网代理/Tailscale，以及查看监视宿主机 systemd 程序。
   */
  host_system?: boolean;
  /**
   * 允许从页面打开宿主机 root 终端。
   */
  host_terminal?: boolean;
  /**
   * 额外绑定的局域网地址（只能是 10/8、172.16/12、192.168/16）。镜像和代码来源服务的端口
   * 除了 127.0.0.1 和内网地址，也绑到这些地址上，在同一局域网里可以直接访问。
   * 机器之间互相访问仍走内网地址，不受影响。
   */
  lan_addrs?: string[];
  /**
   * 是否跳过原地址（例如国内机器访问不了 Docker Hub，直连只会白等）。
   */
  mirrors_only?: boolean;
  /**
   * 接入方式（design 2.10）。不填按检测到的地址推断。`tailscale` 且没检测到 Tailscale 时
   * 由 Wharf 装 Tailscale 容器并加入；`public` 不用内网地址，网关到这台一律走反向隧道。
   */
  network_mode?: NetworkMode | null;
  /**
   * 覆盖 agent 探测到的内网地址。没有组网工具、直接走内网时用它。
   */
  private_addr?: PrivateAddr | null;
  /**
   * 覆盖 agent 探测到的公网 IP。caddy 网关的 DNS 记录指向它。
   */
  public_ip?: string | null;
  /**
   * 拉镜像时 dockerd 用的 HTTP 代理，例如 `http://<海外机器内网地址>:<端口>`。设了 `via` 时不用它。
   * 写进宿主机的 /etc/docker/daemon.json；镜像源和内网地址直连，其余仓库（ghcr 等）走代理。
   */
  pull_proxy?: string | null;
  region?: Region | null;
  /**
   * 拉镜像时的镜像源，按顺序尝试，最后才尝试原地址。
   * 例如 `{ "docker.io" = ["docker.1ms.run"], "ghcr.io" = ["ghcr.nju.edu.cn"] }`。
   */
  registry_mirrors?: Record<string, string[]>;
  /**
   * 服务器续费日（`YYYY-MM-DD`，北京时间）。只用来提醒，不影响任何部署。
   */
  renew_at?: string | null;
  task_limits?: Limits | null;
  /**
   * 每月流量额度（GB），用于显示本期用了多少，用到 80% 时提醒（阈值在告警规则里改）。
   */
  traffic_quota_gb?: number | null;
  /**
   * 流量每月几号重置（1 到 28，按北京时间），不填是 1 号。
   */
  traffic_reset_day?: number | null;
  /**
   * 经哪台的出口出去（那台要设了 `egress`）：本机 agent 起分流代理，
   * dockerd 拉镜像、构建、拉代码都经它，按出口的规则分流，出口连不上时直连。
   */
  via?: string | null;
}

export interface ServerView {
  agent: AgentUsage;
  /**
   * agent 的构建号和控制面不一致，可以 `wharf server upgrade`。
   */
  agent_outdated?: boolean;
  /**
   * 最近一次检查和基线不一样的项（每 6 小时检查一次）。
   */
  baseline_drift?: string[];
  /**
   * 和控制面的时间差（毫秒，agent 比控制面快为正）。旧 agent 没有。
   */
  clock_offset_ms?: number | null;
  /**
   * 按近 7 天趋势预计几天后磁盘写满；数据不足或没在增长时没有。
   */
  disk_days_left?: number | null;
  has_sealed_note?: boolean;
  /**
   * 当前连接的 agent 支持宿主机终端和命令执行。
   */
  host_shell?: boolean;
  /**
   * agent 是否已经加入（完成过 join）。
   */
  joined: boolean;
  /**
   * 当前已注册 agent 公钥的 12 位指纹。
   */
  key_fingerprint?: string | null;
  key_rotation?: boolean;
  last_seen?: string | null;
  name: string;
  note?: string | null;
  omitted?: Record<string, number>;
  online: boolean;
  /**
   * 实际使用的内网地址：设置里的覆盖值，否则是 agent 检测到的组网地址。
   */
  private_addr?: PrivateAddr | null;
  /**
   * 实际使用的公网 IP：设置里的覆盖值，否则是 agent 探测值。
   */
  public_ip?: string | null;
  /**
   * agent 最近一次上报。
   */
  report?: AgentReport | null;
  /**
   * 控制面到 agent 的往返延迟（websocket ping），毫秒。
   */
  rtt_ms?: number | null;
  settings: ServerSettings;
  tailnet_key?: TailnetKey | null;
  version: number;
}

/**
 * 按服务的内置告警规则覆盖。
 */
export interface ServiceAlertOverrideView {
  enabled?: boolean | null;
  for_n?: number | null;
  level?: AlertLevel | null;
  muted_until?: number | null;
  rule: string;
  service: string;
  threshold?: number | null;
}

export interface ServiceData {
  /**
   * 只在这个时间比最近成功晚时才有，也就是最近一次尝试失败了。
   */
  last_failed?: string | null;
  last_ok?: string | null;
  mounts: DataMount[];
  name: string;
  repo_empty?: boolean;
  /**
   * 数据所在的服务器。
   */
  server: string;
  status: DataStatus;
  /**
   * 备份存到哪台服务器，没开备份时为空。
   */
  target?: string | null;
}

/**
 * 从 `docker run` 命令转出的服务配置草稿，还没选服务器。
 * 端口、环境变量、数据卷、资源上限能表达的转成镜像来源，用了别的参数时转成 compose 来源。
 */
export interface ServiceDraft {
  env?: Record<string, string>;
  limits?: Limits | null;
  name: string;
  ports?: PortSpec[];
  source: Source;
  volumes?: VolumeSpec[];
  /**
   * 转换时改动或没认出的地方，要给用户看。
   */
  warnings?: string[];
}

export interface ServiceExecResponse {
  container: string;
  duration_ms: number;
  exit_code: number;
  server: string;
  service: string;
  stderr: string;
  stdout: string;
  truncated: boolean;
}

export interface ServiceRenderView {
  compose: string;
  init_cmd?: string | null;
  secrets_masked?: string[];
  server: string;
  service: string;
  source: string;
  warnings?: string[];
}

/**
 * 单个服务的周期指标。
 */
export interface ServiceReport {
  /**
   * CPU 均值（%）。
   */
  cpu_avg: MetricDelta;
  /**
   * 5xx 占比均值（%）。
   */
  err_pct: MetricDelta;
  /**
   * 内存均值（字节）。
   */
  mem_avg: MetricDelta;
  /**
   * 配置的内存上限（字节）。
   */
  mem_limit?: number | null;
  /**
   * 内存峰值（字节）。
   */
  mem_peak: MetricDelta;
  name: string;
  /**
   * p95 延迟均值（毫秒）。
   */
  p95_ms: MetricDelta;
  /**
   * 该对象的上期覆盖比例（0.0～1.0）。
   */
  previous_ratio?: number | null;
  /**
   * 经网关的总请求数估算。
   */
  requests: MetricDelta;
  server: string;
}

export interface ServiceSpec {
  /**
   * 自动更新：每天检查一次，有新版本就自动更新。只支持没有数据卷的服务（compose 来源看 compose 里有没有挂载）。
   */
  auto_update?: boolean;
  /**
   * 每天自动备份 `/srv/<服务>/` 到另一台服务器（restic）。
   */
  backup?: BackupSpec | null;
  cap_add?: string[];
  command?: string[] | null;
  /**
   * compose 来源：环境变量、资源上限和配置文件加在哪个容器上。只有一个容器时不用填。
   */
  container?: string | null;
  container_limits?: Record<string, Limits>;
  /**
   * 环境变量。值里可以用 `[[SECRET_NAME]]` 引用密钥；compose 来源加到 `container` 指定的容器上，
   * compose 文件内容也会做同样的替换。
   * 也可以用 `[[@服务]]` 引用别的服务，部署时换成它的 `内网地址:宿主机端口`；
   * `[[@服务.端口名]]` 指定端口，末尾加 `:host` / `:port` 只取地址或端口。
   */
  env?: Record<string, string>;
  /**
   * 配置文件：内容存在 Wharf 里，部署时放进容器（只读，属主 root），跟着部署历史和回滚走。
   * 应用自己改写的内容下次部署会被覆盖。
   */
  files?: FileSpec[];
  group_add?: string[];
  heartbeat?: HeartbeatSpec | null;
  hostname?: string | null;
  init?: boolean | null;
  /**
   * 部署前在临时容器内执行的初始化命令。
   */
  init_cmd?: string | null;
  /**
   * 初始化超时秒数（10 到 1800），缺省 300 秒。
   */
  init_timeout_secs?: number | null;
  /**
   * 资源上限，不填不限。
   */
  limits?: Limits | null;
  log_alerts?: LogAlertSpec[];
  log_max?: LogMax | null;
  /**
   * 自定义监控：服务所在机器的 agent 每分钟从本机请求一次，连续 3 次不正常推送。
   */
  monitor?: MonitorSpec | null;
  port_checks?: Record<string, PortCheckSpec>;
  ports?: PortSpec[];
  pull_policy?: ImagePullMode | null;
  /**
   * 运行在哪台服务器上。
   */
  server: string;
  shm_size?: number | null;
  source: Source;
  /**
   * 启动等待上限（秒），缺省 120。
   */
  start_timeout_secs?: number | null;
  /**
   * 容器优雅停机等待秒数（1 到 600），缺省用 Docker 默认。
   */
  stop_grace_secs?: number | null;
  /**
   * 容器停机信号，缺省用镜像默认。
   */
  stop_signal?: string | null;
  /**
   * 停止：容器保留但不运行，部署后也保持停止。不影响 compose，也就不会重建容器。
   */
  stopped?: boolean;
  timezone?: string | null;
  tmpfs?: Record<string, number>;
  ulimits?: Record<string, Ulimit>;
  /**
   * 镜像和构建版本的更新忽略规则。
   */
  update_ignore?: UpdateIgnoreSpec[];
  volumes?: VolumeSpec[];
}

/**
 * 服务的分层状态：期望、已应用、实际、健康、执行，加上按优先级挑出的一句话。
 */
export interface ServiceStatus {
  /**
   * 实际：容器现状。
   */
  actual: Actual;
  /**
   * 实际：容器上标记的哈希。
   */
  actual_hash?: string | null;
  /**
   * 已应用：上次成功部署。
   */
  applied?: Applied | null;
  /**
   * 期望：当前配置生成的 compose 哈希；缺密钥等算不出时为空。
   */
  desired_hash?: string | null;
  /**
   * 查不到现状时的原因。
   */
  error?: string | null;
  health: Health;
  /**
   * 执行：最近一次和这个服务有关的部署、启停、重启、迁移、恢复。
   */
  last_op?: LastOp | null;
  missing_components?: string[];
  /**
   * 最后一次成功查到这台服务器现状的时间；服务器离线时就是"多久前看到的"。
   */
  observed_at?: string | null;
  /**
   * 一句话，例如"运行中"、"部署失败"、"服务器离线"。
   */
  summary: string;
  tone: Tone;
  /**
   * 期望：按配置应该在运行（`stopped` 时为 false）。
   */
  want_running: boolean;
}

export interface ServiceView {
  /**
   * 服务之间互相访问用的地址（内网地址:宿主机端口），例如 `100.101.102.103:20001`。
   */
  addresses: Record<string, string>;
  /**
   * 容器现状，查不到时为空；状态看 `status`。
   */
  containers?: ContainerInfo[];
  /**
   * 服务挂载的数据和归属，从配置里算出来。
   */
  data?: DataMount[];
  has_sealed_note?: boolean;
  /**
   * 后台版本检查发现新镜像、commit 或版本标签。
   */
  has_update?: boolean;
  heartbeat?: HeartbeatView | null;
  /**
   * 端口名到宿主机端口。
   */
  host_ports: Record<string, number>;
  /**
   * 从服务器上已有的容器导入时的记录。
   */
  import?: ImportRecord | null;
  /**
   * 局域网地址：端口名 → 各个局域网地址:宿主机端口（服务器设置了 lan_addrs 时才有）。
   */
  lan_addresses?: Record<string, string[]>;
  log_alerts?: LogAlertView[];
  migration?: MigrationView | null;
  /**
   * 自定义监控的最近一次结果；没配监控或还没检查过时为空。
   */
  monitor?: MonitorView | null;
  name: string;
  /**
   * 备注：给人看的说明，不影响部署。
   */
  note?: string | null;
  omitted?: Record<string, number>;
  port_checks?: Record<string, boolean>;
  /**
   * 在线 agent 是否支持端口探测，能力未知时为空。
   */
  port_checks_supported?: boolean | null;
  risks?: string[];
  spec: ServiceSpec;
  /**
   * 分层状态；只读配置、不查现状时为空。
   */
  status?: ServiceStatus | null;
  /**
   * 被哪些服务引用。
   */
  used_by?: string[];
  /**
   * 用 `[[@服务]]` 引用了哪些服务。
   */
  uses?: string[];
  version: number;
}

/**
 * 页面登录设备。
 */
export interface SessionRow {
  addr: string | null;
  agent: string | null;
  created_at: number;
  current: boolean;
  id: string;
  last_seen_at: number | null;
}

export interface ShellLog {
  actor: string;
  at: string;
  command?: string | null;
  duration_ms?: number | null;
  error?: string | null;
  exit_code?: number | null;
  id: number;
  kind: string;
  output_bytes?: number | null;
  server: string;
}

export interface Snapshot {
  hostname: string;
  id: string;
  keep?: boolean;
  note?: string | null;
  paths: string[];
  short_id: string;
  tags?: string[];
  time: string;
}

/**
 * 服务来源，三选一。git 来源在 P4。
 * 
 * 意图文件里写作 `source = { image = "traefik/whoami" }` 或
 * `source = { compose = { file = "blog.yaml" } }`。
 */
export type Source = {
  image: string;
} | {
  compose: {
  content?: string | null;
  file?: string | null;
};
} | {
  build: BuildSource;
};

export interface SshLogin {
  at: string;
  from: string;
  /**
   * 认证方式，例如 publickey、password。
   */
  method: string;
  user: string;
}

export interface SsoLoginState {
  at: number;
  error: string | null;
  ok: boolean;
}

export type SsoMode = "gate" | "header" | "login" | "oidc";

export interface SsoSpec {
  header?: string | null;
  login?: LoginSpec | null;
  mode: SsoMode;
  /**
   * oidc 方式：应用用 Wharf 账号登录（Wharf 当 OIDC 身份提供方）。
   */
  oidc?: OidcClientSpec | null;
  /**
   * 公开站点：不加门禁，所有人都能访问。login 方式只提供 `/_wharf/login`
   * 入口，主人从入口登录 Wharf 后代登录进应用；oidc 方式由应用自己决定哪里要登录。
   * 只能和 login、oidc 方式一起用。
   */
  public?: boolean;
  /**
   * 不过门禁的路径前缀。
   */
  skip_paths?: string[];
  trust_internal?: boolean;
}

export interface SsoStepResult {
  error: string | null;
  extracted: Record<string, number>;
  method: string;
  ms: number;
  number: number;
  path: string;
  status: number | null;
}

export interface SsoTestResult {
  check: SsoStepResult | null;
  ok: boolean;
  script_log?: string | null;
  steps: SsoStepResult[];
  would_write: string[];
}

export interface Status {
  bookmarks: BookmarkView[];
  edge_apps: EdgeAppView[];
  /**
   * 厂商账号里还没纳管的 Workers / Pages（来自最近一次同步）。
   */
  edge_unmanaged: EdgeProjectView[];
  gateways: GatewayView[];
  /**
   * 最近一次域名检查（后台每 5 分钟），控制面刚启动时为空。
   */
  health?: DoctorReport | null;
  issues: Issue[];
  /**
   * 需要注意的问题，例如服务器离线、服务没在运行。
   */
  problems?: string[];
  routes: RouteView[];
  safe_mode: boolean;
  servers: ServerView[];
  services: ServiceView[];
  /**
   * 后台检查的新版本和未执行的改动，控制面刚启动时为空。
   */
  updates?: UpdatesView | null;
}

export type StepStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface TailnetKey {
  expires: string | null;
  never_expires: boolean;
}

export interface TailnetRelay {
  from: string;
  relay: string;
  to: string;
}

export interface TaskArtifact {
  path: string;
  sha256: string;
  size: number;
}

export type TaskKind = {
  command: string;
  /**
   * compose 服务名，服务只有一个容器时不用填。
   */
  container?: string | null;
  kind: "exec";
  service: string;
} | {
  command?: string | null;
  env?: Record<string, string>;
  image: string;
  kind: "container";
  mounts?: string[];
} | {
  code: string;
  deps?: string;
  env?: Record<string, string>;
  hook?: string | null;
  image?: string | null;
  kind: "script";
  runtime: ScriptRuntime;
} | {
  command: string;
  kind: "host";
} | {
  grace_mins: number;
  kind: "ping";
  /**
   * 报到地址里的口令，新建时自动生成。
   */
  token: string;
};

export interface TaskRunView {
  artifacts?: TaskArtifact[];
  ended_at?: string | null;
  exit_code?: number | null;
  id: number;
  mem_peak?: number | null;
  /**
   * 输出的最后 16 KB，密钥值已换成 `***`；出错时是错误信息。
   */
  output: string;
  service?: string | null;
  started_at: string;
  status: TaskStatus;
  task: string;
  /**
   * 定时触发还是手动（`manual`）。
   */
  trigger: string;
}

/**
 * 定时任务。名字全局唯一。
 */
export type TaskSpec = ({
  command: string;
  /**
   * compose 服务名，服务只有一个容器时不用填。
   */
  container?: string | null;
  kind: "exec";
  service: string;
} | {
  command?: string | null;
  env?: Record<string, string>;
  image: string;
  kind: "container";
  mounts?: string[];
} | {
  code: string;
  deps?: string;
  env?: Record<string, string>;
  hook?: string | null;
  image?: string | null;
  kind: "script";
  runtime: ScriptRuntime;
} | {
  command: string;
  kind: "host";
} | {
  grace_mins: number;
  kind: "ping";
  /**
   * 报到地址里的口令，新建时自动生成。
   */
  token: string;
}) & {
  artifacts_keep?: number | null;
  artifacts_max_mb?: number | null;
  /**
   * 错过触发后允许补跑的分钟数。
   */
  catch_up_mins?: number | null;
  enabled: boolean;
  inherit_server_limits?: boolean;
  limits?: Limits | null;
  /**
   * 失败和恢复时发通知。
   */
  notify: boolean;
  /**
   * 5 段 cron（分 时 日 月 周），北京时间。
   */
  schedule: string;
  server: string;
  /**
   * 关联服务停用时跳过定时执行。
   */
  skip_if_stopped?: boolean;
  /**
   * 超时秒数，默认 600；宿主机命令最长 600，其他最长 6 小时。
   */
  timeout_secs: number;
};

export type TaskStatus = "running" | "succeeded" | "failed" | "timed_out" | "skipped" | "cancelled";

export interface TaskView {
  data_bytes?: number | null;
  hook_url?: string | null;
  last?: TaskRunView | null;
  migrating?: boolean;
  name: string;
  /**
   * 下次运行时间；停用时没有。
   */
  next_at?: string | null;
  /**
   * 外部报到任务的报到地址：成功请求它，失败请求它加 `/fail`。
   */
  ping_url?: string | null;
  spec: TaskSpec;
  target_server?: string | null;
  updated_at: string;
}

export interface Timeline {
  items: TimelineItem[];
  /**
   * 还有更早的记录时，下一页用它作 `before`。
   */
  next_before: number | null;
}

/**
 * 服务时间线上的一条。
 */
export interface TimelineItem {
  /**
   * 只有 op 有：谁做的。
   */
  actor?: string | null;
  at: number;
  /**
   * deploy / backup / task / heal / alert / op / auto_update
   */
  kind: string;
  /**
   * 成功还是失败；没有这个概念的（自动重启）为空。
   */
  ok: boolean | null;
  title: string;
}

export interface TokenExplain {
  from: string | null;
  items: TokenExplainItem[];
  service: string | null;
  token: string;
}

export interface TokenExplainItem {
  method: string;
  op: string;
  path: string;
  perm: Perm | null;
  reason: string | null;
  verdict: ExplainVerdict;
}

export interface TokenSettings {
  allowed_from: string[];
  expires_at: string | null;
  perms: Perm[];
  services: string[];
}

export interface TokenView {
  allowed_from: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at?: string | null;
  name: string;
  perms: Perm[];
  services: string[];
}

/**
 * 页面上的颜色。
 */
export type Tone = "ok" | "warn" | "bad" | "idle";

export interface TotpView {
  enabled: boolean;
  recovery_left: number;
}

/**
 * Caddy 网关的可信上游代理配置。
 */
export interface TrustedProxiesSpec {
  /**
   * 额外手动指定的可信代理 IP 或 CIDR（如前置 CDN 或局域网反代）。
   */
  cidrs?: string[];
  /**
   * 自动同步并信任 Cloudflare 官方回源网段（IPv4 + IPv6）。
   */
  cloudflare?: boolean;
  /**
   * 自动包含本集群所有网关和组网服务器的实际地址（精确 /32 或 /128）。
   */
  cluster?: boolean;
}

export interface Ulimit {
  hard: number;
  soft: number;
}

/**
 * `GET /api/servers/{name}/unmanaged`：服务器上还没纳管的一组容器，
 * 是一个 compose 项目或一个 `docker run` 起的容器。
 */
export interface Unmanaged {
  container?: string | null;
  containers: FoundContainer[];
  ignored: boolean;
  /**
   * 导入时默认的服务名。
   */
  name: string;
  project?: string | null;
  server: string;
}

export type UpdateIgnoreScope = "all" | "major";

export interface UpdateIgnoreSpec {
  /**
   * 镜像仓库名、完整镜像标签，或 *。
   */
  image: string;
  scope: UpdateIgnoreScope;
}

/**
 * 后台检查：镜像标签、代码分支有没有比固定版本新的（每 6 小时），
 * 现在的配置和机器上的现状差几项（每 10 分钟算一次计划，不保存）。
 */
export interface UpdatesView {
  pending?: PendingCheck | null;
  /**
   * 服务 → 版本检查结果，只有 image 和 git 构建来源的服务。
   */
  services: Record<string, VersionCheck>;
}

export type Upstream = "docker_hub" | "git_hub" | "cloudflare";

export type UsageKind = "service" | "gateway" | "agent";

export interface UsageRow {
  cpu: number | null;
  kind: UsageKind;
  mem: number | null;
  memory_limit: number | null;
  memory_pct: number | null;
  name: string;
  net_rx: number | null;
  net_tx: number | null;
  server: string;
}

export interface VersionCheck {
  at: string;
  /**
   * 这次没查到时的原因，`newer` 沿用上一次的结果。
   */
  error?: string | null;
  images?: Record<string, ImageVersionCheck>;
  /**
   * 查到的最新版本（镜像 digest 或 commit）。
   */
  latest?: string | null;
  /**
   * 仓库里有比固定版本新的。
   */
  newer: boolean;
  /**
   * 有新 digest 的镜像名。
   */
  newer_images?: string[];
  /**
   * 仓库里有比现在写的标签更高的版本（例如 `2.20` → `2.21`）。换标签要改配置，不会自动升级。
   */
  tags?: NewerTag[];
}

/**
 * 目录挂载：宿主机 `/srv/<service>/<name>/` 挂到容器内 `target`。
 */
export interface VolumeSpec {
  /**
   * 同机拥有者的托管卷，格式为 <服务名>:<卷名>。
   */
  from_service?: string | null;
  /**
   * 本地卷名。共享卷省略时取拥有者的卷名。
   */
  name?: string;
  read_only?: boolean;
  target: string;
}
