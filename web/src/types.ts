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

export type Source =
  | { image: string }
  | { compose: { content?: string; file?: string } };

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
  containers: ContainerInfo[];
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

export interface Status {
  servers: ServerView[];
  services: ServiceView[];
  gateways: GatewayView[];
  routes: RouteView[];
  problems: string[];
}

export interface AccountView {
  name: string;
  kind: string;
  zones: string[];
}

export type Change =
  | { op: "upsert_service"; name: string; spec: ServiceSpec }
  | { op: "remove_service"; name: string }
  | { op: "upsert_gateway"; name: string; spec: GatewaySpec }
  | { op: "remove_gateway"; name: string }
  | { op: "upsert_route"; spec: RouteSpec }
  | { op: "remove_route"; hostname: string };

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
  log: string[];
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
