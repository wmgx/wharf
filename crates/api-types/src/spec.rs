//! 期望配置。字段与设计文档第 2 节一一对应。
//!
//! 资源名不放在 spec 里，由外层的 key（fleet.toml 的表名、API 路径）给出，
//! 这样意图文件里不会出现"名字写了两遍还不一致"的问题。

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
pub enum Region {
  Cn,
  Overseas,
}

/// 服务器上可以由用户修改的设置。IP 由 agent 上报，这里只是覆盖值。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub region: Option<Region>,
  /// 覆盖 agent 探测到的公网 IP。caddy 网关的 DNS 记录指向它。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub public_ip: Option<String>,
  /// 拉镜像时的镜像源，按顺序尝试，最后才尝试原地址。
  /// 例如 `{ "docker.io" = ["docker.1ms.run"], "ghcr.io" = ["ghcr.nju.edu.cn"] }`。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub registry_mirrors: BTreeMap<String, Vec<String>>,
  /// 是否跳过原地址（例如国内机器访问不了 Docker Hub，直连只会白等）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub mirrors_only: bool,
  /// 覆盖 agent 探测到的内网地址。没有组网工具、直接走内网时用它。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub private_addr: Option<PrivateAddr>,
}

/// 服务器之间互相访问用的地址：网关跨机器访问服务时连它，
/// 服务端口除了 127.0.0.1 也只绑定它。
///
/// Wharf 不负责打洞，组网交给专门的工具；这里只记地址在哪个网络、
/// 网络本身是否加密。
#[derive(
  Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PrivateAddr {
  pub ip: String,
  pub network: PrivateNetwork,
}

/// 内网地址所在的网络。
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
pub enum PrivateNetwork {
  /// Tailscale 或 Headscale（同一个客户端），agent 自动检测。加密。
  Tailscale,
  /// 其他加密组网：WireGuard、ZeroTier、Netbird 等，手动指定。
  Overlay,
  /// 普通内网直连（公司内网、云厂商 VPC、家里局域网）。明文。
  Lan,
}

impl PrivateNetwork {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Tailscale => "tailscale",
      Self::Overlay => "overlay",
      Self::Lan => "lan",
    }
  }

  /// 网络本身是否加密。不加密时，跨机器的流量是明文。
  pub fn encrypted(self) -> bool {
    self != Self::Lan
  }
}

/// 服务来源，三选一。git 来源在 P4。
///
/// 意图文件里写作 `source = { image = "traefik/whoami" }` 或
/// `source = { compose = { file = "blog.yaml" } }`。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
  /// 单个镜像，系统自动生成只有一个服务的 compose。
  Image(String),
  /// 完整的 compose 文件内容。CLI 和意图文件也可以写 `file = "路径"`，
  /// 由 CLI 读出内容后再提交。
  Compose {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
  },
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PortSpec {
  /// 端口名，路由用它指定目标端口，例如 `http`。
  pub name: String,
  /// image 来源：容器内端口；compose 来源：compose 里已经发布的宿主机端口。
  pub port: u16,
  /// 仅 image 来源：指定宿主机端口。不填则由系统从 20000 起自动分配。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub host_port: Option<u16>,
}

/// 目录挂载：宿主机 `/srv/<service>/<name>/` 挂到容器内 `target`。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct VolumeSpec {
  pub name: String,
  pub target: String,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
  /// 运行在哪台服务器上。
  pub server: String,
  pub source: Source,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ports: Vec<PortSpec>,
  /// 环境变量。值里可以用 `[[SECRET_NAME]]` 引用密钥，仅 image 来源生效；
  /// compose 来源的整个文件内容都会做同样的替换。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub env: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub volumes: Vec<VolumeSpec>,
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
pub enum GatewayKind {
  Caddy,
  /// P3。
  CloudflareTunnel,
}

impl GatewayKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Caddy => "caddy",
      Self::CloudflareTunnel => "cloudflare_tunnel",
    }
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GatewaySpec {
  pub kind: GatewayKind,
  /// 网关跑在哪台服务器上。
  pub server: String,
  /// 默认入口：添加路由时不选网关就用它。最多一个。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub default: bool,
  /// caddy：HTTP 端口，默认 80。改端口只用于测试，签证书需要 80。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub http_port: Option<u16>,
  /// caddy：HTTPS 端口，默认 443。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub https_port: Option<u16>,
  /// caddy：ACME 账号邮箱，可选。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub email: Option<String>,
  /// caddy：镜像，默认 `caddy:2`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub image: Option<String>,
  /// caddy：证书方式，默认 `auto`（公网签证书）。
  #[serde(default, skip_serializing_if = "GatewayTls::is_auto")]
  pub tls: GatewayTls,
}

/// 网关的证书方式。
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GatewayTls {
  /// 自动向 Let's Encrypt 等申请证书，需要公网可达的域名。
  #[default]
  Auto,
  /// Caddy 自签证书，浏览器会提示不受信任。用于内网。
  Internal,
  /// 只走 HTTP，不用证书。用于内网演示。
  Off,
}

impl GatewayTls {
  pub fn is_auto(&self) -> bool {
    *self == Self::Auto
  }
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
  /// 例如 `blog.example.com`。
  pub hostname: String,
  /// 目标服务。
  pub service: String,
  /// 目标端口名。服务只有一个端口时可以不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 入口网关。不填则用默认网关。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub gateway: Option<String>,
  /// 登录保护（P3）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub auth: bool,
}

/// 意图文件 fleet.toml 的全部内容。plan 时作为完整期望状态：
/// 文件里没有的服务、网关、路由会被计划删除。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Fleet {
  /// 服务器设置。服务器本身通过 `wharf server add` 加入，不在这里创建或删除。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub servers: BTreeMap<String, ServerSettings>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub services: BTreeMap<String, ServiceSpec>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub gateways: BTreeMap<String, GatewaySpec>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub routes: Vec<RouteSpec>,
}

/// 对期望状态的局部修改。CLI 的 `service deploy`、`route add` 等命令都生成它。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
  /// 服务器必须已经 `wharf server add` 过。
  UpdateServer {
    name: String,
    settings: ServerSettings,
  },
  UpsertService {
    name: String,
    spec: ServiceSpec,
  },
  RemoveService {
    name: String,
  },
  UpsertGateway {
    name: String,
    spec: GatewaySpec,
  },
  RemoveGateway {
    name: String,
  },
  UpsertRoute {
    spec: RouteSpec,
  },
  RemoveRoute {
    hostname: String,
  },
}
