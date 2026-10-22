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
  /// 构建时传给内置模板的参数，例如 `PIP_INDEX_URL`、`GOPROXY`（国内机器配镜像源）。
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub build_env: BTreeMap<String, String>,
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
#[allow(clippy::large_enum_variant)]
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
  /// 从代码构建镜像（在服务所在的服务器上 `docker build`），其余和 image 来源一样。
  Build(BuildSource),
}

/// 代码来源：本机目录（CLI 打包上传）或 git 仓库，二选一。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct BuildSource {
  /// CLI 上传到控制面的代码包（tar.gz）的 sha256。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upload: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git: Option<GitSource>,
  /// 代码里的子目录，作为构建目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  /// Dockerfile 路径（相对构建目录）。不填时有 `Dockerfile` 就用，没有就按语言用内置模板。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile: Option<String>,
  /// 内置模板的基础镜像，例如 `python:3.12-slim`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub base: Option<String>,
  /// 内置模板的启动命令，例如 `uvicorn main:app --host 0.0.0.0 --port $PORT`。
  /// 可以多行（启动脚本），用 `sh -c` 执行。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start: Option<String>,
  /// 内置模板：`python` / `node` / `go` / `static`，不填时按文件识别。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub template: Option<String>,
  /// 覆盖内置模板安装依赖的命令（Python、Node），例如 `npm ci && npm run build`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub install: Option<String>,
  /// 存在 Wharf 里的 Dockerfile 内容，优先于代码里的 Dockerfile 和模板。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub dockerfile_content: Option<String>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GitSource {
  /// https 地址，例如 `https://github.com/owner/repo`。
  pub repo: String,
  /// 分支、标签或 commit。
  #[serde(rename = "ref")]
  pub reference: String,
  /// 私有仓库：保存访问 token 的密钥名（`wharf secret set`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token_secret: Option<String>,
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
  /// 每天自动备份 `/srv/<服务>/` 到另一台服务器（restic）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub backup: Option<BackupSpec>,
}

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct BackupSpec {
  /// 备份存到哪台服务器，不能是服务所在的服务器。
  pub to: String,
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
  /// Wharf 在厂商账号下创建隧道，服务器上跑 cloudflared，不需要公网 IP 和开放端口。
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
  /// cloudflare_tunnel：在哪个厂商账号下建隧道（`wharf account list`）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub account: Option<String>,
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
  /// 目标服务或边缘应用。和 `upstream` 二选一。
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub service: String,
  /// 不归 Wharf 管的上游，写网关所在机器能访问到的 `主机:端口`，例如 `127.0.0.1:7700`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
  /// 目标端口名。服务只有一个端口时可以不填；边缘应用不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 入口网关。不填则用默认网关；边缘应用的域名不经过网关，不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub gateway: Option<String>,
  /// 登录保护（P3）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub auth: bool,
  /// 按路径转发到别的上游，其余路径仍到 `service`。只支持 caddy 网关。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub paths: Vec<PathRoute>,
}

/// 路由里的一条路径转发。`service` 和 `upstream` 二选一。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PathRoute {
  /// Caddy 的路径匹配：`/ws` 只匹配这个路径，`/api/*` 匹配前缀。
  pub path: String,
  /// 目标服务。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub service: Option<String>,
  /// 目标端口名，服务只有一个端口时可以不填。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub port: Option<String>,
  /// 不归 Wharf 管的上游，例如网关所在机器上的 `127.0.0.1:17891`。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upstream: Option<String>,
}

/// 边缘应用的种类。
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
pub enum EdgeKind {
  /// Cloudflare Workers。
  Worker,
  /// Cloudflare Pages。
  Pages,
}

impl EdgeKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Worker => "worker",
      Self::Pages => "pages",
    }
  }
}

/// 边缘应用的代码来源。和服务的构建来源一样，代码来自本机目录上传或 git。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct EdgeSource {
  /// 本机目录上传到控制面的代码包 sha256（`wharf edge deploy` 自动填）。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub upload: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub git: Option<GitSource>,
  /// 代码里的子目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  /// worker：单文件脚本（相对代码目录）。直接调用厂商接口上传，
  /// 保留面板里配置的变量和绑定。不填时按 wrangler 项目发布。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub script: Option<String>,
  /// pages：构建命令，例如 `npm run build`。不填就是静态目录。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub build: Option<String>,
  /// pages：要发布的目录（相对代码目录）。不填时有构建命令用 `dist`，否则用代码目录本身。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub output: Option<String>,
}

/// 边缘应用：Cloudflare Workers / Pages。没有端口、数据卷、迁移、备份。
#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct EdgeAppSpec {
  /// 厂商账号。
  pub account: String,
  pub kind: EdgeKind,
  /// 厂商那边的脚本名 / 项目名。不填时等于边缘应用的名字。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub project: Option<String>,
  /// 不填表示只纳管：Wharf 显示状态、管域名、回滚，不发布代码。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub source: Option<EdgeSource>,
  /// 在哪台服务器上执行 wrangler（构建 Pages、发布 wrangler 项目）。不填时自动选，优先海外。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub builder: Option<String>,
}

impl EdgeAppSpec {
  /// 厂商那边的名字。
  pub fn project_name<'a>(&'a self, name: &'a str) -> &'a str {
    self.project.as_deref().unwrap_or(name)
  }
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
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub edge_apps: BTreeMap<String, EdgeAppSpec>,
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
  UpsertEdgeApp {
    name: String,
    spec: EdgeAppSpec,
  },
  /// 只是不再纳管，不删除厂商那边的 Worker / Pages 项目。
  RemoveEdgeApp {
    name: String,
  },
}
