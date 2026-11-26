//! 由期望状态渲染出 compose 文件和 Caddyfile。纯函数，不碰网络和数据库。

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError,
  agent::{BUILD_IMAGE_PREFIX, TRIAL_PROJECT_PREFIX},
  spec::{
    BuildSource, GatewayKind, GatewaySpec, GatewayTls, LoginTakeover,
    PortSpec, PrivateAddr, ServiceSpec, Source,
  },
};

use crate::world::{ServerRow, World, gateway_project};

mod frp;
mod gate;

pub use frp::{frpc_compose, frps_compose};

/// 网关默认镜像：官方 Caddy 加 layer4、限速、Cloudflare DNS 插件（deploy/caddy/Dockerfile）。
/// 标签只在 Caddy 或插件版本变化时改，改了会重建所有没指定镜像的 caddy 网关。
pub const DEFAULT_CADDY_IMAGE: &str =
  "ghcr.io/wmgx/wharf-caddy:2.11.9-9";

/// Caddyfile 里 acme-dns 密码的占位，执行时换成入口的密钥。
pub const ACME_DNS_KEY: &str = "[[WHARF_ACME_DNS_KEY]]";
/// Caddyfile 里控制面地址的占位，执行时换成 join::default_url。
pub const ACME_DNS_URL: &str = "[[WHARF_ACME_DNS_URL]]";
pub const DEFAULT_CLOUDFLARED_IMAGE: &str =
  "cloudflare/cloudflared:2026.9.3";
/// 隧道连接器 compose 里 token 的占位，执行时才替换，不进计划、不算进哈希。
pub const TUNNEL_TOKEN_SECRET: &str = "WHARF_TUNNEL_TOKEN";
/// 和 agent 里的 `CADDY_ADMIN` 一致：管理接口走 unix socket，不占端口。
const CADDY_ADMIN: &str = "unix//config/caddy-admin.sock";
const UPSTREAM_TRY_DURATION: &str = "8s";
const UPSTREAM_TRY_INTERVAL: &str = "250ms";
pub const SCANNER_PATHS: &str = "/.env /.env.* /.git/* /.svn/* /.aws/* /.DS_Store /wp-login.php /wp-admin /wp-admin/* /xmlrpc.php /phpmyadmin/* /vendor/phpunit/* /cgi-bin/* /boaform/* /HNAP1";
pub const SCANNER_UA: &str = "(?i)(sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|ffuf|feroxbuster|acunetix|netsparker)";

pub fn hash(content: &str) -> String {
  hex::encode(Sha256::digest(content.as_bytes()))
}

/// 每台服务器的网络信息，来自 agent 上报和服务器设置。
#[derive(Debug, Clone, Default)]
pub struct Net {
  pub gate_public: Option<String>,
  pub gate_login: Option<String>,
  pub heartbeat_url: Option<String>,
  /// 实际使用的内网地址：服务器设置的覆盖值，否则是 agent 检测到的组网地址。
  pub private: BTreeMap<String, PrivateAddr>,
  pub reported_private: BTreeMap<String, PrivateAddr>,
  pub docker_subnets: BTreeMap<String, Vec<String>>,
  pub cloudflare_ips: Vec<String>,
  pub tailnet_ips: Vec<ipnet::IpNet>,
  /// agent 上报的其他网卡地址，用来在缺内网地址时给出建议命令。
  pub lan_ips: BTreeMap<String, Vec<String>>,
  /// 服务器设置里额外绑定的局域网地址。
  pub lan_addrs: BTreeMap<String, Vec<String>>,
  pub public_ip: BTreeMap<String, String>,
  /// 连通性探测结果：(网关所在机器, 服务所在机器) → 能否直连内网地址。没探测过的不在里面。
  pub reach: crate::db::Reach,
  /// 登录保护的账号，按密钥名（每个域名的 [route_auth_secret]）。
  /// 不是网络信息，但渲染网关时要用，放在这里不必到处传。
  pub basic_auth: BTreeMap<String, BasicAuth>,
  pub link_ca_cert: Option<String>,
  pub link_token_hashes: BTreeMap<String, String>,
  pub link_certs: BTreeMap<String, crate::link_cert::LinkCertState>,
}

impl Net {
  /// 由服务器设置和 agent 上报推导出网络信息。设置里的地址优先，其次是 agent 检测到的。
  pub fn derive(
    servers: &BTreeMap<String, ServerRow>,
    agents: &[crate::db::AgentRow],
  ) -> Self {
    let mut net = Net::default();
    for (name, server) in servers {
      let report = agents
        .iter()
        .find(|a| &a.server == name)
        .and_then(|a| a.report.as_ref());
      // 接入方式是 public 时不用内网地址：端口只绑 127.0.0.1，网关一律走反向隧道。
      let public = server.settings.network_mode
        == Some(wharf_api_types::spec::NetworkMode::Public);
      if let Some(addr) = server
        .settings
        .private_addr
        .clone()
        .or_else(|| report.and_then(|r| r.private_addr.clone()))
        .filter(|_| !public)
      {
        net.private.insert(name.clone(), addr);
      }
      if let Some(r) = report {
        net.lan_ips.insert(
          name.clone(),
          crate::source_trust::private_ipv4s(&r.lan_ips),
        );
        if !public && let Some(addr) = &r.private_addr {
          net.reported_private.insert(name.clone(), addr.clone());
        }
        net.docker_subnets.insert(
          name.clone(),
          r.docker_subnets.iter().map(|d| d.subnet.clone()).collect(),
        );
      }
      if !server.settings.lan_addrs.is_empty() {
        net
          .lan_addrs
          .insert(name.clone(), server.settings.lan_addrs.clone());
      }
      if let Some(ip) = server
        .settings
        .public_ip
        .clone()
        .or_else(|| report.and_then(|r| r.public_ip.clone()))
      {
        net.public_ip.insert(name.clone(), ip);
      }
    }
    net
  }

  /// 只取影响渲染的地址，给 plan 的 inputs 指纹用。
  /// 服务端口除 127.0.0.1 外要绑定的地址：内网地址，加上设置的局域网地址。
  pub fn bind_ips(&self, server: &str) -> Vec<String> {
    let mut ips: Vec<String> = self
      .private
      .get(server)
      .map(|a| a.ip.clone())
      .into_iter()
      .collect();
    for ip in self.lan_addrs.get(server).into_iter().flatten() {
      if !ips.contains(ip) {
        ips.push(ip.clone());
      }
    }
    ips
  }

  pub fn addresses(&self) -> Addresses {
    Addresses {
      private: self.private.clone(),
      public_ip: self.public_ip.clone(),
    }
  }
}

/// 渲染网关依赖的机器地址。地址变了渲染结果可能变，所以进 plan 的 inputs 指纹；
/// 磁盘、负载这些上报值变化很勤，不能算进去，否则计划频繁失效。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Addresses {
  pub private: BTreeMap<String, PrivateAddr>,
  pub public_ip: BTreeMap<String, String>,
}

/// 登录保护账号的密钥名前缀。写入时值是 `用户名:密码`，保存的是 `用户名 bcrypt哈希`。
const AUTH_PREFIX: &str = "BASIC_AUTH_";

/// 某个域名的登录保护账号存在这个密钥里（域名里的 `.` 换成 `_`，域名本身没有 `_`，不会撞）。
pub fn route_auth_secret(hostname: &str) -> String {
  format!("{AUTH_PREFIX}{}", hostname.replace('.', "_"))
}

pub fn is_auth_secret(name: &str) -> bool {
  name.starts_with(AUTH_PREFIX)
}

impl Net {
  /// 域名的登录保护账号。
  pub fn auth_for(&self, hostname: &str) -> Option<&BasicAuth> {
    self.basic_auth.get(&route_auth_secret(hostname))
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BasicAuth {
  pub user: String,
  pub hash: String,
}

impl BasicAuth {
  /// 解析保存的值 `用户名 bcrypt哈希`。
  pub fn parse(stored: &str) -> Option<Self> {
    let (user, hash) = stored.split_once(' ')?;
    crate::caddy_validate::valid_basic_auth(user, hash).then(|| {
      Self {
        user: user.into(),
        hash: hash.into(),
      }
    })
  }

  /// 把写入的 `用户名:密码` 转成保存的值。盐是随机的，只在写入时算一次，
  /// 这样网关配置是稳定的，不会每次 plan 都显示变化。
  pub fn hash_input(input: &str) -> Result<String, ApiError> {
    let (user, password) =
      input.split_once(':').ok_or_else(|| {
        ApiError::invalid("登录保护账号要写成 用户名:密码")
      })?;
    if !crate::caddy_validate::valid_basic_auth_user(user) {
      return Err(ApiError::invalid(
        "登录保护的用户名须为 1 到 64 位，只能用字母、数字、. _ -",
      ));
    }
    if password.len() < 8 {
      return Err(ApiError::invalid("登录保护的密码至少 8 位"));
    }
    let hash =
      bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| {
        ApiError::internal(format!("计算密码哈希失败：{e}"))
      })?;
    Ok(format!("{user} {hash}"))
  }
}

/// 服务数据目录：`/srv/<service>/<volume>`。
pub fn volume_dir(service: &str, volume: &str) -> String {
  format!("/srv/{service}/{volume}")
}

pub fn service_dirs(name: &str, spec: &ServiceSpec) -> Vec<String> {
  spec
    .volumes
    .iter()
    .map(|v| volume_dir(name, &v.name))
    .collect()
}

#[derive(Serialize)]
struct ComposeFile {
  name: String,
  services: BTreeMap<String, ComposeService>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  configs: BTreeMap<String, ComposeConfigDef>,
}

#[derive(Serialize)]
struct ComposeConfigDef {
  content: String,
}

#[derive(Serialize)]
struct ComposeConfigRef {
  source: String,
  target: String,
}

#[derive(Serialize)]
struct ComposeService {
  image: String,
  restart: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  mem_limit: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  cpus: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  network_mode: Option<&'static str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  entrypoint: Option<Vec<String>>,
  #[serde(skip_serializing_if = "Option::is_none")]
  command: Option<Vec<String>>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  environment: BTreeMap<String, String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  ports: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  volumes: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  configs: Vec<ComposeConfigRef>,
  labels: BTreeMap<String, String>,
}

fn to_yaml(file: &ComposeFile) -> String {
  let body = serde_yaml_ng::to_string(file).unwrap_or_default();
  format!("# 由 Wharf 生成，不要手改。\n{body}")
}

/// 把 `[[NAME]]` 换成密钥。`secrets` 为空时原样保留（用于展示和部署历史）。
pub fn substitute(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  substitute_values(text, secrets, false)
}

fn substitute_values(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
  service_config: bool,
) -> Result<String, ApiError> {
  let Some(secrets) = secrets else {
    return Ok(text.to_string());
  };
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  let mut missing = Vec::new();
  while let Some((start, name)) = next_placeholder(rest) {
    let len = name.len();
    let is_name = !name.is_empty()
      && name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    out.push_str(&rest[..start]);
    let account = service_config.then(|| account_ref(name)).flatten();
    if is_name || account.is_some() {
      match secrets.get(name) {
        Some(value) => out.push_str(value),
        None if let Some(account) = account => {
          return Err(
            ApiError::invalid(format!("应用账号 {account} 不存在"))
              .with_hint("先设置应用账号，密码从标准输入读取")
              .suggest(format!(
                "wharf sso account set {account} --user <用户名>"
              )),
          );
        }
        None => missing.push(name.to_string()),
      }
    } else {
      out.push_str(&rest[start..start + 4 + len]);
    }
    rest = &rest[start + 4 + len..];
  }
  out.push_str(rest);
  if !missing.is_empty() {
    missing.sort();
    missing.dedup();
    let first = missing[0].clone();
    return Err(
      ApiError::invalid(format!(
        "密钥不存在：{}",
        missing.join("、")
      ))
      .with_hint("先设置密钥，值从标准输入读取，不会出现在命令行里")
      .suggest(format!("wharf secret set {first}")),
    );
  }
  Ok(out)
}

pub(crate) fn next_placeholder(text: &str) -> Option<(usize, &str)> {
  let start = text.find("[[")?;
  let rest = &text[start + 2..];
  Some((start, &rest[..rest.find("]]")?]))
}

pub fn service_account_refs(world: &World) -> BTreeSet<String> {
  world
    .services
    .values()
    .flat_map(|row| {
      crate::secret_policy::service_account_refs(&row.spec)
    })
    .map(|(name, _)| name.to_string())
    .collect()
}

pub(crate) fn account_ref(name: &str) -> Option<&str> {
  let (account, field) =
    name.strip_prefix("account.")?.split_once('.')?;
  (matches!(field, "username" | "password")
    && wharf_api_types::validate_name("应用账号", account).is_ok())
  .then_some(account)
}

/// 构建来源的镜像名：`wharf-build/<服务>:<指纹>`。指纹来自构建配置和端口
/// （端口决定模板里的 `$PORT`），配置不变就不用重新构建。
pub fn build_image(
  name: &str,
  build: &BuildSource,
  ports: &[PortSpec],
) -> String {
  // 模板只用到容器端口（`$PORT`），宿主机端口变了不用重新构建。
  let input =
    serde_json::json!({ "build": build, "port": build_port(ports) });
  let key = hash(&input.to_string());
  format!("{BUILD_IMAGE_PREFIX}{name}:{}", &key[..12])
}

/// 构建来源模板里的 `$PORT`：第一个端口，没有端口时 8080。
pub fn build_port(ports: &[PortSpec]) -> u16 {
  ports.first().and_then(|p| p.container).unwrap_or(8080)
}

/// compose 里 cpus 的写法：500 → "0.5"，1000 → "1"，1250 → "1.25"。
pub fn cpus_text(milli: u32) -> String {
  let s = format!("{:.3}", f64::from(milli) / 1000.0);
  s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// 服务设置作用的容器：写了 `container` 就是它，否则 compose 里只能有一个容器。
pub fn compose_target(
  name: &str,
  content: &str,
  container: Option<&str>,
) -> Result<String, ApiError> {
  let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content)
    .map_err(|e| {
      ApiError::invalid(format!("compose 内容解析失败：{e}"))
    })?;
  let names: Vec<String> = value
    .get("services")
    .and_then(|s| s.as_mapping())
    .into_iter()
    .flat_map(|m| m.keys())
    .filter_map(|k| k.as_str().map(str::to_string))
    .collect();
  match container {
    Some(c) if names.iter().any(|n| n == c) => Ok(c.to_string()),
    Some(c) => Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里没有容器 {c}"
    ))
    .with_hint(format!("可选的容器：{}", names.join("、")))),
    None if names.len() == 1 => Ok(names[0].clone()),
    None => Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里有 {} 个容器，要选环境变量和资源上限加在哪个容器上",
      names.len()
    ))
    .with_hint(format!("在设置里选择容器（{}）", names.join("、")))),
  }
}

/// 给 compose 里的一个容器加上服务设置里的资源上限和环境变量，其余文本保持原样
/// （注释、`[[密钥]]` 引用都不动，所以不重新生成 YAML，只插入几行）。
pub fn compose_with_settings(
  name: &str,
  content: &str,
  spec: &ServiceSpec,
) -> Result<String, ApiError> {
  let limits = spec.limits.clone().unwrap_or_default();
  if limits.memory_mb.is_none()
    && limits.cpu_milli.is_none()
    && spec.env.is_empty()
  {
    return Ok(content.to_string());
  }
  let target =
    compose_target(name, content, spec.container.as_deref())?;
  let unsupported = || {
    ApiError::invalid(format!(
      "服务 {name} 的 compose 写法没法自动加上环境变量或资源上限"
    ))
    .with_hint("直接写在 compose 文件里（environment、mem_limit、cpus），然后去掉设置里的")
  };
  let value: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(content).map_err(|_| unsupported())?;
  let body = &value["services"][target.as_str()];
  if (limits.memory_mb.is_some() || limits.cpu_milli.is_some())
    && ["mem_limit", "cpus", "deploy"]
      .iter()
      .any(|key| body.get(*key).is_some())
  {
    return Err(ApiError::invalid(format!(
      "服务 {name} 的 compose 里已经写了 mem_limit、cpus 或 deploy，不能再在这里设资源上限"
    )).with_hint("两处留一处：去掉 compose 里的，或者去掉这里的资源上限"));
  }
  let existing: Vec<String> = match body.get("environment") {
    Some(serde_yaml_ng::Value::Mapping(m)) => m
      .keys()
      .filter_map(|k| k.as_str().map(str::to_string))
      .collect(),
    Some(serde_yaml_ng::Value::Sequence(l)) => l
      .iter()
      .filter_map(|v| v.as_str())
      .map(|v| v.split('=').next().unwrap_or(v).to_string())
      .collect(),
    _ => vec![],
  };
  if let Some(dup) = spec.env.keys().find(|k| existing.contains(k)) {
    return Err(
      ApiError::invalid(format!(
        "环境变量 {dup} 在 compose 里已经写了"
      ))
      .with_hint("两处留一处：去掉 compose 里的，或者去掉设置里的"),
    );
  }

  // 按行定位：services 下的容器、容器里的 environment。
  let lines: Vec<(usize, &str)> = content
    .split_inclusive('\n')
    .scan(0, |offset, line| {
      let start = *offset;
      *offset += line.len();
      Some((start, line))
    })
    .collect();
  let code = |line: &str| {
    !line.trim().is_empty() && !line.trim_start().starts_with('#')
  };
  let indent =
    |line: &str| line.len() - line.trim_start_matches(' ').len();
  let key = |line: &str| {
    line
      .split(" #")
      .next()
      .unwrap()
      .trim()
      .strip_suffix(':')
      .map(|k| k.trim_matches(['"', '\'']).to_string())
  };
  if lines.iter().any(|(_, l)| l.contains('\t')) {
    return Err(unsupported());
  }
  let services = lines
    .iter()
    .position(|(_, l)| {
      code(l)
        && indent(l) == 0
        && key(l).as_deref() == Some("services")
    })
    .ok_or_else(unsupported)?;
  let n = lines[services + 1..]
    .iter()
    .find(|(_, l)| code(l))
    .map(|(_, l)| indent(l))
    .filter(|n| *n > 0)
    .ok_or_else(unsupported)?;
  let header = (services + 1..lines.len())
    .take_while(|i| !code(lines[*i].1) || indent(lines[*i].1) >= n)
    .find(|i| {
      let l = lines[*i].1;
      code(l)
        && indent(l) == n
        && key(l).as_deref() == Some(target.as_str())
    })
    .ok_or_else(unsupported)?;
  let body_end = (header + 1..lines.len())
    .find(|i| code(lines[*i].1) && indent(lines[*i].1) <= n)
    .unwrap_or(lines.len());
  let m = lines[header + 1..body_end]
    .iter()
    .find(|(_, l)| code(l))
    .map(|(_, l)| indent(l))
    .filter(|m| *m > n)
    .ok_or_else(unsupported)?;
  let eol = if lines[header].1.ends_with("\r\n") {
    "\r\n"
  } else {
    "\n"
  };
  let pad = " ".repeat(m);
  let quote = |v: &str| {
    serde_json::to_string(&v.replace('$', "$$")).unwrap_or_default()
  };
  let mut inserts: Vec<(usize, String)> = Vec::new();
  let memory = limits.memory_mb.map(|mb| format!("{mb}m"));
  let cpus = limits.cpu_milli.map(cpus_text);
  let mut added = String::new();
  if let Some(memory) = &memory {
    added.push_str(&format!("{pad}mem_limit: {memory}{eol}"));
  }
  if let Some(cpus) = &cpus {
    added.push_str(&format!("{pad}cpus: \"{cpus}\"{eol}"));
  }
  if !spec.env.is_empty() {
    let env_line = (header + 1..body_end).find(|i| {
      let l = lines[*i].1;
      code(l)
        && indent(l) == m
        && l.trim_start().starts_with("environment:")
    });
    match env_line {
      None => {
        added.push_str(&format!("{pad}environment:{eol}"));
        for (k, v) in &spec.env {
          added.push_str(&format!("{pad}  {k}: {}{eol}", quote(v)));
        }
      }
      Some(e) => {
        if key(lines[e].1).as_deref() != Some("environment") {
          return Err(unsupported());
        }
        let item = lines[e + 1..body_end]
          .iter()
          .find(|(_, l)| code(l))
          .filter(|(_, l)| indent(l) > m)
          .map(|(_, l)| *l)
          .ok_or_else(unsupported)?;
        let k_pad = " ".repeat(indent(item));
        let list = item.trim_start().starts_with("- ");
        let mut text = String::new();
        for (k, v) in &spec.env {
          if list {
            text.push_str(&format!(
              "{k_pad}- {}{eol}",
              quote(&format!("{k}={v}"))
            ));
          } else {
            text.push_str(&format!("{k_pad}{k}: {}{eol}", quote(v)));
          }
        }
        inserts.push((lines[e].0 + lines[e].1.len(), text));
      }
    }
  }
  if !added.is_empty() {
    inserts.push((lines[header].0 + lines[header].1.len(), added));
  }
  inserts.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
  let mut out = content.to_string();
  for (at, text) in inserts {
    out.insert_str(at, &text);
  }
  // 插完再解析一遍，确认加到了对的容器上。
  let parsed: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).map_err(|_| unsupported())?;
  let actual = &parsed["services"][target.as_str()];
  for (key, expected) in [("mem_limit", memory), ("cpus", cpus)] {
    if let Some(expected) = expected
      && actual.get(key).and_then(|v| v.as_str())
        != Some(expected.as_str())
    {
      return Err(unsupported());
    }
  }
  for k in spec.env.keys() {
    let found = match actual.get("environment") {
      Some(serde_yaml_ng::Value::Mapping(map)) => {
        map.get(k.as_str()).is_some()
      }
      Some(serde_yaml_ng::Value::Sequence(l)) => l
        .iter()
        .filter_map(|v| v.as_str())
        .any(|v| v.split('=').next() == Some(k.as_str())),
      _ => false,
    };
    if !found {
      return Err(unsupported());
    }
  }
  Ok(out)
}

/// 服务的 compose 文件。image 来源自动生成；compose 来源原样使用。
/// 端口只绑定 127.0.0.1 和内网地址，不绑定 0.0.0.0。
pub fn service_compose(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  bind_ips: &[String],
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  match &spec.source {
    Source::Compose { content, .. } => {
      let content = content.as_deref().unwrap_or_default();
      substitute_values(
        &compose_with_settings(name, content, spec)?,
        secrets,
        true,
      )
    }
    Source::Image(_) | Source::Build(_) => {
      let mut service = image_service(name, spec, secrets)?;
      for port in &spec.ports {
        let (Some(host), Some(container)) =
          (host_ports.get(&port.name), port.container)
        else {
          continue;
        };
        let protocol = if port.udp { "/udp" } else { "" };
        service
          .ports
          .push(format!("127.0.0.1:{host}:{container}{protocol}"));
        for ip in bind_ips {
          service
            .ports
            .push(format!("{ip}:{host}:{container}{protocol}"));
        }
      }
      service.volumes = spec
        .volumes
        .iter()
        .map(|v| {
          format!("{}:{}", volume_dir(name, &v.name), v.target)
        })
        .collect();
      let file = ComposeFile {
        configs: BTreeMap::new(),
        name: name.to_string(),
        services: BTreeMap::from([(name.to_string(), service)]),
      };
      Ok(to_yaml(&file))
    }
  }
}

fn image_service(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<ComposeService, ApiError> {
  let image = match &spec.source {
    Source::Build(b) => build_image(name, b, &spec.ports),
    Source::Image(image) => image.clone(),
    Source::Compose { .. } => unreachable!(),
  };
  let mut environment = BTreeMap::new();
  for (key, value) in &spec.env {
    // compose 会对 `$` 做变量插值，原样传给容器要写成 `$$`。
    let value = substitute_values(value, secrets, true)?;
    environment.insert(key.clone(), value.replace('$', "$$"));
  }
  Ok(ComposeService {
    configs: vec![],
    image,
    restart: "unless-stopped",
    mem_limit: spec
      .limits
      .as_ref()
      .and_then(|l| l.memory_mb)
      .map(|mb| format!("{mb}m")),
    cpus: spec
      .limits
      .as_ref()
      .and_then(|l| l.cpu_milli)
      .map(cpus_text),
    network_mode: None,
    entrypoint: None,
    command: None,
    environment,
    ports: Vec::new(),
    volumes: Vec::new(),
    labels: BTreeMap::from([(
      "wharf.service".to_string(),
      name.to_string(),
    )]),
  })
}

include!("render/compose_and_caddy.rs");

#[cfg(test)]
mod tests;
