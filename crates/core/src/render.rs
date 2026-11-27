//! 由期望状态渲染出 compose 文件和 Caddyfile。纯函数，不碰网络和数据库。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::{Component, Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value};
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
  pub core_server: Option<String>,
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
    let reports = crate::report_guard::safe_reports(servers, agents);
    for (name, server) in servers {
      let report = reports.get(name);
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

pub fn volume_host_dir(
  service: &str,
  v: &wharf_api_types::spec::VolumeSpec,
) -> Result<String, ApiError> {
  match &v.from_service {
    Some(raw) => {
      let (owner, volume) = crate::shared_volumes::parse_ref(raw)?;
      Ok(volume_dir(owner, volume))
    }
    None => Ok(volume_dir(service, &v.name)),
  }
}

pub fn service_dirs(name: &str, spec: &ServiceSpec) -> Vec<String> {
  let mut seen = BTreeSet::new();
  spec
    .volumes
    .iter()
    .filter_map(|v| volume_host_dir(name, v).ok())
    .filter(|dir| seen.insert(dir.clone()))
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
  stop_grace_period: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  stop_signal: Option<String>,
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

pub const SECRET_FILE_DIR: &str = "/run/wharf-secrets";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretMode {
  Plain,
  Url,
  B64,
  Json,
  File,
}

pub(crate) struct Placeholder<'a> {
  pub mode: SecretMode,
  pub name: &'a str,
}

fn bare_secret(name: &str) -> bool {
  !name.is_empty()
    && name
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(crate) fn parse_placeholder(
  inner: &str,
  allow_account: bool,
) -> Result<Option<Placeholder<'_>>, ApiError> {
  if inner.starts_with('@') {
    return Ok(None);
  }
  let valid = |name| {
    bare_secret(name)
      || (allow_account && account_ref(name).is_some())
  };
  let (mode, name) = match inner.split_once(':') {
    None if valid(inner) => (SecretMode::Plain, inner),
    None => return Ok(None),
    Some((prefix, name)) => {
      let mode = match prefix {
        "url" => SecretMode::Url,
        "b64" => SecretMode::B64,
        "json" => SecretMode::Json,
        "FILE" => SecretMode::File,
        _ if bare_secret(prefix) && valid(name) => {
          return Err(ApiError::invalid(format!("不支持的密钥修饰符：{prefix}"))
            .with_hint("可用修饰符：[[SECRET]]、[[url:SECRET]]、[[b64:SECRET]]、[[json:SECRET]]、[[FILE:SECRET]]"));
        }
        _ => return Ok(None),
      };
      if !valid(name) {
        return Err(ApiError::invalid(format!("密钥引用 [[{inner}]] 格式不对"))
          .with_hint("写成 [[url:密钥名]]、[[b64:密钥名]]、[[json:密钥名]] 或 [[FILE:密钥名]]，密钥名只能用字母、数字、_ 和 -"));
      }
      (mode, name)
    }
  };
  Ok(Some(Placeholder { mode, name }))
}

pub(crate) fn reject_file(
  placeholder: &Placeholder<'_>,
) -> Result<(), ApiError> {
  let name = placeholder.name;
  if placeholder.mode == SecretMode::File {
    return Err(ApiError::invalid(format!("此处不支持 [[FILE:{name}]]，文件形式密钥仅用于服务的环境变量、compose 和配置文件"))
      .with_hint(format!("改用 [[{name}]] 或编码修饰符 [[url:{name}]]、[[b64:{name}]]、[[json:{name}]]")));
  }
  Ok(())
}

fn encode_secret(
  mode: SecretMode,
  value: &str,
) -> Result<String, ApiError> {
  Ok(match mode {
    SecretMode::Plain => value.to_string(),
    SecretMode::Url => urlencoding::encode(value).into_owned(),
    SecretMode::B64 => STANDARD.encode(value),
    SecretMode::Json => {
      let json = serde_json::to_string(value)
        .map_err(|_| ApiError::internal("密钥 JSON 编码失败"))?;
      json[1..json.len() - 1].to_string()
    }
    SecretMode::File => unreachable!(),
  })
}

pub(crate) fn next_placeholder(text: &str) -> Option<(usize, &str)> {
  let start = text.find("[[")?;
  let end = start + 2 + text[start + 2..].find("]]")?;
  let inner_start = start + 1;
  let start = text[inner_start..end]
    .rfind("[[")
    .map_or(start, |inner| inner_start + inner);
  Some((start, &text[start + 2..end]))
}

pub(crate) fn placeholders(
  mut text: &str,
) -> impl Iterator<Item = &str> {
  std::iter::from_fn(move || {
    let (start, inner) = next_placeholder(text)?;
    text = &text[start + inner.len() + 4..];
    Some(inner)
  })
}

fn rewrite_placeholders(
  text: &str,
  service: bool,
  mut replace: impl FnMut(
    Placeholder<'_>,
  ) -> Result<Option<String>, ApiError>,
) -> Result<String, ApiError> {
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  while let Some((start, inner)) = next_placeholder(rest) {
    let end = start + inner.len() + 4;
    out.push_str(&rest[..start]);
    let value = match parse_placeholder(inner, service)? {
      Some(p) => replace(p)?,
      None => None,
    };
    out.push_str(value.as_deref().unwrap_or(&rest[start..end]));
    rest = &rest[end..];
  }
  out.push_str(rest);
  Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretContext {
  Text,
  Env,
  Compose,
  ConfigFile,
}

pub fn substitute(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  substitute_values(
    text,
    secrets,
    SecretContext::Text,
    &mut BTreeSet::new(),
  )
}

fn substitute_values(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
  context: SecretContext,
  files: &mut BTreeSet<String>,
) -> Result<String, ApiError> {
  let service = context != SecretContext::Text;
  let mut missing = BTreeSet::new();
  let out = rewrite_placeholders(text, service, |p| {
    if !service {
      reject_file(&p)?;
    }
    let Some(secrets) = secrets else {
      return Ok(None);
    };
    let name = p.name;
    match secrets.get(name) {
      Some(_) if p.mode == SecretMode::File => {
        files.insert(name.to_string());
        Ok(Some(format!("{SECRET_FILE_DIR}/{name}")))
      }
      Some(value) => {
        let value = encode_secret(p.mode, value)?;
        Ok(Some(if context == SecretContext::Compose {
          value.replace('$', "$$")
        } else {
          value
        }))
      }
      None
        if context == SecretContext::ConfigFile
          && p.mode == SecretMode::Plain =>
      {
        Ok(None)
      }
      None => {
        if let Some(account) =
          service.then(|| account_ref(name)).flatten()
        {
          return Err(
            ApiError::invalid(format!("应用账号 {account} 不存在"))
              .with_hint("先设置应用账号，密码从标准输入读取")
              .suggest(format!(
                "wharf sso account set {account} --user <用户名>"
              )),
          );
        }
        missing.insert(name.to_string());
        Ok(None)
      }
    }
  })?;
  if let Some(first) = missing.first() {
    return Err(
      ApiError::invalid(format!(
        "密钥不存在：{}",
        missing.iter().cloned().collect::<Vec<_>>().join("、")
      ))
      .with_hint("可以随机生成业务密钥，或从标准输入设置已有的值")
      .suggest(format!("wharf secret set {first} --generate"))
      .suggest(format!("wharf secret set {first}")),
    );
  }
  Ok(out)
}

pub(crate) type SecretMounts = BTreeMap<String, BTreeSet<String>>;

fn compose_shape(value: &Value) -> Value {
  match value {
    Value::Mapping(map) => Value::Mapping(
      map
        .iter()
        .map(|(k, v)| (k.clone(), compose_shape(v)))
        .collect(),
    ),
    Value::Sequence(seq) => {
      Value::Sequence(seq.iter().map(compose_shape).collect())
    }
    Value::Tagged(tag) => {
      let mut tag = tag.clone();
      tag.value = compose_shape(&tag.value);
      Value::Tagged(tag)
    }
    _ => Value::Null,
  }
}

fn yaml_contains(value: &Value, text: &str) -> bool {
  match value {
    Value::String(value) => value.contains(text),
    Value::Sequence(values) => {
      values.iter().any(|value| yaml_contains(value, text))
    }
    Value::Mapping(values) => values.iter().any(|(key, value)| {
      yaml_contains(key, text) || yaml_contains(value, text)
    }),
    Value::Tagged(tag) => yaml_contains(&tag.value, text),
    _ => false,
  }
}

pub(crate) fn merge_compose(
  value: &mut Value,
) -> Result<(), serde_yaml_ng::Error> {
  // 先展开被继承的映射，避免一层合并漏掉链式继承或改变优先级。
  match value {
    Value::Mapping(map) => {
      for child in map.values_mut() {
        merge_compose(child)?;
      }
      if map.contains_key("<<") {
        value.apply_merge()?;
      }
    }
    Value::Sequence(seq) => {
      for child in seq {
        merge_compose(child)?;
      }
    }
    Value::Tagged(tag) => merge_compose(&mut tag.value)?,
    _ => {}
  }
  Ok(())
}

pub fn expected_components(
  yaml: &str,
  active_profiles: &[String],
) -> Vec<String> {
  let Ok(mut doc) = serde_yaml_ng::from_str::<Value>(yaml) else {
    return vec![];
  };
  if merge_compose(&mut doc).is_err() {
    return vec![];
  }
  let Some(services) =
    doc.get("services").and_then(Value::as_mapping)
  else {
    return vec![];
  };
  let active =
    |profile: &str| active_profiles.iter().any(|p| p == profile);
  let mut components: Vec<_> = services
    .iter()
    .filter_map(|(name, body)| {
      if body.get("restart").and_then(Value::as_str) == Some("no") {
        return None;
      }
      let enabled = match body.get("profiles") {
        Some(Value::Sequence(p)) => {
          p.is_empty()
            || p.iter().filter_map(Value::as_str).any(active)
        }
        Some(Value::String(p)) => p.is_empty() || active(p),
        _ => true,
      };
      let name = name.as_str()?;
      enabled.then(|| name.to_string())
    })
    .collect();
  components.sort();
  components
}

pub fn service_expected_components(
  name: &str,
  spec: &ServiceSpec,
) -> Vec<String> {
  match &spec.source {
    Source::Image(_) | Source::Build(_) => vec![name.to_string()],
    Source::Compose { content, .. } => content
      .as_deref()
      .map(|yaml| expected_components(yaml, &[]))
      .unwrap_or_default(),
  }
}

pub fn missing_components(
  expected: &[String],
  containers: &[wharf_api_types::agent::ContainerInfo],
) -> Vec<String> {
  let present: BTreeSet<_> = containers
    .iter()
    .filter(|c| !c.foreign)
    .map(|c| c.service.as_str())
    .collect();
  expected
    .iter()
    .filter(|c| !present.contains(c.as_str()))
    .cloned()
    .collect()
}

pub(crate) fn parse_compose(
  content: &str,
) -> Result<Value, ApiError> {
  let mut doc: Value =
    serde_yaml_ng::from_str(content).map_err(|e| {
      let location = e.location().map_or_else(String::new, |loc| {
        format!("（第 {} 行第 {} 列）", loc.line(), loc.column())
      });
      ApiError::invalid(format!("compose 不是合法的 YAML{location}"))
    })?;
  merge_compose(&mut doc).map_err(|_| {
    ApiError::invalid("compose YAML 锚点合并不合法")
      .with_hint("检查 <<: *anchor 是否指向映射")
  })?;
  Ok(doc)
}

pub(crate) fn parse_compose_template(
  content: &str,
) -> Result<Value, ApiError> {
  if !content.contains("[[") {
    return parse_compose(content);
  }
  let mut prefix = "wharf_retag_ref_".to_string();
  let original = serde_yaml_ng::from_str::<Value>(content).ok();
  while content.contains(&prefix)
    || original
      .as_ref()
      .is_some_and(|doc| yaml_contains(doc, &prefix))
  {
    prefix.push('_');
  }
  let mut markers = Vec::new();
  let marked = mark_compose_refs(content, |raw| {
    let marker = format!("{prefix}{}_end", markers.len());
    markers.push(raw);
    marker
  });
  let mut doc = parse_compose(&marked)?;
  restore_compose_refs(&mut doc, &prefix, &markers);
  Ok(doc)
}

pub(crate) fn mark_compose_refs<'a>(
  content: &'a str,
  mut marker: impl FnMut(&'a str) -> String,
) -> String {
  let mut marked = String::new();
  let mut rest = content;
  while let Some((start, inner)) = next_placeholder(rest) {
    let end = start + inner.len() + 4;
    marked.push_str(&rest[..start]);
    let raw = &rest[start..end];
    if parse_placeholder(inner, true).is_ok_and(|p| p.is_some())
      || !crate::refs::used(raw).is_empty()
    {
      marked.push_str(&marker(raw));
    } else {
      marked.push_str(raw);
    }
    rest = &rest[end..];
  }
  marked.push_str(rest);
  marked
}

fn restore_compose_refs(
  value: &mut Value,
  prefix: &str,
  markers: &[&str],
) {
  match value {
    Value::String(s) if s.contains(prefix) => {
      for (i, raw) in markers.iter().enumerate() {
        *s = s.replace(&format!("{prefix}{i}_end"), raw);
      }
    }
    Value::Mapping(map) => {
      *map = std::mem::take(map)
        .into_iter()
        .map(|(mut k, mut v)| {
          restore_compose_refs(&mut k, prefix, markers);
          restore_compose_refs(&mut v, prefix, markers);
          (k, v)
        })
        .collect();
    }
    Value::Sequence(seq) => {
      for child in seq {
        restore_compose_refs(child, prefix, markers);
      }
    }
    Value::Tagged(tag) => {
      restore_compose_refs(&mut tag.value, prefix, markers)
    }
    _ => {}
  }
}

pub(crate) fn host_port(ip: &str, port: u16) -> String {
  if ip.contains(':') && !ip.starts_with('[') {
    format!("[{ip}]:{port}")
  } else {
    format!("{ip}:{port}")
  }
}

fn substitute_compose(
  service: &str,
  content: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(String, SecretMounts), ApiError> {
  let out = substitute_values(
    content,
    secrets,
    SecretContext::Compose,
    &mut BTreeSet::new(),
  )?;
  if out == content {
    return Ok((out, BTreeMap::new()));
  }
  let bad = || {
    let names: BTreeSet<_> = placeholders(content)
      .filter_map(|inner| {
        parse_placeholder(inner, true).ok().flatten()
      })
      .map(|p| p.name)
      .collect();
    let names = names.into_iter().collect::<Vec<_>>();
    let name = names.first().copied().unwrap_or_default();
    ApiError::invalid(format!("服务 {service} 的 compose 填入密钥 {} 后不是合法的 YAML", names.join("、")))
      .with_hint(format!("密钥值里有引号或换行：在双引号里改用 [[json:{name}]]，或改用 [[FILE:{name}]]"))
  };
  let mut after: Value =
    serde_yaml_ng::from_str(&out).map_err(|_| bad())?;
  // 未加引号的 [[X]] 会被 YAML 读成两层列表，先用标量代替占位符。
  let mut prefix = "wharf_secret_ref_".to_string();
  while content.contains(&prefix) || yaml_contains(&after, &prefix) {
    prefix.push('_');
  }
  let mut markers = Vec::new();
  let marked = rewrite_placeholders(content, true, |p| {
    let marker = match p.mode {
      SecretMode::File => {
        let marker = format!("{prefix}{}_end", markers.len());
        markers.push((p.name.to_string(), marker.clone()));
        marker
      }
      _ => prefix.clone(),
    };
    Ok(Some(marker))
  })?;
  let before: Value =
    serde_yaml_ng::from_str(&marked).map_err(|_| bad())?;
  if compose_shape(&before) != compose_shape(&after) {
    return Err(bad());
  }
  merge_compose(&mut after).map_err(|_| bad())?;
  check_compose_secret_volumes(service, &after)?;
  Ok((out, collect_compose_file_secrets(before, &markers)?))
}

fn collect_compose_file_secrets(
  mut doc: Value,
  markers: &[(String, String)],
) -> Result<SecretMounts, ApiError> {
  if markers.is_empty() {
    return Ok(BTreeMap::new());
  }
  let bad = || {
    ApiError::invalid("[[FILE:...]] 只能写在 services 下的容器配置里")
  };
  merge_compose(&mut doc).map_err(|_| bad())?;
  let services = doc
    .get("services")
    .and_then(Value::as_mapping)
    .ok_or_else(bad)?;
  let mut found = BTreeSet::new();
  let mut mounts = SecretMounts::new();
  for (container, body) in services {
    let container = container.as_str().ok_or_else(bad)?;
    for (name, marker) in markers {
      if yaml_contains(body, marker) {
        found.insert(marker);
        mounts
          .entry(container.to_string())
          .or_default()
          .insert(name.clone());
      }
    }
  }
  if found.len() != markers.len() {
    return Err(bad());
  }
  Ok(mounts)
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
  let value = parse_compose_template(content)?;
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
  apply_compose_settings(name, content, spec, true)
}

fn apply_compose_settings(
  name: &str,
  content: &str,
  spec: &ServiceSpec,
  check_inherited: bool,
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
  // 新改动检查继承字段，已存配置渲染仍允许原来生效的覆盖。
  let value = if check_inherited {
    parse_compose_template(content)?
  } else {
    serde_yaml_ng::from_str(content).map_err(|_| unsupported())?
  };
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
        if !existing.is_empty() {
          return Err(unsupported());
        }
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

fn compose_with_resolved_env(
  name: &str,
  content: &str,
  spec: &ServiceSpec,
  secrets: &BTreeMap<String, String>,
) -> Result<(String, SecretMounts), ApiError> {
  // 服务设置里的环境变量先求值，再作为 YAML 字符串插入。
  let (content, mut mounts) =
    substitute_compose(name, content, Some(secrets))?;
  let mut file_secrets = BTreeSet::new();
  let mut spec = spec.clone();
  for value in spec.env.values_mut() {
    *value = substitute_values(
      value,
      Some(secrets),
      SecretContext::Env,
      &mut file_secrets,
    )?;
  }
  let out = apply_compose_settings(name, &content, &spec, false)?;
  if !file_secrets.is_empty() {
    let target =
      compose_target(name, &content, spec.container.as_deref())
        .map_err(|_| {
          ApiError::invalid(format!(
            "服务 {name} 的 compose 无法定位配置文件的目标容器"
          ))
        })?;
    mounts.entry(target).or_default().extend(file_secrets);
  }
  Ok((out, mounts))
}

/// 服务的 compose 文件。image 来源自动生成；compose 来源原样使用。
/// 端口只绑定 127.0.0.1 和内网地址，不绑定 0.0.0.0。
pub fn service_compose(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  bind_ips: &[String],
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(String, SecretMounts), ApiError> {
  match &spec.source {
    Source::Compose { content, .. } => {
      let content = content.as_deref().unwrap_or_default();
      let template =
        apply_compose_settings(name, content, spec, false)?;
      let legacy = substitute_compose(name, &template, secrets);
      let Some(secrets) = secrets.filter(|_| !spec.env.is_empty())
      else {
        return legacy;
      };
      let resolved =
        compose_with_resolved_env(name, content, spec, secrets)?;
      if let Ok((text, mounts)) = &legacy
        && *mounts == resolved.1
        && (text == &resolved.0
          || parse_compose(text)? == parse_compose(&resolved.0)?)
      {
        return legacy;
      }
      Ok(resolved)
    }
    Source::Image(_) | Source::Build(_) => {
      let (mut service, files) = image_service(name, spec, secrets)?;
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
          let bind = self::host_port(ip, *host);
          service.ports.push(format!("{bind}:{container}{protocol}"));
        }
      }
      service.volumes = spec
        .volumes
        .iter()
        .map(|v| {
          let host = volume_host_dir(name, v)?;
          let ro = if v.read_only { ":ro" } else { "" };
          Ok(format!("{host}:{}{ro}", v.target))
        })
        .collect::<Result<_, ApiError>>()?;
      let file = ComposeFile {
        configs: BTreeMap::new(),
        name: name.to_string(),
        services: BTreeMap::from([(name.to_string(), service)]),
      };
      Ok((to_yaml(&file), image_mounts(name, files)))
    }
  }
}

fn image_service(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(ComposeService, BTreeSet<String>), ApiError> {
  let image = match &spec.source {
    Source::Build(b) => build_image(name, b, &spec.ports),
    Source::Image(image) => image.clone(),
    Source::Compose { .. } => unreachable!(),
  };
  let mut files = BTreeSet::new();
  let mut environment = BTreeMap::new();
  for (key, value) in &spec.env {
    // compose 会对 `$` 做变量插值，原样传给容器要写成 `$$`。
    let value = substitute_values(
      value,
      secrets,
      SecretContext::Env,
      &mut files,
    )?;
    environment.insert(key.clone(), value.replace('$', "$$"));
  }
  Ok((
    ComposeService {
      stop_grace_period: spec
        .stop_grace_secs
        .map(|n| format!("{n}s")),
      stop_signal: spec
        .stop_signal
        .as_deref()
        .map(wharf_api_types::compose::normalize_stop_signal)
        .transpose()?,
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
    },
    files,
  ))
}

/// 试跑用的 compose：同一个镜像和环境变量，不发布端口、不自动重启。
/// 只用于 image、build 来源且没有数据卷的服务。
fn image_mounts(name: &str, files: BTreeSet<String>) -> SecretMounts {
  if files.is_empty() {
    return BTreeMap::new();
  }
  BTreeMap::from([(name.to_string(), files)])
}

pub fn trial_compose(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<(String, SecretMounts), ApiError> {
  let (mut service, files) = image_service(name, spec, secrets)?;
  service.restart = "no";
  service.stop_grace_period = None;
  service.labels =
    BTreeMap::from([("wharf.trial".into(), name.into())]);
  Ok((
    to_yaml(&ComposeFile {
      configs: BTreeMap::new(),
      name: format!("{TRIAL_PROJECT_PREFIX}{name}"),
      services: BTreeMap::from([(name.to_string(), service)]),
    }),
    image_mounts(name, files),
  ))
}

/// 配置文件内容里的 `[[密钥名]]` 只替换确实存在的密钥，别的原样保留
/// （TOML 的 `[[servers]]` 这类写法不能当成密钥引用）。`secrets` 为空时原样返回。
pub fn file_content(
  content: &str,
  secrets: Option<&BTreeMap<String, String>>,
  files: &mut BTreeSet<String>,
) -> Result<String, ApiError> {
  substitute_values(
    content,
    secrets,
    SecretContext::ConfigFile,
    files,
  )
}

// 容器内路径按组件比较，不能在控制面上做文件系统解析。
pub(crate) fn normalized_mount_target(
  target: &str,
) -> Option<PathBuf> {
  let target = Path::new(target);
  if !target.is_absolute() {
    return None;
  }
  let mut normalized = PathBuf::from("/");
  for component in target.components() {
    match component {
      Component::Normal(part) => normalized.push(part),
      Component::ParentDir => {
        normalized.pop();
      }
      _ => {}
    }
  }
  Some(normalized)
}

pub(crate) fn reserved_secret_mount(target: &str) -> bool {
  normalized_mount_target(target)
    .is_some_and(|path| path.starts_with(SECRET_FILE_DIR))
}

fn check_compose_secret_volumes(
  name: &str,
  doc: &Value,
) -> Result<(), ApiError> {
  let volumes =
    doc["services"]
      .as_mapping()
      .into_iter()
      .flat_map(|services| {
        services.values().flat_map(|service| {
          service["volumes"].as_sequence().into_iter().flatten()
        })
      });
  for volume in volumes {
    let target = if let Some(short) = volume.as_str() {
      // 从右往左拆，源路径可带 Compose 变量及其默认值。
      let (head, tail) =
        short.rsplit_once(':').unwrap_or(("", short));
      if tail.starts_with('/') {
        Some(tail)
      } else {
        head.rsplit_once(':').map(|(_, target)| target)
      }
    } else {
      volume.get("target").and_then(Value::as_str)
    };
    if target.is_some_and(reserved_secret_mount) {
      return Err(ApiError::invalid(format!(
        "服务 {name} 的 compose 卷不能挂载到 {SECRET_FILE_DIR} 或其子路径"
      )));
    }
  }
  Ok(())
}

/// 把配置文件放进 compose：顶层 `configs` 用 `content` 写内容，容器的 `configs` 引用它。
/// compose 判断要不要重建容器时不看内容，所以名字里带内容的哈希，内容一变名字就变，容器跟着重建。
/// `files` 是（容器内路径，已替换好的内容）。没有配置文件时原样返回，不重新生成 YAML。
pub fn add_files(
  name: &str,
  spec: &ServiceSpec,
  compose: &str,
  files: &[(String, String)],
  file_secrets: BTreeSet<String>,
  mut mounts: SecretMounts,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  if files.is_empty() && mounts.is_empty() {
    return Ok(compose.to_string());
  }
  let bad = || {
    ApiError::invalid(format!(
      "服务 {name} 的 compose 写法没法自动加上配置文件"
    ))
    .with_hint(
      "检查容器和顶层 configs 的写法，以及是否重复使用 /run/wharf-secrets 下的路径",
    )
  };
  let mut doc: Value =
    serde_yaml_ng::from_str(compose).map_err(|_| bad())?;
  let merged = parse_compose(compose).map_err(|_| bad())?;
  let secret_files = !mounts.is_empty() || !file_secrets.is_empty();
  if secret_files {
    check_compose_secret_volumes(name, &merged)?;
    doc = merged.clone();
  }
  let mut defs = Mapping::new();
  let mut refs = BTreeMap::<String, Vec<ComposeConfigRef>>::new();
  let mut add =
    |target: &str, id: String, path: String, content: String| {
      let def = serde_yaml_ng::to_value(ComposeConfigDef { content })
        .map_err(|_| bad())?;
      defs.insert(Value::String(id.clone()), def);
      refs.entry(target.to_string()).or_default().push(
        ComposeConfigRef {
          source: id,
          target: path,
        },
      );
      Ok::<_, ApiError>(())
    };
  if !files.is_empty() {
    let target = match &spec.source {
      Source::Compose { .. } => {
        compose_target(name, compose, spec.container.as_deref())?
      }
      _ => name.to_string(),
    };
    for (i, (path, content)) in files.iter().enumerate() {
      let content = content.replace('$', "$$");
      let id = format!("wharf-file-{i}-{}", &hash(&content)[..12]);
      add(&target, id, path.clone(), content)?;
    }
    if !file_secrets.is_empty() {
      mounts.entry(target).or_default().extend(file_secrets);
    }
  }
  for (container, names) in mounts {
    for secret in names {
      let content = secrets
        .and_then(|s| s.get(&secret))
        .ok_or_else(bad)?
        .replace('$', "$$");
      let id =
        format!("wharf-secret-{secret}-{}", &hash(&content)[..12]);
      add(
        &container,
        id,
        format!("{SECRET_FILE_DIR}/{secret}"),
        content,
      )?;
    }
  }
  let key = |s: &str| Value::String(s.to_string());
  let root = doc.as_mapping_mut().ok_or_else(bad)?;
  let configs = root.entry(key("configs")).or_insert_with(|| {
    merged.get("configs").cloned().unwrap_or(Value::Null)
  });
  if configs.is_null() {
    *configs = Value::Mapping(Mapping::new());
  }
  let configs = configs.as_mapping_mut().ok_or_else(bad)?;
  for (id, def) in defs {
    if id
      .as_str()
      .is_some_and(|id| id.starts_with("wharf-secret-"))
      && configs.contains_key(&id)
    {
      return Err(bad());
    }
    configs.insert(id, def);
  }
  for (target, additions) in refs {
    let services = root
      .entry(key("services"))
      .or_insert_with(|| merged["services"].clone())
      .as_mapping_mut()
      .ok_or_else(bad)?;
    let svc = services
      .entry(key(&target))
      .or_insert_with(|| merged["services"][target.as_str()].clone())
      .as_mapping_mut()
      .ok_or_else(bad)?;
    // 只补受本次挂载覆盖的继承项，保留其余存量输出。
    let list = svc.entry(key("configs")).or_insert_with(|| {
      merged["services"][target.as_str()]
        .get("configs")
        .cloned()
        .unwrap_or(Value::Null)
    });
    if list.is_null() {
      *list = Value::Sequence(vec![]);
    }
    let list = list.as_sequence_mut().ok_or_else(bad)?;
    for entry in additions {
      if reserved_secret_mount(&entry.target) {
        let mount = normalized_mount_target(&entry.target);
        if list.iter().any(|v| {
          let existing = match v.as_str() {
            Some(source) => {
              normalized_mount_target(&format!("/{source}"))
            }
            None => v
              .get("target")
              .and_then(Value::as_str)
              .and_then(normalized_mount_target),
          };
          existing.is_some() && existing == mount
        }) {
          return Err(ApiError::invalid(format!(
            "服务 {name} 的容器 {target} 已有重复的挂载目标 {}",
            entry.target
          )));
        }
      }
      list.push(serde_yaml_ng::to_value(entry).map_err(|_| bad())?);
    }
  }
  let head = if compose.starts_with('#') {
    compose
      .lines()
      .next()
      .map(|l| format!("{l}\n"))
      .unwrap_or_default()
  } else {
    String::new()
  };
  Ok(format!(
    "{head}{}",
    serde_yaml_ng::to_string(&doc).map_err(|_| bad())?
  ))
}

/// compose 来源的基本检查：必须有 services，P1 不支持 build。
pub fn check_compose_template(
  name: &str,
  content: &str,
) -> Result<(), ApiError> {
  let mut value: Value =
    serde_yaml_ng::from_str(content).map_err(|e| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 不是合法的 YAML：{e}"
      ))
    })?;
  let services = value
    .get("services")
    .and_then(|s| s.as_mapping())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 里没有 services"
      ))
    })?;
  for (svc, body) in services {
    if body.get("build").is_some() {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的 compose 里 {} 用了 build，不在服务器上构建",
          svc.as_str().unwrap_or("?")
        ))
        .with_hint("先构建并推送镜像，compose 里改用 image"),
      );
    }
  }
  merge_compose(&mut value).map_err(|_| {
    ApiError::invalid(format!(
      "服务 {name} 的 compose YAML 合并不合法"
    ))
  })?;
  check_compose_secret_volumes(name, &value)
}

pub fn check_compose(
  name: &str,
  content: &str,
) -> Result<(), ApiError> {
  let doc = parse_compose_template(content)?;
  crate::syntax_check::validate_compose_structure(name, &doc)?;
  check_compose_secret_volumes(name, &doc)
}

pub fn gateway_image(spec: &GatewaySpec) -> String {
  spec.image.clone().unwrap_or_else(|| {
    match spec.kind {
      GatewayKind::Caddy => DEFAULT_CADDY_IMAGE,
      GatewayKind::CloudflareTunnel => DEFAULT_CLOUDFLARED_IMAGE,
    }
    .to_string()
  })
}

/// cloudflare_tunnel 网关的连接器：host 网络，上游用 127.0.0.1 和内网地址都能访问。
pub fn tunnel_compose(
  name: &str,
  spec: &GatewaySpec,
  token: Option<&str>,
) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    configs: BTreeMap::new(),
    name: project,
    services: BTreeMap::from([(
      "cloudflared".to_string(),
      ComposeService {
        stop_grace_period: None,
        stop_signal: None,
        configs: vec![],
        image: gateway_image(spec),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: None,
        command: Some(
          ["tunnel", "--no-autoupdate", "run"]
            .map(String::from)
            .to_vec(),
        ),
        environment: BTreeMap::from([(
          "TUNNEL_TOKEN".to_string(),
          token.map_or_else(
            || format!("[[{TUNNEL_TOKEN_SECRET}]]"),
            str::to_string,
          ),
        )]),
        ports: vec![],
        volumes: vec![],
        labels: BTreeMap::from([(
          "wharf.gateway".to_string(),
          name.to_string(),
        )]),
      },
    )]),
  };
  to_yaml(&file)
}

/// caddy 网关的 compose：host 网络，这样上游用 127.0.0.1 和内网地址都能访问。
pub fn gateway_compose(name: &str, spec: &GatewaySpec) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    configs: BTreeMap::new(),
    name: project.clone(),
    services: BTreeMap::from([(
      "caddy".to_string(),
      ComposeService {
        stop_grace_period: None,
        stop_signal: None,
        configs: vec![],
        image: gateway_image(spec),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: None,
        command: Some(
          [
            "caddy",
            "run",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
          ]
          .map(String::from)
          .to_vec(),
        ),
        environment: BTreeMap::new(),
        ports: vec![],
        volumes: vec![
          "./conf:/etc/caddy:ro".to_string(),
          format!("/srv/{project}/data:/data"),
          format!("/srv/{project}/config:/config"),
        ],
        labels: BTreeMap::from([(
          "wharf.gateway".to_string(),
          name.to_string(),
        )]),
      },
    )]),
  };
  to_yaml(&file)
}

/// 业务备份只能追加，清理旧快照在备份服务器本机做。
pub fn backup_server_compose(
  listen_ip: &str,
  htpasswd: &str,
) -> String {
  backup_compose(
    BACKUP_PROJECT,
    listen_ip,
    htpasswd,
    wharf_api_types::agent::REST_SERVER_PORT,
    wharf_api_types::agent::BACKUP_ROOT,
  )
}

pub fn core_backup_server_compose(
  listen_ip: &str,
  htpasswd: &str,
) -> String {
  backup_compose(
    CORE_BACKUP_PROJECT,
    listen_ip,
    htpasswd,
    wharf_api_types::agent::CORE_REST_SERVER_PORT,
    wharf_api_types::agent::CORE_BACKUP_ROOT,
  )
}

fn backup_compose(
  project: &str,
  listen_ip: &str,
  htpasswd: &str,
  port: u16,
  root: &str,
) -> String {
  let host = if listen_ip.contains(':') {
    format!("[{listen_ip}]")
  } else {
    listen_ip.to_string()
  };
  let target = "/etc/rest-server/htpasswd";
  let source = format!("wharf-htpasswd-{}", &hash(htpasswd)[..12]);
  let mut command = vec![
    "--path".into(),
    "/data".into(),
    "--htpasswd-file".into(),
    target.into(),
    "--listen".into(),
    format!("{host}:{port}"),
  ];
  let label = if project == BACKUP_PROJECT {
    command
      .extend(["--private-repos".into(), "--append-only".into()]);
    "rest-server"
  } else {
    "rest-server-core"
  };
  to_yaml(&ComposeFile {
    configs: BTreeMap::from([(
      source.clone(),
      ComposeConfigDef {
        content: htpasswd.replace('$', "$$"),
      },
    )]),
    name: project.to_string(),
    services: BTreeMap::from([(
      "rest-server".to_string(),
      ComposeService {
        stop_grace_period: None,
        stop_signal: None,
        configs: vec![ComposeConfigRef {
          source,
          target: target.into(),
        }],
        image: wharf_api_types::agent::REST_SERVER_IMAGE.to_string(),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: Some(vec!["rest-server".into()]),
        command: Some(command),
        environment: BTreeMap::new(),
        ports: vec![],
        volumes: vec![format!("{root}:/data")],
        labels: BTreeMap::from([(
          "wharf.backup".to_string(),
          label.into(),
        )]),
      },
    )]),
  })
}

pub const BACKUP_PROJECT: &str = "wharf-backup";
pub const CORE_BACKUP_PROJECT: &str = "wharf-backup-core";

/// 路由的上游地址：同机用 127.0.0.1，能直连用服务所在机器的内网地址，否则走反向隧道。
pub fn upstream(
  world: &World,
  net: &Net,
  gateway: &GatewaySpec,
  service: &str,
  port: &str,
  mode: wharf_api_types::spec::LinkMode,
) -> Result<String, ApiError> {
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::invalid(format!("服务 {service} 不存在"))
  })?;
  let host = row.host_ports.get(port).ok_or_else(|| {
    ApiError::internal(format!(
      "服务 {service} 的端口 {port} 没有分配"
    ))
  })?;
  use crate::link::{Choice, choose, tunnel_upstream};
  Ok(match choose(world, net, gateway, service, mode)? {
    Choice::Local => host_port("127.0.0.1", *host),
    Choice::Direct(ip) => host_port(&ip, *host),
    Choice::Tunnel => {
      tunnel_upstream(world, net, &gateway.server, service, port)?
    }
  })
}

pub const FRPS_IMAGE: &str = "snowdreamtech/frps:0.61.1";
pub const FRPC_IMAGE: &str = "snowdreamtech/frpc:0.61.1";

/// 一条 Caddy 站点：hostname → 上游。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Site {
  pub gate: Option<Gate>,
  pub hostname: String,
  pub upstream: String,
  /// 登录保护的账号，没开是 `None`。
  pub auth: Option<BasicAuth>,
  /// 按路径转发：（路径，上游）。
  pub paths: Vec<(String, String)>,
  /// 跳转目标。有值时这个站点只做跳转，`upstream`、`auth`、`paths` 不用。
  pub redirect: Option<String>,
  /// 每分钟限速次数，没开是 `None`。
  pub rate_limit: Option<u32>,
  /// 拦截常见扫描。
  pub block_scanners: bool,
  /// 自定义 Caddy 配置，原样插进站点块。
  pub custom: Option<String>,
  /// 只放行内网来源。
  pub internal: bool,
  pub internal_ranges: Vec<String>,
  pub protection: crate::entry_protection::SiteProtection,
  /// 临时分享的到期时间（毫秒），过了就断开。
  pub expires_at: Option<i64>,
  /// 泛域名站点：只签证书，未匹配具体域名的请求直接断开。
  pub wildcard: bool,
  /// DNS 验证的 subdomain（zone 或域名本身）。
  pub dns: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
  /// 公开站点只处理代登录入口和配置了接管的路径。
  pub public: bool,
  pub site_endpoints: bool,
  pub app_login: bool,
  pub user_header: Option<String>,
  pub trusted: Vec<String>,
  pub login: String,
  pub core: String,
  pub skip_paths: Vec<String>,
  pub takeover: Option<(LoginTakeover, String)>,
}

/// 内置的错误页。
const DEFAULT_ERROR_PAGE: &str = include_str!("error_page.html");
/// 错误页在 Caddyfile 里的结束标记；内容里不能出现它。
pub const ERROR_PAGE_END: &str = "WHARF_ERROR_PAGE";

/// 错误页的 snippet：网关自己产生的 502、503、504 返回这张页面。没填或是空的用内置的默认页。
fn error_snippet(spec: &GatewaySpec) -> String {
  let page = spec
    .error_page
    .as_deref()
    .filter(|p| !p.trim().is_empty())
    .unwrap_or(DEFAULT_ERROR_PAGE);
  let mut out = format!(
    "\n(wharf_errors) {{\n\thandle_errors 502 503 504 {{\n\t\theader Content-Type \"text/html; charset=utf-8\"\n\t\trespond <<{ERROR_PAGE_END}\n"
  );
  for line in page.lines() {
    if !line.is_empty() {
      out.push_str("\t\t");
      out.push_str(line);
    }
    out.push('\n');
  }
  out.push_str(&format!(
    "\t\t{ERROR_PAGE_END} {{err.status_code}}\n\t}}\n}}\n"
  ));
  out
}

#[derive(Clone, Copy)]
pub struct AcmeDnsFill<'a> {
  pub key: &'a str,
  pub url: &'a str,
}

#[derive(Clone, Copy, Default)]
pub struct CaddyFill<'a> {
  pub acme_dns: Option<AcmeDnsFill<'a>>,
  pub gate_revocation_key: Option<&'a str>,
}

fn dns_tls(
  gateway: &str,
  subdomain: &str,
  fill: Option<AcmeDnsFill<'_>>,
) -> String {
  let url = fill.map(|f| {
    format!("{}/agent/acme-dns", f.url.trim_end_matches('/'))
  });
  let url = url.as_deref().unwrap_or(ACME_DNS_URL);
  let key = fill.map_or(ACME_DNS_KEY, |f| f.key);
  format!(
    "\ttls {{\n\t\tdns acmedns {{\n\t\t\tusername {gateway}\n\t\t\tpassword {key}\n\t\t\tsubdomain {subdomain}\n\t\t\tserver_url {url}\n\t\t}}\n\t}}\n"
  )
}

const ACCESS_LOG_SNIPPET: &str = r#"
(wharf_access) {
	log {
		output file /data/access.log {
			roll_size 5MiB
			roll_keep 3
			roll_keep_for 168h
			roll_uncompressed
		}
		format filter {
			request>headers delete
			resp_headers delete
			request>tls delete
			request>uri query {
				replace token REDACTED
				replace access_token REDACTED
				replace refresh_token REDACTED
				replace id_token REDACTED
				replace key REDACTED
				replace api_key REDACTED
				replace apikey REDACTED
				replace secret REDACTED
				replace password REDACTED
				replace passwd REDACTED
				replace pwd REDACTED
				replace auth REDACTED
				replace code REDACTED
				replace sign REDACTED
				replace signature REDACTED
				replace sig REDACTED
				replace session REDACTED
				replace ticket REDACTED
				replace jwt REDACTED
				replace rd REDACTED
				replace state REDACTED
			}
		}
	}
}
"#;

#[cfg(test)]
fn caddyfile(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
  forwards: &[(bool, u16, String)],
  link: bool,
  gate_public: Option<&str>,
) -> String {
  caddyfile_with_fill(
    name,
    spec,
    sites,
    forwards,
    link,
    gate_public,
    &[],
    CaddyFill::default(),
  )
}

#[allow(clippy::too_many_arguments)]
pub fn caddyfile_with_fill(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
  forwards: &[(bool, u16, String)],
  link: bool,
  gate_public: Option<&str>,
  trusted_proxies: &[String],
  fill: CaddyFill<'_>,
) -> String {
  let mut out = format!(
    "# 由 Wharf 生成，不要手改。网关：{name}\n# 手写的站点放到 conf/extra.d/*.caddy\n{{\n\tadmin {CADDY_ADMIN}\n\tmetrics {{\n\t\tper_host\n\t}}\n"
  );
  if let Some(port) = spec.http_port.filter(|p| *p != 80) {
    out.push_str(&format!("\thttp_port {port}\n"));
  }
  if let Some(port) = spec.https_port.filter(|p| *p != 443) {
    out.push_str(&format!("\thttps_port {port}\n"));
  }
  if let Some(email) = &spec.email {
    out.push_str(&format!("\temail {email}\n"));
  }
  match spec.tls {
    GatewayTls::Auto => {}
    GatewayTls::Internal => out.push_str("\tlocal_certs\n"),
    GatewayTls::Off => out.push_str("\tauto_https off\n"),
  }
  crate::entry_protection::render_abort_order(&mut out, sites);
  if sites
    .iter()
    .any(|s| s.redirect.is_none() && s.block_scanners)
  {
    out.push_str("\torder respond before basic_auth\n");
  }
  if sites
    .iter()
    .any(|s| s.redirect.is_none() && s.rate_limit.is_some())
  {
    out.push_str("\torder rate_limit before basic_auth\n");
  }
  if sites.iter().any(|s| s.gate.is_some()) {
    out.push_str("\torder wharf_sso before basic_auth\n");
  }
  crate::entry_protection::render_servers(
    &mut out,
    spec,
    trusted_proxies,
  );
  if !forwards.is_empty() {
    out.push_str("\tlayer4 {\n");
    let mut forwards = forwards.to_vec();
    forwards.sort_by_key(|(udp, listen, _)| (*udp, *listen));
    for (udp, listen, upstream) in forwards {
      let protocol = if udp { "udp/" } else { "" };
      out.push_str(&format!("\t\t{protocol}:{listen} {{\n\t\t\troute {{\n\t\t\t\tproxy {protocol}{upstream}\n\t\t\t}}\n\t\t}}\n"));
    }
    out.push_str("\t}\n");
  }
  out.push_str("}\n");
  out.push_str(ACCESS_LOG_SNIPPET);
  out.push_str(&error_snippet(spec));
  out.push_str(&format!(
    "\n(wharf_upstream) {{\n\tlb_try_duration {UPSTREAM_TRY_DURATION}\n\tlb_try_interval {UPSTREAM_TRY_INTERVAL}\n}}\n"
  ));
  crate::source_trust::render_proxy_headers(
    &mut out,
    trusted_proxies,
  );
  if sites.iter().any(|s| s.block_scanners) {
    out.push_str(&format!(
      "\n(wharf_scanners) {{\n\t@wharf_scanner_path path {SCANNER_PATHS}\n\t@wharf_scanner_ua header_regexp User-Agent \"{SCANNER_UA}\"\n\trespond @wharf_scanner_path 404\n\trespond @wharf_scanner_ua 404\n}}\n"
    ));
  }
  out.push_str("\nimport /etc/caddy/extra.d/*.caddy\n");
  let scheme = match spec.tls {
    GatewayTls::Off => "http://",
    _ => "",
  };
  let mut sites = sites.to_vec();
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  for site in sites {
    site.protection.render_http_redirect(
      &mut out,
      spec,
      &site.hostname,
    );
    out.push_str(&format!("\n{scheme}{} {{\n", site.hostname));
    site.protection.render_matchers(&mut out);
    if site.wildcard {
      if let Some(subdomain) = &site.dns {
        out.push_str(&dns_tls(name, subdomain, fill.acme_dns));
      }
      out.push_str("\tabort\n}\n");
      continue;
    }
    if !site.internal {
      out.push_str("\timport wharf_access\n");
    }
    if let Some(target) = &site.redirect {
      out.push_str(&format!(
        "\tredir {target}{{uri}} permanent\n}}\n"
      ));
      continue;
    }
    out.push_str("\timport wharf_errors\n");
    if !trusted_proxies.is_empty() {
      out.push_str("\timport wharf_strip_forwarded\n");
    }
    if let Some(ms) = site.expires_at {
      out.push_str(&format!(
        "\t@wharf_expired expression `int({{time.now.unix}}) >= {}`\n\tabort @wharf_expired\n",
        ms / 1000
      ));
    }
    if let Some(subdomain) = &site.dns {
      out.push_str(&dns_tls(name, subdomain, fill.acme_dns));
    }
    if site.internal {
      let ranges = if site.internal_ranges.is_empty() {
        "127.0.0.0/8 ::1/128".to_string()
      } else {
        site.internal_ranges.join(" ")
      };
      out.push_str(&format!("\t@wharf_outside not remote_ip {ranges}\n\tabort @wharf_outside\n"));
    }
    if site.block_scanners {
      out.push_str("\timport wharf_scanners\n");
    }
    if let Some(n) = site.rate_limit {
      let zone = site.hostname.replace('.', "_");
      let key = if trusted_proxies.is_empty() {
        "{remote_host}"
      } else {
        "{client_ip}"
      };
      out.push_str(&format!(
        "\trate_limit {{\n\t\tzone wharf_{zone} {{\n\t\t\tkey {key}\n\t\t\tevents {n}\n\t\t\twindow 1m\n\t\t}}\n\t}}\n"
      ));
    }
    if let Some(custom) = &site.custom {
      for line in custom.lines() {
        let line = line.trim_end();
        if !line.is_empty() {
          out.push('\t');
          out.push_str(line);
        }
        out.push('\n');
      }
    }
    if let Some(gate) = &site.gate {
      gate::render_gate(
        &mut out,
        gate,
        gate_public,
        fill.gate_revocation_key,
      );
    }
    if let Some(a) = &site.auth {
      out.push_str(&format!(
        "\tbasic_auth {{\n\t\t{} {}\n\t}}\n",
        a.user, a.hash
      ));
    }
    // 带路径的 reverse_proxy 由 Caddy 排在不带路径的前面。
    for (path, upstream) in &site.paths {
      out.push_str(&format!(
        "\treverse_proxy {path} {upstream} {{\n\t\timport wharf_upstream\n\t}}\n"
      ));
    }
    out.push_str(&format!(
      "\treverse_proxy {} {{\n\t\timport wharf_upstream\n\t}}\n}}\n",
      site.upstream
    ));
  }
  crate::entry_protection::render_http_fallback(&mut out, spec);
  // frpc 按 IP 连进来，用固定 SNI 校验集群 CA 签发的证书。
  if link {
    out.push_str(&format!(
      "\n{} {{\n\ttls /etc/caddy/link.crt /etc/caddy/link.key\n\treverse_proxy {} 127.0.0.1:{}\n}}\n",
      crate::link::LINK_HOST,
      crate::link::FRP_PATH,
      crate::link::FRPS_PORT
    ));
  }
  out
}

#[cfg(test)]
mod tests {
  #[test]
  fn expected_components_skips_profiles_and_explicit_no_restart() {
    let yaml = "services:\n  web: {}\n  worker: {}\n  tools: {profiles: [debug]}\n  init: {restart: \"no\"}\n";
    assert_eq!(
      super::expected_components(yaml, &[]),
      ["web", "worker"]
    );
    assert_eq!(
      super::expected_components(yaml, &["debug".into()]),
      ["tools", "web", "worker"]
    );
  }

  #[test]
  fn stored_compose_keeps_bytes_and_hash() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "limits": {"memory_mb": 64}, "source": {"compose": {
        "content": "# 保留注释\nservices:\n  app:\n    image: nginx:1\n    environment:\n      PASS: \"[[K]]\"\n"
      }}
    })).unwrap();
    let (out, _) = service_compose(
      "app",
      &spec,
      &BTreeMap::new(),
      &[],
      Some(&BTreeMap::from([("K".into(), "a$b".into())])),
    )
    .unwrap();
    assert_eq!(
      out,
      "# 保留注释\nservices:\n  app:\n    mem_limit: 64m\n    image: nginx:1\n    environment:\n      PASS: \"a$$b\"\n"
    );
    assert_eq!(
      hash(&out),
      "137c8cb13222fd17ff61583ca9dbfdc0fcadaa19ed587605145d6880ec7b3ff5"
    );
  }

  #[test]
  fn triple_brackets_replace_inner_secret() {
    let secrets = BTreeMap::from([("K".into(), "v".into())]);
    assert_eq!(substitute("[[[K]]]", Some(&secrets)).unwrap(), "[v]");
  }

  #[test]
  fn compose_settings_preserve_literal_backslashes_in_resolved_env() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "env": {"PASS":"[[K]]"}, "source":{"compose":{
        "content":"services:\n  app:\n    image: nginx\n"
      }}
    }))
    .unwrap();
    let (out, _) = service_compose(
      "app",
      &spec,
      &BTreeMap::new(),
      &[],
      Some(&BTreeMap::from([("K".into(), r"a\nb".into())])),
    )
    .unwrap();
    assert_eq!(
      parse_compose(&out).unwrap()["services"]["app"]["environment"]
        ["PASS"],
      r"a\nb"
    );
  }

  #[test]
  fn compose_settings_detect_inherited_conflicts() {
    let text = concat!(
      "x-a: &a {mem_limit: 128m, environment: {FOO: '1'}}\n",
      "x-b: &b {<<: *a}\n",
      "services:\n  app:\n    <<: *b\n    image: nginx\n",
    );
    for (settings, error) in [
      (
        serde_json::json!({"limits": {"memory_mb": 64}}),
        "已经写了 mem_limit",
      ),
      (
        serde_json::json!({"env": {"FOO": "2"}}),
        "环境变量 FOO 在 compose 里已经写了",
      ),
    ] {
      let mut input = serde_json::json!({"server": "s1", "source": {"compose": {"content": text}}});
      input
        .as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
      let spec = serde_json::from_value(input).unwrap();
      assert!(
        compose_with_settings("app", text, &spec)
          .unwrap_err()
          .message
          .contains(error)
      );
    }
    let stored = serde_json::from_value(serde_json::json!({
      "server": "s1", "limits": {"memory_mb": 64},
      "source": {"compose": {"content": text}},
    }))
    .unwrap();
    let (rendered, _) =
      service_compose("app", &stored, &BTreeMap::new(), &[], None)
        .unwrap();
    assert_eq!(
      rendered,
      text.replacen("  app:\n", "  app:\n    mem_limit: 64m\n", 1)
    );
  }

  #[test]
  fn compose_target_finds_inherited_services() {
    let text =
      "x-base: &b {services: {app: {image: nginx}}}\n<<: *b\n";
    assert_eq!(compose_target("app", text, None).unwrap(), "app");
  }

  #[test]
  fn add_files_preserves_inherited_configs() {
    let text = concat!(
      "x-base: &b {configs: [{source: base, target: /etc/base.conf}]}\n",
      "services: {app: {<<: *b, image: nginx}}\n",
      "configs: {base: {content: base}}\n",
    );
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"compose": {"content": text}}
    }))
    .unwrap();
    let out = add_files(
      "app",
      &spec,
      text,
      &[("/etc/app.conf".into(), "ok".into())],
      BTreeSet::new(),
      BTreeMap::new(),
      None,
    )
    .unwrap();
    let after = parse_compose(&out).unwrap();
    let mounts = &after["services"]["app"]["configs"];
    assert_eq!(mounts[0]["source"], "base");
    assert_eq!(mounts[0]["target"], "/etc/base.conf");
    assert_eq!(mounts[1]["target"], "/etc/app.conf");
  }

  #[test]
  fn compose_settings_escape_resolved_env_with_quotes_and_newlines() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "env": {"PASS":"[[K]]"}, "source":{"compose":{
        "content":"services:\n  app:\n    image: nginx\n"
      }}
    }))
    .unwrap();
    let (out, _) = service_compose(
      "app",
      &spec,
      &BTreeMap::new(),
      &[],
      Some(&BTreeMap::from([("K".into(), "p$\"\\\nline".into())])),
    )
    .unwrap();
    assert_eq!(
      parse_compose(&out).unwrap()["services"]["app"]["environment"]
        ["PASS"],
      "p$$\"\\\nline"
    );
  }

  #[test]
  fn check_compose_blocks_build_in_anchor() {
    let err = check_compose("app", "x-base: &b {build: .}\nservices: {app: {<<: *b, image: nginx}}").unwrap_err();
    assert!(err.message.contains("用了 build"));
  }

  #[test]
  fn add_files_accepts_null_configs() {
    let text =
      "services:\n  app:\n    image: nginx\n    configs:\nconfigs:\n";
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"compose":{"content":text}}
    }))
    .unwrap();
    let out = add_files(
      "app",
      &spec,
      text,
      &[("/etc/app.conf".into(), "ok".into())],
      BTreeSet::new(),
      BTreeMap::new(),
      None,
    )
    .unwrap();
    let doc = parse_compose(&out).unwrap();
    let mount = &doc["services"]["app"]["configs"][0];
    assert_eq!(mount["target"], "/etc/app.conf");
    assert_eq!(
      doc["configs"][mount["source"].as_str().unwrap()]["content"],
      "ok"
    );
    assert_eq!(
      host_port("fd7a:115c:a1e0::1", 8080),
      "[fd7a:115c:a1e0::1]:8080"
    );
  }

  use super::*;
  use wharf_api_types::spec::Limits;
  use wharf_api_types::spec::{GatewayKind, PortSpec, VolumeSpec};

  #[test]
  fn files_become_configs_named_by_content() {
    let base =
      service_compose("whoami", &spec(), &BTreeMap::new(), &[], None)
        .unwrap()
        .0;
    let secrets =
      BTreeMap::from([("PASS".to_string(), "p$w".to_string())]);
    let content = file_content(
      "[[servers]]\npass = \"[[PASS]]\"\n",
      Some(&secrets),
      &mut BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(content, "[[servers]]\npass = \"p$w\"\n");
    let files = vec![("/etc/app.toml".to_string(), content)];
    let out = add_files(
      "whoami",
      &spec(),
      &base,
      &files,
      BTreeSet::new(),
      BTreeMap::new(),
      None,
    )
    .unwrap();
    let v: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let r = &v["services"]["whoami"]["configs"][0];
    assert_eq!(r["target"].as_str(), Some("/etc/app.toml"));
    let id = r["source"].as_str().unwrap();
    assert_eq!(
      v["configs"][id]["content"].as_str(),
      Some("[[servers]]\npass = \"p$$w\"\n")
    );
    let changed =
      vec![("/etc/app.toml".to_string(), "x".to_string())];
    let out2 = add_files(
      "whoami",
      &spec(),
      &base,
      &changed,
      BTreeSet::new(),
      BTreeMap::new(),
      None,
    )
    .unwrap();
    assert!(!out2.contains(id));
    assert_eq!(
      add_files(
        "whoami",
        &spec(),
        &base,
        &[],
        BTreeSet::new(),
        BTreeMap::new(),
        None
      )
      .unwrap(),
      base
    );
  }

  #[test]
  fn shared_volume_renders_owner_path_and_ro_without_legacy_drift() {
    let mut spec = spec();
    let render = |spec| {
      service_compose("app", spec, &BTreeMap::new(), &[], None)
        .unwrap()
        .0
    };
    let volume = &spec.volumes[0];
    let before = render(&spec);
    assert!(before.contains(&format!(
      "/srv/app/{}:{}",
      volume.name, volume.target
    )));
    let volume = &mut spec.volumes[0];
    volume.from_service = Some("photos:originals".into());
    volume.read_only = true;
    let target = volume.target.clone();
    assert!(
      render(&spec)
        .contains(&format!("/srv/photos/originals:{target}:ro"))
    );
    assert_eq!(service_dirs("app", &spec), ["/srv/photos/originals"]);
  }

  fn spec() -> ServiceSpec {
    ServiceSpec {
      backup: None,
      stopped: false,
      monitor: None,
      start_timeout_secs: None,
      log_alerts: vec![],
      port_checks: Default::default(),
      heartbeat: None,
      limits: None,
      auto_update: false,
      container: None,
      files: vec![],
      stop_grace_secs: None,
      stop_signal: None,
      init_cmd: None,
      init_timeout_secs: None,
      server: "node1".into(),
      source: Source::Image("traefik/whoami".into()),
      ports: vec![PortSpec {
        name: "http".into(),
        container: Some(80),
        host: None,
        udp: false,
      }],
      env: BTreeMap::from([
        ("A".to_string(), "x$y".to_string()),
        ("TOKEN".to_string(), "[[WHO_TOKEN]]".to_string()),
      ]),
      volumes: vec![VolumeSpec {
        from_service: None,
        read_only: false,
        name: "data".into(),
        target: "/data".into(),
      }],
    }
  }

  #[test]
  fn stop_grace_zero_drift_and_renders_when_set() {
    let legacy = serde_json::json!({"server": "s1", "source": {"image": "alpine"}});
    let mut spec: ServiceSpec =
      serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(&spec).unwrap(), legacy);
    let render = |spec: &ServiceSpec| {
      service_compose("a", spec, &BTreeMap::new(), &[], None)
        .unwrap()
        .0
    };
    let expected = "# 由 Wharf 生成，不要手改。\nname: a\nservices:\n  a:\n    image: alpine\n    restart: unless-stopped\n    labels:\n      wharf.service: a\n";
    assert_eq!(hash(&render(&spec)), hash(expected));
    spec.stop_grace_secs = Some(300);
    spec.stop_signal = Some("SIGINT".into());
    let yaml = render(&spec);
    assert!(yaml.contains("stop_grace_period: 300s"));
    assert!(yaml.contains("stop_signal: SIGINT"));
    assert!(
      !trial_compose("a", &spec, None)
        .unwrap()
        .0
        .contains("stop_grace_period")
    );
  }

  #[test]
  fn caddyfile_share_expires() {
    let gw: GatewaySpec =
      serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
        .unwrap();
    let mut site = Site {
      hostname: "a.example.com".into(),
      expires_at: Some(1_800_000_000_000),
      ..Default::default()
    };
    let out =
      caddyfile("edge", &gw, &[site.clone()], &[], false, None);
    assert_eq!(
      out.matches("order abort before basic_auth").count(),
      1
    );
    assert!(out.contains(
      "@wharf_expired expression `int({time.now.unix}) >= 1800000000`"
    ));
    assert!(out.contains("abort @wharf_expired"));
    assert!(
      out.find("import wharf_errors").unwrap()
        < out.find("@wharf_expired").unwrap()
    );
    site.expires_at = None;
    assert!(
      !caddyfile("edge", &gw, &[site], &[], false, None)
        .contains("wharf_expired")
    );
  }

  #[test]
  fn caddyfile_internal_site() {
    let gw: GatewaySpec =
      serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
        .unwrap();
    let mut site = Site {
      hostname: "i.example.com".into(),
      upstream: "127.0.0.1:21000".into(),
      internal: true,
      dns: Some("i.example.com".into()),
      ..Default::default()
    };
    let out =
      caddyfile("edge", &gw, &[site.clone()], &[], false, None);
    assert!(out.contains("dns acmedns {"));
    assert!(!out.contains("import wharf_access"));
    assert!(out.contains("@wharf_outside not remote_ip 127.0.0.0/8 ::1/128\n\tabort @wharf_outside"));
    for broad in
      ["private_ranges", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]
    {
      assert!(!out.contains(broad));
    }
    assert!(
      out.find("import wharf_errors").unwrap()
        < out.find("\ttls {").unwrap()
    );
    assert!(
      out.find("\ttls {").unwrap()
        < out.find("@wharf_outside").unwrap()
    );
    assert_eq!(
      out.matches("order abort before basic_auth").count(),
      1
    );
    site.dns = None;
    site.internal_ranges =
      ["10.20.0.0/24", "100.64.0.7/32", "127.0.0.0/8", "::1/128"]
        .map(str::to_string)
        .to_vec();
    let out =
      caddyfile("edge", &gw, &[site.clone()], &[], false, None);
    assert!(out.contains("@wharf_outside not remote_ip 10.20.0.0/24 100.64.0.7/32 127.0.0.0/8 ::1/128"));
    assert!(!out.contains("dns acmedns"));
    site.internal = false;
    let out = caddyfile("edge", &gw, &[site], &[], false, None);
    assert!(!out.contains("wharf_outside"));
    assert!(!out.contains("dns acmedns"));
    assert!(!out.contains("order abort"));
  }

  #[test]
  fn caddyfile_trusted_proxies_controls_headers_and_rate_limit() {
    let mut spec: GatewaySpec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1", "error_page": "fixture",
      "trusted_proxies": {"cloudflare": true, "cluster": true, "cidrs": ["203.0.113.0/24"]}
    })).unwrap();
    let net = Net::default();
    let ranges = crate::source_trust::gateway_trusted_proxies(
      &crate::world::World::default(),
      &net,
      &spec,
      &["173.245.48.0/20".into()],
    );
    let sites = [Site {
      hostname: "example.com".into(),
      upstream: "127.0.0.1:20005".into(),
      rate_limit: Some(42),
      ..Default::default()
    }];
    let out = caddyfile_with_fill(
      "edge",
      &spec,
      &sites,
      &[],
      false,
      None,
      &ranges,
      CaddyFill::default(),
    );
    assert!(out.contains("trusted_proxies static 127.0.0.1/32 173.245.48.0/20 203.0.113.0/24 ::1/128\n\t\ttrusted_proxies_strict"));
    assert!(out.contains("(wharf_strip_forwarded)"));
    assert!(out.contains("import wharf_strip_forwarded"));
    assert!(out.contains(
      "request_header @wharf_untrusted_proxy -CF-Connecting-IP"
    ));
    assert!(out.contains("request_header X-Real-IP {client_ip}"));
    assert!(out.contains("key {client_ip}"));
    spec.trusted_proxies = None;
    let legacy = caddyfile("edge", &spec, &sites, &[], false, None);
    assert!(!legacy.contains("trusted_proxies"));
    assert!(!legacy.contains("wharf_strip_forwarded"));
    assert!(legacy.contains("key {remote_host}"));
    assert_eq!(out.matches("\n\tservers {").count(), 1);
    assert!(out.contains("\tgrace_period 10s\n\tservers {"));
    assert!(out.contains("\t\t\tread_header 10s\n\t\t\tidle 2m"));
    assert_eq!(legacy.matches("\n\tservers {").count(), 1);
    let before_edge_protection = legacy
      .replace("\tgrace_period 10s\n\tservers {\n\t\ttimeouts {\n\t\t\tread_header 10s\n\t\t\tidle 2m\n\t\t}\n\t}\n", "")
      .replace("\nhttp://:80 {\n\tabort\n}\n", "");
    assert_eq!(
      hash(&before_edge_protection),
      "3304837aead9414fe3d3192bbabc2f263fc2817e5ee805cabeac7885c01b2cdf"
    );
  }

  #[test]
  fn caddyfile_layer4_only_when_used() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let sites = vec![Site {
      hostname: "example.com".into(),
      upstream: "127.0.0.1:20005".into(),
      ..Default::default()
    }];
    let empty = caddyfile("edge", &gw, &sites, &[], false, None);
    assert!(!empty.contains("layer4"));
    let out = caddyfile(
      "edge",
      &gw,
      &sites,
      &[
        (false, 15432, "127.0.0.1:20005".into()),
        (false, 2222, "127.0.0.1:20007".into()),
        (true, 27015, "127.0.0.1:20006".into()),
      ],
      false,
      None,
    );
    assert_eq!(out.matches("layer4 {").count(), 1);
    assert!(
      out.find(":2222 {").unwrap() < out.find(":15432 {").unwrap()
    );
    assert!(out.contains(
      ":15432 {\n\t\t\troute {\n\t\t\t\tproxy 127.0.0.1:20005"
    ));
    assert!(out.contains("udp/:27015 {"));
    assert!(out.contains("proxy udp/127.0.0.1:20006"));
    assert_eq!(
      &out[out.find("\nexample.com {").unwrap()..],
      &empty[empty.find("\nexample.com {").unwrap()..]
    );
    let mut svc = spec();
    svc.env.clear();
    svc.ports.push(PortSpec {
      name: "game".into(),
      container: Some(27015),
      host: None,
      udp: true,
    });
    let compose = service_compose(
      "app",
      &svc,
      &BTreeMap::from([
        ("http".into(), 20005),
        ("game".into(), 20006),
      ]),
      &["100.64.0.1".into()],
      None,
    )
    .unwrap()
    .0;
    assert!(compose.contains("127.0.0.1:20006:27015/udp"));
    assert!(compose.contains("100.64.0.1:20006:27015/udp"));
    assert!(compose.contains("127.0.0.1:20005:80"));
    assert!(!compose.contains("20005:80/"));
  }

  #[test]
  fn caddyfile_access_logs_skip_wildcard() {
    let gw =
      serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
        .unwrap();
    let sites = [
      Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:21000".into(),
        ..Default::default()
      },
      Site {
        hostname: "*.example.com".into(),
        wildcard: true,
        ..Default::default()
      },
    ];
    let out = caddyfile("edge", &gw, &sites, &[], false, None);
    assert_eq!(out.matches("(wharf_access) {").count(), 1);
    assert!(out.contains("output file /data/access.log {"));
    assert!(out.contains("a.example.com {\n\timport wharf_access\n"));
    assert!(out.contains("*.example.com {\n\tabort\n}"));
    assert_eq!(out.matches("import wharf_access").count(), 1);
  }

  #[test]
  fn caddyfile_wildcard_site() {
    let mut gw: GatewaySpec =
      serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
        .unwrap();
    let mut site = Site {
      hostname: "*.example.com".into(),
      wildcard: true,
      dns: Some("example.com".into()),
      ..Default::default()
    };
    let empty = caddyfile("edge", &gw, &[], &[], false, None);
    let auto = caddyfile(
      "edge",
      &gw,
      std::slice::from_ref(&site),
      &[],
      false,
      None,
    );
    for text in [
      "*.example.com {",
      "dns acmedns {",
      "username edge",
      "password [[WHARF_ACME_DNS_KEY]]",
      "subdomain example.com",
      "server_url [[WHARF_ACME_DNS_URL]]",
      "\tabort\n}",
    ] {
      assert!(auto.contains(text), "{text}");
    }
    assert!(auto.ends_with("\tabort\n}\n"));
    gw.tls = GatewayTls::Internal;
    site.dns = None;
    let internal = caddyfile("edge", &gw, &[site], &[], false, None);
    assert!(!internal.contains("acmedns"));
    let global = |s: &str| {
      s.split("\n(wharf_errors)").next().unwrap().to_string()
    };
    assert_eq!(global(&auto), global(&empty));
    assert_eq!(
      global(&internal),
      global(&caddyfile("edge", &gw, &[], &[], false, None))
    );
    for out in [&empty, &auto, &internal] {
      assert!(!out.contains("prefer_wildcard"));
    }
  }

  #[test]
  fn gateway_uses_fixed_default_image() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "kind": "caddy"
    }))
    .unwrap();
    assert!(
      gateway_compose("edge", &spec).contains(DEFAULT_CADDY_IMAGE)
    );
    assert!(!DEFAULT_CADDY_IMAGE.contains("latest"));
    assert!(!DEFAULT_CADDY_IMAGE.contains("sha-"));
  }

  #[test]
  fn image_compose_binds_loopback_and_private_only() {
    let ports = BTreeMap::from([("http".to_string(), 20000)]);
    let secrets = BTreeMap::from([(
      "WHO_TOKEN".to_string(),
      "s3$cret".to_string(),
    )]);
    let out = service_compose(
      "whoami",
      &spec(),
      &ports,
      &["100.1.2.3".to_string(), "192.168.1.5".to_string()],
      Some(&secrets),
    )
    .unwrap()
    .0;
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let svc = &yaml["services"]["whoami"];
    assert_eq!(svc["ports"][0], "127.0.0.1:20000:80");
    assert_eq!(svc["ports"][1], "100.1.2.3:20000:80");
    assert_eq!(svc["ports"][2], "192.168.1.5:20000:80");
    assert_eq!(svc["environment"]["A"], "x$$y");
    assert_eq!(svc["environment"]["TOKEN"], "s3$$cret");
    assert_eq!(svc["volumes"][0], "/srv/whoami/data:/data");
    assert!(!out.contains("0.0.0.0"));
    // 不带密钥渲染时保留占位符，用于展示。
    let template =
      service_compose("whoami", &spec(), &ports, &[], None)
        .unwrap()
        .0;
    assert!(template.contains("[[WHO_TOKEN]]"));
    assert!(!template.contains("s3"));
  }

  #[test]
  fn trial_compose_does_not_publish_ports() {
    let mut spec = spec();
    spec.volumes.clear();
    let out = trial_compose("s1", &spec, None).unwrap().0;
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let service = &yaml["services"]["s1"];
    assert_eq!(yaml["name"], "wharf-try-s1");
    assert_eq!(service["restart"], "no");
    assert_eq!(service["environment"]["A"], "x$$y");
    assert_eq!(service["labels"]["wharf.trial"], "s1");
    assert!(service.get("ports").is_none());
    assert!(!out.contains("wharf.service"));
  }

  #[test]
  fn service_limits_are_optional() {
    let mut spec = spec();
    let out =
      service_compose("s1", &spec, &BTreeMap::new(), &[], None)
        .unwrap()
        .0;
    assert!(!out.contains("mem_limit"));
    assert!(!out.contains("cpus"));
    spec.limits = Some(wharf_api_types::spec::Limits {
      memory_mb: Some(512),
      cpu_milli: Some(500),
    });
    let out =
      service_compose("s1", &spec, &BTreeMap::new(), &[], None)
        .unwrap()
        .0;
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let svc = &yaml["services"]["s1"];
    assert_eq!(svc["mem_limit"], "512m");
    assert_eq!(svc["cpus"], "0.5");
    assert_eq!(cpus_text(1000), "1");
    assert_eq!(cpus_text(1250), "1.25");
  }

  fn compose_spec(
    content: &str,
    memory: Option<u32>,
    cpu: Option<u32>,
    env: &[(&str, &str)],
    container: Option<&str>,
  ) -> ServiceSpec {
    let mut spec: ServiceSpec =
      serde_json::from_value(serde_json::json!({
        "server": "s1",
        "source": { "compose": { "content": content } },
      }))
      .unwrap();
    if memory.is_some() || cpu.is_some() {
      spec.limits = Some(Limits {
        memory_mb: memory,
        cpu_milli: cpu,
      });
    }
    spec.env = env
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect();
    spec.container = container.map(str::to_string);
    spec
  }

  #[test]
  fn compose_limits_keep_original_text() {
    let source = "# 原样保留\nservices: # 服务\n  # 注释\n  web: # 容器\n    image: nginx\n    environment:\n      KEY: [[SECRET]]\n    ports:\n      - \"127.0.0.1:8080:80\"\n";
    let expected = "# 原样保留\nservices: # 服务\n  # 注释\n  web: # 容器\n    mem_limit: 512m\n    cpus: \"0.5\"\n    image: nginx\n    environment:\n      KEY: [[SECRET]]\n    ports:\n      - \"127.0.0.1:8080:80\"\n";
    let with = |cpu| {
      compose_with_settings(
        "s1",
        source,
        &compose_spec(source, Some(512), cpu, &[], None),
      )
      .unwrap()
    };
    assert_eq!(with(Some(500)), expected);
    assert_eq!(
      with(None),
      expected.replace("    cpus: \"0.5\"\n", "")
    );
  }

  #[test]
  fn compose_env_goes_to_chosen_container() {
    let source = "services:\n  db:\n    image: mysql\n    environment:\n      - A=1\n  app:\n    image: halo # 主容器\n    environment:\n      KEY: [[SECRET]]\n  side:\n    image: x\n";
    // 多个容器：没选容器时报错，提示可选的容器。
    let error = compose_with_settings(
      "s1",
      source,
      &compose_spec(source, None, None, &[("B", "2")], None),
    )
    .unwrap_err();
    assert!(error.message.contains("3 个容器"));
    // mapping 写法的 environment 里追加，`$` 转义。
    let out = compose_with_settings(
      "s1",
      source,
      &compose_spec(
        source,
        Some(256),
        None,
        &[("B", "a$b")],
        Some("app"),
      ),
    )
    .unwrap();
    assert_eq!(
      out,
      "services:\n  db:\n    image: mysql\n    environment:\n      - A=1\n  app:\n    mem_limit: 256m\n    image: halo # 主容器\n    environment:\n      B: \"a$$b\"\n      KEY: [[SECRET]]\n  side:\n    image: x\n"
    );
    // 列表写法。
    let out = compose_with_settings(
      "s1",
      source,
      &compose_spec(source, None, None, &[("B", "2")], Some("db")),
    )
    .unwrap();
    assert!(
      out
        .contains("    environment:\n      - \"B=2\"\n      - A=1\n")
    );
    // 没有 environment 的容器新加一段。
    let out = compose_with_settings(
      "s1",
      source,
      &compose_spec(source, None, None, &[("B", "2")], Some("side")),
    )
    .unwrap();
    assert!(out.ends_with(
      "  side:\n    environment:\n      B: \"2\"\n    image: x\n"
    ));
    // 和 compose 里重复的变量。
    let error = compose_with_settings(
      "s1",
      source,
      &compose_spec(source, None, None, &[("A", "2")], Some("db")),
    )
    .unwrap_err();
    assert!(error.message.contains("已经写了"));
    let error = compose_with_settings(
      "s1",
      source,
      &compose_spec(source, None, None, &[("B", "2")], Some("nope")),
    )
    .unwrap_err();
    assert!(error.message.contains("没有容器 nope"));
  }

  #[test]
  fn compose_limits_reject_unsupported_forms() {
    let check = |source: &str| {
      compose_with_settings(
        "s1",
        source,
        &compose_spec(source, Some(512), None, &[], None),
      )
      .unwrap_err()
      .message
    };
    assert!(check("services:\n  web:\n    image: nginx\n  worker:\n    image: nginx\n").contains("2 个容器"));
    assert!(
      check(
        "services:\n  web:\n    image: nginx\n    mem_limit: 64m\n"
      )
      .contains("已经写了 mem_limit")
    );
    assert!(
      check("services: {web: {image: nginx}}")
        .contains("写法没法自动加上")
    );
  }

  #[test]
  fn modifiers_encode_environment_compose_and_configuration_files() {
    let value = "p@s#1\n\"\\";
    let secrets = BTreeMap::from([("K".into(), value.into())]);
    let name = "app";
    let source = "services:\n  app:\n    image: nginx:1\n    environment:\n      RAW: \"[[json:K]]\"\n";
    let env = [
      ("URL", "[[url:K]]"),
      ("B64", "[[b64:K]]"),
      ("JSON", "[[json:K]]"),
    ];
    let rendered = |spec: &ServiceSpec| {
      let (yaml, _) = service_compose(
        name,
        spec,
        &BTreeMap::new(),
        &[],
        Some(&secrets),
      )
      .unwrap();
      serde_yaml_ng::from_str::<Value>(&yaml).unwrap()
    };
    let mut compose =
      compose_spec(source, None, None, &env[..2], None);
    let doc = rendered(&compose);
    let env_yaml = &doc["services"][name]["environment"];
    assert_eq!(env_yaml["RAW"], value);
    assert_eq!(env_yaml["URL"], "p%40s%231%0A%22%5C");
    assert_eq!(env_yaml["B64"], "cEBzIzEKIlw=");
    compose.source = Source::Image("nginx:1".into());
    compose.env.extend(env.map(|(k, v)| (k.into(), v.into())));
    let doc = rendered(&compose);
    let env_yaml = &doc["services"][name]["environment"];
    for (key, reference, expected) in [
      ("URL", "[[url:K]]", "p%40s%231%0A%22%5C"),
      ("B64", "[[b64:K]]", "cEBzIzEKIlw="),
      ("JSON", "[[json:K]]", r#"p@s#1\n\"\\"#),
    ] {
      assert_eq!(env_yaml[key], expected);
      assert_eq!(
        substitute(reference, Some(&secrets)).unwrap(),
        expected
      );
      assert_eq!(
        file_content(reference, Some(&secrets), &mut BTreeSet::new())
          .unwrap(),
        expected
      );
    }
    let json = file_content(
      r#""[[json:K]]""#,
      Some(&secrets),
      &mut BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(serde_json::from_str::<String>(&json).unwrap(), value);
  }

  #[test]
  fn malformed_modifiers_and_unclosed_brackets() {
    let secrets =
      BTreeMap::from([("X".into(), "fixture-value".into())]);
    for text in [
      "[[file:X]]",
      "[[URL:X]]",
      "[[hex:X]]",
      "[[b64:]]",
      "[[FILE:b64:X]]",
    ] {
      assert!(
        substitute(text, Some(&secrets)).unwrap_err().hint.is_some()
      );
    }
    assert_eq!(
      substitute("a [[oops [[X]] b", Some(&secrets)).unwrap(),
      "a [[oops fixture-value b"
    );
    let mut files = BTreeSet::new();
    let raw = "[[a b]]\n[[servers]]";
    assert_eq!(
      file_content(raw, Some(&secrets), &mut files).unwrap(),
      raw
    );
    assert!(
      file_content("[[url:NOPE]]", Some(&secrets), &mut files)
        .unwrap_err()
        .message
        .contains("密钥不存在")
    );
  }

  #[test]
  fn compose_doubles_secret_dollars_and_rejects_yaml_damage() {
    let raw = "services:\n  app:\n    image: nginx:1\n    environment:\n      KEY: \"[[KEY]]\"\n";
    let fill = |raw: &str, value: &str| {
      substitute_compose(
        "app",
        raw,
        Some(&BTreeMap::from([("KEY".into(), value.into())])),
      )
    };
    let (out, _) = fill(raw, "a$b").unwrap();
    assert_eq!(out, raw.replace("[[KEY]]", "a$$b"));
    let damaged = "fixture\"quote";
    let error = fill(raw, damaged).unwrap_err();
    assert!(error.message.contains("填入密钥 KEY"));
    assert!(!error.message.contains(damaged));
    assert!(error.hint.unwrap().contains("[[json:KEY]]"));
    let unquoted = raw.replace("\"[[KEY]]\"", "[[KEY]]");
    let error =
      fill(&unquoted, "ok\n      INJECTED: fixture").unwrap_err();
    assert!(!error.message.contains("INJECTED"));
  }

  #[test]
  fn compose_rejects_list_injection_without_echoing_secret() {
    for (field, template, injected) in [
      (
        "environment",
        "FOO=[[KEY]]",
        "ok\n      - BAR=fixture-injected",
      ),
      (
        "volumes",
        "fixture/[[KEY]]:/data",
        "ok:/data\n      - fixture-injected",
      ),
      ("command", "[[KEY]]", "ok\n      - fixture-injected"),
      ("command", "[[KEY]]", "[fixture-injected]"),
    ] {
      let raw = format!(
        "services:\n  app:\n    image: nginx:1\n    {field}:\n      - {template}\n"
      );
      let substituted = raw.replace("[[KEY]]", injected);
      assert!(serde_yaml_ng::from_str::<Value>(&substituted).is_ok());
      let fill = |value: &str| {
        substitute_compose(
          "app",
          &raw,
          Some(&BTreeMap::from([("KEY".into(), value.into())])),
        )
      };
      assert_eq!(
        fill("fixture").unwrap().0,
        raw.replace("[[KEY]]", "fixture")
      );
      let error = fill(injected).unwrap_err();
      assert!(error.message.contains("填入密钥 KEY"));
      assert!(
        !serde_json::to_string(&error)
          .unwrap()
          .contains("fixture-injected")
      );
    }
  }

  #[test]
  fn compose_rejects_normalized_secret_volume_targets() {
    for volume in [
      "./fixture:/run/wharf-secrets//PG_PASS:ro",
      "/run/./wharf-secrets",
      "'${SOURCE:-./fixture}:/run/wharf-secrets/PG_PASS'",
      "{type: volume, source: fixture, target: /run/other/../wharf-secrets/PG_PASS}",
    ] {
      let raw = format!(
        "x-base: &base\n  volumes:\n    - {volume}\nx-derived: &derived\n  <<: *base\nservices:\n  app:\n    <<: *derived\n    image: nginx:1\n"
      );
      let error = check_compose("app", &raw).unwrap_err();
      assert!(error.message.contains(SECRET_FILE_DIR));
    }
    let raw = "services:\n  app:\n    image: nginx:1\n    volumes:\n      - ./fixture:/run/[[KEY]]/PG_PASS\n";
    check_compose("app", raw).unwrap();
    let secrets = BTreeMap::from([(
      "KEY".into(),
      "other/../wharf-secrets".into(),
    )]);
    let error =
      substitute_compose("app", raw, Some(&secrets)).unwrap_err();
    assert!(error.message.contains(SECRET_FILE_DIR));
    assert!(!error.message.contains("other/.."));
  }

  #[test]
  fn missing_secret_suggests_command() {
    let err =
      substitute("a [[NOPE]] b", Some(&BTreeMap::new())).unwrap_err();
    assert_eq!(
      err.suggest,
      ["wharf secret set NOPE --generate", "wharf secret set NOPE"]
    );
    // 不像名字的 [[...]] 原样保留。
    assert_eq!(
      substitute("[[a b]] [x]", Some(&BTreeMap::new())).unwrap(),
      "[[a b]] [x]"
    );
  }

  #[test]
  fn renders_account_password() {
    let spec = serde_json::from_value(serde_json::json!({
      "server": "s1", "source": {"image": "example/app"},
      "env": {"APP_PASSWORD": "[[account.x.password]]"}
    }))
    .unwrap();
    let credentials = BTreeMap::from([(
      "account.x.password".into(),
      "fixture-value".into(),
    )]);
    let render = |values| {
      service_compose("app", &spec, &BTreeMap::new(), &[], values)
        .unwrap()
        .0
    };
    assert!(
      render(Some(&credentials))
        .contains("APP_PASSWORD: fixture-value")
    );
    assert!(render(None).contains("[[account.x.password]]"));
  }

  #[test]
  fn compose_checks() {
    assert!(
      check_compose("x", "services:\n  web:\n    image: nginx\n")
        .is_ok()
    );
    assert!(check_compose("x", "services: {}\n").is_err());
    assert!(
      check_compose("x", "services:\n  web:\n    build: .\n")
        .is_err()
    );
    assert!(check_compose("x", "::: nope").is_err());
  }

  #[test]
  fn caddyfile_lists_sites_sorted() {
    let gw = GatewaySpec {
      kind: GatewayKind::Caddy,
      server: "edge1".into(),
      default: true,
      http_port: Some(8080),
      https_port: None,
      email: None,
      image: None,
      tls: GatewayTls::Auto,
      account: None,
      error_page: None,
      wildcard: vec![],
      layer4: vec![],
      trusted_proxies: None,
      read_header_timeout: None,
      idle_timeout: None,
      grace_period: None,
    };
    let out = caddyfile(
      "edge",
      &gw,
      &[
        Site {
          hostname: "z.example.com".into(),
          upstream: "127.0.0.1:1".into(),
          auth: BasicAuth::parse("admin $2b$12$abc"),
          paths: vec![],
          redirect: None,
          ..Default::default()
        },
        Site {
          hostname: "a.example.com".into(),
          upstream: "100.1.1.1:2".into(),
          auth: None,
          paths: vec![("/ws".into(), "127.0.0.1:17891".into())],
          redirect: None,
          ..Default::default()
        },
      ],
      &[],
      true,
      None,
    );
    assert!(out.contains(
      "link.wharf.internal {\n\ttls /etc/caddy/link.crt /etc/caddy/link.key\n\treverse_proxy /~!frp 127.0.0.1:7000\n}"
    ));
    // 只有开了 auth 的站点带 basic_auth。
    let z = &out[out.find("z.example.com").unwrap()..];
    assert!(z.contains("basic_auth {\n\t\tadmin $2b$12$abc\n\t}"));
    assert_eq!(out.matches("basic_auth").count(), 1);
    assert!(out.contains(
      "a.example.com {\n\timport wharf_access\n\timport wharf_errors\n\treverse_proxy /ws 127.0.0.1:17891 {\n\t\timport wharf_upstream\n\t}\n\treverse_proxy 100.1.1.1:2 {\n\t\timport wharf_upstream\n\t}\n}"
    ));
    assert!(out.contains("http_port 8080"));
    assert!(!out.contains("https_port"));
    assert!(!out.contains("auto_https"));
    assert!(
      out.find("a.example.com").unwrap()
        < out.find("z.example.com").unwrap()
    );
    let compose = gateway_compose("edge", &gw);
    assert!(compose.contains("network_mode: host"));
    assert!(compose.contains("name: wharf-gw-edge"));
    let off = GatewaySpec {
      tls: GatewayTls::Off,
      ..gw
    };
    let out = caddyfile(
      "edge",
      &off,
      &[Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:1".into(),
        auth: None,
        paths: vec![],
        redirect: None,
        ..Default::default()
      }],
      &[],
      false,
      None,
    );
    assert!(out.contains("auto_https off"));
    assert!(out.contains("\nhttp://a.example.com {"));
  }

  #[test]
  fn caddyfile_custom_in_site() {
    let spec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1"
    }))
    .unwrap();
    let out = caddyfile(
      "edge",
      &spec,
      &[Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:1".into(),
        custom: Some(
          "@admin path /admin/*\n\nrespond @admin 403  ".into(),
        ),
        ..Default::default()
      }],
      &[],
      false,
      None,
    );
    assert!(out.contains("\timport wharf_errors\n\t@admin path /admin/*\n\n\trespond @admin 403\n\treverse_proxy 127.0.0.1:1 {"));
  }

  #[test]
  fn caddyfile_guard_per_site() {
    let spec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1"
    }))
    .unwrap();
    let out = caddyfile(
      "edge",
      &spec,
      &[
        Site {
          hostname: "a.example.com".into(),
          upstream: "127.0.0.1:1".into(),
          rate_limit: Some(600),
          block_scanners: true,
          ..Default::default()
        },
        Site {
          hostname: "b.example.com".into(),
          upstream: "127.0.0.1:2".into(),
          ..Default::default()
        },
      ],
      &[],
      false,
      None,
    );
    assert_eq!(
      out.matches("order rate_limit before basic_auth").count(),
      1
    );
    assert_eq!(out.matches("(wharf_scanners) {").count(), 1);
    assert_eq!(out.matches("import wharf_scanners").count(), 1);
    let a = out
      .split("\na.example.com {\n")
      .nth(1)
      .unwrap()
      .split("\nb.example.com {\n")
      .next()
      .unwrap();
    assert!(a.contains("import wharf_scanners"));
    assert!(a.contains("zone wharf_a_example_com {"));
    assert!(a.contains("events 600"));
    assert!(a.contains("window 1m"));
    assert!(out.contains("b.example.com {\n\timport wharf_access\n\timport wharf_errors\n\treverse_proxy 127.0.0.1:2 {\n\t\timport wharf_upstream\n\t}\n}"));
    assert!(!SCANNER_PATHS.contains(" / "));
    assert!(!SCANNER_UA.contains("curl"));
    assert!(!SCANNER_UA.contains("reqwest"));
  }

  #[test]
  fn caddyfile_retries_only_service_upstreams() {
    let spec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1"
    }))
    .unwrap();
    let site = Site {
      hostname: "a.example.com".into(),
      upstream: "127.0.0.1:20000".into(),
      auth: None,
      paths: vec![("/api".into(), "100.64.0.1:20001".into())],
      redirect: None,
      ..Default::default()
    };
    let redirect = Site {
      hostname: "b.example.com".into(),
      redirect: Some("https://a.example.com".into()),
      paths: vec![],
      ..site.clone()
    };
    let out =
      caddyfile("edge", &spec, &[site, redirect], &[], true, None);
    assert_eq!(out.matches("import wharf_upstream").count(), 2);
    assert_eq!(out.matches("(wharf_upstream) {").count(), 1);
    assert!(out.contains("lb_try_duration 8s"));
    assert!(out.contains("lb_try_interval 250ms"));
    let excluded = &out[out.find("\nb.example.com {").unwrap()..];
    assert!(excluded.contains("link.wharf.internal {"));
    assert!(!excluded.contains("import wharf_upstream"));
  }

  #[test]
  fn caddyfile_has_default_error_page() {
    let spec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1"
    }))
    .unwrap();
    let out = caddyfile(
      "edge",
      &spec,
      &[
        Site {
          hostname: "a.example.com".into(),
          upstream: "127.0.0.1:21000".into(),
          auth: None,
          paths: vec![],
          redirect: None,
          ..Default::default()
        },
        Site {
          hostname: "b.example.com".into(),
          upstream: String::new(),
          auth: None,
          paths: vec![],
          redirect: Some("https://a.example.com".into()),
          ..Default::default()
        },
      ],
      &[],
      false,
      None,
    );
    assert!(out.contains("(wharf_errors) {"));
    assert!(out.contains("handle_errors 502 503 504"));
    assert!(out.contains("服务暂时不可用"));
    assert_eq!(out.matches("import wharf_errors").count(), 1);
  }

  #[test]
  fn caddyfile_has_custom_error_page() {
    let spec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1",
      "error_page": "<p>x</p>\n\n<p>y</p>"
    }))
    .unwrap();
    let out = caddyfile("edge", &spec, &[], &[], false, None);
    assert!(out.contains(
      "\t\t<p>x</p>\n\n\t\t<p>y</p>\n\t\tWHARF_ERROR_PAGE {err.status_code}\n"
    ));
    assert!(!out.contains("服务暂时不可用"));
  }

  #[test]
  fn caddyfile_redirect_keeps_uri() {
    let gw = GatewaySpec {
      kind: GatewayKind::Caddy,
      server: "s1".into(),
      default: true,
      http_port: None,
      https_port: None,
      email: None,
      image: None,
      tls: GatewayTls::Auto,
      account: None,
      error_page: None,
      wildcard: vec![],
      layer4: vec![],
      trusted_proxies: None,
      read_header_timeout: None,
      idle_timeout: None,
      grace_period: None,
    };
    let out = caddyfile(
      "edge",
      &gw,
      &[Site {
        hostname: "www.a.com".into(),
        upstream: String::new(),
        auth: None,
        paths: vec![],
        redirect: Some("https://a.com".into()),
        ..Default::default()
      }],
      &[],
      false,
      None,
    );
    assert!(out.contains("www.a.com {\n\timport wharf_access\n\tredir https://a.com{uri} permanent\n"));
    assert!(!out.contains("reverse_proxy"));
  }

  #[test]
  fn tunnel_compose_holds_only_a_token_placeholder() {
    let spec = GatewaySpec {
      kind: GatewayKind::CloudflareTunnel,
      server: "edge1".into(),
      default: false,
      http_port: None,
      https_port: None,
      email: None,
      image: None,
      tls: GatewayTls::Auto,
      account: Some("cf".into()),
      error_page: None,
      wildcard: vec![],
      layer4: vec![],
      trusted_proxies: None,
      read_header_timeout: None,
      idle_timeout: None,
      grace_period: None,
    };
    let out = tunnel_compose("cf", &spec, None);
    assert!(
      out.contains("TUNNEL_TOKEN: '[[WHARF_TUNNEL_TOKEN]]'"),
      "{out}"
    );
    assert!(out.contains("network_mode: host"));
    assert!(out.contains(DEFAULT_CLOUDFLARED_IMAGE));
  }

  #[test]
  fn auth_is_per_route() {
    let mut net = Net::default();
    net.basic_auth.insert(
      route_auth_secret("a.example.com"),
      BasicAuth::parse("mine $2b$12$x").unwrap(),
    );
    assert_eq!(net.auth_for("a.example.com").unwrap().user, "mine");
    assert!(net.auth_for("b.example.com").is_none());
    assert_eq!(
      route_auth_secret("a.example.com"),
      "BASIC_AUTH_a_example_com"
    );
  }

  #[test]
  fn basic_auth_input_is_checked() {
    assert!(BasicAuth::hash_input("no-colon").is_err());
    assert!(BasicAuth::hash_input("ad min:longenough").is_err());
    assert!(BasicAuth::hash_input("admin:short").is_err());
    assert!(BasicAuth::parse("admin plaintext").is_none());
  }

  #[test]
  fn inputs_include_addresses_not_usage() {
    use wharf_api_types::agent::{AgentReport, Disk};
    use wharf_api_types::spec::{PrivateNetwork, ServerSettings};

    let addr = |ip: &str| PrivateAddr {
      ip: ip.into(),
      network: PrivateNetwork::Tailscale,
    };
    let fingerprint = |settings: ServerSettings,
                       report: AgentReport| {
      let servers = BTreeMap::from([(
        "home".to_string(),
        ServerRow {
          settings,
          version: 1,
        },
      )]);
      let agents = vec![crate::db::AgentRow {
        server: "home".into(),
        public_key: None,
        report: Some(report),
        last_seen: None,
      }];
      crate::db::inputs_fingerprint(
        &BTreeMap::new(),
        &BTreeMap::new(),
        &Net::derive(&servers, &agents).addresses(),
      )
    };

    let base = fingerprint(
      ServerSettings::default(),
      AgentReport {
        private_addr: Some(addr("100.64.0.1")),
        ..Default::default()
      },
    );
    // 磁盘用量这类高频上报值变了，指纹不变
    let usage = fingerprint(
      ServerSettings::default(),
      AgentReport {
        private_addr: Some(addr("100.64.0.1")),
        disk: Some(Disk {
          total: 100,
          free: 1,
        }),
        ..Default::default()
      },
    );
    assert_eq!(base, usage);
    // agent 上报的地址变了，指纹要变
    let moved = fingerprint(
      ServerSettings::default(),
      AgentReport {
        private_addr: Some(addr("100.64.0.2")),
        ..Default::default()
      },
    );
    assert_ne!(base, moved);
    // 服务器设置里的地址覆盖变了，指纹也要变
    let overridden = fingerprint(
      ServerSettings {
        private_addr: Some(addr("100.64.0.3")),
        ..Default::default()
      },
      AgentReport::default(),
    );
    assert_ne!(base, overridden);
  }
  #[test]
  fn caddyfile_app_login() {
    let gw = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    site.gate.as_mut().unwrap().app_login = true;
    assert!(
      caddyfile("edge", &gw, &[site], &[], false, Some("public"))
        .contains("\t\tapp_login on\n")
    );
  }
  #[test]
  fn caddyfile_gate_without_app_login() {
    let gw = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    assert!(
      !caddyfile(
        "edge",
        &gw,
        &[gate_site()],
        &[],
        false,
        Some("public")
      )
      .contains("app_login")
    );
  }
  #[test]
  fn caddyfile_public_login_entry_only() {
    let gw = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    for app_login in [true, false] {
      let gate = site.gate.as_mut().unwrap();
      gate.public = true;
      gate.site_endpoints = app_login;
      gate.app_login = app_login;
      let out = caddyfile(
        "edge",
        &gw,
        std::slice::from_ref(&site),
        &[],
        false,
        Some("public"),
      );
      assert_eq!(out.contains("@wharf_site"), app_login);
      assert!(out.contains("\twharf_sso {"));
      assert!(out.contains("\t\tpublic\n"));
    }
  }
  fn gate_site() -> Site {
    Site {
      hostname: "a.example.test".into(),
      upstream: "127.0.0.1:8080".into(),
      gate: Some(Gate {
        public: false,
        site_endpoints: true,
        app_login: false,
        user_header: None,
        trusted: vec![],
        login: "https://core.example.test".into(),
        core: "http://127.0.0.1:7700".into(),
        skip_paths: vec![],
        takeover: None,
      }),
      ..Default::default()
    }
  }
  #[test]
  fn caddyfile_gate() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let out = caddyfile(
      "edge",
      &gw,
      &[gate_site()],
      &[],
      false,
      Some("public"),
    );
    assert!(out.contains("order wharf_sso before basic_auth"));
    assert!(out.contains("handle @wharf_site"));
    assert!(out.contains("uri replace /_wharf/ /gate/site/"));
    assert!(out.contains("public_key public"));
    assert!(out.contains("core http://127.0.0.1:7700"));
    assert!(!out.contains("skip "));
  }
  #[test]
  fn caddyfile_gate_trust() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    let before = caddyfile(
      "edge",
      &gw,
      std::slice::from_ref(&site),
      &[],
      false,
      Some("public"),
    );
    site.gate.as_mut().unwrap().trusted = vec![
      "100.64.0.0/10".into(),
      "127.0.0.0/8".into(),
      "::1/128".into(),
      "fd7a:115c:a1e0::/48".into(),
    ];
    let after =
      caddyfile("edge", &gw, &[site], &[], false, Some("public"));
    assert_eq!(
      after.replace("\t\ttrust 100.64.0.0/10 127.0.0.0/8 ::1/128 fd7a:115c:a1e0::/48\n", ""),
      before
    );
    assert!(after.contains("\t\ttrust 100.64.0.0/10 127.0.0.0/8 ::1/128 fd7a:115c:a1e0::/48\n"));
  }
  #[test]
  fn caddyfile_gate_without_trust_unchanged() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let out = caddyfile(
      "edge",
      &gw,
      &[gate_site()],
      &[],
      false,
      Some("public"),
    );
    assert!(
      out.contains("\t\tlogin https://core.example.test\n\t}\n")
    );
    assert!(!out.contains("\t\ttrust "));
  }
  #[test]
  fn caddyfile_gate_header() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    let before = caddyfile(
      "edge",
      &gw,
      std::slice::from_ref(&site),
      &[],
      false,
      Some("public"),
    );
    site.gate.as_mut().unwrap().user_header =
      Some("Remote-User".into());
    let after =
      caddyfile("edge", &gw, &[site], &[], false, Some("public"));
    assert!(after.contains("\t\tuser_header Remote-User\n"));
    assert_eq!(
      after.replace("\t\tuser_header Remote-User\n", ""),
      before
    );
  }
  #[test]
  fn caddyfile_gate_without_header() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let out = caddyfile(
      "edge",
      &gw,
      &[gate_site()],
      &[],
      false,
      Some("public"),
    );
    assert!(!out.contains("user_header"));
  }
  #[test]
  fn caddyfile_gate_skip() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    let gate = site.gate.as_mut().unwrap();
    gate.skip_paths = vec!["/api".into(), "/hooks".into()];
    gate.core = gate.login.clone();
    let out =
      caddyfile("edge", &gw, &[site], &[], false, Some("public"));
    assert!(out.contains("skip /api /hooks"));
    assert!(out.contains("header_up Host {upstream_hostport}"));
  }
  #[test]
  fn caddyfile_without_gate() {
    let gw: GatewaySpec = serde_json::from_value(
      serde_json::json!({"kind":"caddy","server":"s1"}),
    )
    .unwrap();
    let mut site = gate_site();
    site.gate = None;
    let out = caddyfile("edge", &gw, &[site], &[], false, None);
    assert!(!out.contains("wharf_sso"));
    assert!(!out.contains("/_wharf/"));
    assert!(out.contains(
      "reverse_proxy 127.0.0.1:8080 {\n\t\timport wharf_upstream\n\t}"
    ));
  }
}
