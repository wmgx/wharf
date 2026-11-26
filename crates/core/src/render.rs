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

mod gate;

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

mod caddy;
mod compose;
#[cfg(test)]
use caddy::caddyfile;
pub use caddy::*;
pub use compose::*;

#[cfg(test)]
mod tests;
