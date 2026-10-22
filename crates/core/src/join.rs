//! 加服务器：控制面的候选地址、agent 安装脚本。
//!
//! 页面生成 `curl -fsSL <地址>/join.sh | sh -s -- <地址> <加入凭据>`，
//! 到目标机器上执行。地址由加服务器的人选，不绑定某种组网方式：
//! 内网地址可以用 http，公网必须 https（经网关开放的域名）。

use std::{
  collections::BTreeSet,
  net::{IpAddr, Ipv4Addr},
  sync::Arc,
};

use axum::{
  Json,
  extract::State,
  http::header,
  response::{IntoResponse, Response},
};
use wharf_api_types::{
  ApiError,
  view::{CoreAddress, CoreAddresses, TokenScope},
};

use crate::{
  api::ApiResult, auth::Auth, render::Net, snapshot, state::AppState,
  views, world::World,
};

/// 控制面能被访问到的地址：经网关开放的域名、启动配置的地址、本机网卡地址。
pub async fn addresses(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreAddresses> {
  auth.require(TokenScope::ApplyAll)?;
  let snap = snapshot::load(&s.db).await?;
  let net = snap.net(&snap.world);
  let port = s.listen_port;
  let mut ips: Vec<Ipv4Addr> = if_addrs::get_if_addrs()
    .unwrap_or_default()
    .into_iter()
    .filter(|i| !is_bridge(&i.name))
    .filter_map(|i| match i.ip() {
      IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
      _ => None,
    })
    .collect();
  ips.sort_by_key(|ip| rank(*ip));
  let own: BTreeSet<String> =
    ips.iter().map(|ip| ip.to_string()).collect();
  let server = core_server(&net, &own);

  let mut out: Vec<CoreAddress> = Vec::new();
  let mut push = |url: String, kind: &str| {
    if !out.iter().any(|o| o.url == url) {
      let plaintext = plaintext(&url);
      out.push(CoreAddress {
        url,
        kind: kind.into(),
        plaintext,
      });
    }
  };
  for host in
    core_routes(&snap.world, &net, server.as_deref(), &own, port)
  {
    if let Some(v) = views::route_view(&snap, &net, &host) {
      push(v.url, "route");
    }
  }
  if let Some(url) = &s.public_url {
    push(url.clone(), "configured");
  }
  for ip in ips {
    push(format!("http://{ip}:{port}"), kind(ip));
  }
  Ok(Json(CoreAddresses {
    server,
    port,
    addresses: out,
  }))
}

/// 控制面所在的服务器：哪台的 agent 上报了控制面网卡上的地址。
fn core_server(net: &Net, own: &BTreeSet<String>) -> Option<String> {
  let hit = |ip: &String| own.contains(ip);
  net
    .private
    .iter()
    .find(|(_, a)| hit(&a.ip))
    .map(|(s, _)| s)
    .or_else(|| {
      net
        .lan_ips
        .iter()
        .find(|(_, ips)| ips.iter().any(hit))
        .map(|(s, _)| s)
    })
    .or_else(|| {
      net.public_ip.iter().find(|(_, ip)| hit(ip)).map(|(s, _)| s)
    })
    .cloned()
}

/// 上游指向控制面的路由。
fn core_routes(
  world: &World,
  net: &Net,
  server: Option<&str>,
  own: &BTreeSet<String>,
  port: u16,
) -> Vec<String> {
  world
    .routes
    .iter()
    .filter(|(_, r)| {
      let Some((host, p)) =
        r.spec.upstream.as_deref().and_then(|u| u.rsplit_once(':'))
      else {
        return false;
      };
      if p.parse() != Ok(port) {
        return false;
      }
      let local = host == "127.0.0.1" || host == "localhost";
      let gw_server = world
        .route_gateway(&r.spec)
        .and_then(|g| world.gateways.get(g))
        .map(|g| g.spec.server.as_str());
      if local {
        server.is_some() && gw_server == server
      } else {
        own.contains(host)
          || server
            .and_then(|s| net.private.get(s))
            .is_some_and(|a| a.ip == host)
      }
    })
    .map(|(h, _)| h.clone())
    .collect()
}

fn rank(ip: Ipv4Addr) -> u8 {
  match kind(ip) {
    "public" => 0,
    "tailscale" => 1,
    _ => 2,
  }
}

fn kind(ip: Ipv4Addr) -> &'static str {
  if is_cgnat(ip) {
    "tailscale"
  } else if ip.is_private() || ip.is_link_local() {
    "lan"
  } else {
    "public"
  }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
  let [a, b, ..] = ip.octets();
  a == 100 && (64..128).contains(&b)
}

fn is_bridge(name: &str) -> bool {
  name == "docker0"
    || name.starts_with("br-")
    || name.starts_with("veth")
}

/// 地址里的主机名，去掉端口和路径。
fn host_of(rest: &str) -> &str {
  let hostport = rest.split('/').next().unwrap_or("");
  match hostport.strip_prefix('[') {
    Some(v6) => v6.split(']').next().unwrap_or(""),
    None => hostport.rsplit_once(':').map_or(hostport, |(h, _)| h),
  }
}

/// http 只允许内网地址：普通内网、组网、本机。
fn private_host(host: &str) -> bool {
  match host.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => {
      ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || is_cgnat(ip)
    }
    Ok(IpAddr::V6(ip)) => {
      ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00
    }
    Err(_) => host == "localhost",
  }
}

/// http 且不走组网时是明文（组网本身加密）。
fn plaintext(url: &str) -> bool {
  url.strip_prefix("http://").is_some_and(|rest| {
    let host = host_of(rest);
    !matches!(host.parse::<Ipv4Addr>(), Ok(ip) if is_cgnat(ip) || ip.is_loopback())
  })
}

/// 校验 agent 连接控制面用的地址。只允许常见字符，因为它会拼进给人复制的 shell 命令。
pub fn check_core_url(url: &str) -> Result<String, ApiError> {
  let url = url.trim().trim_end_matches('/');
  let (https, rest) = match url.strip_prefix("https://") {
    Some(rest) => (true, rest),
    None => (false, url.strip_prefix("http://").unwrap_or("")),
  };
  let ok = !host_of(rest).is_empty()
    && rest.len() <= 200
    && rest
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || ".:-_/[]".contains(c));
  if !ok {
    return Err(ApiError::invalid(format!(
      "控制面地址 {url} 不对，要写成 https://域名 或 http://内网IP:端口"
    )));
  }
  if !https && !private_host(host_of(rest)) {
    return Err(
      ApiError::invalid(format!(
        "控制面地址 {url}：公网地址必须用 https，否则 agent 和控制面之间的内容（包括密钥）是明文"
      ))
      .with_hint("先经网关给控制面开放一个域名，或者用内网地址"),
    );
  }
  Ok(url.to_string())
}

pub fn script_command(core_url: &str, token: &str) -> String {
  format!(
    "curl -fsSL {core_url}/join.sh | sh -s -- {core_url} {token}"
  )
}

/// agent 安装脚本。不含凭据，凭据由命令行参数传入。
pub async fn script(State(s): State<Arc<AppState>>) -> Response {
  (
    [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
    SCRIPT.replace("{image}", &s.agent_image),
  )
    .into_response()
}

const SCRIPT: &str = r#"#!/bin/sh
# Wharf agent 安装：curl -fsSL <控制面>/join.sh | sh -s -- <控制面> <加入凭据>
set -eu
CORE_URL="${1:?缺少控制面地址}"
TOKEN="${2:?缺少加入凭据}"
IMAGE="${WHARF_AGENT_IMAGE:-{image}}"
DATA=/var/lib/wharf

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '\n失败：%s\n' "$1" >&2; exit 1; }

step "检查 Docker"
command -v docker >/dev/null 2>&1 || fail "没有 Docker，先安装：https://docs.docker.com/engine/install/"
DOCKER=docker
if ! docker info >/dev/null 2>&1; then
  if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
  else
    fail "Docker 没有运行，或当前用户没有权限"
  fi
fi
T=""
if command -v timeout >/dev/null 2>&1; then T="timeout"; fi
run() { limit=$1; shift; if [ -n "$T" ]; then $T "$limit" "$@"; else "$@"; fi; }

step "拉取 $IMAGE"
run 900 $DOCKER pull "$IMAGE" || fail "拉取镜像失败。国内机器可以设置 WHARF_AGENT_IMAGE 换成镜像站地址"

step "加入 $CORE_URL"
run 60 $DOCKER run --rm --network host -v "$DATA:$DATA" "$IMAGE" join "$CORE_URL" "$TOKEN" \
  || fail "加入失败，确认这台机器能访问 $CORE_URL"

step "启动 agent"
$DOCKER rm -f wharf-agent >/dev/null 2>&1 || true
$DOCKER run -d --name wharf-agent --restart unless-stopped --network host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$DATA:$DATA" -v /srv:/srv \
  "$IMAGE" >/dev/null

printf '\n完成，回到页面查看连接状态。\n'
"#;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn core_url_rejects_shell_characters() {
    assert_eq!(
      check_core_url("https://w.example.com/").unwrap(),
      "https://w.example.com"
    );
    assert!(check_core_url("http://a;rm -rf /").is_err());
    assert!(check_core_url("ftp://a").is_err());
    assert!(check_core_url("http://192.168.1.2:7700").is_ok());
    assert!(check_core_url("http://100.100.1.1:7700").is_ok());
    assert!(check_core_url("http://8.8.8.8:7700").is_err());
    assert!(check_core_url("http://w.example.com").is_err());
  }
}
