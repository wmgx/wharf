//! 加服务器：控制面的候选地址、agent 安装脚本。
//!
//! 页面生成 `curl -fsSL <地址>/join.sh | sh -s -- <地址> <加入凭据>`，
//! 到目标机器上执行。地址由加服务器的人选，不绑定某种组网方式。

use std::{net::Ipv4Addr, sync::Arc};

use axum::{
  Json,
  extract::State,
  http::header,
  response::{IntoResponse, Response},
};
use wharf_api_types::{
  ApiError,
  view::{CoreAddress, TokenScope},
};

use crate::{api::ApiResult, auth::Auth, state::AppState};

/// 控制面能被访问到的地址：配置的对外地址，加上本机网卡地址。
pub async fn addresses(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<CoreAddress>> {
  auth.require(TokenScope::ApplyAll)?;
  let mut out = Vec::new();
  if let Some(url) = &s.public_url {
    out.push(CoreAddress {
      url: url.clone(),
      kind: "configured".into(),
    });
  }
  let mut ifaces: Vec<(u8, CoreAddress)> = if_addrs::get_if_addrs()
    .unwrap_or_default()
    .into_iter()
    .filter(|i| !is_bridge(&i.name))
    .filter_map(|i| match i.ip() {
      std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
      _ => None,
    })
    .map(|ip| {
      let (rank, kind) = classify(ip);
      let url = format!("http://{ip}:{}", s.listen_port);
      (
        rank,
        CoreAddress {
          url,
          kind: kind.into(),
        },
      )
    })
    .collect();
  ifaces.sort_by_key(|(rank, _)| *rank);
  for (_, a) in ifaces {
    if !out.iter().any(|o| o.url == a.url) {
      out.push(a);
    }
  }
  Ok(Json(out))
}

fn classify(ip: Ipv4Addr) -> (u8, &'static str) {
  let [a, b, ..] = ip.octets();
  if a == 100 && (64..128).contains(&b) {
    (1, "tailscale")
  } else if ip.is_private() || ip.is_link_local() {
    (2, "lan")
  } else {
    (0, "public")
  }
}

fn is_bridge(name: &str) -> bool {
  name == "docker0"
    || name.starts_with("br-")
    || name.starts_with("veth")
}

/// 只允许地址里常见的字符，因为它会拼进给人复制的 shell 命令。
pub fn check_core_url(url: &str) -> Result<String, ApiError> {
  let url = url.trim().trim_end_matches('/');
  let rest = url
    .strip_prefix("http://")
    .or_else(|| url.strip_prefix("https://"));
  let ok = rest.is_some_and(|r| {
    !r.is_empty()
      && r.len() <= 200
      && r
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".:-_/[]".contains(c))
  });
  if ok {
    Ok(url.to_string())
  } else {
    Err(ApiError::invalid(format!(
      "控制面地址 {url} 不对，要写成 http://主机:端口 或 https://域名"
    )))
  }
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
    assert!(check_core_url("http://1.2.3.4:7700").is_ok());
    assert!(check_core_url("http://a;rm -rf /").is_err());
    assert!(check_core_url("ftp://a").is_err());
  }
}
