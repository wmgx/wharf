//! Wharf 管理的 Tailscale（design 2.10）：接入方式设为 `tailscale`、机器上又没检测到
//! Tailscale 时，在那台机器上起 Tailscale 容器加入网络。系统里已经装好的不碰。
//!
//! 加入密钥由 OAuth 客户端（密钥 `TAILSCALE_OAUTH`）现开，只能用一次；部署时才填进去，
//! compose 模板和哈希里只有占位。容器的状态目录在宿主机上，重建不会重新加入。

use wharf_api_types::{
  ApiError,
  spec::{NetworkMode, PrivateNetwork},
};

use crate::{
  render, snapshot::Snapshot, state::AppState, world::World,
};

pub const PROJECT: &str = "wharf-tailscale";
pub const OAUTH_SECRET: &str = "TAILSCALE_OAUTH";
/// Wharf 加入的机器都打这个标签，OAuth 开的密钥必须带标签。
pub const TAG: &str = "tag:wharf";
pub const IMAGE: &str = "tailscale/tailscale:v1.104.2";
const KEY: &str = "[[WHARF_TAILSCALE_KEY]]";

pub fn compose(server: &str) -> String {
  format!(
    r#"# 由 Wharf 生成，不要手改。
name: {PROJECT}
services:
  tailscale:
    image: {IMAGE}
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    devices: ["/dev/net/tun:/dev/net/tun"]
    volumes: ["/var/lib/wharf/tailscale:/var/lib/tailscale"]
    environment:
      TS_AUTHKEY: "{KEY}"
      TS_AUTH_ONCE: "true"
      TS_STATE_DIR: /var/lib/tailscale
      TS_USERSPACE: "false"
      TS_HOSTNAME: {server}
      TS_EXTRA_ARGS: --advertise-tags={TAG}
    labels:
      wharf.network: tailscale
"#
  )
}

pub fn hash(server: &str) -> String {
  render::hash(&compose(server))
}

/// 这台机器要不要 Wharf 的 Tailscale 容器。`deployed`：容器已经在了
/// （它起来后 agent 也会检测到 Tailscale，不能据此再删掉）。
pub fn wanted(
  snap: &Snapshot,
  world: &World,
  server: &str,
  deployed: bool,
) -> bool {
  let Some(row) = world.servers.get(server) else {
    return false;
  };
  if row.settings.network_mode != Some(NetworkMode::Tailscale) {
    return false;
  }
  let detected = snap
    .agent(server)
    .and_then(|a| a.report.as_ref())
    .and_then(|r| r.private_addr.as_ref())
    .is_some_and(|a| a.network == PrivateNetwork::Tailscale);
  deployed || !detected
}

/// 部署用的 compose：现开一个加入密钥填进去。
pub async fn deploy_compose(
  state: &AppState,
  server: &str,
) -> Result<String, ApiError> {
  let secret = OAUTH_SECRET.to_string();
  let credential = state
    .db
    .call(move |c| crate::db::secrets(c))
    .await?
    .remove(&secret)
    .ok_or_else(|| {
      ApiError::invalid("还没有设置 Tailscale 的 OAuth 客户端")
        .with_hint(format!(
          "在 Tailscale 后台建一个有 Auth Keys 写权限、标签 {TAG} 的 OAuth 客户端，再执行 wharf secret set {OAUTH_SECRET}（值为 client_id:client_secret）"
        ))
    })?;
  let key = wharf_providers::tailscale::auth_key(
    &credential,
    TAG,
    &format!("wharf {server}"),
  )
  .await
  .map_err(crate::snapshot::provider_error)?;
  Ok(compose(server).replace(KEY, &key))
}
