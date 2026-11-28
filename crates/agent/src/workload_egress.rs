use std::{
  net::{IpAddr, SocketAddr},
  time::Duration,
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode, agent::ProjectUp, egress::WORKLOAD_PROXY_HOST,
};

use crate::{docker::Docker, exec::Ctx};

const QUICK: Duration = Duration::from_secs(15);

pub(crate) fn require_running() -> Result<(), ApiError> {
  if crate::egress::workload_ready() {
    return Ok(());
  }
  Err(
    ApiError::invalid("本机没有启用分流代理")
      .with_hint("先在服务器设置 via 并应用"),
  )
}

fn unreachable() -> ApiError {
  ApiError::new(ErrorCode::Conflict, "容器网络无法访问本机分流代理")
    .with_hint("需要宿主机网络，或 Docker 默认代理允许的 bridge 网段")
}

pub(crate) async fn default_bridge(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  gateway(docker, "bridge", ctx).await.map(|_| ())
}

async fn gateway(
  docker: &Docker,
  network: &str,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let data = docker
    .cmd()
    .args(["network", "inspect", "--", network])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !data.success {
    return Err(unreachable());
  }
  let docs: Vec<Value> =
    serde_json::from_str(&data.stdout).map_err(|_| unreachable())?;
  let net = docs.first().ok_or_else(unreachable)?;
  if net["Driver"].as_str() != Some("bridge")
    || net["Internal"].as_bool() != Some(false)
  {
    return Err(unreachable());
  }
  for subnet in net["IPAM"]["Config"].as_array().into_iter().flatten()
  {
    let Some((base, bits)) = subnet["Subnet"]
      .as_str()
      .and_then(|cidr| cidr.split_once('/'))
    else {
      continue;
    };
    let Some(base) =
      base.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4)
    else {
      continue;
    };
    if bits.parse::<u8>().is_ok_and(|p| (12..=32).contains(&p))
      && crate::egress::local_peer(SocketAddr::new(base, 0))
      && let Some(gateway) = subnet["Gateway"]
        .as_str()
        .filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok())
    {
      return Ok(gateway.to_string());
    }
  }
  Err(unreachable())
}

async fn inspect(
  docker: &Docker,
  id: &str,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let out = docker
    .cmd()
    .args(["inspect", "--", id])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !out.success {
    return Err(unreachable());
  }
  let mut doc: Vec<Value> =
    serde_json::from_str(&out.stdout).map_err(|_| unreachable())?;
  doc.pop().ok_or_else(unreachable)
}

pub(crate) async fn exec_host(
  docker: &Docker,
  id: &str,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let doc = inspect(docker, id, ctx).await?;
  let mode = doc["HostConfig"]["NetworkMode"]
    .as_str()
    .unwrap_or_default();
  if mode == "host" {
    return Ok("127.0.0.1".into());
  }
  if mode.starts_with("container:") || mode == "none" {
    return Err(unreachable());
  }
  let networks = doc["NetworkSettings"]["Networks"]
    .as_object()
    .ok_or_else(unreachable)?;
  if networks.len() != 1 {
    return Err(unreachable());
  }
  let (name, endpoint) =
    networks.iter().next().ok_or_else(unreachable)?;
  let ip = endpoint["IPAddress"]
    .as_str()
    .and_then(|ip| ip.parse::<IpAddr>().ok())
    .ok_or_else(unreachable)?;
  if !crate::egress::local_peer(SocketAddr::new(ip, 0)) {
    return Err(unreachable());
  }
  gateway(docker, name, ctx).await
}

pub(crate) async fn verify_service(
  docker: &Docker,
  up: &ProjectUp,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let doc = wharf_api_types::compose::parse_compose(&up.compose)?;
  let components =
    doc["services"].as_mapping().ok_or_else(unreachable)?;
  let (name, body) = components
    .iter()
    .find(|(_, body)| {
      body["environment"]["HTTP_PROXY"].as_str().is_some_and(
        |value| {
          value
            == format!(
              "http://{WORKLOAD_PROXY_HOST}:{}",
              wharf_api_types::egress::LOCAL_PORT
            )
            || value
              == format!(
                "http://127.0.0.1:{}",
                wharf_api_types::egress::LOCAL_PORT
              )
        },
      )
    })
    .ok_or_else(unreachable)?;
  if body["network_mode"].as_str() == Some("host") {
    return Ok(());
  }
  default_bridge(docker, ctx).await?;
  let name = name.as_str().ok_or_else(unreachable)?;
  let ids = docker
    .compose(&up.project)
    .args(["ps", "--all", "--quiet", name])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("读取服务代理网络")?;
  if ids.stdout.trim().is_empty() {
    return Err(unreachable());
  }
  for id in ids.stdout.split_whitespace() {
    let doc = inspect(docker, id, ctx).await?;
    let networks = doc["NetworkSettings"]["Networks"]
      .as_object()
      .ok_or_else(unreachable)?;
    if networks.is_empty() {
      return Err(unreachable());
    }
    for name in networks.keys() {
      gateway(docker, name, ctx).await?;
    }
  }
  Ok(())
}
