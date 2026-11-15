//! 本机监听与容器权限，只读采集。
use crate::{docker::Docker, exec::Ctx};
use serde_json::Value;
use std::{net::IpAddr, time::Duration};
use wharf_api_types::{
  ApiError,
  agent::{ContainerRisk, ExposureReport, Listen},
};

pub async fn collect(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<ExposureReport, ApiError> {
  let ctx = Ctx {
    cancel: ctx.cancel.child_token(),
    progress: ctx.progress.clone(),
  };
  let cancel = ctx.cancel.clone();
  let timer = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(30)).await;
    cancel.cancel();
  });
  let result = collect_inner(docker, &ctx).await;
  timer.abort();
  result
}

async fn collect_inner(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<ExposureReport, ApiError> {
  let image = crate::adopt::self_image(docker, ctx).await?;
  let helper = format!(
    "wharf-exposure-{}",
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos()
  );
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--name",
      &helper,
      "--pid",
      "host",
      "--network",
      "host",
      "--cgroupns",
      "host",
      "--cap-add",
      "SYS_PTRACE",
      "--cap-add",
      "DAC_READ_SEARCH",
      "--security-opt",
      "apparmor=unconfined",
      "-v",
      "/:/host:ro",
      "--entrypoint",
      "sh",
      &image,
      "-c",
      "chroot /host ss -H -tulnp",
    ])
    .timeout(Duration::from_secs(30))
    .run(ctx)
    .await;
  // docker CLI 被取消不会停止容器，显式回收只读辅助容器。
  let cleanup = docker
    .cmd()
    .args(["rm", "-f", &helper])
    .timeout(Duration::from_secs(5))
    .run(&Ctx::detached())
    .await;
  let out = out?.check("读取监听端口")?;
  cleanup?;
  let mut listens = parse_ss(&out.stdout);
  let ids = docker
    .cmd()
    .args(["ps", "-q"])
    .run(ctx)
    .await?
    .check("列出容器")?;
  let ids: Vec<&str> = ids.stdout.split_whitespace().collect();
  let mut containers = vec![];
  if !ids.is_empty() {
    let out = docker
      .cmd()
      .arg("inspect")
      .args(ids)
      .run(ctx)
      .await?
      .check("读取容器权限")?;
    let values: Vec<Value> = serde_json::from_str(&out.stdout)
      .map_err(|e| {
        ApiError::internal(format!("容器信息解析失败：{e}"))
      })?;
    for v in values {
      let name = v["Name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
      let project =
        v["Config"]["Labels"]["com.docker.compose.project"]
          .as_str()
          .map(str::to_string);
      if let Some(ports) = v["NetworkSettings"]["Ports"].as_object() {
        for (key, bindings) in ports {
          let Some((_, proto)) = key.split_once('/') else {
            continue;
          };
          for b in bindings.as_array().into_iter().flatten() {
            let Some(port) =
              b["HostPort"].as_str().and_then(|p| p.parse().ok())
            else {
              continue;
            };
            let addr = b["HostIp"].as_str().unwrap_or("0.0.0.0");
            if loopback(addr) {
              continue;
            }
            let mut matched = false;
            for l in &mut listens {
              if l.proto == proto
                && l.port == port
                && (l.addr == addr
                  || l.addr == "*"
                  || addr == "0.0.0.0" && l.addr == "::")
              {
                l.container = Some(name.clone());
                l.project = project.clone();
                matched = true;
              }
            }
            // 关闭 docker-proxy 时 ss 没有发布端口，仍以 Docker 的实际绑定补齐。
            if !matched {
              listens.push(Listen {
                proto: proto.into(),
                addr: addr.into(),
                port,
                container: Some(name.clone()),
                project: project.clone(),
                ..Default::default()
              });
            }
          }
        }
      }
      let risks = risks(&v);
      if !risks.is_empty() {
        containers.push(ContainerRisk {
          name,
          project,
          risks,
        });
      }
    }
  }
  Ok(ExposureReport {
    listens,
    containers,
  })
}

fn loopback(addr: &str) -> bool {
  addr.parse::<IpAddr>().is_ok_and(|a| a.is_loopback())
}

fn parse_ss(text: &str) -> Vec<Listen> {
  text
    .lines()
    .filter_map(|line| {
      let cols: Vec<_> = line.split_whitespace().collect();
      let proto = *cols.first()?;
      if !matches!(proto, "tcp" | "udp") {
        return None;
      }
      let (addr, port) = cols.get(4)?.rsplit_once(':')?;
      let addr = addr.trim_matches(['[', ']']);
      if loopback(addr) {
        return None;
      }
      Some(Listen {
        proto: proto.into(),
        addr: addr.into(),
        port: port.parse().ok()?,
        process: line
          .split("users:((\"")
          .nth(1)
          .and_then(|s| s.split('"').next())
          .unwrap_or("")
          .into(),
        ..Default::default()
      })
    })
    .collect()
}

fn risks(v: &Value) -> Vec<String> {
  let h = &v["HostConfig"];
  let sources: Vec<_> = v["Mounts"]
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(|m| m["Source"].as_str())
    .collect();
  [
    ("privileged", h["Privileged"] == true),
    (
      "docker_sock",
      sources.iter().any(|s| s.ends_with("docker.sock")),
    ),
    ("host_root", sources.contains(&"/")),
    (
      "host_sensitive",
      sources.iter().any(|s| {
        [
          "/etc", "/root", "/var/run", "/run", "/proc", "/sys",
          "/boot",
        ]
        .contains(s)
      }),
    ),
    ("host_network", h["NetworkMode"] == "host"),
    ("host_pid", h["PidMode"] == "host"),
    (
      "cap_admin",
      h["CapAdd"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|c| {
          matches!(
            c.to_ascii_uppercase().trim_start_matches("CAP_"),
            "SYS_ADMIN" | "NET_ADMIN" | "ALL"
          )
        }),
    ),
  ]
  .into_iter()
  .filter(|(_, yes)| *yes)
  .map(|(code, _)| code.into())
  .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn parses_tcp_udp_and_ipv6() {
    let rows = parse_ss(
      "tcp LISTEN 0 128 [::]:443 [::]:* users:((\"caddy\",pid=12,fd=3))\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.2:80 *:*\ntcp LISTEN 0 128 [::1]:80 *:*",
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(
      (&*rows[0].addr, &*rows[0].process, rows[0].port),
      ("::", "caddy", 443)
    );
    assert_eq!(rows[1].proto, "udp");
  }
  #[test]
  fn inspect_permissions() {
    let v = serde_json::json!({"HostConfig":{"Privileged":true,"NetworkMode":"host","PidMode":"host","CapAdd":["cap_net_admin"]},"Mounts":[{"Source":"/var/run/docker.sock"},{"Source":"/"},{"Source":"/etc"},{"Source":"/root/sub"}]});
    assert_eq!(
      risks(&v),
      [
        "privileged",
        "docker_sock",
        "host_root",
        "host_sensitive",
        "host_network",
        "host_pid",
        "cap_admin"
      ]
    );
    assert!(
      risks(&serde_json::json!({"Mounts":[{"Source":"/etc/app"}]}))
        .is_empty()
    );
  }
}
