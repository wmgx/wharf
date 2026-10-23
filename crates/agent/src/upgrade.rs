//! agent 自升级。
//!
//! agent 不能停掉自己再启动，所以分两段：
//! 1. 当前 agent 拉新镜像，用新镜像起一个接班容器（`wharf-agent replace`），然后回复控制面；
//! 2. 接班容器按旧容器的参数起新 agent：旧容器改名、停止，新容器启动，
//!    日志里出现"已连接控制面"才删旧容器；否则删掉新容器、恢复旧容器。

use std::time::Duration;

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{UpgradeJob, UpgradeResult},
};

use crate::{
  docker::Docker,
  exec::{Cmd, Ctx},
};

const QUICK: Duration = Duration::from_secs(30);
/// 接班容器的名字，同一时间只有一个。
const HELPER: &str = "wharf-agent-upgrade";
/// 新 agent 要在这么长时间里连上控制面。
const CONNECT_WAIT: Duration = Duration::from_secs(60);
/// agent 连上控制面时打的日志，见 conn.rs。
const CONNECTED: &str = "已连接控制面";
const SOCK: &str = "/var/run/docker.sock";

/// 当前 agent 所在的容器 id。
fn self_container() -> Result<String, ApiError> {
  std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| crate::adopt::container_id(&m))
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::AgentFailed,
        "agent 不在容器里运行，不能自动升级",
      )
    })
}

async fn inspect(
  docker: &Docker,
  target: &str,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  let out = docker
    .cmd()
    .args(["inspect", target])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker inspect")?;
  let mut list: Vec<Value> = serde_json::from_str(&out.stdout)
    .map_err(|e| {
      ApiError::internal(format!("解析 docker inspect：{e}"))
    })?;
  if list.is_empty() {
    return Err(ApiError::not_found(format!("找不到 {target}")));
  }
  Ok(list.swap_remove(0))
}

/// `ghcr.io/o/wharf-agent:latest` → `ghcr.io/o/wharf-agent`。
fn repository(image: &str) -> &str {
  let image = image.split('@').next().unwrap_or(image);
  match image.rsplit_once(':') {
    Some((repo, tag)) if !tag.contains('/') => repo,
    _ => image,
  }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
  path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn strs_at(v: &Value, path: &[&str]) -> Vec<String> {
  path
    .iter()
    .try_fold(v, |v, k| v.get(k))
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
    })
    .unwrap_or_default()
}

/// 宿主机上 docker socket 的路径：沿用旧容器的挂载。
fn sock_bind(container: &Value) -> String {
  strs_at(container, &["HostConfig", "Binds"])
    .into_iter()
    .find(|b| b.split(':').nth(1) == Some(SOCK))
    .unwrap_or_else(|| format!("{SOCK}:{SOCK}"))
}

/// 第一段：拉镜像、起接班容器。
pub async fn start(
  docker: &Docker,
  job: &UpgradeJob,
  ctx: &Ctx,
) -> Result<UpgradeResult, ApiError> {
  let id = self_container()?;
  let me = inspect(docker, &id, ctx).await?;
  let current = str_at(&me, &["Config", "Image"])
    .ok_or_else(|| ApiError::internal("读不到 agent 的镜像名"))?
    .to_string();
  let old_id =
    str_at(&me, &["Image"]).unwrap_or_default().to_string();
  let pulled = match &job.tag {
    Some(tag) => format!("{}:{tag}", repository(&current)),
    None => current.clone(),
  };
  docker
    .pull(&pulled, &job.pull, ctx, &mut Vec::new())
    .await?;
  let new_id = str_at(&inspect(docker, &pulled, ctx).await?, &["Id"])
    .unwrap_or_default()
    .to_string();
  if new_id == old_id {
    ctx.say(format!("已经是 {pulled}，不用升级"));
    return Ok(UpgradeResult {
      image: pulled,
      started: false,
    });
  }
  // 新镜像打上旧容器用的名字，新容器的配置和旧的完全一样。
  if pulled != current {
    docker
      .cmd()
      .args(["tag", &pulled, &current])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("docker tag")?;
  }
  let _ = docker
    .cmd()
    .args(["rm", "-f", HELPER])
    .timeout(QUICK)
    .run(ctx)
    .await;
  ctx.say(format!("启动接班容器，换成 {pulled}"));
  docker
    .cmd()
    .args(["run", "-d", "--rm", "--name", HELPER])
    .args(["-v", &sock_bind(&me)])
    .args(["--entrypoint", "wharf-agent", &new_id])
    .args(["replace", &id, &current, &old_id])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("启动接班容器")?;
  Ok(UpgradeResult {
    image: pulled,
    started: true,
  })
}

/// 按旧容器的配置拼 `docker run` 参数（不含镜像）。
fn run_args(old: &Value, name: &str) -> Vec<String> {
  let mut args =
    vec!["run".into(), "-d".into(), "--name".into(), name.into()];
  if old.pointer("/HostConfig/Privileged") == Some(&Value::Bool(true))
  {
    args.push("--privileged".into());
  }
  let mut flag = |f: &str, v: String| {
    args.push(f.to_string());
    args.push(v);
  };
  for e in strs_at(old, &["Config", "Env"]) {
    flag("-e", e);
  }
  for b in strs_at(old, &["HostConfig", "Binds"]) {
    flag("-v", b);
  }
  for h in strs_at(old, &["HostConfig", "ExtraHosts"]) {
    flag("--add-host", h);
  }
  for c in strs_at(old, &["HostConfig", "CapAdd"]) {
    flag("--cap-add", c);
  }
  if let Some(n) = str_at(old, &["HostConfig", "NetworkMode"]) {
    flag("--network", n.to_string());
  }
  if let Some(r) =
    str_at(old, &["HostConfig", "RestartPolicy", "Name"])
    && !r.is_empty()
    && r != "no"
  {
    flag("--restart", r.to_string());
  }
  if let Some(p) = str_at(old, &["HostConfig", "PidMode"])
    && !p.is_empty()
  {
    flag("--pid", p.to_string());
  }
  if let Some(u) = str_at(old, &["Config", "User"])
    && !u.is_empty()
  {
    flag("--user", u.to_string());
  }
  if let Some(t) = str_at(old, &["HostConfig", "LogConfig", "Type"]) {
    flag("--log-driver", t.to_string());
  }
  if let Some(opts) = old
    .pointer("/HostConfig/LogConfig/Config")
    .and_then(Value::as_object)
  {
    for (k, v) in opts {
      if let Some(v) = v.as_str() {
        flag("--log-opt", format!("{k}={v}"));
      }
    }
  }
  if let Some(ports) = old
    .pointer("/HostConfig/PortBindings")
    .and_then(Value::as_object)
  {
    for (port, binds) in ports {
      let port = port.trim_end_matches("/tcp");
      for b in binds.as_array().into_iter().flatten() {
        let ip = b["HostIp"].as_str().unwrap_or_default();
        let host = b["HostPort"].as_str().unwrap_or_default();
        let spec = if ip.is_empty() {
          format!("{host}:{port}")
        } else {
          format!("{ip}:{host}:{port}")
        };
        flag("-p", spec);
      }
    }
  }
  args
}

async fn docker_ok(ctx: &Ctx, args: &[&str]) -> bool {
  Cmd::new("docker")
    .args(args.iter().copied())
    .timeout(QUICK)
    .run(ctx)
    .await
    .is_ok_and(|o| o.success)
}

/// 等新 agent 连上控制面。
async fn connected(ctx: &Ctx, name: &str) -> bool {
  let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
  while tokio::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_secs(3)).await;
    let Ok(out) = Cmd::new("docker")
      .args(["logs", name])
      .timeout(QUICK)
      .run(ctx)
      .await
    else {
      continue;
    };
    if out.stdout.contains(CONNECTED)
      || out.stderr.contains(CONNECTED)
    {
      return true;
    }
  }
  false
}

/// 第二段，在接班容器里执行：换掉旧容器，失败时恢复。
pub async fn replace(
  container: &str,
  image: &str,
  old_image: &str,
) -> anyhow::Result<()> {
  let ctx = Ctx::detached();
  // 让旧 agent 先把回复发出去。
  tokio::time::sleep(Duration::from_secs(3)).await;
  let docker = Docker {
    bin: "docker".into(),
    data_dir: Default::default(),
  };
  let old = inspect(&docker, container, &ctx)
    .await
    .map_err(|e| anyhow::anyhow!("{}", e.message))?;
  let name = str_at(&old, &["Name"])
    .unwrap_or_default()
    .trim_start_matches('/')
    .to_string();
  anyhow::ensure!(!name.is_empty(), "读不到旧容器的名字");
  let backup = format!("{name}-old");
  let args = run_args(&old, &name);
  let cmd: Vec<String> = strs_at(&old, &["Config", "Cmd"]);

  docker_ok(&ctx, &["rm", "-f", &backup]).await;
  anyhow::ensure!(
    docker_ok(&ctx, &["rename", container, &backup]).await,
    "旧容器改名失败"
  );
  docker_ok(&ctx, &["stop", "-t", "10", &backup]).await;
  let mut run: Vec<&str> = args.iter().map(String::as_str).collect();
  run.push(image);
  run.extend(cmd.iter().map(String::as_str));
  let started = docker_ok(&ctx, &run).await;
  if started && connected(&ctx, &name).await {
    docker_ok(&ctx, &["rm", "-f", &backup]).await;
    // 旧镜像没有别的容器在用时删掉；在用就删不掉，不影响。
    docker_ok(&ctx, &["rmi", old_image]).await;
    tracing::info!("升级完成：{name} 已换成 {image}");
    return Ok(());
  }
  tracing::warn!("新 agent 没有连上控制面，恢复旧容器");
  if let Ok(out) = Cmd::new("docker")
    .args(["logs", "--tail", "20", &name])
    .timeout(QUICK)
    .run(&ctx)
    .await
  {
    tracing::warn!("新 agent 的日志：\n{}{}", out.stdout, out.stderr);
  }
  docker_ok(&ctx, &["rm", "-f", &name]).await;
  docker_ok(&ctx, &["rename", &backup, &name]).await;
  docker_ok(&ctx, &["start", &name]).await;
  anyhow::bail!("升级失败，已恢复旧 agent")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn strips_tag_and_digest() {
    assert_eq!(repository("ghcr.io/o/a:latest"), "ghcr.io/o/a");
    assert_eq!(repository("localhost:5000/a"), "localhost:5000/a");
    assert_eq!(repository("a@sha256:abc"), "a");
  }

  #[test]
  fn copies_container_config() {
    let old = serde_json::json!({
      "Config": {"Env": ["A=1"], "User": ""},
      "HostConfig": {
        "Binds": ["/srv:/srv", "/run/d.sock:/var/run/docker.sock"],
        "NetworkMode": "host",
        "RestartPolicy": {"Name": "unless-stopped"},
        "LogConfig": {"Type": "json-file", "Config": {}},
      },
    });
    let args = run_args(&old, "wharf-agent").join(" ");
    assert_eq!(
      args,
      "run -d --name wharf-agent -e A=1 -v /srv:/srv \
       -v /run/d.sock:/var/run/docker.sock --network host \
       --restart unless-stopped --log-driver json-file"
    );
    assert_eq!(sock_bind(&old), "/run/d.sock:/var/run/docker.sock");
  }
}
