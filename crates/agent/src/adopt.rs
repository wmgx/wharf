//! 导入服务器上已有的容器：列出容器、读取配置、接管时停掉原来的容器。
//!
//! 只读出原始配置（`docker compose config`、`docker inspect`），
//! 转换成 Wharf 服务的事由控制面做。

use std::{collections::BTreeMap, path::Path, time::Duration};

use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{FoundContainer, ImportRaw, ImportTarget, Retire, Retired},
};

use crate::{docker::Docker, exec::Ctx};

const QUICK: Duration = Duration::from_secs(30);
const PROJECT_LABEL: &str = "com.docker.compose.project";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsLine {
  #[serde(default)]
  names: String,
  #[serde(default)]
  image: String,
  #[serde(default)]
  state: String,
  #[serde(default)]
  status: String,
  #[serde(default)]
  ports: String,
  #[serde(default)]
  labels: String,
}

fn labels(raw: &str) -> BTreeMap<&str, &str> {
  raw.split(',').filter_map(|kv| kv.split_once('=')).collect()
}

/// 本机的全部容器，不含 agent 自己。
pub async fn discover(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Vec<FoundContainer>, ApiError> {
  let out = docker
    .cmd()
    .args(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker ps")?;
  Ok(
    out
      .stdout
      .lines()
      .filter_map(|l| serde_json::from_str::<PsLine>(l).ok())
      // Wharf 自己的 agent 和控制面不算。
      .filter(|ps| {
        !ps.image.contains("wharf-agent")
          && !ps.image.contains("wharf-core")
      })
      .map(|ps| {
        let project = labels(&ps.labels)
          .get(PROJECT_LABEL)
          .map(|p| p.to_string());
        FoundContainer {
          name: ps.names,
          image: ps.image,
          state: ps.state,
          status: ps.status,
          ports: ps
            .ports
            .split(", ")
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
          project,
        }
      })
      .collect(),
  )
}

pub async fn read(
  docker: &Docker,
  target: &ImportTarget,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  match (&target.project, &target.container) {
    (Some(project), None) => read_project(docker, project, ctx).await,
    (None, Some(name)) => read_container(docker, name, ctx).await,
    _ => Err(ApiError::invalid("compose 项目和容器二选一")),
  }
}

async fn inspect(
  docker: &Docker,
  what: &str,
  name: &str,
  ctx: &Ctx,
) -> Result<Option<serde_json::Value>, ApiError> {
  let out = docker
    .cmd()
    .args([what, "inspect", name])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !out.success {
    return Ok(None);
  }
  let mut list: Vec<serde_json::Value> =
    serde_json::from_str(&out.stdout).map_err(|e| {
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("解析 inspect 失败：{e}"),
      )
    })?;
  Ok((!list.is_empty()).then(|| list.swap_remove(0)))
}

async fn read_container(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  check_container_name(name)?;
  let container = inspect(docker, "container", name, ctx)
    .await?
    .ok_or_else(|| ApiError::not_found(format!("没有容器 {name}")))?;
  let image =
    container["Config"]["Image"].as_str().unwrap_or_default();
  let image_inspect = inspect(docker, "image", image, ctx).await?;
  Ok(ImportRaw {
    inspect: Some(container),
    image_inspect,
    ..Default::default()
  })
}

/// 用原来的文件跑 `docker compose config`，相对路径和 `.env` 都会被解析。
async fn read_project(
  docker: &Docker,
  project: &str,
  ctx: &Ctx,
) -> Result<ImportRaw, ApiError> {
  let out = docker
    .cmd()
    .args(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    .args(["--filter", &format!("label={PROJECT_LABEL}={project}")])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker ps")?;
  let first = out
    .stdout
    .lines()
    .find_map(|l| serde_json::from_str::<PsLine>(l).ok())
    .ok_or_else(|| {
      ApiError::not_found(format!("没有 compose 项目 {project}"))
    })?;
  let labels = labels(&first.labels);
  let dir = labels
    .get("com.docker.compose.project.working_dir")
    .copied()
    .unwrap_or_default();
  let files: Vec<&str> = labels
    .get("com.docker.compose.project.config_files")
    .map(|f| f.split(',').filter(|f| !f.is_empty()).collect())
    .unwrap_or_default();
  if dir.is_empty() || files.is_empty() {
    return Err(ApiError::invalid(format!(
      "compose 项目 {project} 没有记录 compose 文件的位置，按单个容器导入"
    )));
  }
  let mut args: Vec<String> = vec![
    "compose".into(),
    "-p".into(),
    project.into(),
    "--project-directory".into(),
    dir.into(),
  ];
  for f in &files {
    args.extend(["-f".into(), f.to_string()]);
  }
  if let Some(env) = labels
    .get("com.docker.compose.project.environment_file")
    .filter(|e| !e.is_empty())
  {
    for e in env.split(',') {
      args.extend(["--env-file".into(), e.to_string()]);
    }
  }
  args.push("config".into());

  // agent 在容器里时看不到宿主机上的文件：在一个挂载了这些目录的临时容器里执行。
  let cmd = if Path::new("/.dockerenv").exists() {
    let image = self_image(docker, ctx).await?;
    let mut dirs = vec![dir.to_string()];
    for f in &files {
      if let Some(parent) = Path::new(f).parent()
        && !Path::new(f).starts_with(dir)
      {
        dirs.push(parent.display().to_string());
      }
    }
    let mut c = docker.cmd().args([
      "run",
      "--rm",
      "--network",
      "none",
      "-w",
      dir,
    ]);
    for d in &dirs {
      c = c.args(["-v".to_string(), format!("{d}:{d}:ro")]);
    }
    c.args(["--entrypoint", "docker", image.as_str()])
      .args(args)
  } else {
    docker.cmd().args(args)
  };
  let out = cmd
    .timeout(Duration::from_secs(120))
    .run(ctx)
    .await?
    .check("docker compose config")?;
  let warnings = out
    .stderr
    .lines()
    .filter(|l| l.contains("level=warning") || l.contains("WARN"))
    .map(|l| l.trim().to_string())
    .collect();
  Ok(ImportRaw {
    compose: Some(out.stdout),
    warnings,
    ..Default::default()
  })
}

/// agent 自己的镜像（里面有 docker 命令和 compose 插件）。
async fn self_image(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  if let Ok(image) = std::env::var("WHARF_SELF_IMAGE")
    && !image.is_empty()
  {
    return Ok(image);
  }
  let id = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| container_id(&m))
    .ok_or_else(|| {
      ApiError::new(ErrorCode::AgentFailed, "找不到 agent 自己的容器")
    })?;
  let out = docker
    .cmd()
    .args(["inspect", "--format", "{{.Image}}", &id])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("docker inspect")?;
  Ok(out.stdout.trim().to_string())
}

/// mountinfo 里 `/etc/hostname` 之类的挂载来自 `.../containers/<id>/`。
pub(crate) fn container_id(mountinfo: &str) -> Option<String> {
  mountinfo.lines().find_map(|line| {
    let rest =
      &line[line.find("/containers/")? + "/containers/".len()..];
    let id: String =
      rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (id.len() == 64).then_some(id)
  })
}

/// 容器名只允许 docker 本身允许的字符，也防止被当成命令行参数。
fn check_container_name(name: &str) -> Result<(), ApiError> {
  let ok = name
    .chars()
    .next()
    .is_some_and(|c| c.is_ascii_alphanumeric())
    && name
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
  if ok {
    Ok(())
  } else {
    Err(ApiError::invalid(format!("容器名 {name} 不合法")))
  }
}

struct Info {
  id: String,
  name: String,
  project: String,
  restart: String,
  running: bool,
}

async fn info(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
) -> Result<Option<Info>, ApiError> {
  let out = docker
    .cmd()
    .args([
      "inspect",
      "--format",
      "{{.Id}}|{{.Name}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Running}}",
      name,
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?;
  if !out.success {
    return Ok(None);
  }
  let parts: Vec<&str> = out.stdout.trim().split('|').collect();
  let [id, name, project, restart, running] = parts[..] else {
    return Ok(None);
  };
  Ok(Some(Info {
    id: id.into(),
    name: name.trim_start_matches('/').into(),
    project: project.replace("<no value>", ""),
    restart: restart.into(),
    running: running == "true",
  }))
}

async fn docker_do(
  docker: &Docker,
  args: &[&str],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  docker
    .cmd()
    .args(args.iter().copied())
    .timeout(Duration::from_secs(90))
    .run(ctx)
    .await?
    .check(&format!("docker {}", args[0]))?;
  Ok(())
}

/// 停掉原来的容器，关掉自动重启。单个容器还要改名，让出名字给新容器，留着回退用。
pub async fn retire(
  docker: &Docker,
  r: &Retire,
  ctx: &Ctx,
) -> Result<Vec<Retired>, ApiError> {
  let mut targets: Vec<(Info, bool)> = Vec::new();
  if let Some(project) =
    r.project.as_deref().filter(|p| *p != r.service)
  {
    let out = docker
      .cmd()
      .args(["ps", "-aq", "--no-trunc"])
      .args(["--filter", &format!("label={PROJECT_LABEL}={project}")])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("docker ps")?;
    for id in out.stdout.lines().filter(|l| !l.is_empty()) {
      if let Some(i) = info(docker, id, ctx).await? {
        targets.push((i, false));
      }
    }
  }
  for name in &r.containers {
    check_container_name(name)?;
    match info(docker, name, ctx).await? {
      // 已经是新服务的容器：之前接管过了。
      Some(i) if i.project != r.service => targets.push((i, true)),
      _ => {}
    }
  }
  let mut done = Vec::new();
  for (i, rename) in targets {
    let renamed = if rename {
      let mut to = format!("{}-wharf-old", i.name);
      if info(docker, &to, ctx).await?.is_some() {
        to = format!("{to}-{}", chrono_suffix());
      }
      ctx.say(format!("原来的容器 {} 改名为 {to}", i.name));
      docker_do(docker, &["rename", &i.id, &to], ctx).await?;
      Some(to)
    } else {
      None
    };
    docker_do(docker, &["update", "--restart=no", &i.id], ctx)
      .await?;
    if i.running {
      ctx.say(format!("停止原来的容器 {}", i.name));
      docker_do(docker, &["stop", &i.id], ctx).await?;
    }
    done.push(Retired {
      id: i.id,
      name: i.name,
      renamed,
      restart: i.restart,
      was_running: i.running,
    });
  }
  Ok(done)
}

fn chrono_suffix() -> String {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs().to_string())
    .unwrap_or_default()
}

/// 把 [retire] 停掉的容器恢复原样。
pub async fn unretire(
  docker: &Docker,
  items: &[Retired],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  for item in items {
    if item.renamed.is_some() {
      check_container_name(&item.name)?;
      docker_do(docker, &["rename", &item.id, &item.name], ctx)
        .await?;
    }
    if !item.restart.is_empty() && item.restart != "no" {
      let policy = format!("--restart={}", item.restart);
      docker_do(docker, &["update", &policy, &item.id], ctx).await?;
    }
    if item.was_running {
      ctx.say(format!("启动原来的容器 {}", item.name));
      docker_do(docker, &["start", &item.id], ctx).await?;
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_container_id_in_mountinfo() {
    let id = "a".repeat(64);
    let m = format!(
      "1 2 0:1 / / rw - overlay overlay rw\n3 1 8:1 /var/lib/docker/containers/{id}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
    );
    assert_eq!(container_id(&m), Some(id));
    assert_eq!(container_id("1 2 0:1 / / rw\n"), None);
  }
}
