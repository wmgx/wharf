//! compose project 的读写。每个服务、每个网关都是一个 compose project，
//! 文件放在 `<data_dir>/projects/<project>/compose.yaml`。
//!
//! agent 跑在容器里时，`data_dir` 和 `/srv` 必须以相同路径挂载进来，
//! 这样 compose 里的相对路径、目录挂载在宿主机上解析结果一致。

use std::{
  collections::BTreeMap,
  path::{Path, PathBuf},
  time::Duration,
};

use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ContainerInfo, ImageInfo, ProjectState, PullPolicy},
};

use crate::exec::{Cmd, Ctx};

pub const HASH_FILE: &str = ".wharf-hash";
pub const CONFIG_HASH_FILE: &str = ".wharf-config-hash";

/// 跟随日志的最长时长，到点后页面会自动重连。
const FOLLOW_MAX: Duration = Duration::from_secs(30 * 60);

#[derive(Clone)]
pub struct Docker {
  pub bin: String,
  pub data_dir: PathBuf,
}

impl Docker {
  pub fn project_dir(&self, project: &str) -> PathBuf {
    self.data_dir.join("projects").join(project)
  }

  pub fn cmd(&self) -> Cmd {
    Cmd::new(&self.bin)
  }

  /// `docker compose -p <project> -f <dir>/compose.yaml ...`
  pub fn compose(&self, project: &str) -> Cmd {
    let dir = self.project_dir(project);
    self
      .cmd()
      .args(["compose", "-p", project, "-f"])
      .arg(dir.join("compose.yaml").display().to_string())
      .cwd(&dir)
  }

  pub async fn versions(&self) -> (Option<String>, Option<String>) {
    let ctx = Ctx::detached();
    let quick = Duration::from_secs(10);
    let docker = self
      .cmd()
      .args(["version", "--format", "{{.Server.Version}}"])
      .timeout(quick)
      .run(&ctx)
      .await;
    let compose = self
      .cmd()
      .args(["compose", "version", "--short"])
      .timeout(quick)
      .run(&ctx)
      .await;
    let pick = |out: Result<crate::exec::Output, ApiError>| {
      out
        .ok()
        .filter(|o| o.success)
        .map(|o| o.stdout.trim().to_string())
        .filter(|s| !s.is_empty())
    };
    (pick(docker), pick(compose))
  }

  /// 读多个 project 的现状：一次 `docker ps`，按 compose label 分组。
  pub async fn status(
    &self,
    projects: &[String],
    ctx: &Ctx,
  ) -> Result<Vec<ProjectState>, ApiError> {
    let out = self
      .cmd()
      .args([
        "ps",
        "-a",
        "--no-trunc",
        "--filter",
        "label=com.docker.compose.project",
        "--format",
        "{{json .}}",
      ])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("docker ps")?;
    let mut by_project = parse_ps(&out.stdout);
    Ok(
      projects
        .iter()
        .map(|project| {
          let dir = self.project_dir(project);
          ProjectState {
            project: project.clone(),
            hash: read_trimmed(&dir.join(HASH_FILE)),
            config_hash: read_trimmed(
              &dir.join("conf").join(CONFIG_HASH_FILE),
            ),
            containers: by_project
              .remove(project)
              .unwrap_or_default()
              .into_iter()
              .map(|c| ContainerInfo {
                foreign: c
                  .working_dir
                  .as_deref()
                  .is_some_and(|w| Path::new(w) != dir),
                ..c
              })
              .collect(),
          }
        })
        .collect(),
    )
  }

  pub async fn one_status(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<ProjectState, ApiError> {
    let mut all = self.status(&[project.to_string()], ctx).await?;
    Ok(all.remove(0))
  }

  /// 写入 compose 文件（0600，先写临时文件再改名）。
  pub fn write_compose(
    &self,
    project: &str,
    compose: &str,
  ) -> Result<(), ApiError> {
    let dir = self.project_dir(project);
    std::fs::create_dir_all(&dir).map_err(io_err(&dir))?;
    write_private(&dir.join("compose.yaml"), compose)
  }

  pub fn write_hash(
    &self,
    project: &str,
    hash: &str,
  ) -> Result<(), ApiError> {
    let path = self.project_dir(project).join(HASH_FILE);
    std::fs::write(&path, hash).map_err(io_err(&path))
  }

  /// compose 文件里用到的全部镜像。
  pub async fn images(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<Vec<String>, ApiError> {
    let out = self
      .compose(project)
      .args(["config", "--images"])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("docker compose config")?;
    let mut images: Vec<String> = out
      .stdout
      .lines()
      .map(str::trim)
      .filter(|l| !l.is_empty())
      .map(str::to_string)
      .collect();
    images.sort();
    images.dedup();
    Ok(images)
  }

  pub async fn image_exists(&self, image: &str, ctx: &Ctx) -> bool {
    self
      .cmd()
      .args(["image", "inspect", "--format", "{{.Id}}", image])
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await
      .is_ok_and(|o| o.success)
  }

  /// 按镜像源顺序拉取，每次尝试都有超时。全部失败但本地已有镜像时只警告。
  pub async fn pull(
    &self,
    image: &str,
    policy: &PullPolicy,
    ctx: &Ctx,
    warnings: &mut Vec<String>,
  ) -> Result<(), ApiError> {
    let timeout =
      Duration::from_secs(policy.attempt_timeout_secs.max(10));
    let mut errors = Vec::new();
    for candidate in pull_candidates(image, policy) {
      ctx.say(format!("拉取 {candidate}"));
      let result = self
        .cmd()
        .args(["pull", "--quiet", &candidate])
        .timeout(timeout)
        .stream(false)
        .run(ctx)
        .await
        .and_then(|o| o.check(&format!("docker pull {candidate}")));
      match result {
        Ok(_) => {
          if candidate != image {
            self
              .cmd()
              .args(["tag", &candidate, image])
              .timeout(Duration::from_secs(15))
              .run(ctx)
              .await?
              .check("docker tag")?;
            // 只删掉镜像源的标签，镜像本身保留。
            let _ = self
              .cmd()
              .args(["image", "rm", &candidate])
              .timeout(Duration::from_secs(15))
              .run(ctx)
              .await;
          }
          ctx.say(format!("已拉取 {image}"));
          return Ok(());
        }
        Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
        Err(e) => {
          ctx.say(format!("失败：{}", e.message));
          errors.push(format!("{candidate}：{}", e.message));
        }
      }
    }
    if self.image_exists(image, ctx).await {
      let warning = format!("{image} 拉取失败，使用本地已有的镜像");
      ctx.say(&warning);
      warnings.push(warning);
      return Ok(());
    }
    Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("镜像 {image} 拉取失败：\n{}", errors.join("\n")),
      )
      .with_hint(
        "检查服务器的 registry_mirrors 设置，例如 wharf server set <server> --mirror docker.io=docker.1ms.run",
      ),
    )
  }

  pub async fn up(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    ctx.say("启动容器");
    self
      .compose(project)
      .args(["up", "-d", "--remove-orphans", "--pull", "never"])
      .timeout(Duration::from_secs(300))
      .stream(true)
      .run(ctx)
      .await?
      .check("docker compose up")?;
    Ok(())
  }

  pub async fn down(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let dir = self.project_dir(project);
    let cmd = if dir.join("compose.yaml").exists() {
      self.compose(project)
    } else {
      self.cmd().args(["compose", "-p", project])
    };
    cmd
      .args(["down", "--remove-orphans"])
      .timeout(Duration::from_secs(180))
      .stream(true)
      .run(ctx)
      .await?
      .check("docker compose down")?;
    if dir.exists() {
      std::fs::remove_dir_all(&dir).map_err(io_err(&dir))?;
    }
    Ok(())
  }

  /// 删除没有容器在用的镜像（停止的容器也算在用）和构建缓存。
  pub async fn prune(&self, ctx: &Ctx) -> Result<String, ApiError> {
    let mut freed = Vec::new();
    for (what, args) in [
      ("镜像", ["image", "prune", "--all", "--force"]),
      ("构建缓存", ["builder", "prune", "--all", "--force"]),
    ] {
      ctx.say(format!("清理没在用的{what}"));
      let out = self
        .cmd()
        .args(args)
        .timeout(Duration::from_secs(600))
        .run(ctx)
        .await?
        .check(&format!("docker {}", args[..2].join(" ")))?;
      let total = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("Total reclaimed space:"))
        .map(str::trim)
        .unwrap_or("0B");
      ctx.say(format!("{what}释放 {total}"));
      freed.push(format!("{what} {total}"));
    }
    Ok(format!("释放了{}", freed.join("，")))
  }

  /// `stop` 或 `start`。project 没部署过时什么也不做。
  pub async fn stop_start(
    &self,
    project: &str,
    start: bool,
    ctx: &Ctx,
  ) -> Result<bool, ApiError> {
    if !self.project_dir(project).join("compose.yaml").exists() {
      return Ok(false);
    }
    let action = if start { "start" } else { "stop" };
    ctx.say(if start {
      "启动容器"
    } else {
      "停止容器"
    });
    self
      .compose(project)
      .arg(action)
      .timeout(Duration::from_secs(180))
      .stream(true)
      .run(ctx)
      .await?
      .check(&format!("docker compose {action}"))?;
    Ok(true)
  }

  pub async fn logs(
    &self,
    project: &str,
    tail: u32,
    ctx: &Ctx,
  ) -> Result<String, ApiError> {
    let out = self
      .compose(project)
      .args([
        "logs".to_string(),
        "--no-color".into(),
        "--timestamps".into(),
        "--tail".into(),
        tail.min(5000).to_string(),
      ])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("docker compose logs")?;
    // compose 把日志写到 stdout，部分版本的提示写到 stderr。
    Ok(out.stdout)
  }

  /// 持续推送新日志，直到被取消（页面关闭）或到达上限时长。
  /// 结束本身就是正常情况，所以不返回错误。
  pub async fn follow_logs(
    &self,
    project: &str,
    tail: u32,
    ctx: &Ctx,
  ) {
    let result = self
      .compose(project)
      .args([
        "logs".to_string(),
        "--no-color".into(),
        "--timestamps".into(),
        "--follow".into(),
        "--tail".into(),
        tail.min(5000).to_string(),
      ])
      .timeout(FOLLOW_MAX)
      .stream(true)
      .run(ctx)
      .await;
    if let Err(e) = result
      && !ctx.cancel.is_cancelled()
    {
      ctx.say(format!("日志流结束：{}", e.message));
    }
  }

  /// 镜像 id 和 digest，写进部署历史用于回滚。
  pub async fn image_info(
    &self,
    images: &[String],
    ctx: &Ctx,
  ) -> Vec<ImageInfo> {
    let mut out = Vec::new();
    for image in images {
      let inspected = self
        .cmd()
        .args([
          "image",
          "inspect",
          "--format",
          // `join` 在部分 docker 版本上对 RepoDigests 报类型错误，用 json。
          "{{.Id}}|{{json .RepoDigests}}",
          image,
        ])
        .timeout(Duration::from_secs(15))
        .run(ctx)
        .await
        .ok()
        .filter(|o| o.success);
      let (id, digest) = match inspected {
        Some(o) => {
          let line = o.stdout.trim().to_string();
          let (id, digests) =
            line.split_once('|').unwrap_or((&line, "[]"));
          let digests: Vec<String> =
            serde_json::from_str(digests).unwrap_or_default();
          (id.to_string(), pick_digest(image, &digests.join(",")))
        }
        None => (String::new(), None),
      };
      out.push(ImageInfo {
        image: image.clone(),
        id,
        digest,
      });
    }
    out
  }
}

pub fn io_err(
  path: &Path,
) -> impl Fn(std::io::Error) -> ApiError + '_ {
  move |e| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("读写 {} 失败：{e}", path.display()),
    )
  }
}

pub fn write_private(
  path: &Path,
  content: &str,
) -> Result<(), ApiError> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  let tmp = path.with_extension("tmp");
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(&tmp)
    .map_err(io_err(&tmp))?;
  file.write_all(content.as_bytes()).map_err(io_err(&tmp))?;
  file.sync_all().map_err(io_err(&tmp))?;
  std::fs::rename(&tmp, path).map_err(io_err(path))
}

fn read_trimmed(path: &Path) -> Option<String> {
  std::fs::read_to_string(path)
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsLine {
  #[serde(default)]
  names: String,
  #[serde(default)]
  state: String,
  #[serde(default)]
  status: String,
  #[serde(default)]
  image: String,
  #[serde(default)]
  labels: String,
}

/// 解析 `docker ps --format '{{json .}}'`，按 compose project 分组。
pub fn parse_ps(
  stdout: &str,
) -> BTreeMap<String, Vec<ContainerInfo>> {
  let mut out: BTreeMap<String, Vec<ContainerInfo>> = BTreeMap::new();
  for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
    let Ok(ps) = serde_json::from_str::<PsLine>(line) else {
      continue;
    };
    let labels: BTreeMap<&str, &str> = ps
      .labels
      .split(',')
      .filter_map(|kv| kv.split_once('='))
      .collect();
    let Some(project) = labels.get("com.docker.compose.project")
    else {
      continue;
    };
    let health = ["healthy", "unhealthy", "health: starting"]
      .into_iter()
      .find(|h| ps.status.contains(&format!("({h})")))
      .map(|h| h.trim_start_matches("health: ").to_string());
    out
      .entry(project.to_string())
      .or_default()
      .push(ContainerInfo {
        service: labels
          .get("com.docker.compose.service")
          .unwrap_or(&"")
          .to_string(),
        name: ps.names,
        state: ps.state,
        status: ps.status,
        health,
        image: ps.image,
        foreign: false,
        working_dir: labels
          .get("com.docker.compose.project.working_dir")
          .map(|w| w.to_string()),
      });
  }
  for containers in out.values_mut() {
    containers.sort_by(|a, b| a.name.cmp(&b.name));
  }
  out
}

/// 镜像引用拆成 (registry, 路径, 标签或 digest 后缀)。
fn split_image(image: &str) -> (String, String, String) {
  let (name, suffix) = match image.find('@') {
    Some(i) => (&image[..i], image[i..].to_string()),
    None => {
      let last_slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
      match image[last_slash..].find(':') {
        Some(i) => (
          &image[..last_slash + i],
          image[last_slash + i..].to_string(),
        ),
        None => (image, ":latest".to_string()),
      }
    }
  };
  let (registry, path) = match name.split_once('/') {
    Some((first, rest))
      if first.contains('.')
        || first.contains(':')
        || first == "localhost" =>
    {
      (first.to_string(), rest.to_string())
    }
    _ => ("docker.io".to_string(), name.to_string()),
  };
  let path = if registry == "docker.io" && !path.contains('/') {
    format!("library/{path}")
  } else {
    path
  };
  (registry, path, suffix)
}

/// 拉取顺序：镜像源在前，原地址最后（`mirrors_only` 时不试原地址）。
/// digest 引用不能重新打标签，所以只试原地址。
pub fn pull_candidates(
  image: &str,
  policy: &PullPolicy,
) -> Vec<String> {
  let (registry, path, suffix) = split_image(image);
  let mirrors = policy
    .mirrors
    .get(&registry)
    .filter(|_| !suffix.starts_with('@'))
    .cloned()
    .unwrap_or_default();
  let mut out: Vec<String> = mirrors
    .iter()
    .map(|m| format!("{}/{path}{suffix}", m.trim_end_matches('/')))
    .collect();
  if out.is_empty() || !policy.mirrors_only {
    out.push(image.to_string());
  }
  out
}

fn pick_digest(image: &str, digests: &str) -> Option<String> {
  let (registry, path, _) = split_image(image);
  let digests: Vec<&str> =
    digests.split(',').filter(|d| !d.is_empty()).collect();
  digests
    .iter()
    .find(|d| {
      let repo = d.split('@').next().unwrap_or_default();
      let (r, p, _) = split_image(repo);
      r == registry && p == path
    })
    .or(digests.first())
    .map(|d| d.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn policy(only: bool) -> PullPolicy {
    PullPolicy {
      mirrors: BTreeMap::from([
        (
          "docker.io".to_string(),
          vec![
            "docker.1ms.run".to_string(),
            "docker.m.daocloud.io/".into(),
          ],
        ),
        ("ghcr.io".to_string(), vec!["ghcr.nju.edu.cn".to_string()]),
      ]),
      mirrors_only: only,
      attempt_timeout_secs: 60,
    }
  }

  #[test]
  fn candidates_follow_mirror_order() {
    assert_eq!(
      pull_candidates("traefik/whoami", &policy(false)),
      vec![
        "docker.1ms.run/traefik/whoami:latest",
        "docker.m.daocloud.io/traefik/whoami:latest",
        "traefik/whoami",
      ]
    );
    assert_eq!(
      pull_candidates("caddy:2", &policy(true)),
      vec![
        "docker.1ms.run/library/caddy:2",
        "docker.m.daocloud.io/library/caddy:2",
      ]
    );
    assert_eq!(
      pull_candidates("ghcr.io/acme/app:main", &policy(true)),
      vec!["ghcr.nju.edu.cn/acme/app:main"]
    );
    // 没有镜像源的 registry、带端口的私有 registry、digest 引用都直连。
    assert_eq!(
      pull_candidates("quay.io/a/b:1", &policy(true)),
      vec!["quay.io/a/b:1"]
    );
    assert_eq!(
      pull_candidates("localhost:5000/a:1", &policy(true)),
      vec!["localhost:5000/a:1"]
    );
    assert_eq!(
      pull_candidates("nginx@sha256:abc", &policy(false)),
      vec!["nginx@sha256:abc"]
    );
  }

  #[test]
  fn digest_matches_repo() {
    assert_eq!(
      pick_digest(
        "traefik/whoami:latest",
        "docker.1ms.run/traefik/whoami@sha256:1,traefik/whoami@sha256:2"
      )
      .as_deref(),
      Some("traefik/whoami@sha256:2")
    );
  }

  #[test]
  fn ps_groups_by_project() {
    let out = r#"{"Names":"whoami-whoami-1","State":"running","Status":"Up 2 minutes (healthy)","Image":"traefik/whoami","Labels":"com.docker.compose.project=whoami,com.docker.compose.project.working_dir=/opt/whoami,com.docker.compose.service=whoami"}
{"Names":"x","State":"exited","Status":"Exited (1)","Image":"a","Labels":"com.docker.compose.project=other,com.docker.compose.service=web"}
not json"#;
    let grouped = parse_ps(out);
    assert_eq!(grouped.len(), 2);
    let who = &grouped["whoami"][0];
    assert_eq!(who.service, "whoami");
    assert_eq!(who.health.as_deref(), Some("healthy"));
    assert_eq!(who.working_dir.as_deref(), Some("/opt/whoami"));
    assert_eq!(grouped["other"][0].state, "exited");
  }
}
