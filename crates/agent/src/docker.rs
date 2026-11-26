//! compose project 的读写。每个服务、每个网关都是一个 compose project，
//! 文件放在 `<data_dir>/projects/<project>/compose.yaml`。
//!
//! agent 跑在容器里时，`data_dir` 和 `/srv` 必须以相同路径挂载进来，
//! 这样 compose 里的相对路径、目录挂载在宿主机上解析结果一致。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::Duration,
};

use serde::Deserialize;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{ContainerInfo, ImageInfo, ProjectState, PullPolicy},
};

use tokio_util::sync::CancellationToken;

use crate::exec::{Cmd, Ctx};

pub const HASH_FILE: &str = ".wharf-hash";
pub const CONFIG_HASH_FILE: &str = ".wharf-config-hash";

/// 跟随日志的最长时长，到点后页面会自动重连。
const FOLLOW_MAX: Duration = Duration::from_secs(30 * 60);

pub struct Previous {
  pub compose: String,
  pub hash: String,
  /// 旧容器用的镜像：(compose 里写的镜像名, 镜像 ID)。只有一个镜像、一个容器时才有。
  pub image: Option<(String, String)>,
}

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
    let stopped: Vec<_> = projects
      .iter()
      .filter_map(|p| by_project.get(p))
      .flatten()
      .filter(|c| c.state != "running")
      .map(|c| c.name.as_str())
      .collect();
    let finished =
      crate::docker_observation::finished_at(self, &stopped, ctx)
        .await;
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
                finished_at: finished.get(&c.name).copied(),
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

  /// 这个项目现在唯一的容器用的镜像 ID；容器不是正好一个、或查不到时返回 None。
  pub async fn running_image(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Option<String> {
    let out = self
      .cmd()
      .args(["ps", "-aq", "--no-trunc", "--filter"])
      .arg(format!("label=com.docker.compose.project={project}"))
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await
      .ok()
      .filter(|o| o.success)?;
    let ids: Vec<_> = out.stdout.split_whitespace().collect();
    let [id] = ids.as_slice() else { return None };
    self
      .cmd()
      .args(["inspect", "--format", "{{.Image}}", *id])
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await
      .ok()
      .filter(|o| o.success)
      .map(|o| o.stdout.trim().to_string())
  }

  /// 本地的 `image` 是不是这个 digest（`sha256:…`）。
  pub async fn has_digest(
    &self,
    image: &str,
    digest: &str,
    ctx: &Ctx,
  ) -> bool {
    self
      .cmd()
      .args([
        "image",
        "inspect",
        "--format",
        "{{join .RepoDigests \",\"}}",
        image,
      ])
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await
      .is_ok_and(|o| {
        o.success
          && o
            .stdout
            .trim()
            .split(',')
            .any(|d| d.ends_with(&format!("@{digest}")))
      })
  }

  /// 拉一次镜像。docker 的逐层输出汇总成"已下载 a/n 层"写进日志，
  /// 再每分钟报一次已用时间，大镜像拉很久时也能看出还在进行。
  async fn pull_once(
    &self,
    candidate: &str,
    policy: &PullPolicy,
    timeout: Duration,
    ctx: &Ctx,
  ) -> Result<crate::exec::Output, ApiError> {
    let pull_ctx = layer_progress(ctx, policy);
    let ticker = {
      let ctx = ctx.clone();
      let done = CancellationToken::new();
      let stop = done.clone();
      let task = tokio::spawn(async move {
        let mut minutes = 0;
        loop {
          tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = stop.cancelled() => break,
          }
          minutes += 1;
          ctx.say(format!("仍在拉取，已用 {minutes} 分钟"));
        }
      });
      (done, task)
    };
    let result = self
      .cmd()
      .args(["pull", candidate])
      .timeout(timeout)
      .stream(true)
      .run(&pull_ctx)
      .await
      .and_then(|o| o.check(&format!("docker pull {candidate}")));
    ticker.0.cancel();
    let _ = ticker.1.await;
    result
  }

  /// 按计划固定的 digest 拉取（按镜像源顺序），再打回 `image` 这个标签，compose 不用改。
  pub async fn pull_pinned(
    &self,
    image: &str,
    digest: &str,
    policy: &PullPolicy,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let timeout =
      Duration::from_secs(policy.attempt_timeout_secs.max(10));
    let (registry, path, suffix) = split_image(image);
    let name = image.strip_suffix(suffix.as_str()).unwrap_or(image);
    let mut candidates: Vec<String> = policy
      .mirrors
      .get(&registry)
      .into_iter()
      .flatten()
      .map(|m| format!("{}/{path}@{digest}", m.trim_end_matches('/')))
      .collect();
    if candidates.is_empty() || !policy.mirrors_only {
      candidates.push(format!("{name}@{digest}"));
    }
    let mut errors = Vec::new();
    let mut rate = crate::external::RateLimit::None;
    for candidate in candidates {
      ctx.say(policy.redact(&format!("拉取 {candidate}")));
      let result =
        self.pull_once(&candidate, policy, timeout, ctx).await;
      match result {
        Ok(_) => {
          self
            .cmd()
            .args(["tag", &candidate, image])
            .timeout(Duration::from_secs(15))
            .run(ctx)
            .await?
            .check("docker tag")?;
          ctx.say(format!("已拉取 {image}（{digest}）"));
          return Ok(());
        }
        Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
        Err(e) => {
          rate = rate
            .max(crate::external::rate_limit(&candidate, &e.message));
          errors.push(policy.redact(&e.message));
        }
      }
    }
    Err(crate::external::image_error(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("拉取 {image}@{digest} 失败：{}", errors.join("；")),
      )
      .with_hint(
        "计划里固定的版本可能已经从仓库删除，重新 plan 会查最新版本",
      ),
      image,
      rate,
    ))
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
    let mut rate = crate::external::RateLimit::None;
    for candidate in pull_candidates(image, policy) {
      ctx.say(policy.redact(&format!("拉取 {candidate}")));
      let result =
        self.pull_once(&candidate, policy, timeout, ctx).await;
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
          rate = rate
            .max(crate::external::rate_limit(&candidate, &e.message));
          let message = policy.redact(&e.message);
          ctx.say(format!("失败：{message}"));
          errors
            .push(policy.redact(&format!("{candidate}：{message}")));
        }
      }
    }
    if self.image_exists(image, ctx).await {
      let warning = format!("{image} 拉取失败，使用本地已有的镜像");
      ctx.say(&warning);
      warnings.push(warning);
      return Ok(());
    }
    Err(crate::external::image_error(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("镜像 {image} 拉取失败：\n{}", errors.join("\n")),
      )
      .with_hint(
        "检查服务器的 registry_mirrors 设置，例如 wharf server set <server> --mirror docker.io=docker.1ms.run",
      ),
      image, rate,
    ))
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
    purge: bool,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let dir = self.project_dir(project);
    let cmd = if dir.join("compose.yaml").exists() {
      self.compose(project)
    } else {
      self.cmd().args(["compose", "-p", project])
    };
    let mut args = vec!["down", "--remove-orphans"];
    if purge {
      args.push("--volumes");
    }
    cmd
      .args(args)
      .timeout(Duration::from_secs(180))
      .stream(true)
      .run(ctx)
      .await?
      .check("docker compose down")?;
    if dir.exists() {
      std::fs::remove_dir_all(&dir).map_err(io_err(&dir))?;
    }
    if purge {
      crate::dirfd::remove_service(
        std::path::Path::new("/srv"),
        project,
      )?;
    }
    Ok(())
  }

  /// 当前部署的 compose 和指纹，部署新版本前留着，起不来时换回去。
  pub fn previous(&self, project: &str) -> Option<Previous> {
    let dir = self.project_dir(project);
    Some(Previous {
      compose: std::fs::read_to_string(dir.join("compose.yaml"))
        .ok()?,
      hash: std::fs::read_to_string(dir.join(HASH_FILE))
        .ok()?
        .trim()
        .to_string(),
      image: None,
    })
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
    since: Option<&str>,
    ctx: &Ctx,
  ) -> Result<String, ApiError> {
    let mut args = vec![
      "logs".to_string(),
      "--no-color".into(),
      "--timestamps".into(),
      "--tail".into(),
      tail.min(5000).to_string(),
    ];
    if let Some(since) = since {
      args.push(format!("--since={since}"));
    }
    let out = self
      .compose(project)
      .args(args)
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("docker compose logs")?;
    // compose 把日志写到 stdout，部分版本的提示写到 stderr。
    Ok(out.stdout)
  }

  /// `docker logs <容器>`：容器的标准输出和标准错误分开返回，这里按时间合在一起。
  /// 容器不在这台机器上时报 NotFound。
  pub async fn container_logs(
    &self,
    container: &str,
    tail: u32,
    since: Option<&str>,
    ctx: &Ctx,
  ) -> Result<String, ApiError> {
    let mut args = vec![
      "logs".to_string(),
      "--timestamps".into(),
      "--tail".into(),
      tail.min(5000).to_string(),
    ];
    if let Some(since) = since {
      args.push(format!("--since={since}"));
    }
    args.push(container.to_string());
    let out = self
      .cmd()
      .args(args)
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?;
    if !out.success && out.stderr.contains("No such container") {
      return Err(ApiError::not_found(format!(
        "这台机器上没有容器 {container}"
      )));
    }
    let out = out.check("docker logs")?;
    // Wharf 自己的日志带终端颜色，去掉再给人和 AI 看。
    Ok(strip_ansi(&merge_by_time(&out.stdout, &out.stderr)))
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

mod output;
pub(crate) use output::split_image;
use output::{
  layer_progress, merge_by_time, pick_digest, read_trimmed,
  strip_ansi,
};
pub use output::{parse_ps, pull_candidates};

#[cfg(test)]
mod tests;
