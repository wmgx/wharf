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
  agent::{
    ContainerInfo, ImageInfo, InitRun, ProjectState, ProjectUpResult,
    PullPolicy,
  },
  compose::parse_compose_max_grace_secs,
};

use tokio_util::sync::CancellationToken;

use crate::exec::{Cmd, Ctx};

fn stop_timeout(grace: u64) -> Duration {
  Duration::from_secs(180.max(grace + 60))
}

pub const HASH_FILE: &str = ".wharf-hash";
pub const CONFIG_HASH_FILE: &str = ".wharf-config-hash";

/// 跟随日志的最长时长，到点后页面会自动重连。
const FOLLOW_MAX: Duration = Duration::from_secs(30 * 60);

pub struct Previous {
  pub compose: String,
  pub hash: String,
  pub project_env: Option<String>,
  /// 旧容器用的镜像：compose 里写的镜像名和当时的镜像 ID。
  pub images: BTreeMap<String, String>,
}

struct TempCompose(PathBuf);

impl Drop for TempCompose {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.0);
  }
}

fn parse_running_images(
  lines: &str,
  known: &[String],
) -> BTreeMap<String, String> {
  fn with_implicit_tag(image: &str) -> &str {
    image.strip_suffix(":latest").unwrap_or(image)
  }
  lines
    .lines()
    .filter_map(|line| {
      let (image, id) = line.split_once('|')?;
      let (image, id) = (image.trim(), id.trim());
      if image.is_empty()
        || id.is_empty()
        || image.contains('@')
        || image.starts_with("sha256:")
      {
        return None;
      }
      let name =
        known.iter().find(|i| i.as_str() == image).or_else(|| {
          known.iter().find(|i| {
            with_implicit_tag(i) == with_implicit_tag(image)
          })
        });
      let image = match name {
        Some(name) => name.as_str(),
        None if known.is_empty() => image,
        None => return None,
      };
      Some((image.to_string(), id.to_string()))
    })
    .collect()
}

#[derive(Clone)]
pub struct Docker {
  pub bin: String,
  pub data_dir: PathBuf,
}

#[cfg(test)]
pub(crate) fn fake_docker(
  script: &str,
) -> (tempfile::TempDir, Docker) {
  use std::os::unix::fs::PermissionsExt;

  let dir = tempfile::tempdir().unwrap();
  let bin = dir.path().join("docker");
  std::fs::write(
    &bin,
    format!(
      "#!/bin/sh\ncd -- \"$(dirname -- \"$0\")\" || exit 1\n{script}"
    ),
  )
  .unwrap();
  std::fs::set_permissions(
    &bin,
    std::fs::Permissions::from_mode(0o700),
  )
  .unwrap();
  let docker = Docker {
    bin: bin.display().to_string(),
    data_dir: dir.path().into(),
  };
  (dir, docker)
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
    let env = self.project_env_path(project);
    self.compose_file(
      project,
      &dir,
      &dir.join("compose.yaml"),
      env.is_file().then_some(&env),
    )
  }

  fn compose_file(
    &self,
    project: &str,
    dir: &Path,
    file: &Path,
    env: Option<&Path>,
  ) -> Cmd {
    let mut cmd = self.cmd().args(["compose", "-p", project]);
    if let Some(env) = env {
      cmd = cmd
        .arg("--env-file")
        .arg(env.display().to_string())
        .clear_env();
      for key in ["PATH", "HOME", "DOCKER_CONFIG", "XDG_CONFIG_HOME"]
      {
        if let Ok(value) = std::env::var(key) {
          cmd = cmd.env(key, &value);
        }
      }
    }
    cmd.arg("-f").arg(file.display().to_string()).cwd(dir)
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
    include_links: bool,
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
    let mut projects = projects.to_vec();
    if include_links {
      let discovered: Vec<_> = by_project
        .iter()
        .filter(|&(name, containers)| {
          (name == "wharf-link" || name.starts_with("wharf-link-"))
            && wharf_api_types::validate_name("project", name).is_ok()
            && !projects.contains(name)
            && containers.iter().any(|c| {
              c.working_dir.as_deref().is_some_and(|dir| {
                Path::new(dir) == self.project_dir(name)
              })
            })
        })
        .map(|(name, _)| name.clone())
        .collect();
      projects.extend(discovered);
    }
    let stopped: Vec<_> = projects
      .iter()
      .filter_map(|p| by_project.get(p))
      .flatten()
      .filter(|c| c.state != "running")
      .map(|c| c.name.as_str())
      .collect();
    let finished =
      crate::docker_observation::inspect_stopped(self, &stopped, ctx)
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
            acme_dns_url_hash: project
              .starts_with("wharf-gw-")
              .then(|| {
                std::fs::read_to_string(
                  dir.join("conf").join("Caddyfile"),
                )
                .ok()
              })
              .flatten()
              .as_deref()
              .and_then(acme_dns_url_hash),
            frpc_admin_port: if project.starts_with("wharf-link-") {
              std::fs::read_to_string(
                dir.join("conf").join("frpc.toml"),
              )
              .ok()
              .and_then(|config| {
                config.lines().find_map(|line| {
                  line.strip_prefix("webServer.port = ")?.parse().ok()
                })
              })
            } else {
              None
            },
            containers: by_project
              .remove(project)
              .unwrap_or_default()
              .into_iter()
              .map(|c| ContainerInfo {
                foreign: c
                  .working_dir
                  .as_deref()
                  .is_some_and(|w| Path::new(w) != dir),
                finished_at: finished
                  .get(&c.name)
                  .and_then(|o| o.finished_at),
                exit_code: finished
                  .get(&c.name)
                  .and_then(|o| o.exit_code),
                restart_policy: finished
                  .get(&c.name)
                  .and_then(|o| o.restart_policy.clone()),
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
    let mut all =
      self.status(&[project.to_string()], false, ctx).await?;
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

  fn project_env_path(&self, project: &str) -> PathBuf {
    self
      .data_dir
      .join("project-env")
      .join(format!("{project}.env"))
  }

  pub(crate) fn read_project_env(
    &self,
    project: &str,
  ) -> Result<Option<String>, ApiError> {
    let env = self.project_env_path(project);
    match std::fs::read_to_string(&env) {
      Ok(value) => Ok(Some(value)),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        Ok(None)
      }
      Err(error) => Err(io_err(&env)(error)),
    }
  }

  pub(crate) fn write_project_env(
    &self,
    project: &str,
    content: Option<&str>,
  ) -> Result<(), ApiError> {
    let env = self.project_env_path(project);
    if let Some(content) = content {
      let dir = env.parent().expect("项目变量目录");
      use std::os::unix::fs::DirBuilderExt;
      std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_err(dir))?;
      return write_private(&env, content);
    }
    match std::fs::remove_file(&env) {
      Ok(()) => Ok(()),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        Ok(())
      }
      Err(error) => Err(io_err(&env)(error)),
    }
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
    self.compose_images(self.compose(project), ctx).await
  }

  pub async fn images_for_compose(
    &self,
    project: &str,
    compose: &str,
    env: Option<&str>,
    ctx: &Ctx,
  ) -> Result<Vec<String>, ApiError> {
    let dir = self.project_dir(project);
    std::fs::create_dir_all(&dir).map_err(io_err(&dir))?;
    let pending = TempCompose(dir.join("compose.yaml.next"));
    write_private(&pending.0, compose)?;
    let pending_env = env
      .map(|content| {
        let dir = tempfile::tempdir().map_err(|_| {
          ApiError::internal("无法建立私有 Compose 校验目录")
        })?;
        write_private(&dir.path().join("project.env"), content)?;
        Ok::<_, ApiError>(dir)
      })
      .transpose()?;
    let env = pending_env
      .as_ref()
      .map(|dir| dir.path().join("project.env"));
    let cmd =
      self.compose_file(project, &dir, &pending.0, env.as_deref());
    match self.compose_images(cmd, ctx).await {
      Err(error)
        if env.is_some() && error.code == ErrorCode::AgentFailed =>
      {
        Err(
          ApiError::invalid("Compose 项目变量校验失败")
            .with_hint("检查已声明的环境变量及表达式"),
        )
      }
      result => result,
    }
  }

  pub(crate) async fn check_project_env(
    &self,
    project: &str,
    compose: &str,
    inputs: &BTreeMap<String, String>,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    use wharf_api_types::compose::{parse_compose, project_env_keys};
    let keys = project_env_keys(&parse_compose(compose)?)?;
    let temp = tempfile::Builder::new()
      .prefix("wharf-compose-check-")
      .tempdir()
      .map_err(|_| {
        ApiError::internal("无法建立私有 Compose 校验目录")
      })?;
    let file = temp.path().join("compose.yaml");
    let env = temp.path().join("project.env");
    write_private(&file, compose)?;
    write_private(&env, &dotenv(inputs)?)?;
    let quiet = Ctx {
      progress: None,
      cancel: ctx.cancel.clone(),
    };
    let result = self
      .compose_file(project, temp.path(), &file, Some(&env))
      .args(["config", "--quiet"])
      .timeout(Duration::from_secs(25))
      .run(&quiet)
      .await?;
    if !result.success {
      if let Some(key) = keys
        .iter()
        .filter(|key| !inputs.contains_key(*key))
        .find(|key| {
          result.stderr.contains(&format!("required variable {key} "))
        })
      {
        return Err(
          ApiError::invalid(format!(
            "服务 {project} 的 Compose 插值缺少 {key}"
          ))
          .with_hint(format!("补上 --add-env {key}=...")),
        );
      }
      return Err(
        ApiError::invalid(format!(
          "服务 {project} 的 Compose 项目变量校验失败"
        ))
        .with_hint("检查 environment 中的变量表达式及必填项"),
      );
    }
    Ok(())
  }

  async fn compose_images(
    &self,
    cmd: Cmd,
    ctx: &Ctx,
  ) -> Result<Vec<String>, ApiError> {
    let out = cmd
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

  pub async fn image_label(
    &self,
    image: &str,
    ctx: &Ctx,
  ) -> Option<String> {
    let out = self
      .cmd()
      .args([
        "image",
        "inspect",
        "--format",
        r#"{{index .Config.Labels "wharf.commit"}}"#,
        image,
      ])
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await
      .ok()?;
    let label = out.stdout.trim();
    (out.success && !label.is_empty() && label != "<no value>")
      .then(|| label.to_string())
  }

  pub async fn project_mounts(
    &self,
    projects: &[String],
    running_only: bool,
    ctx: &Ctx,
  ) -> Result<
    std::collections::BTreeMap<
      String,
      Vec<wharf_api_types::agent::ContainerMount>,
    >,
    ApiError,
  > {
    let mut mounts = std::collections::BTreeMap::new();
    if projects.is_empty() {
      return Ok(mounts);
    }
    let mut command = self.cmd().arg("ps");
    if !running_only {
      command = command.arg("-a");
    }
    let listed = command
      .args([
        "--no-trunc",
        "--filter",
        "label=com.docker.compose.project",
        "--format",
        r#"{{.ID}}	{{.Label "com.docker.compose.project"}}"#,
      ])
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await?
      .check("docker ps")?;
    let ids: Vec<_> = listed
      .stdout
      .lines()
      .filter_map(|line| {
        let (id, project) = line.split_once('\t')?;
        projects.iter().any(|p| p == project).then_some(id)
      })
      .collect();
    if ids.is_empty() {
      return Ok(mounts);
    }
    let out = self
      .cmd()
      .arg("inspect")
      .args(ids)
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await?
      .check("docker inspect")?;
    let containers: Vec<serde_json::Value> =
      serde_json::from_str(&out.stdout)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    for container in &containers {
      let Some(project) = container
        .pointer("/Config/Labels/com.docker.compose.project")
        .and_then(serde_json::Value::as_str)
      else {
        continue;
      };
      if projects.iter().any(|p| p == project) {
        mounts
          .entry(project.to_string())
          .or_insert_with(Vec::new)
          .extend(parse_project_mounts(container));
      }
    }
    Ok(mounts)
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

  pub async fn running_images(
    &self,
    project: &str,
    known: &[String],
    ctx: &Ctx,
  ) -> Result<BTreeMap<String, String>, ApiError> {
    let out = self
      .cmd()
      .args(["ps", "-aq", "--no-trunc", "--filter"])
      .arg(format!("label=com.docker.compose.project={project}"))
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await?
      .check("docker ps")?;
    let mut ids = out.stdout.split_whitespace().peekable();
    if ids.peek().is_none() {
      return Ok(BTreeMap::new());
    }
    let out = self
      .cmd()
      .args([
        "inspect",
        "--format",
        "{{.Config.Image}}|{{.Image}}",
        "--",
      ])
      .args(ids)
      .timeout(Duration::from_secs(15))
      .run(ctx)
      .await?
      .check("docker inspect")?;
    Ok(parse_running_images(&out.stdout, known))
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
          if candidate != image && !image.contains('@') {
            self
              .cmd()
              .args(["tag", &candidate, image])
              .timeout(Duration::from_secs(15))
              .run(ctx)
              .await
              .and_then(|out| out.check("docker tag"))
              .map_err(|error| redact_pull_error(policy, error))?;
          }
          if candidate != format!("{name}@{digest}") {
            let _ = self
              .cmd()
              .args(["image", "rm", &candidate])
              .timeout(Duration::from_secs(15))
              .run(ctx)
              .await;
          }
          ctx.say(format!("已拉取 {image}（{digest}）"));
          return Ok(());
        }
        Err(e) if e.code == ErrorCode::Cancelled => {
          return Err(redact_pull_error(policy, e));
        }
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
              .await
              .and_then(|out| out.check("docker tag"))
              .map_err(|error| redact_pull_error(policy, error))?;
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
        Err(e) if e.code == ErrorCode::Cancelled => {
          return Err(redact_pull_error(policy, e));
        }
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

  pub(crate) fn read_compose(
    &self,
    project: &str,
  ) -> std::io::Result<Option<String>> {
    let path = self.project_dir(project).join("compose.yaml");
    match std::fs::read_to_string(path) {
      Ok(text) => Ok(Some(text)),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
      Err(e) => Err(e),
    }
  }

  fn grace_secs(&self, project: &str) -> u64 {
    self
      .read_compose(project)
      .ok()
      .flatten()
      .as_deref()
      .map_or(10, parse_compose_max_grace_secs)
  }

  pub async fn run_init(
    &self,
    project: &str,
    init: &InitRun,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let secs =
      u64::from(init.timeout_secs.unwrap_or(300).clamp(10, 1800));
    let suffix = format!(
      "-{}-{}",
      chrono::Utc::now().timestamp_millis(),
      std::process::id()
    );
    let name: String = project
      .chars()
      .filter(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
      })
      .take(63 - "wharf-init-".len() - suffix.len())
      .collect();
    let cname = format!("wharf-init-{name}{suffix}");
    ctx.say("运行部署前初始化");
    let result = self
      .compose(project)
      .args([
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--pull",
        "never",
        "--name",
        &cname,
        "--label",
        "wharf.temp=1",
        "--label",
        &format!("wharf.init={project}"),
        "--entrypoint",
        "sh",
        "--",
        &init.service,
        "-c",
        &init.command,
      ])
      .timeout(Duration::from_secs(secs))
      .stream(true)
      .run(ctx)
      .await;
    let error = match result {
      Ok(output) if output.success => return Ok(()),
      Ok(output) => {
        let code = output.code.map_or_else(|| "未知".into(), |code| code.to_string());
        let tail = crate::exec::tail_lines(
          if output.stderr.trim().is_empty() { &output.stdout } else { &output.stderr }, 15);
        ApiError::new(ErrorCode::AgentFailed, format!("部署前初始化命令失败（退出码 {code}），已中止部署，原容器未动：{tail}"))
          .with_hint("修好初始化命令后重新部署；完整输出见 wharf run logs")
      }
      Err(e) if e.code == ErrorCode::Timeout => ApiError::new(ErrorCode::Timeout,
        format!("部署前初始化命令超过 {secs} 秒未完成，原容器未动"))
          .with_hint("排查命令是否卡住，或用 --init-timeout 调大上限；完整日志见 wharf run logs"),
      Err(e) => e,
    };
    let cleanup = self
      .cmd()
      .args(["rm", "-f", &cname])
      .timeout(Duration::from_secs(15))
      .run(&Ctx::detached())
      .await;
    if !cleanup.is_ok_and(|out| {
      out.success
        || out.stderr.contains("No such container")
        || out.stderr.lines().any(|line| {
          line.contains("removal of container ")
            && line.trim_end().ends_with(" is already in progress")
        })
    }) {
      ctx.say(format!("清理初始化容器 {cname} 失败，需要手动处理"));
    }
    Err(error)
  }

  pub async fn up(
    &self,
    project: &str,
    no_start: bool,
    previous_grace: u64,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let mode = if no_start { "--no-start" } else { "-d" };
    ctx.say(if no_start {
      "创建容器（保持停止）"
    } else {
      "启动容器"
    });
    self
      .compose(project)
      .args(["up", mode, "--remove-orphans", "--pull", "never"])
      .timeout(Duration::from_secs(
        300.max(self.grace_secs(project).max(previous_grace) + 120),
      ))
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
    self.down_with_options(project, purge, purge, ctx).await
  }

  pub async fn down_trial(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    if !project
      .starts_with(wharf_api_types::agent::TRIAL_PROJECT_PREFIX)
    {
      return Err(ApiError::invalid(format!(
        "非试跑项目禁止调用试跑清理：{project}"
      )));
    }
    self.down_with_options(project, true, false, ctx).await
  }

  async fn down_with_options(
    &self,
    project: &str,
    remove_volumes: bool,
    remove_srv_data: bool,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let dir = self.project_dir(project);
    let cmd = if dir.join("compose.yaml").exists() {
      self.compose(project)
    } else {
      self.cmd().args(["compose", "-p", project])
    };
    let mut args = vec!["down", "--remove-orphans"];
    if remove_volumes {
      args.push("--volumes");
    }
    cmd
      .args(args)
      .timeout(stop_timeout(self.grace_secs(project)))
      .stream(true)
      .run(ctx)
      .await?
      .check("docker compose down")?;
    self.write_project_env(project, None)?;
    if remove_srv_data {
      let path = Path::new("/srv").join(project);
      let users = self.bind_mount_users(&path, ctx).await?;
      if let Err(e) = check_purge_mounts(project, &users) {
        ctx.say(e.message.clone());
        let _ = clean_project_dir(&dir);
        return Err(e);
      }
      crate::dirfd::remove_service(Path::new("/srv"), project, ctx)
        .await?;
    }
    if !clean_project_dir(&dir)? {
      ctx.say(format!(
        "项目目录 {} 里还有非 Wharf 创建的文件，已保留",
        dir.display()
      ));
    }
    Ok(())
  }

  pub async fn bind_mount_users(
    &self,
    target: &Path,
    ctx: &Ctx,
  ) -> Result<Vec<String>, ApiError> {
    let mounts =
      self.inspect_container_mounts(true, false, ctx).await?;
    Ok(containers_using_path(target, &mounts))
  }

  pub async fn inspect_bind_mount_users(
    &self,
    query: &wharf_api_types::agent::BindMountQuery,
    ctx: &Ctx,
  ) -> Result<Vec<wharf_api_types::agent::BindMountUser>, ApiError>
  {
    self.mount_users(query, false, ctx).await
  }

  pub(crate) async fn mount_users(
    &self,
    query: &wharf_api_types::agent::BindMountQuery,
    include_volumes: bool,
    ctx: &Ctx,
  ) -> Result<Vec<wharf_api_types::agent::BindMountUser>, ApiError>
  {
    let mounts = self
      .inspect_container_mounts(
        !query.running_only,
        include_volumes,
        ctx,
      )
      .await?;
    Ok(
      mount_users(
        &[PathBuf::from(&query.path)],
        query.writable_only,
        mounts.into_iter().filter(|m| {
          m.project
            .as_ref()
            .is_none_or(|p| !query.exclude_projects.contains(p))
        }),
      )
      .collect(),
    )
  }

  pub async fn bind_mount_active_users(
    &self,
    targets: &[PathBuf],
    project: &str,
    writable_only: bool,
    ctx: &Ctx,
  ) -> Result<Vec<wharf_api_types::agent::BindMountUser>, ApiError>
  {
    let mounts =
      self.inspect_container_mounts(false, false, ctx).await?;
    Ok(active_mount_users(targets, project, writable_only, mounts))
  }

  async fn inspect_container_mounts(
    &self,
    all: bool,
    include_volumes: bool,
    ctx: &Ctx,
  ) -> Result<Vec<wharf_api_types::agent::BindMountUser>, ApiError>
  {
    let timeout = Duration::from_secs(30);
    let out = self
      .cmd()
      .args(["ps", if all { "-aq" } else { "-q" }])
      .timeout(timeout)
      .run(ctx)
      .await?
      .check("docker ps")?;
    let ids: Vec<_> = out.stdout.split_whitespace().collect();
    if ids.is_empty() {
      return Ok(Vec::new());
    }
    let out = self
      .cmd()
      .args([
        "inspect",
        "--format",
        r#"{{json .Name}} {{json (index .Config.Labels "wharf.system")}} {{json (index .Config.Labels "com.docker.compose.project")}} {{json .Mounts}}"#,
      ])
      .args(ids.iter().copied())
      .timeout(timeout)
      .run(ctx)
      .await?
      .check("docker inspect")?;
    if out.stdout.lines().count() != ids.len() {
      return Err(ApiError::internal(
        "Docker 返回的容器挂载信息不完整",
      ));
    }
    parse_bind_mounts(&out.stdout, include_volumes)
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
      images: BTreeMap::new(),
      project_env: self.read_project_env(project).ok()?,
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

  async fn active_project_containers(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<Vec<(String, String)>, ApiError> {
    let out = self
      .cmd()
      .args([
        "ps",
        "-a",
        "--no-trunc",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
        "--format",
        "{{.Names}} {{.State}}",
      ])
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?
      .check("docker ps")?;
    let mut active = Vec::new();
    for line in out.stdout.lines() {
      let (name, state) = line.split_once(' ').ok_or_else(|| {
        ApiError::internal("Docker 返回的容器状态无效")
      })?;
      if matches!(state, "running" | "paused" | "restarting") {
        active.push((name.to_string(), state.to_string()));
      }
    }
    Ok(active)
  }

  fn missing_compose(
    project: &str,
    active: &[(String, String)],
  ) -> ApiError {
    let names = active
      .iter()
      .map(|(name, _)| name.as_str())
      .collect::<Vec<_>>()
      .join("、");
    ApiError::new(ErrorCode::Conflict, format!("{project} 缺少 compose.yaml，仍有活动容器：{names}"))
      .with_hint(format!("先用 wharf service deploy {project} 重建配置，或手动停止这些容器后重试"))
  }

  pub async fn stop_running_for_data(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<wharf_api_types::agent::StoppedContainers, ApiError> {
    let active = self.active_project_containers(project, ctx).await?;
    let containers: Vec<_> =
      active.iter().map(|(name, _)| name.clone()).collect();
    if containers.is_empty() {
      return Ok(wharf_api_types::agent::StoppedContainers {
        containers,
      });
    }
    if !self.project_dir(project).join("compose.yaml").exists() {
      return Err(Self::missing_compose(project, &active));
    }
    let stopped = async {
      self.stop_start(project, false, ctx).await?;
      if !self
        .active_project_containers(project, ctx)
        .await?
        .is_empty()
      {
        return Err(ApiError::new(
          ErrorCode::Conflict,
          format!("{project} 仍有活动容器，无法安全操作数据"),
        ));
      }
      Ok(())
    }
    .await;
    if let Err(e) = stopped {
      let detached = Ctx::detached();
      let restarted = async {
        let remaining =
          self.active_project_containers(project, &detached).await?;
        let stopped: Vec<_> = containers
          .iter()
          .filter(|name| {
            !remaining.iter().any(|(live, _)| live == *name)
          })
          .cloned()
          .collect();
        self.start_containers(project, &stopped, &detached).await
      }
      .await;
      return Err(match restarted {
        Ok(()) => e,
        Err(err) => {
          e.with_hint(format!("回拉已停止的容器失败：{err}"))
        }
      });
    }
    Ok(wharf_api_types::agent::StoppedContainers { containers })
  }

  pub async fn start_containers(
    &self,
    project: &str,
    containers: &[String],
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    if containers.is_empty() {
      return Ok(());
    }
    if containers.iter().any(|name| {
      name.is_empty()
        || name.starts_with('-')
        || !name.bytes().all(|b| {
          b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
        })
    }) {
      return Err(ApiError::invalid("容器名无效"));
    }
    self
      .cmd()
      .args(["start", "--"])
      .args(containers.iter().map(String::as_str))
      .timeout(Duration::from_secs(180))
      .run(ctx)
      .await?
      .check("docker start")?;
    let active = self.active_project_containers(project, ctx).await?;
    if containers.iter().any(|name| {
      !active
        .iter()
        .any(|(live, state)| live == name && state == "running")
    }) {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        format!("{project} 有容器未回到运行状态"),
      ));
    }
    Ok(())
  }

  pub async fn restart(
    &self,
    project: &str,
    container: Option<&str>,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    let args = container_args(container)?;
    self
      .compose(project)
      .arg("restart")
      .args(args)
      .timeout(stop_timeout(self.grace_secs(project)))
      .stream(true)
      .run(ctx)
      .await?
      .check("docker compose restart")?;
    let containers = self.one_status(project, ctx).await?.containers;
    let images = containers
      .iter()
      .map(|c| c.image.clone())
      .collect::<std::collections::BTreeSet<_>>()
      .into_iter()
      .collect::<Vec<_>>();
    Ok(ProjectUpResult {
      images: self.image_info(&images, ctx).await,
      containers,
      warnings: vec![],
      retired: vec![],
    })
  }

  /// `stop` 或 `start`。project 没部署过时什么也不做。
  pub async fn stop_start(
    &self,
    project: &str,
    start: bool,
    ctx: &Ctx,
  ) -> Result<bool, ApiError> {
    if !self.project_dir(project).join("compose.yaml").exists() {
      if !start {
        let active =
          self.active_project_containers(project, ctx).await?;
        if !active.is_empty() {
          return Err(Self::missing_compose(project, &active));
        }
      }
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
      .timeout(if start {
        Duration::from_secs(180)
      } else {
        stop_timeout(self.grace_secs(project))
      })
      .stream(true)
      .run(ctx)
      .await?
      .check(&format!("docker compose {action}"))?;
    if !start {
      self.verify_project_stopped(project, ctx).await?;
    }
    Ok(true)
  }

  async fn verify_project_stopped(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let active = |state: ProjectState| {
      state
        .containers
        .into_iter()
        .filter(|c| !c.foreign && c.is_active())
        .collect::<Vec<_>>()
    };
    let remaining = active(self.one_status(project, ctx).await?);
    if remaining.is_empty() {
      return Ok(());
    }
    self
      .cmd()
      .args(["stop", "-t", "15", "--"])
      .args(remaining.iter().map(|c| c.name.as_str()))
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await?;
    let remaining = active(self.one_status(project, ctx).await?);
    if remaining.is_empty() {
      return Ok(());
    }
    let names = remaining
      .iter()
      .map(|c| format!("{}({})", c.name, c.state))
      .collect::<Vec<_>>()
      .join("、");
    Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{project} 停止后仍有容器未退出：{names}"),
      )
      .suggest("检查宿主机 Docker 状态或重试停止"),
    )
  }

  pub async fn logs(
    &self,
    project: &str,
    tail: u32,
    since: Option<&str>,
    container: Option<&str>,
    until: Option<&str>,
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
    if let Some(until) = until {
      args.push(format!("--until={until}"));
    }
    let out = self
      .compose(project)
      .args(args)
      .args(container_args(container)?)
      .timeout(Duration::from_secs(30))
      .run(ctx)
      .await?;
    if let Some(c) = container
      && !out.success
      && out.stderr.contains("no such service")
    {
      return Err(ApiError::not_found(format!(
        "服务 {project} 里没有子容器 {c}"
      )));
    }
    let out = out.check("docker compose logs")?;
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
    until: Option<&str>,
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
    if let Some(until) = until {
      args.push(format!("--until={until}"));
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
  pub async fn follow_logs(
    &self,
    project: &str,
    tail: u32,
    container: Option<&str>,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
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
      .args(container_args(container)?)
      .timeout(FOLLOW_MAX)
      .stream(true)
      .run(ctx)
      .await;
    if let Some(c) = container
      && let Ok(out) = &result
      && !out.success
      && out.stderr.contains("no such service")
    {
      return Err(ApiError::not_found(format!(
        "服务 {project} 里没有子容器 {c}"
      )));
    }
    if let Err(e) = result
      && !ctx.cancel.is_cancelled()
    {
      ctx.say(format!("日志流结束：{}", e.message));
    }
    Ok(())
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

pub(crate) fn clean_project_dir(
  dir: &Path,
) -> Result<bool, ApiError> {
  use std::{fs, io::ErrorKind};

  fn remove_files(
    dir: &Path,
    names: &[&str],
  ) -> Result<(), ApiError> {
    for name in names {
      let path = dir.join(name);
      match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {
          fs::remove_file(&path).map_err(io_err(&path))?;
        }
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&path)(e)),
      }
    }
    Ok(())
  }

  fn remove_empty(dir: &Path) -> Result<bool, ApiError> {
    match fs::remove_dir(dir) {
      Ok(()) => Ok(true),
      Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
      Err(e) if e.kind() == ErrorKind::DirectoryNotEmpty => Ok(false),
      Err(e) => Err(io_err(dir)(e)),
    }
  }

  match fs::symlink_metadata(dir) {
    Ok(meta) if !meta.is_dir() => return Ok(false),
    Ok(_) => {}
    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(true),
    Err(e) => return Err(io_err(dir)(e)),
  }
  if dir.join(crate::live_limits::JOURNAL).exists() {
    return Err(ApiError::new(
      ErrorCode::Busy,
      "项目仍有待恢复的限额更新",
    ));
  }
  remove_files(
    dir,
    &[
      "compose.yaml",
      "compose.yaml.tmp",
      "compose.yaml.next",
      HASH_FILE,
      ".wharf-hash.tmp",
      "compose.tmp",
    ],
  )?;
  // 只清理 Wharf 管理的网关和隧道配置。
  let name = dir
    .file_name()
    .and_then(|name| name.to_str())
    .unwrap_or_default();
  let files: &[&str] = if name.starts_with("wharf-gw-") {
    &[
      "Caddyfile",
      "Caddyfile.next",
      "Caddyfile.prev",
      "Caddyfile.tmp",
      "link.crt",
      "link.crt.prev",
      "link.crt.tmp",
      "link.key",
      "link.key.prev",
      "link.key.tmp",
      "link.tmp",
      CONFIG_HASH_FILE,
      ".wharf-config-hash.tmp",
    ]
  } else if name.starts_with("wharf-link-") {
    &[
      "frpc.toml",
      "frpc.toml.next",
      "frpc.toml.prev",
      "frpc.toml.tmp",
      "frpc.tmp",
      "ca.pem",
      "ca.pem.prev",
      "ca.pem.tmp",
      "ca.tmp",
      CONFIG_HASH_FILE,
      ".wharf-config-hash.tmp",
    ]
  } else {
    return remove_empty(dir);
  };
  let conf = dir.join("conf");
  match fs::symlink_metadata(&conf) {
    Ok(meta) if meta.is_dir() => {
      remove_files(&conf, files)?;
      remove_empty(&conf)?;
    }
    Ok(_) => {}
    Err(e) if e.kind() == ErrorKind::NotFound => {}
    Err(e) => return Err(io_err(&conf)(e)),
  }
  remove_empty(dir)
}

pub(crate) fn normalize_abs(path: &Path) -> Option<PathBuf> {
  use std::path::Component;
  if !path.is_absolute() {
    return None;
  }
  let mut result = PathBuf::new();
  for part in path.components() {
    match part {
      Component::ParentDir => {
        result.pop();
      }
      Component::CurDir => {}
      _ => result.push(part),
    }
  }
  Some(result)
}

fn paths_overlap(target: &Path, mount: &Path) -> bool {
  mount.starts_with(target) || target.starts_with(mount)
}

pub(crate) fn parse_bind_mounts(
  output: &str,
  include_volumes: bool,
) -> Result<Vec<wharf_api_types::agent::BindMountUser>, ApiError> {
  #[derive(Deserialize)]
  #[serde(rename_all = "PascalCase")]
  struct Mount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(default)]
    source: PathBuf,
    #[serde(default)]
    destination: PathBuf,
    #[serde(rename = "RW", default = "default_rw")]
    rw: bool,
  }
  fn default_rw() -> bool {
    true
  }

  let invalid =
    || ApiError::internal("Docker 返回的容器挂载信息无效");
  let mut users = Vec::new();
  for line in output.lines() {
    let mut fields =
      serde_json::Deserializer::from_str(line).into_iter::<String>();
    let mut field =
      || fields.next().ok_or_else(invalid)?.map_err(|_| invalid());
    let name = field()?;
    let role = field()?;
    let project = field()?;
    let system = matches!(role.as_str(), "agent" | "core" | "1");
    let mounts: Option<Vec<Mount>> =
      serde_json::from_str(&line[fields.byte_offset()..])
        .map_err(|_| invalid())?;
    for m in mounts.into_iter().flatten().filter(|m| {
      (m.kind == "bind" || (include_volumes && m.kind == "volume"))
        && !(system
          && m.source == Path::new("/srv")
          && m.destination == Path::new("/srv"))
    }) {
      if !m.source.is_absolute() {
        return Err(invalid());
      }
      users.push(wharf_api_types::agent::BindMountUser {
        container: name.trim_start_matches('/').to_string(),
        project: (!project.is_empty()).then(|| project.clone()),
        source: m.source.display().to_string(),
        rw: m.rw,
      });
    }
  }
  Ok(users)
}

fn mount_paths(path: &Path) -> impl Iterator<Item = PathBuf> {
  normalize_abs(path)
    .into_iter()
    .chain(std::fs::canonicalize(path).ok())
}

pub(crate) fn containers_using_path(
  target: &Path,
  mounts: &[wharf_api_types::agent::BindMountUser],
) -> Vec<String> {
  let targets: Vec<_> = mount_paths(target).collect();
  mounts
    .iter()
    .filter(|m| {
      mount_paths(Path::new(&m.source))
        .any(|p| targets.iter().any(|t| paths_overlap(t, &p)))
    })
    .map(|m| m.container.clone())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

fn active_mount_users(
  targets: &[PathBuf],
  project: &str,
  writable_only: bool,
  mounts: Vec<wharf_api_types::agent::BindMountUser>,
) -> Vec<wharf_api_types::agent::BindMountUser> {
  mount_users(
    targets,
    writable_only,
    mounts
      .into_iter()
      .filter(|m| m.project.as_deref() != Some(project)),
  )
  .collect()
}

fn mount_users(
  targets: &[PathBuf],
  writable_only: bool,
  mounts: impl Iterator<Item = wharf_api_types::agent::BindMountUser>,
) -> impl Iterator<Item = wharf_api_types::agent::BindMountUser> {
  let targets: Vec<_> =
    targets.iter().flat_map(|p| mount_paths(p)).collect();
  mounts.filter(move |m| {
    (!writable_only || m.rw)
      && mount_paths(Path::new(&m.source))
        .any(|p| targets.iter().any(|t| paths_overlap(t, &p)))
  })
}

fn check_purge_mounts(
  project: &str,
  users: &[String],
) -> Result<(), ApiError> {
  if users.is_empty() {
    return Ok(());
  }
  Err(ApiError::new(ErrorCode::Conflict, format!(
    "已删除 {project} 的容器，但拒绝删除 /srv/{project}：仍有容器挂载该目录（{}）",
    users.join("、"),
  )).with_hint("先停止并移除挂载该目录的容器，再重新执行删除或手动清理"))
}

#[test]
fn down_purge_refuses_delete_when_other_container_mounts_srv() {
  let inspect = r#""/reader" "" "reader" [{"Type":"bind","Source":"/srv/photos/originals","Destination":"/photos","RW":false}]"#;
  let mounts = parse_bind_mounts(inspect, false).unwrap();
  let users =
    containers_using_path(Path::new("/srv/photos"), &mounts);
  assert_eq!(users, ["reader"]);
  assert_eq!(
    check_purge_mounts("photos", &users).unwrap_err().code,
    ErrorCode::Conflict
  );
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

pub(crate) fn dotenv(
  values: &BTreeMap<String, String>,
) -> Result<String, ApiError> {
  let mut out = String::new();
  for (key, value) in values {
    if !wharf_api_types::compose::valid_project_env_key(key)
      || value.contains('\0')
    {
      return Err(ApiError::invalid(
        "Compose 项目变量键不合法或值含 NUL",
      ));
    }
    out.push_str(key);
    out.push_str("=\"");
    for ch in value.chars() {
      match ch {
        '$' => out.push_str("$$"),
        '\\' => out.push_str("\\\\"),
        '"' => out.push_str("\\\""),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ => out.push(ch),
      }
    }
    out.push_str("\"\n");
  }
  Ok(out)
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

fn acme_dns_url_hash(config: &str) -> Option<String> {
  use sha2::{Digest, Sha256};
  config.lines().find_map(|line| {
    line
      .strip_prefix("\t\t\tserver_url ")
      .filter(|url| url.ends_with("/agent/acme-dns"))
      .map(|url| hex::encode(Sha256::digest(url.as_bytes())))
  })
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
        finished_at: None,
        exit_code: None,
        restart_policy: None,
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
pub(crate) fn split_image(image: &str) -> (String, String, String) {
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

fn redact_pull_error(
  policy: &PullPolicy,
  mut error: ApiError,
) -> ApiError {
  error.message = policy.redact(&error.message);
  error.hint = error.hint.map(|hint| policy.redact(&hint));
  error
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
    .and_then(|d| {
      wharf_api_types::agent::normalize_image_digest(image, d)
    })
}

/// `docker pull` 非终端输出是逐层状态行，如 `0a1b2c3d4e5f: Download complete`。
/// 汇总成已下载、已解压的层数，只在数字变化时报一次。
#[derive(Default)]
struct Layers {
  seen: BTreeSet<String>,
  downloaded: BTreeSet<String>,
  extracted: BTreeSet<String>,
  last: (usize, usize, usize),
}

impl Layers {
  fn feed(&mut self, line: &str) -> Option<String> {
    let (id, status) = line.split_once(": ")?;
    let id = id.trim();
    if !(id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit()))
    {
      return id.eq("Status").then(|| status.trim().to_string());
    }
    self.seen.insert(id.to_string());
    let status = status.trim();
    if matches!(
      status,
      "Download complete" | "Already exists" | "Pull complete"
    ) {
      self.downloaded.insert(id.to_string());
    }
    if matches!(status, "Already exists" | "Pull complete") {
      self.extracted.insert(id.to_string());
    }
    let now =
      (self.seen.len(), self.downloaded.len(), self.extracted.len());
    let changed = (now.1, now.2) != (self.last.1, self.last.2);
    self.last = now;
    if !changed {
      return None;
    }
    Some(format!(
      "镜像层：已下载 {}/{}，已解压 {}/{}",
      now.1, now.0, now.2, now.0
    ))
  }
}

fn layer_progress(ctx: &Ctx, policy: &PullPolicy) -> Ctx {
  let Some(outer) = ctx.progress.clone() else {
    return ctx.clone();
  };
  let layers = Arc::new(Mutex::new(Layers::default()));
  let policy = policy.clone();
  Ctx {
    cancel: ctx.cancel.clone(),
    progress: Some(Arc::new(move |line: String| {
      let msg = layers.lock().ok().and_then(|mut l| l.feed(&line));
      if let Some(msg) = msg {
        outer(policy.redact(&msg));
      }
    })),
  }
}

/// `docker logs --timestamps` 的每行以 RFC 3339 时间开头，按它排序把两路输出合成一份。
/// 同一时间的行保持原来的先后。
fn merge_by_time(stdout: &str, stderr: &str) -> String {
  let mut lines: Vec<&str> =
    stdout.lines().chain(stderr.lines()).collect();
  lines.sort_by_key(|l| l.split_once(' ').map_or(*l, |(t, _)| t));
  let mut out = lines.join("\n");
  if !out.is_empty() {
    out.push('\n');
  }
  out
}

/// 去掉终端颜色之类的控制序列（`ESC [ ... 字母`）。
pub(crate) fn strip_ansi(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  let mut chars = text.chars();
  while let Some(c) = chars.next() {
    if c != '\x1b' {
      out.push(c);
      continue;
    }
    if chars.next() == Some('[') {
      for c in chars.by_ref() {
        if c.is_ascii_alphabetic() {
          break;
        }
      }
    }
  }
  out
}

fn container_args(
  container: Option<&str>,
) -> Result<Vec<&str>, ApiError> {
  match container {
    Some(c) => {
      wharf_api_types::validate_container_name(c)?;
      Ok(vec!["--", c])
    }
    None => Ok(vec![]),
  }
}

#[cfg(test)]
mod tests {
  #[tokio::test]
  async fn down_trial_removes_volumes_without_touching_srv() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("docker");
    let out = root.path().join("args");
    fs::write(
      &bin,
      format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
        out.display()
      ),
    )
    .unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700))
      .unwrap();
    let docker = super::Docker {
      bin: bin.to_string_lossy().into_owned(),
      data_dir: root.path().into(),
    };
    let ctx = crate::exec::Ctx::detached();
    assert!(docker.down_trial("app", &ctx).await.is_err());
    assert!(!out.exists());
    docker.down_trial("wharf-try-app", &ctx).await.unwrap();
    assert!(
      fs::read_to_string(out)
        .unwrap()
        .lines()
        .any(|arg| arg == "--volumes")
    );
  }

  #[test]
  fn clean_project_dir_preserves_relative_mount_data() {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    let service = root.path().join("app");
    fs::create_dir_all(service.join("data")).unwrap();
    fs::write(service.join("data/note.txt"), "keep").unwrap();
    for name in [
      "compose.yaml",
      ".wharf-hash",
      "compose.yaml.tmp",
      "compose.tmp",
    ] {
      fs::write(service.join(name), "").unwrap();
    }
    assert!(!super::clean_project_dir(&service).unwrap());
    assert_eq!(fs::read_dir(&service).unwrap().count(), 1);
    assert_eq!(
      fs::read_to_string(service.join("data/note.txt")).unwrap(),
      "keep"
    );
    let gateway = root.path().join("wharf-gw-test");
    fs::create_dir_all(gateway.join("conf")).unwrap();
    for name in ["Caddyfile", "link.crt"] {
      fs::write(gateway.join("conf").join(name), "").unwrap();
    }
    assert!(super::clean_project_dir(&gateway).unwrap());
    assert!(!gateway.exists());
    let empty = root.path().join("empty");
    fs::create_dir(&empty).unwrap();
    assert!(super::clean_project_dir(&empty).unwrap());
    assert!(!empty.exists());
  }

  #[test]
  fn containers_using_path_catches_exact_child_and_parent_mounts() {
    use std::path::Path;
    let inspect = r#""/indexer" "" "" [{"Type":"bind","Source":"/srv/photos/originals"}]
"/backup-tool" "" "" [{"Type":"bind","Source":"/srv","Destination":"/srv"}]
"/other" "" "" [{"Type":"bind","Source":"/srv/photos2"}]
"/exact" "" "" [{"Type":"bind","Source":"/srv/photos"}]"#;
    let containers =
      super::parse_bind_mounts(inspect, false).unwrap();
    assert_eq!(
      super::containers_using_path(
        Path::new("/srv/photos"),
        &containers
      ),
      ["backup-tool", "exact", "indexer"]
    );
  }

  #[test]
  fn bind_mount_active_users_distinguishes_rw_and_ro() {
    use std::path::PathBuf;
    let inspect = r#""/writer" "" "other" [{"Type":"bind","Source":"/srv/s1/data","RW":true}]
"/reader" "" "" [{"Type":"bind","Source":"/srv/s1/data","RW":false}]
"/wharf-agent" "agent" "" [{"Type":"bind","Source":"/srv","Destination":"/srv"}]
"/self" "" "s1" [{"Type":"bind","Source":"/srv/s1/data"}]"#;
    let mounts = super::parse_bind_mounts(inspect, false).unwrap();
    let paths = [PathBuf::from("/srv/s1")];
    let backup =
      super::active_mount_users(&paths, "s1", true, mounts.clone());
    assert_eq!(backup.len(), 1);
    assert_eq!(backup[0].container, "writer");
    let restore =
      super::active_mount_users(&paths, "s1", false, mounts);
    assert_eq!(restore.len(), 2);
    assert_eq!(restore[1].container, "reader");
  }

  #[tokio::test]
  async fn stop_for_data_rejects_running_containers_without_compose()
  {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("docker");
    use std::{fs, os::unix::fs::PermissionsExt};
    fs::write(&script, "#!/bin/sh\n[ \"$1\" = ps ] || exit 99\nprintf 'web running\ninit exited\n'\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
      .unwrap();
    let docker = super::Docker {
      bin: script.display().to_string(),
      data_dir: dir.path().into(),
    };
    let ctx = super::Ctx::detached();
    let error =
      docker.stop_running_for_data("s1", &ctx).await.unwrap_err();
    assert_eq!(error.code, wharf_api_types::ErrorCode::Conflict);
    assert!(
      error.message.contains("web")
        && !error.message.contains("init")
    );
    assert_eq!(
      docker.stop_start("s1", false, &ctx).await.unwrap_err().code,
      error.code
    );
  }

  #[tokio::test]
  async fn stop_for_data_skips_stopped_and_rolls_back_partial_stop() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("docker");
    let state = dir.path().join("state");
    fs::write(&script, r#"#!/bin/sh
state="$(dirname "$0")/state"
case "$1:$(cat "$state")" in
  ps:stopped) echo 'init exited' ;;
  ps:running|ps:restarted) printf 'web running\nworker running\ninit exited\n' ;;
  compose:running) echo partial > "$state"; exit 1 ;;
  ps:partial) printf 'web exited\nworker running\ninit exited\n' ;;
  start:partial) [ "$#" = 3 ] && [ "$2" = -- ] && [ "$3" = web ] || exit 8
                 echo restarted > "$state" ;;
  *) exit 9 ;;
esac
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
      .unwrap();
    let docker = super::Docker {
      bin: script.display().to_string(),
      data_dir: dir.path().into(),
    };
    let project = docker.project_dir("s1");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("compose.yaml"), "").unwrap();
    let ctx = super::Ctx::detached();
    fs::write(&state, "stopped").unwrap();
    assert!(
      docker
        .stop_running_for_data("s1", &ctx)
        .await
        .unwrap()
        .containers
        .is_empty()
    );
    fs::write(&state, "running").unwrap();
    assert!(docker.stop_running_for_data("s1", &ctx).await.is_err());
    assert_eq!(
      fs::read_to_string(&state).unwrap().trim(),
      "restarted"
    );
  }

  #[test]
  fn bind_mount_users_ignores_only_system_management_mounts() {
    let inspect = r#""/wharf-agent" "agent" "" [{"Type":"bind","Source":"/srv","Destination":"/srv"}]
"/wharf-agent-old" "1" "" [{"Type":"bind","Source":"/srv","Destination":"/srv"}]
"/wharf-core" "core" "" [{"Type":"bind","Source":"/srv","Destination":"/srv"}]
"/dedicated" "core" "" [{"Type":"bind","Source":"/srv/s1","Destination":"/data"}]"#;
    let containers =
      super::parse_bind_mounts(inspect, false).unwrap();
    assert_eq!(
      super::containers_using_path(
        std::path::Path::new("/srv/s1"),
        &containers
      ),
      ["dedicated"]
    );
  }

  #[test]
  fn clean_project_dir_removes_interrupted_link_write() {
    let root = tempfile::tempdir().unwrap();
    let gateway = root.path().join("wharf-gw-s1");
    let conf = gateway.join("conf");
    std::fs::create_dir_all(&conf).unwrap();
    std::fs::write(conf.join("link.tmp"), "interrupted").unwrap();
    assert!(super::clean_project_dir(&gateway).unwrap());
    assert!(!gateway.exists());
  }

  #[test]
  fn clean_project_dir_removes_managed_frpc_files() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("wharf-link-s1");
    let conf = link.join("conf");
    std::fs::create_dir_all(&conf).unwrap();
    for file in [
      "frpc.toml",
      "frpc.toml.next",
      "ca.pem",
      ".wharf-config-hash",
    ] {
      std::fs::write(conf.join(file), "fixture").unwrap();
    }
    assert!(super::clean_project_dir(&link).unwrap());
    assert!(!link.exists());
  }

  #[test]
  fn strips_colors() {
    assert_eq!(
      super::strip_ansi(
        "\x1b[2mT\x1b[0m \x1b[32m INFO\x1b[0m 已连接"
      ),
      "T  INFO 已连接"
    );
  }

  #[test]
  fn merges_logs_by_time() {
    let out = super::merge_by_time(
      "2026-11-22T01:00:02.000Z b\n2026-11-22T01:00:04.000Z d\n",
      "2026-11-22T01:00:01.000Z a\n2026-11-22T01:00:03.000Z c\n",
    );
    let order: Vec<&str> =
      out.lines().map(|l| l.rsplit(' ').next().unwrap()).collect();
    assert_eq!(order, ["a", "b", "c", "d"]);
  }

  #[test]
  fn layer_progress_reports_counts() {
    let mut l = super::Layers::default();
    assert_eq!(l.feed("latest: Pulling from remsky/kokoro"), None);
    assert_eq!(l.feed("0a1b2c3d4e5f: Pulling fs layer"), None);
    assert_eq!(
      l.feed("1a1b2c3d4e5f: Already exists").as_deref(),
      Some("镜像层：已下载 1/2，已解压 1/2")
    );
    assert_eq!(
      l.feed("0a1b2c3d4e5f: Download complete").as_deref(),
      Some("镜像层：已下载 2/2，已解压 1/2")
    );
    assert_eq!(l.feed("0a1b2c3d4e5f: Verifying Checksum"), None);
    assert_eq!(
      l.feed("Status: Downloaded newer image").as_deref(),
      Some("Downloaded newer image")
    );
  }

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
      git_proxy: None,
      github_mirror: None,
      registry_proxy: None,
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
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    assert_eq!(
      pick_digest(
        "traefik/whoami:latest",
        &format!(
          "docker.example.test/traefik/whoami@sha256:{a},traefik/whoami@sha256:{b}"
        )
      ),
      Some(format!("traefik/whoami@sha256:{b}"))
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

#[test]
fn digest_uses_original_repository() {
  let hash = "a".repeat(64);
  let raw = format!(
    "docker.example.test/tok_secret_123456/library/nginx@sha256:{hash}"
  );
  assert_eq!(
    pick_digest("nginx:1.27", &raw),
    Some(format!("nginx@sha256:{hash}"))
  );
}

fn parse_project_mounts(
  container: &serde_json::Value,
) -> Vec<wharf_api_types::agent::ContainerMount> {
  let name = container["Name"]
    .as_str()
    .unwrap_or_default()
    .trim_start_matches('/');
  let service = container
    .pointer("/Config/Labels/com.docker.compose.service")
    .and_then(serde_json::Value::as_str)
    .unwrap_or_default();
  container["Mounts"]
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(|mount| {
      let kind = mount["Type"].as_str()?;
      let source = match kind {
        "volume" => mount["Name"].as_str()?,
        "bind" => mount["Source"].as_str()?,
        _ => return None,
      };
      Some(wharf_api_types::agent::ContainerMount {
        container: name.into(),
        service: service.into(),
        kind: kind.into(),
        source: source.into(),
        target: mount["Destination"].as_str()?.into(),
      })
    })
    .collect()
}

#[cfg(test)]
#[tokio::test]
async fn init_cleanup_accepts_removal_in_progress() {
  let (_dir, docker) = fake_docker(
    r#"
case "$1:$6" in
  compose:run) exit 42;;
  rm:*)
    printf 'Error response from daemon: removal of container %s is already in progress\n' "$3" >&2
    exit 1;;
  *) exit 2;;
esac
"#,
  );
  let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
  let ctx = Ctx {
    progress: Some(std::sync::Arc::new(move |line| {
      tx.send(line).unwrap();
    })),
    ..Ctx::detached()
  };
  let init = InitRun {
    service: "app".into(),
    command: "exit 42".into(),
    timeout_secs: None,
  };
  docker
    .write_compose("app", "services: {app: {image: fixture}}")
    .unwrap();
  let error = docker.run_init("app", &init, &ctx).await.unwrap_err();
  assert!(error.message.contains("退出码 42"));
  assert_eq!(rx.try_recv().unwrap(), "运行部署前初始化");
  assert!(rx.try_recv().is_err());
}

#[cfg(test)]
#[test]
fn parse_compose_max_grace_scales_timeout() {
  let yaml = "services:\n  a: {stop_grace_period: '1m30s'}\n  b: {stop_grace_period: 5m}";
  assert_eq!(parse_compose_max_grace_secs(yaml), 300);
  assert_eq!(
    stop_timeout(parse_compose_max_grace_secs(yaml)).as_secs(),
    360
  );
}

#[cfg(test)]
#[test]
fn parse_running_images_maps_multiple_containers() {
  let known = ["web".into(), "worker:2".into(), "db:latest".into()];
  assert_eq!(
    parse_running_images(
      "web:latest|id1\nworker:2|id2\ndb|id3\nold@sha256:x|id4\nother:1|id5\n",
      &known
    ),
    BTreeMap::from([
      ("web".into(), "id1".into()),
      ("worker:2".into(), "id2".into()),
      ("db:latest".into(), "id3".into())
    ])
  );
}

#[tokio::test]
async fn native_compose_project_env_round_trips_without_expanding_the_input()
 {
  if std::env::var_os("WHARF_TEST_COMPOSE").is_none() {
    return;
  }
  let dir = tempfile::tempdir().unwrap();
  let docker = Docker {
    bin: "docker".into(),
    data_dir: dir.path().into(),
  };
  let ctx = Ctx::detached();
  let yaml = r#"
services:
  first:
    image: alpine
    environment:
      VALUE: '${VALUE:?required}'
  second:
    image: alpine
    environment: ['VALUE=${VALUE:?required}', 'DEFAULT=${UNSET:-default}']
"#;
  let value = "line 1: $literal, \"quotes\", \\backslash\nline 2";
  let inputs =
    BTreeMap::from([("VALUE".to_string(), value.to_string())]);
  docker
    .check_project_env("p23-fixture", yaml, &inputs, &ctx)
    .await
    .unwrap();
  assert!(
    docker
      .check_project_env("p23-fixture", yaml, &BTreeMap::new(), &ctx)
      .await
      .is_err()
  );
  docker.write_compose("p23-fixture", yaml).unwrap();
  let user_dotenv = docker.project_dir("p23-fixture").join(".env");
  std::fs::write(&user_dotenv, "VALUE=from-user-file\n").unwrap();
  let old_name =
    docker.project_dir("p23-fixture").join(".wharf-project.env");
  std::fs::write(&old_name, "VALUE=user-managed\n").unwrap();
  assert_eq!(docker.read_project_env("p23-fixture").unwrap(), None);
  docker
    .write_project_env("p23-fixture", Some(&dotenv(&inputs).unwrap()))
    .unwrap();
  let env = docker
    .compose("p23-fixture")
    .args(["config", "--environment"])
    .timeout(Duration::from_secs(20))
    .run(&ctx)
    .await
    .unwrap()
    .check("Compose dotenv")
    .unwrap();
  assert!(env.stdout.contains(&format!("VALUE={value}\n")));
  let doc = docker
    .compose("p23-fixture")
    .args(["config", "--format", "json"])
    .timeout(Duration::from_secs(20))
    .run(&ctx)
    .await
    .unwrap()
    .check("Compose dotenv")
    .unwrap();
  let doc: serde_json::Value =
    serde_json::from_str(&doc.stdout).unwrap();
  let escaped = value.replace('$', "$$");
  for service in ["first", "second"] {
    let actual = doc["services"][service]["environment"]["VALUE"]
      .as_str()
      .unwrap();
    // Compose 2.x 的 config 输出会把字面量 $ 转义为 $$。
    assert!(actual == value || actual == escaped);
  }
  assert_eq!(
    doc["services"]["second"]["environment"]["DEFAULT"].as_str(),
    Some("default")
  );
  docker.write_project_env("p23-fixture", None).unwrap();
  assert_eq!(docker.read_project_env("p23-fixture").unwrap(), None);
  assert_eq!(
    std::fs::read_to_string(old_name).unwrap(),
    "VALUE=user-managed\n"
  );
  assert_eq!(
    std::fs::read_to_string(user_dotenv).unwrap(),
    "VALUE=from-user-file\n"
  );
}
