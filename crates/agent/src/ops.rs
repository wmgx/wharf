//! 请求分发。修改同一个 project 的请求串行执行。

use std::{
  collections::HashMap,
  path::Path,
  sync::{Arc, Mutex},
  time::Duration,
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, BUILD_IMAGE_PREFIX, GatewayApply, ProjectUp,
    ProjectUpResult,
  },
  validate_name,
};

use crate::{
  docker::{CONFIG_HASH_FILE, Docker, io_err, write_private},
  exec::{Cmd, Ctx},
  report::Reporter,
};

pub struct Ops {
  pub docker: Docker,
  pub reporter: Reporter,
  /// 控制面地址：构建时从这里下载上传的代码包。
  pub core_url: String,
  locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// caddy 的管理接口用 unix socket，不占端口，也就不会和机器上已有的 Caddy 冲突。
pub const CADDY_ADMIN: &str = "unix//config/caddy-admin.sock";

impl Ops {
  pub fn new(
    docker: Docker,
    reporter: Reporter,
    core_url: String,
  ) -> Self {
    Self {
      docker,
      reporter,
      core_url,
      locks: Default::default(),
    }
  }

  fn lock_for(&self, project: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks =
      self.locks.lock().unwrap_or_else(|p| p.into_inner());
    locks.entry(project.to_string()).or_default().clone()
  }

  pub async fn handle(
    &self,
    op: AgentOp,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
    match op {
      AgentOp::Report => to_value(self.reporter.report(true).await),
      AgentOp::ProjectStatus { projects } => {
        for p in &projects {
          check_project(p)?;
        }
        to_value(self.docker.status(&projects, ctx).await?)
      }
      AgentOp::EnsureDirs { dirs } => {
        for dir in &dirs {
          ensure_dir(dir)?;
        }
        Ok(Value::Null)
      }
      AgentOp::ProjectUp(up) => {
        check_project(&up.project)?;
        let lock = self.lock_for(&up.project);
        let _guard = lock.lock().await;
        to_value(self.project_up(&up, ctx).await?)
      }
      AgentOp::ProjectDown { project } => {
        check_project(&project)?;
        let lock = self.lock_for(&project);
        let _guard = lock.lock().await;
        self.docker.down(&project, ctx).await?;
        Ok(Value::Null)
      }
      AgentOp::Logs {
        project,
        tail,
        follow,
      } => {
        check_project(&project)?;
        if follow {
          self.docker.follow_logs(&project, tail, ctx).await;
          to_value(String::new())
        } else {
          to_value(self.docker.logs(&project, tail, ctx).await?)
        }
      }
      AgentOp::GatewayApply(apply) => {
        check_project(&apply.up.project)?;
        let lock = self.lock_for(&apply.up.project);
        let _guard = lock.lock().await;
        to_value(self.gateway_apply(&apply, ctx).await?)
      }
      AgentOp::ProjectStop { project } => {
        self.stop_start(&project, false, ctx).await
      }
      AgentOp::ProjectStart { project } => {
        self.stop_start(&project, true, ctx).await
      }
      AgentOp::SyncServe(s) => crate::sync::serve(&s, ctx).await,
      AgentOp::SyncPush(p) => crate::sync::push(&p, ctx).await,
      AgentOp::RemoveData { service } => {
        self.remove_data(&service, ctx)
      }
      AgentOp::Restic(job) => {
        crate::restic::run(&self.docker, &job, ctx).await
      }
      AgentOp::Build(job) => {
        check_project(&job.service)?;
        if !job.image.starts_with(&format!(
          "{BUILD_IMAGE_PREFIX}{}:",
          job.service
        )) {
          return Err(ApiError::invalid(format!(
            "构建镜像名必须是 {BUILD_IMAGE_PREFIX}{}:<指纹>",
            job.service
          )));
        }
        let lock = self.lock_for(&job.service);
        let _guard = lock.lock().await;
        crate::build::run(&self.docker, &self.core_url, &job, ctx)
          .await
      }
      AgentOp::Probe { targets } => {
        to_value(crate::probe::check(targets).await)
      }
      AgentOp::Discover => {
        to_value(crate::adopt::discover(&self.docker, ctx).await?)
      }
      AgentOp::ImportRead(target) => to_value(
        crate::adopt::read(&self.docker, &target, ctx).await?,
      ),
      AgentOp::Unretire { items } => {
        crate::adopt::unretire(&self.docker, &items, ctx).await?;
        Ok(Value::Null)
      }
      AgentOp::EdgeBuild(job) => {
        let lock = self.lock_for(&format!("edge/{}", job.app));
        let _guard = lock.lock().await;
        crate::edge::run(&self.docker, &self.core_url, &job, ctx)
          .await
      }
    }
  }

  /// 只删迁移留下的旧数据：这台机器上还部署着这个服务就拒绝。
  fn remove_data(
    &self,
    service: &str,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
    check_project(service)?;
    if self
      .docker
      .project_dir(service)
      .join("compose.yaml")
      .exists()
    {
      return Err(ApiError::invalid(format!(
        "服务 {service} 还部署在这台机器上，不删除它的数据"
      )));
    }
    let dir = Path::new("/srv").join(service);
    if dir.exists() {
      ctx.say(format!("删除 {}", dir.display()));
      std::fs::remove_dir_all(&dir).map_err(io_err(&dir))?;
    }
    Ok(Value::Null)
  }

  async fn stop_start(
    &self,
    project: &str,
    start: bool,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
    check_project(project)?;
    let lock = self.lock_for(project);
    let _guard = lock.lock().await;
    to_value(self.docker.stop_start(project, start, ctx).await?)
  }

  async fn pull_all(
    &self,
    up: &ProjectUp,
    ctx: &Ctx,
    warnings: &mut Vec<String>,
  ) -> Result<Vec<String>, ApiError> {
    let images = self.docker.images(&up.project, ctx).await?;
    for image in &images {
      if up.pull_missing_only
        && self.docker.image_exists(image, ctx).await
      {
        continue;
      }
      // 本机构建的镜像不拉取，必须已经构建好。
      if image.starts_with(BUILD_IMAGE_PREFIX) {
        if !self.docker.image_exists(image, ctx).await {
          return Err(ApiError::new(
            ErrorCode::AgentFailed,
            format!("镜像 {image} 还没有构建"),
          ));
        }
        continue;
      }
      self.docker.pull(image, &up.pull, ctx, warnings).await?;
    }
    Ok(images)
  }

  async fn finish_up(
    &self,
    up: &ProjectUp,
    images: &[String],
    warnings: Vec<String>,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    self.docker.up(&up.project, ctx).await?;
    self.docker.write_hash(&up.project, &up.hash)?;
    let state = self.docker.one_status(&up.project, ctx).await?;
    Ok(ProjectUpResult {
      containers: state.containers,
      images: self.docker.image_info(images, ctx).await,
      warnings,
      retired: vec![],
    })
  }

  async fn project_up(
    &self,
    up: &ProjectUp,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    self.docker.write_compose(&up.project, &up.compose)?;
    let mut warnings = Vec::new();
    let images = self.pull_all(up, ctx, &mut warnings).await?;
    // 镜像拉好之后再停原来的容器，中断只有切换的那几秒。
    let retired = match &up.retire {
      Some(r) if r.service == up.project => {
        crate::adopt::retire(&self.docker, r, ctx).await?
      }
      _ => vec![],
    };
    match self.finish_up(up, &images, warnings, ctx).await {
      Ok(result) => Ok(ProjectUpResult { retired, ..result }),
      Err(e) if !retired.is_empty() => {
        ctx.say("启动失败，恢复原来的容器");
        let _ = self.docker.down(&up.project, ctx).await;
        if let Err(back) =
          crate::adopt::unretire(&self.docker, &retired, ctx).await
        {
          ctx
            .say(format!("恢复失败，需要手动处理：{}", back.message));
        }
        Err(e)
      }
      Err(e) => Err(e),
    }
  }

  /// 先校验新配置，通过后再替换；容器在运行时热重载，失败就恢复旧配置。
  async fn gateway_apply(
    &self,
    apply: &GatewayApply,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    let up = &apply.up;
    let dir = self.docker.project_dir(&up.project);
    let conf = dir.join("conf");
    std::fs::create_dir_all(&conf).map_err(io_err(&conf))?;
    let current = conf.join("Caddyfile");
    let next = conf.join("Caddyfile.next");
    let prev = conf.join("Caddyfile.prev");

    let before = self.docker.one_status(&up.project, ctx).await?;
    let compose_changed =
      before.hash.as_deref() != Some(up.hash.as_str());
    let running = before.all_running();

    // 网关 compose 只有 caddy 一个镜像。校验通过之前不动现有 compose 文件。
    let mut warnings = Vec::new();
    let images = vec![apply.image.clone()];
    // 只改路由时容器在跑、镜像就在本地，不必再拉。
    if !running || compose_changed {
      self
        .docker
        .pull(&apply.image, &up.pull, ctx, &mut warnings)
        .await?;
    }

    write_private(&next, &apply.caddyfile)?;
    ctx.say("校验 Caddy 配置");
    let validated = Cmd::new(&self.docker.bin)
      .args(["run", "--rm", "--network", "none", "-v"])
      .arg(format!("{}:/etc/caddy:ro", conf.display()))
      .args([
        apply.image.as_str(),
        "caddy",
        "validate",
        "--config",
        "/etc/caddy/Caddyfile.next",
        "--adapter",
        "caddyfile",
      ])
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await?
      .check("caddy validate");
    if let Err(e) = validated {
      let _ = std::fs::remove_file(&next);
      return Err(e);
    }

    let had_config = current.exists();
    if had_config {
      std::fs::copy(&current, &prev).map_err(io_err(&prev))?;
    }
    std::fs::rename(&next, &current).map_err(io_err(&current))?;
    self.docker.write_compose(&up.project, &up.compose)?;

    let result = if running && !compose_changed {
      ctx.say("热重载 Caddy");
      match self.caddy_reload(&up.project, ctx).await {
        Ok(()) => {
          let state =
            self.docker.one_status(&up.project, ctx).await?;
          Ok(ProjectUpResult {
            containers: state.containers,
            images: self.docker.image_info(&images, ctx).await,
            warnings,
            retired: vec![],
          })
        }
        Err(e) => Err(e),
      }
    } else {
      self.finish_up(up, &images, warnings, ctx).await
    };

    match result {
      Ok(result) => {
        let hash = conf.join(CONFIG_HASH_FILE);
        std::fs::write(&hash, &apply.caddyfile_hash)
          .map_err(io_err(&hash))?;
        Ok(result)
      }
      Err(e) => {
        if had_config {
          ctx.say("失败，恢复旧配置");
          let _ = std::fs::rename(&prev, &current);
          if running {
            let _ = self.caddy_reload(&up.project, ctx).await;
          }
        }
        Err(e)
      }
    }
  }

  async fn caddy_reload(
    &self,
    project: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    self
      .docker
      .compose(project)
      .args([
        "exec",
        "-T",
        "caddy",
        "caddy",
        "reload",
        "--config",
        "/etc/caddy/Caddyfile",
        "--adapter",
        "caddyfile",
        "--address",
        CADDY_ADMIN,
      ])
      .timeout(Duration::from_secs(60))
      .run(ctx)
      .await?
      .check("caddy reload")?;
    Ok(())
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

/// project 名会拼进路径，必须先校验。网关 project 是 `wharf-gw-<name>`。
fn check_project(project: &str) -> Result<(), ApiError> {
  validate_name("project", project)
}

/// 只允许在 `/srv/` 下建目录，防止控制面被冒充时随便写。
fn ensure_dir(dir: &str) -> Result<(), ApiError> {
  let path = Path::new(dir);
  let ok = path.is_absolute()
    && path.starts_with("/srv/")
    && path.components().all(|c| {
      matches!(
        c,
        std::path::Component::RootDir
          | std::path::Component::Normal(_)
      )
    });
  if !ok {
    return Err(ApiError::new(
      ErrorCode::InvalidInput,
      format!("数据目录必须在 /srv/ 下：{dir}"),
    ));
  }
  std::fs::create_dir_all(path).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dirs_stay_under_srv() {
    assert!(ensure_dir("/etc/x").is_err());
    assert!(ensure_dir("/srv/../etc").is_err());
    assert!(ensure_dir("srv/a").is_err());
  }
}
