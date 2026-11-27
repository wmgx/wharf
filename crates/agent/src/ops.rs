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
    AgentOp, BUILD_IMAGE_PREFIX, ProjectUp, ProjectUpResult,
    TRIAL_PROJECT_PREFIX,
  },
};

use crate::{
  docker::{Docker, Previous},
  exec::Ctx,
  host_shell::HostShell,
  report::Reporter,
};

mod gateway;
mod validation;
use validation::{
  check_own_container, check_project, data_dir_relative,
};

pub struct Ops {
  pub docker: Docker,
  pub reporter: Reporter,
  /// 控制面地址：构建时从这里下载上传的代码包。
  pub core_url: String,
  pub host_shell: HostShell,
  /// 数据目录：打包宿主机目录时的临时文件放在它下面的 `tmp/`。
  pub data_dir: std::path::PathBuf,
  locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
  restic_locks: Mutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>,
}

/// caddy 的管理接口用 unix socket，不占端口，也就不会和机器上已有的 Caddy 冲突。
pub const CADDY_ADMIN: &str = "unix//config/caddy-admin.sock";

impl Ops {
  pub fn new(
    docker: Docker,
    reporter: Reporter,
    core_url: String,
    host_shell: HostShell,
    data_dir: std::path::PathBuf,
  ) -> Self {
    Self {
      docker,
      reporter,
      core_url,
      host_shell,
      data_dir,
      locks: Default::default(),
      restic_locks: Default::default(),
    }
  }
  fn lock_for(&self, project: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks =
      self.locks.lock().unwrap_or_else(|p| p.into_inner());
    locks.entry(project.to_string()).or_default().clone()
  }

  pub(crate) fn reserve_removal(
    &self,
    service: &str,
  ) -> Result<tokio::sync::OwnedMutexGuard<()>, ApiError> {
    check_project(service)?;
    self.lock_for(service).try_lock_owned().map_err(|_| {
      ApiError::new(
        ErrorCode::Busy,
        format!("服务 {service} 正在执行其他操作"),
      )
    })
  }

  async fn lock_data(
    &self,
    service: &str,
    ctx: &Ctx,
  ) -> Result<tokio::sync::OwnedMutexGuard<()>, ApiError> {
    tokio::select! {
      biased;
      _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
      guard = self.lock_for(service).lock_owned() => Ok(guard),
    }
  }
  pub(crate) fn rotate_identity(
    &self,
    op: AgentOp,
  ) -> Result<(Value, bool), ApiError> {
    match op {
      AgentOp::RotateAgentKey(job) => {
        crate::identity::rotate_key(&self.data_dir, job)
      }
      AgentOp::TrustCoreKey(job) => {
        crate::identity::trust_core_key(&self.data_dir, job)
      }
      _ => return Err(ApiError::invalid("不是密钥轮换请求")),
    }
    .map_err(|e| ApiError::internal(format!("更新通信身份失败：{e}")))
  }

  pub async fn handle(
    &self,
    op: AgentOp,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
    match op {
      AgentOp::RotateAgentKey(_) | AgentOp::TrustCoreKey(_) => {
        Err(ApiError::invalid("密钥轮换须通过当前连接处理"))
      }
      AgentOp::AccessLogs(job) => {
        to_value(crate::access_logs::read(job, ctx).await?)
      }
      AgentOp::ProbeCoreHost(probe) => to_value(
        crate::core_probe::run(&self.docker, &probe, ctx).await?,
      ),
      AgentOp::Report => to_value(self.reporter.report(true).await),
      AgentOp::ListImages => {
        to_value(crate::images::list(&self.docker, ctx).await?)
      }
      AgentOp::ResolveCommit(job) => to_value(
        crate::build::resolve_commit(&self.docker, &job, ctx).await?,
      ),
      AgentOp::ResolveImages(job) => {
        to_value(crate::registry::resolve(&job, ctx).await?)
      }
      AgentOp::ProjectStatus { projects } => {
        for p in &projects {
          check_project(p)?;
        }
        to_value(self.docker.status(&projects, ctx).await?)
      }
      AgentOp::DiagnoseContainer { project, ports } => {
        check_project(&project)?;
        to_value(
          crate::diagnose::run(&self.docker, &project, &ports, ctx)
            .await?,
        )
      }
      AgentOp::EnsureDirs { dirs } => {
        for dir in &dirs {
          let relative = data_dir_relative(dir)?;
          let project = relative
            .iter()
            .next()
            .and_then(|p| p.to_str())
            .unwrap_or_default();
          let _guard = self.lock_data(project, ctx).await?;
          crate::dirfd::ensure_beneath(Path::new("/srv"), relative)?;
        }
        Ok(Value::Null)
      }
      AgentOp::ProjectUp(up) => {
        check_project(&up.project)?;
        let lock = self.lock_for(&up.project);
        let _guard = lock.lock().await;
        to_value(self.project_up(&up, ctx).await?)
      }
      AgentOp::ProjectDown { project, purge } => {
        check_project(&project)?;
        let lock = self.lock_for(&project);
        let _guard = lock.lock().await;
        if !purge {
          crate::prev_logs::capture(
            &self.docker,
            &project,
            "remove",
            ctx,
          )
          .await;
        }
        self.docker.down(&project, purge, ctx).await?;
        if purge {
          crate::prev_logs::purge(&self.data_dir, &project);
        }
        Ok(Value::Null)
      }
      AgentOp::PreviousLogs {
        project,
        index,
        tail,
        since,
        list,
      } => {
        check_project(&project)?;
        let lock = self.lock_for(&project);
        let _guard = lock.lock().await;
        let data = self.data_dir.clone();
        tokio::task::spawn_blocking(move || {
          if list {
            to_value(crate::prev_logs::list(&data, &project)?)
          } else {
            to_value(crate::prev_logs::read(
              &data,
              &project,
              index,
              tail,
              since.as_deref(),
            )?)
          }
        })
        .await
        .map_err(|e| {
          ApiError::internal(format!("读取旧日志失败：{e}"))
        })?
      }
      AgentOp::Logs {
        project,
        tail,
        follow,
        since,
      } => {
        check_project(&project)?;
        if follow {
          self.docker.follow_logs(&project, tail, ctx).await;
          to_value(String::new())
        } else {
          to_value(
            self
              .docker
              .logs(&project, tail, since.as_deref(), ctx)
              .await?,
          )
        }
      }
      AgentOp::GatewayApply(apply) => {
        check_project(&apply.up.project)?;
        let lock = self.lock_for(&apply.up.project);
        let _guard = lock.lock().await;
        to_value(self.gateway_apply(&apply, ctx).await?)
      }
      AgentOp::GatewayReload { project } => {
        check_project(&project)?;
        let lock = self.lock_for(&project);
        let _guard = lock.lock().await;
        ctx.say("强制热重载 Caddy");
        self.caddy_reload(&project, true, ctx).await?;
        to_value(String::new())
      }
      AgentOp::ProjectStop { project } => {
        self.stop_start(&project, false, ctx).await
      }
      AgentOp::ProjectStart {
        project,
        containers,
      } => {
        if containers.is_empty() {
          self.stop_start(&project, true, ctx).await
        } else {
          let _guard = self.lock_data(&project, ctx).await?;
          self
            .docker
            .start_containers(&project, &containers, ctx)
            .await?;
          to_value(true)
        }
      }
      AgentOp::ServiceStopForData { project } => {
        let _guard = self.lock_data(&project, ctx).await?;
        to_value(
          self.docker.stop_running_for_data(&project, ctx).await?,
        )
      }
      AgentOp::PruneRestore { older_than_days } => {
        let ctx = ctx.clone();
        let result = tokio::task::spawn_blocking(move || {
          crate::restic::prune_restore_kept(
            Path::new("/srv"),
            older_than_days,
            &ctx,
          )
        })
        .await
        .map_err(|_| {
          ApiError::internal("恢复目录清理任务异常结束")
        })??;
        to_value(result)
      }
      AgentOp::ProjectMounts { projects } => {
        to_value(self.docker.project_mounts(&projects, ctx).await?)
      }
      AgentOp::SyncServe(s) => {
        check_project(&s.service)?;
        let _guard = self.lock_data(&s.service, ctx).await?;
        crate::sync::serve(&s, ctx).await
      }
      AgentOp::SyncPush(p) => crate::sync::push(&p, ctx).await,
      AgentOp::RemoveData { service } => {
        self.remove_data(&service, ctx).await
      }
      AgentOp::BindMountUsers(query) => {
        data_dir_relative(&query.path)?;
        to_value(
          self.docker.inspect_bind_mount_users(&query, ctx).await?,
        )
      }
      AgentOp::Restic(job) => self.restic(&job, ctx).await,
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
      AgentOp::Quality { targets, count } => {
        to_value(crate::probe::quality(targets, count).await)
      }
      AgentOp::NetProbe(mut job) => {
        if let Some(scope) = job.container.take() {
          check_project(&scope.project)?;
          return to_value(
            crate::container_probe::run(
              &self.docker,
              scope,
              &job,
              ctx,
            )
            .await?,
          );
        }
        to_value(crate::net_probe::run(&job, ctx).await)
      }
      AgentOp::HttpFetch(job) => {
        tokio::select! {
          result = crate::probe::fetch(job) => to_value(result),
          _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
        }
      }
      AgentOp::HttpCheck(job) => {
        to_value(crate::probe::http(job).await)
      }
      AgentOp::PortChecks { checks } => {
        to_value(crate::port_checks::run(checks, ctx).await)
      }
      AgentOp::Discover => {
        to_value(crate::adopt::discover(&self.docker, ctx).await?)
      }
      AgentOp::RemoveContainers {
        containers,
        volumes,
      } => to_value(
        crate::adopt::remove(&self.docker, &containers, volumes, ctx)
          .await?,
      ),
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
      AgentOp::Upgrade(job) => to_value(
        crate::upgrade::start(&self.docker, &job, ctx).await?,
      ),
      AgentOp::UpgradePrepare(job) => to_value(
        crate::upgrade::prepare(&self.docker, &job, ctx).await?,
      ),
      AgentOp::Prune => to_value(self.docker.prune(ctx).await?),
      // 文件 IO 不长，但还是放到阻塞线程，不卡住连接。
      AgentOp::Files(op) => {
        tokio::task::spawn_blocking(move || crate::files::handle(op))
          .await
          .map_err(|e| ApiError::internal(e.to_string()))?
      }
      AgentOp::UpgradeLog => {
        to_value(crate::upgrade::helper_log(ctx).await)
      }
      AgentOp::Exposure => {
        to_value(crate::exposure::collect(&self.docker, ctx).await?)
      }
      AgentOp::HostUnits => {
        to_value(crate::host_units::list(&self.docker, ctx).await?)
      }
      AgentOp::HostUnitLogs { unit, lines } => to_value(
        crate::host_units::logs(&self.docker, &unit, lines, ctx)
          .await?,
      ),
      AgentOp::ContainerLogs {
        container,
        tail,
        since,
      } => {
        check_own_container(&container)?;
        to_value(
          self
            .docker
            .container_logs(&container, tail, since.as_deref(), ctx)
            .await?,
        )
      }
      AgentOp::DiskUsage { services } => {
        for s in &services {
          check_project(s)?;
        }
        to_value(
          crate::host::disk_usage(&self.docker, &services, ctx)
            .await?,
        )
      }
      AgentOp::SshLogins => {
        to_value(crate::host::ssh_logins(&self.docker, ctx).await?)
      }
      AgentOp::HostInfo => {
        to_value(crate::host::info(&self.docker, ctx).await?)
      }
      AgentOp::HostListDir { path } => to_value(
        crate::host_dir::list(&self.docker, &path, ctx).await?,
      ),
      AgentOp::HostPack(job) => to_value(
        crate::host_dir::pack(
          &self.docker,
          &self.data_dir,
          &self.core_url,
          &job,
          ctx,
        )
        .await?,
      ),
      AgentOp::HostSessions => {
        to_value(self.host_shell.sessions(ctx).await?)
      }
      AgentOp::HostSessionKill { session } => {
        to_value(self.host_shell.kill_session(&session, ctx).await?)
      }
      AgentOp::HostSessionRename { session, to } => to_value(
        self.host_shell.rename_session(&session, &to, ctx).await?,
      ),
      AgentOp::HostExec(job) => {
        to_value(self.host_shell.exec(job, ctx).await)
      }
      AgentOp::Egress(cfg) => {
        crate::egress::apply(
          self.data_dir.clone(),
          &self.core_url,
          cfg,
        )
        .await?;
        Ok(Value::Null)
      }
      AgentOp::TaskRun(job) => {
        to_value(crate::task::run(&self.docker, &job, ctx).await?)
      }
      AgentOp::SsoCleanup { domains, runners } => {
        crate::task::cleanup_sso(
          &self.docker,
          &domains,
          &runners,
          ctx,
        )
        .await?;
        Ok(Value::Null)
      }
      // 要接收输入，由连接那边直接处理。
      AgentOp::Terminal(_)
      | AgentOp::HostTerminal { .. }
      | AgentOp::Forward(_) => {
        Err(ApiError::internal("终端请求没有输入通道"))
      }
    }
  }
  /// 只删迁移留下的旧数据：这台机器上还部署着这个服务就拒绝。
  async fn remove_data(
    &self,
    service: &str,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
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
    let root = Path::new("/srv");
    let blocked_by = self
      .docker
      .bind_mount_users(&root.join(service), ctx)
      .await?;
    let removed = blocked_by.is_empty();
    if removed {
      crate::dirfd::remove_service(root, service, ctx).await?;
      ctx.say(format!("清理 /srv/{service}"));
    } else {
      ctx.say(format!(
        "保留 /srv/{service}：仍有容器挂载该目录（{}）",
        blocked_by.join("、")
      ));
    }
    Ok(serde_json::json!(
      wharf_api_types::agent::RemoveDataResult {
        removed,
        blocked_by
      }
    ))
  }

  async fn restic(
    &self,
    job: &wharf_api_types::agent::ResticJob,
    ctx: &Ctx,
  ) -> Result<Value, ApiError> {
    use wharf_api_types::agent::{ResticAction, ResticRepo};
    wharf_api_types::validate_name("service", &job.service)?;
    let scope = match &job.repo {
      ResticRepo::Local => "local",
      ResticRepo::Rest { .. } => "rest",
    };
    let key = format!("{scope}:{}", job.service);
    let lock = self
      .restic_locks
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .entry(key)
      .or_default()
      .clone();
    let busy = || {
      ApiError::new(
        ErrorCode::Busy,
        format!(
          "服务 {} 的备份仓库正在使用，请稍后再试",
          job.service
        ),
      )
    };
    if matches!(
      &job.action,
      ResticAction::Snapshots
        | ResticAction::ListKeys
        | ResticAction::Preflight(_)
    ) {
      let _guard = tokio::select! {
        biased;
        _ = ctx.cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
        guard = tokio::time::timeout(Duration::from_secs(5), lock.read()) => guard.map_err(|_| busy())?,
      };
      crate::restic::run(&self.docker, job, ctx).await
    } else {
      let _guard = lock.try_write().map_err(|_| busy())?;
      let _data = if matches!(
        job.action,
        ResticAction::Backup { .. } | ResticAction::Restore { .. }
      ) && job.core_marker.is_none()
      {
        Some(self.lock_data(&job.service, ctx).await?)
      } else {
        None
      };
      crate::restic::run(&self.docker, job, ctx).await
    }
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
      if up.expected_images.contains_key(image) {
        continue;
      }
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
      if let Some(digest) = up.pins.get(image) {
        if !self.docker.has_digest(image, digest, ctx).await {
          self
            .docker
            .pull_pinned(image, digest, &up.pull, ctx)
            .await?;
        }
        continue;
      }
      self.docker.pull(image, &up.pull, ctx, warnings).await?;
    }
    Ok(images)
  }

  async fn up_with_crash_logs(
    &self,
    project: &str,
    no_start: bool,
    previous_grace: u64,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let result =
      self.docker.up(project, no_start, previous_grace, ctx).await;
    if result
      .as_ref()
      .is_err_and(|e| e.code != ErrorCode::Cancelled)
    {
      crate::settle::emit_crash_logs(
        &self.docker,
        project,
        None,
        &[],
        ctx,
      )
      .await;
    }
    result
  }

  async fn finish_up(
    &self,
    up: &ProjectUp,
    images: &[String],
    warnings: Vec<String>,
    previous: Option<Previous>,
    previous_grace: u64,
    ctx: &Ctx,
  ) -> Result<ProjectUpResult, ApiError> {
    crate::prev_logs::capture(
      &self.docker,
      &up.project,
      "recreate",
      ctx,
    )
    .await;
    self
      .up_with_crash_logs(
        &up.project,
        up.no_start,
        previous_grace,
        ctx,
      )
      .await?;
    let state = if up.no_start {
      let mut state =
        self.docker.one_status(&up.project, ctx).await?;
      // --no-start leaves unchanged containers running.
      if !up.pull_missing_only
        && state.containers.iter().any(|c| c.state == "running")
      {
        self.docker.stop_start(&up.project, false, ctx).await?;
        state = self.docker.one_status(&up.project, ctx).await?;
      }
      if state.containers.is_empty()
        || state.containers.iter().any(|c| c.state == "running")
      {
        return Err(ApiError::new(
          ErrorCode::AgentFailed,
          "创建后没有容器或容器仍在运行",
        ));
      }
      state
    } else {
      match crate::settle::watch(
        &self.docker,
        &up.project,
        crate::settle::WatchOptions {
          max_watch: crate::settle::max_watch(up.start_timeout_secs),
          readiness: up.readiness.as_ref(),
        },
        ctx,
      )
      .await
      {
        Ok(state) => state,
        Err(e) => {
          let Some(prev) = previous else { return Err(e) };
          if e.code == ErrorCode::Cancelled {
            return Err(e);
          }
          crate::prev_logs::capture(
            &self.docker,
            &up.project,
            "rollback",
            ctx,
          )
          .await;
          ctx.say(format!("{}，换回上一版", e.message));
          self.restore_image(&prev, ctx).await?;
          self.docker.write_compose(&up.project, &prev.compose)?;
          self.docker.write_hash(&up.project, &prev.hash)?;
          let grace =
            wharf_api_types::compose::parse_compose_max_grace_secs(
              &up.compose,
            );
          self.docker.up(&up.project, false, grace, ctx).await?;
          return Err(
            ApiError::new(
              ErrorCode::AgentFailed,
              format!("{}，已换回上一版", e.message),
            )
            .with_hint("配置还是新版本，修好后重新部署；先看日志"),
          );
        }
      }
    };
    self.docker.write_hash(&up.project, &up.hash)?;
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
    if up.trial.is_some()
      && let Err(e) = self
        .docker
        .down_trial(
          &format!("{TRIAL_PROJECT_PREFIX}{}", up.project),
          &Ctx::detached(),
        )
        .await
    {
      ctx.say(format!("清理上次试跑失败：{}", e.message));
    }
    let mut previous = if up.rollback {
      self.docker.previous(&up.project)
    } else {
      None
    };
    if let Some(prev) = &mut previous {
      let images = self.docker.images(&up.project, ctx).await?;
      if let [image] = images.as_slice()
        && let Some(id) =
          self.docker.running_image(&up.project, ctx).await
      {
        prev.image = Some((image.clone(), id));
      }
    }
    let had_compose =
      self.docker.read_compose(&up.project).map_err(|e| {
        ApiError::internal(format!("读取原 compose 失败：{e}"))
      })?;
    let previous_grace = had_compose.as_deref().map_or(
      10,
      wharf_api_types::compose::parse_compose_max_grace_secs,
    );
    let saved_images = if up.init.is_some() && had_compose.is_some() {
      let images = self.docker.images(&up.project, ctx).await?;
      let mut saved = self.docker.image_info(&images, ctx).await;
      if let [image] = saved.as_mut_slice()
        && let Some(id) =
          self.docker.running_image(&up.project, ctx).await
      {
        image.id = id;
      }
      saved
    } else {
      vec![]
    };
    self.docker.write_compose(&up.project, &up.compose)?;
    let mut warnings = Vec::new();
    let prepared = async {
      let images = self.pull_all(up, ctx, &mut warnings).await?;
      if let Some(init) = &up.init {
        crate::adopt::verify_expected_images(
          &self.docker,
          &up.expected_images,
          ctx,
        )
        .await?;
        self.docker.run_init(&up.project, init, ctx).await?;
      }
      Ok(images)
    }
    .await;
    let images = match prepared {
      Ok(images) => images,
      Err(e) => {
        if up.init.is_some() {
          self
            .restore_init(
              &up.project,
              had_compose.as_deref(),
              &saved_images,
              ctx,
            )
            .await;
        }
        return Err(e);
      }
    };
    if let Some(prev) = &previous {
      let now = match &prev.image {
        Some((image, _)) => self
          .docker
          .image_info(std::slice::from_ref(image), ctx)
          .await
          .into_iter()
          .next()
          .filter(|i| !i.id.is_empty())
          .map(|i| i.id),
        None => None,
      };
      if !has_previous(
        &prev.hash,
        &up.hash,
        prev.image.as_ref().map(|(_, id)| id.as_str()),
        now.as_deref(),
      ) {
        previous = None;
      }
    }
    if up.trial.is_some() {
      self.trial_run(up, previous.as_ref(), ctx).await?;
    }
    // 镜像拉好之后再停原来的容器，中断只有切换的那几秒。
    crate::adopt::verify_expected_images(
      &self.docker,
      &up.expected_images,
      ctx,
    )
    .await?;
    let retired = match &up.retire {
      Some(r) if r.service == up.project => {
        crate::adopt::retire(&self.docker, r, ctx).await?
      }
      _ => vec![],
    };
    match self
      .finish_up(up, &images, warnings, previous, previous_grace, ctx)
      .await
    {
      Ok(result) => Ok(ProjectUpResult { retired, ..result }),
      Err(e) if !retired.is_empty() => {
        ctx.say("启动失败，恢复原来的容器");
        let recover = ctx.detached_with_progress();
        if let Err(down) =
          self.docker.down(&up.project, false, &recover).await
        {
          recover.say(format!("清理新容器失败：{}", down.message));
        }
        if let Err(back) =
          crate::adopt::unretire(&self.docker, &retired, &recover)
            .await
        {
          ctx
            .say(format!("恢复失败，需要手动处理：{}", back.message));
        }
        Err(e)
      }
      Err(e) => Err(e),
    }
  }

  async fn restore_init(
    &self,
    project: &str,
    compose: Option<&str>,
    images: &[wharf_api_types::agent::ImageInfo],
    ctx: &Ctx,
  ) {
    let restored = match compose {
      Some(compose) => self.docker.write_compose(project, compose),
      None => {
        let file =
          self.docker.project_dir(project).join("compose.yaml");
        std::fs::remove_file(&file)
          .map_err(crate::docker::io_err(&file))
      }
    };
    if let Err(e) = restored {
      ctx.say(format!("恢复原 compose 失败：{}", e.message));
    }
    let recover = ctx.detached_with_progress();
    for image in images {
      if let Err(e) =
        self.restore_tag(&image.image, &image.id, &recover).await
      {
        ctx.say(format!("恢复原镜像标签失败：{}", e.message));
      }
    }
  }

  async fn restore_image(
    &self,
    previous: &Previous,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    if let Some((image, id)) = &previous.image {
      self.restore_tag(image, id, ctx).await?;
    }
    Ok(())
  }

  async fn restore_tag(
    &self,
    image: &str,
    id: &str,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    if !id.is_empty()
      && self.docker.image_info(&[image.to_string()], ctx).await[0].id
        != id
    {
      self
        .docker
        .cmd()
        .args(["tag", id, image])
        .timeout(Duration::from_secs(15))
        .run(ctx)
        .await?
        .check("docker tag")?;
    }
    Ok(())
  }

  async fn trial_run(
    &self,
    up: &ProjectUp,
    previous: Option<&Previous>,
    ctx: &Ctx,
  ) -> Result<(), ApiError> {
    let project = format!("{TRIAL_PROJECT_PREFIX}{}", up.project);
    let trial = up.trial.as_ref().unwrap();
    ctx.say("试跑新版本");
    let result = async {
      self.docker.write_compose(&project, trial)?;
      self.up_with_crash_logs(&project, false, 10, ctx).await?;
      crate::settle::watch(
        &self.docker,
        &project,
        crate::settle::WatchOptions {
          max_watch: crate::settle::max_watch(up.start_timeout_secs),
          readiness: None,
        },
        ctx,
      )
      .await?;
      Ok(())
    }
    .await;
    let cleanup =
      self.docker.down_trial(&project, &Ctx::detached()).await;
    if let Err(e) = &cleanup {
      ctx.say(format!("清理试跑失败：{}", e.message));
    }
    match result.and(cleanup) {
      Ok(()) => {
        ctx.say("试跑通过，替换线上的容器");
        Ok(())
      }
      Err(e) => {
        if let Some(prev) = previous {
          self.docker.write_compose(&up.project, &prev.compose)?;
          if let Err(back) =
            self.restore_image(prev, &Ctx::detached()).await
          {
            ctx.say(format!("恢复镜像标签失败：{}", back.message));
          }
        }
        if e.code == ErrorCode::Cancelled {
          return Err(e);
        }
        let prefix = format!("{project} 没起来：");
        let why =
          e.message.strip_prefix(&prefix).unwrap_or(&e.message);
        Err(
          ApiError::new(
            ErrorCode::AgentFailed,
            format!("新版本试跑没通过：{why}，线上的容器没有动"),
          )
          .with_hint(
            "配置还是新版本，修好后重新部署；试跑的日志在上面",
          ),
        )
      }
    }
  }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

/// 配置变了，或者配置没变但同一个标签现在指向了别的镜像。
fn has_previous(
  old_hash: &str,
  new_hash: &str,
  old_image: Option<&str>,
  now_image: Option<&str>,
) -> bool {
  old_hash != new_hash
    || (old_image.is_some() && old_image != now_image)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn init_cmd_failure_restores_compose_and_keeps_old_container()
  {
    let (dir, docker) = crate::docker::fake_docker(
      r#"
case "$1:$6" in
  compose:config) echo fixture:1;;
  compose:run) touch init; exit 42;;
  compose:up) touch replaced;;
  rm:*) touch removed;;
  image:*) case "$4" in
    '{{.Id}}') echo 'sha256:old';;
    *) echo 'sha256:old|[]';;
  esac;;
  ps:*) echo id;;
  inspect:*) echo 'sha256:old';;
  *) exit 2;;
esac
"#,
    );
    let ops = Ops::new(
      docker.clone(),
      Reporter::new(docker.clone(), None),
      String::new(),
      HostShell::prepare(docker.clone(), "s1".into()).await,
      dir.path().into(),
    );
    let old = "services: {app: {image: 'fixture:1'}}";
    docker.write_compose("app", old).unwrap();
    let up: ProjectUp = serde_json::from_value(serde_json::json!({
      "project": "app", "compose": "services: {app: {image: 'fixture:1', environment: {A: new}}}",
      "hash": "new", "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 1},
      "expected_images": {"fixture:1": "sha256:old"},
      "init": {"service": "app", "command": "exit 42"}
    })).unwrap();
    let error =
      ops.project_up(&up, &Ctx::detached()).await.unwrap_err();
    assert!(error.message.contains("退出码 42"));
    assert_eq!(
      docker.read_compose("app").unwrap().as_deref(),
      Some(old)
    );
    assert!(dir.path().join("init").exists());
    assert!(dir.path().join("removed").exists());
    assert!(!dir.path().join("replaced").exists());
  }

  #[tokio::test]
  async fn stopped_update_stops_unchanged_running_container() {
    let (dir, docker) = crate::docker::fake_docker(
      r#"
case "$1:$6" in
  compose:up) [ "$7" = --no-start ] && touch updated;;
  compose:stop) [ -f updated ] && touch stopped;;
  ps:*)
    [ -f updated ] || exit 2
    state=running
    [ ! -f stopped ] || state=exited
    echo '{"Names":"app-web-1","Labels":"com.docker.compose.project=app","State":"created"}'
    printf '{"Names":"app-db-1","Labels":"com.docker.compose.project=app","State":"%s"}\n' "$state";;
  *) exit 2;;
esac
"#,
    );
    let ops = Ops::new(
      docker.clone(),
      Reporter::new(docker.clone(), None),
      String::new(),
      HostShell::prepare(docker.clone(), "s1".into()).await,
      dir.path().into(),
    );
    let up: ProjectUp = serde_json::from_value(serde_json::json!({
      "project": "app",
      "compose": "services: {web: {image: web:2}, db: {image: db:1}}",
      "hash": "new",
      "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 1},
      "no_start": true
    })).unwrap();
    docker.write_compose("app", &up.compose).unwrap();
    let result = ops
      .finish_up(&up, &[], vec![], None, 10, &Ctx::detached())
      .await
      .unwrap();
    assert_eq!(
      result
        .containers
        .iter()
        .map(|c| c.state.as_str())
        .collect::<Vec<_>>(),
      ["exited", "created"]
    );
    assert_eq!(
      std::fs::read_to_string(
        docker.project_dir("app").join(crate::docker::HASH_FILE)
      )
      .unwrap(),
      "new"
    );
  }

  #[tokio::test]
  async fn failed_formal_compose_up_prints_container_logs() {
    let (dir, docker) = crate::docker::fake_docker(
      r#"
case "$1:$6" in
  compose:up) touch failed; echo unhealthy-dependency >&2; exit 1;;
  ps:*) if [ -f failed ]; then
    echo '{"Names":"app-db-1","Labels":"com.docker.compose.project=app","State":"exited"}'
  fi;;
  logs:*) echo 'migration failed';;
esac
"#,
    );
    let ops = Ops::new(
      docker.clone(),
      Reporter::new(docker.clone(), None),
      String::new(),
      HostShell::prepare(docker.clone(), "s1".into()).await,
      dir.path().into(),
    );
    let up: ProjectUp = serde_json::from_value(serde_json::json!({
      "project": "app", "compose": "services: {db: {image: db:1}}", "hash": "new",
      "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 1}
    })).unwrap();
    docker.write_compose("app", &up.compose).unwrap();
    let lines =
      std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = lines.clone();
    let ctx = Ctx {
      progress: Some(std::sync::Arc::new(move |line| {
        output.lock().unwrap().push(line)
      })),
      ..Ctx::detached()
    };
    let error = ops
      .finish_up(&up, &[], vec![], None, 10, &ctx)
      .await
      .unwrap_err();
    assert!(error.message.contains("unhealthy-dependency"));
    assert!(
      lines
        .lock()
        .unwrap()
        .iter()
        .any(|line| line == "migration failed")
    );
  }

  #[tokio::test]
  async fn restic_repo_conflicts_do_not_run_docker() {
    let dir = tempfile::tempdir().unwrap();
    let docker = Docker {
      bin: dir.path().join("no-docker").display().to_string(),
      data_dir: dir.path().into(),
    };
    let shell = HostShell::prepare(docker.clone(), "s1".into()).await;
    let reporter = Reporter::new(docker.clone(), None);
    let ops = Ops::new(
      docker,
      reporter,
      String::new(),
      shell,
      dir.path().into(),
    );
    let lock = Arc::new(tokio::sync::RwLock::new(()));
    ops
      .restic_locks
      .lock()
      .unwrap()
      .insert("local:s1".into(), lock.clone());
    let _held = lock.write().await;
    let mut request: wharf_api_types::agent::ResticJob = serde_json::from_value(serde_json::json!({
      "service": "s1", "repo": "local", "password": "", "action": "prune",
      "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 1},
    })).unwrap();
    let ctx = Ctx::detached();
    assert_eq!(
      ops.restic(&request, &ctx).await.unwrap_err().code,
      ErrorCode::Busy
    );
    request.action = wharf_api_types::agent::ResticAction::Snapshots;
    ctx.cancel.cancel();
    assert_eq!(
      ops.restic(&request, &ctx).await.unwrap_err().code,
      ErrorCode::Cancelled
    );
  }

  #[test]
  fn previous_tracks_config_or_image_change() {
    assert!(has_previous("a", "b", None, None));
    assert!(has_previous("a", "a", Some("old"), Some("new")));
    assert!(!has_previous("a", "a", Some("old"), Some("old")));
    assert!(!has_previous("a", "a", None, None));
  }
}
