//! 定时任务和代登录脚本的容器执行。

use std::{
  collections::BTreeMap,
  fs::{self, DirBuilder, OpenOptions},
  io::{Read, Write},
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::{Path, PathBuf},
  sync::{Arc, LazyLock},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    TASK_DATA_PREFIX, TaskHow, TaskRunJob, TaskRunResult,
    sso_runner_name,
  },
  mask_values, validate_name,
  view::ScriptRuntime,
};

use crate::{
  docker::{Docker, io_err},
  exec::{Ctx, Output},
};

/// 输出只留最后这么多字节。
const OUTPUT_TAIL: usize = 16 * 1024;
const QUICK: Duration = Duration::from_secs(20);
const MAX_TIMEOUT: u64 = 6 * 3600;
const MAX_RESULT: u64 = 64 * 1024;
const SSO_ROOT: &str = "/srv/.wharf-sso";
const SSO_MOUNT: &str = "/wharf-sso";
const SSO_LABEL: &str = "wharf.sso-runner";
const DEPS_TIMEOUT: Duration = Duration::from_secs(10 * 60);
static SSO_ACTIVE: LazyLock<Arc<tokio::sync::RwLock<()>>> =
  LazyLock::new(Default::default);
static SSO_START: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

pub async fn run(
  docker: &Docker,
  job: &TaskRunJob,
  ctx: &Ctx,
) -> Result<TaskRunResult, ApiError> {
  validate_name("task", &job.name)?;
  if !(1..=MAX_TIMEOUT).contains(&job.timeout_secs) {
    return Err(ApiError::invalid("超时必须在 1 秒到 6 小时之间"));
  }
  if job.out_dir {
    return run_sso(docker, job, ctx).await;
  }
  let timeout = Duration::from_secs(job.timeout_secs);
  let started = Instant::now();
  let mut mem_peak = None;
  if job.network_host && !matches!(job.how, TaskHow::Script { .. }) {
    return Err(ApiError::invalid("代登录参数只能用于脚本"));
  }
  let output = match &job.how {
    TaskHow::Script {
      image,
      runtime,
      code,
      deps,
      mirrors,
      env,
    } => {
      let root = docker.data_dir.join("tasks");
      fs::create_dir_all(&root).map_err(io_err(&root))?;
      let work = work_dir(&root, &job.name)?;
      let dir = &work.0;
      let (file, entry) = script_command(*runtime);
      write_private(&dir.join(file), code.as_bytes())?;
      let persistent = Path::new("/srv")
        .join(format!("{TASK_DATA_PREFIX}{}", job.name));
      let name = format!("wharf-task-{}", job.name);
      let install_name = format!("wharf-deps-{}", job.name);
      let data_dir = persistent.join("data");
      let deps_dir = persistent.join("deps");
      let with_deps = has_effective_deps(deps);
      fs::create_dir_all(&data_dir).map_err(io_err(&data_dir))?;
      if with_deps {
        fs::create_dir_all(&deps_dir).map_err(io_err(&deps_dir))?;
      } else {
        clear_deps(&deps_dir)?;
      }
      let mut vars = env.clone();
      if with_deps && *runtime == ScriptRuntime::Python {
        vars.insert("PYTHONPATH".into(), "/deps".into());
      }
      if with_deps && *runtime == ScriptRuntime::Node {
        fs::create_dir(dir.join("node_modules"))
          .map_err(io_err(dir))?;
      }
      if let Some(input) = &job.input {
        let body = STANDARD
          .decode(&input.body)
          .map_err(|_| ApiError::invalid("请求体编码无效"))?;
        write_private(&dir.join("body"), &body)?;
        vars.insert("WHARF_METHOD".into(), input.method.clone());
        vars.insert("WHARF_QUERY".into(), input.query.clone());
        vars.insert("WHARF_BODY_FILE".into(), "/wharf/body".into());
      }
      write_env(&dir.join("env"), &vars)?;
      crate::build::remove_container(docker, &name).await;
      docker.pull(image, &job.pull, ctx, &mut Vec::new()).await?;
      let ids = if with_deps {
        docker.image_info(std::slice::from_ref(image), ctx).await
      } else {
        vec![]
      };
      let image_id = ids.first().map_or("", |i| i.id.as_str());
      let runtime_image = if image_id.is_empty() {
        image.as_str()
      } else {
        image_id
      };
      let execution_started = Instant::now();
      let mut install_output = String::new();
      if needs_install(
        fs::read_to_string(deps_dir.join(".wharf-hash"))
          .ok()
          .as_deref(),
        image,
        image_id,
        deps,
      ) {
        fs::remove_dir_all(&deps_dir).map_err(io_err(&deps_dir))?;
        fs::create_dir_all(&deps_dir).map_err(io_err(&deps_dir))?;
        write_private(
          &dir.join("requirements.txt"),
          deps.as_bytes(),
        )?;
        crate::build::remove_container(docker, &install_name).await;
        let mut cmd = docker
          .cmd()
          .args([
            "run",
            "--rm",
            "--label",
            "wharf.temp=1",
            "--name",
            &install_name,
          ])
          .args(["-v", &format!("{}:/deps", deps_dir.display())])
          .args(["-v", &format!("{}:/wharf:ro", dir.display())]);
        cmd = match runtime {
          ScriptRuntime::Python => {
            let mut c = cmd.args([
              "--entrypoint",
              "pip",
              runtime_image,
              "install",
              "--no-cache-dir",
              "--target",
              "/deps",
              "-r",
              "/wharf/requirements.txt",
            ]);
            if let Some(source) = mirrors.get("PIP_INDEX_URL") {
              c = c.args(["-i", source]);
            }
            c
          }
          ScriptRuntime::Node => {
            let mut c = cmd.args([
              "--entrypoint",
              "npm",
              runtime_image,
              "install",
              "--prefix",
              "/deps",
              "--no-audit",
              "--no-fund",
            ]);
            if let Some(source) = mirrors.get("NPM_CONFIG_REGISTRY") {
              c = c.args(["--registry", source]);
            }
            // 包名是独立参数，-- 防止清单变成 npm 选项。
            c.arg("--").args(node_packages(deps))
          }
          ScriptRuntime::Shell => {
            return Err(ApiError::invalid(
              "shell 脚本不支持依赖清单",
            ));
          }
        };
        let installed = cmd.timeout(timeout).run(ctx).await;
        if installed.is_err() {
          crate::build::remove_container(docker, &install_name).await;
        }
        let installed = installed?;
        install_output =
          tail(&format!("{}{}", installed.stdout, installed.stderr));
        if !installed.success {
          return Ok(TaskRunResult {
            result: None,
            exit_code: installed.code,
            timed_out: false,
            output: install_output,
            duration_ms: started.elapsed().as_millis() as u64,
            mem_peak: None,
          });
        }
        write_private(
          &deps_dir.join(".wharf-hash"),
          deps_hash(image, image_id, deps).as_bytes(),
        )?;
      }
      let remaining = timeout
        .checked_sub(execution_started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
          ApiError::new(ErrorCode::Timeout, "安装依赖超时")
        })?;
      let mut cmd = docker
        .cmd()
        .args(["run", "--rm", "--name", &name])
        .args(["--label", &format!("wharf.task={}", job.name)])
        .args([
          "-v",
          &format!("{}:/wharf:ro", dir.display()),
          "-w",
          "/wharf",
        ])
        .args(["--env-file", &dir.join("env").to_string_lossy()])
        .args(["-v", &format!("{}:/data", data_dir.display())]);
      if with_deps {
        cmd = cmd
          .args(["-v", &format!("{}:/deps:ro", deps_dir.display())]);
      }
      if job.network_host {
        cmd = cmd.args(["--network", "host"]);
      }
      if *runtime == ScriptRuntime::Node
        && with_deps
        && deps_dir.join("node_modules").is_dir()
      {
        cmd = cmd.args([
          "-v",
          &format!(
            "{}:/wharf/node_modules:ro",
            deps_dir.display().to_string() + "/node_modules"
          ),
        ]);
      }
      let run = cmd
        .args([
          "--entrypoint",
          entry,
          runtime_image,
          &format!("/wharf/{file}"),
        ])
        .timeout(remaining)
        .run(ctx);
      tokio::pin!(run);
      let sampling_ctx = Ctx {
        cancel: ctx.cancel.child_token(),
        progress: None,
      };
      let mut out = {
        let sample =
          sample_memory(docker, &name, &sampling_ctx, &mut mem_peak);
        tokio::pin!(sample);
        tokio::select! {
          out = &mut run => {
            sampling_ctx.cancel.cancel();
            sample.await;
            out
          },
          _ = &mut sample => run.await,
        }
      };
      sampling_ctx.cancel.cancel();
      if let Ok(ref mut output) = out {
        output.stdout = format!("{install_output}{}", output.stdout);
      }
      if out.is_err() {
        crate::build::remove_container(docker, &name).await;
      }
      out
    }
    TaskHow::Exec {
      project,
      service,
      command,
    } => {
      let id =
        find_container(docker, project, service.as_deref(), ctx)
          .await?;
      // 容器里有 timeout 就让它到点杀掉命令，免得 docker exec 被杀后命令还在容器里跑。
      let wrapper = format!(
        "command -v timeout >/dev/null 2>&1 && exec timeout -s KILL {} sh -c \"$0\" || exec sh -c \"$0\"",
        job.timeout_secs
      );
      docker
        .cmd()
        .args(["exec", &id, "sh", "-c", &wrapper, command])
        .timeout(timeout + Duration::from_secs(5))
        .run(ctx)
        .await
    }
    TaskHow::Container {
      image,
      command,
      env,
      mounts,
    } => {
      let name = format!("wharf-task-{}", job.name);
      crate::build::remove_container(docker, &name).await;
      docker.pull(image, &job.pull, ctx, &mut Vec::new()).await?;
      let mut cmd = docker
        .cmd()
        .args(["run", "--rm", "--name", &name])
        .args(["--label", &format!("wharf.task={}", job.name)]);
      let (with_env, work) =
        container_env(cmd, &docker.data_dir, &job.name, env)?;
      cmd = with_env;
      for m in mounts {
        cmd = cmd.args(["-v", m]);
      }
      cmd = match command {
        Some(c) => cmd.args(["--entrypoint", "sh", image, "-c", c]),
        None => cmd.arg(image),
      };
      let out = cmd.timeout(timeout).run(ctx).await;
      drop(work);
      if out.is_err() {
        crate::build::remove_container(docker, &name).await;
      }
      out
    }
  };
  let duration_ms = started.elapsed().as_millis() as u64;
  match output {
    Ok(o) => Ok(TaskRunResult {
      result: None,
      mem_peak,
      exit_code: o.code,
      timed_out: false,
      output: tail(&format!("{}{}", o.stdout, o.stderr)),
      duration_ms,
    }),
    Err(e) if e.code == ErrorCode::Timeout => Ok(TaskRunResult {
      result: None,
      mem_peak,
      exit_code: None,
      timed_out: true,
      output: e.message,
      duration_ms,
    }),
    Err(e) => Err(e),
  }
}

async fn run_sso(
  docker: &Docker,
  job: &TaskRunJob,
  ctx: &Ctx,
) -> Result<TaskRunResult, ApiError> {
  let TaskHow::Script {
    image,
    runtime,
    code,
    deps,
    mirrors,
    env,
  } = &job.how
  else {
    return Err(ApiError::invalid("代登录参数只能用于脚本"));
  };
  let active = SSO_ACTIVE.clone().read_owned().await;
  let dir = Path::new(SSO_ROOT).join(&job.name);
  fs::create_dir_all(&dir).map_err(io_err(&dir))?;
  let deps_dir = dir.join("deps");
  let with_deps = has_effective_deps(deps);
  let installing = || {
    ApiError::new(ErrorCode::Conflict, "代登录依赖正在安装，稍后重试")
  };
  let lock_path = dir.join("run.lock");
  let lock = OpenOptions::new()
    .create(true)
    .truncate(false)
    .write(true)
    .open(&lock_path)
    .map_err(io_err(&lock_path))?;
  loop {
    match lock.try_lock() {
      Ok(()) => break,
      Err(std::fs::TryLockError::WouldBlock) if job.wait_for_deps => {
        tokio::select! {
          _ = ctx.cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "代登录已取消")),
          _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
      }
      Err(std::fs::TryLockError::WouldBlock) => {
        return Err(if with_deps {
          installing()
        } else {
          ApiError::new(
            ErrorCode::Conflict,
            "上次代登录正在清理，请重试",
          )
        });
      }
      Err(std::fs::TryLockError::Error(e)) => {
        return Err(io_err(&lock_path)(e));
      }
    }
  }
  let name = sso_runner_name(*runtime, image);
  let mount = format!("{SSO_MOUNT}/{}", job.name);
  let runner =
    ensure_sso_runner(docker, &name, image, &job.pull, ctx).await?;
  let image_id = if with_deps {
    docker
      .cmd()
      .args(["inspect", "--format", "{{.Image}}", &runner])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("检查代登录镜像")?
      .stdout
      .trim()
      .to_string()
  } else {
    clear_deps(&deps_dir)?;
    String::new()
  };
  let needs_deps = needs_install(
    fs::read_to_string(deps_dir.join(".wharf-hash"))
      .ok()
      .as_deref(),
    image,
    &image_id,
    deps,
  );
  if needs_deps && !job.wait_for_deps {
    let (docker, deps, mirrors, ctx, hash, runtime) = (
      docker.clone(),
      deps.clone(),
      mirrors.clone(),
      Ctx {
        cancel: ctx.cancel.clone(),
        progress: None,
      },
      deps_hash(image, &image_id, deps),
      *runtime,
    );
    tokio::spawn(async move {
      let (_active, _lock) = (active, lock);
      if let Err(error) = install_sso_deps(
        &docker, &runner, &dir, &mount, runtime, &hash, &deps,
        &mirrors, &ctx,
      )
      .await
      {
        tracing::warn!(code = ?error.code, "后台安装代登录依赖失败");
      }
    });
    return Err(installing());
  }
  if needs_deps {
    install_sso_deps(
      docker,
      &runner,
      &dir,
      &mount,
      *runtime,
      &deps_hash(image, &image_id, deps),
      deps,
      mirrors,
      ctx,
    )
    .await?;
  }
  let started = Instant::now();
  let (file, entry) = script_command(*runtime);
  let node_deps = *runtime == ScriptRuntime::Node && with_deps;
  let work = work_dir(&dir, "run")?;
  let script_dir = if node_deps { &deps_dir } else { &dir };
  let script = script_dir.join(file);
  if fs::read(&script).ok().as_deref() != Some(code.as_bytes()) {
    let next = work.0.join(file);
    write_private(&next, code.as_bytes())?;
    fs::rename(&next, &script).map_err(io_err(&script))?;
  }
  let work_name = work.0.file_name().unwrap().to_string_lossy();
  let mut vars = env.clone();
  vars.insert(
    "WHARF_OUT".into(),
    format!("{mount}/{work_name}/result.json"),
  );
  if *runtime == ScriptRuntime::Python && with_deps {
    vars.insert("PYTHONPATH".into(), format!("{mount}/deps"));
  }
  let env_file = work.0.join("env");
  write_env(&env_file, &vars)?;
  let timeout = Duration::from_secs(job.timeout_secs.min(60));
  let script_path = if node_deps {
    format!("deps/{file}")
  } else {
    file.into()
  };
  let args = sso_exec_args(
    &runner,
    &env_file,
    &mount,
    timeout,
    [entry, &script_path],
  );
  let output = sso_exec(docker, args, &runner, timeout, ctx).await;
  let hidden: Vec<String> = env
    .values()
    .filter(|value| !value.is_empty())
    .cloned()
    .collect();
  let duration_ms = started.elapsed().as_millis() as u64;
  match output {
    Ok(o) => Ok(TaskRunResult {
      result: read_result(&work.0),
      mem_peak: None,
      exit_code: o.code,
      timed_out: o.code == Some(137),
      output: tail(&mask_values(
        &format!("{}{}", o.stdout, o.stderr),
        &hidden,
      )),
      duration_ms,
    }),
    Err(e) if e.code == ErrorCode::Timeout => Ok(TaskRunResult {
      result: None,
      mem_peak: None,
      exit_code: None,
      timed_out: true,
      output: e.message,
      duration_ms,
    }),
    Err(e) => Err(e),
  }
}

async fn ensure_sso_runner(
  docker: &Docker,
  name: &str,
  image: &str,
  pull: &wharf_api_types::agent::PullPolicy,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let _start = tokio::select! {
    guard = SSO_START.lock() => guard,
    _ = ctx.cancel.cancelled() => return Err(ApiError::new(ErrorCode::Cancelled, "代登录已取消")),
  };
  let existing = docker
    .cmd()
    .args([
      "ps",
      "-aq",
      "--no-trunc",
      "--filter",
      &format!("name=^/{name}$"),
      "--filter",
      &format!("label={SSO_LABEL}"),
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("查找代登录容器")?;
  let id = existing.stdout.trim();
  if !id.is_empty() {
    let state = docker
      .cmd()
      .args(["inspect", "--format", "{{.State.Running}}", id])
      .timeout(QUICK)
      .run(ctx)
      .await?
      .check("检查代登录容器")?;
    if state.stdout.trim() != "true" {
      docker
        .cmd()
        .args(["start", id])
        .timeout(QUICK)
        .run(ctx)
        .await?
        .check("启动代登录容器")?;
    }
    return Ok(id.into());
  }
  if !docker.image_exists(image, ctx).await {
    docker.pull(image, pull, ctx, &mut Vec::new()).await?;
  }
  let out = docker
    .cmd()
    .args([
      "run",
      "-di",
      "--init",
      "--name",
      name,
      "--label",
      SSO_LABEL,
      "--network",
      "host",
      "--restart",
      "unless-stopped",
      "-v",
      &format!("{SSO_ROOT}:{SSO_MOUNT}"),
      "--entrypoint",
      "sh",
      image,
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("创建代登录容器")?;
  Ok(out.stdout.trim().into())
}

fn sso_exec_args(
  runner: &str,
  env_file: &Path,
  mount: &str,
  timeout: Duration,
  command: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
  [
    "exec", "--env-file", &env_file.to_string_lossy(), "-w", mount,
    runner, "sh", "-c",
    r#"seconds=$1; shift; if command -v timeout >/dev/null 2>&1; then exec timeout -s KILL "$seconds" "$@"; fi; exec "$@""#,
    "sh", &timeout.as_secs().to_string(),
  ].into_iter().map(str::to_string).chain(command.into_iter().map(Into::into)).collect()
}

// 容器内外的超时和取消都可能留下子进程，重启可确认它们已退出。
async fn sso_exec(
  docker: &Docker,
  args: Vec<String>,
  runner: &str,
  timeout: Duration,
  ctx: &Ctx,
) -> Result<Output, ApiError> {
  if ctx.cancel.is_cancelled() {
    return Err(ApiError::new(ErrorCode::Cancelled, "代登录已取消"));
  }
  let out = docker
    .cmd()
    .args(args)
    .timeout(timeout + Duration::from_secs(2))
    .run(ctx)
    .await;
  if !out.as_ref().is_ok_and(|o| o.code != Some(137)) {
    docker
      .cmd()
      .args(["restart", "-t", "0", runner])
      .timeout(QUICK)
      .run(&Ctx::detached())
      .await?
      .check("回收代登录进程")?;
  }
  out
}

#[allow(clippy::too_many_arguments)]
async fn install_sso_deps(
  docker: &Docker,
  runner: &str,
  dir: &Path,
  mount: &str,
  runtime: ScriptRuntime,
  hash: &str,
  deps: &str,
  mirrors: &BTreeMap<String, String>,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  let deps_dir = dir.join("deps");
  if let Err(e) = fs::remove_dir_all(&deps_dir)
    && e.kind() != std::io::ErrorKind::NotFound
  {
    return Err(io_err(&deps_dir)(e));
  }
  fs::create_dir(&deps_dir).map_err(io_err(&deps_dir))?;
  let work = work_dir(dir, "run")?;
  let env_file = work.0.join("env");
  let source = match runtime {
    ScriptRuntime::Python => "PIP_INDEX_URL",
    ScriptRuntime::Node => "NPM_CONFIG_REGISTRY",
    ScriptRuntime::Shell => {
      return Err(ApiError::invalid("shell 脚本不支持依赖清单"));
    }
  };
  let vars = mirrors
    .get(source)
    .map(|value| (source.to_string(), value.clone()))
    .into_iter()
    .collect();
  write_env(&env_file, &vars)?;
  let target = format!("{mount}/deps");
  let requirements;
  let command = match runtime {
    ScriptRuntime::Python => {
      let file = "requirements.txt";
      write_private(&work.0.join(file), deps.as_bytes())?;
      let work_name = work.0.file_name().unwrap().to_string_lossy();
      requirements = format!("{mount}/{work_name}/{file}");
      vec![
        "pip",
        "install",
        "--no-cache-dir",
        "--target",
        &target,
        "-r",
        &requirements,
      ]
    }
    ScriptRuntime::Node => {
      let mut args = vec![
        "npm",
        "install",
        "--prefix",
        &target,
        "--no-audit",
        "--no-fund",
        "--",
      ];
      args.extend(node_packages(deps));
      args
    }
    ScriptRuntime::Shell => unreachable!(),
  };
  let args =
    sso_exec_args(runner, &env_file, mount, DEPS_TIMEOUT, command);
  let out = sso_exec(docker, args, runner, DEPS_TIMEOUT, ctx).await?;
  if !out.success {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      "安装代登录依赖失败",
    ));
  }
  write_private(&deps_dir.join(".wharf-hash"), hash.as_bytes())
}

pub async fn cleanup_sso(
  docker: &Docker,
  domains: &[String],
  runners: &[String],
  ctx: &Ctx,
) -> Result<(), ApiError> {
  // 正在登录或安装依赖时等下一轮，避免删正在使用的容器或目录。
  let Ok(_idle) = SSO_ACTIVE.try_write() else {
    return Ok(());
  };
  let out = docker
    .cmd()
    .args([
      "ps",
      "-a",
      "--filter",
      &format!("label={SSO_LABEL}"),
      "--format",
      "{{.Names}}",
    ])
    .timeout(QUICK)
    .run(ctx)
    .await?
    .check("列出代登录容器")?;
  for name in out.stdout.lines() {
    if !runners.iter().any(|runner| runner == name) {
      docker
        .cmd()
        .args(["rm", "-f", name])
        .timeout(QUICK)
        .run(ctx)
        .await?
        .check("删除闲置代登录容器")?;
    }
  }
  let root = Path::new(SSO_ROOT);
  if !root.exists() {
    return Ok(());
  }
  for entry in fs::read_dir(root).map_err(io_err(root))? {
    let entry = entry.map_err(io_err(root))?;
    let name = entry.file_name();
    let name = name.to_string_lossy();
    if name.len() != 32
      || !name.bytes().all(|c| c.is_ascii_hexdigit())
      || !entry.file_type().map_err(io_err(root))?.is_dir()
    {
      continue;
    }
    let dir = entry.path();
    if !domains.iter().any(|domain| domain == &name) {
      fs::remove_dir_all(&dir).map_err(io_err(&dir))?;
    } else {
      for work in fs::read_dir(&dir).map_err(io_err(&dir))? {
        let work = work.map_err(io_err(&dir))?;
        let name = work.file_name();
        if name.to_string_lossy().starts_with("run-")
          && work.file_type().map_err(io_err(&dir))?.is_dir()
        {
          fs::remove_dir_all(work.path()).map_err(io_err(&dir))?;
        }
      }
    }
  }
  Ok(())
}

fn container_env(
  cmd: crate::exec::Cmd,
  data_dir: &Path,
  name: &str,
  env: &BTreeMap<String, String>,
) -> Result<(crate::exec::Cmd, Option<WorkDir>), ApiError> {
  if env.is_empty() {
    return Ok((cmd, None));
  }
  let root = data_dir.join("tasks");
  fs::create_dir_all(&root).map_err(io_err(&root))?;
  let work = work_dir(&root, name)?;
  let file = work.0.join("env");
  write_env(&file, env)?;
  Ok((
    cmd.args(["--env-file", &file.to_string_lossy()]),
    Some(work),
  ))
}

fn write_env(
  path: &Path,
  vars: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
  let mut text = String::new();
  for (k, v) in vars {
    if k.is_empty() || k.contains(['=', '\n', '\r', '\0']) {
      return Err(ApiError::invalid("环境变量名无效"));
    }
    if v.contains(['\n', '\r', '\0']) {
      return Err(ApiError::invalid(format!(
        "环境变量 {k} 不能包含换行或空字符"
      )));
    }
    text.push_str(&format!("{k}={v}\n"));
  }
  write_private(path, text.as_bytes())
}

fn read_result(out: &Path) -> Option<String> {
  let file = OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
    .open(out.join("result.json"))
    .ok()?;
  if !file.metadata().ok()?.is_file() {
    return None;
  }
  let mut bytes = Vec::new();
  file.take(MAX_RESULT + 1).read_to_end(&mut bytes).ok()?;
  if bytes.len() as u64 > MAX_RESULT {
    return None;
  }
  String::from_utf8(bytes).ok()
}

fn clear_deps(path: &Path) -> Result<(), ApiError> {
  match fs::remove_dir_all(path) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(io_err(path)(e)),
  }
}

fn has_effective_deps(deps: &str) -> bool {
  deps
    .lines()
    .map(str::trim)
    .any(|l| !l.is_empty() && !l.starts_with('#'))
}

fn deps_hash(image: &str, image_id: &str, deps: &str) -> String {
  let key = if image_id.is_empty() { image } else { image_id };
  hex::encode(Sha256::digest(format!("{image}\n{key}\n{deps}")))
}

fn needs_install(
  hash: Option<&str>,
  image: &str,
  image_id: &str,
  deps: &str,
) -> bool {
  has_effective_deps(deps)
    && hash != Some(deps_hash(image, image_id, deps).as_str())
}

fn node_packages(deps: &str) -> Vec<&str> {
  deps
    .lines()
    .map(str::trim)
    .filter(|s| !s.is_empty() && !s.starts_with('#'))
    .collect()
}

async fn sample_memory(
  docker: &Docker,
  name: &str,
  ctx: &Ctx,
  peak: &mut Option<u64>,
) {
  let mut interval = tokio::time::interval(Duration::from_secs(2));
  interval.tick().await;
  loop {
    tokio::select! {
      _ = ctx.cancel.cancelled() => return,
      _ = interval.tick() => {},
    }
    if let Ok(out) = docker
      .cmd()
      .args([
        "stats",
        "--no-stream",
        "--format",
        "{{.MemUsage}}",
        name,
      ])
      .timeout(QUICK)
      .run(ctx)
      .await
      && out.success
      && !out.stdout.trim().is_empty()
    {
      let bytes = crate::metrics::first_size(&out.stdout);
      *peak = Some(peak.unwrap_or(0).max(bytes));
    }
  }
}

/// compose 项目里在运行的容器；`service` 不填时必须只有一个。
async fn find_container(
  docker: &Docker,
  project: &str,
  service: Option<&str>,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let mut cmd = docker.cmd().args([
    "ps",
    "-q",
    "--filter",
    &format!("label=com.docker.compose.project={project}"),
  ]);
  if let Some(s) = service {
    cmd = cmd.args([
      "--filter",
      &format!("label=com.docker.compose.service={s}"),
    ]);
  }
  let out = cmd.timeout(QUICK).run(ctx).await?.check("查找容器")?;
  let ids: Vec<&str> = out.stdout.split_whitespace().collect();
  match ids.as_slice() {
    [id] => Ok(id.to_string()),
    [] => Err(ApiError::new(
      ErrorCode::NotFound,
      format!("服务 {project} 没有在运行的容器"),
    )),
    _ => Err(
      ApiError::invalid(format!("服务 {project} 有多个容器"))
        .with_hint("在任务里指定 compose 服务名（container）"),
    ),
  }
}

/// 最后 [OUTPUT_TAIL] 字节，从完整的字符开始。
fn tail(s: &str) -> String {
  if s.len() <= OUTPUT_TAIL {
    return s.to_string();
  }
  let mut start = s.len() - OUTPUT_TAIL;
  while !s.is_char_boundary(start) {
    start += 1;
  }
  format!("…{}", &s[start..])
}

fn work_dir(root: &Path, prefix: &str) -> Result<WorkDir, ApiError> {
  let mut random = [0u8; 12];
  getrandom::fill(&mut random)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  let dir = root.join(format!("{prefix}-{}", hex::encode(random)));
  DirBuilder::new()
    .mode(0o700)
    .create(&dir)
    .map_err(io_err(&dir))?;
  Ok(WorkDir(dir))
}

struct WorkDir(PathBuf);

impl Drop for WorkDir {
  fn drop(&mut self) {
    if fs::remove_dir_all(&self.0).is_err() {
      tracing::warn!("清理脚本工作目录失败");
    }
  }
}

/// 启动时清掉上次进程被杀后留下的脚本文件。
pub fn cleanup(data_dir: &Path) -> std::io::Result<()> {
  for dir in ["tasks", "sso-scripts"] {
    if let Err(e) = fs::remove_dir_all(data_dir.join(dir))
      && e.kind() != std::io::ErrorKind::NotFound
    {
      return Err(e);
    }
  }
  Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), ApiError> {
  OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(path)
    .and_then(|mut f| f.write_all(data))
    .map_err(io_err(path))
}

fn script_command(
  runtime: ScriptRuntime,
) -> (&'static str, &'static str) {
  match runtime {
    ScriptRuntime::Python => ("main.py", "python"),
    ScriptRuntime::Node => ("main.js", "node"),
    ScriptRuntime::Shell => ("main.sh", "sh"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sso_credentials_only_go_in_env_file() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("env");
    let value = "fixture-value";
    write_env(
      &env_file,
      &BTreeMap::from([("WHARF_PASSWORD".into(), value.into())]),
    )
    .unwrap();
    let args = sso_exec_args(
      "runner",
      &env_file,
      "/work",
      Duration::from_secs(30),
      ["python", "main.py"],
    );
    assert_eq!(
      &args[..3],
      ["exec", "--env-file", env_file.to_str().unwrap()]
    );
    assert!(args.iter().all(|arg| !arg.contains(value)));
  }

  #[test]
  fn unchanged_deps_skip_install() {
    let hash = deps_hash("python:3", "sha256:aaa", "example==1");
    assert!(!needs_install(
      Some(&hash),
      "python:3",
      "sha256:aaa",
      "example==1"
    ));
    assert!(needs_install(
      Some(&hash),
      "python:4",
      "sha256:aaa",
      "example==1"
    ));
    assert!(needs_install(
      Some(&hash),
      "python:3",
      "sha256:aaa",
      "example==2"
    ));
    assert!(!needs_install(None, "python:3", "sha256:aaa", "  "));
  }

  #[test]
  fn node_dependency_lines() {
    assert_eq!(
      node_packages("\n # 注释\n example@1 \n\n@scope/pkg@2\n"),
      vec!["example@1", "@scope/pkg@2"]
    );
  }

  #[test]
  fn script_commands() {
    assert_eq!(
      script_command(ScriptRuntime::Python),
      ("main.py", "python")
    );
    assert_eq!(
      script_command(ScriptRuntime::Node),
      ("main.js", "node")
    );
    assert_eq!(
      script_command(ScriptRuntime::Shell),
      ("main.sh", "sh")
    );
  }
}

#[tokio::test]
async fn container_env_file_is_private_and_removed() {
  use std::os::unix::fs::PermissionsExt;
  let data = tempfile::tempdir().unwrap();
  let env =
    BTreeMap::from([("DB_PASS".into(), "fixture-secret".into())]);
  let cmd = crate::exec::Cmd::new("sh").args([
    "-c",
    "printf '%s\n' \"$@\"",
    "sh",
  ]);
  let (cmd, work) =
    container_env(cmd, data.path(), "t1", &env).unwrap();
  let work = work.unwrap();
  let file = work.0.join("env");
  assert_eq!(
    fs::metadata(&file).unwrap().permissions().mode() & 0o777,
    0o600
  );
  assert_eq!(
    fs::read_to_string(&file).unwrap(),
    "DB_PASS=fixture-secret\n"
  );
  let output = cmd.run(&crate::exec::Ctx::detached()).await.unwrap();
  assert_eq!(
    output.stdout.lines().collect::<Vec<_>>(),
    ["--env-file", file.to_str().unwrap()]
  );
  drop(work);
  assert!(!file.exists());
}
