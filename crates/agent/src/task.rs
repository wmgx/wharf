//! 定时任务的执行：在服务容器里执行命令，或跑一次性容器。宿主机命令走 HostExec，不在这里。

use std::{
  fs::{self, DirBuilder, OpenOptions},
  io::Write,
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{TASK_DATA_PREFIX, TaskHow, TaskRunJob, TaskRunResult},
  validate_name,
  view::ScriptRuntime,
};

use crate::{
  docker::{Docker, io_err},
  exec::Ctx,
};

/// 输出只留最后这么多字节。
const OUTPUT_TAIL: usize = 16 * 1024;
const QUICK: Duration = Duration::from_secs(20);
const MAX_TIMEOUT: u64 = 6 * 3600;

pub async fn run(
  docker: &Docker,
  job: &TaskRunJob,
  ctx: &Ctx,
) -> Result<TaskRunResult, ApiError> {
  validate_name("task", &job.name)?;
  if !(1..=MAX_TIMEOUT).contains(&job.timeout_secs) {
    return Err(ApiError::invalid("超时必须在 1 秒到 6 小时之间"));
  }
  let timeout = Duration::from_secs(job.timeout_secs);
  let started = Instant::now();
  let mut mem_peak = None;
  let output = match &job.how {
    TaskHow::Script {
      image,
      runtime,
      code,
      deps,
      mirrors,
      env,
    } => {
      let mut random = [0u8; 4];
      getrandom::fill(&mut random)
        .map_err(|_| ApiError::internal("随机数不可用"))?;
      let root = docker.data_dir.join("tasks");
      fs::create_dir_all(&root).map_err(io_err(&root))?;
      let dir =
        root.join(format!("{}-{}", job.name, hex::encode(random)));
      DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(io_err(&dir))?;
      let _cleanup = WorkDir(dir.clone());
      let (file, entry) = script_command(*runtime);
      write_private(&dir.join(file), code.as_bytes())?;
      let persistent = Path::new("/srv")
        .join(format!("{TASK_DATA_PREFIX}{}", job.name));
      let data_dir = persistent.join("data");
      let deps_dir = persistent.join("deps");
      for path in [&data_dir, &deps_dir] {
        fs::create_dir_all(path).map_err(io_err(path))?;
      }
      let mut vars = env.clone();
      if *runtime == ScriptRuntime::Python {
        vars.insert("PYTHONPATH".into(), "/deps".into());
      }
      if *runtime == ScriptRuntime::Node {
        fs::create_dir(dir.join("node_modules"))
          .map_err(io_err(&dir))?;
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
      let mut env_file = String::new();
      for (k, v) in vars {
        if k.is_empty() || k.contains(['=', '\n', '\r', '\0']) {
          return Err(ApiError::invalid("环境变量名无效"));
        }
        if v.contains(['\n', '\r']) {
          return Err(ApiError::invalid(format!(
            "环境变量 {k} 不能包含换行"
          )));
        }
        env_file.push_str(&format!("{k}={v}\n"));
      }
      write_private(&dir.join("env"), env_file.as_bytes())?;
      let name = format!("wharf-task-{}", job.name);
      crate::build::remove_container(docker, &name).await;
      docker.pull(image, &job.pull, ctx, &mut Vec::new()).await?;
      let execution_started = Instant::now();
      let mut install_output = String::new();
      if !deps.trim().is_empty()
        && needs_install(
          fs::read_to_string(deps_dir.join(".wharf-hash"))
            .ok()
            .as_deref(),
          image,
          deps,
        )
      {
        fs::remove_dir_all(&deps_dir).map_err(io_err(&deps_dir))?;
        fs::create_dir_all(&deps_dir).map_err(io_err(&deps_dir))?;
        write_private(
          &dir.join("requirements.txt"),
          deps.as_bytes(),
        )?;
        let install_name = format!("wharf-deps-{}", job.name);
        crate::build::remove_container(docker, &install_name).await;
        let mut cmd = docker
          .cmd()
          .args(["run", "--rm", "--name", &install_name])
          .args(["-v", &format!("{}:/deps", deps_dir.display())])
          .args(["-v", &format!("{}:/wharf:ro", dir.display())]);
        cmd = match runtime {
          ScriptRuntime::Python => {
            let mut c = cmd.args([
              "--entrypoint",
              "pip",
              image,
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
              image,
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
            exit_code: installed.code,
            timed_out: false,
            output: install_output,
            duration_ms: started.elapsed().as_millis() as u64,
            mem_peak: None,
          });
        }
        write_private(
          &deps_dir.join(".wharf-hash"),
          deps_hash(image, deps).as_bytes(),
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
        .args(["-v", &format!("{}:/data", data_dir.display())])
        .args(["-v", &format!("{}:/deps:ro", deps_dir.display())]);
      if *runtime == ScriptRuntime::Node
        && !deps.trim().is_empty()
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
          image,
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
      for (k, v) in env {
        cmd = cmd.args(["-e", &format!("{k}={v}")]);
      }
      for m in mounts {
        cmd = cmd.args(["-v", m]);
      }
      cmd = match command {
        Some(c) => cmd.args(["--entrypoint", "sh", image, "-c", c]),
        None => cmd.arg(image),
      };
      let out = cmd.timeout(timeout).run(ctx).await;
      if out.is_err() {
        crate::build::remove_container(docker, &name).await;
      }
      out
    }
  };
  let duration_ms = started.elapsed().as_millis() as u64;
  match output {
    Ok(o) => Ok(TaskRunResult {
      mem_peak,
      exit_code: o.code,
      timed_out: false,
      output: tail(&format!("{}{}", o.stdout, o.stderr)),
      duration_ms,
    }),
    Err(e) if e.code == ErrorCode::Timeout => Ok(TaskRunResult {
      mem_peak,
      exit_code: None,
      timed_out: true,
      output: e.message,
      duration_ms,
    }),
    Err(e) => Err(e),
  }
}

fn deps_hash(image: &str, deps: &str) -> String {
  hex::encode(Sha256::digest(format!("{image}\n{deps}")))
}

fn needs_install(
  hash_on_disk: Option<&str>,
  image: &str,
  deps: &str,
) -> bool {
  !deps.trim().is_empty()
    && hash_on_disk != Some(deps_hash(image, deps).as_str())
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
  let root = data_dir.join("tasks");
  match fs::remove_dir_all(root) {
    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
    _ => Ok(()),
  }
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
  fn unchanged_deps_skip_install() {
    let hash = deps_hash("python:3", "example==1");
    assert!(!needs_install(Some(&hash), "python:3", "example==1"));
    assert!(needs_install(Some(&hash), "python:4", "example==1"));
    assert!(needs_install(Some(&hash), "python:3", "example==2"));
    assert!(!needs_install(None, "python:3", "  "));
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
