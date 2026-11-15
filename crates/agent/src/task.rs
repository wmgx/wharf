//! 定时任务的执行：在服务容器里执行命令，或跑一次性容器。宿主机命令走 HostExec，不在这里。

use std::{
  fs::{self, DirBuilder, OpenOptions},
  io::Write,
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{TaskHow, TaskRunJob, TaskRunResult},
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
  let output = match &job.how {
    TaskHow::Script {
      image,
      runtime,
      code,
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
      let mut vars = env.clone();
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
      let out = docker
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
        .args([
          "--entrypoint",
          entry,
          image,
          &format!("/wharf/{file}"),
        ])
        .timeout(timeout)
        .run(ctx)
        .await;
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
      exit_code: o.code,
      timed_out: false,
      output: tail(&format!("{}{}", o.stdout, o.stderr)),
      duration_ms,
    }),
    Err(e) if e.code == ErrorCode::Timeout => Ok(TaskRunResult {
      exit_code: None,
      timed_out: true,
      output: e.message,
      duration_ms,
    }),
    Err(e) => Err(e),
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
