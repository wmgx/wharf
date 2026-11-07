//! 定时任务的执行：在服务容器里执行命令，或跑一次性容器。宿主机命令走 HostExec，不在这里。

use std::time::{Duration, Instant};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{TaskHow, TaskRunJob, TaskRunResult},
  validate_name,
};

use crate::{docker::Docker, exec::Ctx};

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
