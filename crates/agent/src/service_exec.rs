use std::{
  collections::BTreeMap,
  path::Path,
  process::Stdio,
  time::{Duration, Instant},
};

use tokio::process::Command;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    HostExecFailure, HostExecResult, ServiceExecJob,
    ServiceExecOutcome,
  },
  validate_container_name, validate_name,
};

use crate::{
  docker::Docker,
  exec::{Ctx, Output, kill_group},
  host_shell::{
    StreamOutput, capture, complete_output, finish_capture,
    finish_stderr, random_id,
  },
};

const QUICK: Duration = Duration::from_secs(5);
const WRAPPER: &str = r#"
umask 077
if ! command -v setsid >/dev/null 2>&1 || ! mkdir "$2"; then
  [ "$4" = legacy ] || exit 125
  # shortcut: 旧任务继续在极简镜像运行，镜像有 setsid 和可写 /tmp 后才能即时取消整个进程组。
  script='sh -c "$1"; rc=$?; printf "\n%s:DONE:%d\n" "$2" "$rc" >&2; exit "$rc"'
  if command -v timeout >/dev/null 2>&1; then
    timeout -s KILL "$5" sh -c "$script" _ "$1" "$3"
  else
    sh -c "$script" _ "$1" "$3"
  fi
  rc=$?
  printf '\n%s:WRAP:%d\n' "$3" "$rc" >&2
  exit "$rc"
fi
trap 'rm -f "$2/pid"; rmdir "$2"' EXIT
exec 3<&0
setsid sh -c '
  printf "%s\n" "$$" > "$2/pid" || exit 125
  if [ "$4" = stdin ]; then sh -s; else sh -c "$1"; fi
  rc=$?
  printf "\n%s:DONE:%d\n" "$3" "$rc" >&2
  exit "$rc"
' _ "$1" "$2" "$3" "$4" <&3 3<&- &
pid=$!
wait "$pid"
rc=$?
kill -KILL "-$pid" 2>/dev/null || true
printf '\n%s:WRAP:%d\n' "$3" "$rc" >&2
exit "$rc"
"#;
const CLEANUP: &str = r#"
if read -r pid < "$1/pid"; then
  case "$pid" in ''|*[!0-9]*) exit 1;; esac
  [ "$pid" -gt 1 ] || exit 1
  if [ -r "/proc/$pid/stat" ]; then
    read -r stat < "/proc/$pid/stat" || exit 0
    set -- ${stat##*) }
    if [ "$3" = "$pid" ] && [ "$4" = "$pid" ]; then
      kill -KILL "-$pid" 2>/dev/null || [ ! -d "/proc/$pid" ]
    fi
  fi
fi
"#;

async fn find(
  docker: &Docker,
  job: &ServiceExecJob,
  ctx: &Ctx,
) -> Result<(String, String), ApiError> {
  validate_name("service", &job.project)?;
  if let Some(c) = &job.container {
    validate_container_name(c)?;
  }
  let dir = docker.project_dir(&job.project);
  let out = docker.cmd().args([
    "ps", "--no-trunc", "--filter", &format!("label=com.docker.compose.project={}", job.project),
    "--filter", "status=running", "--format",
    "{{.ID}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}",
  ]).timeout(QUICK).run(ctx).await?.check("查找运行中的子容器")?;
  let containers: Vec<_> = out
    .stdout
    .lines()
    .filter_map(|line| {
      let mut parts = line.splitn(3, '\t');
      let (id, service, working_dir) =
        (parts.next()?, parts.next()?, parts.next()?);
      (Path::new(working_dir) == dir
        && !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_hexdigit())
        && validate_container_name(service).is_ok())
      .then_some((id, service))
    })
    .collect();
  let names = containers
    .iter()
    .map(|(_, name)| *name)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>()
    .join("、");
  let choices: Vec<_> = containers
    .into_iter()
    .filter(|(_, name)| {
      job.container.as_deref().is_none_or(|c| c == *name)
    })
    .collect();
  match choices.as_slice() {
    [(id, name)] => Ok((id.to_string(), name.to_string())),
    [] => Err(
      ApiError::not_found(format!(
        "服务 {} 没有匹配的运行中容器",
        job.project
      ))
      .with_hint(format!("运行中的子容器：{names}")),
    ),
    _ => Err(
      ApiError::invalid(format!(
        "服务 {} 有多个匹配的运行中容器",
        job.project
      ))
      .with_hint(format!("用 --container 指定子容器：{names}")),
    ),
  }
}

pub(crate) async fn run(
  docker: &Docker,
  job: ServiceExecJob,
  ctx: &Ctx,
) -> ServiceExecOutcome {
  let started = Instant::now();
  match run_service(docker, job, ctx).await {
    Ok((container, mut result)) => {
      result.duration_ms = started.elapsed().as_millis() as u64;
      ServiceExecOutcome::Finished { container, result }
    }
    Err((error, output_bytes)) => {
      ServiceExecOutcome::Failed(HostExecFailure {
        error,
        output_bytes,
        duration_ms: started.elapsed().as_millis() as u64,
      })
    }
  }
}

async fn run_service(
  docker: &Docker,
  job: ServiceExecJob,
  ctx: &Ctx,
) -> Result<(String, HostExecResult), (ApiError, u64)> {
  if job.command.trim().is_empty()
    || job.command.len() > 64 * 1024
    || job.command.contains('\0')
    || !(1..=600).contains(&job.timeout_secs)
    || job.cwd.as_deref().is_some_and(|cwd| {
      cwd.contains('\0') || !Path::new(cwd).is_absolute()
    })
  {
    return Err((
      ApiError::invalid("容器内命令、工作目录或超时不合法"),
      0,
    ));
  }
  let (id, name) =
    find(docker, &job, ctx).await.map_err(|e| (e, 0))?;
  let mut cmd = Command::new(&docker.bin);
  cmd.arg("exec");
  if let Some(cwd) = job.cwd {
    cmd.args(["-w", &cwd]);
  }
  let session = Session::new();
  cmd.arg(&id).args(session.args(&job.command, "", "0"));
  cmd
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .process_group(0);
  let mut child = cmd
    .spawn()
    .map_err(|_| (ApiError::internal("无法启动容器命令"), 0))?;
  let pid = child.id();
  let stream = StreamOutput::new(job.stream, ctx);
  let mut stdout =
    tokio::spawn(capture(child.stdout.take(), stream.clone(), false));
  let mut stderr =
    tokio::spawn(capture(child.stderr.take(), stream.clone(), true));
  let end = tokio::select! {
    result = child.wait() => result.map_err(|_| ApiError::internal("等待容器命令失败")),
    () = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "容器命令已取消")),
    () = tokio::time::sleep(Duration::from_secs(job.timeout_secs)) => Err(ApiError::new(ErrorCode::Timeout, "容器命令超时")),
  };
  if end.is_err() {
    let ((), ()) = tokio::join!(
      kill_group(pid, &mut child),
      session.cleanup(docker, &id)
    );
  }
  let out = finish_capture(&mut stdout).await;
  let err = finish_capture(&mut stderr).await;
  let bytes = out.total.saturating_add(err.total);
  end.map_err(|e| (e, bytes))?;
  let (err, exit_code) =
    session.finish(err).map_err(|e| (e, bytes))?;
  let output_bytes = out.total.saturating_add(err.total);
  let (stdout, stderr, truncated) =
    complete_output(out, err, stream.as_ref());
  Ok((
    name,
    HostExecResult {
      exit_code,
      stdout,
      stderr,
      truncated,
      duration_ms: 0,
      output_bytes,
    },
  ))
}

struct Session {
  dir: String,
  marker: String,
}

impl Session {
  fn new() -> Self {
    let id = random_id();
    Self {
      dir: format!("/tmp/.wharf-exec-{id}"),
      marker: format!("__WHARF_SE_{id}__"),
    }
  }

  fn args<'a>(
    &'a self,
    command: &'a str,
    input: &'a str,
    timeout: &'a str,
  ) -> [&'a str; 9] {
    [
      "sh",
      "-c",
      WRAPPER,
      "wharf-service-exec",
      command,
      &self.dir,
      &self.marker,
      input,
      timeout,
    ]
  }

  fn finish(
    &self,
    err: crate::host_shell::Captured,
  ) -> Result<(crate::host_shell::Captured, i32), ApiError> {
    let wrap = format!("\n{}:WRAP:", self.marker);
    let done = format!("\n{}:DONE:", self.marker);
    let (err, _) = finish_stderr(err, wrap.as_bytes())
      .map_err(|_| no_exec_status())?;
    finish_stderr(err, done.as_bytes()).map_err(|_| no_exec_status())
  }

  async fn cleanup(&self, docker: &Docker, id: &str) {
    let ctx = Ctx::detached();
    for _ in 0..2 {
      let _ = docker
        .cmd()
        .args(["exec", id, "sh", "-c", CLEANUP, "_", &self.dir])
        .timeout(Duration::from_secs(2))
        .run(&ctx)
        .await;
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  }
}

fn no_exec_status() -> ApiError {
  ApiError::new(ErrorCode::AgentFailed, "容器命令没有返回退出状态")
    .with_hint("确认镜像包含 sh、setsid 且容器内 /tmp 可写")
}

pub(crate) async fn run_task(
  docker: &Docker,
  id: &str,
  command: &str,
  env: &BTreeMap<String, String>,
  timeout: Duration,
  ctx: &Ctx,
) -> Result<(Output, bool), ApiError> {
  let session = Session::new();
  let mut cmd = docker.cmd().arg("exec");
  let cmd = if env.is_empty() {
    cmd.arg(id).args(session.args(
      command,
      "legacy",
      &timeout.as_secs().to_string(),
    ))
  } else {
    // 通过标准输入传入，值既不进 argv，也不进入本地 Docker CLI 的环境。
    let mut script = String::from("{\n");
    for (key, value) in env {
      let mut bytes = key.bytes();
      if !bytes
        .next()
        .is_some_and(|b| b == b'_' || b.is_ascii_alphabetic())
        || !bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
        || value.contains('\0')
      {
        return Err(ApiError::invalid("临时环境变量不合法"));
      }
      script
        .push_str(&format!("export {key}={}\n", shell_quote(value)));
    }
    script.push_str(&format!(
      "exec sh -c {} </dev/null\n}}\n",
      shell_quote(command)
    ));
    cmd = cmd.arg("-i");
    cmd
      .arg(id)
      .args(session.args("", "stdin", "0"))
      .input(script.into_bytes())
  }
  .timeout(timeout);
  let result =
    crate::task::run_wrapped(cmd, &session.marker, ctx).await;
  if result.is_err()
    || result.as_ref().is_ok_and(|(_, timed_out)| *timed_out)
  {
    session.cleanup(docker, id).await;
  }
  result
}

fn shell_quote(value: &str) -> String {
  format!("'{}'", value.replace('\'', "'\"'\"'"))
}
