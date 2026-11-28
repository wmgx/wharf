//! 部署后观察一会儿：容器起来马上又退出、反复重启、镜像自带的健康检查不通过，
//! 都算没起来。`up -d` 返回时容器只是"创建并启动了"，不代表能用。

use std::{collections::HashMap, time::Duration};

use tokio::time::{Instant, sleep_until, timeout_at};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{HttpCheck, ProjectState, SettleProbe, judge_http_check},
};

use crate::{docker::Docker, exec::Ctx};

/// 至少观察这么久。
const MIN_WATCH: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_secs(2);

pub struct WatchOptions<'a> {
  pub max_watch: Duration,
  pub readiness: Option<&'a SettleProbe>,
}

pub fn max_watch(seconds: Option<u32>) -> Duration {
  Duration::from_secs(u64::from(
    seconds.unwrap_or(120).clamp(1, 1800),
  ))
}

pub async fn watch(
  docker: &Docker,
  project: &str,
  opts: WatchOptions<'_>,
  ctx: &Ctx,
) -> Result<ProjectState, ApiError> {
  ctx.say("观察容器是否稳定运行");
  let start = Instant::now();
  let deadline = start + opts.max_watch;
  let stable_at = deadline.min(start + MIN_WATCH);
  let mut last_state = None;
  let mut restarted = vec![];
  let mut last_probe = None;
  let mut readiness_ok = opts.readiness.is_none();
  let result = async {
    if let Some(probe) = opts.readiness {
      let local =
        reqwest::Url::parse(&probe.url).ok().is_some_and(|u| {
          u.scheme() == "http"
            && u.host_str() == Some("127.0.0.1")
            && u.username().is_empty()
            && u.password().is_none()
        });
      if !local {
        return Err(ApiError::invalid(
          "就绪探活地址必须是本机 HTTP 地址",
        ));
      }
    }
    let mut restarts_before = None;
    loop {
      let sampled_at = Instant::now();
      let final_check = sampled_at >= deadline;
      // 到点重新读一次 Docker，给这次复查留独立的 I/O 时间。
      let read_deadline = if final_check {
        sampled_at + POLL
      } else {
        deadline
      };
      let watch_ctx = Ctx {
        cancel: ctx.cancel.child_token(),
        progress: ctx.progress.clone(),
      };
      let cancel = watch_ctx.cancel.clone();
      let timer = tokio::spawn(async move {
        sleep_until(read_deadline).await;
        cancel.cancel();
      });
      let observed = async {
        let state = docker.one_status(project, &watch_ctx).await?;
        last_state = Some(state);
        let state = last_state.as_ref().unwrap();
        if let Some(bad) = problem(state) {
          return Err(failed(project, bad));
        }
        Ok(restart_counts(docker, state, &watch_ctx).await)
      }
      .await;
      timer.abort();
      if ctx.cancel.is_cancelled() {
        return Err(cancelled());
      }
      let restarts = match observed {
        Ok(restarts) => restarts,
        Err(e)
          if e.code == ErrorCode::Cancelled
            && watch_ctx.cancel.is_cancelled() =>
        {
          HashMap::new()
        }
        Err(e) => return Err(e),
      };
      if watch_ctx.cancel.is_cancelled() {
        if final_check {
          return Err(cancelled());
        }
        // 中途读 Docker 跨过截止点时，重新取一次当前状态。
        continue;
      }
      let state = last_state.as_ref().unwrap();
      let baseline =
        restarts_before.get_or_insert_with(|| restarts.clone());
      restarted = state
        .containers
        .iter()
        .filter(|c| !c.foreign)
        .filter(|c| {
          restarts.get(&c.name).copied().unwrap_or(0)
            > baseline.get(&c.name).copied().unwrap_or(0)
        })
        .map(|c| c.name.clone())
        .collect();
      if !restarted.is_empty() {
        return Err(failed(
          project,
          format!("{} 退出后被重启", restarted.join("、")),
        ));
      }
      let starting = starting(state);
      if let Some(probe) =
        opts.readiness.filter(|_| !starting && !readiness_ok)
      {
        let rem = deadline.saturating_duration_since(Instant::now());
        if !rem.is_zero() {
          let probe_result = timeout_at(
            deadline,
            crate::probe::http(HttpCheck {
              headers: probe.headers.clone(),
              url: probe.url.clone(),
              keyword: probe.keyword.clone(),
              timeout_secs: rem.as_secs().clamp(1, 5),
            }),
          );
          let r = tokio::select! {
            r = probe_result => r,
            _ = ctx.cancel.cancelled() => return Err(cancelled()),
          };
          if let Ok(r) = r {
            let (ok, detail) = judge_http_check(
              probe.expect,
              probe.keyword.as_deref(),
              &r,
            );
            if ok {
              readiness_ok = true;
              ctx.say(format!("就绪探活通过：{detail}"));
            } else {
              last_probe = Some(detail);
            }
          }
        }
      }
      if !starting && readiness_ok && sampled_at >= stable_at {
        ctx.say("容器运行正常");
        return Ok(last_state.take().unwrap());
      }
      if final_check {
        return Err(cancelled());
      }
      let now = Instant::now();
      let next = if sampled_at < stable_at {
        (now + POLL).min(stable_at)
      } else {
        now + POLL
      };
      tokio::select! {
        _ = ctx.cancel.cancelled() => return Err(cancelled()),
        _ = sleep_until(next.min(deadline)) => {}
      }
    }
  }
  .await;
  if ctx.cancel.is_cancelled() {
    return Err(cancelled());
  }
  let result = match result {
    Err(e) if e.code == ErrorCode::Cancelled => {
      let secs = opts.max_watch.as_secs();
      let error = failed(
        project,
        timeout_detail(
          secs,
          last_state.as_ref().is_some_and(starting),
          readiness_ok,
          last_probe.as_deref(),
        ),
      );
      Err(if secs == 120 {
        error.with_hint("启动较慢的服务可通过 wharf service deploy <服务> --start-timeout <秒> 调大上限")
      } else {
        error
      })
    }
    other => other,
  };
  if result.is_err() {
    emit_crash_logs(
      docker,
      project,
      last_state.as_ref(),
      &restarted,
      ctx,
    )
    .await;
  }
  result
}

fn timeout_detail(
  secs: u64,
  starting: bool,
  readiness_ok: bool,
  last_probe: Option<&str>,
) -> String {
  if starting {
    format!("健康检查 {secs} 秒内没有通过")
  } else if !readiness_ok {
    let last = last_probe.unwrap_or("没有应答");
    format!("就绪探活 {secs} 秒内没有通过（最后一次：{last}）")
  } else {
    format!("{secs} 秒内未能确认容器稳定运行")
  }
}

fn cancelled() -> ApiError {
  ApiError::new(ErrorCode::Cancelled, "已取消")
}

pub async fn emit_crash_logs(
  docker: &Docker,
  project: &str,
  state: Option<&ProjectState>,
  restarted: &[String],
  ctx: &Ctx,
) {
  if ctx.cancel.is_cancelled() {
    return;
  }
  let detached = Ctx {
    cancel: ctx.cancel.child_token(),
    progress: None,
  };
  let cancel = detached.cancel.clone();
  let timer = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(10)).await;
    cancel.cancel();
  });
  let queried = if state.is_none() {
    docker.one_status(project, &detached).await.ok()
  } else {
    None
  };
  let mut lines = vec![];
  if let Some(state) = state.or(queried.as_ref()) {
    let owned: Vec<_> =
      state.containers.iter().filter(|c| !c.foreign).collect();
    let has_running = owned.iter().any(|c| c.is_running());
    let mut targets: Vec<_> = owned
      .iter()
      .copied()
      .filter(|c| {
        !c.is_healthy_state(has_running)
          || c.health.as_deref() == Some("unhealthy")
          || restarted.contains(&c.name)
      })
      .collect();
    if targets.is_empty() {
      targets = owned;
    }
    let multi = targets.len() > 1;
    if !targets.is_empty() {
      let per = (50 / targets.len()).clamp(10, 50);
      for c in targets {
        if let Ok(logs) = docker
          .container_logs(&c.name, per as u32, None, &detached)
          .await
        {
          let prefix = if multi {
            format!("[{}] ", c.service)
          } else {
            String::new()
          };
          lines.extend(crash_lines(&logs, per, &prefix));
        }
        if lines.len() >= 50 || detached.cancel.is_cancelled() {
          break;
        }
      }
    }
  }
  timer.abort();
  if ctx.cancel.is_cancelled() {
    return;
  }
  lines.truncate(50);
  if lines.is_empty() {
    ctx.say("未能读取崩溃容器日志（容器可能未产生输出）");
  } else {
    ctx.say(format!("--- 崩溃日志（最后 {} 行）---", lines.len()));
    for line in lines {
      ctx.say(line);
    }
    ctx.say("--- 崩溃日志结束 ---");
  }
}

fn crash_lines(
  logs: &str,
  limit: usize,
  prefix: &str,
) -> Vec<String> {
  let logs = crate::docker::strip_ansi(logs);
  let lines: Vec<_> = logs
    .lines()
    .filter(|line| !line.trim().is_empty())
    .collect();
  lines[lines.len().saturating_sub(limit)..]
    .iter()
    .map(|line| {
      let mut chars = prefix.chars().chain(line.chars());
      let mut text: String = chars.by_ref().take(500).collect();
      if chars.next().is_some() {
        text.pop();
        text.push('…');
      }
      text
    })
    .collect()
}

fn starting(state: &ProjectState) -> bool {
  state.containers.iter().any(|c| {
    c.is_running() && c.health.as_deref() == Some("starting")
  })
}

/// 已经能下结论的问题：没有容器、容器退出、健康检查失败。
fn problem(state: &ProjectState) -> Option<String> {
  if state.containers.iter().all(|c| c.foreign) {
    return Some("启动后没有容器".into());
  }
  let has_running = state.containers.iter().any(|c| c.is_running());
  let bad: Vec<String> = state
    .containers
    .iter()
    .filter(|c| !(c.foreign || has_running && c.is_completed_init()))
    .filter_map(|c| {
      if c.health.as_deref() == Some("unhealthy") {
        Some(format!("{} 健康检查不通过", c.service))
      } else if c.state != "running" {
        Some(format!("{} {}（{}）", c.service, c.state, c.status))
      } else {
        None
      }
    })
    .collect();
  (!bad.is_empty()).then(|| bad.join("，"))
}

fn failed(project: &str, why: String) -> ApiError {
  ApiError::new(
    ErrorCode::AgentFailed,
    format!("{project} 没起来：{why}"),
  )
  .suggest(format!("wharf service logs {project}"))
}

/// 容器名 → 重启次数。查不到时返回空，不影响判断其他条件。
async fn restart_counts(
  docker: &Docker,
  state: &ProjectState,
  ctx: &Ctx,
) -> HashMap<String, u64> {
  if state.containers.is_empty() {
    return HashMap::new();
  }
  let out = docker
    .cmd()
    .args(["inspect", "--format", "{{.Name}} {{.RestartCount}}"])
    .args(state.containers.iter().map(|c| c.name.clone()))
    .timeout(Duration::from_secs(15))
    .run(ctx)
    .await;
  let Ok(out) = out else { return HashMap::new() };
  out
    .stdout
    .lines()
    .filter_map(|l| {
      let (name, n) = l.trim().rsplit_once(' ')?;
      Some((
        name.trim_start_matches('/').to_string(),
        n.parse().ok()?,
      ))
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::agent::{ContainerInfo, HttpCheckResult};

  #[test]
  fn exempts_init_only_with_running_sibling() {
    let init = ContainerInfo {
      exit_code: Some(0),
      restart_policy: Some("no".into()),
      ..container("exited", None)
    };
    let mut state = ProjectState {
      project: "app".into(),
      hash: None,
      config_hash: None,
      acme_dns_url_hash: None,
      frpc_admin_port: None,
      containers: vec![init],
    };
    assert!(problem(&state).is_some());
    assert!(!state.all_running());
    state.containers.push(container("running", None));
    assert!(problem(&state).is_none());
    assert!(state.all_running());
  }

  #[tokio::test]
  async fn short_start_limits_recheck_containers_at_end_of_window() {
    async fn run(
      limit: u32,
      crash_at: Option<Duration>,
    ) -> Result<ProjectState, ApiError> {
      let (dir, docker) = crate::docker::fake_docker(
        r#"
case "$1" in
  ps)
    sleep 0.2
    state=running
    [ ! -f crashed ] || state=exited
    printf '{"Names":"app-web-1","Labels":"com.docker.compose.project=app,com.docker.compose.service=web","State":"%s"}\n' "$state";;
  inspect) sleep 0.2; echo /app-web-1 0;;
esac
"#,
      );
      let crash = async {
        if let Some(at) = crash_at {
          tokio::time::sleep(at).await;
          std::fs::write(dir.path().join("crashed"), "").unwrap();
        }
      };
      let cap = max_watch(Some(limit));
      assert_eq!(cap.as_secs(), u64::from(limit));
      let ctx = Ctx::detached();
      let (result, ()) = tokio::join!(
        watch(
          &docker,
          "app",
          WatchOptions {
            max_watch: cap,
            readiness: None
          },
          &ctx
        ),
        crash,
      );
      result
    }

    let (one, ten, eleven, crash) = tokio::join!(
      run(1, None),
      run(10, None),
      run(11, None),
      run(10, Some(Duration::from_millis(9900))),
    );
    for state in [one, ten, eleven] {
      assert!(state.unwrap().all_running());
    }
    let error = crash.unwrap_err();
    assert_eq!(error.code, ErrorCode::AgentFailed);
    assert!(
      error.message.contains("web exited"),
      "{}",
      error.message
    );
  }

  #[test]
  fn timeout_after_successful_probe_reports_stability() {
    assert_eq!(
      timeout_detail(11, false, true, Some("HTTP 503")),
      "11 秒内未能确认容器稳定运行",
    );
    assert_eq!(
      timeout_detail(11, false, false, Some("HTTP 503")),
      "就绪探活 11 秒内没有通过（最后一次：HTTP 503）",
    );
  }

  #[test]
  fn readiness_probe_and_custom_timeout() {
    assert_eq!(max_watch(None).as_secs(), 120);
    assert_eq!(max_watch(Some(300)).as_secs(), 300);
    let mut result = HttpCheckResult {
      status: Some(200),
      found: Some(false),
      ..Default::default()
    };
    assert!(!judge_http_check(Some(200), Some("ready"), &result).0);
    result.found = Some(true);
    assert!(judge_http_check(Some(200), Some("ready"), &result).0);
  }

  #[test]
  fn crash_logs_truncated_to_50_lines() {
    let logs = (0..80)
      .map(|i| format!("\x1b[31m{i} {}\x1b[0m\n", "文".repeat(500)))
      .collect::<String>();
    let lines = crash_lines(&logs, 50, "[web] ");
    assert_eq!(lines.len(), 50);
    assert!(lines[0].starts_with("[web] 30 "));
    assert!(lines.iter().all(
      |line| !line.contains('\x1b') && line.chars().count() == 500
    ));
  }

  fn container(state: &str, health: Option<&str>) -> ContainerInfo {
    ContainerInfo {
      service: "app".into(),
      name: "app-app-1".into(),
      state: state.into(),
      status: String::new(),
      health: health.map(str::to_string),
      image: String::new(),
      foreign: false,
      working_dir: None,
      finished_at: None,
      exit_code: None,
      restart_policy: None,
    }
  }

  #[test]
  fn normalized_health_is_still_starting() {
    assert!(starting(&ProjectState {
      project: "app".into(),
      hash: None,
      config_hash: None,
      acme_dns_url_hash: None,
      frpc_admin_port: None,
      containers: vec![container("running", Some("starting"))],
    }));
  }

  #[test]
  fn judges_containers() {
    let state = |c| ProjectState {
      project: "app".into(),
      hash: None,
      config_hash: None,
      acme_dns_url_hash: None,
      frpc_admin_port: None,
      containers: vec![c],
    };
    assert!(problem(&state(container("running", None))).is_none());
    assert!(
      problem(&state(container("running", Some("starting"))))
        .is_none()
    );
    assert!(problem(&state(container("exited", None))).is_some());
    assert!(
      problem(&state(container("running", Some("unhealthy"))))
        .is_some()
    );
  }
}
