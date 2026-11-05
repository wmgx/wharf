//! 页面上给服务器装系统更新（apt）。和宿主机终端共用一个开关，要 exec 和 apply 权限，记审计。
//!
//! 在宿主机上用 `systemd-run` 起一个独立的 `wharf-apt` 单元跑 `apt-get upgrade`：
//! 更新到 docker 时 docker 会重启，agent 和临时容器都会断，单元不受影响，接着跑完。
//! 输出写在 /var/log/wharf-apt.log，页面轮询状态和最后几行。只做 upgrade，不做 dist-upgrade、不重启机器。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, HostExecJob, HostExecOutcome},
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  host_dir::check_server,
  shell::{End, finish, start},
  state::AppState,
};

const TIMEOUT_SECS: u64 = 60;

const START: &str = r#"
command -v apt-get >/dev/null 2>&1 || { echo "这台机器不是 apt 系统"; exit 3; }
command -v systemd-run >/dev/null 2>&1 || { echo "这台机器没有 systemd-run"; exit 3; }
if systemctl is-active --quiet wharf-apt; then echo "已经在装了"; exit 0; fi
systemctl stop wharf-apt >/dev/null 2>&1
systemctl reset-failed wharf-apt >/dev/null 2>&1
systemd-run --unit=wharf-apt --remain-after-exit --description="Wharf apt upgrade" \
  --setenv=DEBIAN_FRONTEND=noninteractive \
  sh -c 'exec >/var/log/wharf-apt.log 2>&1; date; apt-get update && apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; code=$?; date; exit $code'
"#;

const STATUS: &str = r#"
state=$(systemctl show -p ActiveState --value wharf-apt 2>/dev/null)
result=$(systemctl show -p Result --value wharf-apt 2>/dev/null)
echo "$state $result"
tail -n 40 /var/log/wharf-apt.log 2>/dev/null
"#;

async fn run(
  s: &AppState,
  server: &str,
  command: &str,
) -> Result<(i32, String), ApiError> {
  let outcome: HostExecOutcome = s
    .hub
    .call(
      server,
      AgentOp::HostExec(HostExecJob {
        command: command.into(),
        timeout_secs: TIMEOUT_SECS,
        cwd: "/".into(),
      }),
      Duration::from_secs(TIMEOUT_SECS + 30),
      None,
      &CancellationToken::new(),
    )
    .await?;
  match outcome {
    HostExecOutcome::Finished(r) => {
      Ok((r.exit_code, format!("{}{}", r.stdout, r.stderr)))
    }
    HostExecOutcome::Failed(f) => Err(f.error),
  }
}

#[derive(Serialize)]
pub struct AptStatus {
  /// `none` 没装过、`running` 正在装、`done` 装完、`failed` 失败。
  pub state: &'static str,
  /// 日志最后 40 行。
  pub log: String,
}

/// `GET /api/servers/{name}/apt`：最近一次装更新的状态。
pub async fn status(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<AptStatus> {
  auth.require(Perm::Exec)?;
  check_server(&s, &name).await?;
  let (_, out) = run(&s, &name, STATUS).await?;
  let (head, log) = out.split_once('\n').unwrap_or((&out, ""));
  Ok(Json(AptStatus {
    state: parse_state(head),
    log: log.to_string(),
  }))
}

fn parse_state(head: &str) -> &'static str {
  let mut it = head.split_whitespace();
  match (it.next(), it.next()) {
    (Some("activating" | "deactivating"), _) => "running",
    (Some("active"), Some("success")) => "done",
    (Some("active"), _) => "running",
    (Some("failed"), _) => "failed",
    (Some("inactive"), Some(r)) if r != "success" => "failed",
    _ => "none",
  }
}

/// `POST /api/servers/{name}/apt`：开始装更新，立刻返回。
pub async fn upgrade(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<String> {
  auth.require(Perm::Exec)?;
  auth.require(Perm::Apply)?;
  check_server(&s, &name).await?;
  let audit =
    start(&s.db, &auth.name, &name, "apt.upgrade", None).await?;
  let result = run(&s, &name, START).await;
  let end = match &result {
    Ok((code, out)) => End {
      exit_code: Some(*code),
      duration_ms: None,
      output_bytes: Some(out.len() as u64),
      error: None,
    },
    Err(e) => End::error(e),
  };
  finish(&s.db, audit, end).await;
  let (code, out) = result?;
  if code != 0 {
    return Err(ApiError::invalid(out.trim().to_string()).into());
  }
  Ok(Json(out.trim().to_string()))
}

#[cfg(test)]
mod tests {
  use super::parse_state;

  #[test]
  fn reads_unit_state() {
    assert_eq!(parse_state("active success"), "done");
    assert_eq!(parse_state("activating success"), "running");
    assert_eq!(parse_state("failed exit-code"), "failed");
    assert_eq!(parse_state(" "), "none");
  }
}
