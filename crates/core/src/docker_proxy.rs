//! 拉镜像代理（服务器设置 `pull_proxy`）：写进宿主机 dockerd 的 `/etc/docker/daemon.json`。
//!
//! agent 拉镜像用的是 `docker pull`，真正下载的是 dockerd，所以代理只能配在 dockerd 上。
//! 镜像源和内网地址写进 `no-proxy`，只有海外仓库（ghcr 等）走代理。
//! 同时开启 `live-restore`（可以热加载），之后重启 dockerd 时容器不停。
//! 写入前用 `dockerd --validate` 检查，配置有错时不动原文件。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HostExecJob, HostExecOutcome},
  spec::ServerSettings,
};

use crate::{hub::ProgressFn, state::AppState};

const EXEC_SECS: u64 = 60;
/// 重启 dockerd 后等它带着新配置回来的时间。
const READY_SECS: u64 = 120;

/// 总是直连的地址：本机、内网、Tailscale。
const ALWAYS_DIRECT: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10";

/// 想要的 dockerd 代理配置：`(代理, no-proxy)`。没设代理时为 `None`。
pub fn wanted(s: &ServerSettings) -> Option<(String, String)> {
  // 经出口时指向本机的分流代理，改规则不用再动 dockerd。
  let local = crate::egress::local_url();
  let proxy = match crate::egress::via(s) {
    Some(_) => local.as_str(),
    None => s.pull_proxy.as_deref()?.trim(),
  };
  if proxy.is_empty() {
    return None;
  }
  let mut direct: Vec<String> =
    ALWAYS_DIRECT.split(',').map(str::to_string).collect();
  for host in s.registry_mirrors.values().flatten() {
    let host = host.split('/').next().unwrap_or(host).to_string();
    if !direct.contains(&host) {
      direct.push(host);
    }
  }
  Some((proxy.to_string(), direct.join(",")))
}

fn quote(s: &str) -> String {
  format!("'{}'", s.replace('\'', r"'\''"))
}

const WRITE: &str = r#"
command -v python3 >/dev/null 2>&1 || { echo "这台机器没有 python3，改不了 daemon.json"; exit 3; }
command -v systemd-run >/dev/null 2>&1 || { echo "这台机器没有 systemd-run"; exit 3; }
result=$(python3 - "$P" "$N" <<'PY'
import json, os, subprocess, sys
proxy, no_proxy = sys.argv[1], sys.argv[2]
path = '/etc/docker/daemon.json'
try:
    with open(path) as f:
        conf = json.load(f)
except FileNotFoundError:
    conf = {}
before = json.dumps(conf, sort_keys=True)
had_live_restore = conf.get('live-restore') is True
conf['live-restore'] = True
if proxy:
    conf['proxies'] = {'http-proxy': proxy, 'https-proxy': proxy, 'no-proxy': no_proxy}
else:
    conf.pop('proxies', None)
if json.dumps(conf, sort_keys=True) == before:
    print('unchanged')
    sys.exit(0)
os.makedirs('/etc/docker', exist_ok=True)
tmp = path + '.wharf-new'
with open(tmp, 'w') as f:
    json.dump(conf, f, indent=2)
    f.write('\n')
check = subprocess.run(['dockerd', '--validate', '--config-file', tmp], capture_output=True, text=True)
if check.returncode != 0:
    os.remove(tmp)
    print('invalid ' + (check.stderr or check.stdout).strip())
    sys.exit(0)
os.replace(tmp, path)
print('changed' if had_live_restore else 'changed-live-restore')
PY
) || exit 4
echo "$result"
case "$result" in
  unchanged) exit 0 ;;
  invalid*) exit 5 ;;
  changed-live-restore) kill -HUP "$(pidof dockerd)"; sleep 2 ;;
esac
systemctl reset-failed wharf-docker-restart >/dev/null 2>&1
systemd-run --unit=wharf-docker-restart --on-active=3 systemctl restart docker >/dev/null
"#;

const CHECK: &str =
  r#"docker info -f '{{.HTTPSProxy}}|{{.LiveRestoreEnabled}}'"#;

async fn exec(
  state: &AppState,
  server: &str,
  command: String,
  cancel: &CancellationToken,
) -> Result<(i32, String), ApiError> {
  let outcome: HostExecOutcome = state
    .hub
    .call(
      server,
      AgentOp::HostExec(HostExecJob {
        command,
        timeout_secs: EXEC_SECS,
        cwd: "/".into(),
      }),
      Duration::from_secs(EXEC_SECS + 30),
      None,
      cancel,
    )
    .await?;
  match outcome {
    HostExecOutcome::Finished(r) => {
      Ok((r.exit_code, format!("{}{}", r.stdout, r.stderr)))
    }
    HostExecOutcome::Failed(f) => Err(f.error),
  }
}

/// 计划里的一步：按服务器设置改 dockerd 的代理，有变化时重启 dockerd 并确认生效。
pub async fn apply(
  state: &AppState,
  server: &str,
  settings: &ServerSettings,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let (proxy, no_proxy) = wanted(settings).unwrap_or_default();
  let script =
    format!("P={}\nN={}\n{WRITE}", quote(&proxy), quote(&no_proxy));
  let (code, out) = exec(state, server, script, cancel).await?;
  let out = out.trim();
  if code != 0 {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("改 {server} 的 dockerd 配置失败：{out}"),
      )
      .with_hint("daemon.json 没有改动；修好后用 --pull-proxy \"\" 清掉再重新设置"),
    );
  }
  if out.ends_with("unchanged") {
    progress("dockerd 配置已经是这样，不用改".into());
    return Ok(());
  }
  progress("已写入 daemon.json，重启 dockerd（容器不停）".into());
  let want = format!("{proxy}|true");
  let deadline =
    tokio::time::Instant::now() + Duration::from_secs(READY_SECS);
  tokio::time::sleep(Duration::from_secs(8)).await;
  loop {
    if let Ok((0, out)) =
      exec(state, server, CHECK.to_string(), cancel).await
      && out.trim() == want
    {
      progress(if proxy.is_empty() {
        "dockerd 已去掉拉镜像代理".into()
      } else {
        format!("dockerd 已经通过 {proxy} 拉海外镜像")
      });
      return Ok(());
    }
    if cancel.is_cancelled() {
      return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
    }
    if tokio::time::Instant::now() >= deadline {
      return Err(
        ApiError::new(
          ErrorCode::Timeout,
          format!("{server} 的 dockerd 重启后 {READY_SECS} 秒内没有带上新配置"),
        )
        .with_hint("到机器上看 systemctl status docker 和 /etc/docker/daemon.json"),
      );
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mirrors_go_direct() {
    let mut s = ServerSettings::default();
    assert_eq!(wanted(&s), None);
    s.pull_proxy = Some("http://100.80.120.24:8118".into());
    s.registry_mirrors
      .insert("ghcr.io".into(), vec!["ghcr.nju.edu.cn".into()]);
    let (p, n) = wanted(&s).unwrap();
    assert_eq!(p, "http://100.80.120.24:8118");
    assert!(n.starts_with("localhost,"));
    assert!(n.ends_with(",ghcr.nju.edu.cn"));
    assert_eq!(quote("a'b"), r"'a'\''b'");
  }
}
