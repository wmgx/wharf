//! 机器基线（P9）：服务器设置 `baseline` 是系统设置的期望值。
//!
//! - 后台每 [EVERY] 检查一次各台的实际值，差异进"需要注意"，也让下一次 plan 带上纠正步骤；
//! - 设置改了或有差异时，plan 加一步"纠正基线"，apply 时在宿主机上执行。
//!
//! 检查和纠正是同一个脚本（宿主机上的 python3），模式不同。只管填了的项，没填的不碰。
//! 差异只存在内存里，控制面重启后等下一轮检查。

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use base64::Engine;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HostExecJob, HostExecOutcome},
  spec::Baseline,
};

use crate::{hub::ProgressFn, state::AppState};

const EVERY: Duration = Duration::from_secs(6 * 3600);
/// 装 unattended-upgrades 可能要一会儿。
const EXEC_SECS: u64 = 300;

static DRIFT: Mutex<BTreeMap<String, Vec<String>>> =
  Mutex::new(BTreeMap::new());

/// 最近一次检查出的差异。
pub fn drift(server: &str) -> Vec<String> {
  DRIFT
    .lock()
    .map(|d| d.get(server).cloned().unwrap_or_default())
    .unwrap_or_default()
}

fn remember(server: &str, diffs: Vec<String>) {
  if let Ok(mut d) = DRIFT.lock() {
    if diffs.is_empty() {
      d.remove(server);
    } else {
      d.insert(server.to_string(), diffs);
    }
  }
}

pub fn problems() -> Vec<String> {
  DRIFT
    .lock()
    .map(|d| {
      d.iter()
        .map(|(s, diffs)| {
          format!(
            "服务器 {s} 偏离基线 {} 项（wharf server baseline {s} --apply 纠正）",
            diffs.len()
          )
        })
        .collect()
    })
    .unwrap_or_default()
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(180)).await;
    loop {
      check_all(&state).await;
      tokio::time::sleep(EVERY).await;
    }
  });
}

/// 检查全部在线、设了基线的机器。
pub async fn check_all(state: &AppState) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  if let Ok(mut d) = DRIFT.lock() {
    d.retain(|s, _| {
      snap
        .world
        .servers
        .get(s)
        .is_some_and(|r| !r.settings.baseline.is_empty())
    });
  }
  for (name, row) in &snap.world.servers {
    if row.settings.baseline.is_empty() || !state.hub.is_online(name)
    {
      continue;
    }
    match run(state, name, &row.settings.baseline, false, None).await
    {
      Ok(r) => remember(name, r.diffs),
      Err(e) => {
        tracing::warn!("检查 {name} 的基线失败：{}", e.message)
      }
    }
  }
}

#[derive(Debug, Default, Deserialize, serde::Serialize)]
pub struct Report {
  /// 和期望不一样的项（纠正模式下是纠正前的）。
  #[serde(default)]
  pub diffs: Vec<String>,
  /// 纠正了哪些。
  #[serde(default)]
  pub done: Vec<String>,
  /// 纠正失败的项。
  #[serde(default)]
  pub errors: Vec<String>,
}

const SCRIPT: &str = r#"
command -v python3 >/dev/null 2>&1 || { echo "这台机器没有 python3，管不了基线"; exit 3; }
python3 - "$M" "$B" <<'PY'
import base64, json, os, subprocess, sys
mode = sys.argv[1]
want = json.loads(base64.b64decode(sys.argv[2]))
out = {'diffs': [], 'done': [], 'errors': []}

def run(*a, env=None):
    r = subprocess.run(a, capture_output=True, text=True, timeout=240, env=env)
    if r.returncode != 0:
        raise Exception((r.stderr or r.stdout).strip()[:300] or f'{a[0]} 退出码 {r.returncode}')
    return r.stdout.strip()

def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ''

def write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(body)

def item(label, cur, wanted, fix):
    if cur == wanted:
        return
    out['diffs'].append(f'{label}：现在 {cur or "未设置"}，应为 {wanted}')
    if mode != 'apply':
        return
    try:
        fix()
        out['done'].append(label)
    except Exception as e:
        out['errors'].append(f'{label}：{e}')

tz = want.get('timezone')
if tz:
    try:
        cur = run('timedatectl', 'show', '-p', 'Timezone', '--value')
    except Exception:
        cur = read('/etc/timezone').strip()
    item('时区', cur, tz, lambda: run('timedatectl', 'set-timezone', tz))

swap = want.get('swap_gb')
if swap:
    active = [l for l in read('/proc/swaps').splitlines()[1:] if l.strip()]
    def make_swap():
        if not os.path.exists('/swapfile'):
            run('fallocate', '-l', f'{swap}G', '/swapfile')
            os.chmod('/swapfile', 0o600)
            run('mkswap', '/swapfile')
        run('swapon', '/swapfile')
        if '/swapfile' not in read('/etc/fstab'):
            with open('/etc/fstab', 'a') as f:
                f.write('\n/swapfile none swap sw 0 0\n')
    if not active:
        item('swap', '无', f'{swap}G', make_swap)

sysctl = want.get('sysctl') or {}
if sysctl:
    norm = lambda v: ' '.join(str(v).split())
    now = {k: norm(read('/proc/sys/' + k.replace('.', '/'))) for k in sysctl}
    bad = sorted(k for k, v in sysctl.items() if now[k] != norm(v))
    def fix_sysctl():
        if sysctl.get('net.ipv4.tcp_congestion_control') == 'bbr':
            write('/etc/modules-load.d/90-wharf.conf', 'tcp_bbr\n')
            run('modprobe', 'tcp_bbr')
        path = '/etc/sysctl.d/90-wharf.conf'
        write(path, '# 由 Wharf 管理（机器基线），不要手改。\n' + ''.join(f'{k} = {v}\n' for k, v in sorted(sysctl.items())))
        run('sysctl', '-p', path)
    if bad:
        item('内核参数', '，'.join(f'{k}={now[k] or "?"}' for k in bad), '，'.join(f'{k}={norm(sysctl[k])}' for k in bad), fix_sysctl)

size = want.get('docker_log_size')
if size:
    files = str(want.get('docker_log_files') or 3)
    path = '/etc/docker/daemon.json'
    try:
        conf = json.loads(read(path) or '{}')
    except ValueError:
        conf = None
    if conf is None:
        out['errors'].append('容器日志轮转：/etc/docker/daemon.json 不是合法的 JSON，没有动它')
    else:
        opts = conf.get('log-opts') or {}
        cur = f"{opts.get('max-size', '')} × {opts.get('max-file', '')}" if opts.get('max-size') else ''
        def fix_log():
            had_live = conf.get('live-restore') is True
            conf['live-restore'] = True
            conf.setdefault('log-driver', 'json-file')
            conf['log-opts'] = {**opts, 'max-size': size, 'max-file': files}
            tmp = path + '.wharf-new'
            write(tmp, json.dumps(conf, indent=2) + '\n')
            check = subprocess.run(['dockerd', '--validate', '--config-file', tmp], capture_output=True, text=True)
            if check.returncode != 0:
                os.remove(tmp)
                raise Exception('配置校验没过：' + (check.stderr or check.stdout).strip()[:200])
            os.replace(tmp, path)
            if not had_live:
                subprocess.run(['sh', '-c', 'kill -HUP "$(pidof dockerd)"; sleep 2'])
            subprocess.run(['systemctl', 'reset-failed', 'wharf-docker-restart'], capture_output=True)
            run('systemd-run', '--unit=wharf-docker-restart', '--on-active=3', 'systemctl', 'restart', 'docker')
        item('容器日志轮转', cur, f'{size} × {files}', fix_log)

journal = want.get('journal_max')
if journal:
    path = '/etc/systemd/journald.conf.d/90-wharf.conf'
    cur = ''
    for line in read(path).splitlines():
        if line.startswith('SystemMaxUse='):
            cur = line.split('=', 1)[1].strip()
    def fix_journal():
        write(path, f'# 由 Wharf 管理（机器基线），不要手改。\n[Journal]\nSystemMaxUse={journal}\n')
        run('systemctl', 'restart', 'systemd-journald')
        subprocess.run(['journalctl', f'--vacuum-size={journal}'], capture_output=True)
    item('journald 上限', cur, journal, fix_journal)

sec = want.get('security_updates')
if sec is not None:
    if not os.path.exists('/usr/bin/apt-get'):
        out['errors'].append('自动安全更新：不是 apt 系统，没有处理')
    else:
        path = '/etc/apt/apt.conf.d/20auto-upgrades'
        installed = os.path.exists('/usr/bin/unattended-upgrade')
        on = installed and 'Unattended-Upgrade "1"' in read(path)
        def fix_sec():
            if sec and not installed:
                env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
                run('apt-get', 'install', '-y', 'unattended-upgrades', env=env)
            flag = '1' if sec else '0'
            write(path, f'APT::Periodic::Update-Package-Lists "{flag}";\nAPT::Periodic::Unattended-Upgrade "{flag}";\n')
        item('自动安全更新', '开' if on else '关', '开' if sec else '关', fix_sec)

print(json.dumps(out, ensure_ascii=False))
PY
"#;

/// 在 `server` 上检查（`apply = false`）或纠正基线。
pub async fn run(
  state: &AppState,
  server: &str,
  baseline: &Baseline,
  apply: bool,
  cancel: Option<&CancellationToken>,
) -> Result<Report, ApiError> {
  let want = serde_json::to_string(baseline).unwrap_or_default();
  let b64 = base64::engine::general_purpose::STANDARD.encode(want);
  let mode = if apply { "apply" } else { "check" };
  let command = format!("M={mode}\nB={b64}\n{SCRIPT}");
  let fallback = CancellationToken::new();
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
      cancel.unwrap_or(&fallback),
    )
    .await?;
  let r = match outcome {
    HostExecOutcome::Finished(r) => r,
    HostExecOutcome::Failed(f) => return Err(f.error),
  };
  let text = format!("{}{}", r.stdout, r.stderr);
  if r.exit_code != 0 {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("在 {server} 上检查基线失败：{}", text.trim()),
    ));
  }
  let last = r.stdout.lines().last().unwrap_or_default();
  serde_json::from_str(last).map_err(|_| {
    ApiError::new(
      ErrorCode::AgentFailed,
      format!("{server} 的基线检查输出看不懂：{}", text.trim()),
    )
  })
}

/// `POST /api/servers/{name}/baseline/check`：立即检查一次，返回差异。
pub async fn check_now(
  axum::extract::State(s): axum::extract::State<Arc<AppState>>,
  auth: crate::auth::Auth,
  axum::extract::Path(name): axum::extract::Path<String>,
) -> crate::api::ApiResult<Report> {
  auth.require(wharf_api_types::view::Perm::Plan)?;
  let snap = crate::snapshot::load(&s.db).await?;
  let row = snap
    .world
    .servers
    .get(&name)
    .ok_or_else(|| crate::world::server_not_found(&name))?;
  if row.settings.baseline.is_empty() {
    return Err(
      ApiError::invalid(format!("{name} 还没有设置基线"))
        .with_hint("例如 wharf server baseline NAME --timezone Asia/Shanghai --journal-max 500M")
        .into(),
    );
  }
  if !s.hub.is_online(&name) {
    return Err(crate::hub::offline(&name).into());
  }
  let r = run(&s, &name, &row.settings.baseline, false, None).await?;
  remember(&name, r.diffs.clone());
  Ok(axum::Json(r))
}

/// 计划里的一步：纠正，再检查一次更新差异。
pub async fn apply(
  state: &AppState,
  server: &str,
  baseline: &Baseline,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let r = run(state, server, baseline, true, Some(cancel)).await?;
  if r.diffs.is_empty() {
    progress("已经符合基线，不用改".into());
  }
  for d in &r.done {
    progress(format!("已纠正：{d}"));
  }
  // 改了 daemon.json 时 dockerd 几秒后重启，等它回来再检查。
  if !r.done.is_empty() {
    tokio::time::sleep(Duration::from_secs(10)).await;
  }
  if let Ok(after) =
    run(state, server, baseline, false, Some(cancel)).await
  {
    remember(server, after.diffs);
  }
  if !r.errors.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{server} 有基线项没能纠正：{}", r.errors.join("；")),
      )
      .with_hint(format!("看现状：wharf server baseline {server}")),
    );
  }
  Ok(())
}
