//! 服务器详情页的宿主机信息。内核、负载、内存直接读 /proc（容器和宿主机共用内核）；
//! 系统版本、待装更新、日志占用要看宿主机的文件，借 agent 自己的镜像
//! 只读挂载宿主机根目录跑一个小脚本。

use std::time::Duration;

use wharf_api_types::{
  ApiError,
  agent::{DockerUsage, HostInfo, PackageUpdate},
};

use crate::{docker::Docker, exec::Ctx};

const PROBE_TIMEOUT: Duration = Duration::from_secs(90);
const QUICK: Duration = Duration::from_secs(20);

/// 输出 `key value` 行；apt 模拟升级成功时先输出 `apt`，再原样输出 `Inst` 行。
const SCRIPT: &str = r#"
grep '^PRETTY_NAME=' /host/etc/os-release 2>/dev/null | sed 's/^PRETTY_NAME=//; s/"//g; s/^/os /'
echo "container_logs $(find "/host$ROOT/containers" -name '*-json.log*' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')"
echo "journal $(du -sb /host/var/log/journal 2>/dev/null | cut -f1)"
echo "var_log $(du -sb /host/var/log 2>/dev/null | cut -f1)"
[ -e /host/var/run/reboot-required ] && echo reboot
if [ -x /host/usr/bin/apt-get ] && out=$(chroot /host apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null); then
  echo apt
  echo "$out" | grep '^Inst '
fi
"#;

pub async fn info(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<HostInfo, ApiError> {
  let mut info = HostInfo {
    kernel: read("/proc/sys/kernel/osrelease"),
    uptime_secs: read("/proc/uptime")
      .split('.')
      .next()
      .and_then(|s| s.parse().ok())
      .unwrap_or(0),
    load: load(&read("/proc/loadavg")),
    cpus: read("/proc/cpuinfo")
      .lines()
      .filter(|l| l.starts_with("processor"))
      .count() as u32,
    ..Default::default()
  };
  let mem = read("/proc/meminfo");
  info.mem_total = meminfo(&mem, "MemTotal:");
  info.mem_available = meminfo(&mem, "MemAvailable:");
  info.docker = docker_df(docker, ctx).await;
  let root = docker
    .cmd()
    .args(["info", "--format", "{{.DockerRootDir}}"])
    .timeout(QUICK)
    .run(ctx)
    .await
    .ok()
    .filter(|o| o.success)
    .map(|o| o.stdout.trim().to_string())
    .unwrap_or_else(|| "/var/lib/docker".into());
  let image = crate::adopt::self_image(docker, ctx).await?;
  let out = docker
    .cmd()
    .args([
      "run",
      "--rm",
      "--network",
      "none",
      "--entrypoint",
      "sh",
      "--mount",
      "type=bind,src=/,dst=/host,readonly",
      "-e",
    ])
    .arg(format!("ROOT={root}"))
    .args([image.as_str(), "-c", SCRIPT])
    .timeout(PROBE_TIMEOUT)
    .run(ctx)
    .await?
    .check("读取宿主机信息")?;
  parse_script(&out.stdout, &mut info);
  Ok(info)
}

fn read(path: &str) -> String {
  std::fs::read_to_string(path)
    .map(|s| s.trim().to_string())
    .unwrap_or_default()
}

fn load(s: &str) -> [f64; 3] {
  let mut it = s.split_whitespace().map(|v| v.parse().unwrap_or(0.0));
  [
    it.next().unwrap_or(0.0),
    it.next().unwrap_or(0.0),
    it.next().unwrap_or(0.0),
  ]
}

/// `/proc/meminfo` 的值是 kB。
fn meminfo(s: &str, key: &str) -> u64 {
  s.lines()
    .find_map(|l| l.strip_prefix(key))
    .and_then(|v| v.split_whitespace().next())
    .and_then(|v| v.parse::<u64>().ok())
    .map_or(0, |kb| kb * 1024)
}

async fn docker_df(docker: &Docker, ctx: &Ctx) -> Vec<DockerUsage> {
  #[derive(serde::Deserialize)]
  #[serde(rename_all = "PascalCase")]
  struct Row {
    #[serde(rename = "Type")]
    kind: String,
    total_count: String,
    active: String,
    size: String,
    reclaimable: String,
  }
  let Ok(out) = docker
    .cmd()
    .args(["system", "df", "--format", "{{json .}}"])
    .timeout(QUICK)
    .run(ctx)
    .await
  else {
    return Vec::new();
  };
  out
    .stdout
    .lines()
    .filter_map(|l| serde_json::from_str::<Row>(l).ok())
    .map(|r| DockerUsage {
      kind: r.kind,
      total: r.total_count,
      active: r.active,
      size: r.size,
      reclaimable: r.reclaimable,
    })
    .collect()
}

fn parse_script(out: &str, info: &mut HostInfo) {
  let mut updates = None;
  for line in out.lines() {
    let (key, value) = line.split_once(' ').unwrap_or((line, ""));
    let bytes = || value.trim().parse().ok();
    match key {
      "os" if !value.is_empty() => info.os = Some(value.to_string()),
      "container_logs" => info.container_logs = bytes(),
      "journal" => info.journal = bytes(),
      "var_log" => info.var_log = bytes(),
      "reboot" => info.reboot_required = true,
      "apt" => updates = Some(Vec::new()),
      "Inst" => {
        if let (Some(list), Some(u)) = (updates.as_mut(), inst(value))
        {
          list.push(u);
        }
      }
      _ => {}
    }
  }
  info.updates = updates;
}

/// `name [旧版本] (新版本 来源 [架构])`；新装的依赖没有旧版本。
fn inst(s: &str) -> Option<PackageUpdate> {
  let (name, rest) = s.split_once(' ')?;
  let (from, rest) = match rest.strip_prefix('[') {
    Some(r) => {
      let (v, rest) = r.split_once("] ")?;
      (v.to_string(), rest)
    }
    None => (String::new(), rest),
  };
  let inner = rest.strip_prefix('(')?;
  let (to, source) = inner.split_once(' ').unwrap_or((inner, ""));
  Some(PackageUpdate {
    name: name.to_string(),
    from,
    to: to.trim_end_matches(')').to_string(),
    security: source.to_ascii_lowercase().contains("security"),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse() {
    let mut info = HostInfo::default();
    parse_script(
      "os Debian GNU/Linux 12 (bookworm)\n\
       container_logs 67194769\njournal \nvar_log 159206470\napt\n\
       Inst docker-ce [5:29.4.2-2] (5:29.9.2-1 Docker CE:bookworm [amd64])\n\
       Inst libssl3 [3.0.15-1] (3.0.17-1 Debian-Security:12/stable-security [amd64])\n\
       Inst linux-image-6.1.0-50-amd64 (6.1.158-1 Debian:12/stable [amd64])\n",
      &mut info,
    );
    assert_eq!(
      info.os.as_deref(),
      Some("Debian GNU/Linux 12 (bookworm)")
    );
    assert_eq!(info.container_logs, Some(67194769));
    assert_eq!(info.journal, None);
    let u = info.updates.unwrap();
    assert_eq!(u.len(), 3);
    assert_eq!(u[0].from, "5:29.4.2-2");
    assert_eq!(u[0].to, "5:29.9.2-1");
    assert!(!u[0].security && u[1].security);
    assert_eq!(u[2].from, "");
  }
}
