//! 资源采样：整机读 /proc（agent 用主机网络，看到的网卡和宿主机一样），
//! 容器用 `docker stats`。速率要和上一次比，第一次只记下基准。

use std::{
  collections::{BTreeMap, HashMap},
  time::{Duration, Instant},
};

use wharf_api_types::agent::{Metrics, ProjectMetrics};

use crate::{docker::Docker, exec::Ctx};

const STATS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
pub struct Sampler {
  prev: Option<Prev>,
}

struct Prev {
  at: Instant,
  /// /proc/stat 的 (总, 空闲) 节拍数。
  cpu: (u64, u64),
  net: (u64, u64),
  /// project 的容器网络累计 (收, 发)。
  projects: HashMap<String, (u64, u64)>,
}

impl Sampler {
  pub async fn sample(
    &mut self,
    docker: &Docker,
    disk: Option<wharf_api_types::agent::Disk>,
  ) -> Option<Metrics> {
    let now = Instant::now();
    let cpu = cpu_ticks(&read("/proc/stat"))?;
    let net = host_net(&read("/proc/net/dev"));
    let cpus = cpu_count();
    let containers = container_stats(docker).await;
    let mem = read("/proc/meminfo");
    let mem_total = meminfo(&mem, "MemTotal:");
    let projects_now: HashMap<String, (u64, u64)> = containers
      .iter()
      .map(|(p, s)| (p.clone(), (s.rx, s.tx)))
      .collect();
    let prev = self.prev.replace(Prev {
      at: now,
      cpu,
      net,
      projects: projects_now,
    })?;
    let secs = now.duration_since(prev.at).as_secs_f64().max(1.0);
    let rate = |cur: u64, old: u64| {
      (cur.saturating_sub(old) as f64 / secs).round() as u64
    };
    let (total, idle) = (
      cpu.0.saturating_sub(prev.cpu.0),
      cpu.1.saturating_sub(prev.cpu.1),
    );
    let projects = containers
      .into_iter()
      .map(|(name, s)| {
        let (rx, tx) =
          prev.projects.get(&name).map_or((0, 0), |(rx, tx)| {
            (rate(s.rx, *rx), rate(s.tx, *tx))
          });
        let m = ProjectMetrics {
          cpu: s.cpu / cpus,
          mem: s.mem,
          net_rx: rx,
          net_tx: tx,
        };
        (name, m)
      })
      .collect();
    Some(Metrics {
      cpu: if total == 0 {
        0.0
      } else {
        100.0 * (total - idle.min(total)) as f32 / total as f32
      },
      mem_used: mem_total
        .saturating_sub(meminfo(&mem, "MemAvailable:")),
      mem_total,
      net_rx: rate(net.0, prev.net.0),
      net_tx: rate(net.1, prev.net.1),
      disk_used: disk.map_or(0, |d| d.total.saturating_sub(d.free)),
      disk_total: disk.map_or(0, |d| d.total),
      projects,
    })
  }
}

fn read(path: &str) -> String {
  std::fs::read_to_string(path).unwrap_or_default()
}

fn cpu_count() -> f32 {
  let n = read("/proc/cpuinfo")
    .lines()
    .filter(|l| l.starts_with("processor"))
    .count();
  n.max(1) as f32
}

/// 第一行 `cpu  user nice system idle iowait irq softirq steal ...`。
fn cpu_ticks(stat: &str) -> Option<(u64, u64)> {
  let line = stat.lines().find(|l| l.starts_with("cpu "))?;
  let v: Vec<u64> = line
    .split_whitespace()
    .skip(1)
    .take(8)
    .filter_map(|x| x.parse().ok())
    .collect();
  if v.len() < 5 {
    return None;
  }
  Some((v.iter().sum(), v[3] + v[4]))
}

fn meminfo(s: &str, key: &str) -> u64 {
  s.lines()
    .find_map(|l| l.strip_prefix(key))
    .and_then(|v| v.split_whitespace().next())
    .and_then(|v| v.parse::<u64>().ok())
    .map_or(0, |kb| kb * 1024)
}

/// 物理网卡的累计 (收, 发) 字节。组网网卡的流量已经算在物理网卡上了。
fn host_net(dev: &str) -> (u64, u64) {
  dev
    .lines()
    .skip(2)
    .filter_map(|l| {
      let (name, rest) = l.split_once(':')?;
      let name = name.trim();
      let skip = name == "lo"
        || name == "docker0"
        || ["br-", "veth", "tailscale", "ts", "wg", "zt"]
          .iter()
          .any(|p| name.starts_with(p));
      if skip {
        return None;
      }
      let v: Vec<u64> = rest
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
      Some((*v.first()?, *v.get(8)?))
    })
    .fold((0, 0), |(a, b), (rx, tx)| (a + rx, b + tx))
}

#[derive(Default)]
struct Stat {
  cpu: f32,
  mem: u64,
  rx: u64,
  tx: u64,
}

/// 按 compose project 合计。不属于任何 project 的容器不算。
async fn container_stats(docker: &Docker) -> BTreeMap<String, Stat> {
  let ctx = Ctx::detached();
  let run = |args: &'static [&'static str]| {
    docker
      .cmd()
      .args(args.iter().copied())
      .timeout(STATS_TIMEOUT)
      .run(&ctx)
  };
  let (ps, stats) = tokio::join!(
    run(&[
      "ps",
      "--format",
      "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}",
    ]),
    run(&["stats", "--no-stream", "--format", "{{json .}}"]),
  );
  let (Ok(ps), Ok(stats)) = (ps, stats) else {
    return BTreeMap::new();
  };
  let project: HashMap<&str, &str> = ps
    .stdout
    .lines()
    .filter_map(|l| l.split_once('\t'))
    .filter(|(_, p)| !p.is_empty())
    .collect();
  #[derive(serde::Deserialize)]
  #[serde(rename_all = "PascalCase")]
  struct Row {
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu: String,
    mem_usage: String,
    #[serde(rename = "NetIO")]
    net: String,
  }
  let mut out: BTreeMap<String, Stat> = BTreeMap::new();
  for row in stats
    .stdout
    .lines()
    .filter_map(|l| serde_json::from_str::<Row>(l).ok())
  {
    let Some(p) = project.get(row.name.as_str()) else {
      continue;
    };
    let e = out.entry(p.to_string()).or_default();
    e.cpu +=
      row.cpu.trim_end_matches('%').parse::<f32>().unwrap_or(0.0);
    e.mem += first_size(&row.mem_usage);
    let (rx, tx) = row.net.split_once('/').unwrap_or(("", ""));
    e.rx += size(rx);
    e.tx += size(tx);
  }
  out
}

fn first_size(s: &str) -> u64 {
  size(s.split('/').next().unwrap_or(""))
}

/// docker 的大小写法：`1.5GiB`、`648B`、`12.3kB`、`4MB`。
fn size(s: &str) -> u64 {
  let s = s.trim();
  let split = s
    .find(|c: char| !(c.is_ascii_digit() || c == '.'))
    .unwrap_or(s.len());
  let (num, unit) = s.split_at(split);
  let n: f64 = num.parse().unwrap_or(0.0);
  let mul: f64 = match unit.trim() {
    "kB" | "KB" => 1e3,
    "MB" => 1e6,
    "GB" => 1e9,
    "TB" => 1e12,
    "KiB" => 1024.0,
    "MiB" => 1024.0 * 1024.0,
    "GiB" => 1024.0 * 1024.0 * 1024.0,
    "TiB" => 1024f64.powi(4),
    _ => 1.0,
  };
  (n * mul) as u64
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse() {
    assert_eq!(size("1.5GiB"), 1610612736);
    assert_eq!(size("648B"), 648);
    assert_eq!(size("12.3kB"), 12300);
    assert_eq!(first_size("12MiB / 1.9GiB"), 12 * 1024 * 1024);
    assert_eq!(
      cpu_ticks("cpu  10 0 10 70 10 0 0 0 0 0\ncpu0 1"),
      Some((100, 80))
    );
    let dev = "h1\nh2\n  lo: 5 0 0 0 0 0 0 0 5 0\n  eth0: 100 1 0 0 0 0 0 0 200 1\n  docker0: 9 0 0 0 0 0 0 0 9 0\n  tailscale0: 7 0 0 0 0 0 0 0 7 0\n";
    assert_eq!(host_net(dev), (100, 200));
  }
}
