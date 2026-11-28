//! 资源采样：整机读 /proc（agent 用主机网络，看到的网卡和宿主机一样），
//! 容器用 `docker stats`。速率要和上一次比，第一次只记下基准。

use std::{
  collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
  time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use wharf_api_types::agent::{
  ComponentMetrics, Metrics, ProjectMetrics, TRIAL_PROJECT_PREFIX,
};

use crate::{docker::Docker, exec::Ctx};

const STATS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
pub struct Sampler {
  prev: Option<Prev>,
  gateway:
    Option<(Instant, HashMap<String, crate::gw_stats::Totals>)>,
  events_since: Option<u64>,
  seen_oom: VecDeque<(u64, String)>,
}

struct Prev {
  host_at: Instant,
  containers_at: Instant,
  /// /proc/stat 的 (总, 空闲) 节拍数。
  cpu: (u64, u64),
  agent_cpu: Option<(bool, u64)>,
  net: (u64, u64),
  /// project 的容器网络累计 (收, 发)。
  projects: HashMap<String, (u64, u64)>,
}

impl Sampler {
  pub async fn sample(
    &mut self,
    docker: &Docker,
    disk: Option<crate::report::DiskSample>,
    ctx: &Ctx,
  ) -> Option<Metrics> {
    let gw_now = crate::gw_stats::collect().await;
    let now = Instant::now();
    let hosts = match self.gateway.replace((now, gw_now.clone())) {
      Some((at, old)) => crate::gw_stats::diff(
        &gw_now,
        &old,
        now.duration_since(at).as_secs_f64().max(1.0),
      ),
      None => Default::default(),
    };
    let cpu = cpu_ticks(&read("/proc/stat"))?;
    let net = host_net(&read("/proc/net/dev"));
    let agent = crate::agent_memory::sample();
    let host_at = Instant::now();
    let cpus = cpu_count();
    let containers = container_stats(docker, ctx).await;
    let containers_at = Instant::now();
    let mem = read("/proc/meminfo");
    let mem_total = meminfo(&mem, "MemTotal:");
    let projects_now: HashMap<String, (u64, u64)> = containers
      .iter()
      .map(|(p, s)| (p.clone(), (s.rx, s.tx)))
      .collect();
    let prev = self.prev.replace(Prev {
      host_at,
      containers_at,
      cpu,
      net,
      projects: projects_now,
      agent_cpu: agent.0,
    });
    let unix_now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs();
    let Some(prev) = prev else {
      self.events_since.get_or_insert(unix_now);
      return None;
    };
    let host_secs =
      host_at.duration_since(prev.host_at).as_secs_f64().max(1.0);
    let container_secs = containers_at
      .duration_since(prev.containers_at)
      .as_secs_f64()
      .max(1.0);
    let rate =
      |delta: u64, secs: f64| (delta as f64 / secs).round() as u64;
    let rx_bytes = net.0.saturating_sub(prev.net.0);
    let tx_bytes = net.1.saturating_sub(prev.net.1);
    let oom = if let Some(since) =
      self.events_since.filter(|since| *since <= unix_now)
    {
      let from = since.max(unix_now.saturating_sub(600));
      let events = oom_events(docker, from, unix_now, ctx).await;
      self.accept_oom(unix_now, events)
    } else {
      self.events_since = Some(unix_now);
      None
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
            (
              rate(s.rx.saturating_sub(*rx), container_secs),
              rate(s.tx.saturating_sub(*tx), container_secs),
            )
          });
        let m = ProjectMetrics {
          components: s
            .components
            .into_iter()
            .map(|(name, mut metrics)| {
              metrics.cpu /= cpus;
              (name, metrics)
            })
            .collect(),
          cpu: s.cpu / cpus,
          mem: s.mem,
          net_rx: rx,
          net_tx: tx,
        };
        (name, m)
      })
      .collect();
    let agent_cpu = agent.0.zip(prev.agent_cpu).and_then(
      |((cgroup, now), (was_cgroup, old))| {
        (cgroup == was_cgroup).then(|| {
          (100.0 * now.saturating_sub(old) as f64
            / (host_secs * 1e6 * f64::from(cpus)))
          .min(100.0) as f32
        })
      },
    );
    let inode = disk.and_then(|(_, inode)| inode);
    let disk = disk.map(|(disk, _)| disk);
    Some(Metrics {
      agent_cpu,
      agent_mem: agent.1,
      inode_used: inode.map(|(used, _)| used),
      inode_total: inode.map(|(_, total)| total),
      cpu: if total == 0 {
        0.0
      } else {
        100.0 * (total - idle.min(total)) as f32 / total as f32
      },
      mem_used: mem_total
        .saturating_sub(meminfo(&mem, "MemAvailable:")),
      mem_total,
      net_rx: rate(rx_bytes, host_secs),
      net_tx: rate(tx_bytes, host_secs),
      net_rx_bytes: Some(rx_bytes),
      net_tx_bytes: Some(tx_bytes),
      disk_used: disk.map_or(0, |d| d.total.saturating_sub(d.free)),
      disk_total: disk.map_or(0, |d| d.total),
      projects,
      hosts,
      oom,
    })
  }

  fn accept_oom(
    &mut self,
    until: u64,
    events: Option<Vec<OomEvent>>,
  ) -> Option<Vec<String>> {
    let events = events?;
    self.events_since = Some(until);
    let cutoff = until.saturating_sub(120) * 1_000_000_000;
    self.seen_oom.retain(|(at, _)| *at >= cutoff);
    let mut projects = BTreeSet::new();
    for event in events {
      let key = (event.at, event.id);
      if !self.seen_oom.contains(&key) {
        if event.at >= cutoff {
          self.seen_oom.push_back(key);
        }
        projects.insert(event.project);
      }
    }
    Some(projects.into_iter().collect())
  }
}

struct OomEvent {
  at: u64,
  id: String,
  project: String,
}

async fn oom_events(
  docker: &Docker,
  since: u64,
  until: u64,
  ctx: &Ctx,
) -> Option<Vec<OomEvent>> {
  let result = docker
    .cmd()
    .args([
      "events".to_string(),
      "--since".into(),
      since.to_string(),
      "--until".into(),
      until.to_string(),
      "--filter".into(),
      "type=container".into(),
      "--filter".into(),
      "event=oom".into(),
      "--format".into(),
      "{{.TimeNano}} {{.Actor.ID}} {{index .Actor.Attributes \"com.docker.compose.project\"}}".into(),
    ])
    .timeout(STATS_TIMEOUT)
    .run(ctx)
    .await;
  match result {
    Ok(out) if out.success => Some(parse_oom(&out.stdout)),
    Ok(out) => {
      tracing::warn!(code = ?out.code, "读取容器 OOM 事件失败");
      None
    }
    Err(e) => {
      tracing::warn!("读取容器 OOM 事件失败：{e}");
      None
    }
  }
}

fn parse_oom(text: &str) -> Vec<OomEvent> {
  text
    .lines()
    .filter_map(|line| {
      let mut fields = line.splitn(3, ' ');
      let at = fields.next()?.parse().ok()?;
      let id = fields.next()?;
      let project = fields.next()?.trim();
      (!id.is_empty()
        && !project.is_empty()
        && project != "<no value>")
        .then(|| OomEvent {
          at,
          id: id.into(),
          project: project.into(),
        })
    })
    .collect()
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
  components: BTreeMap<String, ComponentMetrics>,
  cpu: f32,
  mem: u64,
  rx: u64,
  tx: u64,
}

/// 按 compose project 合计。不属于任何 project 的容器不算。
async fn container_stats(
  docker: &Docker,
  ctx: &Ctx,
) -> BTreeMap<String, Stat> {
  let run = |args: &'static [&'static str]| {
    docker
      .cmd()
      .args(args.iter().copied())
      .timeout(STATS_TIMEOUT)
      .run(ctx)
  };
  let (ps, stats) = tokio::join!(
    run(&[
      "ps",
      "--format",
      "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.oneoff\"}}",
    ]),
    run(&["stats", "--no-stream", "--format", "{{json .}}"]),
  );
  let (Ok(ps), Ok(stats)) = (ps, stats) else {
    return BTreeMap::new();
  };
  let project: HashMap<&str, (&str, Option<&str>)> = ps
    .stdout
    .lines()
    .filter_map(|line| {
      let mut fields = line.split('\t');
      let (name, project, component, cwd, oneoff) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
      );
      if project.is_empty()
        || project.starts_with(TRIAL_PROJECT_PREFIX)
      {
        return None;
      }
      let managed = !component.is_empty()
        && oneoff.eq_ignore_ascii_case("false")
        && std::path::Path::new(cwd) == docker.project_dir(project);
      Some((name, (project, managed.then_some(component))))
    })
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
    let Some(&(p, component)) = project.get(row.name.as_str()) else {
      continue;
    };
    let e = out.entry(p.to_string()).or_default();
    let cpu =
      row.cpu.trim_end_matches('%').parse::<f32>().unwrap_or(0.0);
    let mem = first_size(&row.mem_usage);
    e.cpu += cpu;
    e.mem = e.mem.saturating_add(mem);
    if let Some(component) = component {
      let entry = e.components.entry(component.into()).or_default();
      entry.cpu += cpu;
      entry.mem = entry.mem.saturating_add(mem);
    }
    let (rx, tx) = row.net.split_once('/').unwrap_or(("", ""));
    e.rx += size(rx);
    e.tx += size(tx);
  }
  out
}

pub(crate) fn first_size(s: &str) -> u64 {
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
  fn oom_cursor_holds_on_error_and_deduplicates_boundary() {
    let mut sampler = Sampler {
      events_since: Some(5),
      ..Sampler::default()
    };
    assert_eq!(sampler.accept_oom(10, None), None);
    assert_eq!(sampler.events_since, Some(5));
    let events = || {
      Some(parse_oom(
        "10000000000 c1 web\n10000000000 c2 <no value>\n",
      ))
    };
    assert_eq!(
      sampler.accept_oom(10, events()),
      Some(vec!["web".into()])
    );
    assert_eq!(sampler.events_since, Some(10));
    assert_eq!(sampler.accept_oom(11, events()), Some(vec![]));
  }

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
