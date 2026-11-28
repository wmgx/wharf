use std::{
  collections::{BTreeMap, VecDeque},
  sync::{Arc, Mutex},
};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::Metrics, resources::percent, spec::ServiceSpec,
  view::AlertLevel,
};

use super::{Ctx, Mode, Op, Rule, ev, observe_at};
use crate::{notify::Event, snapshot, state::AppState};

// 容忍连续漏掉两个一分钟采样周期和短暂抖动。
const SAMPLE_GAP_MS: i64 = 210_000;

pub(super) const HOST_CPU: Rule = Rule {
  id: "host_cpu_high",
  name: "CPU 长时间占满",
  metric: "host.cpu",
  for_n: 15,
  key: |s| format!("host.cpu.high.{s}"),
  fire: |c| host_fire(c, "CPU"),
  ok: |c| host_ok(c, "CPU"),
  ..REPORT_RULE
};

pub(super) const HOST_MEM: Rule = Rule {
  id: "host_mem_high",
  name: "内存长时间占满",
  metric: "host.mem_pct",
  key: |s| format!("host.mem.high.{s}"),
  fire: |c| host_fire(c, "内存"),
  ok: |c| host_ok(c, "内存"),
  ..REPORT_RULE
};

const REPORT_RULE: Rule = Rule {
  id: "",
  name: "",
  metric: "",
  op: Op::Gt,
  threshold: 90.0,
  threshold_editable: true,
  for_n: 10,
  mode: Mode::Consecutive,
  recover: None,
  every: "每分钟一次",
  period_secs: 60,
  default_level: AlertLevel::Urgent,
  key: |_| String::new(),
  fire: |_| unreachable!(),
  ok: |_| unreachable!(),
};

pub(super) const SERVICE_MEM: Rule = Rule {
  id: "svc_mem_near_limit",
  name: "服务内存接近上限",
  metric: "svc.mem_pct",
  key: |s| format!("svc.mem.high.{s}"),
  fire: |c| {
    ev(
      format!("服务 {} 内存接近上限", c.subject),
      format!(
        "{}，已用 {:.1}%。确认后重启服务，或调大上限：{}",
        c.detail,
        c.value,
        if c.detail.contains("Compose 上限") {
          "调整 compose 文件里的 mem_limit / deploy.resources.limits.memory".into()
        } else {
          format!(
            "wharf service limits {} --memory <MB> --apply",
            c.subject
          )
        }
      ),
    )
  },
  ok: |c| {
    ev(
      format!("服务 {} 内存回到阈值以下", c.subject),
      format!("{}，已用 {:.1}%", c.detail, c.value),
    )
  },
  ..REPORT_RULE
};

pub(super) const INODE: Rule = Rule {
  id: "inode_high",
  name: "inode 快用完",
  metric: "host.inode_pct",
  for_n: 3,
  key: |s| format!("host.inode.high.{s}"),
  fire: |c| {
    ev(
      format!("服务器 {} 的 inode 快用完", c.subject),
      format!(
        "{}，已用 {:.1}%。小文件过多，常见于日志、缓存、构建目录，用 wharf server disk {} 查占用",
        c.detail, c.value, c.subject
      ),
    )
  },
  ok: |c| host_ok(c, "inode"),
  ..REPORT_RULE
};

pub(super) const MEM_FORECAST: Rule = Rule {
  id: "mem_forecast",
  name: "内存预计用完",
  metric: "mem.days_left",
  op: Op::Lt,
  threshold: 3.0,
  threshold_editable: true,
  for_n: 1,
  mode: Mode::Consecutive,
  recover: Some(5.0),
  every: "每小时一次，按近 3 天趋势",
  period_secs: 3600,
  default_level: AlertLevel::Digest,
  key: |s| format!("mem.forecast.{s}"),
  fire: |c| {
    ev(
      format!("{} 的内存预计 {:.1} 天后用完", c.subject, c.value),
      format!(
        "{}，预计 {:.1} 天用完。可能有内存泄漏，确认后重启或调大上限",
        c.detail, c.value
      ),
    )
  },
  ok: |c| {
    ev(
      format!("{} 的内存不再预计很快用完", c.subject),
      if c.value == f64::MAX {
        "近 3 天内存用量平稳".into()
      } else {
        format!("{}，预计还能用 {:.1} 天", c.detail, c.value)
      },
    )
  },
};

pub(super) const AGENT_MEM: Rule = Rule {
  id: "agent_mem_high",
  name: "agent 内存接近上限",
  metric: "agent.mem_pct",
  threshold: 80.0,
  key: |s| format!("agent.mem.high.{s}"),
  fire: |c| {
    ev(
      format!("服务器 {} 的 agent 内存接近上限", c.subject),
      format!("{}，已用 {:.1}%", c.detail, c.value),
    )
  },
  ok: |c| host_ok(c, "agent 内存"),
  ..REPORT_RULE
};

pub(super) fn is_report_metric(metric: &str) -> bool {
  matches!(
    metric,
    "host.cpu"
      | "host.mem_pct"
      | "svc.cpu"
      | "svc.mem"
      | "svc.mem_pct"
      | "host.inode_pct"
      | "agent.mem_pct"
  )
}

pub(super) fn prepare_sample(
  points: &mut VecDeque<f64>,
  previous_at: i64,
  now: i64,
) -> bool {
  if now <= previous_at {
    return false;
  }
  if now - previous_at >= SAMPLE_GAP_MS {
    points.clear();
  }
  true
}

fn host_fire(c: &Ctx, label: &str) -> Event {
  ev(
    format!("服务器 {} 的 {label} 长时间占满", c.subject),
    format!(
      "当前 {:.1}%，超过 {:.1}% 已持续 {} 分钟。{}",
      c.value, c.threshold, c.for_n, c.detail
    ),
  )
}

fn host_ok(c: &Ctx, label: &str) -> Event {
  ev(
    format!("服务器 {} 的 {label} 回到阈值以下", c.subject),
    format!("当前 {:.1}%", c.value),
  )
}

fn top_projects(m: &Metrics, cpu: bool) -> String {
  let mut projects: Vec<_> = m.projects.iter().collect();
  projects.sort_by(|(_, a), (_, b)| {
    if cpu {
      b.cpu.total_cmp(&a.cpu)
    } else {
      b.mem.cmp(&a.mem)
    }
  });
  let top = projects
    .into_iter()
    .take(3)
    .map(|(name, v)| {
      let name = name
        .strip_prefix(crate::world::GATEWAY_PROJECT_PREFIX)
        .map_or_else(
          || name.clone(),
          |gateway| format!("网关 {gateway}"),
        );
      if cpu {
        format!("{name} {:.1}%", v.cpu)
      } else {
        format!("{name} {}", mib(v.mem as f64))
      }
    })
    .collect::<Vec<_>>()
    .join("、");
  if top.is_empty() {
    "没有服务占用数据".into()
  } else {
    format!("占用最高：{top}")
  }
}

pub(crate) fn mib(bytes: f64) -> String {
  format!("{:.1} MiB", bytes / f64::from(1 << 20))
}

type Limits = BTreeMap<String, (u64, bool)>;
type Sample = (i64, Metrics, Limits, Option<u64>);

pub(crate) async fn settings(
  state: &AppState,
  server: &str,
) -> Option<(u64, Limits)> {
  let snap = snapshot::load(&state.db)
    .await
    .map_err(|e| {
      tracing::warn!("读取资源告警配置失败：{}", e.message);
    })
    .ok()?;
  let settings = &snap.world.servers.get(server)?.settings;
  let limits = snap
    .world
    .services
    .iter()
    .filter_map(|(name, row)| {
      if row.spec.stopped
        || snapshot::service_runtime_server(&snap, name)
          != Some(server)
      {
        return None;
      }
      Some((name.clone(), service_limit_with_source(&row.spec)?))
    })
    .collect();
  Some((settings.agent_memory_bytes(), limits))
}

pub(crate) fn service_limit(spec: &ServiceSpec) -> Option<u64> {
  service_limit_with_source(spec).map(|(bytes, _)| bytes)
}

pub(crate) fn service_limit_with_source(
  spec: &ServiceSpec,
) -> Option<(u64, bool)> {
  if !matches!(
    spec.source,
    wharf_api_types::spec::Source::Compose { .. }
  ) && let Some(mb) = spec
    .limits
    .as_ref()
    .and_then(|l| l.memory_mb)
    .filter(|&n| n > 0)
  {
    return Some((u64::from(mb) << 20, false));
  }
  let (bytes, all_limited) =
    crate::lint::compose_memory_limits(spec)?;
  (all_limited && bytes > 0).then_some((bytes, true))
}

#[derive(Default)]
pub(crate) struct ReportQueue {
  samples: Mutex<VecDeque<Sample>>,
  ready: Notify,
  space: Notify,
}

impl ReportQueue {
  const MAX: usize = 16;
  pub(crate) fn push(&self, sample: Sample) {
    let mut queue =
      self.samples.lock().unwrap_or_else(|e| e.into_inner());
    if queue.len() == Self::MAX {
      queue.pop_front();
    }
    queue.push_back(sample);
    self.ready.notify_one();
  }

  pub(crate) async fn push_backfill(&self, sample: Sample) {
    loop {
      {
        let mut queue =
          self.samples.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() < Self::MAX {
          queue.push_back(sample);
          self.ready.notify_one();
          return;
        }
      }
      self.space.notified().await;
    }
  }

  async fn next(&self) -> Sample {
    loop {
      if let Some(sample) = self
        .samples
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_front()
      {
        self.space.notify_one();
        return sample;
      }
      self.ready.notified().await;
    }
  }
}

pub(crate) fn report_queue(
  state: Arc<AppState>,
  server: String,
  cancel: CancellationToken,
) -> Arc<ReportQueue> {
  let queue = Arc::new(ReportQueue::default());
  let receiver = queue.clone();
  tokio::spawn(async move {
    let process = async {
      loop {
        let (at, m, limits, agent_limit) = receiver.next().await;
        observe_report(&state, at, &server, &m, &limits, agent_limit)
          .await;
      }
    };
    tokio::select! {
      _ = cancel.cancelled() => {},
      _ = process => {},
    }
  });
  queue
}

async fn observe_report(
  state: &AppState,
  at: i64,
  server: &str,
  m: &Metrics,
  limits: &Limits,
  agent_limit: Option<u64>,
) {
  observe_at(
    state,
    at,
    HOST_CPU.metric,
    server,
    f64::from(m.cpu),
    &top_projects(m, true),
  )
  .await;
  if let Some(pct) = percent(m.mem_used, m.mem_total) {
    observe_at(
      state,
      at,
      HOST_MEM.metric,
      server,
      pct,
      &top_projects(m, false),
    )
    .await;
  }
  for (name, v) in m.projects.iter().filter(|(name, _)| {
    !name.starts_with(crate::world::GATEWAY_PROJECT_PREFIX)
  }) {
    let server_detail = format!("服务器 {server}");
    observe_at(
      state,
      at,
      "svc.cpu",
      name,
      f64::from(v.cpu),
      &server_detail,
    )
    .await;
    // 单位为 MB（MiB，1 MB = 1024*1024 字节），与 wharf top / service limits 一致。
    let mem_mb = v.mem as f64 / f64::from(1 << 20);
    observe_at(state, at, "svc.mem", name, mem_mb, &server_detail)
      .await;
  }
  for (name, used, total, compose) in
    limits.iter().filter_map(|(name, &(total, compose))| {
      Some((name, m.projects.get(name)?.mem, total, compose))
    })
  {
    if let Some(pct) = percent(used, total) {
      let detail = format!(
        "服务器 {server}，当前 {}，{}上限 {}",
        mib(used as f64),
        if compose { "Compose " } else { "" },
        mib(total as f64)
      );
      observe_at(state, at, SERVICE_MEM.metric, name, pct, &detail)
        .await;
    }
  }
  if let Some((used, total)) = m.inode_used.zip(m.inode_total)
    && let Some(pct) = percent(used, total)
  {
    observe_at(
      state,
      at,
      INODE.metric,
      server,
      pct,
      &format!("已用 {used}，共 {total}"),
    )
    .await;
  }
  if let Some((used, total)) = m.agent_mem.zip(agent_limit)
    && let Some(pct) = percent(used, total)
  {
    let detail = format!(
      "当前 {}，上限 {}",
      mib(used as f64),
      mib(total as f64)
    );
    observe_at(state, at, AGENT_MEM.metric, server, pct, &detail)
      .await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rules::{Verdict, judge};

  #[test]
  fn host_cpu_needs_15_points() {
    let mut points = VecDeque::from(vec![91.0; 14]);
    let judge = |p: &VecDeque<f64>| {
      judge(&HOST_CPU, HOST_CPU.threshold, HOST_CPU.for_n, p)
    };
    assert!(matches!(judge(&points), Verdict::Hold));
    points.push_back(91.0);
    assert!(matches!(judge(&points), Verdict::Fire));
    points.push_back(90.0);
    assert!(matches!(judge(&points), Verdict::Hold));
    points.push_back(89.0);
    assert!(matches!(judge(&points), Verdict::Recover));
  }

  #[test]
  fn cpu_window_survives_single_skip_and_top_includes_gateway() {
    let mut points = VecDeque::from(vec![91.0; 14]);
    for gap in [120_000, 180_000] {
      assert!(prepare_sample(&mut points, 0, gap));
      assert_eq!(points.len(), 14);
    }
    assert!(prepare_sample(&mut points, 0, 240_000));
    assert!(points.is_empty());
    let mut metrics = Metrics::default();
    metrics.projects.insert(
      "wharf-gw-edge".into(),
      wharf_api_types::agent::ProjectMetrics {
        cpu: 90.0,
        ..Default::default()
      },
    );
    assert!(top_projects(&metrics, true).contains("网关 edge 90.0%"));
  }

  #[test]
  fn service_limit_reads_compose_yaml_memory() {
    let limit = |extra: &str| {
      let spec = serde_json::from_value(serde_json::json!({
        "server":"s1", "limits":{}, "source":{"compose":{"content":format!("services:\n  web: {{mem_limit: 256m}}\n  db: {{{extra}}}")}}
      })).unwrap();
      service_limit_with_source(&spec)
    };
    assert_eq!(
      limit("deploy: {resources: {limits: {memory: 512M}}}"),
      Some((768 << 20, true))
    );
    assert_eq!(limit("image: redis"), None);
  }

  #[test]
  fn memory_forecast_has_hysteresis() {
    let judge = |v| {
      judge(
        &MEM_FORECAST,
        MEM_FORECAST.threshold,
        MEM_FORECAST.for_n,
        &VecDeque::from([v]),
      )
    };
    assert!(matches!(judge(2.9), Verdict::Fire));
    assert!(matches!(judge(4.0), Verdict::Hold));
    assert!(matches!(judge(5.1), Verdict::Recover));
  }
}
