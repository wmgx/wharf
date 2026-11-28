//! 服务日志、端口、长期停止和心跳监控。HTTP 健康检查仍由 monitor 管理。

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  sync::{Arc, Mutex},
  time::Duration,
};

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ContainerInfo},
  service_checks::{
    LogAlertView, LogHit, LogWatch, PortCheck, PortCheckSpec,
  },
  spec::ServiceSpec,
  view::{Issue, IssueLevel, IssueSubject, OpStatus},
};

use crate::{
  db::now_ms,
  rules,
  snapshot::Snapshot,
  state::AppState,
  world::{ServiceRow, World},
};

pub mod heartbeat;
#[cfg(test)]
mod tests;
pub mod unmanaged;

const MINUTE: i64 = 60_000;
const DAY: i64 = 24 * 60 * MINUTE;
const LOG_METRIC: &str = "log.count_over_minimum";
const PORT_METRIC: &str = "port.ok";

#[derive(Default)]
struct Hits {
  batches: VecDeque<(i64, u32)>,
  last: Option<i64>,
  started_at: i64,
  lines: VecDeque<String>,
}

impl Hits {
  fn add(&mut self, hit: LogHit, now: i64) {
    let at = hit.at.min(now);
    self.last = Some(self.last.unwrap_or(at).max(at));
    self.batches.push_back((at, hit.count));
    for line in hit.lines.into_iter().take(3) {
      if self.lines.len() == 3 {
        self.lines.pop_front();
      }
      self.lines.push_back(line.chars().take(300).collect());
    }
  }

  fn value(&mut self, watch: &LogWatch, now: i64) -> (f64, u64) {
    let since = now - i64::from(watch.spec.window_mins) * MINUTE;
    self.batches.retain(|(at, _)| *at > since);
    let count: u64 =
      self.batches.iter().map(|(_, n)| u64::from(*n)).sum();
    if count == 0 {
      self.lines.clear();
      (-f64::MAX, 0)
    } else {
      (count as f64 - f64::from(watch.spec.min_count), count)
    }
  }
}

#[derive(Default)]
struct Memory {
  watches: BTreeMap<String, Vec<LogWatch>>,
  hits: BTreeMap<String, Hits>,
  ports: BTreeMap<String, (i64, bool)>,
  old_agents: BTreeSet<String>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);
static LOG_UPDATE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

fn memory<T>(f: impl FnOnce(&mut Memory) -> T) -> T {
  f(MEMORY.lock().unwrap().get_or_insert_with(Memory::default))
}

pub fn validate(
  spec: &ServiceSpec,
  previous: Option<&ServiceSpec>,
) -> Result<(), ApiError> {
  if spec.log_alerts.len() > 20 {
    return Err(ApiError::invalid(
      "每个服务最多有 20 条日志告警规则",
    ));
  }
  for alert in &spec.log_alerts {
    if previous.is_some_and(|p| p.log_alerts.contains(alert)) {
      alert.compile_stored()?;
    } else {
      alert.compile()?;
    }
  }
  for (name, check) in &spec.port_checks {
    let port =
      spec.ports.iter().find(|p| &p.name == name).ok_or_else(
        || ApiError::invalid(format!("服务没有端口 {name}")),
      )?;
    if previous
      .is_some_and(|p| p.port_checks.get(name) == Some(check))
    {
      check.validate_stored(port.udp)?;
    } else {
      check.validate(port.udp)?;
    }
  }
  if let Some(heartbeat) = &spec.heartbeat
    && !previous.and_then(|p| p.heartbeat.as_ref()).is_some_and(
      |previous| {
        previous.every_mins == heartbeat.every_mins
          && previous.grace_mins == heartbeat.grace_mins
      },
    )
  {
    heartbeat.validate()?;
  }
  Ok(())
}

pub fn config_only(old: &ServiceRow, new: &ServiceRow) -> bool {
  let mut stripped = new.clone();
  stripped.spec.log_alerts.clone_from(&old.spec.log_alerts);
  stripped.spec.port_checks.clone_from(&old.spec.port_checks);
  if let (Some(old), Some(new)) =
    (&old.spec.heartbeat, &mut stripped.spec.heartbeat)
    && old.token == new.token
  {
    new.clone_from(old);
  }
  old != new && &stripped == old
}

pub(crate) fn watches(
  world: &World,
) -> BTreeMap<String, Vec<LogWatch>> {
  let mut watches = BTreeMap::<String, Vec<LogWatch>>::new();
  for (name, row) in &world.services {
    if row.spec.stopped {
      continue;
    }
    let mut duplicates = BTreeMap::<String, usize>::new();
    for spec in &row.spec.log_alerts {
      // 相同配置调整顺序仍保留状态。同一服务迁移后重新累计。
      let input = serde_json::to_vec(&(name, &row.spec.server, spec))
        .unwrap_or_default();
      let hash = hex::encode(Sha256::digest(input));
      let occurrence = duplicates.entry(hash.clone()).or_default();
      let id = format!("{name}:{hash}:{occurrence}");
      *occurrence += 1;
      watches.entry(row.spec.server.clone()).or_default().push(
        LogWatch {
          id,
          project: name.clone(),
          spec: spec.clone(),
        },
      );
    }
  }
  watches
}

pub async fn sync_watches(
  state: &AppState,
  connecting: Option<&str>,
) {
  let _lock = LOG_UPDATE.lock().await;
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let new = watches(&snap.world);
  let keep: BTreeSet<_> =
    new.values().flatten().map(|w| w.id.clone()).collect();
  memory(|m| {
    let old = std::mem::replace(&mut m.watches, new);
    m.hits.retain(|id, _| keep.contains(id));
    let started_at = now_ms();
    for id in &keep {
      m.hits.entry(id.clone()).or_insert_with(|| Hits {
        started_at,
        ..Hits::default()
      });
    }
    for server in
      old.keys().chain(m.watches.keys()).collect::<BTreeSet<_>>()
    {
      if old.get(server) != m.watches.get(server)
        || connecting == Some(server.as_str())
      {
        state.hub.log_watches(
          server,
          m.watches.get(server).cloned().unwrap_or_default(),
        );
      }
    }
    if let Some(server) = connecting
      && !old.contains_key(server)
      && !m.watches.contains_key(server)
      && state.hub.supports_service_checks(server)
    {
      state.hub.log_watches(server, vec![]);
    }
  });
  rules::retain_subjects(state, "log_keyword", &keep).await;
}

pub fn report(server: &str, hits: Vec<LogHit>) {
  if hits.is_empty() {
    return;
  }
  let now = now_ms();
  memory(|m| {
    let Some(watches) = m.watches.get(server) else {
      return;
    };
    for hit in hits {
      if hit.count > 0 && watches.iter().any(|w| w.id == hit.id) {
        m.hits.entry(hit.id.clone()).or_default().add(hit, now);
      }
    }
  });
}

async fn logs(state: &AppState) {
  let _lock = LOG_UPDATE.lock().await;
  let now = now_ms();
  let updates = memory(|m| {
    let mut out = Vec::new();
    for (server, list) in &m.watches {
      if !state.hub.supports_service_checks(server) {
        continue;
      }
      for watch in list {
        // 无命中时也上报，窗口清零才恢复。
        let window = m.hits.entry(watch.id.clone()).or_default();
        let (value, count) = window.value(watch, now);
        if count == 0
          && window.last.is_none()
          && rules::firing_since("log_keyword", &watch.id).is_none()
          && now - window.started_at
            < i64::from(watch.spec.window_mins) * MINUTE
        {
          continue;
        }
        let pattern = &watch.spec.pattern;
        let body = if count == 0 {
          format!(
            "关键字 {pattern} 已有 {} 分钟没有命中",
            watch.spec.window_mins
          )
        } else {
          let lines = window
            .lines
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n");
          format!(
            "关键字 {pattern} 在最近 {} 分钟命中 {count} 次\n{lines}",
            watch.spec.window_mins
          )
        };
        out.push((watch.id.clone(), value, body));
      }
    }
    out
  });
  for (id, value, body) in updates {
    rules::observe(state, LOG_METRIC, &id, value, &body).await;
  }
}

pub fn log_views(
  name: &str,
  spec: &ServiceSpec,
) -> Vec<LogAlertView> {
  let firing = rules::firing_subjects("log_keyword");
  memory(|m| {
    let active = m
      .watches
      .get(&spec.server)
      .into_iter()
      .flatten()
      .filter(|w| w.project == name)
      .collect::<Vec<_>>();
    spec
      .log_alerts
      .iter()
      .enumerate()
      .map(|(i, rule)| {
        let id = active
          .get(i)
          .filter(|w| &w.spec == rule)
          .map(|w| w.id.as_str());
        LogAlertView {
          pattern: rule.pattern.clone(),
          last_hit: id
            .and_then(|id| m.hits.get(id))
            .and_then(|h| h.last),
          firing: id
            .is_some_and(|id| firing.iter().any(|(s, _)| s == id)),
        }
      })
      .collect()
  })
}

pub(crate) fn ports(
  row: &ServiceRow,
) -> impl Iterator<Item = (&str, PortCheck)> {
  row.spec.ports.iter().filter_map(|p| {
    let port = row.host_ports.get(&p.name).copied().or(p.host)?;
    let udp = match (p.udp, row.spec.port_checks.get(&p.name)) {
      (_, Some(PortCheckSpec::Off)) | (true, None) => return None,
      (true, check) => check.cloned(),
      (false, _) => None,
    };
    Some((p.name.as_str(), PortCheck { port, udp }))
  })
}

pub fn port_views(
  service: &str,
  row: &ServiceRow,
  applied_at: i64,
) -> BTreeMap<String, bool> {
  if row.spec.stopped {
    return BTreeMap::new();
  }
  memory(|m| {
    ports(row)
      .filter_map(|(name, _)| {
        let &(at, ok) = m.ports.get(&format!("{service}:{name}"))?;
        (at >= applied_at).then(|| (name.to_string(), ok))
      })
      .collect()
  })
}

fn record_port(id: String, at: i64, ok: bool) {
  memory(|m| {
    let entry = m.ports.entry(id).or_insert((at, ok));
    if entry.0 <= at {
      *entry = (at, ok);
    }
  });
}

pub(crate) async fn doctor_ports(
  state: &AppState,
  service: &str,
  row: &ServiceRow,
) -> Vec<wharf_api_types::view::DoctorCheck> {
  use wharf_api_types::view::CheckStatus;
  let targets: Vec<_> = ports(row).collect();
  if targets.is_empty() || row.spec.stopped {
    return vec![];
  }
  let server = &row.spec.server;
  let skip = |detail| {
    vec![crate::doctor::check(
      "port",
      service,
      CheckStatus::Skip,
      detail,
    )]
  };
  if !state.hub.is_online(server) {
    return skip("agent 离线，测不了");
  }
  if !state.hub.supports_service_checks(server) {
    return skip("agent 版本旧，升级后可测端口（wharf upgrade）");
  }
  let at = now_ms();
  let results = state
    .hub
    .call::<Vec<bool>>(
      server,
      AgentOp::PortChecks {
        checks: targets
          .iter()
          .map(|(_, check)| check.clone())
          .collect(),
      },
      Duration::from_secs(10),
      None,
      &CancellationToken::new(),
    )
    .await;
  match results {
    Ok(results) if results.len() == targets.len() => targets
      .into_iter()
      .zip(results)
      .map(|((port, _), ok)| {
        record_port(format!("{service}:{port}"), at, ok);
        let (status, detail) = if ok {
          (CheckStatus::Ok, "通过")
        } else {
          (CheckStatus::Bad, "未通过")
        };
        crate::doctor::check(
          "port",
          service,
          status,
          format!("端口 {port} {detail}"),
        )
      })
      .collect(),
    _ => vec![crate::doctor::check(
      "port",
      service,
      CheckStatus::Bad,
      "未取得端口探测结果",
    )],
  }
}

async fn check_ports(state: &AppState) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let mut active = BTreeSet::new();
  let mut batches = BTreeMap::<&str, Vec<(String, PortCheck)>>::new();
  for (name, row) in &snap.world.services {
    if row.spec.stopped || !snap.applied.contains_key(name) {
      continue;
    }
    let server = row.spec.server.as_str();
    let skip = !state.hub.is_online(server)
      || deploying(&snap, name, now_ms())
      || rules::op_silence::service_busy(state, name);
    for (port, check) in ports(row) {
      let id = format!("{name}:{port}");
      active.insert(id.clone());
      if !skip {
        batches.entry(server).or_default().push((id, check));
      }
    }
  }
  memory(|m| m.ports.retain(|k, _| active.contains(k)));
  rules::retain_subjects(state, "port_down", &active).await;
  let results = futures_util::future::join_all(
    batches.into_iter().map(|(server, targets)| async move {
      if !state.hub.supports_service_checks(server) {
        if memory(|m| m.old_agents.insert(server.to_string())) {
          tracing::info!(
            "服务器 {server} 的 agent 暂不支持端口检查，跳过"
          );
        }
        return None;
      }
      let r = state
        .hub
        .call::<Vec<bool>>(
          server,
          AgentOp::PortChecks {
            checks: targets
              .iter()
              .map(|(_, check)| check.clone())
              .collect(),
          },
          Duration::from_secs(10),
          None,
          &CancellationToken::new(),
        )
        .await
        .ok()?;
      (r.len() == targets.len()).then_some((targets, r))
    }),
  )
  .await;
  let Ok(latest) = crate::snapshot::load(&state.db).await else {
    return;
  };
  for (targets, results) in results.into_iter().flatten() {
    for ((id, check), ok) in targets.into_iter().zip(results) {
      let (name, _) = id.split_once(':').unwrap_or((&id, ""));
      if snap.world.services.get(name)
        != latest.world.services.get(name)
        || deploying(&latest, name, now_ms())
        || !state
          .hub
          .is_online(&latest.world.services[name].spec.server)
      {
        continue;
      }
      record_port(id.clone(), now, ok);
      let suffix = if check.udp.is_some() { "UDP" } else { "TCP" };
      let detail = format!("{suffix} 127.0.0.1:{}", check.port);
      rules::observe(
        state,
        PORT_METRIC,
        &id,
        f64::from(u8::from(ok)),
        &detail,
      )
      .await;
    }
  }
}

fn deploying(snap: &Snapshot, name: &str, now: i64) -> bool {
  snap.ops.get(name).is_some_and(|op| {
    op.status == OpStatus::Running
      || now - op.at.timestamp_millis() < 2 * MINUTE
  }) || snap
    .applied
    .get(name)
    .is_some_and(|a| now - a.at.timestamp_millis() < 2 * MINUTE)
}

pub fn spawn(state: Arc<AppState>) {
  let ports = state.clone();
  tokio::spawn(async move {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      tick.tick().await;
      check_ports(&ports).await;
    }
  });
  tokio::spawn(async move {
    sync_watches(&state, None).await;
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      tick.tick().await;
      tokio::join!(logs(&state), heartbeat::round(&state));
    }
  });
}

pub fn stopped_issue(
  service: &str,
  containers: &[ContainerInfo],
  now: i64,
) -> Option<Issue> {
  let mut latest = i64::MIN;
  for c in containers.iter().filter(|c| !c.foreign) {
    if c.is_active() {
      return None;
    }
    latest = latest.max(c.finished_at?.timestamp_millis());
  }
  let elapsed = now.checked_sub(latest)?;
  (elapsed > 7 * DAY).then(|| Issue {
    code: "service_stopped_long".into(),
    level: IssueLevel::Info,
    subject: Some(IssueSubject {
      kind: "service".into(),
      name: service.into(),
    }),
    title: format!("服务 {service} 已停止 {} 天", elapsed / DAY),
    hint: Some(format!(
      "wharf service rm {service}；wharf service start {service}"
    )),
    ack: None,
    alert: None,
  })
}

pub fn issues(world: &World) -> Vec<Issue> {
  ["log_keyword", "port_down", "heartbeat_late"]
    .into_iter()
    .flat_map(|rule| {
      rules::firing_subjects(rule).into_iter().filter_map(
        move |(subject, title)| {
          let (name, detail) =
            subject.split_once(':').unwrap_or((&subject, ""));
          let row = world.services.get(name)?;
          let active = !row.spec.stopped
            && match rule {
              "log_keyword" => memory(|m| {
                m.watches
                  .get(&row.spec.server)
                  .is_some_and(|w| w.iter().any(|w| w.id == subject))
              }),
              "port_down" => {
                ports(row).any(|(name, _)| name == detail)
              }
              _ => row.spec.heartbeat.is_some(),
            };
          active.then(|| {
            let (alert, ack) = rules::issue_alert(rule, &subject);
            Issue {
              code: rule.into(),
              level: IssueLevel::Fault,
              subject: Some(IssueSubject {
                kind: "service".into(),
                name: name.into(),
              }),
              title,
              hint: None,
              ack,
              alert,
            }
          })
        },
      )
    })
    .collect()
}
