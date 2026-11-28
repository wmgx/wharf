use std::collections::{BTreeMap, BTreeSet};

use super::{Mode, Rule, service_overrides, suppress};
use crate::{
  notify::Event,
  planner::{Step, StepPlan},
  state::AppState,
};

pub(super) const ID: &str = "suppress_ops";
const SUCCESS_MS: i64 = 90_000;
const FAILURE_MS: i64 = 15_000;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Target {
  Service(String),
  Server(String),
  Docker(String),
  Tailnet(String),
  Gateway(String),
}

#[derive(Default)]
pub(crate) struct Windows(BTreeMap<u64, Window>);

struct Window {
  targets: BTreeSet<Target>,
  reason: String,
  cooldown: Option<(i64, bool)>,
  recorded: BTreeSet<(String, String)>,
}

impl Windows {
  pub(crate) fn any(&mut self, now: i64) -> bool {
    self
      .0
      .retain(|_, w| w.cooldown.is_none_or(|(end, _)| end > now));
    !self.0.is_empty()
  }

  pub(crate) fn active_service(&self, service: &str) -> bool {
    self.0.values().any(|window| {
      window.cooldown.is_none() && window.targets.iter().any(|target| {
        matches!(target, Target::Service(name) if name == service)
      })
    })
  }

  pub(crate) fn start(
    &mut self,
    id: u64,
    targets: BTreeSet<Target>,
    reason: String,
    now: i64,
  ) {
    self.any(now);
    if !targets.is_empty() {
      self.0.insert(
        id,
        Window {
          targets,
          reason,
          cooldown: None,
          recorded: BTreeSet::new(),
        },
      );
    }
  }

  pub(crate) fn finish(&mut self, id: u64, success: bool, now: i64) {
    let duration = if success { SUCCESS_MS } else { FAILURE_MS };
    if let Some(w) = self.0.get_mut(&id)
      && w.cooldown.is_none()
    {
      w.cooldown = Some((now + duration, success));
    }
  }

  pub(crate) fn sample(
    &mut self,
    targets: &BTreeSet<Target>,
    rule: &str,
    subject: &str,
    healthy: bool,
    now: i64,
  ) -> (bool, Vec<String>) {
    self.any(now);
    let mut skip = false;
    let mut reasons = Vec::new();
    for window in self.0.values_mut() {
      if window.targets.is_disjoint(targets) {
        continue;
      }
      if healthy {
        if window.cooldown.is_some_and(|(_, success)| success) {
          window.targets.retain(|target| !targets.contains(target));
        }
      } else {
        skip = true;
        if window.recorded.insert((rule.into(), subject.into())) {
          reasons.push(window.reason.clone());
        }
      }
    }
    (skip, reasons)
  }
}

pub(crate) fn steps_scope(steps: &[StepPlan]) -> BTreeSet<Target> {
  let mut targets = BTreeSet::new();
  for step in steps {
    let target = match &step.step {
      Step::ServiceUp { service, .. }
      | Step::Rebuild { service }
      | Step::VolumeSync { service, .. }
      | Step::Backup { service }
      | Step::Restore { service, .. }
      | Step::ServiceRestart { service, .. }
      | Step::ServiceStop { service }
      | Step::ServiceDown { service, .. } => {
        Target::Service(service.clone())
      }
      Step::AgentUpgrade { server } => Target::Server(server.clone()),
      Step::AgentUpgrades { servers } => {
        targets.extend(servers.iter().cloned().map(Target::Server));
        continue;
      }
      Step::DockerProxy { server } => Target::Docker(server.clone()),
      Step::TailscaleUp { server } => Target::Tailnet(server.clone()),
      Step::GatewaySync { gateway, .. }
      | Step::GatewayDown { gateway, .. } => {
        Target::Gateway(gateway.clone())
      }
      _ => continue,
    };
    targets.insert(target);
  }
  targets
}

pub(crate) fn enabled() -> bool {
  super::with(|m| {
    m.config.get(ID).is_none_or(super::Override::enabled)
  })
}

pub(crate) fn service_busy(state: &AppState, service: &str) -> bool {
  enabled()
    && state.is_service_busy(service)
    && state.locks.has_active_service_silence(service)
}

pub(super) async fn skip_sample(
  state: &AppState,
  rule: &Rule,
  subject: &str,
  value: f64,
  threshold: f64,
  now: i64,
) -> bool {
  let mut targets = BTreeSet::new();
  let service = match rule.id {
    "container_restarting"
    | "monitor_failed"
    | "port_down"
    | "heartbeat_late"
    | "http_5xx" => {
      service_overrides::service_of_subject(rule.id, subject)
    }
    "domain_down" | "server_offline" | "host_unit_down"
    | "link_loss" | "tailnet_relay" => None,
    _ => return false,
  };
  if !enabled() || !state.locks.has_alert_windows(now) {
    return false;
  }
  if let Some(service) = service {
    targets.insert(Target::Service(service.into()));
    if let Some(world) = suppress::load_world(state).await
      && let Some(row) = world.services.get(service)
    {
      targets.insert(Target::Docker(row.spec.server.clone()));
    }
  } else if rule.id == "domain_down" {
    let Some(world) = suppress::load_world(state).await else {
      return false;
    };
    let Some(route) = world.routes.get(subject) else {
      return false;
    };
    if let Some(gateway) = world.live_gateway(subject, &route.spec) {
      targets.insert(Target::Gateway(gateway.into()));
    }
    targets.extend(
      std::iter::once(route.spec.service.as_str())
        .filter(|s| !s.is_empty())
        .chain(
          route
            .spec
            .paths
            .iter()
            .filter_map(|p| p.service.as_deref()),
        )
        .map(|s| Target::Service(s.into())),
    );
    for server in suppress::related_servers(
      rule.id,
      subject,
      &world,
      &BTreeMap::new(),
    ) {
      targets.insert(Target::Docker(server.clone()));
      targets.insert(Target::Tailnet(server));
    }
  } else {
    let servers = if matches!(rule.id, "link_loss" | "tailnet_relay")
    {
      subject
        .split_once('>')
        .into_iter()
        .flat_map(|(a, b)| [a, b])
        .collect::<Vec<_>>()
    } else {
      vec![super::split_unit(subject).0]
    };
    for server in servers {
      targets.insert(Target::Server(server.into()));
      targets.insert(Target::Docker(server.into()));
      targets.insert(Target::Tailnet(server.into()));
    }
  }
  let healthy = !(rule.op.hit(value, threshold)
    || (matches!(rule.mode, Mode::Heartbeat) && value == f64::MAX));
  let (skip, reasons) = state
    .locks
    .alert_sample(&targets, rule.id, subject, healthy, now);
  for reason in reasons {
    super::record_at(
      state,
      now,
      rule.id,
      Some(subject),
      &Event {
        title: format!("{}：{subject}", rule.name),
        body: String::new(),
      },
      false,
      Some(format!("被抑制：{reason}")),
    )
    .await;
  }
  if skip && rule.id == "http_5xx" {
    crate::http_stats::forget_sample(subject);
  }
  skip
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cooldown_ends_on_healthy_sample_or_deadline() {
    let mut w = Windows::default();
    let targets = BTreeSet::from([Target::Service("web".into())]);
    w.start(1, targets.clone(), "备份 web".into(), 0);
    assert_eq!(
      w.sample(&targets, "port_down", "web:http", false, 100_000),
      (true, vec!["备份 web".into()])
    );
    assert_eq!(
      w.sample(&targets, "port_down", "web:http", false, 100_000),
      (true, vec![])
    );
    w.finish(1, true, 100_000);
    assert!(
      !w.sample(&targets, "port_down", "web:http", true, 100_010).0
    );
    assert!(
      !w.sample(
        &targets,
        "domain_down",
        "web.example",
        false,
        100_020
      )
      .0
    );
    w.start(2, targets.clone(), "备份 web".into(), 200_000);
    w.finish(2, false, 200_001);
    assert!(
      !w.sample(&targets, "port_down", "web:http", true, 214_999).0
    );
    assert!(
      w.sample(&targets, "port_down", "web:http", false, 215_000)
        .0
    );
    assert!(
      !w.sample(&targets, "port_down", "web:http", false, 215_001)
        .0
    );
  }
}
