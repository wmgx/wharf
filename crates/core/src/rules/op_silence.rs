use std::collections::{BTreeMap, BTreeSet};

use super::{Rule, Verdict, judge, service_overrides, suppress};
use crate::{planner::Step, state::AppState};

pub(super) const ID: &str = "suppress_ops";
const SUCCESS_MS: i64 = 90_000;
const FAILURE_MS: i64 = 15_000;

#[derive(Default)]
pub(crate) struct Windows(BTreeMap<String, BTreeMap<u64, Window>>);

#[derive(Default)]
struct Window {
  cooldown: Option<(i64, bool)>,
  healthy: BTreeSet<(String, String)>,
}

impl Windows {
  fn expire(&mut self, now: i64) {
    self.0.retain(|_, windows| {
      windows
        .retain(|_, w| w.cooldown.is_none_or(|(end, _)| end > now));
      !windows.is_empty()
    });
  }

  pub(crate) fn start(&mut self, id: u64, service: &str, now: i64) {
    self.expire(now);
    self
      .0
      .entry(service.into())
      .or_default()
      .entry(id)
      .or_default();
  }

  pub(crate) fn finish(&mut self, id: u64, success: bool, now: i64) {
    self.expire(now);
    let duration = if success { SUCCESS_MS } else { FAILURE_MS };
    for windows in self.0.values_mut() {
      if let Some(w) = windows.get_mut(&id)
        && w.cooldown.is_none()
      {
        w.cooldown = Some((now + duration, success));
      }
    }
  }

  pub(crate) fn suppress(
    &mut self,
    service: &str,
    rule: &str,
    subject: &str,
    healthy: bool,
    now: i64,
  ) -> bool {
    self.expire(now);
    let Some(windows) = self.0.get_mut(service) else {
      return false;
    };
    let key = (rule.into(), subject.into());
    if healthy {
      for w in windows
        .values_mut()
        .filter(|w| w.cooldown.is_some_and(|(_, success)| success))
      {
        w.healthy.insert(key.clone());
      }
      return false;
    }
    windows.values().any(|w| !w.healthy.contains(&key))
  }
}

/// 与执行记录用同一批步骤。备份也有独立的执行记录和服务锁。
pub(crate) fn service<'a>(
  step: &'a Step,
  recorded_service: Option<&'a str>,
) -> Option<&'a str> {
  match step {
    Step::Backup { service } => Some(service),
    Step::ServiceDown { .. } => None,
    _ => recorded_service,
  }
}

pub(super) async fn skip_sample(
  state: &AppState,
  rule: &Rule,
  subject: &str,
  value: f64,
  threshold: f64,
  now: i64,
) -> bool {
  if !matches!(
    rule.id,
    "container_restarting"
      | "monitor_failed"
      | "port_down"
      | "heartbeat_late"
      | "http_5xx"
      | "domain_down"
  ) || super::with(|m| {
    m.config.get(ID).is_some_and(|o| !o.enabled())
  }) {
    return false;
  }
  if rule.id == "domain_down" && !state.locks.has_alert_windows(now) {
    return false;
  }
  let healthy = matches!(
    judge(
      rule,
      threshold,
      1,
      &std::collections::VecDeque::from([value])
    ),
    Verdict::Recover
  );
  if rule.id != "domain_down" {
    let skip =
      service_overrides::service_of_subject(rule.id, subject)
        .is_some_and(|service| {
          state
            .locks
            .suppress_alert(service, rule.id, subject, healthy, now)
        });
    if skip && rule.id == "http_5xx" {
      // 受控操作期间的 5xx 不带进下一轮统计。
      crate::http_stats::forget_sample(subject);
    }
    return skip;
  }
  let Some(world) = suppress::load_world(state).await else {
    return false;
  };
  let Some(route) = world.routes.get(subject) else {
    return false;
  };
  // HTTPS 探针只访问域名根路径。
  if route.spec.upstream.is_some() || route.spec.redirect.is_some() {
    return false;
  }
  state.locks.suppress_alert(
    &route.spec.service,
    rule.id,
    subject,
    healthy,
    now,
  )
}

impl Windows {
  pub(crate) fn any(&mut self, now: i64) -> bool {
    self.expire(now);
    !self.0.is_empty()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cooldown_ends_on_healthy_sample_or_deadline() {
    let mut w = Windows::default();
    w.start(1, "s1", 0);
    let sample = |w: &mut Windows, healthy, now| {
      w.suppress("s1", "port_down", "s1:web", healthy, now)
    };
    assert!(sample(&mut w, false, 100_000));
    assert!(!w.suppress("s2", "port_down", "s2:web", false, 100_000));
    w.finish(1, true, 100_000);
    assert!(!sample(&mut w, true, 100_010));
    assert!(!sample(&mut w, false, 100_020));
    assert!(w.suppress(
      "s1",
      "domain_down",
      "s1.example",
      false,
      189_999
    ));
    assert!(!w.suppress(
      "s1",
      "domain_down",
      "s1.example",
      false,
      190_000
    ));
    w.start(2, "s1", 200_000);
    w.finish(2, false, 200_001);
    assert!(!sample(&mut w, true, 214_999));
    assert!(sample(&mut w, false, 215_000));
    assert!(!sample(&mut w, false, 215_001));
  }
}
