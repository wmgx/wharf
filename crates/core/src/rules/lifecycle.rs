use std::collections::BTreeSet;

use rusqlite::{Connection, params};
use wharf_api_types::{ApiError, spec::RouteSpec};

use super::{
  RULES, resources::service_limit,
  service_overrides::service_of_subject, split_unit, with,
};
use crate::{db, state::AppState, world::World};

const NOTIFY: &str = "notify.state.";

pub(crate) async fn clear(
  state: &AppState,
  rule: &'static str,
  subject: &str,
) {
  let subject = subject.to_string();
  clear_matching(state, move |r, s| r == rule && s == subject).await;
}

pub(crate) async fn clear_matching(
  state: &AppState,
  remove: impl Fn(&str, &str) -> bool + Send + 'static,
) {
  super::ensure_loaded(state).await;
  let result = state
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(db::sql_err)?;
      clear_rows(&tx, &remove)?;
      tx.commit().map_err(db::sql_err)?;
      clear_cache(&remove);
      Ok(())
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("清理告警状态失败：{}", e.message);
  }
}

fn clear_cache(remove: &impl Fn(&str, &str) -> bool) {
  with(|m| {
    m.firing.retain(|(rule, subject), _| !remove(rule, subject));
    m.acks.retain(|(rule, subject), _| !remove(rule, subject));
    m.series.retain(|(metric, subject), _| {
      !RULES
        .iter()
        .any(|r| r.metric == metric && remove(r.id, subject))
        && !m.custom_rules.values().any(|r| {
          r.service == *subject
            && r.metric == *metric
            && remove(&r.name, subject)
        })
    });
  });
}

pub(super) fn clear_rows(
  c: &Connection,
  remove: &impl Fn(&str, &str) -> bool,
) -> Result<(), ApiError> {
  let mut stmt = c.prepare(
    "SELECT rule, subject FROM alert_firing
      UNION SELECT rule, subject FROM alert_acks
      UNION SELECT source, subject FROM alert_digest
        WHERE is_notice = 0 AND recovered_at IS NULL AND subject IS NOT NULL",
  ).map_err(db::sql_err)?;
  let subjects: Vec<(String, String)> = stmt
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .and_then(Iterator::collect)
    .map_err(db::sql_err)?;
  let custom = super::custom::load_from_db(c)?;
  for (rule, subject) in subjects {
    if !remove(&rule, &subject) {
      continue;
    }
    c.execute(
      "DELETE FROM alert_firing WHERE rule = ?1 AND subject = ?2",
      params![rule, subject],
    )
    .map_err(db::sql_err)?;
    c.execute(
      "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
      params![rule, subject],
    )
    .map_err(db::sql_err)?;
    c.execute(
      "DELETE FROM alert_digest WHERE source = ?1 AND subject = ?2 AND is_notice = 0 AND recovered_at IS NULL",
      params![rule, subject],
    ).map_err(db::sql_err)?;
    if let Some(r) = RULES.iter().find(|r| r.id == rule) {
      db::set_setting(
        c,
        &format!("{NOTIFY}{}", (r.key)(&subject)),
        None,
      )?;
    }
  }
  // 旧版本可能只留下去重键，没有对应的触发记录。
  let prefixes: Vec<_> =
    RULES.iter().map(|r| (r.id, (r.key)(""))).collect();
  for (key, _) in db::settings_with_prefix(c, NOTIFY)? {
    let stale = prefixes.iter().any(|(rule, prefix)| {
      if *rule == "host_unit_down" {
        return key
          .strip_prefix("hostunit.")
          .and_then(|s| s.split_once('.'))
          .is_some_and(|(server, unit)| {
            remove(rule, &format!("{server}:{unit}"))
          });
      }
      if *rule == "link_ca_expiring" {
        return key == *prefix && remove(rule, "ca");
      }
      key
        .strip_prefix(prefix.as_str())
        .is_some_and(|subject| remove(rule, subject))
    }) || key
      .strip_prefix("custom.")
      .and_then(|name| custom.get(name))
      .is_some_and(|r| remove(&r.name, &r.service));
    if stale {
      db::set_setting(c, &format!("{NOTIFY}{key}"), None)?;
    }
  }
  Ok(())
}

pub(crate) fn server_alert(
  rule: &str,
  subject: &str,
  server: &str,
) -> bool {
  match rule {
    "server_offline"
    | "clock_skew"
    | "disk_forecast"
    | "traffic_quota"
    | "host_cpu_high"
    | "host_mem_high"
    | "inode_high"
    | "agent_mem_high"
    | "tailnet_key_expiring" => subject == server,
    "expiry_soon" | "expiry_urgent" => {
      subject.strip_prefix("server:") == Some(server)
    }
    "mem_forecast" => subject.strip_prefix("服务器 ") == Some(server),
    "host_unit_down" => split_unit(subject).0 == server,
    "link_loss" | "tailnet_relay" => pair_has(subject, server),
    _ => false,
  }
}

pub(crate) fn pair_has(subject: &str, server: &str) -> bool {
  subject
    .split_once('>')
    .is_some_and(|(a, b)| a == server || b == server)
}

pub(crate) fn stopped_route(
  world: &World,
  route: &RouteSpec,
) -> bool {
  route.upstream.is_none()
    && route.redirect.is_none()
    && world
      .services
      .get(&route.service)
      .is_some_and(|r| r.spec.stopped)
}

pub(crate) struct Changes {
  services: BTreeSet<String>,
  limits: BTreeSet<String>,
  monitors: BTreeSet<String>,
  heartbeats: BTreeSet<String>,
  routes: BTreeSet<String>,
  servers: BTreeSet<String>,
}

impl Changes {
  pub(crate) fn between(old: &World, new: &World) -> Self {
    let mut changes = Self {
      services: BTreeSet::new(),
      limits: BTreeSet::new(),
      monitors: BTreeSet::new(),
      heartbeats: BTreeSet::new(),
      routes: BTreeSet::new(),
      servers: BTreeSet::new(),
    };
    for (name, row) in &old.services {
      let Some(next) = new.services.get(name) else {
        changes.services.insert(name.clone());
        continue;
      };
      if row.instance_id != next.instance_id
        || (!row.spec.stopped && next.spec.stopped)
      {
        changes.services.insert(name.clone());
      } else {
        if service_limit(&row.spec).is_some()
          && service_limit(&next.spec).is_none()
        {
          changes.limits.insert(name.clone());
        }
        if row.spec.monitor.is_some() && next.spec.monitor.is_none() {
          changes.monitors.insert(name.clone());
        }
        if row.spec.heartbeat.is_some()
          && next.spec.heartbeat.is_none()
        {
          changes.heartbeats.insert(name.clone());
        }
      }
    }
    for (host, row) in &old.routes {
      if new.routes.get(host).is_none_or(|next| {
        !stopped_route(old, &row.spec)
          && stopped_route(new, &next.spec)
      }) {
        changes.routes.insert(host.clone());
      }
    }
    changes.servers.extend(
      old
        .servers
        .keys()
        .filter(|name| !new.servers.contains_key(*name))
        .cloned(),
    );
    changes
  }

  fn is_empty(&self) -> bool {
    self.services.is_empty()
      && self.limits.is_empty()
      && self.monitors.is_empty()
      && self.heartbeats.is_empty()
      && self.routes.is_empty()
      && self.servers.is_empty()
  }

  fn matches(&self, rule: &str, subject: &str) -> bool {
    service_of_subject(rule, subject)
      .is_some_and(|svc| self.services.contains(svc))
      || (rule == "svc_mem_near_limit"
        && self.limits.contains(subject))
      || (rule == "monitor_failed" && self.monitors.contains(subject))
      || (rule == "heartbeat_late"
        && self.heartbeats.contains(subject))
      || (matches!(rule, "domain_down" | "cert_expiring")
        && self.routes.contains(subject))
      || self
        .servers
        .iter()
        .any(|name| server_alert(rule, subject, name))
  }

  pub(crate) fn clear_storage(
    &self,
    c: &Connection,
  ) -> Result<(), ApiError> {
    if self.is_empty() {
      return Ok(());
    }
    let custom = super::custom::load_from_db(c)?;
    clear_rows(c, &|rule, subject| {
      self.matches(rule, subject)
        || custom
          .get(rule)
          .is_some_and(|r| self.services.contains(&r.service))
    })
  }

  pub(crate) fn clear_after_commit(&self) {
    if self.is_empty() {
      return;
    }
    crate::probe::forget(&self.routes);
    crate::monitor::forget(&self.services, &self.monitors);
    let custom = with(|m| {
      m.custom_rules
        .iter()
        .filter(|(_, r)| self.services.contains(&r.service))
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>()
    });
    clear_cache(&|rule, subject| {
      self.matches(rule, subject) || custom.contains(rule)
    });
  }
}
