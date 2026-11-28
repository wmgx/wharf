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
  rule: &str,
  subject: &str,
) {
  let rule = rule.to_string();
  let subject = subject.to_string();
  clear_matching(state, move |r, s| {
    r == rule
      && (s == subject
        || (r == "external_incident"
          && s.eq_ignore_ascii_case(&subject)))
  })
  .await;
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
      Ok(clear_cache(&remove))
    })
    .await;
  match result {
    Ok(true) => {
      super::suppress::schedule_unsuppress(state, db::now_ms()).await
    }
    Ok(false) => {}
    Err(e) => tracing::warn!("清理告警状态失败：{}", e.message),
  }
}

fn clear_cache(remove: &impl Fn(&str, &str) -> bool) -> bool {
  with(|m| {
    let before = m.firing.len();
    m.firing.retain(|(rule, subject), _| !remove(rule, subject));
    m.unsuppress_grace
      .retain(|(rule, subject), _| !remove(rule, subject));
    m.acks.retain(|(rule, subject), _| !remove(rule, subject));
    m.series.retain(|(metric, subject), _| {
      let mut rules = RULES
        .iter()
        .filter(|r| r.metric == metric)
        .map(|r| r.id)
        .chain(
          m.custom_rules
            .values()
            .filter(|r| r.service == *subject && r.metric == *metric)
            .map(|r| r.name.as_str()),
        )
        .peekable();
      rules.peek().is_none()
        || !rules.all(|rule| remove(rule, subject))
    });
    before != m.firing.len()
  })
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
  let mut prefixes: Vec<_> =
    RULES.iter().map(|r| (r.id, (r.key)(""))).collect();
  prefixes.sort_by_key(|(_, prefix)| std::cmp::Reverse(prefix.len()));
  for (key, _) in db::settings_with_prefix(c, NOTIFY)? {
    let stale = prefixes
      .iter()
      .find(|(_, prefix)| key.starts_with(prefix))
      .is_some_and(|(rule, prefix)| {
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
      })
      || key
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
    && !route.paths.iter().any(|p| active_path(world, p))
    && world
      .services
      .get(&route.service)
      .is_some_and(|r| r.spec.stopped)
}

pub(crate) fn active_path(
  world: &World,
  path: &wharf_api_types::spec::PathRoute,
) -> bool {
  path.upstream.is_some()
    || path
      .service
      .as_deref()
      .is_some_and(|name| running_service(world, name))
}

pub(crate) fn running_service(world: &World, name: &str) -> bool {
  world
    .services
    .get(name)
    .is_some_and(|row| !row.spec.stopped)
}

pub(crate) fn active_route(
  world: &World,
  host: &str,
  now: i64,
) -> bool {
  world.edge_domain(host).is_some()
    || world.routes.get(host).is_some_and(|row| {
      !stopped_route(world, &row.spec)
        && row.spec.expires_at.is_none_or(|end| end > now)
    })
}

pub(crate) fn route_has_tls(world: &World, host: &str) -> bool {
  world.edge_domain(host).is_some()
    || world.routes.get(host).is_some_and(|row| {
      world
        .live_gateway(host, &row.spec)
        .and_then(|name| world.gateways.get(name))
        .is_none_or(|gateway| {
          gateway.spec.tls != wharf_api_types::spec::GatewayTls::Off
        })
    })
}

pub(crate) fn forget_server(server: &str) {
  crate::clock::forget_server(server);
  crate::disk_forecast::forget_server(server);
  crate::quality::forget_server(server);
  crate::vendor_checks::forget_server(server);
  crate::tailnet_probe::forget_server(server);
}

pub(crate) async fn reconcile_world(
  state: &AppState,
  snap: crate::snapshot::Snapshot,
) -> Result<(), ApiError> {
  let now = db::now_ms();
  let host_units =
    crate::host_units::watched_subjects(state, &snap.world).await?;
  let external_pages =
    crate::external_status::enabled_names(state).await?;
  let tailnet = crate::tailnet_probe::addresses(&snap);
  let net = snap.net(&snap.world);
  let certs = crate::link_cert::leaf_expiries(&snap, &net)
    .map(|(name, _)| name.to_string())
    .collect::<BTreeSet<_>>();
  let domain_expiries = snap
    .world
    .routes
    .keys()
    .flat_map(|host| crate::rdap::candidates(host))
    .collect::<BTreeSet<_>>();
  let log_watches = crate::service_monitor::watches(&snap.world)
    .into_values()
    .flatten()
    .map(|watch| watch.id)
    .collect::<BTreeSet<_>>();
  super::ensure_loaded(state).await;
  let (cfg, overrides, custom) = with(|m| {
    (
      m.config.clone(),
      m.service_overrides.clone(),
      m.custom_rules.clone(),
    )
  });
  clear_matching(state, move |rule, subject| {
    if cfg.get(rule).is_some_and(|o| !o.enabled())
      && service_of_subject(rule, subject)
        .and_then(|service| {
          overrides.get(&(rule.into(), service.into()))
        })
        .is_none_or(|o| o.enabled != Some(true))
    {
      return true;
    }
    let world = &snap.world;
    let server = || world.servers.contains_key(subject);
    let service = || running_service(world, subject);
    let pair = |exists: &dyn Fn(&str) -> bool| {
      subject.split_once('>').is_some_and(|(from, to)| {
        from != to && exists(from) && exists(to)
      })
    };
    let oauth =
      snap.secrets.contains_key(crate::tailscale::OAUTH_SECRET);
    let keep = match rule {
      "server_offline" => {
        server()
          && snap
            .agent(subject)
            .is_some_and(|row| row.public_key.is_some())
      }
      "host_cpu_high" | "host_mem_high" | "inode_high"
      | "agent_mem_high" | "clock_skew" | "disk_forecast" => server(),
      "traffic_quota" => world
        .servers
        .get(subject)
        .is_some_and(|row| row.settings.traffic_quota_gb.is_some()),
      "link_loss" => pair(&|name| world.servers.contains_key(name)),
      "tailnet_relay" => pair(&|name| tailnet.contains_key(name)),
      "tailnet_key_expiring" => oauth && server(),
      "vendor_token_invalid" => {
        crate::vendor_checks::active_account(&snap, subject)
      }
      "external_incident" => external_pages
        .iter()
        .any(|name| name.eq_ignore_ascii_case(subject)),
      "host_unit_down" => host_units.contains(subject),
      "link_cert_expiring" => certs.contains(subject),
      "link_ca_expiring" => {
        crate::link_cert::ca_expiry(&snap).is_some()
      }
      "domain_down" => active_route(world, subject, now),
      "cert_expiring" => {
        active_route(world, subject, now)
          && route_has_tls(world, subject)
      }
      "container_restarting" | "oom_killed" | "http_5xx" => service(),
      "svc_mem_near_limit" => {
        service()
          && service_limit(&world.services[subject].spec).is_some()
      }
      "monitor_failed" => {
        service()
          && snap.applied.contains_key(subject)
          && world.services[subject].spec.monitor.is_some()
      }
      "heartbeat_late" => {
        service() && world.services[subject].spec.heartbeat.is_some()
      }
      "port_down" => {
        let (name, port) = split_unit(subject);
        snap.applied.contains_key(name)
          && world.services.get(name).is_some_and(|row| {
            !row.spec.stopped
              && crate::service_monitor::ports(row)
                .any(|(p, _)| p == port)
          })
      }
      "log_keyword" => log_watches.contains(subject),
      "expiry_soon" | "expiry_urgent" => subject
        .split_once(':')
        .is_some_and(|(kind, name)| match kind {
          "domain" => domain_expiries.contains(name),
          "server" => world
            .servers
            .get(name)
            .is_some_and(|row| row.settings.renew_at.is_some()),
          _ => false,
        }),
      "mem_forecast" => {
        subject
          .strip_prefix("服务器 ")
          .is_some_and(|name| world.servers.contains_key(name))
          || subject
            .strip_prefix("服务 ")
            .is_some_and(|name| running_service(world, name))
      }
      _ => custom.get(rule).is_none_or(|r| {
        r.enabled
          && r.service == subject
          && service()
          && (r.metric != "svc.mem_pct"
            || service_limit(&world.services[subject].spec).is_some())
      }),
    };
    !keep
  })
  .await;
  Ok(())
}

#[derive(Default)]
pub(crate) struct Changes {
  services: BTreeSet<String>,
  limits: BTreeSet<String>,
  monitors: BTreeSet<String>,
  heartbeats: BTreeSet<String>,
  routes: BTreeSet<String>,
  servers: BTreeSet<String>,
  gateways: BTreeSet<String>,
  certs: BTreeSet<String>,
}

impl Changes {
  pub(crate) fn deleted_service(name: &str) -> Self {
    Self {
      services: BTreeSet::from([name.to_string()]),
      ..Self::default()
    }
  }

  pub(crate) fn between(old: &World, new: &World) -> Self {
    let mut changes = Self::default();
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
    changes.routes.extend(
      old
        .edge_apps
        .values()
        .flat_map(|row| row.spec.domains.iter())
        .filter(|host| new.edge_domain(host).is_none())
        .cloned(),
    );
    changes.certs.extend(
      old
        .routes
        .keys()
        .filter(|host| {
          route_has_tls(old, host) && !route_has_tls(new, host)
        })
        .cloned(),
    );
    changes.gateways.extend(
      old
        .gateways
        .keys()
        .filter(|name| !new.gateways.contains_key(*name))
        .cloned(),
    );
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
      && self.gateways.is_empty()
      && self.certs.is_empty()
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
      || (rule == "cert_expiring" && self.certs.contains(subject))
      || (rule == "link_cert_expiring"
        && self.gateways.contains(subject))
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
        || custom.get(rule).is_some_and(|r| {
          self.services.contains(&r.service)
            || (r.metric == "svc.mem_pct"
              && self.limits.contains(&r.service))
        })
    })
  }

  pub(crate) fn clear_after_commit(&self) -> bool {
    if self.is_empty() {
      return false;
    }
    crate::http_stats::forget(&self.services);
    crate::probe::forget(&self.routes);
    crate::monitor::forget(&self.services, &self.monitors);
    for server in &self.servers {
      forget_server(server);
    }
    let availability_changed = with(|m| {
      let before = m.unavailable_gateways.len();
      m.unavailable_gateways
        .retain(|name| !self.gateways.contains(name));
      before != m.unavailable_gateways.len()
    });
    let custom = with(|m| {
      m.custom_rules
        .iter()
        .filter(|(_, r)| {
          self.services.contains(&r.service)
            || (r.metric == "svc.mem_pct"
              && self.limits.contains(&r.service))
        })
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>()
    });
    clear_cache(&|rule, subject| {
      self.matches(rule, subject) || custom.contains(rule)
    }) || availability_changed
  }
}
