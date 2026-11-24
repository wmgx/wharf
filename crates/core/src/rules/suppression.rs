use rusqlite::{Connection, params};
use wharf_api_types::{
  ApiError,
  view::{AlertSuppressRequest, AlertSuppression},
};

use super::*;
use crate::world::World;

pub(super) const OFFLINE: &str = "suppress_offline";
pub(super) const GATEWAY: &str = "suppress_gateway";
pub(super) const BUILT_INS: &[&str] = &[OFFLINE, GATEWAY];
const LIMIT: i64 = 50;

fn enabled(cfg: &BTreeMap<String, Override>, id: &str) -> bool {
  cfg.get(id).is_none_or(Override::enabled)
}

fn endpoint(s: &str) -> (&str, Option<&str>) {
  s.split_once(':')
    .map_or((s, None), |(id, subject)| (id, Some(subject)))
}

fn matches(s: &str, id: &str, subject: &str) -> bool {
  let (r, obj) = endpoint(s);
  r == id && obj.is_none_or(|obj| obj == subject)
}

pub(super) fn list(
  c: &Connection,
) -> Result<Vec<AlertSuppression>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT id, source, ignore FROM alert_suppression ORDER BY id",
    )
    .map_err(db::sql_err)?;
  stmt
    .query_map([], |r| {
      Ok(AlertSuppression {
        id: r.get(0)?,
        source: r.get(1)?,
        ignore: r.get(2)?,
      })
    })
    .and_then(Iterator::collect)
    .map_err(db::sql_err)
}

pub(super) fn add(
  c: &Connection,
  req: AlertSuppressRequest,
) -> Result<Vec<AlertSuppression>, ApiError> {
  for (s, source) in [(&req.source, true), (&req.ignore, false)] {
    let (id, subject) = endpoint(s);
    if !(RULES.iter().any(|r| r.id == id)
      || if source {
        matches!(id, "task" | "backup")
      } else {
        NOTICES.iter().any(|n| n.0 == id)
      })
      || subject.is_some_and(str::is_empty)
    {
      return Err(
        ApiError::invalid(format!("告警条件无效：{s}"))
          .with_hint("wharf alert list"),
      );
    }
  }
  let count: i64 = c
    .query_row("SELECT COUNT(*) FROM alert_suppression", [], |r| {
      r.get(0)
    })
    .map_err(db::sql_err)?;
  if count >= LIMIT {
    return Err(ApiError::invalid(format!(
      "最多 {LIMIT} 条自定义抑制"
    )));
  }
  c.execute(
    "INSERT INTO alert_suppression (source, ignore) VALUES (?1, ?2)",
    params![req.source, req.ignore],
  )
  .map_err(db::sql_err)?;
  list(c)
}

type Firing = BTreeMap<(String, String), (i64, String)>;

fn custom(
  items: &[AlertSuppression],
  firing: &Firing,
  id: &str,
  subject: &str,
) -> Option<String> {
  items
    .iter()
    .filter(|item| matches(&item.ignore, id, subject))
    .find_map(|item| {
      firing
        .iter()
        .find(|((r, s), _)| {
          (r != id || s != subject) && matches(&item.source, r, s)
        })
        .map(|(_, (_, title))| title.clone())
    })
}

fn route_host<'a>(id: &str, subject: &'a str) -> Option<&'a str> {
  match id {
    "domain_down" | "cert_expiring" | "cert_expired" | "failover" => {
      Some(subject)
    }
    "expiry_soon" | "expiry_urgent" => {
      subject.strip_prefix("domain:")
    }
    _ => None,
  }
}

fn built_in(
  world: &World,
  cfg: &BTreeMap<String, Override>,
  firing: &Firing,
  id: &str,
  subject: &str,
) -> Option<String> {
  let route = route_host(id, subject)
    .and_then(|host| world.routes.get(host).map(|r| (host, &r.spec)));
  let gateway =
    route.and_then(|(host, spec)| world.live_gateway(host, spec));
  let title = |rule: &str, key: &str| {
    firing
      .get(&(rule.to_string(), key.to_string()))
      .map(|(_, title)| title.clone())
  };
  if id != "server_offline" && enabled(cfg, OFFLINE) {
    let service = |name: &str| {
      world.services.get(name).map(|row| row.spec.server.as_str())
    };
    let gateway_server = |name: &str| {
      world.gateways.get(name).map(|row| row.spec.server.as_str())
    };
    let server = match id {
      "container_restarting"
      | "oom_killed"
      | "monitor_failed"
      | "http_5xx"
      | "heartbeat_late"
      | "svc_mem_near_limit"
      | "backup"
      | "update"
      | "auto_update" => service(subject),
      "log_keyword" | "port_down" => service(split_unit(subject).0),
      "gateway_down" => gateway_server(subject),
      "host_unit_down" => Some(split_unit(subject).0),
      "mem_forecast" => subject
        .strip_prefix("服务器 ")
        .or_else(|| subject.strip_prefix("服务 ").and_then(service)),
      "link_loss" => subject.split_once('>').map(|(from, _)| from),
      "expiry_soon" | "expiry_urgent" => {
        subject.strip_prefix("server:")
      }
      "clock_skew"
      | "disk_forecast"
      | "disk_full"
      | "host_cpu_high"
      | "host_mem_high"
      | "inode_high"
      | "agent_mem_high"
      | "tailnet_key_expiring"
      | "tailnet_relay"
      | "traffic_quota"
      | "exposure"
      | "unmanaged_container" => Some(subject),
      _ => None,
    };
    let offline = |s: &str| title("server_offline", s);
    if let Some(cause) = server
      .and_then(offline)
      .or_else(|| gateway.and_then(gateway_server).and_then(offline))
      .or_else(|| {
        route
          .and_then(|(_, spec)| service(&spec.service))
          .and_then(offline)
      })
      .or_else(|| {
        (id == "link_loss")
          .then_some(subject.split_once('>'))
          .flatten()
          .and_then(|(_, to)| offline(to))
      })
    {
      return Some(cause);
    }
  }
  if id != "failover" && enabled(cfg, GATEWAY) {
    return gateway.and_then(|name| title("gateway_down", name));
  }
  None
}

pub(super) async fn reason(
  state: &AppState,
  cfg: &BTreeMap<String, Override>,
  id: &str,
  subject: &str,
) -> Result<Option<String>, ApiError> {
  let firing = with(|m| m.firing.clone());
  if firing.is_empty() {
    return Ok(None);
  }
  let custom_rules = state.db.call(|c| list(c)).await?;
  let mut cause = custom(&custom_rules, &firing, id, subject);
  if cause.is_none()
    && ((enabled(cfg, OFFLINE)
      && firing.keys().any(|(r, _)| r == "server_offline"))
      || (enabled(cfg, GATEWAY)
        && route_host(id, subject).is_some()
        && firing.keys().any(|(r, _)| r == "gateway_down")))
  {
    let snap = crate::snapshot::load(&state.db).await?;
    cause = built_in(&snap.world, cfg, &firing, id, subject);
    if id == "task" && enabled(cfg, OFFLINE) {
      let tasks = crate::tasks::load(state).await?;
      if let Some((_, spec, _)) =
        tasks.into_iter().find(|(name, _, _)| name == subject)
      {
        cause = firing
          .get(&("server_offline".into(), spec.server))
          .map(|(_, t)| t.clone());
      }
    }
  }
  Ok(cause.map(|title| format!("被抑制：{title}")))
}

pub(super) async fn release(
  state: &AppState,
  cfg: &BTreeMap<String, Override>,
) -> Result<(), ApiError> {
  let pending = state.db.call(|c| pending(c)).await?;
  for (id, subject, event) in pending {
    push(
      state,
      Delivery {
        id: &id,
        subject: Some(&subject),
        paired: true,
        ok: false,
        now: now_ms(),
        replay: true,
      },
      cfg,
      event,
      None,
    )
    .await;
  }
  Ok(())
}

fn pending(
  c: &Connection,
) -> Result<Vec<(String, String, Event)>, ApiError> {
  let mut stmt = c.prepare(
      "SELECT e.source, e.subject, e.title, e.body FROM alert_episode e
       JOIN alert_firing f ON f.rule = e.source AND f.subject = e.subject
       WHERE e.outcome LIKE '被抑制：%' ORDER BY e.at",
    ).map_err(db::sql_err)?;
  stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, String>(1)?,
        Event {
          title: r.get(2)?,
          body: r.get(3)?,
        },
      ))
    })
    .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
    .map_err(db::sql_err)
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
