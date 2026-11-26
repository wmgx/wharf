use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  net::{IpAddr, Ipv4Addr},
  sync::Mutex,
  time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use wharf_api_types::{
  agent::{AgentReport, Metrics},
  spec::GatewayKind,
};

use crate::{
  db::AgentRow,
  source_trust::{is_cgnat_v4, is_global_unicast, private_ipv4s},
  world::{ServerRow, World, gateway_project},
};

pub const MAX_WS_MESSAGE_BYTES: usize = 16 << 20;
const METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

#[derive(PartialEq, Eq, Debug)]
pub enum RateDecision {
  DropAll,
  AcceptNoMetrics,
  AcceptAll,
}

#[derive(Default)]
pub struct RateGate(Mutex<HashMap<String, ServerRate>>);

struct ServerRate {
  conn_id: u64,
  report: Instant,
  metrics: Option<Instant>,
}

impl RateGate {
  pub fn check(
    &self,
    server: &str,
    conn_id: u64,
    has_metrics: bool,
    now: Instant,
  ) -> RateDecision {
    use RateDecision::*;
    let mut rates = self.0.lock().unwrap_or_else(|e| e.into_inner());
    // 一个 agent 名即使被删除，也至多占一个采样间隔的空间。
    rates.retain(|_, rate| {
      now.saturating_duration_since(rate.report)
        < Duration::from_secs(25)
    });
    let previous = rates.get(server);
    if previous.is_some_and(|r| {
      let min = if r.conn_id == conn_id { 10 } else { 2 };
      now.saturating_duration_since(r.report)
        < Duration::from_secs(min)
    }) {
      return DropAll;
    }
    let metrics = previous.and_then(|r| r.metrics);
    let throttled = has_metrics
      && metrics.is_some_and(|m| {
        now.saturating_duration_since(m) < Duration::from_secs(25)
      });
    rates.insert(
      server.to_owned(),
      ServerRate {
        conn_id,
        report: now,
        metrics: if has_metrics && !throttled {
          Some(now)
        } else {
          metrics
        },
      },
    );
    if throttled {
      AcceptNoMetrics
    } else {
      AcceptAll
    }
  }
}

fn ip(raw: &str) -> Option<IpAddr> {
  Some(raw.parse::<IpAddr>().ok()?.to_canonical())
}

pub fn is_valid_private_ip(raw: &str) -> Option<String> {
  let ip = ip(raw)?;
  let valid = match ip {
    IpAddr::V4(v4) => {
      v4 != METADATA && (v4.is_private() || is_cgnat_v4(v4))
    }
    IpAddr::V6(v6) => {
      v6.is_unique_local()
        && v6.segments() != [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]
    }
  };
  valid.then(|| ip.to_string())
}

pub fn is_valid_public_ip(raw: &str) -> Option<String> {
  let ip = ip(raw)?;
  is_global_unicast(ip).then(|| ip.to_string())
}

pub fn is_valid_private_subnet(raw: &str) -> Option<String> {
  let net = raw.parse::<Ipv4Net>().ok()?.trunc();
  (net.prefix_len() >= 8
    && [net.network(), net.broadcast()]
      .into_iter()
      .all(|ip| ip.is_private() || is_cgnat_v4(ip))
    && !net.contains(&METADATA))
  .then(|| net.to_string())
}

fn clean(s: &mut String, max: usize) {
  *s = s.chars().filter(|c| !c.is_control()).take(max).collect();
}

pub fn sanitize_report(r: &mut AgentReport) {
  r.private_addr = r.private_addr.take().and_then(|mut addr| {
    addr.ip = is_valid_private_ip(&addr.ip)?;
    Some(addr)
  });
  r.public_ip = r.public_ip.as_deref().and_then(is_valid_public_ip);
  r.lan_ips =
    private_ipv4s(&r.lan_ips).into_iter().take(32).collect();
  r.host_subnets = r
    .host_subnets
    .iter()
    .filter_map(|s| is_valid_private_subnet(s))
    .take(64)
    .collect();
  r.docker_subnets = std::mem::take(&mut r.docker_subnets)
    .into_iter()
    .filter_map(|mut d| {
      d.subnet = is_valid_private_subnet(&d.subnet)?;
      clean(&mut d.name, 64);
      Some(d)
    })
    .take(64)
    .collect();
  for s in [&mut r.version, &mut r.hostname, &mut r.os]
    .into_iter()
    .chain(r.docker_version.iter_mut())
    .chain(r.compose_version.iter_mut())
  {
    clean(s, 128);
  }
  clean(&mut r.data_dir, 256);
  r.build.retain(|c| {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
  });
  r.build.truncate(r.build.len().min(64));
  r.arch
    .retain(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
  r.arch.truncate(r.arch.len().min(32));
  if let Some(e) = &mut r.egress_info {
    e.ipv4 = e
      .ipv4
      .as_deref()
      .filter(|s| ip(s).is_some_and(|ip| ip.is_ipv4()))
      .and_then(is_valid_public_ip);
    e.ipv6 = e
      .ipv6
      .as_deref()
      .filter(|s| ip(s).is_some_and(|ip| ip.is_ipv6()))
      .and_then(is_valid_public_ip);
    for s in
      [&mut e.asn, &mut e.operator, &mut e.country, &mut e.city]
        .into_iter()
        .flatten()
    {
      clean(s, 128);
    }
  }
  r.log_hits.truncate(64);
  for hit in &mut r.log_hits {
    hit.lines.truncate(3);
    for line in &mut hit.lines {
      clean(line, 300);
    }
  }
  if let Some(m) = &mut r.metrics {
    m.cpu = nonnegative(m.cpu).min(100.0);
    m.agent_cpu = m.agent_cpu.map(|n| nonnegative(n).min(100.0));
    for project in m.projects.values_mut() {
      project.cpu = nonnegative(project.cpu).min(100.0);
    }
    for traffic in m.hosts.values_mut() {
      traffic.secs = nonnegative(traffic.secs).clamp(1.0, 3600.0);
      traffic.p50_ms = nonnegative(traffic.p50_ms);
      traffic.p95_ms = nonnegative(traffic.p95_ms);
      traffic.errors = traffic.errors.min(traffic.reqs);
    }
  }
}

fn nonnegative(n: f32) -> f32 {
  if n.is_finite() { n.max(0.0) } else { 0.0 }
}

fn configured(row: &ServerRow) -> impl Iterator<Item = IpAddr> + '_ {
  let settings = &row.settings;
  settings
    .private_addr
    .iter()
    .map(|a| &a.ip)
    .chain(settings.public_ip.iter())
    .chain(&settings.lan_addrs)
    .filter_map(|s| ip(s))
}

pub fn strip_conflicting_ips(
  server: &str,
  report: &mut AgentReport,
  servers: &BTreeMap<String, ServerRow>,
  agents: &[AgentRow],
) {
  let mut occupied = servers
    .iter()
    .filter(|(name, _)| *name != server)
    .flat_map(|(_, row)| configured(row))
    .collect::<BTreeSet<_>>();
  for other in agents
    .iter()
    .filter(|a| a.server != server && servers.contains_key(&a.server))
  {
    if let Some(r) = &other.report {
      occupied.extend(
        r.private_addr
          .as_ref()
          .and_then(|a| is_valid_private_ip(&a.ip))
          .as_deref()
          .and_then(ip),
      );
      occupied.extend(
        r.public_ip
          .as_deref()
          .and_then(is_valid_public_ip)
          .as_deref()
          .and_then(ip),
      );
    }
  }
  if report
    .private_addr
    .as_ref()
    .and_then(|a| ip(&a.ip))
    .is_some_and(|a| occupied.contains(&a))
  {
    report.private_addr = None;
  }
  if report
    .public_ip
    .as_deref()
    .and_then(ip)
    .is_some_and(|a| occupied.contains(&a))
  {
    report.public_ip = None;
  }
}

/// 对旧报告采用相同校验，两个同时声称持有同一地址时都不采用。
pub fn safe_reports(
  servers: &BTreeMap<String, ServerRow>,
  agents: &[AgentRow],
) -> BTreeMap<String, AgentReport> {
  agents
    .iter()
    .filter_map(|agent| {
      if !servers.contains_key(&agent.server) {
        return None;
      }
      let mut report = agent.report.clone()?;
      sanitize_report(&mut report);
      strip_conflicting_ips(
        &agent.server,
        &mut report,
        servers,
        agents,
      );
      Some((agent.server.clone(), report))
    })
    .collect()
}

pub fn filter_owned_metrics(
  server: &str,
  m: &mut Metrics,
  world: &World,
  deployed: &BTreeMap<String, String>,
) {
  let services = world
    .services
    .iter()
    .filter(|(name, s)| {
      s.spec.server == server
        || deployed.get(*name).is_some_and(|s| s == server)
    })
    .map(|(name, _)| name.as_str())
    .collect::<BTreeSet<_>>();
  let gateways = world
    .gateways
    .iter()
    .filter(|(_, g)| g.spec.server == server)
    .map(|(name, _)| gateway_project(name))
    .collect::<BTreeSet<_>>();
  m.projects.retain(|p, _| {
    services.contains(p.as_str()) || gateways.contains(p)
  });
  trim_map(&mut m.projects, 256);
  m.hosts
    .retain(|h, _| route_owned_by_server(world, server, h).is_some());
  trim_map(&mut m.hosts, 256);
  if let Some(oom) = &mut m.oom {
    oom.retain(|p| services.contains(p.as_str()));
    oom.truncate(64);
  }
}

fn trim_map<V>(map: &mut BTreeMap<String, V>, max: usize) {
  if let Some(key) = map.keys().nth(max).cloned() {
    map.split_off(&key);
  }
}

pub fn route_owned_by_server(
  world: &World,
  server: &str,
  hostname: &str,
) -> Option<String> {
  let route = &world.routes.get(hostname)?.spec;
  (!route.service.is_empty()
    && world.route_gateways(route).iter().any(|g| {
      world.gateways.get(*g).is_some_and(|g| {
        g.spec.kind == GatewayKind::Caddy && g.spec.server == server
      })
    }))
  .then(|| route.service.clone())
}

pub async fn filter_report(
  db: &crate::db::Db,
  server: &str,
  report: AgentReport,
) -> Result<AgentReport, wharf_api_types::ApiError> {
  let server = server.to_string();
  db.call(move |c| {
    let mut report = report;
    let world = World::from_rows(crate::db::all_resources(c)?)?;
    let before =
      (report.private_addr.clone(), report.public_ip.clone());
    sanitize_report(&mut report);
    strip_conflicting_ips(
      &server,
      &mut report,
      &world.servers,
      &crate::db::agents(c)?,
    );
    if (before.0.is_some() && report.private_addr.is_none())
      || (before.1.is_some() && report.public_ip.is_none())
    {
      tracing::warn!("已忽略服务器 {server} 上报的无效或冲突地址");
    }
    if let Some(m) = &mut report.metrics {
      filter_owned_metrics(
        &server,
        m,
        &world,
        &crate::db::deployed_servers(c)?,
      );
    }
    Ok(report)
  })
  .await
}

#[cfg(test)]
mod tests;
