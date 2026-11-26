//! Agent 上报数据校验、归属过滤与频控（A5.1 + A6.2）。
//!
//! 在入库和告警消费之前，统一对不可信的 `AgentReport` 做边界清洗：
//! - 严校验 `private_addr`、`public_ip`、`lan_ips`、`host_subnets`、`docker_subnets`；
//! - 拒绝抢占其他服务器已配置或已上报的 IP；
//! - 仅放行属于本机的服务/网关指标与路由流量统计；
//! - 限制上报频率和集合长度，防止失陷节点写爆 SQLite 或刷屏告警。

use std::{
  collections::{BTreeMap, BTreeSet, HashMap, HashSet},
  net::{IpAddr, Ipv4Addr},
  sync::{LazyLock, Mutex},
  time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use wharf_api_types::{
  agent::{AgentReport, Metrics},
  spec::GatewayKind,
};

use crate::{
  db::AgentRow,
  source_trust::{is_cgnat_v4, is_global_unicast},
  world::{World, gateway_project},
};

pub const REPORT_MIN_INTERVAL: Duration = Duration::from_secs(10);
pub const RECONNECT_REPORT_MIN: Duration = Duration::from_secs(2);
pub const METRICS_MIN_INTERVAL: Duration = Duration::from_secs(25);

pub const MAX_LAN_IPS: usize = 32;
pub const MAX_SUBNETS: usize = 64;
pub const MAX_PROJECTS: usize = 256;
pub const MAX_HOSTS: usize = 256;
pub const MAX_OOM: usize = 64;
pub const MAX_LOG_HITS: usize = 64;
pub const MAX_LOG_LINES: usize = 3;
pub const MAX_WS_MESSAGE_BYTES: usize = 16 << 20;

const CLOUD_METADATA_CGNAT_V4: Ipv4Addr =
  Ipv4Addr::new(100, 100, 100, 200);
const CLOUD_METADATA_V6: [u16; 8] =
  [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254];
const WARN_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
  /// 10s 内同连接重复上报，或 2s 内跨重连洪泛：整条丢弃。
  DropAll,
  /// 允许更新上报与在线状态，但 25s 内重复携带 metrics 时剥离 metrics。
  AcceptNoMetrics,
  /// 完整接收。
  AcceptAll,
}

#[derive(Debug, Clone)]
struct ServerRate {
  last_conn_id: u64,
  last_report: Instant,
  last_metrics: Option<Instant>,
}

#[derive(Default)]
pub struct RateGate {
  inner: Mutex<HashMap<String, ServerRate>>,
}

impl RateGate {
  pub fn check(
    &self,
    server: &str,
    conn_id: u64,
    has_metrics: bool,
    now: Instant,
  ) -> RateDecision {
    let mut map =
      self.inner.lock().unwrap_or_else(|e| e.into_inner());
    let Some(entry) = map.get_mut(server) else {
      map.insert(
        server.to_string(),
        ServerRate {
          last_conn_id: conn_id,
          last_report: now,
          last_metrics: has_metrics.then_some(now),
        },
      );
      return RateDecision::AcceptAll;
    };
    let since_report =
      now.saturating_duration_since(entry.last_report);
    let min_gap = if entry.last_conn_id != conn_id {
      RECONNECT_REPORT_MIN
    } else {
      REPORT_MIN_INTERVAL
    };
    if since_report < min_gap {
      return RateDecision::DropAll;
    }
    entry.last_conn_id = conn_id;
    entry.last_report = now;
    if has_metrics {
      let too_soon = entry.last_metrics.is_some_and(|last| {
        now.saturating_duration_since(last) < METRICS_MIN_INTERVAL
      });
      if too_soon {
        return RateDecision::AcceptNoMetrics;
      }
      entry.last_metrics = Some(now);
    }
    RateDecision::AcceptAll
  }
}

static RATE_GATE: LazyLock<RateGate> =
  LazyLock::new(RateGate::default);
static LAST_WARN: LazyLock<Mutex<HashMap<String, Instant>>> =
  LazyLock::new(Default::default);

pub fn check_rate(
  server: &str,
  conn_id: u64,
  has_metrics: bool,
) -> RateDecision {
  RATE_GATE.check(server, conn_id, has_metrics, Instant::now())
}

pub fn warn_throttled(server: &str, warnings: &[String]) {
  if warnings.is_empty() {
    return;
  }
  let now = Instant::now();
  let should_log = {
    let mut map = LAST_WARN.lock().unwrap_or_else(|e| e.into_inner());
    let due = map.get(server).is_none_or(|last| {
      now.saturating_duration_since(*last) >= WARN_COOLDOWN
    });
    if due {
      map.insert(server.to_string(), now);
    }
    due
  };
  if should_log {
    tracing::warn!(
      "服务器 {server} 上报存在异常字段，已清洗：{}",
      warnings.join("；")
    );
  }
}

/// 严校验私网或组网 IP：允许 RFC1918、CGNAT `100.64.0.0/10`（排除 `100.100.100.200`）、
/// IPv6 ULA `fc00::/7`（排除 `fd00:ec2::254`）；拒绝空白、控制字符、回环、链路本地、公网等。
pub fn is_valid_private_ip(raw: &str) -> Option<String> {
  let ip = raw.parse::<IpAddr>().ok()?.to_canonical();
  let ok = match ip {
    IpAddr::V4(v4) => {
      (v4.is_private() || is_cgnat_v4(v4))
        && v4 != CLOUD_METADATA_CGNAT_V4
    }
    IpAddr::V6(v6) => {
      v6.is_unique_local() && v6.segments() != CLOUD_METADATA_V6
    }
  };
  ok.then(|| ip.to_string())
}

/// 严校验公网单播 IP（拒绝空白、控制字符、私网、回环、链路本地、组播等）。
pub fn is_valid_public_ip(raw: &str) -> Option<String> {
  let ip = raw.parse::<IpAddr>().ok()?.to_canonical();
  is_global_unicast(ip).then(|| ip.to_string())
}

/// 严校验私网或 CGNAT IPv4 子网：前缀长度 `>= 8`、起止地址同属 RFC1918 或 CGNAT，
/// 且不包含云元数据 `100.100.100.200`（同时天然排除 `0.0.0.0/0`）。
pub fn is_valid_private_subnet(raw: &str) -> Option<String> {
  let net = raw.parse::<Ipv4Net>().ok()?.trunc();
  if net.prefix_len() < 8 {
    return None;
  }
  let first = net.network();
  let last = net.broadcast();
  let all_private = first.is_private() && last.is_private();
  let all_cgnat = is_cgnat_v4(first) && is_cgnat_v4(last);
  if !(all_private || all_cgnat)
    || net.contains(&CLOUD_METADATA_CGNAT_V4)
  {
    return None;
  }
  Some(net.to_string())
}

fn clean_text(raw: &str, max_chars: usize) -> String {
  raw
    .chars()
    .filter(|c| !c.is_control())
    .take(max_chars)
    .collect()
}

fn clean_opt_text(opt: &mut Option<String>, max_chars: usize) {
  if let Some(s) = opt {
    *s = clean_text(s, max_chars);
    if s.is_empty() {
      *opt = None;
    }
  }
}

fn clean_token_text(
  raw: &str,
  max_chars: usize,
  allow_dot: bool,
) -> String {
  raw
    .chars()
    .filter(|c| {
      c.is_ascii_alphanumeric()
        || *c == '-'
        || *c == '_'
        || (allow_dot && *c == '.')
    })
    .take(max_chars)
    .collect()
}

fn clamp_pct(v: f32) -> f32 {
  if v.is_finite() && v >= 0.0 {
    v.min(100.0)
  } else {
    0.0
  }
}

fn clamp_non_neg(v: f32) -> f32 {
  if v.is_finite() && v >= 0.0 { v } else { 0.0 }
}

/// 对刚收到的 `AgentReport` 做原地清洗，返回被拦截/清洗项的摘要。
pub fn sanitize_report(
  _server: &str,
  report: &mut AgentReport,
) -> Vec<String> {
  let mut warnings = Vec::new();

  if let Some(addr) = report.private_addr.as_mut() {
    match is_valid_private_ip(&addr.ip) {
      Some(clean) => addr.ip = clean,
      None => {
        warnings.push("非法 private_addr 已丢弃".into());
        report.private_addr = None;
      }
    }
  }

  if let Some(ip) = report.public_ip.as_deref() {
    match is_valid_public_ip(ip) {
      Some(clean) => report.public_ip = Some(clean),
      None => {
        warnings.push("非法 public_ip 已丢弃".into());
        report.public_ip = None;
      }
    }
  }

  let mut lan_seen = BTreeSet::new();
  let orig_lan = report.lan_ips.len();
  report.lan_ips.retain_mut(|raw| {
    let Ok(ip) = raw.parse::<Ipv4Addr>() else {
      return false;
    };
    if !ip.is_private() {
      return false;
    }
    let clean = ip.to_string();
    if !lan_seen.insert(clean.clone()) {
      return false;
    }
    *raw = clean;
    lan_seen.len() <= MAX_LAN_IPS
  });
  if report.lan_ips.len() < orig_lan {
    warnings.push("已过滤非法或超限的 lan_ips".into());
  }

  let mut host_sub_seen = BTreeSet::new();
  let orig_host_sub = report.host_subnets.len();
  report.host_subnets.retain_mut(|raw| {
    let Some(clean) = is_valid_private_subnet(raw) else {
      return false;
    };
    if !host_sub_seen.insert(clean.clone()) {
      return false;
    }
    *raw = clean;
    host_sub_seen.len() <= MAX_SUBNETS
  });
  if report.host_subnets.len() < orig_host_sub {
    warnings.push("已过滤非法或超限的 host_subnets".into());
  }

  let orig_docker_sub = report.docker_subnets.len();
  let mut kept_docker = 0usize;
  report.docker_subnets.retain_mut(|entry| {
    let Some(clean) = is_valid_private_subnet(&entry.subnet) else {
      return false;
    };
    if kept_docker >= MAX_SUBNETS {
      return false;
    }
    entry.subnet = clean;
    entry.name = clean_text(&entry.name, 64);
    kept_docker += 1;
    true
  });
  if report.docker_subnets.len() < orig_docker_sub {
    warnings.push("已过滤非法或超限的 docker_subnets".into());
  }

  if let Some(info) = report.egress_info.as_mut() {
    info.ipv4 = info
      .ipv4
      .as_deref()
      .and_then(is_valid_public_ip)
      .filter(|s| s.parse::<Ipv4Addr>().is_ok());
    info.ipv6 = info
      .ipv6
      .as_deref()
      .and_then(is_valid_public_ip)
      .filter(|s| s.parse::<std::net::Ipv6Addr>().is_ok());
    clean_opt_text(&mut info.asn, 128);
    clean_opt_text(&mut info.operator, 128);
    clean_opt_text(&mut info.country, 128);
    clean_opt_text(&mut info.city, 128);
  }

  report.version = clean_text(&report.version, 128);
  report.hostname = clean_text(&report.hostname, 128);
  report.os = clean_text(&report.os, 128);
  report.arch = clean_token_text(&report.arch, 32, false);
  report.build = clean_token_text(&report.build, 64, true);
  report.data_dir = clean_text(&report.data_dir, 256);
  clean_opt_text(&mut report.docker_version, 128);
  clean_opt_text(&mut report.compose_version, 128);

  if report.log_hits.len() > MAX_LOG_HITS {
    report.log_hits.truncate(MAX_LOG_HITS);
    warnings.push("log_hits 超限已截断".into());
  }
  for hit in &mut report.log_hits {
    hit.id = clean_text(&hit.id, 128);
    if hit.lines.len() > MAX_LOG_LINES {
      hit.lines.truncate(MAX_LOG_LINES);
    }
    for line in &mut hit.lines {
      *line = clean_text(line, 300);
    }
  }

  if let Some(m) = report.metrics.as_mut() {
    sanitize_metrics(m, &mut warnings);
  }

  warnings
}

fn sanitize_metrics(m: &mut Metrics, warnings: &mut Vec<String>) {
  m.cpu = clamp_pct(m.cpu);
  if let Some(c) = m.agent_cpu.as_mut() {
    *c = clamp_pct(*c);
  }
  if m.projects.len() > MAX_PROJECTS {
    let keep: BTreeMap<_, _> = std::mem::take(&mut m.projects)
      .into_iter()
      .take(MAX_PROJECTS)
      .collect();
    m.projects = keep;
    warnings.push("metrics.projects 超限已截断".into());
  }
  for pm in m.projects.values_mut() {
    pm.cpu = clamp_pct(pm.cpu);
  }
  if m.hosts.len() > MAX_HOSTS {
    let keep: BTreeMap<_, _> = std::mem::take(&mut m.hosts)
      .into_iter()
      .take(MAX_HOSTS)
      .collect();
    m.hosts = keep;
    warnings.push("metrics.hosts 超限已截断".into());
  }
  for h in m.hosts.values_mut() {
    h.secs = if h.secs.is_finite() && h.secs > 0.0 {
      h.secs.clamp(1.0, 3600.0)
    } else {
      1.0
    };
    h.p50_ms = clamp_non_neg(h.p50_ms);
    h.p95_ms = clamp_non_neg(h.p95_ms);
    h.errors = h.errors.min(h.reqs);
  }
  if let Some(oom) = m.oom.as_mut()
    && oom.len() > MAX_OOM
  {
    oom.truncate(MAX_OOM);
    warnings.push("metrics.oom 超限已截断".into());
  }
}

/// 剥离与其他服务器已配置或已入库上报冲突的 `private_addr` / `public_ip`，防止跨机抢占。
pub fn strip_conflicting_ips(
  server: &str,
  report: &mut AgentReport,
  world: &World,
  agents: &[AgentRow],
) -> Vec<String> {
  let mut other_private = HashSet::new();
  let mut other_public = HashSet::new();

  for (other, row) in &world.servers {
    if other == server {
      continue;
    }
    if let Some(addr) = &row.settings.private_addr
      && let Some(clean) = is_valid_private_ip(&addr.ip)
    {
      other_private.insert(clean);
    }
    for lan in &row.settings.lan_addrs {
      if let Some(clean) = is_valid_private_ip(lan) {
        other_private.insert(clean);
      }
    }
    if let Some(pub_ip) = &row.settings.public_ip
      && let Some(clean) = is_valid_public_ip(pub_ip)
    {
      other_public.insert(clean);
    }
  }
  for agent in agents {
    if agent.server == server
      || !world.servers.contains_key(&agent.server)
    {
      continue;
    }
    let Some(r) = &agent.report else { continue };
    if let Some(addr) = &r.private_addr
      && let Some(clean) = is_valid_private_ip(&addr.ip)
    {
      other_private.insert(clean);
    }
    if let Some(pub_ip) = &r.public_ip
      && let Some(clean) = is_valid_public_ip(pub_ip)
    {
      other_public.insert(clean);
    }
  }

  let mut warnings = Vec::new();
  if let Some(addr) = &report.private_addr
    && (other_private.contains(&addr.ip)
      || other_public.contains(&addr.ip))
  {
    warnings.push(format!(
      "private_addr {} 与其他服务器冲突，已忽略",
      addr.ip
    ));
    report.private_addr = None;
  }
  if let Some(ip) = &report.public_ip
    && other_public.contains(ip)
  {
    warnings.push(format!("public_ip {ip} 与其他服务器冲突，已忽略"));
    report.public_ip = None;
  }
  warnings
}

/// 仅保留属于本机（配置在本机或当前部署在本机）的服务与网关的 `projects` 与 `oom`。
pub fn filter_owned_metrics(
  server: &str,
  m: &mut Metrics,
  world: &World,
  deployed: &BTreeMap<String, String>,
) {
  let mut owned: HashSet<String> = world
    .services
    .iter()
    .filter(|(name, row)| {
      row.spec.server == server
        || deployed.get(name.as_str()).map(String::as_str)
          == Some(server)
    })
    .map(|(name, _)| name.clone())
    .collect();
  for (name, gw) in &world.gateways {
    if gw.spec.server == server {
      owned.insert(gateway_project(name));
    }
  }
  m.projects.retain(|project, _| owned.contains(project));
  if let Some(oom) = m.oom.as_mut() {
    oom.retain(|project| owned.contains(project));
  }
}

/// 仅当域名 `hostname` 的主/备 Caddy 网关之一跑在 `server` 上且目标服务非空时返回服务名。
pub fn route_owned_by_server(
  world: &World,
  server: &str,
  hostname: &str,
) -> Option<String> {
  let route = world.routes.get(hostname)?;
  if route.spec.service.is_empty() {
    return None;
  }
  let on_server =
    world
      .route_gateways(&route.spec)
      .into_iter()
      .any(|gw_name| {
        world.gateways.get(gw_name).is_some_and(|gw| {
          gw.spec.kind == GatewayKind::Caddy
            && gw.spec.server == server
        })
      });
  on_server.then(|| route.spec.service.clone())
}

/// 在 `hub.rs` 收到 `AgentMsg::Report` 时统一执行频控、字段清洗、IP 冲突剥离与归属过滤。
/// 返回 `false` 表示该条上报因频控被整条丢弃。
pub async fn prepare_report(
  state: &crate::state::AppState,
  server: &str,
  conn_id: u64,
  report: &mut AgentReport,
) -> bool {
  match check_rate(server, conn_id, report.metrics.is_some()) {
    RateDecision::DropAll => return false,
    RateDecision::AcceptNoMetrics => report.metrics = None,
    RateDecision::AcceptAll => {}
  }
  let mut warnings = sanitize_report(server, report);
  if let Ok((world, deployed, agents)) = state
    .db
    .call(|c| {
      Ok((
        World::from_rows(crate::db::all_resources(c)?)?,
        crate::db::deployed_servers(c)?,
        crate::db::agents(c)?,
      ))
    })
    .await
  {
    warnings
      .extend(strip_conflicting_ips(server, report, &world, &agents));
    if let Some(m) = report.metrics.as_mut() {
      filter_owned_metrics(server, m, &world, &deployed);
    }
  }
  warn_throttled(server, &warnings);
  true
}

#[cfg(test)]
mod tests;
