//! 周期报告（`GET /api/report`）：统计本期和上一个同长度周期的机器、服务指标与告警次数，
//! 生成模板文字摘要，不调用任何外部 AI 接口。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Query, State},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use wharf_api_types::{
  ApiError,
  report::{
    AlertReport, MetricDelta, ReportCoverage, ReportView,
    ServerReport, ServiceReport,
  },
  view::Perm,
};

use crate::{
  api::ApiResult,
  auth::Auth,
  db::{now_ms, sql_err},
  metrics::{self, COARSE_MS, HOUR_MS, MINUTE_MS},
  rules::resources::service_limit,
  snapshot,
  state::AppState,
  world::World,
};

#[path = "report/summary.rs"]
mod summary;

const DAY_MS: i64 = 24 * HOUR_MS;
/// 单次报告最多扫描的数据点数，防止全量扫表拖慢控制面。
pub const MAX_SCAN_POINTS: usize = 500_000;
/// 上期至少覆盖周期长度的 80% 才参与同比，避免旧数据不足时算出假暴涨。
pub const MIN_PREVIOUS_RATIO: f64 = 0.8;

#[derive(Deserialize)]
pub struct ReportQuery {
  /// 统计天数，只支持 1 或 7，默认 7。
  pub days: Option<u32>,
  /// 只统计指定服务器及其上的服务。
  pub server: Option<String>,
  /// 只统计指定服务。
  pub service: Option<String>,
}

/// `GET /api/report?days=7&server=&service=`
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Query(q): Query<ReportQuery>,
) -> ApiResult<ReportView> {
  auth.require(Perm::Read)?;
  if let Some(allowed) = &auth.services {
    if q.server.is_some() {
      return Err(
        crate::token_scope::forbidden(
          &auth.name,
          allowed,
          "；不能按服务器查报告",
        )
        .into(),
      );
    }
    if let Some(service) = &q.service {
      crate::token_scope::require_service(&auth, service)?;
    }
  }
  let allowed = auth.services;
  let days = q.days.unwrap_or(7);
  if days != 1 && days != 7 {
    return Err(
      ApiError::invalid("days 只支持 1 或 7")
        .with_hint("用法：wharf report --days 1 或 --days 7")
        .into(),
    );
  }
  let snap = snapshot::load(&s.db).await?;
  let server_filter = q.server.clone();
  let service_filter = q.service.clone();
  let now = now_ms();
  let view = s
    .db
    .call(move |c| {
      compute_at(
        c,
        &snap,
        now,
        days,
        server_filter.as_deref(),
        service_filter.as_deref(),
        MAX_SCAN_POINTS,
        allowed.as_ref(),
      )
    })
    .await?;
  Ok(Json(view))
}

#[derive(Default)]
struct SeriesAcc {
  /// 按小时分桶求均值再平均，避免 1 分钟 / 10 分钟 / 1 小时混合粒度导致权重偏移。
  hours: BTreeMap<i64, (f64, u64)>,
  points: Vec<(i64, f64)>,
  max: Option<f64>,
  first: Option<(i64, f64)>,
  last: Option<(i64, f64)>,
}

impl SeriesAcc {
  fn push(&mut self, at: i64, value: f64) {
    self.points.push((at, value));
    let e = self.hours.entry(at / HOUR_MS).or_insert((0.0, 0));
    e.0 += value;
    e.1 += 1;
    self.max = Some(self.max.map_or(value, |m| m.max(value)));
    if self.first.is_none_or(|(t, _)| at < t) {
      self.first = Some((at, value));
    }
    if self.last.is_none_or(|(t, _)| at > t) {
      self.last = Some((at, value));
    }
  }

  fn avg(&self) -> Option<f64> {
    if self.hours.is_empty() {
      return None;
    }
    let sum: f64 =
      self.hours.values().map(|(s, c)| s / *c as f64).sum();
    Some(sum / self.hours.len() as f64)
  }

  fn peak(&self) -> Option<f64> {
    self.max
  }

  fn delta(&self) -> Option<f64> {
    let ((t0, v0), (t1, v1)) = (self.first?, self.last?);
    (t1 > t0).then_some(v1 - v0)
  }

  fn latest(&self) -> Option<f64> {
    self.last.map(|(_, v)| v)
  }

  fn hour_avg(&self, h: i64) -> Option<f64> {
    self.hours.get(&h).map(|(sum, count)| sum / *count as f64)
  }

  fn hourly_avg_peak(&self) -> Option<f64> {
    self
      .hours
      .keys()
      .filter_map(|&h| self.hour_avg(h))
      .reduce(f64::max)
  }

  fn hour_integrals(
    &self,
    window: Window,
    cutoffs: (i64, i64),
  ) -> BTreeMap<i64, f64> {
    let mut totals = BTreeMap::new();
    for (i, &(at, value)) in self.points.iter().enumerate() {
      let step = sample_step(at, cutoffs);
      let next = self.points.get(i + 1).map(|&(t, _)| t);
      let max_gap = if step == MINUTE_MS {
        5 * MINUTE_MS
      } else {
        step
      };
      let end = match next {
        Some(t) if t - at <= max_gap => {
          if step == MINUTE_MS {
            t
          } else {
            t.min(at + step)
          }
        }
        _ => at + step,
      }
      .min(window.end);
      let mut start = at.max(window.start);
      while start < end {
        let hour = start.div_euclid(HOUR_MS);
        let to = end.min((hour + 1) * HOUR_MS);
        *totals.entry(hour).or_default() +=
          value * (to - start) as f64 / 1000.0;
        start = to;
      }
    }
    totals
  }
}

#[derive(Clone, Copy)]
struct Window {
  start: i64,
  end: i64,
}

fn sample_step(at: i64, (coarse, hourly): (i64, i64)) -> i64 {
  if at < hourly && at % HOUR_MS == 0 {
    HOUR_MS
  } else if at < coarse && at % COARSE_MS == 0 {
    COARSE_MS
  } else {
    MINUTE_MS
  }
}

fn total(hours: &BTreeMap<i64, f64>) -> Option<f64> {
  (!hours.is_empty()).then(|| hours.values().sum())
}

fn weighted_avg_by_hour(
  metric: &SeriesAcc,
  weights: &BTreeMap<i64, f64>,
) -> Option<f64> {
  let (weighted, weight) = metric
    .hours
    .keys()
    .filter_map(|&h| {
      let weight = *weights.get(&h)?;
      (weight > 0.0).then(|| {
        (metric.hour_avg(h).unwrap_or_default() * weight, weight)
      })
    })
    .fold((0.0, 0.0), |(s, w), (value, weight)| {
      (s + value, w + weight)
    });
  if weight > 0.0 {
    Some(weighted / weight)
  } else {
    metric.avg()
  }
}

fn peak_delta(
  current: Option<&SeriesAcc>,
  current_max: Option<&SeriesAcc>,
  previous: Option<&SeriesAcc>,
  previous_max: Option<&SeriesAcc>,
  cutoffs: (i64, i64),
) -> (MetricDelta, Option<f64>) {
  let raw = |base: Option<&SeriesAcc>, max: Option<&SeriesAcc>| {
    base
      .and_then(SeriesAcc::peak)
      .into_iter()
      .chain(max.and_then(SeriesAcc::peak))
      .reduce(f64::max)
  };
  let raw_peak = raw(current, current_max);
  let legacy = previous.is_some_and(|s| {
    s.points.iter().any(|&(at, _)| {
      sample_step(at, cutoffs) != MINUTE_MS
        && previous_max.is_none_or(|peaks| {
          peaks.points.binary_search_by_key(&at, |p| p.0).is_err()
        })
    })
  });
  let delta = if legacy {
    make_delta(
      current.and_then(SeriesAcc::hourly_avg_peak),
      previous.and_then(SeriesAcc::hourly_avg_peak),
    )
  } else {
    make_delta(raw_peak, raw(previous, previous_max))
  };
  (delta, raw_peak)
}

fn calc_change_pct(
  current: Option<f64>,
  previous: Option<f64>,
) -> Option<f64> {
  let (curr, prev) = (current?, previous?);
  if prev.abs() < 1e-12 {
    if curr.abs() < 1e-12 { Some(0.0) } else { None }
  } else {
    Some((curr - prev) / prev.abs() * 100.0)
  }
}

fn make_delta(
  current: Option<f64>,
  previous: Option<f64>,
) -> MetricDelta {
  MetricDelta {
    current,
    previous,
    change_pct: calc_change_pct(current, previous),
  }
}

fn previous_coverage_ratio(
  earliest_at: Option<i64>,
  previous_start: i64,
  previous_end: i64,
) -> f64 {
  let Some(earliest) = earliest_at else {
    return 0.0;
  };
  let span = previous_end - previous_start;
  if span <= 0 || earliest >= previous_end {
    return 0.0;
  }
  let covered = (previous_end - earliest.max(previous_start)) as f64;
  (covered / span as f64).clamp(0.0, 1.0)
}

fn update_bounds(
  earliest: &mut Option<i64>,
  latest: &mut Option<i64>,
  at: i64,
) {
  if earliest.is_none_or(|t| at < t) {
    *earliest = Some(at);
  }
  if latest.is_none_or(|t| at > t) {
    *latest = Some(at);
  }
}

struct AlertFilterIndex<'a> {
  services: BTreeSet<String>,
  server: Option<&'a str>,
  filtered: bool,
  routes: BTreeSet<&'a str>,
  root_domains: BTreeSet<String>,
  gateways: BTreeSet<&'a str>,
  tasks: BTreeSet<String>,
  backups: BTreeSet<String>,
}

impl<'a> AlertFilterIndex<'a> {
  fn build(
    c: &Connection,
    world: &'a World,
    services: BTreeSet<String>,
    server: Option<&'a str>,
    service: Option<&str>,
    scoped: bool,
  ) -> Result<Self, ApiError> {
    let filtered = scoped || server.is_some() || service.is_some();
    let mut index = Self {
      services,
      server,
      filtered,
      routes: BTreeSet::new(),
      root_domains: BTreeSet::new(),
      gateways: BTreeSet::new(),
      tasks: BTreeSet::new(),
      backups: BTreeSet::new(),
    };
    if !filtered {
      return Ok(index);
    }
    if let Some(server) = server {
      index.gateways.extend(
        world
          .gateways
          .iter()
          .filter(|(_, g)| g.spec.server == server)
          .map(|(name, _)| name.as_str()),
      );
      index.backups.extend(
        world
          .services
          .iter()
          .filter(|(_, r)| {
            r.spec.backup.as_ref().is_some_and(|b| b.to == server)
          })
          .map(|(name, _)| name.clone()),
      );
      if db_core_backup_owned(c, server)? {
        index.backups.insert(crate::core_backup::REPO.to_string());
      }
    }
    for (host, route) in &world.routes {
      let spec = &route.spec;
      if index.services.contains(&spec.service)
        || spec.paths.iter().any(|p| {
          p.service
            .as_ref()
            .is_some_and(|s| index.services.contains(s))
        })
        || world
          .route_gateways(spec)
          .iter()
          .any(|g| index.gateways.contains(g))
      {
        index.routes.insert(host.as_str());
        index.root_domains.extend(crate::rdap::candidates(host));
      }
    }
    for (name, spec, _) in crate::tasks::load_rows(c)? {
      if server.is_some_and(|srv| spec.server == srv)
        || matches!(spec.how, wharf_api_types::view::TaskKind::Exec { service, .. } if index.services.contains(&service))
      {
        index.tasks.insert(name);
      }
    }
    Ok(index)
  }
}

fn db_core_backup_owned(
  c: &Connection,
  server: &str,
) -> Result<bool, ApiError> {
  Ok(
    crate::core_node::load_persisted(c)?
      .is_some_and(|(name, _)| name == server)
      || crate::db::setting(c, crate::core_backup::TO)?.as_deref()
        == Some(server),
  )
}

fn alert_matches_filter(
  source: &str,
  subject: Option<&str>,
  custom_service: Option<&str>,
  idx: &AlertFilterIndex<'_>,
) -> bool {
  if !idx.filtered {
    return true;
  }
  if let Some(service) = custom_service {
    return idx.services.contains(service);
  }
  let Some(s) = subject else { return false };
  let server = |name: &str| idx.server == Some(name);
  match source {
    "domain_down" | "cert_expiring" | "failover"
    | "failover_error" => idx.routes.contains(s),
    "expiry_soon" | "expiry_urgent" => {
      s.strip_prefix("server:").is_some_and(server)
        || s
          .strip_prefix("domain:")
          .is_some_and(|d| idx.root_domains.contains(d))
    }
    "link_cert_expiring" => idx.gateways.contains(s),
    "task" => idx.tasks.contains(s),
    "backup" => idx.services.contains(s) || idx.backups.contains(s),
    "heal" | "auto_update" | "update" => idx.services.contains(s),
    "exposure" | "unmanaged_container" | "ssh_login" => server(s),
    "vendor_token_invalid"
    | "external_incident"
    | "login"
    | "recovery"
    | "login_lockout"
    | "security_receipt" => false,
    _ => {
      idx.services.contains(s)
        || s
          .strip_prefix("服务 ")
          .is_some_and(|name| idx.services.contains(name))
        || s.split_once(':').is_some_and(|(name, _)| {
          idx.services.contains(name) || server(name)
        })
        || server(s)
        || s.strip_prefix("服务器 ").is_some_and(server)
        || s
          .split_once('>')
          .is_some_and(|(from, to)| server(from) || server(to))
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn compute_at(
  c: &Connection,
  snap: &snapshot::Snapshot,
  now: i64,
  days: u32,
  server_filter: Option<&str>,
  service_filter: Option<&str>,
  max_points: usize,
  allowed_services: Option<&BTreeSet<String>>,
) -> Result<ReportView, ApiError> {
  let world = &snap.world;
  let runtime = |name: &str| {
    snapshot::service_runtime_server(snap, name).unwrap_or_default()
  };
  if let Some(srv) = server_filter
    && !world.servers.contains_key(srv)
  {
    return Err(crate::world::server_not_found(srv));
  }
  if let Some(svc) = service_filter {
    world.services.get(svc).ok_or_else(|| {
      ApiError::not_found(format!("没有服务 {svc}"))
        .with_hint("用 wharf service list 查看服务名")
    })?;
    if let Some(srv) = server_filter
      && runtime(svc) != srv
    {
      return Err(ApiError::invalid(format!(
        "服务 {svc} 不在服务器 {srv} 上"
      )));
    }
  }

  let selected_servers: Vec<String> =
    match (server_filter, service_filter, allowed_services) {
      (Some(srv), _, None) => vec![srv.to_string()],
      (None, None, None) => world.servers.keys().cloned().collect(),
      _ => vec![],
    };
  let mut selected_services: Vec<(String, String, Option<u64>)> =
    if let Some(svc) = service_filter {
      let row = &world.services[svc];
      vec![(
        svc.to_string(),
        runtime(svc).to_string(),
        service_limit(&row.spec),
      )]
    } else {
      world
        .services
        .iter()
        .filter(|(name, _)| {
          server_filter.is_none_or(|srv| runtime(name) == srv)
        })
        .map(|(n, r)| {
          (n.clone(), runtime(n).to_string(), service_limit(&r.spec))
        })
        .collect()
    };

  if let Some(allowed) = allowed_services {
    selected_services.retain(|(name, _, _)| allowed.contains(name));
  }
  let span = i64::from(days) * DAY_MS;
  let period_end = now;
  let period_start = now - span;
  let previous_end = period_start;
  let previous_start = period_start - span;
  let windows = [
    Window {
      start: previous_start,
      end: previous_end,
    },
    Window {
      start: period_start,
      end: period_end,
    },
  ];
  let cutoffs = metrics::cutoffs(now);
  let mut raw_peaks = summary::RawPeaks::default();

  let mut scanned: usize = 0;
  let mut earliest_at: Option<i64> = None;
  let mut latest_at: Option<i64> = None;

  // 服务器指标扫描
  let mut srv_stmt = c
    .prepare_cached(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND at < ?3
         AND name IN ('host.cpu', 'host.mem', 'host.mem_total', 'host.disk', 'host.disk_total', 'host.net_rx', 'host.net_tx', 'host.cpu.max', 'host.mem.max') ORDER BY at ASC",
    )
    .map_err(sql_err)?;
  let mut servers = Vec::with_capacity(selected_servers.len());
  for srv in &selected_servers {
    let mut obj_earliest = None;
    let mut acc: [BTreeMap<String, SeriesAcc>; 2] =
      Default::default();
    let rows = srv_stmt
      .query_map(params![srv, previous_start, period_end], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, i64>(1)?,
          r.get::<_, f64>(2)?,
        ))
      })
      .map_err(sql_err)?;
    for row in rows {
      let (name, at, value) = row.map_err(sql_err)?;
      scanned += 1;
      if scanned > max_points {
        return Err(
          ApiError::invalid(format!(
            "报告查询扫描超过上限（{max_points} 个点）"
          ))
          .with_hint(
            "加上 --server <机器>、--service <服务> 或 --days 1 缩小范围",
          ),
        );
      }
      update_bounds(&mut earliest_at, &mut latest_at, at);
      obj_earliest =
        Some(obj_earliest.map_or(at, |old: i64| old.min(at)));
      let idx = usize::from(at >= period_start);
      acc[idx].entry(name).or_default().push(at, value);
    }
    let ratio = previous_coverage_ratio(
      obj_earliest,
      previous_start,
      previous_end,
    );
    let get = |idx: usize, metric: &str| {
      if idx == 0 && ratio < MIN_PREVIOUS_RATIO {
        None
      } else {
        acc[idx].get(metric)
      }
    };
    let peak = |metric: &str, max: &str| {
      peak_delta(
        get(1, metric),
        get(1, max),
        get(0, metric),
        get(0, max),
        cutoffs,
      )
    };
    let (cpu_peak, raw_cpu) = peak("host.cpu", "host.cpu.max");
    let (mem_peak, raw_mem) = peak("host.mem", "host.mem.max");
    raw_peaks.servers.push((raw_cpu, raw_mem));
    let integral = |idx, metric: &str| {
      get(idx, metric)
        .and_then(|a| total(&a.hour_integrals(windows[idx], cutoffs)))
    };
    servers.push(ServerReport {
      previous_ratio: Some(ratio),
      name: srv.clone(),
      cpu_avg: make_delta(
        get(1, "host.cpu").and_then(SeriesAcc::avg),
        get(0, "host.cpu").and_then(SeriesAcc::avg),
      ),
      cpu_peak,
      mem_avg: make_delta(
        get(1, "host.mem").and_then(SeriesAcc::avg),
        get(0, "host.mem").and_then(SeriesAcc::avg),
      ),
      mem_peak,
      mem_total: get(1, "host.mem_total")
        .or_else(|| get(0, "host.mem_total"))
        .and_then(SeriesAcc::latest),
      disk_change: make_delta(
        get(1, "host.disk").and_then(SeriesAcc::delta),
        get(0, "host.disk").and_then(SeriesAcc::delta),
      ),
      disk_used: get(1, "host.disk").and_then(SeriesAcc::latest),
      disk_total: get(1, "host.disk_total")
        .or_else(|| get(0, "host.disk_total"))
        .and_then(SeriesAcc::latest),
      net_rx_bytes: make_delta(
        integral(1, "host.net_rx"),
        integral(0, "host.net_rx"),
      ),
      net_tx_bytes: make_delta(
        integral(1, "host.net_tx"),
        integral(0, "host.net_tx"),
      ),
    });
  }

  // 服务指标扫描
  let mut svc_stmt = c
    .prepare_cached(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND at < ?3
         AND name IN ('svc.cpu', 'svc.mem', 'req.qps', 'req.err', 'req.p95', 'svc.mem.max') ORDER BY at ASC",
    )
    .map_err(sql_err)?;
  let mut services = Vec::with_capacity(selected_services.len());
  for (svc, srv, limit) in &selected_services {
    let mut obj_earliest = None;
    let mut acc: [BTreeMap<String, SeriesAcc>; 2] =
      Default::default();
    let rows = svc_stmt
      .query_map(params![svc, previous_start, period_end], |r| {
        Ok((
          r.get::<_, String>(0)?,
          r.get::<_, i64>(1)?,
          r.get::<_, f64>(2)?,
        ))
      })
      .map_err(sql_err)?;
    for row in rows {
      let (name, at, value) = row.map_err(sql_err)?;
      scanned += 1;
      if scanned > max_points {
        return Err(
          ApiError::invalid(format!(
            "报告查询扫描超过上限（{max_points} 个点）"
          ))
          .with_hint(
            "加上 --server <机器>、--service <服务> 或 --days 1 缩小范围",
          ),
        );
      }
      update_bounds(&mut earliest_at, &mut latest_at, at);
      obj_earliest =
        Some(obj_earliest.map_or(at, |old: i64| old.min(at)));
      let idx = usize::from(at >= period_start);
      acc[idx].entry(name).or_default().push(at, value);
    }
    let ratio = previous_coverage_ratio(
      obj_earliest,
      previous_start,
      previous_end,
    );
    let get = |idx: usize, metric: &str| {
      if idx == 0 && ratio < MIN_PREVIOUS_RATIO {
        None
      } else {
        acc[idx].get(metric)
      }
    };
    let peak = |metric: &str, max: &str| {
      peak_delta(
        get(1, metric),
        get(1, max),
        get(0, metric),
        get(0, max),
        cutoffs,
      )
    };
    let (mem_peak, raw_mem) = peak("svc.mem", "svc.mem.max");
    raw_peaks.services.push(raw_mem);
    let weights = windows.map(|window| {
      let idx = usize::from(window.start == period_start);
      get(idx, "req.qps")
        .map(|a| a.hour_integrals(window, cutoffs))
        .unwrap_or_default()
    });
    let weighted = |idx, metric: &str| {
      get(idx, metric)
        .and_then(|a| weighted_avg_by_hour(a, &weights[idx]))
    };
    services.push(ServiceReport {
      previous_ratio: Some(ratio),
      name: svc.clone(),
      server: srv.clone(),
      cpu_avg: make_delta(
        get(1, "svc.cpu").and_then(SeriesAcc::avg),
        get(0, "svc.cpu").and_then(SeriesAcc::avg),
      ),
      mem_avg: make_delta(
        get(1, "svc.mem").and_then(SeriesAcc::avg),
        get(0, "svc.mem").and_then(SeriesAcc::avg),
      ),
      mem_peak,
      mem_limit: *limit,
      requests: make_delta(total(&weights[1]), total(&weights[0])),
      err_pct: make_delta(
        weighted(1, "req.err"),
        weighted(0, "req.err"),
      ),
      p95_ms: make_delta(
        weighted(1, "req.p95"),
        weighted(0, "req.p95"),
      ),
    });
  }

  // 告警触发次数按规则分组对比
  let index = AlertFilterIndex::build(
    c,
    world,
    selected_services
      .iter()
      .map(|(n, _, _)| n.clone())
      .collect(),
    server_filter,
    service_filter,
    allowed_services.is_some(),
  )?;
  let mut alert_counts: BTreeMap<String, (u64, u64)> =
    BTreeMap::new();
  let mut alert_stmt = c
    .prepare_cached(
      "SELECT at, source, subject,
              (SELECT service FROM alert_custom_rules WHERE name = alert_history.source AND service = alert_history.subject)
       FROM alert_history
       WHERE at >= ?1 AND at < ?2 AND (ok = 0 OR source = 'update') AND source != 'daily_digest'",
    )
    .map_err(sql_err)?;
  let alert_rows = alert_stmt
    .query_map(params![previous_start, period_end], |r| {
      Ok((
        r.get::<_, i64>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, Option<String>>(2)?,
        r.get::<_, Option<String>>(3)?,
      ))
    })
    .map_err(sql_err)?;
  for row in alert_rows {
    let (at, source, subject, custom_service) =
      row.map_err(sql_err)?;
    let matches = if allowed_services.is_some() {
      if source == "task" {
        subject
          .as_ref()
          .is_some_and(|name| index.tasks.contains(name))
      } else {
        crate::scope_filter::alert_in_scope(
          &index.services,
          world,
          custom_service.as_deref(),
          &source,
          subject.as_deref(),
        )
      }
    } else {
      alert_matches_filter(
        &source,
        subject.as_deref(),
        custom_service.as_deref(),
        &index,
      )
    };
    if !matches {
      continue;
    }
    let entry = alert_counts.entry(source).or_default();
    if at >= period_start {
      entry.1 += 1;
    } else {
      entry.0 += 1;
    }
  }

  let has_current = latest_at.is_some_and(|t| t >= period_start);
  let previous_ratio = previous_coverage_ratio(
    earliest_at,
    previous_start,
    previous_end,
  );
  let has_previous = previous_ratio >= MIN_PREVIOUS_RATIO;

  let mut alerts: Vec<AlertReport> = alert_counts
    .into_iter()
    .filter(|(_, (_, curr))| has_previous || *curr > 0)
    .map(|(rule, (prev, curr))| {
      let previous = has_previous.then_some(prev);
      let change_pct = calc_change_pct(
        Some(curr as f64),
        previous.map(|p| p as f64),
      );
      AlertReport {
        name: crate::rules::rule_display_name(&rule),
        rule,
        current: curr,
        previous,
        change_pct,
      }
    })
    .collect();
  alerts.sort_by(|a, b| {
    b.current.cmp(&a.current).then_with(|| a.rule.cmp(&b.rule))
  });

  let summary =
    summary::build_summary(&servers, &services, &alerts, &raw_peaks);
  let coverage = ReportCoverage {
    period_start,
    period_end,
    previous_start,
    previous_end,
    earliest_at,
    latest_at,
    has_current,
    has_previous,
    previous_ratio,
  };
  Ok(ReportView {
    days,
    coverage,
    summary,
    servers,
    services,
    alerts,
  })
}

#[cfg(test)]
#[path = "report/tests.rs"]
mod tests;
