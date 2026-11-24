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
  rules::resources::service_limit,
  snapshot,
  state::AppState,
  world::World,
};

#[path = "report/summary.rs"]
mod summary;

const HOUR_MS: i64 = 60 * 60 * 1000;
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
  let world = snap.world;
  let view = s
    .db
    .call(move |c| {
      compute_at(
        c,
        &world,
        now,
        days,
        server_filter.as_deref(),
        service_filter.as_deref(),
        MAX_SCAN_POINTS,
      )
    })
    .await?;
  Ok(Json(view))
}

#[derive(Default)]
struct SeriesAcc {
  /// 按小时分桶求均值再平均，避免 1 分钟 / 10 分钟 / 1 小时混合粒度导致权重偏移。
  hours: BTreeMap<i64, (f64, u64)>,
  max: Option<f64>,
  first: Option<(i64, f64)>,
  last: Option<(i64, f64)>,
}

impl SeriesAcc {
  fn push(&mut self, at: i64, value: f64) {
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

  /// 对按秒计数的速率指标（网速、QPS）按小时重叠时长积分得到周期总量。
  fn integral_per_sec(&self, start: i64, end: i64) -> Option<f64> {
    if self.hours.is_empty() {
      return None;
    }
    let mut total = 0.0;
    for (&h, &(sum, count)) in &self.hours {
      let h_start = (h * HOUR_MS).max(start);
      let h_end = ((h + 1) * HOUR_MS).min(end);
      if h_end > h_start {
        let avg_rate = sum / count as f64;
        total += avg_rate * (h_end - h_start) as f64 / 1000.0;
      }
    }
    Some(total)
  }
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

fn clear_previous(d: &mut MetricDelta) {
  d.previous = None;
  d.change_pct = None;
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

fn alert_matches_filter(
  subject: Option<&str>,
  server: Option<&str>,
  service: Option<&str>,
  server_services: &BTreeSet<String>,
) -> bool {
  let matches_svc = |s: &str, svc: &str| {
    s == svc
      || s
        .strip_prefix(svc)
        .is_some_and(|rest| rest.starts_with(':'))
      || s.strip_prefix("服务 ").is_some_and(|rest| rest == svc)
  };
  if let Some(svc) = service {
    return subject.is_some_and(|s| matches_svc(s, svc));
  }
  if let Some(srv) = server {
    return subject.is_some_and(|s| {
      s == srv
        || s
          .strip_prefix(srv)
          .is_some_and(|rest| rest.starts_with(':'))
        || s.strip_prefix("服务器 ").is_some_and(|rest| rest == srv)
        || s
          .strip_prefix(srv)
          .is_some_and(|rest| rest.starts_with('>'))
        || s.strip_suffix(srv).is_some_and(|rest| rest.ends_with('>'))
        || server_services.iter().any(|svc| matches_svc(s, svc))
    });
  }
  true
}

fn compute_at(
  c: &Connection,
  world: &World,
  now: i64,
  days: u32,
  server_filter: Option<&str>,
  service_filter: Option<&str>,
  max_points: usize,
) -> Result<ReportView, ApiError> {
  if let Some(srv) = server_filter
    && !world.servers.contains_key(srv)
  {
    return Err(crate::world::server_not_found(srv));
  }
  if let Some(svc) = service_filter {
    let row = world.services.get(svc).ok_or_else(|| {
      ApiError::not_found(format!("没有服务 {svc}"))
        .with_hint("用 wharf service list 查看服务名")
    })?;
    if let Some(srv) = server_filter
      && row.spec.server != srv
    {
      return Err(ApiError::invalid(format!(
        "服务 {svc} 不在服务器 {srv} 上"
      )));
    }
  }

  let selected_servers: Vec<String> =
    match (server_filter, service_filter) {
      (Some(srv), _) => vec![srv.to_string()],
      (None, Some(_)) => vec![],
      (None, None) => world.servers.keys().cloned().collect(),
    };
  let selected_services: Vec<(String, String, Option<u64>)> =
    if let Some(svc) = service_filter {
      let row = &world.services[svc];
      vec![(
        svc.to_string(),
        row.spec.server.clone(),
        service_limit(&row.spec),
      )]
    } else {
      world
        .services
        .iter()
        .filter(|(_, r)| {
          server_filter.is_none_or(|srv| r.spec.server == srv)
        })
        .map(|(n, r)| {
          (n.clone(), r.spec.server.clone(), service_limit(&r.spec))
        })
        .collect()
    };

  let span = i64::from(days) * DAY_MS;
  let period_end = now;
  let period_start = now - span;
  let previous_end = period_start;
  let previous_start = period_start - span;

  let mut scanned: usize = 0;
  let mut earliest_at: Option<i64> = None;
  let mut latest_at: Option<i64> = None;

  // 服务器指标扫描
  let mut srv_stmt = c
    .prepare_cached(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND at < ?3
         AND name IN ('host.cpu', 'host.mem', 'host.mem_total', 'host.disk', 'host.disk_total', 'host.net_rx', 'host.net_tx')",
    )
    .map_err(sql_err)?;
  let mut servers = Vec::with_capacity(selected_servers.len());
  for srv in &selected_servers {
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
      let idx = usize::from(at >= period_start);
      acc[idx].entry(name).or_default().push(at, value);
    }
    let get = |idx: usize, metric: &str| acc[idx].get(metric);
    servers.push(ServerReport {
      name: srv.clone(),
      cpu_avg: make_delta(
        get(1, "host.cpu").and_then(SeriesAcc::avg),
        get(0, "host.cpu").and_then(SeriesAcc::avg),
      ),
      cpu_peak: make_delta(
        get(1, "host.cpu").and_then(SeriesAcc::peak),
        get(0, "host.cpu").and_then(SeriesAcc::peak),
      ),
      mem_avg: make_delta(
        get(1, "host.mem").and_then(SeriesAcc::avg),
        get(0, "host.mem").and_then(SeriesAcc::avg),
      ),
      mem_peak: make_delta(
        get(1, "host.mem").and_then(SeriesAcc::peak),
        get(0, "host.mem").and_then(SeriesAcc::peak),
      ),
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
        get(1, "host.net_rx")
          .and_then(|a| a.integral_per_sec(period_start, period_end)),
        get(0, "host.net_rx").and_then(|a| {
          a.integral_per_sec(previous_start, previous_end)
        }),
      ),
      net_tx_bytes: make_delta(
        get(1, "host.net_tx")
          .and_then(|a| a.integral_per_sec(period_start, period_end)),
        get(0, "host.net_tx").and_then(|a| {
          a.integral_per_sec(previous_start, previous_end)
        }),
      ),
    });
  }

  // 服务指标扫描
  let mut svc_stmt = c
    .prepare_cached(
      "SELECT name, at, value FROM points
       WHERE subject = ?1 AND at >= ?2 AND at < ?3
         AND name IN ('svc.cpu', 'svc.mem', 'req.qps', 'req.err', 'req.p95')",
    )
    .map_err(sql_err)?;
  let mut services = Vec::with_capacity(selected_services.len());
  for (svc, srv, limit) in &selected_services {
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
      let idx = usize::from(at >= period_start);
      acc[idx].entry(name).or_default().push(at, value);
    }
    let get = |idx: usize, metric: &str| acc[idx].get(metric);
    services.push(ServiceReport {
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
      mem_peak: make_delta(
        get(1, "svc.mem").and_then(SeriesAcc::peak),
        get(0, "svc.mem").and_then(SeriesAcc::peak),
      ),
      mem_limit: *limit,
      requests: make_delta(
        get(1, "req.qps")
          .and_then(|a| a.integral_per_sec(period_start, period_end)),
        get(0, "req.qps").and_then(|a| {
          a.integral_per_sec(previous_start, previous_end)
        }),
      ),
      err_pct: make_delta(
        get(1, "req.err").and_then(SeriesAcc::avg),
        get(0, "req.err").and_then(SeriesAcc::avg),
      ),
      p95_ms: make_delta(
        get(1, "req.p95").and_then(SeriesAcc::avg),
        get(0, "req.p95").and_then(SeriesAcc::avg),
      ),
    });
  }

  // 告警触发次数按规则分组对比
  let server_services: BTreeSet<String> = selected_services
    .iter()
    .map(|(n, _, _)| n.clone())
    .collect();
  let mut alert_counts: BTreeMap<String, (u64, u64)> =
    BTreeMap::new();
  let mut alert_stmt = c
    .prepare_cached(
      "SELECT at, source, subject FROM alert_history
       WHERE at >= ?1 AND at < ?2 AND ok = 0 AND source != 'daily_digest'",
    )
    .map_err(sql_err)?;
  let alert_rows = alert_stmt
    .query_map(params![previous_start, period_end], |r| {
      Ok((
        r.get::<_, i64>(0)?,
        r.get::<_, String>(1)?,
        r.get::<_, Option<String>>(2)?,
      ))
    })
    .map_err(sql_err)?;
  for row in alert_rows {
    let (at, source, subject) = row.map_err(sql_err)?;
    if !alert_matches_filter(
      subject.as_deref(),
      server_filter,
      service_filter,
      &server_services,
    ) {
      continue;
    }
    update_bounds(&mut earliest_at, &mut latest_at, at);
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

  if !has_previous {
    for s in &mut servers {
      clear_previous(&mut s.cpu_avg);
      clear_previous(&mut s.cpu_peak);
      clear_previous(&mut s.mem_avg);
      clear_previous(&mut s.mem_peak);
      clear_previous(&mut s.disk_change);
      clear_previous(&mut s.net_rx_bytes);
      clear_previous(&mut s.net_tx_bytes);
    }
    for svc in &mut services {
      clear_previous(&mut svc.cpu_avg);
      clear_previous(&mut svc.mem_avg);
      clear_previous(&mut svc.mem_peak);
      clear_previous(&mut svc.requests);
      clear_previous(&mut svc.err_pct);
      clear_previous(&mut svc.p95_ms);
    }
  }

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

  let summary = summary::build_summary(&servers, &services, &alerts);
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
