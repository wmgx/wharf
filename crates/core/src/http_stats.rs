//! 服务维度的请求打点：agent 上报网关各域名的请求统计，按路由换成服务，记成
//! `req.qps`、`req.p50`、`req.p95`（毫秒）、`req.err`（5xx 占比，百分数），对象是服务名。
//! 只覆盖经 Wharf Caddy 网关进来的 HTTP；Cloudflare 隧道和服务之间的调用不在里面。
//!
//! 5xx 告警：最近 [WINDOW] 次上报合计的 5xx 占比交给 [crate::rules]（规则 http_5xx），5xx 不到 [MIN_ERRORS] 个时
//! 只报低于 [RECOVER_PCT]% 的点（只能恢复，不会触发）。计数只在内存里。

use std::{
  collections::{BTreeMap, VecDeque},
  sync::{Arc, Mutex},
};

use wharf_api_types::agent::HostTraffic;

use crate::state::AppState;

const WINDOW: usize = 5;
const MIN_ERRORS: u64 = 10;
const RECOVER_PCT: f64 = 2.0;

static WINDOWS: Mutex<BTreeMap<String, VecDeque<(u64, u64)>>> =
  Mutex::new(BTreeMap::new());

/// 一个服务这段时间的合计：多个域名指向同一服务时请求相加、延迟按请求数加权。
#[derive(Debug, Default, PartialEq)]
struct Sum {
  reqs: u64,
  errors: u64,
  secs: f64,
  p50: f64,
  p95: f64,
}

fn by_service(
  hosts: &BTreeMap<String, HostTraffic>,
  service_of: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, Sum> {
  let mut out: BTreeMap<String, Sum> = BTreeMap::new();
  for (host, t) in hosts {
    let Some(svc) = service_of(host) else {
      continue;
    };
    let s = out.entry(svc).or_default();
    let w = t.reqs as f64;
    s.reqs += t.reqs;
    s.errors += t.errors;
    s.secs = s.secs.max(t.secs as f64);
    s.p50 += t.p50_ms as f64 * w;
    s.p95 += t.p95_ms as f64 * w;
  }
  for s in out.values_mut() {
    if s.reqs > 0 {
      s.p50 /= s.reqs as f64;
      s.p95 /= s.reqs as f64;
    }
  }
  out
}

pub async fn record(
  state: Arc<AppState>,
  hosts: BTreeMap<String, HostTraffic>,
) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let sums = by_service(&hosts, |h| {
    snap
      .world
      .routes
      .get(h)
      .map(|r| r.spec.service.clone())
      .filter(|s| !s.is_empty())
  });
  let mut points: Vec<(String, String, f64)> = Vec::new();
  for (svc, s) in &sums {
    points.push((
      "req.qps".into(),
      svc.clone(),
      s.reqs as f64 / s.secs.max(1.0),
    ));
    if s.reqs > 0 {
      points.push(("req.p50".into(), svc.clone(), s.p50));
      points.push(("req.p95".into(), svc.clone(), s.p95));
      points.push((
        "req.err".into(),
        svc.clone(),
        100.0 * s.errors as f64 / s.reqs as f64,
      ));
    }
  }
  crate::metrics::insert_owned(&state, points).await;

  let mut events = Vec::new();
  {
    let mut w = WINDOWS.lock().unwrap_or_else(|e| e.into_inner());
    for (svc, s) in &sums {
      let q = w.entry(svc.clone()).or_default();
      q.push_back((s.reqs, s.errors));
      while q.len() > WINDOW {
        q.pop_front();
      }
      let (reqs, errors) =
        q.iter().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
      let pct = if reqs == 0 {
        0.0
      } else {
        100.0 * errors as f64 / reqs as f64
      };
      // 错误太少时不算触发，只报能让它恢复的点。
      if errors >= MIN_ERRORS || pct < RECOVER_PCT {
        events.push((svc.clone(), pct));
      }
    }
  }
  for (svc, pct) in events {
    crate::rules::observe(&state, "req.err_pct_5m", &svc, pct, "")
      .await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hosts_of_one_service_add_up() {
    let t = |reqs, errors, p50| HostTraffic {
      reqs,
      errors,
      secs: 60.0,
      p50_ms: p50,
      p95_ms: p50,
    };
    let hosts = BTreeMap::from([
      ("a.example.com".to_string(), t(30, 3, 10.0)),
      ("b.example.com".to_string(), t(10, 0, 50.0)),
      ("x.example.com".to_string(), t(5, 0, 1.0)),
    ]);
    let s = by_service(&hosts, |h| {
      (h != "x.example.com").then(|| "web".to_string())
    });
    assert_eq!(s.len(), 1);
    let web = &s["web"];
    assert_eq!((web.reqs, web.errors), (40, 3));
    assert!((web.p50 - 20.0).abs() < 1e-9);
  }
}
