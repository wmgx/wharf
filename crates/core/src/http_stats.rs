//! 服务维度的请求打点：agent 上报网关各域名的请求统计，按路由换成服务，记成
//! `req.qps`、`req.p50`、`req.p95`（毫秒）、`req.err`（5xx 占比，百分数），对象是服务名。
//! 只覆盖经 Wharf Caddy 网关进来的 HTTP；Cloudflare 隧道和服务之间的调用不在里面。
//!
//! 5xx 告警：合计各网关最近五分钟的请求和错误，5xx 不到 [MIN_ERRORS] 个时
//! 只报低于 [RECOVER_PCT]% 的点（只能恢复，不会触发）。计数只在内存里。

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  sync::{Arc, Mutex},
  time::Duration,
};

use wharf_api_types::agent::HostTraffic;

use crate::{
  db::{self, now_ms},
  report_guard, rules,
  state::AppState,
  world::World,
};

const WINDOW: usize = 5;
const MIN_ERRORS: u64 = 10;
const RECOVER_PCT: f64 = 2.0;

const WINDOW_MS: i64 = 300_000;
const LATEST_MS: i64 = 90_000;
type Gateways = BTreeMap<String, VecDeque<(i64, Sum)>>;
static WINDOWS: Mutex<BTreeMap<String, Gateways>> =
  Mutex::new(BTreeMap::new());

pub(crate) fn forget(services: &BTreeSet<String>) {
  if !services.is_empty() {
    WINDOWS
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .retain(|name, _| !services.contains(name));
  }
}

pub(crate) fn forget_sample(service: &str) {
  WINDOWS
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .remove(service);
}

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
    s.reqs = s.reqs.saturating_add(t.reqs);
    s.errors = s.errors.saturating_add(t.errors);
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

fn accumulate(
  windows: &mut Gateways,
  at: i64,
  online: impl Fn(&str) -> bool,
) -> (Sum, f64, Option<f64>) {
  let (mut requests, mut errors) = (0_u64, 0_u64);
  let mut latest = Sum::default();
  let mut qps = 0.0;
  windows.retain(|server, samples| {
    samples.retain(|(sample_at, _)| at - *sample_at < WINDOW_MS);
    if online(server) {
      for (_, sample) in
        samples.iter().filter(|(stamp, _)| *stamp <= at)
      {
        requests = requests.saturating_add(sample.reqs);
        errors = errors.saturating_add(sample.errors);
      }
      if let Some((sample_at, sample)) =
        samples.iter().rev().find(|(stamp, _)| *stamp <= at)
        && at - *sample_at < LATEST_MS
      {
        let weight = sample.reqs as f64;
        qps += weight / sample.secs.max(1.0);
        latest.reqs = latest.reqs.saturating_add(sample.reqs);
        latest.errors = latest.errors.saturating_add(sample.errors);
        latest.p50 += sample.p50 * weight;
        latest.p95 += sample.p95 * weight;
      }
    }
    !samples.is_empty()
  });
  if latest.reqs > 0 {
    latest.p50 /= latest.reqs as f64;
    latest.p95 /= latest.reqs as f64;
  }
  let pct = 100.0 * errors as f64 / requests.max(1) as f64;
  let observation = if errors >= MIN_ERRORS {
    Some(pct)
  } else {
    (pct < RECOVER_PCT).then_some(pct)
  };
  (latest, qps, observation)
}

fn service_gateways(world: &World) -> BTreeMap<&str, BTreeSet<&str>> {
  let mut services = BTreeMap::<_, BTreeSet<_>>::new();
  for route in world.routes.values().map(|row| &row.spec) {
    if let Some(service) = report_guard::single_service(route) {
      for server in report_guard::caddy_servers(world, route) {
        services.entry(service).or_default().insert(server);
      }
    }
  }
  services
}

fn has_fresh_samples(
  gateways: &BTreeSet<&str>,
  samples: &Gateways,
  at: i64,
  online: impl Fn(&str) -> bool,
) -> bool {
  gateways.iter().all(|&server| {
    online(server)
      && samples.get(server).is_some_and(|samples| {
        samples
          .iter()
          .rev()
          .any(|(stamp, _)| (0..LATEST_MS).contains(&(at - *stamp)))
      })
  })
}

pub async fn record_at(
  state: &AppState,
  server: &str,
  at: i64,
  hosts: BTreeMap<String, HostTraffic>,
) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let sums = by_service(&hosts, |host| {
    let service =
      report_guard::route_single_service(&snap.world, server, host)?;
    rules::lifecycle::running_service(&snap.world, &service)
      .then_some(service)
  });
  let gateways = service_gateways(&snap.world);
  let events: Vec<_> = {
    let mut windows =
      WINDOWS.lock().unwrap_or_else(|e| e.into_inner());
    sums
      .into_iter()
      .map(|(service, sum)| {
        let by_server = windows.entry(service.clone()).or_default();
        let samples =
          by_server.entry(server.to_string()).or_default();
        if samples.back().is_none_or(|(last, _)| at > *last) {
          if samples.len() == WINDOW {
            samples.pop_front();
          }
          samples.push_back((at, sum));
        }
        let expected = &gateways[service.as_str()];
        let online = |s: &str| state.hub.is_online(s);
        let (summary, qps, pct) = accumulate(by_server, at, |s| {
          expected.contains(s) && (s == server || online(s))
        });
        let known =
          has_fresh_samples(expected, by_server, at, online);
        (service, summary, qps, pct, known)
      })
      .collect()
  };
  let mut points = Vec::new();
  for (service, sum, qps, _, _) in &events {
    points.push(("req.qps".into(), service.clone(), *qps));
    if sum.reqs > 0 {
      points.push(("req.p50".into(), service.clone(), sum.p50));
      points.push(("req.p95".into(), service.clone(), sum.p95));
      points.push((
        "req.err".into(),
        service.clone(),
        100.0 * sum.errors as f64 / sum.reqs as f64,
      ));
    }
  }
  crate::metrics::insert_owned_at(
    state,
    at.div_euclid(60_000) * 60_000,
    points,
  )
  .await;
  for (service, sum, _, pct, known) in events {
    if !known {
      continue;
    }
    if let Some(pct) = pct {
      rules::observe_at(
        state,
        at,
        "req.err_pct_5m",
        &service,
        pct,
        "",
      )
      .await;
    }
    if sum.reqs > 0 {
      let detail = format!("最近 1 分钟共 {} 次请求", sum.reqs);
      rules::observe_at(
        state,
        at,
        "req.err",
        &service,
        100.0 * sum.errors as f64 / sum.reqs as f64,
        &detail,
      )
      .await;
      rules::observe_at(
        state, at, "req.p95", &service, sum.p95, &detail,
      )
      .await;
    }
  }
}

pub(crate) async fn sweep(state: &AppState, at: i64) {
  rules::ensure_loaded(state).await;
  let Ok(world) = state
    .db
    .call(|c| World::from_rows(db::all_resources(c)?))
    .await
  else {
    return;
  };
  let gateways = service_gateways(&world);
  let (idle, recovered) = {
    let mut windows =
      WINDOWS.lock().unwrap_or_else(|e| e.into_inner());
    let mut idle = BTreeSet::new();
    let mut recovered = BTreeSet::new();
    windows.retain(|service, by_server| {
      let Some(expected) = gateways.get(service.as_str()) else {
        return false;
      };
      let online = |s: &str| state.hub.is_online(s);
      let (latest, _, pct) = accumulate(by_server, at, |s| {
        expected.contains(s) && online(s)
      });
      if has_fresh_samples(expected, by_server, at, online) {
        if latest.reqs == 0 {
          idle.insert(service.clone());
        }
        if pct.is_some_and(|pct| pct < RECOVER_PCT) {
          recovered.insert(service.clone());
        }
      }
      !by_server.is_empty()
    });
    (idle, recovered)
  };
  for (service, _) in rules::firing_subjects("http_5xx") {
    if recovered.contains(&service) {
      rules::observe_at(
        state,
        at,
        "req.err_pct_5m",
        &service,
        0.0,
        "",
      )
      .await;
    }
  }
  rules::recover_idle_http(state, at, &idle).await;
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_secs(60)).await;
      sweep(&state, now_ms()).await;
    }
  });
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn multi_gateway_isolated_idle_recovers() {
    let mut gateways = Gateways::from([
      (
        "s1".into(),
        VecDeque::from([(
          60_000,
          Sum {
            reqs: 60,
            errors: 15,
            secs: 60.0,
            ..Default::default()
          },
        )]),
      ),
      (
        "s2".into(),
        VecDeque::from([(
          65_000,
          Sum {
            reqs: 60,
            secs: 60.0,
            ..Default::default()
          },
        )]),
      ),
    ]);
    let (latest, qps, pct) =
      accumulate(&mut gateways, 65_000, |_| true);
    assert_eq!((latest.reqs, qps, pct), (120, 2.0, Some(12.5)));
    gateways
      .get_mut("s2")
      .unwrap()
      .push_back((240_000, Sum::default()));
    assert_eq!(
      accumulate(&mut gateways, 240_000, |_| true).2,
      Some(12.5)
    );
    let (latest, _, pct) =
      accumulate(&mut gateways, 365_000, |_| true);
    assert_eq!((latest.reqs, pct), (0, Some(0.0)));
  }

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
