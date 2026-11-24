//! 从控制面向公共递归解析器发 UDP 查询，比较已保存的路由意图。
use std::{
  collections::{BTreeMap, BTreeSet},
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Json,
  extract::{Path, State},
};
use ipnet::IpNet;
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  external::{DnsCheck, DnsResolver, DnsVerdict},
  plan::{RunStep, StepStatus},
  spec::EdgeKind,
  view::{Issue, IssueLevel, IssueSubject, Perm},
};
use wharf_providers::http::Http;

use crate::{
  api::ApiResult,
  auth::Auth,
  planner::{self, Step, StepPlan},
  snapshot::{self, Snapshot},
  state::AppState,
};

const RESOLVERS: &[&str] = &["1.1.1.1", "8.8.8.8", "223.5.5.5"];
const UDP_TIMEOUT: Duration = Duration::from_secs(3);
const WATCH_LIMIT: Duration = Duration::from_secs(600);
const CF_IPS: &str = "https://api.cloudflare.com/client/v4/ips";

#[derive(Default)]
struct Answer {
  ips: BTreeSet<IpAddr>,
  cname: Option<String>,
}

#[derive(Clone)]
enum Expected {
  Deleted,
  Cloudflare,
  Address(IpAddr),
  Cname(String),
}

impl Expected {
  fn label(&self) -> String {
    match self {
      Self::Deleted => "没有 A / AAAA 记录".into(),
      Self::Cloudflare => "Cloudflare 的地址".into(),
      Self::Address(ip) => ip.to_string(),
      Self::Cname(target) => format!("CNAME {target}"),
    }
  }
}

#[derive(Deserialize)]
struct IpRanges {
  result: IpRangeLists,
}

#[derive(Deserialize)]
struct IpRangeLists {
  ipv4_cidrs: Vec<IpNet>,
  ipv6_cidrs: Vec<IpNet>,
}

static CF_RANGES: tokio::sync::Mutex<Option<(Instant, Vec<IpNet>)>> =
  tokio::sync::Mutex::const_new(None);

async fn cf_ranges() -> Option<Vec<IpNet>> {
  let mut cache = CF_RANGES.lock().await;
  if let Some((at, ranges)) = cache.as_ref()
    && at.elapsed() < Duration::from_secs(86_400)
  {
    return Some(ranges.clone());
  }
  let http = Http::new(Duration::from_secs(10)).ok()?;
  let fresh = async {
    let res = http
      .send(|c| c.get(CF_IPS))
      .await
      .ok()?
      .error_for_status()
      .ok()?;
    let ranges: IpRanges = res.json().await.ok()?;
    if ranges.result.ipv4_cidrs.is_empty()
      || ranges.result.ipv6_cidrs.is_empty()
    {
      return None;
    }
    Some(
      ranges
        .result
        .ipv4_cidrs
        .into_iter()
        .chain(ranges.result.ipv6_cidrs)
        .collect::<Vec<_>>(),
    )
  }
  .await;
  if let Some(ranges) = fresh {
    *cache = Some((Instant::now(), ranges.clone()));
    Some(ranges)
  } else {
    cache.as_ref().map(|(_, ranges)| ranges.clone())
  }
}

fn hostname(raw: &str) -> Result<String, ApiError> {
  let name = raw.trim_end_matches('.').to_ascii_lowercase();
  if name.is_empty()
    || name.len() > 253
    || !name.split('.').all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && label.bytes().all(|c| {
          c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
        })
    })
  {
    return Err(ApiError::invalid("域名不合法"));
  }
  Ok(name)
}

async fn expectation(
  snap: &Snapshot,
  host: &str,
) -> Result<Expected, ApiError> {
  let record = if let Some(route) = snap.world.routes.get(host) {
    let gateway = snap
      .world
      .live_gateway(host, &route.spec)
      .filter(|name| snap.world.gateways.contains_key(*name));
    if gateway.is_none() {
      return Err(ApiError::invalid("路由没有可用的网关"));
    }
    planner::desired_record(
      snap,
      &snap.world,
      &snap.net(&snap.world),
      host,
    )?
  } else if let Some((name, app)) = snap
    .world
    .edge_apps
    .iter()
    .find(|(_, app)| app.spec.domains.iter().any(|d| d == host))
  {
    if app.spec.kind == EdgeKind::Worker {
      return Ok(Expected::Cloudflare);
    }
    tokio::time::timeout(
      Duration::from_secs(10),
      crate::edge_plan::pages_record(snap, name, &app.spec),
    )
    .await
    .map_err(|_| ApiError::invalid("Pages 期望记录查不到"))??
  } else {
    return Ok(Expected::Deleted);
  };
  if record.proxied {
    Ok(Expected::Cloudflare)
  } else if record.record_type == "CNAME" {
    Ok(Expected::Cname(hostname(&record.content)?))
  } else {
    record
      .content
      .parse()
      .map(Expected::Address)
      .map_err(|_| ApiError::invalid("期望记录不是 IP 地址"))
  }
}

fn compare(
  want: &Expected,
  a: Option<&Answer>,
  aaaa: Option<&Answer>,
  ranges: Option<&[IpNet]>,
) -> DnsVerdict {
  use DnsVerdict::{Matches, Mismatch, Unavailable};
  let ip_ok = |a: &Answer, expected| {
    a.ips.len() == 1 && a.ips.contains(&expected) && a.cname.is_none()
  };
  let empty = |a: &Answer| a.ips.is_empty() && a.cname.is_none();
  let (matched, complete) = match want {
    Expected::Address(ip) => {
      let (same, other) =
        if ip.is_ipv4() { (a, aaaa) } else { (aaaa, a) };
      (
        same.is_none_or(|a| ip_ok(a, *ip)) && other.is_none_or(empty),
        same.is_some() && other.is_some(),
      )
    }
    Expected::Deleted => (
      a.is_none_or(empty) && aaaa.is_none_or(empty),
      a.is_some() && aaaa.is_some(),
    ),
    Expected::Cname(host) => {
      let has = |a: &Answer| a.cname.as_ref() == Some(host);
      (
        a.is_none_or(has) && aaaa.is_none_or(has),
        a.is_some() && aaaa.is_some(),
      )
    }
    Expected::Cloudflare => {
      let Some(ranges) = ranges else {
        return Unavailable;
      };
      let ips: Vec<_> = [a, aaaa]
        .into_iter()
        .flatten()
        .flat_map(|a| a.ips.iter())
        .collect();
      let complete = a.is_some() && aaaa.is_some();
      (
        (!complete || !ips.is_empty())
          && ips
            .iter()
            .all(|ip| ranges.iter().any(|r| r.contains(*ip))),
        complete,
      )
    }
  };
  if !complete {
    Unavailable
  } else if matched {
    Matches
  } else {
    Mismatch
  }
}

async fn check(host: &str, want: Expected) -> DnsCheck {
  let ranges = if matches!(want, Expected::Cloudflare) {
    cf_ranges().await
  } else {
    None
  };
  let resolvers = futures_util::future::join_all(
    RESOLVERS.iter().map(|resolver| async {
      let start = Instant::now();
      let (a, aaaa) = tokio::join!(
        query(resolver, host, 1),
        query(resolver, host, 28)
      );
      let ips = |a: Option<Answer>| {
        a.map(|a| {
          a.ips.into_iter().map(|ip| ip.to_string()).collect()
        })
      };
      let verdict =
        compare(&want, a.as_ref(), aaaa.as_ref(), ranges.as_deref());
      DnsResolver {
        resolver: resolver.to_string(),
        verdict,
        a: ips(a),
        aaaa: ips(aaaa),
        elapsed_ms: start.elapsed().as_millis() as u64,
      }
    }),
  )
  .await;
  DnsCheck {
    hostname: host.to_string(),
    expected: want.label(),
    effective: resolvers
      .iter()
      .all(|r| r.verdict != DnsVerdict::Mismatch),
    resolvers,
  }
}

async fn query(
  resolver: &str,
  host: &str,
  kind: u16,
) -> Option<Answer> {
  tokio::time::timeout(UDP_TIMEOUT, async {
    let mut id = [0; 2];
    getrandom::fill(&mut id).ok()?;
    let mut request =
      vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
      request.push(label.len() as u8);
      request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&kind.to_be_bytes());
    request.extend_from_slice(&1u16.to_be_bytes());
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect((resolver, 53)).await.ok()?;
    socket.send(&request).await.ok()?;
    let mut response = [0; 4096];
    loop {
      let n = socket.recv(&mut response).await.ok()?;
      if response[..n].starts_with(&id) {
        break parse_response(&response[..n], host, kind);
      }
    }
  })
  .await
  .ok()
  .flatten()
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
  Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn read_name(data: &[u8], at: &mut usize) -> Option<String> {
  let mut cursor = *at;
  let mut jumped = false;
  let mut name = String::new();
  for _ in 0..128 {
    let length = *data.get(cursor)?;
    cursor += 1;
    if length & 0xc0 == 0xc0 {
      if !jumped {
        *at = cursor + 1;
        jumped = true;
      }
      let target = (usize::from(length & 0x3f) << 8)
        | usize::from(*data.get(cursor)?);
      if target >= cursor - 1 {
        return None;
      }
      cursor = target;
      continue;
    }
    if length == 0 {
      if !jumped {
        *at = cursor;
      }
      return Some(name.to_ascii_lowercase());
    }
    if length > 63 || name.len() + usize::from(length) + 1 > 254 {
      return None;
    }
    let end = cursor + usize::from(length);
    let label = std::str::from_utf8(data.get(cursor..end)?).ok()?;
    if !name.is_empty() {
      name.push('.');
    }
    name.push_str(label);
    cursor = end;
  }
  None
}

fn parse_response(
  data: &[u8],
  host: &str,
  kind: u16,
) -> Option<Answer> {
  let flags = read_u16(data, 2)?;
  let rcode = flags & 15;
  if flags & 0xfa00 != 0x8000
    || !matches!(rcode, 0 | 3)
    || read_u16(data, 4)? != 1
  {
    return None;
  }
  let mut pos = 12;
  if read_name(data, &mut pos)? != host
    || read_u16(data, pos)? != kind
    || read_u16(data, pos + 2)? != 1
  {
    return None;
  }
  pos += 4;
  let mut addr: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
  let mut aliases = BTreeMap::new();
  for _ in 0..read_u16(data, 6)? {
    let name = read_name(data, &mut pos)?;
    let ty = read_u16(data, pos)?;
    let class = read_u16(data, pos + 2)?;
    let len = usize::from(read_u16(data, pos + 8)?);
    pos += 10;
    let rdata = data.get(pos..pos + len)?;
    if class == 1 {
      match (ty, len) {
        (5, _) => {
          let mut end = pos;
          let target = read_name(data, &mut end)?;
          if end != pos + len {
            return None;
          }
          aliases.insert(name, target);
        }
        (1, 4) if kind == 1 => {
          addr.entry(name).or_default().insert(
            Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?).into(),
          );
        }
        (28, 16) if kind == 28 => {
          addr.entry(name).or_default().insert(
            Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).into(),
          );
        }
        _ => {}
      }
    }
    pos += len;
  }
  let mut canonical = host;
  let mut seen = BTreeSet::new();
  while let Some(target) = aliases.get(canonical) {
    if !seen.insert(canonical) {
      return None;
    }
    canonical = target;
  }
  Some(Answer {
    ips: addr.remove(canonical).unwrap_or_default(),
    cname: aliases.remove(host),
  })
}

struct Watch {
  cancel: CancellationToken,
  started: Instant,
  lagging: Vec<String>,
}

static WATCHES: Mutex<BTreeMap<String, Watch>> =
  Mutex::new(BTreeMap::new());

fn watches() -> std::sync::MutexGuard<'static, BTreeMap<String, Watch>>
{
  WATCHES.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn after_apply(
  state: Arc<AppState>,
  steps: &[StepPlan],
  results: &[RunStep],
) {
  let hosts: BTreeSet<_> = steps
    .iter()
    .zip(results)
    .filter_map(|(step, result)| {
      if result.status != StepStatus::Done {
        return None;
      }
      match &step.step {
        Step::DnsUpsert { hostname, .. }
        | Step::DnsDelete { hostname, .. }
        | Step::EdgeAttach { hostname, .. } => Some(hostname.clone()),
        Step::EdgeDetach { domain } => Some(domain.hostname.clone()),
        _ => None,
      }
    })
    .collect();
  for host in hosts {
    let cancel = CancellationToken::new();
    let started = Instant::now();
    if let Some(old) = watches().insert(
      host.clone(),
      Watch {
        cancel: cancel.clone(),
        started,
        lagging: vec![],
      },
    ) {
      old.cancel.cancel();
    }
    let state = state.clone();
    tokio::spawn(async move {
      tokio::select! {
        _ = cancel.cancelled() => {}
        _ = watch(&state, &host, started) => {}
      }
    });
  }
}

fn update(host: &str, started: Option<Instant>, result: &DnsCheck) {
  let mut watches = watches();
  let Some(watch) = watches.get_mut(host) else {
    return;
  };
  if started != Some(watch.started) {
    return;
  }
  if result.effective {
    if let Some(watch) = watches.remove(host) {
      watch.cancel.cancel();
    }
  } else if watch.started.elapsed() >= WATCH_LIMIT {
    watch.lagging = result
      .resolvers
      .iter()
      .filter(|r| r.verdict == DnsVerdict::Mismatch)
      .map(|r| r.resolver.clone())
      .collect();
  }
}

async fn watch(state: &AppState, host: &str, started: Instant) {
  let mut tick = tokio::time::interval(Duration::from_secs(30));
  tick
    .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  loop {
    tick.tick().await;
    if let Ok(snap) = snapshot::load(&state.db).await
      && let Ok(want) = expectation(&snap, host).await
    {
      let result = check(host, want).await;
      update(host, Some(started), &result);
      if result.effective {
        break;
      }
    }
    if started.elapsed() >= WATCH_LIMIT {
      // 十分钟后降低频率，仍自动检查已记入「需要注意」的域名。
      tokio::time::sleep(Duration::from_secs(270)).await;
    }
  }
}

pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(host): Path<String>,
) -> ApiResult<DnsCheck> {
  auth.require(Perm::Read)?;
  let host = hostname(&host)?;
  let started = watches().get(&host).map(|w| w.started);
  let snap = snapshot::load(&s.db).await?;
  let result = check(&host, expectation(&snap, &host).await?).await;
  update(&host, started, &result);
  Ok(Json(result))
}

pub fn issues() -> Vec<Issue> {
  watches()
    .iter()
    .filter(|(_, watch)| !watch.lagging.is_empty())
    .map(|(host, watch)| Issue {
      alert: None,
      ack: None,
      code: "dns_not_effective".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "route".into(),
        name: host.clone(),
      }),
      title: format!(
        "{host} 的解析 10 分钟还没在 {} 生效",
        watch.lagging.join("、")
      ),
      hint: Some(format!("wharf route dns-check {host}")),
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn resolvers_and_proxied_records() {
    // 一条 A 应答，答案里的 owner 用压缩指针指向问题名。
    let answer = |ip: [u8; 4]| {
      let mut response =
        vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
      response
        .extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
      response.extend_from_slice(&[
        0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
      ]);
      response.extend_from_slice(&ip);
      parse_response(&response, "example.com", 1).unwrap()
    };
    let want = Expected::Address("1.2.3.4".parse().unwrap());
    let aaaa = Answer::default();
    let results =
      [Some(answer([1, 2, 3, 4])), Some(answer([5, 6, 7, 8])), None]
        .map(|a| {
          compare(&want, a.as_ref(), a.as_ref().map(|_| &aaaa), None)
        });
    assert_eq!(
      results,
      [
        DnsVerdict::Matches,
        DnsVerdict::Mismatch,
        DnsVerdict::Unavailable
      ]
    );
    assert!(results.contains(&DnsVerdict::Mismatch));
    let proxied = compare(
      &Expected::Cloudflare,
      Some(&answer([104, 16, 0, 1])),
      Some(&aaaa),
      Some(&["104.16.0.0/13".parse().unwrap()]),
    );
    assert_eq!(proxied, DnsVerdict::Matches);
  }
}
