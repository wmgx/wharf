//! 网关请求统计：读本机 Caddy 网关的 `/metrics`（管理口是 `/srv/wharf-gw-*/config/` 下的 unix socket），
//! 按域名汇总 `caddy_http_request_duration_seconds`，和上一次比得到这一段的请求数、5xx 数和延迟分位。
//!
//! 只数 `handler="reverse_proxy"`：同一个请求经过每个中间件都会记一次，只取转发那一层不会重复。
//! 需要 Caddyfile 全局开 `metrics { per_host }`，否则没有 host 标签，这里什么也拿不到。

use std::{
  collections::{BTreeMap, HashMap},
  time::Duration,
};

use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::UnixStream,
};
use wharf_api_types::agent::HostTraffic;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 8 << 20;
const METRIC: &str = "caddy_http_request_duration_seconds";

/// 一个域名的累计值：请求数、5xx 数、各上界（秒）的累计个数。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Totals {
  count: u64,
  errors: u64,
  buckets: BTreeMap<String, (f64, u64)>,
}

/// 本机所有 Caddy 网关的累计值合在一起，按域名。
pub async fn collect() -> HashMap<String, Totals> {
  let mut all = HashMap::new();
  let Ok(dir) = std::fs::read_dir("/srv") else {
    return all;
  };
  for entry in dir.flatten() {
    let name = entry.file_name().to_string_lossy().to_string();
    if !name.starts_with("wharf-gw-") {
      continue;
    }
    let sock = entry.path().join("config/caddy-admin.sock");
    if !sock.exists() {
      continue;
    }
    let Ok(Ok(text)) =
      tokio::time::timeout(TIMEOUT, fetch(&sock)).await
    else {
      continue;
    };
    for (host, t) in parse(&text) {
      let e: &mut Totals = all.entry(host).or_default();
      e.count += t.count;
      e.errors += t.errors;
      for (k, (le, n)) in t.buckets {
        e.buckets.entry(k).or_insert((le, 0)).1 += n;
      }
    }
  }
  all
}

async fn fetch(sock: &std::path::Path) -> std::io::Result<String> {
  let mut s = UnixStream::connect(sock).await?;
  s.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
    .await?;
  let mut body = Vec::new();
  s.take(MAX_BODY as u64).read_to_end(&mut body).await?;
  let text = String::from_utf8_lossy(&body);
  Ok(
    text
      .split_once("\r\n\r\n")
      .map(|(_, b)| b.to_string())
      .unwrap_or_default(),
  )
}

/// 解析 Prometheus 文本里 reverse_proxy 那层的直方图，按 host 汇总。
pub fn parse(text: &str) -> HashMap<String, Totals> {
  let mut out: HashMap<String, Totals> = HashMap::new();
  for line in text.lines() {
    let Some(rest) = line.strip_prefix(METRIC) else {
      continue;
    };
    let (kind, rest) = match rest.split_once('{') {
      Some((k, r)) => (k, r),
      None => continue,
    };
    let Some((labels, value)) = rest.rsplit_once('}') else {
      continue;
    };
    let Ok(value) = value.trim().parse::<f64>() else {
      continue;
    };
    let labels = parse_labels(labels);
    if labels.get("handler").map(String::as_str)
      != Some("reverse_proxy")
    {
      continue;
    }
    let Some(host) = labels.get("host").filter(|h| !h.is_empty())
    else {
      continue;
    };
    let t = out.entry(host.clone()).or_default();
    let n = value as u64;
    match kind {
      "_count" => {
        t.count += n;
        if labels.get("code").is_some_and(|c| c.starts_with('5')) {
          t.errors += n;
        }
      }
      "_bucket" => {
        let Some(le) = labels.get("le") else { continue };
        let bound = if le == "+Inf" {
          f64::INFINITY
        } else {
          le.parse().unwrap_or(f64::INFINITY)
        };
        t.buckets.entry(le.clone()).or_insert((bound, 0)).1 += n;
      }
      _ => {}
    }
  }
  out
}

fn parse_labels(s: &str) -> HashMap<String, String> {
  let mut out = HashMap::new();
  let mut rest = s;
  while let Some((key, after)) = rest.split_once("=\"") {
    let Some(end) = after.find('"') else { break };
    out.insert(
      key.trim_start_matches(',').trim().to_string(),
      after[..end].to_string(),
    );
    rest = &after[end + 1..];
  }
  out
}

/// 和上一次的累计值相减。计数变小（网关重启）的域名这一轮不算。
pub fn diff(
  now: &HashMap<String, Totals>,
  prev: &HashMap<String, Totals>,
  secs: f64,
) -> BTreeMap<String, HostTraffic> {
  let mut out = BTreeMap::new();
  for (host, cur) in now {
    let Some(old) = prev.get(host) else { continue };
    if cur.count < old.count || cur.errors < old.errors {
      continue;
    }
    let reqs = cur.count - old.count;
    let mut buckets: Vec<(f64, u64)> = cur
      .buckets
      .iter()
      .map(|(k, (le, n))| {
        let o = old.buckets.get(k).map_or(0, |b| b.1);
        (*le, n.saturating_sub(o))
      })
      .collect();
    buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
    out.insert(
      host.clone(),
      HostTraffic {
        reqs,
        errors: cur.errors - old.errors,
        secs: secs as f32,
        p50_ms: quantile(&buckets, reqs, 0.5) * 1000.0,
        p95_ms: quantile(&buckets, reqs, 0.95) * 1000.0,
      },
    );
  }
  out
}

/// 累计直方图里取分位，桶内线性插值；落在 +Inf 桶时取上一个上界。
fn quantile(buckets: &[(f64, u64)], total: u64, q: f64) -> f32 {
  if total == 0 {
    return 0.0;
  }
  let rank = q * total as f64;
  let (mut lo, mut below) = (0.0, 0u64);
  for &(le, cum) in buckets {
    if cum as f64 >= rank {
      if le.is_infinite() {
        return lo as f32;
      }
      let inside = (cum - below).max(1) as f64;
      return (lo + (le - lo) * (rank - below as f64) / inside)
        as f32;
    }
    lo = le;
    below = cum;
  }
  lo as f32
}

#[cfg(test)]
mod tests {
  use super::*;

  const BEFORE: &str = r#"
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="0.1"} 10
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="1"} 10
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="+Inf"} 10
caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0"} 10
caddy_http_request_duration_seconds_count{code="200",handler="basic_auth",host="a.example.com",method="GET",server="srv0"} 99
"#;
  const AFTER: &str = r#"
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="0.1"} 90
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="1"} 100
caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="+Inf"} 100
caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0"} 100
caddy_http_request_duration_seconds_bucket{code="502",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="0.1"} 0
caddy_http_request_duration_seconds_bucket{code="502",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="1"} 10
caddy_http_request_duration_seconds_bucket{code="502",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0",le="+Inf"} 10
caddy_http_request_duration_seconds_count{code="502",handler="reverse_proxy",host="a.example.com",method="GET",server="srv0"} 10
"#;

  #[test]
  fn diff_counts_reverse_proxy_only() {
    let d = diff(&parse(AFTER), &parse(BEFORE), 60.0);
    let a = &d["a.example.com"];
    // 新增 100 个：80 个在 0.1 秒内，20 个在 0.1 到 1 秒；其中 10 个 502。
    assert_eq!((a.reqs, a.errors), (100, 10));
    assert!((a.p50_ms - 62.5).abs() < 0.1);
    assert!(a.p95_ms > 100.0 && a.p95_ms < 1000.0);
    // 计数变小（网关重启）不算。
    assert!(diff(&parse(BEFORE), &parse(AFTER), 60.0).is_empty());
  }
}
