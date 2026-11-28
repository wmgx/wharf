//! 报告文字摘要生成：纯函数模板拼接，不调用任何 AI 接口。

use wharf_api_types::report::{
  AlertReport, MetricDelta, ServerReport, ServiceReport,
};

const MAX_SUMMARY_ITEMS: usize = 5;
const SUMMARY_CHANGE_PCT: f64 = 30.0;
const PEAK_LIMIT_PCT: f64 = 85.0;

fn fmt_bytes(bytes: f64) -> String {
  let sign = if bytes < 0.0 { "-" } else { "" };
  let mut v = bytes.abs();
  let units = ["B", "KB", "MB", "GB", "TB"];
  let mut i = 0;
  while v >= 1024.0 && i + 1 < units.len() {
    v /= 1024.0;
    i += 1;
  }
  if i == 0 {
    format!("{sign}{v:.0} {}", units[i])
  } else {
    format!("{sign}{v:.1} {}", units[i])
  }
}

fn fmt_count(n: f64) -> String {
  if n >= 1_000_000.0 {
    format!("{:.2}M", n / 1_000_000.0)
  } else if n >= 1_000.0 {
    format!("{:.1}k", n / 1_000.0)
  } else {
    format!("{n:.0}")
  }
}

fn push_change(
  out: &mut Vec<(f64, String)>,
  label: &str,
  delta: &MetricDelta,
  fmt: impl Fn(f64) -> String,
) {
  let (Some(curr), Some(prev), Some(pct)) =
    (delta.current, delta.previous, delta.change_pct)
  else {
    return;
  };
  if pct.abs() < SUMMARY_CHANGE_PCT || (curr - prev).abs() < 1e-6 {
    return;
  }
  let dir = if pct > 0.0 { "上升" } else { "下降" };
  out.push((
    pct.abs(),
    format!(
      "{label}较上期{dir} {:.1}%（{} → {}）",
      pct.abs(),
      fmt(prev),
      fmt(curr)
    ),
  ));
}

#[derive(Default)]
pub(super) struct RawPeaks {
  pub servers: Vec<(Option<f64>, Option<f64>)>,
  pub services: Vec<Option<f64>>,
}

/// 从统计结果里挑出最值得关注的 1～5 条摘要，没有明显变化则返回固定文案。
pub(super) fn build_summary(
  servers: &[ServerReport],
  services: &[ServiceReport],
  alerts: &[AlertReport],
  raw: &RawPeaks,
) -> Vec<String> {
  let mut items: Vec<(f64, String)> = Vec::new();
  let pct_fmt = |v: f64| format!("{v:.1}%");
  let ms_fmt = |v: f64| format!("{v:.0}ms");

  for (s, &(cpu_peak, mem_peak)) in servers.iter().zip(&raw.servers) {
    if let Some(peak) = cpu_peak
      && peak >= PEAK_LIMIT_PCT
    {
      items.push((
        200.0 + peak,
        format!(
          "服务器 {} CPU 峰值达到 {peak:.1}%，接近上限",
          s.name
        ),
      ));
    }
    if let (Some(peak), Some(total)) = (mem_peak, s.mem_total)
      && total > 0.0
    {
      let pct = peak / total * 100.0;
      if pct >= PEAK_LIMIT_PCT {
        items.push((
          200.0 + pct,
          format!(
            "服务器 {} 内存峰值占整机 {pct:.1}%（{}/{}），接近上限",
            s.name,
            fmt_bytes(peak),
            fmt_bytes(total)
          ),
        ));
      }
    }
    if let (Some(used), Some(total)) = (s.disk_used, s.disk_total)
      && total > 0.0
    {
      let pct = used / total * 100.0;
      if pct >= PEAK_LIMIT_PCT {
        items.push((
          200.0 + pct,
          format!(
            "服务器 {} 磁盘已用 {pct:.1}%（{}/{}），接近上限",
            s.name,
            fmt_bytes(used),
            fmt_bytes(total)
          ),
        ));
      }
    }
    push_change(
      &mut items,
      &format!("服务器 {} CPU 均值", s.name),
      &s.cpu_avg,
      pct_fmt,
    );
    push_change(
      &mut items,
      &format!("服务器 {} CPU 峰值", s.name),
      &s.cpu_peak,
      pct_fmt,
    );
    push_change(
      &mut items,
      &format!("服务器 {} 内存均值", s.name),
      &s.mem_avg,
      fmt_bytes,
    );
    push_change(
      &mut items,
      &format!("服务器 {} 内存峰值", s.name),
      &s.mem_peak,
      fmt_bytes,
    );
    push_change(
      &mut items,
      &format!("服务器 {} 网络接收总量", s.name),
      &s.net_rx_bytes,
      fmt_bytes,
    );
    push_change(
      &mut items,
      &format!("服务器 {} 网络发送总量", s.name),
      &s.net_tx_bytes,
      fmt_bytes,
    );
  }

  for (svc, &mem_peak) in services.iter().zip(&raw.services) {
    if let (Some(peak), Some(limit)) = (mem_peak, svc.mem_limit)
      && limit > 0
    {
      let pct = peak / limit as f64 * 100.0;
      if pct >= PEAK_LIMIT_PCT {
        items.push((
          200.0 + pct,
          format!(
            "服务 {} 内存峰值占上限 {pct:.1}%（{}/{}），接近上限",
            svc.name,
            fmt_bytes(peak),
            fmt_bytes(limit as f64)
          ),
        ));
      }
    }
    push_change(
      &mut items,
      &format!("服务 {} CPU 均值", svc.name),
      &svc.cpu_avg,
      pct_fmt,
    );
    push_change(
      &mut items,
      &format!("服务 {} 内存均值", svc.name),
      &svc.mem_avg,
      fmt_bytes,
    );
    push_change(
      &mut items,
      &format!("服务 {} 内存峰值", svc.name),
      &svc.mem_peak,
      fmt_bytes,
    );
    push_change(
      &mut items,
      &format!("服务 {} 请求数", svc.name),
      &svc.requests,
      fmt_count,
    );
    push_change(
      &mut items,
      &format!("服务 {} 5xx 占比", svc.name),
      &svc.err_pct,
      pct_fmt,
    );
    push_change(
      &mut items,
      &format!("服务 {} p95 延迟", svc.name),
      &svc.p95_ms,
      ms_fmt,
    );
  }

  for a in alerts {
    if a.previous == Some(0) && a.current > 0 {
      items.push((
        150.0 + a.current as f64,
        format!(
          "新出现告警 {}（{}），本期触发 {} 次",
          a.name, a.rule, a.current
        ),
      ));
    } else if let (Some(prev), Some(pct)) = (a.previous, a.change_pct)
      && pct.abs() >= SUMMARY_CHANGE_PCT
    {
      let dir = if pct > 0.0 { "上升" } else { "下降" };
      items.push((
        pct.abs(),
        format!(
          "告警 {}（{}）触发次数较上期{dir} {:.1}%（{prev} → {} 次）",
          a.name,
          a.rule,
          pct.abs(),
          a.current
        ),
      ));
    }
  }

  if items.is_empty() {
    return vec!["和上期相比没有明显变化".into()];
  }
  items
    .sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
  items
    .into_iter()
    .take(MAX_SUMMARY_ITEMS)
    .map(|(_, text)| text)
    .collect()
}
