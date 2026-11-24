//! `wharf report`：展示控制面计算的周期指标报告与同比摘要。

use clap::Args;
use wharf_api_types::report::{MetricDelta, ReportView};

use crate::{
  client::{CliResult, Client, seg},
  commands::{fmt_ms, out},
};

fn parse_days(s: &str) -> Result<u32, String> {
  match s.trim() {
    "1" => Ok(1),
    "7" => Ok(7),
    _ => Err("只支持 1 或 7".into()),
  }
}

#[derive(Args)]
pub struct ReportArgs {
  /// 统计天数（1 或 7，默认 7）。
  #[arg(long, default_value = "7", value_parser = parse_days)]
  days: u32,
  /// 只看这台服务器及其上的服务。
  #[arg(long)]
  server: Option<String>,
  /// 只看这个服务。
  #[arg(long)]
  service: Option<String>,
}

fn fmt_bytes(bytes: f64) -> String {
  let sign = if bytes < 0.0 { "-" } else { "" };
  let mut v = bytes.abs();
  let units = [" B", " KB", " MB", " GB", " TB"];
  let mut i = 0;
  while v >= 1024.0 && i + 1 < units.len() {
    v /= 1024.0;
    i += 1;
  }
  if i == 0 {
    format!("{sign}{v:.0}{}", units[i])
  } else {
    format!("{sign}{v:.1}{}", units[i])
  }
}

fn fmt_signed_bytes(bytes: f64) -> String {
  if bytes > 0.0 {
    format!("+{}", fmt_bytes(bytes))
  } else {
    fmt_bytes(bytes)
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

fn fmt_pct(v: f64) -> String {
  format!("{v:.1}%")
}

fn fmt_ms_val(v: f64) -> String {
  format!("{v:.0}ms")
}

fn fmt_delta(d: &MetricDelta, fmt: impl Fn(f64) -> String) -> String {
  let Some(curr) = d.current else {
    return "-".into();
  };
  let change = match (d.previous, d.change_pct) {
    (None, _) => "无对比".into(),
    (Some(_), Some(pct)) => format!("{pct:+.1}%"),
    (Some(_), None) => "上期为 0".into(),
  };
  format!("{} ({change})", fmt(curr))
}

fn print_report(v: &ReportView) {
  let cov = &v.coverage;
  println!(
    "周期报告：最近 {} 天（{} ～ {}）",
    v.days,
    fmt_ms(cov.period_start),
    fmt_ms(cov.period_end)
  );
  if !cov.has_previous {
    match (cov.earliest_at, cov.latest_at) {
      (Some(a), Some(b)) => {
        println!(
          "数据范围：{} ～ {}（上期数据不足，同比标为无对比）",
          fmt_ms(a),
          fmt_ms(b)
        );
      }
      _ => println!("数据范围：暂无采样数据"),
    }
  }
  println!("\n摘要：");
  for line in &v.summary {
    println!("  - {line}");
  }

  if !v.servers.is_empty() {
    println!("\n服务器：");
    for s in &v.servers {
      println!(
        "  {}\n    CPU 均值 {}  峰值 {}\n    内存 均值 {}  峰值 {}\n    磁盘变化 {}  网络 收 {}  发 {}",
        s.name,
        fmt_delta(&s.cpu_avg, fmt_pct),
        fmt_delta(&s.cpu_peak, fmt_pct),
        fmt_delta(&s.mem_avg, fmt_bytes),
        fmt_delta(&s.mem_peak, fmt_bytes),
        fmt_delta(&s.disk_change, fmt_signed_bytes),
        fmt_delta(&s.net_rx_bytes, fmt_bytes),
        fmt_delta(&s.net_tx_bytes, fmt_bytes),
      );
    }
  }

  if !v.services.is_empty() {
    println!("\n服务：");
    for svc in &v.services {
      println!(
        "  {}（{}）\n    CPU 均值 {}  内存 均值 {}  峰值 {}\n    请求 {}  5xx {}  p95 {}",
        svc.name,
        svc.server,
        fmt_delta(&svc.cpu_avg, fmt_pct),
        fmt_delta(&svc.mem_avg, fmt_bytes),
        fmt_delta(&svc.mem_peak, fmt_bytes),
        fmt_delta(&svc.requests, fmt_count),
        fmt_delta(&svc.err_pct, fmt_pct),
        fmt_delta(&svc.p95_ms, fmt_ms_val),
      );
    }
  }

  println!("\n告警触发次数：");
  if v.alerts.is_empty() {
    println!("  （本期和上期均无触发记录）");
  } else {
    for a in &v.alerts {
      let cmp = match (a.previous, a.change_pct) {
        (None, _) => "无对比".into(),
        (Some(0), None) if a.current > 0 => "新增（上期 0）".into(),
        (Some(prev), Some(pct)) => {
          format!("上期 {prev}，{pct:+.1}%")
        }
        (Some(prev), None) => format!("上期 {prev}"),
      };
      println!(
        "  {:<22} {:<16} 本期 {:<4} ({cmp})",
        a.rule, a.name, a.current
      );
    }
  }
}

pub async fn run(
  c: &Client,
  args: ReportArgs,
  json: bool,
) -> CliResult<()> {
  let mut path = format!("/api/report?days={}", args.days);
  if let Some(s) = &args.server {
    path.push_str(&format!("&server={}", seg(s)));
  }
  if let Some(s) = &args.service {
    path.push_str(&format!("&service={}", seg(s)));
  }
  let view: ReportView = c.get(&path).await?;
  out(json, &view, print_report);
  Ok(())
}
