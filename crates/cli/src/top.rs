use clap::{Args, ValueEnum};
use wharf_api_types::{
  resources::{ImagesView, LimitSuggestion, UsageKind, UsageRow},
  view::ServerView,
};

use crate::{
  client::{CliResult, Client, seg},
  commands::{out, pretty},
  files::format_size,
};

#[derive(Args)]
#[command(
  long_about = "按最近一次资源采样排列各服务器的服务、网关和 agent，或用 --images 现查镜像体积。\nserver usage 看单台机器最近 10 分钟的平均用量，server disk 看服务的目录、日志和卷，server host 看宿主机概况。"
)]
pub struct TopArgs {
  /// CPU、内存或网络收发合计，默认按 CPU 排。
  #[arg(long, value_enum, conflicts_with_all = ["images", "suggest_limits"])]
  by: Option<Sort>,
  /// 根据历史样本估算服务资源上限。
  #[arg(long, conflicts_with = "images")]
  suggest_limits: bool,
  #[arg(long, requires = "suggest_limits")]
  service: Option<String>,
  /// 历史窗口，1 到 14 天，默认 14。
  #[arg(long, requires = "suggest_limits")]
  days: Option<i64>,
  /// 只看指定服务器。
  #[arg(long)]
  server: Option<String>,
  /// 现查镜像大小和占用它的容器，按体积排序。
  #[arg(long)]
  images: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Sort {
  Cpu,
  Mem,
  Net,
}

pub fn parse_agent_memory(value: &str) -> Result<String, String> {
  wharf_api_types::resources::parse_agent_memory(value)
    .map_err(|e| e.message)?;
  Ok(value.trim().to_ascii_lowercase())
}

fn size(bytes: u64) -> String {
  format_size(bytes, &[" B", " KB", " MB", " GB", " TB"])
}

fn bytes(v: Option<u64>) -> String {
  v.map(size).unwrap_or_else(|| "-".into())
}

fn rate(v: Option<u64>) -> String {
  v.map(|n| format!("{}/s", size(n)))
    .unwrap_or_else(|| "-".into())
}

fn pct(v: Option<f64>) -> String {
  v.map(|v| format!("{v:.1}%")).unwrap_or_else(|| "-".into())
}

pub fn show_server(view: &ServerView) {
  pretty(view);
  crate::external::server(view);
  let agent = &view.agent;
  let limit = |v| if v == 0 { "不限".into() } else { size(v) };
  println!(
    "\nagent\nCPU {}  内存 {}  上限 {}  已用 {}",
    pct(agent.cpu.map(f64::from)),
    bytes(agent.mem),
    agent.memory_limit.map(limit).unwrap_or_else(|| "-".into()),
    pct(agent.memory_pct)
  );
  println!("设置上限 {}", limit(agent.configured_limit));
  if let Some(error) = &agent.limit_error {
    println!("设置上限失败：{error}");
  }
}

pub async fn run(
  c: &Client,
  args: TopArgs,
  json: bool,
) -> CliResult<()> {
  let filter = args
    .server
    .as_ref()
    .map_or_else(String::new, |s| format!("server={}", seg(s)));
  if args.suggest_limits {
    let service = args
      .service
      .as_deref()
      .map_or_else(String::new, |s| format!("&service={}", seg(s)));
    let days = args.days.unwrap_or(14);
    let rows: Vec<LimitSuggestion> = c
      .get(&format!(
        "/api/metrics/limits-suggest?{filter}{service}&days={days}"
      ))
      .await?;
    out(json, &rows, |rows| {
      for row in rows {
        println!(
          "{}	{}	{}	{} 小时	OOM 采样点 {}",
          row.name,
          row.server,
          row.memory_class,
          row.memory.hours,
          row.oom_points
        );
        for reason in [&row.skip, &row.memory_reason, &row.cpu_reason]
          .into_iter()
          .flatten()
        {
          println!("  {reason}");
        }
        if row.memory_mb.is_some() || row.cpu_milli.is_some() {
          let memory = row
            .memory_mb
            .map_or_else(String::new, |mb| format!(" --memory {mb}"));
          let cpu = row.cpu_milli.map_or_else(String::new, |m| {
            format!(" --cpus {}", f64::from(m) / 1000.0)
          });
          println!(
            "  wharf service limits {}{memory}{cpu}",
            row.name
          );
        }
      }
    });
  } else if args.images {
    let view: ImagesView =
      c.get(&format!("/api/metrics/images?{filter}")).await?;
    out(json, &view, |v| {
      println!("镜像\t机器\t体积\t在用容器");
      for r in &v.rows {
        let used = if r.image.used_by.is_empty() {
          "未用".into()
        } else {
          r.image.used_by.join("、")
        };
        println!(
          "{}\t{}\t{}\t{used}",
          r.image.image,
          r.server,
          size(r.image.size)
        );
      }
      for (server, reason) in &v.errors {
        println!("没查到：{server}（{reason}）");
      }
      if !v.unused.is_empty() {
        let totals = v
          .unused
          .iter()
          .map(|(server, n)| {
            format!(
              "{server} {}（wharf server prune {server}）",
              size(*n)
            )
          })
          .collect::<Vec<_>>();
        println!("没在用的镜像合计：{}", totals.join("、"));
      }
    });
  } else {
    let mut rows: Vec<UsageRow> =
      c.get(&format!("/api/metrics/top?{filter}")).await?;
    match args.by.unwrap_or(Sort::Cpu) {
      Sort::Cpu => rows.sort_by(|a, b| {
        b.cpu
          .partial_cmp(&a.cpu)
          .unwrap_or(std::cmp::Ordering::Equal)
      }),
      Sort::Mem => rows.sort_by_key(|row| std::cmp::Reverse(row.mem)),
      Sort::Net => rows.sort_by_key(|row| {
        std::cmp::Reverse(
          row
            .net_rx
            .zip(row.net_tx)
            .map(|(rx, tx)| rx.saturating_add(tx)),
        )
      }),
    }
    out(json, &rows, |rows| {
      println!(
        "名称\t种类\t机器\tCPU\t内存\t内存上限\t占上限\t网络收\t网络发"
      );
      for row in rows {
        let kind = match row.kind {
          UsageKind::Service => "服务",
          UsageKind::Gateway => "网关",
          UsageKind::Agent => "agent",
        };
        println!(
          "{}\t{kind}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
          row.name,
          row.server,
          pct(row.cpu),
          bytes(row.mem),
          bytes(row.memory_limit),
          pct(row.memory_pct),
          rate(row.net_rx),
          rate(row.net_tx),
        );
      }
    });
  }
  Ok(())
}
