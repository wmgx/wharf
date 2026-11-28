use clap::{Args, ValueEnum};
use wharf_api_types::{
  resources::{ImagesView, UsageKind, UsageRow},
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
  /// CPU、内存或网络收发合计。
  #[arg(
    long,
    value_enum,
    default_value = "cpu",
    conflicts_with = "images"
  )]
  by: Sort,
  /// 只看指定服务器。
  #[arg(long)]
  server: Option<String>,
  #[arg(long, conflicts_with = "images")]
  service: Option<String>,
  #[arg(long, requires = "service", conflicts_with = "images")]
  containers: bool,
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
  let mut filter = args
    .server
    .as_ref()
    .map_or_else(String::new, |s| format!("server={}", seg(s)));
  if let Some(service) = args.service.as_deref() {
    filter.push('&');
    filter.push_str(&format!(
      "service={}&containers={}",
      seg(service),
      args.containers
    ));
  }
  if args.images {
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
    match args.by {
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
        for component in &row.components {
          let cpu = component
            .cpu_limit_milli
            .map(|milli| format!("{}", f64::from(milli) / 1000.0))
            .unwrap_or_else(|| "-".into());
          let pids = component
            .pids_limit
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
          println!(
            "  {}  CPU 上限 {} 核  内存上限 {}  PID 上限 {}  7 天峰值 CPU {} 内存 {}",
            component.name,
            cpu,
            bytes(component.memory_limit),
            pids,
            pct(component.cpu_peak),
            bytes(component.memory_peak)
          );
        }
      }
    });
  }
  Ok(())
}
