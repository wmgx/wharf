use chrono::SecondsFormat;
use clap::Args;
use wharf_api_types::access_logs::AccessLogsResult;

use crate::{
  LogArgs,
  client::{CliResult, Client, seg},
  commands::{follow_logs, out, show_logs},
};

#[derive(Args)]
struct Filters {
  /// 状态码，例如 502、5xx、400-499 或 401,403,5xx。
  #[arg(long)]
  status: Option<String>,
  /// 路径前缀，例如 /api/。
  #[arg(long)]
  path: Option<String>,
  /// HTTP 方法，例如 GET 或 POST。
  #[arg(long)]
  method: Option<String>,
}

#[derive(Args)]
pub struct GatewayArgs {
  name: String,
  #[command(flatten)]
  logs: LogArgs,
  /// 持续跟随容器日志。
  #[arg(long, short, conflicts_with_all = ["access", "since", "grep", "errors", "max_line", "until", "exclude", "regex", "after_context", "before_context", "context", "where_exprs", "cols"])]
  follow: bool,
  /// 查看访问日志。例：wharf gateway logs edge --access --host blog.example.com --status 5xx。
  #[arg(long, conflicts_with_all = ["grep", "errors", "max_line", "until", "exclude", "regex", "after_context", "before_context", "context", "where_exprs", "cols"])]
  access: bool,
  /// 仅查看此域名，需要 --access。
  #[arg(long)]
  host: Option<String>,
  #[command(flatten)]
  filters: Filters,
}

#[derive(Args)]
pub struct RouteArgs {
  hostname: String,
  /// 最多输出多少条，上限 1000。
  #[arg(long, default_value_t = 200)]
  tail: u32,
  /// 只看这段时间内的：30m、2h、3d，或 RFC 3339 时间。
  #[arg(long)]
  since: Option<String>,
  #[command(flatten)]
  filters: Filters,
}

pub async fn gateway(
  c: &Client,
  args: GatewayArgs,
  json: bool,
) -> CliResult<()> {
  let base = format!("/api/gateways/{}", seg(&args.name));
  if args.follow {
    if json {
      return Err(
        wharf_api_types::ApiError::invalid(
          "--json 需要一次性输出，跟随日志请去掉 --json 或 --follow",
        )
        .into(),
      );
    }
    follow_logs(
      c,
      &format!("{base}/logs/stream?tail={}", args.logs.tail),
    )
    .await
  } else if args.access {
    show(
      c,
      &base,
      args.logs.tail,
      args.logs.since.as_deref(),
      args.host.as_deref(),
      &args.filters,
      json,
    )
    .await
  } else {
    show_logs(c, &format!("{base}/logs"), &args.logs, json).await
  }
}

pub async fn route(
  c: &Client,
  args: RouteArgs,
  json: bool,
) -> CliResult<()> {
  let base = format!("/api/routes/{}", seg(&args.hostname));
  show(
    c,
    &base,
    args.tail,
    args.since.as_deref(),
    None,
    &args.filters,
    json,
  )
  .await
}

async fn show(
  c: &Client,
  base: &str,
  tail: u32,
  since: Option<&str>,
  host: Option<&str>,
  filters: &Filters,
  json: bool,
) -> CliResult<()> {
  let mut path = format!("{base}/access-logs?tail={tail}");
  for (key, value) in [
    ("host", host),
    ("status", filters.status.as_deref()),
    ("path", filters.path.as_deref()),
    ("method", filters.method.as_deref()),
    ("since", since),
  ] {
    if let Some(value) = value {
      path.push_str(&format!("&{key}={}", seg(value)));
    }
  }
  let result: AccessLogsResult = c.get(&path).await?;
  out(json, &result, |result| {
    for warning in &result.warnings {
      eprintln!("{warning}");
    }
    for entry in &result.entries {
      let query_prefix =
        if entry.query.is_empty() { "" } else { "?" };
      println!(
        "{}  {}  {:.0}ms  {}  {}{}{}{}  {}  {}B",
        entry.ts.to_rfc3339_opts(SecondsFormat::Millis, true),
        entry.status,
        entry.duration_ms,
        entry.method,
        entry.host,
        entry.path,
        query_prefix,
        entry.query,
        entry.client_ip,
        entry.size
      );
    }
    println!(
      "命中 {} 条（扫了 {} 行、{} 个文件）",
      result.matched, result.scanned_lines, result.scanned_files
    );
    if result.truncated {
      println!("扫描到上限，缩小 --since 再查");
    }
  });
  Ok(())
}
