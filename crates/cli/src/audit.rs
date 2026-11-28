//! `wharf audit`：操作和登录记录。

use wharf_api_types::view::AuditEntry;

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

#[derive(clap::Args)]
pub struct AuditArgs {
  /// 只看这个发起人（令牌名，或 页面:<用户名>）。
  #[arg(long)]
  actor: Option<String>,
  /// 只看一类：api 或 login。
  #[arg(long, value_parser = ["api", "login"])]
  kind: Option<String>,
  #[arg(long, default_value_t = 50)]
  limit: u32,
  /// 起始时间，例如 24h 或 2026-11-28。
  #[arg(long)]
  since: Option<String>,
  /// 截止时间，例如 now 或 2026-11-28。
  #[arg(long)]
  until: Option<String>,
  /// 目标，例如 service/blog。
  #[arg(long)]
  target: Option<String>,
  /// 只看失败操作。
  #[arg(long)]
  errors: bool,
  /// 按 HTTP 状态码筛选。
  #[arg(long)]
  status: Option<u16>,
}

pub async fn audit(
  c: &Client,
  args: AuditArgs,
  j: bool,
) -> CliResult<()> {
  let mut path =
    format!("/api/audit?limit={}&errors={}", args.limit, args.errors);
  for (key, value) in [
    ("actor", args.actor),
    ("kind", args.kind),
    ("since", args.since),
    ("until", args.until),
    ("target", args.target),
    ("status", args.status.map(|status| status.to_string())),
  ] {
    if let Some(value) = value {
      path.push_str(&format!("&{key}={}", seg(&value)));
    }
  }
  let rows: Vec<AuditEntry> = c.get(&path).await?;
  out(j, &rows, |rows| {
    for row in rows {
      let at = chrono::DateTime::from_timestamp_millis(row.at)
        .map(|t| {
          t.with_timezone(&chrono::Local)
            .format("%m-%d %H:%M")
            .to_string()
        })
        .unwrap_or_default();
      println!(
        "{at}  {}  {} {}  {}  {}",
        row.actor,
        row.method,
        row.path,
        row.status.map(|s| s.to_string()).unwrap_or_default(),
        row.detail.as_deref().unwrap_or_default(),
      );
    }
  });
  Ok(())
}
