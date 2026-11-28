use std::time::Duration;

use clap::Subcommand;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::CleanupKind,
  view::{
    DataCleanupExecRequest, DataCleanupPolicy, DataCleanupResult,
    DataCleanupView,
  },
};

use crate::{
  client::{CliError, CliResult, Client},
  commands::out,
  print,
};

const ROOT: &str = "/api/data/cleanup";
const POLICY: &str = "/api/data/cleanup/policy";

#[derive(clap::Args)]
pub struct CleanupArgs {
  #[command(subcommand)]
  sub: Option<CleanupSubCmd>,
  /// 只看或清理这台服务器。
  #[arg(long)]
  server: Option<String>,
  /// 只看或清理这个服务。
  #[arg(long)]
  service: Option<String>,
  /// 按类型筛选，例如 restore_backup 或 orphan_volume。
  #[arg(long, value_parser = parse_kind)]
  kind: Option<CleanupKind>,
  /// 只看或清理已到期的留底。
  #[arg(long)]
  expired: bool,
  /// 删除清单项 ID，可重复。
  #[arg(long = "id", value_name = "ID", conflicts_with = "expired")]
  ids: Vec<String>,
  /// 清理筛选范围内未阻塞的项，默认跳过无标签卷。
  #[arg(long, conflicts_with_all = ["expired", "ids"])]
  all: bool,
  /// 将无标签的悬空卷纳入批量清理，需要全权管理员权限。
  #[arg(long, requires = "all")]
  include_unlabeled: bool,
  /// 申请删除确认，提供正确确认串后删除。
  #[arg(long)]
  apply: bool,
  /// 首次加 --apply 时返回的确认串。
  #[arg(long, requires = "apply")]
  confirm: Option<String>,
}

#[derive(Subcommand)]
enum CleanupSubCmd {
  /// 查看或修改到期清理策略，无参数只读查看。
  Policy {
    /// 开启自动清理到期的迁移、恢复留底目录。
    #[arg(long, conflicts_with = "off")]
    on: bool,
    /// 关闭自动清理。
    #[arg(long, conflicts_with = "on")]
    off: bool,
    /// 默认保留天数。
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=365))]
    keep_days: Option<u32>,
  },
}

fn parse_kind(raw: &str) -> Result<CleanupKind, String> {
  serde_json::from_value(json!(raw)).map_err(|e| e.to_string())
}

pub async fn run(
  c: &Client,
  args: CleanupArgs,
  j: bool,
) -> CliResult<()> {
  if let Some(CleanupSubCmd::Policy { on, off, keep_days }) = args.sub
  {
    let policy: DataCleanupPolicy = if on
      || off
      || keep_days.is_some()
    {
      c.put(POLICY, &json!({ "auto_expire": (on || off).then_some(on), "keep_days": keep_days })).await?
    } else {
      c.get(POLICY).await?
    };
    out(j, &policy, |p| {
      println!(
        "自动清理{}，默认保留 {} 天",
        if p.auto_expire {
          "已开启"
        } else {
          "已关闭"
        },
        p.keep_days
      );
    });
    return Ok(());
  }
  if args.apply {
    let result: DataCleanupResult = c
      .post_timeout(
        ROOT,
        &DataCleanupExecRequest {
          ids: args.ids,
          expired_only: args.expired,
          all: args.all,
          server: args.server,
          service: args.service,
          kind: args.kind,
          include_unlabeled: args.include_unlabeled,
          confirm: args.confirm,
        },
        Duration::from_secs(3600),
      )
      .await?;
    return print_result(&result, j);
  }
  if !args.ids.is_empty() || args.all || args.include_unlabeled {
    return Err(
      ApiError::invalid("指定删除目标需要同时加 --apply")
        .with_hint(
          "先不带 --id 或 --all 运行 wharf data cleanup 查看清单",
        )
        .into(),
    );
  }
  let kind = args
    .kind
    .map(|kind| json!(kind).as_str().unwrap_or_default().to_owned());
  let query = [
    ("server", args.server.as_deref()),
    ("service", args.service.as_deref()),
    ("kind", kind.as_deref()),
    ("expired_only", args.expired.then_some("true")),
  ]
  .into_iter()
  .filter_map(|(key, value)| {
    Some(format!("{key}={}", crate::client::seg(value?)))
  })
  .collect::<Vec<_>>()
  .join("&");
  let view: DataCleanupView =
    c.get(&format!("{ROOT}?{query}")).await?;
  out(j, &view, print_view);
  Ok(())
}

fn print_view(view: &DataCleanupView) {
  println!(
    "{:<17}  {:<12}  {:<10}  {:<12}  {:<28}  {:>12}  {:<16}  到期/状态",
    "ID", "来源", "服务器", "服务", "目标", "大小", "产生时间"
  );
  for i in &view.items {
    let status = i
      .blocked_reason
      .clone()
      .or_else(|| i.server_status.clone())
      .unwrap_or_else(|| {
        if i.expired {
          "已到期".into()
        } else if let Some(at) = i.expires_at {
          format!(
            "剩余 {} 天",
            (at - chrono::Utc::now()).num_days().max(0)
          )
        } else if i.unlabeled {
          "无标签，批量默认跳过".into()
        } else {
          "-".into()
        }
      });
    println!(
      "{:<17}  {:<12}  {:<10}  {:<12}  {:<28}  {:>12}  {:<16}  {}",
      i.id,
      i.source,
      i.server,
      i.service.as_deref().unwrap_or("-"),
      i.display,
      i.size_bytes
        .map(|n| format!(
          "{}{n} B",
          if i.size_estimated { "约 " } else { "" }
        ))
        .unwrap_or_else(|| "-".into()),
      i.created_at
        .map(|at| at.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".into()),
      status
    );
  }
  println!(
    "共 {} 项，{} 字节，{} 项到期，{} 项阻塞",
    view.total_items,
    view.total_bytes,
    view.expired_items,
    view.blocked_items
  );
  for warning in &view.warnings {
    println!("{warning}");
  }
  if let Some(bytes) = view.prune_reclaimable_bytes.filter(|n| *n > 0)
  {
    println!(
      "另有约 {bytes} 字节镜像和构建缓存可通过 wharf server prune 清理"
    );
  }
  if let Some(hint) = &view.hint {
    println!("{hint}");
  }
}

fn print_result(
  result: &DataCleanupResult,
  j: bool,
) -> CliResult<()> {
  let failed = result.failed != 0;
  if j && failed {
    let mut value = json!(result);
    value["error"] = json!(ApiError::new(
      ErrorCode::AgentFailed,
      "部分清理项执行失败"
    ));
    print::json(&value);
  } else {
    out(j, result, |r| {
      for item in &r.results {
        let status = match item.status.as_str() {
          "deleted" => "已删除",
          "blocked" => "已阻塞",
          "skipped" => "已跳过",
          _ => "失败",
        };
        println!(
          "{} {} {} {} {}",
          item.id,
          item.server,
          item.display,
          status,
          item.reason.as_deref().unwrap_or_default()
        );
      }
      println!(
        "删除 {} 项，阻塞 {} 项，跳过 {} 项，失败 {} 项，释放 {} 字节",
        r.deleted, r.blocked, r.skipped, r.failed, r.freed_bytes
      );
      for warning in &r.warnings {
        println!("{warning}");
      }
    });
  }
  if failed {
    Err(CliError::Exit(1))
  } else {
    Ok(())
  }
}

#[test]
fn cli_data_cleanup_readonly_single_json_and_describe_schema() {
  use clap::Parser;
  for (words, cleanup) in [
    (vec!["wharf", "data"], false),
    (vec!["wharf", "data", "cleanup"], true),
  ] {
    assert!(
      match crate::Cli::try_parse_from(words).unwrap().command {
        crate::Command::Data { cmd: None } => !cleanup,
        crate::Command::Data {
          cmd: Some(crate::DataCmd::Cleanup(args)),
        } => cleanup && !args.apply,
        _ => false,
      }
    );
  }
  let meta = crate::describe::commands(&["data".into()]);
  let commands = meta["commands"].as_array().unwrap();
  assert!(
    commands
      .iter()
      .any(|v| v["command"] == "wharf data" && v["effect"] == "read")
  );
  assert!(commands.iter().any(|v| v["returns"] == "data_cleanup"
    && v["apply_perms"] == json!(["apply", "confirm"])));
  assert_eq!(ErrorCode::ConfirmRequired.exit_code(), 2);
}
