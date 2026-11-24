use crate::{
  client::{CliResult, Client, seg},
  commands::{fmt_ms, out},
};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  view::{
    AlertAck, AlertAckRequest, AlertLevel, AlertOptions, AlertPatch,
    AlertSuppressRequest, AlertSuppression, AlertsView, FiringView,
  },
};

#[derive(Subcommand)]
pub enum AlertCmd {
  /// 告警里附带服务最近的日志：`wharf alert options --include-logs on`。
  Options {
    #[arg(long, value_parser = ["on", "off"])]
    include_logs: String,
  },
  /// 规则、事件通知、正在触发的告警、最近的推送。
  List,
  /// 正在触发的告警和确认状态。
  Firing,
  /// 确认一条正在触发的告警。
  Ack {
    rule: String,
    subject: String,
    #[arg(long)]
    note: Option<String>,
  },
  /// 取消确认。
  Unack { rule: String, subject: String },
  /// 预览待发的每日汇总。
  Digest {
    #[arg(long, required = true)]
    preview: bool,
  },
  #[command(subcommand)]
  Suppress(SuppressCmd),
  /// 改一条规则或事件通知（id 见 list）。只改给了的选项。
  Set {
    id: String,
    /// 打开
    #[arg(long, conflicts_with = "off")]
    on: bool,
    /// 关闭
    #[arg(long)]
    off: bool,
    #[arg(long)]
    threshold: Option<f64>,
    /// 连续多少次（窗口规则是窗口里多少次）才触发。
    #[arg(long = "for")]
    for_n: Option<u32>,
    /// 静默多少分钟，0 取消。
    #[arg(long)]
    mute: Option<u32>,
    #[arg(long, value_enum)]
    level: Option<Level>,
    /// 恢复默认值。
    #[arg(long)]
    reset: bool,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
}

#[derive(Clone, ValueEnum)]
pub enum Level {
  Urgent,
  Digest,
}

#[derive(Subcommand)]
pub enum SuppressCmd {
  List,
  Add {
    source: String,
    #[arg(long)]
    ignore: String,
  },
  Rm {
    id: i64,
  },
}

/// `alert set --dry-run`：规则或事件通知改前改后。恢复默认值要控制面算，只标出来。
fn preview(
  now: &AlertsView,
  id: &str,
  patch: &AlertPatch,
  j: bool,
) -> CliResult<()> {
  let before = if let Some(r) = now.rules.iter().find(|r| r.id == id)
  {
    json!({
      "enabled": r.enabled,
      "level": r.level,
      "threshold": r.threshold,
      "for": r.for_n,
      "muted_until": r.muted_until.map(fmt_ms),
    })
  } else if let Some(n) = now.notices.iter().find(|n| n.id == id) {
    json!({ "enabled": n.enabled, "level": n.level, "muted_until": n.muted_until.map(fmt_ms) })
  } else if let Some(enabled) = now.suppressions.get(id) {
    json!({ "enabled": enabled })
  } else {
    return Err(
      ApiError::not_found(format!("没有告警规则或事件通知 {id}"))
        .suggest("wharf alert list")
        .into(),
    );
  };
  let mut after = before.clone();
  if patch.reset {
    after["reset"] = json!("恢复默认值");
  }
  if let Some(v) = patch.enabled {
    after["enabled"] = json!(v);
  }
  if let Some(level) = patch.level {
    after["level"] = json!(level);
  }
  if let Some(v) = patch.threshold {
    after["threshold"] = json!(v);
  }
  if let Some(v) = patch.for_n {
    after["for"] = json!(v);
  }
  match patch.mute_minutes {
    Some(0) => after["muted_until"] = Value::Null,
    Some(m) => {
      after["muted_until"] = json!(fmt_ms(
        chrono::Utc::now().timestamp_millis() + i64::from(m) * 60_000
      ))
    }
    None => {}
  }
  crate::preview::show(j, &format!("alert/{id}"), &before, &after)
}

pub async fn run(
  c: &Client,
  cmd: AlertCmd,
  j: bool,
) -> CliResult<()> {
  let v: AlertsView = match cmd {
    AlertCmd::List => c.get("/api/alerts").await?,
    AlertCmd::Firing => {
      let v: AlertsView = c.get("/api/alerts").await?;
      out(j, &v.firing, |items| print_firing(items));
      return Ok(());
    }
    AlertCmd::Ack {
      rule,
      subject,
      note,
    } => {
      return ack(
        c,
        j,
        AlertAckRequest {
          rule,
          subject,
          note,
          acked: true,
        },
      )
      .await;
    }
    AlertCmd::Unack { rule, subject } => {
      return ack(
        c,
        j,
        AlertAckRequest {
          rule,
          subject,
          note: None,
          acked: false,
        },
      )
      .await;
    }
    AlertCmd::Digest { preview: false } => {
      return Err(ApiError::invalid("请加 --preview").into());
    }
    AlertCmd::Digest { preview: true } => {
      let body: Option<String> = c.get("/api/alerts/digest").await?;
      out(j, &body, |body| match body {
        Some(body) => print!("每日汇总\n{body}"),
        None => println!("没有待汇总的通知"),
      });
      return Ok(());
    }
    AlertCmd::Suppress(cmd) => {
      let items: Vec<AlertSuppression> = match cmd {
        SuppressCmd::List => c.get("/api/alerts/suppress").await?,
        SuppressCmd::Add { source, ignore } => {
          c.post(
            "/api/alerts/suppress",
            &AlertSuppressRequest { source, ignore },
          )
          .await?
        }
        SuppressCmd::Rm { id } => {
          c.delete(&format!("/api/alerts/suppress/{id}")).await?
        }
      };
      out(j, &items, |items| {
        for item in items {
          println!(
            "  #{}  {} → {}",
            item.id, item.source, item.ignore
          );
        }
      });
      return Ok(());
    }
    AlertCmd::Options { include_logs } => {
      c.put(
        "/api/alerts/options",
        &AlertOptions {
          include_logs: include_logs == "on",
        },
      )
      .await?
    }
    AlertCmd::Set {
      id,
      on,
      off,
      threshold,
      for_n,
      mute,
      reset,
      level,
      dry_run,
    } => {
      let patch = AlertPatch {
        enabled: (on || off).then_some(on),
        threshold,
        for_n,
        mute_minutes: mute,
        reset,
        level: level.map(|level| match level {
          Level::Urgent => AlertLevel::Urgent,
          Level::Digest => AlertLevel::Digest,
        }),
      };
      if dry_run {
        let now: AlertsView = c.get("/api/alerts").await?;
        return preview(&now, &id, &patch, j);
      }
      c.put(&format!("/api/alerts/{}", seg(&id)), &patch).await?
    }
  };
  out(j, &v, |v| {
    let state = |on: bool, muted: Option<i64>| match (on, muted) {
      (false, _) => "关".to_string(),
      (true, Some(t)) => format!("静默到 {}", fmt_ms(t)),
      (true, None) => "开".to_string(),
    };
    println!("告警规则：");
    for r in &v.rules {
      println!(
        "  {:<22} {:<8} {:<6} {}  {}",
        r.id,
        state(r.enabled, r.muted_until),
        r.level.as_str(),
        r.name,
        r.condition
      );
    }
    println!("事件通知：");
    for n in &v.notices {
      println!(
        "  {:<22} {:<8} {:<6} {}",
        n.id,
        state(n.enabled, n.muted_until),
        n.level.as_str(),
        n.name
      );
    }
    println!("内置抑制：");
    for (id, enabled) in &v.suppressions {
      println!("  {id:<22} {}", state(*enabled, None));
    }
    if !v.firing.is_empty() {
      println!("正在触发：");
      print_firing(&v.firing);
    }
    println!(
      "告警附带日志：{}",
      if v.include_logs { "开" } else { "关" }
    );
  });
  Ok(())
}

fn print_firing(items: &[FiringView]) {
  for f in items {
    println!(
      "  {} / {}  {}（{} 起）",
      f.rule,
      f.subject,
      f.title,
      fmt_ms(f.since)
    );
    if let Some(a) = &f.ack {
      println!(
        "    已确认 · {} · {}{}",
        a.by,
        fmt_ms(a.at),
        a.note
          .as_ref()
          .map_or_else(String::new, |n| format!(" · {n}"))
      );
    }
  }
}

async fn ack(
  c: &Client,
  j: bool,
  req: AlertAckRequest,
) -> CliResult<()> {
  let ack: Option<AlertAck> = c.put("/api/alerts/ack", &req).await?;
  out(j, &ack, |_| {
    println!(
      "{}",
      if req.acked {
        "已确认"
      } else {
        "已取消确认"
      }
    )
  });
  Ok(())
}
