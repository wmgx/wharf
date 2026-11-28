use clap::Subcommand;
use serde_json::json;
use wharf_api_types::{
  ApiError,
  view::{
    AlertAckRequest, AlertAckView, AlertDigestPreview, AlertLevel,
    AlertOptions, AlertPatch, AlertSuppressionRequest,
    AlertSuppressionView, AlertUnackRequest, AlertsView,
    CustomAlertRuleRequest, CustomAlertRuleView,
  },
};

use crate::{
  client::{CliResult, Client, seg},
  commands::{fmt_ms, out},
};

#[derive(Subcommand)]
pub enum AlertCmd {
  /// 告警里附带服务最近的日志：`wharf alert options --include-logs on`。
  Options {
    #[arg(long, value_parser = ["on", "off"])]
    include_logs: String,
  },
  /// 规则、事件通知、内置抑制、正在触发的告警、最近的推送。
  List,
  /// 改一条规则、事件通知或内置抑制（id 见 list）。加 `--service` 只覆盖单个服务。只改给了的选项。
  Set {
    id: String,
    /// 只覆盖指定服务（仅对对象是服务的内置规则有效）。
    #[arg(long)]
    service: Option<String>,
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
    /// 通知级别：urgent（立即推）或 digest（并入每日汇总）。
    #[arg(long, value_parser = ["urgent", "digest"])]
    level: Option<String>,
    /// 静默多少分钟，0 取消。
    #[arg(long)]
    mute: Option<u32>,
    /// 恢复默认值。
    #[arg(long)]
    reset: bool,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
  /// 新增按服务的自定义告警规则（名称全局唯一，最多 50 条）。
  Add {
    /// 规则名称（全局唯一，小写字母、数字、-、_）。
    name: String,
    /// 目标服务名。
    #[arg(long)]
    service: String,
    /// 指标：cpu（%）、mem（MB，与 wharf top 一致）、mem_pct（%）、err（%）、p95（ms）。
    #[arg(long, value_parser = ["cpu", "mem", "mem_pct", "err", "p95"])]
    metric: String,
    /// 比较符：> 或 <。
    #[arg(long, value_parser = [">", "<"])]
    op: String,
    /// 阈值（cpu/mem_pct/err 为 %，mem 为 MB，p95 为 ms）。
    #[arg(long)]
    threshold: f64,
    /// 连续触发次数（按该指标每分钟一次的上报频率计算）。
    #[arg(long = "for")]
    for_n: u32,
    /// 通知级别：urgent（立即推，默认）或 digest（并入每日汇总）。
    #[arg(long, default_value = "urgent", value_parser = ["urgent", "digest"])]
    level: String,
  },
  /// 删除一条自定义告警规则。
  Rm { name: String },
  /// 列出正在触发的告警和确认状态。
  Firing,
  /// 确认一条正在触发的告警（连续 1 小时不触发后自动失效）。
  Ack {
    rule: String,
    subject: String,
    /// 备注，最多 200 字。
    #[arg(long)]
    note: Option<String>,
  },
  /// 取消一条告警的确认状态。
  Unack { rule: String, subject: String },
  /// 预览当前待发送的每日汇总内容（不发送）。
  Digest {
    /// 预览而不发送。
    #[arg(long)]
    preview: bool,
  },
  /// 自定义告警抑制规则。
  #[command(subcommand)]
  Suppress(SuppressCmd),
}

#[derive(Subcommand)]
pub enum SuppressCmd {
  /// 新增自定义抑制：`wharf alert suppress add <A规则>[:<对象>] --ignore <B规则>[:<对象>]`。
  Add {
    /// 触发中的上游告警，例如 `server_offline:s1` 或 `server_offline`。
    source: String,
    /// 要忽略的告警，例如 `domain_down` 或 `monitor_failed:app`。
    #[arg(long)]
    ignore: String,
  },
  /// 列出自定义抑制规则。
  List,
  /// 按序号删除一条自定义抑制规则。
  Rm { id: i64 },
}

fn level_text(level: AlertLevel) -> &'static str {
  match level {
    AlertLevel::Urgent => "urgent",
    AlertLevel::Digest => "digest",
  }
}

fn ack_text(ack: &AlertAckView) -> String {
  match &ack.note {
    Some(n) if !n.is_empty() => {
      format!("已确认 · {} · {} · {n}", ack.by, fmt_ms(ack.at))
    }
    _ => format!("已确认 · {} · {}", ack.by, fmt_ms(ack.at)),
  }
}

fn parse_rule_subject(
  raw: &str,
) -> Result<(String, Option<String>), ApiError> {
  if let Some((rule, subject)) = raw.split_once(':') {
    let rule = rule.trim();
    let subject = subject.trim();
    if rule.is_empty() || subject.is_empty() {
      return Err(ApiError::invalid(format!(
        "格式不对：{raw}，应为 <规则> 或 <规则>:<对象>"
      )));
    }
    Ok((rule.to_string(), Some(subject.to_string())))
  } else {
    let rule = raw.trim();
    if rule.is_empty() {
      return Err(ApiError::invalid("规则名不能为空"));
    }
    Ok((rule.to_string(), None))
  }
}

fn fmt_target(rule: &str, subject: Option<&str>) -> String {
  match subject {
    Some(s) => format!("{rule}:{s}"),
    None => rule.to_string(),
  }
}

fn preview(
  now: &AlertsView,
  id: &str,
  service: Option<&str>,
  patch: &AlertPatch,
  j: bool,
) -> CliResult<()> {
  let inherited_mute = service.and_then(|_| {
    now
      .rules
      .iter()
      .find(|r| r.id == id)
      .and_then(|r| r.muted_until)
  });
  let (label, before) = if let Some(svc) = service {
    let Some(r) = now.rules.iter().find(|r| r.id == id) else {
      return Err(
        ApiError::not_found(format!("没有告警规则 {id}"))
          .suggest("wharf alert list")
          .into(),
      );
    };
    let o = now
      .service_overrides
      .iter()
      .find(|o| o.rule == id && o.service == svc);
    (
      format!("alert/{id}/service/{svc}"),
      json!({
        "enabled": o.and_then(|o| o.enabled).unwrap_or(r.enabled),
        "level": level_text(o.and_then(|o| o.level).unwrap_or(r.level)),
        "threshold": o.and_then(|o| o.threshold).unwrap_or(r.threshold),
        "for": o.and_then(|o| o.for_n).unwrap_or(r.for_n),
        "muted_until": o.and_then(|o| o.muted_until).max(inherited_mute).map(fmt_ms),
      }),
    )
  } else if let Some(r) = now.rules.iter().find(|r| r.id == id) {
    (
      format!("alert/{id}"),
      json!({
        "enabled": r.enabled,
        "level": level_text(r.level),
        "threshold": r.threshold,
        "for": r.for_n,
        "muted_until": r.muted_until.map(fmt_ms),
      }),
    )
  } else if let Some(c) =
    now.custom_rules.iter().find(|c| c.name == id)
  {
    (
      format!("alert/{id}"),
      json!({
        "enabled": c.enabled,
        "level": level_text(c.level),
        "threshold": c.threshold,
        "for": c.for_n,
        "muted_until": c.muted_until.map(fmt_ms),
      }),
    )
  } else if let Some(n) = now.notices.iter().find(|n| n.id == id) {
    (
      format!("alert/{id}"),
      json!({
        "enabled": n.enabled,
        "level": level_text(n.level),
        "muted_until": n.muted_until.map(fmt_ms),
      }),
    )
  } else if let Some(s) =
    now.builtin_suppressions.iter().find(|s| s.id == id)
  {
    (format!("alert/{id}"), json!({ "enabled": s.enabled }))
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
  if let Some(v) = patch.level {
    after["level"] = json!(level_text(v));
  }
  if let Some(v) = patch.threshold {
    after["threshold"] = json!(v);
  }
  if let Some(v) = patch.for_n {
    after["for"] = json!(v);
  }
  if let Some(m) = patch.mute_minutes {
    let proposed = (m > 0).then(|| {
      chrono::Utc::now().timestamp_millis() + i64::from(m) * 60_000
    });
    after["muted_until"] =
      json!(proposed.max(inherited_mute).map(fmt_ms));
  } else if patch.reset {
    after["muted_until"] = json!(inherited_mute.map(fmt_ms));
  }
  crate::preview::show(j, &label, &before, &after)
}

fn print_view(v: &AlertsView) {
  let state = |on: bool, muted: Option<i64>| match (on, muted) {
    (false, _) => "关".to_string(),
    (true, Some(t)) => format!("静默到 {}", fmt_ms(t)),
    (true, None) => "开".to_string(),
  };
  println!("告警规则：");
  for r in &v.rules {
    println!(
      "  {:<22} {:<8} {:<7} {}  {}",
      r.id,
      state(r.enabled, r.muted_until),
      level_text(r.level),
      r.name,
      r.condition
    );
    for o in v.service_overrides.iter().filter(|o| o.rule == r.id) {
      let mut parts = Vec::new();
      if let Some(en) = o.enabled {
        parts.push(if en { "开".into() } else { "关".into() });
      }
      if let Some(lvl) = o.level {
        parts.push(format!("level={}", level_text(lvl)));
      }
      if let Some(t) = o.threshold {
        parts.push(format!("threshold={t}"));
      }
      if let Some(n) = o.for_n {
        parts.push(format!("for={n}"));
      }
      if let Some(m) = o.muted_until {
        parts.push(format!("静默到 {}", fmt_ms(m)));
      }
      println!("    └ 服务 {:<16} {}", o.service, parts.join("  "));
    }
  }
  if !v.custom_rules.is_empty() {
    println!("自定义规则：");
    for c in &v.custom_rules {
      println!(
        "  {:<22} {:<8} {:<7} 服务 {}  {}",
        c.name,
        state(c.enabled, c.muted_until),
        level_text(c.level),
        c.service,
        c.condition
      );
    }
  }
  println!("事件通知：");
  for n in &v.notices {
    println!(
      "  {:<22} {:<8} {:<7} {}",
      n.id,
      state(n.enabled, n.muted_until),
      level_text(n.level),
      n.name
    );
  }
  if !v.builtin_suppressions.is_empty() {
    println!("内置抑制：");
    for s in &v.builtin_suppressions {
      println!(
        "  {:<22} {:<8} {}",
        s.id,
        if s.enabled { "开" } else { "关" },
        s.name
      );
    }
  }
  if !v.suppressions.is_empty() {
    println!("自定义抑制：");
    for s in &v.suppressions {
      println!(
        "  #{:<3} {} -> 忽略 {}",
        s.id,
        fmt_target(&s.source_rule, s.source_subject.as_deref()),
        fmt_target(&s.target_rule, s.target_subject.as_deref()),
      );
    }
  }
  if !v.firing.is_empty() {
    println!("正在触发：");
    for f in &v.firing {
      let ack = f
        .ack
        .as_ref()
        .map(|a| format!("  [{}]", ack_text(a)))
        .unwrap_or_default();
      println!(
        "  {}/{}  {}（{} 起）{ack}",
        f.rule,
        f.subject,
        f.title,
        fmt_ms(f.since)
      );
    }
  }
  println!(
    "告警附带日志：{}",
    if v.include_logs { "开" } else { "关" }
  );
}

pub async fn run(
  c: &Client,
  cmd: AlertCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    AlertCmd::Firing => {
      let v: AlertsView = c.get("/api/alerts").await?;
      out(j, &v.firing, |firing| {
        if firing.is_empty() {
          println!("现在没有正在触发的告警");
          return;
        }
        for f in firing {
          let ack = f
            .ack
            .as_ref()
            .map(ack_text)
            .unwrap_or_else(|| "未确认".into());
          println!(
            "{:<22} {:<20} {}（{} 起）  {ack}",
            f.rule,
            f.subject,
            f.title,
            fmt_ms(f.since)
          );
        }
      });
      return Ok(());
    }
    AlertCmd::Ack {
      rule,
      subject,
      note,
    } => {
      let v: AlertsView = c
        .post(
          "/api/alerts/ack",
          &AlertAckRequest {
            rule: rule.clone(),
            subject: subject.clone(),
            note,
          },
        )
        .await?;
      out(j, &v, |_| {
        println!("已确认告警 {rule} / {subject}");
      });
      return Ok(());
    }
    AlertCmd::Unack { rule, subject } => {
      let v: AlertsView = c
        .post(
          "/api/alerts/unack",
          &AlertUnackRequest {
            rule: rule.clone(),
            subject: subject.clone(),
          },
        )
        .await?;
      out(j, &v, |_| {
        println!("已取消确认 {rule} / {subject}");
      });
      return Ok(());
    }
    AlertCmd::Digest { preview: _ } => {
      let d: AlertDigestPreview = c.get("/api/alerts/digest").await?;
      out(j, &d, |d| match (&d.title, &d.body) {
        (Some(title), Some(body)) => {
          println!("{title}\n\n{body}");
        }
        _ => println!("当前没有待汇总的内容"),
      });
      return Ok(());
    }
    AlertCmd::Suppress(sub) => {
      match sub {
        SuppressCmd::List => {
          let list: Vec<AlertSuppressionView> =
            c.get("/api/alerts/suppress").await?;
          out(j, &list, |list| {
            if list.is_empty() {
              println!("没有自定义抑制规则");
              return;
            }
            for s in list {
              println!(
                "#{:<3} {} -> 忽略 {}",
                s.id,
                fmt_target(
                  &s.source_rule,
                  s.source_subject.as_deref()
                ),
                fmt_target(
                  &s.target_rule,
                  s.target_subject.as_deref()
                ),
              );
            }
          });
        }
        SuppressCmd::Add { source, ignore } => {
          let (source_rule, source_subject) =
            parse_rule_subject(&source)?;
          let (target_rule, target_subject) =
            parse_rule_subject(&ignore)?;
          let row: AlertSuppressionView = c
            .post(
              "/api/alerts/suppress",
              &AlertSuppressionRequest {
                source_rule,
                source_subject,
                target_rule,
                target_subject,
              },
            )
            .await?;
          out(j, &row, |s| {
            println!(
              "已添加抑制规则 #{}：{} -> 忽略 {}",
              s.id,
              fmt_target(&s.source_rule, s.source_subject.as_deref()),
              fmt_target(&s.target_rule, s.target_subject.as_deref()),
            );
          });
        }
        SuppressCmd::Rm { id } => {
          let v: AlertsView =
            c.delete(&format!("/api/alerts/suppress/{id}")).await?;
          out(j, &v, |_| {
            println!("已删除抑制规则 #{id}");
          });
        }
      }
      return Ok(());
    }
    AlertCmd::List => {
      let v: AlertsView = c.get("/api/alerts").await?;
      out(j, &v, print_view);
      return Ok(());
    }
    AlertCmd::Options { include_logs } => {
      let v: AlertsView = c
        .put(
          "/api/alerts/options",
          &AlertOptions {
            include_logs: include_logs == "on",
          },
        )
        .await?;
      out(j, &v, print_view);
      return Ok(());
    }
    AlertCmd::Set {
      id,
      service,
      on,
      off,
      threshold,
      for_n,
      level,
      mute,
      reset,
      dry_run,
    } => {
      let level = level.map(|l| match l.as_str() {
        "digest" => AlertLevel::Digest,
        _ => AlertLevel::Urgent,
      });
      let patch = AlertPatch {
        enabled: (on || off).then_some(on),
        threshold,
        for_n,
        level,
        mute_minutes: mute,
        reset,
      };
      if dry_run {
        let now: AlertsView = c.get("/api/alerts").await?;
        return preview(&now, &id, service.as_deref(), &patch, j);
      }
      let path = match &service {
        Some(svc) => {
          format!("/api/alerts/{}/services/{}", seg(&id), seg(svc))
        }
        None => format!("/api/alerts/{}", seg(&id)),
      };
      let v: AlertsView = c.put(&path, &patch).await?;
      out(j, &v, print_view);
    }
    AlertCmd::Add {
      name,
      service,
      metric,
      op,
      threshold,
      for_n,
      level,
    } => {
      let level = match level.as_str() {
        "digest" => AlertLevel::Digest,
        _ => AlertLevel::Urgent,
      };
      let row: CustomAlertRuleView = c
        .post(
          "/api/alerts/custom",
          &CustomAlertRuleRequest {
            name,
            service,
            metric,
            op,
            threshold,
            for_n,
            level,
          },
        )
        .await?;
      out(j, &row, |r| {
        println!(
          "已添加自定义规则 {}（服务 {}，{}，{}）",
          r.name,
          r.service,
          level_text(r.level),
          r.condition
        );
      });
    }
    AlertCmd::Rm { name } => {
      let v: AlertsView = c
        .delete(&format!("/api/alerts/custom/{}", seg(&name)))
        .await?;
      out(j, &v, |_| {
        println!("已删除自定义规则 {name}");
      });
    }
  }
  Ok(())
}
