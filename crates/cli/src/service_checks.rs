use clap::Subcommand;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  service_checks::{
    HeartbeatReportView, HeartbeatSpec, LogAlertSpec, PortCheckSpec,
  },
  spec::{Change, ServiceSpec},
  view::ServiceView,
};

use crate::{
  ApplyFlags,
  client::{CliResult, Client, seg},
  commands::{changes, out, pretty},
};

#[derive(Subcommand)]
pub enum LogAlertCmd {
  /// 新增日志关键字规则。
  Add {
    pattern: String,
    /// 按正则表达式匹配。
    #[arg(long)]
    regex: bool,
    /// 统计窗口，单位分钟。
    #[arg(long, default_value = "5m", value_parser = minutes)]
    window: u32,
    #[arg(long, default_value_t = 1)]
    count: u32,
    /// 仅查看此 Compose 服务。
    #[arg(long)]
    container: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 用列表中的序号或关键字删除一条规则。
  Rm {
    rule: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

pub fn minutes(value: &str) -> Result<u32, &'static str> {
  value
    .strip_suffix('m')
    .and_then(|n| n.parse().ok())
    .ok_or("用分钟表示，例如 5m")
}

async fn get(c: &Client, name: &str) -> CliResult<ServiceView> {
  c.get(&format!("/api/services/{}", seg(name))).await
}

async fn put(
  c: &Client,
  name: String,
  spec: ServiceSpec,
  apply: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  changes(
    c,
    vec![Change::UpsertService {
      pins: None,
      commit: None,
      name,
      spec,
      adopt: None,
    }],
    apply,
    j,
  )
  .await
}

pub async fn log(
  c: &Client,
  name: String,
  cmd: Option<LogAlertCmd>,
  off: bool,
  flags: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  let view = get(c, &name).await?;
  let mut spec = view.spec;
  let flags = match cmd {
    Some(LogAlertCmd::Add {
      pattern,
      regex,
      window,
      count,
      container,
      apply,
    }) => {
      if spec.log_alerts.len() >= 20 {
        return Err(
          ApiError::invalid("每个服务最多有 20 条日志告警规则")
            .into(),
        );
      }
      let rule = LogAlertSpec {
        pattern,
        regex,
        window_mins: window,
        min_count: count,
        container,
      };
      rule.compile()?;
      spec.log_alerts.push(rule);
      apply
    }
    Some(LogAlertCmd::Rm { rule, apply }) => {
      let index = rule
        .parse::<usize>()
        .ok()
        .and_then(|i| i.checked_sub(1))
        .filter(|i| *i < spec.log_alerts.len())
        .or_else(|| {
          spec.log_alerts.iter().position(|r| r.pattern == rule)
        })
        .ok_or_else(|| ApiError::not_found("没有这条日志告警规则"))?;
      spec.log_alerts.remove(index);
      apply
    }
    None if off => {
      spec.log_alerts.clear();
      flags
    }
    None => {
      flags.check_read_only()?;
      let rows: Vec<_> = spec
        .log_alerts
        .iter()
        .enumerate()
        .map(|(i, rule)| {
          let view = view.log_alerts.get(i);
          json!({
            "index": i + 1, "rule": rule,
            "last_hit": view.and_then(|v| v.last_hit),
            "firing": view.is_some_and(|v| v.firing),
          })
        })
        .collect();
      out(j, &rows, |rows| {
        if rows.is_empty() {
          println!("没有日志告警规则");
        }
        for row in rows {
          let at = row["last_hit"]
            .as_i64()
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map_or_else(|| "从未命中".into(), |at| at.to_rfc3339());
          let pattern =
            row["rule"]["pattern"].as_str().unwrap_or_default();
          let status = if row["firing"] == true {
            "正在触发"
          } else {
            "未触发"
          };
          println!("{}  {pattern}  {status}  {at}", row["index"]);
        }
      });
      return Ok(());
    }
  };
  put(c, name, spec, flags, j).await
}

#[derive(clap::Args)]
pub struct PortArgs {
  name: String,
  port: String,
  /// 检查 UDP DNS 应答。用 . 查询根域的 NS。
  #[arg(long, conflicts_with_all = ["udp_send", "udp_expect", "off"])]
  udp_dns: Option<String>,
  /// UDP 请求，十六进制。
  #[arg(long, requires = "udp_expect", conflicts_with = "off")]
  udp_send: Option<String>,
  /// UDP 应答前缀，十六进制。
  #[arg(long, requires = "udp_send", conflicts_with = "off")]
  udp_expect: Option<String>,
  /// 关闭此端口的检查。
  #[arg(long)]
  off: bool,
  /// 开启或恢复 TCP 端口检查。
  #[arg(long, conflicts_with_all = ["off", "udp_dns", "udp_send", "udp_expect"])]
  on: bool,
  #[command(flatten)]
  apply: ApplyFlags,
}

impl PortArgs {
  fn has_edits(&self) -> bool {
    self.on
      || self.off
      || self.udp_dns.is_some()
      || self.udp_send.is_some()
      || self.udp_expect.is_some()
  }
}

pub async fn port(
  c: &Client,
  args: PortArgs,
  j: bool,
) -> CliResult<()> {
  let has_edits = args.has_edits();
  let PortArgs {
    name,
    port,
    udp_dns,
    udp_send,
    udp_expect,
    on,
    off,
    apply,
  } = args;
  let view = get(c, &name).await?;
  let mut spec = view.spec;
  let p =
    spec.ports.iter().find(|p| p.name == port).ok_or_else(|| {
      ApiError::not_found(format!("服务 {name} 没有端口 {port}"))
    })?;
  if !has_edits {
    apply.check_read_only()?;
    let host_port = view.host_ports.get(&port).copied().or(p.host);
    let check = spec.port_checks.get(&port);
    let mode = match check {
      Some(PortCheckSpec::Off) => "off",
      Some(PortCheckSpec::Dns { .. }) => "udp_dns",
      Some(PortCheckSpec::Custom { .. }) => "udp_custom",
      None if p.udp => "off",
      None => "tcp",
    };
    let hint =
      "不带参数现为只读查看；恢复 TCP 检查请加 --on，关闭请加 --off";
    let protocol = if p.udp { "udp" } else { "tcp" };
    let ok = view.port_checks.get(&port);
    let supported = view.port_checks_supported.unwrap_or(false);
    out(
      j,
      &json!({
        "service": name, "port": port, "protocol": protocol,
        "published": host_port.is_some(), "host_port": host_port, "supported": supported,
        "enabled": mode != "off" && host_port.is_some(), "mode": mode, "spec": check,
        "ok": ok, "hint": hint,
      }),
      |_| {
        println!(
          "{name}/{port} {protocol}  发布端口：{}  模式：{mode}",
          host_port
            .map_or_else(|| "未发布".into(), |p| p.to_string())
        );
        println!(
          "最近检查：{}",
          match ok {
            Some(true) => "正常",
            Some(false) => "异常",
            None => "暂无数据",
          }
        );
        if !supported {
          println!("当前服务器 agent 暂不支持端口探测，请升级 agent");
        }
        println!("{hint}");
      },
    );
    return Ok(());
  }
  if on && p.udp {
    return Err(ApiError::invalid("UDP 端口开启检查需要指定探针")
      .with_hint("用 --udp-dns <域名> 或 --udp-send <hex> --udp-expect <hex>").into());
  }
  if !view.host_ports.contains_key(&port) && p.host.is_none() {
    return Err(
      ApiError::invalid(format!("端口 {port} 没有发布到宿主机"))
        .into(),
    );
  }
  let check = match (off, udp_dns, udp_send, udp_expect) {
    (true, _, _, _) => {
      spec.port_checks.remove(&port);
      (!p.udp).then_some(PortCheckSpec::Off)
    }
    (_, Some(domain), _, _) => Some(PortCheckSpec::Dns { domain }),
    (_, _, Some(send), Some(expect)) => Some(PortCheckSpec::Custom { send, expect }),
    _ if p.udp => Some(spec.port_checks.get(&port).cloned()
      .filter(|check| !matches!(check, PortCheckSpec::Off))
      .ok_or_else(|| ApiError::invalid("这个 UDP 端口还没配置检查")
        .with_hint("用 --udp-dns <域名>，或同时给 --udp-send <hex> 和 --udp-expect <hex>"))?),
    _ => {
      spec.port_checks.remove(&port);
      None
    }
  };
  if let Some(check) = check {
    check.validate(p.udp)?;
    spec.port_checks.insert(port, check);
  }
  put(c, name, spec, apply, j).await
}

pub fn show_auto_update(
  name: &str,
  enabled: bool,
  j: bool,
) -> CliResult<()> {
  let hint = "不带参数现为只读查看；开启请加 --on，关闭请加 --off";
  out(
    j,
    &json!({"service": name, "auto_update": enabled, "hint": hint}),
    |_| {
      println!(
        "{name} 自动更新：{}\n{hint}",
        if enabled { "已开启" } else { "已关闭" }
      );
    },
  );
  Ok(())
}

pub fn show_monitor(
  name: &str,
  spec: &ServiceSpec,
  last: Option<&wharf_api_types::view::MonitorView>,
  j: bool,
) -> CliResult<()> {
  let hint = "不带参数现为只读查看；开启请加 --on 或 --path /health，关闭请加 --off";
  let enabled = spec.monitor.is_some();
  out(
    j,
    &json!({"service": name, "enabled": enabled, "spec": spec.monitor,
    "start_timeout_secs": spec.start_timeout_secs, "last": last, "hint": hint}),
    |value| {
      pretty(value);
      println!("{hint}");
    },
  );
  Ok(())
}

#[derive(clap::Args)]
pub struct HeartbeatArgs {
  name: String,
  /// 目标 Compose 容器。
  #[arg(long)]
  container: Option<String>,
  /// 报到间隔，例如 10m。
  #[arg(long, conflicts_with = "off", value_parser = minutes)]
  every: Option<u32>,
  /// 宽限，默认 5 分钟。
  #[arg(long, conflicts_with = "off", value_parser = minutes)]
  grace: Option<u32>,
  #[arg(long)]
  off: bool,
  /// 换新口令并重新部署。
  #[arg(long, conflicts_with = "off")]
  rotate: bool,
  /// 只读查看时最多显示多少条报到记录，上限 50。
  #[arg(long, conflicts_with_all = ["every", "grace", "off", "rotate", "container"])]
  limit: Option<u32>,
  /// 显示完整报到地址，需要 apply 权限。
  #[arg(long, conflicts_with_all = ["every", "grace", "off", "rotate", "container"])]
  reveal: bool,
  #[command(flatten)]
  apply: ApplyFlags,
}

pub async fn heartbeat(
  c: &Client,
  args: HeartbeatArgs,
  j: bool,
) -> CliResult<()> {
  let HeartbeatArgs {
    name,
    every,
    grace,
    container,
    off,
    rotate,
    limit,
    reveal,
    apply,
  } = args;
  let target = format!("/api/services/{}", seg(&name));
  if every.is_none()
    && grace.is_none()
    && !off
    && !rotate
    && container.is_none()
  {
    apply.check_read_only()?;
    let service_path = if reveal {
      format!("{target}?reveal=true")
    } else {
      target.clone()
    };
    let view: ServiceView = c.get(&service_path).await?;
    let reports: Vec<HeartbeatReportView> = c
      .get(&format!(
        "{target}/heartbeat/reports?limit={}",
        limit.unwrap_or(20)
      ))
      .await?;
    let mut spec = view.spec.heartbeat;
    if let Some(h) = &mut spec {
      h.token.clear();
    }
    let heartbeat = view.heartbeat;
    out(
      j,
      &json!({"service": name, "enabled": spec.is_some(), "spec": spec,
        "status": heartbeat.as_ref().map(|h| &h.status),
        "url": heartbeat.as_ref().map(|h| &h.url),
        "last_at": heartbeat.as_ref().and_then(|h| h.last_at), "reports": reports,
      }),
      |value| {
        pretty(value);
        if !reveal && spec.is_some() {
          println!("加 --reveal 查看完整报到地址");
        }
      },
    );
    return Ok(());
  }
  let mut spec = get(c, &name).await?.spec;
  if let Some(container) = container {
    spec.container = Some(container);
  }
  let current = spec.heartbeat.take();
  if !off {
    let every_mins = every
      .or_else(|| current.as_ref().map(|h| h.every_mins))
      .ok_or_else(|| {
        ApiError::invalid(if rotate {
          "服务尚未开启心跳，无法轮换口令"
        } else {
          "开启心跳需要指定报到间隔"
        })
        .with_hint("加上 --every 10m")
      })?;
    let grace_mins = grace
      .or_else(|| current.as_ref().map(|h| h.grace_mins))
      .unwrap_or(5);
    spec.heartbeat = Some(HeartbeatSpec {
      every_mins,
      grace_mins,
      token: String::new(),
      targeted: false,
      rotate,
    });
  }
  if !j && (rotate || current.is_some() != spec.heartbeat.is_some()) {
    eprintln!("心跳配置需要重新部署才生效");
  }
  put(c, name, spec, apply, j).await
}

pub async fn ignore(
  c: &Client,
  server: &str,
  project: Option<String>,
  container: Option<String>,
  undo: bool,
  j: bool,
) -> CliResult<()> {
  let result: Value = c.post(
    &format!("/api/servers/{}/unmanaged/ignore", seg(server)),
    &json!({ "project": project, "container": container, "undo": undo }),
  ).await?;
  out(j, &result, pretty);
  Ok(())
}

#[test]
fn port_check_no_args_is_read_only() {
  use clap::Parser;
  fn edit(flags: &[&str]) -> bool {
    let argv = ["wharf", "service", "port-check", "app", "metrics"]
      .into_iter()
      .chain(flags.iter().copied());
    match crate::Cli::try_parse_from(argv).unwrap().command {
      crate::Command::Service(crate::ServiceCmd::PortCheck(args)) => {
        args.has_edits()
      }
      _ => panic!("应解析成端口检查命令"),
    }
  }
  assert!(!edit(&["--json"]));
  assert!(edit(&["--on"]));
}
