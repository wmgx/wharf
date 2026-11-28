use clap::Subcommand;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError,
  service_checks::{HeartbeatSpec, LogAlertSpec, PortCheckSpec},
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
  #[command(flatten)]
  apply: ApplyFlags,
}

pub async fn port(
  c: &Client,
  args: PortArgs,
  j: bool,
) -> CliResult<()> {
  let PortArgs {
    name,
    port,
    udp_dns,
    udp_send,
    udp_expect,
    off,
    apply,
  } = args;
  let view = get(c, &name).await?;
  let mut spec = view.spec;
  let p =
    spec.ports.iter().find(|p| p.name == port).ok_or_else(|| {
      ApiError::not_found(format!("服务 {name} 没有端口 {port}"))
    })?;
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

#[allow(clippy::too_many_arguments)]
pub async fn heartbeat(
  c: &Client,
  name: String,
  every: Option<u32>,
  grace: Option<u32>,
  off: bool,
  container: Option<String>,
  apply: ApplyFlags,
  j: bool,
) -> CliResult<()> {
  let mut spec = get(c, &name).await?.spec;
  if let Some(container) = container {
    spec.container = Some(container);
  }
  let current = spec.heartbeat.take();
  if !off {
    let every_mins = every
      .or_else(|| current.as_ref().map(|h| h.every_mins))
      .ok_or_else(|| {
        ApiError::invalid("开启心跳需要指定报到间隔")
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
    });
  }
  if current.is_some() != spec.heartbeat.is_some() {
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
