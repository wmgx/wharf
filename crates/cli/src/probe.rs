use clap::Args;
use serde_json::json;
use wharf_api_types::net_probe::{NetProbeErrorKind, NetProbeReport};

use crate::{
  client::{CliError, CliResult, Client, seg},
  commands::out,
};

#[derive(Args)]
pub struct ServerProbeArgs {
  /// 发起探测的服务器。
  server: String,
  #[command(flatten)]
  probe: ProbeArgs,
  /// 使用本机外网出口代理（仅 HTTP(S)）。
  #[arg(long)]
  egress: bool,
}

#[derive(Args)]
pub struct ServiceProbeArgs {
  /// 发起探测的服务。
  service: String,
  #[command(flatten)]
  probe: ProbeArgs,
  /// Compose 组件名，多容器服务必须指定。
  #[arg(long)]
  component: Option<String>,
}

#[derive(Args)]
struct ProbeArgs {
  /// 域名、裸 IP、主机:端口或 HTTP(S) URL。
  target: String,
  /// 覆盖自动判定的探测类型。
  #[arg(long, value_parser = ["tcp", "http", "dns"])]
  kind: Option<String>,
  /// 总超时（秒），TCP/DNS 默认 5 秒，HTTP 默认 10 秒，上限 30 秒。
  #[arg(long)]
  timeout: Option<u32>,
}

pub async fn server(
  c: &Client,
  args: ServerProbeArgs,
  json: bool,
) -> CliResult<()> {
  run(
    c,
    &format!("/api/servers/{}/probe", seg(&args.server)),
    &args.server,
    args.probe,
    args.egress,
    None,
    json,
  )
  .await
}

pub async fn service(
  c: &Client,
  args: ServiceProbeArgs,
  json: bool,
) -> CliResult<()> {
  run(
    c,
    &format!("/api/services/{}/probe", seg(&args.service)),
    &args.service,
    args.probe,
    false,
    args.component,
    json,
  )
  .await
}

async fn run(
  c: &Client,
  path: &str,
  source: &str,
  args: ProbeArgs,
  egress: bool,
  component: Option<String>,
  json: bool,
) -> CliResult<()> {
  let result: NetProbeReport = c
    .post(
      path,
      &json!({
        "target": args.target,
        "kind": args.kind,
        "timeout_secs": args.timeout,
        "egress": egress,
        "component": component,
      }),
    )
    .await?;
  out(json, &result, |report| print(report, source));
  if result.ok {
    Ok(())
  } else {
    Err(CliError::Exit(1))
  }
}

fn print(report: &NetProbeReport, source: &str) {
  let mark = if report.ok { '✓' } else { '✗' };
  let r = &report.result;
  if let Some(container) = &r.container {
    println!(
      "{}（容器 {}，网络 {}）→ {}  {mark}",
      source,
      container.name.escape_debug(),
      container.network_mode.escape_debug(),
      report.target,
    );
    if !container.proxy_env.is_empty() {
      println!(
        "  容器代理：{}",
        container.proxy_env.join("、").escape_debug()
      );
    }
  } else {
    println!(
      "{} → {}  {mark}（{}ms）",
      report.server, report.target, r.elapsed_ms
    );
  }
  if r.dns.as_ref().is_some_and(|dns| dns.resolved_by_egress) {
    println!("    dns   由出口代理解析");
  } else if let Some(dns) = &r.dns {
    let ips = dns
      .ips
      .iter()
      .map(ToString::to_string)
      .collect::<Vec<_>>()
      .join("、");
    let nameservers = dns.nameservers.join("、");
    let search = dns.search.join("、");
    if !ips.is_empty() {
      print!("  ✓ dns   解析到 {ips}（{}ms", dns.elapsed_ms);
    } else {
      print!("  ✗ dns   未取得地址（{}ms", dns.elapsed_ms);
    }
    if !nameservers.is_empty() {
      print!("，nameserver {}", nameservers.escape_debug());
    }
    if !search.is_empty() {
      print!("，search {}", search.escape_debug());
    }
    println!("）");
  }
  if let Some(tcp) = &r.tcp {
    println!(
      "  ✓ tcp   {} 连上（{}ms）",
      tcp.remote_addr, tcp.elapsed_ms
    );
  }
  if let Some(http) = &r.http {
    let proxy = if http.egress {
      "外网分流代理"
    } else {
      "直连"
    };
    print!("  {mark} http  HTTP {}（{proxy}）", http.status);
    for (key, value) in &http.headers {
      print!("，{key} {}", value.escape_debug());
    }
    println!();
  }
  if let Some(error) = &r.error {
    let layer = match error.kind {
      NetProbeErrorKind::Tls => "tls",
      NetProbeErrorKind::DnsFailed => "dns",
      _ => report.kind.as_str(),
    };
    match &report.hint {
      Some(hint)
        if (error.kind == NetProbeErrorKind::Tls
          && report.certificate.is_some())
          || hint == &error.message =>
      {
        println!("  ✗ {layer:<5} {}", hint.escape_debug());
      }
      Some(hint) => println!(
        "  ✗ {layer:<5} {}。{}",
        error.message.escape_debug(),
        hint.escape_debug()
      ),
      None => {
        println!("  ✗ {layer:<5} {}", error.message.escape_debug())
      }
    }
  } else if let Some(cert) = &report.certificate {
    println!(
      "  ✓ tls   CN={}，到期 {}（剩 {} 天）",
      cert.subject_cn.as_deref().unwrap_or("—").escape_debug(),
      cert.not_after.format("%Y-%m-%d"),
      cert.days_left,
    );
  }
  if r.error.is_none()
    && let Some(hint) = &report.hint
  {
    println!("  提示   {}", hint.escape_debug());
  }
}
