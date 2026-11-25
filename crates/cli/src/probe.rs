use clap::Args;
use serde_json::json;
use wharf_api_types::net_probe::{NetProbeErrorKind, NetProbeReport};

use crate::{
  client::{CliError, CliResult, Client, seg},
  commands::out,
};

#[derive(Args)]
pub struct ProbeArgs {
  /// 发起探测的服务器。
  server: String,
  /// 域名、裸 IP、主机:端口或 HTTP(S) URL。
  target: String,
  /// 覆盖自动判定的探测类型。
  #[arg(long, value_parser = ["tcp", "http", "dns"])]
  kind: Option<String>,
  /// 总超时（秒），TCP/DNS 默认 5 秒，HTTP 默认 10 秒，上限 30 秒。
  #[arg(long)]
  timeout: Option<u32>,
  /// 使用本机外网出口代理（仅 HTTP(S)）。
  #[arg(long)]
  egress: bool,
}

pub async fn run(
  c: &Client,
  args: ProbeArgs,
  json: bool,
) -> CliResult<()> {
  let result: NetProbeReport = c
    .post(
      &format!("/api/servers/{}/probe", seg(&args.server)),
      &json!({
        "target": args.target,
        "kind": args.kind,
        "timeout_secs": args.timeout,
        "egress": args.egress,
      }),
    )
    .await?;
  out(json, &result, print);
  if result.ok {
    Ok(())
  } else {
    Err(CliError::Exit(1))
  }
}

fn print(report: &NetProbeReport) {
  let mark = if report.ok { '✓' } else { '✗' };
  let r = &report.result;
  println!(
    "{} → {}  {mark}（{}ms）",
    report.server, report.target, r.elapsed_ms
  );
  if let Some(dns) = &r.dns {
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
        if error.kind == NetProbeErrorKind::Tls
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
}
