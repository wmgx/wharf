use clap::Subcommand;
use serde_json::json;
use wharf_api_types::{
  external::{AclView, DnsCheck, DnsVerdict, ExternalStatus},
  view::ServerView,
};

use crate::{
  client::{CliResult, Client, seg},
  commands::out,
};

#[derive(Subcommand)]
pub enum NetworkCmd {
  /// 读取组网策略文件。
  Acl {
    /// 跳过十分钟缓存。
    #[arg(long)]
    refresh: bool,
  },
}

#[derive(Subcommand)]
pub enum ExternalCmd {
  /// 列出外部服务状态。
  List,
  /// 添加一个公开的 Statuspage。
  Add { name: String, url: String },
  /// 删除自己添加的状态页。
  Rm { name: String },
  /// 开启或关闭检查。
  Set {
    name: String,
    /// 关闭检查。
    #[arg(
      long,
      required_unless_present = "on",
      conflicts_with = "on"
    )]
    off: bool,
    /// 开启检查。
    #[arg(long)]
    on: bool,
  },
}

pub async fn acl(
  c: &Client,
  cmd: NetworkCmd,
  j: bool,
) -> CliResult<()> {
  let NetworkCmd::Acl { refresh } = cmd;
  let result: AclView = c
    .get(&format!("/api/network/acl?refresh={refresh}"))
    .await?;
  out(j, &result, |r| {
    if let Some(raw) = &r.raw {
      print!("{raw}");
    } else {
      println!("{}", r.status);
      if let Some(hint) = &r.hint {
        println!("{hint}");
      }
    }
  });
  Ok(())
}

pub async fn dns(c: &Client, host: &str, j: bool) -> CliResult<()> {
  let v: DnsCheck = c
    .get(&format!("/api/routes/{}/dns-check", seg(host)))
    .await?;
  out(j, &v, |r| {
    println!("{}  期望 {}", r.hostname, r.expected);
    let records = |ips: &Option<Vec<String>>| match ips {
      None => "查不到".into(),
      Some(ips) if ips.is_empty() => "无记录".into(),
      Some(ips) => ips.join("、"),
    };
    for dns in &r.resolvers {
      let status = match dns.verdict {
        DnsVerdict::Matches => "一致",
        DnsVerdict::Mismatch => "不一致",
        DnsVerdict::Unavailable => "查不到",
      };
      println!(
        "{}  A {}  AAAA {}  {status}  {} ms",
        dns.resolver,
        records(&dns.a),
        records(&dns.aaaa),
        dns.elapsed_ms
      );
    }
    println!(
      "{}",
      if r.effective {
        if r
          .resolvers
          .iter()
          .any(|r| r.verdict == DnsVerdict::Matches)
        {
          "已查到的结果一致"
        } else {
          "三个 DNS 均查不到"
        }
      } else {
        "未生效"
      }
    );
  });
  Ok(())
}

fn show_status(r: &ExternalStatus) {
  let at = r.checked_at.map_or("-".into(), |t| {
    t.format("%Y-%m-%d %H:%M UTC").to_string()
  });
  println!(
    "{}  {}  {}  {at}",
    r.name,
    r.indicator.as_deref().unwrap_or("-"),
    r.description
  );
  for i in &r.incidents {
    println!("  {}  {}", i.name, i.url);
  }
}

pub async fn command(
  c: &Client,
  cmd: ExternalCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    ExternalCmd::List => {
      let v: Vec<ExternalStatus> = c.get("/api/external").await?;
      out(j, &v, |rows| rows.iter().for_each(show_status));
    }
    ExternalCmd::Add { name, url } => {
      let v: ExternalStatus = c
        .post("/api/external", &json!({"name": name, "url": url}))
        .await?;
      out(j, &v, show_status);
    }
    ExternalCmd::Set { name, off, on: _ } => {
      let v: ExternalStatus = c
        .put(
          &format!("/api/external/{}", seg(&name)),
          &json!({"enabled": !off}),
        )
        .await?;
      out(j, &v, show_status);
    }
    ExternalCmd::Rm { name } => {
      c.delete::<()>(&format!("/api/external/{}", seg(&name)))
        .await?;
      out(j, &json!({"name": name}), |_| println!("已删除 {name}"));
    }
  }
  Ok(())
}

pub fn network(v: &wharf_api_types::view::NetworkView) {
  if v
    .servers
    .iter()
    .any(|s| s.tailnet_ip.is_some() && s.tailnet_ip != s.private_ip)
  {
    println!("\n谁能连谁的组网地址");
    for row in &v.tailnet_reach {
      let status = if row.stale {
        "结果过期"
      } else if row.ok {
        "通"
      } else {
        "不通"
      };
      println!("  {} → {}  {status}", row.from, row.to);
    }
  }
  for relay in &v.tailnet_relays {
    println!(
      "  {} ⇄ {}  组网走中继 {}",
      relay.from, relay.to, relay.relay
    );
  }
}

pub fn server(view: &ServerView) {
  let report = view.report.as_ref();
  let egress = report.and_then(|r| r.egress_info.as_ref());
  let value = |items: &[Option<&str>]| {
    let joined = items
      .iter()
      .flatten()
      .copied()
      .collect::<Vec<_>>()
      .join(" ");
    if joined.is_empty() {
      "查不到".into()
    } else {
      joined
    }
  };
  println!(
    "  出口 IPv4  {}",
    egress
      .and_then(|r| r.ipv4.as_deref())
      .or_else(|| report.and_then(|r| r.public_ip.as_deref()))
      .unwrap_or("查不到")
  );
  println!(
    "  出口 IPv6  {}",
    egress.map_or("查不到", |i| i.ipv6.as_deref().unwrap_or("无"))
  );
  if let Some(e) = egress {
    println!(
      "  运营商  {}",
      value(&[e.asn.as_deref(), e.operator.as_deref()])
    );
    println!(
      "  地区  {}",
      value(&[e.country.as_deref(), e.city.as_deref()])
    );
  } else {
    println!("  运营商  查不到\n  地区  查不到");
  }
  if let Some(key) = &view.tailnet_key {
    if key.never_expires {
      println!("  组网密钥  不过期");
    } else if let Some(expiry) = key.expires {
      println!(
        "  组网密钥到期  {}",
        expiry.format("%Y-%m-%d %H:%M UTC")
      );
    }
  }
  let mirror = if view
    .settings
    .registry_mirrors
    .get("docker.io")
    .is_some_and(|m| !m.is_empty())
  {
    " · 已设镜像源"
  } else {
    ""
  };
  match report.and_then(|r| r.docker_quota) {
    Some(q) => println!(
      "  Docker Hub 剩余额度  {} / {}（{} 小时窗口，查于 {}）{mirror}",
      q.remaining,
      q.limit,
      f64::from(q.window_secs) / 3600.0,
      q.checked_at.format("%Y-%m-%d %H:%M UTC")
    ),
    None => println!("  Docker Hub 剩余额度  查不到{mirror}"),
  }
}
