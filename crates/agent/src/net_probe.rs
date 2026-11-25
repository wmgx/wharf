use std::{
  error::Error,
  io,
  net::{IpAddr, SocketAddr},
  time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Proxy, Response, Url};
use tokio::net::{TcpStream, lookup_host};
use wharf_api_types::{
  agent::{NetProbeJob, NetProbeResult},
  net_probe::{
    NetProbeDns, NetProbeError,
    NetProbeErrorKind::{self, *},
    NetProbeHttp, NetProbeKind, NetProbeTcp, NetProbeTls, dns_target,
    is_public, tcp_target,
  },
};

use crate::exec::Ctx;

pub async fn run(job: &NetProbeJob, ctx: &Ctx) -> NetProbeResult {
  let start = Instant::now();
  let mut result = NetProbeResult::default();
  let timeout =
    Duration::from_secs(u64::from(job.timeout_secs.clamp(1, 30)));
  let outcome = tokio::select! {
    biased;
    _ = ctx.cancel.cancelled() => Err(error(Cancelled, "已取消")),
    outcome = tokio::time::timeout(timeout, probe(job, &mut result)) => {
      outcome.unwrap_or_else(|_| Err(error(Timeout, "探测超时")))
    }
  };
  if let Err(e) = outcome
    && (e.kind == Cancelled || result.error.is_none())
  {
    result.error = Some(e);
  }
  result.elapsed_ms = elapsed(start);
  result
}

async fn probe(
  job: &NetProbeJob,
  result: &mut NetProbeResult,
) -> Result<(), NetProbeError> {
  if job.egress && job.kind != NetProbeKind::Http {
    return Err(error(Other, "只有 HTTP 探测可以使用外网出口"));
  }

  let url = if job.kind == NetProbeKind::Http {
    let mut url = Url::parse(&job.target)
      .map_err(|_| error(Other, "无效的 HTTP URL"))?;
    let userinfo =
      job.target.split_once("://").is_some_and(|(_, rest)| {
        rest
          .split(['/', '?', '#', '\\'])
          .next()
          .is_some_and(|authority| authority.contains('@'))
      });
    if !matches!(url.scheme(), "http" | "https")
      || url.host_str().is_none()
      || url.port() == Some(0)
      || userinfo
      || !url.username().is_empty()
      || url.password().is_some()
    {
      return Err(error(Other, "无效的 HTTP URL 或包含用户凭据"));
    }
    url.set_fragment(None);
    Some(url)
  } else {
    None
  };
  let invalid = || error(Other, "无效的探测目标");
  let (host, port) = match job.kind {
    NetProbeKind::Dns if dns_target(&job.target) => {
      (job.target.as_str(), 0)
    }
    NetProbeKind::Dns => return Err(invalid()),
    NetProbeKind::Tcp => {
      tcp_target(&job.target).ok_or_else(invalid)?
    }
    NetProbeKind::Http => {
      let url = url.as_ref().ok_or_else(invalid)?;
      let host =
        url.host_str().ok_or_else(invalid)?.trim_matches(['[', ']']);
      (host, url.port_or_known_default().ok_or_else(invalid)?)
    }
  };

  let mut dns = NetProbeDns::default();
  if let Ok(text) =
    tokio::fs::read_to_string("/etc/resolv.conf").await
  {
    (dns.nameservers, dns.search) = resolv_conf(&text);
  }
  let started = Instant::now();
  result.dns = Some(dns);
  let addresses = match host.parse::<IpAddr>() {
    Ok(ip) => Ok(vec![SocketAddr::new(ip, port)]),
    Err(_) => lookup_host((host, port)).await.map(Iterator::collect),
  };
  let dns = result.dns.as_mut().expect("DNS 结果已初始化");
  dns.elapsed_ms = elapsed(started);
  let addresses: Vec<SocketAddr> =
    addresses.map_err(|e| error(DnsFailed, e.to_string()))?;
  if addresses.is_empty() {
    return Err(error(DnsFailed, "系统解析未返回 IP 地址"));
  }
  for addr in &addresses {
    let ip = addr.ip();
    if !dns.ips.contains(&ip) {
      dns.ips.push(ip);
    }
  }
  if dns.ips.iter().copied().any(blocked) {
    return Err(error(Blocked, "解析结果包含禁止探测的 IP 地址"));
  }
  if job.egress && dns.ips.iter().any(|&ip| !is_public(ip)) {
    return Err(error(Blocked, "出口代理只用来测外网"));
  }
  match job.kind {
    NetProbeKind::Dns => Ok(()),
    NetProbeKind::Tcp => {
      let started = Instant::now();
      let stream = TcpStream::connect(addresses.as_slice())
        .await
        .map_err(io_error)?;
      let remote_addr =
        stream.peer_addr().map_err(io_error)?.to_string();
      result.tcp = Some(NetProbeTcp {
        remote_addr,
        elapsed_ms: elapsed(started),
      });
      Ok(())
    }
    NetProbeKind::Http => {
      http(url.ok_or_else(invalid)?, &addresses, job.egress, result)
        .await
    }
  }
}

async fn http(
  url: Url,
  addresses: &[SocketAddr],
  egress: bool,
  result: &mut NetProbeResult,
) -> Result<(), NetProbeError> {
  let https = url.scheme() == "https";
  let url = &url;
  let request = |insecure| async move {
    let mut builder = Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .retry(reqwest::retry::never())
      .no_proxy()
      .user_agent("wharf-probe")
      .tls_info(true)
      .tls_danger_accept_invalid_certs(insecure);
    if egress {
      let proxy = Proxy::all(crate::egress::local_url())
        .map_err(|e| http_error(e, https, egress))?;
      builder = builder.proxy(proxy);
    } else if let Some(host) = url.host_str() {
      builder = builder.resolve_to_addrs(host, addresses);
    }
    builder
      .build()
      .map_err(|e| http_error(e, https, egress))?
      .get(url.clone())
      .send()
      .await
      .map_err(|e| http_error(e, https, egress))
  };
  let response = match request(false).await {
    Ok(response) => response,
    Err(e) if e.kind == Tls => {
      result.tls = Some(NetProbeTls {
        verified: false,
        verify_error: Some(e.message.clone()),
        peer_der: None,
      });
      result.error = Some(e);
      request(true).await?
    }
    Err(e) => return Err(e),
  };

  if https {
    let tls = result.tls.get_or_insert(NetProbeTls {
      verified: true,
      verify_error: None,
      peer_der: None,
    });
    tls.peer_der = response
      .extensions()
      .get::<reqwest::tls::TlsInfo>()
      .and_then(|t| t.peer_certificate())
      .map(|der| STANDARD.encode(der));
  }
  result.http = Some(http_headers(response, egress));
  Ok(())
}

fn http_headers(response: Response, egress: bool) -> NetProbeHttp {
  let headers = ["content-type", "server", "location"]
    .into_iter()
    .filter_map(|name| {
      let value = response.headers().get(name)?.to_str().ok()?;
      let value = if name == "location" {
        value.split('?').next().unwrap_or_default()
      } else {
        value
      };
      Some((name.to_string(), value.to_string()))
    })
    .collect();
  NetProbeHttp {
    status: response.status().as_u16(),
    headers,
    egress,
  }
}

fn http_error(
  e: reqwest::Error,
  https: bool,
  egress: bool,
) -> NetProbeError {
  let e = e.without_url();
  let mut kind = if e.is_timeout() { Timeout } else { Other };
  let mut message = e.to_string();
  let mut source = e.source();
  while let Some(cause) = source {
    let detail = cause.to_string();
    if https
      && e.is_connect()
      && (detail.starts_with("invalid peer certificate:")
        || detail.starts_with("received fatal alert:")
        || detail.starts_with("peer is incompatible:")
        || detail.starts_with("peer misbehaved:")
        || detail
          .starts_with("received unexpected handshake message:")
        || detail
          .starts_with("peer doesn't support any known protocol")
        || detail.starts_with("peer sent no certificates")
        || detail.starts_with("received corrupt message"))
    {
      kind = Tls;
    } else if kind == Other
      && let Some(io) = cause.downcast_ref::<io::Error>()
    {
      kind = io_kind(io.kind());
    }
    if !message.ends_with(&detail) {
      message.push_str(": ");
      message.push_str(&detail);
    }
    source = cause.source();
  }
  if egress && kind == Refused {
    message = format!("这台机器没有开外网出口：{message}");
  }
  error(kind, message)
}

fn io_error(e: io::Error) -> NetProbeError {
  error(io_kind(e.kind()), e.to_string())
}

fn io_kind(kind: io::ErrorKind) -> NetProbeErrorKind {
  match kind {
    io::ErrorKind::ConnectionRefused => Refused,
    io::ErrorKind::TimedOut => Timeout,
    io::ErrorKind::HostUnreachable
    | io::ErrorKind::NetworkUnreachable => Unreachable,
    _ => Other,
  }
}

fn error(
  kind: NetProbeErrorKind,
  message: impl Into<String>,
) -> NetProbeError {
  NetProbeError {
    kind,
    message: message.into(),
  }
}

fn elapsed(start: Instant) -> u64 {
  start.elapsed().as_millis() as u64
}

fn blocked(ip: IpAddr) -> bool {
  match ip.to_canonical() {
    IpAddr::V4(ip) => matches!(
      ip.octets(),
      [0, ..] | [169, 254, ..] | [100, 100, 100, 200]
    ),
    IpAddr::V6(ip) => {
      ip.is_unspecified()
        || ip.is_unicast_link_local()
        || ip.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]
    }
  }
}

fn resolv_conf(text: &str) -> (Vec<String>, Vec<String>) {
  let mut nameservers = Vec::new();
  let mut search = Vec::new();
  for line in text.lines() {
    let mut words = line
      .split(['#', ';'])
      .next()
      .unwrap_or_default()
      .split_whitespace();
    match words.next() {
      Some("nameserver") => {
        nameservers.extend(words.take(1).map(str::to_string))
      }
      Some("search") => search = words.map(str::to_string).collect(),
      _ => {}
    }
  }
  (nameservers, search)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn blocks_metadata_and_link_local_addresses() {
    for ip in [
      "169.254.169.254",
      "100.100.100.200",
      "::ffff:169.254.169.254",
      "fe80::1",
      "fd00:ec2::254",
      "0.1.2.3",
      "::",
    ] {
      assert!(blocked(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
      "100.126.247.71",
      "127.0.0.1",
      "192.168.31.105",
      "172.17.232.122",
      "8.8.8.8",
    ] {
      assert!(!blocked(ip.parse().unwrap()), "{ip}");
    }
  }

  #[test]
  fn parses_resolver_config() {
    let input = "# system DNS\n nameserver 100.100.100.100 # tailscale\nnameserver 1.1.1.1\nsearch example.net tail.test ; comment\noptions ndots:1";
    let (nameservers, search) = resolv_conf(input);
    assert_eq!(nameservers, ["100.100.100.100", "1.1.1.1"]);
    assert_eq!(search, ["example.net", "tail.test"]);
  }
}
