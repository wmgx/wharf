use std::{
  collections::BTreeMap,
  net::{IpAddr, Ipv6Addr},
};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NetProbeKind {
  Tcp,
  Http,
  Dns,
}

impl NetProbeKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Tcp => "tcp",
      Self::Http => "http",
      Self::Dns => "dns",
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetProbeJob {
  pub kind: NetProbeKind,
  pub target: String,
  pub timeout_secs: u32,
  pub egress: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeRequest {
  pub target: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub kind: Option<NetProbeKind>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub timeout_secs: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub egress: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeResult {
  pub elapsed_ms: u64,
  pub dns: Option<NetProbeDns>,
  pub tcp: Option<NetProbeTcp>,
  pub http: Option<NetProbeHttp>,
  pub tls: Option<NetProbeTls>,
  pub error: Option<NetProbeError>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeDns {
  pub ips: Vec<IpAddr>,
  pub elapsed_ms: u64,
  pub nameservers: Vec<String>,
  pub search: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeTcp {
  pub remote_addr: String,
  pub elapsed_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeHttp {
  pub status: u16,
  pub headers: BTreeMap<String, String>,
  pub egress: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeTls {
  pub verified: bool,
  pub verify_error: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  #[schemars(skip)]
  pub peer_der: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeError {
  pub kind: NetProbeErrorKind,
  pub message: String,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NetProbeErrorKind {
  DnsFailed,
  Blocked,
  Refused,
  Timeout,
  Unreachable,
  Tls,
  Other,
  Cancelled,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeCertificate {
  pub subject_cn: Option<String>,
  pub issuer: Option<String>,
  pub san: Vec<String>,
  pub not_after: DateTime<Utc>,
  pub days_left: i64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NetProbeReport {
  pub server: String,
  pub kind: NetProbeKind,
  pub target: String,
  pub ok: bool,
  pub reachable: bool,
  pub hint: Option<String>,
  pub certificate: Option<NetProbeCertificate>,
  #[serde(flatten)]
  pub result: NetProbeResult,
}

pub fn tcp_target(target: &str) -> Option<(&str, u16)> {
  let (host, port) = target.rsplit_once(':')?;
  if !port.bytes().all(|b| b.is_ascii_digit()) {
    return None;
  }
  let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
  let host =
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
      Some(ip) if ip.parse::<Ipv6Addr>().is_ok() => ip,
      _ if dns_target(host) && !host.contains(':') => host,
      _ => return None,
    };
  Some((host, port))
}

pub fn dns_target(host: &str) -> bool {
  host.parse::<IpAddr>().is_ok()
    || (!host.is_empty()
      && host.strip_suffix('.').unwrap_or(host).split('.').all(
        |label| {
          !label.is_empty()
            && label.bytes().all(|b| {
              b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
            })
        },
      ))
}

pub fn is_public(ip: IpAddr) -> bool {
  match ip.to_canonical() {
    IpAddr::V4(ip) => !matches!(
      ip.octets(),
      [0 | 10 | 127 | 224..=255, ..]
        | [100, 64..=127, ..]
        | [169, 254, ..]
        | [172, 16..=31, ..]
        | [192, 0, 0 | 2, _]
        | [192, 88, 99, _]
        | [192, 168, ..]
        | [198, 18 | 19, ..]
        | [198, 51, 100, _]
        | [203, 0, 113, _]
    ),
    IpAddr::V6(ip) => {
      matches!(ip.segments(), [0x2000..=0x3fff, ..])
        && !matches!(
          ip.segments(),
          [0x2001, 0..=0x01ff | 0x0db8, ..] | [0x2002 | 0x3fff, ..]
        )
    }
  }
}
