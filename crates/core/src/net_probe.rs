use std::{
  collections::{HashMap, VecDeque},
  net::IpAddr,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Extension, Json,
  extract::{Path, State},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use reqwest::Url;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, NetProbeJob, NetProbeResult},
  net_probe::{
    NetProbeCertificate, NetProbeErrorKind, NetProbeKind,
    NetProbeReport, NetProbeRequest, dns_target, is_public,
    tcp_target,
  },
  view::Perm,
};

use crate::{
  api::ApiResult, audit::AuditSlot, auth::Auth, snapshot,
  state::AppState,
};

const WINDOW: Duration = Duration::from_secs(60);
static LIMITS: LazyLock<Mutex<HashMap<String, Limit>>> =
  LazyLock::new(Default::default);

struct Limit {
  permits: Arc<Semaphore>,
  starts: VecDeque<Instant>,
}

fn reserve(server: &str) -> Result<OwnedSemaphorePermit, ApiError> {
  let mut limits = LIMITS.lock().unwrap_or_else(|e| e.into_inner());
  let now = Instant::now();
  limits.retain(|_, limit| {
    limit.permits.available_permits() < 2
      || limit
        .starts
        .back()
        .is_some_and(|&t| now.duration_since(t) < WINDOW)
  });
  let limit =
    limits.entry(server.to_string()).or_insert_with(|| Limit {
      permits: Arc::new(Semaphore::new(2)),
      starts: VecDeque::new(),
    });
  let permit =
    limit.permits.clone().try_acquire_owned().map_err(|_| {
      ApiError::new(
        ErrorCode::Conflict,
        "这台机器上已经有 2 个探测在跑，稍后再试",
      )
    })?;
  while limit
    .starts
    .front()
    .is_some_and(|&t| now.duration_since(t) >= WINDOW)
  {
    limit.starts.pop_front();
  }
  if limit.starts.len() >= 30
    && let Some(&first) = limit.starts.front()
  {
    let wait = (WINDOW - now.duration_since(first))
      .as_secs_f64()
      .ceil() as u64;
    return Err(ApiError::new(
      ErrorCode::Conflict,
      format!("这台机器每分钟最多探测 30 次，{wait} 秒后再试"),
    ));
  }
  limit.starts.push_back(now);
  Ok(permit)
}

pub(crate) fn unsupported(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，不支持探测"),
  )
  .with_hint("运行 wharf upgrade")
}

pub async fn probe(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Json(request): Json<NetProbeRequest>,
) -> ApiResult<NetProbeReport> {
  auth.require(Perm::Plan)?;
  let (job, url) = prepare(request)?;
  let target = match &url {
    Some(url) => {
      let mut url = url.clone();
      url.set_query(None);
      url.to_string()
    }
    None => job.target.clone(),
  };
  let kind = job.kind;
  audit.set_detail(format!("{} {target}", kind.as_str()));

  let snapshot = snapshot::load(&state.db).await?;
  let row = snapshot
    .world
    .servers
    .get(&server)
    .ok_or_else(|| crate::world::server_not_found(&server))?;
  let has_egress = crate::egress::via(&row.settings).is_some();
  state.hub.supports_net_probe(&server)?;
  let _permit = reserve(&server)?;
  let timeout = Duration::from_secs(u64::from(job.timeout_secs) + 5);
  let egress = job.egress;
  let mut result: NetProbeResult = state
    .hub
    .call(
      &server,
      AgentOp::NetProbe(job),
      timeout,
      None,
      &CancellationToken::new(),
    )
    .await?;

  let host = url
    .as_ref()
    .and_then(Url::host_str)
    .unwrap_or_default()
    .trim_matches(['[', ']']);
  let certificate = result
    .tls
    .as_mut()
    .and_then(|t| t.peer_der.take())
    .and_then(|b64| STANDARD.decode(b64).ok())
    .and_then(|der| crate::cert::probe_info(&der, host, Utc::now()));
  let https = url.as_ref().is_some_and(|u| u.scheme() == "https");
  let (ok, reachable, hint) = conclude(
    kind,
    https,
    &result,
    certificate.as_ref(),
    host,
    egress,
    has_egress,
  );
  Ok(Json(NetProbeReport {
    server,
    kind,
    target,
    ok,
    reachable,
    hint,
    certificate: certificate.map(|(info, _)| info),
    result,
  }))
}

fn prepare(
  request: NetProbeRequest,
) -> Result<(NetProbeJob, Option<Url>), ApiError> {
  let target = request.target;
  if target.len() > 2048 {
    return Err(ApiError::invalid("探测目标不能超过 2048 字节"));
  }
  if target.is_empty()
    || target.contains('\\')
    || target.chars().any(char::is_whitespace)
    || target.chars().any(char::is_control)
  {
    return Err(ApiError::invalid("无效的探测目标"));
  }
  let kind = request.kind.unwrap_or_else(|| {
    if target.starts_with("http://") || target.starts_with("https://")
    {
      NetProbeKind::Http
    } else if target.contains(':')
      && target.parse::<IpAddr>().is_err()
    {
      NetProbeKind::Tcp
    } else {
      NetProbeKind::Dns
    }
  });
  let egress = request.egress.unwrap_or(false);
  if egress && kind != NetProbeKind::Http {
    return Err(ApiError::invalid("只有 HTTP 探测可以使用 --egress"));
  }
  let url = match kind {
    NetProbeKind::Http => Some(http_url(&target, egress)?),
    NetProbeKind::Tcp if tcp_target(&target).is_none() => {
      return Err(ApiError::invalid(
        "TCP 目标应为主机:端口或 [IPv6]:端口，端口范围 1–65535",
      ));
    }
    NetProbeKind::Dns if !dns_target(&target) => {
      return Err(ApiError::invalid("DNS 目标应为域名或 IP 地址"));
    }
    _ => None,
  };
  let timeout_secs = request
    .timeout_secs
    .unwrap_or(match kind {
      NetProbeKind::Http => 10,
      _ => 5,
    })
    .clamp(1, 30);
  Ok((
    NetProbeJob {
      kind,
      target,
      timeout_secs,
      egress,
    },
    url,
  ))
}

fn http_url(target: &str, egress: bool) -> Result<Url, ApiError> {
  let invalid = || {
    ApiError::invalid(
      "HTTP 目标应为 http:// 或 https:// URL，端口范围 1–65535",
    )
  };
  let (scheme, rest) =
    target.split_once("://").ok_or_else(invalid)?;
  let authority =
    rest.split(['/', '?', '#']).next().unwrap_or_default();
  if !matches!(scheme, "http" | "https")
    || authority.is_empty()
    || authority.ends_with(':')
  {
    return Err(invalid());
  }
  let mut url = Url::parse(target).map_err(|_| invalid())?;
  let host = url.host_str().ok_or_else(invalid)?;
  if url.port() == Some(0) {
    return Err(invalid());
  }
  if authority.contains('@')
    || !url.username().is_empty()
    || url.password().is_some()
  {
    return Err(ApiError::invalid("探测 URL 不能包含用户凭据"));
  }
  if egress
    && host
      .trim_matches(['[', ']'])
      .parse::<IpAddr>()
      .is_ok_and(|ip| !is_public(ip))
  {
    return Err(ApiError::invalid("出口代理只用来测外网"));
  }
  url.set_fragment(None);
  Ok(url)
}

fn suspicious_dns_ip(ips: &[IpAddr]) -> Option<IpAddr> {
  if !ips.iter().copied().any(is_public) {
    return None;
  }
  let has_public_v4 = ips
    .iter()
    .any(|&ip| ip.to_canonical().is_ipv4() && is_public(ip));
  ips.iter().copied().find(|&ip| {
    matches!(ip.to_canonical(), IpAddr::V6(v6)
      if (!v6.is_loopback() || has_public_v4) && !is_public(ip))
  })
}

fn conclude(
  kind: NetProbeKind,
  https: bool,
  result: &NetProbeResult,
  certificate: Option<&(NetProbeCertificate, bool)>,
  host: &str,
  egress: bool,
  has_egress: bool,
) -> (bool, bool, Option<String>) {
  let reachable = match kind {
    NetProbeKind::Dns => {
      result.dns.as_ref().is_some_and(|dns| !dns.ips.is_empty())
    }
    NetProbeKind::Tcp => result.tcp.is_some(),
    NetProbeKind::Http => result.http.is_some(),
  };
  let ok = match kind {
    NetProbeKind::Http => result.http.as_ref().is_some_and(|http| {
      http.status < 500
        && (!https
          || result.tls.as_ref().is_some_and(|tls| tls.verified))
    }),
    _ => reachable && result.error.is_none(),
  };
  let suspicious_ip = result
    .dns
    .as_ref()
    .filter(|_| !egress)
    .and_then(|dns| suspicious_dns_ip(&dns.ips));
  let can_try_egress = has_egress && !egress;
  let mut hint = result.error.as_ref().and_then(|error| match error.kind {
    NetProbeErrorKind::Blocked if error.message == "出口代理只用来测外网" => {
      Some(error.message.clone())
    }
    NetProbeErrorKind::Blocked => Some("目标属于云厂商元数据或链路本地地址，不允许探测".into()),
    NetProbeErrorKind::Tls if certificate.is_none() && result.http.is_none() => {
      let message = if host.parse::<IpAddr>().is_ok() {
        "对方拒绝了 TLS 握手：用 IP 访问时网关没有对应证书，改用域名再测"
      } else {
        "对方拒绝了 TLS 握手，证书没拿到"
      };
      Some(message.into())
    }
    NetProbeErrorKind::Tls => certificate.map(|(cert, matches_host)| {
      let mut hint = format!(
        "证书校验未通过（{}）；对方证书 CN={}，SAN={}，到期 {}（剩 {} 天）",
        error.message, cert.subject_cn.as_deref().unwrap_or("—"), cert.san.join("、"),
        cert.not_after.format("%Y-%m-%d"), cert.days_left,
      );
      if !matches_host {
        hint.push_str(&format!("；证书不包含 {host}"));
      }
      hint
    }),
    NetProbeErrorKind::Timeout if can_try_egress && kind == NetProbeKind::Http && suspicious_ip.is_none() => {
      Some("直连超时；这台机器配了外网出口，可加 --egress 再测".into())
    }
    NetProbeErrorKind::Refused if !error.message.starts_with("这台机器没有开外网出口") => {
      Some("端口没有程序在听，或被防火墙拒绝".into())
    }
    _ => None,
  });
  if let Some(ip) = suspicious_ip {
    let hint = hint.get_or_insert_with(String::new);
    if !hint.is_empty() {
      hint.push('。');
    }
    hint.push_str(&format!(
      "解析结果里有疑似被污染的地址（{ip}），这台机器的 DNS 可能被干扰"
    ));
    if can_try_egress {
      hint.push_str("；海外站点可加 --egress 再测");
    }
  }
  (ok, reachable, hint)
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::net_probe::{
    NetProbeError, NetProbeHttp, NetProbeTls,
  };

  fn request(target: &str, egress: bool) -> NetProbeRequest {
    NetProbeRequest {
      target: target.into(),
      kind: None,
      timeout_secs: None,
      egress: Some(egress),
    }
  }

  #[test]
  fn infers_kind_and_validates_target() {
    for (target, kind) in [
      ("https://a.com/x", NetProbeKind::Http),
      ("100.126.247.71:3773", NetProbeKind::Tcp),
      ("[::1]:80", NetProbeKind::Tcp),
      ("a.com", NetProbeKind::Dns),
      ("::1", NetProbeKind::Dns),
    ] {
      assert_eq!(
        prepare(request(target, false)).unwrap().0.kind,
        kind
      );
    }
    for target in [
      "ftp://a.com",
      "https://u:p@a.com",
      "a.com:0",
      "https://a.com:65536",
    ] {
      assert_eq!(
        prepare(request(target, false)).unwrap_err().code,
        ErrorCode::InvalidInput
      );
    }
  }

  #[test]
  fn limits_egress_to_public_http_targets() {
    assert!(prepare(request("https://192.168.31.1", true)).is_err());
    assert!(prepare(request("https://api.github.com", true)).is_ok());
    assert!(prepare(request("a.com:80", true)).is_err());
  }

  #[test]
  fn detects_suspicious_dns_answers() {
    let mixed = ["142.251.157.119", "2001::1"]
      .map(|ip| ip.parse::<IpAddr>().unwrap());
    assert_eq!(suspicious_dns_ip(&mixed), Some(mixed[1]));
    let public = ["20.205.243.168".parse::<IpAddr>().unwrap()];
    assert_eq!(suspicious_dns_ip(&public), None);
  }

  #[test]
  fn explains_rejected_tls_handshake_without_certificate() {
    let result = NetProbeResult {
      error: Some(NetProbeError {
        kind: NetProbeErrorKind::Tls,
        message: "received fatal alert: HandshakeFailure".into(),
      }),
      ..Default::default()
    };
    for (host, expected) in [
      (
        "192.168.31.1",
        "对方拒绝了 TLS 握手：用 IP 访问时网关没有对应证书，改用域名再测",
      ),
      ("a.com", "对方拒绝了 TLS 握手，证书没拿到"),
    ] {
      let (_, _, hint) = conclude(
        NetProbeKind::Http,
        true,
        &result,
        None,
        host,
        false,
        false,
      );
      assert_eq!(hint.as_deref(), Some(expected));
    }
  }

  #[test]
  fn distinguishes_success_from_reachability() {
    let mut result = NetProbeResult {
      http: Some(NetProbeHttp {
        status: 200,
        headers: Default::default(),
        egress: false,
      }),
      tls: Some(NetProbeTls {
        verified: true,
        verify_error: None,
        peer_der: None,
      }),
      ..Default::default()
    };
    let http = |r: &NetProbeResult| {
      conclude(
        NetProbeKind::Http,
        true,
        r,
        None,
        "a.com",
        false,
        false,
      )
    };
    assert_eq!(http(&result), (true, true, None));
    result.tls.as_mut().unwrap().verified = false;
    assert_eq!(http(&result), (false, true, None));
    result.tls.as_mut().unwrap().verified = true;
    result.http.as_mut().unwrap().status = 502;
    assert_eq!(http(&result), (false, true, None));
    let refused = NetProbeResult {
      error: Some(NetProbeError {
        kind: NetProbeErrorKind::Refused,
        message: "Connection refused".into(),
      }),
      ..Default::default()
    };
    let (ok, reachable, hint) = conclude(
      NetProbeKind::Tcp,
      false,
      &refused,
      None,
      "a.com",
      false,
      false,
    );
    assert!(!ok && !reachable);
    assert_eq!(
      hint.as_deref(),
      Some("端口没有程序在听，或被防火墙拒绝")
    );
  }
}
