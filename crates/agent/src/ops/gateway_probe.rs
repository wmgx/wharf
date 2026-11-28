use std::{net::SocketAddr, time::Duration};

use reqwest::{Client, Url};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{GatewayProbeJob, GatewayProbeResult},
};

use crate::exec::Ctx;

fn result(
  stage: &str,
  status: Option<u16>,
  ok: bool,
  detail: &str,
) -> GatewayProbeResult {
  GatewayProbeResult {
    ok,
    stage: stage.into(),
    status,
    cert_pending: stage == "http_cert_pending",
    detail: detail.into(),
  }
}

fn hostname_valid(host: &str) -> bool {
  Url::parse(&format!("http://{host}"))
    .is_ok_and(|url| url.domain().is_some())
    && host.split('.').all(|label| {
      !label.is_empty()
        && label
          .bytes()
          .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn upstream_addr(upstream: &str) -> Result<Url, ApiError> {
  let invalid = || ApiError::invalid("网关探测上游须为主机:端口");
  if upstream.bytes().any(|b| b.is_ascii_whitespace())
    || upstream.contains(['/', '\\', '@', '#', '?', '%'])
  {
    return Err(invalid());
  }
  let (_, port) = upstream.rsplit_once(':').ok_or_else(invalid)?;
  if !port.parse::<u16>().is_ok_and(|port| port != 0) {
    return Err(invalid());
  }
  Url::parse(&format!("http://{upstream}")).map_err(|_| invalid())
}

fn tls_failed(e: &reqwest::Error) -> bool {
  let mut cause = std::error::Error::source(e);
  while let Some(error) = cause {
    let text = error.to_string().to_ascii_lowercase();
    if ["tls", "handshake", "certificate", "ssl", "eof"]
      .iter()
      .any(|s| text.contains(s))
    {
      return true;
    }
    cause = error.source();
  }
  false
}

async fn status(
  client: &Client,
  url: Url,
  host: &str,
) -> Result<u16, reqwest::Error> {
  client
    .get(url)
    .header("Host", host)
    .send()
    .await
    .map(|r| r.status().as_u16())
}

async fn probe(
  job: &GatewayProbeJob,
  upstream: Option<Url>,
) -> Result<GatewayProbeResult, ApiError> {
  let host = job.hostname.as_str();
  let bad_upstream =
    || result("upstream_unreachable", None, false, "网关连不上上游");
  if let Some(url) = &upstream {
    let target = (
      url.host_str().unwrap().trim_matches(['[', ']']),
      url.port_or_known_default().unwrap(),
    );
    if tokio::net::TcpStream::connect(target).await.is_err() {
      return Ok(bad_upstream());
    }
  }
  if job.upstream_only {
    return Ok(result("upstream_only", None, true, "上游 TCP 可达"));
  }
  let builder = || {
    Client::builder()
      .no_proxy()
      .redirect(reqwest::redirect::Policy::none())
      .user_agent("wharf-probe")
      .retry(reqwest::retry::never())
      .tls_danger_accept_invalid_certs(true)
  };
  let client = |port| {
    builder()
      .resolve(host, SocketAddr::from(([127, 0, 0, 1], port)))
      .build()
      .map_err(|_| ApiError::internal("无法创建网关探测客户端"))
  };
  let url = |tls| {
    let (scheme, port) = if tls {
      ("https", job.https_port)
    } else {
      ("http", job.http_port)
    };
    Url::parse(&format!("{scheme}://{host}:{port}{}", job.path))
      .map_err(|_| ApiError::invalid("网关探测地址无效"))
  };
  let port = if job.tls {
    job.https_port
  } else {
    job.http_port
  };
  let first = status(&client(port)?, url(job.tls)?, host).await;
  let (response, cert_pending) = match first {
    Err(error) if job.tls && tls_failed(&error) => (
      status(&client(job.http_port)?, url(false)?, host).await,
      true,
    ),
    other => (other, false),
  };
  let code = match response {
    Ok(code @ (502 | 504)) => {
      return Ok(result(
        "gateway_http_bad",
        Some(code),
        false,
        &format!("网关返回 HTTP {code}"),
      ));
    }
    Ok(code) => code,
    Err(_) => {
      return Ok(result(
        "gateway_unreachable",
        None,
        false,
        "无法连接本机网关",
      ));
    }
  };
  if cert_pending {
    if let Some(mut upstream) = upstream {
      upstream.set_path(&job.path);
      let upstream_client = builder()
        .build()
        .map_err(|_| ApiError::internal("无法创建上游探测客户端"))?;
      if !matches!(status(&upstream_client, upstream, host).await, Ok(n) if !matches!(n, 502 | 504))
      {
        return Ok(bad_upstream());
      }
    }
    return Ok(result(
      "http_cert_pending",
      Some(code),
      true,
      "证书待签发，上游 HTTP 可达",
    ));
  }
  Ok(result(
    if job.tls { "https" } else { "http" },
    Some(code),
    true,
    &format!("HTTP {code}"),
  ))
}

pub(super) async fn run(
  job: &GatewayProbeJob,
  ctx: &Ctx,
) -> Result<GatewayProbeResult, ApiError> {
  if !hostname_valid(&job.hostname)
    || !job.path.starts_with('/')
    || job.path.contains(['@', '\\', '?', '#'])
    || job.path.contains("..")
    || job.http_port == 0
    || job.https_port == 0
  {
    return Err(ApiError::invalid("网关探测目标无效"));
  }
  let upstream =
    job.upstream.as_deref().map(upstream_addr).transpose()?;
  let limit =
    Duration::from_secs(job.timeout_secs.clamp(2, 15).into());
  tokio::select! {
    biased;
    _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "网关探测已取消")),
    outcome = tokio::time::timeout(limit, probe(job, upstream)) => {
      outcome.unwrap_or_else(|_| Ok(result("gateway_unreachable", None, false, "网关探测超时")))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn pending_certificate_requires_a_working_http_upstream() {
    use tokio::{
      io::{AsyncReadExt, AsyncWriteExt},
      net::TcpListener,
    };

    let bind = || TcpListener::bind(("127.0.0.1", 0));
    let tls = bind().await.unwrap();
    let http = bind().await.unwrap();
    let upstream = bind().await.unwrap();
    let job = GatewayProbeJob {
      hostname: "probe.example.test".into(),
      path: "/".into(),
      tls: true,
      http_port: http.local_addr().unwrap().port(),
      https_port: tls.local_addr().unwrap().port(),
      upstream: Some(upstream.local_addr().unwrap().to_string()),
      upstream_only: false,
      timeout_secs: 5,
    };
    let tls_fail = async move {
      let (mut conn, _) = tls.accept().await.unwrap();
      let mut hello = [0; 4096];
      assert!(conn.read(&mut hello).await.unwrap() > 0);
      conn.shutdown().await.unwrap();
    };
    async fn respond(listener: TcpListener, response: &[u8]) {
      loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        if stream.read(&mut request).await.unwrap() > 0 {
          stream.write_all(response).await.unwrap();
          break;
        }
      }
    }
    let fixtures = tokio::spawn(async move {
      tokio::join!(
        tls_fail,
        respond(http, b"HTTP/1.1 308 Permanent Redirect\r\nContent-Length: 0\r\n\r\n"),
        respond(upstream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
      );
    });
    let result = run(&job, &Ctx::detached()).await.unwrap();
    fixtures.abort();
    assert!(result.ok && result.cert_pending, "{result:?}");
    assert_eq!(result.status, Some(308));
  }

  #[test]
  fn upstream_accepts_only_authority() {
    assert!(upstream_addr("100.64.0.2:80").is_ok());
    assert!(upstream_addr("s1:8080").is_ok());
    for input in ["s1", "s1:0", "s1:80/a", "a@s1:80", "s1\\a:80"] {
      assert!(upstream_addr(input).is_err(), "{input}");
    }
  }
}
