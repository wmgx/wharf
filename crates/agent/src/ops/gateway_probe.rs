use std::{net::SocketAddr, time::Duration};

use reqwest::{Client, StatusCode, Url};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{GatewayProbeJob, GatewayProbeResult, OneTimeSecret},
  gateway_http::{inspect, tls_failed},
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

async fn status(
  client: &Client,
  url: Url,
  host: &str,
  cookie: Option<&OneTimeSecret>,
) -> Result<(StatusCode, bool), reqwest::Error> {
  let mut request = client.get(url).header("Host", host);
  if let Some(cookie) = cookie {
    request = request.header(reqwest::header::COOKIE, &cookie.0);
  }
  let (code, rejected, _) =
    inspect(request.send().await?, cookie.is_some(), false).await;
  Ok((code, cookie.is_some() && rejected))
}

async fn probe(
  job: &GatewayProbeJob,
) -> Result<GatewayProbeResult, ApiError> {
  let host = job.hostname.as_str();
  let builder = || {
    Client::builder()
      .no_proxy()
      .redirect(reqwest::redirect::Policy::none())
      .user_agent("wharf-probe")
      .retry(reqwest::retry::never())
      .tls_danger_accept_invalid_certs(true)
  };
  let check_upstream = || async {
    if let Some(address) = &job.upstream {
      let mut upstream = upstream_addr(address)?;
      upstream.set_path(&job.path);
      let client = builder()
        .build()
        .map_err(|_| ApiError::internal("无法创建上游探测客户端"))?;
      return Ok::<_, ApiError>(matches!(
        status(&client, upstream, host, None).await,
        Ok((code, _)) if !code.is_server_error()
      ));
    }
    Ok(true)
  };
  if job.upstream_only {
    return Ok(result(
      "upstream_only",
      None,
      check_upstream().await?,
      "探测上游 HTTP",
    ));
  }
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
  let first = status(
    &client(port)?,
    url(job.tls)?,
    host,
    job.gate_cookie.as_ref(),
  )
  .await;
  let (response, cert_pending) = match first {
    Err(error)
      if job.tls && job.allow_pending_cert && tls_failed(&error) =>
    {
      (
        status(&client(job.http_port)?, url(false)?, host, None)
          .await,
        true,
      )
    }
    other => (other, false),
  };
  let code = match response {
    Ok((code, true)) => {
      return Ok(result(
        "gateway_auth_rejected",
        Some(code.as_u16()),
        false,
        "Wharf 门禁未放行探测请求",
      ));
    }
    Ok((code, _))
      if code.is_server_error()
        || cert_pending && !matches!(code.as_u16(), 301 | 308) =>
    {
      return Ok(result(
        "gateway_http_bad",
        Some(code.as_u16()),
        false,
        &format!("网关返回 HTTP {}", code.as_u16()),
      ));
    }
    Ok((code, _)) => code,
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
    if !check_upstream().await? {
      return Ok(result(
        "upstream_unreachable",
        None,
        false,
        "网关连不上上游 HTTP",
      ));
    }
    return Ok(result(
      "http_cert_pending",
      Some(code.as_u16()),
      true,
      "证书待签发，上游 HTTP 可达",
    ));
  }
  Ok(result(
    if job.tls { "https" } else { "http" },
    Some(code.as_u16()),
    true,
    &format!("HTTP {}", code.as_u16()),
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
  let limit =
    Duration::from_secs(job.timeout_secs.clamp(2, 15).into());
  tokio::select! {
    biased;
    _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "网关探测已取消")),
    outcome = tokio::time::timeout(limit, probe(job)) => {
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
    let mut job = GatewayProbeJob {
      hostname: "probe.example.test".into(),
      path: "/".into(),
      tls: true,
      allow_pending_cert: true,
      gate_cookie: None,
      http_port: http.local_addr().unwrap().port(),
      https_port: tls.local_addr().unwrap().port(),
      upstream: Some(upstream.local_addr().unwrap().to_string()),
      upstream_only: false,
      timeout_secs: 5,
    };
    let tls_fail = async move {
      for _ in 0..2 {
        let (mut conn, _) = tls.accept().await.unwrap();
        let mut header = [0; 5];
        conn.read_exact(&mut header).await.unwrap();
        let mut hello = vec![
          0;
          u16::from_be_bytes([header[3], header[4]])
            as usize
        ];
        conn.read_exact(&mut hello).await.unwrap();
        assert!(
          hello
            .windows(b"probe.example.test".len())
            .any(|bytes| bytes == b"probe.example.test")
        );
        conn.shutdown().await.unwrap();
      }
    };
    async fn respond(listener: TcpListener, response: &[u8]) {
      loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        if stream.read(&mut request).await.unwrap() > 0 {
          stream.write_all(response).await.unwrap();
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
    assert!(result.ok && result.cert_pending, "{result:?}");
    assert_eq!(result.status, Some(308));
    job.allow_pending_cert = false;
    let result = run(&job, &Ctx::detached()).await.unwrap();
    assert!(!result.ok && !result.cert_pending, "{result:?}");
    assert_eq!(result.stage, "gateway_unreachable");
    fixtures.abort();
  }

  #[tokio::test]
  async fn signed_gateway_probe_distinguishes_gate_denial_from_backend()
   {
    use tokio::{
      io::{AsyncReadExt, AsyncWriteExt},
      net::TcpListener,
    };

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let job = GatewayProbeJob {
      hostname: "probe.example.test".into(),
      path: "/".into(),
      tls: false,
      allow_pending_cert: false,
      gate_cookie: Some(OneTimeSecret("wharf_gate=fixture".into())),
      http_port: listener.local_addr().unwrap().port(),
      https_port: 443,
      upstream: None,
      upstream_only: false,
      timeout_secs: 2,
    };
    let replies = [
      (401, "需要登录\n", false),
      (401, "backend", true),
      (403, "backend", true),
      (500, "", false),
      (502, "", false),
      (504, "", false),
    ];
    let server = tokio::spawn(async move {
      for (code, body, _) in replies {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
          request.push(stream.read_u8().await.unwrap());
        }
        let request =
          String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.contains("\r\nhost: probe.example.test\r\n"));
        let (code, body) =
          if request.contains("\r\ncookie: wharf_gate=fixture\r\n") {
            (code, body)
          } else {
            (302, "")
          };
        stream.write_all(format!("HTTP/1.1 {code} Fixture\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
      }
    });
    for (code, _, ok) in replies {
      let result = run(&job, &Ctx::detached()).await.unwrap();
      assert_eq!(
        (result.status, result.ok),
        (Some(code), ok),
        "{result:?}"
      );
    }
    server.await.unwrap();
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
