use reqwest::{Response, StatusCode, header::LOCATION};

/// 同时供 doctor、网关本机探测和 DNS 预验识别 Wharf 门禁响应。
pub async fn inspect(
  mut response: Response,
  gated: bool,
  read_body: bool,
) -> (StatusCode, bool, Vec<u8>) {
  let code = response.status();
  let login_redirect = code == StatusCode::FOUND
    && response
      .headers()
      .get(LOCATION)
      .and_then(|v| v.to_str().ok())
      .is_some_and(|v| v.contains("/gate/login"));
  let mut body = Vec::new();
  if (gated && code == StatusCode::UNAUTHORIZED) || read_body {
    while body.len() < 64 * 1024 {
      match response.chunk().await {
        Ok(Some(chunk)) => body.extend_from_slice(
          &chunk[..chunk.len().min(64 * 1024 - body.len())],
        ),
        _ => break,
      }
    }
  }
  let gate_rejected = login_redirect
    || (code == StatusCode::UNAUTHORIZED
      && String::from_utf8_lossy(&body).trim() == "需要登录");
  (code, gate_rejected, body)
}

pub fn tls_failed(error: &reqwest::Error) -> bool {
  let mut cause = std::error::Error::source(error);
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
