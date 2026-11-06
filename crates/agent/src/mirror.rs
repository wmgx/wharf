//! `wharf-agent mirror`：镜像仓库和 GitHub 的反向代理，部署在海外机器上，前面挂 HTTPS 网关。
//!
//! 按请求域名的第一段选上游，换机器、换根域名都不用改配置：
//! - `ghcr.*` → ghcr.io，`docker.*` → Docker Hub：只转发拉取（GET / HEAD）；
//!   上游要的 token 由这里匿名去换，镜像层的跳转（到 CDN）也在这里跟随，客户端只连这一个地址；
//! - `github.*` → github.com：转发 git 的 HTTP 请求（clone、fetch、ls-remote）。
//!
//! 认证：路径第一段是访问口令（`MIRROR_TOKEN`），不对时一律 404。
//! 镜像源写成 `ghcr.<域名>/<口令>`，`docker pull ghcr.<域名>/<口令>/owner/image` 就能用，不用 `docker login`。
//! 不做缓存。

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use anyhow::Context;
use axum::{
  Router,
  body::{Body, Bytes},
  extract::State,
  http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
  response::{IntoResponse, Response},
};

/// git 的请求体（要的对象列表）通常很小；给足余量。
const MAX_BODY: usize = 64 << 20;
const TOKEN_TTL: Duration = Duration::from_secs(50);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
  Registry,
  Git,
}

fn upstream(host: &str) -> Option<(&'static str, Kind)> {
  let first = host.split('.').next()?;
  Some(match first {
    "ghcr" => ("https://ghcr.io", Kind::Registry),
    "docker" => ("https://registry-1.docker.io", Kind::Registry),
    "github" => ("https://github.com", Kind::Git),
    _ => return None,
  })
}

struct Mirror {
  token: String,
  client: reqwest::Client,
  /// 上游 token：`上游 + 仓库` → (token, 换到的时间)。
  tokens: Mutex<HashMap<String, (String, Instant)>>,
}

pub async fn run(listen: &str) -> anyhow::Result<()> {
  let token = std::env::var("MIRROR_TOKEN").unwrap_or_default();
  anyhow::ensure!(
    token.len() >= 16,
    "MIRROR_TOKEN 没设或太短（至少 16 个字符）"
  );
  let client = reqwest::Client::builder()
    .connect_timeout(Duration::from_secs(15))
    .read_timeout(Duration::from_secs(120))
    .build()?;
  let state = Arc::new(Mirror {
    token,
    client,
    tokens: Mutex::new(HashMap::new()),
  });
  let app = Router::new().fallback(handle).with_state(state);
  let listener = tokio::net::TcpListener::bind(listen)
    .await
    .with_context(|| format!("监听 {listen}"))?;
  tracing::info!("mirror 已启动，监听 {listen}");
  axum::serve(listener, app).await?;
  Ok(())
}

/// 比较口令，耗时和内容无关。
fn same(a: &str, b: &str) -> bool {
  a.len() == b.len()
    && a
      .bytes()
      .zip(b.bytes())
      .fold(0u8, |acc, (x, y)| acc | (x ^ y))
      == 0
}

/// 去掉口令后的上游路径。口令不对返回 `None`。
fn strip_token<'a>(
  path: &'a str,
  kind: Kind,
  token: &str,
) -> Option<&'a str> {
  let rest = match kind {
    Kind::Registry => path.strip_prefix("/v2/")?,
    Kind::Git => path.strip_prefix('/')?,
  };
  let (given, rest) = rest.split_once('/')?;
  same(given, token).then_some(rest)
}

/// 仓库名：`owner/image/manifests/tag` → `owner/image`。
fn repository(rest: &str) -> &str {
  ["/manifests/", "/blobs/", "/tags/"]
    .iter()
    .find_map(|m| rest.find(m).map(|i| &rest[..i]))
    .unwrap_or(rest)
}

fn not_found() -> Response {
  StatusCode::NOT_FOUND.into_response()
}

async fn handle(
  State(m): State<Arc<Mirror>>,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Body,
) -> Response {
  let host = headers
    .get(header::HOST)
    .and_then(|h| h.to_str().ok())
    .unwrap_or_default();
  let Some((base, kind)) = upstream(host) else {
    return not_found();
  };
  let path = uri.path();
  // 客户端先探一下 /v2/：直接说支持，不要求登录（口令在后面的路径里）。
  if kind == Kind::Registry && (path == "/v2/" || path == "/v2") {
    return (
      [("Docker-Distribution-API-Version", "registry/2.0")],
      "{}",
    )
      .into_response();
  }
  let Some(rest) = strip_token(path, kind, &m.token) else {
    return not_found();
  };
  let query =
    uri.query().map(|q| format!("?{q}")).unwrap_or_default();
  let url = match kind {
    Kind::Registry => format!("{base}/v2/{rest}{query}"),
    Kind::Git => format!("{base}/{rest}{query}"),
  };
  let result = match kind {
    Kind::Registry => {
      if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
      }
      registry(&m, base, repository(rest), method, &url, &headers)
        .await
    }
    Kind::Git => git(&m, method, &url, &headers, body).await,
  };
  match result {
    Ok(resp) => {
      tracing::info!(
        "{host} {} → {}",
        rest_for_log(rest),
        resp.status()
      );
      relay(resp)
    }
    Err(e) => {
      tracing::warn!("{host} {} 失败：{e}", rest_for_log(rest));
      (StatusCode::BAD_GATEWAY, e).into_response()
    }
  }
}

fn rest_for_log(rest: &str) -> &str {
  rest.split('?').next().unwrap_or(rest)
}

fn copy(
  from: &HeaderMap,
  names: &[header::HeaderName],
  mut req: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
  for name in names {
    for v in from.get_all(name) {
      req = req.header(name, v);
    }
  }
  req
}

async fn registry(
  m: &Mirror,
  base: &str,
  repo: &str,
  method: Method,
  url: &str,
  headers: &HeaderMap,
) -> Result<reqwest::Response, String> {
  let key = format!("{base} {repo}");
  let cached = m
    .tokens
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .get(&key)
    .filter(|(_, at)| at.elapsed() < TOKEN_TTL)
    .map(|(t, _)| t.clone());
  let send = |token: Option<&str>| {
    let mut req = copy(
      headers,
      &[header::ACCEPT, header::RANGE],
      m.client.request(method.clone(), url),
    );
    if let Some(t) = token {
      req = req.bearer_auth(t);
    }
    req.send()
  };
  let resp = send(cached.as_deref())
    .await
    .map_err(|e| e.without_url().to_string())?;
  if resp.status() != StatusCode::UNAUTHORIZED {
    return Ok(resp);
  }
  let challenge = resp
    .headers()
    .get(header::WWW_AUTHENTICATE)
    .and_then(|v| v.to_str().ok())
    .unwrap_or_default()
    .to_string();
  let token = crate::registry::token(&m.client, &challenge).await?;
  m.tokens
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(key, (token.clone(), Instant::now()));
  send(Some(&token))
    .await
    .map_err(|e| e.without_url().to_string())
}

async fn git(
  m: &Mirror,
  method: Method,
  url: &str,
  headers: &HeaderMap,
  body: Body,
) -> Result<reqwest::Response, String> {
  let body: Bytes = axum::body::to_bytes(body, MAX_BODY)
    .await
    .map_err(|e| format!("读请求体失败：{e}"))?;
  let req = copy(
    headers,
    &[
      header::ACCEPT,
      header::CONTENT_TYPE,
      header::CONTENT_ENCODING,
      header::AUTHORIZATION,
      header::USER_AGENT,
      header::HeaderName::from_static("git-protocol"),
    ],
    m.client.request(method, url),
  );
  req
    .body(body)
    .send()
    .await
    .map_err(|e| e.without_url().to_string())
}

/// 上游的回复原样流回去，只带客户端用得到的头。
fn relay(resp: reqwest::Response) -> Response {
  const KEEP: [&str; 8] = [
    "content-type",
    "content-length",
    "content-encoding",
    "content-range",
    "accept-ranges",
    "etag",
    "docker-content-digest",
    "docker-distribution-api-version",
  ];
  let status = resp.status();
  let mut out = Response::builder().status(status.as_u16());
  for (name, value) in resp.headers() {
    if KEEP.contains(&name.as_str()) {
      out = out.header(name.as_str(), value.as_bytes());
    }
  }
  if status == StatusCode::UNAUTHORIZED {
    // 私有仓库：git 收到这个才会带上凭据重试。
    if let Some(v) = resp.headers().get(header::WWW_AUTHENTICATE)
      && v.as_bytes().starts_with(b"Basic")
    {
      out = out.header(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"GitHub\""),
      );
    }
  }
  out
    .body(Body::from_stream(resp.bytes_stream()))
    .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn routes_and_token() {
    assert_eq!(
      upstream("ghcr.wmgx.top").unwrap().0,
      "https://ghcr.io"
    );
    assert_eq!(upstream("github.example.com").unwrap().1, Kind::Git);
    assert!(upstream("evil.wmgx.top").is_none());
    let t = "0123456789abcdef";
    assert_eq!(
      strip_token(
        "/v2/0123456789abcdef/wmgx/wharf-core/manifests/latest",
        Kind::Registry,
        t
      ),
      Some("wmgx/wharf-core/manifests/latest")
    );
    assert_eq!(
      strip_token(
        "/v2/wrong/wmgx/x/manifests/latest",
        Kind::Registry,
        t
      ),
      None
    );
    assert_eq!(
      strip_token(
        "/0123456789abcdef/o/r.git/info/refs",
        Kind::Git,
        t
      ),
      Some("o/r.git/info/refs")
    );
    assert_eq!(
      repository("library/nginx/blobs/sha256:ab"),
      "library/nginx"
    );
  }
}
