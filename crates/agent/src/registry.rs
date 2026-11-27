//! 查镜像标签当前对应的 digest 和平台，只读清单和镜像配置，不拉镜像层。
//! 按镜像源顺序尝试（和拉取一样），匿名 token；要登录的私有仓库查不到。

use std::time::Duration;

use reqwest::{StatusCode, header};
use serde_json::Value;
use tokio::time::Instant;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{PullPolicy, ResolveImages, ResolvedImage},
};

use crate::{docker::split_image, exec::Ctx};

/// 每次 registry 请求的超时。
const ATTEMPT: Duration = Duration::from_secs(20);
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// 多架构镜像返回索引的 digest，和 `docker pull` 记下的一致。
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
  application/vnd.docker.distribution.manifest.list.v2+json, \
  application/vnd.docker.distribution.manifest.v2+json, \
  application/vnd.oci.image.manifest.v1+json";

/// 镜像源直连；原仓库和 dockerd 拉镜像一样走代理（经出口时是本机的分流代理）。
struct Clients {
  direct: reqwest::Client,
  proxy: Option<reqwest::Client>,
}

impl Clients {
  fn repo(&self, mirror: bool, host: &str, path: &str) -> Repo<'_> {
    let proxy = self.proxy.as_ref().filter(|_| !mirror);
    Repo::new(
      proxy.unwrap_or(&self.direct),
      proxy.is_some(),
      host,
      path,
    )
  }
}

fn client(proxy: Option<&str>) -> Result<reqwest::Client, ApiError> {
  let proxied = proxy.is_some();
  let mut b = reqwest::Client::builder().timeout(ATTEMPT).redirect(
    reqwest::redirect::Policy::custom(move |attempt| {
      if attempt.previous().len() >= 10 {
        return attempt.error("仓库重定向次数过多");
      }
      if attempt
        .previous()
        .first()
        .is_some_and(|url| url.path().ends_with("/tags/list"))
      {
        return attempt.stop();
      }
      if proxied
        && validate_realm_url(attempt.url().as_str(), None).is_err()
      {
        return attempt.error(realm_denied());
      }
      attempt.follow()
    }),
  );
  if let Some(p) = proxy {
    b = b.proxy(
      reqwest::Proxy::all(p)
        .map_err(|e| ApiError::invalid(e.to_string()))?,
    );
  }
  b.build().map_err(|e| ApiError::internal(e.to_string()))
}

pub async fn resolve(
  job: &ResolveImages,
  ctx: &Ctx,
) -> Result<Vec<ResolvedImage>, ApiError> {
  let proxy = crate::build::usable_proxy(
    job.pull.registry_proxy.as_deref(),
    ctx,
  )
  .await;
  let clients = Clients {
    direct: client(None)?,
    proxy: proxy
      .as_deref()
      .map(|proxy| client(Some(proxy)))
      .transpose()?,
  };
  // 各镜像同时查，一台机器镜像多、出口慢时不会排队超时。
  let all = futures_util::future::join_all(
    job.images.iter().map(|image| one(&clients, image, job)),
  );
  tokio::select! {
    out = all => Ok(out),
    _ = ctx.cancel.cancelled() => {
      Err(ApiError::new(ErrorCode::Cancelled, "查询镜像版本已取消"))
    }
  }
}

async fn one(
  clients: &Clients,
  image: &str,
  job: &ResolveImages,
) -> ResolvedImage {
  let host_platform = format!("{}/{}", std::env::consts::OS, arch());
  let result =
    resolve_one(clients, image, &job.pull, &host_platform).await;
  let newer_tags = if job.tags {
    tokio::time::timeout(
      TAGS_LIMIT,
      newer_tags(clients, image, &job.pull),
    )
    .await
    .unwrap_or_default()
  } else {
    vec![]
  };
  match result {
    Ok((digest, config, platforms)) => ResolvedImage {
      image: image.to_string(),
      digest: Some(digest),
      config,
      platforms,
      host_platform: Some(host_platform),
      error: None,
      newer_tags,
    },
    Err(e) => ResolvedImage {
      image: image.to_string(),
      digest: None,
      config: None,
      platforms: None,
      host_platform: Some(host_platform),
      error: Some(e),
      newer_tags,
    },
  }
}

/// (清单 digest, 本机平台的镜像 ID, 镜像支持的平台)。
type Found = (String, Option<String>, Option<Vec<String>>);

async fn resolve_one(
  clients: &Clients,
  image: &str,
  policy: &PullPolicy,
  host_platform: &str,
) -> Result<Found, String> {
  // 元数据是补充信息，给控制面的 60 秒调用上限留出余量。
  let metadata_deadline = Instant::now() + ATTEMPT * 2;
  let (registry, path, suffix) = split_image(image);
  let reference = suffix
    .strip_prefix('@')
    .or_else(|| suffix.strip_prefix(':'))
    .unwrap_or("latest")
    .to_string();
  let mut errors = Vec::new();
  let mut best = None;
  for (host, mirror) in hosts(&registry, policy) {
    let mut repo = clients.repo(mirror, &host, &path);
    match repo.head(&reference).await {
      Ok(digest) => {
        let (config, platforms) = repo
          .details(&digest, host_platform, metadata_deadline)
          .await;
        if platforms.is_some() {
          return Ok((digest, config, platforms));
        }
        if best
          .as_ref()
          .is_none_or(|(_, prior, _): &Found| prior.is_none())
        {
          best = Some((digest, config, platforms));
        }
      }
      Err(e) => errors.push(policy.redact(&format!("{host}：{e}"))),
    }
  }
  best.ok_or_else(|| errors.join("；"))
}

/// 按镜像源顺序要试的仓库地址，和拉取一样：（地址，是不是镜像源）。
fn hosts(registry: &str, policy: &PullPolicy) -> Vec<(String, bool)> {
  let mut hosts: Vec<(String, bool)> = policy
    .mirrors
    .get(registry)
    .into_iter()
    .flatten()
    .map(|h| (h.clone(), true))
    .collect();
  if hosts.is_empty() || !policy.mirrors_only {
    hosts.push((registry_host(registry).to_string(), false));
  }
  hosts
}

/// 列一个镜像的标签最多花多久，超时就当没有更高版本，不影响查 digest。
const TAGS_LIMIT: Duration = Duration::from_secs(30);
/// 最多翻几页标签列表（每页 1000 个）。
const TAG_PAGES: usize = 20;

/// 仓库里比现在的标签更高的版本：同一大版本里最高的，和更高大版本里最高的。
/// 只认和现在的标签写法一样的（数字段数、`v` 前缀、后缀都相同），例如 `2.20` 只和 `2.21` 比，
/// 不和 `2.21.0`、`2.21-rc1` 比。查不到就是空的。
async fn newer_tags(
  clients: &Clients,
  image: &str,
  policy: &PullPolicy,
) -> Vec<String> {
  let (registry, path, suffix) = split_image(image);
  let Some(current) =
    suffix.strip_prefix(':').and_then(Version::parse)
  else {
    return vec![];
  };
  for (host, mirror) in hosts(&registry, policy) {
    let mut repo = clients.repo(mirror, &host, &path);
    if let Ok(tags) = repo.tags().await {
      return pick(&current, &tags);
    }
  }
  vec![]
}

fn pick(current: &Version, tags: &[String]) -> Vec<String> {
  let mut same: Option<(Version, &String)> = None;
  let mut major: Option<(Version, &String)> = None;
  for tag in tags {
    let Some(v) = Version::parse(tag) else {
      continue;
    };
    if !v.like(current) || v.nums <= current.nums {
      continue;
    }
    let slot = if v.nums[0] == current.nums[0] {
      &mut same
    } else {
      &mut major
    };
    if slot.as_ref().is_none_or(|(best, _)| v.nums > best.nums) {
      *slot = Some((v, tag));
    }
  }
  same
    .into_iter()
    .chain(major)
    .map(|(_, t)| t.clone())
    .collect()
}

/// 标签里的版本号：`v` 前缀 + 点分数字 + 后缀（例如 `-alpine`）。
#[derive(Debug)]
struct Version {
  v: bool,
  nums: Vec<u64>,
  rest: String,
}

impl Version {
  fn parse(tag: &str) -> Option<Self> {
    let (v, t) = match tag.strip_prefix('v') {
      Some(t) => (true, t),
      None => (false, tag),
    };
    let end = t
      .find(|c: char| !c.is_ascii_digit() && c != '.')
      .unwrap_or(t.len());
    let (head, rest) = t.split_at(end);
    let nums = head
      .split('.')
      .map(|n| n.parse().ok())
      .collect::<Option<Vec<u64>>>()?;
    Some(Self {
      v,
      nums,
      rest: rest.to_string(),
    })
  }

  fn like(&self, other: &Self) -> bool {
    self.v == other.v
      && self.nums.len() == other.nums.len()
      && self.rest == other.rest
  }
}

fn registry_host(registry: &str) -> &str {
  if registry == "docker.io" {
    "registry-1.docker.io"
  } else {
    registry
  }
}

struct Repo<'a> {
  client: &'a reqwest::Client,
  proxied: bool,
  /// `https://host`
  origin: String,
  base: String,
  path: String,
  token: Option<String>,
}

impl<'a> Repo<'a> {
  fn new(
    client: &'a reqwest::Client,
    proxied: bool,
    host: &str,
    path: &str,
  ) -> Self {
    let scheme = if host.starts_with("127.0.0.1:")
      || host.starts_with("localhost:")
    {
      "http"
    } else {
      "https"
    };
    let host = host.trim_end_matches('/');
    let (authority, prefix) =
      host.split_once('/').unwrap_or((host, ""));
    let origin = format!("{scheme}://{authority}");
    let base = if prefix.is_empty() {
      format!("{origin}/v2/{path}")
    } else {
      format!("{origin}/v2/{prefix}/{path}")
    };
    Self {
      client,
      proxied,
      base,
      path: path.to_string(),
      origin,
      token: None,
    }
  }

  /// 全部标签，按 `Link` 翻页。
  async fn tags(&mut self) -> Result<Vec<String>, String> {
    let mut url = format!("{}/tags/list?n=1000", self.base);
    let mut out = Vec::new();
    for _ in 0..TAG_PAGES {
      let resp = self.send(&url, false).await?;
      let next = resp
        .headers()
        .get(header::LINK)
        .and_then(|v| v.to_str().ok())
        .filter(|l| l.contains("rel=\"next\""))
        .and_then(|l| l.split_once('<')?.1.split_once('>'))
        .map(|(u, _)| u.to_string());
      let body = read_json(resp, MAX_METADATA_BYTES).await?;
      out.extend(
        body["tags"]
          .as_array()
          .into_iter()
          .flatten()
          .filter_map(|t| t.as_str().map(str::to_string)),
      );
      let Some(next) = next else { break };
      url = self.next_page(&next)?;
    }
    Ok(out)
  }

  fn next_page(&self, next: &str) -> Result<String, String> {
    let denied = || "仓库分页地址不合法，已拒绝访问".to_string();
    let origin =
      reqwest::Url::parse(&self.origin).map_err(|_| denied())?;
    if next.starts_with("//") {
      return Err(denied());
    }
    let mut page = if next.starts_with('/') {
      origin.join(next)
    } else {
      reqwest::Url::parse(next)
    }
    .map_err(|_| denied())?;
    if page.origin() != origin.origin()
      || !page.username().is_empty()
      || page.password().is_some()
    {
      return Err(denied());
    }
    let tags =
      reqwest::Url::parse(&format!("{}/tags/list", self.base))
        .map_err(|_| denied())?;
    if page.path() == format!("/v2/{}/tags/list", self.path) {
      page.set_path(tags.path());
    }
    if page.path() != tags.path() {
      return Err(denied());
    }
    Ok(page.into())
  }

  /// 请求仓库；遇到 401 匿名换 token 再试一次。
  async fn send(
    &mut self,
    url: &str,
    head: bool,
  ) -> Result<reqwest::Response, String> {
    let err = |e: reqwest::Error| e.without_url().to_string();
    for retry in [false, true] {
      let mut req = if head {
        self.client.head(url)
      } else {
        self.client.get(url)
      }
      .header(header::ACCEPT, ACCEPT);
      if let Some(t) = &self.token {
        req = req.bearer_auth(t);
      }
      let resp = req.send().await.map_err(err)?;
      if resp.status() == StatusCode::UNAUTHORIZED && !retry {
        let challenge = resp
          .headers()
          .get(header::WWW_AUTHENTICATE)
          .and_then(|v| v.to_str().ok())
          .unwrap_or_default()
          .to_string();
        self.token = Some(
          token(
            &self.origin,
            &challenge,
            self.proxied.then_some(self.client),
          )
          .await?,
        );
        continue;
      }
      if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
      }
      return Ok(resp);
    }
    Err("仓库要求登录".into())
  }

  async fn head(
    &mut self,
    reference: &str,
  ) -> Result<String, String> {
    let url = format!("{}/manifests/{reference}", self.base);
    self
      .send(&url, true)
      .await?
      .headers()
      .get("docker-content-digest")
      .and_then(|v| v.to_str().ok())
      .filter(|d| d.starts_with("sha256:"))
      .map(str::to_string)
      .ok_or_else(|| "仓库没有返回 digest".to_string())
  }

  async fn metadata(
    &mut self,
    path: &str,
    max_bytes: usize,
    deadline: Instant,
  ) -> Option<Value> {
    let url = format!("{}/{path}", self.base);
    tokio::time::timeout_at(deadline, async {
      read_json(self.send(&url, false).await?, max_bytes).await
    })
    .await
    .map_err(|_| "读取镜像元数据超时".to_string())
    .flatten()
    .inspect_err(|_| tracing::debug!("读取镜像元数据失败"))
    .ok()
  }

  /// 保留 HEAD 返回的 digest。索引已有平台信息，只读本机清单来取镜像 ID。
  async fn details(
    &mut self,
    digest: &str,
    host: &str,
    deadline: Instant,
  ) -> (Option<String>, Option<Vec<String>>) {
    let Some(body) = self
      .metadata(
        &format!("manifests/{digest}"),
        MAX_METADATA_BYTES,
        deadline,
      )
      .await
    else {
      return (None, None);
    };
    if let Some(config) = body["config"]["digest"].as_str() {
      // reqwest 默认在跨主机、端口或协议重定向时移除 Authorization。
      let supported = self
        .metadata(
          &format!("blobs/{config}"),
          MAX_CONFIG_BYTES,
          deadline,
        )
        .await
        .and_then(|body| platforms(&body));
      return (Some(config.to_string()), supported);
    }
    let supported = platforms(&body);
    let Some(child) = body["manifests"]
      .as_array()
      .into_iter()
      .flatten()
      .filter(|m| platform(&m["platform"]).as_deref() == Some(host))
      .find_map(|m| m["digest"].as_str())
    else {
      return (None, supported);
    };
    let config = self
      .metadata(
        &format!("manifests/{child}"),
        MAX_METADATA_BYTES,
        deadline,
      )
      .await
      .and_then(|body| {
        body["config"]["digest"].as_str().map(str::to_string)
      });
    (config, supported)
  }
}

fn platform(body: &Value) -> Option<String> {
  let os = body["os"].as_str()?;
  let arch = body["architecture"].as_str()?;
  if [os, arch].iter().any(|s| s.is_empty() || *s == "unknown") {
    return None;
  }
  match body["variant"].as_str() {
    None | Some("") => Some(format!("{os}/{arch}")),
    Some("v8") if arch == "arm64" => Some(format!("{os}/{arch}")),
    Some(variant) => Some(format!("{os}/{arch}/{variant}")),
  }
}

fn platforms(body: &Value) -> Option<Vec<String>> {
  if let Some(manifests) = body["manifests"].as_array() {
    let mut platforms: Vec<_> = manifests
      .iter()
      .filter_map(|m| platform(&m["platform"]))
      .collect();
    platforms.sort_unstable();
    platforms.dedup();
    return Some(platforms);
  }
  platform(body).map(|p| vec![p])
}

async fn read_json(
  mut response: reqwest::Response,
  max_bytes: usize,
) -> Result<Value, String> {
  let too_large = || format!("仓库响应超过 {max_bytes} 字节");
  if response
    .content_length()
    .is_some_and(|n| n > max_bytes as u64)
  {
    return Err(too_large());
  }
  let mut body = Vec::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(|e| e.without_url().to_string())?
  {
    if chunk.len() > max_bytes - body.len() {
      return Err(too_large());
    }
    body.extend_from_slice(&chunk);
  }
  serde_json::from_slice(&body).map_err(|e| e.to_string())
}

fn arch() -> &'static str {
  match std::env::consts::ARCH {
    "x86_64" => "amd64",
    "aarch64" => "arm64",
    other => other,
  }
}

/// 按 `WWW-Authenticate: Bearer realm=…,service=…,scope=…` 匿名换 token。
pub(crate) async fn token(
  origin: &str,
  challenge: &str,
  proxy: Option<&reqwest::Client>,
) -> Result<String, String> {
  let params = challenge
    .strip_prefix("Bearer ")
    .ok_or_else(|| "仓库要求登录".to_string())?;
  let mut realm = None;
  let mut query = Vec::new();
  for part in params.split(',') {
    let Some((k, v)) = part.trim().split_once('=') else {
      continue;
    };
    let v = v.trim_matches('"').to_string();
    match k {
      "realm" => realm = Some(v),
      "service" | "scope" => query.push((k.to_string(), v)),
      _ => {}
    }
  }
  let realm =
    realm.ok_or_else(|| "仓库的认证信息不完整".to_string())?;
  let response = tokio::time::timeout(ATTEMPT, async {
    let url =
      validate_realm_url(&realm, proxy.is_none().then_some(origin))?;
    let direct;
    let client = if let Some(proxy) = proxy {
      proxy
    } else {
      direct = pinned_client(&url, origin).await?;
      &direct
    };
    client
      .get(url)
      .query(&query)
      .send()
      .await
      .and_then(|r| r.error_for_status())
      .map_err(|e| format!("取 token 失败：{}", e.without_url()))
  })
  .await
  .map_err(|_| "仓库认证请求超时".to_string())??;
  let body = read_json(response, MAX_CONFIG_BYTES).await?;
  body["token"]
    .as_str()
    .or_else(|| body["access_token"].as_str())
    .map(str::to_string)
    .ok_or_else(|| "仓库要求登录".to_string())
}

async fn pinned_client(
  url: &reqwest::Url,
  origin: &str,
) -> Result<reqwest::Client, String> {
  let host = url.host_str().ok_or_else(realm_denied)?;
  let port = url.port_or_known_default().ok_or_else(realm_denied)?;
  let mut client = reqwest::Client::builder()
    .timeout(ATTEMPT)
    .no_proxy()
    .redirect(reqwest::redirect::Policy::none());
  if host
    .trim_matches(['[', ']'])
    .parse::<std::net::IpAddr>()
    .is_err()
  {
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
      .await
      .map_err(|_| realm_denied())?
      .collect();
    if addresses.is_empty()
      || addresses.iter().any(|a| {
        if local_realm(url, origin) {
          !a.ip().is_loopback()
        } else {
          !wharf_api_types::net_probe::is_public(a.ip())
        }
      })
    {
      return Err(realm_denied());
    }
    client = client.resolve_to_addrs(host, &addresses);
  }
  client.build().map_err(|_| realm_denied())
}

fn realm_denied() -> String {
  "仓库认证地址不合法，已拒绝访问".into()
}

fn local_realm(url: &reqwest::Url, origin: &str) -> bool {
  url.scheme() == "http"
    && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
    && reqwest::Url::parse(origin)
      .is_ok_and(|origin| url.origin() == origin.origin())
}

fn validate_realm_url(
  raw: &str,
  origin: Option<&str>,
) -> Result<reqwest::Url, String> {
  let url = reqwest::Url::parse(raw).map_err(|_| realm_denied())?;
  if !url.username().is_empty()
    || url.password().is_some()
    || url.port_or_known_default().is_none_or(|port| port == 0)
  {
    return Err(realm_denied());
  }
  if origin.is_some_and(|origin| local_realm(&url, origin)) {
    return Ok(url);
  }
  let host = url
    .host_str()
    .ok_or_else(realm_denied)?
    .trim_end_matches('.');
  if url.scheme() != "https"
    || matches!(
      host,
      "localhost" | "metadata" | "metadata.google.internal"
    )
    || host.ends_with(".localhost")
    || host
      .trim_matches(['[', ']'])
      .parse::<std::net::IpAddr>()
      .is_ok_and(|ip| !wharf_api_types::net_probe::is_public(ip))
  {
    return Err(realm_denied());
  }
  Ok(url)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[tokio::test]
  async fn registry_proxy_receives_manifest_and_token_requests() {
    use tokio::{
      io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
      net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let clients = Clients {
      direct: client(None).unwrap(),
      proxy: Some(client(Some(&proxy)).unwrap()),
    };
    let mut repo = clients.repo(false, "127.0.0.1:1", "org/app");
    let serve = async {
      for (expected, response) in [
        (
          "HEAD http://127.0.0.1:1/v2/org/app/manifests/latest HTTP/1.1",
          concat!(
            "HTTP/1.1 401 Unauthorized\r\n",
            "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\"\r\n",
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
          ),
        ),
        (
          "CONNECT auth.example.test:443 HTTP/1.1",
          "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
      ] {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        socket.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), expected);
        loop {
          line.clear();
          assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
          if line == "\r\n" {
            break;
          }
        }
        socket
          .get_mut()
          .write_all(response.as_bytes())
          .await
          .unwrap();
      }
    };
    let (_, result) =
      tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve, repo.head("latest"))
      })
      .await
      .expect("token 请求应到达代理");
    assert!(result.unwrap_err().starts_with("取 token 失败"));
  }

  #[test]
  fn parses_index_and_config_platforms() {
    let index = json!({
      "manifests": [
        {"platform": {"os": "linux", "architecture": "amd64"}},
        {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
        {"platform": {"os": "unknown", "architecture": "unknown"}}
      ]
    });
    assert_eq!(
      platforms(&index),
      Some(["linux/amd64", "linux/arm64"].map(String::from).to_vec())
    );
    let config = json!({"os": "linux", "architecture": "amd64"});
    assert_eq!(
      platforms(&config),
      Some(vec!["linux/amd64".to_string()])
    );
  }

  #[test]
  fn origin_registry_is_not_a_mirror() {
    let policy: PullPolicy =
      serde_json::from_value(serde_json::json!({
        "mirrors": {"docker.io": ["docker.1ms.run"]},
        "mirrors_only": false,
        "attempt_timeout_secs": 60
      }))
      .unwrap();
    assert_eq!(
      hosts("docker.io", &policy),
      vec![
        ("docker.1ms.run".to_string(), true),
        (registry_host("docker.io").to_string(), false),
      ]
    );
  }

  #[test]
  fn picks_newer_tags_of_same_shape() {
    let tags: Vec<String> = [
      "2.19", "2.20", "2.21", "2.22", "2.22.1", "2.23-rc1", "3.0",
      "latest", "v2.30",
    ]
    .map(String::from)
    .to_vec();
    let cur = Version::parse("2.20").unwrap();
    assert_eq!(pick(&cur, &tags), vec!["2.22", "3.0"]);
    let cur = Version::parse("3.0").unwrap();
    assert!(pick(&cur, &tags).is_empty());
    assert!(Version::parse("latest").is_none());
    let tags: Vec<String> = ["1.27-alpine", "1.28-alpine", "1.28"]
      .map(String::from)
      .to_vec();
    let cur = Version::parse("1.27-alpine").unwrap();
    assert_eq!(pick(&cur, &tags), vec!["1.28-alpine"]);
  }
}

#[test]
fn registry_prefix_and_pagination_are_origin_bound() {
  let client = reqwest::Client::new();
  let repo = Repo::new(
    &client,
    false,
    "ghcr.example.test/tok_secret_123456",
    "org/app",
  );
  assert_eq!(
    repo.base,
    "https://ghcr.example.test/v2/tok_secret_123456/org/app"
  );
  assert_eq!(
    repo.next_page("/v2/org/app/tags/list?last=1").unwrap(),
    format!("{}/tags/list?last=1", repo.base)
  );
  assert!(repo.next_page("https://evil.example.test/next").is_err());
  assert!(
    validate_realm_url("http://127.0.0.1:7700/token", None).is_err()
  );
  assert!(
    validate_realm_url("https://169.254.169.254/latest", None)
      .is_err()
  );
}
