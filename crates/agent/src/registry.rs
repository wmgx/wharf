//! 查镜像标签当前对应的 digest：只发 HEAD 读清单，不拉镜像。
//! 按镜像源顺序尝试（和拉取一样），匿名 token；要登录的私有仓库查不到。

use std::time::Duration;

use reqwest::{StatusCode, header};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{PullPolicy, ResolveImages, ResolvedImage},
};

use crate::{docker::split_image, exec::Ctx};

/// 查一次清单的上限：只是一个 HEAD 请求，比拉镜像短得多。
const ATTEMPT: Duration = Duration::from_secs(20);

/// 多架构镜像返回索引的 digest，和 `docker pull` 记下的一致。
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
  application/vnd.docker.distribution.manifest.list.v2+json, \
  application/vnd.docker.distribution.manifest.v2+json, \
  application/vnd.oci.image.manifest.v1+json";

pub async fn resolve(
  job: &ResolveImages,
  ctx: &Ctx,
) -> Result<Vec<ResolvedImage>, ApiError> {
  let client = reqwest::Client::builder()
    .timeout(ATTEMPT)
    .build()
    .map_err(|e| ApiError::internal(e.to_string()))?;
  // 各镜像同时查，一台机器镜像多、出口慢时不会排队超时。
  let all = futures_util::future::join_all(
    job.images.iter().map(|image| one(&client, image, job)),
  );
  tokio::select! {
    out = all => Ok(out),
    _ = ctx.cancel.cancelled() => {
      Err(ApiError::new(ErrorCode::Cancelled, "查询镜像版本已取消"))
    }
  }
}

async fn one(
  client: &reqwest::Client,
  image: &str,
  job: &ResolveImages,
) -> ResolvedImage {
  let result = resolve_one(client, image, &job.pull).await;
  let newer_tags = if job.tags {
    tokio::time::timeout(
      TAGS_LIMIT,
      newer_tags(client, image, &job.pull),
    )
    .await
    .unwrap_or_default()
  } else {
    vec![]
  };
  match result {
    Ok((digest, config)) => ResolvedImage {
      image: image.to_string(),
      digest: Some(digest),
      config,
      error: None,
      newer_tags,
    },
    Err(e) => ResolvedImage {
      image: image.to_string(),
      digest: None,
      config: None,
      error: Some(e),
      newer_tags,
    },
  }
}

/// (清单 digest, 本机平台的镜像 ID)。镜像 ID 用来和本地已有的镜像比，读不到时为空。
type Found = (String, Option<String>);

async fn resolve_one(
  client: &reqwest::Client,
  image: &str,
  policy: &PullPolicy,
) -> Result<Found, String> {
  let (registry, path, suffix) = split_image(image);
  let reference = suffix
    .strip_prefix('@')
    .or_else(|| suffix.strip_prefix(':'))
    .unwrap_or("latest")
    .to_string();
  let mut errors = Vec::new();
  for host in hosts(&registry, policy) {
    let mut repo = Repo::new(client, &host, &path);
    match repo.head(&reference).await {
      Ok(digest) => {
        let config = repo.config(&digest).await.ok();
        return Ok((digest, config));
      }
      Err(e) => errors.push(format!("{host}：{e}")),
    }
  }
  Err(errors.join("；"))
}

/// 按镜像源顺序要试的仓库地址，和拉取一样。
fn hosts(registry: &str, policy: &PullPolicy) -> Vec<String> {
  let mut hosts: Vec<String> =
    policy.mirrors.get(registry).cloned().unwrap_or_default();
  if hosts.is_empty() || !policy.mirrors_only {
    hosts.push(registry_host(registry).to_string());
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
  client: &reqwest::Client,
  image: &str,
  policy: &PullPolicy,
) -> Vec<String> {
  let (registry, path, suffix) = split_image(image);
  let Some(current) =
    suffix.strip_prefix(':').and_then(Version::parse)
  else {
    return vec![];
  };
  for host in hosts(&registry, policy) {
    let mut repo = Repo::new(client, &host, &path);
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
  /// `https://host`
  origin: String,
  base: String,
  token: Option<String>,
}

impl<'a> Repo<'a> {
  fn new(
    client: &'a reqwest::Client,
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
    let origin = format!("{scheme}://{}", host.trim_end_matches('/'));
    Self {
      client,
      base: format!("{origin}/v2/{path}"),
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
      let body: serde_json::Value =
        resp.json().await.map_err(|e| e.without_url().to_string())?;
      out.extend(
        body["tags"]
          .as_array()
          .into_iter()
          .flatten()
          .filter_map(|t| t.as_str().map(str::to_string)),
      );
      match next {
        Some(n) if n.starts_with('/') => {
          url = format!("{}{n}", self.origin)
        }
        Some(n) if n.starts_with("http") => url = n,
        _ => break,
      }
    }
    Ok(out)
  }

  /// 请求清单；遇到 401 匿名换 token 再试一次。
  async fn manifest(
    &mut self,
    reference: &str,
    head: bool,
  ) -> Result<reqwest::Response, String> {
    let url = format!("{}/manifests/{reference}", self.base);
    self.send(&url, head).await
  }

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
        self.token = Some(token(self.client, &challenge).await?);
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
    self
      .manifest(reference, true)
      .await?
      .headers()
      .get("docker-content-digest")
      .and_then(|v| v.to_str().ok())
      .filter(|d| d.starts_with("sha256:"))
      .map(str::to_string)
      .ok_or_else(|| "仓库没有返回 digest".to_string())
  }

  /// 本机平台的镜像 ID（清单里 config 的 digest），和 `docker image inspect` 的 Id 相同。
  async fn config(&mut self, digest: &str) -> Result<String, String> {
    let mut reference = digest.to_string();
    // 多架构：索引 → 本机平台的清单 → config。最多两层。
    for _ in 0..2 {
      let body: serde_json::Value = self
        .manifest(&reference, false)
        .await?
        .json()
        .await
        .map_err(|e| e.without_url().to_string())?;
      if let Some(config) = body["config"]["digest"].as_str() {
        return Ok(config.to_string());
      }
      reference = body["manifests"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| {
          m["platform"]["os"] == "linux"
            && m["platform"]["architecture"] == arch()
        })
        .and_then(|m| m["digest"].as_str())
        .ok_or_else(|| "清单里没有本机平台".to_string())?
        .to_string();
    }
    Err("清单层数不对".into())
  }
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
  client: &reqwest::Client,
  challenge: &str,
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
  let body: serde_json::Value = client
    .get(&realm)
    .query(&query)
    .send()
    .await
    .and_then(|r| r.error_for_status())
    .map_err(|e| format!("取 token 失败：{}", e.without_url()))?
    .json()
    .await
    .map_err(|e| e.without_url().to_string())?;
  body["token"]
    .as_str()
    .or_else(|| body["access_token"].as_str())
    .map(str::to_string)
    .ok_or_else(|| "仓库要求登录".to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

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
