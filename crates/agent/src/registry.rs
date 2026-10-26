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
  let mut out = Vec::new();
  for image in &job.images {
    let result = tokio::select! {
      r = resolve_one(&client, image, &job.pull) => r,
      _ = ctx.cancel.cancelled() => {
        return Err(ApiError::new(ErrorCode::Cancelled, "查询镜像版本已取消"));
      }
    };
    out.push(match result {
      Ok((digest, config)) => ResolvedImage {
        image: image.clone(),
        digest: Some(digest),
        config,
        error: None,
      },
      Err(e) => ResolvedImage {
        image: image.clone(),
        digest: None,
        config: None,
        error: Some(e),
      },
    });
  }
  Ok(out)
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
  let mut hosts: Vec<String> =
    policy.mirrors.get(&registry).cloned().unwrap_or_default();
  if hosts.is_empty() || !policy.mirrors_only {
    hosts.push(registry_host(&registry).to_string());
  }
  let mut errors = Vec::new();
  for host in hosts {
    let mut repo = Repo {
      client,
      base: format!(
        "https://{}/v2/{path}",
        host.trim_end_matches('/')
      ),
      token: None,
    };
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

fn registry_host(registry: &str) -> &str {
  if registry == "docker.io" {
    "registry-1.docker.io"
  } else {
    registry
  }
}

struct Repo<'a> {
  client: &'a reqwest::Client,
  base: String,
  token: Option<String>,
}

impl Repo<'_> {
  /// 请求清单；遇到 401 匿名换 token 再试一次。
  async fn manifest(
    &mut self,
    reference: &str,
    head: bool,
  ) -> Result<reqwest::Response, String> {
    let url = format!("{}/manifests/{reference}", self.base);
    let err = |e: reqwest::Error| e.without_url().to_string();
    for retry in [false, true] {
      let mut req = if head {
        self.client.head(&url)
      } else {
        self.client.get(&url)
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
async fn token(
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
