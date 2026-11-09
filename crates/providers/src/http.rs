//! 调厂商 API 的 HTTP 客户端：控制面设了出口时，按出口的规则决定每个请求走不走出口，
//! 出口连不上（出口机器离线）时用直连再发一次。

use std::{sync::RwLock, time::Duration};

use reqwest::{Client, RequestBuilder, Response};

/// 经出口出去的设置。
#[derive(Clone)]
pub struct Route {
  /// 带口令的代理地址。
  pub proxy: String,
  pub all: bool,
  pub domains: Vec<String>,
}

static ROUTE: RwLock<Option<Route>> = RwLock::new(None);

/// 控制面加载设置后调用；`None` 全部直连。
pub fn set_route(route: Option<Route>) {
  if let Ok(mut r) = ROUTE.write() {
    *r = route;
  }
}

pub(crate) struct Http {
  direct: Client,
  /// 经出口的客户端和规则。
  exit: Option<(Client, Route)>,
}

impl Http {
  pub(crate) fn new(timeout: Duration) -> reqwest::Result<Http> {
    let builder = || {
      Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
    };
    let route = ROUTE.read().ok().and_then(|r| r.clone());
    Ok(Http {
      direct: builder().no_proxy().build()?,
      exit: match route {
        Some(r) => Some((
          builder().proxy(reqwest::Proxy::all(&r.proxy)?).build()?,
          r,
        )),
        None => None,
      },
    })
  }

  /// `req` 拼出请求；命中出口规则的经出口发，出口连不上时换直连再发。
  pub(crate) async fn send(
    &self,
    req: impl Fn(&Client) -> RequestBuilder,
  ) -> reqwest::Result<Response> {
    let request = req(&self.direct).build()?;
    let host = request.url().host_str().unwrap_or("").to_string();
    let Some((client, _)) = self.exit.as_ref().filter(|(_, r)| {
      wharf_api_types::egress::via_exit(&host, r.all, &r.domains)
    }) else {
      return self.direct.execute(request).await;
    };
    let Some(retry) = request.try_clone() else {
      return client.execute(request).await;
    };
    match client.execute(request).await {
      Err(e) if e.is_connect() => self.direct.execute(retry).await,
      r => r,
    }
  }
}

/// 查 GitHub 上最新发布的 Wharf 构建（`build-<短提交号>`），和 `current` 比。
/// 返回 `Some(短提交号)` 表示有更新的构建，`None` 表示已经是最新。
pub async fn newer_build(
  repo: &str,
  current: &str,
) -> Result<Option<String>, String> {
  let http =
    Http::new(Duration::from_secs(15)).map_err(|e| e.to_string())?;
  let get = |url: String| {
    let http = &http;
    async move {
      let r = http
        .send(|c| {
          c.get(&url)
            .header("user-agent", "wharf")
            .header("accept", "application/vnd.github+json")
        })
        .await
        .map_err(|e| format!("连不上 GitHub：{e}"))?;
      if !r.status().is_success() {
        return Err(format!("GitHub 返回 {}", r.status()));
      }
      r.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("GitHub 返回的内容不对：{e}"))
    }
  };
  let releases = get(format!(
    "https://api.github.com/repos/{repo}/releases?per_page=5"
  ))
  .await?;
  let latest = releases
    .as_array()
    .into_iter()
    .flatten()
    .find_map(|r| {
      r["tag_name"].as_str()?.strip_prefix("build-")?;
      r["target_commitish"].as_str().map(str::to_string)
    })
    .ok_or("GitHub 上还没有发布过构建")?;
  if latest.starts_with(current) {
    return Ok(None);
  }
  // 发布可能比自己旧（新提交的发布还在打包），比一下先后。
  let cmp = get(format!(
    "https://api.github.com/repos/{repo}/compare/{current}...{latest}"
  ))
  .await?;
  Ok(
    (cmp["status"].as_str() == Some("ahead"))
      .then(|| latest.chars().take(7).collect()),
  )
}
