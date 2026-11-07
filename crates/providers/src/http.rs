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
