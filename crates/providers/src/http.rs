//! 调厂商 API 的 HTTP 客户端：控制面设了出口（`api_proxy`）时走代理，
//! 连不上代理（出口机器离线）时用直连再发一次。

use std::{sync::RwLock, time::Duration};

use reqwest::{Client, RequestBuilder, Response};

static PROXY: RwLock<Option<String>> = RwLock::new(None);

/// 控制面加载设置后调用；`None` 直连。
pub fn set_proxy(proxy: Option<String>) {
  if let Ok(mut p) = PROXY.write() {
    *p = proxy.filter(|p| !p.trim().is_empty());
  }
}

pub(crate) struct Http {
  main: Client,
  /// 走代理时备用的直连客户端。
  direct: Option<Client>,
}

impl Http {
  pub(crate) fn new(timeout: Duration) -> reqwest::Result<Http> {
    let builder = || {
      Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
    };
    let proxy = PROXY.read().ok().and_then(|p| p.clone());
    Ok(match proxy {
      Some(p) => Http {
        main: builder().proxy(reqwest::Proxy::all(&p)?).build()?,
        direct: Some(builder().no_proxy().build()?),
      },
      None => Http {
        main: builder().no_proxy().build()?,
        direct: None,
      },
    })
  }

  /// `req` 用给定的客户端拼出请求；走代理连不上时换直连再发。
  pub(crate) async fn send(
    &self,
    req: impl Fn(&Client) -> RequestBuilder,
  ) -> reqwest::Result<Response> {
    match req(&self.main).send().await {
      Err(e) if e.is_connect() && self.direct.is_some() => {
        let direct = self.direct.as_ref().expect("上面判断过");
        req(direct).send().await
      }
      r => r,
    }
  }
}
