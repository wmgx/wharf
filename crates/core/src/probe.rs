//! 域名探测：控制面每 5 分钟对每个路由的地址发一次请求。
//! 2xx、3xx、4xx 算通（服务在应答），5xx、超时、连不上算不通。
//! 连续 [FAILS] 次不通进"需要注意"并推送，恢复时再推一次。结果只存在内存里。

use std::{
  collections::BTreeMap, sync::Arc, sync::Mutex, time::Duration,
};

use wharf_api_types::view::ProbeView;

use crate::state::AppState;

const EVERY: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(15);
/// 连续失败几次才算挂了，避开偶发抖动。
const FAILS: u32 = 3;

static LAST: Mutex<BTreeMap<String, ProbeView>> =
  Mutex::new(BTreeMap::new());

/// 这个域名最近一次的探测结果。
pub fn last(host: &str) -> Option<ProbeView> {
  LAST.lock().ok()?.get(host).cloned()
}

/// 连续失败够次数的域名。
pub fn problems() -> Vec<String> {
  let Ok(m) = LAST.lock() else { return vec![] };
  m.iter()
    .filter(|(_, p)| p.fails >= FAILS)
    .map(|(h, p)| format!("域名 {h} 打不开：{}", p.detail))
    .collect()
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    // 刚启动时网络、网关可能还没就绪，晚一点开始。
    tokio::time::sleep(Duration::from_secs(60)).await;
    let client = match reqwest::Client::builder()
      .timeout(TIMEOUT)
      .redirect(reqwest::redirect::Policy::none())
      .user_agent("wharf-probe")
      .build()
    {
      Ok(c) => c,
      Err(e) => {
        tracing::warn!("域名探测起不来：{e}");
        return;
      }
    };
    loop {
      round(&state, &client).await;
      tokio::time::sleep(EVERY).await;
    }
  });
}

async fn round(state: &AppState, client: &reqwest::Client) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let net = snap.net(&snap.world);
  let urls: Vec<(String, String)> = snap
    .world
    .routes
    .keys()
    .filter_map(|h| {
      crate::views::route_view(&snap, &net, h)
        .map(|v| (h.clone(), v.url))
    })
    .collect();
  // 删掉的路由不再显示。
  if let Ok(mut m) = LAST.lock() {
    m.retain(|h, _| urls.iter().any(|(u, _)| u == h));
  }
  let checks = urls.into_iter().map(|(host, url)| async move {
    let r = check(client, &url).await;
    (host, url, r)
  });
  for (host, url, (ok, detail, ms)) in
    futures_util::future::join_all(checks).await
  {
    let prev = last(&host).map_or(0, |p| p.fails);
    let fails = if ok { 0 } else { prev + 1 };
    if let Ok(mut m) = LAST.lock() {
      m.insert(
        host.clone(),
        ProbeView {
          ok,
          detail: detail.clone(),
          ms,
          at: chrono::Utc::now().timestamp_millis(),
          fails,
        },
      );
    }
    // 只在"刚满次数"和"恢复"时交给通知，它自己只在状态变化时发。
    if ok || fails == FAILS {
      crate::notify::on_result(
        state,
        &format!("probe.{host}"),
        ok,
        crate::notify::Event {
          title: if ok {
            format!("域名 {host} 恢复了")
          } else {
            format!("域名 {host} 打不开")
          },
          body: if ok {
            format!("{url}：{detail}")
          } else {
            format!("{url} 连续 {FAILS} 次探测失败（每 5 分钟一次）：{detail}")
          },
        },
      )
      .await;
    }
  }
}

/// 返回（通不通，说明，耗时毫秒）。
async fn check(
  client: &reqwest::Client,
  url: &str,
) -> (bool, String, u64) {
  let start = std::time::Instant::now();
  let r = client.get(url).send().await;
  let ms = start.elapsed().as_millis() as u64;
  match r {
    Ok(resp) => {
      let code = resp.status().as_u16();
      (code < 500, format!("HTTP {code}"), ms)
    }
    Err(e) if e.is_timeout() => {
      (false, format!("{} 秒没有应答", TIMEOUT.as_secs()), ms)
    }
    Err(e) if e.is_connect() => (false, "连不上".into(), ms),
    Err(e) => (false, e.without_url().to_string(), ms),
  }
}
