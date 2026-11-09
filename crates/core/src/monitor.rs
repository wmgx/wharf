//! 按服务的自定义监控（服务配置 `monitor`）：每分钟让服务所在机器的 agent 从本机请求
//! `http://127.0.0.1:<宿主机端口><path>`。连续 [FAILS] 次不正常进"需要注意"并推送，恢复再推。
//! 结果只存在内存里。

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use wharf_api_types::{
  agent::{AgentOp, HttpCheck, HttpCheckResult},
  spec::MonitorSpec,
  view::MonitorView,
};

use crate::{state::AppState, world::ServiceRow};

const EVERY: Duration = Duration::from_secs(60);
const FAILS: u32 = 3;
const TIMEOUT_SECS: u64 = 10;

static LAST: Mutex<BTreeMap<String, MonitorView>> =
  Mutex::new(BTreeMap::new());

pub fn last(service: &str) -> Option<MonitorView> {
  LAST.lock().ok()?.get(service).cloned()
}

pub fn problems() -> Vec<String> {
  let Ok(m) = LAST.lock() else { return vec![] };
  m.iter()
    .filter(|(_, v)| v.fails >= FAILS)
    .map(|(s, v)| format!("服务 {s} 的监控不正常：{}", v.detail))
    .collect()
}

/// 监控的地址；端口找不到时返回原因。
pub fn url(
  row: &ServiceRow,
  m: &MonitorSpec,
) -> Result<String, String> {
  let name = match &m.port {
    Some(p) => p.clone(),
    None => row
      .spec
      .ports
      .first()
      .map(|p| p.name.clone())
      .ok_or("服务没有端口，监控不了")?,
  };
  let port = row
    .host_ports
    .get(&name)
    .copied()
    .or_else(|| {
      row
        .spec
        .ports
        .iter()
        .find(|p| p.name == name)
        .and_then(|p| p.host)
    })
    .ok_or_else(|| format!("端口 {name} 没有宿主机端口"))?;
  let path = if m.path.starts_with('/') {
    m.path.clone()
  } else {
    format!("/{}", m.path)
  };
  Ok(format!("http://127.0.0.1:{port}{path}"))
}

/// 判断一次结果，返回（正常吗，说明）。
pub fn judge(m: &MonitorSpec, r: &HttpCheckResult) -> (bool, String) {
  let Some(code) = r.status else {
    return (
      false,
      r.error.clone().unwrap_or_else(|| "没有应答".into()),
    );
  };
  let code_ok = match m.expect {
    Some(e) => code == e,
    None => (200..400).contains(&code),
  };
  if !code_ok {
    let want =
      m.expect.map_or("2xx 或 3xx".to_string(), |e| e.to_string());
    return (false, format!("HTTP {code}，期望 {want}"));
  }
  if r.found == Some(false) {
    let k = m.keyword.as_deref().unwrap_or_default();
    return (
      false,
      format!("HTTP {code}，但应答里没有\u{201c}{k}\u{201d}"),
    );
  }
  (true, format!("HTTP {code} · {} ms", r.ms))
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(90)).await;
    loop {
      round(&state).await;
      tokio::time::sleep(EVERY).await;
    }
  });
}

async fn round(state: &AppState) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let targets: Vec<(
    String,
    String,
    MonitorSpec,
    Result<String, String>,
  )> = snap
    .world
    .services
    .iter()
    .filter(|(_, r)| !r.spec.stopped)
    .filter_map(|(n, r)| {
      let m = r.spec.monitor.clone()?;
      Some((n.clone(), r.spec.server.clone(), m.clone(), url(r, &m)))
    })
    .collect();
  if let Ok(mut l) = LAST.lock() {
    l.retain(|n, _| targets.iter().any(|(t, ..)| t == n));
  }
  let checks =
    targets
      .into_iter()
      .map(|(name, server, m, url)| async move {
        let outcome = match url {
          Err(e) => Some((false, e)),
          // agent 离线或太旧：这一轮不算，离线有自己的告警。
          Ok(_) if !state.hub.is_online(&server) => None,
          Ok(url) => {
            let job = HttpCheck {
              url,
              keyword: m.keyword.clone(),
              timeout_secs: TIMEOUT_SECS,
            };
            match state
              .hub
              .call::<HttpCheckResult>(
                &server,
                AgentOp::HttpCheck(job),
                Duration::from_secs(TIMEOUT_SECS + 10),
                None,
                &tokio_util::sync::CancellationToken::new(),
              )
              .await
            {
              Ok(r) => Some(judge(&m, &r)),
              Err(e) => {
                tracing::debug!("监控 {name}：{}", e.message);
                None
              }
            }
          }
        };
        (name, outcome)
      });
  for (name, outcome) in futures_util::future::join_all(checks).await
  {
    let Some((ok, detail)) = outcome else {
      continue;
    };
    let prev = last(&name).map_or(0, |v| v.fails);
    let fails = if ok { 0 } else { prev + 1 };
    if let Ok(mut l) = LAST.lock() {
      l.insert(
        name.clone(),
        MonitorView {
          ok,
          detail: detail.clone(),
          at: chrono::Utc::now().timestamp_millis(),
          fails,
        },
      );
    }
    crate::rules::observe(
      state,
      "monitor.ok",
      &name,
      f64::from(u8::from(ok)),
      &detail,
    )
    .await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn judges_results() {
    let m = |expect, keyword: Option<&str>| MonitorSpec {
      path: "/health".into(),
      port: None,
      expect,
      keyword: keyword.map(String::from),
    };
    let r = |status, found| HttpCheckResult {
      status,
      ms: 5,
      found,
      error: None,
    };
    assert!(judge(&m(None, None), &r(Some(204), None)).0);
    assert!(!judge(&m(None, None), &r(Some(502), None)).0);
    assert!(!judge(&m(Some(200), None), &r(Some(301), None)).0);
    assert!(
      !judge(&m(None, Some("ok")), &r(Some(200), Some(false))).0
    );
    assert!(!judge(&m(None, None), &r(None, None)).0);
  }
}
