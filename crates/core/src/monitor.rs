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
  view::{Issue, IssueLevel, IssueSubject, MonitorView},
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

pub fn issues() -> Vec<Issue> {
  let Ok(m) = LAST.lock() else { return vec![] };
  m.iter()
    .filter(|(_, v)| v.fails >= FAILS)
    .map(|(s, v)| {
      let (alert, ack) =
        crate::rules::issue_alert("monitor_failed", s);
      Issue {
        code: "monitor_down".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: s.clone(),
        }),
        title: format!("服务 {s} 的监控不正常：{}", v.detail),
        hint: None,
        ack,
        alert,
      }
    })
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
      .iter()
      .find(|p| !p.udp)
      .map(|p| p.name.clone())
      .ok_or("服务没有 TCP 端口，监控不了")?,
  };
  if row.spec.ports.iter().any(|p| p.name == name && p.udp) {
    return Err(format!("端口 {name} 是 UDP，监控不了"));
  }
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
  wharf_api_types::agent::judge_http_check(
    m.expect,
    m.keyword.as_deref(),
    r,
  )
}

pub(crate) fn record_manual(
  service: &str,
  at: i64,
  ok: bool,
  detail: String,
) {
  if let Ok(mut results) = LAST.lock() {
    let fails = match results.get(service) {
      Some(old) if old.at > at => return,
      Some(old) => old.fails,
      None => 0,
    };
    results.insert(
      service.into(),
      MonitorView {
        ok,
        detail,
        at,
        fails,
      },
    );
  }
}

pub(crate) async fn doctor_monitor(
  state: &AppState,
  service: &str,
  row: &ServiceRow,
) -> Option<wharf_api_types::view::DoctorCheck> {
  use wharf_api_types::view::CheckStatus;
  let monitor =
    row.spec.monitor.as_ref().filter(|_| !row.spec.stopped)?;
  let server = &row.spec.server;
  let check = |status, detail: String| {
    crate::doctor::check("monitor", service, status, detail)
  };
  if !state.hub.is_online(server) {
    return Some(check(
      CheckStatus::Skip,
      "agent 离线，测不了".into(),
    ));
  }
  let at = chrono::Utc::now().timestamp_millis();
  let (ok, detail) = match url(row, monitor) {
    Ok(url) => match request(state, server, url, monitor).await {
      Ok(result) => judge(monitor, &result),
      Err(_) => {
        return Some(check(
          CheckStatus::Bad,
          "未取得监控结果".into(),
        ));
      }
    },
    Err(e) => (false, e),
  };
  record_manual(service, at, ok, detail.clone());
  Some(check(
    if ok {
      CheckStatus::Ok
    } else {
      CheckStatus::Bad
    },
    detail,
  ))
}

async fn request(
  state: &AppState,
  server: &str,
  url: String,
  monitor: &MonitorSpec,
) -> Result<HttpCheckResult, wharf_api_types::ApiError> {
  let job = HttpCheck {
    url,
    keyword: monitor.keyword.clone(),
    timeout_secs: TIMEOUT_SECS,
  };
  state
    .hub
    .call(
      server,
      AgentOp::HttpCheck(job),
      Duration::from_secs(TIMEOUT_SECS + 10),
      None,
      &tokio_util::sync::CancellationToken::new(),
    )
    .await
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
          Ok(url) => match request(state, &server, url, &m).await {
            Ok(r) => Some(judge(&m, &r)),
            Err(e) => {
              tracing::debug!("监控 {name}：{}", e.message);
              None
            }
          },
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
  fn url_skips_udp_ports() {
    let mut row: ServiceRow = ServiceRow {
      instance_id: "svc_fixture".into(),
      spec: serde_json::from_value(serde_json::json!({
        "server": "s1",
        "source": { "image": "traefik/whoami" },
        "ports": [
          { "name": "game", "container": 9999, "udp": true },
          { "name": "http", "container": 80 }
        ]
      }))
      .unwrap(),
      host_ports: BTreeMap::from([
        ("game".into(), 20001),
        ("http".into(), 20002),
      ]),
      import: None,
      pins: BTreeMap::new(),
      commit: None,
      version: 1,
    };
    let mut m = MonitorSpec {
      path: "/health".into(),
      port: None,
      expect: None,
      keyword: None,
    };
    assert_eq!(
      url(&row, &m).unwrap(),
      "http://127.0.0.1:20002/health"
    );
    row.spec.ports.pop();
    assert_eq!(
      url(&row, &m).unwrap_err(),
      "服务没有 TCP 端口，监控不了"
    );
    m.port = Some("game".into());
    assert_eq!(
      url(&row, &m).unwrap_err(),
      "端口 game 是 UDP，监控不了"
    );
  }

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
