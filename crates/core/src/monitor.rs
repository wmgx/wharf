//! 按服务的自定义监控（服务配置 `monitor`）：每分钟让服务所在机器的 agent 从本机请求
//! `http://127.0.0.1:<宿主机端口><path>`。连续多次不正常进"需要注意"并推送，恢复再推。
//! 结果只存在内存里。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, HttpCheck, HttpCheckResult},
  spec::MonitorSpec,
  view::{Issue, IssueLevel, IssueSubject, MonitorView},
};

use crate::{
  service_monitor, snapshot::Snapshot, state::AppState,
  world::ServiceRow,
};

const TICK: Duration = Duration::from_secs(10);
const TIMEOUT_SECS: u64 = 10;

#[derive(Clone, PartialEq)]
struct Target {
  server: String,
  connection: u64,
  instance: String,
  spec: MonitorSpec,
  url: Result<String, String>,
}

static LAST: Mutex<BTreeMap<String, (Target, MonitorView)>> =
  Mutex::new(BTreeMap::new());
static LAST_RUN: Mutex<BTreeMap<String, Instant>> =
  Mutex::new(BTreeMap::new());
static IN_FLIGHT: Mutex<BTreeSet<String>> =
  Mutex::new(BTreeSet::new());

fn target(
  state: &AppState,
  snap: &Snapshot,
  service: &str,
  row: &ServiceRow,
) -> Option<Target> {
  let (server, connection) =
    service_monitor::probe_server(state, snap, service, row)?;
  let spec = row.spec.monitor.clone()?;
  let url = url(row, &spec);
  Some(Target {
    server: server.into(),
    connection,
    instance: row.instance_id.clone(),
    spec,
    url,
  })
}

pub fn last_for(
  state: &AppState,
  snap: &Snapshot,
  service: &str,
  row: &ServiceRow,
) -> Option<MonitorView> {
  let target = target(state, snap, service, row)?;
  let applied_at = snap
    .applied
    .get(service)
    .map_or(0, |applied| applied.at.timestamp_millis());
  let results = LAST.lock().ok()?;
  let (old, view) = results.get(service)?;
  (*old == target && view.at >= applied_at).then(|| view.clone())
}

pub fn issues(world: &crate::world::World) -> Vec<Issue> {
  crate::rules::firing_subjects("monitor_failed")
    .into_iter()
    .filter(|(s, _)| {
      world.services.get(s).is_some_and(|row| {
        !row.spec.stopped && row.spec.monitor.is_some()
      })
    })
    .map(|(s, title)| {
      let (alert, ack) =
        crate::rules::issue_alert("monitor_failed", &s);
      Issue {
        code: "monitor_down".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: s,
        }),
        title,
        hint: None,
        ack,
        alert,
      }
    })
    .collect()
}

pub(crate) fn forget(
  services: &BTreeSet<String>,
  monitors: &BTreeSet<String>,
) {
  if let Ok(mut last) = LAST.lock() {
    last.retain(|svc, _| {
      !services.contains(svc) && !monitors.contains(svc)
    });
  }
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

pub fn validate(
  m: &MonitorSpec,
  old: Option<&MonitorSpec>,
) -> Result<(), ApiError> {
  if old.is_none_or(|old| old.port != m.port)
    && m.port.as_deref().is_some_and(|p| p.trim().is_empty())
  {
    return Err(ApiError::invalid("监控端口名不能为空"));
  }
  if old.is_none_or(|old| old.expect != m.expect)
    && m.expect.is_some_and(|code| !(100..=599).contains(&code))
  {
    return Err(ApiError::invalid("期望状态码应为 100 到 599"));
  }
  if m.headers.len() > 16 {
    return Err(ApiError::invalid("自定义监控最多设置 16 个请求头"));
  }
  let mut names = BTreeSet::new();
  for (k, v) in &m.headers {
    let Ok(name) =
      reqwest::header::HeaderName::from_bytes(k.as_bytes())
    else {
      return Err(ApiError::invalid("监控请求头名称无效"));
    };
    if matches!(
      name.as_str(),
      "content-length"
        | "transfer-encoding"
        | "connection"
        | "te"
        | "upgrade"
        | "proxy-authorization"
    ) || !names.insert(name.as_str().to_string())
    {
      return Err(ApiError::invalid("监控请求头重复或不允许设置"));
    }
    if v.len() > 2048
      || reqwest::header::HeaderValue::from_str(v).is_err()
    {
      return Err(ApiError::invalid(
        "监控请求头值无效或超过 2048 字节",
      ));
    }
  }
  if m.interval_secs.is_some_and(|n| !(10..=3600).contains(&n)) {
    return Err(ApiError::invalid("监控间隔需在 10 到 3600 秒之间"));
  }
  if m.retries.is_some_and(|n| n > 5) {
    return Err(ApiError::invalid("监控重试次数需在 0 到 5 之间"));
  }
  Ok(())
}

pub fn sensitive_header(name: &str) -> bool {
  let name = name.to_ascii_lowercase();
  matches!(name.as_str(), "authorization" | "cookie")
    || ["token", "secret", "key"]
      .into_iter()
      .any(|part| name.contains(part))
}

pub fn require_agent(
  state: &AppState,
  spec: &wharf_api_types::spec::ServiceSpec,
) -> Result<(), ApiError> {
  require_agent_on(state, spec, &spec.server)
}

fn require_agent_on(
  state: &AppState,
  spec: &wharf_api_types::spec::ServiceSpec,
  server: &str,
) -> Result<(), ApiError> {
  if spec.monitor.as_ref().is_some_and(|m| !m.headers.is_empty())
    && state.hub.is_online(server)
    && !state.hub.supports_monitor_v2(server)
  {
    return Err(old_agent(server));
  }
  Ok(())
}

pub(crate) fn old_agent(server: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!(
      "服务器 {server} 的 agent 版本旧，不支持自定义监控请求头"
    ),
  )
  .with_hint("先升级 agent：wharf upgrade")
}

pub fn build_http_check(
  row: &ServiceRow,
  m: &MonitorSpec,
  secrets: &BTreeMap<String, String>,
) -> Result<HttpCheck, String> {
  http_check(url(row, m)?, m, secrets)
}

fn http_check(
  url: String,
  m: &MonitorSpec,
  secrets: &BTreeMap<String, String>,
) -> Result<HttpCheck, String> {
  crate::missing_refs::check_text(
    "monitor",
    m.headers
      .iter()
      .map(|(k, v)| (format!("headers.{k}"), v.as_str())),
    secrets,
  )
  .map_err(|e| e.message)?;
  let mut headers = BTreeMap::new();
  for (key, template) in &m.headers {
    let value = crate::render::substitute(template, Some(secrets))
      .map_err(|_| "监控请求头引用的密钥不可用".to_string())?;
    if value.len() > 2048
      || reqwest::header::HeaderValue::from_str(&value).is_err()
    {
      return Err("替换后的监控请求头值无效".into());
    }
    headers.insert(key.clone(), value);
  }
  Ok(HttpCheck {
    url,
    headers,
    keyword: m.keyword.clone(),
    timeout_secs: TIMEOUT_SECS,
  })
}

pub(crate) fn readiness(
  row: &ServiceRow,
  m: &MonitorSpec,
  secrets: &BTreeMap<String, String>,
) -> Result<Option<wharf_api_types::agent::SettleProbe>, ApiError> {
  let Ok(url) = url(row, m) else {
    return Ok(None);
  };
  let job = http_check(url, m, secrets).map_err(ApiError::invalid)?;
  Ok(Some(wharf_api_types::agent::SettleProbe {
    url: job.url,
    expect: m.expect,
    keyword: job.keyword,
    headers: job.headers,
  }))
}

fn due(now: Instant, last: Option<Instant>, m: &MonitorSpec) -> bool {
  last.is_none_or(|then| {
    now.duration_since(then)
      >= Duration::from_secs(u64::from(m.interval_secs.unwrap_or(60)))
  })
}

/// 判断一次结果，返回（正常吗，说明）。
pub fn judge(m: &MonitorSpec, r: &HttpCheckResult) -> (bool, String) {
  wharf_api_types::agent::judge_http_check(
    m.expect,
    m.keyword.as_deref(),
    r,
  )
}

async fn record(
  state: &AppState,
  service: &str,
  target: Target,
  at: i64,
  ok: bool,
  detail: &str,
  manual: bool,
) {
  {
    let Ok(mut results) = LAST.lock() else { return };
    let fails = match results
      .get(service)
      .filter(|(old, _)| old == &target)
      .map(|(_, view)| view)
    {
      Some(old) if old.at > at => return,
      previous if !ok => previous
        .map_or(0, |old| old.fails)
        .saturating_add(u32::from(!manual)),
      _ => 0,
    };
    results.insert(
      service.into(),
      (
        target,
        MonitorView {
          ok,
          detail: detail.into(),
          at,
          fails,
        },
      ),
    );
  }
  if ok || !manual {
    crate::rules::observe(
      state,
      "monitor.ok",
      service,
      f64::from(u8::from(ok)),
      detail,
    )
    .await;
  }
}

pub(crate) async fn doctor_monitor(
  state: &AppState,
  snap: &crate::snapshot::Snapshot,
  service: &str,
  row: &ServiceRow,
) -> Option<wharf_api_types::view::DoctorCheck> {
  use wharf_api_types::view::CheckStatus;
  let monitor =
    row.spec.monitor.as_ref().filter(|_| !row.spec.stopped)?;
  let check = |status, detail: String| {
    crate::doctor::check("monitor", service, status, detail)
  };
  let Some(observed) = target(state, snap, service, row) else {
    return Some(check(
      CheckStatus::Skip,
      "agent 离线，测不了".into(),
    ));
  };
  let at = crate::db::now_ms();
  if let Err(error) =
    require_agent_on(state, &row.spec, &observed.server)
  {
    return Some(check(CheckStatus::Skip, error.message));
  }
  let secrets = crate::secret_policy::service_secrets(
    &snap.world,
    service,
    &snap.secrets,
  );
  let (ok, detail) = match build_http_check(row, monitor, &secrets) {
    Ok(job) => match request(state, &observed.server, job).await {
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
  let detail = crate::log_redact::redact_text(&detail);
  if let Ok(fresh) = crate::snapshot::load(&state.db).await
    && fresh
      .world
      .services
      .get(service)
      .and_then(|row| target(state, &fresh, service, row))
      .as_ref()
      == Some(&observed)
  {
    record(state, service, observed, at, ok, &detail, true).await;
  }
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
  job: HttpCheck,
) -> Result<HttpCheckResult, wharf_api_types::ApiError> {
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
      tokio::time::sleep(TICK).await;
    }
  });
}

async fn round(state: &Arc<AppState>) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let targets: BTreeSet<_> = snap
    .world
    .services
    .iter()
    .filter(|(n, r)| {
      !r.spec.stopped
        && r.spec.monitor.is_some()
        && snap.applied.contains_key(*n)
    })
    .map(|(n, _)| n.clone())
    .collect();
  crate::rules::retain_subjects(state, "monitor_failed", &targets)
    .await;
  LAST.lock().unwrap().retain(|name, (observed, _)| {
    targets.contains(name)
      && target(state, &snap, name, &snap.world.services[name])
        .as_ref()
        == Some(observed)
  });
  let mut last_run = LAST_RUN.lock().unwrap();
  last_run.retain(|n, _| targets.contains(n));
  let mut running = IN_FLIGHT.lock().unwrap();
  let now = Instant::now();
  for name in targets {
    let row = &snap.world.services[&name];
    let Some(observed) = target(state, &snap, &name, row) else {
      continue;
    };
    if !service_monitor::can_probe_in_background(state, &snap, &name)
    {
      continue;
    }
    let m = &observed.spec;
    if !due(now, last_run.get(&name).copied(), m)
      || !running.insert(name.clone())
    {
      continue;
    }
    last_run.insert(name.clone(), now);
    if let Err(e) =
      require_agent_on(state, &row.spec, &observed.server)
    {
      tracing::warn!("{}", e.message);
      running.remove(&name);
      continue;
    }
    let secrets = crate::secret_policy::service_secrets(
      &snap.world,
      &name,
      &snap.secrets,
    );
    let job = build_http_check(row, m, &secrets);
    let state = state.clone();
    let at = crate::db::now_ms();
    tokio::spawn(async move {
      if let Some((ok, detail)) =
        check_one(&state, &observed.server, &observed.spec, job).await
        && let Ok(current) = crate::snapshot::load(&state.db).await
        && service_monitor::can_probe_in_background(
          &state, &current, &name,
        )
        && current
          .world
          .services
          .get(&name)
          .and_then(|row| target(&state, &current, &name, row))
          .as_ref()
          == Some(&observed)
      {
        record(&state, &name, observed, at, ok, &detail, false).await;
      }
      IN_FLIGHT.lock().unwrap().remove(&name);
    });
  }
}

async fn check_one(
  state: &AppState,
  server: &str,
  m: &MonitorSpec,
  job: Result<HttpCheck, String>,
) -> Option<(bool, String)> {
  if !state.hub.is_online(server) {
    return None;
  }
  let job = match job {
    Ok(job) => job,
    Err(e) => return Some((false, e)),
  };
  let retries = m.retries.unwrap_or_default().min(5);
  for attempt in 0..=retries {
    let result = request(state, server, job.clone()).await.ok()?;
    let (ok, mut detail) = judge(m, &result);
    if ok || attempt == retries {
      if !ok && retries > 0 {
        detail.push_str(&format!("（重试 {retries} 次后仍失败）"));
      }
      return Some((ok, crate::log_redact::redact_text(&detail)));
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  None
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
      ..Default::default()
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

  #[tokio::test]
  async fn manual_monitor_recovery_clears_failed_status() {
    let _guard = crate::rules::tests::TEST_LOCK.lock().await;
    crate::rules::tests::reset_memory();
    let state = crate::rules::tests::test_state();
    let service = "p203-monitor-worker";
    for _ in 0..3 {
      crate::rules::observe(
        &state,
        "monitor.ok",
        service,
        0.0,
        "503",
      )
      .await;
    }
    assert!(
      crate::rules::firing_since("monitor_failed", service).is_some()
    );
    let target = Target {
      server: "s1".into(),
      connection: 1,
      instance: "fixture".into(),
      spec: MonitorSpec {
        path: "/health".into(),
        ..Default::default()
      },
      url: Ok("http://127.0.0.1:8080/health".into()),
    };
    LAST.lock().unwrap().insert(
      service.into(),
      (
        target.clone(),
        MonitorView {
          ok: false,
          detail: "503".into(),
          at: 1,
          fails: 3,
        },
      ),
    );
    record(&state, service, target.clone(), 2, false, "503", true)
      .await;
    assert_eq!(LAST.lock().unwrap()[service].1.fails, 3);
    record(&state, service, target.clone(), 3, true, "200", true)
      .await;
    record(&state, service, target, 2, false, "503", false).await;
    assert!(
      crate::rules::firing_since("monitor_failed", service).is_none()
    );
    let (_, recovered) =
      LAST.lock().unwrap().remove(service).unwrap();
    assert!(recovered.ok);
    assert_eq!(recovered.fails, 0);
  }

  #[test]
  fn judges_results() {
    let m = |expect, keyword: Option<&str>| MonitorSpec {
      path: "/health".into(),
      port: None,
      expect,
      keyword: keyword.map(String::from),
      ..Default::default()
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

#[tokio::test]
async fn monitor_sends_custom_headers_respects_interval_retries_and_redacts_secrets()
 {
  use std::sync::atomic::{AtomicUsize, Ordering};
  let state = crate::rules::tests::test_state();
  let attempts = Arc::new(AtomicUsize::new(0));
  let tries = attempts.clone();
  state.hub.mock_agent("s1", false, move |op| {
    let AgentOp::HttpCheck(job) = op else {
      panic!("预期 HTTP 检查")
    };
    assert_eq!(job.headers["Host"], "app.example.test");
    assert_eq!(job.headers["Authorization"], "Bearer fixture-value");
    let status = if tries.fetch_add(1, Ordering::Relaxed) < 2 {
      503
    } else {
      200
    };
    Ok(serde_json::json!({"status":status,"ms":1}))
  });
  let mut spec: wharf_api_types::spec::ServiceSpec = serde_json::from_value(serde_json::json!({
    "server":"s1","source":{"image":"app:1"},"ports":[{"name":"http","host":20001}],
    "monitor":{"path":"/health","headers":{"Host":"app.example.test","Authorization":"Bearer [[API_KEY]]"},"interval_secs":15,"retries":2}
  })).unwrap();
  assert!(require_agent(&state, &spec).is_err());
  state.hub.enable_mock_monitor_v2("s1");
  assert!(crate::secret_policy::service_uses_secret(
    &spec, "API_KEY"
  ));
  let row = ServiceRow {
    instance_id: "svc_fixture".into(),
    spec: spec.clone(),
    host_ports: BTreeMap::new(),
    import: None,
    pins: BTreeMap::new(),
    commit: None,
    version: 1,
  };
  let m = row.spec.monitor.as_ref().unwrap();
  let now = Instant::now();
  assert!(!due(now + Duration::from_secs(14), Some(now), m));
  assert!(due(now + Duration::from_secs(15), Some(now), m));
  let secrets =
    BTreeMap::from([("API_KEY".into(), "fixture-value".into())]);
  let job = build_http_check(&row, m, &secrets);
  let outcome = check_one(&state, "s1", m, job).await.unwrap();
  assert!(outcome.0);
  assert_eq!(attempts.load(Ordering::Relaxed), 3);
  assert!(!outcome.1.contains("fixture-value"));
  let invalid =
    BTreeMap::from([("API_KEY".into(), "fixture-value\r\n".into())]);
  let error = build_http_check(&row, m, &invalid).unwrap_err();
  assert!(!error.contains("fixture-value"));
  spec
    .monitor
    .as_mut()
    .unwrap()
    .headers
    .insert("Authorization".into(), "[[FILE:KEY]]".into());
  let world = crate::world::World {
    services: BTreeMap::from([(
      "app".into(),
      ServiceRow { spec, ..row },
    )]),
    ..Default::default()
  };
  assert!(crate::secret_policy::validate_world(&world).is_err());
}

#[test]
fn readiness_skips_udp_but_rejects_invalid_headers_for_tcp() {
  let mut row = ServiceRow {
    instance_id: "svc_fixture".into(),
    spec: serde_json::from_value(serde_json::json!({
      "server":"s1","source":{"image":"app:1"},"ports":[{"name":"http","host":20001,"udp":true}],
      "monitor":{"path":"/health","port":"http","headers":{"Authorization":"Bearer [[API_KEY]]"}}
    })).unwrap(),
    host_ports: BTreeMap::new(),
    import: None,
    pins: BTreeMap::new(),
    commit: None,
    version: 1,
  };
  let m = row.spec.monitor.clone().unwrap();
  let secrets =
    BTreeMap::from([("API_KEY".into(), "fixture".into())]);
  assert!(readiness(&row, &m, &secrets).unwrap().is_none());
  row.spec.ports[0].udp = false;
  assert_eq!(
    readiness(&row, &m, &secrets).unwrap().unwrap().headers["Authorization"],
    "Bearer fixture",
  );
  assert!(readiness(&row, &m, &BTreeMap::new()).is_err());
}

#[test]
fn service_monitor_rejects_new_blank_config() {
  let monitor = MonitorSpec {
    port: Some(" ".into()),
    ..Default::default()
  };
  assert!(validate(&monitor, None).is_err());
  assert!(validate(&monitor, Some(&monitor)).is_ok());
  assert!(
    validate(
      &MonitorSpec {
        expect: Some(0),
        ..Default::default()
      },
      None
    )
    .is_err()
  );
}
