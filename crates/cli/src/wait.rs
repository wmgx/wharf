//! `wharf wait`：阻塞到某件事发生再返回，AI 不用自己反复轮询。
//! 每 5 秒查一次，进度打到标准错误；条件满足退出码 0，超时退出码 1。

use std::time::{Duration, Instant};

use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  service_checks::PortCheckSpec,
  view::{
    Actual, CheckStatus, DoctorReport, Health, Issue, IssueLevel,
    ServiceView, Status,
  },
};

use crate::{
  WaitCmd,
  client::{CliError, CliResult, Client},
  print,
};

const INTERVAL: Duration = Duration::from_secs(5);

/// `10m`、`90s`、`1h`，纯数字按秒。
pub fn parse_timeout(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let (num, unit) = match s.char_indices().last() {
    Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
    _ => (s, 's'),
  };
  let invalid = || format!("时长 {s} 看不懂，写成 90s、10m 或 1h");
  let n: u64 = num.parse().map_err(|_| invalid())?;
  let multiplier = match unit {
    's' => 1,
    'm' => 60,
    'h' => 3600,
    _ => return Err(invalid()),
  };
  let secs = n.checked_mul(multiplier).ok_or_else(invalid)?;
  Ok(Duration::from_secs(secs))
}

/// 一次检查的结果：满足了没有，以及现在的情况（一句话）。
type Check = (bool, String);

fn service_base(v: &ServiceView) -> Check {
  let Some(st) = &v.status else {
    return (false, "还查不到现状".into());
  };
  let synced = st
    .desired_hash
    .as_ref()
    .is_none_or(|d| st.actual_hash.as_ref() == Some(d));
  let ok = if st.want_running {
    st.actual == Actual::Running
      && matches!(st.health, Health::Healthy | Health::None)
      && synced
  } else {
    st.actual == Actual::Stopped
  };
  (ok, st.summary.clone())
}

fn fresh_monitor(
  v: &ServiceView,
) -> Option<&wharf_api_types::view::MonitorView> {
  let monitor = v.monitor.as_ref()?;
  v.status
    .as_ref()
    .and_then(|status| status.applied.as_ref())
    .is_none_or(|a| monitor.at >= a.at.timestamp_millis())
    .then_some(monitor)
}

fn pending_port(v: &ServiceView) -> Option<&str> {
  if v.port_checks_supported == Some(false) {
    return None;
  }
  v.spec.ports.iter().find_map(|p| {
    let enabled = match v.spec.port_checks.get(&p.name) {
      Some(PortCheckSpec::Off) => false,
      None => !p.udp,
      _ => true,
    };
    (enabled
      && (v.host_ports.contains_key(&p.name) || p.host.is_some())
      && v.port_checks.get(&p.name) != Some(&true))
    .then_some(p.name.as_str())
  })
}

fn service_ready(v: &ServiceView) -> Check {
  let base = service_base(v);
  if !base.0 || !v.status.as_ref().is_some_and(|st| st.want_running) {
    return base;
  }
  if v.spec.monitor.is_some() {
    match fresh_monitor(v) {
      Some(m) if !m.ok => return (false, m.detail.clone()),
      Some(_) => {}
      None => return (false, "等待自定义监控结果".into()),
    }
  }
  if let Some(port) = pending_port(v) {
    return (false, format!("端口 {port} 尚未通过探测"));
  }
  base
}

fn needs_service_probe(v: &ServiceView) -> bool {
  service_base(v).0
    && v.status.as_ref().is_some_and(|st| st.want_running)
    && ((v.spec.monitor.is_some()
      && !fresh_monitor(v).is_some_and(|m| m.ok))
      || pending_port(v).is_some())
}

fn route_pending(report: &DoctorReport) -> Result<(), Vec<String>> {
  if report.routes.is_empty() {
    return Err(vec!["没有可检查的路由".into()]);
  }
  let pending: Vec<_> = report
    .routes
    .iter()
    .flat_map(|r| &r.checks)
    .filter(|ch| match ch.status {
      CheckStatus::Ok => false,
      CheckStatus::Bad => true,
      CheckStatus::Warn => ch.layer != "cert",
      CheckStatus::Skip => {
        ch.layer != "container" || ch.subject != "外部上游"
      }
    })
    .map(|ch| format!("{}：{}", ch.layer, ch.detail))
    .collect();
  if pending.is_empty() {
    Ok(())
  } else {
    Err(pending)
  }
}

fn clear_pending(issue: &Issue, strict: bool) -> bool {
  strict || (issue.level != IssueLevel::Info && issue.ack.is_none())
}

fn is_transient(err: &CliError) -> bool {
  matches!(err, CliError::Api(api) if matches!(api.code, ErrorCode::AgentOffline | ErrorCode::Internal | ErrorCode::Busy))
}

async fn check(c: &Client, cmd: &WaitCmd) -> CliResult<Check> {
  Ok(match cmd {
    WaitCmd::Service { name, .. } => {
      let name = crate::client::seg(name);
      let path = format!("/api/services/{name}");
      let v: ServiceView = c.get(&path).await?;
      if needs_service_probe(&v) {
        let _: DoctorReport =
          c.get(&format!("/api/doctor?service={name}")).await?;
        service_ready(&c.get(&path).await?)
      } else {
        service_ready(&v)
      }
    }
    WaitCmd::Route { hostname, .. } => {
      let v: DoctorReport = c
        .get(&format!(
          "/api/doctor?host={}",
          crate::client::seg(hostname)
        ))
        .await?;
      match route_pending(&v) {
        Ok(()) => (true, "各层都通".into()),
        Err(pending) => (false, pending.join("；")),
      }
    }
    WaitCmd::Clear {
      subject, strict, ..
    } => {
      let v: Status = c.get("/api/status").await?;
      let open: Vec<_> = v
        .issues
        .iter()
        .filter(|i| clear_pending(i, *strict))
        .filter(|i| {
          subject.as_ref().is_none_or(|s| {
            i.subject.as_ref().is_some_and(|x| {
              &x.name == s || format!("{}/{}", x.kind, x.name) == *s
            })
          })
        })
        .map(|i| i.title.as_str())
        .collect();
      if open.is_empty() {
        (true, "没有需要注意的事".into())
      } else {
        (false, open.join("；"))
      }
    }
  })
}

pub async fn run(c: &Client, cmd: WaitCmd, j: bool) -> CliResult<()> {
  let timeout = match &cmd {
    WaitCmd::Service { timeout, .. }
    | WaitCmd::Route { timeout, .. }
    | WaitCmd::Clear { timeout, .. } => {
      parse_timeout(timeout).map_err(ApiError::invalid)?
    }
  };
  let start = Instant::now();
  let deadline = start
    .checked_add(timeout)
    .ok_or_else(|| ApiError::invalid("等待时间太长"))?;
  let mut last = "检查超时".to_string();
  loop {
    let (ok, now) =
      match tokio::time::timeout_at(deadline.into(), check(c, &cmd))
        .await
      {
        Ok(Ok(result)) => result,
        Ok(Err(err)) if is_transient(&err) => {
          let CliError::Api(api) = err else {
            unreachable!()
          };
          (false, format!("临时错误（重试中）：{}", api.message))
        }
        Ok(Err(err)) => return Err(err),
        Err(_) => (false, last.clone()),
      };
    if now != last {
      if !j {
        eprintln!("{}s  {now}", start.elapsed().as_secs());
      }
      last = now.clone();
    }
    if ok {
      if j {
        print::json(
          &json!({ "met": true, "state": now, "waited_secs": start.elapsed().as_secs() }),
        );
      }
      return Ok(());
    }
    let remaining =
      deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
      let elapsed = start.elapsed().as_secs();
      let error = ApiError::new(ErrorCode::Timeout, format!("等了 {elapsed} 秒还没满足：{now}"))
        .with_hint("看现状再决定：wharf service show / wharf doctor / wharf status");
      if j {
        print::json(
          &json!({ "met": false, "state": now, "waited_secs": elapsed, "error": error }),
        );
        return Err(CliError::Exit(1));
      }
      return Err(error.into());
    }
    tokio::time::sleep(poll_delay(remaining)).await;
  }
}

fn poll_delay(remaining: Duration) -> Duration {
  INTERVAL.min(remaining)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn transient_error_classification_and_deadline() {
    for code in [
      ErrorCode::AgentOffline,
      ErrorCode::Internal,
      ErrorCode::Busy,
    ] {
      assert!(is_transient(&ApiError::new(code, "测试").into()));
    }
    for code in [ErrorCode::Forbidden, ErrorCode::NotFound] {
      assert!(!is_transient(&ApiError::new(code, "测试").into()));
    }
    let short = Duration::from_secs(3);
    assert_eq!(poll_delay(short), short);
  }

  #[test]
  fn route_rejects_warn_and_skip_except_allowed() {
    let mut report: DoctorReport = serde_json::from_value(json!({
      "checked_at": "2026-01-01T00:00:00Z", "servers": [], "routes": [
        {"hostname":"example.test", "url":"https://example.test", "checks":[]}
      ]
    })).unwrap();
    for (layer, status, subject, ok) in [
      ("dns", "warn", "example.test", false),
      ("link", "skip", "s1", false),
      ("container", "warn", "app", false),
      ("cert", "warn", "example.test", true),
      ("container", "skip", "外部上游", true),
    ] {
      report.routes[0].checks = vec![serde_json::from_value(json!({
        "layer":layer, "status":status, "subject":subject, "detail":"测试",
        "at":"2026-01-01T00:00:00Z"
      })).unwrap()];
      assert_eq!(route_pending(&report).is_ok(), ok);
    }
  }

  #[test]
  fn clear_ignores_info_and_acked_unless_strict() {
    let mut issue: Issue = serde_json::from_value(json!({
      "code":"update_available", "level":"info", "title":"测试",
    }))
    .unwrap();
    assert!(!clear_pending(&issue, false));
    assert!(clear_pending(&issue, true));
    issue.level = IssueLevel::Warn;
    issue.ack = Some(
      serde_json::from_value(json!({"by":"fixture","at":0})).unwrap(),
    );
    assert!(!clear_pending(&issue, false));
    assert!(clear_pending(&issue, true));
  }

  fn service_fixture() -> ServiceView {
    serde_json::from_value(json!({
      "name":"app", "spec":{"server":"s1","source":{"image":"nginx:1"},
        "ports":[{"name":"http","container":80}], "monitor":{"path":"/health"}},
      "host_ports":{"http":21000}, "addresses":{}, "version":1,
      "status":{"want_running":true,"desired_hash":"h1","actual":"running","health":"none","tone":"ok","summary":"运行中"}
    })).unwrap()
  }

  #[test]
  fn service_unsynced_when_actual_hash_missing() {
    assert!(!service_base(&service_fixture()).0);
  }

  #[test]
  fn service_checks_monitor_freshness_and_ports() {
    let mut service = service_fixture();
    let s = service.status.as_mut().unwrap();
    s.actual_hash = s.desired_hash.clone();
    s.applied = Some(
      serde_json::from_value(
        json!({"hash":"h1","at":"1970-01-01T00:00:01Z"}),
      )
      .unwrap(),
    );
    service.monitor = Some(
      serde_json::from_value(
        json!({"ok":true,"detail":"测试","at":999}),
      )
      .unwrap(),
    );
    service.port_checks.insert("http".into(), false);
    assert!(!service_ready(&service).0);
    service.monitor.as_mut().unwrap().at = 1000;
    assert!(!service_ready(&service).0);
    service.port_checks.insert("http".into(), true);
    assert!(service_ready(&service).0);
    service.monitor.as_mut().unwrap().ok = false;
    assert!(!service_ready(&service).0);
    assert!(needs_service_probe(&service));
    service.monitor.as_mut().unwrap().ok = true;
    assert!(service_ready(&service).0);
    assert!(!needs_service_probe(&service));
  }

  #[test]
  fn legacy_agent_falls_back_without_port_checks() {
    let mut service = service_fixture();
    let status = service.status.as_mut().unwrap();
    status.actual_hash = status.desired_hash.clone();
    service.spec.monitor = None;
    assert!(!service_ready(&service).0);
    service.port_checks_supported = Some(true);
    assert!(needs_service_probe(&service));
    service.port_checks_supported = Some(false);
    assert!(service_ready(&service).0);
    assert!(!needs_service_probe(&service));
  }

  #[test]
  fn parses_timeouts() {
    assert_eq!(parse_timeout("90s"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_timeout("10m"), Ok(Duration::from_secs(600)));
    assert_eq!(parse_timeout("30"), Ok(Duration::from_secs(30)));
    assert!(parse_timeout("1d").is_err());
  }
}
