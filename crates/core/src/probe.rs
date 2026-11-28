//! 域名告警：不自己发请求，用后台域名体检（[crate::doctor]，每 2 分钟一轮）的结果。
//! HTTP(S) 那一层是坏的算不通（5xx、超时、连不上）。
//! 连续 [FAILS] 轮不通进"需要注意"并推送，恢复时再推一次；证书剩不到 14 天也推送。
//! 结果只存在内存里。

use std::{collections::BTreeMap, sync::Mutex};

use wharf_api_types::view::{
  CheckStatus, DoctorReport, Issue, IssueLevel, IssueSubject,
  ProbeView, RouteDiagnosis,
};

use crate::state::AppState;

/// 连续失败几次才算挂了，避开偶发抖动。
const FAILS: u32 = 3;

static LAST: Mutex<BTreeMap<String, ProbeView>> =
  Mutex::new(BTreeMap::new());

/// 这个域名最近一次的探测结果。
pub fn last(host: &str) -> Option<ProbeView> {
  LAST.lock().ok()?.get(host).cloned()
}

/// 连续失败够次数的域名。
pub fn issues() -> Vec<Issue> {
  let Ok(m) = LAST.lock() else { return vec![] };
  m.iter()
    .filter(|(_, p)| p.fails >= FAILS)
    .map(|(h, p)| {
      let (alert, ack) = crate::rules::issue_alert("domain_down", h);
      Issue {
        code: "route_down".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "route".into(),
          name: h.clone(),
        }),
        title: format!("域名 {h} 打不开：{}", p.detail),
        hint: None,
        ack,
        alert,
      }
    })
    .chain(m.iter().filter_map(|(h, p)| {
      p.cert_days
        .filter(|d| *d < crate::cert::WARN_DAYS)
        .map(|d| {
          let (alert, ack) =
            crate::rules::issue_alert("cert_expiring", h);
          Issue {
            code: "cert_expiring".into(),
            level: IssueLevel::Warn,
            subject: Some(IssueSubject {
              kind: "route".into(),
              name: h.clone(),
            }),
            title: format!("域名 {h} 的证书 {d} 天后到期"),
            hint: None,
            ack,
            alert,
          }
        })
    }))
    .collect()
}

/// 每轮完整体检后调用。
pub async fn observe(state: &AppState, report: &DoctorReport) {
  if let Ok(mut m) = LAST.lock() {
    m.retain(|h, _| report.routes.iter().any(|r| &r.hostname == h));
  }
  observe_routes(state, &report.routes).await;
}

pub async fn observe_routes(
  state: &AppState,
  routes: &[RouteDiagnosis],
) {
  for route in routes {
    observe_one(state, route).await;
  }
}

async fn observe_one(state: &AppState, r: &RouteDiagnosis) {
  let Some(web) = r
    .checks
    .iter()
    .find(|c| c.layer == "https" || c.layer == "http")
  else {
    return;
  };
  if web.status == CheckStatus::Skip {
    return;
  }
  let ok = web.status != CheckStatus::Bad;
  let host = r.hostname.clone();
  let cert_days =
    r.cert_expires.map(|t| (t - chrono::Utc::now()).num_days());
  if let Some(days) = cert_days {
    cert_notify(state, &host, days).await;
  }
  if let Ok(mut m) = LAST.lock() {
    if m
      .get(&host)
      .is_some_and(|p| p.at > web.at.timestamp_millis())
    {
      return;
    }
    let fails = if ok {
      0
    } else {
      m.get(&host).map_or(1, |p| p.fails.saturating_add(1))
    };
    m.insert(
      host.clone(),
      ProbeView {
        ok,
        detail: web.detail.clone(),
        ms: 0,
        at: web.at.timestamp_millis(),
        fails,
        cert_days,
      },
    );
  }
  // 除了 HTTPS 这层，还有哪一层不通：多半就是原因。
  let cause = r
    .checks
    .iter()
    .find(|c| c.status == CheckStatus::Bad && c.layer != web.layer);
  let detail = match cause {
    Some(c) if !ok => {
      format!(
        "{}：{}；{}：{}",
        r.url, web.detail, c.subject, c.detail
      )
    }
    _ => format!("{}：{}", r.url, web.detail),
  };
  crate::rules::observe(
    state,
    "probe.ok",
    &host,
    f64::from(u8::from(ok)),
    &detail,
  )
  .await;
}

/// 证书剩余天数，规则见 [crate::rules]。
async fn cert_notify(state: &AppState, host: &str, days: i64) {
  crate::rules::observe(state, "cert.days", host, days as f64, "")
    .await;
}

#[tokio::test]
async fn observe_routes_clears_single_host_without_wiping_others() {
  let state = crate::rules::tests::test_state();
  let a = "p203-a.example.test";
  let b = "p203-b.example.test";
  {
    let mut last = LAST.lock().unwrap();
    for host in [a, b] {
      last.insert(
        host.into(),
        ProbeView {
          ok: false,
          detail: String::new(),
          ms: 0,
          at: 0,
          fails: 3,
          cert_days: None,
        },
      );
    }
  }
  observe_routes(
    &state,
    &[RouteDiagnosis {
      hostname: a.into(),
      url: format!("https://{a}"),
      checks: vec![crate::doctor::check(
        "https",
        a,
        CheckStatus::Ok,
        "HTTP 200",
      )],
      cert_expires: None,
      domain_expires: None,
      edge_app: None,
    }],
  )
  .await;
  assert_eq!(last(a).unwrap().fails, 0);
  assert_eq!(last(b).unwrap().fails, 3);
  assert!(
    !issues()
      .iter()
      .any(|i| i.subject.as_ref().is_some_and(|s| s.name == a))
  );
  LAST
    .lock()
    .unwrap()
    .retain(|host, _| host != a && host != b);
}
