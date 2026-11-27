//! 域名告警：不自己发请求，用后台域名体检（[crate::doctor]，每 2 分钟一轮）的结果。
//! HTTP(S) 那一层是坏的算不通（5xx、超时、连不上）。
//! 连续多轮不通进"需要注意"并推送，恢复时再推一次；证书剩不到 14 天也推送。
//! 结果只存在内存里。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Mutex,
};

use wharf_api_types::view::{
  CheckStatus, DoctorReport, Issue, IssueLevel, IssueSubject,
  ProbeView,
};

use crate::state::AppState;

static LAST: Mutex<BTreeMap<String, ProbeView>> =
  Mutex::new(BTreeMap::new());

/// 这个域名最近一次的探测结果。
pub fn last(host: &str) -> Option<ProbeView> {
  LAST.lock().ok()?.get(host).cloned()
}

/// 连续失败够次数的域名。
pub fn issues() -> Vec<Issue> {
  ["domain_down", "cert_expiring"]
    .into_iter()
    .flat_map(|rule| {
      crate::rules::firing_subjects(rule).into_iter().map(
        move |(name, title)| {
          let (alert, ack) = crate::rules::issue_alert(rule, &name);
          let down = rule == "domain_down";
          Issue {
            code: if down { "route_down" } else { rule }.into(),
            level: if down {
              IssueLevel::Fault
            } else {
              IssueLevel::Warn
            },
            subject: Some(IssueSubject {
              kind: "route".into(),
              name,
            }),
            title,
            hint: None,
            alert,
            ack,
          }
        },
      )
    })
    .collect()
}

pub(crate) fn forget(hosts: &BTreeSet<String>) {
  if let Ok(mut last) = LAST.lock() {
    last.retain(|host, _| !hosts.contains(host));
  }
}

/// 每轮完整体检后调用。
pub async fn observe(state: &AppState, report: &DoctorReport) {
  let Ok(snap) = crate::snapshot::load(&state.db).await else {
    return;
  };
  let active = snap
    .world
    .routes
    .iter()
    .filter(|(_, row)| {
      !crate::rules::lifecycle::stopped_route(&snap.world, &row.spec)
        && row
          .spec
          .expires_at
          .is_none_or(|end| end > crate::db::now_ms())
    })
    .map(|(host, _)| host.clone())
    .collect::<BTreeSet<_>>();
  if let Ok(mut m) = LAST.lock() {
    m.retain(|h, _| active.contains(h));
  }
  for rule in ["domain_down", "cert_expiring"] {
    crate::rules::retain_subjects(state, rule, &active).await;
  }
  for r in report
    .routes
    .iter()
    .filter(|r| active.contains(&r.hostname))
  {
    let Some(web) = r
      .checks
      .iter()
      .find(|c| c.layer == "https" || c.layer == "http")
    else {
      continue;
    };
    let ok = web.status != CheckStatus::Bad;
    let host = r.hostname.clone();
    let cert_days =
      r.cert_expires.map(|t| (t - chrono::Utc::now()).num_days());
    if let Some(days) = cert_days {
      cert_notify(state, &host, days).await;
    }
    let prev = last(&host).map_or(0, |p| p.fails);
    let fails = if ok { 0 } else { prev + 1 };
    if let Ok(mut m) = LAST.lock() {
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
}

/// 证书剩余天数，规则见 [crate::rules]。
async fn cert_notify(state: &AppState, host: &str, days: i64) {
  crate::rules::observe(state, "cert.days", host, days as f64, "")
    .await;
}
