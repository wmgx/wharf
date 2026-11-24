//! 外部只读检查的定时入口和无推送的「需要注意」项。
use std::{sync::Arc, time::Duration};

use wharf_api_types::view::{
  Issue, IssueLevel, IssueSubject, ServerView,
};

use crate::{
  dns_check, external_status, state::AppState, tailnet_probe,
  vendor_checks,
};

pub fn spawn(state: Arc<AppState>) {
  let relay = state.clone();
  let key = state.clone();
  let vendor = state.clone();
  tokio::spawn(async move {
    loop {
      let _ = external_status::refresh(&state).await;
      tokio::time::sleep(external_status::INTERVAL).await;
    }
  });
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(45)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(300));
    tick.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      tick.tick().await;
      let _ = tailnet_probe::refresh(&relay).await;
    }
  });
  tokio::spawn(async move {
    loop {
      let _ = vendor_checks::refresh_keys(&key).await;
      tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
  });
  tokio::spawn(async move {
    loop {
      let _ = vendor_checks::refresh(&vendor).await;
      tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    }
  });
}

pub fn issues(servers: &[ServerView]) -> Vec<Issue> {
  let mut issues = dns_check::issues();
  issues.extend(servers.iter().filter_map(|server| {
    let quota = server.report.as_ref()?.docker_quota.as_ref()?;
    let (remaining, limit) = (quota.remaining?, quota.limit?);
    if chrono::Utc::now() - quota.checked_at
      >= chrono::TimeDelta::days(1)
      || u64::from(remaining) * 10 >= u64::from(limit)
    {
      return None;
    }
    Some(Issue {
      code: "docker_hub_quota_low".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "server".into(),
        name: server.name.clone(),
      }),
      title: format!(
        "{} 的 Docker Hub 拉取额度剩 {remaining} / {limit}",
        server.name
      ),
      hint: Some(format!("wharf server show {}", server.name)),
      ack: None,
      alert: None,
    })
  }));
  issues
}
