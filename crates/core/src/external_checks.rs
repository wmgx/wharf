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

pub fn issues(
  servers: &[ServerView],
  snap: &crate::snapshot::Snapshot,
) -> Vec<Issue> {
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
  for (rule, level) in [
    ("vendor_token_invalid", IssueLevel::Fault),
    ("tailnet_key_expiring", IssueLevel::Warn),
    ("tailnet_relay", IssueLevel::Warn),
    ("external_incident", IssueLevel::Warn),
  ] {
    for (name, title) in crate::rules::firing_subjects(rule) {
      let subject = match rule {
        "vendor_token_invalid"
          if !vendor_checks::active_account(snap, &name) =>
        {
          continue;
        }
        "tailnet_key_expiring" => {
          if !snap.world.servers.contains_key(&name)
            || !snap
              .secrets
              .contains_key(crate::tailscale::OAUTH_SECRET)
          {
            continue;
          }
          Some(IssueSubject {
            kind: "server".into(),
            name: name.clone(),
          })
        }
        "tailnet_relay"
          if !name.split_once('>').is_some_and(|(from, to)| {
            snap.world.servers.contains_key(from)
              && snap.world.servers.contains_key(to)
          }) =>
        {
          continue;
        }
        _ => None,
      };
      let (alert, ack) = crate::rules::issue_alert(rule, &name);
      issues.push(Issue {
        code: rule.into(),
        level,
        subject,
        title,
        hint: None,
        alert,
        ack,
      });
    }
  }
  issues
}
