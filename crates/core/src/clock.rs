//! 以控制面为准，扣除半个往返延迟后检查 agent 的时间。

use std::{collections::BTreeMap, sync::Mutex};

use wharf_api_types::view::{Issue, IssueLevel, IssueSubject};

use crate::{rules, state::AppState};

pub fn offset_ms(agent_ms: i64, recv_ms: i64, rtt_ms: u32) -> i64 {
  agent_ms - (recv_ms - i64::from(rtt_ms) / 2)
}

static LAST: Mutex<BTreeMap<String, i64>> =
  Mutex::new(BTreeMap::new());

pub async fn record(
  state: &AppState,
  server: &str,
  agent_ms: Option<i64>,
) {
  let recv_ms = crate::db::now_ms();
  let Some(agent_ms) = agent_ms else { return };
  let Some(rtt) = state.hub.rtt_ms(server) else { return };
  if rtt > 2000 {
    return;
  }
  let offset = offset_ms(agent_ms, recv_ms, rtt);
  LAST.lock().unwrap_or_else(|e| e.into_inner())
    .insert(server.into(), offset);
  rules::observe(
    state, "clock.skew_s", server, offset.unsigned_abs() as f64 / 1000.0, "",
  ).await;
}

pub fn offset_of(server: &str) -> Option<i64> {
  LAST.lock().ok()?.get(server).copied()
}

pub fn issues() -> Vec<Issue> {
  rules::firing_subjects("clock_skew")
    .into_iter()
    .map(|(name, title)| Issue {
      code: "clock_skew".into(),
      level: IssueLevel::Warn,
      subject: Some(IssueSubject {
        kind: "server".into(),
        name,
      }),
      title,
      hint: None,
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn subtracts_half_the_round_trip() {
    assert!((offset_ms(1_008_000, 1_000_100, 200) - 8000).abs() <= 1);
  }
}
