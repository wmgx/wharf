//! 触发告警的页面入口、最近部署和日志。

use std::{cmp::Reverse, time::Duration};

use rusqlite::OptionalExtension;
use tokio_util::sync::CancellationToken;
use wharf_api_types::agent::AgentOp;

use crate::{db, notify::Event, snapshot, state::AppState};

pub async fn enrich(
  state: &AppState,
  rule: &str,
  subject: Option<&str>,
  mut event: Event,
) -> Event {
  if matches!(
    rule,
    "container_restarting" | "monitor_failed" | "http_5xx"
  ) && let Some(service) = subject
  {
    let name = service.to_string();
    if let Ok(Some(at)) = state
      .db
      .call(move |c| {
        c.query_row(
          "SELECT created_at FROM deployments WHERE service = ?1 ORDER BY id DESC LIMIT 1",
          [name],
          |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(db::sql_err)
      })
      .await
    {
      event.body.push_str(&format!("\n最近部署：{}", ago(at)));
    }
    let include_logs = if rule == "http_5xx" {
      false
    } else {
      match state
        .db
        .call(|c| db::setting(c, "alerts.include_logs"))
        .await
      {
        Ok(value) => value.is_some(),
        Err(_) => {
          tracing::warn!("读取告警日志开关失败");
          false
        }
      }
    };
    if include_logs {
      match snapshot::load(&state.db).await {
        Ok(snap) => {
          if let Some(row) = snap.world.services.get(service) {
            let mut secrets: Vec<String> =
              snap.secrets.values().cloned().collect();
            secrets.extend(
              row
                .spec
                .env
                .iter()
                .filter(|(k, _)| {
                  let key = k.to_uppercase();
                  ["KEY", "TOKEN", "SECRET", "PASS"]
                    .iter()
                    .any(|part| key.contains(*part))
                })
                .map(|(_, v)| v.clone()),
            );
            let logs = tokio::time::timeout(
              Duration::from_secs(8),
              state.hub.call::<String>(
                &row.spec.server,
                AgentOp::Logs {
                  project: service.to_string(),
                  tail: 30,
                  follow: false,
                },
                Duration::from_secs(5),
                None,
                &CancellationToken::new(),
              ),
            )
            .await;
            let logs = match logs {
              Ok(Ok(logs)) => redact_and_trim(&logs, &secrets),
              _ => "（获取失败）".into(),
            };
            event.body.push_str(&format!("\n最近日志：\n{logs}"));
          }
        }
        Err(_) => event.body.push_str("\n最近日志：\n（获取失败）"),
      }
    }
  }
  if let Some(url) = crate::join::default_url(state).await {
    event.body.push_str(&format!(
      "\n查看：{}{}",
      url.trim_end_matches('/'),
      page_path(rule, subject)
    ));
  }
  event
}

fn page_path(rule: &str, subject: Option<&str>) -> String {
  let Some(subject) = subject else {
    return "/alerts".into();
  };
  match rule {
    "server_offline" => format!("/servers/{subject}"),
    "container_restarting" | "monitor_failed" | "http_5xx" => {
      format!("/services/{subject}")
    }
    "domain_down" | "cert_expiring" => "/entries".into(),
    "link_loss" => "/network".into(),
    "host_unit_down" => {
      let server = subject.split_once(':').map_or(subject, |s| s.0);
      format!("/servers/{server}")
    }
    _ => "/alerts".into(),
  }
}

fn ago(at_ms: i64) -> String {
  let minutes = (db::now_ms() - at_ms) / 60_000;
  if minutes < 60 {
    format!("{minutes} 分钟前")
  } else if minutes < 48 * 60 {
    format!("{} 小时前", minutes / 60)
  } else {
    format!("{} 天前", minutes / (24 * 60))
  }
}

fn redact_and_trim(logs: &str, secrets: &[String]) -> String {
  let mut secrets: Vec<_> =
    secrets.iter().filter(|s| s.len() >= 6).collect();
  secrets.sort_unstable();
  secrets.dedup();
  secrets.sort_unstable_by_key(|s| Reverse(s.len()));
  let mut logs = logs.to_string();
  for secret in secrets {
    logs = logs.replace(secret.as_str(), "***");
  }
  let lines: Vec<String> = logs
    .lines()
    .map(|line| line.chars().take(200).collect())
    .collect();
  let mut kept = Vec::new();
  let mut bytes = 0;
  for line in lines.into_iter().rev() {
    let size = line.len() + usize::from(!kept.is_empty());
    if bytes + size > 2000 {
      break;
    }
    bytes += size;
    kept.push(line);
  }
  kept.reverse();
  kept.join("\n")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn logs_are_redacted_and_bounded() {
    let secrets =
      vec!["abcdef".into(), "abcdefgh".into(), "abc".into()];
    assert_eq!(redact_and_trim("abcdefgh abc", &secrets), "*** abc");
    assert_eq!(
      redact_and_trim(&"字".repeat(300), &[]).chars().count(),
      200
    );
    let logs = (0..100)
      .map(|n| format!("{n:03}{}", "x".repeat(97)))
      .collect::<Vec<_>>()
      .join("\n");
    let out = redact_and_trim(&logs, &[]);
    assert!(out.len() <= 2000);
    assert_eq!(out.lines().last(), logs.lines().last());
  }
}
