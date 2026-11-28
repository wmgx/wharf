//! 触发告警的页面入口、最近部署和日志。

use std::time::Duration;

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
    "container_restarting"
      | "monitor_failed"
      | "http_5xx"
      | "oom_killed"
  ) && let Some(service) = subject
  {
    let name = service.to_string();
    if let Ok(Some(at)) = state
      .db
      .call(move |c| {
        c.query_row(
          "SELECT d.created_at FROM deployments d JOIN resources r
             ON r.kind = 'service' AND r.name = d.service AND d.instance_id = json_extract(r.meta, '$.instance_id')
           WHERE d.service = ?1 ORDER BY d.id DESC LIMIT 1",
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
          if let Some(row) = snap.world.services.get(service)
            && let Some(server) =
              snapshot::service_runtime_server(&snap, service)
          {
            let secrets =
              crate::log_redact::service_values(&row.spec);
            let logs = tokio::time::timeout(
              Duration::from_secs(8),
              state.hub.call::<String>(
                server,
                AgentOp::Logs {
                  project: service.to_string(),
                  tail: 30,
                  follow: false,
                  since: None,
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
  if rule == "disk_forecast"
    && let Some(server) = subject
  {
    let top = crate::disk::top(state, server, 3).await;
    if !top.is_empty() {
      event.body.push_str(&format!(
        "\n占得最多的服务：{}",
        crate::disk::top_text(&top)
      ));
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

/// 服务器恢复在线：离线了多久，这台机器上的服务现在是不是都起来了。
/// 断电、断网恢复后不用自己挨个去看。
pub async fn back_online(
  state: &AppState,
  server: &str,
  since: Option<i64>,
  mut event: Event,
) -> Event {
  if let Some(since) = since {
    event.body.push_str(&format!(
      "，离线约 {}",
      duration(db::now_ms() - since)
    ));
  }
  let Ok(snap) = snapshot::load(&state.db).await else {
    return event;
  };
  let services: Vec<(String, bool)> = snap
    .world
    .services
    .iter()
    .filter(|(n, _)| {
      snapshot::service_runtime_server(&snap, n) == Some(server)
    })
    .map(|(n, r)| (n.clone(), !r.spec.stopped))
    .collect();
  if services.is_empty() {
    return event;
  }
  let projects = services.iter().map(|(n, _)| n.clone()).collect();
  let live = snapshot::project_status(
    &state.hub,
    server,
    projects,
    Duration::from_secs(15),
  )
  .await;
  let Ok(live) = live else {
    event.body.push_str(
      "\n这台机器上的服务现状查不到，稍后用 wharf status 看",
    );
    return event;
  };
  event.body.push_str(&services_summary(&services, &live));
  event
}

/// `want` 是（服务，按配置应该在运行）。
fn services_summary(
  want: &[(String, bool)],
  live: &std::collections::BTreeMap<
    String,
    wharf_api_types::agent::ProjectState,
  >,
) -> String {
  let down: Vec<&str> = want
    .iter()
    .filter(|(n, running)| {
      *running && !live.get(n).is_some_and(|p| p.all_running())
    })
    .map(|(n, _)| n.as_str())
    .collect();
  let total = want.iter().filter(|(_, r)| *r).count();
  if down.is_empty() {
    format!("\n受影响的 {total} 个服务都已恢复运行")
  } else {
    format!(
      "\n受影响的 {total} 个服务里还有 {} 个没在运行：{}",
      down.len(),
      down.join("、")
    )
  }
}

fn duration(ms: i64) -> String {
  let minutes = (ms / 60_000).max(1);
  if minutes < 60 {
    format!("{minutes} 分钟")
  } else if minutes < 48 * 60 {
    format!("{} 小时 {} 分钟", minutes / 60, minutes % 60)
  } else {
    format!("{} 天", minutes / (24 * 60))
  }
}

fn page_path(rule: &str, subject: Option<&str>) -> String {
  let Some(subject) = subject else {
    return "/alerts".into();
  };
  let name = urlencoding::encode(subject);
  match rule {
    "server_offline" | "host_cpu_high" | "host_mem_high"
    | "inode_high" | "agent_mem_high" | "clock_skew"
    | "traffic_quota" => format!("/servers/{name}"),
    "disk_forecast" => format!("/servers/{name}?tab=disk"),
    "container_restarting" | "http_5xx" | "oom_killed" => {
      format!("/services/{name}?tab=logs")
    }
    "monitor_failed" | "svc_mem_near_limit" | "heartbeat_late" => {
      format!("/services/{name}?tab=metrics")
    }
    "log_keyword" | "port_down" => {
      let service = subject.split_once(':').map_or(subject, |s| s.0);
      format!(
        "/services/{}?tab=metrics",
        urlencoding::encode(service)
      )
    }
    "mem_forecast" => {
      if let Some(service) = subject.strip_prefix("服务 ") {
        format!(
          "/services/{}?tab=metrics",
          urlencoding::encode(service)
        )
      } else if let Some(server) = subject.strip_prefix("服务器 ")
      {
        format!("/servers/{}", urlencoding::encode(server))
      } else {
        "/alerts".into()
      }
    }
    "domain_down" | "cert_expiring" => {
      format!("/domains?open={name}")
    }
    "link_cert_expiring" | "link_ca_expiring" => {
      "/domains?tab=entries".into()
    }
    "link_loss"
    | "tailnet_relay"
    | "tailnet_key_expiring"
    | "external_incident" => "/network".into(),
    "vendor_token_invalid" => "/settings".into(),
    "expiry_soon" | "expiry_urgent" => {
      match subject.split_once(':') {
        Some(("domain", domain)) => {
          format!("/domains?q={}", urlencoding::encode(domain))
        }
        Some(("server", server)) => format!(
          "/servers/{}?tab=settings",
          urlencoding::encode(server)
        ),
        _ => "/alerts".into(),
      }
    }
    "host_unit_down" => {
      let server = subject.split_once(':').map_or(subject, |s| s.0);
      format!("/servers/{}?tab=host", urlencoding::encode(server))
    }
    _ if crate::rules::is_custom_rule(rule) => {
      format!("/services/{name}?tab=metrics")
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
  let logs = crate::log_redact::redact_text_with(logs, secrets);
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
  #[test]
  fn summary_lists_services_still_down() {
    let state =
      |running: bool| -> wharf_api_types::agent::ProjectState {
        serde_json::from_value(serde_json::json!({
        "project": "x",
        "containers": [{"service": "x", "name": "x-1", "image": "i", "state": if running { "running" } else { "exited" }, "status": ""}],
      }))
      .unwrap()
      };
    let want = vec![
      ("a".to_string(), true),
      ("b".to_string(), true),
      ("c".to_string(), false),
    ];
    let live = std::collections::BTreeMap::from([
      ("a".to_string(), state(true)),
      ("b".to_string(), state(false)),
    ]);
    assert_eq!(
      super::services_summary(&want, &live),
      "\n受影响的 2 个服务里还有 1 个没在运行：b"
    );
    let live = std::collections::BTreeMap::from([
      ("a".to_string(), state(true)),
      ("b".to_string(), state(true)),
    ]);
    assert_eq!(
      super::services_summary(&want, &live),
      "\n受影响的 2 个服务都已恢复运行"
    );
  }

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
