//! 在控制面并发取多个服务的日志，按原始时间合并。

use std::{collections::BTreeMap, fmt::Write, time::Duration};

use chrono::{DateTime, Datelike, TimeDelta, Utc};
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
  sync::Semaphore,
  time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, ErrorCode, agent::AgentOp};

use crate::{
  api::{AppError, LogsQuery, service_not_found},
  clock, log_search, snapshot,
  state::AppState,
};

#[derive(Deserialize)]
pub(super) struct Services {
  #[serde(default)]
  services: String,
}

#[derive(Serialize)]
struct Failure<'a> {
  service: &'a str,
  server: &'a str,
  message: String,
}

pub(super) fn service_target<'a>(
  snap: &'a snapshot::Snapshot,
  name: &str,
) -> Result<(&'a str, String), ApiError> {
  let server = snapshot::service_runtime_server(snap, name)
    .ok_or_else(|| service_not_found(name))?;
  Ok((server, name.to_owned()))
}

fn service_names(raw: &str) -> Result<Vec<&str>, ApiError> {
  let mut names = Vec::new();
  for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty())
  {
    if !names.contains(&name) {
      names.push(name);
    }
    if names.len() > 10 {
      return Err(
        ApiError::invalid("服务数超过 10 个")
          .with_hint("一次最多合看 10 个服务，按调用链挑关键的几个"),
      );
    }
  }
  if names.len() < 2 {
    return Err(ApiError::invalid("合看至少需要 2 个不同的服务"));
  }
  Ok(names)
}

pub(super) fn anchor_since(value: &str) -> Option<String> {
  let since = log_search::since_arg(value)?;
  if DateTime::parse_from_rfc3339(&since).is_ok() {
    return Some(since);
  }
  let (unit, digits) = since.as_bytes().split_last()?;
  let seconds_per_unit = match unit {
    b's' => 1,
    b'm' => 60,
    b'h' => 3600,
    _ => return None,
  };
  let seconds =
    std::str::from_utf8(digits).ok()?.parse::<i64>().ok()?;
  let delta =
    TimeDelta::try_seconds(seconds.checked_mul(seconds_per_unit)?)?;
  let time = Utc::now().checked_sub_signed(delta)?;
  (0..=9999).contains(&time.year()).then(|| time.to_rfc3339())
}

fn line_budget(count: u32, tail: u32, filtering: bool) -> u32 {
  if filtering {
    (6000 / count).clamp(300, 3000)
  } else {
    tail.min((4000 / count).max(100))
  }
}

fn merge(logs: &[(&str, String)], limit: usize) -> String {
  let mut rows = Vec::new();
  for (order, (service, logs)) in logs.iter().enumerate() {
    let mut time = None;
    for (index, line) in logs.lines().enumerate() {
      let (container, timestamp, message) = log_search::split(line);
      if let Some(parsed) =
        timestamp.and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
      {
        time = Some(parsed.with_timezone(&Utc));
      }
      rows.push((
        (time, order, index),
        service,
        container,
        timestamp,
        message,
      ));
    }
  }
  // 服务序号和原行号使排序键唯一，同一时间也保持原顺序。
  rows.sort_unstable_by_key(|row| row.0);
  let mut merged = String::new();
  for (_, service, container, timestamp, message) in
    &rows[rows.len().saturating_sub(limit)..]
  {
    if let Some(ts) = timestamp {
      writeln!(merged, "{service}/{container} | {ts} {message}")
        .unwrap();
    } else {
      writeln!(merged, "{service}/{container} | {message}").unwrap();
    }
  }
  merged
}

fn clock_warning<'a>(
  offsets: impl IntoIterator<Item = (&'a str, i64)>,
) -> Option<String> {
  let mut offsets = offsets.into_iter();
  let first = offsets.next()?;
  let (mut slow, mut fast) = (first, first);
  for offset in offsets {
    if offset.1 < slow.1 {
      slow = offset;
    }
    if offset.1 > fast.1 {
      fast = offset;
    }
  }
  let diff = fast.1.abs_diff(slow.1);
  (diff > 1000).then(|| {
    format!(
      "{} 比 {} 快约 {:.1} 秒，跨机器的先后顺序可能不准",
      fast.0,
      slow.0,
      diff as f64 / 1000.0
    )
  })
}

pub(super) async fn fetch(
  state: &AppState,
  auth: &crate::auth::Auth,
  services: Services,
  q: LogsQuery,
) -> Result<Value, AppError> {
  let names = service_names(&services.services)?;
  for name in &names {
    crate::token_scope::require_service(auth, name)?;
  }
  let snap = snapshot::load(&state.db).await?;
  let targets = names
    .iter()
    .map(|name| service_target(&snap, name))
    .collect::<Result<Vec<_>, _>>()?;
  let since = q
    .since
    .as_deref()
    .filter(|s| !s.trim().is_empty())
    .map(|value| {
      anchor_since(value).ok_or_else(|| {
        ApiError::invalid(format!("时间范围 {value} 看不懂"))
          .with_hint("写成 30m、2h、3d，或 2026-11-22T08:00:00+08:00")
      })
    })
    .transpose()?;
  let tail = q.tail.min(2000);
  let grep = q.grep.as_deref().filter(|g| !g.trim().is_empty());
  let filtering = grep.is_some() || q.errors;
  let per = line_budget(names.len() as u32, tail, filtering);
  let mut limits = BTreeMap::new();
  for (server, _) in &targets {
    limits.entry(*server).or_insert_with(|| Semaphore::new(3));
  }
  let mut warnings: Vec<_> =
    clock_warning(limits.keys().filter_map(|&server| {
      clock::offset_of(server).map(|offset| (server, offset))
    }))
    .into_iter()
    .collect();

  let deadline = Instant::now() + Duration::from_secs(45);
  let call_timeout = Duration::from_secs(40);
  let cancel = CancellationToken::new();
  let pulls = targets.iter().map(|(server, project)| {
    let limit = &limits[server];
    let since = since.clone();
    let cancel = &cancel;
    async move {
      let pull = async {
        let _permit =
          limit.acquire().await.expect("日志信号量不会关闭");
        let call = state.hub.call::<String>(
          server,
          AgentOp::Logs {
            project: project.clone(),
            container: None,
            tail: per,
            follow: false,
            since,
          },
          call_timeout,
          None,
          cancel,
        );
        // hub 会额外留出等待回包的宽限时间，这里限制实际等待时间。
        timeout(call_timeout, call).await.unwrap_or_else(|_| {
          Err(ApiError::new(
            ErrorCode::Timeout,
            format!("服务器 {server} 超过 40 秒没有返回日志"),
          ))
        })
      };
      tokio::select! {
        biased;
        () = sleep_until(deadline) => Err(ApiError::new(
          ErrorCode::Timeout, "多服务日志拉取超过 45 秒",
        )),
        result = pull => result,
      }
    }
  });

  let mut services = Vec::new();
  let mut logs = Vec::new();
  let mut errors = Vec::new();
  let results = join_all(pulls).await;
  for ((service, (server, _)), result) in
    names.into_iter().zip(targets).zip(results)
  {
    match result {
      Ok(raw) => {
        let lines = raw.lines().count();
        let truncated = lines >= per as usize;
        if truncated && since.is_some() {
          warnings.push(format!(
            "{service} 日志太多，只拿到最近 {lines} 行，可能没覆盖完整时间范围；缩小 --since 或单独看它"
          ));
        }
        services.push(json!({ "service": service, "server": server, "lines": lines, "truncated": truncated }));
        logs.push((service, crate::log_redact::redact_text(&raw)));
      }
      Err(e) => errors.push(Failure {
        service,
        server,
        message: crate::log_redact::redact_text(&e.message),
      }),
    }
  }
  if services.is_empty() {
    let details = errors
      .iter()
      .map(|e| {
        format!("{}（{}）：{}", e.service, e.server, e.message)
      })
      .collect::<Vec<_>>()
      .join("；");
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("所有服务的日志都没拿到：{details}"),
      )
      .suggest("wharf status")
      .into(),
    );
  }

  let mut result = if !filtering && q.max_line.is_none() {
    json!({ "logs": merge(&logs, tail as usize) })
  } else {
    let merged = merge(&logs, usize::MAX);
    drop(logs);
    let found = log_search::search(
      &merged,
      &log_search::Options {
        grep,
        errors: q.errors,
        max_line: q.max_line.unwrap_or(500).max(20),
        limit: tail as usize,
      },
    );
    serde_json::to_value(found).unwrap_or_default()
  };
  result["services"] = json!(services);
  result["warnings"] = json!(warnings);
  result["errors"] = json!(errors);
  Ok(result)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn per_service_line_budget() {
    assert_eq!(line_budget(2, 200, false), 200);
    assert_eq!(line_budget(10, 2000, false), 400);
    assert_eq!(line_budget(2, 200, true), 3000);
    assert_eq!(line_budget(10, 200, true), 600);
  }

  #[test]
  fn merges_timestamps_and_keeps_continuations() {
    let logs = [
      (
        "a",
        concat!(
          "web-1  | 2026-11-22T02:00:00.1Z first\n",
          "web-1  | continuation\n",
          "web-1  | 2026-11-22T02:00:01Z third\n",
        )
        .into(),
      ),
      (
        "b",
        concat!(
          "worker-1  | 2026-11-22T02:00:00.123456789Z second\n",
          "worker-1  | 2026-11-22T02:00:01Z fourth\n",
          "worker-1  | 2026-11-22T02:00:02Z fifth\n",
        )
        .into(),
      ),
    ];
    assert_eq!(
      merge(&logs, usize::MAX),
      concat!(
        "a/web-1 | 2026-11-22T02:00:00.1Z first\n",
        "a/web-1 | continuation\n",
        "b/worker-1 | 2026-11-22T02:00:00.123456789Z second\n",
        "a/web-1 | 2026-11-22T02:00:01Z third\n",
        "b/worker-1 | 2026-11-22T02:00:01Z fourth\n",
        "b/worker-1 | 2026-11-22T02:00:02Z fifth\n",
      )
    );
  }

  #[test]
  fn grep_keeps_source_prefix() {
    let merged = merge(
      &[
        ("a", "web-1  | 2026-11-22T02:00:00Z ok\n".into()),
        ("b", "api-1  | 2026-11-22T02:00:01Z TIMEOUT\n".into()),
      ],
      usize::MAX,
    );
    let found = log_search::search(
      &merged,
      &log_search::Options {
        grep: Some("timeout"),
        errors: false,
        max_line: 500,
        limit: 10,
      },
    );
    assert_eq!((found.scanned, found.matched), (2, 1));
    assert_eq!(
      found.logs.as_deref(),
      Some("b/api-1 | 2026-11-22T02:00:01Z TIMEOUT\n")
    );
  }

  #[test]
  fn warns_about_cross_server_clock_skew() {
    assert_eq!(
      clock_warning([("s1", 0), ("s2", 1800)]).as_deref(),
      Some("s2 比 s1 快约 1.8 秒，跨机器的先后顺序可能不准")
    );
    assert_eq!(clock_warning([("s1", 0), ("s3", 300)]), None);
  }

  #[test]
  fn rejects_out_of_range_service_counts() {
    for raw in ["a", "a,b,c,d,e,f,g,h,i,j,k"] {
      assert!(matches!(
        service_names(raw).unwrap_err().code,
        ErrorCode::InvalidInput
      ));
    }
  }
}
