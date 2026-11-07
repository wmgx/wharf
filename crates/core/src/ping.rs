//! 外部报到（Healthchecks 那种心跳）：cron、systemd timer 这类 Wharf 不执行的任务，
//! 跑完请求 `/ping/<口令>`（失败时 `/ping/<口令>/fail`）。到了预期时间加宽限还没报到，
//! 记一条"没有按时报到"的失败并通知。报到地址不用登录，口令就是凭证。

use std::sync::Arc;

use axum::{
  extract::{Path, State},
  http::StatusCode,
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, params};
use wharf_api_types::view::{TaskKind, TaskSpec, TaskStatus};

use crate::{cron::Cron, db::sql_err, state::AppState, tasks};

/// 报到时带的输出最多留这么多。
const MAX_OUTPUT: usize = 10_000;

/// 预期时间 `t` 加宽限落在 `(after, until]` 里、而 `t` 之后没有报到过，记失败。
pub async fn check_due(
  state: &Arc<AppState>,
  name: &str,
  spec: &TaskSpec,
  cron: &Cron,
  grace_mins: u32,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) {
  let Some(due) = due_in(cron, grace_mins, after, until) else {
    return;
  };
  let task = name.to_string();
  let since = due.timestamp_millis();
  let seen = state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT 1 FROM task_runs WHERE task = ?1 AND trigger = 'ping' AND started_at >= ?2 LIMIT 1",
        params![task, since],
        |_| Ok(()),
      )
      .optional()
      .map_err(sql_err)
    })
    .await;
  if !matches!(seen, Ok(None)) {
    return;
  }
  let output = format!(
    "预期 {} 前后运行，过了 {grace_mins} 分钟还没有报到：脚本可能没启动、卡住，或者没请求报到地址",
    due
      .with_timezone(
        &chrono::FixedOffset::east_opt(8 * 3600).expect("东八区")
      )
      .format("%m-%d %H:%M")
  );
  record(state, name, spec, TaskStatus::Failed, "late", &output)
    .await;
}

/// 预期时间加宽限落在 `(after, until]` 里的那次预期时间。
fn due_in(
  cron: &Cron,
  grace_mins: u32,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
  let grace = Duration::minutes(i64::from(grace_mins));
  cron
    .next_after(after - grace)
    .filter(|due| *due + grace <= until)
}

async fn record(
  state: &AppState,
  name: &str,
  spec: &TaskSpec,
  status: TaskStatus,
  trigger: &str,
  output: &str,
) {
  match tasks::insert_run(state, name, status, trigger).await {
    Ok(id) => tasks::finish(state, id, status, None, output).await,
    Err(e) => tracing::warn!("记录 {name} 的报到失败：{e}"),
  }
  tasks::notify_result(state, name, spec, status, output).await;
}

/// `GET/POST /ping/{token}`：报到成功。请求体（可选）记为输出。
pub async fn ok(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  body: String,
) -> (StatusCode, &'static str) {
  handle(&s, &token, TaskStatus::Succeeded, body).await
}

/// `GET/POST /ping/{token}/fail`：报到失败。
pub async fn fail(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  body: String,
) -> (StatusCode, &'static str) {
  handle(&s, &token, TaskStatus::Failed, body).await
}

async fn handle(
  s: &AppState,
  token: &str,
  status: TaskStatus,
  body: String,
) -> (StatusCode, &'static str) {
  let Ok(all) = tasks::load(s).await else {
    return (StatusCode::SERVICE_UNAVAILABLE, "稍后再试\n");
  };
  let found = all.into_iter().find(|(_, spec, _)| {
    matches!(&spec.how, TaskKind::Ping { token: t, .. } if !t.is_empty() && t == token)
  });
  let Some((name, spec, _)) = found else {
    return (StatusCode::NOT_FOUND, "没有这个报到地址\n");
  };
  let mut output = body;
  if output.len() > MAX_OUTPUT {
    let mut cut = MAX_OUTPUT;
    while !output.is_char_boundary(cut) {
      cut -= 1;
    }
    output.truncate(cut);
  }
  record(s, &name, &spec, status, "ping", &output).await;
  (StatusCode::OK, "ok\n")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn late_only_once_after_grace() {
    // 北京时间每天 4 点 = UTC 20 点，宽限 30 分钟。
    let cron = Cron::parse("0 4 * * *").unwrap();
    let at = |h, m| {
      chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
        .unwrap()
        .and_hms_opt(h, m, 0)
        .unwrap()
        .and_utc()
    };
    assert!(due_in(&cron, 30, at(20, 0), at(20, 29)).is_none());
    assert_eq!(
      due_in(&cron, 30, at(20, 29), at(20, 30)),
      Some(at(20, 0))
    );
    assert!(due_in(&cron, 30, at(20, 30), at(20, 31)).is_none());
  }
}
