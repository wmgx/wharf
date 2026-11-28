//! 外部报到（Healthchecks 那种心跳）：cron、systemd timer 这类 Wharf 不执行的任务，
//! 跑完请求 `/ping/<口令>`（失败时 `/ping/<口令>/fail`）。到了预期时间加宽限还没报到，
//! 记一条"没有按时报到"的失败并通知。报到地址不用登录，口令就是凭证。

use std::{
  net::SocketAddr,
  sync::{Arc, LazyLock, Mutex},
};

use axum::{
  extract::{ConnectInfo, Path, State},
  http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, params};
use wharf_api_types::view::{TaskKind, TaskSpec, TaskStatus};

use crate::{
  cron::Cron, db::sql_err, notify_keys::RequestLimit,
  service_monitor::heartbeat, state::AppState, tasks,
};

/// 报到时带的输出最多留这么多。
const MAX_OUTPUT: usize = 10_000;
const PER_MINUTE: usize = 30;
static INVALID: LazyLock<Mutex<RequestLimit>> =
  LazyLock::new(Default::default);
static VALID: LazyLock<Mutex<RequestLimit>> =
  LazyLock::new(Default::default);
const LIMITED: (StatusCode, &str) =
  (StatusCode::TOO_MANY_REQUESTS, "请求过于频繁\n");

/// 每轮过了宽限仍没有匹配的报到时，记失败。
pub async fn check_due(
  state: &Arc<AppState>,
  name: &str,
  spec: &TaskSpec,
  cron: &Cron,
  grace_mins: u32,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) {
  let TaskKind::Ping { token, .. } = &spec.how else {
    return;
  };
  for due in dues_in(cron, grace_mins, after, until) {
    let task = name.to_string();
    let (since, before) = ping_window(cron, due);
    let seen = state
      .db
      .call(move |c| {
        c.query_row(
          "SELECT 1 FROM task_runs WHERE task = ?1 AND trigger = 'ping' AND started_at >= ?2 AND (?3 IS NULL OR started_at < ?3) LIMIT 1",
          params![task, since, before],
          |_| Ok(()),
        )
        .optional()
        .map_err(sql_err)
      })
      .await;
    if !matches!(seen, Ok(None)) {
      continue;
    }
    let output = format!(
      "预期 {} 前后运行，过了 {grace_mins} 分钟还没有报到：脚本可能没启动、卡住，或者没请求报到地址",
      due
        .with_timezone(
          &chrono::FixedOffset::east_opt(8 * 3600).expect("东八区")
        )
        .format("%m-%d %H:%M")
    );
    if let Err(e) =
      record(state, name, token, TaskStatus::Failed, "late", &output)
        .await
    {
      tracing::warn!("记录 {name} 的报到失败：{e}");
    }
  }
}

fn dues_in(
  cron: &Cron,
  grace_mins: u32,
  after: DateTime<Utc>,
  until: DateTime<Utc>,
) -> impl Iterator<Item = DateTime<Utc>> + '_ {
  let grace = Duration::minutes(i64::from(grace_mins));
  std::iter::successors(cron.next_after(after - grace), move |due| {
    cron.next_after(*due)
  })
  .take_while(move |due| *due + grace <= until)
}

fn ping_window(
  cron: &Cron,
  due: DateTime<Utc>,
) -> (i64, Option<i64>) {
  let lower = |at| {
    let early = cron
      .prev_before(at)
      .map_or(60, |prev| ((at - prev).num_seconds() / 2).min(60));
    (at - Duration::seconds(early)).timestamp_millis()
  };
  (lower(due), cron.next_after(due).map(lower))
}

async fn record(
  state: &AppState,
  name: &str,
  token: &str,
  status: TaskStatus,
  trigger: &str,
  output: &str,
) -> Result<bool, wharf_api_types::ApiError> {
  let recorded =
    tasks::record_ping(state, name, token, status, trigger, output)
      .await?;
  if let Some(id) = recorded {
    tasks::notify_result(state, name, id, status, output, None).await;
  }
  Ok(recorded.is_some())
}

/// `GET/POST /ping/{token}`：报到成功。请求体（可选）记为输出。
pub async fn ok(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: String,
) -> (StatusCode, &'static str) {
  handle(
    &s,
    &token,
    TaskStatus::Succeeded,
    body,
    &crate::login::client_key(peer.ip(), &headers),
  )
  .await
}

/// `GET/POST /ping/{token}/fail`：报到失败。
pub async fn fail(
  State(s): State<Arc<AppState>>,
  Path(token): Path<String>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: String,
) -> (StatusCode, &'static str) {
  handle(
    &s,
    &token,
    TaskStatus::Failed,
    body,
    &crate::login::client_key(peer.ip(), &headers),
  )
  .await
}

async fn handle(
  s: &AppState,
  token: &str,
  status: TaskStatus,
  body: String,
  source: &str,
) -> (StatusCode, &'static str) {
  if INVALID
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .blocked(source, PER_MINUTE)
  {
    return LIMITED;
  }
  let Ok(all) = tasks::load(s).await else {
    return (StatusCode::SERVICE_UNAVAILABLE, "稍后再试\n");
  };
  let found = all.into_iter().find(|(_, spec, _)| {
    matches!(&spec.how, TaskKind::Ping { token: t, .. } if !t.is_empty() && tasks::constant_time_eq(t, token))
  });
  let Some((name, spec, _)) = found else {
    match heartbeat::service_for_token(s, token).await {
      Ok(Some(name)) if accept_token(token) => {
        return heartbeat::ping(
          s,
          &name,
          token,
          status == TaskStatus::Succeeded,
          &body,
        )
        .await;
      }
      Ok(Some(_)) => return LIMITED,
      Ok(None) => {
        if !INVALID
          .lock()
          .unwrap_or_else(|e| e.into_inner())
          .record(source, PER_MINUTE)
        {
          return LIMITED;
        }
        return (StatusCode::NOT_FOUND, "没有这个报到地址\n");
      }
      Err(_) => {
        return (StatusCode::SERVICE_UNAVAILABLE, "稍后再试\n");
      }
    }
  };
  if !accept_token(token) {
    return LIMITED;
  }
  if !spec.enabled {
    return (StatusCode::FORBIDDEN, "任务已停用\n");
  }
  let mut output = body.replace(token, "…");
  if output.len() > MAX_OUTPUT {
    let mut cut = MAX_OUTPUT;
    while !output.is_char_boundary(cut) {
      cut -= 1;
    }
    output.truncate(cut);
  }
  match record(s, &name, token, status, "ping", &output).await {
    Ok(true) => (StatusCode::OK, "ok\n"),
    Ok(false) => {
      (StatusCode::FORBIDDEN, "任务已停用或报到地址已变更\n")
    }
    Err(e) => {
      tracing::warn!("记录 {name} 的报到失败：{e}");
      (StatusCode::SERVICE_UNAVAILABLE, "稍后再试\n")
    }
  }
}

fn accept_token(token: &str) -> bool {
  VALID
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .record(&crate::auth::hash_token(token), PER_MINUTE)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn disabled_task_ping_keeps_runs_and_notifications_untouched()
  {
    let state = crate::rules::tests::test_state();
    let token = crate::auth::new_token();
    let fixture = serde_json::json!({
      "server": "s1", "kind": "ping", "enabled": false,
      "schedule": "0 4 * * *", "token": token
    })
    .to_string();
    state.db.call(move |c| {
      c.execute("INSERT INTO tasks (name, spec, created_at, updated_at) VALUES ('daily', ?1, 0, 0)", [fixture]).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    assert_eq!(
      handle(
        &state,
        &token,
        TaskStatus::Failed,
        String::new(),
        "disabled-task"
      )
      .await
      .0,
      StatusCode::FORBIDDEN
    );
    assert!(
      tasks::record_ping(
        &state,
        "daily",
        &token,
        TaskStatus::Failed,
        "ping",
        ""
      )
      .await
      .unwrap()
      .is_none()
    );
    state
      .db
      .call(|c| {
        assert_eq!(
          c.query_row("SELECT count(*) FROM task_runs", [], |r| r
            .get::<_, i64>(0))
            .map_err(sql_err)?,
          0
        );
        assert!(
          crate::db::setting(c, "notify.state.task.daily")?.is_none()
        );
        Ok(())
      })
      .await
      .unwrap();
  }
  #[test]
  fn high_freq_ping_miss_not_masked_by_next_round() {
    let cron = Cron::parse("*/5 * * * *").unwrap();
    let due = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let next = due + Duration::minutes(5);
    let (start, end) = ping_window(&cron, due);
    assert_eq!(start, due.timestamp_millis() - 60_000);
    assert_eq!(end, Some(next.timestamp_millis() - 60_000));
    assert_eq!(end, Some(ping_window(&cron, next).0));
    assert_eq!(
      dues_in(&cron, 10, due, next + Duration::minutes(10))
        .collect::<Vec<_>>(),
      [due - Duration::minutes(5), due, next]
    );
  }

  #[tokio::test]
  async fn ping_invalid_token_rate_limit() {
    let state = crate::rules::tests::test_state();
    let token = crate::auth::new_token();
    for _ in 0..30 {
      assert_eq!(
        handle(
          &state,
          &token,
          TaskStatus::Succeeded,
          String::new(),
          "ping-limit-test"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
      );
    }
    assert_eq!(
      handle(
        &state,
        &token,
        TaskStatus::Succeeded,
        String::new(),
        "ping-limit-test"
      )
      .await
      .0,
      StatusCode::TOO_MANY_REQUESTS
    );
  }

  #[tokio::test]
  async fn ping_db_error_returns_503_without_notify() {
    let state = crate::rules::tests::test_state();
    let token = crate::auth::new_token();
    let spec = serde_json::json!({"server":"s1", "kind":"ping", "enabled":true, "schedule":"0 4 * * *", "token":token}).to_string();
    state.db.call(move |c| {
      c.execute("INSERT INTO tasks (name,spec,created_at,updated_at) VALUES ('daily',?1,0,0)", [spec]).map_err(sql_err)?;
      c.execute_batch("CREATE TRIGGER reject_run BEFORE INSERT ON task_runs BEGIN SELECT RAISE(ABORT, 'test'); END;").map_err(sql_err)
    }).await.unwrap();
    assert_eq!(
      handle(
        &state,
        &token,
        TaskStatus::Failed,
        String::new(),
        "ping-db-error"
      )
      .await
      .0,
      StatusCode::SERVICE_UNAVAILABLE
    );
  }

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
    assert!(
      dues_in(&cron, 30, at(20, 0), at(20, 29)).next().is_none()
    );
    assert_eq!(
      dues_in(&cron, 30, at(20, 29), at(20, 30)).next(),
      Some(at(20, 0))
    );
    assert!(
      dues_in(&cron, 30, at(20, 30), at(20, 31)).next().is_none()
    );
  }
}
