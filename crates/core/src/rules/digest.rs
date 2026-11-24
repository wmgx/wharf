use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{Json, extract::State};
use chrono::{FixedOffset, Timelike};
use rusqlite::params;
use wharf_api_types::{
  ApiError,
  view::{AlertDigestPreview, Perm},
};

use super::{ack, source_name, store::record_at};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms, to_time},
  notify::{self, Event},
  state::AppState,
};

const LAST_DATE_KEY: &str = "alerts.digest_last_date";
const CHECK_EVERY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(super) struct DigestItem {
  pub id: i64,
  pub at: i64,
  pub rule: String,
  pub subject: Option<String>,
  pub title: String,
  pub ok: bool,
}

pub(super) fn beijing() -> FixedOffset {
  FixedOffset::east_opt(8 * 3600).unwrap()
}

pub(super) fn beijing_date(ms: i64) -> String {
  to_time(ms)
    .with_timezone(&beijing())
    .format("%Y-%m-%d")
    .to_string()
}

fn fmt_time(ms: i64, today: &str) -> String {
  let dt = to_time(ms).with_timezone(&beijing());
  if dt.format("%Y-%m-%d").to_string() == today {
    dt.format("%H:%M").to_string()
  } else {
    dt.format("%m-%d %H:%M").to_string()
  }
}

/// 判断此时是否应该发送每日汇总：东八区 09:00 及以后且今天尚未发送过。
pub(super) fn should_send_digest(
  now: i64,
  last_date: Option<&str>,
) -> Option<String> {
  let dt = to_time(now).with_timezone(&beijing());
  if dt.hour() < 9 {
    return None;
  }
  let today = dt.format("%Y-%m-%d").to_string();
  if last_date == Some(today.as_str()) {
    return None;
  }
  Some(today)
}

/// 按规则分组拼出每日汇总正文。没有内容返回 None。
pub(super) fn format_digest(
  date: &str,
  items: &[DigestItem],
) -> Option<(String, String)> {
  if items.is_empty() {
    return None;
  }
  let mut by_rule: BTreeMap<&str, Vec<&DigestItem>> = BTreeMap::new();
  for item in items {
    by_rule.entry(item.rule.as_str()).or_default().push(item);
  }
  let mut sections = Vec::new();
  for (rule, group) in by_rule {
    let mut lines = vec![format!("【{}】", source_name(rule))];
    let mut by_subject: BTreeMap<&str, (Option<i64>, bool, i64)> =
      BTreeMap::new();
    let mut notices = Vec::new();
    for item in group {
      if let Some(subj) = item.subject.as_deref() {
        let entry =
          by_subject.entry(subj).or_insert((None, item.ok, item.at));
        if !item.ok && entry.0.is_none() {
          entry.0 = Some(item.at);
        }
        entry.1 = item.ok;
        entry.2 = item.at;
      } else {
        notices.push(item);
      }
    }
    for (subj, (first_fire, last_ok, last_at)) in by_subject {
      let line = match (first_fire, last_ok) {
        (Some(fired), true) => format!(
          "- {subj}：{} 触发，已恢复（{}）",
          fmt_time(fired, date),
          fmt_time(last_at, date)
        ),
        (Some(fired), false) => {
          format!(
            "- {subj}：{} 触发，仍在触发",
            fmt_time(fired, date)
          )
        }
        (None, true) => {
          format!("- {subj}：已恢复（{}）", fmt_time(last_at, date))
        }
        (None, false) => format!(
          "- {subj}：{} 触发，仍在触发",
          fmt_time(last_at, date)
        ),
      };
      lines.push(line);
    }
    for item in notices {
      lines.push(format!(
        "- {} {}",
        fmt_time(item.at, date),
        item.title
      ));
    }
    sections.push(lines.join("\n"));
  }
  Some((format!("每日汇总（{date}）"), sections.join("\n\n")))
}

pub(super) async fn enqueue(
  state: &AppState,
  at: i64,
  rule: &str,
  subject: Option<&str>,
  title: &str,
  ok: bool,
) {
  let (rule, subject, title) = (
    rule.to_string(),
    subject.map(str::to_string),
    title.to_string(),
  );
  if let Err(e) = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO alert_digest (at, rule, subject, title, ok) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![at, rule, subject, title, ok],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("写入每日汇总队列失败：{}", e.message);
  }
}

pub(super) async fn load_pending(
  state: &AppState,
) -> Result<Vec<DigestItem>, ApiError> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT id, at, rule, subject, title, ok FROM alert_digest ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      stmt
        .query_map([], |r| {
          Ok(DigestItem {
            id: r.get(0)?,
            at: r.get(1)?,
            rule: r.get(2)?,
            subject: r.get(3)?,
            title: r.get(4)?,
            ok: r.get(5)?,
          })
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)
    })
    .await
}

/// 检查是否到了每日汇总时间；若需要发送且有内容则发送并记录历史。
/// 返回本次是否实际触发了汇总发送。
pub(super) async fn tick_at(
  state: &AppState,
  now: i64,
) -> Result<bool, ApiError> {
  let last_date =
    state.db.call(|c| db::setting(c, LAST_DATE_KEY)).await?;
  let Some(today) = should_send_digest(now, last_date.as_deref())
  else {
    return Ok(false);
  };
  let items = load_pending(state).await?;
  let Some((title, body)) = format_digest(&today, &items) else {
    // 09:00 时没有待汇总内容：记下今天日期，避免今天后续事件被当成补发立刻推出。
    let d = today;
    state
      .db
      .call(move |c| db::set_setting(c, LAST_DATE_KEY, Some(&d)))
      .await?;
    return Ok(false);
  };
  let max_id = items.last().map_or(0, |i| i.id);
  let event = Event { title, body };
  let skipped = notify::deliver(state, &event).await;
  record_at(state, now, ("digest", None), &event, true, skipped)
    .await;
  let d = today;
  state
    .db
    .call(move |c| {
      c.execute("DELETE FROM alert_digest WHERE id <= ?1", [max_id])
        .map_err(db::sql_err)?;
      db::set_setting(c, LAST_DATE_KEY, Some(&d))
    })
    .await?;
  Ok(true)
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(5)).await;
    loop {
      let now = now_ms();
      if let Err(e) = tick_at(&state, now).await {
        tracing::warn!("每日汇总检查失败：{}", e.message);
      }
      ack::prune_expired(&state, now).await;
      tokio::time::sleep(CHECK_EVERY).await;
    }
  });
}

/// `GET /api/alerts/digest/preview`
pub async fn preview(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<AlertDigestPreview> {
  auth.require(Perm::Read)?;
  let date = beijing_date(now_ms());
  let items = load_pending(&s).await?;
  let count = items.len();
  let (empty, title, body) = match format_digest(&date, &items) {
    Some((t, b)) => (false, t, b),
    None => (true, format!("每日汇总（{date}）"), String::new()),
  };
  Ok(Json(AlertDigestPreview {
    date,
    empty,
    title,
    body,
    count,
  }))
}
