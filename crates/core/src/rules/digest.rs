use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{Json, extract::State};
use chrono::{FixedOffset, Timelike};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  view::{AlertDigestPreview, Perm},
};

use super::{display_name, record_at};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  notify::{self, Event},
  state::AppState,
};

pub(super) const SOURCE_ID: &str = "daily_digest";
const LAST_DATE_KEY: &str = "alerts.digest.last_date";
const RETRY_KEY: &str = "alerts.digest.retry";
const MAX_RENDER_BYTES: usize = 12_000;
const MAX_RENDER_ITEMS: usize = 80;

#[derive(Serialize, Deserialize)]
struct Retry {
  date: String,
  attempts: u32,
  next_at: i64,
}

#[derive(Debug, Clone)]
pub(super) struct DigestRow {
  pub id: i64,
  pub source: String,
  pub subject: Option<String>,
  pub title: String,
  pub fired_at: i64,
  pub recovered_at: Option<i64>,
  pub is_notice: bool,
}

#[cfg(test)]
pub(super) fn beijing() -> FixedOffset {
  FixedOffset::east_opt(8 * 3600).expect("固定时区")
}

fn fmt_hm(ms: i64, offset: FixedOffset) -> String {
  db::to_time(ms)
    .with_timezone(&offset)
    .format("%H:%M")
    .to_string()
}

/// 东八区到了 09:00 且今天还没发过时，返回今天的日期（`YYYY-MM-DD`）。
fn due_action(
  now: i64,
  last_date: Option<&str>,
  retry: Option<&Retry>,
  offset: FixedOffset,
  hour: u16,
) -> Option<String> {
  let dt = db::to_time(now).with_timezone(&offset);
  if dt.hour() < u32::from(hour) {
    return None;
  }
  let today = dt.format("%Y-%m-%d").to_string();
  (last_date != Some(today.as_str())
    && retry.is_none_or(|r| r.date != today || now >= r.next_at))
  .then_some(today)
}

/// 按规则分组拼每日汇总正文；没有内容返回 `None`。
fn render(
  rows: &[DigestRow],
  offset: FixedOffset,
) -> Option<(String, String)> {
  if rows.is_empty() {
    return None;
  }
  let mut groups: BTreeMap<&str, Vec<&DigestRow>> = BTreeMap::new();
  for row in rows {
    groups.entry(row.source.as_str()).or_default().push(row);
  }
  let mut body = String::new();
  let mut count = 0;
  'groups: for (source, items) in groups {
    let mut header = format!("【{}】\n", display_name(source));
    for item in items {
      let at = fmt_hm(item.fired_at, offset);
      let line = if item.is_notice {
        format!("- {}（{at}）\n", item.title)
      } else {
        let state = match item.recovered_at {
          Some(t) => format!("已恢复（{}）", fmt_hm(t, offset)),
          None => "仍在触发".into(),
        };
        let label = item.subject.as_deref().unwrap_or(&item.title);
        format!("- {label}（{at} 触发，{state}）· {}\n", item.title)
      };
      if count == MAX_RENDER_ITEMS
        || body.len() + header.len() + line.len()
          > MAX_RENDER_BYTES - 160
      {
        break 'groups;
      }
      body.push_str(&header);
      header.clear();
      body.push_str(&line);
      count += 1;
    }
    body.push('\n');
  }
  let total = rows.len();
  if count < total {
    body.push_str(&format!(
      "\n……其余 {} 条已省略，运行 wharf alert history 查看完整记录",
      total - count
    ));
  }
  Some((
    format!("每日汇总（共 {total} 条）"),
    body.trim().to_string(),
  ))
}

pub(super) fn mark_recovered(
  c: &Connection,
  source: &str,
  subject: Option<&str>,
  now: i64,
) -> Result<(), ApiError> {
  c.execute(
    "UPDATE alert_digest SET recovered_at = ?3
     WHERE source = ?1 AND subject IS ?2 AND is_notice = 0 AND recovered_at IS NULL",
    params![source, subject, now],
  ).map(|_| ()).map_err(db::sql_err)
}

/// 把一条 `digest` 级别的告警或事件通知记入待汇总队列。
pub(super) async fn enqueue(
  state: &AppState,
  source: &str,
  subject: Option<&str>,
  title: &str,
  ok: bool,
  is_notice: bool,
  now: i64,
) {
  let (source, subject, title) = (
    source.to_string(),
    subject.map(str::to_string),
    title.to_string(),
  );
  let res = state
    .db
    .call(move |c| {
      if is_notice {
        c.execute(
          "INSERT INTO alert_digest (source, subject, title, fired_at, recovered_at, is_notice)
           VALUES (?1, ?2, ?3, ?4, NULL, 1)",
          params![source, subject, title, now],
        )
        .map(|_| ())
        .map_err(db::sql_err)
      } else if !ok {
        let updated = c.execute(
          "UPDATE alert_digest SET title = ?3
           WHERE source = ?1 AND subject IS ?2 AND is_notice = 0 AND recovered_at IS NULL",
          params![source, subject, title],
        ).map_err(db::sql_err)?;
        if updated == 0 {
          c.execute(
            "INSERT INTO alert_digest (source, subject, title, fired_at, recovered_at, is_notice)
             VALUES (?1, ?2, ?3, ?4, NULL, 0)",
            params![source, subject, title, now],
          ).map_err(db::sql_err)?;
        }
        Ok(())
      } else {
        mark_recovered(c, &source, subject.as_deref(), now)
      }
    })
    .await;
  if let Err(e) = res {
    tracing::warn!("记录每日汇总条目失败：{}", e.message);
  }
}

async fn load_rows(
  state: &AppState,
) -> Result<(Vec<DigestRow>, Option<String>, Option<Retry>), ApiError>
{
  state
    .db
    .call(|c| {
      let last = db::setting(c, LAST_DATE_KEY)?;
      let retry = db::setting(c, RETRY_KEY)?.and_then(|data| serde_json::from_str(&data).ok());
      let mut stmt = c
        .prepare(
          "SELECT id, source, subject, title, fired_at, recovered_at, is_notice
           FROM alert_digest ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      let rows = stmt
        .query_map([], |r| {
          Ok(DigestRow {
            id: r.get(0)?,
            source: r.get(1)?,
            subject: r.get(2)?,
            title: r.get(3)?,
            fired_at: r.get(4)?,
            recovered_at: r.get(5)?,
            is_notice: r.get::<_, i64>(6)? != 0,
          })
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)?;
      Ok((rows, last, retry))
    })
    .await
}

pub(super) async fn preview(
  state: &AppState,
) -> Result<AlertDigestPreview, ApiError> {
  let (rows, last_sent_date, _) = load_rows(state).await?;
  let count = rows.len();
  let offset =
    state.db.call(|c| crate::config_api::offset(c)).await?;
  let (title, body) = match render(&rows, offset) {
    Some((t, b)) => (Some(t), Some(b)),
    None => (None, None),
  };
  Ok(AlertDigestPreview {
    count,
    title,
    body,
    last_sent_date,
  })
}

/// 投递成功或未配置通知渠道时清理已读条目。
fn should_clear(skipped: Option<&str>) -> bool {
  matches!(skipped, None | Some("没有配置通知渠道"))
}

/// 检查东八区 09:00 是否该发每日汇总。真正发了返回 true。
pub(super) async fn tick_at(state: &AppState, now: i64) -> bool {
  if state.is_safe_mode() {
    return false;
  }
  tick_at_with(state, now, |event| async move {
    notify::deliver(state, &event).await
  })
  .await
}

pub(super) async fn tick_at_with<F, Fut>(
  state: &AppState,
  now: i64,
  deliver: F,
) -> bool
where
  F: FnOnce(Event) -> Fut,
  Fut: std::future::Future<Output = Option<String>>,
{
  let Ok((rows, last_date, retry)) = load_rows(state).await else {
    return false;
  };
  let Ok((offset, hour)) = state
    .db
    .call(|c| {
      Ok((
        crate::config_api::offset(c)?,
        crate::config_api::number(c, "alerts.digest_hour")?,
      ))
    })
    .await
  else {
    return false;
  };
  let Some(today) = due_action(
    now,
    last_date.as_deref(),
    retry.as_ref(),
    offset,
    hour,
  ) else {
    return false;
  };
  let Some((title, body)) = render(&rows, offset) else {
    // 今天 09:00 没有待汇总内容：不发送，但记下今天已过 09:00，免得之后的新条目提前发出。
    let _ = state
      .db
      .call(move |c| db::set_setting(c, LAST_DATE_KEY, Some(&today)))
      .await;
    return false;
  };
  let max_id = rows.last().map(|r| r.id);
  let attempts = retry
    .filter(|r| r.date == today)
    .map_or(1, |r| r.attempts + 1);
  let event = Event { title, body };
  let deliver_event = Event {
    title: event.title.clone(),
    body: event.body.clone(),
  };
  let skipped = deliver(deliver_event).await;
  let clear = should_clear(skipped.as_deref());
  record_at(state, now, SOURCE_ID, None, &event, true, skipped).await;
  let res = state
    .db
    .call(move |c| {
      let tx = c.unchecked_transaction().map_err(db::sql_err)?;
      if clear && let Some(max_id) = max_id {
        tx.execute(
          "DELETE FROM alert_digest WHERE id <= ?1",
          [max_id],
        )
        .map_err(db::sql_err)?;
      }
      if clear || attempts >= 3 {
        db::set_setting(&tx, LAST_DATE_KEY, Some(&today))?;
        db::set_setting(&tx, RETRY_KEY, None)?;
      } else {
        let delay = if attempts == 1 { 15 } else { 60 };
        let retry = Retry {
          date: today,
          attempts,
          next_at: now + delay * 60_000,
        };
        let json = serde_json::to_string(&retry)
          .map_err(|e| ApiError::internal(e.to_string()))?;
        db::set_setting(&tx, RETRY_KEY, Some(&json))?;
      }
      tx.commit().map_err(db::sql_err)
    })
    .await;
  if let Err(e) = res {
    tracing::warn!("更新每日汇总状态失败：{}", e.message);
  }
  true
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    loop {
      tick_at(&state, now_ms()).await;
      tokio::time::sleep(Duration::from_secs(30)).await;
    }
  });
}

/// `GET /api/alerts/digest`
pub async fn preview_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<AlertDigestPreview> {
  auth.require(Perm::Read)?;
  Ok(Json(preview(&s).await?))
}

#[cfg(test)]
#[test]
fn digest_render_caps_body_without_losing_total_count() {
  let rows = (0..100)
    .map(|id| DigestRow {
      id,
      source: "disk_forecast".into(),
      subject: Some("s1".into()),
      title: "磁盘预警".repeat(300),
      fired_at: 0,
      recovered_at: None,
      is_notice: false,
    })
    .collect::<Vec<_>>();
  let (title, body) = render(&rows, beijing()).unwrap();
  assert!(title.contains("100 条"));
  assert!(body.contains("条已省略"));
  assert!(body.len() <= MAX_RENDER_BYTES);
}
