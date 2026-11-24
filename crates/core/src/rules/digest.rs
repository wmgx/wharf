use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{Json, extract::State};
use chrono::{FixedOffset, Timelike};
use rusqlite::{OptionalExtension, params};
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

#[derive(Debug, Clone)]
pub(super) struct DigestRow {
  pub source: String,
  pub subject: Option<String>,
  pub title: String,
  pub fired_at: i64,
  pub recovered_at: Option<i64>,
  pub is_notice: bool,
}

pub(super) fn beijing() -> FixedOffset {
  FixedOffset::east_opt(8 * 3600).expect("固定时区")
}

fn fmt_hm(ms: i64) -> String {
  db::to_time(ms)
    .with_timezone(&beijing())
    .format("%H:%M")
    .to_string()
}

/// 东八区到了 09:00 且今天还没发过时，返回今天的日期（`YYYY-MM-DD`）。
pub(super) fn beijing_due_date(
  now: i64,
  last_date: Option<&str>,
) -> Option<String> {
  let dt = db::to_time(now).with_timezone(&beijing());
  if dt.hour() < 9 {
    return None;
  }
  let today = dt.format("%Y-%m-%d").to_string();
  (last_date != Some(today.as_str())).then_some(today)
}

/// 按规则分组拼每日汇总正文；没有内容返回 `None`。
pub(super) fn render(rows: &[DigestRow]) -> Option<(String, String)> {
  if rows.is_empty() {
    return None;
  }
  let mut groups: BTreeMap<&str, Vec<&DigestRow>> = BTreeMap::new();
  for row in rows {
    groups.entry(row.source.as_str()).or_default().push(row);
  }
  let mut sections = Vec::with_capacity(groups.len());
  for (source, items) in groups {
    let mut lines = vec![format!("【{}】", display_name(source))];
    for item in items {
      let at = fmt_hm(item.fired_at);
      if item.is_notice {
        lines.push(format!("- {}（{at}）", item.title));
      } else {
        let state = match item.recovered_at {
          Some(t) => format!("已恢复（{}）", fmt_hm(t)),
          None => "仍在触发".into(),
        };
        let label = item.subject.as_deref().unwrap_or(&item.title);
        lines.push(format!(
          "- {label}（{at} 触发，{state}）· {}",
          item.title
        ));
      }
    }
    sections.push(lines.join("\n"));
  }
  let title = format!("每日汇总（{} 条）", rows.len());
  Some((title, sections.join("\n\n")))
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
        let existing: Option<(i64, Option<i64>)> = c
          .query_row(
            "SELECT id, recovered_at FROM alert_digest
             WHERE source = ?1 AND subject IS ?2 AND is_notice = 0
             ORDER BY id DESC LIMIT 1",
            params![source, subject],
            |r| Ok((r.get(0)?, r.get(1)?)),
          )
          .optional()
          .map_err(db::sql_err)?;
        match existing {
          Some((id, None)) => c.execute(
            "UPDATE alert_digest SET title = ?2 WHERE id = ?1",
            params![id, title],
          ),
          Some((id, Some(_))) => c.execute(
            "UPDATE alert_digest SET title = ?2, fired_at = ?3, recovered_at = NULL WHERE id = ?1",
            params![id, title, now],
          ),
          None => c.execute(
            "INSERT INTO alert_digest (source, subject, title, fired_at, recovered_at, is_notice)
             VALUES (?1, ?2, ?3, ?4, NULL, 0)",
            params![source, subject, title, now],
          ),
        }
        .map(|_| ())
        .map_err(db::sql_err)
      } else {
        c.execute(
          "UPDATE alert_digest SET recovered_at = ?3
           WHERE source = ?1 AND subject IS ?2 AND is_notice = 0 AND recovered_at IS NULL",
          params![source, subject, now],
        )
        .map(|_| ())
        .map_err(db::sql_err)
      }
    })
    .await;
  if let Err(e) = res {
    tracing::warn!("记录每日汇总条目失败：{}", e.message);
  }
}

async fn load_rows(
  state: &AppState,
) -> Result<(Vec<DigestRow>, Option<String>), ApiError> {
  state
    .db
    .call(|c| {
      let last = db::setting(c, LAST_DATE_KEY)?;
      let mut stmt = c
        .prepare(
          "SELECT source, subject, title, fired_at, recovered_at, is_notice
           FROM alert_digest ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      let rows = stmt
        .query_map([], |r| {
          Ok(DigestRow {
            source: r.get(0)?,
            subject: r.get(1)?,
            title: r.get(2)?,
            fired_at: r.get(3)?,
            recovered_at: r.get(4)?,
            is_notice: r.get::<_, i64>(5)? != 0,
          })
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)?;
      Ok((rows, last))
    })
    .await
}

pub(super) async fn preview(
  state: &AppState,
) -> Result<AlertDigestPreview, ApiError> {
  let (rows, last_sent_date) = load_rows(state).await?;
  let count = rows.len();
  let (title, body) = match render(&rows) {
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

/// 检查东八区 09:00 是否该发每日汇总。真正发了返回 true。
pub(super) async fn tick_at(state: &AppState, now: i64) -> bool {
  let Ok((rows, last_date)) = load_rows(state).await else {
    return false;
  };
  let Some(today) = beijing_due_date(now, last_date.as_deref())
  else {
    return false;
  };
  let Some((title, body)) = render(&rows) else {
    // 今天 09:00 没有待汇总内容：不发送，但记下今天已过 09:00，免得之后的新条目提前发出。
    let _ = state
      .db
      .call(move |c| db::set_setting(c, LAST_DATE_KEY, Some(&today)))
      .await;
    return false;
  };
  let event = Event { title, body };
  let skipped = notify::deliver(state, &event).await;
  record_at(state, now, SOURCE_ID, None, &event, true, skipped).await;
  let res = state
    .db
    .call(move |c| {
      let tx = c.unchecked_transaction().map_err(db::sql_err)?;
      tx.execute("DELETE FROM alert_digest", [])
        .map_err(db::sql_err)?;
      db::set_setting(&tx, LAST_DATE_KEY, Some(&today))?;
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
