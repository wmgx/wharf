use std::{sync::Arc, time::Duration};

use chrono::{DateTime, FixedOffset, Timelike};
use rusqlite::Connection;

use super::*;

const LAST: &str = "alerts.digest_date";

fn local(ms: i64) -> DateTime<FixedOffset> {
  db::to_time(ms)
    .with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap())
}

fn due(now: i64, last: Option<&str>) -> Option<String> {
  let time = local(now);
  let date = time.date_naive().to_string();
  (time.hour() >= 9 && last.is_none_or(|last| last < date.as_str()))
    .then_some(date)
}

pub(in crate::rules) fn preview(
  c: &Connection,
) -> Result<Option<String>, ApiError> {
  let mut stmt = c.prepare(
    "SELECT source, subject, at, title, paired, recovered_at FROM alert_digest ORDER BY source, at, id",
  ).map_err(db::sql_err)?;
  let rows = stmt
    .query_map([], |r| {
      Ok((
        r.get::<_, String>(0)?,
        r.get::<_, Option<String>>(1)?,
        r.get::<_, i64>(2)?,
        r.get::<_, String>(3)?,
        r.get::<_, bool>(4)?,
        r.get::<_, Option<i64>>(5)?,
      ))
    })
    .map_err(db::sql_err)?;
  let stamp = |ms| local(ms).format("%m-%d %H:%M").to_string();
  let mut body = String::new();
  let mut last = String::new();
  for row in rows {
    let (id, subject, at, title, paired, end) =
      row.map_err(db::sql_err)?;
    if last != id {
      if !body.is_empty() {
        body.push('\n');
      }
      let name = RULES
        .iter()
        .find(|r| r.id == id)
        .map(|r| r.name)
        .or_else(|| NOTICES.iter().find(|n| n.0 == id).map(|n| n.1))
        .unwrap_or(&id);
      body.push_str(&format!("{name}（{id}）\n"));
      last = id;
    }
    let subject =
      subject.map_or_else(String::new, |s| format!("{s} · "));
    let status = match end {
      Some(end) => format!(" · 已恢复（{}）", stamp(end)),
      None if paired => " · 仍在触发".into(),
      None => String::new(),
    };
    body.push_str(&format!(
      "- {subject}{title} · {}{status}\n",
      stamp(at)
    ));
  }
  Ok((!body.is_empty()).then_some(body))
}

fn claim(
  c: &Connection,
  now: i64,
) -> Result<Option<String>, ApiError> {
  let last = db::setting(c, LAST)?;
  let Some(date) = due(now, last.as_deref()) else {
    return Ok(None);
  };
  let body = preview(c)?;
  db::set_setting(c, LAST, Some(&date))?;
  Ok(body)
}

pub(crate) fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Skip,
    );
    loop {
      interval.tick().await;
      let _guard = UPDATE.lock().await;
      let now = now_ms();
      let cfg = config(&state).await;
      let result = state
        .db
        .call(move |c| {
          c.execute(
            "DELETE FROM alert_ack WHERE recovered_at <= ?1",
            [now - super::policy::ACK_MS],
          )
          .map_err(db::sql_err)?;
          claim(c, now)
        })
        .await;
      match result {
        Ok(Some(body)) => {
          push(
            &state,
            Delivery {
              id: super::policy::DIGEST_ID,
              subject: None,
              paired: false,
              ok: false,
              now,
              replay: false,
            },
            &cfg,
            ev("每日汇总".into(), body),
            None,
          )
          .await;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("生成每日汇总失败：{}", e.message),
      }
      release(&state, &cfg).await;
    }
  });
}

#[cfg(test)]
#[path = "digest_tests.rs"]
mod tests;
