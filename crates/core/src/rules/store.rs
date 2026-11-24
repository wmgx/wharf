use std::collections::BTreeMap;

use wharf_api_types::view::CustomSuppressionView;

use super::{
  AckEntry, CONFIG_KEY, FiringEntry, KEEP_HISTORY_MS, Override, ack,
  with,
};
use crate::{
  db::{self, now_ms},
  notify::Event,
  state::AppState,
};

pub(crate) const MIGRATION: &str = r#"
ALTER TABLE alert_firing ADD COLUMN body TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_firing ADD COLUMN pushed INTEGER NOT NULL DEFAULT 1;
CREATE TABLE alert_acks (
  rule TEXT NOT NULL,
  subject TEXT NOT NULL,
  by TEXT NOT NULL,
  at INTEGER NOT NULL,
  note TEXT,
  cleared_at INTEGER,
  PRIMARY KEY (rule, subject)
);
CREATE TABLE alert_digest (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  rule TEXT NOT NULL,
  subject TEXT,
  title TEXT NOT NULL,
  ok INTEGER NOT NULL
);
CREATE INDEX alert_digest_at ON alert_digest (at);
CREATE TABLE alert_suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_rule TEXT NOT NULL,
  source_subject TEXT,
  target_rule TEXT NOT NULL,
  target_subject TEXT
);
"#;

pub(super) async fn config(
  state: &AppState,
) -> BTreeMap<String, Override> {
  if let Some(c) = with(|m| m.config.clone()) {
    return c;
  }
  let now = now_ms();
  let loaded = state
    .db
    .call(move |c| {
      let cfg = db::setting(c, CONFIG_KEY)?;
      let mut stmt = c
        .prepare(
          "SELECT rule, subject, since, title, body, pushed FROM alert_firing",
        )
        .map_err(db::sql_err)?;
      let firing: BTreeMap<(String, String), FiringEntry> = stmt
        .query_map([], |r| {
          Ok((
            (r.get(0)?, r.get(1)?),
            FiringEntry {
              since: r.get(2)?,
              title: r.get(3)?,
              body: r.get(4)?,
              pushed: r.get::<_, i64>(5)? != 0,
            },
          ))
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)?;
      let mut stmt = c
        .prepare(
          "SELECT rule, subject, by, at, note, cleared_at FROM alert_acks",
        )
        .map_err(db::sql_err)?;
      let mut acks: BTreeMap<(String, String), AckEntry> = stmt
        .query_map([], |r| {
          Ok((
            (r.get(0)?, r.get(1)?),
            AckEntry {
              by: r.get(2)?,
              at: r.get(3)?,
              note: r.get(4)?,
              cleared_at: r.get(5)?,
            },
          ))
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)?;
      let mut expired = Vec::new();
      for (k, e) in &mut acks {
        if e.cleared_at.is_none() && !firing.contains_key(k) {
          e.cleared_at = Some(now);
          c.execute(
            "UPDATE alert_acks SET cleared_at = ?3 WHERE rule = ?1 AND subject = ?2",
            rusqlite::params![k.0, k.1, now],
          )
          .map_err(db::sql_err)?;
        }
        if ack::is_expired(e.cleared_at, now) {
          expired.push(k.clone());
        }
      }
      for k in expired {
        acks.remove(&k);
        c.execute(
          "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
          rusqlite::params![k.0, k.1],
        )
        .map_err(db::sql_err)?;
      }
      let mut stmt = c
        .prepare(
          "SELECT id, source_rule, source_subject, target_rule, target_subject FROM alert_suppressions ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      let suppressions: Vec<CustomSuppressionView> = stmt
        .query_map([], |r| {
          Ok(CustomSuppressionView {
            id: r.get(0)?,
            source_rule: r.get(1)?,
            source_subject: r.get(2)?,
            target_rule: r.get(3)?,
            target_subject: r.get(4)?,
          })
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)?;
      Ok((cfg, firing, acks, suppressions))
    })
    .await;
  let (cfg, firing, acks, suppressions) = match loaded {
    Ok((cfg, firing, acks, suppressions)) => (
      cfg
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default(),
      firing,
      acks,
      suppressions,
    ),
    Err(e) => {
      tracing::warn!("读告警配置失败：{}", e.message);
      return BTreeMap::new();
    }
  };
  with(|m| {
    if m.config.is_none() {
      m.firing = firing;
      m.acks = acks;
      m.suppressions = suppressions;
    }
    m.config.get_or_insert(cfg).clone()
  })
}

/// 标记一条正在触发的告警已经策略放行推送/汇总。
pub(super) async fn mark_pushed(
  state: &AppState,
  key: &(String, String),
) {
  let updated = with(|m| {
    let Some(e) = m.firing.get_mut(key) else {
      return false;
    };
    if !e.pushed {
      e.pushed = true;
      true
    } else {
      false
    }
  });
  if !updated {
    return;
  }
  let (rule, subject) = key.clone();
  if let Err(e) = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE alert_firing SET pushed = 1 WHERE rule = ?1 AND subject = ?2",
        rusqlite::params![rule, subject],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("更新告警推送标记失败：{}", e.message);
  }
}

/// 开始触发（已经在触发就保留原来的开始时间）或结束触发，内存和库一起改。
pub(super) async fn set_firing(
  state: &AppState,
  key: (String, String),
  fire: Option<FiringEntry>,
) {
  let changed = with(|m| match &fire {
    Some(v) if !m.firing.contains_key(&key) => {
      m.firing.insert(key.clone(), v.clone());
      true
    }
    Some(_) => false,
    None => m.firing.remove(&key).is_some(),
  });
  if !changed {
    return;
  }
  let result = state
    .db
    .call(move |c| {
      let (rule, subject) = key;
      match fire {
        Some(f) => c.execute(
          "INSERT OR REPLACE INTO alert_firing (rule, subject, since, title, body, pushed) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
          rusqlite::params![rule, subject, f.since, f.title, f.body, i64::from(f.pushed)],
        ),
        None => c.execute(
          "DELETE FROM alert_firing WHERE rule = ?1 AND subject = ?2",
          rusqlite::params![rule, subject],
        ),
      }
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录正在触发的告警失败：{}", e.message);
  }
}

/// 记一条推送，顺手删掉 7 天前的。
pub(super) async fn record_at(
  state: &AppState,
  now: i64,
  target: (&str, Option<&str>),
  event: &Event,
  ok: bool,
  skipped: Option<String>,
) {
  let (id, title) = (target.0.to_string(), event.title.clone());
  let subject = target.1.map(str::to_string);
  let result = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO alert_history (at, source, subject, title, ok, skipped) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![now, id, subject, title, ok, skipped],
      )
      .and_then(|_| {
        c.execute(
          "DELETE FROM alert_history WHERE at < ?1",
          [now - KEEP_HISTORY_MS],
        )
      })
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
  if let Err(e) = result {
    tracing::warn!("记录推送失败：{}", e.message);
  }
}
