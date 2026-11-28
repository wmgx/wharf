use std::collections::BTreeMap;

use wharf_api_types::view::{AlertHistoryView, AlertSuppressionView};

use super::{CONFIG_KEY, with};
use crate::{db, notify::Event, state::AppState};

/// 页面和 CLI 一次最多看多少条推送。
const HISTORY: usize = 200;
const KEEP_HISTORY_MS: i64 = 14 * 24 * 60 * 60 * 1000;

pub(crate) const MIGRATION: &str = r#"
ALTER TABLE alert_firing ADD COLUMN body TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_firing ADD COLUMN delivery TEXT NOT NULL DEFAULT 'urgent';
ALTER TABLE alert_firing ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE alert_acks (
  rule TEXT NOT NULL,
  subject TEXT NOT NULL,
  by_actor TEXT NOT NULL,
  at INTEGER NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  cleared_at INTEGER,
  PRIMARY KEY (rule, subject)
);
CREATE TABLE alert_digest (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  subject TEXT,
  title TEXT NOT NULL,
  fired_at INTEGER NOT NULL,
  recovered_at INTEGER,
  is_notice INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alert_digest_source_subject ON alert_digest (source, subject);
CREATE TABLE alert_suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_rule TEXT NOT NULL,
  source_subject TEXT,
  target_rule TEXT NOT NULL,
  target_subject TEXT,
  created_at INTEGER NOT NULL
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Delivery {
  #[default]
  None,
  Urgent,
  Digest,
}

impl Delivery {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Delivery::None => "",
      Delivery::Urgent => "urgent",
      Delivery::Digest => "digest",
    }
  }

  pub(super) fn parse(s: &str) -> Self {
    match s {
      "urgent" => Delivery::Urgent,
      "digest" => Delivery::Digest,
      _ => Delivery::None,
    }
  }
}

#[derive(Debug, Clone)]
pub(super) struct FiringEntry {
  pub(super) since: i64,
  pub(super) title: String,
  pub(super) body: String,
  pub(super) delivery: Delivery,
  pub(super) suppressed: bool,
}

#[derive(Debug, Clone)]
pub(super) struct AckEntry {
  pub(super) by: String,
  pub(super) at: i64,
  pub(super) note: Option<String>,
  pub(super) cleared_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct SuppressionRule {
  pub(super) id: i64,
  pub(super) source_rule: String,
  pub(super) source_subject: Option<String>,
  pub(super) target_rule: String,
  pub(super) target_subject: Option<String>,
  pub(super) created_at: i64,
}

impl SuppressionRule {
  pub(super) fn to_view(&self) -> AlertSuppressionView {
    AlertSuppressionView {
      id: self.id,
      source_rule: self.source_rule.clone(),
      source_subject: self.source_subject.clone(),
      target_rule: self.target_rule.clone(),
      target_subject: self.target_subject.clone(),
      created_at: self.created_at,
    }
  }
}

/// 确保内存缓存已从数据库加载。
pub async fn ensure_loaded(state: &AppState) {
  if with(|m| m.loaded) {
    return;
  }
  let loaded = state
    .db
    .call(|c| {
      let cfg = db::setting(c, CONFIG_KEY)?;
      let mut stmt = c
        .prepare(
          "SELECT rule, subject, since, title, body, delivery, suppressed FROM alert_firing",
        )
        .map_err(db::sql_err)?;
      let firing = stmt
        .query_map([], |r| {
          let delivery: String = r.get(5)?;
          Ok((
            (r.get(0)?, r.get(1)?),
            FiringEntry {
              since: r.get(2)?,
              title: r.get(3)?,
              body: r.get(4)?,
              delivery: Delivery::parse(&delivery),
              suppressed: r.get::<_, i64>(6)? != 0,
            },
          ))
        })
        .and_then(Iterator::collect::<Result<BTreeMap<_, _>, _>>)
        .map_err(db::sql_err)?;
      let mut stmt = c
        .prepare(
          "SELECT rule, subject, by_actor, at, note, cleared_at FROM alert_acks",
        )
        .map_err(db::sql_err)?;
      let acks = stmt
        .query_map([], |r| {
          let note: String = r.get(4)?;
          Ok((
            (r.get(0)?, r.get(1)?),
            AckEntry {
              by: r.get(2)?,
              at: r.get(3)?,
              note: (!note.is_empty()).then_some(note),
              cleared_at: r.get(5)?,
            },
          ))
        })
        .and_then(Iterator::collect::<Result<BTreeMap<_, _>, _>>)
        .map_err(db::sql_err)?;
      let mut stmt = c
        .prepare(
          "SELECT id, source_rule, source_subject, target_rule, target_subject, created_at
           FROM alert_suppressions ORDER BY id ASC",
        )
        .map_err(db::sql_err)?;
      let suppressions = stmt
        .query_map([], |r| {
          Ok(SuppressionRule {
            id: r.get(0)?,
            source_rule: r.get(1)?,
            source_subject: r.get(2)?,
            target_rule: r.get(3)?,
            target_subject: r.get(4)?,
            created_at: r.get(5)?,
          })
        })
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(db::sql_err)?;
      let service_overrides =
        super::service_overrides::load_from_db(c)?;
      let custom_rules = super::custom::load_from_db(c)?;
      Ok((
        cfg,
        firing,
        acks,
        suppressions,
        service_overrides,
        custom_rules,
      ))
    })
    .await;
  let (
    cfg,
    firing,
    acks,
    suppressions,
    service_overrides,
    custom_rules,
  ) = match loaded {
    Ok((
      cfg,
      firing,
      acks,
      suppressions,
      service_overrides,
      custom_rules,
    )) => (
      cfg
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default(),
      firing,
      acks,
      suppressions,
      service_overrides,
      custom_rules,
    ),
    Err(e) => {
      tracing::warn!("读告警配置失败：{}", e.message);
      return;
    }
  };
  with(|m| {
    if !m.loaded {
      m.config = cfg;
      m.firing = firing;
      m.acks = acks;
      m.suppressions = suppressions;
      m.service_overrides = service_overrides;
      m.custom_rules = custom_rules;
      m.loaded = true;
    }
  });
}

/// 开始触发（已经在触发就保留原来的开始时间）或结束触发，内存和库一起改。
pub(super) async fn set_firing(
  state: &AppState,
  key: (String, String),
  fire: Option<FiringEntry>,
) {
  let update = with(|m| match &fire {
    Some(v) => {
      if let Some(old) = m.firing.get_mut(&key) {
        if old.title == v.title && old.body == v.body {
          return None;
        }
        old.title.clone_from(&v.title);
        old.body.clone_from(&v.body);
        Some(true)
      } else {
        m.firing.insert(key.clone(), v.clone());
        Some(false)
      }
    }
    None => m.firing.remove(&key).map(|_| false),
  });
  let Some(update) = update else { return };
  let result = state
    .db
    .call(move |c| {
      let (rule, subject) = key;
      match fire {
        Some(f) if update => c.execute(
          "UPDATE alert_firing SET title = ?3, body = ?4 WHERE rule = ?1 AND subject = ?2",
          rusqlite::params![rule, subject, f.title, f.body],
        ),
        Some(f) => c.execute(
          "INSERT OR REPLACE INTO alert_firing (rule, subject, since, title, body, delivery, suppressed)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
          rusqlite::params![
            rule,
            subject,
            f.since,
            f.title,
            f.body,
            f.delivery.as_str(),
            i64::from(f.suppressed),
          ],
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

pub(super) async fn set_firing_delivery(
  state: &AppState,
  key: (String, String),
  delivery: Delivery,
) {
  let updated = with(|m| {
    if let Some(f) = m.firing.get_mut(&key) {
      f.delivery = delivery;
      true
    } else {
      false
    }
  });
  if !updated {
    return;
  }
  let (rule, subject) = key;
  let d = delivery.as_str();
  if let Err(e) = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE alert_firing SET delivery = ?3 WHERE rule = ?1 AND subject = ?2",
        rusqlite::params![rule, subject, d],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("更新告警推送状态失败：{}", e.message);
  }
}

pub(super) async fn set_firing_suppressed(
  state: &AppState,
  key: (String, String),
  suppressed: bool,
) {
  let updated = with(|m| {
    if let Some(f) = m.firing.get_mut(&key) {
      f.suppressed = suppressed;
      true
    } else {
      false
    }
  });
  if !updated {
    return;
  }
  let (rule, subject) = key;
  if let Err(e) = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE alert_firing SET suppressed = ?3 WHERE rule = ?1 AND subject = ?2",
        rusqlite::params![rule, subject, i64::from(suppressed)],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("更新告警抑制标记失败：{}", e.message);
  }
}

/// 记一条推送，顺手删掉 14 天前的。
pub(super) async fn record_at(
  state: &AppState,
  now: i64,
  id: &str,
  subject: Option<&str>,
  event: &Event,
  ok: bool,
  skipped: Option<String>,
) {
  let (id, title) = (id.to_string(), event.title.clone());
  let subject = subject.map(str::to_string);
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

/// 最近的推送，新的在前。
pub(super) async fn history(
  state: &AppState,
) -> Vec<(AlertHistoryView, Option<String>)> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT at, source, title, ok, skipped, subject FROM alert_history ORDER BY id DESC LIMIT ?1",
        )
        .map_err(db::sql_err)?;
      stmt
        .query_map([HISTORY as i64], |r| {
          Ok((AlertHistoryView {
            at: r.get(0)?,
            source: r.get(1)?,
            title: r.get(2)?,
            ok: r.get(3)?,
            skipped: r.get(4)?,
          }, r.get(5)?))
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)
    })
    .await
    .unwrap_or_else(|e| {
      tracing::warn!("读推送记录失败：{}", e.message);
      vec![]
    })
}
