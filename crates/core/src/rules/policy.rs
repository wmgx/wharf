use rusqlite::{Connection, OptionalExtension, params};
use wharf_api_types::{
  ApiError,
  view::{AlertAck, AlertAckRequest, AlertLevel},
};

use super::*;

pub(super) const ACK_MS: i64 = 60 * 60 * 1000;
pub(super) const DIGEST_SKIP: &str = "并入每日汇总";
pub(super) const DIGEST_ID: &str = "daily_digest";

pub(crate) const MIGRATION: &str = "
CREATE TABLE alert_ack (
  rule TEXT NOT NULL,
  subject TEXT NOT NULL,
  actor TEXT NOT NULL,
  at INTEGER NOT NULL,
  note TEXT,
  recovered_at INTEGER,
  PRIMARY KEY (rule, subject)
);
CREATE TABLE alert_episode (
  source TEXT NOT NULL,
  subject TEXT NOT NULL,
  at INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  outcome TEXT NOT NULL,
  digest_id INTEGER,
  PRIMARY KEY (source, subject)
);
INSERT INTO alert_episode (source, subject, at, title, body, outcome)
SELECT f.rule, f.subject, f.since, f.title, '', 'sent'
FROM alert_firing f
JOIN alert_history h ON h.id = (
  SELECT id FROM alert_history
  WHERE source = f.rule AND subject = f.subject AND at >= f.since
  ORDER BY id DESC LIMIT 1
)
WHERE h.ok = 0 AND h.skipped IS NULL;
CREATE TABLE alert_digest (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  subject TEXT,
  at INTEGER NOT NULL,
  title TEXT NOT NULL,
  paired INTEGER NOT NULL,
  recovered_at INTEGER
);
CREATE TABLE alert_suppression (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  ignore TEXT NOT NULL
);
";

pub(super) fn default_level(id: &str) -> AlertLevel {
  match id {
    "traffic_quota"
    | "disk_forecast"
    | "mem_forecast"
    | "expiry_soon"
    | "expiry_urgent"
    | "cert_expiring"
    | "tailnet_key_expiring"
    | "tailnet_relay"
    | "external_incident"
    | "svc_mem_near_limit"
    | "inode_high"
    | "agent_mem_high"
    | "update"
    | "unmanaged_container" => AlertLevel::Digest,
    _ => AlertLevel::Urgent,
  }
}

pub(super) fn guard(
  o: &Override,
  acked: bool,
  now: i64,
) -> Option<&'static str> {
  if !o.enabled() {
    Some("已关闭")
  } else if o.muted(now) {
    Some("静默中")
  } else if acked {
    Some("已确认")
  } else {
    None
  }
}

pub(super) fn update_ack(
  c: &Connection,
  rule: &str,
  subject: &str,
  fire: bool,
  now: i64,
) -> rusqlite::Result<()> {
  if fire {
    c.execute(
      "DELETE FROM alert_ack WHERE rule = ?1 AND subject = ?2 AND recovered_at <= ?3",
      params![rule, subject, now - ACK_MS],
    )?;
    c.execute(
      "UPDATE alert_ack SET recovered_at = NULL WHERE rule = ?1 AND subject = ?2",
      params![rule, subject],
    )?;
  } else {
    c.execute(
      "UPDATE alert_ack SET recovered_at = ?3 WHERE rule = ?1 AND subject = ?2 AND recovered_at IS NULL",
      params![rule, subject, now],
    )?;
  }
  Ok(())
}

pub(super) fn write_ack(
  c: &Connection,
  req: AlertAckRequest,
  actor: &str,
  now: i64,
) -> Result<Option<AlertAck>, ApiError> {
  let AlertAckRequest {
    rule,
    subject,
    acked,
    note,
  } = req;
  if !acked {
    c.execute(
      "DELETE FROM alert_ack WHERE rule = ?1 AND subject = ?2",
      params![rule, subject],
    )
    .map_err(db::sql_err)?;
    return Ok(None);
  }
  if note.as_ref().is_some_and(|n| n.chars().count() > 200) {
    return Err(ApiError::invalid("备注最多 200 字"));
  }
  let active: bool = c.query_row(
    "SELECT EXISTS (SELECT 1 FROM alert_firing WHERE rule = ?1 AND subject = ?2)",
    params![rule, subject], |r| r.get(0),
  ).map_err(db::sql_err)?;
  if !active {
    return Err(
      ApiError::not_found(format!(
        "告警 {rule} / {subject} 正在触发的记录不存在"
      ))
      .with_hint("wharf alert firing"),
    );
  }
  let note =
    note.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
  c.execute(
    "INSERT OR REPLACE INTO alert_ack (rule, subject, actor, at, note) VALUES (?1, ?2, ?3, ?4, ?5)",
    params![rule, subject, actor, now, note],
  ).map_err(db::sql_err)?;
  Ok(Some(AlertAck {
    by: actor.into(),
    at: now,
    note,
  }))
}

pub(crate) async fn acks(
  state: &AppState,
) -> Result<BTreeMap<(String, String), AlertAck>, ApiError> {
  state
    .db
    .call(|c| {
      let mut stmt = c
        .prepare(
          "SELECT a.rule, a.subject, a.actor, a.at, a.note
       FROM alert_ack a JOIN alert_firing f USING (rule, subject)
       WHERE a.recovered_at IS NULL",
        )
        .map_err(db::sql_err)?;
      stmt
        .query_map([], |r| {
          Ok((
            (r.get(0)?, r.get(1)?),
            AlertAck {
              by: r.get(2)?,
              at: r.get(3)?,
              note: r.get(4)?,
            },
          ))
        })
        .and_then(Iterator::collect)
        .map_err(db::sql_err)
    })
    .await
}

#[derive(Clone, Copy)]
pub(super) struct Delivery<'a> {
  pub id: &'a str,
  pub subject: Option<&'a str>,
  pub paired: bool,
  pub ok: bool,
  pub now: i64,
  pub replay: bool,
}

fn is_acked(
  c: &Connection,
  id: &str,
  subject: &str,
  now: i64,
) -> rusqlite::Result<bool> {
  c.query_row(
    "SELECT EXISTS (SELECT 1 FROM alert_ack
     WHERE rule = ?1 AND subject = ?2 AND (recovered_at IS NULL OR recovered_at > ?3))",
    params![id, subject, now - ACK_MS], |r| r.get(0),
  )
}

pub(super) struct Episode {
  at: i64,
  title: String,
  outcome: String,
  digest_id: Option<i64>,
}

pub(super) fn episode(
  c: &Connection,
  id: &str,
  subject: &str,
) -> rusqlite::Result<Option<Episode>> {
  c.query_row(
    "SELECT at, title, outcome, digest_id FROM alert_episode WHERE source = ?1 AND subject = ?2",
    params![id, subject],
    |r| Ok(Episode { at: r.get(0)?, title: r.get(1)?, outcome: r.get(2)?, digest_id: r.get(3)? }),
  ).optional()
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
  Send,
  Digest,
  Skip(String),
  Suppress(String),
}

fn decide(
  guard: Option<&str>,
  suppression: Option<String>,
  level: AlertLevel,
  recovery: bool,
  previous: Option<&Episode>,
) -> Decision {
  if let Some(reason) = guard {
    return Decision::Skip(reason.into());
  }
  if let Some(reason) = suppression {
    return Decision::Suppress(reason);
  }
  if recovery {
    return match previous.map(|e| e.outcome.as_str()) {
      Some("sent") => Decision::Send,
      Some("digest") => Decision::Digest,
      Some(reason) if reason.starts_with("被抑制：") => {
        Decision::Skip(reason.into())
      }
      _ => Decision::Skip("触发未推送".into()),
    };
  }
  match level {
    AlertLevel::Urgent => Decision::Send,
    AlertLevel::Digest => Decision::Digest,
  }
}

/// 调用方持有 UPDATE，保证触发、恢复、补推和汇总按序落库。
pub(super) async fn push(
  state: &AppState,
  d: Delivery<'_>,
  cfg: &BTreeMap<String, Override>,
  event: Event,
  online_since: Option<i64>,
) -> Option<String> {
  match push_inner(state, d, cfg, event, online_since).await {
    Ok(skipped) => skipped,
    Err(e) => {
      tracing::warn!("处理告警推送失败：{}", e.message);
      Some(format!("处理失败：{}", e.message))
    }
  }
}

async fn push_inner(
  state: &AppState,
  d: Delivery<'_>,
  cfg: &BTreeMap<String, Override>,
  mut event: Event,
  online_since: Option<i64>,
) -> Result<Option<String>, ApiError> {
  let Delivery {
    id,
    subject,
    paired,
    ok,
    now,
    replay,
  } = d;
  let o = cfg.get(id).cloned().unwrap_or_default();
  let key = (id.to_string(), subject.unwrap_or_default().to_string());
  let recovery = paired && ok;
  let (acked, previous) = if paired {
    state
      .db
      .call({
        let (id, subject) = key.clone();
        move |c| {
          let acked =
            is_acked(c, &id, &subject, now).map_err(db::sql_err)?;
          let previous = if recovery || replay {
            episode(c, &id, &subject).map_err(db::sql_err)?
          } else {
            None
          };
          Ok((acked, previous))
        }
      })
      .await?
  } else {
    (false, None)
  };
  let guard = guard(&o, acked, now);
  let suppression =
    if guard.is_none() && subject.is_some() && id != DIGEST_ID {
      super::suppression::reason(state, cfg, id, &key.1).await?
    } else {
      None
    };
  let decision = decide(
    guard,
    suppression,
    o.level(id),
    recovery,
    previous.as_ref(),
  );
  if replay && matches!(decision, Decision::Suppress(_)) {
    return Ok(None);
  }
  let skipped = match &decision {
    Decision::Skip(reason) | Decision::Suppress(reason) => {
      Some(reason.clone())
    }
    Decision::Digest => Some(DIGEST_SKIP.into()),
    Decision::Send => {
      if !ok && !matches!(id, DIGEST_ID | "notify_hook") {
        event =
          crate::alert_context::enrich(state, id, subject, event)
            .await;
      } else if id == "server_offline"
        && let Some(subject) = subject
      {
        event = crate::alert_context::back_online(
          state,
          subject,
          online_since,
          event,
        )
        .await;
      }
      notify::deliver(state, &event).await
    }
  };
  let source = key.0;
  let subject = subject.map(str::to_string);
  state
    .db
    .call({
      let skipped = skipped.clone();
      move |c| {
        let tx = c.transaction().map_err(db::sql_err)?;
        let d = Delivery {
          id: &source,
          subject: subject.as_deref(),
          paired,
          ok,
          now,
          replay,
        };
        persist(
          &tx,
          d,
          &event,
          skipped.as_deref(),
          previous.as_ref(),
        )
        .map_err(db::sql_err)?;
        tx.commit().map_err(db::sql_err)
      }
    })
    .await?;
  Ok(skipped)
}

pub(super) fn persist(
  c: &Connection,
  d: Delivery<'_>,
  event: &Event,
  skipped: Option<&str>,
  previous: Option<&Episode>,
) -> rusqlite::Result<()> {
  let Delivery {
    id,
    subject,
    paired,
    ok,
    now,
    ..
  } = d;
  let key = subject.unwrap_or_default();
  let outcome = match skipped {
    None => "sent",
    Some(DIGEST_SKIP) => "digest",
    Some(reason) => reason,
  };
  let digest_id =
    save_digest(c, d, &event.title, outcome == "digest", previous)?;
  if paired && ok {
    c.execute(
      "DELETE FROM alert_episode WHERE source = ?1 AND subject = ?2",
      params![id, key],
    )?;
  } else if paired {
    let at = previous.map_or(now, |e| e.at);
    let body = if outcome.starts_with("被抑制：") {
      event.body.as_str()
    } else {
      ""
    };
    c.execute(
      "INSERT OR REPLACE INTO alert_episode (source, subject, at, title, body, outcome, digest_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
      params![id, key, at, event.title, body, outcome, digest_id],
    )?;
  }
  if id == DIGEST_ID && skipped.is_none() {
    c.execute("DELETE FROM alert_digest", [])?;
  }
  c.execute(
    "INSERT INTO alert_history (at, source, subject, title, ok, skipped) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![now, id, subject, event.title, ok, skipped],
  )?;
  c.execute(
    "DELETE FROM alert_history WHERE at < ?1",
    [now - KEEP_HISTORY_MS],
  )?;
  Ok(())
}

fn save_digest(
  c: &Connection,
  d: Delivery<'_>,
  title: &str,
  queue: bool,
  previous: Option<&Episode>,
) -> rusqlite::Result<Option<i64>> {
  let Delivery {
    id,
    subject,
    paired,
    ok,
    now,
    ..
  } = d;
  if paired && ok {
    if let Some(previous) = previous
      && let Some(row) = previous.digest_id
      && c.execute(
        "UPDATE alert_digest SET recovered_at = ?2 WHERE id = ?1",
        params![row, now],
      )? > 0
    {
      return Ok(None);
    }
    if queue && let Some(previous) = previous {
      return insert_digest(
        c,
        id,
        subject,
        previous.at,
        &previous.title,
        true,
        Some(now),
      )
      .map(Some);
    }
  } else if queue {
    let at = previous.map_or(now, |e| e.at);
    return insert_digest(c, id, subject, at, title, paired, None)
      .map(Some);
  }
  Ok(None)
}

fn insert_digest(
  c: &Connection,
  source: &str,
  subject: Option<&str>,
  at: i64,
  title: &str,
  paired: bool,
  recovered: Option<i64>,
) -> rusqlite::Result<i64> {
  c.execute(
    "INSERT INTO alert_digest (source, subject, at, title, paired, recovered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    params![source, subject, at, title, paired, recovered],
  )?;
  Ok(c.last_insert_rowid())
}

pub(super) fn forget_episode(
  c: &Connection,
  id: &str,
  subject: &str,
  now: i64,
) -> rusqlite::Result<()> {
  let previous = episode(c, id, subject)?;
  let d = Delivery {
    id,
    subject: Some(subject),
    paired: true,
    ok: true,
    now,
    replay: false,
  };
  save_digest(c, d, "", false, previous.as_ref())?;
  c.execute(
    "DELETE FROM alert_episode WHERE source = ?1 AND subject = ?2",
    params![id, subject],
  )?;
  Ok(())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
