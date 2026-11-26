use std::sync::Arc;

use axum::{Json, extract::State};
use rusqlite::params;
use wharf_api_types::{
  ApiError,
  view::{
    AlertAckRequest, AlertAckView, AlertUnackRequest, AlertsView,
    Perm,
  },
};

use super::{AckEntry, ensure_loaded, view_for, with};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  state::AppState,
};

/// 连续不触发满 1 小时后确认自动失效。
pub(super) const ACK_TTL_MS: i64 = 60 * 60 * 1000;
pub(super) const MAX_NOTE_CHARS: usize = 200;

pub(super) fn is_expired(ack: &AckEntry, now: i64) -> bool {
  ack.cleared_at.is_some_and(|at| now - at >= ACK_TTL_MS)
}

enum Persist {
  None,
  Delete,
  ClearedAt(Option<i64>),
}

/// 触发状态变化时更新确认计时：恢复开始计时，1 小时内再触发清零，超时则失效。
pub(super) async fn on_firing_change(
  state: &AppState,
  key: &(String, String),
  firing: bool,
  now: i64,
) {
  let action = with(|m| {
    let Some(ack) = m.acks.get_mut(key) else {
      return Persist::None;
    };
    if is_expired(ack, now) {
      m.acks.remove(key);
      return Persist::Delete;
    }
    if firing {
      if ack.cleared_at.is_some() {
        ack.cleared_at = None;
        Persist::ClearedAt(None)
      } else {
        Persist::None
      }
    } else if ack.cleared_at.is_none() {
      ack.cleared_at = Some(now);
      Persist::ClearedAt(Some(now))
    } else {
      Persist::None
    }
  });
  let (rule, subject) = key.clone();
  let res = match action {
    Persist::None => return,
    Persist::Delete => {
      state
        .db
        .call(move |c| {
          c.execute(
            "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
            params![rule, subject],
          )
          .map(|_| ())
          .map_err(db::sql_err)
        })
        .await
    }
    Persist::ClearedAt(cleared) => {
      state
        .db
        .call(move |c| {
          c.execute(
            "UPDATE alert_acks SET cleared_at = ?3 WHERE rule = ?1 AND subject = ?2",
            params![rule, subject, cleared],
          )
          .map(|_| ())
          .map_err(db::sql_err)
        })
        .await
    }
  };
  if let Err(e) = res {
    tracing::warn!("更新告警确认状态失败：{}", e.message);
  }
}

/// 推送前判断该告警当前是否处于有效确认状态；已过期则顺手清理。
pub(super) async fn is_active(
  state: &AppState,
  rule: &str,
  subject: &str,
  now: i64,
) -> bool {
  let key = (rule.to_string(), subject.to_string());
  let (active, expired) = with(|m| match m.acks.get(&key) {
    None => (false, false),
    Some(a) if is_expired(a, now) => {
      m.acks.remove(&key);
      (false, true)
    }
    Some(_) => (true, false),
  });
  if expired {
    let (r, s) = key;
    if let Err(e) = state
      .db
      .call(move |c| {
        c.execute(
          "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
          params![r, s],
        )
        .map(|_| ())
        .map_err(db::sql_err)
      })
      .await
    {
      tracing::warn!("清理过期告警确认失败：{}", e.message);
    }
  }
  active
}

pub(super) fn view_of(
  rule: &str,
  subject: &str,
  now: i64,
) -> Option<AlertAckView> {
  with(|m| {
    let a = m.acks.get(&(rule.to_string(), subject.to_string()))?;
    (!is_expired(a, now)).then(|| AlertAckView {
      by: a.by.clone(),
      at: a.at,
      note: a.note.clone(),
    })
  })
}

pub(super) async fn delete_key(
  state: &AppState,
  rule: &str,
  subject: &str,
) {
  let key = (rule.to_string(), subject.to_string());
  let existed = with(|m| m.acks.remove(&key).is_some());
  if !existed {
    return;
  }
  let (r, s) = key;
  let _ = state
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
        params![r, s],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
}

pub(super) async fn ack_at(
  state: &AppState,
  rule: &str,
  subject: &str,
  by: &str,
  note: Option<String>,
  now: i64,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let key = (rule.to_string(), subject.to_string());
  if !with(|m| m.firing.contains_key(&key)) {
    return Err(
      ApiError::invalid(format!(
        "告警 {rule} / {subject} 没有在触发"
      ))
      .with_hint("先查看正在触发的告警：wharf alert firing")
      .suggest("wharf alert firing"),
    );
  }
  let note =
    note.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
  if note
    .as_ref()
    .is_some_and(|n| n.chars().count() > MAX_NOTE_CHARS)
  {
    return Err(ApiError::invalid(format!(
      "备注最多 {MAX_NOTE_CHARS} 字"
    )));
  }
  let (r, s, actor, note_db) = (
    rule.to_string(),
    subject.to_string(),
    by.to_string(),
    note.clone().unwrap_or_default(),
  );
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT OR REPLACE INTO alert_acks (rule, subject, by_actor, at, note, cleared_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
        params![r, s, actor, now, note_db],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await?;
  with(|m| {
    m.acks.insert(
      key,
      AckEntry {
        by: by.to_string(),
        at: now,
        note,
        cleared_at: None,
      },
    );
  });
  Ok(())
}

pub(super) async fn unack(
  state: &AppState,
  rule: &str,
  subject: &str,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let key = (rule.to_string(), subject.to_string());
  with(|m| m.acks.remove(&key));
  let (r, s) = key;
  state
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
        params![r, s],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await?;
  Ok(())
}

async fn check_ack_scope(
  s: &AppState,
  auth: &Auth,
  rule: &str,
  subject: &str,
) -> Result<(), ApiError> {
  let Some(allowed) = &auth.services else {
    return Ok(());
  };
  ensure_loaded(s).await;
  let custom_svc =
    with(|m| m.custom_rules.get(rule).map(|r| r.service.clone()));
  let snap = crate::snapshot::load(&s.db).await?;
  if !crate::scope_filter::alert_in_scope(
    allowed,
    &snap.world,
    custom_svc.as_deref(),
    rule,
    Some(subject),
  ) {
    return Err(crate::token_scope::forbidden(
      &auth.name,
      allowed,
      "；这条告警不属于名单里的服务或域名",
    ));
  }
  Ok(())
}

/// `POST /api/alerts/ack`
pub async fn ack_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertAckRequest>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  check_ack_scope(&s, &auth, &req.rule, &req.subject).await?;
  ack_at(&s, &req.rule, &req.subject, &auth.name, req.note, now_ms())
    .await?;
  Ok(Json(view_for(&s, &auth).await?))
}

/// `POST /api/alerts/unack`
pub async fn unack_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertUnackRequest>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  check_ack_scope(&s, &auth, &req.rule, &req.subject).await?;
  unack(&s, &req.rule, &req.subject).await?;
  Ok(Json(view_for(&s, &auth).await?))
}
