use std::sync::Arc;

use axum::{Json, extract::State};
use rusqlite::params;
use wharf_api_types::{
  ApiError,
  view::{
    AlertAck, AlertAckRequest, AlertUnackRequest, AlertsView, Perm,
  },
};

use super::{AckEntry, http::view, store::config, with};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  state::AppState,
};

/// 告警连续不触发超过此时长后，确认自动失效（1 小时）。
pub(super) const ACK_EXPIRE_MS: i64 = 60 * 60 * 1000;
const MAX_NOTE_CHARS: usize = 200;

pub(super) fn is_expired(cleared_at: Option<i64>, now: i64) -> bool {
  cleared_at.is_some_and(|at| now - at >= ACK_EXPIRE_MS)
}

/// 告警重新进入触发：若恢复已满 1 小时则确认失效，否则清零恢复计时。
pub(super) async fn on_fire(
  state: &AppState,
  key: &(String, String),
  now: i64,
) {
  enum Action {
    None,
    Expire,
    ClearTimer,
  }
  let action = with(|m| {
    let Some(entry) = m.acks.get_mut(key) else {
      return Action::None;
    };
    if is_expired(entry.cleared_at, now) {
      m.acks.remove(key);
      Action::Expire
    } else if entry.cleared_at.is_some() {
      entry.cleared_at = None;
      Action::ClearTimer
    } else {
      Action::None
    }
  });
  let (rule, subject) = key.clone();
  let res = match action {
    Action::None => return,
    Action::Expire => {
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
    Action::ClearTimer => {
      state
        .db
        .call(move |c| {
          c.execute(
            "UPDATE alert_acks SET cleared_at = NULL WHERE rule = ?1 AND subject = ?2",
            params![rule, subject],
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

/// 告警结束触发：若有确认记录，开始 1 小时失效计时。
pub(super) async fn on_recover(
  state: &AppState,
  key: &(String, String),
  now: i64,
) {
  let updated = with(|m| {
    let Some(entry) = m.acks.get_mut(key) else {
      return false;
    };
    if entry.cleared_at.is_none() {
      entry.cleared_at = Some(now);
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
        "UPDATE alert_acks SET cleared_at = ?3 WHERE rule = ?1 AND subject = ?2",
        params![rule, subject, now],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await
  {
    tracing::warn!("记录告警恢复确认计时失败：{}", e.message);
  }
}

/// 检查某条告警当前是否在确认有效期内；过期则顺手清理，不发通知。
pub(super) async fn is_acked(
  state: &AppState,
  rule: &str,
  subject: &str,
  now: i64,
) -> bool {
  let key = (rule.to_string(), subject.to_string());
  let (active, expired) = with(|m| match m.acks.get(&key) {
    Some(e) if is_expired(e.cleared_at, now) => {
      m.acks.remove(&key);
      (false, true)
    }
    Some(_) => (true, false),
    None => (false, false),
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

/// 删除监控项时移除残留确认记录。
pub(super) async fn remove_quiet(
  state: &AppState,
  key: (String, String),
) {
  let existed = with(|m| m.acks.remove(&key).is_some());
  if !existed {
    return;
  }
  let (rule, subject) = key;
  let _ = state
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
        params![rule, subject],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await;
}

/// 定期清理已失效的确认记录，不推任何消息。
pub(super) async fn prune_expired(state: &AppState, now: i64) {
  let _ = config(state).await;
  let expired: Vec<(String, String)> = with(|m| {
    let keys: Vec<_> = m
      .acks
      .iter()
      .filter(|(_, e)| is_expired(e.cleared_at, now))
      .map(|(k, _)| k.clone())
      .collect();
    for k in &keys {
      m.acks.remove(k);
    }
    keys
  });
  if expired.is_empty() {
    return;
  }
  if let Err(e) = state
    .db
    .call(move |c| {
      for (rule, subject) in expired {
        c.execute(
          "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
          params![rule, subject],
        )
        .map_err(db::sql_err)?;
      }
      Ok(())
    })
    .await
  {
    tracing::warn!("清理过期确认记录失败：{}", e.message);
  }
}

/// 读取某条告警当前有效的确认信息（同步读内存，供视图和待处理使用）。
pub(crate) fn active_ack(
  rule: &str,
  subject: &str,
  now: i64,
) -> Option<AlertAck> {
  with(|m| {
    let e = m.acks.get(&(rule.to_string(), subject.to_string()))?;
    if is_expired(e.cleared_at, now) {
      return None;
    }
    Some(AlertAck {
      by: e.by.clone(),
      at: e.at,
      note: e.note.clone(),
    })
  })
}

pub(super) async fn ack_at(
  state: &AppState,
  by: &str,
  req: AlertAckRequest,
  now: i64,
) -> Result<AlertsView, ApiError> {
  let _ = config(state).await;
  let note = req
    .note
    .map(|n| n.trim().to_string())
    .filter(|n| !n.is_empty());
  if let Some(n) = &note
    && n.chars().count() > MAX_NOTE_CHARS
  {
    return Err(ApiError::invalid(format!(
      "备注最多 {MAX_NOTE_CHARS} 字"
    )));
  }
  let key = (req.rule.clone(), req.subject.clone());
  let is_firing = with(|m| m.firing.contains_key(&key));
  if !is_firing {
    return Err(
      ApiError::invalid(format!(
        "告警 {}:{} 当前没有在触发",
        req.rule, req.subject
      ))
      .with_hint("查看正在触发的告警：wharf alert firing"),
    );
  }
  let entry = AckEntry {
    by: by.to_string(),
    at: now,
    note: note.clone(),
    cleared_at: None,
  };
  let (rule, subject, by_s) = (req.rule, req.subject, by.to_string());
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT OR REPLACE INTO alert_acks (rule, subject, by, at, note, cleared_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
        params![rule, subject, by_s, now, note],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await?;
  with(|m| {
    m.acks.insert(key, entry);
  });
  view(state).await
}

pub(super) async fn unack_impl(
  state: &AppState,
  req: AlertUnackRequest,
) -> Result<AlertsView, ApiError> {
  let _ = config(state).await;
  let key = (req.rule.clone(), req.subject.clone());
  let existed = with(|m| m.acks.remove(&key).is_some());
  let (rule, subject) = key;
  let deleted = state
    .db
    .call(move |c| {
      c.execute(
        "DELETE FROM alert_acks WHERE rule = ?1 AND subject = ?2",
        params![rule, subject],
      )
      .map_err(db::sql_err)
    })
    .await?;
  if !existed && deleted == 0 {
    return Err(
      ApiError::not_found(format!(
        "告警 {}:{} 没有确认记录",
        req.rule, req.subject
      ))
      .with_hint("查看正在触发的告警：wharf alert firing"),
    );
  }
  view(state).await
}

/// `POST /api/alerts/ack`
pub async fn ack(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertAckRequest>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  Ok(Json(ack_at(&s, &auth.name, req, now_ms()).await?))
}

/// `POST /api/alerts/unack`
pub async fn unack(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertUnackRequest>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  Ok(Json(unack_impl(&s, req).await?))
}
