use std::sync::Arc;

use axum::{
  Json,
  extract::{Path, State},
};
use wharf_api_types::{
  ApiError,
  view::{
    AlertAckView, AlertOptions, AlertPatch, AlertRuleView,
    AlertsView, BuiltinSuppressionView, FiringView, NoticeView, Perm,
  },
};

use super::{
  CONFIG_KEY, KEEP, Mode, NOTICES, Override, RULES, SuppressionRule,
  ack, config, default_level, store, suppress, with,
};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  state::AppState,
};

pub(super) async fn view(
  state: &AppState,
) -> Result<AlertsView, ApiError> {
  let include_logs = state
    .db
    .call(|c| db::setting(c, "alerts.include_logs"))
    .await?
    .is_some();
  let cfg = config(state).await;
  let now = now_ms();
  let muted = |o: &Override| o.muted_until.filter(|t| *t > now);
  let rules = RULES
    .iter()
    .map(|r| {
      let o = cfg.get(r.id).cloned().unwrap_or_default();
      let threshold = o.threshold.unwrap_or(r.threshold);
      let for_n = o.for_n.unwrap_or(r.for_n);
      let level = o.level.unwrap_or(r.default_level);
      let times = match r.mode {
        Mode::Consecutive | Mode::ServiceLog | Mode::Heartbeat => {
          format!("连续 {for_n} 次")
        }
        Mode::Window(w) => format!("最近 {w} 次里有 {for_n} 次"),
      };
      AlertRuleView {
        id: r.id.into(),
        name: r.name.into(),
        metric: r.metric.into(),
        condition: format!(
          "{} {} {threshold} {times}（{}）",
          r.metric,
          r.op.text(),
          r.every
        ),
        op: r.op.text().into(),
        threshold,
        for_n,
        threshold_editable: r.threshold_editable,
        enabled: o.enabled(),
        level,
        muted_until: muted(&o),
        customized: o.threshold.is_some()
          || o.for_n.is_some()
          || o.level.is_some()
          || o.enabled == Some(false),
      }
    })
    .collect();
  let notices = NOTICES
    .iter()
    .map(|(id, name, def_level)| {
      let o = cfg.get(*id).cloned().unwrap_or_default();
      NoticeView {
        id: (*id).into(),
        name: (*name).into(),
        enabled: o.enabled(),
        level: o.level.unwrap_or(*def_level),
        muted_until: muted(&o),
        customized: o.level.is_some() || o.enabled == Some(false),
      }
    })
    .collect();
  let builtin_suppressions = suppress::BUILTINS
    .iter()
    .map(|(id, name)| {
      let o = cfg.get(*id).cloned().unwrap_or_default();
      BuiltinSuppressionView {
        id: (*id).into(),
        name: (*name).into(),
        enabled: o.enabled(),
      }
    })
    .collect();
  let history = store::history(state).await;
  Ok(with(|m| {
    let firing = m
      .firing
      .iter()
      .map(|((rule, subject), f)| FiringView {
        rule: rule.clone(),
        subject: subject.clone(),
        title: f.title.clone(),
        since: f.since,
        ack: m
          .acks
          .get(&(rule.clone(), subject.clone()))
          .filter(|a| !ack::is_expired(a, now))
          .map(|a| AlertAckView {
            by: a.by.clone(),
            at: a.at,
            note: a.note.clone(),
          }),
      })
      .collect();
    let suppressions = m
      .suppressions
      .iter()
      .map(SuppressionRule::to_view)
      .collect();
    AlertsView {
      include_logs,
      rules,
      notices,
      firing,
      history,
      builtin_suppressions,
      suppressions,
    }
  }))
}

/// `GET /api/alerts`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Read)?;
  Ok(Json(view(&s).await?))
}

/// `PUT /api/alerts/{id}`：规则、事件通知或内置抑制的开关、阈值、连续次数、级别、静默。
pub async fn patch(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
  Json(p): Json<AlertPatch>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  let rule = RULES.iter().find(|r| r.id == id);
  let notice = NOTICES.iter().find(|(n, _, _)| *n == id);
  let builtin_sup = suppress::is_builtin(&id);
  if rule.is_none() && notice.is_none() && !builtin_sup {
    let ids: Vec<&str> = RULES
      .iter()
      .map(|r| r.id)
      .chain(NOTICES.iter().map(|n| n.0))
      .chain(suppress::BUILTINS.iter().map(|b| b.0))
      .collect();
    return Err(
      ApiError::not_found(format!("没有告警 {id}"))
        .with_hint(format!("可选：{}", ids.join("、")))
        .into(),
    );
  }
  if builtin_sup
    && (p.threshold.is_some()
      || p.for_n.is_some()
      || p.level.is_some()
      || p.mute_minutes.is_some())
  {
    return Err(
      ApiError::invalid("内置抑制规则只能开关或恢复默认").into(),
    );
  }
  if rule.is_none()
    && !builtin_sup
    && (p.threshold.is_some() || p.for_n.is_some())
  {
    return Err(
      ApiError::invalid(
        "事件通知没有阈值和连续次数，只能改开关、级别和静默",
      )
      .into(),
    );
  }
  if let Some(r) = rule {
    if p.threshold.is_some() && !r.threshold_editable {
      return Err(
        ApiError::invalid(format!(
          "{} 的阈值固定，改连续次数",
          r.name
        ))
        .into(),
      );
    }
    if p.threshold.is_some_and(|t| !t.is_finite()) {
      return Err(ApiError::invalid("阈值要是数字").into());
    }
    if p.for_n.is_some_and(|n| n == 0 || n as usize > KEEP) {
      return Err(
        ApiError::invalid(format!("连续次数在 1 到 {KEEP} 之间"))
          .into(),
      );
    }
  }
  let mut cfg = config(&s).await;
  let o = cfg.entry(id.clone()).or_default();
  if p.reset {
    *o = Override::default();
  }
  if let Some(v) = p.enabled {
    o.enabled = (!v).then_some(false);
  }
  if let Some(t) = p.threshold {
    o.threshold = rule.filter(|r| r.threshold != t).map(|_| t);
  }
  if let Some(n) = p.for_n {
    o.for_n = rule.filter(|r| r.for_n != n).map(|_| n);
  }
  if let Some(lvl) = p.level {
    o.level = (lvl != default_level(&id)).then_some(lvl);
  }
  if let Some(m) = p.mute_minutes {
    o.muted_until = (m > 0).then(|| now_ms() + i64::from(m) * 60_000);
  }
  cfg.retain(|_, o| {
    o.enabled.is_some()
      || o.threshold.is_some()
      || o.for_n.is_some()
      || o.level.is_some()
      || o.muted_until.is_some()
  });
  let json = serde_json::to_string(&cfg)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  s.db
    .call(move |c| db::set_setting(c, CONFIG_KEY, Some(&json)))
    .await?;
  with(|m| m.config = cfg);
  if builtin_sup && p.enabled == Some(false) {
    suppress::flush_unsuppressed(&s, now_ms()).await;
  }
  Ok(Json(view(&s).await?))
}

/// `PUT /api/alerts/options`：触发的告警是否附带服务日志。
pub async fn set_options(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(o): Json<AlertOptions>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  s.db
    .call(move |c| {
      db::set_setting(
        c,
        "alerts.include_logs",
        o.include_logs.then_some("1"),
      )
    })
    .await?;
  Ok(Json(view(&s).await?))
}
