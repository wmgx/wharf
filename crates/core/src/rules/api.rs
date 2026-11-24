use axum::{
  Json,
  extract::{Path, State},
};
use wharf_api_types::view::{
  AlertAck, AlertAckRequest, AlertOptions, AlertPatch, AlertRuleView,
  AlertSuppressRequest, AlertSuppression, AlertsView, FiringView,
  NoticeView, Perm,
};

use crate::{api::ApiResult, auth::Auth};

use super::*;

async fn view(state: &AppState) -> Result<AlertsView, ApiError> {
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
        level: o.level(r.id),
        muted_until: muted(&o),
        customized: o.threshold.is_some()
          || o.for_n.is_some()
          || o.enabled == Some(false)
          || o.level.is_some(),
      }
    })
    .collect();
  let notices = NOTICES
    .iter()
    .map(|(id, name)| {
      let o = cfg.get(*id).cloned().unwrap_or_default();
      NoticeView {
        id: (*id).into(),
        name: (*name).into(),
        enabled: o.enabled(),
        level: o.level(id),
        muted_until: muted(&o),
      }
    })
    .collect();
  let history = history(state).await;
  let acks = policy::acks(state).await?;
  let suppressions = suppression::BUILT_INS
    .iter()
    .map(|id| {
      (id.to_string(), cfg.get(*id).is_none_or(Override::enabled))
    })
    .collect();
  Ok(with(|m| AlertsView {
    include_logs,
    rules,
    notices,
    suppressions,
    firing: m
      .firing
      .iter()
      .map(|((rule, subject), (since, title))| FiringView {
        rule: rule.clone(),
        subject: subject.clone(),
        title: title.clone(),
        since: *since,
        ack: acks.get(&(rule.clone(), subject.clone())).cloned(),
      })
      .collect(),
    history,
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

/// `PUT /api/alerts/{id}`：规则或事件通知的开关、阈值、连续次数、静默。
pub async fn patch(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<String>,
  Json(p): Json<AlertPatch>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  let _guard = UPDATE.lock().await;
  let rule = RULES.iter().find(|r| r.id == id);
  let builtin = suppression::BUILT_INS.contains(&id.as_str());
  if rule.is_none()
    && !builtin
    && !NOTICES.iter().any(|(n, _)| *n == id)
  {
    let ids: Vec<&str> = RULES
      .iter()
      .map(|r| r.id)
      .chain(NOTICES.iter().map(|n| n.0))
      .chain(suppression::BUILT_INS.iter().copied())
      .collect();
    return Err(
      ApiError::not_found(format!("没有告警 {id}"))
        .with_hint(format!("可选：{}", ids.join("、")))
        .into(),
    );
  }
  if rule.is_none() && (p.threshold.is_some() || p.for_n.is_some()) {
    return Err(
      ApiError::invalid("只有告警规则支持设置阈值和连续次数").into(),
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
  if builtin && (p.level.is_some() || p.mute_minutes.is_some()) {
    return Err(
      ApiError::invalid("内置抑制规则只支持开关和重置").into(),
    );
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
  if let Some(m) = p.mute_minutes {
    o.muted_until = (m > 0).then(|| now_ms() + i64::from(m) * 60_000);
  }
  if let Some(level) = p.level {
    o.level = (level != policy::default_level(&id)).then_some(level);
  }
  cfg.retain(|_, o| {
    o.enabled.is_some()
      || o.threshold.is_some()
      || o.for_n.is_some()
      || o.muted_until.is_some()
      || o.level.is_some()
  });
  let json = serde_json::to_string(&cfg)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  s.db
    .call(move |c| db::set_setting(c, CONFIG_KEY, Some(&json)))
    .await?;
  with(|m| m.config = Some(cfg.clone()));
  if p.enabled == Some(false) && !builtin {
    let now = now_ms();
    for (subject, _) in firing_subjects(&id) {
      set_firing(&s, (id.clone(), subject.clone()), None, now, None)
        .await?;
      let id = id.clone();
      s.db
        .call(move |c| {
          policy::forget_episode(c, &id, &subject, now)
            .map_err(db::sql_err)
        })
        .await?;
    }
  }
  if builtin || p.enabled == Some(false) {
    release(&s, &cfg).await;
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

pub async fn ack(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertAckRequest>,
) -> ApiResult<Option<AlertAck>> {
  auth.require(Perm::Admin)?;
  let _guard = UPDATE.lock().await;
  let ack = s
    .db
    .call(move |c| policy::write_ack(c, req, &auth.name, now_ms()))
    .await?;
  if ack.is_none() {
    let cfg = config(&s).await;
    release(&s, &cfg).await;
  }
  Ok(Json(ack))
}

pub async fn digest_preview(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Option<String>> {
  auth.require(Perm::Read)?;
  Ok(Json(s.db.call(|c| digest::preview(c)).await?))
}

pub async fn suppressions(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<AlertSuppression>> {
  auth.require(Perm::Read)?;
  Ok(Json(s.db.call(|c| suppression::list(c)).await?))
}

pub async fn suppress_add(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertSuppressRequest>,
) -> ApiResult<Vec<AlertSuppression>> {
  auth.require(Perm::Admin)?;
  let _guard = UPDATE.lock().await;
  Ok(Json(s.db.call(move |c| suppression::add(c, req)).await?))
}

pub async fn suppress_remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<i64>,
) -> ApiResult<Vec<AlertSuppression>> {
  auth.require(Perm::Admin)?;
  let _guard = UPDATE.lock().await;
  let items = s
    .db
    .call(move |c| {
      if c
        .execute("DELETE FROM alert_suppression WHERE id = ?1", [id])
        .map_err(db::sql_err)?
        == 0
      {
        return Err(ApiError::not_found(format!(
          "没有抑制规则 #{id}"
        )));
      }
      suppression::list(c)
    })
    .await?;
  let cfg = config(&s).await;
  release(&s, &cfg).await;
  Ok(Json(items))
}
