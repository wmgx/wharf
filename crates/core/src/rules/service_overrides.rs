//! 按服务的内置告警规则覆盖。

use std::{collections::BTreeMap, sync::Arc};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{Connection, params};
use wharf_api_types::{
  ApiError,
  view::{AlertPatch, AlertsView, Perm, ServiceAlertOverrideView},
};

use super::{
  KEEP, NOTICES, Override, RULES,
  custom::{CustomRule, level_str, parse_level, service_exists},
  ensure_loaded, split_unit, suppress, with,
};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  state::AppState,
};

/// 支持按服务覆盖的内置规则（对象为服务或 `<服务>:<子项>`）。
pub(super) const SERVICE_RULES: &[&str] = &[
  "svc_mem_near_limit",
  "container_restarting",
  "oom_killed",
  "monitor_failed",
  "http_5xx",
  "log_keyword",
  "port_down",
  "heartbeat_late",
  "mem_forecast",
];

pub(crate) fn is_service_rule(id: &str) -> bool {
  SERVICE_RULES.contains(&id)
}

/// 从一条内置规则的 subject 提取对应的服务名；非服务对象返回 `None`。
pub(crate) fn service_of_subject<'a>(
  rule_id: &str,
  subject: &'a str,
) -> Option<&'a str> {
  match rule_id {
    "svc_mem_near_limit"
    | "container_restarting"
    | "oom_killed"
    | "monitor_failed"
    | "http_5xx"
    | "heartbeat_late" => Some(subject),
    "log_keyword" | "port_down" => Some(split_unit(subject).0),
    "mem_forecast" => subject.strip_prefix("服务 "),
    _ => None,
  }
}

/// 纯函数：合并全局覆盖与服务覆盖（服务覆盖优先于全局覆盖）。
pub(super) fn effective_override(
  global: Option<&Override>,
  service: Option<&Override>,
  now: i64,
) -> Override {
  let mut g = global.cloned().unwrap_or_default();
  g.muted_until = g.muted_until.filter(|&until| until > now);
  let Some(s) = service else {
    return g;
  };
  Override {
    enabled: s.enabled.or(g.enabled),
    threshold: s.threshold.or(g.threshold),
    for_n: s.for_n.or(g.for_n),
    level: s.level.or(g.level),
    muted_until: s
      .muted_until
      .filter(|&until| until > now)
      .max(g.muted_until),
  }
}

/// 给补推（flush_unsuppressed）查有效覆盖，支持内置规则（含服务覆盖）和自定义规则。
pub(super) fn override_for_firing(
  cfg: &BTreeMap<String, Override>,
  service_overrides: &BTreeMap<(String, String), Override>,
  custom_rules: &BTreeMap<String, CustomRule>,
  rule_id: &str,
  subject: &str,
  now: i64,
) -> Override {
  if let Some(cr) = custom_rules.get(rule_id) {
    return cr.as_override();
  }
  let svc = service_of_subject(rule_id, subject).and_then(|svc| {
    service_overrides.get(&(rule_id.to_string(), svc.to_string()))
  });
  effective_override(cfg.get(rule_id), svc, now)
}

pub(super) fn load_from_db(
  c: &Connection,
) -> Result<BTreeMap<(String, String), Override>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT rule, service, enabled, threshold, for_n, level, muted_until
       FROM alert_service_overrides",
    )
    .map_err(db::sql_err)?;
  stmt
    .query_map([], |r| {
      let enabled: Option<i64> = r.get(2)?;
      let for_n: Option<i64> = r.get(4)?;
      let level: Option<String> = r.get(5)?;
      Ok((
        (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
        Override {
          enabled: enabled.map(|v| v != 0),
          threshold: r.get(3)?,
          for_n: for_n.and_then(|v| u32::try_from(v).ok()),
          level: level.as_deref().map(parse_level),
          muted_until: r.get(6)?,
        },
      ))
    })
    .and_then(Iterator::collect::<Result<BTreeMap<_, _>, _>>)
    .map_err(db::sql_err)
}

pub(super) fn views(
  overrides: &BTreeMap<(String, String), Override>,
  now: i64,
) -> Vec<ServiceAlertOverrideView> {
  overrides
    .iter()
    .map(|((rule, service), o)| ServiceAlertOverrideView {
      rule: rule.clone(),
      service: service.clone(),
      enabled: o.enabled,
      threshold: o.threshold,
      for_n: o.for_n,
      level: o.level,
      muted_until: o.muted_until.filter(|t| *t > now),
    })
    .collect()
}

pub(super) async fn set_override(
  state: &AppState,
  id: &str,
  service: &str,
  p: AlertPatch,
  now: i64,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let rule = RULES.iter().find(|r| r.id == id);
  let Some(rule) = rule else {
    if NOTICES.iter().any(|(n, _, _)| *n == id)
      || suppress::is_builtin(id)
    {
      return Err(
        ApiError::invalid(format!(
          "{id} 不是服务类告警规则，不能按服务覆盖"
        ))
        .with_hint(format!(
          "支持按服务覆盖的规则：{}",
          SERVICE_RULES.join("、")
        )),
      );
    }
    return Err(
      ApiError::not_found(format!("没有告警规则 {id}"))
        .with_hint("用 wharf alert list 查看规则 id"),
    );
  };
  if !is_service_rule(id) {
    return Err(
      ApiError::invalid(format!(
        "规则 {id} 的对象不是服务，不能按服务覆盖"
      ))
      .with_hint(format!(
        "支持按服务覆盖的规则：{}",
        SERVICE_RULES.join("、")
      )),
    );
  }
  if !p.reset && !service_exists(state, service).await? {
    return Err(
      ApiError::not_found(format!("没有服务 {service}"))
        .with_hint("用 wharf service list 查看服务名"),
    );
  }
  if p.threshold.is_some() && !rule.threshold_editable {
    return Err(ApiError::invalid(format!(
      "{} 的阈值固定，改连续次数",
      rule.name
    )));
  }
  if p.threshold.is_some_and(|t| !t.is_finite()) {
    return Err(ApiError::invalid("阈值要是数字"));
  }
  if p.for_n.is_some_and(|n| n == 0 || n as usize > KEEP) {
    return Err(ApiError::invalid(format!(
      "连续次数在 1 到 {KEEP} 之间"
    )));
  }

  let key = (id.to_string(), service.to_string());
  let mut o = if p.reset {
    Override::default()
  } else {
    with(|m| m.service_overrides.get(&key).cloned())
      .unwrap_or_default()
  };
  if let Some(v) = p.enabled {
    o.enabled = Some(v);
  }
  if let Some(t) = p.threshold {
    o.threshold = Some(t);
  }
  if let Some(n) = p.for_n {
    o.for_n = Some(n);
  }
  if let Some(lvl) = p.level {
    o.level = Some(lvl);
  }
  if let Some(m) = p.mute_minutes {
    o.muted_until = (m > 0).then(|| now + i64::from(m) * 60_000);
  }

  let empty = o.enabled.is_none()
    && o.threshold.is_none()
    && o.for_n.is_none()
    && o.level.is_none()
    && o.muted_until.is_none();

  let (r_db, s_db) = key.clone();
  let o_db = o.clone();
  state
    .db
    .call(move |c| {
      if empty {
        c.execute(
          "DELETE FROM alert_service_overrides WHERE rule = ?1 AND service = ?2",
          params![r_db, s_db],
        )
      } else {
        c.execute(
          "INSERT OR REPLACE INTO alert_service_overrides
           (rule, service, enabled, threshold, for_n, level, muted_until)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
          params![
            r_db,
            s_db,
            o_db.enabled.map(i64::from),
            o_db.threshold,
            o_db.for_n,
            o_db.level.map(level_str),
            o_db.muted_until,
          ],
        )
      }
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await?;

  with(|m| {
    if empty {
      m.service_overrides.remove(&key);
    } else {
      m.service_overrides.insert(key, o.clone());
    }
  });

  if with(|m| {
    !effective_override(m.config.get(id), (!empty).then_some(&o), now)
      .enabled()
  }) {
    let service = service.to_string();
    let id = id.to_string();
    super::lifecycle::clear_matching(state, move |rule, subj| {
      rule == id
        && service_of_subject(rule, subj) == Some(service.as_str())
    })
    .await;
  }
  Ok(())
}

/// `PUT /api/alerts/{id}/services/{service}`
pub async fn patch_service(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((id, service)): Path<(String, String)>,
  Json(p): Json<AlertPatch>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  crate::token_scope::require_service(&auth, &service)?;
  set_override(&s, &id, &service, p, now_ms()).await?;
  Ok(Json(super::api::view_for(&s, &auth).await?))
}
