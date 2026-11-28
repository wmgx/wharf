//! 按服务的自定义告警规则：增删改、评估、进“需要注意”以及随服务删除清理。

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::{Connection, OptionalExtension, params};
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{
    AlertLevel, AlertPatch, AlertsView, CustomAlertRuleRequest,
    CustomAlertRuleView, Issue, IssueLevel, IssueSubject, Perm,
  },
};

use super::{
  Delivery, FiringEntry, KEEP, NOTICES, Op, Override, PushArgs,
  RULES, Verdict, ack, digest, ensure_loaded, ev, issue_alert,
  judge_consecutive, push_with_world, resources, set_firing,
  suppress, with,
};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  notify,
  state::AppState,
  world::World,
};

pub(super) const MAX_CUSTOM_RULES: usize = 50;

pub(crate) const MIGRATION: &str = r#"
CREATE TABLE alert_service_overrides (
  rule TEXT NOT NULL,
  service TEXT NOT NULL,
  enabled INTEGER,
  threshold REAL,
  for_n INTEGER,
  level TEXT,
  muted_until INTEGER,
  PRIMARY KEY (rule, service)
);
CREATE TABLE alert_custom_rules (
  name TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  metric TEXT NOT NULL,
  op TEXT NOT NULL,
  threshold REAL NOT NULL,
  for_n INTEGER NOT NULL,
  level TEXT NOT NULL DEFAULT 'urgent',
  enabled INTEGER NOT NULL DEFAULT 1,
  muted_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX alert_custom_rules_service ON alert_custom_rules (service);
"#;

#[derive(Debug, Clone)]
pub(super) struct CustomRule {
  pub name: String,
  pub service: String,
  pub metric: String,
  pub op: Op,
  pub threshold: f64,
  pub for_n: u32,
  pub level: AlertLevel,
  pub enabled: bool,
  pub muted_until: Option<i64>,
  pub created_at: i64,
}

impl CustomRule {
  pub(super) fn notify_key(&self) -> String {
    format!("custom.{}", self.name)
  }

  pub(super) fn as_override(&self) -> Override {
    Override {
      enabled: Some(self.enabled),
      threshold: None,
      for_n: None,
      level: Some(self.level),
      muted_until: self.muted_until,
    }
  }

  pub(super) fn condition(&self) -> String {
    let unit = metric_unit(&self.metric);
    let suffix = if unit.is_empty() {
      String::new()
    } else {
      format!(" {unit}")
    };
    format!(
      "{} {} {}{suffix} 连续 {} 次（每分钟一次）",
      self.metric,
      self.op.text(),
      self.threshold,
      self.for_n
    )
  }

  pub(super) fn to_view(&self, now: i64) -> CustomAlertRuleView {
    CustomAlertRuleView {
      name: self.name.clone(),
      service: self.service.clone(),
      metric: self.metric.clone(),
      op: self.op.text().into(),
      threshold: self.threshold,
      for_n: self.for_n,
      condition: self.condition(),
      enabled: self.enabled,
      level: self.level,
      muted_until: self.muted_until.filter(|t| *t > now),
      created_at: self.created_at,
    }
  }
}

pub(super) fn normalize_metric(
  raw: &str,
) -> Result<&'static str, ApiError> {
  match raw.trim() {
    "cpu" | "svc.cpu" => Ok("svc.cpu"),
    "mem" | "svc.mem" => Ok("svc.mem"),
    "mem_pct" | "svc.mem_pct" => Ok("svc.mem_pct"),
    "err" | "req.err" => Ok("req.err"),
    "p95" | "req.p95" => Ok("req.p95"),
    other => Err(
      ApiError::invalid(format!("不支持的指标 {other}")).with_hint(
        "可选：cpu（%）、mem（MB，与 wharf top 一致）、mem_pct（%）、err（%）、p95（ms）",
      ),
    ),
  }
}

pub(super) fn metric_unit(metric: &str) -> &'static str {
  match metric {
    "svc.cpu" | "svc.mem_pct" | "req.err" => "%",
    "svc.mem" => "MB",
    "req.p95" => "ms",
    _ => "",
  }
}

fn fmt_value(metric: &str, value: f64) -> String {
  match metric {
    "svc.cpu" | "svc.mem_pct" | "req.err" => format!("{value:.1}%"),
    "svc.mem" => format!("{value:.1} MB"),
    "req.p95" => format!("{value:.0} ms"),
    _ => format!("{value:.2}"),
  }
}

pub(super) fn parse_op(raw: &str) -> Result<Op, ApiError> {
  match raw.trim() {
    ">" => Ok(Op::Gt),
    "<" => Ok(Op::Lt),
    other => Err(
      ApiError::invalid(format!("不支持的比较符 {other}"))
        .with_hint("比较符只支持 > 或 <"),
    ),
  }
}

pub(super) fn level_str(level: AlertLevel) -> &'static str {
  match level {
    AlertLevel::Urgent => "urgent",
    AlertLevel::Digest => "digest",
  }
}

pub(super) fn parse_level(s: &str) -> AlertLevel {
  match s {
    "digest" => AlertLevel::Digest,
    _ => AlertLevel::Urgent,
  }
}

pub(super) fn validate_custom_name(
  name: &str,
) -> Result<(), ApiError> {
  let ok =
    !name.is_empty()
      && name.len() <= 48
      && name.bytes().all(|c| {
        c.is_ascii_lowercase()
          || c.is_ascii_digit()
          || c == b'-'
          || c == b'_'
      })
      && name.as_bytes().first().is_some_and(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit()
      })
      && name.as_bytes().last().is_some_and(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit()
      });
  if ok {
    Ok(())
  } else {
    Err(
      ApiError::invalid(format!("自定义规则名称 '{name}' 不合法"))
        .with_hint(
          "只能用小写字母、数字、- 和 _，以字母或数字开头和结尾，最长 48 个字符",
        ),
    )
  }
}

pub(super) fn load_from_db(
  c: &Connection,
) -> Result<BTreeMap<String, CustomRule>, ApiError> {
  let mut stmt = c
    .prepare(
      "SELECT name, service, metric, op, threshold, for_n, level, enabled, muted_until, created_at
       FROM alert_custom_rules",
    )
    .map_err(db::sql_err)?;
  stmt
    .query_map([], |r| {
      let name: String = r.get(0)?;
      let op_str: String = r.get(3)?;
      let lvl_str: String = r.get(6)?;
      let op = if op_str == "<" { Op::Lt } else { Op::Gt };
      Ok((
        name.clone(),
        CustomRule {
          name,
          service: r.get(1)?,
          metric: r.get(2)?,
          op,
          threshold: r.get(4)?,
          for_n: r.get::<_, u32>(5)?,
          level: parse_level(&lvl_str),
          enabled: r.get::<_, i64>(7)? != 0,
          muted_until: r.get(8)?,
          created_at: r.get(9)?,
        },
      ))
    })
    .and_then(Iterator::collect::<Result<BTreeMap<_, _>, _>>)
    .map_err(db::sql_err)
}

pub(super) async fn service_exists(
  state: &AppState,
  service: &str,
) -> Result<bool, ApiError> {
  let svc = service.to_string();
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT 1 FROM resources WHERE kind = 'service' AND name = ?1",
        [svc],
        |_| Ok(()),
      )
      .optional()
      .map(|v| v.is_some())
      .map_err(db::sql_err)
    })
    .await
}

pub(super) async fn add_rule(
  state: &AppState,
  req: CustomAlertRuleRequest,
  now: i64,
) -> Result<CustomAlertRuleView, ApiError> {
  ensure_loaded(state).await;
  validate_custom_name(&req.name)?;
  if RULES.iter().any(|r| r.id == req.name)
    || NOTICES.iter().any(|(n, _, _)| *n == req.name)
    || suppress::is_builtin(&req.name)
    || req.name == digest::SOURCE_ID
  {
    return Err(ApiError::new(
      ErrorCode::AlreadyExists,
      format!("名称 {} 已被内置规则或通知占用", req.name),
    ));
  }
  let metric = normalize_metric(&req.metric)?;
  let op = parse_op(&req.op)?;
  if !req.threshold.is_finite() || req.threshold < 0.0 {
    return Err(ApiError::invalid("阈值要是大于等于 0 的数字"));
  }
  if req.for_n == 0 || req.for_n as usize > KEEP {
    return Err(ApiError::invalid(format!(
      "连续次数在 1 到 {KEEP} 之间"
    )));
  }
  if !service_exists(state, &req.service).await? {
    return Err(
      ApiError::not_found(format!("没有服务 {}", req.service))
        .with_hint("用 wharf service list 查看服务名"),
    );
  }
  let (dup, count) = with(|m| {
    (m.custom_rules.contains_key(&req.name), m.custom_rules.len())
  });
  if dup {
    return Err(ApiError::new(
      ErrorCode::AlreadyExists,
      format!("自定义规则 {} 已存在", req.name),
    ));
  }
  if count >= MAX_CUSTOM_RULES {
    return Err(ApiError::invalid(format!(
      "自定义告警规则最多 {MAX_CUSTOM_RULES} 条"
    )));
  }
  let cr = CustomRule {
    name: req.name,
    service: req.service,
    metric: metric.into(),
    op,
    threshold: req.threshold,
    for_n: req.for_n,
    level: req.level,
    enabled: true,
    muted_until: None,
    created_at: now,
  };
  let db_cr = cr.clone();
  state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO alert_custom_rules
         (name, service, metric, op, threshold, for_n, level, enabled, muted_until, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL, ?8)",
        params![
          db_cr.name,
          db_cr.service,
          db_cr.metric,
          db_cr.op.text(),
          db_cr.threshold,
          db_cr.for_n,
          level_str(db_cr.level),
          db_cr.created_at,
        ],
      )
      .map(|_| ())
      .map_err(db::sql_err)
    })
    .await?;
  let v = cr.to_view(now);
  with(|m| {
    m.custom_rules.insert(cr.name.clone(), cr);
  });
  Ok(v)
}

fn require_custom_scope(
  auth: &Auth,
  rule: Option<&CustomRule>,
) -> Result<(), ApiError> {
  if let Some(allowed) = &auth.services
    && !rule.is_some_and(|rule| allowed.contains(&rule.service))
  {
    return Err(crate::token_scope::forbidden(
      &auth.name, allowed, "",
    ));
  }
  Ok(())
}

pub(super) async fn patch_custom(
  state: &AppState,
  auth: &Auth,
  name: &str,
  p: AlertPatch,
  now: i64,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let rule = with(|m| m.custom_rules.get(name).cloned());
  require_custom_scope(auth, rule.as_ref())?;
  let Some(mut cr) = rule else {
    return Err(ApiError::not_found(format!(
      "没有自定义规则 {name}"
    )));
  };
  if p.threshold.is_some_and(|t| !t.is_finite() || t < 0.0) {
    return Err(ApiError::invalid("阈值要是大于等于 0 的数字"));
  }
  if p.for_n.is_some_and(|n| n == 0 || n as usize > KEEP) {
    return Err(ApiError::invalid(format!(
      "连续次数在 1 到 {KEEP} 之间"
    )));
  }
  if p.reset {
    cr.enabled = true;
    cr.muted_until = None;
  }
  if let Some(v) = p.enabled {
    cr.enabled = v;
  }
  if let Some(t) = p.threshold {
    cr.threshold = t;
  }
  if let Some(n) = p.for_n {
    cr.for_n = n;
  }
  if let Some(lvl) = p.level {
    cr.level = lvl;
  }
  if let Some(m) = p.mute_minutes {
    cr.muted_until = (m > 0).then(|| now + i64::from(m) * 60_000);
  }
  let db_cr = cr.clone();
  let changed = state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE alert_custom_rules
         SET enabled = ?2, threshold = ?3, for_n = ?4, level = ?5, muted_until = ?6
         WHERE name = ?1 AND service = ?7 AND created_at = ?8",
        params![
          db_cr.name,
          i64::from(db_cr.enabled),
          db_cr.threshold,
          db_cr.for_n,
          level_str(db_cr.level),
          db_cr.muted_until,
          db_cr.service,
          db_cr.created_at,
        ],
      )
      .map_err(db::sql_err)
    })
    .await?;
  if changed == 0 {
    require_custom_scope(auth, None)?;
    return Err(ApiError::not_found(format!(
      "没有自定义规则 {name}"
    )));
  }
  let svc = cr.service.clone();
  let disabled = !cr.enabled;
  with(|m| {
    if m.custom_rules.get(name).is_some_and(|r| {
      r.service == cr.service && r.created_at == cr.created_at
    }) {
      m.custom_rules.insert(cr.name.clone(), cr);
    }
  });
  if disabled {
    super::lifecycle::clear(state, name, &svc).await;
  }
  Ok(())
}

pub(super) async fn remove_rule(
  state: &AppState,
  auth: &Auth,
  name: &str,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let rule = with(|m| m.custom_rules.get(name).cloned());
  require_custom_scope(auth, rule.as_ref())?;
  let Some(cr) = rule else {
    return Err(
      ApiError::not_found(format!("没有自定义规则 {name}"))
        .with_hint("用 wharf alert list 查看自定义规则")
        .suggest("wharf alert list"),
    );
  };
  let (n, service, created_at) =
    (name.to_string(), cr.service.clone(), cr.created_at);
  let changed = state.db.call(move |c| {
    let tx = c.transaction().map_err(db::sql_err)?;
    let exists = tx.query_row(
      "SELECT EXISTS(SELECT 1 FROM alert_custom_rules WHERE name = ?1 AND service = ?2 AND created_at = ?3)",
      params![n, service, created_at], |row| row.get::<_, bool>(0),
    ).map_err(db::sql_err)?;
    if exists {
      super::lifecycle::clear_rows(&tx, &|rule, subject| rule == n && subject == service)?;
      tx.execute("DELETE FROM alert_custom_rules WHERE name = ?1", [&n]).map_err(db::sql_err)?;
    }
    tx.commit().map_err(db::sql_err)?;
    Ok(exists)
  }).await?;
  if !changed {
    require_custom_scope(auth, None)?;
    return Err(ApiError::not_found(format!(
      "没有自定义规则 {name}"
    )));
  }
  with(|m| {
    if m.custom_rules.get(name).is_some_and(|r| {
      r.service == cr.service && r.created_at == cr.created_at
    }) {
      m.custom_rules.remove(name);
    }
  });
  super::lifecycle::clear(state, &cr.name, &cr.service).await;
  Ok(())
}

/// 在 `db::apply_write` 删除服务事务里同步删掉覆盖和自定义规则。
pub(crate) fn delete_service_rows(
  c: &Connection,
  service: &str,
) -> Result<(), ApiError> {
  let mut stmt = c
    .prepare("SELECT name FROM alert_custom_rules WHERE service = ?1")
    .map_err(db::sql_err)?;
  let names: BTreeSet<String> = stmt
    .query_map([service], |r| r.get(0))
    .and_then(Iterator::collect)
    .map_err(db::sql_err)?;
  if !names.is_empty() {
    super::lifecycle::clear_rows(c, &|rule, subject| {
      names.contains(rule) && subject == service
    })?;
  }
  c.execute(
    "DELETE FROM alert_service_overrides WHERE service = ?1",
    [service],
  )
  .map_err(db::sql_err)?;
  c.execute(
    "DELETE FROM alert_custom_rules WHERE service = ?1",
    [service],
  )
  .map_err(db::sql_err)?;
  Ok(())
}

/// 服务被删除后，同步清理内存和数据库里的服务覆盖、自定义规则及其触发状态。
pub async fn on_service_deleted(state: &AppState, service: &str) {
  ensure_loaded(state).await;
  let names = with(|m| {
    m.custom_rules
      .iter()
      .filter(|(_, r)| r.service == service)
      .map(|(name, _)| name.clone())
      .collect::<BTreeSet<_>>()
  });
  let svc = service.to_string();
  super::lifecycle::clear_matching(state, move |rule, subject| {
    names.contains(rule) && subject == svc
  })
  .await;
  with(|m| {
    m.service_overrides.retain(|(_, svc), _| svc != service);
    m.custom_rules.retain(|_, r| r.service != service);
  });
  let service = service.to_string();
  let _ = state
    .db
    .call(move |c| delete_service_rows(c, &service))
    .await;
}

/// 判断匹配 `(metric, subject)` 的自定义规则，走与内置规则完全相同的触发、推送、确认和抑制链路。
pub(super) async fn evaluate_at(
  state: &AppState,
  now: i64,
  metric: &str,
  subject: &str,
  value: f64,
  detail: &str,
  points: &VecDeque<f64>,
) {
  // 没有请求时没有真实采样，只允许恢复正在触发的上限告警。
  let idle = points.is_empty();
  let matched: Vec<CustomRule> = with(|m| {
    m.custom_rules
      .values()
      .filter(|r| {
        r.metric == metric
          && r.service == subject
          && (!idle
            || (matches!(r.op, Op::Gt)
              && m
                .firing
                .contains_key(&(r.name.clone(), r.service.clone()))))
      })
      .cloned()
      .collect()
  });
  for cr in matched {
    let fkey = (cr.name.clone(), cr.service.clone());
    if !cr.enabled {
      set_firing(state, fkey, None, now).await;
      continue;
    }
    let verdict = if idle {
      Verdict::Recover
    } else {
      judge_consecutive(
        cr.op,
        cr.threshold,
        cr.for_n,
        None,
        resources::is_report_metric(&cr.metric),
        points,
      )
    };
    let mut prev = None;
    let (ok, event) = match verdict {
      Verdict::Hold => continue,
      Verdict::Fire => {
        let mut body = format!(
          "当前 {}，条件：{}",
          fmt_value(&cr.metric, value),
          cr.condition()
        );
        if !detail.is_empty() {
          body.push_str(&format!("（{detail}）"));
        }
        let e = ev(
          format!("服务 {} 触发告警 {}", cr.service, cr.name),
          body,
        );
        set_firing(
          state,
          fkey.clone(),
          Some(FiringEntry {
            since: now,
            title: e.title.clone(),
            body: e.body.clone(),
            delivery: Delivery::None,
            suppressed: false,
          }),
          now,
        )
        .await;
        ack::on_firing_change(state, &fkey, true, now).await;
        (false, e)
      }
      Verdict::Recover => {
        prev = with(|m| m.firing.get(&fkey).cloned());
        set_firing(state, fkey.clone(), None, now).await;
        ack::on_firing_change(state, &fkey, false, now).await;
        let e = ev(
          format!("服务 {} 的告警 {} 已恢复", cr.service, cr.name),
          if idle {
            detail.to_string()
          } else {
            format!("当前 {}", fmt_value(&cr.metric, value))
          },
        );
        (true, e)
      }
    };
    if notify::transition(state, &cr.notify_key(), ok).await {
      let o = cr.as_override();
      push_with_world(
        state,
        PushArgs {
          id: &cr.name,
          subject: Some(subject),
          o: &o,
          ok,
          event,
          prev_delivery: prev.map(|f| f.delivery),
          now,
          world: None,
        },
      )
      .await;
      if ok {
        suppress::flush_unsuppressed(state, now).await;
      }
    }
  }
}

/// 正在触发的自定义告警，进“需要注意”。
pub fn issues(world: &World) -> Vec<Issue> {
  let firing: Vec<(String, String, String, AlertLevel)> = with(|m| {
    m.firing
      .iter()
      .filter_map(|((rule, subj), f)| {
        let cr = m.custom_rules.get(rule)?;
        world
          .services
          .get(subj)
          .is_some_and(|row| !row.spec.stopped)
          .then(|| {
            (rule.clone(), subj.clone(), f.title.clone(), cr.level)
          })
      })
      .collect()
  });
  firing
    .into_iter()
    .map(|(rule, subject, title, level)| {
      let (alert, ack) = issue_alert(&rule, &subject);
      Issue {
        code: "custom_alert".into(),
        level: match level {
          AlertLevel::Urgent => IssueLevel::Fault,
          AlertLevel::Digest => IssueLevel::Warn,
        },
        subject: Some(IssueSubject {
          kind: "service".into(),
          name: subject,
        }),
        title,
        hint: None,
        ack,
        alert,
      }
    })
    .collect()
}

/// `POST /api/alerts/custom`
pub async fn add_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<CustomAlertRuleRequest>,
) -> ApiResult<CustomAlertRuleView> {
  auth.require(Perm::Apply)?;
  crate::token_scope::require_service(&auth, &req.service)?;
  Ok(Json(add_rule(&s, req, now_ms()).await?))
}

/// `DELETE /api/alerts/custom/{name}`
pub async fn rm_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Apply)?;
  remove_rule(&s, &auth, &name).await?;
  Ok(Json(super::api::view_for(&s, &auth).await?))
}
