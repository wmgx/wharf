use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Json,
  extract::{Path, State},
};
use rusqlite::params;
use wharf_api_types::{
  ApiError,
  view::{
    AlertSuppressRequest, AlertsView, BuiltinSuppressionView,
    CustomSuppressionView, Perm,
  },
};

use super::{
  FiringEntry, Override, Push, RULES, ack,
  http::view,
  push_at, split_unit,
  store::{config, mark_pushed},
  with,
};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  notify::Event,
  snapshot,
  state::AppState,
  world::World,
};

pub(super) const SUPPRESS_OFFLINE: &str = "suppress_offline";
pub(super) const SUPPRESS_GATEWAY: &str = "suppress_gateway";
pub(super) const MAX_CUSTOM: usize = 50;

pub(super) const BUILTINS: &[(&str, &str)] = &[
  (SUPPRESS_OFFLINE, "机器离线时忽略其上对象的告警"),
  (SUPPRESS_GATEWAY, "网关不可用时忽略经过该网关的域名告警"),
];

pub(super) fn is_builtin(id: &str) -> bool {
  BUILTINS.iter().any(|(b, _)| *b == id)
}

pub(super) fn builtin_views(
  cfg: &BTreeMap<String, Override>,
) -> Vec<BuiltinSuppressionView> {
  BUILTINS
    .iter()
    .map(|(id, name)| BuiltinSuppressionView {
      id: (*id).into(),
      name: (*name).into(),
      enabled: cfg.get(*id).is_none_or(|o| o.enabled()),
    })
    .collect()
}

/// 根据当前快照计算一条告警归属的服务器（用于“机器离线”抑制）。
pub(super) fn servers_of(
  world: &World,
  rule: &str,
  subject: &str,
) -> Vec<String> {
  match rule {
    "server_offline" => vec![],
    "host_cpu_high"
    | "host_mem_high"
    | "inode_high"
    | "agent_mem_high"
    | "traffic_quota"
    | "clock_skew"
    | "disk_forecast"
    | "tailnet_key_expiring"
    | "tailnet_relay" => vec![subject.to_string()],
    "host_unit_down" => vec![split_unit(subject).0.to_string()],
    "expiry_soon" | "expiry_urgent" => subject
      .strip_prefix("server:")
      .map(|s| vec![s.to_string()])
      .unwrap_or_default(),
    "mem_forecast" => {
      if let Some(s) = subject.strip_prefix("服务器 ") {
        vec![s.to_string()]
      } else if let Some(svc) = subject.strip_prefix("服务 ") {
        world
          .services
          .get(svc)
          .map(|r| vec![r.spec.server.clone()])
          .unwrap_or_default()
      } else {
        vec![]
      }
    }
    "container_restarting"
    | "oom_killed"
    | "monitor_failed"
    | "http_5xx"
    | "svc_mem_near_limit"
    | "heartbeat_late" => world
      .services
      .get(subject)
      .map(|r| vec![r.spec.server.clone()])
      .unwrap_or_default(),
    "log_keyword" | "port_down" => world
      .services
      .get(split_unit(subject).0)
      .map(|r| vec![r.spec.server.clone()])
      .unwrap_or_default(),
    "domain_down" => {
      let mut out = Vec::new();
      if let Some(route) = world.routes.get(subject) {
        if let Some(gw_name) =
          world.live_gateway(subject, &route.spec)
          && let Some(gw) = world.gateways.get(gw_name)
        {
          out.push(gw.spec.server.clone());
        }
        if !route.spec.service.is_empty()
          && let Some(svc) = world.services.get(&route.spec.service)
          && !out.contains(&svc.spec.server)
        {
          out.push(svc.spec.server.clone());
        }
      }
      out
    }
    "link_loss" => subject
      .split_once('>')
      .map(|(a, b)| vec![a.to_string(), b.to_string()])
      .unwrap_or_default(),
    _ => vec![],
  }
}

/// 根据当前快照计算域名告警经过的网关（用于“网关不可用”抑制）。
pub(super) fn gateway_of(
  world: &World,
  rule: &str,
  subject: &str,
) -> Option<String> {
  if !matches!(rule, "domain_down" | "cert_expiring") {
    return None;
  }
  let route = world.routes.get(subject)?;
  world.live_gateway(subject, &route.spec).map(str::to_string)
}

pub(super) struct SuppressCtx<'a> {
  pub cfg: &'a BTreeMap<String, Override>,
  pub firing: &'a BTreeMap<(String, String), FiringEntry>,
  pub custom: &'a [CustomSuppressionView],
  pub world: Option<&'a World>,
  pub down_gateways: &'a BTreeSet<String>,
}

/// 纯函数：判断告警 (rule, subject) 是否被内置或自定义规则抑制，返回 `被抑制：<原因>`。
pub(super) fn match_suppression(
  rule: &str,
  subject: &str,
  ctx: &SuppressCtx<'_>,
) -> Option<String> {
  if let Some(world) = ctx.world {
    if ctx.cfg.get(SUPPRESS_OFFLINE).is_none_or(|o| o.enabled()) {
      for server in servers_of(world, rule, subject) {
        if let Some(entry) =
          ctx.firing.get(&("server_offline".to_string(), server))
        {
          return Some(format!("被抑制：{}", entry.title));
        }
      }
    }
    if ctx.cfg.get(SUPPRESS_GATEWAY).is_none_or(|o| o.enabled())
      && let Some(gw) = gateway_of(world, rule, subject)
      && ctx.down_gateways.contains(&gw)
    {
      return Some(format!("被抑制：网关 {gw} 不可用"));
    }
  }
  for c in ctx.custom {
    if c.target_rule != rule {
      continue;
    }
    if c.target_subject.as_deref().is_some_and(|t| t != subject) {
      continue;
    }
    let source = match c.source_subject.as_deref() {
      Some(s) => {
        ctx.firing.get(&(c.source_rule.clone(), s.to_string()))
      }
      None => ctx
        .firing
        .iter()
        .find(|((r, _), _)| r == &c.source_rule)
        .map(|(_, e)| e),
    };
    if let Some(entry) = source {
      return Some(format!("被抑制：{}", entry.title));
    }
  }
  None
}

/// 检查某条正在触发的告警当前是否应被抑制。
pub(super) async fn check(
  state: &AppState,
  rule: &str,
  subject: &str,
) -> Option<String> {
  let cfg = config(state).await;
  let snap = snapshot::load(&state.db).await.ok();
  let world = snap.as_ref().map(|s| &s.world);
  let down_gateways = world
    .map(|w| crate::views::unavailable_gateways(state, w))
    .unwrap_or_default();
  with(|m| {
    match_suppression(
      rule,
      subject,
      &SuppressCtx {
        cfg: &cfg,
        firing: &m.firing,
        custom: &m.suppressions,
        world,
        down_gateways: &down_gateways,
      },
    )
  })
}

/// 抑制源恢复或抑制规则被删后，补推仍在触发且此前未推送的告警。
pub(super) async fn recheck_suppressed(state: &AppState, now: i64) {
  let pending: Vec<((String, String), Event)> = with(|m| {
    m.firing
      .iter()
      .filter(|(_, e)| !e.pushed)
      .map(|(k, e)| {
        (
          k.clone(),
          Event {
            title: e.title.clone(),
            body: e.body.clone(),
          },
        )
      })
      .collect()
  });
  if pending.is_empty() {
    return;
  }
  let cfg = config(state).await;
  let snap = snapshot::load(&state.db).await.ok();
  let world = snap.as_ref().map(|s| &s.world);
  let down_gateways = world
    .map(|w| crate::views::unavailable_gateways(state, w))
    .unwrap_or_default();
  for ((rule, subject), event) in pending {
    let o = cfg.get(&rule).cloned().unwrap_or_default();
    if !o.enabled() || o.muted(now) {
      continue;
    }
    if ack::is_acked(state, &rule, &subject, now).await {
      continue;
    }
    let still_suppressed = with(|m| {
      m.firing
        .get(&(rule.clone(), subject.clone()))
        .is_none_or(|e| e.pushed)
        || match_suppression(
          &rule,
          &subject,
          &SuppressCtx {
            cfg: &cfg,
            firing: &m.firing,
            custom: &m.suppressions,
            world,
            down_gateways: &down_gateways,
          },
        )
        .is_some()
    });
    if still_suppressed {
      continue;
    }
    let pushed = push_at(
      state,
      Push {
        now,
        id: &rule,
        subject: Some(&subject),
        over: &o,
        ok: false,
        prev_pushed: true,
      },
      event,
    )
    .await;
    if pushed {
      mark_pushed(state, &(rule, subject)).await;
    }
  }
}

fn clean_opt(s: Option<String>) -> Option<String> {
  s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub(super) async fn add_impl(
  state: &AppState,
  req: AlertSuppressRequest,
) -> Result<AlertsView, ApiError> {
  let _ = config(state).await;
  if !RULES.iter().any(|r| r.id == req.source_rule) {
    return Err(
      ApiError::not_found(format!(
        "没有告警规则 {}",
        req.source_rule
      ))
      .suggest("wharf alert list"),
    );
  }
  if !RULES.iter().any(|r| r.id == req.target_rule) {
    return Err(
      ApiError::not_found(format!(
        "没有告警规则 {}",
        req.target_rule
      ))
      .suggest("wharf alert list"),
    );
  }
  let source_subject = clean_opt(req.source_subject);
  let target_subject = clean_opt(req.target_subject);
  if req.source_rule == req.target_rule
    && source_subject == target_subject
  {
    return Err(ApiError::invalid("不能用同一条规则抑制自己"));
  }
  let (count, dup) = with(|m| {
    let dup = m.suppressions.iter().any(|c| {
      c.source_rule == req.source_rule
        && c.source_subject == source_subject
        && c.target_rule == req.target_rule
        && c.target_subject == target_subject
    });
    (m.suppressions.len(), dup)
  });
  if dup {
    return Err(ApiError::invalid("这条抑制规则已经存在"));
  }
  if count >= MAX_CUSTOM {
    return Err(ApiError::invalid(format!(
      "自定义抑制规则最多 {MAX_CUSTOM} 条"
    )));
  }
  let (sr, ss, tr, ts) = (
    req.source_rule.clone(),
    source_subject.clone(),
    req.target_rule.clone(),
    target_subject.clone(),
  );
  let id = state
    .db
    .call(move |c| {
      c.execute(
        "INSERT INTO alert_suppressions (source_rule, source_subject, target_rule, target_subject) VALUES (?1, ?2, ?3, ?4)",
        params![sr, ss, tr, ts],
      )
      .map_err(db::sql_err)?;
      Ok(c.last_insert_rowid())
    })
    .await?;
  with(|m| {
    m.suppressions.push(CustomSuppressionView {
      id,
      source_rule: req.source_rule,
      source_subject,
      target_rule: req.target_rule,
      target_subject,
    });
  });
  view(state).await
}

pub(super) async fn remove_impl(
  state: &AppState,
  id: i64,
  now: i64,
) -> Result<AlertsView, ApiError> {
  let _ = config(state).await;
  let removed = state
    .db
    .call(move |c| {
      c.execute("DELETE FROM alert_suppressions WHERE id = ?1", [id])
        .map_err(db::sql_err)
    })
    .await?;
  if removed == 0 {
    return Err(
      ApiError::not_found(format!("没有编号为 {id} 的抑制规则"))
        .suggest("wharf alert suppress list"),
    );
  }
  with(|m| {
    m.suppressions.retain(|c| c.id != id);
  });
  recheck_suppressed(state, now).await;
  view(state).await
}

/// `GET /api/alerts/suppress`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<CustomSuppressionView>> {
  auth.require(Perm::Read)?;
  let _ = config(&s).await;
  Ok(Json(with(|m| m.suppressions.clone())))
}

/// `POST /api/alerts/suppress`
pub async fn add(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertSuppressRequest>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  Ok(Json(add_impl(&s, req).await?))
}

/// `DELETE /api/alerts/suppress/{id}`
pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<i64>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  Ok(Json(remove_impl(&s, id, now_ms()).await?))
}
