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
  ApiError, ErrorCode,
  view::{
    AlertSuppressionRequest, AlertSuppressionView, AlertsView, Perm,
  },
};

use super::{
  Delivery, FiringEntry, NOTICES, Override, PushArgs, RULES,
  SuppressionRule, config, custom, ensure_loaded, push_with_world,
  service_overrides, set_firing_suppressed, split_unit, view, with,
};
use crate::{
  api::ApiResult,
  auth::Auth,
  db::{self, now_ms},
  notify::Event,
  state::AppState,
  world::World,
};

pub(super) const BUILTIN_OFFLINE: &str = "suppress_offline";
pub(super) const BUILTIN_GATEWAY: &str = "suppress_gateway";
pub(super) const MAX_CUSTOM: usize = 50;

pub(super) const BUILTINS: &[(&str, &str)] = &[
  (super::op_silence::ID, "受控操作期间抑制服务告警"),
  (BUILTIN_OFFLINE, "机器离线时抑制其上告警"),
  (BUILTIN_GATEWAY, "网关不可用时抑制其下域名告警"),
];

pub(super) fn is_builtin(id: &str) -> bool {
  BUILTINS.iter().any(|(b, _)| *b == id)
}

/// 根据当前快照算一条告警主体关联到哪台（或哪几台）服务器。
pub(super) fn related_servers(
  rule: &str,
  subject: &str,
  world: &World,
  custom_rules: &BTreeMap<String, custom::CustomRule>,
) -> Vec<String> {
  if custom_rules.contains_key(rule) {
    return world
      .services
      .get(subject)
      .map(|s| vec![s.spec.server.clone()])
      .unwrap_or_default();
  }
  match rule {
    "server_offline" => vec![],
    "host_cpu_high"
    | "host_mem_high"
    | "inode_high"
    | "agent_mem_high"
    | "traffic_quota"
    | "clock_skew"
    | "disk_forecast"
    | "tailnet_key_expiring" => vec![subject.to_string()],
    "host_unit_down" => vec![split_unit(subject).0.to_string()],
    "container_restarting"
    | "oom_killed"
    | "monitor_failed"
    | "http_5xx"
    | "svc_mem_near_limit"
    | "heartbeat_late" => world
      .services
      .get(subject)
      .map(|s| vec![s.spec.server.clone()])
      .unwrap_or_default(),
    "log_keyword" | "port_down" => {
      let svc = split_unit(subject).0;
      world
        .services
        .get(svc)
        .map(|s| vec![s.spec.server.clone()])
        .unwrap_or_default()
    }
    "mem_forecast" => {
      if let Some(srv) = subject.strip_prefix("服务器 ") {
        vec![srv.to_string()]
      } else if let Some(svc) = subject.strip_prefix("服务 ") {
        world
          .services
          .get(svc)
          .map(|s| vec![s.spec.server.clone()])
          .unwrap_or_default()
      } else {
        vec![]
      }
    }
    "domain_down" | "cert_expiring" => {
      let mut out = Vec::new();
      if let Some(route) = world.routes.get(subject) {
        if let Some(gw_name) =
          world.live_gateway(subject, &route.spec)
          && let Some(gw) = world.gateways.get(gw_name)
        {
          out.push(gw.spec.server.clone());
        }
        let primary = (route.spec.upstream.is_none()
          && route.spec.redirect.is_none())
        .then_some(route.spec.service.as_str());
        for service in primary.into_iter().chain(
          route.spec.paths.iter().map(|path| path.service.as_str()),
        ) {
          if let Some(svc) = world.services.get(service)
            && !out.contains(&svc.spec.server)
          {
            out.push(svc.spec.server.clone());
          }
        }
      }
      out
    }
    "link_loss" | "tailnet_relay" => match subject.split_once('>') {
      Some((from, to)) => vec![from.to_string(), to.to_string()],
      None => vec![],
    },
    _ => vec![],
  }
}

/// 纯函数判断是否命中内置或自定义抑制，返回抑制原因（上游告警的标题）。
#[allow(clippy::too_many_arguments)]
pub(super) fn match_reason(
  id: &str,
  subject: Option<&str>,
  world: Option<&World>,
  firing: &BTreeMap<(String, String), FiringEntry>,
  unavailable_gateways: &BTreeSet<String>,
  cfg: &BTreeMap<String, Override>,
  custom: &[SuppressionRule],
  custom_rules: &BTreeMap<String, custom::CustomRule>,
) -> Option<String> {
  let offline_on =
    cfg.get(BUILTIN_OFFLINE).is_none_or(Override::enabled);
  if offline_on && let (Some(subj), Some(world)) = (subject, world) {
    for srv in related_servers(id, subj, world, custom_rules) {
      if let Some(entry) =
        firing.get(&(String::from("server_offline"), srv))
      {
        return Some(entry.title.clone());
      }
    }
  }
  let gateway_on =
    cfg.get(BUILTIN_GATEWAY).is_none_or(Override::enabled);
  if gateway_on
    && matches!(id, "domain_down" | "cert_expiring")
    && let (Some(host), Some(world)) = (subject, world)
    && let Some(route) = world.routes.get(host)
    && let Some(gw_name) = world.live_gateway(host, &route.spec)
  {
    let gw_down = unavailable_gateways.contains(gw_name)
      || world.gateways.get(gw_name).is_some_and(|g| {
        firing.contains_key(&(
          String::from("server_offline"),
          g.spec.server.clone(),
        ))
      });
    if gw_down {
      return Some(format!("网关 {gw_name} 不可用"));
    }
  }
  for rule in custom {
    if rule.target_rule != id {
      continue;
    }
    if rule.target_subject.is_some()
      && rule.target_subject.as_deref() != subject
    {
      continue;
    }
    for ((fr, fs), entry) in firing {
      if fr != &rule.source_rule {
        continue;
      }
      if rule.source_subject.is_some()
        && rule.source_subject.as_deref() != Some(fs.as_str())
      {
        continue;
      }
      if fr == id && Some(fs.as_str()) == subject {
        continue;
      }
      return Some(entry.title.clone());
    }
  }
  None
}

pub(super) async fn load_world(state: &AppState) -> Option<World> {
  state
    .db
    .call(|c| World::from_rows(db::all_resources(c)?))
    .await
    .ok()
}

pub(super) async fn check(
  state: &AppState,
  id: &str,
  subject: Option<&str>,
  cfg: &BTreeMap<String, Override>,
  cached_world: Option<&World>,
) -> Option<String> {
  let need_world = cached_world.is_none()
    && subject.is_some()
    && (cfg.get(BUILTIN_OFFLINE).is_none_or(Override::enabled)
      || cfg.get(BUILTIN_GATEWAY).is_none_or(Override::enabled));
  let loaded = if need_world {
    load_world(state).await
  } else {
    None
  };
  let world = cached_world.or(loaded.as_ref());
  with(|m| {
    match_reason(
      id,
      subject,
      world,
      &m.firing,
      &m.unavailable_gateways,
      cfg,
      &m.suppressions,
      &m.custom_rules,
    )
  })
}

/// 抑制源恢复（或抑制规则关闭/删除）后，把仍在触发且还没推过的告警按自身级别补推一次。
pub(super) async fn flush_unsuppressed(state: &AppState, now: i64) {
  let pending: Vec<(String, String, Event)> = with(|m| {
    m.firing
      .iter()
      .filter(|(_, f)| f.suppressed && f.delivery == Delivery::None)
      .map(|((r, s), f)| {
        (
          r.clone(),
          s.clone(),
          Event {
            title: f.title.clone(),
            body: f.body.clone(),
          },
        )
      })
      .collect()
  });
  if pending.is_empty() {
    return;
  }
  let cfg = config(state).await;
  let (svc_overrides, custom_rules) =
    with(|m| (m.service_overrides.clone(), m.custom_rules.clone()));
  let world = load_world(state).await;
  for (rule_id, subject, event) in pending {
    if check(state, &rule_id, Some(&subject), &cfg, world.as_ref())
      .await
      .is_some()
    {
      continue;
    }
    set_firing_suppressed(
      state,
      (rule_id.clone(), subject.clone()),
      false,
    )
    .await;
    let o = service_overrides::override_for_firing(
      &cfg,
      &svc_overrides,
      &custom_rules,
      &rule_id,
      &subject,
    );
    push_with_world(
      state,
      PushArgs {
        id: &rule_id,
        subject: Some(&subject),
        o: &o,
        ok: false,
        event,
        prev_delivery: None,
        now,
        world: world.as_ref(),
      },
    )
    .await;
  }
}

/// 同步当前不可用的网关列表；有网关恢复时触发补推。
pub async fn sync_unavailable_gateways(
  state: &AppState,
  down: BTreeSet<String>,
) {
  ensure_loaded(state).await;
  let recovered = with(|m| {
    let any_recovered =
      m.unavailable_gateways.iter().any(|g| !down.contains(g));
    m.unavailable_gateways = down;
    any_recovered
  });
  if recovered {
    flush_unsuppressed(state, now_ms()).await;
  }
}

fn clean_subject(
  raw: Option<String>,
) -> Result<Option<String>, ApiError> {
  match raw {
    None => Ok(None),
    Some(s) => {
      let trimmed = s.trim().to_string();
      if trimmed.is_empty() {
        Err(ApiError::invalid("对象不能为空"))
      } else {
        Ok(Some(trimmed))
      }
    }
  }
}

pub(super) async fn add_rule(
  state: &AppState,
  req: AlertSuppressionRequest,
  now: i64,
) -> Result<AlertSuppressionView, ApiError> {
  ensure_loaded(state).await;
  let source_valid = RULES.iter().any(|r| r.id == req.source_rule)
    || with(|m| m.custom_rules.contains_key(&req.source_rule));
  if !source_valid {
    return Err(
      ApiError::not_found(format!(
        "没有告警规则 {}",
        req.source_rule
      ))
      .with_hint(
        "抑制来源必须是内置或自定义告警规则，用 wharf alert list 查看",
      ),
    );
  }
  let target_valid = RULES.iter().any(|r| r.id == req.target_rule)
    || NOTICES.iter().any(|(n, _, _)| *n == req.target_rule)
    || with(|m| m.custom_rules.contains_key(&req.target_rule));
  if !target_valid {
    return Err(
      ApiError::not_found(format!("没有告警 {}", req.target_rule))
        .with_hint("用 wharf alert list 查看可用的规则和事件通知"),
    );
  }
  let source_subject = clean_subject(req.source_subject)?;
  let target_subject = clean_subject(req.target_subject)?;
  if req.source_rule == req.target_rule
    && source_subject == target_subject
  {
    return Err(ApiError::invalid("不能用一条告警抑制它自己"));
  }
  let (count, dup) = with(|m| {
    let dup = m.suppressions.iter().any(|r| {
      r.source_rule == req.source_rule
        && r.source_subject == source_subject
        && r.target_rule == req.target_rule
        && r.target_subject == target_subject
    });
    (m.suppressions.len(), dup)
  });
  if dup {
    return Err(ApiError::new(
      ErrorCode::AlreadyExists,
      "相同的抑制规则已存在",
    ));
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
        "INSERT INTO alert_suppressions (source_rule, source_subject, target_rule, target_subject, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![sr, ss, tr, ts, now],
      )
      .map_err(db::sql_err)?;
      Ok(c.last_insert_rowid())
    })
    .await?;
  let row = SuppressionRule {
    id,
    source_rule: req.source_rule,
    source_subject,
    target_rule: req.target_rule,
    target_subject,
    created_at: now,
  };
  let view_row = row.to_view();
  with(|m| m.suppressions.push(row));
  Ok(view_row)
}

pub(super) async fn remove_rule(
  state: &AppState,
  id: i64,
  now: i64,
) -> Result<(), ApiError> {
  ensure_loaded(state).await;
  let removed = state
    .db
    .call(move |c| {
      c.execute("DELETE FROM alert_suppressions WHERE id = ?1", [id])
        .map_err(db::sql_err)
    })
    .await?;
  if removed == 0 {
    return Err(
      ApiError::not_found(format!("没有序号为 {id} 的抑制规则"))
        .with_hint("用 wharf alert suppress list 查看序号")
        .suggest("wharf alert suppress list"),
    );
  }
  with(|m| m.suppressions.retain(|r| r.id != id));
  flush_unsuppressed(state, now).await;
  Ok(())
}

/// `GET /api/alerts/suppress`
pub async fn list_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<AlertSuppressionView>> {
  auth.require(Perm::Read)?;
  ensure_loaded(&s).await;
  Ok(Json(with(|m| {
    m.suppressions
      .iter()
      .map(SuppressionRule::to_view)
      .collect()
  })))
}

/// `POST /api/alerts/suppress`
pub async fn add_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<AlertSuppressionRequest>,
) -> ApiResult<AlertSuppressionView> {
  auth.require(Perm::Admin)?;
  Ok(Json(add_rule(&s, req, now_ms()).await?))
}

/// `DELETE /api/alerts/suppress/{id}`
pub async fn rm_api(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(id): Path<i64>,
) -> ApiResult<AlertsView> {
  auth.require(Perm::Admin)?;
  remove_rule(&s, id, now_ms()).await?;
  Ok(Json(view(&s).await?))
}
