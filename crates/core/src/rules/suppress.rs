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
  (super::op_silence::ID, "Wharf 操作期间自动静默相关告警"),
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
    | "heartbeat_late"
    | "heal"
    | "auto_update"
    | "update" => world
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
    "domain_down" | "cert_expiring" | "failover" => {
      route_servers(world, subject, rule == "failover")
    }
    "backup" => world
      .services
      .get(subject)
      .map(|row| {
        let mut servers = vec![row.spec.server.clone()];
        if let Some(backup) = &row.spec.backup {
          servers.push(backup.to.clone());
        }
        servers
      })
      .unwrap_or_default(),
    "exposure" | "unmanaged_container" => vec![subject.to_string()],
    "link_cert_expiring" => world
      .gateways
      .get(subject)
      .map(|row| vec![row.spec.server.clone()])
      .unwrap_or_default(),
    "link_loss" | "tailnet_relay" => match subject.split_once('>') {
      Some((from, to)) => vec![from.to_string(), to.to_string()],
      None => vec![],
    },
    _ => vec![],
  }
}

fn route_servers(
  world: &World,
  host: &str,
  all_gateways: bool,
) -> Vec<String> {
  let Some(route) = world.routes.get(host) else {
    return vec![];
  };
  let spec = &route.spec;
  let gateways = if all_gateways {
    world.route_gateways(spec)
  } else {
    world.live_gateway(host, spec).into_iter().collect()
  };
  let mut servers: BTreeSet<_> = gateways
    .into_iter()
    .filter_map(|name| {
      world.gateways.get(name).map(|g| g.spec.server.clone())
    })
    .collect();
  let upstream = (spec.upstream.is_none() && spec.redirect.is_none())
    .then_some(spec.service.as_str());
  for service in upstream
    .into_iter()
    .chain(spec.paths.iter().filter_map(|p| p.service.as_deref()))
  {
    if let Some(row) = world.services.get(service) {
      servers.insert(row.spec.server.clone());
    }
  }
  // 主入口离线正是切到备用入口的原因，即使它也承载上游服务。
  if all_gateways
    && let Some(primary) = world.route_gateway(spec)
    && let Some(gateway) = world.gateways.get(primary)
  {
    servers.remove(&gateway.spec.server);
  }
  servers.into_iter().collect()
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
  if cfg.get(BUILTIN_OFFLINE).is_none_or(Override::enabled)
    && let Some(subject) = subject
    && (id == "task"
      || (id == "backup" && subject == crate::core_backup::REPO))
  {
    let name = subject.to_string();
    let task = id == "task";
    let servers = state.db.call(move |c| {
      if task {
        let mut stmt = c.prepare(
          "SELECT json_extract(spec, '$.server') FROM tasks WHERE name = ?1"
        ).map_err(db::sql_err)?;
        return stmt.query_map([name], |r| r.get::<_, String>(0))
          .map_err(db::sql_err)?.collect::<Result<Vec<_>, _>>().map_err(db::sql_err);
      }
      Ok(crate::core_node::load_persisted(c)?.map(|(server, _)| server).into_iter()
        .chain(db::setting(c, crate::core_backup::TO)?).collect())
    }).await.unwrap_or_default();
    if let Some(reason) = with(|m| {
      servers.into_iter().find_map(|server| {
        m.firing
          .get(&("server_offline".to_string(), server))
          .map(|entry| entry.title.clone())
      })
    }) {
      return Some(reason);
    }
  }
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

fn pending() -> Vec<(String, String, Event)> {
  with(|m| {
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
  })
}

fn grace_ms(rule_id: &str) -> i64 {
  RULES
    .iter()
    .find(|rule| rule.id == rule_id)
    .map_or(180_000, |rule| {
      (rule.period_secs as i64 * 1000 + 60_000).max(180_000)
    })
}

async fn eligible(
  state: &AppState,
  rule: &str,
  subject: &str,
  cfg: &BTreeMap<String, Override>,
  world: Option<&World>,
) -> bool {
  let service = service_overrides::service_of_subject(rule, subject)
    .or_else(|| {
      with(|m| m.custom_rules.contains_key(rule)).then_some(subject)
    });
  !service.is_some_and(|service| {
    super::op_silence::service_busy(state, service)
  }) && check(state, rule, Some(subject), cfg, world)
    .await
    .is_none()
}

pub(crate) async fn schedule_unsuppress(state: &AppState, now: i64) {
  let pending = pending();
  if pending.is_empty() {
    return;
  }
  let cfg = config(state).await;
  let world = load_world(state).await;
  for (rule, subject, _) in pending {
    let ready =
      eligible(state, &rule, &subject, &cfg, world.as_ref()).await;
    with(|m| {
      let key = (rule.clone(), subject);
      if ready
        && m.firing.get(&key).is_some_and(|f| {
          f.suppressed && f.delivery == Delivery::None
        })
      {
        m.unsuppress_grace
          .entry(key)
          .or_insert_with(|| now + grace_ms(&rule));
      } else {
        m.unsuppress_grace.remove(&key);
      }
    });
  }
}

pub(super) async fn confirm_sample(
  state: &AppState,
  key: &(String, String),
) -> bool {
  if !with(|m| m.unsuppress_grace.contains_key(key)) {
    return false;
  }
  let cfg = config(state).await;
  if !eligible(state, &key.0, &key.1, &cfg, None).await {
    return false;
  }
  claim(state, key, |deadline| deadline.is_some()).await
}

async fn claim(
  state: &AppState,
  key: &(String, String),
  due: impl Fn(Option<i64>) -> bool,
) -> bool {
  let claimed = with(|m| {
    let suppressed = m
      .firing
      .get(key)
      .is_some_and(|f| f.suppressed && f.delivery == Delivery::None);
    let deadline = m.unsuppress_grace.get(key).copied();
    if !suppressed || !due(deadline) {
      return false;
    }
    m.unsuppress_grace.remove(key);
    if let Some(f) = m.firing.get_mut(key) {
      f.suppressed = false;
    }
    true
  });
  if claimed {
    set_firing_suppressed(state, key.clone(), false).await;
  }
  claimed
}

pub(super) async fn flush_unsuppressed_now(
  state: &AppState,
  now: i64,
) {
  flush(state, now, true).await;
}

pub(crate) async fn flush_due_unsuppressed(
  state: &AppState,
  now: i64,
) {
  schedule_unsuppress(state, now).await;
  flush(state, now, false).await;
}

async fn flush(state: &AppState, now: i64, immediate: bool) {
  let pending = pending();
  if pending.is_empty() {
    return;
  }
  let cfg = config(state).await;
  let (svc_overrides, custom_rules) =
    with(|m| (m.service_overrides.clone(), m.custom_rules.clone()));
  let world = load_world(state).await;
  for (rule_id, subject, event) in pending {
    if !eligible(state, &rule_id, &subject, &cfg, world.as_ref())
      .await
    {
      continue;
    }
    let key = (rule_id.clone(), subject.clone());
    if !claim(state, &key, |deadline| {
      immediate || deadline.is_some_and(|deadline| deadline <= now)
    })
    .await
    {
      continue;
    }
    let o = service_overrides::override_for_firing(
      &cfg,
      &svc_overrides,
      &custom_rules,
      &rule_id,
      &subject,
      now,
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
    schedule_unsuppress(state, now_ms()).await;
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

fn creates_cycle(
  existing: &[SuppressionRule],
  source: (&str, Option<&str>),
  target: (&str, Option<&str>),
) -> bool {
  let overlaps = |a: (&str, Option<&str>),
                  b: (&str, Option<&str>)| {
    a.0 == b.0 && (a.1.is_none() || b.1.is_none() || a.1 == b.1)
  };
  let mut pending = vec![target];
  let mut visited = BTreeSet::new();
  while let Some(node) = pending.pop() {
    if overlaps(node, source) {
      return true;
    }
    if visited.insert(node) {
      pending.extend(existing.iter().filter_map(|r| {
        overlaps(node, (&r.source_rule, r.source_subject.as_deref()))
          .then_some((
            r.target_rule.as_str(),
            r.target_subject.as_deref(),
          ))
      }));
    }
  }
  false
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
  static ADD: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());
  let _add = ADD.lock().await;
  let (count, dup, cycle) = with(|m| {
    let dup = m.suppressions.iter().any(|r| {
      r.source_rule == req.source_rule
        && r.source_subject == source_subject
        && r.target_rule == req.target_rule
        && r.target_subject == target_subject
    });
    let cycle = creates_cycle(
      &m.suppressions,
      (&req.source_rule, source_subject.as_deref()),
      (&req.target_rule, target_subject.as_deref()),
    );
    (m.suppressions.len(), dup, cycle)
  });
  if dup {
    return Err(ApiError::new(
      ErrorCode::AlreadyExists,
      "相同的抑制规则已存在",
    ));
  }
  if cycle {
    return Err(
      ApiError::invalid(
        "这条抑制规则会和现有规则形成循环抑制，导致告警互相吞掉",
      )
      .with_hint("用 wharf alert suppress list 查看现有规则"),
    );
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
  flush_unsuppressed_now(state, now).await;
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
