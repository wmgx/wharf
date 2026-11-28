use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use wharf_api_types::{ApiError, plan::Plan};

use crate::{
  db::{self, Write, json_err, sql_err},
  planner::{Step, StepPlan},
  world::{KIND_SERVICE, World},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigratePhase {
  Pending,
  Synced,
  UpDone,
}

impl MigratePhase {
  fn key(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Synced => "synced",
      Self::UpDone => "up_done",
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigratePayload {
  pub service: String,
  pub from: String,
  pub to: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub instance_id: Option<String>,
  #[serde(default)]
  pub has_managed_data: bool,
  #[serde(default)]
  pub source_stopped: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub target_backup: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub target_prepared: bool,
}

pub struct Migration {
  pub phase: MigratePhase,
  pub payload: MigratePayload,
}

impl Migration {
  pub fn phase_name(&self) -> &'static str {
    self.phase.key()
  }
}

#[derive(Serialize, Deserialize)]
pub struct ServiceDeletePayload {
  pub service: String,
  pub server: String,
  pub instance_id: String,
  #[serde(default)]
  pub purge_data: bool,
  #[serde(default)]
  pub has_relative_mounts: bool,
}

#[derive(Serialize, Deserialize)]
pub struct EnsureDirsPayload {
  pub service: String,
  pub server: String,
  pub dirs: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub instance_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GatewayDownPayload {
  pub gateway: String,
  pub server: String,
  #[serde(default)]
  pub keep_tunnel: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TunnelDeletePayload {
  pub gateway: String,
  pub account: String,
  pub scope: String,
  pub tunnel_id: String,
}

#[derive(Default)]
pub struct PendingState {
  pub migrations: BTreeMap<String, Migration>,
  pub adopt_data:
    BTreeMap<String, wharf_api_types::adopt_data::AdoptDataJob>,
  pub backup_moves: BTreeMap<String, crate::backup_move::PendingMove>,
  pub gateway_downs: Vec<GatewayDownPayload>,
  pub tunnel_deletes: Vec<TunnelDeletePayload>,
  pub service_deletes: Vec<ServiceDeletePayload>,
  pub edge_deploys: BTreeSet<String>,
  pub docker_proxies: BTreeSet<String>,
  pub egresses: BTreeSet<String>,
  pub baselines: BTreeSet<String>,
  pub ensure_dirs: BTreeMap<String, EnsureDirsPayload>,
  pub gateways_after_dns: BTreeSet<String>,
  pub links_after_dns: BTreeSet<String>,
  pub dns_cutovers: BTreeSet<String>,
}

pub fn load(c: &Connection) -> Result<PendingState, ApiError> {
  // 服务配置已删除，续删从原执行记录恢复同批步骤的顺序。
  let mut stmt = c
    .prepare(
      "SELECT p.kind, p.target_key, p.phase, p.payload
     FROM pending_steps p
     LEFT JOIN runs r ON p.kind = 'service_delete' AND r.id = p.run_id
     ORDER BY r.started_at, r.id, (
       SELECT CAST(s.key AS INTEGER)
       FROM json_each(r.retry_meta, '$.steps') s
       WHERE s.value ->> '$.step.kind' = 'service_down'
         AND s.value ->> '$.step.service' = p.payload ->> '$.service'
         AND s.value ->> '$.step.server' = p.payload ->> '$.server'
         AND s.value ->> '$.step.instance_id' = p.instance_id
       ORDER BY CAST(s.key AS INTEGER)
       LIMIT 1
     ), p.target_key",
    )
    .map_err(sql_err)?;
  let mut rows = stmt.query([]).map_err(sql_err)?;
  let mut pending = PendingState::default();
  while let Some(row) = rows.next().map_err(sql_err)? {
    let kind: String = row.get(0).map_err(sql_err)?;
    let key: String = row.get(1).map_err(sql_err)?;
    let phase: String = row.get(2).map_err(sql_err)?;
    let payload: String = row.get(3).map_err(sql_err)?;
    match kind.as_str() {
      crate::backup_move::KIND => {
        pending.backup_moves.insert(
          key,
          serde_json::from_str(&payload).map_err(json_err)?,
        );
      }
      "migrate" => {
        let phase = match phase.as_str() {
          "pending" => MigratePhase::Pending,
          "synced" => MigratePhase::Synced,
          "up_done" => MigratePhase::UpDone,
          _ => return Err(ApiError::internal("迁移阶段无效")),
        };
        pending.migrations.insert(
          key,
          Migration {
            phase,
            payload: serde_json::from_str(&payload)
              .map_err(json_err)?,
          },
        );
      }
      "adopt_data" => {
        pending.adopt_data.insert(
          key,
          serde_json::from_str(&payload).map_err(json_err)?,
        );
      }
      "gateway_down" => pending
        .gateway_downs
        .push(serde_json::from_str(&payload).map_err(json_err)?),
      "tunnel_delete" => pending
        .tunnel_deletes
        .push(serde_json::from_str(&payload).map_err(json_err)?),
      "service_delete" => pending
        .service_deletes
        .push(serde_json::from_str(&payload).map_err(json_err)?),
      "edge_deploy" => {
        pending.edge_deploys.insert(key);
      }
      "docker_proxy" => {
        pending.docker_proxies.insert(key);
      }
      "egress" => {
        pending.egresses.insert(key);
      }
      "baseline" => {
        pending.baselines.insert(key);
      }
      "gateway_after_dns" => {
        pending.gateways_after_dns.insert(key);
      }
      "link_after_dns" => {
        pending.links_after_dns.insert(key);
      }
      "dns_cutover" => {
        pending.dns_cutovers.insert(key);
      }
      "ensure_dirs" => {
        pending.ensure_dirs.insert(
          key,
          serde_json::from_str(&payload).map_err(json_err)?,
        );
      }
      _ => {}
    }
  }
  Ok(pending)
}

fn put(
  c: &Connection,
  (kind, target): (&str, &str),
  (run_id, plan_id): (&str, &str),
  instance: Option<&str>,
  payload: &impl Serialize,
) -> Result<(), ApiError> {
  let payload = serde_json::to_string(payload).map_err(json_err)?;
  c.execute(
    "INSERT INTO pending_steps (kind,target_key,run_id,plan_id,instance_id,payload,updated_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7)
     ON CONFLICT(kind,target_key) DO UPDATE SET run_id=excluded.run_id, plan_id=excluded.plan_id,
     instance_id=excluded.instance_id,phase='pending',payload=excluded.payload,updated_at=excluded.updated_at",
    params![kind,target,run_id,plan_id,instance,payload,db::now_ms()],
  ).map_err(sql_err)?;
  Ok(())
}

pub fn put_gateway_down(
  c: &Connection,
  ids: (&str, &str),
  p: &GatewayDownPayload,
) -> Result<(), ApiError> {
  put(
    c,
    ("gateway_down", &format!("{}@{}", p.gateway, p.server)),
    ids,
    None,
    p,
  )
}

pub fn put_tunnel_delete(
  c: &Connection,
  ids: (&str, &str),
  p: &TunnelDeletePayload,
) -> Result<(), ApiError> {
  put(
    c,
    ("tunnel_delete", &format!("{}:{}", p.account, p.tunnel_id)),
    ids,
    None,
    p,
  )
}

pub fn clear(
  c: &Connection,
  kind: &str,
  target: &str,
) -> Result<(), ApiError> {
  c.execute(
    "DELETE FROM pending_steps WHERE kind=?1 AND target_key=?2",
    params![kind, target],
  )
  .map_err(sql_err)?;
  Ok(())
}

pub fn clear_service(
  c: &Connection,
  service: &str,
  include_deletes: bool,
) -> Result<(), ApiError> {
  c.execute(
    "DELETE FROM pending_steps
     WHERE (kind IN ('migrate','ensure_dirs','adopt_data') OR (?2 AND kind='service_delete'))
       AND json_extract(payload,'$.service')=?1",
    params![service,include_deletes],
  ).map_err(sql_err)?;
  Ok(())
}

pub fn clear_delete(
  c: &Connection,
  service: &str,
  server: &str,
  instance: Option<&str>,
) -> Result<(), ApiError> {
  c.execute(
    "DELETE FROM pending_steps WHERE kind='service_delete' AND target_key=?1 AND (?2 IS NULL OR instance_id=?2)",
    params![format!("{service}@{server}"),instance],
  ).map_err(sql_err)?;
  Ok(())
}

pub fn put_delete(
  c: &Connection,
  ids: (&str, &str),
  p: &ServiceDeletePayload,
) -> Result<(), ApiError> {
  put(
    c,
    ("service_delete", &format!("{}@{}", p.service, p.server)),
    ids,
    Some(&p.instance_id),
    p,
  )
}

pub fn update_migration(
  c: &Connection,
  service: &str,
  update: impl FnOnce(&mut Migration),
) -> Result<(), ApiError> {
  let Some(mut migration) = load(c)?.migrations.remove(service)
  else {
    return Ok(());
  };
  update(&mut migration);
  let payload =
    serde_json::to_string(&migration.payload).map_err(json_err)?;
  c.execute(
    "UPDATE pending_steps SET phase=?2,payload=?3,updated_at=?4 WHERE kind='migrate' AND target_key=?1",
    params![service,migration.phase.key(),payload,db::now_ms()],
  ).map_err(sql_err)?;
  Ok(())
}

// 源目录可能再次写入，切换前要重新停机同步。
pub async fn source_changed(
  state: &crate::state::AppState,
  service: &str,
) -> Result<(), ApiError> {
  let service = service.to_string();
  state.db.call(move |c| {
    c.execute("UPDATE pending_steps SET phase='pending', updated_at=?2 WHERE kind='migrate' AND target_key=?1 AND phase='synced'",
      params![service, db::now_ms()]).map_err(sql_err)?;
    Ok(())
  }).await
}

pub fn simple_key(step: &Step) -> Option<(&'static str, &str)> {
  match step {
    Step::EdgeDeploy { app, .. } => Some(("edge_deploy", app)),
    Step::DockerProxy { server } => Some(("docker_proxy", server)),
    Step::Egress { server } => Some(("egress", server)),
    Step::Baseline { server } => Some(("baseline", server)),
    _ => None,
  }
}

fn dns_cleanup_key(step: &Step) -> Option<(&'static str, String)> {
  match step {
    Step::GatewaySync {
      gateway,
      after_dns: true,
      ..
    } => Some(("gateway_after_dns", gateway.clone())),
    Step::LinkUp {
      server,
      project,
      after_dns: true,
      ..
    } => Some(("link_after_dns", format!("{server}/{project}"))),
    _ => None,
  }
}

// 配置与未执行步骤一起提交。执行器启动前，重规划就能看到这些步骤。
pub fn stage(
  c: &Connection,
  run_id: &str,
  plan: &Plan,
  writes: &[Write],
  steps: &[StepPlan],
) -> Result<(), ApiError> {
  let ids = (run_id, plan.plan_id.as_str());
  let world = World::from_rows(db::all_resources(c)?)?;
  let pending = load(c)?;
  for write in writes {
    if let Write::Delete { kind, name } = write
      && kind == KIND_SERVICE
    {
      clear_service(c, name, false)?;
    }
  }
  for (name, m) in &pending.migrations {
    if m.phase != MigratePhase::UpDone
      && world
        .services
        .get(name)
        .is_some_and(|row| row.spec.server == m.payload.from)
    {
      clear(c, "migrate", name)?;
    }
  }
  for host in &pending.dns_cutovers {
    if !world.routes.contains_key(host) {
      clear(c, "dns_cutover", host)?;
    }
  }
  let cutovers: Vec<_> = steps
    .iter()
    .filter_map(|step| match &step.step {
      Step::DnsUpsert {
        hostname,
        expected_gateway: Some(_),
        verify_target: true,
        ..
      } => Some(hostname),
      _ => None,
    })
    .collect();
  if !cutovers.is_empty() {
    let mut cleanup = steps
      .iter()
      .filter_map(|step| dns_cleanup_key(&step.step))
      .peekable();
    if cleanup.peek().is_some() {
      for (kind, key) in cleanup {
        put(c, (kind, &key), ids, None, &())?;
      }
      for host in cutovers {
        put(c, ("dns_cutover", host), ids, None, &())?;
      }
    }
  }
  for step in steps {
    if let Some((kind, name)) = simple_key(&step.step) {
      let payload = if kind == "edge_deploy" {
        serde_json::json!({"app": name, "fingerprint": crate::edge_plan::fingerprint(name, &world.edge_apps[name].spec)})
      } else {
        serde_json::json!({"server": name})
      };
      put(c, (kind, name), ids, None, &payload)?;
      continue;
    }
    match &step.step {
      Step::GatewayDown {
        server,
        gateway,
        keep_tunnel,
      } => {
        put_gateway_down(
          c,
          ids,
          &GatewayDownPayload {
            server: server.clone(),
            gateway: gateway.clone(),
            keep_tunnel: *keep_tunnel,
          },
        )?;
      }
      Step::TunnelDelete {
        gateway,
        account,
        scope,
        tunnel_id,
      } => {
        put_tunnel_delete(
          c,
          ids,
          &TunnelDeletePayload {
            gateway: gateway.clone(),
            account: account.clone(),
            scope: scope.clone(),
            tunnel_id: tunnel_id.clone(),
          },
        )?;
      }
      Step::AdoptData {
        job, instance_id, ..
      } => {
        put(
          c,
          ("adopt_data", &job.service),
          ids,
          instance_id.as_deref(),
          job,
        )?;
      }
      Step::EnsureDirs { server, dirs, .. } => {
        if let Some(service) = step.items.iter().find_map(|id| {
          plan
            .items
            .iter()
            .find(|item| item.id == *id)?
            .address
            .strip_prefix("service/")
        }) && let Some(row) = world.services.get(service)
        {
          let p = EnsureDirsPayload {
            service: service.into(),
            server: server.clone(),
            dirs: dirs.clone(),
            instance_id: Some(row.instance_id.clone()),
          };
          put(
            c,
            ("ensure_dirs", &format!("{service}@{server}")),
            ids,
            p.instance_id.as_deref(),
            &p,
          )?;
        }
      }
      Step::ServiceDown {
        service,
        server,
        purge_data,
        instance_id: Some(instance_id),
        has_relative_mounts,
      } => {
        let row = world.services.get(service);
        let old = pending.migrations.get(service);
        let abort = old.is_some_and(|m| {
          m.phase != MigratePhase::UpDone
            && m.payload.to == *server
            && row.is_some_and(|r| r.spec.server == m.payload.from)
        });
        if row.is_none() || abort {
          put_delete(c, ids, &ServiceDeletePayload { service: service.clone(), server: server.clone(), instance_id: instance_id.clone(), purge_data: *purge_data, has_relative_mounts: *has_relative_mounts })?;
        } else if let Some(row) = row
          && steps.iter().any(|s| matches!(&s.step, Step::ServiceUp { service: name, .. } if name == service))
          && old.is_none_or(|m| m.payload.to != row.spec.server)
        {
          let has_managed_data = steps.iter().any(|s| matches!(&s.step, Step::VolumeSync { service: name, .. } if name == service));
          let p = MigratePayload {
            service: service.clone(), from: server.clone(), to: row.spec.server.clone(),
            instance_id: Some(instance_id.clone()), has_managed_data,
            source_stopped: old.is_some_and(|m| m.payload.from == *server && m.payload.source_stopped),
            target_backup: None, target_prepared: false,
          };
          put(c, ("migrate", service), ids, Some(instance_id), &p)?;
        }
      }
      _ => {}
    }
  }
  Ok(())
}

pub async fn finish_step(
  state: &crate::state::AppState,
  step: &Step,
) -> Result<(), ApiError> {
  if let Some((kind, target)) = simple_key(step) {
    let target = target.to_string();
    return state.db.call(move |c| clear(c, kind, &target)).await;
  }
  let cleanup = match step {
    Step::AdoptData { job, .. } => {
      Some(("adopt_data", job.service.clone()))
    }
    Step::DnsUpsert { hostname, .. } => {
      Some(("dns_cutover", hostname.clone()))
    }
    Step::GatewayDown { gateway, .. } => {
      Some(("gateway_after_dns", gateway.clone()))
    }
    Step::LinkDown { server, project } => {
      Some(("link_after_dns", format!("{server}/{project}")))
    }
    _ => dns_cleanup_key(step),
  };
  if let Some((kind, target)) = cleanup {
    return state.db.call(move |c| clear(c, kind, &target)).await;
  }
  if let Step::EnsureDirs { server, dirs, .. } = step {
    let (server, dirs) = (server.clone(), dirs.clone());
    state
      .db
      .call(move |c| {
        for (key, p) in load(c)?.ensure_dirs {
          if p.server == server
            && p.dirs.iter().all(|d| dirs.contains(d))
          {
            clear(c, "ensure_dirs", &key)?;
          }
        }
        Ok(())
      })
      .await?;
  }
  Ok(())
}
