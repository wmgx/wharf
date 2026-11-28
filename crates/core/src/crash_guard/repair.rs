use axum::Extension;
use serde_json::Value;
use wharf_api_types::{
  agent::{RepairLease, ServiceRepairOp},
  view::{
    HostExecResponse, RepairView, ServiceExecResponse,
    ServiceRepairRequest,
  },
};

use super::*;
use crate::{audit::AuditSlot, locks::LockSpec, shell::ExecRequest};

pub(crate) type Lease = RepairLease;
const LEASE_MS: i64 = 30 * 60_000;

fn view(
  name: String,
  row: Option<&Recovery>,
  execution: Option<ServiceExecResponse>,
) -> RepairView {
  RepairView {
    service: name,
    phase: row.map(|r| r.phase.clone()),
    expires_ms: row
      .and_then(|r| r.lease.as_ref())
      .map(|l| l.expires_ms),
    execution,
  }
}

pub async fn get(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<RepairView> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  let snap = snapshot::load_inner(&state.db).await?;
  if !snap.world.services.contains_key(&name) {
    return Err(crate::api::service_not_found(&name).into());
  }
  Ok(Json(view(name.clone(), snap.recovery.get(&name), None)))
}

pub async fn act(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(slot): Extension<AuditSlot>,
  Json(req): Json<ServiceRepairRequest>,
) -> ApiResult<RepairView> {
  for perm in [Perm::Admin, Perm::Apply, Perm::Confirm] {
    auth.require(perm)?;
  }
  if auth.services.is_some() {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        "修复需要不限制服务范围的管理员令牌",
      )
      .into(),
    );
  }
  let _lock = state
    .locks
    .acquire(LockSpec::apply([name.clone()]), "修复服务")?;
  let snap = snapshot::load_inner(&state.db).await?;
  let row = snap
    .world
    .services
    .get(&name)
    .ok_or_else(|| crate::api::service_not_found(&name))?;
  let server = &row.spec.server;
  let conn = state.hub.service_repair_conn_id(server)?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let existing = snap.recovery.get(&name);
  match req {
    ServiceRepairRequest::Start => {
      let applied = snap.applied.get(&name).ok_or_else(|| {
        ApiError::new(ErrorCode::Conflict, "服务尚未部署")
      })?;
      if !row.spec.stopped
        || snap.pending.migrations.contains_key(&name)
        || snap.pending.adopt_data.contains_key(&name)
        || row.import.is_some()
        || crate::shared_volumes::owners(&row.spec).next().is_some()
        || crate::shared_volumes::consumers_on(
          &snap.world,
          &name,
          server,
        )
        .next()
        .is_some()
      {
        return Err(
          ApiError::new(
            ErrorCode::Conflict,
            "服务必须确认停止且托管数据可独占",
          )
          .with_hint("先停止服务并排除共享数据和未完成运维")
          .into(),
        );
      }
      let mut recovery = existing.cloned().unwrap_or(Recovery {
        phase: "repair_starting".into(),
        evidence: None,
        policies: vec![],
        attempts: 0,
        run: String::new(),
        lease: None,
      });
      let lease = if let Some(lease) = &recovery.lease {
        if recovery.phase != "repair_starting"
          || lease.expires_ms <= db::now_ms()
        {
          return Err(
            ApiError::new(
              ErrorCode::Conflict,
              "修复租约仍在用或等待清理",
            )
            .with_hint("运行 wharf service repair --exit")
            .into(),
          );
        }
        lease.clone()
      } else {
        if existing.is_some_and(|r| r.phase != "protected") {
          return Err(blocker(&name).into());
        }
        RepairLease {
          service: name.clone(),
          instance: row.instance_id.clone(),
          id: crate::world::new_id("repair").replace('_', "-"),
          hash: applied.hash.clone(),
          expires_ms: db::now_ms() + LEASE_MS,
        }
      };
      recovery.phase = "repair_starting".into();
      recovery.lease = Some(lease.clone());
      persist(
        &state,
        &name,
        server,
        &row.instance_id,
        Some(&recovery),
      )
      .await?;
      state
        .hub
        .call_bound::<bool>(
          (server, conn),
          AgentOp::ServiceRepair(ServiceRepairOp::Start { lease }),
          Duration::from_secs(120),
          None,
          &cancel,
        )
        .await?;
      recovery.phase = "repair".into();
      persist(
        &state,
        &name,
        server,
        &row.instance_id,
        Some(&recovery),
      )
      .await?;
      Ok(Json(view(name, Some(&recovery), None)))
    }
    ServiceRepairRequest::Exit => {
      let Some(mut recovery) = existing.cloned() else {
        return Ok(Json(view(name, None, None)));
      };
      let Some(lease) = recovery.lease.take() else {
        return Ok(Json(view(name, Some(&recovery), None)));
      };
      state
        .hub
        .call_bound::<bool>(
          (server, conn),
          AgentOp::ServiceRepair(ServiceRepairOp::End { lease }),
          Duration::from_secs(90),
          None,
          &cancel,
        )
        .await?;
      let next = recovery.evidence.is_some().then(|| {
        recovery.phase = "protected".into();
        recovery
      });
      persist(&state, &name, server, &row.instance_id, next.as_ref())
        .await?;
      Ok(Json(view(name, next.as_ref(), None)))
    }
    ServiceRepairRequest::Exec {
      command,
      timeout_secs,
    } => {
      auth.require(Perm::Exec)?;
      let lease = existing
        .filter(|r| r.phase == "repair")
        .and_then(|r| r.lease.as_ref())
        .filter(|lease| lease.expires_ms > db::now_ms())
        .ok_or_else(|| {
          ApiError::new(ErrorCode::Conflict, "没有可用的修复租约")
        })?;
      let valid = ExecRequest {
        command,
        timeout_secs,
        cwd: None,
      }
      .job()?;
      let audit = slot
        .start_exec(
          &state,
          &auth.name,
          format!("service={name} repair_command"),
        )
        .await?;
      let result = state
        .hub
        .call_bound::<HostExecResponse>(
          (server, conn),
          AgentOp::ServiceRepair(ServiceRepairOp::Exec {
            lease: lease.clone(),
            command: valid.command,
            timeout_secs: valid.timeout_secs,
          }),
          Duration::from_secs(valid.timeout_secs + 30),
          None,
          &cancel,
        )
        .await;
      let mut values = crate::log_redact::service_values(&row.spec);
      crate::log_redact::add_encoded_values(&mut values);
      values.extend(snap.log_values.iter().cloned());
      let (status, duration, detail) = match &result {
        Ok(r) => {
          (200, r.duration_ms, format!("exit_code={}", r.exit_code))
        }
        Err(e) => (
          e.code.http_status(),
          0,
          format!("error={}", e.code.as_str()),
        ),
      };
      crate::audit::finish_exec(
        &state, audit, status, duration, detail,
      )
      .await?;
      let clean = |text: &str, truncated| {
        crate::exec_stream::redact(text, &values, truncated)
      };
      let result = result.map_err(|mut e| {
        e.message = clean(&e.message, false);
        e.hint = e.hint.map(|v| clean(&v, false));
        e
      })?;
      let execution = ServiceExecResponse {
        service: name.clone(),
        server: server.clone(),
        container: "repair".into(),
        exit_code: result.exit_code,
        stdout: clean(&result.stdout, result.truncated),
        stderr: clean(&result.stderr, result.truncated),
        truncated: result.truncated,
        duration_ms: result.duration_ms,
      };
      Ok(Json(view(name, existing, Some(execution))))
    }
  }
}

pub(crate) async fn sweep(state: &AppState, snap: &Snapshot) {
  for (name, row) in &snap.recovery {
    if let Some(lease) = row
      .lease
      .as_ref()
      .filter(|lease| lease.expires_ms <= db::now_ms())
    {
      let Ok(_lock) = state
        .locks
        .acquire(LockSpec::apply([name.clone()]), "清理过期修复租约")
      else {
        continue;
      };
      let current = name.clone();
      let Ok(Some(mut row)) =
        state.db.call(move |c| read_raw(c, &current)).await
      else {
        continue;
      };
      if row.lease.as_ref() != Some(lease) {
        continue;
      }
      let server = &snap.world.services[name].spec.server;
      let Ok(conn) = state.hub.service_repair_conn_id(server) else {
        continue;
      };
      let cancel = CancellationToken::new();
      let _cancel = cancel.clone().drop_guard();
      let closed = state
        .hub
        .call_bound::<Value>(
          (server, conn),
          AgentOp::ServiceRepair(ServiceRepairOp::End {
            lease: lease.clone(),
          }),
          Duration::from_secs(90),
          None,
          &cancel,
        )
        .await;
      if closed.is_ok() {
        row.lease = None;
        row.phase = "protected".into();
        let _ = persist(
          state,
          name,
          server,
          &lease.instance,
          row.evidence.is_some().then_some(&row),
        )
        .await;
      }
    }
  }
}

async fn persist(
  state: &AppState,
  name: &str,
  server: &str,
  instance: &str,
  recovery: Option<&Recovery>,
) -> Result<(), ApiError> {
  let (n, s, i, r) = (
    name.to_owned(),
    server.to_owned(),
    instance.to_owned(),
    recovery.cloned(),
  );
  state
    .db
    .call(move |c| {
      if let Some(recovery) = &r {
        store(c, &n, &s, &i, recovery)
      } else {
        c.execute(
          "DELETE FROM service_recovery WHERE instance_id=?1",
          [i],
        )
        .map_err(sql_err)?;
        Ok(())
      }
    })
    .await
}
