use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Query, State},
};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, AgentReport, LocalImage, ProjectMetrics},
  resources::{
    AgentUsage, ComponentUsage, ImageRow, ImagesView, UsageKind,
    UsageRow, percent,
  },
  spec::ServerSettings,
  view::Perm,
};

use crate::{
  api::ApiResult, auth::Auth, rules::resources::service_limit,
  snapshot, state::AppState,
};

const IMAGE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
pub struct Filter {
  server: Option<String>,
  service: Option<String>,
  #[serde(default)]
  containers: bool,
}

pub fn agent_usage(
  settings: &ServerSettings,
  report: Option<&AgentReport>,
) -> AgentUsage {
  let sample = report.and_then(|r| r.metrics.as_deref());
  let state = report.and_then(|r| r.agent_memory.as_ref());
  let mem = sample.and_then(|m| m.agent_mem);
  let memory_limit = state.and_then(|s| s.limit);
  AgentUsage {
    configured_limit: settings.agent_memory_bytes(),
    cpu: sample.and_then(|m| m.agent_cpu),
    mem,
    memory_limit,
    memory_pct: mem
      .zip(memory_limit)
      .and_then(|(used, total)| percent(used, total)),
    limit_error: state.and_then(|s| s.error.clone()),
  }
}

pub async fn usage(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(filter): Query<Filter>,
) -> ApiResult<Vec<UsageRow>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&state.db).await?;
  let servers = servers(&snap, &filter)?;
  let mut rows = Vec::new();
  if filter.containers && filter.service.is_none() {
    return Err(
      ApiError::invalid("--containers 需要 --service").into(),
    );
  }
  if let Some(service) = &filter.service {
    crate::token_scope::require_service(&auth, service)?;
    if !snap.world.services.contains_key(service) {
      return Err(
        ApiError::not_found(format!("服务 {service} 不存在")).into(),
      );
    }
  }
  for server in servers {
    let report = snap.agent(server).and_then(|a| a.report.as_ref());
    let sample = report.and_then(|r| r.metrics.as_deref());
    let project =
      |name: &str| sample.and_then(|m| m.projects.get(name));
    for (name, row) in
      snap.world.services.iter().filter(|(name, _)| {
        snapshot::service_runtime_server(&snap, name) == Some(server)
          && filter
            .service
            .as_ref()
            .is_none_or(|selected| selected == *name)
      })
    {
      let mut usage = project_row(
        name,
        UsageKind::Service,
        server,
        project(name),
        service_limit(&row.spec),
      );
      if filter.containers {
        usage.components =
          component_usage(&state, row, server).await?;
      }
      rows.push(usage);
    }
    if filter.service.is_some() {
      continue;
    }
    for (name, _) in snap
      .world
      .gateways
      .iter()
      .filter(|(_, g)| g.spec.server == server)
    {
      rows.push(project_row(
        name,
        UsageKind::Gateway,
        server,
        project(&crate::world::gateway_project(name)),
        None,
      ));
    }
    if snap.agent(server).is_some_and(|a| a.public_key.is_some()) {
      let agent =
        agent_usage(&snap.world.servers[server].settings, report);
      rows.push(UsageRow {
        components: Vec::new(),
        name: "wharf-agent".into(),
        kind: UsageKind::Agent,
        server: server.into(),
        cpu: agent.cpu.map(f64::from),
        mem: agent.mem,
        memory_limit: agent.memory_limit.filter(|&v| v > 0),
        memory_pct: agent.memory_pct,
        net_rx: None,
        net_tx: None,
      });
    }
  }
  rows.sort_by(|a, b| {
    b.cpu
      .partial_cmp(&a.cpu)
      .unwrap_or(std::cmp::Ordering::Equal)
  });
  Ok(Json(rows))
}

async fn component_usage(
  state: &AppState,
  row: &crate::world::ServiceRow,
  server: &str,
) -> Result<Vec<ComponentUsage>, ApiError> {
  let wharf_api_types::spec::Source::Compose {
    content: Some(content),
    ..
  } = &row.spec.source
  else {
    return Ok(Vec::new());
  };
  let doc = crate::render::parse_compose(content)?;
  let Some(services) = doc["services"].as_mapping() else {
    return Ok(Vec::new());
  };
  let mut entries = Vec::new();
  for (key, body) in services {
    let Some(name) = key.as_str() else { continue };
    let legacy = row
      .spec
      .container
      .as_deref()
      .map_or(services.len() == 1, |target| target == name);
    let limits = row.spec.container_limits.get(name).or_else(|| {
      legacy.then_some(row.spec.limits.as_ref()).flatten()
    });
    let deploy = &body["deploy"]["resources"]["limits"];
    let cpu = deploy
      .get("cpus")
      .or_else(|| body.get("cpus"))
      .and_then(|value| {
        value.as_f64().or_else(|| value.as_str()?.parse().ok())
      })
      .filter(|value| value.is_finite() && *value > 0.0)
      .map(|value| (value * 1000.0).round() as u32);
    let pids = deploy
      .get("pids")
      .or_else(|| body.get("pids_limit"))
      .and_then(|value| {
        value
          .as_u64()
          .and_then(|n| u32::try_from(n).ok())
          .or_else(|| value.as_str()?.parse().ok())
      })
      .filter(|&n| n > 0);
    entries.push((
      crate::metrics::component_subject(
        &row.instance_id,
        server,
        name,
      ),
      ComponentUsage {
        name: name.into(),
        cpu_limit_milli: limits
          .and_then(|limit| limit.cpu_milli)
          .or(cpu),
        memory_limit: crate::lint::effective_component_memory(
          &row.spec,
          key,
          body,
          services.len() == 1,
        )
        .filter(|&mb| mb > 0.0)
        .map(|mb| (mb * (1 << 20) as f64) as u64),
        pids_limit: limits.and_then(|limit| limit.pids).or(pids),
        cpu_peak: None,
        memory_peak: None,
      },
    ));
  }
  state
    .db
    .call(move |c| {
      entries
        .into_iter()
        .map(|(subject, mut row)| {
          (row.cpu_peak, row.memory_peak) =
            crate::metrics::component_peaks(c, &subject)?;
          Ok(row)
        })
        .collect()
    })
    .await
}

fn project_row(
  name: &str,
  kind: UsageKind,
  server: &str,
  sample: Option<&ProjectMetrics>,
  limit: Option<u64>,
) -> UsageRow {
  UsageRow {
    components: Vec::new(),
    name: name.into(),
    kind,
    server: server.into(),
    cpu: sample.map(|s| f64::from(s.cpu)),
    mem: sample.map(|s| s.mem),
    memory_limit: limit,
    memory_pct: limit
      .zip(sample)
      .and_then(|(total, s)| percent(s.mem, total)),
    net_rx: sample.map(|s| s.net_rx),
    net_tx: sample.map(|s| s.net_tx),
  }
}

fn servers<'a>(
  snap: &'a snapshot::Snapshot,
  filter: &Filter,
) -> Result<Vec<&'a str>, ApiError> {
  if let Some(name) = &filter.server {
    let (server, _) = snap
      .world
      .servers
      .get_key_value(name)
      .ok_or_else(|| crate::world::server_not_found(name))?;
    Ok(vec![server.as_str()])
  } else {
    Ok(snap.world.servers.keys().map(String::as_str).collect())
  }
}

pub async fn images(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Query(filter): Query<Filter>,
) -> ApiResult<ImagesView> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&state.db).await?;
  let results = futures_util::future::join_all(servers(&snap, &filter)?.into_iter().map(|server| {
    let hub = &state.hub;
    async move {
      let cancel = CancellationToken::new();
      let call = hub.call::<Vec<LocalImage>>(server, AgentOp::ListImages, IMAGE_TIMEOUT, None, &cancel);
      tokio::pin!(call);
      let result = tokio::select! {
        result = &mut call => result,
        _ = tokio::time::sleep(IMAGE_TIMEOUT) => {
          cancel.cancel();
          let _ = call.await;
          Err(ApiError::new(ErrorCode::Timeout, "镜像查询超过 15 秒"))
        }
      };
      (server, result)
    }
  })).await;
  let mut view = ImagesView::default();
  for (server, result) in results {
    match result {
      Ok(images) => {
        let mut ids = BTreeSet::new();
        let mut unused = 0_u64;
        for image in images {
          if image.used_by.is_empty() && ids.insert(image.id.clone())
          {
            unused = unused.saturating_add(image.size);
          }
          view.rows.push(ImageRow {
            server: server.into(),
            image,
          });
        }
        view.unused.insert(server.into(), unused);
      }
      Err(e) => {
        view.errors.insert(server.into(), e.message);
      }
    }
  }
  view.rows.sort_by(|a, b| {
    b.image
      .size
      .cmp(&a.image.size)
      .then_with(|| a.image.image.cmp(&b.image.image))
  });
  Ok(Json(view))
}
