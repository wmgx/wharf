//! 导入已有容器的接口：列出没纳管的容器、生成导入预览。转换逻辑在 [crate::import]。

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, State},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, FoundContainer, ImportRaw, ImportTarget},
  spec::{ServiceSpec, Source},
  validate_name,
  view::{ImportPreview, ImportRequest, Perm, Unmanaged},
};

use crate::{
  api::ApiResult,
  auth::Auth,
  import, render, snapshot,
  state::AppState,
  world::{World, gateway_project, server_not_found},
};

/// Wharf 自己的 compose 项目：服务、网关、备份。
fn managed(world: &World, project: &str) -> bool {
  world.services.contains_key(project)
    || world.gateways.keys().any(|g| gateway_project(g) == project)
    || project == render::BACKUP_PROJECT
    || crate::link::is_link_project(project)
}

pub async fn unmanaged(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
) -> ApiResult<Vec<Unmanaged>> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let found: Vec<FoundContainer> = s
    .hub
    .call(
      &server,
      AgentOp::Discover,
      Duration::from_secs(40),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let mut projects: BTreeMap<String, Vec<FoundContainer>> =
    BTreeMap::new();
  let mut out = Vec::new();
  for c in found {
    match c.project.clone() {
      Some(p) if managed(&snap.world, &p) => {}
      Some(p) => projects.entry(p).or_default().push(c),
      None => out.push(Unmanaged {
        server: server.clone(),
        project: None,
        container: Some(c.name.clone()),
        name: import::service_name(&c.name),
        containers: vec![c],
      }),
    }
  }
  for (p, containers) in projects {
    out.push(Unmanaged {
      server: server.clone(),
      name: import::service_name(&p),
      project: Some(p),
      container: None,
      containers,
    });
  }
  out.sort_by(|a, b| a.name.cmp(&b.name));
  Ok(Json(out))
}

pub async fn preview(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<ImportRequest>,
) -> ApiResult<ImportPreview> {
  auth.require(Perm::Plan)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&req.server) {
    return Err(server_not_found(&req.server).into());
  }
  let raw_name = match (&req.project, &req.container) {
    (Some(p), None) => p,
    (None, Some(c)) => c,
    _ => {
      return Err(
        ApiError::invalid("compose 项目和容器二选一").into(),
      );
    }
  };
  let name = req
    .name
    .clone()
    .filter(|n| !n.trim().is_empty())
    .unwrap_or_else(|| import::service_name(raw_name));
  validate_name("服务", &name)?;
  if snap.world.services.contains_key(&name) {
    Err(
      ApiError::new(
        ErrorCode::AlreadyExists,
        format!("服务 {name} 已存在"),
      )
      .with_hint("换一个服务名"),
    )?;
  }
  let raw: ImportRaw = s
    .hub
    .call(
      &req.server,
      AgentOp::ImportRead(ImportTarget {
        project: req.project.clone(),
        container: req.container.clone(),
      }),
      Duration::from_secs(150),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let converted = match (&req.project, raw.compose, raw.inspect) {
    (Some(p), Some(config), _) => {
      import::from_compose(&config, p, &name)?
    }
    (None, _, Some(inspect)) => import::from_container(
      &inspect,
      raw.image_inspect.as_ref(),
      &name,
    )?,
    _ => {
      return Err(
        ApiError::new(ErrorCode::AgentFailed, "agent 没有返回配置")
          .with_hint("升级这台服务器上的 agent"),
      )?;
    }
  };
  let mut warnings = raw.warnings;
  warnings.extend(converted.warnings);
  Ok(Json(ImportPreview {
    spec: ServiceSpec {
      server: req.server,
      source: Source::Compose {
        content: Some(converted.compose),
        file: None,
      },
      ports: converted.ports,
      env: Default::default(),
      volumes: vec![],
      backup: None,
      stopped: false,
      monitor: None,
      limits: None,
    },
    adopt: converted.adopt,
    name,
    warnings,
  }))
}

#[derive(serde::Deserialize)]
pub struct RemoveRequest {
  #[serde(default)]
  project: Option<String>,
  #[serde(default)]
  container: Option<String>,
  /// 连同具名数据卷一起删。
  #[serde(default)]
  volumes: bool,
}

/// `POST /api/servers/{name}/unmanaged/remove`：删掉一个没纳管的容器或 compose 项目的全部容器。
/// 只认现在仍然没纳管的，Wharf 自己的服务、网关不会被删。
pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
  Json(req): Json<RemoveRequest>,
) -> ApiResult<wharf_api_types::agent::RemovedContainers> {
  auth.require(Perm::Apply)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  let found: Vec<FoundContainer> = s
    .hub
    .call(
      &server,
      AgentOp::Discover,
      Duration::from_secs(40),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let names: Vec<String> = match (&req.project, &req.container) {
    (Some(p), None) => {
      if managed(&snap.world, p) {
        return Err(
          ApiError::invalid(format!(
            "{p} 是 Wharf 管理的，不能在这里删"
          ))
          .into(),
        );
      }
      found
        .iter()
        .filter(|c| c.project.as_deref() == Some(p.as_str()))
        .map(|c| c.name.clone())
        .collect()
    }
    (None, Some(name)) => found
      .iter()
      .filter(|c| &c.name == name && c.project.is_none())
      .map(|c| c.name.clone())
      .collect(),
    _ => {
      return Err(
        ApiError::invalid("project 和 container 二选一").into(),
      );
    }
  };
  if names.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::NotFound,
        "没找到这个容器，可能已经删掉了",
      )
      .into(),
    );
  }
  let removed = s
    .hub
    .call(
      &server,
      AgentOp::RemoveContainers {
        containers: names,
        volumes: req.volumes,
      },
      Duration::from_secs(180),
      None,
      &CancellationToken::new(),
    )
    .await?;
  tracing::info!(
    "删除 {server} 上没纳管的 {}（数据卷：{}）",
    req
      .project
      .as_deref()
      .or(req.container.as_deref())
      .unwrap_or(""),
    req.volumes
  );
  Ok(Json(removed))
}
