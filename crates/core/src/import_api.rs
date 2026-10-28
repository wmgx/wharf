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
  view::{ImportPreview, ImportRequest, TokenScope, Unmanaged},
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
  auth.require(TokenScope::Read)?;
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
  auth.require(TokenScope::Plan)?;
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
    },
    adopt: converted.adopt,
    name,
    warnings,
  }))
}
