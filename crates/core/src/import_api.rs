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

use crate::secret_import::SecretChangesExt;

use crate::{
  api::ApiResult,
  auth::Auth,
  import, render, snapshot,
  state::AppState,
  world::{World, gateway_project, server_not_found},
};

/// Wharf 自己的 compose 项目：服务、网关、备份。
pub(crate) fn managed(world: &World, project: &str) -> bool {
  world.services.contains_key(project)
    || world.gateways.keys().any(|g| gateway_project(g) == project)
    || matches!(
      project,
      render::BACKUP_PROJECT | render::CORE_BACKUP_PROJECT
    )
    || project == crate::tailscale::PROJECT
    || crate::link::is_link_project(project)
    || project
      .starts_with(wharf_api_types::agent::TRIAL_PROJECT_PREFIX)
    || project.starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
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
  let mut out = discover(&s, &snap.world, &server).await?;
  crate::service_monitor::unmanaged::flags(&s, &server, &mut out)
    .await?;
  Ok(Json(out))
}

pub(crate) async fn discover(
  s: &AppState,
  world: &World,
  server: &str,
) -> Result<Vec<Unmanaged>, ApiError> {
  let found: Vec<FoundContainer> = s
    .hub
    .call(
      server,
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
      Some(p) if managed(world, &p) => {}
      Some(p) => projects.entry(p).or_default().push(c),
      None => out.push(Unmanaged {
        server: server.to_string(),
        ignored: false,
        project: None,
        container: Some(c.name.clone()),
        name: import::service_name(&c.name),
        containers: vec![c],
      }),
    }
  }
  for (p, containers) in projects {
    out.push(Unmanaged {
      server: server.to_string(),
      ignored: false,
      name: import::service_name(&p),
      project: Some(p),
      container: None,
      containers,
    });
  }
  out.sort_by(|a, b| a.name.cmp(&b.name));
  Ok(out)
}

pub async fn preview(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  axum::Extension(audit): axum::Extension<crate::audit::AuditSlot>,
  Json(req): Json<ImportRequest>,
) -> ApiResult<ImportPreview> {
  if req.commit_secrets {
    auth.require(Perm::Admin)?;
    if !req.extract_secrets || auth.services.is_some() {
      return Err(
        ApiError::new(
          ErrorCode::Forbidden,
          "转存密钥需要完整管理权限",
        )
        .into(),
      );
    }
  }
  let (kind, raw_name) = target(&req.project, &req.container)?;
  let snap = snapshot::load(&s.db).await?;
  crate::host_access::require_with(
    &auth,
    crate::host_access::HostTarget::ImportPreview {
      server: &req.server,
      target: raw_name,
    },
    snap.world.servers.get(&req.server).map(|r| &r.settings),
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if !snap.world.servers.contains_key(&req.server) {
    return Err(server_not_found(&req.server).into());
  }
  if kind == "project" && managed(&snap.world, raw_name) {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        format!(
          "项目 {raw_name} 属于 Wharf 管理，不能作为未纳管容器导入"
        ),
      )
      .into(),
    );
  }
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
  if !discover(&s, &snap.world, &req.server).await?.iter().any(
    |item| {
      crate::service_monitor::unmanaged::target(item)
        == (kind, raw_name)
    },
  ) {
    return Err(
      ApiError::not_found(
        "没找到这个未纳管容器或项目，可能已被 Wharf 纳管或已删除",
      )
      .with_hint(
        "先执行 wharf server unmanaged <服务器> 查看可导入列表",
      )
      .into(),
    );
  }
  s.hub.require_safe_adopt(&req.server)?;
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
      import::from_compose(&config, &raw.containers, p, &name)?
    }
    (None, _, Some(inspect)) => import::from_container(
      &inspect,
      raw.image_inspect.as_ref(),
      raw.tag_image_id.as_deref(),
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
  if raw.config_files.len() > 1 || !raw.env_files.is_empty() {
    warnings.insert(
      0,
      format!(
        "已合并读取 compose 文件：{}；env 文件：{}",
        raw.config_files.join("、"),
        raw.env_files.join("、")
      ),
    );
  }
  warnings.extend(converted.warnings);
  let (compose, extracted_secrets) = if req.extract_secrets {
    let (compose, mut items, values) =
      import::extract_secrets_from_compose(
        &converted.compose,
        &name,
        req.secret_prefix.as_deref(),
      )?;
    let summary = crate::secret_import::write(&s, values, req.secret_conflict, None, !req.commit_secrets).await
      .map_err(|mut e| {
        if e.code == ErrorCode::Conflict {
          e.hint = Some("加 --only-missing-secrets 保留已有密钥、--overwrite-secrets 覆盖，或用 --secret-prefix 换前缀".into());
        }
        e
      })?;
    for item in &mut items {
      item.action = summary.action(&item.secret_name).into();
    }
    if req.commit_secrets {
      audit.set_detail(format!(
        "import_extract_secrets service={name} {}",
        summary.audit()
      ));
    }
    if !req.commit_secrets {
      audit.skip_record();
    }
    (compose, items)
  } else {
    let (compose, keys) =
      crate::redact::redact_compose_secrets(&converted.compose);
    if compose.is_empty() {
      return Err(
        ApiError::invalid("无法生成脱敏后的导入预览").into(),
      );
    }
    if !keys.is_empty() {
      warnings.push(format!("以下变量疑似包含口令，预览已脱敏：{}。可加 --extract-secrets 自动转存进密钥库", keys.join("、")));
    }
    (compose, Vec::new())
  };
  Ok(Json(ImportPreview {
    spec: ServiceSpec {
      server: req.server,
      source: Source::Compose {
        content: Some(compose),
        file: None,
      },
      ports: converted.ports,
      env: Default::default(),
      volumes: vec![],
      backup: None,
      stopped: converted.stopped,
      monitor: None,
      start_timeout_secs: None,
      log_alerts: vec![],
      port_checks: Default::default(),
      heartbeat: None,
      limits: None,
      auto_update: false,
      update_ignore: vec![],
      container: None,
      files: vec![],
      stop_grace_secs: None,
      stop_signal: None,
      init_cmd: None,
      init_timeout_secs: None,
      lan: None,
      extra_hosts: Default::default(),
      self_refs: false,
    },
    adopt: converted.adopt,
    extracted_secrets,
    secrets_committed: req.commit_secrets,
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

fn require_remove(
  auth: &Auth,
  server: &str,
  target: &str,
  settings: Option<&wharf_api_types::spec::ServerSettings>,
  core_server: Option<&str>,
) -> Result<(), crate::api::AppError> {
  crate::host_access::require_with(
    auth,
    crate::host_access::HostTarget::RemoveUnmanaged {
      server,
      target,
    },
    settings,
    core_server,
  )?;
  auth.require(Perm::Confirm)
}

/// `POST /api/servers/{name}/unmanaged/remove`：删掉一个没纳管的容器或 compose 项目的全部容器。
/// 只认现在仍然没纳管的，Wharf 自己的服务、网关不会被删。
pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
  Json(req): Json<RemoveRequest>,
) -> ApiResult<wharf_api_types::agent::RemovedContainers> {
  let (kind, name) = target(&req.project, &req.container)?;
  let snap = snapshot::load(&s.db).await?;
  require_remove(
    &auth,
    &server,
    name,
    snap.world.servers.get(&server).map(|r| &r.settings),
    crate::join::core_server_of(&snap).as_deref(),
  )?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  if kind == "project" && managed(&snap.world, name) {
    return Err(
      ApiError::invalid(format!(
        "{name} 是 Wharf 管理的，不能在这里删"
      ))
      .into(),
    );
  }

  let found = discover(&s, &snap.world, &server).await?;
  let names = found
    .into_iter()
    .find(|item| {
      crate::service_monitor::unmanaged::target(item) == (kind, name)
    })
    .ok_or_else(|| {
      ApiError::not_found("没找到这个未纳管容器，可能已经删掉了")
    })?
    .containers
    .into_iter()
    .map(|c| c.name)
    .collect();
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

fn target<'a>(
  project: &'a Option<String>,
  container: &'a Option<String>,
) -> Result<(&'static str, &'a str), ApiError> {
  match (project.as_deref(), container.as_deref()) {
    (Some(p), None) if !p.is_empty() => Ok(("project", p)),
    (None, Some(c)) if !c.is_empty() => Ok(("container", c)),
    _ => Err(ApiError::invalid("project 和 container 二选一")),
  }
}

#[derive(serde::Deserialize)]
pub struct IgnoreRequest {
  project: Option<String>,
  container: Option<String>,
  #[serde(default)]
  undo: bool,
}

pub async fn ignore(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(server): Path<String>,
  Json(req): Json<IgnoreRequest>,
) -> ApiResult<serde_json::Value> {
  auth.require(Perm::Apply)?;
  let (kind, name) = target(&req.project, &req.container)?;
  let snap = snapshot::load(&s.db).await?;
  if !snap.world.servers.contains_key(&server) {
    return Err(server_not_found(&server).into());
  }
  if !req.undo
    && !discover(&s, &snap.world, &server)
      .await?
      .iter()
      .any(|item| {
        crate::service_monitor::unmanaged::target(item)
          == (kind, name)
      })
  {
    return Err(ApiError::not_found("没找到这个未纳管容器").into());
  }
  crate::service_monitor::unmanaged::set_ignored(
    &s,
    server,
    kind,
    name.to_string(),
    req.undo,
  )
  .await?;
  Ok(Json(serde_json::json!({ "ignored": !req.undo })))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::host_access::tests::auth;
  use wharf_api_types::ErrorCode;

  #[test]
  fn remove_unmanaged_requires_host_confirm_and_docker_switch() {
    use wharf_api_types::spec::ServerSettings;

    let check = |perms: &[Perm], host_docker| {
      require_remove(
        &auth(perms.iter().copied(), false),
        "s1",
        "foreign",
        Some(&ServerSettings {
          host_docker,
          ..Default::default()
        }),
        Some("core"),
      )
    };
    for (perms, enabled, reason) in [
      (&[Perm::Confirm][..], true, "host 权限"),
      (&[Perm::Host][..], true, "confirm 权限"),
      (&[Perm::Host, Perm::Confirm][..], false, "host_docker"),
    ] {
      let err = check(perms, enabled).unwrap_err().0;
      assert_eq!(err.code, ErrorCode::Forbidden);
      assert!(err.message.contains(reason));
    }
    assert!(check(&[Perm::Host, Perm::Confirm], true).is_ok());
    assert!(managed(&World::default(), "wharf-tailscale"));
  }
}
