use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{AgentOp, ProjectUp, ProjectUpResult, ServiceCopy},
  plan::{PlannedServiceAction, ServiceActionKind},
  view::TaskKind,
};

use super::*;
use crate::hub::ProgressFn;

const CHECK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RenameJob {
  pub source: String,
  pub target: String,
  pub server: String,
  pub instance: String,
  pub receipt: String,
  pub services: Vec<String>,
  before_hash: String,
  expected_hash: String,
  has_data: bool,
}
impl RenameJob {
  pub(crate) fn is_retiring(
    &self,
    c: &rusqlite::Connection,
  ) -> Result<bool, ApiError> {
    c.query_row("SELECT EXISTS(SELECT 1 FROM pending_steps WHERE kind='clone_data' AND target_key=?1 AND instance_id=?2 AND payload=?3)
      AND NOT EXISTS(SELECT 1 FROM resources WHERE kind='service' AND name=?1)",
      rusqlite::params![self.source, self.instance, serde_json::to_string(&self.receipt).map_err(db::json_err)?],
      |row| row.get(0),
    ).map_err(db::sql_err)
  }
}

fn reject(reason: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("无法安全改名：{reason}"),
  )
  .with_hint("处理列出的关系，或先克隆后手动切换")
}
pub(crate) async fn plan(
  state: &AppState,
  snap: Snapshot,
  source: String,
  target: String,
  note: Option<&str>,
) -> Result<Planned, ApiError> {
  let row = snap
    .world
    .services
    .get(&source)
    .ok_or_else(|| crate::api::service_not_found(&source))?;
  let applied = snap
    .applied
    .get(&source)
    .ok_or_else(|| reject("源服务尚未部署"))?;
  let mounts = config_checks(&snap, &source, &target)?;
  if crate::pins::images(&row.spec.source).iter().any(|image| {
    !row.pins.contains_key(image)
      && !applied.image_ids.contains_key(image)
  }) {
    return Err(reject("已应用镜像版本无法核实"));
  }
  let desired = candidate(&snap, &source, &target)?;
  let net = snap.net(&desired);
  let expected_hash = snapshot::service_hash(
    &desired,
    &net,
    &target,
    &snap.render_values(&desired, &target),
    None,
  )?;
  let cancel = CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  check_storage(state, &snap, &source, &target, &cancel).await?;
  let conn = state.hub.service_copy_conn_id(&row.spec.server)?;
  if row.spec.uses_runtime_options() {
    state.hub.runtime_options_conn_id(&row.spec.server)?;
  }
  require_stopped(
    state,
    (&row.spec.server, conn),
    &source,
    &applied.hash,
    &cancel,
  )
  .await?;
  service_clone::inspect_source(
    state,
    &snap,
    (&source, &row.spec.server, conn),
    true,
    &cancel,
  )
  .await?;
  copy(
    state,
    (&row.spec.server, conn),
    ServiceCopy::Check {
      target: target.clone(),
    },
    CHECK,
    None,
    &cancel,
  )
  .await?;

  let mut b = Builder::default();
  let mut services = vec![source.clone()];
  for (kind, name, before, after) in
    changed_config(&snap.world, &desired, &source, &target)
  {
    if kind == KIND_SERVICE {
      services.push(name.clone());
    }
    b.item(
      format!("{kind}/{name}"),
      Layer::Config,
      Action::Update,
      before,
      after,
      vec![],
      "改名并保留实例",
    );
  }
  let archive_id = Utc::now().format("%Y%m%d-%H%M%S").to_string();
  let job = RenameJob {
    source: source.clone(),
    target: target.clone(),
    server: row.spec.server.clone(),
    instance: row.instance_id.clone(),
    receipt: format!("rename-{archive_id}"),
    before_hash: applied.hash.clone(),
    expected_hash,
    services,
    has_data: mounts > 0,
  };
  let id = b.item(
    format!("service/{source}"),
    Layer::Container,
    Action::Update,
    None,
    None,
    vec![Impact::Downtime],
    "新项目保持停止，旧项目拆除并归档托管数据",
  );
  b.step(
    vec![id],
    format!("将 {source} 改名为 {target}"),
    Step::RenameService { job: Box::new(job) },
  );
  let mut plan = finish_plan(
    &snap,
    &desired,
    b,
    vec![],
    crate::render::service_account_refs(&snap.world),
    note,
  );
  let address = format!("service/{source}");
  plan.plan.needs_confirm.push(address.clone());
  if let Some(suggest) = plan.plan.suggest.first_mut() {
    suggest.push_str(&format!(" --confirm {address}"));
  }
  plan.plan.service_action = Some(PlannedServiceAction {
    action: ServiceActionKind::Rename,
    tag: None,
    targets: vec![source, target],
  });
  Ok(plan)
}
fn config_checks(
  snap: &Snapshot,
  from: &str,
  to: &str,
) -> Result<usize, ApiError> {
  wharf_api_types::validate_name("服务", to)?;
  if to.starts_with(wharf_api_types::agent::TASK_DATA_PREFIX)
    || to.starts_with(wharf_api_types::agent::TRIAL_PROJECT_PREFIX)
  {
    return Err(reject("目标名称使用保留前缀"));
  }
  if snap.world.services.contains_key(to)
    || snap.pending.clones.contains(to)
    || snap.deployed.contains_key(to)
    || snap
      .pending
      .service_deletes
      .iter()
      .any(|delete| delete.service == to || delete.service == from)
  {
    return Err(reject("目标名称正在使用或保留"));
  }
  let row = &snap.world.services[from];
  if !row.spec.stopped
    || !matches!(
      row.spec.source,
      Source::Image(_) | Source::Compose { .. }
    )
  {
    return Err(reject("仅支持已停止且来源可验证的服务"));
  }
  if row.spec.compose_env
    || row.spec.use_egress
    || !row.spec.networks.is_empty()
    || crate::project_files::needs_agent(&row.spec)
  {
    return Err(reject(
      "存在项目变量、专用网络或需单独下发的文件和卷配置",
    ));
  }
  if row.spec.backup.is_some()
    || snap.pending.backup_moves.contains_key(from)
    || snap.pending.backup_moves.contains_key(to)
    || row.spec.heartbeat.is_some()
    || snap
      .account_links
      .iter()
      .any(|(service, _)| service == from || service == to)
  {
    return Err(reject("存在备份、心跳或账号绑定"));
  }
  if snap.world.services.values().any(|row| {
    crate::shared_volumes::owners(&row.spec)
      .any(|owner| owner == from || owner == to)
  }) || snap.world.gateways.values().any(|row| {
    row.spec.layer4.iter().any(|forward| {
      forward
        .service
        .as_deref()
        .is_some_and(|name| name == from || name == to)
    })
  }) || snap.world.routes.values().any(|row| {
    let spec = &row.spec;
    let related = spec.service == from
      || spec
        .paths
        .iter()
        .any(|path| path.service.as_deref() == Some(from));
    related
      && (spec.caddy.is_some()
        || spec.caddy_file.is_some()
        || spec.sso.is_some())
  }) || snap
    .secret_restrictions
    .values()
    .any(|services| services.contains(to))
  {
    return Err(reject(
      "存在共享卷、四层入口、自定义入口或目标密钥权限",
    ));
  }
  service_clone::validate_source(snap, from, "", false)
}
fn candidate(
  snap: &Snapshot,
  from: &str,
  to: &str,
) -> Result<World, ApiError> {
  let mut desired = snap.world.clone();
  let mut row = desired
    .services
    .remove(from)
    .ok_or_else(|| reject("源服务已不存在"))?;
  if let Source::Compose {
    content: Some(content),
    ..
  } = &mut row.spec.source
  {
    *content = crate::data::rewrite_clone_mounts(content, from, to)?;
  }
  desired.services.insert(to.into(), row);
  for row in desired.services.values_mut() {
    for value in row
      .spec
      .env
      .values_mut()
      .chain(row.spec.files.iter_mut().map(|file| &mut file.content))
      .chain(row.spec.init_cmd.iter_mut())
    {
      crate::refs::rename_in(value, from, to);
    }
    if let Source::Compose {
      content: Some(content),
      ..
    } = &mut row.spec.source
    {
      crate::refs::rename_in(content, from, to);
    }
  }
  for row in desired.routes.values_mut() {
    if row.spec.service == from {
      row.spec.service = to.into();
    }
    for path in &mut row.spec.paths {
      if path.service.as_deref() == Some(from) {
        path.service = Some(to.into());
      }
    }
  }
  let mut restrictions = snap.secret_restrictions.clone();
  for services in restrictions.values_mut() {
    if services.remove(from) {
      services.insert(to.into());
    }
  }
  desired.validate_against(&snap.world)?;
  crate::missing_refs::check_plan(&desired, snap)?;
  crate::secret_policy::validate_restrictions(
    &desired,
    &restrictions,
  )?;
  crate::secret_policy::validate_accounts(
    &desired,
    &snap.account_links,
  )?;
  let before = snap.net(&snap.world);
  let after = snap.net(&desired);
  for (name, row) in &snap.world.services {
    if name == from || row.spec == desired.services[name].spec {
      continue;
    }
    let old = snapshot::service_hash(
      &snap.world,
      &before,
      name,
      &snap.render_values(&snap.world, name),
      None,
    )?;
    let new = snapshot::service_hash(
      &desired,
      &after,
      name,
      &snap.render_values(&desired, name),
      None,
    )?;
    if old != new {
      return Err(reject("有关联服务需要重部署"));
    }
  }
  for gateway in desired.gateways.keys() {
    let old =
      snapshot::gateway_render(&snap.world, &before, gateway)?;
    let new = snapshot::gateway_render(&desired, &after, gateway)?;
    if old.fingerprint() != new.fingerprint() {
      return Err(reject("入口配置需要重新下发"));
    }
  }
  let links = |world, net| -> Result<BTreeMap<_, _>, ApiError> {
    Ok(
      crate::link::projects(world, net)?
        .into_iter()
        .map(|p| ((p.project, p.server), p.hash))
        .collect(),
    )
  };
  if links(&snap.world, &before)? != links(&desired, &after)? {
    return Err(reject("需要重建网关链路"));
  }
  Ok(desired)
}
type ConfigItem =
  (&'static str, String, Option<Value>, Option<Value>);
fn changed_config(
  current: &World,
  desired: &World,
  from: &str,
  to: &str,
) -> Vec<ConfigItem> {
  let mut changes = vec![(
    KIND_SERVICE,
    to.into(),
    spec_json(current, KIND_SERVICE, from),
    spec_json(desired, KIND_SERVICE, to),
  )];
  for (name, row) in &desired.services {
    if name != to && current.services[name].spec != row.spec {
      changes.push((
        KIND_SERVICE,
        name.clone(),
        spec_json(current, KIND_SERVICE, name),
        spec_json(desired, KIND_SERVICE, name),
      ));
    }
  }
  for (name, row) in &desired.routes {
    if current.routes[name].spec != row.spec {
      changes.push((
        KIND_ROUTE,
        name.clone(),
        spec_json(current, KIND_ROUTE, name),
        spec_json(desired, KIND_ROUTE, name),
      ));
    }
  }
  changes
}
fn inspect_db(
  c: &rusqlite::Connection,
  from: &str,
  to: &str,
) -> Result<(), ApiError> {
  let key = db::scoped_secret_name(crate::backup::KEY_PREFIX, from)?;
  let target_key =
    db::scoped_secret_name(crate::backup::KEY_PREFIX, to)?;
  let blocked: bool = c.query_row(
    "SELECT
      EXISTS(SELECT 1 FROM settings WHERE
        substr(key, 1, length('backup_move.arrived.' || ?1 || '@')) = 'backup_move.arrived.' || ?1 || '@' OR
        substr(key, 1, length('backup_move.arrived.' || ?2 || '@')) = 'backup_move.arrived.' || ?2 || '@') OR
      EXISTS(SELECT 1 FROM backups WHERE service IN (?1,?2)) OR
      EXISTS(SELECT 1 FROM cleanups WHERE service IN (?1,?2)) OR
      EXISTS(SELECT 1 FROM api_tokens, json_each(api_tokens.services) WHERE json_each.value IN (?1,?2)) OR
      EXISTS(SELECT 1 FROM alert_service_overrides WHERE service=?2) OR
      EXISTS(SELECT 1 FROM alert_custom_rules WHERE service=?2) OR
      EXISTS(SELECT 1 FROM secret_allowed_services WHERE service=?2) OR
      EXISTS(SELECT 1 FROM secrets WHERE name IN (?3,?4))",
    rusqlite::params![from,to,key,target_key], |row| row.get(0),
  ).map_err(db::sql_err)?;
  if blocked {
    return Err(reject(
      "存在备份记录、待清理数据、服务令牌或目标已绑定告警或密钥",
    ));
  }
  for (_, task, _) in crate::tasks::load_rows(c)? {
    if matches!(&task.how, TaskKind::Exec {service,..} if service==from || service==to)
      || crate::refs::used(
        &serde_json::to_string(&task).map_err(db::json_err)?,
      )
      .iter()
      .any(|service| service == from || service == to)
    {
      return Err(reject("存在任务绑定"));
    }
  }
  Ok(())
}
async fn check_storage(
  state: &AppState,
  snap: &Snapshot,
  from: &str,
  to: &str,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let (source, target) = (from.to_owned(), to.to_owned());
  state
    .db
    .call(move |c| inspect_db(c, &source, &target))
    .await?;
  for server in snap.world.servers.keys() {
    let conn = state
      .hub
      .service_copy_conn_id(server)
      .map_err(|_| reject("无法核实所有机器的备份仓库"))?;
    for service in [from, to] {
      copy(
        state,
        (server, conn),
        ServiceCopy::CheckBackup {
          service: service.into(),
        },
        CHECK,
        None,
        cancel,
      )
      .await?;
    }
  }
  Ok(())
}
async fn status(
  state: &AppState,
  server: (&str, u64),
  name: &str,
  cancel: &CancellationToken,
) -> Result<ProjectState, ApiError> {
  let response: Vec<ProjectState> = state
    .hub
    .call_bound(
      server,
      AgentOp::ProjectStatus {
        projects: vec![name.into()],
        include_links: false,
      },
      CHECK,
      None,
      cancel,
    )
    .await?;
  response
    .into_iter()
    .find(|p| p.project == name)
    .ok_or_else(|| reject("无法核实真实项目状态"))
}
async fn require_stopped(
  state: &AppState,
  server: (&str, u64),
  name: &str,
  expected: &str,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let live = status(state, server, name, cancel).await?;
  if live.hash.as_deref() != Some(expected)
    || live.containers.is_empty()
    || live.containers.iter().any(|c| c.foreign || c.is_active())
  {
    return Err(reject("源项目未确认停止，或应用指纹与历史不符"));
  }
  Ok(())
}
async fn copy(
  state: &AppState,
  server: (&str, u64),
  op: ServiceCopy,
  timeout: Duration,
  progress: Option<ProgressFn>,
  cancel: &CancellationToken,
) -> Result<bool, ApiError> {
  let value: Value = state
    .hub
    .call_bound(
      server,
      AgentOp::ServiceCopy(op),
      timeout,
      progress,
      cancel,
    )
    .await?;
  Ok(
    value
      .get("committed")
      .and_then(Value::as_bool)
      .unwrap_or(false),
  )
}
pub(crate) async fn execute(
  state: &AppState,
  snap: &Snapshot,
  run_id: &str,
  job: &RenameJob,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let server = (
    job.server.as_str(),
    state.hub.service_copy_conn_id(&job.server)?,
  );
  let retiring = state
    .db
    .call({
      let job = job.clone();
      move |c| job.is_retiring(c)
    })
    .await?;
  if retiring {
    return retire(state, server, job, &progress, cancel)
      .await
      .map_err(|error| {
        error.with_hint("已改名，旧项目待清理；重试原执行")
      });
  }
  if snap
    .world
    .services
    .get(&job.target)
    .is_some_and(|r| r.instance_id == job.instance)
    && !snap.world.services.contains_key(&job.source)
    && !snap.pending.clones.contains(&job.target)
  {
    return Ok(());
  }
  if !snap.pending.clones.contains(&job.target)
    || !snap.world.services.get(&job.source).is_some_and(|r| {
      r.instance_id == job.instance
        && r.spec.server == job.server
        && r.spec.stopped
    })
  {
    return Err(reject("源或目标实例已变化"));
  }
  require_stopped(
    state,
    server,
    &job.source,
    &job.before_hash,
    cancel,
  )
  .await?;
  check_storage(state, snap, &job.source, &job.target, cancel)
    .await?;
  let desired = candidate(snap, &job.source, &job.target)?;
  let row = &desired.services[&job.target];
  let net = snap.net(&desired);
  let (compose, hash) = snapshot::service_resolved(
    &desired,
    &net,
    &job.target,
    &snap.render_values(&desired, &job.target),
  )?;
  if hash != job.expected_hash {
    return Err(
      ApiError::new(ErrorCode::PlanStale, "改名后项目指纹已变化")
        .with_hint("重新执行原命令生成计划"),
    );
  }
  let target = status(state, server, &job.target, cancel).await?;
  let already_created = target.hash.as_deref() == Some(hash.as_str())
    && !target.containers.is_empty()
    && target
      .containers
      .iter()
      .all(|c| !c.foreign && !c.is_active());
  let images = if already_created {
    Vec::new()
  } else {
    if !target.containers.is_empty() || target.hash.is_some() {
      return Err(reject("目标出现无法核实的容器"));
    }
    if job.has_data {
      let params = (&job.target, &job.receipt);
      let staged = copy(
        state,
        server,
        ServiceCopy::Stage {
          target: params.0.clone(),
          receipt: params.1.clone(),
        },
        CHECK,
        None,
        cancel,
      )
      .await?;
      if !staged {
        service_clone::inspect_source(
          state,
          snap,
          (&job.source, server.0, server.1),
          true,
          cancel,
        )
        .await?;
        copy(
          state,
          server,
          ServiceCopy::Local {
            source: job.source.clone(),
            target: params.0.clone(),
            receipt: params.1.clone(),
          },
          Duration::from_secs(4 * 3600),
          Some(progress.clone()),
          cancel,
        )
        .await?;
        copy(
          state,
          server,
          ServiceCopy::Commit {
            target: params.0.clone(),
            receipt: params.1.clone(),
          },
          CHECK,
          None,
          cancel,
        )
        .await?;
      }
    } else {
      copy(
        state,
        server,
        ServiceCopy::Check {
          target: job.target.clone(),
        },
        CHECK,
        None,
        cancel,
      )
      .await?;
    }
    let images = if row.spec.pull_policy.is_some() {
      crate::pins::select_explicit_images(
        state, snap, row, server.1, cancel,
      )
      .await?
    } else {
      Default::default()
    };
    let mut pins = row.pins.clone();
    pins.extend(images.pins);
    let result: ProjectUpResult = state
      .hub
      .call_bound(
        server,
        AgentOp::ProjectUp(ProjectUp {
          image_pull_mode: row.spec.pull_policy,
          local_images: images.local,
          project: job.target.clone(),
          compose,
          hash: hash.clone(),
          pull: snapshot::pull_policy(&desired.servers[server.0]),
          pull_missing_only: false,
          retire: None,
          rollback: false,
          pins,
          expected_images: snap.applied[&job.source]
            .image_ids
            .clone(),
          no_start: true,
          networks: Default::default(),
          project_env: None,
          host_binds: Vec::new(),
          volume_owners: Default::default(),
          project_files: Vec::new(),
          refresh_files_from: None,
          workload_egress: false,
          trial: None,
          init: None,
          start_timeout_secs: None,
          readiness: None,
        }),
        Duration::from_secs(70 * 60),
        Some(progress.clone()),
        cancel,
      )
      .await?;
    require_stopped(state, server, &job.target, &hash, cancel)
      .await?;
    result.images
  };
  let template =
    snapshot::service_template(&desired, &net, &job.target)?;
  let template = crate::log_redact::redact_text(&template);
  let writes = desired.writes_from(&snap.world);
  let job_db = job.clone();
  let run = run_id.to_owned();
  let captured = run.clone();
  state
    .db
    .call_credentials(move |c, key| {
      crate::apply::record_retry_changes(c, key, &captured, |tx| {
        switch_name(tx, &job_db, &run, writes, &images, &template)
      })
    })
    .await?;
  crate::rules::rename_service_cache(&job.source, &job.target);
  progress(format!("已改名为 {}，正在清理旧项目", job.target));
  retire(state, server, job, &progress, cancel)
    .await
    .map_err(|e| e.with_hint("已改名，旧项目待清理；重试原执行"))
}
fn switch_name(
  tx: &rusqlite::Transaction<'_>,
  job: &RenameJob,
  run: &str,
  writes: Vec<Write>,
  images: &[wharf_api_types::agent::ImageInfo],
  template: &str,
) -> Result<(), ApiError> {
  inspect_db(tx, &job.source, &job.target)?;
  let reservation = tx.execute("UPDATE pending_steps SET target_key=?2 WHERE kind='clone_data' AND target_key=?1 AND instance_id=?3 AND payload=?4",
    rusqlite::params![job.target,job.source,job.instance,serde_json::to_string(&job.receipt).map_err(db::json_err)?]).map_err(db::sql_err)?;
  if reservation != 1 {
    return Err(reject("目标名称保留已失效"));
  }
  let changed = tx.execute("UPDATE resources SET name=?2 WHERE kind='service' AND name=?1 AND json_extract(meta,'$.instance_id')=?3",
    rusqlite::params![job.source,job.target,job.instance]).map_err(db::sql_err)?;
  if changed != 1 {
    return Err(reject("源实例已变化"));
  }
  tx.execute(
    "UPDATE secret_allowed_services SET service=?2 WHERE service=?1",
    rusqlite::params![job.source, job.target],
  )
  .map_err(db::sql_err)?;
  tx.execute("UPDATE deployments SET service=?2, original_service=COALESCE(original_service,?1) WHERE service=?1 AND instance_id=?3",
    rusqlite::params![job.source,job.target,job.instance]).map_err(db::sql_err)?;
  tx.execute(
    "UPDATE alert_service_overrides SET service=?2 WHERE service=?1",
    rusqlite::params![job.source, job.target],
  )
  .map_err(db::sql_err)?;
  tx.execute(
    "UPDATE alert_custom_rules SET service=?2 WHERE service=?1",
    rusqlite::params![job.source, job.target],
  )
  .map_err(db::sql_err)?;
  let mut applied_spec = None;
  for write in writes {
    if matches!(&write,Write::Delete {kind,name} if kind==KIND_SERVICE && name==&job.source)
    {
      continue;
    }
    if let Write::Upsert {
      kind, name, spec, ..
    } = &write
      && kind == KIND_SERVICE
      && name == &job.target
    {
      applied_spec = Some(spec.to_string());
    }
    db::apply_write(tx, &write)?;
  }
  let images = serde_json::to_string(images).map_err(db::json_err)?;
  tx.execute("INSERT INTO deployments(service,server,run_id,hash,compose,images,created_at,spec,instance_id,started)
      VALUES (?1,?2,?3,?4,?5,CASE WHEN ?6='[]' THEN COALESCE((SELECT images FROM deployments WHERE service=?1 AND instance_id=?9 ORDER BY id DESC LIMIT 1),'[]') ELSE ?6 END,?7,?8,?9,0)",
    rusqlite::params![job.target,job.server,run,job.expected_hash,template,images,db::now_ms(),applied_spec,job.instance],
  ).map_err(db::sql_err)?;
  Ok(())
}
async fn retire(
  state: &AppState,
  server: (&str, u64),
  job: &RenameJob,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let live = status(state, server, &job.source, cancel).await?;
  if live.containers.iter().any(|c| c.is_active() || c.foreign)
    || live
      .hash
      .as_ref()
      .is_some_and(|hash| hash != &job.before_hash)
  {
    return Err(reject("旧项目归属不明或再次运行"));
  }
  if live.hash.is_some() || !live.containers.is_empty() {
    state
      .hub
      .call_bound::<Value>(
        server,
        AgentOp::ProjectDown {
          project: job.source.clone(),
          purge: false,
        },
        Duration::from_secs(10 * 60),
        Some(progress.clone()),
        cancel,
      )
      .await?;
  }
  if job.has_data {
    copy(
      state,
      server,
      ServiceCopy::Archive {
        service: job.source.clone(),
        receipt: job.receipt.clone(),
      },
      CHECK,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  }
  if !job.has_data {
    copy(
      state,
      server,
      ServiceCopy::Check {
        target: job.source.clone(),
      },
      CHECK,
      None,
      cancel,
    )
    .await?;
  }
  let (source, instance, receipt) = (
    job.source.clone(),
    job.instance.clone(),
    job.receipt.clone(),
  );
  state
    .db
    .call(move |c| {
      c.execute("DELETE FROM pending_steps WHERE kind='clone_data' AND target_key=?1 AND instance_id=?2 AND payload=?3",
        rusqlite::params![source, instance, serde_json::to_string(&receipt).map_err(db::json_err)?]).map_err(db::sql_err)?;
      Ok(())
    })
    .await?;
  progress(format!("旧项目 {} 已拆除，数据保留", job.source));
  Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn rename_switch_releases_new_name_and_keeps_old_name_until_archive()
 {
  use std::sync::atomic::{AtomicBool, Ordering};
  use wharf_api_types::spec::Change;

  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    c.execute("INSERT INTO resources VALUES ('server','s1','{}','{}',1,0,0)", []).map_err(db::sql_err)?;
    c.execute("INSERT INTO resources VALUES ('service','old',?1,?2,1,0,0)", [
      json!({"server":"s1","source":{"image":"alpine"},"stopped":true,"volumes":[{"name":"data","target":"/data"}]}).to_string(),
      json!({"instance_id":"svc_old","pins":{"alpine":format!("sha256:{}", "a".repeat(64))}}).to_string(),
    ]).map_err(db::sql_err)?;
    c.execute("INSERT INTO pending_steps (kind,target_key,run_id,plan_id,instance_id,payload,updated_at)
      VALUES ('clone_data','new','run','plan','svc_old','\"rename-receipt\"',0)", []).map_err(db::sql_err)?;
    c.execute("INSERT INTO alert_service_overrides (rule,service,muted_until) VALUES ('oom_killed','old',42)", []).map_err(db::sql_err)?;
    c.execute("INSERT INTO alert_custom_rules (name,service,metric,op,threshold,for_n,muted_until,created_at)
      VALUES ('fixture','old','svc.mem','gt',100,1,42,0)", []).map_err(db::sql_err)?;
    Ok(())
  }).await.unwrap();
  let snap = snapshot::load(&state.db).await.unwrap();
  let mut desired = snap.world.clone();
  let row = desired.services.remove("old").unwrap();
  desired.services.insert("new".into(), row);
  let (compose, hash) = snapshot::service_resolved(
    &desired,
    &snap.net(&desired),
    "new",
    &BTreeMap::new(),
  )
  .unwrap();
  let job = RenameJob {
    source: "old".into(),
    target: "new".into(),
    server: "s1".into(),
    instance: "svc_old".into(),
    receipt: "rename-receipt".into(),
    services: vec!["old".into()],
    before_hash: "before".into(),
    expected_hash: hash.clone(),
    has_data: true,
  };
  let writes = desired.writes_from(&snap.world);
  state
    .db
    .call({
      let job = job.clone();
      move |c| {
        let tx = c.transaction().map_err(db::sql_err)?;
        switch_name(&tx, &job, "run", writes, &[], &compose)?;
        let silence: (String, i64) = tx
          .query_row(
            "SELECT service,muted_until FROM alert_service_overrides",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
          )
          .map_err(db::sql_err)?;
        assert_eq!(silence, ("new".into(), 42));
        let custom: (String, i64) = tx
          .query_row(
            "SELECT service,muted_until FROM alert_custom_rules",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
          )
          .map_err(db::sql_err)?;
        assert_eq!(custom, ("new".into(), 42));
        tx.commit().map_err(db::sql_err)?;
        Ok(())
      }
    })
    .await
    .unwrap();
  let fail_archive = AtomicBool::new(true);
  state.hub.mock_safe_migrate_agent("s1", move |op, _| Some(match op {
    AgentOp::ProjectStatus { projects, .. } => Ok(json!(projects.iter().map(|p| if p == "new" {
      json!({"project":p,"hash": hash,"containers":[{"service":"new","name":"new-1","state":"exited"}]})
    } else {
      json!({"project":p,"containers":[]})
    }).collect::<Vec<_>>())),
    AgentOp::ResolveImages(_) => Ok(json!([{"image":"alpine","digest":format!("sha256:{}", "a".repeat(64))}])),
    AgentOp::ServiceCopy(ServiceCopy::Archive { .. }) if fail_archive.swap(false, Ordering::Relaxed) => Err(ApiError::internal("归档失败")),
    AgentOp::ServiceCopy(ServiceCopy::Archive { .. }) => Ok(json!({"committed":true})),
    _ => panic!("不应改动目标项目"),
  }));
  state.hub.enable_mock_service_copy("s1");
  let conn = state.hub.service_copy_conn_id("s1").unwrap();
  let cancel = CancellationToken::new();
  let progress: ProgressFn = std::sync::Arc::new(|_| {});
  assert!(
    retire(&state, ("s1", conn), &job, &progress, &cancel)
      .await
      .is_err()
  );

  let snap = snapshot::load(&state.db).await.unwrap();
  assert_eq!(snap.pending.clones, BTreeSet::from(["old".into()]));
  assert_eq!(snap.world.services["new"].instance_id, job.instance);
  let recreate = PlanRequest {
    changes: vec![Change::UpsertService {
      no_defaults: false,
      name: "old".into(),
      spec: snap.world.services["new"].spec.clone(),
      adopt: None,
      pins: None,
      commit: None,
      migrate: None,
    }],
    ..Default::default()
  };
  let err =
    make_plan_inner(&state, recreate.clone(), snap, false, true)
      .await
      .err()
      .unwrap();
  assert_eq!(err.code, ErrorCode::Conflict);
  let plan = make_plan(&state, PlanRequest::default()).await.unwrap();
  assert!(plan.steps.is_empty());

  let plan = make_plan_inner(
    &state,
    PlanRequest {
      changes: vec![Change::UpsertService {
        no_defaults: false,
        name: "new".into(),
        spec: {
          let mut spec = desired.services["new"].spec.clone();
          spec.stopped = false;
          spec
        },
        adopt: None,
        pins: None,
        commit: None,
        migrate: None,
      }],
      ..Default::default()
    },
    snapshot::load(&state.db).await.unwrap(),
    false,
    true,
  )
  .await
  .unwrap();
  assert!(plan.steps.iter().any(|s| matches!(&s.step, Step::ServiceStart { service, .. } if service == "new")));

  let snap = snapshot::load(&state.db).await.unwrap();
  execute(&state, &snap, "run", &job, progress, &cancel)
    .await
    .unwrap();
  let snap = snapshot::load(&state.db).await.unwrap();
  assert!(snap.pending.clones.is_empty());
  let plan = make_plan_inner(&state, recreate, snap, false, true)
    .await
    .unwrap();
  assert!(plan.writes.iter().any(|write| matches!(write, Write::Upsert { name, meta, .. }
    if name == "old" && meta["instance_id"].as_str().is_some_and(|id| id != job.instance))));
  assert!(
    plan
      .steps
      .iter()
      .any(|step| matches!(&step.step, Step::EnsureDirs {dirs, ..}
    if dirs == &["/srv/old/data"]))
  );
}

#[cfg(test)]
#[tokio::test]
async fn rename_rejects_completed_backup_move_for_either_name() {
  let db = db::Db::memory();
  db.call(|c| {
    db::set_setting(
      c,
      "backup_move.arrived.old-other@s1",
      Some("run"),
    )?;
    inspect_db(c, "old", "new")?;
    db::set_setting(c, "backup_move.arrived.new@s1", Some("run"))?;
    assert_eq!(
      inspect_db(c, "old", "new").unwrap_err().code,
      ErrorCode::Conflict
    );
    assert_eq!(
      inspect_db(c, "new", "other").unwrap_err().code,
      ErrorCode::Conflict
    );
    Ok(())
  })
  .await
  .unwrap();
}
