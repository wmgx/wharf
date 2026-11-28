use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{
    AgentOp, ContainerMount, DirSpaceInfo, SYNC_READY, ServiceCopy,
    SyncKind, SyncPass, SyncPush, SyncServe,
  },
  plan::{PlannedServiceAction, ServiceActionKind},
  spec::Change,
};

use super::*;
use crate::{hub::ProgressFn, migrate};

const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(4 * 3600);

pub(crate) struct CloneRequest {
  pub source: String,
  pub target: String,
  pub server: Option<String>,
  pub copy_data: bool,
  pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CloneJob {
  pub source: String,
  pub source_instance: String,
  pub source_server: String,
  pub target: String,
  pub target_instance: String,
  pub target_server: String,
  pub receipt: String,
  copy_data: bool,
  reserve_dir: bool,
  write: Write,
}

#[derive(Deserialize)]
struct CopyState {
  committed: bool,
}

fn occupied() -> ApiError {
  ApiError::new(ErrorCode::Conflict, "克隆目标已存在")
    .with_hint("换一个名称")
}

fn unsupported(reason: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("无法安全克隆：{reason}"),
  )
  .with_hint(
    "先用 service adopt-data 收编外部挂载，或另行准备外部依赖",
  )
}

pub(crate) async fn plan(
  state: &AppState,
  snap: Snapshot,
  allowed: Option<&BTreeSet<String>>,
  admin: bool,
  req: CloneRequest,
) -> Result<Planned, ApiError> {
  let CloneRequest {
    source,
    target,
    server,
    copy_data,
    note,
  } = req;
  if allowed.is_some_and(|names| {
    !names.contains(&source) || !names.contains(&target)
  }) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "克隆需要同时拥有源和目标服务权限",
    ));
  }
  wharf_api_types::validate_name("服务", &target)?;
  let current = &snap.world;
  if current.services.contains_key(&target)
    || snap.pending.clones.contains(&target)
    || snap
      .pending
      .service_deletes
      .iter()
      .any(|p| p.service == target)
    || snap.deployed.contains_key(&target)
  {
    return Err(occupied());
  }
  let row = current
    .services
    .get(&source)
    .ok_or_else(|| crate::api::service_not_found(&source))?;
  let from = &row.spec.server;
  let to = server.as_deref().unwrap_or(from);
  let mount_count = validate_source(&snap, &source, to, copy_data)?;
  if !current.servers.contains_key(to) {
    return Err(crate::world::server_not_found(to));
  }
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let src_conn = state.hub.service_copy_conn_id(from)?;
  let dst_conn = state.hub.service_copy_conn_id(to)?;
  inspect_source(
    state,
    &snap,
    (&source, from, src_conn),
    copy_data,
    &cancel,
  )
  .await?;
  copy_rpc(
    state,
    (to, dst_conn),
    ServiceCopy::Check {
      target: target.clone(),
    },
    CHECK_TIMEOUT,
    None,
    &cancel,
  )
  .await?;
  if copy_data {
    check_capacity(
      state,
      (&source, from, src_conn),
      (&target, to, dst_conn),
      &cancel,
    )
    .await?;
    if from != to {
      cross_machine(state, &snap, from, to)?;
    }
  }
  let mut spec = row.spec.clone();
  spec.server = to.into();
  spec.stopped = true;
  spec.backup = None;
  spec.crash_guard = false;
  spec.auto_update = false;
  spec.heartbeat = None;
  spec.monitor = None;
  spec.log_alerts.clear();
  spec.port_checks.clear();
  if let Source::Compose {
    content: Some(content),
    ..
  } = &mut spec.source
  {
    *content =
      crate::data::rewrite_clone_mounts(content, &source, &target)?;
  }
  let mut desired = current.clone();
  desired.apply_changes(&[Change::UpsertService {
    name: target.clone(),
    spec,
    adopt: None,
    pins: Some(row.pins.clone()),
    commit: row.commit.clone(),
    migrate: None,
  }])?;
  desired
    .allocate_ports_with(&retiring_ports(&snap, current, &desired))?;
  crate::secret_policy::validate_restrictions(
    &desired,
    &snap.secret_restrictions,
  )?;
  crate::secret_policy::validate_accounts(
    &desired,
    &snap.account_links,
  )?;
  crate::secret_policy::require_plan_git_secrets(
    current, &desired, admin,
  )?;
  crate::missing_refs::check_plan(&desired, &snap)?;
  desired.validate_against(current)?;
  crate::link::validate_new_admin_port_bindings(current, &desired)?;
  let net = snap.net(&desired);
  let values = snap.render_values(&desired, &target);
  let expect =
    snapshot::service_hash(&desired, &net, &target, &values, None)?;
  crate::syntax_check::validate_service_files(
    &desired,
    &net,
    &target,
    &values,
    &snap.log_values,
  )?;
  let writes = desired.writes_from(current);
  let [write] = writes.as_slice() else {
    return Err(unsupported("分配目标配置会改变其他资源"));
  };
  let job = CloneJob {
    source: source.clone(),
    source_instance: row.instance_id.clone(),
    source_server: from.clone(),
    target: target.clone(),
    target_instance: desired.services[&target].instance_id.clone(),
    target_server: to.into(),
    receipt: new_id("copy").replace('_', "-"),
    copy_data,
    reserve_dir: mount_count > 0,
    write: write.clone(),
  };
  let mut b = Builder::default();
  config_items(&mut b, current, &desired, &writes);
  let title = if copy_data {
    "复制托管目录"
  } else {
    "核实目标空闲"
  };
  let id = b.item(
    format!("service/{target}"),
    Layer::Volume,
    Action::Create,
    Some(json!({"service":source,"server":from})),
    Some(json!({"service":target,"server":to})),
    vec![],
    title,
  );
  b.step(
    vec![id],
    format!("{title}，登记停止的 {target}"),
    Step::CloneData { job: Box::new(job) },
  );
  let dirs =
    crate::data::mounts(&target, &desired.services[&target].spec)
      .into_iter()
      .map(|mount| mount.source)
      .collect::<Vec<_>>();
  if !dirs.is_empty() {
    b.step(
      vec![id],
      format!("准备 {target} 的数据目录"),
      Step::EnsureDirs {
        server: to.into(),
        dirs,
        after_sync: true,
      },
    );
  }
  let id = b.item(
    format!("service/{target}"),
    Layer::Container,
    Action::Create,
    None,
    None,
    vec![],
    "准备停止的服务",
  );
  b.step(
    vec![id],
    format!("准备 {to} 上的 {target}（停止）"),
    Step::ServiceUp {
      service: target.clone(),
      instance_id: Some(
        desired.services[&target].instance_id.clone(),
      ),
      expect: Some(expect),
    },
  );
  b.warnings.push("确认外部依赖后再显式启动新服务".into());
  state.hub.require_safe_migrate(to)?;
  build_agent_warnings(state, &desired, &mut b)?;
  let mut planned = finish_plan(
    &snap,
    &desired,
    b,
    vec![],
    crate::render::service_account_refs(current),
    note.as_deref(),
  );
  if copy_data {
    let address = format!("service/{target}");
    planned.plan.needs_confirm.push(address.clone());
    if let Some(suggest) = planned.plan.suggest.first_mut() {
      suggest.push_str(&format!(" --confirm {address}"));
    }
  }
  planned.plan.service_action = Some(PlannedServiceAction {
    action: ServiceActionKind::Clone,
    tag: None,
    targets: vec![source, target],
  });
  Ok(planned)
}

pub(super) fn validate_source(
  snap: &Snapshot,
  source: &str,
  target_server: &str,
  copy: bool,
) -> Result<usize, ApiError> {
  crate::crash_guard::require_idle(snap, source)?;
  let row = &snap.world.services[source];
  let spec = &row.spec;
  if moved_from(snap, &snap.world, source, &spec.server).is_some()
    || snap.pending.migrations.contains_key(source)
    || snap.pending.adopt_data.contains_key(source)
    || row.import.is_some()
  {
    return Err(unsupported("源服务仍有未完成的运维操作"));
  }
  if copy && !spec.stopped {
    return Err(
      ApiError::new(ErrorCode::Conflict, "源服务仍在运行")
        .with_hint("先用 wharf service stop 停止源服务"),
    );
  }
  if let Source::Build(build) = &spec.source
    && (build.git.is_some() && row.commit.is_none()
      || build.git.is_none() && build.upload.is_none())
  {
    return Err(unsupported("源构建版本无法重建"));
  }
  let mounts = crate::data::mounts(source, spec);
  if mounts.iter().any(|mount| {
    mount.kind != DataKind::Managed
      || !mount.source.starts_with(&format!("/srv/{source}/"))
  }) {
    return Err(unsupported("存在外部、共享或非托管挂载"));
  }
  if copy && mounts.is_empty() {
    return Err(
      ApiError::invalid("源服务没有托管数据")
        .with_hint("省略 --copy-data 克隆配置"),
    );
  }
  if let Source::Compose { content, .. } = &spec.source {
    let doc = crate::render::parse_compose_template(
      content.as_deref().unwrap_or_default(),
    )?;
    let components = doc
      .get("services")
      .and_then(serde_yaml_ng::Value::as_mapping)
      .ok_or_else(|| unsupported("无法解析 Compose 组件"))?;
    if doc.get("include").is_some()
      || components.values().any(|component| {
        [
          "extends",
          "container_name",
          "external_links",
          "volumes_from",
          "build",
          "env_file",
        ]
        .iter()
        .any(|key| component.get(*key).is_some())
          || component
            .get("volumes")
            .and_then(serde_yaml_ng::Value::as_sequence)
            .is_some_and(|volumes| {
              volumes
                .iter()
                .any(|v| v.as_str().is_some_and(|v| !v.contains(':')))
            })
      })
      || !crate::host_access::compose_host_reasons(
        source,
        content.as_deref().unwrap_or_default(),
      )
      .is_empty()
    {
      return Err(unsupported(
        "Compose 包含无法验证的宿主资源或固定容器名",
      ));
    }
  }
  if target_server == spec.server
    && spec.ports.iter().any(|port| port.host.is_some())
  {
    return Err(unsupported("同机克隆和源服务的固定宿主端口冲突"));
  }
  Ok(mounts.len())
}

pub(super) async fn inspect_source(
  state: &AppState,
  snap: &Snapshot,
  (name, server, conn): (&str, &str, u64),
  copy: bool,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let statuses: Vec<ProjectState> = state
    .hub
    .call_bound(
      (server, conn),
      AgentOp::ProjectStatus {
        projects: vec![name.into()],
        include_links: false,
      },
      CHECK_TIMEOUT,
      None,
      cancel,
    )
    .await?;
  let project = statuses
    .iter()
    .find(|p| p.project == name)
    .ok_or_else(|| unsupported("无法核实源项目"))?;
  if project
    .containers
    .iter()
    .any(|c| c.foreign || (copy && c.is_active()))
  {
    return Err(unsupported("源服务仍在运行或项目归属无法核实"));
  }
  let actual: BTreeMap<String, Vec<ContainerMount>> = state
    .hub
    .call_bound(
      (server, conn),
      AgentOp::ProjectMounts {
        projects: vec![name.into()],
      },
      CHECK_TIMEOUT,
      None,
      cancel,
    )
    .await?;
  if let Some(used) = actual.get(name) {
    let declared =
      crate::data::mounts(name, &snap.world.services[name].spec);
    if !crate::data::undeclared_mounts(name, &declared, used)
      .is_empty()
      || used.iter().any(|m| {
        m.kind == "volume"
          || (m.kind == "bind"
            && declared.iter().any(|d| d.target == m.target)
            && !declared
              .iter()
              .any(|d| d.target == m.target && d.source == m.source))
      })
    {
      return Err(unsupported("源服务存在未托管挂载"));
    }
  } else if !project.containers.is_empty() {
    return Err(unsupported("无法核实源服务挂载"));
  }
  if copy {
    migrate::check_writers(
      state,
      (server, conn),
      name,
      false,
      cancel,
    )
    .await?;
  }
  Ok(())
}

async fn copy_rpc(
  state: &AppState,
  server: (&str, u64),
  job: ServiceCopy,
  timeout: Duration,
  progress: Option<ProgressFn>,
  cancel: &CancellationToken,
) -> Result<CopyState, ApiError> {
  state
    .hub
    .call_bound(
      server,
      AgentOp::ServiceCopy(job),
      timeout,
      progress,
      cancel,
    )
    .await
}

async fn check_capacity(
  state: &AppState,
  (source, from, source_conn): (&str, &str, u64),
  (target, to, target_conn): (&str, &str, u64),
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let query = |name: String, server, measure_data| {
    state.hub.call_bound::<DirSpaceInfo>(
      server,
      AgentOp::DirSpace {
        service: name,
        measure_data,
      },
      CHECK_TIMEOUT,
      None,
      cancel,
    )
  };
  let (source, target) = tokio::try_join!(
    query(source.into(), (from, source_conn), true),
    query(target.into(), (to, target_conn), false),
  )?;
  migrate::check_migration_disk(
    to,
    source
      .data_bytes
      .ok_or_else(|| unsupported("源数据容量未知"))?,
    0,
    target.fs_avail_bytes,
    target.fs_total_bytes,
  )
}

fn cross_machine(
  state: &AppState,
  snap: &Snapshot,
  from: &str,
  to: &str,
) -> Result<(), ApiError> {
  state.hub.require_migrate_v2(from)?;
  state.hub.require_migrate_v2(to)?;
  let net = snap.net(&snap.world);
  migrate::private_ip(&net, from)?;
  migrate::private_ip(&net, to)?;
  if net.reach.get(&(from.into(), to.into())) == Some(&false) {
    return Err(unsupported("两台机器的内网不通"));
  }
  Ok(())
}

async fn transfer(
  state: &AppState,
  snap: &Snapshot,
  job: &CloneJob,
  (from, to): ((&str, u64), (&str, u64)),
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let net = snap.net(&snap.world);
  let source_ip = migrate::private_ip(&net, from.0)?;
  let target_ip = migrate::private_ip(&net, to.0)?;
  let password = migrate::one_time_password();
  let limits = [from.0, to.0].map(|server| {
    snap
      .world
      .servers
      .get(server)
      .and_then(|row| row.settings.bg_bwlimit_kbps())
  });
  let bwlimit_kbps =
    wharf_api_types::resources::effective_bwlimit_kbps(None, &limits);
  let stop = cancel.child_token();
  let _stop = stop.clone().drop_guard();
  let (sender, receiver) = tokio::sync::oneshot::channel::<u16>();
  let sender = std::sync::Mutex::new(Some(sender));
  let forward = progress.clone();
  let ready: ProgressFn = std::sync::Arc::new(move |line| {
    if let Some(port) =
      line.strip_prefix(SYNC_READY).and_then(|p| p.parse().ok())
    {
      if let Some(sender) =
        sender.lock().unwrap_or_else(|p| p.into_inner()).take()
      {
        let _ = sender.send(port);
      }
    } else {
      forward(line);
    }
  });
  let serve = state.hub.call_bound::<Value>(
    to,
    AgentOp::SyncServe(SyncServe {
      service: job.receipt.clone(),
      bind: target_ip.clone(),
      allow: source_ip,
      password: password.clone(),
      preserve_existing: false,
      require_empty: false,
      kind: SyncKind::CloneData,
    }),
    TRANSFER_TIMEOUT,
    Some(ready),
    &stop,
  );
  let push = async {
    let port = tokio::time::timeout(CHECK_TIMEOUT, receiver)
      .await
      .map_err(|_| {
        ApiError::new(ErrorCode::Timeout, "复制接收端没有就绪")
      })?
      .map_err(|_| {
        ApiError::new(ErrorCode::AgentFailed, "复制接收端已关闭")
      })?;
    let result: Value = state
      .hub
      .call_bound(
        from,
        AgentOp::SyncPush(SyncPush {
          service: job.source.clone(),
          host: target_ip,
          port,
          password,
          pass: SyncPass::Final,
          kind: SyncKind::CloneSource,
          bwlimit_kbps,
        }),
        TRANSFER_TIMEOUT,
        Some(progress.clone()),
        &stop,
      )
      .await?;
    if result.get("synced").and_then(Value::as_bool) != Some(true) {
      return Err(ApiError::new(
        ErrorCode::AgentFailed,
        "源数据没有完成传输",
      ));
    }
    Ok(())
  };
  tokio::pin!(serve, push);
  tokio::select! {
    result = &mut serve => result.and_then(|_| Err(ApiError::new(ErrorCode::AgentFailed,"复制接收端提前退出"))),
    result = &mut push => {
      stop.cancel();
      let _ = serve.await;
      result
    }
  }
}

pub(crate) async fn execute(
  state: &AppState,
  snap: &Snapshot,
  run_id: &str,
  job: &CloneJob,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  if let Some(target) = snap.world.services.get(&job.target) {
    return if target.instance_id == job.target_instance {
      Ok(())
    } else {
      Err(occupied())
    };
  }
  if !snap.pending.clones.contains(&job.target)
    || snap.world.services.get(&job.source).is_none_or(|r| {
      r.instance_id != job.source_instance
        || r.spec.server != job.source_server
    })
  {
    return Err(
      ApiError::new(ErrorCode::PlanStale, "克隆源或目标实例发生变化")
        .with_hint("重新执行原命令生成计划"),
    );
  }
  validate_source(
    snap,
    &job.source,
    &job.target_server,
    job.copy_data,
  )?;
  let from = (
    job.source_server.as_str(),
    state.hub.service_copy_conn_id(&job.source_server)?,
  );
  let to = (
    job.target_server.as_str(),
    state.hub.service_copy_conn_id(&job.target_server)?,
  );
  inspect_source(
    state,
    snap,
    (&job.source, from.0, from.1),
    job.copy_data,
    cancel,
  )
  .await?;
  if job.copy_data && from.0 != to.0 {
    cross_machine(state, snap, from.0, to.0)?;
  }
  if job.reserve_dir {
    let start = copy_rpc(
      state,
      to,
      ServiceCopy::Stage {
        target: job.target.clone(),
        receipt: job.receipt.clone(),
      },
      CHECK_TIMEOUT,
      None,
      cancel,
    )
    .await?;
    if !start.committed {
      if job.copy_data {
        check_capacity(
          state,
          (&job.source, from.0, from.1),
          (&job.target, to.0, to.1),
          cancel,
        )
        .await?;
        if from.0 == to.0 {
          copy_rpc(
            state,
            to,
            ServiceCopy::Local {
              source: job.source.clone(),
              target: job.target.clone(),
              receipt: job.receipt.clone(),
            },
            TRANSFER_TIMEOUT,
            Some(progress.clone()),
            cancel,
          )
          .await?;
        } else {
          transfer(state, snap, job, (from, to), &progress, cancel)
            .await?;
        }
        inspect_source(
          state,
          snap,
          (&job.source, from.0, from.1),
          true,
          cancel,
        )
        .await?;
      }
      let commit = copy_rpc(
        state,
        to,
        ServiceCopy::Commit {
          target: job.target.clone(),
          receipt: job.receipt.clone(),
        },
        CHECK_TIMEOUT,
        None,
        cancel,
      )
      .await?;
      if !commit.committed {
        return Err(ApiError::new(
          ErrorCode::AgentFailed,
          "未确认目标目录已提交",
        ));
      }
    }
  } else {
    copy_rpc(
      state,
      to,
      ServiceCopy::Check {
        target: job.target.clone(),
      },
      CHECK_TIMEOUT,
      None,
      cancel,
    )
    .await?;
  }
  let job = job.clone();
  let id = run_id.to_owned();
  let run = crate::apply::load_run(state, run_id).await?;
  let plan = crate::apply::load_plan(state, &run.plan_id).await?;
  let name = job.target.clone();
  state.db.call_credentials(move |c,key| {
    crate::apply::record_retry_changes(c,key,&id, |tx| {
      let receipt: Option<String> = tx.query_row(
        "SELECT payload FROM pending_steps WHERE kind='clone_data' AND target_key=?1 AND instance_id=?2",
        rusqlite::params![job.target,job.target_instance], |row| row.get(0),
      ).optional().map_err(db::sql_err)?;
      if receipt != Some(serde_json::to_string(&job.receipt).map_err(db::json_err)?) {
        return Err(occupied());
      }
      crate::pending::clear(tx,"clone_data",&job.target)?;
      let effects = crate::apply::apply_writes(tx,&plan,&[job.write],true)?;
      effects.clear_storage(tx)?;
      Ok(())
    })
  }).await?;
  progress(format!("已登记 {name}，保持停止"));
  Ok(())
}
