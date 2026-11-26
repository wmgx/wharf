/// 计划时的产物指纹和现在渲染的不一致：说明计划之后有东西变了，
/// 现在下发的和用户看过的不一样，重新 plan 再确认。
pub(crate) fn check_expect(
  expect: Option<&str>,
  current: &str,
  what: &str,
) -> Result<(), ApiError> {
  let Some(expect) = expect else {
    // 旧计划没有指纹，照常执行。
    return Ok(());
  };
  if expect == current {
    return Ok(());
  }
  Err(
    ApiError::new(
      ErrorCode::PlanStale,
      format!(
        "{what} 的配置在 plan 之后变了，现在下发的会和计划里看过的不一样"
      ),
    )
    .with_hint("重新 plan，确认新的差异后再 apply")
    .suggest("wharf plan"),
  )
}

/// 失败只记日志：状态显示不全不影响执行本身。
async fn record_op(
  state: &AppState,
  service: &str,
  action: &str,
  run_id: &str,
  status: OpStatus,
  error: Option<String>,
) {
  let service = service.to_string();
  let op = LastOp {
    action: action.to_string(),
    run_id: run_id.to_string(),
    status,
    at: Utc::now(),
    error,
  };
  let result = state
    .db
    .call(move |c| db::set_service_op(c, &service, &op))
    .await;
  if let Err(e) = result {
    tracing::warn!("记录服务操作失败：{e}");
  }
}

pub(crate) async fn run_step(
  state: &AppState,
  run_id: &str,
  step: &Step,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let mut snap = snapshot::load(&state.db).await?;
  if matches!(step, Step::LinkUp { .. } | Step::GatewaySync { .. }) {
    snap.reach =
      crate::link::probe(state, &snap.net(&snap.world), &snap.world)
        .await;
  }
  let world = &snap.world;
  let net = snap.net(world);
  match step {
    Step::EnsureDirs { server, dirs } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::EnsureDirs { dirs: dirs.clone() },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::VolumeSync { service, from, to } => {
      crate::migrate::volume_sync(
        state, &net, service, from, to, progress, cancel,
      )
      .await?;
    }
    Step::Backup { service } => {
      crate::backup::backup(state, run_id, service, progress, cancel)
        .await?;
    }
    Step::Restore { service, snapshot } => {
      crate::backup::restore(
        state, service, snapshot, progress, cancel,
      )
      .await?;
    }
    Step::ServiceUp { service, expect } => {
      service_up(
        state,
        run_id,
        &snap,
        service,
        false,
        expect.as_deref(),
        progress,
        cancel,
      )
      .await?;
    }
    Step::Rebuild { service } => {
      service_up(
        state, run_id, &snap, service, true, None, progress, cancel,
      )
      .await?;
    }
    Step::AgentUpgrade { server } => {
      crate::agent_upgrade::upgrade(state, server, progress, cancel)
        .await?;
    }
    Step::AgentUpgrades { servers } => {
      crate::agent_upgrade::upgrade_each(
        state, servers, progress, cancel,
      )
      .await?;
    }
    Step::ServiceStop { service } => {
      let server = service_server(&snap, service)?;
      project_stop_start(
        state, &server, service, false, &progress, cancel,
      )
      .await?;
    }
    Step::ServiceRestart { service } => {
      let server = service_server(&snap, service)?;
      project_stop_start(
        state, &server, service, false, &progress, cancel,
      )
      .await?;
      project_stop_start(
        state, &server, service, true, &progress, cancel,
      )
      .await?;
    }
    Step::CoreBackup { user_key } => {
      crate::core_backup::backup(
        state,
        run_id,
        user_key.as_ref(),
        progress,
        cancel,
      )
      .await?;
    }
    Step::DockerProxy { server } => {
      let settings = &world
        .servers
        .get(server)
        .ok_or_else(|| crate::world::server_not_found(server))?
        .settings;
      crate::docker_proxy::apply(
        state, server, settings, progress, cancel,
      )
      .await?;
    }
    Step::Baseline { server } => {
      let baseline = &world
        .servers
        .get(server)
        .ok_or_else(|| crate::world::server_not_found(server))?
        .settings
        .baseline;
      crate::baseline::apply(
        state, server, baseline, progress, cancel,
      )
      .await?;
    }
    Step::Egress { server } => {
      crate::egress::apply(state, server, cancel).await?;
    }
    Step::Prune { server } => {
      crate::prune::prune(state, server, progress, cancel).await?;
    }
    Step::EdgeDeploy { app } => {
      let key = crate::edge_plan::deployed_key(app);
      let fingerprint = world
        .edge_apps
        .get(app)
        .map(|a| crate::edge_plan::fingerprint(app, &a.spec));
      let k = key.clone();
      state
        .db
        .call(move |c| {
          db::set_setting(c, &k, Some(crate::edge_plan::DEPLOYING))
        })
        .await?;
      crate::edge::deploy(state, &snap, app, &progress, cancel)
        .await?;
      state
        .db
        .call(move |c| {
          db::set_setting(c, &key, fingerprint.as_deref())
        })
        .await?;
    }
    Step::EdgeAttach {
      hostname,
      app,
      takeover,
    } => {
      crate::edge::attach_domain(
        state, &snap, hostname, app, *takeover,
      )
      .await?;
    }
    Step::EdgeDetach { domain } => {
      crate::edge::detach_domain(state, &snap, domain).await?;
    }
    Step::EdgeRollback { app, version } => {
      crate::edge::rollback(state, &snap, app, version, &progress)
        .await?;
    }
    Step::ServiceDown {
      server,
      service,
      purge_data,
    } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: service.clone(),
            purge: *purge_data,
          },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::GatewaySync { gateway, expect } => {
      let gw = world.gateways.get(gateway).ok_or_else(|| {
        ApiError::new(
          ErrorCode::PlanStale,
          format!("网关 {gateway} 已不存在"),
        )
      })?;
      if gw.spec.kind == GatewayKind::CloudflareTunnel {
        return crate::tunnel::sync(
          state, &snap, gateway, progress, cancel,
        )
        .await;
      }
      let server = &gw.spec.server;
      let r = snapshot::gateway_render(world, &net, gateway)?;
      check_expect(
        expect.as_deref(),
        &r.fingerprint(),
        &format!("网关 {gateway}"),
      )?;
      let r =
        gateway::caddyfile_for_apply(state, world, &net, gateway, r)
          .await?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::GatewayApply(GatewayApply {
            up: ProjectUp {
              project: gateway_project(gateway),
              compose: r.compose,
              hash: r.compose_hash,
              pull: snapshot::pull_policy(&world.servers[server]),
              pull_missing_only: false,
              retire: None,
              rollback: false,
              pins: Default::default(),
              trial: None,
            },
            caddyfile: r.config,
            caddyfile_hash: r.config_hash,
            extra_files: r.extra_files,
            image: render::gateway_image(&gw.spec),
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        &format!("网关 {gateway}"),
        &format!("wharf gateway logs {gateway}"),
      )?;
    }
    Step::LinkUp { server, project } => {
      let p = crate::link::projects(world, &net)?
        .into_iter()
        .find(|p| &p.server == server && &p.project == project)
        .ok_or_else(|| {
          ApiError::new(
            ErrorCode::PlanStale,
            format!("{server} 上已经不需要 {project}"),
          )
          .suggest("wharf plan")
        })?;
      let gateway_server = &world.gateways[&p.gateway].spec.server;
      crate::link_cert::require_gateway_agent(
        &state.hub,
        gateway_server,
        &p.gateway,
      )?;
      let gateway = p.gateway;
      let client = project != crate::link::SERVER_PROJECT;
      let (token, ca) = state
        .db
        .call_credentials({
          let gateway = gateway.clone();
          move |c, key| {
            let now = db::now_ms();
            let tx = c.transaction().map_err(db::sql_err)?;
            let token = db::ensure_scoped_secret(
              &tx,
              key,
              crate::link::TOKEN_PREFIX,
              &gateway,
              now,
            )?;
            let ca = if client {
              Some(crate::link_cert::ensure_ca(&tx, key, now)?.cert)
            } else {
              None
            };
            tx.commit().map_err(db::sql_err)?;
            Ok((token, ca))
          }
        })
        .await?;
      let mut secrets = snap.secrets.clone();
      secrets.insert(
        format!("{}{gateway}", crate::link::TOKEN_PREFIX),
        token,
      );
      if let Some(ca) = ca {
        secrets.insert(crate::link::CA_CERT_SECRET.into(), ca);
      }
      let p =
        crate::link::projects_with_secrets(world, &net, &secrets)?
          .into_iter()
          .find(|p| &p.server == server && &p.project == project)
          .ok_or_else(|| ApiError::internal("反向隧道配置丢失"))?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::ProjectUp(ProjectUp {
            project: project.clone(),
            compose: p.compose,
            hash: p.hash,
            pull: snapshot::pull_policy(&world.servers[server]),
            pull_missing_only: false,
            retire: None,
            rollback: false,
            pins: Default::default(),
            trial: None,
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        &format!("反向隧道 {project}"),
        &format!(
          "在 {server} 上 docker logs {project}-{}-1",
          if project == crate::link::SERVER_PROJECT {
            "frps"
          } else {
            "frpc"
          }
        ),
      )?;
    }
    Step::TailscaleUp { server } => {
      let compose =
        crate::tailscale::deploy_compose(state, server).await?;
      let result: ProjectUpResult = state
        .hub
        .call(
          server,
          AgentOp::ProjectUp(ProjectUp {
            project: crate::tailscale::PROJECT.to_string(),
            compose,
            hash: crate::tailscale::hash(server),
            pull: snapshot::pull_policy(&world.servers[server]),
            pull_missing_only: false,
            retire: None,
            rollback: false,
            pins: Default::default(),
            trial: None,
          }),
          GATEWAY_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
      ensure_running(
        &result,
        "Tailscale",
        &format!(
          "在 {server} 上 docker logs {}-tailscale-1",
          crate::tailscale::PROJECT
        ),
      )?;
    }
    Step::LinkDown { server, project } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: project.clone(),
            purge: false,
          },
          SHORT_TIMEOUT,
          Some(progress),
          cancel,
        )
        .await?;
    }
    Step::GatewayDown { server, gateway } => {
      state
        .hub
        .call::<serde_json::Value>(
          server,
          AgentOp::ProjectDown {
            project: gateway_project(gateway),
            purge: false,
          },
          SHORT_TIMEOUT,
          Some(progress.clone()),
          cancel,
        )
        .await?;
      // cloudflare_tunnel 网关：连接器停了之后删除它的隧道。
      crate::tunnel::destroy(
        state, &snap, gateway, &progress, cancel,
      )
      .await?;
    }
    Step::DnsUpsert {
      hostname,
      account,
      spec,
      existing,
      extra,
    } => {
      let owner_id = world.dns_owner(hostname).ok_or_else(|| {
        ApiError::new(
          ErrorCode::PlanStale,
          format!("域名 {hostname} 已经没有路由或边缘应用使用"),
        )
      })?;
      let account_row = find_account(&snap, account)?;
      let provider = snapshot::dns_provider(account_row)?;
      let owner = Owner { id: owner_id };
      let spec = match &spec.tunnel {
        Some(gateway) => {
          let t = snap.tunnels.get(gateway).ok_or_else(|| {
            ApiError::new(
              ErrorCode::PlanStale,
              format!("网关 {gateway} 的隧道还没有创建"),
            )
            .suggest("wharf plan")
          })?;
          crate::planner::DnsSpec {
            content: crate::planner::tunnel_target(&t.tunnel_id),
            ..spec.clone()
          }
        }
        None => spec.clone(),
      };
      let want = spec.to_provider();
      let existing_record = existing.as_ref().map(|r| RemoteRecord {
        remote_id: r.remote_id.clone(),
        scope: r.scope.clone(),
        canonical: serde_json::Value::Null,
        marker: None,
      });
      progress(format!(
        "{hostname} → {} {}",
        spec.record_type, spec.content
      ));
      let record = cancellable(
        cancel,
        snapshot::with_timeout(
          "写入 DNS 记录",
          provider.upsert(
            hostname,
            &want,
            &owner,
            existing_record.as_ref(),
          ),
        ),
      )
      .await?;
      add_owned(
        state,
        &owner.id,
        hostname,
        account,
        &record.scope,
        &record.remote_id,
      )
      .await?;
      for r in extra {
        progress(format!("删除多余的记录 {}", r.remote_id));
        cancellable(
          cancel,
          snapshot::with_timeout(
            "删除 DNS 记录",
            provider.delete(&r.scope, &r.remote_id, None),
          ),
        )
        .await?;
        remove_owned(state, account, r).await?;
      }
    }
    Step::DnsDelete {
      hostname,
      account,
      remote,
      owner,
    } => {
      let account_row = find_account(&snap, account)?;
      let provider = snapshot::dns_provider(account_row)?;
      let owner = owner.as_ref().map(|id| Owner { id: id.clone() });
      progress(format!(
        "删除 {hostname} 的记录 {}",
        remote.remote_id
      ));
      cancellable(
        cancel,
        snapshot::with_timeout(
          "删除 DNS 记录",
          provider.delete(
            &remote.scope,
            &remote.remote_id,
            owner.as_ref(),
          ),
        ),
      )
      .await?;
      remove_owned(state, account, remote).await?;
    }
  }
  Ok(())
}

fn ensure_running(
  result: &ProjectUpResult,
  what: &str,
  logs: &str,
) -> Result<(), ApiError> {
  let bad: Vec<String> = result
    .containers
    .iter()
    .filter(|c| c.state != "running")
    .map(|c| format!("{} {}（{}）", c.service, c.state, c.status))
    .collect();
  if result.containers.is_empty() {
    return Err(ApiError::new(
      ErrorCode::AgentFailed,
      format!("{what} 启动后没有容器"),
    ));
  }
  if !bad.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::AgentFailed,
        format!("{what} 有容器没在运行：{}", bad.join("，")),
      )
      .suggest(logs),
    );
  }
  Ok(())
}

pub(crate) async fn cancellable<T>(
  cancel: &CancellationToken,
  fut: impl std::future::Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
  tokio::select! {
    r = fut => r,
    _ = cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "已取消")),
  }
}

fn find_account<'a>(
  snap: &'a snapshot::Snapshot,
  name: &str,
) -> Result<&'a db::AccountRow, ApiError> {
  snap
    .accounts
    .iter()
    .find(|a| a.name == name)
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::PlanStale,
        format!("厂商账号 {name} 已不存在"),
      )
    })
}

async fn add_owned(
  state: &AppState,
  route_id: &str,
  hostname: &str,
  account: &str,
  scope: &str,
  remote_id: &str,
) -> Result<(), ApiError> {
  let record = OwnedRecord {
    route_id: route_id.to_string(),
    hostname: hostname.to_string(),
    account: account.to_string(),
    scope: scope.to_string(),
    remote_id: remote_id.to_string(),
  };
  state.db.call(move |c| db::add_owned(c, &record)).await
}

async fn remove_owned(
  state: &AppState,
  account: &str,
  r: &RemoteRef,
) -> Result<(), ApiError> {
  let (account, scope, id) =
    (account.to_string(), r.scope.clone(), r.remote_id.clone());
  state
    .db
    .call(move |c| db::remove_owned(c, &account, &scope, &id))
    .await
}
