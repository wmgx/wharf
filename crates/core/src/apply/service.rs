/// 一次成功部署的内容，写进部署历史。
/// 部署一个服务：构建来源先构建镜像（`force` 时重新构建），再 `up`。
#[allow(clippy::too_many_arguments)]
async fn service_up(
  state: &AppState,
  run_id: &str,
  snap: &snapshot::Snapshot,
  service: &str,
  force: bool,
  expect: Option<&str>,
  progress: ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let world = &snap.world;
  let net = snap.net(world);
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::new(
      ErrorCode::PlanStale,
      format!("服务 {service} 已不存在"),
    )
  })?;
  let server = &row.spec.server;
  let (compose, hash) = snapshot::service_resolved(
    world,
    &net,
    service,
    &snap.render_values(world, service),
  )?;
  // 先比对指纹再构建：计划过期时不用白构建一次。
  check_expect(expect, &hash, &format!("服务 {service}"))?;
  let commit = crate::build::ensure_image(
    state, snap, service, force, &progress, cancel,
  )
  .await?;
  let template = snapshot::service_template(world, &net, service)?;
  // 导入的服务：agent 拉好镜像后停掉原来的容器，启动失败时由 agent 恢复。
  let retire = row
    .import
    .as_ref()
    .filter(|a| a.project.is_some() || !a.containers.is_empty())
    .map(|a| Retire {
      service: service.to_string(),
      project: a.project.clone(),
      containers: a.containers.clone(),
    });
  // 刚导入时本机已有的镜像不拉取，避免拉到新版本而重建容器。
  let pull_missing_only =
    row.import.is_some() && !has_deployment(state, service).await?;
  // 起不来时自动换回上一版：只对没有数据的服务做，新版本可能已经改了数据，
  // 旧版本不一定认。compose 来源看不出有没有数据，不做。
  let rollback = row.spec.volumes.is_empty()
    && retire.is_none()
    && !matches!(row.spec.source, Source::Compose { .. });
  // 先试跑再替换：和自动换回上一版的条件一样，另外要已经部署过、不是要保持停止的。
  let trial = if rollback
    && !row.spec.stopped
    && has_deployment(state, service).await?
    && !world
      .services
      .contains_key(&format!("{TRIAL_PROJECT_PREFIX}{service}"))
  {
    Some(snapshot::service_trial(
      world,
      &net,
      service,
      &snap.render_values(world, service),
    )?)
  } else {
    None
  };
  let result: ProjectUpResult = state
    .hub
    .call(
      server,
      AgentOp::ProjectUp(ProjectUp {
        project: service.to_string(),
        compose,
        hash: hash.clone(),
        pull: snapshot::pull_policy(&world.servers[server]),
        pull_missing_only,
        retire,
        rollback,
        pins: row.pins.clone(),
        trial,
      }),
      SERVICE_UP_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  let retired = result.retired.clone();
  for warning in &result.warnings {
    progress(format!("提醒：{warning}"));
  }
  record_deployment(
    state,
    Deployed {
      service,
      server,
      run_id,
      hash: &hash,
      template: &template,
      spec: &row.spec,
      commit: commit.as_deref(),
    },
    &result,
  )
  .await?;
  let running = ensure_running(
    &result,
    service,
    &format!("wharf service logs {service}"),
  );
  if running.is_err() && !retired.is_empty() {
    restore(state, server, service, retired, &progress).await;
  }
  running?;
  if let Some(import) = row.import.clone() {
    let retired: Vec<String> = result
      .retired
      .iter()
      .map(|r| r.renamed.clone().unwrap_or_else(|| r.name.clone()))
      .collect();
    let (service, server) = (service.to_string(), server.to_string());
    state
      .db
      .call(move |c| {
        db::finish_import(c, &service, &server, &import, &retired)
      })
      .await?;
  }
  if row.spec.stopped {
    project_stop_start(
      state, server, service, false, &progress, cancel,
    )
    .await?;
  }
  Ok(())
}

fn service_server(
  snap: &snapshot::Snapshot,
  service: &str,
) -> Result<String, ApiError> {
  snap
    .world
    .services
    .get(service)
    .map(|s| s.spec.server.clone())
    .ok_or_else(|| {
      ApiError::new(
        ErrorCode::PlanStale,
        format!("服务 {service} 已不存在"),
      )
    })
}

/// `docker compose stop` / `start`，容器不删除、不重建。
async fn project_stop_start(
  state: &AppState,
  server: &str,
  service: &str,
  start: bool,
  progress: &ProgressFn,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let op = if start {
    AgentOp::ProjectStart {
      project: service.to_string(),
    }
  } else {
    AgentOp::ProjectStop {
      project: service.to_string(),
    }
  };
  let done: bool = state
    .hub
    .call(
      server,
      op,
      STOP_START_TIMEOUT,
      Some(progress.clone()),
      cancel,
    )
    .await?;
  if !done {
    return Err(ApiError::new(
      ErrorCode::NotFound,
      format!("{server} 上还没有部署 {service}"),
    ));
  }
  Ok(())
}

/// 接管失败：删掉新起的 project，恢复原来的容器。不受取消影响。
async fn restore(
  state: &AppState,
  server: &str,
  service: &str,
  retired: Vec<Retired>,
  progress: &ProgressFn,
) {
  progress("部署失败，恢复原来的容器".into());
  let cancel = CancellationToken::new();
  let down: Result<serde_json::Value, ApiError> = state
    .hub
    .call(
      server,
      AgentOp::ProjectDown {
        project: service.to_string(),
        purge: false,
      },
      SHORT_TIMEOUT,
      Some(progress.clone()),
      &cancel,
    )
    .await;
  if let Err(e) = down {
    progress(format!("删除新容器失败：{}", e.message));
  }
  let back: Result<serde_json::Value, ApiError> = state
    .hub
    .call(
      server,
      AgentOp::Unretire { items: retired },
      SHORT_TIMEOUT,
      Some(progress.clone()),
      &cancel,
    )
    .await;
  match back {
    Ok(_) => progress("已恢复原来的容器".into()),
    Err(e) => progress(format!(
      "恢复原来的容器失败，需要手动处理：{}",
      e.message
    )),
  }
}

async fn has_deployment(
  state: &AppState,
  service: &str,
) -> Result<bool, ApiError> {
  let service = service.to_string();
  state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT 1 FROM deployments WHERE service = ?1 LIMIT 1",
        params![service],
        |_| Ok(()),
      )
      .optional()
      .map(|r| r.is_some())
      .map_err(sql_err)
    })
    .await
}

struct Deployed<'a> {
  service: &'a str,
  server: &'a str,
  run_id: &'a str,
  hash: &'a str,
  template: &'a str,
  spec: &'a ServiceSpec,
  /// 构建来源：实际构建的 git commit。
  commit: Option<&'a str>,
}

async fn record_deployment(
  state: &AppState,
  d: Deployed<'_>,
  result: &ProjectUpResult,
) -> Result<(), ApiError> {
  let images =
    serde_json::to_string(&result.images).map_err(json_err)?;
  let spec = serde_json::to_string(d.spec).map_err(json_err)?;
  let commit = d.commit.map(str::to_string);
  // 记下实际跑起来的版本：导入（按本机已有的镜像启动）和每次部署之后，固定的版本都和正在跑的一致。
  let pinnable = crate::pins::images(&d.spec.source);
  let pins: std::collections::BTreeMap<&str, &str> = result
    .images
    .iter()
    .filter(|i| pinnable.contains(&i.image))
    .filter_map(|i| {
      let (_, digest) = i.digest.as_deref()?.split_once('@')?;
      Some((i.image.as_str(), digest))
    })
    .collect();
  let pins = (!pins.is_empty())
    .then(|| serde_json::to_string(&pins))
    .transpose()
    .map_err(json_err)?;
  let values = (
    d.service.to_string(),
    d.server.to_string(),
    d.run_id.to_string(),
    d.hash.to_string(),
    d.template.to_string(),
  );
  state
    .db
    .call(move |c| {
      let (service, server, run_id, hash, compose) = values;
      c.execute(
        "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, spec, commit_sha)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![service, server, run_id, hash, compose, images, now_ms(), spec, commit],
      )
      .map_err(sql_err)?;
      if let Some(pins) = pins {
        c.execute(
          "UPDATE resources SET meta = json_set(COALESCE(meta, '{}'), '$.pins', json(?1))
           WHERE kind = 'service' AND name = ?2",
          params![pins, service],
        )
        .map_err(sql_err)?;
      }
      Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn old_plan_without_fingerprint_still_runs() {
    let step: Step = serde_json::from_str(
      r#"{"kind":"service_up","service":"web"}"#,
    )
    .unwrap();
    assert_eq!(
      step,
      Step::ServiceUp {
        service: "web".into(),
        expect: None,
      }
    );
    let with = serde_json::to_string(&Step::ServiceUp {
      service: "web".into(),
      expect: Some("h".into()),
    })
    .unwrap();
    assert!(with.contains(r#""expect":"h""#));
    let gateway: Step = serde_json::from_str(
      r#"{"kind":"gateway_sync","gateway":"gw"}"#,
    )
    .unwrap();
    assert_eq!(
      gateway,
      Step::GatewaySync {
        gateway: "gw".into(),
        expect: None,
      }
    );
  }

  #[test]
  fn fingerprint_mismatch_asks_for_a_new_plan() {
    assert!(check_expect(None, "x", "服务 web").is_ok());
    assert!(check_expect(Some("x"), "x", "服务 web").is_ok());
    let e = check_expect(Some("x"), "y", "服务 web").unwrap_err();
    assert_eq!(e.code, ErrorCode::PlanStale);
    assert_eq!(e.suggest, ["wharf plan"]);
  }

  #[test]
  fn api_token_cannot_apply_opening_host_exec() {
    let now = Utc::now();
    let plan = Plan {
      plan_id: "p1".into(),
      status: PlanStatus::Pending,
      created_at: now,
      expires_at: now,
      base_versions: Default::default(),
      inputs: None,
      items: vec![wharf_api_types::plan::PlanItem {
        id: 1,
        address: "server/s1".into(),
        layer: wharf_api_types::plan::Layer::Config,
        action: wharf_api_types::plan::Action::Update,
        before: Some(serde_json::json!({})),
        after: Some(serde_json::json!({"host_exec": true})),
        impacts: vec![],
        reason: "修改配置".into(),
        changes: vec![],
        host_access: vec![],
      }],
      warnings: vec![],
      needs_host: vec![],
      needs_confirm: vec![],
      suggest: vec![],
      note: None,
    };
    assert_eq!(
      crate::host_access::require_plan_host(
        &plan,
        &[],
        Some(&[]),
        &Perm::ALL.into_iter().collect(),
        false,
        &Default::default(),
        Some("core"),
      )
      .unwrap_err()
      .code,
      ErrorCode::Forbidden
    );
  }
}
