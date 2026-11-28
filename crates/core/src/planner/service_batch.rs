use wharf_api_types::{
  plan::{PlannedServiceAction, ServiceAction, ServiceActionKind},
  spec::{Change, UpdateIgnoreScope},
};

use super::*;

pub(crate) async fn make_service_action_plan(
  state: &AppState,
  req: PlanRequest,
  snap: Snapshot,
  allowed: Option<&BTreeSet<String>>,
  admin: bool,
) -> Result<Planned, ApiError> {
  if !req.changes.is_empty()
    || req.fleet.is_some()
    || req.partial.is_some()
  {
    return Err(ApiError::invalid(
      "service_action、changes、fleet、partial 只能给一个",
    ));
  }
  if req.no_defaults {
    return Err(ApiError::invalid("计划 no_defaults 仅用于 Fleet"));
  }
  match req.service_action {
    Some(ServiceAction::ResumeProtected { service }) => {
      if allowed.is_some_and(|scope| !scope.contains(&service)) {
        return Err(ApiError::new(
          ErrorCode::Forbidden,
          "服务不在令牌范围内",
        ));
      }
      resume_plan(state, &snap, &service, req.note.as_deref())
    }
    Some(ServiceAction::Rename { source, target }) => {
      if !admin || allowed.is_some() {
        return Err(ApiError::new(
          ErrorCode::Forbidden,
          "服务改名需要不限制服务范围的管理员令牌",
        ));
      }
      service_rename::plan(
        state,
        snap,
        source,
        target,
        req.note.as_deref(),
      )
      .await
    }
    Some(ServiceAction::Clone {
      source,
      target,
      server,
      copy_data,
    }) => {
      service_clone::plan(
        state,
        snap,
        allowed,
        admin,
        service_clone::CloneRequest {
          source,
          target,
          server,
          copy_data,
          note: req.note,
        },
      )
      .await
    }
    Some(ServiceAction::Restart { tag }) => {
      make_batch_plan(
        state,
        snap,
        allowed,
        ServiceActionKind::Restart,
        &tag,
        req.note.as_deref(),
      )
      .await
    }
    Some(ServiceAction::Stop { tag }) => {
      make_batch_plan(
        state,
        snap,
        allowed,
        ServiceActionKind::Stop,
        &tag,
        req.note.as_deref(),
      )
      .await
    }
    Some(ServiceAction::Update { tag }) => {
      make_batch_plan(
        state,
        snap,
        allowed,
        ServiceActionKind::Update,
        &tag,
        req.note.as_deref(),
      )
      .await
    }
    None => Err(ApiError::invalid("缺少 service_action")),
  }
}

async fn make_batch_plan(
  state: &AppState,
  snap: Snapshot,
  allowed: Option<&BTreeSet<String>>,
  action: ServiceActionKind,
  tag: &str,
  note: Option<&str>,
) -> Result<Planned, ApiError> {
  let tag = crate::world::normalize_service_tag(tag)?;
  let current = &snap.world;
  let targets: Vec<_> = current
    .services
    .iter()
    .filter(|(name, row)| {
      allowed.is_none_or(|allowed| allowed.contains(*name))
        && row.spec.tags.contains(tag)
    })
    .map(|(name, _)| name.clone())
    .collect();
  if targets.is_empty() {
    return Err(
      ApiError::not_found("可见范围内没有匹配的服务").with_hint(
        format!("先运行 wharf service list --tag {}", tag),
      ),
    );
  }

  let mut desired = current.clone();
  let mut b = Builder::default();
  let mut active = BTreeSet::new();
  let mut projects = BTreeMap::<String, Vec<String>>::new();
  let mut refresh_changes = Vec::new();
  let outside =
    |service: &str| !targets.iter().any(|name| name == service);
  for name in &targets {
    crate::crash_guard::require_idle(&snap, name)?;
    let row = &current.services[name];
    if action == ServiceActionKind::Restart && row.spec.stopped {
      b.warnings.push(format!("跳过 {name}：服务已停"));
      continue;
    }
    if moved_from(&snap, current, name, &row.spec.server).is_some()
      || snap.pending.migrations.contains_key(name)
      || snap.pending.adopt_data.contains_key(name)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务 {name} 有未完成的运维操作"),
        )
        .with_hint("先完成原执行，再重新生成计划"),
      );
    }
    if action == ServiceActionKind::Update {
      let spec = &row.spec;
      if row.import.is_some()
        || spec.update_ignore.iter().any(|rule| {
          rule.image == "*" && rule.scope == UpdateIgnoreScope::All
        })
      {
        b.warnings
          .push(format!("跳过 {name}：尚未完成接管或已忽略更新"));
        continue;
      }
      if let Some(reason) = crate::pins::unsupported(&spec.source) {
        b.warnings.push(format!("跳过 {name}：{reason}"));
        continue;
      }
      if matches!(spec.source, Source::Build(_)) {
        refresh_changes.push(Change::RefreshImages {
          name: name.clone(),
          image: None,
        });
      } else {
        let images: Vec<_> = crate::pins::images(&spec.source)
          .into_iter()
          .filter(|image| !image.contains('@'))
          .filter(|image| {
            crate::updates::effective_ignore(
              &spec.update_ignore,
              image,
            ) != Some(UpdateIgnoreScope::All)
          })
          .collect();
        if images.is_empty() {
          b.warnings.push(format!("跳过 {name}：没有可更新的镜像"));
          continue;
        }
        refresh_changes.extend(images.into_iter().map(|image| {
          Change::RefreshImages {
            name: name.clone(),
            image: Some(image),
          }
        }));
      }
    }
    if !state.hub.is_online(&row.spec.server) {
      return Err(
        ApiError::new(
          ErrorCode::AgentOffline,
          format!("服务 {name} 所在机器 {} 离线", row.spec.server),
        )
        .with_hint("恢复连接后重出计划"),
      );
    }
    projects
      .entry(row.spec.server.clone())
      .or_default()
      .push(name.clone());
    active.insert(name.clone());
  }

  let mut status = StatusMap::new();
  for (server, names) in projects {
    let projects = snapshot::project_status(
      &state.hub,
      &server,
      names,
      STATUS_TIMEOUT,
    )
    .await
    .map_err(|e| e.with_hint("恢复连接后重出计划"))?;
    status.insert(server, Some(projects));
  }
  let mut runtime = BTreeSet::new();
  if action == ServiceActionKind::Update {
    desired.apply_changes(&refresh_changes)?;
    let refresh = refresh_changes
      .iter()
      .filter_map(|c| match c {
        Change::RefreshImages { name, image } => {
          Some(crate::pins::refresh_key(name, image.as_deref()))
        }
        _ => None,
      })
      .collect();
    let resolved = crate::pins::resolve(
      state,
      &snap,
      &mut desired,
      &refresh,
      false,
      Some(&active),
    )
    .await?;
    b.image_ids = resolved.image_ids;
    b.warnings.extend(resolved.warnings);
    crate::pins::resolve_commits(
      state,
      &snap,
      &mut desired,
      &refresh,
      &mut b.warnings,
      Some(&active),
    )
    .await?;
    for name in &active {
      let before = &current.services[name];
      let after = desired
        .services
        .get_mut(name)
        .expect("批量选择来自当前服务");
      for (image, digest) in &before.pins {
        after
          .pins
          .entry(image.clone())
          .or_insert_with(|| digest.clone());
      }
      if before.pins == after.pins && before.commit == after.commit {
        b.warnings.push(format!("跳过 {name}：没有新版"));
      } else {
        runtime.insert(name.clone());
      }
    }
  } else {
    for name in &active {
      let row = &current.services[name];
      let project = status
        .get(&row.spec.server)
        .and_then(Option::as_ref)
        .and_then(|projects| projects.get(name));
      if action == ServiceActionKind::Stop {
        desired
          .services
          .get_mut(name)
          .expect("批量选择来自当前服务")
          .spec
          .stopped = true;
        if project.is_none_or(|project| {
          project.containers.iter().all(|c| !c.is_active())
        }) {
          continue;
        }
      } else if project.is_none_or(|project| {
        project.containers.iter().all(|c| !c.is_active())
      }) {
        b.warnings.push(format!("跳过 {name}：服务已停"));
        continue;
      }
      runtime.insert(name.clone());
    }
  }

  for name in &runtime {
    let spec = &current.services[name].spec;
    let has_foreign = status
      .get(&spec.server)
      .and_then(Option::as_ref)
      .and_then(|projects| projects.get(name))
      .is_some_and(|project| {
        (project.hash.is_none() && !project.containers.is_empty())
          || project.containers.iter().any(|c| c.foreign)
      });
    if has_foreign {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("无法核实服务 {name} 的容器归属"),
        )
        .with_hint("先确认并单独规划此服务"),
      );
    }
    if crate::shared_volumes::uses(spec)
      .iter()
      .any(|name| outside(name))
      || crate::shared_volumes::consumers_on(
        current,
        name,
        &spec.server,
      )
      .any(outside)
    {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("服务 {name} 的依赖超出批量范围"),
        )
        .with_hint("缩小选择或单独规划依赖服务"),
      );
    }
  }
  let writes = desired.writes_from(current);
  config_items(&mut b, current, &desired, &writes);
  match action {
    ServiceActionKind::Update => {
      b.explicit_pins.clone_from(&runtime);
      b.service_targets = Some(runtime);
      let net = snap.net(&desired);
      service_items(
        &mut b, &snap, current, &desired, &net, &status, &writes,
      )?;
      build_agent_warnings(state, &desired, &mut b)?;
      select_planned_service_images(state, &snap, &desired, &mut b)
        .await?;
    }
    kind => {
      for name in runtime {
        let (verb, impact, step) =
          if kind == ServiceActionKind::Restart {
            (
              "重启",
              Impact::Restart,
              Step::ServiceRestart {
                service: name.clone(),
                container: None,
              },
            )
          } else {
            (
              "停止",
              Impact::Downtime,
              Step::ServiceStop {
                service: name.clone(),
              },
            )
          };
        let title = format!("{verb} {name}");
        let id = b.item(
          format!("service/{name}"),
          Layer::Container,
          Action::Update,
          None,
          None,
          vec![impact],
          &title,
        );
        b.step(vec![id], title, step);
      }
    }
  }
  let mut planned = finish_plan(
    &snap,
    &desired,
    b,
    writes,
    crate::render::service_account_refs(&desired),
    note,
  );
  planned.plan.service_action = Some(PlannedServiceAction {
    action,
    tag: Some(tag.into()),
    targets,
  });
  Ok(planned)
}

fn resume_plan(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
  note: Option<&str>,
) -> Result<Planned, ApiError> {
  let row = snap
    .world
    .services
    .get(name)
    .ok_or_else(|| crate::api::service_not_found(name))?;
  let recovery = snap
    .recovery
    .get(name)
    .ok_or_else(|| ApiError::invalid("服务没有保护停机状态"))?;
  if !row.spec.stopped
    || recovery.phase != "protected"
    || recovery.lease.is_some()
  {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        "服务仍在保护停机确认或修复",
      )
      .with_hint(format!(
        "运行 wharf service repair {name} --status"
      )),
    );
  }
  state.hub.crash_guard_conn_id(&row.spec.server)?;
  let address = format!("service/{name}");
  let mut b = Builder::default();
  let id = b.item(
    address.clone(),
    Layer::Container,
    Action::Update,
    None,
    None,
    vec![Impact::Restart],
    "恢复原重启策略并启动服务",
  );
  b.step(
    vec![id],
    format!("恢复并启动 {name}"),
    Step::ResumeProtected {
      service: name.into(),
      instance: row.instance_id.clone(),
    },
  );
  let mut plan = finish_plan(
    snap,
    &snap.world,
    b,
    vec![],
    crate::render::service_account_refs(&snap.world),
    note,
  );
  plan.plan.needs_confirm.push(address.clone());
  if let Some(suggest) = plan.plan.suggest.first_mut() {
    suggest.push_str(&format!(" --confirm {address}"));
  }
  plan.plan.service_action = Some(PlannedServiceAction {
    action: ServiceActionKind::ResumeProtected,
    tag: None,
    targets: vec![name.into()],
  });
  Ok(plan)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn batch_uses_visible_targets_and_does_not_plan_other_drift()
  {
    let state = crate::rules::tests::test_state();
    state.db.call(|c| {
      for name in ["a", "b", "c"] {
        db::apply_write(c, &Write::Upsert {
          kind: "service".into(), name: name.into(), meta: json!({}),
          spec: json!({"server":"s1","source":{"image":"fixture:1"},"stopped":name == "b","tags":["试验"]}),
        })?;
      }
      Ok(())
    }).await.unwrap();
    state.hub.mock_agent("s1", false, |op| {
      assert!(matches!(op, wharf_api_types::agent::AgentOp::ProjectStatus { projects, .. } if projects == ["a"]));
      Ok(json!([{"project":"a","hash":"fixture","containers":[{"service":"a","name":"a-1","state":"exited"}]}]))
    });
    let allowed = BTreeSet::from(["a".into(), "b".into()]);
    let req = serde_json::from_value(json!({
      "service_action":{"action":"restart","tag":" 试验 "}
    }))
    .unwrap();
    let snap = snapshot::load(&state.db).await.unwrap();
    let plan = make_service_action_plan(
      &state,
      req,
      snap,
      Some(&allowed),
      false,
    )
    .await
    .unwrap();
    assert!(plan.steps.is_empty());
    assert!(plan.writes.is_empty());
    assert_eq!(
      plan.plan.service_action.as_ref().unwrap().targets,
      ["a", "b"]
    );
    assert_eq!(plan.plan.warnings.len(), 2);
    assert!(
      crate::token_scope::check_plan_scope(
        &BTreeSet::from(["a".into()]),
        &plan.plan,
        &plan.route_effects
      )
      .is_err()
    );
    state.db.call_credentials(move |c,key| {
      c.execute("UPDATE resources SET version=version+1 WHERE kind='service' AND name='a'",[]).map_err(db::sql_err)?;
      let err=crate::apply::require_fresh(c,key,&plan.plan,Some(&plan.account_refs),Some(&plan.base_instances)).unwrap_err();
      assert_eq!(err.code,ErrorCode::PlanStale);
      assert_eq!(err.hint.as_deref(),Some("重新执行原命令生成计划"));
      Ok(())
    }).await.unwrap();
  }
}
