use wharf_api_types::{
  plan::{PlannedServiceAction, ServiceActionKind},
  spec::{Change, UpdateIgnoreScope},
};

use super::*;

pub(crate) async fn make_batch_plan(
  state: &AppState,
  req: PlanRequest,
  snap: Snapshot,
  allowed: Option<&BTreeSet<String>>,
) -> Result<Planned, ApiError> {
  if !req.changes.is_empty()
    || req.fleet.is_some()
    || req.partial.is_some()
  {
    return Err(ApiError::invalid(
      "service_action、changes、fleet、partial 只能给一个",
    ));
  }
  let mut action = req
    .service_action
    .ok_or_else(|| ApiError::invalid("缺少 service_action"))?;
  action.tag =
    crate::world::normalize_service_tag(&action.tag)?.to_owned();
  let current = &snap.world;
  let targets: Vec<_> = current
    .services
    .iter()
    .filter(|(name, row)| {
      allowed.is_none_or(|allowed| allowed.contains(*name))
        && row.spec.tags.contains(&action.tag)
    })
    .map(|(name, _)| name.clone())
    .collect();
  if targets.is_empty() {
    return Err(
      ApiError::not_found("可见范围内没有匹配的服务").with_hint(
        format!("先运行 wharf service list --tag {}", action.tag),
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
    let row = &current.services[name];
    if action.action == ServiceActionKind::Restart && row.spec.stopped
    {
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
    if action.action == ServiceActionKind::Update {
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
  if action.action == ServiceActionKind::Update {
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
      if action.action == ServiceActionKind::Stop {
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
      } else if project
        .is_none_or(|project| project.containers.is_empty())
      {
        b.warnings.push(format!("跳过 {name}：没有部署容器"));
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
  match action.action {
    ServiceActionKind::Update => {
      b.service_targets = Some(runtime);
      let net = snap.net(&desired);
      service_items(
        &mut b, &snap, current, &desired, &net, &status, &writes,
      )?;
      build_agent_warnings(state, &desired, &mut b)?;
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
    req.note.as_deref(),
  );
  planned.plan.service_action = Some(PlannedServiceAction {
    action: action.action,
    tag: action.tag,
    targets,
  });
  Ok(planned)
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
          spec: json!({"server":"s1","source":{"image":"fixture:1"},"stopped":name != "c","tags":["试验"]}),
        })?;
      }
      Ok(())
    }).await.unwrap();
    let allowed = BTreeSet::from(["a".into(), "b".into()]);
    let req = serde_json::from_value(json!({
      "service_action":{"action":"restart","tag":" 试验 "}
    }))
    .unwrap();
    let snap = snapshot::load(&state.db).await.unwrap();
    let plan = make_batch_plan(&state, req, snap, Some(&allowed))
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
  }
}
