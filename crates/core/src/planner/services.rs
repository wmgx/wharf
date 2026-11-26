fn finish_plan(
  snap: &Snapshot,
  desired: &World,
  mut b: Builder,
  writes: Vec<Write>,
  account_refs: BTreeSet<String>,
  note: Option<&str>,
) -> Planned {
  b.warnings.extend(crate::lint::plan_warnings(
    snap, desired, &b.items, &b.steps,
  ));
  b.steps.sort_by_key(|s| s.step.order());
  // 同一次执行里要起 Tailscale：起来后机器地址会变，后面的服务和网关按新地址渲染，
  // 和计划时的指纹对不上是正常的，不校验。
  if b
    .steps
    .iter()
    .any(|s| matches!(s.step, Step::TailscaleUp { .. }))
  {
    for s in &mut b.steps {
      if let Step::ServiceUp { expect, .. }
      | Step::GatewaySync { expect, .. } = &mut s.step
      {
        *expect = None;
      }
    }
  }
  let (needs_host, host_requirements) = crate::host_access::mark_plan(
    &snap.world,
    desired,
    &mut b.items,
    &b.steps,
  );
  let plan_id = new_id("p");
  let mut needs_confirm: Vec<String> = b
    .items
    .iter()
    .filter(|i| i.needs_confirm())
    .map(|i| i.address.clone())
    .collect();
  needs_confirm.sort();
  needs_confirm.dedup();
  let suggest = if b.items.is_empty() {
    vec![]
  } else {
    let confirms: String = needs_confirm
      .iter()
      .map(|a| format!(" --confirm {a}"))
      .collect();
    vec![format!("wharf apply {plan_id}{confirms}")]
  };
  let now = Utc::now();
  let plan = Plan {
    plan_id,
    status: PlanStatus::Pending,
    created_at: now,
    expires_at: now + chrono::Duration::minutes(PLAN_TTL_MINUTES),
    base_versions: snap.world.versions(),
    inputs: Some(crate::db::inputs_fingerprint(
      &snap.reach,
      &snap.service_values,
      &snap.net(&snap.world).addresses(),
    )),
    items: b.items,
    warnings: b.warnings,
    needs_host,
    needs_confirm,
    suggest,
    note: note
      .map(str::trim)
      .filter(|n| !n.is_empty())
      .map(|n| n.chars().take(500).collect()),
  };
  Planned {
    plan,
    account_refs,
    host_requirements,
    route_effects: b.route_effects,
    steps: b.steps,
    writes,
  }
}

/// 服务实际在哪台服务器上：最近一次成功部署的位置，没部署过就看配置。
///
/// 迁移失败时配置已经写成新服务器，但容器和数据还在旧服务器上；
/// 按部署记录判断，重新 plan 时会再次迁移，而不是在新服务器上用不完整的数据启动。
fn running_on<'a>(
  snap: &'a Snapshot,
  current: &'a World,
  name: &str,
) -> Option<&'a str> {
  let configured = &current.services.get(name)?.spec.server;
  Some(snap.deployed.get(name).unwrap_or(configured))
}

/// 服务要换服务器时，返回它现在所在的服务器。
fn moved_from<'a>(
  snap: &'a Snapshot,
  current: &'a World,
  name: &str,
  server: &str,
) -> Option<&'a str> {
  running_on(snap, current, name).filter(|old| *old != server)
}

fn to_json<T: Serialize>(v: &T) -> Value {
  serde_json::to_value(v).unwrap_or_default()
}

fn spec_json(world: &World, kind: &str, name: &str) -> Option<Value> {
  match kind {
    KIND_SERVER => {
      world.servers.get(name).map(|r| to_json(&r.settings))
    }
    KIND_SERVICE => world.services.get(name).map(|r| {
      let mut v =
        to_json(&crate::service_monitor::heartbeat::redact(&r.spec));
      v["host_ports"] = json!(r.host_ports);
      v
    }),
    KIND_GATEWAY => {
      world.gateways.get(name).map(|r| to_json(&r.spec))
    }
    KIND_ROUTE => world.routes.get(name).map(|r| to_json(&r.spec)),
    KIND_EDGE => world.edge_apps.get(name).map(|r| to_json(&r.spec)),
    KIND_BOOKMARK => {
      world.bookmarks.get(name).map(|r| to_json(&r.spec))
    }
    _ => None,
  }
}

fn config_items(
  b: &mut Builder,
  current: &World,
  desired: &World,
  writes: &[Write],
) {
  for write in writes {
    let (kind, name) = match write {
      Write::Upsert { kind, name, .. }
      | Write::Delete { kind, name } => {
        (kind.as_str(), name.as_str())
      }
    };
    let before = spec_json(current, kind, name);
    let after = spec_json(desired, kind, name);
    let action = match (&before, &after) {
      (None, _) => Action::Create,
      (_, None) => Action::Delete,
      _ => Action::Update,
    };
    let (risk, reason) = match (kind, action) {
      (KIND_BOOKMARK, action) => {
        let spec = if action == Action::Delete {
          &before
        } else {
          &after
        };
        let title = spec
          .as_ref()
          .and_then(|v| v["title"].as_str())
          .unwrap_or_default();
        let verb = match action {
          Action::Create => "新增",
          Action::Delete => "删除",
          _ => "修改",
        };
        (vec![], format!("{verb}书签 {title}"))
      }
      (KIND_SERVICE, Action::Delete) => {
        (vec![Impact::Remove], "删除服务（数据目录保留）".to_string())
      }
      (KIND_SERVICE, Action::Create)
        if desired
          .services
          .get(name)
          .and_then(|r| r.import.as_ref())
          .is_some() =>
      {
        let adopt = desired.services[name].import.as_ref();
        match adopt.and_then(|a| a.project.as_deref()) {
          Some(project) => (
            vec![Impact::Restart],
            format!(
              "导入：停掉原来的 compose 项目 {project}，用新名字重新创建容器"
            ),
          ),
          None if adopt.is_some_and(|a| !a.containers.is_empty()) => {
            (
              vec![Impact::Restart],
              format!(
                "导入：原来的容器 {} 改名停掉（失败时恢复），重新创建",
                adopt
                  .map(|a| a.containers.join("、"))
                  .unwrap_or_default()
              ),
            )
          }
          None => (
            vec![],
            "导入：沿用同名 compose 项目，配置一致时不重建容器"
              .to_string(),
          ),
        }
      }
      (KIND_GATEWAY, Action::Delete) => (
        vec![Impact::Remove, Impact::Downtime],
        "删除网关".to_string(),
      ),
      (KIND_EDGE, Action::Delete) => {
        (vec![], "不再纳管（厂商那边的项目保留）".to_string())
      }
      (KIND_ROUTE, action) => route_impact::route_impact(
        current.routes.get(name).map(|r| &r.spec),
        desired.routes.get(name).map(|r| &r.spec),
        action,
      ),
      (_, Action::Create) => (vec![], "新增".to_string()),
      // 配置没变，只是记下固定的镜像版本（存在 meta 里）。
      (KIND_SERVICE, Action::Update) if before == after => {
        let pinned = desired
          .services
          .get(name)
          .and_then(|r| r.pins.values().next())
          .map(|d| crate::pins::short(d).to_string());
        match pinned {
          Some(d) => (vec![], format!("固定镜像版本 {d}，不重建")),
          None => (vec![], "更新内部记录，不重建".to_string()),
        }
      }
      _ => (vec![], "修改配置".to_string()),
    };
    b.item(
      format!("{kind}/{name}"),
      Layer::Config,
      action,
      before,
      after,
      risk,
      reason,
    );
  }
}

type StatusMap =
  BTreeMap<String, Option<BTreeMap<String, ProjectState>>>;

/// 每台相关服务器查一次现状。查不到的服务器值为 `None`，并记一条提醒。
async fn gather_status(
  state: &AppState,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
  b: &mut Builder,
) -> StatusMap {
  let mut projects: BTreeMap<String, BTreeSet<String>> =
    BTreeMap::new();
  for world in [current, desired] {
    for (name, s) in &world.services {
      projects
        .entry(s.spec.server.clone())
        .or_default()
        .insert(name.clone());
    }
    for (name, g) in &world.gateways {
      projects
        .entry(g.spec.server.clone())
        .or_default()
        .insert(gateway_project(name));
    }
    for p in crate::link::projects(world, net).unwrap_or_default() {
      projects.entry(p.server).or_default().insert(p.project);
    }
    for (name, server) in leftovers(&snap.deployed, current, desired)
    {
      projects
        .entry(server.to_string())
        .or_default()
        .insert(name.to_string());
    }
    for (name, row) in &world.servers {
      if row.settings.network_mode == Some(NetworkMode::Tailscale) {
        projects
          .entry(name.clone())
          .or_default()
          .insert(crate::tailscale::PROJECT.to_string());
      }
    }
  }
  let futures =
    projects.into_iter().map(|(server, projects)| async move {
      let result = snapshot::project_status(
        &state.hub,
        &server,
        projects.into_iter().collect(),
        STATUS_TIMEOUT,
      )
      .await;
      (server, result)
    });
  let mut out = StatusMap::new();
  for (server, result) in
    futures_util::future::join_all(futures).await
  {
    match result {
      Ok(map) => {
        out.insert(server, Some(map));
      }
      Err(e) => {
        let joined =
          snap.agent(&server).is_some_and(|a| a.public_key.is_some());
        b.warnings.push(if joined {
          format!("无法读取服务器 {server} 的现状：{}", e.message)
        } else {
          format!("服务器 {server} 还没有完成 agent 加入，无法部署")
        });
        out.insert(server, None);
      }
    }
  }
  out
}

fn changed(writes: &[Write], kind: &str, name: &str) -> bool {
  writes.iter().any(|w| match w {
    Write::Upsert {
      kind: k, name: n, ..
    }
    | Write::Delete { kind: k, name: n } => k == kind && n == name,
  })
}

fn describe_containers(state: &ProjectState) -> String {
  state
    .containers
    .iter()
    .filter(|c| c.state != "running")
    .map(|c| format!("{} {}", c.service, c.state))
    .collect::<Vec<_>>()
    .join("，")
}

fn service_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
  writes: &[Write],
) -> Result<(), ApiError> {
  for (name, svc) in &desired.services {
    if current.services.get(name).is_some_and(|old| {
      crate::service_monitor::config_only(old, svc)
    }) {
      continue;
    }
    let address = format!("{KIND_SERVICE}/{name}");
    let server = &svc.spec.server;
    let moved = moved_from(snap, current, name, server);
    // 数据卷：新增的目录。迁移时新机器上要建全部目录。
    let old_dirs: BTreeSet<String> = current
      .services
      .get(name)
      .filter(|_| moved.is_none())
      .map(|s| {
        crate::render::service_dirs(name, &s.spec)
          .into_iter()
          .collect()
      })
      .unwrap_or_default();
    let new_dirs: Vec<String> =
      crate::render::service_dirs(name, &svc.spec)
        .into_iter()
        .filter(|d| !old_dirs.contains(d))
        .collect();
    if !new_dirs.is_empty() {
      let id = b.item(
        address.clone(),
        Layer::Volume,
        Action::Create,
        None,
        Some(json!({ "dirs": new_dirs })),
        vec![],
        "创建数据目录",
      );
      b.step(
        vec![id],
        format!("在 {server} 上创建 {name} 的数据目录"),
        Step::EnsureDirs {
          server: server.clone(),
          dirs: new_dirs,
        },
      );
    }

    if let Some(from) = moved {
      move_items(b, current, name, from, server, net);
    }

    let (_, hash) = snapshot::service_resolved(
      desired,
      net,
      name,
      &snap.render_values(desired, name),
    )?;
    let template = snapshot::service_template(desired, net, name)?;
    let after =
      Some(json!({ "server": server, "compose": template }));
    let live = status
      .get(server)
      .and_then(|s| s.as_ref())
      .and_then(|p| p.get(name));
    // 配置没变、只是要停下来：不重建，直接停。
    if svc.spec.stopped
      && let Some(state) = live
      && state.hash.as_deref() == Some(hash.as_str())
    {
      if state.containers.iter().any(|c| c.state == "running") {
        let id = b.item(
          address.clone(),
          Layer::Container,
          Action::Update,
          Some(json!({ "containers": state.containers })),
          after,
          vec![Impact::Downtime],
          "停止服务",
        );
        b.step(
          vec![id],
          format!("停止 {server} 上的 {name}"),
          Step::ServiceStop {
            service: name.clone(),
          },
        );
      }
      continue;
    }
    let upgrade = crate::pins::change(
      snap.applied.get(name),
      &svc.pins,
      b.image_ids.get(name),
    )
    .map(|(image, old, new)| {
      let what = match &svc.spec.source {
        Source::Image(_) => String::new(),
        _ => format!(" {image}"),
      };
      format!(
        "更新镜像版本{what} {old} → {}",
        crate::pins::short(&new)
      )
    })
    .or_else(|| {
      crate::pins::commit_change(
        snap.applied.get(name),
        svc.commit.as_deref(),
      )
      .map(|(old, new)| {
        format!("更新代码 {old} → {}，重新构建", &new[..12])
      })
    });
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      None if changed(writes, KIND_SERVICE, name) => Some((
        Action::Update,
        vec![Impact::Restart],
        "无法读取现状，按新配置部署".to_string(),
        None,
      )),
      None => None,
      Some(projects) => match projects.get(name) {
        None => {
          Some((Action::Create, vec![], "部署新服务".into(), None))
        }
        Some(state)
          if state.hash.is_none() && state.containers.is_empty() =>
        {
          Some((Action::Create, vec![], "部署新服务".into(), None))
        }
        Some(state)
          if state.hash.as_deref() != Some(hash.as_str()) =>
        {
          let before = json!({ "hash": state.hash, "containers": state.containers });
          let adopting = svc.import.is_some();
          let reason: String = if state.hash.is_none() && adopting {
            "接管服务器上的同名 compose 项目，配置一致时不重建容器"
              .into()
          } else if state.hash.is_none() {
            "服务器上已有同名 project，但不是 Wharf 部署的，将被接管重建".into()
          } else {
            let (head, all) = if changed(writes, KIND_SERVICE, name) {
              ("配置变化", "配置变化，重建容器")
            } else {
              (
                "漂移：服务器上的部署和配置不一致",
                "漂移：服务器上的部署和配置不一致，重新部署",
              )
            };
            deployed_template(
              current,
              net,
              name,
              snap.applied.get(name),
            )
            .and_then(|old| changed_components(&old, &template))
            .map_or(all.to_string(), |(redo, keep)| {
              format!(
                "{head}，只重建 {}（{} 不变）",
                redo.join("、"),
                keep.join("、")
              )
            })
          };
          let risk = if state.hash.is_none() && !adopting {
            vec![Impact::Restart, Impact::Overwrite]
          } else {
            vec![Impact::Restart]
          };
          Some((
            Action::Update,
            risk,
            reason.to_string(),
            Some(before),
          ))
        }
        Some(state) if !state.all_running() => Some((
          Action::Update,
          vec![Impact::Restart],
          if changed(writes, KIND_SERVICE, name) {
            "启动服务".to_string()
          } else {
            format!(
              "漂移：容器没在运行（{}）",
              describe_containers(state)
            )
          },
          Some(json!({ "containers": state.containers })),
        )),
        Some(_) => upgrade.map(|reason| {
          (Action::Update, vec![Impact::Restart], reason, None)
        }),
      },
    };
    // 同名 compose 项目里混着别处起的容器：compose up 会把它们当成自己的删掉。导入时本来就要接管。
    let foreign: Vec<&str> = status
      .get(server)
      .and_then(|s| s.as_ref())
      .and_then(|p| p.get(name))
      .map(|s| {
        s.containers
          .iter()
          .filter(|c| c.foreign)
          .map(|c| c.name.as_str())
          .collect()
      })
      .unwrap_or_default();
    let decision = match decision {
      Some((action, _, _, before))
        if !foreign.is_empty() && svc.import.is_none() =>
      {
        Some((
          action,
          vec![Impact::Restart, Impact::Overwrite],
          format!(
            "{server} 上同名 compose 项目里有不是 Wharf 部署的容器（{}），部署会删除它们；要保留请先导入，或换个服务名",
            foreign.join("、")
          ),
          before,
        ))
      }
      d => d,
    };
    if let Some((action, mut risk, reason, before)) = decision {
      if !risk.contains(&Impact::Public)
        && crate::host_access::has_new_public_bind(
          current, name, &svc.spec,
        )
      {
        risk.push(Impact::Public);
      }
      let reason = if matches!(svc.spec.source, Source::Build(_)) {
        format!("{reason}（镜像不在 {server} 上时先构建）")
      } else {
        reason
      };
      let reason = if svc.spec.stopped {
        format!("{reason}，部署后保持停止")
      } else {
        reason
      };
      let id = b.item(
        address.clone(),
        Layer::Container,
        action,
        before,
        after,
        risk,
        reason,
      );
      b.step(
        vec![id],
        format!("在 {server} 上部署 {name}"),
        Step::ServiceUp {
          service: name.clone(),
          expect: Some(hash.clone()),
        },
      );
    }
  }
  for (name, svc) in &current.services {
    let old =
      running_on(snap, current, name).unwrap_or(&svc.spec.server);
    if desired
      .services
      .get(name)
      .is_some_and(|d| d.spec.server == old)
    {
      continue;
    }
    // 迁移走的服务：旧服务器上的容器在网关切换之后删除，数据目录保留。
    if let Some(to) =
      desired.services.get(name).map(|d| &d.spec.server)
    {
      let server = &old.to_string();
      let id = b.item(
        format!("{KIND_SERVICE}/{name}"),
        Layer::Container,
        Action::Delete,
        Some(json!({ "server": server })),
        None,
        vec![],
        format!(
          "迁移到 {to} 后删除 {server} 上的旧容器（数据目录保留）"
        ),
      );
      b.step(
        vec![id],
        format!("删除 {server} 上的旧 {name}"),
        Step::ServiceDown {
          server: server.clone(),
          service: name.clone(),
          purge_data: false,
        },
      );
      continue;
    }
    let server = &svc.spec.server;
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      vec![Impact::Remove],
      "停止并删除容器",
    );
    let purge = b.purge_data.contains(name);
    for m in crate::data::mounts(name, &svc.spec) {
      let gone = purge
        && m.kind != wharf_api_types::view::DataKind::ExternalDir;
      b.warnings.push(if gone {
        format!(
          "服务 {name} 的{} 会被永久删除，不能恢复",
          crate::data::describe(&m)
        )
      } else {
        format!(
          "服务 {name} 的{} 会保留在 {server} 上，需要时手动删除",
          crate::data::describe(&m)
        )
      });
    }
    b.step(
      vec![id],
      if purge {
        format!("在 {server} 上删除 {name} 和它的数据")
      } else {
        format!("在 {server} 上删除 {name}")
      },
      Step::ServiceDown {
        server: server.clone(),
        service: name.clone(),
        purge_data: purge,
      },
    );
  }
  Ok(())
}

/// compose 里多个组件时，比较新旧模板逐个组件看：有的变了、有的没变时返回 (要重建的, 不变的)。
/// `docker compose up -d` 本来就只重建配置变了的组件，这里只是在计划里说清楚。
/// 服务器上现在跑的 compose：按上次部署的配置渲染；没有记录时退回当前配置。
/// 上次部署失败时新配置已经写进去了，拿当前配置比会看不出哪些容器要重建。
fn deployed_template(
  current: &World,
  net: &Net,
  name: &str,
  applied: Option<&wharf_api_types::view::Applied>,
) -> Option<String> {
  current.services.get(name)?;
  match applied.and_then(|a| a.spec.clone()) {
    Some(spec) => {
      let mut world = current.clone();
      world.services.get_mut(name)?.spec = spec;
      snapshot::service_template(&world, net, name).ok()
    }
    None => snapshot::service_template(current, net, name).ok(),
  }
}

fn changed_components(
  old: &str,
  new: &str,
) -> Option<(Vec<String>, Vec<String>)> {
  let parse =
    |t: &str| -> Option<BTreeMap<String, serde_yaml_ng::Value>> {
      let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(t).ok()?;
      let services = doc.get("services")?.as_mapping()?;
      Some(
        services
          .iter()
          .filter_map(|(k, v)| {
            Some((k.as_str()?.to_string(), v.clone()))
          })
          .collect(),
      )
    };
  let (old, new) = (parse(old)?, parse(new)?);
  if new.len() < 2 {
    return None;
  }
  let (redo, keep): (Vec<&String>, Vec<&String>) =
    new.keys().partition(|k| old.get(*k) != new.get(*k));
  (!redo.is_empty() && !keep.is_empty()).then(|| {
    (
      redo.into_iter().cloned().collect(),
      keep.into_iter().cloned().collect(),
    )
  })
}

/// 部署过、但配置里已经没有的服务：(服务, 最后部署在的服务器)。
/// 删除服务时配置先提交，删容器那步失败了，靠它在下次 plan 时接着清理。
fn leftovers<'a>(
  deployed: &'a BTreeMap<String, String>,
  current: &'a World,
  desired: &'a World,
) -> impl Iterator<Item = (&'a str, &'a str)> {
  deployed
    .iter()
    .filter(|(name, _)| {
      !current.services.contains_key(*name)
        && !desired.services.contains_key(*name)
    })
    .map(|(n, s)| (n.as_str(), s.as_str()))
}

/// 上次删除没做完：项目目录（Wharf 的部署指纹）还在。别人同名的项目没有指纹，不碰。
fn leftover_items(
  b: &mut Builder,
  deployed: &BTreeMap<String, String>,
  current: &World,
  desired: &World,
  status: &StatusMap,
) {
  for (name, server) in leftovers(deployed, current, desired) {
    let Some(Some(projects)) = status.get(server) else {
      continue;
    };
    let Some(state) = projects.get(name).filter(|s| s.hash.is_some())
    else {
      continue;
    };
    let id = b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Container,
      Action::Delete,
      Some(
        json!({ "server": server, "containers": state.containers }),
      ),
      None,
      vec![Impact::Remove],
      "上次删除没有完成，停止并删除留下的容器（数据目录保留）",
    );
    b.step(
      vec![id],
      format!("在 {server} 上删除 {name}"),
      Step::ServiceDown {
        server: server.to_string(),
        service: name.to_string(),
        purge_data: false,
      },
    );
  }
}
