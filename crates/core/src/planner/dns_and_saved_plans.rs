async fn dns_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  scope: Option<&BTreeSet<String>>,
) -> Result<(), ApiError> {
  let in_scope = |h: &str| scope.is_none_or(|s| s.contains(h));
  let edge_ids: Vec<String> = desired
    .edge_apps
    .values()
    .flat_map(|a| {
      a.spec.domains.iter().map(|d| crate::world::edge_owner(d))
    })
    .collect();
  let live_ids: BTreeSet<&str> = desired
    .routes
    .values()
    .map(|r| r.id.as_str())
    .chain(edge_ids.iter().map(String::as_str))
    .collect();
  // 已删除路由留下的记录。
  for owned in &snap.owned {
    if live_ids.contains(owned.route_id.as_str()) {
      continue;
    }
    let id = b.item(
      format!("{KIND_ROUTE}/{}", owned.hostname),
      Layer::Dns,
      Action::Delete,
      Some(json!({ "account": owned.account, "remote_id": owned.remote_id })),
      None,
      vec![Impact::Remove],
      "删除路由留下的 DNS 记录",
    );
    b.step(
      vec![id],
      format!("删除 {} 的 DNS 记录", owned.hostname),
      Step::DnsDelete {
        hostname: owned.hostname.clone(),
        account: owned.account.clone(),
        remote: RemoteRef {
          scope: owned.scope.clone(),
          remote_id: owned.remote_id.clone(),
        },
        owner: Some(owned.route_id.clone()),
      },
    );
  }

  for (host, route) in &desired.routes {
    if !in_scope(host) {
      continue;
    }
    if let Some(warning) = plaintext_hop(desired, net, &route.spec) {
      b.warnings.push(format!("路由 {host}：{warning}"));
    }
  }

  // 代理路由，加上 Pages 的自定义域名；Workers 的由厂商连同 DNS 一起管，见 edge_plan。
  let mut targets: Vec<DnsTarget> = desired
    .routes
    .iter()
    .filter(|(host, _)| in_scope(host))
    .map(|(host, r)| (host.clone(), r.id.clone(), None))
    .collect();
  for (name, app) in &desired.edge_apps {
    if app.spec.kind != EdgeKind::Pages {
      continue;
    }
    for d in app.spec.domains.iter().filter(|d| in_scope(d)) {
      targets.push((
        d.clone(),
        crate::world::edge_owner(d),
        Some((name.as_str(), &app.spec)),
      ));
    }
  }
  // 各域名的 DNS 记录并发读取：从国内逐个请求厂商 API 很慢。
  let mut fetched: BTreeMap<
    String,
    Result<Vec<RemoteRecord>, ApiError>,
  > = futures_util::future::join_all(targets.iter().filter_map(
    |(host, _, _)| {
      let (account, _) = snap.account_for(host)?;
      let provider = snapshot::dns_provider(account).ok()?;
      Some(async move {
        let records = snapshot::with_timeout(
          &format!("读取 {host} 的 DNS 记录"),
          provider.list(host),
        )
        .await;
        (host.clone(), records)
      })
    },
  ))
  .await
  .into_iter()
  .collect();
  for (host, owner_id, edge) in targets {
    let host = &host;
    let Some((account, _zone)) = snap.account_for(host) else {
      b.warnings.push(format!(
        "没有厂商账号管理 {host} 所在的域名，DNS 需要自己配置（或执行 wharf account add）"
      ));
      continue;
    };
    let spec = match edge {
      Some((name, app)) => {
        crate::edge_plan::pages_record(snap, name, app).await?
      }
      None => desired_record(snap, desired, net, host)?,
    };
    let provider = snapshot::dns_provider(account)?;
    let want = spec.to_provider();
    if spec.content != TUNNEL_PENDING {
      provider
        .validate(host, &want)
        .map_err(snapshot::provider_error)?;
    }
    let records = match fetched.remove(host) {
      Some(records) => records?,
      None => {
        snapshot::with_timeout(
          &format!("读取 {host} 的 DNS 记录"),
          provider.list(host),
        )
        .await?
      }
    };
    let owner = wharf_providers::Owner {
      id: owner_id.clone(),
    };
    let (ours, foreign): (Vec<&RemoteRecord>, Vec<&RemoteRecord>) =
      records.iter().partition(|r| provider.is_owned(r, &owner));
    let canonical = want.canonical();
    let address = format!("{KIND_ROUTE}/{host}");
    let after = Some(canonical.clone());
    let upsert = |existing: Option<&RemoteRecord>,
                  extra: Vec<RemoteRef>| {
      Step::DnsUpsert {
        hostname: host.clone(),
        account: account.name.clone(),
        spec: spec.clone(),
        existing: existing.map(remote_ref),
        extra,
      }
    };
    let title = format!("写入 {host} 的 DNS 记录");
    if !foreign.is_empty() {
      let mut targets: Vec<&RemoteRecord> = ours.clone();
      targets.extend(foreign.iter().copied());
      let existing = targets[0];
      let extra =
        targets[1..].iter().map(|r| remote_ref(r)).collect();
      let id = b.item(
        address,
        Layer::Dns,
        Action::Adopt,
        Some(json!(
          foreign
            .iter()
            .map(|r| r.canonical.clone())
            .collect::<Vec<_>>()
        )),
        after,
        vec![Impact::Overwrite],
        format!(
          "{host} 已有 {} 条不是 Wharf 创建的记录，接管会覆盖{}",
          foreign.len(),
          if targets.len() > 1 {
            "并删除多余记录"
          } else {
            ""
          }
        ),
      );
      b.step(vec![id], title, upsert(Some(existing), extra));
      continue;
    }
    match ours.as_slice() {
      [] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Create,
          None,
          after,
          if edge.is_some() {
            vec![Impact::Public]
          } else {
            vec![]
          },
          if edge.is_some() {
            "新增边缘应用自定义域名的公网 DNS 记录".into()
          } else {
            format!("新建 {} 记录", spec.record_type)
          },
        );
        b.step(vec![id], title, upsert(None, vec![]));
      }
      [only] if only.canonical == canonical => {}
      [first, rest @ ..] => {
        let id = b.item(
          address,
          Layer::Dns,
          Action::Update,
          Some(first.canonical.clone()),
          after,
          vec![Impact::Restart],
          if first.canonical == canonical {
            "删除重复的记录".to_string()
          } else {
            "记录内容变化".to_string()
          },
        );
        let extra = rest.iter().map(|r| remote_ref(r)).collect();
        b.step(vec![id], title, upsert(Some(first), extra));
      }
    }
  }
  Ok(())
}

/// 保存计划。
pub async fn save(
  state: &AppState,
  planned: &Planned,
) -> Result<(), ApiError> {
  let id = planned.plan.plan_id.clone();
  let mut body =
    serde_json::to_value(&planned.plan).map_err(db::json_err)?;
  body["account_refs"] = json!(&planned.account_refs);
  body["host_access_checked"] = json!(true);
  body["host_requirements"] = json!(&planned.host_requirements);
  if !planned.route_effects.is_empty() {
    body["route_effects"] = json!(&planned.route_effects);
  }
  let body = body.to_string();
  let steps =
    serde_json::to_string(&planned.steps).map_err(db::json_err)?;
  let writes =
    serde_json::to_string(&planned.writes).map_err(db::json_err)?;
  let created = planned.plan.created_at.timestamp_millis();
  let expires = planned.plan.expires_at.timestamp_millis();
  state
    .db
    .call(move |c| {
      // 只保留最近的计划。
      c.execute(
        "DELETE FROM plans WHERE created_at < ?1",
        rusqlite::params![db::now_ms() - 7 * 24 * 3600 * 1000],
      )
      .map_err(db::sql_err)?;
      c.execute(
        "INSERT INTO plans (id, status, body, steps, writes, created_at, expires_at)
         VALUES (?1, 'pending', ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, body, steps, writes, created, expires],
      )
      .map_err(db::sql_err)?;
      Ok(())
    })
    .await
}

/// 网关跨机器访问服务、而服务所在机器的内网地址不加密时，返回提醒。
fn plaintext_hop(
  world: &World,
  net: &Net,
  route: &RouteSpec,
) -> Option<String> {
  let gateway = world.gateways.get(world.route_gateway(route)?)?;
  let server = &world.services.get(&route.service)?.spec.server;
  if &gateway.spec.server == server {
    return None;
  }
  let addr = net.private.get(server)?;
  (!addr.network.encrypted()).then(|| {
    format!(
      "网关（{}）到服务（{server}）这一段走内网直连 {}，是明文",
      gateway.spec.server, addr.ip
    )
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::world::{RouteRow, ServerRow, ServiceRow};
  use wharf_api_types::{agent::ContainerInfo, spec::Limits};

  #[test]
  fn internal_route_points_to_private_ip() {
    let snap = Snapshot::default();
    let mut w = world();
    w.gateways.insert(
      "edge".into(),
      crate::world::GatewayRow {
        spec: serde_json::from_value(
          json!({"kind":"caddy", "server":"s1"}),
        )
        .unwrap(),
        version: 1,
      },
    );
    w.routes.insert("i.example.com".into(), crate::world::RouteRow {
      id:"r1".into(), spec:serde_json::from_value(json!({"hostname":"i.example.com", "service":"app", "gateway":"edge"})).unwrap(), version:1,
    });
    let mut net = Net::default();
    net.public_ip.insert("s1".into(), "203.0.113.1".into());
    net.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "100.64.0.1".into(),
        network: wharf_api_types::spec::PrivateNetwork::Tailscale,
      },
    );
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap()
        .content,
      "203.0.113.1"
    );
    w.routes.get_mut("i.example.com").unwrap().spec.internal = true;
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap()
        .content,
      "100.64.0.1"
    );
    net.private.clear();
    assert_eq!(
      desired_record(&snap, &w, &net, "i.example.com")
        .unwrap_err()
        .message,
      "路由 i.example.com 只在内网访问，但入口 edge 所在的 s1 没有内网地址"
    );
  }

  #[test]
  fn names_only_changed_components() {
    let old = "services:\n  web:\n    image: a\n  worker:\n    image: w:1\n  db:\n    image: pg\n";
    let new = "services:\n  web:\n    image: a\n  worker:\n    image: w:2\n  db:\n    image: pg\n";
    let (redo, keep) = changed_components(old, new).unwrap();
    assert_eq!(redo, vec!["worker"]);
    assert_eq!(keep, vec!["db", "web"]);
    assert!(changed_components(new, new).is_none());
  }

  #[test]
  fn cleans_up_unfinished_deletes() {
    let deployed = BTreeMap::from([
      ("half".to_string(), "s1".to_string()),
      ("done".to_string(), "s1".to_string()),
    ]);
    let state = |hash: Option<&str>| ProjectState {
      project: String::new(),
      hash: hash.map(str::to_string),
      config_hash: None,
      containers: vec![],
    };
    let status = StatusMap::from([(
      "s1".to_string(),
      Some(BTreeMap::from([
        ("half".to_string(), state(Some("h"))),
        // 删干净了，或者是别人同名的项目：没有 Wharf 的指纹。
        ("done".to_string(), state(None)),
      ])),
    )]);
    let world = World::default();
    let mut b = Builder::default();
    leftover_items(&mut b, &deployed, &world, &world, &status);
    let found: Vec<&str> =
      b.items.iter().map(|i| i.address.as_str()).collect();
    assert_eq!(found, ["service/half"]);
    assert!(b.items[0].needs_confirm());
  }

  /// 一台 s1，一个 image 服务 app（nginx:1，端口 80）。
  fn world() -> World {
    let spec = serde_json::from_value(json!({
      "server": "s1",
      "source": {"image": "nginx:1"},
      "ports": [{"name": "http", "container": 80}],
    }))
    .unwrap();
    let mut world = World::default();
    world.servers.insert(
      "s1".to_string(),
      ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    world.services.insert(
      "app".to_string(),
      ServiceRow {
        spec,
        host_ports: BTreeMap::from([("http".to_string(), 21000)]),
        import: None,
        pins: BTreeMap::new(),
        commit: None,
        version: 1,
      },
    );
    world
  }

  fn container(state: &str) -> ContainerInfo {
    ContainerInfo {
      service: "app".into(),
      name: "app-app-1".into(),
      state: state.into(),
      status: String::new(),
      health: None,
      image: String::new(),
      foreign: false,
      working_dir: None,
      finished_at: None,
    }
  }

  /// s1 上 app 的现状。`hash` 为 None 表示不是 Wharf 部署的。
  fn live(
    hash: Option<String>,
    containers: Vec<ContainerInfo>,
  ) -> StatusMap {
    StatusMap::from([(
      "s1".to_string(),
      Some(BTreeMap::from([(
        "app".to_string(),
        ProjectState {
          project: "app".into(),
          hash,
          config_hash: None,
          containers,
        },
      )])),
    )])
  }

  fn hash_of(w: &World) -> String {
    snapshot::service_resolved(
      w,
      &Net::default(),
      "app",
      &BTreeMap::new(),
    )
    .unwrap()
    .1
  }

  /// 跑一次 service_items，返回生成的计划项。
  fn plan(
    current: &World,
    desired: &World,
    status: &StatusMap,
  ) -> Builder {
    let mut b = Builder::default();
    let writes = desired.writes_from(current);
    service_items(
      &mut b,
      &Snapshot {
        world: current.clone(),
        ..Snapshot::default()
      },
      current,
      desired,
      &Net::default(),
      status,
      &writes,
    )
    .unwrap();
    b
  }

  #[test]
  fn no_change_no_item() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some(hash_of(&w)), vec![container("running")]),
    );
    assert!(b.items.is_empty());
  }

  #[test]
  fn new_service_creates() {
    let desired = world();
    let mut current = desired.clone();
    current.services.clear();
    let status =
      StatusMap::from([("s1".into(), Some(BTreeMap::new()))]);
    let b = plan(&current, &desired, &status);
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Create);
    assert!(b.items[0].impacts.is_empty());
    assert!(b.items[0].reason.contains("部署新服务"));
  }

  #[test]
  fn config_change_restarts() {
    let current = world();
    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&current)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("配置变化"));
  }

  #[test]
  fn plan_warns_only_for_service_being_redeployed() {
    let mut current = world();
    let changed_password = concat!("fixture", "-changed");
    let idle_password = concat!("fixture", "-idle");
    let app = current.services.get_mut("app").unwrap();
    app
      .spec
      .env
      .insert("DB_PASSWORD".into(), changed_password.into());
    let mut idle = app.clone();
    idle.host_ports.insert("http".into(), 21001);
    idle
      .spec
      .env
      .insert("DB_PASSWORD".into(), idle_password.into());
    current.services.insert("idle".into(), idle);

    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let mut status =
      live(Some(hash_of(&current)), vec![container("running")]);
    let (_, idle_hash) = snapshot::service_resolved(
      &current,
      &Net::default(),
      "idle",
      &BTreeMap::new(),
    )
    .unwrap();
    status.get_mut("s1").unwrap().as_mut().unwrap().insert(
      "idle".into(),
      ProjectState {
        project: "idle".into(),
        hash: Some(idle_hash),
        config_hash: None,
        containers: vec![container("running")],
      },
    );
    let b = plan(&current, &desired, &status);
    let snap = Snapshot {
      world: current,
      ..Snapshot::default()
    };
    let planned =
      finish_plan(&snap, &desired, b, vec![], BTreeSet::new(), None);
    assert_eq!(planned.plan.items.len(), 1);
    assert_eq!(planned.plan.warnings.len(), 1);
    let warning = &planned.plan.warnings[0];
    assert!(warning.contains("服务 app 的 env 变量 DB_PASSWORD"));
    assert!(!warning.contains("服务 idle"));
    assert!(
      !warning.contains(changed_password)
        && !warning.contains(idle_password)
    );
  }

  #[test]
  fn drift_redeploys() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some("old".into()), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("漂移"));
  }

  #[test]
  fn stopped_container_is_drift() {
    let w = world();
    let b = plan(
      &w,
      &w,
      &live(Some(hash_of(&w)), vec![container("exited")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("容器没在运行"));
  }

  #[test]
  fn stop_keeps_containers() {
    let current = world();
    let mut desired = current.clone();
    desired.services.get_mut("app").unwrap().spec.stopped = true;
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&desired)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Downtime]);
    assert!(b.items[0].reason.contains("停止服务"));
    assert!(matches!(b.steps[0].step, Step::ServiceStop { .. }));
  }

  #[test]
  fn unreachable_server() {
    let current = world();
    let mut desired = current.clone();
    desired
      .services
      .get_mut("app")
      .unwrap()
      .spec
      .env
      .insert("MODE".into(), "new".into());
    let status = StatusMap::from([("s1".into(), None)]);
    let b = plan(&current, &desired, &status);
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(b.items[0].reason.contains("无法读取现状"));
    assert!(plan(&current, &current, &status).items.is_empty());
  }

  #[test]
  fn foreign_project_overwrites() {
    let desired = world();
    let mut current = desired.clone();
    current.services.clear();
    let b = plan(
      &current,
      &desired,
      &live(None, vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert!(b.items[0].impacts.contains(&Impact::Overwrite));
    assert!(b.items[0].needs_confirm());
  }

  #[test]
  fn foreign_container_warns() {
    let w = world();
    let mut c = container("running");
    c.foreign = true;
    let b = plan(&w, &w, &live(Some("old".into()), vec![c]));
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert!(b.items[0].impacts.contains(&Impact::Overwrite));
    assert!(b.items[0].reason.contains("会删除它们"));
  }

  #[test]
  fn remove_keeps_data() {
    let current = world();
    let mut desired = current.clone();
    desired.services.clear();
    let b = plan(&current, &desired, &StatusMap::new());
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Delete);
    assert_eq!(b.items[0].impacts, vec![Impact::Remove]);
    assert!(b.items[0].needs_confirm());
    assert!(matches!(
      b.steps[0].step,
      Step::ServiceDown {
        purge_data: false,
        ..
      }
    ));
  }

  #[test]
  fn limits_change_restarts() {
    let current = world();
    let mut desired = current.clone();
    desired.services.get_mut("app").unwrap().spec.limits =
      Some(Limits {
        memory_mb: Some(256),
        cpu_milli: None,
      });
    let b = plan(
      &current,
      &desired,
      &live(Some(hash_of(&current)), vec![container("running")]),
    );
    assert_eq!(b.items.len(), 1);
    assert_eq!(b.items[0].action, Action::Update);
    assert_eq!(b.items[0].impacts, vec![Impact::Restart]);
    assert!(hash_of(&current) != hash_of(&desired));
  }

  #[test]
  fn route_impacts() {
    let current = world();
    let mut desired = current.clone();
    desired.routes.insert(
      "a.example.com".into(),
      RouteRow {
        id: "a".into(),
        spec: serde_json::from_value(json!({
          "hostname": "a.example.com",
          "service": "app"
        }))
        .unwrap(),
        version: 1,
      },
    );
    desired.routes.insert(
      "b.example.com".into(),
      RouteRow {
        id: "b".into(),
        spec: serde_json::from_value(json!({
          "hostname": "b.example.com",
          "redirect": "https://a.example.com"
        }))
        .unwrap(),
        version: 1,
      },
    );
    let mut b = Builder::default();
    config_items(
      &mut b,
      &current,
      &desired,
      &desired.writes_from(&current),
    );
    let a = b
      .items
      .iter()
      .find(|i| i.address == "route/a.example.com")
      .unwrap();
    let redirect = b
      .items
      .iter()
      .find(|i| i.address == "route/b.example.com")
      .unwrap();
    assert!(a.impacts.contains(&Impact::Public));
    assert!(redirect.impacts.is_empty());
    assert!(redirect.reason.contains("新增跳转"));
  }
  #[test]
  fn removing_gate_requires_public_confirmation() {
    let mut current = world();
    current.routes.insert("a.example.com".into(),RouteRow{id:"a".into(),version:1,spec:serde_json::from_value(json!({"hostname":"a.example.com","service":"app","sso":{"mode":"gate"}})).unwrap()});
    let mut desired = current.clone();
    desired.routes.get_mut("a.example.com").unwrap().spec.sso = None;
    let mut b = Builder::default();
    config_items(
      &mut b,
      &current,
      &desired,
      &desired.writes_from(&current),
    );
    assert_eq!(b.items[0].impacts, vec![Impact::Public]);
    assert_eq!(b.items[0].reason, "去掉门禁后这个域名对公网开放");
  }
}
