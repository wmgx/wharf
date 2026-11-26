/// 迁移数据的计划项和步骤，以及相关提醒。
fn move_items(
  b: &mut Builder,
  current: &World,
  name: &str,
  from: &str,
  to: &str,
  net: &Net,
) {
  let old = &current.services[name];
  let mounts = crate::data::mounts(name, &old.spec);
  let left: Vec<String> = mounts
    .iter()
    .filter(|m| m.kind != DataKind::Managed)
    .map(crate::data::describe)
    .collect();
  // 不归 Wharf 管的数据不会跟着走，新服务器上的服务看不到它们，要用户确认。
  if !left.is_empty() {
    b.item(
      format!("{KIND_SERVICE}/{name}"),
      Layer::Volume,
      Action::Update,
      None,
      None,
      vec![Impact::DataLoss],
      format!(
        "{} 不归 Wharf 管，不会迁移到 {to}：迁移后服务看不到这些数据",
        left.join("、")
      ),
    );
  }
  // 没有 Wharf 管理的数据：没有要搬的，新容器起来、网关切过去即可，不停服。
  if !mounts.iter().any(|m| m.kind == DataKind::Managed) {
    return;
  }
  let id = b.item(
    format!("{KIND_SERVICE}/{name}"),
    Layer::Volume,
    Action::Update,
    Some(json!({ "server": from, "dir": format!("/srv/{name}/") })),
    Some(json!({ "server": to, "dir": format!("/srv/{name}/") })),
    vec![Impact::Downtime],
    format!("迁移 /srv/{name}/ 从 {from} 到 {to}：先同步一遍，再停掉旧容器做增量同步，这段时间服务不可用"),
  );
  b.step(
    vec![id],
    format!("迁移 {name} 的数据 {from} → {to}"),
    Step::VolumeSync {
      service: name.to_string(),
      from: from.to_string(),
      to: to.to_string(),
    },
  );
  for (server, role) in [(from, "源"), (to, "目标")] {
    match net.private.get(server) {
      None => b.warnings.push(format!(
        "迁移 {name} 需要{role}服务器 {server} 的内网地址，执行时会失败：先 wharf server set {server} --private-ip <ip>"
      )),
      Some(addr) if !addr.network.encrypted() && role == "目标" => {
        b.warnings.push(format!(
          "迁移 {name} 的数据走内网直连 {from} → {to}，是明文"
        ))
      }
      _ => {}
    }
  }
  b.warnings.push(format!(
    "迁移后 {from} 上的 /srv/{name}/ 保留 7 天，之后自动删除（期间迁回 {from} 就不删）"
  ));
}

/// 网关上次应用的配置哈希：caddy 由 agent 上报，隧道的规则在厂商那边，记在控制面里。
fn applied_config<'a>(
  snap: &'a Snapshot,
  gateway: &str,
  kind: GatewayKind,
  state: &'a ProjectState,
) -> Option<&'a str> {
  match kind {
    GatewayKind::Caddy => state.config_hash.as_deref(),
    GatewayKind::CloudflareTunnel => {
      snap.tunnels.get(gateway).map(|t| t.config_hash.as_str())
    }
  }
}

/// 反向隧道的 frps / frpc：按路由算出该有哪些，和现状比对。
fn link_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
) -> Result<(), ApiError> {
  let want =
    crate::link::projects_with_secrets(desired, net, &snap.secrets)?;
  for p in &want {
    // 查不到现状的服务器已经单独提醒过。
    let Some(Some(projects)) = status.get(&p.server) else {
      continue;
    };
    let decision = match projects.get(&p.project) {
      Some(s) if !(s.hash.is_none() && s.containers.is_empty()) => {
        if s.hash.as_deref() != Some(p.hash.as_str()) {
          Some((
            Action::Update,
            vec![Impact::Restart],
            format!(
              "{}（配置变化，重建，经这条隧道的路由会断几秒）",
              p.summary
            ),
          ))
        } else if !s.all_running() {
          Some((
            Action::Update,
            vec![Impact::Restart],
            format!(
              "漂移：隧道容器没在运行（{}）",
              describe_containers(s)
            ),
          ))
        } else {
          None
        }
      }
      _ => Some((Action::Create, vec![], p.summary.clone())),
    };
    let Some((action, risk, reason)) = decision else {
      continue;
    };
    let id = b.item(
      format!("link/{}/{}", p.server, p.project),
      Layer::Gateway,
      action,
      None,
      Some(json!({ "server": p.server, "summary": p.summary })),
      risk,
      reason,
    );
    b.step(
      vec![id],
      format!("在 {} 上部署 {}", p.server, p.project),
      Step::LinkUp {
        server: p.server.clone(),
        project: p.project.clone(),
      },
    );
  }
  for p in crate::link::projects(current, net).unwrap_or_default() {
    if want
      .iter()
      .any(|w| w.server == p.server && w.project == p.project)
    {
      continue;
    }
    let exists = status
      .get(&p.server)
      .and_then(|s| s.as_ref())
      .and_then(|s| s.get(&p.project))
      .is_some_and(|s| !s.containers.is_empty());
    if !exists {
      continue;
    }
    let id = b.item(
      format!("link/{}/{}", p.server, p.project),
      Layer::Gateway,
      Action::Delete,
      Some(json!({ "server": p.server, "summary": p.summary })),
      None,
      vec![Impact::Remove],
      "没有路由再用这条隧道，停止并删除",
    );
    b.step(
      vec![id],
      format!("在 {} 上删除 {}", p.server, p.project),
      Step::LinkDown {
        server: p.server.clone(),
        project: p.project,
      },
    );
  }
  Ok(())
}

/// 出口设置变了（自己的规则、经哪台、那台的规则）：让这台的 agent 重新起出口和本地分流。
/// 排在 dockerd 代理前面，那边要用本机的分流代理。
fn egress_items(b: &mut Builder, current: &World, desired: &World) {
  use crate::egress::effective;
  for server in desired.servers.keys() {
    let after = effective(server, desired);
    let before = effective(server, current);
    if after == before {
      continue;
    }
    let show = |e: &Option<(
      Option<wharf_api_types::egress::EgressSpec>,
      Option<String>,
      Option<wharf_api_types::egress::EgressSpec>,
    )>| {
      e.as_ref().map(|(own, via, rules)| {
        json!({ "egress": own, "via": via, "via_rules": rules })
      })
    };
    let mut what = Vec::new();
    if let Some((own, via, _)) = &after {
      if let Some(o) = own {
        what.push(if o.all {
          "给其他机器当外网代理（所有网站）".to_string()
        } else {
          format!(
            "给其他机器当外网代理（{} 个域名）",
            o.domains().len()
          )
        });
      }
      if let Some(v) = via {
        what.push(format!(
          "访问外网借 {v}（只转发规则里的网站，{v} 不通时直连）"
        ));
      }
    }
    let reason = if what.is_empty() {
      format!("{server} 不再当外网代理或借道，相关请求改为直连")
    } else {
      format!("{server}：{}", what.join("；"))
    };
    let id = b.item(
      format!("egress/{server}"),
      Layer::Container,
      match (&before, &after) {
        (None, _) => Action::Create,
        (_, None) => Action::Delete,
        _ => Action::Update,
      },
      show(&before),
      show(&after),
      vec![],
      reason,
    );
    b.step(
      vec![id],
      format!("更新 {server} 的外网代理"),
      Step::Egress {
        server: server.clone(),
      },
    );
  }
}

/// 机器基线：设置改了，或者最近一次检查有差异时，加一步纠正。
fn baseline_items(b: &mut Builder, current: &World, desired: &World) {
  for (server, row) in &desired.servers {
    let want = &row.settings.baseline;
    if want.is_empty() {
      continue;
    }
    let before =
      current.servers.get(server).map(|r| &r.settings.baseline);
    let drift = crate::baseline::drift(server);
    if before == Some(want) && drift.is_empty() {
      continue;
    }
    let reason = if drift.is_empty() {
      "按新的基线检查并纠正系统设置".to_string()
    } else {
      drift.join("；")
    };
    let id = b.item(
      format!("baseline/{server}"),
      Layer::Container,
      Action::Update,
      before.map(|b| json!(b)),
      Some(json!(want)),
      vec![],
      reason,
    );
    b.step(
      vec![id],
      format!("纠正 {server} 的基线"),
      Step::Baseline {
        server: server.clone(),
      },
    );
  }
}

/// Wharf 管理的 Tailscale 容器：要的时候起，接入方式改掉之后删。
/// 拉镜像代理的设置（或它要直连的镜像源）变了：改 dockerd 配置。
fn docker_proxy_items(
  b: &mut Builder,
  current: &World,
  desired: &World,
) {
  use crate::docker_proxy::wanted;
  for (server, row) in &desired.servers {
    let after = wanted(&row.settings);
    let before = current
      .servers
      .get(server)
      .and_then(|r| wanted(&r.settings));
    if after == before {
      continue;
    }
    let (reason, title) = match &after {
      Some((proxy, _)) => (
        format!(
          "拉镜像改走{}，镜像源和内网直连；重启 dockerd，开启 live-restore 后容器不停",
          shown(proxy)
        ),
        format!("在 {server} 上给 dockerd 配拉镜像代理"),
      ),
      None => (
        "去掉拉镜像代理，重启 dockerd（开启 live-restore，容器不停）"
          .to_string(),
        format!("在 {server} 上去掉 dockerd 的拉镜像代理"),
      ),
    };
    let id = b.item(
      format!("docker/{server}"),
      Layer::Container,
      if before.is_none() {
        Action::Create
      } else if after.is_none() {
        Action::Delete
      } else {
        Action::Update
      },
      before
        .map(|(p, n)| json!({ "proxy": shown(&p), "no_proxy": n })),
      after
        .map(|(p, n)| json!({ "proxy": shown(&p), "no_proxy": n })),
      vec![Impact::Restart],
      reason,
    );
    b.step(
      vec![id],
      title,
      Step::DockerProxy {
        server: server.clone(),
      },
    );
  }
}

/// 代理地址给人看的样子。
fn shown(value: &str) -> String {
  if value == crate::egress::local_url() {
    "本机分流代理（按借道规则）".into()
  } else {
    format!("代理 {value}")
  }
}

fn tailscale_items(
  b: &mut Builder,
  snap: &Snapshot,
  desired: &World,
  status: &StatusMap,
) {
  use crate::tailscale::{self as ts, PROJECT};
  for server in desired.servers.keys() {
    // 查不到现状的服务器已经单独提醒过。
    let Some(Some(projects)) = status.get(server) else {
      continue;
    };
    let existing = projects
      .get(PROJECT)
      .filter(|s| !(s.hash.is_none() && s.containers.is_empty()));
    let address = format!("network/{server}/tailscale");
    if !ts::wanted(snap, desired, server, existing.is_some()) {
      if existing.is_some() {
        let id = b.item(
          address,
          Layer::Tunnel,
          Action::Delete,
          Some(json!({ "server": server })),
          None,
          vec![Impact::Remove],
          "接入方式不再是 tailscale，删除 Wharf 装的 Tailscale（机器会留在 Tailscale 后台，显示离线）",
        );
        b.step(
          vec![id],
          format!("在 {server} 上删除 Tailscale"),
          Step::LinkDown {
            server: server.clone(),
            project: PROJECT.to_string(),
          },
        );
      }
      continue;
    }
    let hash = ts::hash(server);
    let decision = match existing {
      None => Some((
        Action::Create,
        vec![],
        format!("没检测到 Tailscale，起容器并以 {} 加入", ts::TAG),
      )),
      Some(s) if s.hash.as_deref() != Some(hash.as_str()) => Some((
        Action::Update,
        vec![Impact::Restart],
        "Tailscale 容器配置变化，重建（不会重新加入）".to_string(),
      )),
      Some(s) if !s.all_running() => Some((
        Action::Update,
        vec![Impact::Restart],
        format!(
          "漂移：Tailscale 容器没在运行（{}）",
          describe_containers(s)
        ),
      )),
      Some(_) => None,
    };
    let Some((action, risk, reason)) = decision else {
      continue;
    };
    let id = b.item(
      address,
      Layer::Tunnel,
      action,
      None,
      Some(json!({ "server": server, "image": ts::IMAGE })),
      risk,
      reason,
    );
    b.step(
      vec![id],
      format!("在 {server} 上部署 Tailscale"),
      Step::TailscaleUp {
        server: server.clone(),
      },
    );
  }
}

fn gateway_items(
  b: &mut Builder,
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
  status: &StatusMap,
  hub: &crate::hub::Hub,
) -> Result<(), ApiError> {
  for name in desired.gateways.keys() {
    let gw = &desired.gateways[name];
    if gw.spec.kind == GatewayKind::Caddy {
      for zone in &gw.spec.wildcard {
        if current
          .gateways
          .get(name)
          .is_some_and(|g| g.spec.wildcard.contains(zone))
        {
          continue;
        }
        if gw.spec.tls == GatewayTls::Auto
          && snap.account_for(zone).is_none()
        {
          return Err(ApiError::invalid(format!(
                        "入口 {name} 的泛域名证书 *.{zone}：没有厂商账号管理 {zone}"
                    ))
                    .suggest("wharf account list"));
        }
        b.warnings.push(format!("入口 {name} 开启 *.{zone} 的泛域名证书：这个入口上 {zone} 下一级的域名都改用这张证书，签出来之前（DNS 验证通常几十秒）这些域名的 HTTPS 打不开（验证记录由控制面写）"));
      }
    }
    if gw.spec.kind == GatewayKind::Caddy
      && gw.spec.tls == GatewayTls::Auto
    {
      for (host, route) in &desired.routes {
        if desired.route_gateway(&route.spec) == Some(name.as_str())
          && route.spec.internal
          && !host.split_once('.').is_some_and(|(_, zone)| {
            gw.spec.wildcard.iter().any(|z| z == zone)
          })
          && snap.account_for(host).is_none()
        {
          b.warnings.push(format!("内网域名 {host} 的证书要用 DNS 验证签，但没有厂商账号管理它，证书签不出来"));
        }
      }
    }
    let server = &gw.spec.server;
    let project = gateway_project(name);
    let r = snapshot::gateway_render(desired, net, name)?;
    let online = hub.is_online(server);
    if r.needs_link_cert && online {
      crate::link_cert::require_gateway_agent(hub, server, name)?;
    }
    let after = Some(json!({
      "server": server,
      "sites": r.sites.iter().map(|s| json!({ "hostname": s.hostname, "upstream": s.upstream })).collect::<Vec<_>>(),
      "config": snapshot::redacted_config(&r.config, net),
    }));
    let decision = match status.get(server).and_then(|s| s.as_ref()) {
      // 查不到现状时，只有配置变了才计划（服务器离线已经单独提醒过）。
      None => {
        let same = current.gateways.get(name)
          == desired.gateways.get(name)
          && gateway_sites_same(current, desired, net, name);
        (!same).then(|| {
          (
            Action::Update,
            vec![Impact::Restart],
            "无法读取现状，按新配置应用".to_string(),
          )
        })
      }
      Some(projects) => match projects.get(&project) {
        Some(s) if s.hash.is_none() && s.containers.is_empty() => {
          Some((Action::Create, vec![], "部署网关".to_string()))
        }
        None => {
          Some((Action::Create, vec![], "部署网关".to_string()))
        }
        Some(s)
          if s.hash.as_deref() != Some(r.compose_hash.as_str()) =>
        {
          Some((
            Action::Update,
            vec![Impact::Restart],
            "网关容器配置变化，重建".to_string(),
          ))
        }
        Some(s) if !s.all_running() => Some((
          Action::Update,
          vec![Impact::Restart],
          format!(
            "漂移：网关容器没在运行（{}）",
            describe_containers(s)
          ),
        )),
        Some(s)
          if applied_config(snap, name, gw.spec.kind, s)
            != Some(r.config_hash.as_str()) =>
        {
          Some((
            Action::Update,
            vec![],
            match gw.spec.kind {
              GatewayKind::Caddy if r.needs_link_cert => {
                let now = chrono::Utc::now();
                match net
                  .link_certs
                  .get(name)
                  .and_then(|cert| cert.expires_at)
                {
                  Some(at)
                    if crate::link_cert::needs_renew(
                      Some(at),
                      now,
                    ) =>
                  {
                    let days = crate::link_cert::days_left(at, now);
                    if days <= 0 {
                      "隧道叶证书已过期，续签并热重载配置".into()
                    } else {
                      format!(
                        "隧道叶证书将于 {days} 天后到期，续签并热重载配置"
                      )
                    }
                  }
                  _ if gateway_sites_same(
                    current, desired, net, name,
                  ) =>
                  {
                    "隧道证书变化，热重载配置".into()
                  }
                  _ => "路由变化，热重载配置".into(),
                }
              }
              GatewayKind::Caddy => "路由变化，热重载配置".into(),
              GatewayKind::CloudflareTunnel => {
                "路由变化，更新隧道入口规则".into()
              }
            },
          ))
        }
        Some(_) => None,
      },
    };
    if let Some((action, mut risk, reason)) = decision {
      if r.needs_link_cert && !online {
        b.warnings.push(format!("服务器 {server} 离线，无法确认网关 {name} 的 agent 能下发隧道证书"));
      }
      if gw.spec.kind == GatewayKind::Caddy {
        for f in &gw.spec.layer4 {
          if current
            .gateways
            .get(name)
            .is_some_and(|g| g.spec.layer4.contains(f))
          {
            continue;
          }
          if !risk.contains(&Impact::Public) {
            risk.push(Impact::Public);
          }
          let protocol = if f.udp { "UDP" } else { "TCP" };
          let listen = f.listen;
          b.warnings.push(format!("入口 {name} 在 {server} 上对公网开放 {protocol} 端口 {listen}（四层转发，没有登录保护）；云厂商的安全组、机器的防火墙要自己放行"));
        }
      }
      let (layer, reason) = match gw.spec.kind {
        GatewayKind::Caddy => (Layer::Gateway, reason),
        GatewayKind::CloudflareTunnel
          if !snap.tunnels.contains_key(name) =>
        {
          (
            Layer::Tunnel,
            format!(
              "在账号 {} 下创建隧道 {}，部署 cloudflared",
              gw.spec.account.as_deref().unwrap_or_default(),
              crate::tunnel::tunnel_name(name)
            ),
          )
        }
        GatewayKind::CloudflareTunnel => (Layer::Tunnel, reason),
      };
      let routes = if gw.spec.kind == GatewayKind::Caddy
        && action == Action::Update
        && risk.is_empty()
        && current.gateways.get(name) == Some(gw)
        && let Some(hash) = status
          .get(server)
          .and_then(Option::as_ref)
          .and_then(|p| p.get(&project))
          .and_then(|s| s.config_hash.as_deref())
      {
        crate::token_scope::gateway_routes(
          &b.items, current, desired, net, name, hash,
        )
      } else {
        vec![]
      };
      let id = b.item(
        format!("{KIND_GATEWAY}/{name}"),
        layer,
        action,
        None,
        after,
        risk,
        reason,
      );
      if !routes.is_empty() {
        b.route_effects.insert(id, routes);
      }
      b.step(
        vec![id],
        format!("在 {server} 上应用网关 {name}"),
        Step::GatewaySync {
          gateway: name.clone(),
          expect: (gw.spec.kind == GatewayKind::Caddy)
            .then(|| r.fingerprint()),
        },
      );
    }
  }
  for (name, gw) in &current.gateways {
    if desired.gateways.contains_key(name) {
      continue;
    }
    let server = &gw.spec.server;
    let id = b.item(
      format!("{KIND_GATEWAY}/{name}"),
      Layer::Gateway,
      Action::Delete,
      Some(json!({ "server": server })),
      None,
      vec![Impact::Remove, Impact::Downtime],
      "停止并删除网关容器",
    );
    b.step(
      vec![id],
      format!("在 {server} 上删除网关 {name}"),
      Step::GatewayDown {
        server: server.clone(),
        gateway: name.clone(),
      },
    );
  }
  Ok(())
}

fn gateway_sites_same(
  current: &World,
  desired: &World,
  net: &Net,
  name: &str,
) -> bool {
  let a = snapshot::gateway_render(current, net, name).ok();
  let b = snapshot::gateway_render(desired, net, name).ok();
  matches!((a, b), (Some(a), Some(b)) if a.config_hash == b.config_hash)
}

/// 路由期望的 DNS 记录。
pub(crate) fn desired_record(
  snap: &Snapshot,
  desired: &World,
  net: &Net,
  hostname: &str,
) -> Result<DnsSpec, ApiError> {
  let route = &desired.routes[hostname];
  let gateway = desired
    .live_gateway(hostname, &route.spec)
    .unwrap_or_default();
  let gw = &desired.gateways[gateway].spec;
  if gw.kind == GatewayKind::CloudflareTunnel {
    return Ok(DnsSpec {
      record_type: "CNAME".into(),
      content: snap
        .tunnels
        .get(gateway)
        .map(|t| tunnel_target(&t.tunnel_id))
        .unwrap_or_else(|| TUNNEL_PENDING.into()),
      proxied: true,
      tunnel: Some(gateway.to_string()),
    });
  }
  let server = &gw.server;
  let ip = if route.spec.internal {
    net.private.get(server).map(|a| &a.ip).ok_or_else(|| {
      ApiError::invalid(format!("路由 {hostname} 只在内网访问，但入口 {gateway} 所在的 {server} 没有内网地址"))
        .with_hint("装好组网或手动指定内网地址")
        .suggest(format!("wharf server set {server} --private-ip <ip>"))
    })?
  } else {
    net.public_ip.get(server).ok_or_else(|| {
    ApiError::invalid(format!(
      "网关 {gateway} 所在的服务器 {server} 没有公网 IP，{hostname} 的 DNS 无处可指"
    ))
    .with_hint("agent 没探测到公网 IP 时，可以手动设置")
    .suggest(format!("wharf server set {server} --public-ip <ip>"))
  })?
  };
  let record_type = if ip.parse::<std::net::Ipv6Addr>().is_ok() {
    "AAAA"
  } else {
    "A"
  };
  Ok(DnsSpec {
    record_type: record_type.to_string(),
    content: ip.clone(),
    proxied: false,
    tunnel: None,
  })
}

fn remote_ref(r: &RemoteRecord) -> RemoteRef {
  RemoteRef {
    scope: r.scope.clone(),
    remote_id: r.remote_id.clone(),
  }
}

/// 要写 DNS 的域名、记录所有者，Pages 域名还带上边缘应用。
type DnsTarget<'a> =
  (String, String, Option<(&'a str, &'a EdgeAppSpec)>);

/// 这次改动会让 DNS 期望值变化的域名：新增或改了的路由、指向变了的路由、改了的 Pages。
fn affected_hosts(
  snap: &Snapshot,
  current: &World,
  desired: &World,
  net: &Net,
) -> BTreeSet<String> {
  let mut out: BTreeSet<String> = desired
    .routes
    .iter()
    .filter(|(host, r)| {
      current.routes.get(*host).is_none_or(|c| c != *r)
        || desired_record(snap, current, net, host).ok()
          != desired_record(snap, desired, net, host).ok()
    })
    .map(|(h, _)| h.clone())
    .collect();
  for (name, app) in &desired.edge_apps {
    if current
      .edge_apps
      .get(name)
      .is_none_or(|c| c.spec != app.spec)
    {
      out.extend(app.spec.domains.iter().cloned());
    }
  }
  out
}
