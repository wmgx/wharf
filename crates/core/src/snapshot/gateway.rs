use super::*;

/// 网关的 compose、Caddyfile，以及它承载的站点。
pub struct GatewayRender {
  /// cloudflare_tunnel 的 compose 里 token 是占位，执行时才替换。
  pub compose: String,
  pub compose_hash: String,
  /// caddy：Caddyfile；cloudflare_tunnel：入口规则（JSON）。
  pub config: String,
  pub config_hash: String,
  pub sites: Vec<render::Site>,
  pub needs_acme_dns: bool,
  pub needs_link_cert: bool,
  pub extra_files: BTreeMap<String, String>,
}

impl GatewayRender {
  /// 下发内容的指纹：compose 和配置各自的 hash 一起再算一次。
  pub fn fingerprint(&self) -> String {
    render::hash(&format!(
      "{} {}",
      self.compose_hash, self.config_hash
    ))
  }

  /// 隧道的入口规则：`(hostname, http://上游)`。
  pub fn tunnel_rules(&self) -> Vec<(String, String)> {
    self
      .sites
      .iter()
      .map(|s| (s.hostname.clone(), format!("http://{}", s.upstream)))
      .collect()
  }
}

/// 给人看的网关配置：不带出登录保护的密码哈希。
pub fn redacted_config(config: &str, net: &Net) -> String {
  net
    .basic_auth
    .values()
    .fold(config.to_string(), |c, a| c.replace(&a.hash, "<bcrypt>"))
}

pub fn gateway_render(
  world: &World,
  net: &Net,
  name: &str,
) -> Result<GatewayRender, ApiError> {
  gateway_render_with_fill(
    world,
    net,
    name,
    render::CaddyFill::default(),
  )
}

pub fn gateway_render_with_fill(
  world: &World,
  net: &Net,
  name: &str,
  fill: render::CaddyFill<'_>,
) -> Result<GatewayRender, ApiError> {
  let gateway = world.gateways.get(name).ok_or_else(|| {
    ApiError::not_found(format!("网关 {name} 不存在"))
  })?;
  let mut sites = Vec::new();
  for (host, route) in &world.routes {
    if !world.route_gateways(&route.spec).contains(&name) {
      continue;
    }
    let protection = crate::entry_protection::SiteProtection::new(
      world,
      net,
      &gateway.spec,
      host,
      &route.spec,
    )?;
    if let Some(target) = &route.spec.redirect {
      sites.push(render::Site {
        protection,
        hostname: host.clone(),
        upstream: String::new(),
        auth: None,
        paths: Vec::new(),
        redirect: Some(target.clone()),
        ..Default::default()
      });
      continue;
    }
    let tunnel = gateway.spec.kind == GatewayKind::CloudflareTunnel;
    if route.spec.auth && tunnel {
      return Err(ApiError::invalid(format!(
        "路由 {host}：cloudflare_tunnel 网关还不支持登录保护，换 caddy 网关或去掉 --auth"
      )));
    }
    if route.spec.auth && net.auth_for(host).is_none() {
      return Err(
        ApiError::invalid(format!(
          "路由 {host} 开启了登录保护，但还没有设置账号"
        ))
        .with_hint(
          "值写成 用户名:密码，从标准输入读取，不会出现在命令行里",
        )
        .suggest(format!(
          "wharf secret set {}",
          render::route_auth_secret(host)
        )),
      );
    }
    if tunnel && !route.spec.paths.is_empty() {
      return Err(ApiError::invalid(format!(
        "路由 {host}：按路径转发只支持 caddy 网关"
      )));
    }
    let mut paths = Vec::new();
    for p in &route.spec.paths {
      let upstream = match (&p.service, &p.upstream) {
        (_, Some(up)) => up.clone(),
        (Some(svc), None) => {
          let port = world
            .service_port(svc, p.port.as_deref())
            .ok_or_else(|| {
              ApiError::invalid(format!(
                "路由 {host} 的路径 {} 没有可用的端口",
                p.path
              ))
            })?;
          render::upstream(
            world,
            net,
            &gateway.spec,
            svc,
            port,
            route.spec.link,
          )?
        }
        (None, None) => continue,
      };
      paths.push((p.path.clone(), upstream));
    }
    let gate = route
      .spec
      .sso
      .as_ref()
      .map(|sso| {
        let login = net
          .gate_login
          .as_ref()
          .filter(|u| u.starts_with("https://"))
          .ok_or_else(|| {
            ApiError::invalid("控制面还没有公网域名，开不了门禁")
              .with_hint("先给控制面加一个域名")
          })?;
        let url = reqwest::Url::parse(login).map_err(|_| {
          ApiError::invalid("控制面还没有公网域名，开不了门禁")
        })?;
        if url.host_str() == Some(host.as_str())
          || crate::gate::is_core_host(world, net, host)
        {
          return Err(ApiError::invalid(
            "控制面自己的域名不能开门禁",
          ));
        }
        let core = url
          .host_str()
          .and_then(|h| world.routes.get(h))
          .filter(|r| world.route_gateways(&r.spec).contains(&name))
          .map(|r| {
            world.route_upstream(
              net,
              &gateway.spec,
              &r.spec.hostname,
              &r.spec,
            )
          })
          .transpose()?
          .map(|u| format!("http://{u}"))
          .unwrap_or_else(|| login.clone());
        Ok(render::Gate {
          public: sso.public,
          site_endpoints: crate::gate::site_endpoints(sso),
          app_login: sso.mode
            == wharf_api_types::spec::SsoMode::Login,
          user_header: (sso.mode
            == wharf_api_types::spec::SsoMode::Header)
            .then(|| {
              sso
                .header
                .clone()
                .unwrap_or_else(|| "Remote-User".into())
            }),
          trusted: if sso.trust_internal {
            crate::gate::trusted_ranges(net, &gateway.spec.server)
          } else {
            vec![]
          },
          login: login.clone(),
          core,
          skip_paths: sso.skip_paths.clone(),
          takeover: sso.login.as_ref().and_then(|login| {
            login.takeover.clone().map(|takeover| {
              (takeover, login.entry.as_deref().unwrap_or("/").into())
            })
          }),
        })
      })
      .transpose()?;
    sites.push(render::Site {
      protection,
      gate,
      wildcard: false,
      internal: route.spec.internal,
      internal_ranges: if route.spec.internal {
        crate::source_trust::internal_route_ranges(
          net,
          &gateway.spec.server,
        )
      } else {
        vec![]
      },
      expires_at: route.spec.expires_at,
      dns: (route.spec.internal
        && gateway.spec.tls == GatewayTls::Auto
        && !host.split_once('.').is_some_and(|(_, zone)| {
          gateway.spec.wildcard.iter().any(|z| z == zone)
        }))
      .then(|| host.clone()),
      rate_limit: route.spec.rate_limit,
      block_scanners: route.spec.block_scanners,
      custom: route
        .spec
        .caddy
        .clone()
        .filter(|c| !c.trim().is_empty()),
      redirect: None,
      paths,
      auth: route
        .spec
        .auth
        .then(|| net.auth_for(host).cloned())
        .flatten(),
      hostname: host.clone(),
      upstream: world.route_upstream(
        net,
        &gateway.spec,
        host,
        &route.spec,
      )?,
    });
  }
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  let mut needs_acme_dns = false;
  let needs_link_cert = gateway.spec.kind == GatewayKind::Caddy
    && crate::link::caddy_site(world, net, name, &gateway.spec)?;
  let (compose, config) = match gateway.spec.kind {
    GatewayKind::Caddy => {
      let mut forwards = Vec::new();
      for f in &gateway.spec.layer4 {
        let upstream = if let Some(up) = &f.upstream {
          up.clone()
        } else if let Some(svc) = &f.service {
          let port = world
            .service_port(svc, f.port.as_deref())
            .ok_or_else(|| {
              ApiError::invalid(format!(
                "入口 {name} 的四层转发 {}：找不到服务 {svc} 的端口",
                f.listen
              ))
            })?;
          let host = world.services[svc]
            .host_ports
            .get(port)
            .ok_or_else(|| {
              ApiError::internal(format!(
                "服务 {svc} 的端口 {port} 没有分配"
              ))
            })?;
          match crate::link::choose(world, net, &gateway.spec, svc, wharf_api_types::spec::LinkMode::Auto)? {
            crate::link::Choice::Local => format!("127.0.0.1:{host}"),
            crate::link::Choice::Direct(ip) => format!("{ip}:{host}"),
            crate::link::Choice::Tunnel => return Err(ApiError::invalid(format!("入口 {name} 的四层转发 {}：入口所在机器连不到 {svc} 所在机器的内网地址，四层转发不支持反向隧道", f.listen)).with_hint(format!("让两台机器在同一个组网里，或者在 {svc} 所在的机器上建入口"))),
          }
        } else {
          return Err(ApiError::invalid(format!(
            "入口 {name} 的四层转发 {}：服务和上游二选一",
            f.listen
          )));
        };
        forwards.push((f.udp, f.listen, upstream));
      }
      forwards.sort_by_key(|(udp, listen, _)| (*udp, *listen));
      let mut caddy_sites = sites.clone();
      for zone in &gateway.spec.wildcard {
        caddy_sites.push(render::Site {
          hostname: format!("*.{zone}"),
          wildcard: true,
          dns: (gateway.spec.tls == GatewayTls::Auto)
            .then(|| zone.clone()),
          ..Default::default()
        });
      }
      needs_acme_dns = caddy_sites.iter().any(|s| s.dns.is_some());
      (
        render::gateway_compose(name, &gateway.spec),
        render::caddyfile_with_fill(
          name,
          &gateway.spec,
          &caddy_sites,
          &forwards,
          needs_link_cert,
          net.gate_public.as_deref(),
          &crate::source_trust::gateway_trusted_proxies(
            world,
            net,
            &gateway.spec,
            &net.cloudflare_ips,
          ),
          fill,
        ),
      )
    }
    GatewayKind::CloudflareTunnel => {
      let rules: Vec<serde_json::Value> = sites
        .iter()
        .map(|s| {
          serde_json::json!({
            "hostname": s.hostname,
            "service": format!("http://{}", s.upstream),
          })
        })
        .collect();
      (
        render::tunnel_compose(name, &gateway.spec, None),
        serde_json::to_string_pretty(&rules).unwrap_or_default(),
      )
    }
  };
  let config_hash = if needs_link_cert {
    let tag = match net.link_certs.get(name) {
      Some(cert)
        if !crate::link_cert::needs_renew(
          cert.expires_at,
          chrono::Utc::now(),
        ) =>
      {
        cert.fingerprint.as_str()
      }
      Some(_) => "renew",
      None => "pending",
    };
    crate::link_cert::config_hash(&config, tag)
  } else {
    render::hash(&config)
  };
  Ok(GatewayRender {
    compose_hash: render::hash(&compose),
    config_hash,
    compose,
    config,
    sites,
    needs_acme_dns,
    needs_link_cert,
    extra_files: BTreeMap::new(),
  })
}
