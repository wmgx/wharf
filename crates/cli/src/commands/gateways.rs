/// 目录名转成服务名：小写，非字母数字换成 `-`。
fn dir_name(dir: &std::path::Path) -> CliResult<String> {
  let abs = std::fs::canonicalize(dir).map_err(|e| {
    ApiError::invalid(format!("{}：{e}", dir.display()))
  })?;
  let raw = abs
    .file_name()
    .map(|n| n.to_string_lossy().to_lowercase())
    .unwrap_or_default();
  let mut name: String = raw
    .chars()
    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
    .collect();
  name = name.trim_matches('-').to_string();
  while name.contains("--") {
    name = name.replace("--", "-");
  }
  name.truncate(48);
  if name.is_empty() {
    return Err(
      ApiError::invalid("从目录名取不出服务名，请用 --name 指定")
        .into(),
    );
  }
  Ok(name)
}

/// 只有一台已加入的服务器时自动选它。
async fn pick_server(c: &Client) -> CliResult<String> {
  let servers: Vec<ServerView> = c.get("/api/servers").await?;
  let joined: Vec<&ServerView> =
    servers.iter().filter(|s| s.joined).collect();
  match joined.as_slice() {
    [only] => Ok(only.name.clone()),
    [] => Err(
      ApiError::invalid("还没有已加入的服务器")
        .suggest("wharf server add <name>")
        .into(),
    ),
    many => Err(
      ApiError::invalid(format!(
        "有多台服务器，请用 --server 指定：{}",
        many
          .iter()
          .map(|s| s.name.as_str())
          .collect::<Vec<_>>()
          .join("、")
      ))
      .into(),
    ),
  }
}

// GATEWAYS / ROUTES

pub(crate) fn fmt_ms(ms: i64) -> String {
  chrono::DateTime::from_timestamp_millis(ms)
    .map(|t| {
      t.with_timezone(&chrono::Local)
        .format("%m-%d %H:%M")
        .to_string()
    })
    .unwrap_or_default()
}

async fn gateway(
  c: &Client,
  cmd: GatewayCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    GatewayCmd::List => {
      let v: Vec<GatewayView> = c.get("/api/gateways").await?;
      out(j, &v, |v| {
        for g in v {
          println!(
            "{:<14} {:<8} {}{}  路由 {}",
            g.name,
            g.spec.server,
            g.spec.kind.as_str(),
            if g.spec.default { "（默认）" } else { "" },
            g.routes.join(" ")
          );
        }
      });
      Ok(())
    }
    GatewayCmd::Show { name } => {
      let v: GatewayView =
        c.get(&format!("/api/gateways/{}", seg(&name))).await?;
      out(j, &v, pretty);
      Ok(())
    }
    GatewayCmd::Config { name } => {
      let v: Value = c
        .get(&format!("/api/gateways/{}/config", seg(&name)))
        .await?;
      out(j, &v, |v| {
        println!(
          "# Caddyfile\n{}",
          v["caddyfile"].as_str().unwrap_or_default()
        );
        println!(
          "# compose.yaml\n{}",
          v["compose"].as_str().unwrap_or_default()
        );
      });
      Ok(())
    }
    GatewayCmd::RotateLink {
      name,
      token,
      cert,
      apply,
      ..
    } => {
      let both = !token && !cert;
      let response =
        c.rotate_link(&name, token || both, cert || both).await?;
      if apply.apply {
        if !j {
          print::rotate_link(&response);
        }
        plan_and_maybe_apply(c, PlanRequest::default(), apply, j)
          .await
      } else {
        out(j, &response, print::rotate_link);
        Ok(())
      }
    }
    GatewayCmd::Logs(args) => {
      crate::access_logs::gateway(c, args, j).await
    }
    GatewayCmd::ErrorPage {
      name, file, apply, ..
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      spec.error_page = match file {
        None => None,
        Some(path) => Some(
          (if path == "-" {
            std::io::read_to_string(std::io::stdin())
          } else {
            std::fs::read_to_string(&path)
          })
          .map_err(|e| {
            ApiError::invalid(format!("读不了文件 {path}：{e}"))
              .with_hint("检查路径；从标准输入读用 --file -")
          })?,
        ),
      };
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Wildcard {
      name,
      zone,
      off,
      apply,
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      let zone =
        zone.trim().trim_end_matches('.').to_ascii_lowercase();
      if off {
        spec.wildcard.retain(|z| z != &zone);
      } else if !spec.wildcard.contains(&zone) {
        spec.wildcard.push(zone);
      }
      spec.wildcard.sort();
      spec.wildcard.dedup();
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Timeouts(args) => {
      entry_protection::timeouts(c, args, j).await
    }
    GatewayCmd::TrustedProxies {
      name,
      cloudflare,
      cluster,
      add,
      rm,
      off,
      apply,
    } => {
      use wharf_api_types::trusted_proxies::parse_cidr;

      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      if cloudflare.is_none()
        && cluster.is_none()
        && add.is_empty()
        && rm.is_empty()
        && !off
      {
        out(j, &spec.trusted_proxies, pretty);
        return Ok(());
      }
      if off {
        spec.trusted_proxies = None;
      } else {
        let mut proxies =
          spec.trusted_proxies.take().unwrap_or_default();
        proxies.cloudflare = cloudflare.unwrap_or(proxies.cloudflare);
        proxies.cluster = cluster.unwrap_or(proxies.cluster);
        proxies.normalize()?;
        for cidr in add {
          let cidr = parse_cidr(&cidr)?.to_string();
          if !proxies.cidrs.contains(&cidr) {
            proxies.cidrs.push(cidr);
          }
        }
        for cidr in rm {
          let cidr = parse_cidr(&cidr)?.to_string();
          proxies.cidrs.retain(|current| current != &cidr);
        }
        proxies.normalize()?;
        spec.trusted_proxies =
          (!proxies.is_empty()).then_some(proxies);
      }
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Forward {
      name,
      listen,
      udp,
      service,
      port,
      upstream,
      rm,
      apply,
    } => {
      let mut spec = c
        .get::<GatewayView>(&format!("/api/gateways/{}", seg(&name)))
        .await?
        .spec;
      let before = spec.layer4.len();
      spec.layer4.retain(|f| f.listen != listen || f.udp != udp);
      if rm {
        if before == spec.layer4.len() {
          let protocol = if udp { "UDP 端口" } else { "端口" };
          return Err(
            ApiError::invalid(format!(
              "入口 {name} 上没有{protocol} {listen} 的四层转发"
            ))
            .into(),
          );
        }
      } else {
        if service.is_none() && upstream.is_none() {
          return Err(
            ApiError::invalid("要给 --service 或 --upstream").into(),
          );
        }
        spec.layer4.push(wharf_api_types::spec::Layer4Forward {
          listen,
          udp,
          service,
          port,
          upstream,
        });
      }
      spec.layer4.sort_by_key(|f| (f.udp, f.listen));
      changes(c, vec![Change::UpsertGateway { name, spec }], apply, j)
        .await
    }
    GatewayCmd::Add {
      name,
      server,
      kind,
      account,
      default,
      http_port,
      https_port,
      email,
      image,
      tls,
      apply,
    } => {
      let gateways: Vec<GatewayView> = c.get("/api/gateways").await?;
      let old =
        gateways.iter().find(|g| g.name == name).map(|g| &g.spec);
      let kind = kind.map(|k| match k.as_str() {
        "cloudflare_tunnel" => GatewayKind::CloudflareTunnel,
        _ => GatewayKind::Caddy,
      });
      let tls = tls.map(|t| match t.as_str() {
        "internal" => GatewayTls::Internal,
        "off" => GatewayTls::Off,
        _ => GatewayTls::Auto,
      });
      let spec = match old {
        Some(old) => {
          if kind.is_some_and(|k| k != old.kind) {
            return Err(
              ApiError::invalid("不能改入口类型，删掉重建")
                .suggest(format!("wharf gateway rm {name}"))
                .into(),
            );
          }
          GatewaySpec {
            server: server.unwrap_or_else(|| old.server.clone()),
            default: default || old.default,
            http_port: http_port.or(old.http_port),
            https_port: https_port.or(old.https_port),
            email: email.or_else(|| old.email.clone()),
            image: image.or_else(|| old.image.clone()),
            tls: tls.unwrap_or(old.tls),
            account: account.or_else(|| old.account.clone()),
            ..old.clone()
          }
        }
        None => {
          let server = server.ok_or_else(|| {
            ApiError::invalid("新入口要给 --server").suggest(format!(
              "wharf gateway add {name} --server <服务器>"
            ))
          })?;
          let kind = kind.unwrap_or(GatewayKind::Caddy);
          // 隧道网关只有一个厂商账号时自动选它。
          let account = match (kind, account) {
            (GatewayKind::CloudflareTunnel, None) => {
              let accounts: Vec<AccountView> =
                c.get("/api/accounts").await?;
              match accounts.as_slice() {
                [only] => Some(only.name.clone()),
                [] => {
                  return Err(
                    ApiError::invalid(
                      "还没有厂商账号，隧道要建在账号下",
                    )
                    .suggest("wharf account add cf --kind cloudflare")
                    .into(),
                  );
                }
                _ => {
                  return Err(
                    ApiError::invalid(
                      "有多个厂商账号，请用 --account 指定",
                    )
                    .suggest("wharf account list")
                    .into(),
                  );
                }
              }
            }
            (_, account) => account,
          };
          GatewaySpec {
            kind,
            server,
            default,
            http_port,
            https_port,
            email,
            image,
            tls: tls.unwrap_or_default(),
            account,
            error_page: None,
            wildcard: vec![],
            layer4: vec![],
            trusted_proxies: None,
            read_header_timeout: None,
            idle_timeout: None,
            grace_period: None,
          }
        }
      };
      // 默认入口只能有一个：设了新的，同一个计划里取消旧的。
      let mut list = Vec::new();
      if default {
        for g in
          gateways.iter().filter(|g| g.name != name && g.spec.default)
        {
          list.push(Change::UpsertGateway {
            name: g.name.clone(),
            spec: GatewaySpec {
              default: false,
              ..g.spec.clone()
            },
          });
        }
      }
      list.push(Change::UpsertGateway { name, spec });
      changes(c, list, apply, j).await
    }
    GatewayCmd::Rm { name, apply } => {
      changes(c, vec![Change::RemoveGateway { name }], apply, j).await
    }
  }
}
