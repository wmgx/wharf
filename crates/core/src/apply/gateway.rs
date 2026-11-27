use wharf_api_types::{ApiError, spec::GatewaySpec};

use crate::{
  db,
  gate::revocations,
  render::{self, Net},
  snapshot::{self, GatewayRender},
  state::AppState,
  world::World,
};

pub(super) async fn caddyfile_for_apply(
  state: &AppState,
  run_id: &str,
  world: &World,
  net: &Net,
  gateway: &str,
  mut rendered: GatewayRender,
) -> Result<GatewayRender, ApiError> {
  if rendered.needs_link_cert {
    let server = &world.gateways[gateway].spec.server;
    crate::link_cert::require_gateway_agent(
      &state.hub, server, gateway,
    )?;
    let pair =
      ensure_link_certificate(state, run_id, gateway).await?;
    fill_link_certificate(&mut rendered, pair);
  }
  let acme = if rendered.needs_acme_dns {
    Some(
      acme_credentials(
        state,
        run_id,
        world,
        gateway,
        &world.gateways[gateway].spec,
        &rendered,
        net.acme_dns_url.as_deref(),
      )
      .await?,
    )
  } else {
    None
  };
  let revocation_key =
    if rendered.sites.iter().any(|site| site.gate.is_some()) {
      Some(revocations::config_key(&state.db).await?)
    } else {
      None
    };
  if acme.is_some() || revocation_key.is_some() {
    let fill = render::CaddyFill {
      acme_dns_url: None,
      acme_dns: acme
        .as_ref()
        .map(|(key, url)| render::AcmeDnsFill { key, url }),
      gate_revocation_key: revocation_key.as_deref(),
    };
    rendered.config =
      snapshot::gateway_render_with_fill(world, net, gateway, fill)?
        .config;
  }
  Ok(rendered)
}

async fn ensure_link_certificate(
  state: &AppState,
  run_id: &str,
  gateway: &str,
) -> Result<crate::link_cert::CertPair, ApiError> {
  let gateway = gateway.to_string();
  let run_id = run_id.to_string();
  state
    .db
    .call_credentials(move |c, key| {
      super::record_retry_changes(c, key, &run_id, |tx| {
        crate::link_cert::ensure_gateway_cert(
          tx,
          key,
          &gateway,
          db::now_ms(),
          false,
        )
      })
    })
    .await
}

pub(super) fn fill_link_certificate(
  r: &mut GatewayRender,
  pair: crate::link_cert::CertPair,
) {
  let fingerprint =
    crate::link_cert::fingerprint(&pair.cert, &pair.key);
  r.config_hash =
    crate::link_cert::config_hash(&r.config, &fingerprint);
  r.extra_files.insert("link.crt".into(), pair.cert);
  r.extra_files.insert("link.key".into(), pair.key);
}

async fn acme_credentials(
  state: &AppState,
  run_id: &str,
  world: &World,
  gateway: &str,
  spec: &GatewaySpec,
  r: &GatewayRender,
  url: Option<&str>,
) -> Result<(String, String), ApiError> {
  let name = crate::acme_dns::secret_name(gateway);
  let url = url.ok_or_else(|| {
    ApiError::invalid(format!(
      "控制面没有对外地址，入口 {gateway} 做 DNS 验证时要连回控制面"
    ))
    .with_hint("用 --public-url 启动控制面，或者给控制面加一个域名")
  })?;
  if let Ok(parsed) = reqwest::Url::parse(url)
    && let Some(host) = parsed.host_str()
    && world.routes.get(host).is_some_and(|route| {
      world.route_gateways(&route.spec).contains(&gateway)
    })
    && let Some((_, zone)) = host.split_once('.')
    && spec.wildcard.iter().any(|z| z == zone)
  {
    return Err(ApiError::invalid(format!("控制面的域名 {host} 在入口 {gateway} 的泛域名证书 *.{zone} 下，开了以后签证书时连不回控制面")).with_hint("用 --public-url 给控制面指定一个不经过这个入口的地址，或者把控制面的域名换到别的 zone"));
  }
  if let Ok(parsed) = reqwest::Url::parse(url)
    && let Some(host) = parsed.host_str()
    && world.routes.get(host).is_some_and(|route| {
      route.spec.internal
        && world.route_gateways(&route.spec).contains(&gateway)
    })
    && r
      .sites
      .iter()
      .any(|site| site.hostname == host && site.dns.is_some())
  {
    return Err(ApiError::invalid(format!("控制面的域名 {host} 是内网域名，证书要用 DNS 验证签，签的时候连不回控制面")).with_hint("用 --public-url 给控制面指定一个不经过这个入口的地址，或者把控制面的域名换到别的 zone"));
  }
  let run_id = run_id.to_string();
  let key = state
    .db
    .call_credentials(move |c, key| {
      super::record_retry_changes(c, key, &run_id, |tx| {
        db::ensure_secret(tx, key, &name, db::now_ms())
      })
    })
    .await?;
  crate::caddy_validate::validate_acme_dns_fill(&key, url)?;
  Ok((key, url.to_string()))
}
