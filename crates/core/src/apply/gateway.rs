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
  world: &World,
  net: &Net,
  gateway: &str,
  mut rendered: GatewayRender,
) -> Result<GatewayRender, ApiError> {
  let acme = if rendered.needs_acme_dns {
    Some(
      acme_credentials(
        state,
        world,
        gateway,
        &world.gateways[gateway].spec,
        &rendered,
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

async fn acme_credentials(
  state: &AppState,
  world: &World,
  gateway: &str,
  spec: &GatewaySpec,
  r: &GatewayRender,
) -> Result<(String, String), ApiError> {
  let name = crate::acme_dns::secret_name(gateway);
  let url =
    crate::join::default_url(state).await.ok_or_else(|| {
      ApiError::invalid(format!(
        "控制面没有对外地址，入口 {gateway} 做 DNS 验证时要连回控制面"
      ))
      .with_hint("用 --public-url 启动控制面，或者给控制面加一个域名")
    })?;
  if let Ok(parsed) = reqwest::Url::parse(&url)
    && let Some(host) = parsed.host_str()
    && world.routes.get(host).is_some_and(|route| {
      world.route_gateway(&route.spec) == Some(gateway)
    })
    && let Some((_, zone)) = host.split_once('.')
    && spec.wildcard.iter().any(|z| z == zone)
  {
    return Err(ApiError::invalid(format!("控制面的域名 {host} 在入口 {gateway} 的泛域名证书 *.{zone} 下，开了以后签证书时连不回控制面")).with_hint("用 --public-url 给控制面指定一个不经过这个入口的地址，或者把控制面的域名换到别的 zone"));
  }
  if let Ok(parsed) = reqwest::Url::parse(&url)
    && let Some(host) = parsed.host_str()
    && world.routes.get(host).is_some_and(|route| {
      route.spec.internal
        && world.route_gateway(&route.spec) == Some(gateway)
    })
    && r
      .sites
      .iter()
      .any(|site| site.hostname == host && site.dns.is_some())
  {
    return Err(ApiError::invalid(format!("控制面的域名 {host} 是内网域名，证书要用 DNS 验证签，签的时候连不回控制面")).with_hint("用 --public-url 给控制面指定一个不经过这个入口的地址，或者把控制面的域名换到别的 zone"));
  }
  let key = state
    .db
    .call_credentials(move |c, key| {
      db::ensure_secret(c, key, &name, db::now_ms())
    })
    .await?;
  crate::caddy_validate::validate_acme_dns_fill(&key, &url)?;
  Ok((key, url))
}
