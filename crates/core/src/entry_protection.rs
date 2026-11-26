use std::fmt::Write;

use wharf_api_types::{
  ApiError,
  spec::{GatewayKind, GatewaySpec, GatewayTls, RouteSpec},
  tunnel::TUNNEL_PATH,
};

use crate::{
  render::{Net, Site},
  world::World,
};

pub(crate) fn validate_gateway(
  name: &str,
  spec: &GatewaySpec,
) -> Result<(), ApiError> {
  if spec.kind != GatewayKind::Caddy
    && [
      spec.read_header_timeout,
      spec.idle_timeout,
      spec.grace_period,
    ]
    .iter()
    .any(Option::is_some)
  {
    return Err(ApiError::invalid(format!(
      "网关 {name}：连接超时和重载宽限只支持 Caddy 网关"
    )));
  }
  if spec.read_header_timeout == Some(0)
    || spec.idle_timeout == Some(0)
  {
    return Err(ApiError::invalid(format!(
      "网关 {name}：读请求头和空闲超时至少为 1 秒"
    )));
  }
  Ok(())
}

pub(crate) fn validate_route(
  world: &World,
  host: &str,
  spec: &RouteSpec,
) -> Result<(), ApiError> {
  if (spec.cf_origin_only || spec.core_mesh_only)
    && world.route_gateways(spec).iter().any(|name| {
      world
        .gateways
        .get(*name)
        .is_some_and(|g| g.spec.kind != GatewayKind::Caddy)
    })
  {
    return Err(ApiError::invalid(format!(
      "路由 {host}：仅允许 Cloudflare 回源和控制面组网限制只支持 Caddy 网关"
    )));
  }
  Ok(())
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SiteProtection {
  core_ranges: Vec<String>,
  cf_ranges: Option<Vec<String>>,
  use_client_ip: bool,
}

impl SiteProtection {
  pub(crate) fn new(
    world: &World,
    net: &Net,
    gateway: &GatewaySpec,
    host: &str,
    spec: &RouteSpec,
  ) -> Result<Self, ApiError> {
    validate_route(world, host, spec)?;
    if spec.core_mesh_only
      && !crate::gate::is_core_host(world, net, host)
    {
      return Err(ApiError::invalid(format!(
        "路由 {host}：控制面组网限制只能用在指向控制面的路由"
      )));
    }
    Ok(Self {
      core_ranges: if spec.core_mesh_only {
        crate::source_trust::internal_route_ranges(
          net,
          &gateway.server,
        )
      } else {
        vec![]
      },
      cf_ranges: spec
        .cf_origin_only
        .then(|| net.cloudflare_ips.clone()),
      use_client_ip: spec.core_mesh_only
        && gateway.trusted_proxies.is_some(),
    })
  }

  fn enabled(&self) -> bool {
    !self.core_ranges.is_empty() || self.cf_ranges.is_some()
  }

  pub(crate) fn render_matchers(&self, out: &mut String) {
    if let Some(ranges) = &self.cf_ranges {
      if ranges.is_empty() {
        out.push_str("\tabort\n");
      } else {
        writeln!(
          out,
          "\t@wharf_non_cf not remote_ip {}\n\tabort @wharf_non_cf",
          ranges.join(" ")
        )
        .unwrap();
      }
    }
    if !self.core_ranges.is_empty() {
      let matcher = if self.use_client_ip {
        "client_ip"
      } else {
        "remote_ip"
      };
      writeln!(
        out,
        "\t@wharf_core_outside {{\n\t\tnot {matcher} {}\n\t\tnot expression `{{http.request.uri}}.matches('^({})([?].*)?$')`\n\t}}\n\tabort @wharf_core_outside",
        self.core_ranges.join(" "),
        core_public_paths(),
      ).unwrap();
    }
  }

  pub(crate) fn render_http_redirect(
    &self,
    out: &mut String,
    spec: &GatewaySpec,
    hostname: &str,
  ) {
    if self.enabled() && spec.tls != GatewayTls::Off {
      let port = spec
        .https_port
        .filter(|p| *p != 443)
        .map_or_else(String::new, |p| format!(":{p}"));
      writeln!(out, "\nhttp://{hostname} {{").unwrap();
      self.render_matchers(out);
      writeln!(
        out,
        "\tredir https://{hostname}{port}{{uri}} 308\n}}"
      )
      .unwrap();
    }
  }
}

fn core_public_paths() -> String {
  // 使用原始 URI，避免 Caddy 与 Axum 的解码或路径归一化差异放行页面。
  [
    TUNNEL_PATH,
    "/agent/(ws|join|acme-dns/update|uploads/[0-9a-f]{64})",
    "/(join[.]sh|cli[.]sh|skill[.]md|healthz)",
    "/gate/(key|login|refresh|revocations|site/(login|gate|logout))",
    "/[.]well-known/openid-configuration",
    "/oidc/(jwks|authorize|token|userinfo|logout)",
    "/(hook|notify)/[a-zA-Z0-9_-]+",
    "/ping/[a-zA-Z0-9_-]+(/fail)?",
  ]
  .join("|")
}

pub(crate) fn render_abort_order(out: &mut String, sites: &[Site]) {
  if sites.iter().any(|s| s.protection.enabled()) {
    out.push_str("\torder abort first\n");
  } else if sites.iter().any(|s| s.internal || s.expires_at.is_some())
  {
    out.push_str("\torder abort before basic_auth\n");
  }
}

pub(crate) fn render_servers(
  out: &mut String,
  spec: &GatewaySpec,
  trusted_proxies: &[String],
) {
  writeln!(
    out,
    "\tgrace_period {}s\n\tservers {{",
    spec.grace_period.unwrap_or(10)
  )
  .unwrap();
  crate::source_trust::render_proxy_options(out, trusted_proxies);
  let idle = spec
    .idle_timeout
    .map_or_else(|| "2m".into(), |seconds| format!("{seconds}s"));
  writeln!(
    out,
    "\t\ttimeouts {{\n\t\t\tread_header {}s\n\t\t\tidle {idle}\n\t\t}}\n\t}}",
    spec.read_header_timeout.unwrap_or(10),
  ).unwrap();
}

pub(crate) fn render_http_fallback(
  out: &mut String,
  spec: &GatewaySpec,
) {
  writeln!(
    out,
    "\nhttp://:{} {{\n\tabort\n}}",
    spec.http_port.unwrap_or(80)
  )
  .unwrap();
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn core_mesh_guard_keeps_tunnel_public() {
    let guard = SiteProtection {
      core_ranges: vec!["100.64.0.2/32".into()],
      use_client_ip: true,
      ..Default::default()
    };
    let mut out = String::new();
    guard.render_matchers(&mut out);
    assert!(out.contains("not client_ip 100.64.0.2/32"));
    assert!(out.contains("abort @wharf_core_outside"));
    assert!(out.contains(
      "not expression `{http.request.uri}.matches('^(/api/tunnel|"
    ));
    assert!(out.contains(")([?].*)?$')`"));
    assert!(!out.contains("/api/session"));
    assert!(!out.contains("/api/tunnel.*"));
  }

  #[test]
  fn cloudflare_guard_matches_the_peer_and_fails_closed() {
    let mut guard = SiteProtection {
      cf_ranges: Some(vec!["173.245.48.0/20".into()]),
      ..Default::default()
    };
    let mut out = String::new();
    guard.render_matchers(&mut out);
    assert_eq!(
      out,
      "\t@wharf_non_cf not remote_ip 173.245.48.0/20\n\tabort @wharf_non_cf\n"
    );
    guard.cf_ranges = Some(vec![]);
    out.clear();
    guard.render_matchers(&mut out);
    assert_eq!(out, "\tabort\n");
  }

  #[test]
  fn gateway_timeouts_override_defaults() {
    let spec: GatewaySpec = serde_json::from_str(r#"{
      "kind":"caddy","server":"s1","read_header_timeout":3,"idle_timeout":45,"grace_period":0
    }"#).unwrap();
    assert!(validate_gateway("edge", &spec).is_ok());
    let mut out = String::new();
    render_servers(&mut out, &spec, &["192.0.2.0/24".into()]);
    assert_eq!(out.matches("servers {").count(), 1);
    for value in [
      "grace_period 0s",
      "read_header 3s",
      "idle 45s",
      "trusted_proxies static 192.0.2.0/24",
    ] {
      assert!(out.contains(value), "{value}");
    }
    let tunnel = GatewaySpec {
      kind: GatewayKind::CloudflareTunnel,
      ..spec
    };
    assert!(validate_gateway("edge", &tunnel).is_err());
  }

  #[test]
  fn unknown_host_fallback_is_http_only_and_keeps_share_site() {
    let spec = serde_json::from_str(
      r#"{"kind":"caddy","server":"s1","http_port":8080}"#,
    )
    .unwrap();
    let site = Site {
      hostname: "*.s.example.com".into(),
      wildcard: true,
      ..Default::default()
    };
    let share = Site {
      hostname: "demo.s.example.com".into(),
      upstream: "127.0.0.1:8080".into(),
      ..Default::default()
    };
    let out = crate::render::caddyfile_with_fill(
      "edge",
      &spec,
      &[site, share],
      &[],
      false,
      None,
      &[],
      Default::default(),
    );
    assert!(out.contains("\n*.s.example.com {\n\tabort\n}\n"));
    let share = out.split_once("\ndemo.s.example.com {\n").unwrap().1;
    assert!(
      share
        .split_once("\n}\n")
        .unwrap()
        .0
        .contains("reverse_proxy 127.0.0.1:8080")
    );
    assert!(out.ends_with("\nhttp://:8080 {\n\tabort\n}\n"));
  }
}
