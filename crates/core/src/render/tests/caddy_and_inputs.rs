use super::*;

#[test]
fn caddyfile_custom_in_site() {
  let spec = serde_json::from_value(serde_json::json!({
    "kind": "caddy", "server": "s1"
  }))
  .unwrap();
  let out = caddyfile(
    "edge",
    &spec,
    &[Site {
      hostname: "a.example.com".into(),
      upstream: "127.0.0.1:1".into(),
      custom: Some(
        "@admin path /admin/*\n\nrespond @admin 403  ".into(),
      ),
      ..Default::default()
    }],
    &[],
    false,
    None,
  );
  assert!(out.contains("\timport wharf_errors\n\t@admin path /admin/*\n\n\trespond @admin 403\n\treverse_proxy 127.0.0.1:1 {"));
}

#[test]
fn caddyfile_guard_per_site() {
  let spec = serde_json::from_value(serde_json::json!({
    "kind": "caddy", "server": "s1"
  }))
  .unwrap();
  let out = caddyfile(
    "edge",
    &spec,
    &[
      Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:1".into(),
        rate_limit: Some(600),
        block_scanners: true,
        ..Default::default()
      },
      Site {
        hostname: "b.example.com".into(),
        upstream: "127.0.0.1:2".into(),
        ..Default::default()
      },
    ],
    &[],
    false,
    None,
  );
  assert_eq!(
    out.matches("order rate_limit before basic_auth").count(),
    1
  );
  assert_eq!(out.matches("(wharf_scanners) {").count(), 1);
  assert_eq!(out.matches("import wharf_scanners").count(), 1);
  let a = out
    .split("\na.example.com {\n")
    .nth(1)
    .unwrap()
    .split("\nb.example.com {\n")
    .next()
    .unwrap();
  assert!(a.contains("import wharf_scanners"));
  assert!(a.contains("zone wharf_a_example_com {"));
  assert!(a.contains("events 600"));
  assert!(a.contains("window 1m"));
  assert!(out.contains("b.example.com {\n\timport wharf_access\n\timport wharf_errors\n\treverse_proxy 127.0.0.1:2 {\n\t\timport wharf_upstream\n\t}\n}"));
  assert!(!SCANNER_PATHS.contains(" / "));
  assert!(!SCANNER_UA.contains("curl"));
  assert!(!SCANNER_UA.contains("reqwest"));
}

#[test]
fn caddyfile_retries_only_service_upstreams() {
  let spec = serde_json::from_value(serde_json::json!({
    "kind": "caddy", "server": "s1"
  }))
  .unwrap();
  let site = Site {
    hostname: "a.example.com".into(),
    upstream: "127.0.0.1:20000".into(),
    auth: None,
    paths: vec![("/api".into(), "100.64.0.1:20001".into())],
    redirect: None,
    ..Default::default()
  };
  let redirect = Site {
    hostname: "b.example.com".into(),
    redirect: Some("https://a.example.com".into()),
    paths: vec![],
    ..site.clone()
  };
  let out =
    caddyfile("edge", &spec, &[site, redirect], &[], true, None);
  assert_eq!(out.matches("import wharf_upstream").count(), 2);
  assert_eq!(out.matches("(wharf_upstream) {").count(), 1);
  assert!(out.contains("lb_try_duration 8s"));
  assert!(out.contains("lb_try_interval 250ms"));
  let excluded = &out[out.find("\nb.example.com {").unwrap()..];
  assert!(excluded.contains("link.wharf.internal {"));
  assert!(!excluded.contains("import wharf_upstream"));
}

#[test]
fn caddyfile_has_default_error_page() {
  let spec = serde_json::from_value(serde_json::json!({
    "kind": "caddy", "server": "s1"
  }))
  .unwrap();
  let out = caddyfile(
    "edge",
    &spec,
    &[
      Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:21000".into(),
        auth: None,
        paths: vec![],
        redirect: None,
        ..Default::default()
      },
      Site {
        hostname: "b.example.com".into(),
        upstream: String::new(),
        auth: None,
        paths: vec![],
        redirect: Some("https://a.example.com".into()),
        ..Default::default()
      },
    ],
    &[],
    false,
    None,
  );
  assert!(out.contains("(wharf_errors) {"));
  assert!(out.contains("handle_errors 502 503 504"));
  assert!(out.contains("服务暂时不可用"));
  assert_eq!(out.matches("import wharf_errors").count(), 1);
}

#[test]
fn caddyfile_has_custom_error_page() {
  let spec = serde_json::from_value(serde_json::json!({
    "kind": "caddy", "server": "s1",
    "error_page": "<p>x</p>\n\n<p>y</p>"
  }))
  .unwrap();
  let out = caddyfile("edge", &spec, &[], &[], false, None);
  assert!(out.contains(
    "\t\t<p>x</p>\n\n\t\t<p>y</p>\n\t\tWHARF_ERROR_PAGE {err.status_code}\n"
  ));
  assert!(!out.contains("服务暂时不可用"));
}

#[test]
fn caddyfile_redirect_keeps_uri() {
  let gw = GatewaySpec {
    kind: GatewayKind::Caddy,
    server: "s1".into(),
    default: true,
    http_port: None,
    https_port: None,
    email: None,
    image: None,
    tls: GatewayTls::Auto,
    account: None,
    error_page: None,
    wildcard: vec![],
    layer4: vec![],
    trusted_proxies: None,
    read_header_timeout: None,
    idle_timeout: None,
    grace_period: None,
  };
  let out = caddyfile(
    "edge",
    &gw,
    &[Site {
      hostname: "www.a.com".into(),
      upstream: String::new(),
      auth: None,
      paths: vec![],
      redirect: Some("https://a.com".into()),
      ..Default::default()
    }],
    &[],
    false,
    None,
  );
  assert!(out.contains("www.a.com {\n\timport wharf_access\n\tredir https://a.com{uri} permanent\n"));
  assert!(!out.contains("reverse_proxy"));
}

#[test]
fn tunnel_compose_holds_only_a_token_placeholder() {
  let spec = GatewaySpec {
    kind: GatewayKind::CloudflareTunnel,
    server: "edge1".into(),
    default: false,
    http_port: None,
    https_port: None,
    email: None,
    image: None,
    tls: GatewayTls::Auto,
    account: Some("cf".into()),
    error_page: None,
    wildcard: vec![],
    layer4: vec![],
    trusted_proxies: None,
    read_header_timeout: None,
    idle_timeout: None,
    grace_period: None,
  };
  let out = tunnel_compose("cf", &spec, None);
  assert!(
    out.contains("TUNNEL_TOKEN: '[[WHARF_TUNNEL_TOKEN]]'"),
    "{out}"
  );
  assert!(out.contains("network_mode: host"));
  assert!(out.contains(DEFAULT_CLOUDFLARED_IMAGE));
}

#[test]
fn auth_is_per_route() {
  let mut net = Net::default();
  net.basic_auth.insert(
    route_auth_secret("a.example.com"),
    BasicAuth::parse("mine $2b$12$x").unwrap(),
  );
  assert_eq!(net.auth_for("a.example.com").unwrap().user, "mine");
  assert!(net.auth_for("b.example.com").is_none());
  assert_eq!(
    route_auth_secret("a.example.com"),
    "BASIC_AUTH_a_example_com"
  );
}

#[test]
fn basic_auth_input_is_checked() {
  assert!(BasicAuth::hash_input("no-colon").is_err());
  assert!(BasicAuth::hash_input("ad min:longenough").is_err());
  assert!(BasicAuth::hash_input("admin:short").is_err());
  assert!(BasicAuth::parse("admin plaintext").is_none());
}

#[test]
fn inputs_include_addresses_not_usage() {
  use wharf_api_types::agent::{AgentReport, Disk};
  use wharf_api_types::spec::{PrivateNetwork, ServerSettings};

  let addr = |ip: &str| PrivateAddr {
    ip: ip.into(),
    network: PrivateNetwork::Tailscale,
  };
  let fingerprint = |settings: ServerSettings,
                     report: AgentReport| {
    let servers = BTreeMap::from([(
      "home".to_string(),
      ServerRow {
        settings,
        version: 1,
      },
    )]);
    let agents = vec![crate::db::AgentRow {
      server: "home".into(),
      public_key: None,
      report: Some(report),
      last_seen: None,
    }];
    crate::db::inputs_fingerprint(
      &BTreeMap::new(),
      &BTreeMap::new(),
      &Net::derive(&servers, &agents).addresses(),
    )
  };

  let base = fingerprint(
    ServerSettings::default(),
    AgentReport {
      private_addr: Some(addr("100.64.0.1")),
      ..Default::default()
    },
  );
  // 磁盘用量这类高频上报值变了，指纹不变
  let usage = fingerprint(
    ServerSettings::default(),
    AgentReport {
      private_addr: Some(addr("100.64.0.1")),
      disk: Some(Disk {
        total: 100,
        free: 1,
      }),
      ..Default::default()
    },
  );
  assert_eq!(base, usage);
  // agent 上报的地址变了，指纹要变
  let moved = fingerprint(
    ServerSettings::default(),
    AgentReport {
      private_addr: Some(addr("100.64.0.2")),
      ..Default::default()
    },
  );
  assert_ne!(base, moved);
  // 服务器设置里的地址覆盖变了，指纹也要变
  let overridden = fingerprint(
    ServerSettings {
      private_addr: Some(addr("100.64.0.3")),
      ..Default::default()
    },
    AgentReport::default(),
  );
  assert_ne!(base, overridden);
}
#[test]
fn caddyfile_app_login() {
  let gw = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  site.gate.as_mut().unwrap().app_login = true;
  assert!(
    caddyfile("edge", &gw, &[site], &[], false, Some("public"))
      .contains("\t\tapp_login on\n")
  );
}
#[test]
fn caddyfile_gate_without_app_login() {
  let gw = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  assert!(
    !caddyfile(
      "edge",
      &gw,
      &[gate_site()],
      &[],
      false,
      Some("public")
    )
    .contains("app_login")
  );
}
#[test]
fn caddyfile_public_login_entry_only() {
  let gw = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  for app_login in [true, false] {
    let gate = site.gate.as_mut().unwrap();
    gate.public = true;
    gate.site_endpoints = app_login;
    gate.app_login = app_login;
    let out = caddyfile(
      "edge",
      &gw,
      std::slice::from_ref(&site),
      &[],
      false,
      Some("public"),
    );
    assert_eq!(out.contains("@wharf_site"), app_login);
    assert!(out.contains("\twharf_sso {"));
    assert!(out.contains("\t\tpublic\n"));
  }
}
fn gate_site() -> Site {
  Site {
    hostname: "a.example.test".into(),
    upstream: "127.0.0.1:8080".into(),
    gate: Some(Gate {
      public: false,
      site_endpoints: true,
      app_login: false,
      user_header: None,
      trusted: vec![],
      login: "https://core.example.test".into(),
      core: "http://127.0.0.1:7700".into(),
      skip_paths: vec![],
      takeover: None,
    }),
    ..Default::default()
  }
}
#[test]
fn caddyfile_gate() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let out = caddyfile(
    "edge",
    &gw,
    &[gate_site()],
    &[],
    false,
    Some("public"),
  );
  assert!(out.contains("order wharf_sso before basic_auth"));
  assert!(out.contains("handle @wharf_site"));
  assert!(out.contains("uri replace /_wharf/ /gate/site/"));
  assert!(out.contains("public_key public"));
  assert!(out.contains("core http://127.0.0.1:7700"));
  assert!(!out.contains("skip "));
}
#[test]
fn caddyfile_gate_trust() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  let before = caddyfile(
    "edge",
    &gw,
    std::slice::from_ref(&site),
    &[],
    false,
    Some("public"),
  );
  site.gate.as_mut().unwrap().trusted = vec![
    "100.64.0.0/10".into(),
    "127.0.0.0/8".into(),
    "::1/128".into(),
    "fd7a:115c:a1e0::/48".into(),
  ];
  let after =
    caddyfile("edge", &gw, &[site], &[], false, Some("public"));
  assert_eq!(
    after.replace("\t\ttrust 100.64.0.0/10 127.0.0.0/8 ::1/128 fd7a:115c:a1e0::/48\n", ""),
    before
  );
  assert!(after.contains("\t\ttrust 100.64.0.0/10 127.0.0.0/8 ::1/128 fd7a:115c:a1e0::/48\n"));
}
#[test]
fn caddyfile_gate_without_trust_unchanged() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let out = caddyfile(
    "edge",
    &gw,
    &[gate_site()],
    &[],
    false,
    Some("public"),
  );
  assert!(out.contains("\t\tlogin https://core.example.test\n\t}\n"));
  assert!(!out.contains("\t\ttrust "));
}
#[test]
fn caddyfile_gate_header() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  let before = caddyfile(
    "edge",
    &gw,
    std::slice::from_ref(&site),
    &[],
    false,
    Some("public"),
  );
  site.gate.as_mut().unwrap().user_header =
    Some("Remote-User".into());
  let after =
    caddyfile("edge", &gw, &[site], &[], false, Some("public"));
  assert!(after.contains("\t\tuser_header Remote-User\n"));
  assert_eq!(
    after.replace("\t\tuser_header Remote-User\n", ""),
    before
  );
}
#[test]
fn caddyfile_gate_without_header() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let out = caddyfile(
    "edge",
    &gw,
    &[gate_site()],
    &[],
    false,
    Some("public"),
  );
  assert!(!out.contains("user_header"));
}
#[test]
fn caddyfile_gate_skip() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  let gate = site.gate.as_mut().unwrap();
  gate.skip_paths = vec!["/api".into(), "/hooks".into()];
  gate.core = gate.login.clone();
  let out =
    caddyfile("edge", &gw, &[site], &[], false, Some("public"));
  assert!(out.contains("skip /api /hooks"));
  assert!(out.contains("header_up Host {upstream_hostport}"));
}
#[test]
fn caddyfile_without_gate() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let mut site = gate_site();
  site.gate = None;
  let out = caddyfile("edge", &gw, &[site], &[], false, None);
  assert!(!out.contains("wharf_sso"));
  assert!(!out.contains("/_wharf/"));
  assert!(out.contains(
    "reverse_proxy 127.0.0.1:8080 {\n\t\timport wharf_upstream\n\t}"
  ));
}
