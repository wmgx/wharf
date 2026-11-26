use super::*;
use crate::{
  render::{self, BasicAuth, Gate, Site},
  world::{GatewayRow, RouteRow, ServerRow, World},
};
use serde_json::json;

#[test]
fn custom_caddy_lexical_boundaries() {
  for text in [
    "# {\n}",
    "header X-A `\\`\n}",
    "respond {foo\n}",
    "respond <<EOF\ntext\nEOF",
    "foo\"{\"",
    "respond foo#bar",
    "header X-A {$HOME}",
    "header X-A {EnV.PATH}",
    "header X-A \"unterminated",
    "header X-A \"a\"}",
    "header X-A `a`b",
    "header X-A \\",
    "header X-A value\\ \t\r\n",
    "header X-A \\ value",
    "# comment with \\ in it\n",
    "header X-A a\0b",
    "header X-A a\rb",
    "header X-A a\u{a0}{foo",
    "header X-A a\u{7f}b",
  ] {
    assert!(check_custom_caddy(text).is_err(), "{text:?}");
  }
  assert!(check_custom_caddy(&"x".repeat(8001)).is_err());
  for text in [
    "# 注释里的 {\r\nheader {\r\n\tX-A \"{host}\"\r\n}",
    "header X-A \"a\\\"b\"",
    "header X-A `\\`",
    "@m expression `{http.request.method} == 'GET'`",
    "@m path /admin/*\nrespond @m 403",
    "@m {\n\tpath /admin/*\n\tnot remote_ip private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\n}\nrespond @m 403",
    "@m not remote_ip 203.0.113.0/24 private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\nrespond @m 403",
    "@deny path /private/*\nrespond @deny 403\nheader X-Robots-Tag \"noindex, nofollow\"",
  ] {
    assert_eq!(check_custom_caddy(text), Ok(()), "{text:?}");
  }
}

#[test]
fn custom_caddy_requires_admin_to_change() {
  let mut plan: Plan = serde_json::from_value(json!({
    "plan_id": "p", "status": "pending",
    "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z",
    "base_versions": {},
    "items": [
      {"id": 1, "address": "route/a.example.com", "layer": "config", "action": "create", "reason": ""}
    ]
  }))
  .unwrap();
  for (action, before, after, needs_admin) in [
    (Action::Create, None, Some("respond 403"), true),
    (
      Action::Update,
      Some("respond 403"),
      Some("respond 404"),
      true,
    ),
    (Action::Update, Some("respond 403"), None, true),
    (Action::Update, Some("respond 403"), Some(" \r\n"), true),
    (
      Action::Update,
      Some("respond 403"),
      Some("respond 403"),
      false,
    ),
    (Action::Update, None, Some(" \t"), false),
    (Action::Delete, Some("respond 403"), None, false),
  ] {
    plan.items[0].action = action;
    plan.items[0].before =
      before.map(|caddy| json!({"caddy": caddy}));
    plan.items[0].after = after.map(|caddy| json!({"caddy": caddy}));
    let result = require_route_caddy(&plan, false);
    if needs_admin {
      assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
    } else {
      assert!(result.is_ok());
    }
    assert!(require_route_caddy(&plan, true).is_ok());
  }
  plan.items[0].action = Action::Update;
  plan.items[0].before = Some(json!({}));
  plan.items[0].after = Some(json!({"core_mesh_only": true}));
  assert_eq!(
    require_route_caddy(&plan, false).unwrap_err().code,
    ErrorCode::Forbidden
  );
  assert!(require_route_caddy(&plan, true).is_ok());
}

#[test]
fn upstream_addresses() {
  for up in [
    "foo}{abort}#x:80",
    "127.0.0.1:0",
    "127.0.0.1:080",
    "::1:8080",
    "[fe80::1%eth0]:80",
    "127.0.0.1:80\n}",
    "12345:80",
    "{$HOST}:80",
    "999.999.999.999:80",
    "localhost:65536",
  ] {
    assert!(!valid_upstream(up), "{up:?}");
  }
  for up in [
    "127.0.0.1:1",
    "127.0.0.1:17891",
    "127.0.0.1:18081",
    "100.64.0.1:7700",
    "[::1]:8080",
    "[fd7a:115c:a1e0::1]:7700",
    "localhost:8080",
    "app.internal:8080",
  ] {
    assert!(valid_upstream(up), "{up}");
  }
}

#[test]
fn route_path_and_urls() {
  for path in [
    "/_wharf",
    "/_wharf/*",
    "/_wharf/login",
    "/_WHARF/login",
    "/_whar*",
    "/api/../admin",
    "/api/./v1",
    "//api",
    "/",
    "/*",
    "/a/*/b",
    "/api`echo`",
    "/api{$X}",
  ] {
    assert!(validate_route_path(path).is_err(), "{path}");
  }
  for path in ["/ws", "/api", "/api/", "/api/*", "/v1/files.json"] {
    assert_eq!(validate_route_path(path), Ok(()), "{path}");
  }
  for target in [
    "https://a.com:0",
    "https://a.com:080",
    "https://..",
    "https://a.com/x/../y",
    "https://a.com//x",
    "https://[::1]app",
    "https://a.com/",
  ] {
    assert_eq!(redirect_host(target), None, "{target}");
  }
  assert_eq!(redirect_host("https://a.com"), Some("a.com"));
  assert_eq!(redirect_host("https://[::1]:8443/app"), Some("[::1]"));
  for url in [
    "https://core.example.com\n}",
    "https://core.example.com/{$X}",
    "https://user:pass@core.example.com",
    "https://core.example.com?a=1",
    "https://core.example.com//",
    "https://core.example.com/~app",
  ] {
    assert!(!valid_public_url(url), "{url:?}");
  }
  for url in [
    "https://wharf.example.com",
    "http://100.64.0.1:7700",
    "https://[::1]:8443/app/",
  ] {
    assert!(valid_public_url(url), "{url}");
  }
}

#[test]
fn rendered_secrets_and_error_pages() {
  for page in [
    "WHARF_ERROR_PAGE",
    "{$HOME}",
    "{env.PATH}",
    "{ENV.SECRET}",
    "hi\0there",
    "a\rb",
  ] {
    assert!(check_error_page("edge", page).is_err(), "{page:?}");
  }
  assert!(
    check_error_page(
      "edge",
      "{err.status_code}\r\n\t<style>body{color:red}</style>"
    )
    .is_ok()
  );
  for stored in [
    "admin $2b$12$abc}\ninvalid {",
    "ad\nmin $2b$12$abc",
    "admin $2b$12${$ENV}",
  ] {
    assert!(BasicAuth::parse(stored).is_none());
  }
  assert!(BasicAuth::parse("admin $2b$12$abc").is_some());
  assert!(BasicAuth::parse("admin $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6Ttx3Lw.oR7wwM9H.P6sbFGZKquny").is_some());
  assert!(
    BasicAuth::hash_input(&format!("{}:longenough", "a".repeat(65)))
      .is_err()
  );
  assert!(valid_acme_dns_key(&"a1".repeat(24)));
  assert!(!valid_acme_dns_key("abc\n}"));
}

#[test]
fn world_rechecks_config_loaded_from_storage() {
  let mut world = World::default();
  world.servers.insert(
    "s1".into(),
    ServerRow {
      settings: Default::default(),
      version: 1,
    },
  );
  world.gateways.insert(
    "edge".into(),
    GatewayRow {
      spec: serde_json::from_value(
        json!({"kind": "caddy", "server": "s1", "default": true}),
      )
      .unwrap(),
      version: 1,
    },
  );
  world.routes.insert("a.example.com".into(), RouteRow {
    id: "r".into(), version: 1,
    spec: serde_json::from_value(json!({"hostname": "a.example.com", "upstream": "127.0.0.1:1"})).unwrap(),
  });
  assert!(world.validate().is_ok());

  fn gateway(w: &mut World) -> &mut GatewaySpec {
    &mut w.gateways.get_mut("edge").unwrap().spec
  }
  for email in [
    "a@b.com\n}\nother.com {",
    "a@b.com ",
    "a@localhost",
    "a b@example.com",
    "",
  ] {
    let mut invalid = world.clone();
    gateway(&mut invalid).email = Some(email.into());
    assert!(
      invalid.validate().unwrap_err().message.contains("邮箱"),
      "{email:?}"
    );
  }
  gateway(&mut world).email = Some("ops+wharf@example.com".into());
  assert!(world.validate().is_ok());

  let mut invalid = world.clone();
  let gateway_row = invalid.gateways.remove("edge").unwrap();
  invalid.gateways.insert("bad#name".into(), gateway_row);
  assert!(
    invalid
      .validate()
      .unwrap_err()
      .message
      .contains("网关 名称")
  );

  let mut invalid = world.clone();
  let row = invalid.routes.remove("a.example.com").unwrap();
  invalid.routes.insert("a.example.com#".into(), row);
  assert!(
    invalid.validate().unwrap_err().message.contains("hostname")
  );
  let mut invalid = world.clone();
  invalid
    .routes
    .get_mut("a.example.com")
    .unwrap()
    .spec
    .hostname = "b.example.com".into();
  assert!(
    invalid
      .validate()
      .unwrap_err()
      .message
      .contains("资源名不一致")
  );

  let mut invalid = world.clone();
  invalid.servers.get_mut("s1").unwrap().settings.private_addr = Some(
    serde_json::from_value(
      json!({"ip": "100.64.0.1\n}", "network": "tailscale"}),
    )
    .unwrap(),
  );
  assert!(
    invalid.validate().unwrap_err().message.contains("内网地址")
  );

  let up = "foo}{abort}#x:80";
  let mut invalid = world.clone();
  invalid
    .routes
    .get_mut("a.example.com")
    .unwrap()
    .spec
    .upstream = Some(up.into());
  assert!(invalid.validate().unwrap_err().message.contains("的上游"));
  let mut invalid = world.clone();
  invalid.routes.get_mut("a.example.com").unwrap().spec.paths =
    serde_json::from_value(json!([{"path": "/api", "upstream": up}]))
      .unwrap();
  assert!(
    invalid
      .validate()
      .unwrap_err()
      .message
      .contains("路径 /api 的上游")
  );
  gateway(&mut world).layer4 =
    serde_json::from_value(json!([{"listen": 8443, "upstream": up}]))
      .unwrap();
  assert!(
    world
      .validate()
      .unwrap_err()
      .message
      .contains("四层转发 8443 的上游")
  );
}

#[test]
fn global_caddy_directive_order() {
  let gateway =
    serde_json::from_value(json!({"kind": "caddy", "server": "s1"}))
      .unwrap();
  let mut site = Site {
    hostname: "a.example.com".into(),
    upstream: "127.0.0.1:1".into(),
    internal: true,
    expires_at: Some(1_800_000_000_000),
    block_scanners: true,
    rate_limit: Some(60),
    gate: Some(Gate {
      public: false,
      site_endpoints: true,
      app_login: false,
      user_header: None,
      trusted: vec![],
      login: "https://core.example.com".into(),
      core: "http://127.0.0.1:7700".into(),
      skip_paths: vec![],
      takeover: None,
    }),
    auth: BasicAuth::parse("admin $2b$12$abc"),
    ..Default::default()
  };
  let orders = |site: &Site| {
    render::caddyfile_with_fill(
      "edge",
      &gateway,
      std::slice::from_ref(site),
      &[],
      false,
      Some("public"),
      &[],
      Default::default(),
    )
    .lines()
    .filter_map(|line| {
      line.strip_prefix("\torder ").map(str::to_owned)
    })
    .collect::<Vec<_>>()
  };
  assert_eq!(
    orders(&site),
    [
      "abort before basic_auth",
      "respond before basic_auth",
      "rate_limit before basic_auth",
      "wharf_sso before basic_auth",
    ]
  );
  site.block_scanners = false;
  assert_eq!(
    orders(&site),
    [
      "abort before basic_auth",
      "rate_limit before basic_auth",
      "wharf_sso before basic_auth",
    ]
  );
}
