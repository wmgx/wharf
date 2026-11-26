use std::collections::BTreeSet;

use chrono::Utc;
use serde_json::{Value, json};
use wharf_api_types::{
  ErrorCode,
  plan::{Action, Layer, Plan, PlanItem, PlanRequest, PlanStatus},
  spec::{
    Change, GatewaySpec, PrivateAddr, PrivateNetwork, RouteSpec,
    ServerSettings,
  },
  view::Perm,
};

use super::*;
use crate::{
  auth::Auth,
  render::{BasicAuth, Gate, Site, caddyfile_with_acme},
  token_scope::{
    RouteEffects, check_plan_scope, require_plan_request,
  },
  world::{GatewayRow, RouteRow, ServerRow, World},
};

fn base_world() -> World {
  let mut w = World::default();
  w.servers.insert(
    "s1".into(),
    ServerRow {
      settings: ServerSettings::default(),
      version: 1,
    },
  );
  w.gateways.insert(
    "edge".into(),
    GatewayRow {
      spec: serde_json::from_value(json!({
        "kind": "caddy",
        "server": "s1",
        "default": true
      }))
      .unwrap(),
      version: 1,
    },
  );
  w
}

fn route_plan(
  action: Action,
  before: Option<Value>,
  after: Option<Value>,
) -> Plan {
  let now = Utc::now();
  Plan {
    plan_id: "p1".into(),
    status: PlanStatus::Pending,
    created_at: now,
    expires_at: now,
    base_versions: Default::default(),
    inputs: None,
    items: vec![PlanItem {
      id: 1,
      address: "route/a.example.com".into(),
      layer: Layer::Config,
      action,
      before,
      after,
      impacts: vec![],
      reason: "修改配置".into(),
      changes: vec![],
      host_access: vec![],
    }],
    warnings: vec![],
    needs_host: vec![],
    needs_confirm: vec![],
    suggest: vec![],
    note: None,
  }
}

#[test]
fn custom_caddy_blocks_lexical_escapes_and_env() {
  for bad in [
    "# {\n}\nevil.example.com {\n\treverse_proxy 127.0.0.1:7700\n# }",
    "header X-A `\\`\n}\nevil.example.com {\n# `",
    "respond {foo\n}\nevil.example.com {\nrespond bar}",
    "respond <<EOF\n{\nEOF\n}\nevil.example.com {\nrespond <<EOF\n}\nEOF",
    "foo\"{\"\n}\nevil.example.com {\nfoo\"}\"",
    "header X-A {$HOME}",
    "header X-A {env.PATH}",
    "header X-A {ENV.SECRET}",
    "header X-A \"ok\"}\nevil.example.com {",
    "header X-A \\\n}\nevil.example.com {",
    "header X-A \"unclosed\\",
    "header X-A `unclosed",
    "header X-A \0bad",
    "header X-A a\rb",
  ] {
    assert!(check_custom_caddy(bad).is_err(), "{bad:?}");
  }
}

#[test]
fn custom_caddy_allows_valid_snippets_and_presets() {
  for good in [
    "# comment with { and \" and `\nheader {\n\tX-A \"{host}\"\n}",
    "@cel expression `{path}.startsWith(\"/api\")`\nrespond @cel 403",
    "@deny path /secret/*\nrespond @deny 403\nheader X-Robots-Tag \"noindex, nofollow\"",
    "@m path /admin/*\nrespond @m 403",
    "@m {\n\tpath /admin/*\n\tnot remote_ip private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\n}\nrespond @m 403",
    "@m not remote_ip 203.0.113.0/24 private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\nrespond @m 403",
    "header {\r\n\tX-A \"ok\"\r\n}",
  ] {
    assert!(check_custom_caddy(good).is_ok(), "{good:?}");
  }
}

#[test]
fn route_caddy_requires_admin_when_changed() {
  let without =
    json!({"hostname": "a.example.com", "service": "blog"});
  let blank = json!({"hostname": "a.example.com", "service": "blog", "caddy": "  \n\t "});
  let with_a = json!({"hostname": "a.example.com", "service": "blog", "caddy": "header X-A 1"});
  let with_b = json!({"hostname": "a.example.com", "service": "blog", "caddy": "header X-A 2"});
  let with_a_rate = json!({
    "hostname": "a.example.com",
    "service": "blog",
    "caddy": "header X-A 1",
    "rate_limit": 60
  });

  // 无 Perm::Admin：新建、修改、清空均拒绝。
  for plan in [
    route_plan(Action::Create, None, Some(with_a.clone())),
    route_plan(Action::Update, Some(with_a.clone()), Some(with_b)),
    route_plan(
      Action::Update,
      Some(with_a.clone()),
      Some(without.clone()),
    ),
    route_plan(
      Action::Update,
      Some(with_a.clone()),
      Some(blank.clone()),
    ),
  ] {
    let err = require_route_caddy(&plan, false).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(require_route_caddy(&plan, true).is_ok());
  }

  // 无 Perm::Admin：caddy 未变、空白归一化等价、或删路由均放行。
  for plan in [
    route_plan(
      Action::Update,
      Some(with_a.clone()),
      Some(with_a_rate),
    ),
    route_plan(Action::Update, Some(without), Some(blank)),
    route_plan(Action::Delete, Some(with_a), None),
  ] {
    assert!(require_route_caddy(&plan, false).is_ok());
  }
}

#[test]
fn scoped_token_cannot_change_route_caddy() {
  let services = BTreeSet::from(["blog".to_string()]);
  let auth = Auth {
    name: "ci".into(),
    perms: Perm::ALL.into_iter().collect(),
    expires_at: None,
    allowed_from: vec![],
    services: Some(services.clone()),
    human: false,
  };
  let mut world = base_world();
  let existing: RouteSpec = serde_json::from_value(json!({
    "hostname": "blog.example.com",
    "service": "blog",
    "caddy": "header X-A 1"
  }))
  .unwrap();
  world.routes.insert(
    "blog.example.com".into(),
    RouteRow {
      id: "rt_1".into(),
      spec: existing.clone(),
      version: 1,
    },
  );

  // 仅修改其他字段、caddy 未变：plan 请求与计划范围检查均放行。
  let mut same_caddy = existing.clone();
  same_caddy.rate_limit = Some(100);
  let ok_req = PlanRequest {
    changes: vec![Change::UpsertRoute {
      spec: same_caddy.clone(),
    }],
    ..Default::default()
  };
  assert!(require_plan_request(&auth, &world, &ok_req).is_ok());

  let ok_plan = Plan {
    items: vec![PlanItem {
      id: 1,
      address: "route/blog.example.com".into(),
      layer: Layer::Config,
      action: Action::Update,
      before: Some(serde_json::to_value(&existing).unwrap()),
      after: Some(serde_json::to_value(&same_caddy).unwrap()),
      impacts: vec![],
      reason: String::new(),
      changes: vec![],
      host_access: vec![],
    }],
    ..route_plan(Action::Update, None, None)
  };
  assert_eq!(
    check_plan_scope(&services, &ok_plan, &RouteEffects::new()),
    Ok(())
  );

  // 修改 caddy：plan 请求与计划范围检查均拒绝。
  let mut changed_caddy = existing.clone();
  changed_caddy.caddy = Some("header X-A 2".into());
  let bad_req = PlanRequest {
    changes: vec![Change::UpsertRoute {
      spec: changed_caddy.clone(),
    }],
    ..Default::default()
  };
  assert_eq!(
    require_plan_request(&auth, &world, &bad_req)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );

  let bad_plan = Plan {
    items: vec![PlanItem {
      id: 1,
      address: "route/blog.example.com".into(),
      layer: Layer::Config,
      action: Action::Update,
      before: Some(serde_json::to_value(&existing).unwrap()),
      after: Some(serde_json::to_value(&changed_caddy).unwrap()),
      impacts: vec![],
      reason: String::new(),
      changes: vec![],
      host_access: vec![],
    }],
    ..route_plan(Action::Update, None, None)
  };
  assert_eq!(
    check_plan_scope(&services, &bad_plan, &RouteEffects::new()),
    Err(vec!["route/blog.example.com".into()])
  );
}

#[test]
fn upstream_whitelist_blocks_metachars_and_allows_valid() {
  for bad in [
    "foo}{abort}#x:80",
    "127.0.0.1:0",
    "127.0.0.1:080",
    "::1:8080",
    "[fe80::1%eth0]:80",
    "127.0.0.1:80\n}",
    "12345:80",
    "1.2.3:80",
    "999.999.999.999:80",
    "{$HOST}:80",
  ] {
    assert!(!valid_upstream(bad), "{bad:?}");
  }
  for good in [
    "127.0.0.1:1",
    "127.0.0.1:17891",
    "127.0.0.1:18081",
    "100.64.0.10:7700",
    "[::1]:8080",
    "[fd7a:115c:a1e0::1]:7700",
    "localhost:8080",
    "app.internal:8080",
  ] {
    assert!(valid_upstream(good), "{good:?}");
  }
}

#[test]
fn world_validate_blocks_malicious_upstreams_across_all_entries() {
  // 1. 路由主上游
  let mut w = base_world();
  w.apply_changes(&[Change::UpsertRoute {
    spec: serde_json::from_value(json!({
      "hostname": "a.example.com",
      "upstream": "foo}{abort}#x:80"
    }))
    .unwrap(),
  }])
  .unwrap();
  assert!(w.validate().is_err());

  // 2. 路径上游
  let mut w = base_world();
  w.apply_changes(&[Change::UpsertRoute {
    spec: serde_json::from_value(json!({
      "hostname": "a.example.com",
      "upstream": "127.0.0.1:8080",
      "paths": [{"path": "/api", "upstream": "127.0.0.1:080"}]
    }))
    .unwrap(),
  }])
  .unwrap();
  assert!(w.validate().is_err());

  // 3. 四层转发上游
  let mut w = base_world();
  w.gateways.get_mut("edge").unwrap().spec.layer4 = vec![
    serde_json::from_value(json!({
      "listen": 15432,
      "upstream": "{$HOST}:80"
    }))
    .unwrap(),
  ];
  assert!(w.validate().is_err());
}

#[test]
fn caddyfile_order_directives_follow_expected_precedence() {
  let gw: GatewaySpec = serde_json::from_value(json!({
    "kind": "caddy",
    "server": "s1"
  }))
  .unwrap();
  let mut site = Site {
    hostname: "a.example.com".into(),
    upstream: "127.0.0.1:8080".into(),
    internal: true,
    expires_at: Some(1_800_000_000_000),
    block_scanners: true,
    rate_limit: Some(60),
    auth: BasicAuth::parse("admin $2b$12$abc"),
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
    ..Default::default()
  };
  let out = caddyfile_with_acme(
    "edge",
    &gw,
    std::slice::from_ref(&site),
    &[],
    false,
    Some("public"),
    &[],
    None,
  );
  let i_abort =
    out.find("\torder abort before basic_auth\n").unwrap();
  let i_respond =
    out.find("\torder respond before basic_auth\n").unwrap();
  let i_rate =
    out.find("\torder rate_limit before basic_auth\n").unwrap();
  let i_sso =
    out.find("\torder wharf_sso before basic_auth\n").unwrap();
  assert!(i_abort < i_respond);
  assert!(i_respond < i_rate);
  assert!(i_rate < i_sso);

  site.block_scanners = false;
  let without_scanners = caddyfile_with_acme(
    "edge",
    &gw,
    &[site],
    &[],
    false,
    Some("public"),
    &[],
    None,
  );
  assert!(
    !without_scanners.contains("order respond before basic_auth")
  );
}

#[test]
fn route_path_whitelist_checks() {
  for bad in [
    "/_wharf",
    "/_wharf/*",
    "/_wharf/login",
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
    assert!(validate_route_path(bad).is_err(), "{bad:?}");
  }
  for good in ["/ws", "/api", "/api/", "/api/*", "/v1/files.json"] {
    assert!(validate_route_path(good).is_ok(), "{good:?}");
  }
}

#[test]
fn gateway_email_whitelist_checks() {
  for bad in [
    "a@b.com\n}\nevil.com {",
    "a@b.com ",
    "a@localhost",
    "a b@example.com",
    "",
  ] {
    let mut w = base_world();
    w.gateways.get_mut("edge").unwrap().spec.email = Some(bad.into());
    assert!(w.validate().is_err(), "{bad:?}");
  }
  let mut w = base_world();
  w.gateways.get_mut("edge").unwrap().spec.email =
    Some("ops+wharf@example.com".into());
  assert!(w.validate().is_ok());
}

#[test]
fn error_page_blocks_env_and_control_chars() {
  for bad in [
    "{env.PATH}",
    "{ENV.SECRET}",
    "hi\0there",
    "a\rb",
    "x WHARF_ERROR_PAGE y",
    "{$HOME}",
  ] {
    assert!(check_error_page("edge", bad).is_err(), "{bad:?}");
  }
  assert!(
    check_error_page(
      "edge",
      "<style>body{color:red}</style>\r\n<p>{err.status_code}</p>"
    )
    .is_ok()
  );
}

#[test]
fn redirect_host_strict_checks() {
  for bad in [
    "https://a.com:0",
    "https://a.com:080",
    "https://..",
    "https://a.com/x/../y",
    "https://a.com//x",
  ] {
    assert_eq!(redirect_host(bad), None, "{bad:?}");
  }
  assert_eq!(redirect_host("https://a.com"), Some("a.com"));
  assert_eq!(redirect_host("https://[::1]:8443/app"), Some("[::1]"));
}

#[test]
fn basic_auth_parse_blocks_metachars() {
  for bad in [
    "admin $2b$12$abc}\nevil {",
    "ad\nmin $2b$12$abc",
    "admin $2b$12${$ENV}",
  ] {
    assert!(BasicAuth::parse(bad).is_none(), "{bad:?}");
  }
  assert!(BasicAuth::parse("admin $2b$12$abc").is_some());
  assert!(
    BasicAuth::parse(
      "ops_1 $2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
    )
    .is_some()
  );
  assert!(
    BasicAuth::hash_input(&format!("{}:longenough", "a".repeat(65)))
      .is_err()
  );
}

#[test]
fn public_url_and_acme_dns_key_checks() {
  for bad in [
    "https://core.example.com\n}",
    "https://core.example.com/{$X}",
    "https://user:pass@core.example.com",
    "https://core.example.com?a=1",
  ] {
    assert!(!valid_public_url(bad), "{bad:?}");
  }
  for good in ["https://wharf.example.com", "http://100.64.0.1:7700"]
  {
    assert!(valid_public_url(good), "{good:?}");
  }
  assert!(!valid_acme_dns_key("abc\n}"));
  assert!(valid_acme_dns_key(&"a1".repeat(24)));
}

#[test]
fn world_validate_rechecks_gateway_route_and_server_fields() {
  // 非法网关名
  let mut w = base_world();
  let gw = w.gateways.remove("edge").unwrap();
  w.gateways.insert("bad\n{".into(), gw);
  assert!(w.validate().is_err());

  // 非法路由域名或与 map key 不一致
  let mut w = base_world();
  w.routes.insert(
    "bad\n{.example.com".into(),
    RouteRow {
      id: "rt_1".into(),
      spec: serde_json::from_value(json!({
        "hostname": "bad\n{.example.com",
        "upstream": "127.0.0.1:8080"
      }))
      .unwrap(),
      version: 1,
    },
  );
  assert!(w.validate().is_err());

  let mut w = base_world();
  w.routes.insert(
    "a.example.com".into(),
    RouteRow {
      id: "rt_1".into(),
      spec: serde_json::from_value(json!({
        "hostname": "b.example.com",
        "upstream": "127.0.0.1:8080"
      }))
      .unwrap(),
      version: 1,
    },
  );
  assert!(w.validate().is_err());

  // 非法服务器内网地址
  let mut w = base_world();
  w.servers.get_mut("s1").unwrap().settings.private_addr =
    Some(PrivateAddr {
      ip: "203.0.113.10".into(),
      network: PrivateNetwork::Lan,
    });
  assert!(w.validate().is_err());
}
