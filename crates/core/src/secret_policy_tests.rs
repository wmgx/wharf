use std::collections::BTreeMap;

use serde_json::{Value, json};
use wharf_api_types::{
  ErrorCode,
  plan::{Plan, PlanRequest},
  spec::RouteSpec,
  view::{Perm, TaskKind},
};

use crate::{
  app_accounts::AccountLinks,
  apply,
  auth::Auth,
  render, secret_policy as policy, snapshot, token_scope,
  world::{GatewayRow, RouteRow, ServerRow, ServiceRow, World},
};

fn service(env: Value) -> Value {
  json!({"server": "s1", "source": {"image": "nginx:1"}, "env": env})
}

fn add_service(world: &mut World, name: &str, value: Value) {
  world.services.insert(
    name.into(),
    ServiceRow {
      instance_id: "svc_fixture".into(),
      spec: serde_json::from_value(value).unwrap(),
      host_ports: Default::default(),
      import: None,
      pins: Default::default(),
      commit: None,
      version: 1,
    },
  );
}

fn add_route(world: &mut World, value: Value) -> RouteSpec {
  let spec: RouteSpec = serde_json::from_value(value).unwrap();
  world.routes.insert(
    spec.hostname.clone(),
    RouteRow {
      id: "route-id".into(),
      version: 1,
      spec: spec.clone(),
    },
  );
  spec
}

#[tokio::test]
async fn service_allowlist_persists_and_can_be_cleared() {
  use axum::{
    Json,
    extract::{Path, State},
  };
  let state = crate::rules::tests::test_state();
  let admin = || Auth {
    name: "operator".into(),
    perms: [Perm::Admin].into(),
    expires_at: None,
    allowed_from: vec![],
    services: None,
    human: false,
  };
  state
    .db
    .call_credentials(|c, key| {
      key.put_secret(c, "APP_KEY", "fixture-original", 1, true)?;
      let mut world = World::default();
      add_service(
        &mut world,
        "app",
        service(json!({"KEY": "[[url:APP_KEY]]"})),
      );
      for write in world.writes_from(&World::default()) {
        crate::db::apply_write(c, &write)?;
      }
      Ok(())
    })
    .await
    .unwrap();
  let allowed = ["app".into()].into();
  let Json(saved) = crate::secret_restrictions::put(
    State(state.clone()),
    admin(),
    Path("APP_KEY".into()),
    Json(Some(allowed)),
  )
  .await
  .map_err(|error| error.0)
  .unwrap();
  assert!(saved.unwrap().contains("app"));
  state
    .db
    .call(|c| {
      let allowed = crate::secret_restrictions::load(c)?;
      assert!(allowed["APP_KEY"].contains("app"));
      let world = World::from_rows(crate::db::all_resources(c)?)?;
      policy::validate_restrictions(&world, &allowed)
    })
    .await
    .unwrap();
  let Json(cleared) = crate::secret_restrictions::put(
    State(state.clone()),
    admin(),
    Path("APP_KEY".into()),
    Json(None),
  )
  .await
  .map_err(|error| error.0)
  .unwrap();
  assert!(cleared.is_none());
  assert!(
    state
      .db
      .call(|c| crate::secret_restrictions::load(c))
      .await
      .unwrap()
      .is_empty()
  );
}

#[test]
fn restricted_secret_rejects_outside_service_and_nonservice_users() {
  let restrictions =
    [("APP_KEY".into(), ["app".into()].into())].into();
  let mut world = World::default();
  add_service(
    &mut world,
    "other",
    service(json!({"KEY": "[[FILE:APP_KEY]]"})),
  );
  let err =
    policy::validate_restrictions(&world, &restrictions).unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  assert!(err.message.contains("密钥 APP_KEY，仅允许服务 app"));

  world.services.clear();
  add_route(
    &mut world,
    json!({
      "hostname": "app.example.test", "gateway": "g1", "service": "app",
      "sso": {"mode": "login", "login": {"script": {
        "runtime": "shell", "code": "true", "env": {"KEY": "[[b64:APP_KEY]]"}
      }}}
    }),
  );
  let err =
    policy::validate_restrictions(&world, &restrictions).unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  let task = TaskKind::Host {
    command: "[[json:APP_KEY]]".into(),
  };
  let err =
    policy::validate_task_restrictions("job", &task, &restrictions)
      .unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
}

fn plan(address: &str, before: Value, after: Value) -> Plan {
  serde_json::from_value(json!({
    "plan_id": "p-test", "status": "pending",
    "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T01:00:00Z",
    "base_versions": {}, "warnings": [], "needs_confirm": [], "suggest": [],
    "items": [{
      "id": 1, "address": address, "layer": "config", "action": "update",
      "before": before, "after": after, "reason": ""
    }]
  })).unwrap()
}

#[test]
fn plan_scope_checked_before_any_agent_op() {
  let auth = Auth {
    name: "scoped".into(),
    perms: [Perm::Plan].into(),
    expires_at: None,
    allowed_from: vec![],
    services: Some(["blog".into()].into()),
    human: false,
  };
  let req: PlanRequest = serde_json::from_value(json!({
    "changes": [{
      "op": "upsert_service", "name": "other", "spec": {"server": "s1", "source": {
        "build": {"git": {"repo": "https://example.test/blog", "ref": "main", "token_secret": "KEY"}}
      }}
    }]
  })).unwrap();
  let err =
    token_scope::require_plan_request(&auth, &World::default(), &req)
      .unwrap_err();
  assert_eq!(err.code, ErrorCode::Forbidden);
  assert!(err.message.contains("service/other"));
}

#[test]
fn plan_uses_committed_pull_policy() {
  let mut current = World::default();
  current.servers.insert(
    "s1".into(),
    ServerRow {
      settings: serde_json::from_value(json!({
        "registry_mirrors": {"docker.io": ["registry.example.test"]},
        "github_mirror": "https://git.example.test"
      }))
      .unwrap(),
      version: 1,
    },
  );
  let mut desired = current.clone();
  let settings = &mut desired.servers.get_mut("s1").unwrap().settings;
  settings
    .registry_mirrors
    .insert("docker.io".into(), vec!["127.0.0.1:1/[[X]]".into()]);
  settings.github_mirror = Some("https://127.0.0.1:1/[[X]]".into());
  let pull = snapshot::committed_pull_policy(&current, "s1");
  assert_eq!(pull.mirrors["docker.io"], ["registry.example.test"]);
  assert_eq!(
    pull.github_mirror.as_deref(),
    Some("https://git.example.test")
  );
  assert_ne!(
    pull.mirrors,
    desired.servers["s1"].settings.registry_mirrors
  );
  let new_server = snapshot::committed_pull_policy(&current, "new");
  assert!(new_server.mirrors.is_empty());
  assert!(new_server.github_mirror.is_none());
}

#[test]
fn private_addr_rejects_loopback_and_public() {
  use wharf_api_types::spec::{Change, PrivateAddr, PrivateNetwork};
  let mut world = World::default();
  world.servers.insert(
    "s1".into(),
    ServerRow {
      settings: Default::default(),
      version: 1,
    },
  );
  for (ip, allowed) in [
    ("127.0.0.1", false),
    ("8.8.8.8", false),
    ("0.0.0.0", false),
    ("fe80::1", false),
    ("localhost", false),
    ("::1", false),
    ("10.0.0.5", true),
    ("100.80.1.2", true),
    ("fd00::1", true),
  ] {
    let result = world.apply_changes(&[Change::UpdateServer {
      name: "s1".into(),
      settings: wharf_api_types::spec::ServerSettings {
        private_addr: Some(PrivateAddr {
          ip: ip.into(),
          network: PrivateNetwork::Lan,
        }),
        ..Default::default()
      },
    }]);
    if allowed {
      result.unwrap();
    } else {
      assert_eq!(result.unwrap_err().code, ErrorCode::InvalidInput);
    }
  }
}

#[test]
fn service_cannot_reference_system_secret() {
  let mut world = World::default();
  add_route(
    &mut world,
    json!({
      "hostname": "a.example.test", "service": "a", "sso": {"mode": "oidc"}
    }),
  );
  for name in ["WHARF_BACKUP_KEY", "TAILSCALE_OAUTH", "OIDC_X"] {
    add_service(
      &mut world,
      "a",
      service(json!({"KEY": format!("[[{name}]]")})),
    );
    let err = policy::validate_world(&world).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains(name));
  }
  let oidc_key = crate::oidc::secret_name("a.example.test");
  add_service(
    &mut world,
    "a",
    service(json!({"KEY": format!("[[{oidc_key}]]")})),
  );
  policy::validate_world(&world).unwrap();
  let mut build = service(json!({}));
  build["source"] = json!({"build": {"git": {"repo": "https://example.test/a", "ref": "main", "token_secret": oidc_key}}});
  add_service(&mut world, "a", build);
  assert_eq!(
    policy::validate_world(&world).unwrap_err().code,
    ErrorCode::InvalidInput
  );
}

#[test]
fn service_secrets_only_contains_own_refs() {
  let mut world = World::default();
  add_service(
    &mut world,
    "a",
    service(json!({"TOKEN": "[[KEY_A]]"})),
  );
  add_service(
    &mut world,
    "b",
    service(json!({"TOKEN": "[[KEY_B]]"})),
  );
  let all = [
    ("KEY_A".into(), "value-a".into()),
    ("KEY_B".into(), "value-b".into()),
    ("WHARF_TEST".into(), "internal".into()),
  ]
  .into();
  assert_eq!(
    policy::service_secrets(&world, "a", &all),
    BTreeMap::from([("KEY_A".into(), "value-a".into())])
  );

  let snap = snapshot::Snapshot {
    account_links: AccountLinks::from([(
      "operator".into(),
      "b.example.test".into(),
    )]),
    service_values: [(
      "account.operator.password".into(),
      "account-value".into(),
    )]
    .into(),
    ..Default::default()
  };
  add_service(
    &mut world,
    "a",
    service(json!({"ACCOUNT": "[[FILE:account.operator.password]]"})),
  );
  add_route(
    &mut world,
    json!({"hostname": "b.example.test", "service": "b"}),
  );
  assert_eq!(
    policy::validate_accounts(&world, &snap.account_links)
      .unwrap_err()
      .code,
    ErrorCode::InvalidInput
  );
  assert!(snap.render_values(&world, "a").is_empty());
  add_route(
    &mut world,
    json!({"hostname": "b.example.test", "service": "a"}),
  );
  policy::validate_accounts(&world, &snap.account_links).unwrap();
  assert!(
    snap
      .render_values(&world, "a")
      .contains_key("account.operator.password")
  );
}

#[test]
fn borrowing_other_service_secret_requires_admin() {
  let mut world = World::default();
  let before = service(json!({"SHARED": "[[KEY_SHARED]]"}));
  add_service(&mut world, "a", before.clone());
  add_service(
    &mut world,
    "b",
    service(
      json!({"TOKEN": "[[KEY_B]]", "SHARED": "[[KEY_SHARED]]"}),
    ),
  );
  let change = |name: &str| {
    plan(
      "service/a",
      before.clone(),
      service(json!({
        "ADDED": format!("[[{name}]]"), "SHARED": "[[KEY_SHARED]]"
      })),
    )
  };
  let err = policy::require_apply(&change("KEY_B"), &world, false)
    .unwrap_err();
  assert_eq!(err.code, ErrorCode::Forbidden);
  assert!(err.message.contains("已经被服务 b 使用"));
  policy::require_apply(&change("KEY_B"), &world, true).unwrap();
  policy::require_apply(&change("KEY_NEW"), &world, false).unwrap();
  policy::require_apply(&change("KEY_SHARED"), &world, false)
    .unwrap();

  let mut desired = world.clone();
  let mut build = before;
  build["source"] = json!({"build": {"git": {"repo": "https://example.test/a", "ref": "main", "token_secret": "KEY_B"}}});
  add_service(&mut desired, "a", build);
  assert_eq!(
    policy::require_plan_git_secrets(&world, &desired, false)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
}

#[test]
fn restricted_secret_rejects_server_mirrors() {
  let restrictions =
    [("APP_KEY".into(), ["app".into()].into())].into();
  let mut world = World::default();
  for settings in [
    json!({"github_mirror": "https://git.example.test/[[url:APP_KEY]]"}),
    json!({"registry_mirrors": {
      "docker.io": ["https://registry.example.test/[[b64:APP_KEY]]"]
    }}),
  ] {
    world.servers.insert(
      "s1".into(),
      ServerRow {
        settings: serde_json::from_value(settings).unwrap(),
        version: 1,
      },
    );
    policy::validate_world(&world).unwrap();
    let err = policy::validate_restrictions(&world, &restrictions)
      .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(
      err.message,
      "服务器 s1 的镜像源不能引用密钥 APP_KEY，仅允许服务 app 引用"
    );
  }
}

#[test]
fn file_secret_is_rejected_in_non_service_contexts() {
  let mut world = World::default();
  let task: TaskKind = serde_json::from_value(json!({
    "kind": "container", "image": "nginx:1", "env": {"X": "[[FILE:X]]"}
  })).unwrap();
  let check = |err: wharf_api_types::ApiError| {
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.hint.unwrap().contains("[[json:X]]"));
  };
  check(policy::validate_task("task", &task).unwrap_err());
  world.servers.insert("s1".into(), ServerRow {
    settings: serde_json::from_value(json!({
      "registry_mirrors": {"docker.io": ["https://registry.example.test/[[FILE:X]]"]}
    })).unwrap(),
    version: 1,
  });
  check(policy::validate_world(&world).unwrap_err());
  world.servers.clear();
  let route = add_route(
    &mut world,
    json!({
      "hostname": "a.example.test", "service": "a", "sso": {"mode": "login", "login": {
        "script": {"runtime": "shell", "code": "true", "env": {"X": "[[FILE:X]]"}}
      }}
    }),
  );
  check(
    crate::sso_login::validate(
      "a.example.test",
      route.sso.as_ref().unwrap(),
    )
    .unwrap_err(),
  );
  check(policy::validate_world(&world).unwrap_err());
  world.routes.clear();
  add_route(
    &mut world,
    json!({
      "hostname": "a.example.test", "service": "a", "caddy": "[[FILE:X]]"
    }),
  );
  check(policy::validate_world(&world).unwrap_err());
}

#[test]
fn task_accepts_encoding_modifiers() {
  let task: TaskKind = serde_json::from_value(json!({
    "kind": "container", "image": "nginx:1",
    "env": {"URL": "[[url:K]]", "B64": "[[b64:K]]", "JSON": "[[json:K]]"}
  })).unwrap();
  policy::validate_task("task", &task).unwrap();
}

#[test]
fn secret_modifiers_preserve_system_and_cross_service_checks() {
  let mut world = World::default();
  for reference in
    ["[[FILE:WHARF_BACKUP_KEY]]", "[[b64:TAILSCALE_OAUTH]]"]
  {
    add_service(&mut world, "a", service(json!({"KEY": reference})));
    assert_eq!(
      policy::validate_world(&world).unwrap_err().code,
      ErrorCode::InvalidInput
    );
  }
  let before = service(json!({}));
  add_service(&mut world, "a", before.clone());
  add_service(&mut world, "b", service(json!({"KEY": "[[url:S]]"})));
  let change =
    plan("service/a", before, service(json!({"KEY": "[[FILE:S]]"})));
  assert_eq!(
    policy::require_apply(&change, &world, false)
      .unwrap_err()
      .code,
    ErrorCode::Forbidden
  );
  policy::require_apply(&change, &world, true).unwrap();
}

#[test]
fn task_rejects_system_secret() {
  let key = "[[TAILSCALE_OAUTH]]";
  for task in [
    json!({"kind": "host", "command": key}),
    json!({"kind": "exec", "service": "a", "command": key}),
    json!({"kind": "script", "runtime": "shell", "code": "true", "env": {"X": key}}),
    json!({"kind": "container", "image": "alpine:3", "command": key, "env": {"X": key}}),
  ] {
    let how: TaskKind = serde_json::from_value(task).unwrap();
    assert_eq!(
      policy::validate_task("task", &how).unwrap_err().code,
      ErrorCode::InvalidInput
    );
  }
  let all = [
    ("TAILSCALE_OAUTH".into(), "internal".into()),
    ("NOTIFY_URL_OPS".into(), "url".into()),
  ]
  .into();
  assert_eq!(
    policy::non_system_secrets(&all),
    BTreeMap::from([("NOTIFY_URL_OPS".into(), "url".into())])
  );
}

#[test]
fn sso_login_limited_to_target_service_secrets() {
  let mut world = World::default();
  add_service(
    &mut world,
    "a",
    service(json!({"TOKEN": "[[KEY_A]]"})),
  );
  add_service(
    &mut world,
    "b",
    service(json!({"TOKEN": "[[KEY_B]]"})),
  );
  let all = [
    ("KEY_A".into(), "value-a".into()),
    ("KEY_B".into(), "value-b".into()),
    ("TAILSCALE_OAUTH".into(), "internal".into()),
  ]
  .into();
  let route = |name: &str, use_account| {
    json!({
      "hostname": "a.example.test", "service": "a", "sso": {"mode": "login", "login": {
        "write": [{"local_storage": {"key": "token", "value": format!("{{{{secret.{name}}}}}")}}],
        "use_account": use_account,
      }}
    })
  };
  let spec = add_route(&mut world, route("KEY_A", false));
  policy::validate_world(&world).unwrap();
  let secrets = policy::login_secrets(&world, &spec, &all);
  assert_eq!(
    crate::sso_login::render(
      "{{secret.KEY_A}}",
      &Default::default(),
      &secrets
    )
    .unwrap(),
    "value-a"
  );
  for name in ["KEY_B", "TAILSCALE_OAUTH"] {
    add_route(&mut world, route(name, false));
    assert_eq!(
      policy::validate_world(&world).unwrap_err().code,
      ErrorCode::InvalidInput
    );
    assert!(!secrets.contains_key(name));
  }
  let plan = plan(
    "route/a.example.test",
    route("KEY_A", false),
    route("KEY_A", true),
  );
  assert_eq!(
    apply::require_login_account(&plan, false).unwrap_err().code,
    ErrorCode::Forbidden
  );
  apply::require_login_account(&plan, true).unwrap();
}

#[test]
fn acme_dns_key_only_in_dns_block() {
  let mut world = World::default();
  world.gateways.insert(
    "edge".into(),
    GatewayRow {
      spec: serde_json::from_value(json!({
        "kind": "caddy", "server": "s1", "wildcard": ["example.test"],
        "error_page": format!("<p>{}</p>", render::ACME_DNS_KEY),
      }))
      .unwrap(),
      version: 1,
    },
  );
  let err = policy::validate_world(&world).unwrap_err();
  assert_eq!(err.code, ErrorCode::InvalidInput);
  assert!(err.message.contains("错误页"));
  let net = render::Net::default();
  let placeholder =
    snapshot::gateway_render(&world, &net, "edge").unwrap();
  let filled = snapshot::gateway_render_with_fill(
    &world,
    &net,
    "edge",
    render::CaddyFill {
      acme_dns_url: None,
      acme_dns: Some(render::AcmeDnsFill {
        key: "test-dns-secret",
        url: "https://core.example.test/",
      }),
      ..Default::default()
    },
  )
  .unwrap();
  let old_block = "\ttls {\n\t\tdns acmedns {\n\t\t\tusername edge\n\t\t\tpassword [[WHARF_ACME_DNS_KEY]]\n\t\t\tsubdomain example.test\n\t\t\tserver_url [[WHARF_ACME_DNS_URL]]\n\t\t}\n\t}\n";
  let new_block = old_block
    .replace(render::ACME_DNS_KEY, "test-dns-secret")
    .replace(
      render::ACME_DNS_URL,
      "https://core.example.test/agent/acme-dns",
    );
  assert!(placeholder.needs_acme_dns);
  assert!(filled.config.contains(&new_block));
  assert_eq!(filled.config.matches("test-dns-secret").count(), 1);
  let legacy = filled.config.replace(&new_block, old_block);
  assert_eq!(placeholder.config, legacy);
  assert_eq!(placeholder.config_hash, render::hash(&legacy));
  assert!(filled.config.contains(render::ACME_DNS_KEY));
}

#[test]
fn secret_api_rejects_reserved_prefix() {
  for name in [
    "WHARF_X",
    "OIDC_X",
    "ACME_DNS_X",
    "NOTIFY_URL_X",
    "EGRESS_TOKEN",
  ] {
    assert_eq!(
      policy::refuse_managed(name).unwrap_err().code,
      ErrorCode::Forbidden
    );
  }
  for name in
    ["TAILSCALE_OAUTH", "NOTIFY_FEISHU_SECRET", "BASIC_AUTH_X"]
  {
    policy::refuse_managed(name).unwrap();
  }
}
