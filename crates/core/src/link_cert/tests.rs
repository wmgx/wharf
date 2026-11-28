use std::{
  collections::BTreeMap,
  net::SocketAddr,
  sync::{Arc, Mutex},
};

use axum::{
  body::{Body, to_bytes},
  extract::ConnectInfo,
  http::{Request, StatusCode, header},
};
use rustls_pki_types::{ServerName, UnixTime};
use serde_json::{Value, json};
use tower::ServiceExt;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentMsg, AgentOp, ContainerInfo, GatewayApply, ProjectState,
  },
  plan::{Action, PlanRequest},
  spec::{Change, GatewayTls},
  view::{IssueLevel, Perm},
};

use super::*;
use crate::{
  api, apply, auth,
  planner::{self, Step},
  snapshot::{self, GatewayRender},
  state::AppState,
  world::{KIND_GATEWAY, ServerRow, World, gateway_project},
};

fn check_chain(
  ca: &Certificate,
  leaf: &Certificate,
  now: OffsetDateTime,
) -> Result<(), webpki::Error> {
  let ca = webpki::anchor_from_trusted_cert(ca.der())?;
  webpki::EndEntityCert::try_from(leaf.der())?
    .verify_for_usage(
      webpki::ALL_VERIFICATION_ALGS,
      &[ca],
      &[],
      UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        now.unix_timestamp() as u64,
      )),
      webpki::KeyUsage::server_auth(),
      None,
      None,
    )
    .map(|_| ())
}

#[test]
fn link_ca_signs_server_certificate_with_expected_lifetime() {
  let now = OffsetDateTime::now_utc();
  let (ca, key) = generate_ca(now).unwrap();
  let (leaf, _) = issue_gateway_cert(&ca, &key, "gw-a", now).unwrap();
  check_chain(&ca, &leaf, now).unwrap();
  let leaf_der = webpki::EndEntityCert::try_from(leaf.der()).unwrap();
  leaf_der
    .verify_is_valid_for_subject_name(
      &ServerName::try_from(LINK_HOST).unwrap(),
    )
    .unwrap();
  assert!(
    leaf_der
      .verify_is_valid_for_subject_name(
        &ServerName::try_from("evil.example.com").unwrap()
      )
      .is_err()
  );
  assert_eq!(
    pem_not_after(&ca.pem()).unwrap().timestamp(),
    now.unix_timestamp() + CA_TTL_DAYS * 86_400
  );
  assert_eq!(
    pem_not_after(&leaf.pem()).unwrap().timestamp(),
    now.unix_timestamp() + LEAF_TTL_DAYS * 86_400
  );
}

#[test]
fn link_ca_rejects_untrusted_issuer() {
  let now = OffsetDateTime::now_utc();
  let (trusted, _) = generate_ca(now).unwrap();
  let other_key =
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
  let mut other = ca_params(now);
  other
    .distinguished_name
    .push(DnType::CommonName, "Untrusted Link CA");
  let other = other.self_signed(&other_key).unwrap();
  let (leaf, _) =
    issue_gateway_cert(&other, &other_key, "gw-a", now).unwrap();
  assert_eq!(
    check_chain(&trusted, &leaf, now).unwrap_err(),
    webpki::Error::UnknownIssuer
  );
}

fn world(second_gateway: bool) -> World {
  let mut world = World::default();
  for (index, name) in ["s1", "s2", "s3"].into_iter().enumerate() {
    world.servers.insert(
      name.into(),
      ServerRow {
        settings: serde_json::from_value(
          json!({"public_ip": format!("203.0.113.{}", index + 1)}),
        )
        .unwrap(),
        version: 1,
      },
    );
  }
  let mut changes = vec![
    json!({"op":"upsert_gateway","name":"gw-a","spec":{"kind":"caddy","server":"s1","default":true}}),
    json!({"op":"upsert_service","name":"app","spec":{"server":"s3","source":{"image":"traefik/whoami:1.11.0"},"ports":[{"name":"http","container":80}]}}),
    json!({"op":"upsert_route","spec":{"hostname":"a.example.com","service":"app","gateway":"gw-a","link":"tunnel"}}),
  ];
  if second_gateway {
    changes.extend([
      json!({"op":"upsert_gateway","name":"gw-b","spec":{"kind":"caddy","server":"s2"}}),
      json!({"op":"upsert_route","spec":{"hostname":"b.example.com","service":"app","gateway":"gw-b","link":"tunnel"}}),
    ]);
  }
  let changes: Vec<Change> = changes
    .into_iter()
    .map(|v| serde_json::from_value(v).unwrap())
    .collect();
  world.apply_changes(&changes).unwrap();
  world.allocate_ports().unwrap();
  world.services.get_mut("app").unwrap().pins.insert(
    "traefik/whoami:1.11.0".into(),
    format!("sha256:{}", "a".repeat(64)),
  );
  world
}

#[tokio::test]
async fn tokens_are_isolated_between_gateway_projects() {
  let world = world(true);
  let net = Net::derive(&world.servers, &[]);
  let secrets = db::Db::memory()
    .call_credentials(|c, key| {
      for gateway in ["gw-a", "gw-b"] {
        db::ensure_scoped_secret(
          c,
          key,
          link::TOKEN_PREFIX,
          gateway,
          db::now_ms(),
        )?;
      }
      let tx = c.transaction().map_err(db::sql_err)?;
      ensure_ca(&tx, key, db::now_ms())?;
      tx.commit().map_err(db::sql_err)?;
      db::secrets(c, key)
    })
    .await
    .unwrap();
  let a = &secrets["WHARF_LINK_TOKEN_gw-a"];
  let b = &secrets["WHARF_LINK_TOKEN_gw-b"];
  assert!(a != b);
  let projects =
    link::projects_with_secrets(&world, &net, &secrets).unwrap();
  assert_eq!(projects.len(), 4);
  for (server, project, own, other) in [
    ("s1", "wharf-link", a, b),
    ("s2", "wharf-link", b, a),
    ("s3", "wharf-link-s1", a, b),
    ("s3", "wharf-link-s2", b, a),
  ] {
    let p = projects
      .iter()
      .find(|p| p.server == server && p.project == project)
      .unwrap();
    assert!(p.compose.contains(own));
    assert!(!p.compose.contains(other));
  }
}

#[test]
fn frp_uses_inline_configs_and_encrypts_every_proxy() {
  let token = auth::new_token();
  let rotated = auth::new_token();
  let (ca, _) = generate_ca(OffsetDateTime::now_utc()).unwrap();
  let proxies = [
    ("app.http".into(), 20000, 30000),
    ("app.admin".into(), 20001, 30001),
  ];
  let client = |secret| {
    render::frpc_compose(
      "wharf-link-s1",
      "203.0.113.1",
      443,
      &proxies,
      secret,
      &ca.pem(),
    )
  };
  let server = |secret| render::frps_compose("wharf-link", secret);
  for (bin, compose, after) in [
    ("frps", server(&token), server(&rotated)),
    ("frpc", client(&token), client(&rotated)),
  ] {
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&compose).unwrap();
    let service = &yaml["services"][bin];
    let config = &service["configs"][0];
    assert!(service.get("environment").is_none());
    assert!(!compose.contains("sh -c"));
    let config_path = format!("/etc/frp/{bin}.toml");
    assert_eq!(service["entrypoint"][0].as_str(), Some(bin));
    assert_eq!(
      service["entrypoint"][2].as_str(),
      Some(config_path.as_str())
    );
    assert_eq!(config["target"].as_str(), Some(config_path.as_str()));
    let source = config["source"].as_str().unwrap();
    assert_eq!(source.rsplit('-').next().unwrap().len(), 12);
    let toml = yaml["configs"][source]["content"].as_str().unwrap();
    assert!(toml.contains(&token));
    assert!(!after.contains(source));
    assert!(render::hash(&compose) != render::hash(&after));
    if bin == "frpc" {
      assert_eq!(
        service["configs"][1]["target"].as_str(),
        Some("/etc/frp/ca.pem")
      );
      assert!(toml.contains(
        r#"transport.tls.trustedCaFile = "/etc/frp/ca.pem""#
      ));
      let sections: Vec<_> =
        toml.split("[[proxies]]").skip(1).collect();
      assert_eq!(sections.len(), 2);
      assert!(
        sections
          .iter()
          .all(|s| s.contains("transport.useEncryption = true"))
      );
    }
  }
}

#[test]
fn tunnel_site_uses_issued_certificate_and_rejects_tls_off() {
  let mut world = world(false);
  let net = Net::derive(&world.servers, &[]);
  for tls in [GatewayTls::Auto, GatewayTls::Internal, GatewayTls::Off]
  {
    world.gateways.get_mut("gw-a").unwrap().spec.tls = tls;
    let rendered = snapshot::gateway_render(&world, &net, "gw-a");
    if tls == GatewayTls::Off {
      let error = rendered.err().unwrap();
      assert_eq!(error.code, ErrorCode::InvalidInput);
      assert!(error.hint.unwrap().contains("gw-a"));
    } else {
      let GatewayRender {
        config,
        needs_link_cert,
        ..
      } = rendered.unwrap();
      assert!(needs_link_cert);
      let site =
        config.split("link.wharf.internal {").nth(1).unwrap();
      assert!(
        site.contains("tls /etc/caddy/link.crt /etc/caddy/link.key")
      );
      assert!(!site.contains("tls internal"));
    }
  }
}

#[test]
fn secret_registry_preserves_notify_templates_and_redacts_private_material()
 {
  use crate::secret_policy::{
    describe, redact_values, refuse_managed, validate_world,
  };
  let mut world = world(false);
  let app = world.services.get_mut("app").unwrap();
  app
    .spec
    .env
    .insert("WEBHOOK".into(), "[[NOTIFY_URL_ops]]".into());
  validate_world(&world).unwrap();
  world
    .services
    .get_mut("app")
    .unwrap()
    .spec
    .env
    .insert("CREDENTIAL".into(), "[[WHARF_LINK_TOKEN_gw-a]]".into());
  assert!(validate_world(&world).is_err());
  let (cert, key) = generate_ca(OffsetDateTime::now_utc()).unwrap();
  let secrets = BTreeMap::<String, String>::from([
    ("WHARF_LINK_TOKEN_gw-a".into(), auth::new_token()),
    (CA_CERT_SECRET.into(), cert.pem()),
    (CA_KEY_SECRET.into(), key.serialize_pem()),
    ("WHARF_BACKUP_KEY_notes".into(), auth::new_token()),
    (
      "WHARF_BACKUP_HTTP_HASH_notes".into(),
      "测试用哈希占位".into(),
    ),
    ("NOTIFY_URL_ops".into(), "https://example.com/hook".into()),
  ]);
  for name in secrets.keys() {
    assert!(describe(name).unwrap().managed);
    assert_eq!(
      refuse_managed(name).unwrap_err().code.http_status(),
      403
    );
  }
  let redacted = redact_values(&secrets);
  assert!(redacted.contains(&secrets["WHARF_LINK_TOKEN_gw-a"]));
  assert!(redacted.contains(&secrets["NOTIFY_URL_ops"]));
  assert!(
    secrets[CA_KEY_SECRET]
      .lines()
      .skip(1)
      .take_while(|line| !line.starts_with("-----"))
      .all(|line| redacted.iter().any(|value| value == line))
  );
  assert!(!redacted.contains(&secrets[CA_CERT_SECRET]));
  assert!(
    !redacted.contains(&secrets["WHARF_BACKUP_HTTP_HASH_notes"])
  );
}

#[tokio::test]
async fn scoped_credentials_are_idempotent_rotatable_and_deleted_with_gateway()
 {
  db::Db::memory()
    .call_credentials(|c, key| {
      let tx = c.transaction().map_err(db::sql_err)?;
      let now = db::now_ms();
      let token = db::ensure_scoped_secret(
        &tx,
        key,
        link::TOKEN_PREFIX,
        "gw-a",
        now,
      )?;
      assert!(
        token
          == db::ensure_scoped_secret(
            &tx,
            key,
            link::TOKEN_PREFIX,
            "gw-a",
            now
          )?
      );
      let rotated = db::rotate_scoped_secret(
        &tx,
        key,
        link::TOKEN_PREFIX,
        "gw-a",
        now,
      )?;
      assert!(token != rotated);
      assert!(
        Some(rotated) == key.secret(&tx, "WHARF_LINK_TOKEN_gw-a")?
      );
      ensure_gateway_cert(&tx, key, "gw-a", now, false)?;
      ensure_gateway_cert(&tx, key, "gw-b", now, false)?;
      db::ensure_scoped_secret(
        &tx,
        key,
        link::TOKEN_PREFIX,
        "gw-b",
        now,
      )?;
      db::ensure_secret(&tx, key, "WHARF_LINK_TOKEN", now)?;
      let before = db::secrets(&tx, key)?;
      for write in world(true).writes_from(&World::default()) {
        db::apply_write(&tx, &write)?;
      }
      db::apply_write(
        &tx,
        &db::Write::Delete {
          kind: KIND_GATEWAY.into(),
          name: "gw-a".into(),
        },
      )?;
      let after = db::secrets(&tx, key)?;
      assert_eq!(after.len(), before.len() - 3);
      for (name, value) in before {
        if name.ends_with("_gw-a") {
          assert!(!after.contains_key(&name));
        } else {
          assert!(after.get(&name) == Some(&value));
        }
      }
      tx.commit().map_err(db::sql_err)
    })
    .await
    .unwrap();
}

type Projects = Arc<Mutex<BTreeMap<String, ProjectState>>>;

fn fake_agent(
  state: &AppState,
  server: &str,
  capable: bool,
) -> Projects {
  let projects = Projects::default();
  let live = projects.clone();
  state.hub.mock_agent(server, capable, move |op| {
    let mut live = live.lock().unwrap();
    let (up, config_hash) = match op {
      AgentOp::ProjectStatus { projects, .. } => {
        return Ok(json!(
          projects
            .iter()
            .filter_map(|p| live.get(p))
            .collect::<Vec<_>>()
        ));
      }
      AgentOp::EnsureDirs { .. } => return Ok(Value::Null),
      AgentOp::ProjectUp(up) => (up, None),
      AgentOp::GatewayApply(apply) => {
        assert_eq!(
          apply.extra_files.len(),
          if apply.caddyfile.contains("link.wharf.internal") {
            2
          } else {
            0
          }
        );
        (apply.up, Some(apply.caddyfile_hash))
      }
      _ => {
        return Err(ApiError::internal("测试收到意外的 agent 操作"));
      }
    };
    let info =
      running_project(up.project.clone(), up.hash, config_hash);
    let result = json!({"containers": info.containers, "images": []});
    live.insert(up.project, info);
    Ok(result)
  });
  projects
}

fn running_project(
  project: String,
  hash: String,
  config_hash: Option<String>,
) -> ProjectState {
  ProjectState {
    project: project.clone(),
    hash: Some(hash),
    config_hash,
    acme_dns_url_hash: None,
    frpc_admin_port: None,
    containers: vec![serde_json::from_value::<ContainerInfo>(json!({
      "service": project, "name": "container", "image": "fixture:1", "state": "running",
    })).unwrap()],
  }
}

async fn seed(state: &AppState, world: World) {
  let writes = world.writes_from(&World::default());
  state
    .db
    .call(move |c| {
      for write in writes {
        db::apply_write(c, &write)?;
      }
      Ok(())
    })
    .await
    .unwrap();
}

async fn make_plan(
  state: &AppState,
) -> Result<planner::Planned, ApiError> {
  planner::make_plan(state, PlanRequest::default()).await
}

async fn apply_steps(state: &AppState, plan: &planner::Planned) {
  for step in &plan.steps {
    apply::run_step(
      state,
      "r1",
      &step.step,
      Arc::new(|_| {}),
      &Default::default(),
    )
    .await
    .unwrap();
  }
}

#[tokio::test]
async fn old_agent_defaults_and_capability_gate_only_tunnel_gateways()
{
  let hello: AgentMsg = serde_json::from_value(json!({
    "type":"hello","server":"s1","public_key":"k","signature":"s","nonce":"n","version":"0.1.0","protocol":2
  })).unwrap();
  assert!(matches!(
    hello,
    AgentMsg::Hello {
      gateway_extra_files: false,
      ..
    }
  ));
  let apply: GatewayApply = serde_json::from_value(json!({
    "up":{"project":"wharf-gw-gw-a","compose":"","hash":"old","pull":{"mirrors":{},"mirrors_only":false,"attempt_timeout_secs":10}},
    "image":"fixture:1","caddyfile":"","caddyfile_hash":"old"
  })).unwrap();
  assert!(apply.extra_files.is_empty());

  let state = crate::rules::tests::test_state();
  fake_agent(&state, "s1", false);
  fake_agent(&state, "s3", true);
  seed(&state, world(false)).await;
  let error = make_plan(&state).await.err().unwrap();
  assert_eq!(error.code, ErrorCode::Conflict);
  assert_eq!(error.suggest, ["wharf server upgrade s1"]);
  let step = Step::GatewaySync {
    gateway: "gw-a".into(),
    after_dns: false,
    expect: None,
  };
  let cancel = tokio_util::sync::CancellationToken::new();
  let run = || {
    apply::run_step(&state, "r1", &step, Arc::new(|_| {}), &cancel)
  };
  let error = run().await.unwrap_err();
  assert_eq!(error.code, ErrorCode::Conflict);
  assert_eq!(error.suggest, ["wharf server upgrade s1"]);

  state
    .db
    .call(move |c| {
      db::apply_write(
        c,
        &db::Write::Delete {
          kind: "route".into(),
          name: "a.example.com".into(),
        },
      )
    })
    .await
    .unwrap();
  make_plan(&state).await.unwrap();
  run().await.unwrap();
}

#[tokio::test]
async fn first_tunnel_plan_writes_no_secrets_and_applies_in_order_without_drift()
 {
  let state = crate::rules::tests::test_state();
  fake_agent(&state, "s1", true);
  fake_agent(&state, "s3", true);
  seed(&state, world(false)).await;
  let plan = make_plan(&state).await.unwrap();
  let snap = snapshot::load(&state.db).await.unwrap();
  assert!(snap.secrets.is_empty());
  let order: Vec<_> = plan
    .steps
    .iter()
    .filter_map(|s| match &s.step {
      Step::LinkUp { .. } | Step::GatewaySync { .. } => {
        Some(s.step.order())
      }
      _ => None,
    })
    .collect();
  assert_eq!(order, [3, 4, 5]);
  for step in &plan.steps {
    apply::run_step(
      &state,
      "r1",
      &step.step,
      Arc::new(|_| {}),
      &Default::default(),
    )
    .await
    .unwrap();
    if matches!(&step.step, Step::LinkUp { project, .. } if project == link::SERVER_PROJECT)
    {
      let secrets = snapshot::load(&state.db).await.unwrap().secrets;
      assert_eq!(secrets.len(), 1);
      assert!(secrets.contains_key("WHARF_LINK_TOKEN_gw-a"));
    }
  }
  let snap = snapshot::load(&state.db).await.unwrap();
  assert_eq!(snap.secrets.len(), 5);
  assert!(make_plan(&state).await.unwrap().plan.items.is_empty());
}

#[tokio::test]
async fn link_rotation_requires_admin_and_updates_only_selected_projects()
 {
  let state = crate::rules::tests::test_state();
  fake_agent(&state, "s1", true);
  fake_agent(&state, "s3", true);
  seed(&state, world(false)).await;
  let initial = make_plan(&state).await.unwrap();
  apply_steps(&state, &initial).await;

  let admin = auth::new_token();
  let read = auth::new_token();
  state
    .db
    .call({
      let (admin, read) = (admin.clone(), read.clone());
      move |c| {
        auth::insert_token(c, "admin", &Perm::ALL, &admin)?;
        auth::insert_token(c, "read", &[Perm::Read], &read)?;
        db::apply_write(
          c,
          &db::Write::Upsert {
            kind: KIND_GATEWAY.into(),
            name: "cloud".into(),
            spec: json!({"kind":"cloudflare_tunnel","server":"s2"}),
            meta: json!({}),
          },
        )
      }
    })
    .await
    .unwrap();
  let router = api::router(state.clone());
  let rotate = |name: &str, token: &str, body: &'static str| {
    router.clone().oneshot(
      Request::post(format!("/api/gateways/{name}/link/rotate"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(ConnectInfo(
          "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(body))
        .unwrap(),
    )
  };
  assert_eq!(
    rotate("gw-a", &read, "{}").await.unwrap().status(),
    StatusCode::FORBIDDEN
  );
  assert_eq!(
    rotate("cloud", &admin, "{}").await.unwrap().status(),
    StatusCode::BAD_REQUEST
  );
  assert_eq!(
    rotate("gw-a", &admin, r#"{"token":false,"cert":false}"#)
      .await
      .unwrap()
      .status(),
    StatusCode::BAD_REQUEST
  );
  state
    .db
    .call(|c| {
      db::apply_write(
        c,
        &db::Write::Delete {
          kind: KIND_GATEWAY.into(),
          name: "cloud".into(),
        },
      )
    })
    .await
    .unwrap();

  for (body, expected) in [
    (r#"{"token":false,"cert":true}"#, vec!["gateway/gw-a"]),
    (
      r#"{"token":true,"cert":false}"#,
      vec!["link/s1/wharf-link", "link/s3/wharf-link-s1"],
    ),
    (
      "{}",
      vec![
        "gateway/gw-a",
        "link/s1/wharf-link",
        "link/s3/wharf-link-s1",
      ],
    ),
  ] {
    let response = rotate("gw-a", &admin, body).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(!text.contains("-----BEGIN"));
    let snap = snapshot::load(&state.db).await.unwrap();
    assert!(snap.secrets.values().all(|value| !text.contains(value)));
    let plan = make_plan(&state).await.unwrap();
    let mut changes: Vec<_> =
      plan.plan.items.iter().map(|i| i.address.as_str()).collect();
    changes.sort_unstable();
    assert_eq!(changes, expected);
    assert!(
      plan.plan.items.iter().all(|i| i.action == Action::Update)
    );
    apply_steps(&state, &plan).await;
  }
}

#[tokio::test]
async fn expiry_windows_trigger_renewal_issues_and_rules() {
  let _lock = crate::rules::tests::TEST_LOCK.lock().await;
  let state = crate::rules::tests::test_state();
  let gateway = fake_agent(&state, "s1", true);
  fake_agent(&state, "s3", true);
  seed(&state, world(false)).await;
  let initial = make_plan(&state).await.unwrap();
  apply_steps(&state, &initial).await;

  for days in [200, 60, 20, -1] {
    let issued_at = (Utc::now()
      - Duration::days(LEAF_TTL_DAYS - days))
    .timestamp_millis();
    state
      .db
      .call_credentials(move |c, key| {
        let tx = c.transaction().map_err(db::sql_err)?;
        ensure_gateway_cert(&tx, key, "gw-a", issued_at, true)?;
        tx.commit().map_err(db::sql_err)
      })
      .await
      .unwrap();
    let snap = snapshot::load(&state.db).await.unwrap();
    let net = snap.net(&snap.world);
    let rendered =
      snapshot::gateway_render(&snap.world, &net, "gw-a").unwrap();
    gateway
      .lock()
      .unwrap()
      .get_mut(&gateway_project("gw-a"))
      .unwrap()
      .config_hash = Some(config_hash(
      &rendered.config,
      &net.link_certs["gw-a"].fingerprint,
    ));
    let issues = issues(&snap, &net);
    let expected = match days {
      200 => None,
      -1 => Some(IssueLevel::Fault),
      _ => Some(IssueLevel::Warn),
    };
    assert_eq!(
      issues
        .iter()
        .find(|i| i.code == "link_cert_expiring")
        .map(|i| i.level),
      expected
    );
    let plan = make_plan(&state).await.unwrap();
    assert_eq!(plan.plan.items.len(), usize::from(days <= 90));
    if days <= 90 {
      assert_eq!(plan.plan.items[0].address, "gateway/gw-a");
      assert!(plan.plan.items[0].reason.contains("续签"));
    }
    crate::alerts::observe_link_certificates(&state, &snap).await;
    let observed =
      crate::rules::firing_subjects("link_cert_expiring")
        .iter()
        .any(|(name, _)| name == "gw-a");
    assert_eq!(observed, days <= 30);
  }
  let mut snap = snapshot::load(&state.db).await.unwrap();
  let (ca, _) = generate_ca(
    OffsetDateTime::now_utc()
      - time::Duration::days(CA_TTL_DAYS - 100),
  )
  .unwrap();
  snap.secrets.insert(CA_CERT_SECRET.into(), ca.pem());
  let net = snap.net(&snap.world);
  assert!(issues(&snap, &net).iter().any(|i| i.code
    == "link_ca_expiring"
    && i.level == IssueLevel::Warn));
  crate::alerts::observe_link_certificates(&state, &snap).await;
  assert!(
    !crate::rules::firing_subjects("link_ca_expiring").is_empty()
  );
  crate::rules::tests::reset_memory();
}

mod review;
