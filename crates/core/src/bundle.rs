use std::{
  collections::{BTreeMap, BTreeSet},
  io::{Read, Write},
  sync::Arc,
};

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{Extension, Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
  ChaCha20Poly1305, KeyInit, Nonce,
  aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError, ErrorCode, bundle::*, plan::PlanRequest, spec::Fleet,
  view::Perm,
};

use crate::secret_import::SecretChangesExt;

use crate::{
  api::ApiResult, audit::AuditSlot, auth::Auth, state::AppState,
};

const FORMAT: &str = "wharf-bundle";
const CIPHER: &str = "chacha20-poly1305";
const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
pub(crate) const MAX_REQUEST: usize = 24 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct BundlePayload {
  version: u8,
  exported_at: i64,
  partial: bool,
  fleet: Fleet,
  secrets: BTreeMap<String, BundleSecret>,
}

#[derive(Serialize, Deserialize)]
struct BundleSecret {
  value: String,
  #[serde(default)]
  pre_hashed: bool,
}

fn invalid_bundle() -> ApiError {
  ApiError::new(ErrorCode::Forbidden, "口令错误或加密包已损坏")
}

fn random<const N: usize>() -> Result<[u8; N], ApiError> {
  let mut bytes = [0; N];
  getrandom::fill(&mut bytes)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  Ok(bytes)
}

fn key(
  passphrase: &str,
  kdf: &BundleKdf,
  salt: &[u8],
) -> Result<ChaCha20Poly1305, ApiError> {
  let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
    .map_err(|_| invalid_bundle())?;
  let mut key = [0; 32];
  Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    .hash_password_into(passphrase.as_bytes(), salt, &mut key)
    .map_err(|_| invalid_bundle())?;
  Ok(ChaCha20Poly1305::new((&key).into()))
}

fn aad(kdf: &BundleKdf, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
  let mut data = b"wharf-bundle:v1\0".to_vec();
  for param in [kdf.m_kib, kdf.t, kdf.p] {
    data.extend(param.to_be_bytes());
  }
  data.extend(salt);
  data.extend(nonce);
  data
}

fn encrypt(
  passphrase: &str,
  payload: &BundlePayload,
) -> Result<EncryptedBundle, ApiError> {
  if passphrase.chars().count() < 12 {
    return Err(ApiError::invalid("加密口令至少 12 个字符"));
  }
  let plain = serde_json::to_vec(payload)
    .map_err(|_| ApiError::internal("无法编码便携包"))?;
  if plain.len() > MAX_PLAINTEXT {
    return Err(ApiError::invalid("便携包解压内容超过 16 MiB"));
  }
  let mut gz = flate2::write::GzEncoder::new(
    Vec::new(),
    flate2::Compression::default(),
  );
  gz.write_all(&plain)
    .map_err(|_| ApiError::internal("无法压缩便携包"))?;
  let compressed = gz
    .finish()
    .map_err(|_| ApiError::internal("无法压缩便携包"))?;
  let salt = random::<16>()?;
  let nonce = random::<12>()?;
  let kdf = BundleKdf {
    m_kib: 65536,
    t: 3,
    p: 1,
    salt: STANDARD.encode(salt),
  };
  let cipher = key(passphrase, &kdf, &salt)?;
  let ciphertext = cipher
    .encrypt(
      Nonce::from_slice(&nonce),
      Payload {
        msg: &compressed,
        aad: &aad(&kdf, &salt, &nonce),
      },
    )
    .map_err(|_| ApiError::internal("无法加密便携包"))?;
  Ok(EncryptedBundle {
    format: FORMAT.into(),
    version: 1,
    kdf,
    cipher: CIPHER.into(),
    nonce: STANDARD.encode(nonce),
    ciphertext: STANDARD.encode(ciphertext),
  })
}

fn decrypt(
  passphrase: &str,
  bundle: &EncryptedBundle,
) -> Result<BundlePayload, ApiError> {
  let kdf = &bundle.kdf;
  if bundle.format != FORMAT
    || bundle.version != 1
    || bundle.cipher != CIPHER
    || !(65536..=131072).contains(&kdf.m_kib)
    || !(3..=10).contains(&kdf.t)
    || !(1..=4).contains(&kdf.p)
    || bundle.ciphertext.len() > MAX_REQUEST
    || kdf.salt.len() != 24
    || bundle.nonce.len() != 16
  {
    return Err(invalid_bundle());
  }
  let salt =
    STANDARD.decode(&kdf.salt).map_err(|_| invalid_bundle())?;
  let nonce = STANDARD
    .decode(&bundle.nonce)
    .map_err(|_| invalid_bundle())?;
  if salt.len() != 16 || nonce.len() != 12 {
    return Err(invalid_bundle());
  }
  let ciphertext = STANDARD
    .decode(&bundle.ciphertext)
    .map_err(|_| invalid_bundle())?;
  let compressed = key(passphrase, kdf, &salt)?
    .decrypt(
      Nonce::from_slice(&nonce),
      Payload {
        msg: &ciphertext,
        aad: &aad(kdf, &salt, &nonce),
      },
    )
    .map_err(|_| invalid_bundle())?;
  let mut plain = Vec::new();
  flate2::read::GzDecoder::new(compressed.as_slice())
    .take(MAX_PLAINTEXT as u64 + 1)
    .read_to_end(&mut plain)
    .map_err(|_| invalid_bundle())?;
  if plain.len() > MAX_PLAINTEXT {
    return Err(ApiError::invalid("便携包解压内容超过 16 MiB"));
  }
  let payload: BundlePayload =
    serde_json::from_slice(&plain).map_err(|_| invalid_bundle())?;
  if payload.version != 1 {
    return Err(invalid_bundle());
  }
  Ok(payload)
}

pub(crate) async fn export(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<ExportBundleRequest>,
) -> ApiResult<ExportBundleResponse> {
  require_admin(&auth)?;
  let snap = crate::snapshot::load(&state.db).await?;
  let mut fleet = crate::views::export(&snap.world);
  let partial = !req.services.is_empty();
  if partial {
    for name in &req.services {
      if !fleet.services.contains_key(name) {
        return Err(crate::api::service_not_found(name).into());
      }
    }
    fleet.services.retain(|name, _| req.services.contains(name));
    fleet.routes.retain(|route| {
      req.services.contains(&route.service)
        || route.paths.iter().any(|path| {
          path
            .service
            .as_ref()
            .is_some_and(|n| req.services.contains(n))
        })
    });
  }
  fleet.servers.clear();
  fleet.gateways.clear();
  fleet.bookmarks.clear();
  fleet.edge_apps.clear();
  let (references, mut warnings) =
    crate::secret_policy::fleet_secret_refs(&fleet, &snap.secrets);
  let mut secrets = BTreeMap::new();
  let mut skipped_managed = Vec::new();
  for name in references {
    let basic = crate::render::is_auth_secret(&name);
    if crate::secret_policy::is_managed_secret(&name)
      || (!basic && crate::secret_policy::is_system_secret(&name))
    {
      skipped_managed.push(name);
    } else {
      secrets.insert(
        name.clone(),
        BundleSecret {
          value: snap.secrets[&name].clone(),
          pre_hashed: basic,
        },
      );
    }
  }
  if secrets.len() > 200
    || secrets.values().any(|v| v.value.len() > 64 * 1024)
  {
    return Err(
      ApiError::invalid("便携包最多 200 条密钥，每条最多 64 KiB")
        .into(),
    );
  }
  if !skipped_managed.is_empty() {
    warnings.push("请在目标集群补配所需的系统密钥".into());
  }
  let summary = BundleExportSummary {
    services: fleet.services.keys().cloned().collect(),
    routes: fleet.routes.iter().map(|r| r.hostname.clone()).collect(),
    secret_names: secrets.keys().cloned().collect(),
    skipped_managed,
    warnings,
  };
  let bundle = crate::login::run_argon2(move || {
    encrypt(
      &req.passphrase,
      &BundlePayload {
        version: 1,
        exported_at: crate::db::now_ms(),
        partial,
        fleet,
        secrets,
      },
    )
  })
  .await??;
  audit.set_detail(format!(
    "bundle_export services={} secrets={} names={}",
    summary.services.join(","),
    summary.secret_names.len(),
    summary.secret_names.join(",")
  ));
  Ok(Json(ExportBundleResponse { bundle, summary }))
}

pub(crate) async fn import(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<ImportBundleRequest>,
) -> ApiResult<serde_json::Value> {
  require_admin(&auth)?;
  auth.require(Perm::Plan)?;
  if req.dry_run {
    audit.skip_record();
  }
  let ImportBundleRequest {
    bundle,
    passphrase,
    mode,
    keep_days,
    server_map,
    default_server,
    gateway_map,
    no_routes,
    dry_run,
  } = req;
  let payload =
    crate::login::run_argon2(move || decrypt(&passphrase, &bundle))
      .await??;
  let mut snap = crate::snapshot::load(&state.db).await?;
  let mut fleet = payload.fleet;
  fleet.servers.clear();
  fleet.gateways.clear();
  fleet.bookmarks.clear();
  fleet.edge_apps.clear();
  let mut missing_servers = BTreeSet::new();
  let mut missing_gateways = BTreeSet::new();
  let mut backup_warnings = Vec::new();
  for (name, svc) in &mut fleet.services {
    if let Some(server) =
      server_map.get(&svc.server).or(default_server.as_ref())
    {
      svc.server.clone_from(server);
    }
    if !snap.world.servers.contains_key(&svc.server) {
      missing_servers.insert(svc.server.clone());
    }
    if let Some(backup) = &mut svc.backup {
      if let Some(server) = server_map.get(&backup.to) {
        backup.to.clone_from(server);
      }
      if !snap.world.servers.contains_key(&backup.to) {
        missing_servers.insert(backup.to.clone());
      }
      if backup.to == svc.server {
        backup_warnings.push(format!(
          "服务 {name} 的部署和备份服务器均为 {}",
          svc.server
        ));
      }
    }
    if let Some(heartbeat) = &mut svc.heartbeat {
      heartbeat.token.clear();
    }
  }
  if no_routes {
    fleet.routes.clear();
  }
  for route in &mut fleet.routes {
    for gateway in [&mut route.gateway, &mut route.backup_gateway]
      .into_iter()
      .flatten()
    {
      if let Some(mapped) = gateway_map.get(gateway) {
        gateway.clone_from(mapped);
      }
      if !snap.world.gateways.contains_key(gateway) {
        missing_gateways.insert(gateway.clone());
      }
    }
  }
  let mut values = BTreeMap::new();
  for (name, secret) in payload.secrets {
    if crate::render::is_auth_secret(&name) {
      if no_routes {
        continue;
      }
      if !secret.pre_hashed
        || crate::render::BasicAuth::parse(&secret.value).is_none()
      {
        return Err(
          ApiError::invalid("便携包内的 Basic Auth 哈希不合法")
            .into(),
        );
      }
    }
    values.insert(name, secret.value);
  }
  let (_, mut warnings) =
    crate::secret_policy::fleet_secret_refs(&fleet, &values);
  let secrets = crate::secret_import::write(
    &state,
    values.clone(),
    mode,
    keep_days,
    true,
  )
  .await?;
  if dry_run {
    warnings.extend(backup_warnings);
    return Ok(Json(
      serde_json::to_value(BundleImportPreview {
        services: fleet.services.keys().cloned().collect(),
        routes: fleet
          .routes
          .iter()
          .map(|r| r.hostname.clone())
          .collect(),
        secrets,
        missing_servers: missing_servers.into_iter().collect(),
        missing_gateways: missing_gateways.into_iter().collect(),
        warnings,
        hint: "加 --plan-only 写入密钥并生成计划，或加 --apply 执行"
          .into(),
      })
      .map_err(crate::db::json_err)?,
    ));
  }
  if !missing_servers.is_empty() || !missing_gateways.is_empty() {
    return Err(ApiError::invalid("便携包引用目标集群没有的服务器或网关")
      .with_details(serde_json::json!({ "missing_servers": missing_servers, "missing_gateways": missing_gateways })).into());
  }
  crate::secret_import::require_no_conflicts(&secrets)?;
  for name in secrets.create.iter().chain(&secrets.update) {
    snap.secrets.insert(name.clone(), values[name].clone());
    snap
      .service_values
      .insert(name.clone(), values[name].clone());
  }
  // 便携包的旧服务没有时区字段时，按原环境部署。
  for svc in fleet.services.values_mut() {
    if !matches!(
      svc.source,
      wharf_api_types::spec::Source::Compose { .. }
    ) && svc.timezone.is_none()
    {
      svc.timezone = Some("off".into());
    }
  }
  let planned = crate::planner::make_plan_inner(
    &state,
    PlanRequest {
      partial: Some(fleet),
      ..Default::default()
    },
    snap,
    true,
    true,
  )
  .await?;
  let plan = planned.plan.clone();
  let expected = secrets;
  let secrets = crate::secret_import::write_with(
    &state,
    values,
    mode,
    keep_days,
    false,
    move |c, key, actual| {
      if actual != &expected {
        return Err(ApiError::new(
          ErrorCode::PlanStale,
          "导入期间密钥状态变了，请重新预览",
        ));
      }
      crate::apply::require_fresh(
        c,
        key,
        &planned.plan,
        Some(&planned.account_refs),
        Some(&planned.base_instances),
      )?;
      crate::planner::save_in(c, &planned)
    },
  )
  .await?;
  audit.set_detail(format!(
    "bundle_import {} plan_id={}",
    secrets.audit(),
    plan.plan_id
  ));
  Ok(Json(
    serde_json::to_value(BundleImportResponse {
      secrets: SecretImportResponse {
        created: secrets.create,
        updated: secrets.update,
        skipped: secrets.skip,
      },
      plan,
      warnings,
    })
    .map_err(crate::db::json_err)?,
  ))
}

fn require_admin(auth: &Auth) -> Result<(), ApiError> {
  auth.require(Perm::Admin).map_err(|err| err.0)?;
  if auth.services.is_some() {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "便携包需要完整管理权限",
    ));
  }
  Ok(())
}

#[test]
fn bundle_envelope_roundtrip_and_rejects_wrong_passphrase() {
  let payload = BundlePayload {
    version: 1,
    exported_at: 0,
    partial: true,
    fleet: Fleet::default(),
    secrets: BTreeMap::from([(
      "DB_PASS".into(),
      BundleSecret {
        value: "fixture-sensitive-value".into(),
        pre_hashed: false,
      },
    )]),
  };
  let bundle = encrypt("fixture-passphrase", &payload).unwrap();
  assert!(
    !serde_json::to_string(&bundle)
      .unwrap()
      .contains("fixture-sensitive-value")
  );
  assert_eq!(
    decrypt("different-passphrase", &bundle).err().unwrap().code,
    ErrorCode::Forbidden
  );
  assert_eq!(decrypt("fixture-passphrase", &bundle).unwrap().secrets["DB_PASS"].value, "fixture-sensitive-value");
}

#[tokio::test]
async fn bundle_import_maps_backup_and_commits_secrets_with_plan() {
  use serde_json::json;
  let state = crate::rules::tests::test_state();
  state
    .db
    .call(|c| {
      for server in ["s1", "s2"] {
        crate::db::apply_write(
          c,
          &crate::db::Write::Upsert {
            kind: "server".into(),
            name: server.into(),
            spec: json!({}),
            meta: json!({}),
          },
        )?;
      }
      Ok(())
    })
    .await
    .unwrap();
  let payload = BundlePayload {
    version: 1,
    exported_at: 0,
    partial: true,
    fleet: serde_json::from_value(json!({
      "services": {"blog": {"server": "old-app", "source": {"image": format!("fixture@sha256:{}", "a".repeat(64))},
        "env": {"PASS": "[[BLOG_PASS]]"},
        "backup": {"to": "old-backup"}, "volumes": [{"name": "data", "target": "/data"}]}}
    })).unwrap(),
    secrets: BTreeMap::from([("BLOG_PASS".into(), BundleSecret {
      value: "fixture-secret".into(), pre_hashed: false,
    })]),
  };
  let encoded = serde_json::to_string(
    &encrypt("fixture-passphrase", &payload).unwrap(),
  )
  .unwrap();
  let request = |dry_run, backup: Option<&str>| {
    let mut server_map =
      BTreeMap::from([("old-app".into(), "s1".into())]);
    if let Some(backup) = backup {
      server_map.insert("old-backup".into(), backup.into());
    }
    import(
      State(state.clone()),
      crate::host_access::tests::auth(
        [Perm::Admin, Perm::Plan],
        false,
      ),
      Extension(AuditSlot::default()),
      Json(ImportBundleRequest {
        bundle: serde_json::from_str(&encoded).unwrap(),
        passphrase: "fixture-passphrase".into(),
        mode: Default::default(),
        keep_days: None,
        server_map,
        default_server: None,
        gateway_map: BTreeMap::new(),
        no_routes: false,
        dry_run,
      }),
    )
  };
  let state_counts = || {
    state.db.call(|c| {
    c.query_row("SELECT (SELECT COUNT(*) FROM secrets WHERE name = 'BLOG_PASS'), (SELECT COUNT(*) FROM plans)", [],
      |row| Ok((row.get::<_, usize>(0)?, row.get::<_, usize>(1)?))).map_err(crate::db::sql_err)
  })
  };
  assert_eq!(
    request(true, None)
      .await
      .map_err(|error| error.0)
      .unwrap()
      .0["missing_servers"],
    json!(["old-backup"])
  );
  assert!(request(false, Some("s1")).await.is_err());
  assert_eq!(state_counts().await.unwrap(), (0, 0));
  state.db.call(|c| {
    c.execute_batch("CREATE TRIGGER reject_plan BEFORE INSERT ON plans BEGIN SELECT RAISE(ABORT, 'fixture'); END;")
      .map_err(crate::db::sql_err)
  }).await.unwrap();
  assert!(request(false, Some("s2")).await.is_err());
  assert_eq!(state_counts().await.unwrap(), (0, 0));
  state
    .db
    .call(|c| {
      c.execute_batch("DROP TRIGGER reject_plan")
        .map_err(crate::db::sql_err)
    })
    .await
    .unwrap();
  let result = request(false, Some("s2"))
    .await
    .map_err(|error| error.0)
    .unwrap()
    .0;
  assert_eq!(
    result["secrets"],
    json!({"created": ["BLOG_PASS"], "updated": [], "skipped": []})
  );
  assert!(result["plan"]["plan_id"].is_string());
  assert!(result["plan"]["items"].as_array().unwrap().iter().any(
    |item| {
      item["address"] == "service/blog"
        && item["layer"] == "config"
        && item["after"].get("timezone").is_none()
    }
  ));
  assert_eq!(state_counts().await.unwrap(), (1, 1));
}
