//! 原子导入业务密钥。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Extension, Json,
  extract::{State, rejection::JsonRejection},
};
use rusqlite::{Connection, TransactionBehavior};
use serde::Deserialize;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{Perm, SecretImportMode, SecretImportResponse},
};

use crate::{
  api::ApiResult,
  audit::AuditSlot,
  auth::Auth,
  db::{self, CredentialsKey, sql_err},
  secret_policy,
  state::AppState,
  world::World,
};

#[derive(Deserialize)]
pub struct SecretImportRequest {
  items: BTreeMap<String, String>,
  #[serde(default)]
  mode: SecretImportMode,
  keep_days: Option<u16>,
}

impl std::fmt::Debug for SecretImportRequest {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("SecretImportRequest")
      .field("items_count", &self.items.len())
      .finish()
  }
}

pub async fn import(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  body: Result<Json<SecretImportRequest>, JsonRejection>,
) -> ApiResult<SecretImportResponse> {
  auth.require(Perm::Admin)?;
  let Json(mut req) = body.map_err(|_| {
    ApiError::invalid("批量导入请求格式不对或超过大小限制")
  })?;
  if req.items.is_empty() || req.items.len() > 200 {
    return Err(
      ApiError::invalid("每次须导入 1 到 200 条密钥").into(),
    );
  }
  if req.keep_days.is_some_and(|n| n > 30) {
    return Err(
      ApiError::invalid("保留天数须在 0 到 30 之间").into(),
    );
  }
  for (name, value) in &req.items {
    crate::api::check_secret_name(name)?;
    secret_policy::refuse_managed(name)?;
    if !crate::render::is_auth_secret(name) {
      secret_policy::reject_system_secret(name, "批量导入")?;
    }
    if value.len() > 64 * 1024 {
      return Err(
        ApiError::invalid(format!("密钥 {name} 的值超过 64 KiB"))
          .into(),
      );
    }
  }
  for (name, value) in &mut req.items {
    if crate::render::is_auth_secret(name) {
      *value =
        crate::login::hash_basic_auth(std::mem::take(value)).await?;
    }
  }
  let result = s
    .db
    .call_credentials(move |c, key| store(c, key, req))
    .await?;
  crate::log_redact::refresh(&s.db).await;
  let names = result
    .created
    .iter()
    .chain(&result.updated)
    .chain(&result.skipped)
    .map(String::as_str)
    .collect::<Vec<_>>()
    .join(",");
  audit.set_detail(format!(
    "created={} updated={} skipped={} names={names}",
    result.created.len(),
    result.updated.len(),
    result.skipped.len()
  ));
  Ok(Json(result))
}

fn store(
  c: &mut Connection,
  key: &CredentialsKey,
  req: SecretImportRequest,
) -> Result<SecretImportResponse, ApiError> {
  let tx = c
    .transaction_with_behavior(TransactionBehavior::Immediate)
    .map_err(sql_err)?;
  let existing: BTreeSet<String> = {
    let mut stmt =
      tx.prepare("SELECT name FROM secrets").map_err(sql_err)?;
    stmt
      .query_map([], |r| r.get(0))
      .and_then(Iterator::collect)
      .map_err(sql_err)?
  };
  if req.mode == SecretImportMode::FailOnConflict {
    let conflicts = req
      .items
      .keys()
      .filter(|n| existing.contains(*n))
      .collect::<Vec<_>>();
    if !conflicts.is_empty() {
      let names = conflicts
        .iter()
        .map(|n| n.as_str())
        .collect::<Vec<_>>()
        .join("、");
      return Err(ApiError::new(ErrorCode::Conflict, format!("密钥已存在：{names}"))
        .with_hint("加 --only-missing 跳过已有密钥，或加 --overwrite 覆盖并保留旧值")
        .with_details(json!({ "conflicts": conflicts })));
    }
  }
  let keep_days = match req.keep_days {
    Some(days) => days,
    None => {
      crate::config_api::number(&tx, "retention.secret_keep_days")?
    }
  };
  let now = db::now_ms();
  let until =
    (keep_days != 0).then(|| now + i64::from(keep_days) * 86_400_000);
  let mut result = SecretImportResponse::default();
  for (name, value) in req.items {
    if existing.contains(&name) {
      if req.mode == SecretImportMode::OnlyMissing {
        result.skipped.push(name);
        continue;
      }
      key.rotate_secret(&tx, &name, &value, now, until, true)?;
      result.updated.push(name);
    } else {
      key.rotate_secret(&tx, &name, &value, now, until, true)?;
      result.created.push(name);
    }
  }
  let world = World::from_rows(db::all_resources(&tx)?)?;
  let (services, gateways) = affected(&world, |name| {
    result
      .created
      .iter()
      .chain(&result.updated)
      .any(|n| n == name)
  });
  result.affected_services = services;
  result.affected_gateways = gateways;
  result.needs_plan = !result.affected_services.is_empty()
    || !result.affected_gateways.is_empty();
  if result.needs_plan {
    result.suggest.push("wharf plan".into());
  }
  tx.commit().map_err(sql_err)?;
  Ok(result)
}

pub(crate) fn affected(
  world: &World,
  changed: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>) {
  let services = world
    .services
    .iter()
    .filter(|(_, row)| {
      secret_policy::service_render_refs(&row.spec).any(&changed)
    })
    .map(|(name, _)| name.clone())
    .collect();
  let gateways = world
    .routes
    .iter()
    .filter(|(host, row)| {
      row.spec.auth
        && changed(&crate::render::route_auth_secret(host))
    })
    .flat_map(|(_, row)| world.route_gateways(&row.spec))
    .map(str::to_string)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
  (services, gateways)
}

#[tokio::test]
async fn batch_conflict_leaves_no_partial_write() {
  let db = db::Db::memory();
  db.call_credentials(|c, key| {
    key.put_secret(c, "B", "fixture-old", 1, false)?;
    let request = |mode| SecretImportRequest {
      items: [
        ("A".into(), "fixture-first".into()),
        ("B".into(), "fixture-second".into()),
      ]
      .into(),
      mode,
      keep_days: None,
    };
    let err =
      store(c, key, request(SecretImportMode::FailOnConflict))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    assert_eq!(err.details.unwrap()["conflicts"], json!(["B"]));
    assert!(!db::secrets(c, key)?.contains_key("A"));
    let result =
      store(c, key, request(SecretImportMode::OnlyMissing))?;
    assert_eq!(result.created, ["A"]);
    assert_eq!(result.skipped, ["B"]);
    let text = serde_json::to_string(&result).unwrap();
    assert!(
      !text.contains("fixture-first")
        && !text.contains("fixture-second")
    );
    Ok(())
  })
  .await
  .unwrap();
}
