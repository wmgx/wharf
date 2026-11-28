//! 原子导入业务密钥。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::Arc,
};

use axum::{
  Extension, Json,
  extract::{State, rejection::JsonRejection},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  bundle::SecretChanges,
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

pub(crate) trait SecretChangesExt {
  fn action(&self, name: &str) -> &'static str;
  fn audit(&self) -> String;
}

impl SecretChangesExt for SecretChanges {
  fn action(&self, name: &str) -> &'static str {
    if self.conflicts.iter().any(|n| n == name) {
      "conflict"
    } else if self.update.iter().any(|n| n == name) {
      "overwrite"
    } else if self.skip.iter().any(|n| n == name) {
      "skip"
    } else {
      "create"
    }
  }

  fn audit(&self) -> String {
    let names = self
      .create
      .iter()
      .chain(&self.update)
      .cloned()
      .collect::<Vec<_>>();
    format!(
      "created={} updated={} skipped={} names={}",
      self.create.len(),
      self.update.len(),
      self.skip.len(),
      names.join(",")
    )
  }
}

pub(crate) async fn write(
  state: &AppState,
  values: BTreeMap<String, String>,
  mode: SecretImportMode,
  keep_days: Option<u16>,
  preview: bool,
) -> Result<SecretChanges, ApiError> {
  write_with(
    state,
    values,
    mode,
    keep_days,
    preview,
    |_, _, _| Ok(()),
  )
  .await
}

pub(crate) fn require_no_conflicts(
  summary: &SecretChanges,
) -> Result<(), ApiError> {
  if !summary.conflicts.is_empty() {
    return Err(ApiError::new(ErrorCode::Conflict, format!("已有同名密钥：{}", summary.conflicts.join("、")))
      .with_hint("加 --only-missing 保留已有密钥，或加 --overwrite 覆盖（默认保留旧值 7 天）")
      .with_details(serde_json::json!({"conflicts": summary.conflicts})));
  }
  Ok(())
}

pub(crate) async fn write_with(
  state: &AppState,
  values: BTreeMap<String, String>,
  mode: SecretImportMode,
  keep_days: Option<u16>,
  preview: bool,
  finish: impl FnOnce(
    &rusqlite::Connection,
    &db::CredentialsKey,
    &SecretChanges,
  ) -> Result<(), ApiError>
  + Send
  + 'static,
) -> Result<SecretChanges, ApiError> {
  let keep_days = keep_days.unwrap_or(db::DEFAULT_SECRET_KEEP_DAYS);
  if keep_days > 30 || values.len() > 200 {
    return Err(ApiError::invalid(
      "保留天数须在 0 到 30 之间，单次最多导入 200 条密钥",
    ));
  }
  for (name, value) in &values {
    crate::api::check_secret_name(name)
      .map_err(|_| ApiError::invalid("导入结果含非法密钥名"))?;
    crate::secret_policy::refuse_managed(name)?;
    if !crate::render::is_auth_secret(name) {
      crate::secret_policy::reject_system_secret(name, "导入")?;
    }
    if value.len() > 64 * 1024 {
      return Err(ApiError::invalid(format!(
        "密钥 {name} 超过 64 KiB"
      )));
    }
  }
  let changes = state
    .db
    .call_credentials(move |c, key| {
      let behavior = if preview {
        TransactionBehavior::Deferred
      } else {
        TransactionBehavior::Immediate
      };
      let tx =
        c.transaction_with_behavior(behavior).map_err(sql_err)?;
      let summary =
        write_in(&tx, key, &values, mode, keep_days, preview)?;
      if !preview {
        finish(&tx, key, &summary)?;
        tx.commit().map_err(sql_err)?;
      }
      Ok(summary)
    })
    .await?;
  if !preview {
    crate::log_redact::refresh(&state.db).await;
  }
  Ok(changes)
}

fn write_in(
  c: &Connection,
  key: &CredentialsKey,
  values: &BTreeMap<String, String>,
  mode: SecretImportMode,
  keep_days: u16,
  preview: bool,
) -> Result<SecretChanges, ApiError> {
  let mut summary = SecretChanges::default();
  for name in values.keys() {
    let exists = c
      .query_row(
        "SELECT 1 FROM secrets WHERE name=?1",
        [name],
        |_| Ok(()),
      )
      .optional()
      .map_err(db::sql_err)?
      .is_some();
    let list = if !exists {
      &mut summary.create
    } else {
      match mode {
        SecretImportMode::FailOnConflict => &mut summary.conflicts,
        SecretImportMode::OnlyMissing => &mut summary.skip,
        SecretImportMode::Overwrite => &mut summary.update,
      }
    };
    list.push(name.clone());
  }
  if preview {
    return Ok(summary);
  }
  require_no_conflicts(&summary)?;
  let now = db::now_ms();
  let until =
    (keep_days > 0).then(|| now + i64::from(keep_days) * 86_400_000);
  for name in summary.create.iter().chain(&summary.update) {
    key.rotate_secret_in(c, name, &values[name], now, until, true)?;
  }
  Ok(summary)
}

fn store(
  c: &mut Connection,
  key: &CredentialsKey,
  req: SecretImportRequest,
) -> Result<SecretImportResponse, ApiError> {
  let tx = c
    .transaction_with_behavior(TransactionBehavior::Immediate)
    .map_err(sql_err)?;
  let keep_days = match req.keep_days {
    Some(days) => days,
    None => {
      crate::config_api::number(&tx, "retention.secret_keep_days")?
    }
  };
  let changes = write_in(&tx, key, &req.items, req.mode, keep_days, false)
    .map_err(|mut error| {
      if error.code == ErrorCode::Conflict {
        error.hint = Some("加 --only-missing 跳过已有密钥，或加 --overwrite 覆盖并保留旧值".into());
      }
      error
    })?;
  let mut result = SecretImportResponse {
    created: changes.create,
    updated: changes.update,
    skipped: changes.skip,
    ..Default::default()
  };
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

#[tokio::test]
async fn default_conflict_is_atomic_and_only_missing_keeps_existing()
{
  let state = crate::rules::tests::test_state();
  let existing =
    BTreeMap::from([("APP_PASS".into(), "old-fixture".into())]);
  write(
    &state,
    existing,
    SecretImportMode::FailOnConflict,
    None,
    false,
  )
  .await
  .unwrap();
  let values = BTreeMap::from([
    ("APP_PASS".into(), "new-fixture".into()),
    ("APP_OTHER".into(), "other-fixture".into()),
  ]);
  let preview = write(
    &state,
    values.clone(),
    SecretImportMode::FailOnConflict,
    None,
    true,
  )
  .await
  .unwrap();
  assert_eq!(preview.conflicts, ["APP_PASS"]);
  let err = write(
    &state,
    values.clone(),
    SecretImportMode::FailOnConflict,
    None,
    false,
  )
  .await
  .err()
  .unwrap();
  assert_eq!(
    err.details.unwrap()["conflicts"],
    serde_json::json!(["APP_PASS"])
  );
  let actual = state
    .db
    .call_credentials(|c, key| db::secrets(c, key))
    .await
    .unwrap();
  assert_eq!(actual.get("APP_OTHER"), None);
  let result =
    write(&state, values, SecretImportMode::OnlyMissing, None, false)
      .await
      .unwrap();
  assert_eq!(result.skip, ["APP_PASS"]);
  assert_eq!(result.create, ["APP_OTHER"]);
}
