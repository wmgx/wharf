use std::collections::BTreeMap;

use rusqlite::OptionalExtension;
use wharf_api_types::{ApiError, ErrorCode, view::SecretImportMode};

use crate::{db, state::AppState};

use wharf_api_types::bundle::SecretChanges;

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
  if values.is_empty() {
    return Ok(SecretChanges::default());
  }
  let changes = state.db.call_credentials(move |c, key| {
    let tx = c.unchecked_transaction().map_err(db::sql_err)?;
    let mut summary = SecretChanges::default();
    for name in values.keys() {
      let exists = tx.query_row("SELECT 1 FROM secrets WHERE name=?1", [name], |_| Ok(()))
        .optional().map_err(db::sql_err)?.is_some();
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
    if !summary.conflicts.is_empty() {
      return Err(ApiError::new(ErrorCode::Conflict, format!("已有同名密钥：{}", summary.conflicts.join("、")))
        .with_hint("加 --only-missing 保留已有密钥，或加 --overwrite 覆盖（默认保留旧值 7 天）")
        .with_details(serde_json::json!({"conflicts": summary.conflicts})));
    }
    let now = db::now_ms();
    let until = (keep_days > 0).then(|| now + i64::from(keep_days) * 86_400_000);
    for name in summary.create.iter().chain(&summary.update) {
      key.rotate_secret_in(&tx, name, &values[name], now, until, true)?;
    }
    tx.commit().map_err(db::sql_err)?;
    Ok(summary)
  }).await?;
  if !preview {
    crate::log_redact::refresh(&state.db).await;
  }
  Ok(changes)
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
