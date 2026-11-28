use std::{collections::BTreeMap, path::PathBuf};

use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{SecretImportMode, SecretImportResponse, SecretView},
};

use crate::{
  client::{CliResult, Client},
  commands::out,
  dotenv,
};

#[derive(clap::Args)]
pub struct ImportArgs {
  file: Option<PathBuf>,
  #[arg(long)]
  prefix: Option<String>,
  #[arg(long, conflicts_with = "overwrite")]
  only_missing: bool,
  #[arg(long)]
  overwrite: bool,
  #[arg(long, value_parser = clap::value_parser!(u16).range(0..=30))]
  keep_days: Option<u16>,
  #[arg(long, value_delimiter = ',')]
  keys: Vec<String>,
  #[arg(long)]
  dry_run: bool,
}

pub async fn run(
  c: &Client,
  args: ImportArgs,
  j: bool,
) -> CliResult<()> {
  let entries = dotenv::read(args.file.as_deref())?;
  let prefix = args.prefix.as_deref().unwrap_or_default();
  for key in &args.keys {
    if !entries.contains_key(key) {
      return Err(
        ApiError::invalid("指定的键未在 .env 中找到").into(),
      );
    }
  }
  let items = entries
    .into_iter()
    .filter(|(k, _)| args.keys.is_empty() || args.keys.contains(k))
    .map(|(k, v)| (format!("{prefix}{k}"), v))
    .collect::<BTreeMap<_, _>>();
  if items.is_empty() || items.len() > 200 {
    return Err(
      ApiError::invalid("每次须导入 1 到 200 条密钥").into(),
    );
  }
  for (name, value) in &items {
    let upper = name.to_ascii_uppercase();
    if !dotenv::check_name(name)
      || ["WHARF_", "OIDC_SECRET_", "ACME_DNS_", "NOTIFY_URL_"]
        .iter()
        .any(|p| upper.starts_with(*p))
    {
      return Err(
        ApiError::invalid("导入包含格式错误或保留的密钥名").into(),
      );
    }
    if value.len() > 64 * 1024 {
      return Err(
        ApiError::invalid(format!("密钥 {name} 的值超过 64 KiB"))
          .into(),
      );
    }
  }
  let mode = if args.only_missing {
    SecretImportMode::OnlyMissing
  } else if args.overwrite {
    SecretImportMode::Overwrite
  } else {
    SecretImportMode::FailOnConflict
  };
  if args.dry_run {
    let existing: Vec<SecretView> = c.get("/api/secrets").await?;
    let result = preview(items.into_keys(), &existing, mode)?;
    out(j, &result, show);
    return Ok(());
  }
  let result = import(c, items, mode, args.keep_days).await?;
  out(j, &result, show);
  Ok(())
}

fn preview(
  names: impl IntoIterator<Item = String>,
  existing: &[SecretView],
  mode: SecretImportMode,
) -> Result<SecretImportResponse, ApiError> {
  let mut result = SecretImportResponse::default();
  let mut conflicts = Vec::new();
  for name in names {
    if existing.iter().any(|v| v.name == name) {
      match mode {
        SecretImportMode::OnlyMissing => result.skipped.push(name),
        SecretImportMode::Overwrite => result.updated.push(name),
        SecretImportMode::FailOnConflict => conflicts.push(name),
      }
    } else {
      result.created.push(name);
    }
  }
  if !conflicts.is_empty() {
    return Err(
      ApiError::new(
        ErrorCode::Conflict,
        format!("预览发现同名密钥：{}", conflicts.join("、")),
      )
      .with_hint("加 --only-missing 或 --overwrite")
      .with_details(json!({"conflicts": conflicts})),
    );
  }
  result.needs_plan =
    !result.created.is_empty() || !result.updated.is_empty();
  Ok(result)
}

pub(crate) async fn import(
  c: &Client,
  items: BTreeMap<String, String>,
  mode: SecretImportMode,
  keep_days: Option<u16>,
) -> CliResult<SecretImportResponse> {
  c.post(
    "/api/secrets/import",
    &json!({ "items": items, "mode": mode, "keep_days": keep_days }),
  )
  .await
}

fn show(result: &SecretImportResponse) {
  for (label, names) in [
    ("新建", &result.created),
    ("更新", &result.updated),
    ("跳过", &result.skipped),
  ] {
    if !names.is_empty() {
      println!("{label}：{}", names.join("、"));
    }
  }
  if result.needs_plan {
    println!("下一步：wharf plan");
  }
}

#[test]
fn import_preview_lists_all_conflicts_and_matches_receipt_schema() {
  let existing = ["API_KEY", "DB_PASS"].map(|name| {
    serde_json::from_value(json!({
      "name":name, "updated_at":"2026-11-28T00:00:00Z",
      "used_by":[], "has_previous":false, "managed":false
    }))
    .unwrap()
  });
  let names = || ["API_KEY", "DB_PASS", "NEW_KEY"].map(str::to_owned);
  let error =
    preview(names(), &existing, SecretImportMode::FailOnConflict)
      .unwrap_err();
  assert!(error.message.contains("API_KEY、DB_PASS"));
  let receipt =
    preview(names(), &existing, SecretImportMode::Overwrite).unwrap();
  let body = serde_json::to_value(receipt).unwrap();
  assert_eq!(body["created"], json!(["NEW_KEY"]));
  assert_eq!(body["updated"], json!(["API_KEY", "DB_PASS"]));
}
