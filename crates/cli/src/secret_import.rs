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
    let mut actions = BTreeMap::new();
    let mut conflicts = Vec::new();
    for name in items.keys() {
      let action = if existing.iter().any(|v| &v.name == name) {
        match mode {
          SecretImportMode::OnlyMissing => "skip",
          SecretImportMode::Overwrite => "update",
          SecretImportMode::FailOnConflict => {
            conflicts.push(name);
            "conflict"
          }
        }
      } else {
        "create"
      };
      actions.insert(name, action);
    }
    if !conflicts.is_empty() {
      return Err(
        ApiError::new(ErrorCode::Conflict, "预览发现同名密钥")
          .with_hint("加 --only-missing 或 --overwrite")
          .with_details(
            json!({ "conflicts": conflicts, "actions": actions }),
          )
          .into(),
      );
    }
    out(j, &actions, |actions| {
      for (name, action) in actions {
        println!("{action}  {name}");
      }
    });
    return Ok(());
  }
  let result = import(c, items, mode, args.keep_days).await?;
  out(j, &result, show);
  Ok(())
}

pub(crate) async fn import(
  c: &Client,
  items: BTreeMap<String, String>,
  mode: SecretImportMode,
  keep_days: Option<u16>,
) -> CliResult<SecretImportResponse> {
  Ok(c.post("/api/secrets/import", &json!({ "items": items, "mode": mode, "keep_days": keep_days })).await?)
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
