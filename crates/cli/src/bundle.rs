use std::{
  io::{IsTerminal, Read, Write},
  path::{Path, PathBuf},
  time::Duration,
};

use clap::Args;
use serde_json::json;
use wharf_api_types::{ApiError, bundle::*, view::SecretImportMode};

use crate::{
  ApplyFlags,
  client::{CliResult, Client},
  commands, print,
};

#[derive(Args)]
pub struct Passphrase {
  #[arg(long, conflicts_with = "passphrase_env")]
  passphrase_file: Option<PathBuf>,
  #[arg(long)]
  passphrase_env: Option<String>,
}

impl Passphrase {
  fn read(&self, confirm: bool) -> CliResult<String> {
    let value = if let Some(path) = &self.passphrase_file {
      let mut text = read(path, 64 * 1024)?;
      if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
          text.pop();
        }
      }
      text
    } else if let Some(var) = &self.passphrase_env {
      std::env::var(var)
        .map_err(|_| ApiError::invalid("无法读取口令环境变量"))?
    } else {
      if !std::io::stdin().is_terminal() {
        return Err(
          ApiError::invalid("需要终端输入口令")
            .with_hint(
              "也可以用 --passphrase-file 或 --passphrase-env",
            )
            .into(),
        );
      }
      let value = rpassword::prompt_password("加密口令：")
        .map_err(anyhow::Error::from)?;
      if confirm
        && value
          != rpassword::prompt_password("再输入一次：")
            .map_err(anyhow::Error::from)?
      {
        return Err(ApiError::invalid("两次口令不同").into());
      }
      value
    };
    if value.is_empty() || value.len() > 64 * 1024 {
      return Err(ApiError::invalid("口令为空或过长").into());
    }
    Ok(value)
  }
}

#[derive(Args)]
pub struct ImportArgs {
  file: PathBuf,
  #[arg(long)]
  server: Option<String>,
  #[arg(long, value_parser = commands::parse_server_mapping)]
  map_server: Vec<(String, String)>,
  #[arg(long, value_parser = commands::parse_server_mapping)]
  map_gateway: Vec<(String, String)>,
  #[arg(long)]
  no_routes: bool,
  #[arg(long, conflicts_with = "overwrite")]
  only_missing: bool,
  #[arg(long)]
  overwrite: bool,
  #[arg(long, value_parser = clap::value_parser!(u16).range(0..=30))]
  keep_days: Option<u16>,
  #[arg(long, conflicts_with_all = ["apply", "plan_only"])]
  dry_run: bool,
  #[arg(long, conflicts_with = "apply")]
  plan_only: bool,
  #[command(flatten)]
  passphrase: Passphrase,
  #[command(flatten)]
  flags: ApplyFlags,
}

fn read(path: &Path, limit: u64) -> CliResult<String> {
  let mut text = String::new();
  std::fs::File::open(path)
    .and_then(|f| f.take(limit + 1).read_to_string(&mut text))
    .map_err(|_| ApiError::invalid("无法读取文件"))?;
  if text.len() as u64 > limit {
    return Err(ApiError::invalid("文件超过大小上限").into());
  }
  Ok(text)
}

pub(crate) async fn export(
  c: &Client,
  output: PathBuf,
  services: Vec<String>,
  passphrase: Passphrase,
  j: bool,
) -> CliResult<()> {
  let passphrase = passphrase.read(true)?;
  let response: ExportBundleResponse = c
    .post_timeout(
      "/api/export/bundle",
      &ExportBundleRequest {
        services,
        passphrase,
      },
      Duration::from_secs(90),
    )
    .await?;
  let data = serde_json::to_vec(&response.bundle)
    .map_err(anyhow::Error::from)?;
  let (mut file, temp) = crate::client::Config::open_temp(&output)?;
  let result = file
    .write_all(&data)
    .and_then(|()| file.sync_all())
    .and_then(|()| std::fs::rename(&temp, &output));
  if result.is_err() {
    let _ = std::fs::remove_file(temp);
  }
  result.map_err(anyhow::Error::from)?;
  if j {
    print::json(&response.summary);
  } else {
    println!("已写入 {}", output.display());
    for warning in response.summary.warnings {
      println!("  {warning}");
    }
  }
  Ok(())
}

pub(crate) async fn import(
  c: &Client,
  args: ImportArgs,
  j: bool,
) -> CliResult<()> {
  let raw = read(&args.file, 24 * 1024 * 1024)?;
  let bundle = serde_json::from_str(&raw)
    .map_err(|_| ApiError::invalid("便携包格式不对"))?;
  let dry_run =
    args.dry_run || (!args.flags.apply && !args.plan_only);
  let req = ImportBundleRequest {
    bundle,
    passphrase: args.passphrase.read(false)?,
    dry_run,
    mode: if args.only_missing {
      SecretImportMode::OnlyMissing
    } else if args.overwrite {
      SecretImportMode::Overwrite
    } else {
      SecretImportMode::FailOnConflict
    },
    keep_days: args.keep_days,
    server_map: args.map_server.into_iter().collect(),
    default_server: args.server,
    gateway_map: args.map_gateway.into_iter().collect(),
    no_routes: args.no_routes,
  };
  let timeout = Duration::from_secs(180);
  if dry_run {
    let preview: BundleImportPreview =
      c.post_timeout("/api/import/bundle", &req, timeout).await?;
    print::json(&preview);
    return Ok(());
  }
  let result: BundleImportResponse =
    c.post_timeout("/api/import/bundle", &req, timeout).await?;
  if j && !args.flags.apply {
    print::json(&result);
    return Ok(());
  }
  let context =
    json!({"secrets": result.secrets, "warnings": result.warnings});
  commands::apply_prepared_plan(
    c,
    result.plan,
    args.flags,
    j,
    Some(("import", context)),
  )
  .await
}
