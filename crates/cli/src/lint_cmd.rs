use wharf_api_types::view::{LintReport, LintSeverity};

use crate::{
  client::{CliError, CliResult, Client, seg},
  commands::out,
};

#[derive(clap::Args)]
pub struct LintArgs {
  #[arg(long, value_parser = ["error", "warning", "info"])]
  severity: Option<String>,
  #[arg(long, value_parser = ["consistency", "config"])]
  category: Option<String>,
  #[arg(long)]
  service: Option<String>,
  #[arg(long)]
  strict: bool,
}

pub async fn run(
  c: &Client,
  args: LintArgs,
  j: bool,
) -> CliResult<()> {
  let mut path = format!("/api/lint?strict={}", args.strict);
  for (key, value) in [
    ("severity", args.severity),
    ("category", args.category),
    ("service", args.service),
  ] {
    if let Some(value) = value {
      path.push_str(&format!("&{key}={}", seg(&value)));
    }
  }
  let report: LintReport = c.get(&path).await?;
  out(j, &report, |r| {
    for f in &r.findings {
      let level = match f.severity {
        LintSeverity::Info => "提示",
        LintSeverity::Warning => "警告",
        LintSeverity::Error => "错误",
      };
      println!("{level}  {}  {}", f.subject, f.message);
      for cmd in &f.suggest {
        println!("  {cmd}");
      }
    }
    println!(
      "{} 错误，{} 警告，{} 提示",
      r.summary.error, r.summary.warning, r.summary.info
    );
  });
  if report.ok {
    Ok(())
  } else {
    Err(CliError::Exit(1))
  }
}
