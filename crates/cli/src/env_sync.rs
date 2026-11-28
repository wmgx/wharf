//! 从 .env 同步服务变量。预览只处理名称及引用，写操作需要 --apply。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::PathBuf,
};

use serde::Serialize;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{
    ApplyRequest, ApplyResponse, Plan, PlanRequest, Run, RunStatus,
  },
  references::{account_ref, parse_placeholder},
  secret_detect::{
    detect_secret_value, has_wharf_ref, is_placeholder_value,
    is_sensitive_env_key,
  },
  spec::Change,
  view::{SecretImportMode, SecretView, ServiceView},
};

use crate::{
  ApplyFlags,
  client::{CliError, CliResult, Client, seg},
  commands::{out, wait_run},
  dotenv, secret_import,
};

#[derive(clap::Subcommand)]
pub enum ServiceEnvCmd {
  /// 查看服务变量名称和密钥引用。
  List { name: String },
  /// 预览 .env 与当前变量的差异，加 --apply 安全同步。
  Sync(EnvSyncArgs),
}

#[derive(clap::Args)]
pub struct EnvSyncArgs {
  name: String,
  file: PathBuf,
  #[arg(long, conflicts_with = "apply")]
  dry_run: bool,
  #[arg(long)]
  prune: bool,
  #[arg(long)]
  secret_prefix: Option<String>,
  #[arg(long, value_delimiter = ',')]
  to_secret: Vec<String>,
  #[arg(long, value_delimiter = ',')]
  plain: Vec<String>,
  #[arg(long)]
  generate_secrets: bool,
  #[arg(long)]
  overwrite_secrets: bool,
  #[arg(long)]
  no_secret_detect: bool,
  #[command(flatten)]
  flags: ApplyFlags,
}

#[derive(Serialize)]
struct EnvChange {
  key: String,
  action: &'static str,
  before: Option<String>,
  after: Option<String>,
}

#[derive(Serialize)]
struct SecretAction {
  name: String,
  action: &'static str,
}

struct SyncPlan {
  env: BTreeMap<String, String>,
  changes: Vec<EnvChange>,
  imports: BTreeMap<String, String>,
  generated: BTreeSet<String>,
  missing: BTreeSet<String>,
  actions: Vec<SecretAction>,
}

fn secret_ref(value: &str) -> Option<&str> {
  let raw = value.strip_prefix("[[")?.strip_suffix("]]")?;
  let p = parse_placeholder(raw, false).ok().flatten()?;
  account_ref(p.name).is_none().then_some(p.name)
}

fn display_value(value: &str) -> String {
  if secret_ref(value).is_some() {
    value.to_string()
  } else {
    "***".into()
  }
}

fn plan_env_sync(
  args: &EnvSyncArgs,
  local: BTreeMap<String, String>,
  remote: &BTreeMap<String, String>,
  existing: &BTreeSet<String>,
) -> Result<SyncPlan, ApiError> {
  let prefix = args.secret_prefix.clone().unwrap_or_else(|| {
    format!("{}_", args.name.to_ascii_uppercase().replace('-', "_"))
  });
  let mut plan = SyncPlan {
    env: remote.clone(),
    changes: Vec::new(),
    imports: BTreeMap::new(),
    generated: BTreeSet::new(),
    missing: BTreeSet::new(),
    actions: Vec::new(),
  };
  for (key, value) in &local {
    let before = remote.get(key);
    let force_plain = args.plain.contains(key);
    let old_ref = before.and_then(|old| secret_ref(old));
    let candidate = !force_plain
      && !has_wharf_ref(value)
      && (old_ref.is_some()
        || args.to_secret.contains(key)
        || !args.no_secret_detect
          && (is_sensitive_env_key(key)
            || detect_secret_value(value).is_some()));
    let (after, diff) = if candidate {
      let name = old_ref
        .map(str::to_string)
        .unwrap_or_else(|| format!("{prefix}{key}"));
      if !dotenv::check_name(&name) {
        return Err(
          ApiError::invalid(format!(
            "变量 {key} 生成的密钥名称不合法"
          ))
          .with_hint("使用 --secret-prefix 指定较短的合法前缀"),
        );
      }
      let placeholder = is_placeholder_value(value);
      let in_vault = existing.contains(&name);
      let (action, diff) = if old_ref.is_some()
        && (!args.overwrite_secrets || placeholder)
      {
        ("keep", "keep_secret_ref")
      } else if in_vault && (!args.overwrite_secrets || placeholder) {
        ("reuse", "use_secret_ref")
      } else if placeholder {
        if args.generate_secrets {
          plan.generated.insert(name.clone());
          ("generate", "generate_secret")
        } else {
          plan.missing.insert(name.clone());
          ("needs_input", "needs_secret_input")
        }
      } else {
        if let Some(previous) =
          plan.imports.insert(name.clone(), value.clone())
          && previous != *value
        {
          return Err(ApiError::invalid(format!(
            "多个变量为密钥 {name} 提供了不同的值"
          )));
        }
        if in_vault {
          ("rotate", "rotate_secret")
        } else {
          ("import", "import_secret")
        }
      };
      plan.actions.push(SecretAction {
        name: name.clone(),
        action,
      });
      let new_ref = if old_ref.is_some() {
        before.cloned().unwrap_or_default()
      } else {
        format!("[[{name}]]")
      };
      (new_ref, diff)
    } else {
      (
        value.clone(),
        if before.is_some() { "update" } else { "add" },
      )
    };
    if before != Some(&after) || candidate {
      plan.changes.push(EnvChange {
        key: key.clone(),
        action: diff,
        before: before.map(|v| display_value(v)),
        after: Some(display_value(&after)),
      });
    }
    plan.env.insert(key.clone(), after);
  }
  for (key, value) in remote {
    if !local.contains_key(key) {
      if args.prune {
        plan.env.remove(key);
      }
      plan.changes.push(EnvChange {
        key: key.clone(),
        action: if args.prune {
          "remove"
        } else {
          "ignored_remote"
        },
        before: Some(display_value(value)),
        after: None,
      });
    }
  }
  Ok(plan)
}

pub async fn run(
  c: &Client,
  command: ServiceEnvCmd,
  j: bool,
) -> CliResult<()> {
  match command {
    ServiceEnvCmd::List { name } => {
      let service: ServiceView =
        c.get(&format!("/api/services/{}", seg(&name))).await?;
      let env = service
        .spec
        .env
        .iter()
        .map(|(k, v)| (k, display_value(v)))
        .collect::<BTreeMap<_, _>>();
      out(j, &env, |env| {
        for (k, v) in env {
          println!("{k}={v}");
        }
      });
      Ok(())
    }
    ServiceEnvCmd::Sync(args) => sync(c, args, j).await,
  }
}

async fn sync(
  c: &Client,
  args: EnvSyncArgs,
  j: bool,
) -> CliResult<()> {
  let local = dotenv::read(Some(&args.file))?;
  let mut service: ServiceView =
    c.get(&format!("/api/services/{}", seg(&args.name))).await?;
  let secrets: Vec<SecretView> = c.get("/api/secrets").await?;
  let existing = secrets.into_iter().map(|s| s.name).collect();
  let mut mask = local
    .values()
    .chain(service.spec.env.values())
    .filter(|v| !v.is_empty() && secret_ref(v).is_none())
    .cloned()
    .collect::<Vec<_>>();
  mask.sort_unstable();
  mask.dedup();
  let mut env =
    plan_env_sync(&args, local, &service.spec.env, &existing)?;
  if args.dry_run || !args.flags.apply {
    let pending =
      env.imports.len() + env.generated.len() + env.missing.len();
    let preview = json!({
      "service": args.name, "file": args.file, "env_changes": env.changes,
      "secret_actions": env.actions, "warnings": [],
      "hint": (pending > 0).then_some("确认预览后加 --apply；缺少的密钥须提供值或用 --generate-secrets"),
    });
    out(j, &preview, |_| {
      for change in &env.changes {
        println!("{}  {}", change.key, change.action);
      }
      for action in &env.actions {
        println!("{}  {}", action.name, action.action);
      }
      if let Some(hint) = preview["hint"].as_str() {
        println!("{hint}");
      }
    });
    return Ok(());
  }
  if !env.missing.is_empty() {
    return Err(
      ApiError::invalid(format!(
        "缺少这些密钥的值：{}",
        env.missing.iter().cloned().collect::<Vec<_>>().join("、")
      ))
      .with_hint("填入密钥值，或加 --generate-secrets")
      .into(),
    );
  }

  for name in &env.generated {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
      .map_err(|_| ApiError::internal("无法生成随机密钥"))?;
    env.imports.insert(name.clone(), hex::encode(bytes));
  }
  service.spec.env = env.env;
  let operation = execute(c, args, service, env.imports).await;
  let (secrets, plan, run) = operation.map_err(|e| match e {
    CliError::Api(mut e) => {
      e.message = wharf_api_types::mask_values(&e.message, &mask);
      if let Some(hint) = &mut e.hint {
        *hint = wharf_api_types::mask_values(hint, &mask);
      }
      for suggestion in &mut e.suggest {
        *suggestion = wharf_api_types::mask_values(suggestion, &mask);
      }
      if let Some(details) = &mut e.details {
        redact(details, &mask);
      }
      CliError::Api(e)
    }
    e => e,
  })?;
  let succeeded = run
    .as_ref()
    .is_none_or(|run| run.status == RunStatus::Succeeded);
  let mut result =
    json!({ "secrets": secrets, "plan": plan, "run": run });
  redact(&mut result, &mask);
  out(j, &result, |_| {
    println!("计划 {}，{} 项变更", plan.plan_id, plan.items.len());
    if let Some(run) = &run {
      println!(
        "执行 {}：{}",
        run.run_id,
        if succeeded { "成功" } else { "失败" }
      );
    }
  });
  if succeeded {
    Ok(())
  } else {
    Err(CliError::Exit(4))
  }
}

fn redact(json: &mut Value, values: &[String]) {
  match json {
    Value::String(s) => *s = wharf_api_types::mask_values(s, values),
    Value::Array(items) => {
      items.iter_mut().for_each(|item| redact(item, values))
    }
    Value::Object(items) => {
      items.values_mut().for_each(|item| redact(item, values))
    }
    _ => {}
  }
}

async fn execute(
  c: &Client,
  args: EnvSyncArgs,
  service: ServiceView,
  imports: BTreeMap<String, String>,
) -> CliResult<(
  wharf_api_types::view::SecretImportResponse,
  Plan,
  Option<Run>,
)> {
  let mut secrets =
    wharf_api_types::view::SecretImportResponse::default();
  if !imports.is_empty() {
    let mode = if args.overwrite_secrets {
      SecretImportMode::Overwrite
    } else {
      SecretImportMode::OnlyMissing
    };
    secrets = secret_import::import(c, imports, mode, None).await?;
  }
  let plan: Plan = c
    .post(
      "/api/plan",
      &PlanRequest {
        changes: vec![Change::UpsertService {
          name: service.name,
          spec: service.spec,
          pins: None,
          commit: None,
          adopt: None,
        }],
        note: args.flags.note,
        ..Default::default()
      },
    )
    .await?;
  if plan.items.is_empty() {
    return Ok((secrets, plan, None));
  }
  let missing = plan
    .needs_confirm
    .iter()
    .filter(|a| !args.flags.confirm.contains(a))
    .collect::<Vec<_>>();
  if !missing.is_empty() {
    return Err(ApiError::new(ErrorCode::ConfirmRequired, "计划需要确认")
      .with_details(json!({ "plan_id": plan.plan_id, "expires_at": plan.expires_at, "items": missing, "warnings": plan.warnings, "secrets": secrets }))
      .suggest(format!("wharf apply {}{}", plan.plan_id, missing.iter().map(|a| format!(" --confirm {a}")).collect::<String>())).into());
  }
  let applying: ApplyResponse = c
    .post(
      "/api/apply",
      &ApplyRequest {
        plan_id: plan.plan_id.clone(),
        confirm: args.flags.confirm,
        skip_snapshot: false,
        verify_before_dns: args.flags.dns_verify.mode(),
      },
    )
    .await?;
  let run = wait_run(c, &applying.run_id, true).await?;
  Ok((secrets, plan, Some(run)))
}

#[test]
fn sync_preserves_refs_and_masks_preview() {
  use clap::Parser;
  let cli = crate::Cli::try_parse_from([
    "wharf", "service", "env", "sync", "app", ".env",
  ])
  .unwrap();
  let crate::Command::Service(crate::ServiceCmd::Env(
    ServiceEnvCmd::Sync(args),
  )) = cli.command
  else {
    panic!("预期为 env sync");
  };
  let map = |s| dotenv::parse(s).unwrap();
  let old = map("APP_ENV=prod\nDB_PASS=[[APP_DB_PASS]]");
  let local = map(
    "APP_ENV=staging\nDB_PASS=fixture-old-plain\nNEW_TOKEN=fixture-new-plain\nEMPTY_SECRET=changeme",
  );
  let names = ["APP_DB_PASS".into()].into();
  let result = plan_env_sync(&args, local, &old, &names).unwrap();
  assert_eq!(result.env["APP_ENV"], "staging");
  assert_eq!(result.env["DB_PASS"], "[[APP_DB_PASS]]");
  assert_eq!(result.env["NEW_TOKEN"], "[[APP_NEW_TOKEN]]");
  assert!(result.missing.contains("APP_EMPTY_SECRET"));
  let preview = serde_json::to_string(&result.changes).unwrap();
  assert!(
    !preview.contains("fixture-old-plain")
      && !preview.contains("fixture-new-plain")
  );
}
