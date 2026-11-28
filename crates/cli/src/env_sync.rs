//! 从 .env 同步服务变量。预览只处理名称及引用，写操作需要 --apply。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::PathBuf,
};

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;
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

#[derive(clap::Args)]
#[command(subcommand_precedence_over_arg = true)]
pub struct ServiceEnvArgs {
  name: Option<String>,
  #[command(subcommand)]
  command: Option<ServiceEnvCmd>,
}

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

#[derive(Serialize, JsonSchema)]
pub(crate) struct EnvChange {
  key: String,
  action: &'static str,
  before: Option<String>,
  after: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SecretAction {
  name: String,
  action: &'static str,
}

type Env = BTreeMap<String, String>;

#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum EnvList {
  Service(Env),
  All(BTreeMap<String, Env>),
}

#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum SyncResponse {
  Preview {
    service: String,
    file: PathBuf,
    env_changes: Vec<EnvChange>,
    secret_actions: Vec<SecretAction>,
    warnings: Vec<String>,
    hint: Option<&'static str>,
  },
  Applied {
    secrets: wharf_api_types::view::SecretImportResponse,
    plan: Box<Plan>,
    run: Option<Run>,
  },
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
  args: ServiceEnvArgs,
  j: bool,
) -> CliResult<()> {
  let (name, command) = (args.name, args.command);
  let name = match (name, command) {
    (None, Some(ServiceEnvCmd::Sync(args))) => {
      return sync(c, args, j).await;
    }
    (None, Some(ServiceEnvCmd::List { name })) => Some(name),
    (name, None) => name,
    _ => {
      return Err(
        ApiError::invalid("服务名和子命令只能选一个入口").into(),
      );
    }
  };
  let masked = |service: ServiceView| -> Env {
    service
      .spec
      .env
      .into_iter()
      .map(|(k, v)| (k, display_value(&v)))
      .collect()
  };
  let listing = if let Some(name) = name {
    let service =
      c.get(&format!("/api/services/{}", seg(&name))).await?;
    EnvList::Service(masked(service))
  } else {
    let services: Vec<ServiceView> = c.get("/api/services").await?;
    EnvList::All(
      services
        .into_iter()
        .map(|s| (s.name.clone(), masked(s)))
        .collect(),
    )
  };
  let show = |env: &Env| {
    for (k, v) in env {
      println!("{k}={v}");
    }
  };
  out(j, &listing, |result| match result {
    EnvList::Service(env) => show(env),
    EnvList::All(services) => {
      for (service, env) in services {
        println!("[{service}]");
        show(env);
      }
    }
  });
  Ok(())
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
  let mut mask = sensitive_values(&local);
  mask.extend(sensitive_values(&service.spec.env));
  let mut env =
    plan_env_sync(&args, local, &service.spec.env, &existing)?;
  if args.dry_run || !args.flags.apply {
    let pending =
      env.imports.len() + env.generated.len() + env.missing.len();
    let hint = (pending > 0).then_some("确认预览后加 --apply；缺少的密钥须提供值或用 --generate-secrets");
    let preview = SyncResponse::Preview {
      service: args.name,
      file: args.file,
      env_changes: env.changes,
      secret_actions: env.actions,
      warnings: Vec::new(),
      hint,
    };
    out(j, &preview, |response| {
      if let SyncResponse::Preview {
        env_changes,
        secret_actions,
        ..
      } = response
      {
        for change in env_changes {
          println!("{}  {}", change.key, change.action);
        }
        for action in secret_actions {
          println!("{}  {}", action.name, action.action);
        }
        if let Some(hint) = hint {
          println!("{hint}");
        }
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
  mask.extend(env.imports.values().filter(|v| v.len() >= 6).cloned());
  service.spec.env = env.env;
  let (secrets, plan, run) =
    execute(c, args, service, env.imports, j, &mask)
      .await
      .map_err(|e| match e {
        CliError::Api(mut e)
          if e.code != ErrorCode::ConfirmRequired =>
        {
          redact_error(&mut e, &mask);
          CliError::Api(e)
        }
        e => e,
      })?;
  let succeeded = run
    .as_ref()
    .is_none_or(|run| run.status == RunStatus::Succeeded);
  out(
    j,
    &SyncResponse::Applied {
      secrets,
      plan: Box::new(plan),
      run,
    },
    |response| {
      if let SyncResponse::Applied { run: Some(run), .. } = response {
        crate::print::run_summary(run);
      }
    },
  );
  if succeeded {
    Ok(())
  } else {
    Err(CliError::Exit(4))
  }
}

fn sensitive_values(env: &BTreeMap<String, String>) -> Vec<String> {
  env
    .iter()
    .filter(|(key, value)| {
      value.len() >= 6
        && !has_wharf_ref(value)
        && (is_sensitive_env_key(key)
          || detect_secret_value(value).is_some())
    })
    .map(|(_, value)| value.clone())
    .collect()
}

fn redact_error(error: &mut ApiError, values: &[String]) {
  error.message =
    wharf_api_types::mask_values(&error.message, values);
  if let Some(hint) = &mut error.hint {
    *hint = wharf_api_types::mask_values(hint, values);
  }
}

pub(crate) fn redact_run(run: &mut Run, values: &[String]) {
  for step in &mut run.steps {
    for line in &mut step.log {
      *line = wharf_api_types::mask_values(line, values);
    }
    if let Some(error) = &mut step.error {
      redact_error(error, values);
    }
  }
}

fn redact_plan(plan: &mut Plan, values: &[String]) {
  let mask = |text: &mut String| {
    *text = wharf_api_types::mask_values(text, values);
  };
  let mask_env = |key: &str, value: &mut Value| {
    if let Value::String(text) = value {
      if is_sensitive_env_key(key) && secret_ref(text).is_none() {
        *text = "***".into();
      } else {
        mask(text);
      }
    }
  };
  if let Some(note) = &mut plan.note {
    mask(note);
  }
  plan.warnings.iter_mut().for_each(mask);
  for item in &mut plan.items {
    mask(&mut item.reason);
    for change in &mut item.changes {
      change.lines.iter_mut().for_each(mask);
      if let Some(key) = change.path.strip_prefix("env.") {
        for value in change.before.iter_mut().chain(&mut change.after)
        {
          mask_env(key, value);
        }
      }
    }
    for value in item.before.iter_mut().chain(&mut item.after) {
      if let Some(env) =
        value.get_mut("env").and_then(Value::as_object_mut)
      {
        for (key, value) in env {
          mask_env(key, value);
        }
      }
    }
  }
}

async fn execute(
  c: &Client,
  args: EnvSyncArgs,
  service: ServiceView,
  imports: BTreeMap<String, String>,
  j: bool,
  mask: &[String],
) -> CliResult<(
  wharf_api_types::view::SecretImportResponse,
  Plan,
  Option<Run>,
)> {
  let req = PlanRequest {
    changes: vec![Change::UpsertService {
      no_defaults: false,
      name: service.name,
      spec: service.spec,
      pins: None,
      commit: None,
      adopt: None,
      migrate: None,
    }],
    note: args.flags.note.clone(),
    ..Default::default()
  };
  let path =
    crate::plan_cmd::brief_path("/api/plan", args.flags.brief);
  let mut secrets =
    wharf_api_types::view::SecretImportResponse::default();
  if !imports.is_empty() {
    let names = imports.keys().cloned().collect::<Vec<_>>().join(",");
    let sep = if args.flags.brief { '&' } else { '?' };
    let mut preview: Plan = c
      .post(
        &format!("{path}{sep}preview_secrets={}", seg(&names)),
        &req,
      )
      .await?;
    redact_plan(&mut preview, mask);
    require_confirmation(&preview, &args, j, true)?;
    let mode = if args.overwrite_secrets {
      SecretImportMode::Overwrite
    } else {
      SecretImportMode::OnlyMissing
    };
    secrets = secret_import::import(c, imports, mode, None).await?;
  }
  let mut plan: Plan = c.post(path.as_ref(), &req).await?;
  redact_plan(&mut plan, mask);
  require_confirmation(&plan, &args, j, false)?;
  if !j {
    crate::print::plan_with(&plan, false);
  }
  if plan.items.is_empty() {
    return Ok((secrets, plan, None));
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
  let mut run = wait_run(c, &applying.run_id, j, mask).await?;
  if args.flags.brief {
    crate::plan_cmd::compact_run(&mut run);
  }
  Ok((secrets, plan, Some(run)))
}

fn require_confirmation(
  plan: &Plan,
  args: &EnvSyncArgs,
  j: bool,
  preview: bool,
) -> CliResult<()> {
  let missing: Vec<_> = plan
    .needs_confirm
    .iter()
    .filter(|a| !args.flags.confirm.contains(a))
    .collect();
  if missing.is_empty() {
    return Ok(());
  }
  if !j {
    crate::print::plan_with(plan, !preview);
  }
  let names = missing.iter().map(|a| a.as_str()).collect::<Vec<_>>();
  let mut error = ApiError::new(
    ErrorCode::ConfirmRequired,
    format!("计划里有高风险项，需要确认：{}", names.join("、")),
  )
  .with_details(wharf_api_types::plan::confirm_details(
    plan, &missing,
  ));
  let flags = names
    .iter()
    .map(|a| format!(" --confirm {a}"))
    .collect::<String>();
  if preview {
    error = error.with_hint(format!("重新运行原命令并追加{flags}"));
  } else {
    let verify = match args.flags.dns_verify.mode() {
      Some(true) => " --verify-before-dns",
      Some(false) => " --no-verify-before-dns",
      None => "",
    };
    error = error
      .with_hint(format!("plan_id = {}", plan.plan_id))
      .suggest(format!(
        "wharf apply {}{flags}{verify}",
        plan.plan_id
      ));
  }
  Err(error.into())
}

#[test]
fn sync_preserves_refs_and_masks_preview() {
  use clap::Parser;
  let cli = crate::Cli::try_parse_from([
    "wharf", "service", "env", "sync", "app", ".env",
  ])
  .unwrap();
  let crate::Command::Service(crate::ServiceCmd::Env(
    ServiceEnvArgs {
      command: Some(ServiceEnvCmd::Sync(args)),
      ..
    },
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

#[test]
fn sync_masks_only_secret_text_and_preserves_plan_run_receipts() {
  use serde_json::json;
  let values = sensitive_values(&dotenv::parse(
    "DEBUG=1\nPORT=80\nAPP_ENV=production\nSHORT_TOKEN=short\nAPI_KEY=fixture-secret"
  ).unwrap());
  assert_eq!(values, ["fixture-secret"]);
  let mut run = serde_json::from_value(json!({
    "run_id":"fixture-secret-180","plan_id":"fixture-secret-801",
    "status":"succeeded","started_at":"2026-11-28T00:00:00Z",
    "steps":[{"items":[1],"title":"fixture","status":"done","log":["fixture-secret DEBUG=1 PORT=80"]}]
  })).unwrap();
  redact_run(&mut run, &values);
  let receipt = serde_json::to_value(run).unwrap();
  assert_eq!(receipt["run_id"], "fixture-secret-180");
  assert_eq!(receipt["plan_id"], "fixture-secret-801");
  assert_eq!(receipt["status"], "succeeded");
  assert_eq!(receipt["steps"][0]["log"][0], "*** DEBUG=1 PORT=80");
}

#[test]
fn env_accepts_read_only_shorthand_and_keeps_sync() {
  use clap::Parser;
  for argv in [
    &["wharf", "service", "env"][..],
    &["wharf", "service", "env", "app"],
    &["wharf", "service", "env", "list", "app"],
    &["wharf", "service", "env", "sync", "app", ".env"],
  ] {
    assert!(crate::Cli::try_parse_from(argv).is_ok(), "{argv:?}");
  }
}

#[test]
fn sync_confirmation_preserves_machine_receipt_and_retry_command() {
  use clap::Parser;
  use serde_json::json;
  let cli = crate::Cli::try_parse_from([
    "wharf",
    "service",
    "env",
    "sync",
    "app",
    ".env",
    "--apply",
    "--no-verify-before-dns",
  ])
  .unwrap();
  let crate::Command::Service(crate::ServiceCmd::Env(
    ServiceEnvArgs {
      command: Some(ServiceEnvCmd::Sync(args)),
      ..
    },
  )) = cli.command
  else {
    panic!("预期为 env sync")
  };
  let plan = serde_json::from_value(json!({
    "plan_id":"plan-180","status":"pending",
    "created_at":"2026-11-28T00:00:00Z","expires_at":"2026-11-28T00:15:00Z",
    "base_versions":{},"items":[],"needs_confirm":["service/app"],
  })).unwrap();
  let CliError::Api(err) =
    require_confirmation(&plan, &args, true, false).unwrap_err()
  else {
    panic!("预期为确认错误")
  };
  assert_eq!(err.code, ErrorCode::ConfirmRequired);
  assert_eq!(err.hint.as_deref(), Some("plan_id = plan-180"));
  assert_eq!(
    err.suggest,
    [
      "wharf apply plan-180 --confirm service/app --no-verify-before-dns"
    ]
  );
  assert_eq!(err.details.unwrap()["plan_id"], "plan-180");

  let CliError::Api(preview) =
    require_confirmation(&plan, &args, true, true).unwrap_err()
  else {
    panic!("预期为确认错误")
  };
  assert!(preview.hint.unwrap().contains("--confirm service/app"));
  assert!(preview.suggest.is_empty());
}
