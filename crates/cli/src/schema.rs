use std::collections::BTreeMap;

use schemars::{Schema, schema_for};
use serde_json::{Value, json};
use wharf_api_types::{ApiError, backup, plan, spec, view};

use crate::{client::CliResult, commands::out, print};

fn entries() -> BTreeMap<&'static str, Schema> {
  BTreeMap::from([
    ("fleet", schema_for!(spec::Fleet)),
    ("server", schema_for!(spec::ServerSettings)),
    ("service", schema_for!(spec::ServiceSpec)),
    ("wait_condition", schema_for!(spec::WaitCondition)),
    ("restart_schedule", schema_for!(view::RestartScheduleView)),
    ("gateway", schema_for!(spec::GatewaySpec)),
    ("route", schema_for!(spec::RouteSpec)),
    ("change", schema_for!(spec::Change)),
    ("plan", schema_for!(plan::Plan)),
    ("plan_run", schema_for!(crate::commands::PlanRun<'_>)),
    ("plan_summary", schema_for!(plan::PlanSummary)),
    ("run", schema_for!(plan::Run)),
    ("status", schema_for!(view::Status)),
    ("file_entry", schema_for!(wharf_api_types::agent::FileEntry)),
    (
      "file_tail",
      schema_for!(wharf_api_types::agent::FileTailResult),
    ),
    (
      "file_grep",
      schema_for!(wharf_api_types::agent::FileGrepResult),
    ),
    ("file_rm", schema_for!(wharf_api_types::agent::FileRmResult)),
    ("file_mv", schema_for!(wharf_api_types::agent::FileMvResult)),
    (
      "file_mkdir",
      schema_for!(wharf_api_types::agent::FileMkdirResult),
    ),
    ("wait", schema_for!(crate::wait::WaitOutput)),
    ("error", schema_for!(ApiError)),
    (
      "adopt-mount",
      schema_for!(wharf_api_types::adopt_data::AdoptMountSpec),
    ),
    (
      "data-manifest-request",
      schema_for!(wharf_api_types::data_sync::ManifestRequest),
    ),
    (
      "data-manifest",
      schema_for!(wharf_api_types::data_sync::DataManifestResult),
    ),
    (
      "data-pull-request",
      schema_for!(wharf_api_types::data_sync::PullRequest),
    ),
    (
      "data-push-options",
      schema_for!(wharf_api_types::data_sync::PushOptions),
    ),
    (
      "data-push-plan",
      schema_for!(wharf_api_types::data_sync::DataPushPlan),
    ),
    (
      "data-pull-summary",
      schema_for!(wharf_api_types::data_sync::DataSyncSummary),
    ),
    (
      "data-push-summary",
      schema_for!(wharf_api_types::data_sync::DataSyncSummary),
    ),
    (
      "bundle-export-request",
      schema_for!(wharf_api_types::bundle::ExportBundleRequest),
    ),
    (
      "bundle-export-summary",
      schema_for!(wharf_api_types::bundle::BundleExportSummary),
    ),
    (
      "bundle-export-response",
      schema_for!(wharf_api_types::bundle::ExportBundleResponse),
    ),
    (
      "bundle-import-request",
      schema_for!(wharf_api_types::bundle::ImportBundleRequest),
    ),
    (
      "bundle-import-preview",
      schema_for!(wharf_api_types::bundle::BundleImportPreview),
    ),
    (
      "bundle-import-response",
      schema_for!(wharf_api_types::bundle::BundleImportResponse),
    ),
    (
      "import-preview",
      schema_for!(wharf_api_types::view::ImportPreview),
    ),
    (
      "service-import-preview",
      schema_for!(view::ServiceImportPreview),
    ),
    (
      "import-request",
      schema_for!(wharf_api_types::view::ImportRequest),
    ),
    (
      "extracted-secret",
      schema_for!(wharf_api_types::view::ExtractedSecretItem),
    ),
    ("server_view", schema_for!(view::ServerView)),
    ("service_render", schema_for!(view::ServiceRenderView)),
    ("crash-guard", schema_for!(view::CrashGuardView)),
    ("service-repair", schema_for!(view::RepairView)),
    (
      "service_compose_export",
      schema_for!(view::ServiceComposeExport),
    ),
    ("var", schema_for!(spec::VarView)),
    ("service_exec", schema_for!(view::ServiceExecResponse)),
    ("host_exec", schema_for!(view::HostExecResponse)),
    ("exec_stream_event", schema_for!(view::ExecStreamEvent)),
    ("service_view", schema_for!(view::ServiceView)),
    (
      "limits-suggest",
      schema_for!(Vec<wharf_api_types::resources::LimitSuggestion>),
    ),
    ("service_action", schema_for!(plan::ServiceAction)),
    ("gateway_view", schema_for!(view::GatewayView)),
    ("route_view", schema_for!(view::RouteView)),
    ("doctor", schema_for!(view::DoctorReport)),
    ("network", schema_for!(view::NetworkView)),
    ("data", schema_for!(view::DataView)),
    ("data_cleanup", schema_for!(view::DataCleanupView)),
    ("data_cleanup_result", schema_for!(view::DataCleanupResult)),
    ("data_cleanup_policy", schema_for!(view::DataCleanupPolicy)),
    ("exposure", schema_for!(view::ExposureView)),
    ("alerts", schema_for!(view::AlertsView)),
    ("task", schema_for!(view::TaskView)),
    ("task_run", schema_for!(view::TaskRunView)),
    ("apply_response", schema_for!(plan::ApplyResponse)),
    ("backup_move_preview", schema_for!(view::BackupMovePreview)),
    ("backup_move_abort", schema_for!(view::BackupMoveAbort)),
    (
      "core_backup_verify",
      schema_for!(view::CoreBackupVerifyView),
    ),
    (
      "core_backup_export",
      schema_for!(view::CoreBackupExportResult),
    ),
    ("backup", schema_for!(view::BackupsView)),
    ("backup_ls", schema_for!(backup::BackupLsView)),
    ("backup_extract", schema_for!(backup::BackupExtractResult)),
    ("backup_diff", schema_for!(backup::BackupDiffView)),
    ("backup_keep", schema_for!(backup::BackupKeepResult)),
    ("backup_policy", schema_for!(backup::BackupPolicy)),
    ("backup_unlock", schema_for!(view::BackupUnlockResult)),
    ("core_safe_mode", schema_for!(view::CoreSafeModeView)),
    ("deployment", schema_for!(view::DeploymentView)),
    ("edge", schema_for!(view::EdgeAppView)),
    ("account", schema_for!(view::AccountView)),
    ("secret", schema_for!(view::SecretView)),
    ("secret_import", schema_for!(view::SecretImportResponse)),
    ("service_env", schema_for!(crate::env_sync::EnvList)),
    (
      "service_env_sync",
      schema_for!(crate::env_sync::SyncResponse),
    ),
    ("config", schema_for!(view::ConfigItemView)),
    ("service_defaults", schema_for!(spec::ServiceDefaults)),
    ("ref_report", schema_for!(view::RefReport)),
    ("tree", schema_for!(view::TreeView)),
    ("search", schema_for!(view::SearchResponse)),
    ("lint", schema_for!(view::LintReport)),
    ("task_artifacts", schema_for!(view::TaskArtifactsView)),
    (
      "missing_ref",
      schema_for!(wharf_api_types::error::MissingRef),
    ),
    ("token", schema_for!(view::TokenView)),
    ("token_explain", schema_for!(view::TokenExplain)),
    ("report", schema_for!(wharf_api_types::report::ReportView)),
    ("top", schema_for!(wharf_api_types::resources::UsageRow)),
    (
      "service_limits",
      schema_for!(crate::runtime_options::LimitView<'_>),
    ),
    (
      "access_logs",
      schema_for!(wharf_api_types::access_logs::AccessLogsResult),
    ),
    (
      "net_probe",
      schema_for!(wharf_api_types::net_probe::NetProbeReport),
    ),
    ("cert", schema_for!(view::CertStatus)),
    (
      "dns_check",
      schema_for!(wharf_api_types::external::DnsCheck),
    ),
    (
      "external",
      schema_for!(wharf_api_types::external::ExternalStatus),
    ),
    ("audit", schema_for!(view::AuditEntry)),
    ("core_snapshots", schema_for!(view::CoreSnapshotsView)),
    ("core_key", schema_for!(view::CoreKeyView)),
    ("oidc", schema_for!(view::OidcView)),
    ("timeline", schema_for!(view::Timeline)),
  ])
}

fn paths(root: &Value) -> Vec<Value> {
  fn walk<'a>(
    root: &'a Value,
    node: &'a Value,
    path: &str,
    active: &mut Vec<&'a str>,
    rows: &mut BTreeMap<String, Value>,
  ) {
    if let Some(reference) = node["$ref"].as_str()
      && let Some(target) =
        reference.strip_prefix('#').and_then(|r| root.pointer(r))
      && !active.contains(&reference)
    {
      active.push(reference);
      walk(root, target, path, active, rows);
      active.pop();
    }
    let types: Vec<_> = match &node["type"] {
      Value::String(ty) => vec![ty.as_str()],
      Value::Array(types) => {
        types.iter().filter_map(Value::as_str).collect()
      }
      _ => Vec::new(),
    };
    if !path.is_empty() && !types.is_empty() {
      let row = rows.entry(path.to_string()).or_insert_with(|| json!({
        "path": path, "type": "", "nullable": false, "description": null,
      }));
      let ty = types
        .iter()
        .copied()
        .filter(|ty| *ty != "null")
        .collect::<Vec<_>>()
        .join(" | ");
      if !ty.is_empty() {
        row["type"] = json!(ty);
      }
      if types.contains(&"null") {
        row["nullable"] = json!(true);
      }
      if node["description"].is_string() {
        row["description"] = node["description"].clone();
      }
    }
    if let Some(properties) = node["properties"].as_object() {
      for (key, schema) in properties {
        let path = if path.is_empty() {
          key.clone()
        } else {
          format!("{path}.{key}")
        };
        walk(root, schema, &path, active, rows);
      }
    }
    if let Some(items) = node.get("items") {
      walk(root, items, &format!("{path}[]"), active, rows);
    }
    if let Some(additional) = node.get("additionalProperties") {
      walk(root, additional, &format!("{path}.*"), active, rows);
    }
    for key in ["anyOf", "oneOf"] {
      if let Some(variants) = node[key].as_array() {
        for variant in variants {
          walk(root, variant, path, active, rows);
        }
      }
    }
  }

  let mut rows = BTreeMap::new();
  walk(root, root, "", &mut Vec::new(), &mut rows);
  rows.into_values().collect()
}

fn command_output_schema(
  command: &Value,
  mut schema: Value,
) -> Value {
  if !matches!(
    command.as_str(),
    Some(
      "wharf plan list"
        | "wharf run list"
        | "wharf server list"
        | "wharf service list"
        | "wharf service files"
        | "wharf service files ls"
        | "wharf service history"
        | "wharf gateway list"
        | "wharf route list"
        | "wharf ops account list"
        | "wharf ops task ls"
        | "wharf ops task logs"
        | "wharf ops token list"
        | "wharf network edge list"
        | "wharf network external list"
        | "wharf config"
        | "wharf config list"
        | "wharf config var list"
        | "wharf secret list"
        | "wharf secret unused"
        | "wharf inspect audit"
        | "wharf inspect top"
    )
  ) {
    return schema;
  }
  let mut array = json!({"type": "array"});
  if let Some(item) = schema.as_object_mut() {
    for key in ["$schema", "$defs"] {
      if let Some(value) = item.remove(key) {
        array[key] = value;
      }
    }
  }
  array["items"] = schema;
  array
}

pub fn run(
  resource: &[String],
  command_query: bool,
  flat: bool,
  j: bool,
) -> CliResult<()> {
  let all = entries();
  let schema = match resource {
    [] => {
      print::json(&all);
      return Ok(());
    }
    [name] if !command_query && name == "web" => {
      wharf_api_types::web_schema::web_schema()
    }
    [name] if !command_query && all.contains_key(name.as_str()) => {
      serde_json::to_value(&all[name.as_str()])
        .map_err(anyhow::Error::from)?
    }
    _ => {
      let mut description = crate::describe::lookup(resource)
        .ok_or_else(|| {
          let name = resource.join(" ");
          if resource.len() == 1 && !command_query {
            ApiError::invalid(format!(
              "没有 {name}，可选：{}、web",
              all.keys().copied().collect::<Vec<_>>().join("、")
            ))
          } else {
            ApiError::invalid(format!("没有命令 wharf {name}"))
          }
        })?;
      let schema = description["returns"]
        .as_str()
        .and_then(|name| all.get(name))
        .map(serde_json::to_value)
        .transpose()
        .map_err(anyhow::Error::from)?
        .map(|schema| {
          command_output_schema(&description["command"], schema)
        });
      if !flat {
        description["schema"] = schema.unwrap_or(Value::Null);
        print::json(&description);
        return Ok(());
      }
      schema.ok_or_else(|| {
          let command = description["command"].as_str().unwrap_or_default();
          ApiError::invalid(format!(
            "{command} 没有已登记的默认返回类型，去掉 --paths 可查看命令说明"
          ))
        })?
    }
  };
  if flat {
    out(j, &paths(&schema), |paths| {
      for row in paths {
        println!(
          "{}  {}  {}",
          row["path"].as_str().unwrap_or_default(),
          row["type"].as_str().unwrap_or_default(),
          row["description"].as_str().unwrap_or_default()
        );
      }
    });
  } else {
    print::json(&schema);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  #[test]
  fn service_view_schema_paths() {
    let all = super::entries();
    let schema = serde_json::to_value(&all["service_view"]).unwrap();
    let paths = super::paths(&schema);
    assert!(paths.iter().any(|row| row["path"] == "status.actual"));
    let cleanup = serde_json::to_value(&all["data_cleanup"]).unwrap();
    assert!(
      super::paths(&cleanup)
        .iter()
        .any(|row| row["path"] == "items[].id")
    );
    let commands = crate::describe::commands(&[]);
    for entry in commands["commands"].as_array().unwrap() {
      if let Some(schema) = entry["returns"].as_str() {
        assert!(all.contains_key(schema));
      }
    }
  }

  #[test]
  fn cleanup_web_schema_matches_serialized_fields() {
    let web = wharf_api_types::web_schema::web_schema();
    for (name, fields) in [
      (
        "DataCleanupExecRequest",
        &[
          "all",
          "confirm",
          "expired_only",
          "ids",
          "include_unlabeled",
          "kind",
          "server",
          "service",
        ][..],
      ),
      ("DataCleanupPolicy", &["auto_expire", "keep_days"][..]),
      ("DataCleanupItem", &["blocked", "expired"][..]),
      ("DataCleanupActionResult", &["freed_bytes"][..]),
    ] {
      let schema = &web["$defs"][name];
      for field in fields {
        assert!(
          schema["properties"][*field].is_object(),
          "{name}.{field}"
        );
        assert!(
          schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|required| required == *field),
          "{name}.{field}"
        );
      }
    }
    assert!(
      serde_json::from_value::<
        wharf_api_types::view::DataCleanupExecRequest,
      >(serde_json::json!({}))
      .is_ok()
    );
  }
}
