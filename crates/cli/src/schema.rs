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
    ("gateway", schema_for!(spec::GatewaySpec)),
    ("route", schema_for!(spec::RouteSpec)),
    ("change", schema_for!(spec::Change)),
    ("plan", schema_for!(plan::Plan)),
    ("plan_summary", schema_for!(plan::PlanSummary)),
    ("run", schema_for!(plan::Run)),
    ("status", schema_for!(view::Status)),
    ("error", schema_for!(ApiError)),
    ("server_view", schema_for!(view::ServerView)),
    ("service_render", schema_for!(view::ServiceRenderView)),
    ("service_exec", schema_for!(view::ServiceExecResponse)),
    ("host_exec", schema_for!(view::HostExecResponse)),
    ("exec_stream_event", schema_for!(view::ExecStreamEvent)),
    ("service_view", schema_for!(view::ServiceView)),
    ("gateway_view", schema_for!(view::GatewayView)),
    ("route_view", schema_for!(view::RouteView)),
    ("doctor", schema_for!(view::DoctorReport)),
    ("network", schema_for!(view::NetworkView)),
    ("data", schema_for!(view::DataView)),
    ("exposure", schema_for!(view::ExposureView)),
    ("alerts", schema_for!(view::AlertsView)),
    ("task", schema_for!(view::TaskView)),
    ("task_run", schema_for!(view::TaskRunView)),
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
    ("token", schema_for!(view::TokenView)),
    ("token_explain", schema_for!(view::TokenExplain)),
    ("report", schema_for!(wharf_api_types::report::ReportView)),
    ("top", schema_for!(wharf_api_types::resources::UsageRow)),
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

pub fn run(
  resource: Option<&str>,
  flat: bool,
  j: bool,
) -> CliResult<()> {
  let all = entries();
  let Some(name) = resource else {
    print::json(&all);
    return Ok(());
  };
  let schema = if name == "web" {
    wharf_api_types::web_schema::web_schema()
  } else {
    let schema = all.get(name).ok_or_else(|| {
      ApiError::invalid(format!(
        "没有 {name}，可选：{}、web",
        all.keys().copied().collect::<Vec<_>>().join("、")
      ))
    })?;
    serde_json::to_value(schema).map_err(anyhow::Error::from)?
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
    let commands = crate::describe::commands(&[]);
    for entry in commands["commands"].as_array().unwrap() {
      if let Some(schema) = entry["returns"].as_str() {
        assert!(all.contains_key(schema));
      }
    }
  }
}
