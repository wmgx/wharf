//! `wharf commands`：全部命令的机器可读说明，AI 一次读完，不用反复试 `--help`。

use clap::CommandFactory;
use serde_json::{Value, json};

use crate::command_paths;

/// 只留有内容的字段，省 AI 的上下文。
fn compact(v: Value) -> Value {
  match v {
    Value::Object(m) => Value::Object(
      m.into_iter()
        .filter(|(_, v)| match v {
          Value::Null | Value::Bool(false) => false,
          Value::Array(a) => !a.is_empty(),
          _ => true,
        })
        .collect(),
    ),
    other => other,
  }
}

fn arg(a: &clap::Arg) -> Value {
  let flag = match (a.get_long(), a.get_short()) {
    _ if a.is_positional() => format!("<{}>", a.get_id()),
    (Some(l), _) => format!("--{l}"),
    (None, Some(c)) => format!("-{c}"),
    (None, None) => a.get_id().to_string(),
  };
  compact(json!({
    "arg": flag,
    "required": a.is_required_set(),
    "value": !a.is_positional() && a.get_action().takes_values(),
    "repeat": matches!(a.get_action(), clap::ArgAction::Append) || a.get_num_args().is_some_and(|r| r.max_values() > 1),
    "default": a.get_default_values().iter().map(|v| v.to_string_lossy().into_owned()).collect::<Vec<_>>(),
    "choices": a.get_possible_values().iter().map(|v| v.get_name().to_string()).collect::<Vec<_>>(),
    "help": a.get_long_help().or(a.get_help()).map(|h| h.to_string()),
  }))
}

fn children(
  cmd: &clap::Command,
) -> impl Iterator<Item = &clap::Command> {
  cmd.get_subcommands().filter(|sub| sub.get_name() != "help")
}

fn walk<'a>(
  cmd: &'a clap::Command,
  path: &mut Vec<&'a str>,
  out: &mut Vec<Value>,
  legacy: bool,
) {
  if let Some(entry) = entry(cmd, path) {
    out.push(entry);
  }
  for sub in children(cmd) {
    if path.is_empty()
      && !legacy
      && command_paths::group(sub.get_name()).is_some()
    {
      continue;
    }
    path.push(sub.get_name());
    walk(sub, path, out, legacy);
    path.pop();
  }
}

fn entry(cmd: &clap::Command, path: &[&str]) -> Option<Value> {
  if children(cmd).next().is_none()
    || !path.is_empty() && !cmd.is_subcommand_required_set()
  {
    let args: Vec<Value> = cmd
      .get_arguments()
      .filter(|a| {
        !a.is_global_set()
          && !matches!(a.get_id().as_str(), "help" | "version")
      })
      .map(arg)
      .collect();
    let command = command_paths::business_path(path).join(" ");
    let mut entry = compact(json!({
      "command": format!("wharf {}", path.join(" ")),
      "about": cmd.get_about().map(|h| h.to_string()),
      "details": cmd.get_long_about().map(|h| h.to_string()),
      "args": args,
    }));
    let (effect, perms) = effect(&command, cmd);
    entry["effect"] = json!(effect);
    entry["perms"] = json!(perms);
    entry["returns"] = json!(returns(&command));
    if matches!(command.as_str(), "exec" | "service exec") {
      entry["exit_code"] = json!("remote");
    }
    if perms.is_empty() {
      entry["offline"] = json!(true);
    }
    if read_when_no_args(&command) {
      entry["read_when_no_args"] = json!(true);
    }
    if command == "data cleanup policy" {
      entry["write_perms"] = json!(["admin"]);
    }
    if matches!(
      command.as_str(),
      "data push" | "data cleanup" | "import"
    ) || cmd
      .get_arguments()
      .any(|a| a.get_long() == Some("dry-run"))
    {
      entry["dry_run"] = json!(true);
    }
    if cmd.get_arguments().any(|a| a.get_long() == Some("apply")) {
      entry["apply_perms"] = match command.as_str() {
        "data cleanup" => json!(["apply", "confirm"]),
        "data push" => json!(["exec"]),
        "service env sync" => json!(["plan", "apply"]),
        _ => json!(["apply"]),
      };
    }
    match command.as_str() {
      "service repair" => {
        entry["flag_variants"] = json!({
          "--status": {"effect": "read", "perms": ["read"], "returns": "service-repair"},
          "command": {"perms": ["admin", "apply", "confirm", "exec"]}
        });
      }
      "service crash-guard" => {
        entry["flag_variants"] = json!({
          "--on": {"effect": "plan", "perms": ["plan"], "returns": "plan"},
          "--off": {"effect": "plan", "perms": ["plan"], "returns": "plan"}
        });
      }
      "top" => {
        entry["flag_variants"] = json!({
          "--suggest-limits": {"effect": "read", "perms": ["read"], "returns": "limits-suggest"}
        });
      }
      "service restart" | "service stop" | "service update" => {
        entry["flag_variants"] = json!({
          "--tag": {"effect": "plan", "perms": ["plan"], "returns": "plan"}
        });
      }
      "var set" => {
        entry["returns_without_value"] = json!("var");
      }
      "data push" => {
        entry["flag_variants"] = json!({
          "--delete": {"apply_perms": ["exec", "confirm"]},
          "--apply": {"returns": "data-push-summary"}
        });
      }
      "export" => {
        entry["flag_variants"] = json!({
          "--with-secrets": {"perms": ["admin"], "returns": "bundle-export-summary"}
        });
      }
      "service import" => {
        entry["flag_variants"] = json!({
          "--extract-secrets": {"returns": "service-import-preview", "when": "无 --apply 且提取到密钥"}
        });
      }
      "defaults" => {
        entry["write_perms"] = json!(["admin"]);
        entry["flag_variants"] = json!({
          "--server": {
            "returns": "plan_run",
            "write_perms": ["plan"],
            "when": "同时提供修改参数",
            "otherwise": "config"
          }
        });
      }
      "service restart-schedule" => {
        entry["write_perms"] = json!(["plan"]);
        entry["returns_by_flag"] = json!({
          "--cron": "plan", "--skip-if-stopped": "plan", "--catch-up": "plan",
          "--unset-catch-up": "plan", "--off": "plan", "--apply": "run"
        });
      }
      "service limits" => {
        entry["returns_by_flag"] = json!({
          "--memory": "plan", "--cpus": "plan", "--pids": "plan",
          "--unset-memory": "plan", "--unset-cpus": "plan",
          "--unset-pids": "plan", "--off": "plan", "--apply": "plan_run"
        });
        entry["flag_variants"] = json!({
          "--apply": {
            "returns": "plan_run",
            "when": "带修改参数且计划有变更项，优先于修改参数的返回类型",
            "otherwise": "plan"
          }
        });
      }
      "service env sync" => {
        entry["import_perms"] = json!(["admin"]);
      }
      "backup core" => {
        entry["returns_by_flag"] = json!({
          "--verify-password":"core_backup_verify", "--export":"core_backup_export"
        });
        entry["perms_by_flag"] = json!({
          "--verify-password":["admin"], "--export":["admin"], "--to":["admin"],
          "--unlock":["admin"], "--run":["apply"]
        });
      }
      "backup move" => {
        entry["returns_by_flag"] = json!({
          "--dry-run":"backup_move_preview", "--abort":"backup_move_abort", "--no-wait":"apply_response"
        });
        entry["perms_by_flag"] =
          json!({"--core":["admin"], "--confirm":["confirm"]});
      }
      _ => {}
    }
    Some(entry)
  } else {
    None
  }
}

pub fn lookup(words: &[String]) -> Option<Value> {
  let mut root = command_paths::app();
  root.build();
  let mut cmd = &root;
  let mut path = Vec::new();
  if let Some(group) =
    words.first().and_then(|name| command_paths::group(name))
  {
    cmd = root.find_subcommand(group)?;
    path.push(group);
  }
  for word in words {
    cmd = children(cmd).find(|sub| {
      sub.get_name() == word.as_str()
        || sub.get_all_aliases().any(|alias| alias == word.as_str())
    })?;
    path.push(cmd.get_name());
  }
  let mut description = entry(cmd, &path).unwrap_or_else(|| {
    let mut group = compact(json!({
      "command": format!("wharf {}", path.join(" ")),
      "about": cmd.get_about().map(|h| h.to_string()),
      "details": cmd.get_long_about().map(|h| h.to_string()),
    }));
    group["returns"] = Value::Null;
    group
  });
  let subcommands: Vec<_> =
    children(cmd).map(clap::Command::get_name).collect();
  if !subcommands.is_empty() {
    description["subcommands"] = json!(subcommands);
  }
  Some(description)
}

fn read_when_no_args(command: &str) -> bool {
  matches!(
    command,
    "defaults"
      | "service auto-update"
      | "service monitor"
      | "service limits"
      | "service port-check"
      | "service heartbeat"
      | "service note"
      | "service log-alert"
      | "service restart-schedule"
      | "service update-ignore"
      | "service file"
      | "service deploy"
      | "server note"
      | "server set"
      | "server watch-unit"
      | "server baseline"
      | "gateway add"
      | "gateway forward"
      | "gateway wildcard"
      | "gateway error-page"
      | "gateway trusted-proxies"
      | "gateway timeouts"
      | "route note"
      | "route sso"
      | "route caddy"
      | "route guard"
      | "route add"
      | "alert set"
      | "alert options"
      | "token set"
      | "sso email"
      | "secret restrict"
      | "external set"
      | "egress api"
      | "backup core"
      | "data cleanup"
      | "data cleanup policy"
      | "backup set"
      | "task set"
      | "var set"
  )
}

fn effect(
  command: &str,
  cmd: &clap::Command,
) -> (&'static str, &'static [&'static str]) {
  if command == "defaults" {
    return ("direct", &["read"]);
  }
  if matches!(command, "var set" | "var rm") {
    return ("plan", &["plan", "admin"]);
  }
  if command == "var get" {
    return ("read", &["read"]);
  }
  if matches!(command, "schema" | "commands" | "validate" | "login") {
    return ("read", &[]);
  }
  if matches!(
    command,
    "audit"
      | "token list"
      | "token explain"
      | "gate key list"
      | "core snapshot list"
  ) {
    return ("read", &["admin"]);
  }
  if matches!(command, "sso account list" | "sso account show") {
    return ("read", &["admin"]);
  }
  if matches!(
    command,
    "exec"
      | "server apt"
      | "server watch-unit"
      | "server host-units"
      | "server host-logs"
  ) {
    let effect = if matches!(
      command,
      "exec" | "server apt" | "server watch-unit"
    ) {
      "direct"
    } else {
      "read"
    };
    return (effect, &["host"]);
  }
  match command {
    "data pull" => return ("read", &["read"]),
    "data push" => return ("direct", &["read"]),
    "service adopt-data" => {
      return ("plan", &["plan", "host", "admin"]);
    }
    "service import" => return ("plan", &["plan", "host"]),
    "service export-compose" | "service crash-guard" => {
      return ("read", &["read"]);
    }
    "service clone" => return ("plan", &["plan"]),
    "service rename" => return ("plan", &["plan", "admin"]),
    "service repair" => {
      return ("direct", &["admin", "apply", "confirm"]);
    }
    "import" => return ("plan", &["admin", "plan"]),
    _ => {}
  }
  if matches!(
    command,
    "service files rm" | "service files mv" | "service files mkdir"
  ) {
    return ("direct", &["exec"]);
  }
  if matches!(command, "service files tail" | "service files grep") {
    return ("read", &["read"]);
  }
  if command == "gateway rotate-link" {
    return ("direct", &["apply"]);
  }
  if command == "egress presets" {
    return ("read", &[]);
  }
  if matches!(command, "data cleanup" | "data cleanup policy") {
    return ("direct", &["read"]);
  }
  if command == "service env sync" {
    return ("read", &["read"]);
  }
  if command == "plan"
    || cmd.get_arguments().any(|a| a.get_long() == Some("apply"))
  {
    return ("plan", &["plan"]);
  }
  if matches!(command, "config set" | "config unset") {
    return ("direct", &["admin"]);
  }
  let leaf = cmd.get_name();
  if matches!(command, "task run" | "task cancel") {
    return ("direct", &["apply", "exec"]);
  }
  if matches!(command, "connect" | "service exec") {
    return ("direct", &["exec"]);
  }
  if matches!(
    command,
    "status"
      | "top"
      | "report"
      | "whoami"
      | "doctor"
      | "metrics"
      | "data"
      | "egress"
      | "network"
      | "export"
      | "audit"
      | "shell-log"
      | "self-update"
      | "core addresses"
      | "core key"
      | "core logs"
      | "alert digest"
      | "route cert"
      | "route dns-check"
      | "gateway config"
      | "service origin"
      | "service render"
      | "service history"
      | "service timeline"
      | "server exposure"
      | "server dirs"
      | "server usage"
      | "server traffic"
      | "server sessions"
      | "server host"
      | "server disk"
      | "server host-units"
      | "secret explain"
      | "sso oidc"
      | "network acl"
      | "service files"
      | "alert firing"
      | "refs"
      | "tree"
      | "search"
      | "lint"
      | "config"
      | "config get"
      | "secret refs"
      | "secret unused"
      | "task artifacts"
      | "backup diff"
      | "backup extract"
  ) || command.starts_with("wait ")
    || matches!(
      leaf,
      "list" | "ls" | "show" | "logs" | "host-logs" | "versions"
    )
  {
    return ("read", &["read"]);
  }
  if command.starts_with("token ")
    || command.starts_with("secret ")
    || command.starts_with("sso account ")
    || command.starts_with("core ")
    || command.starts_with("external ")
    || command.starts_with("gate ")
    || command.starts_with("notify ")
    || matches!(
      command,
      "upgrade" | "egress api" | "sso email" | "sso oidc"
    )
  {
    return ("direct", &["admin"]);
  }
  ("direct", &["apply"])
}

fn returns(command: &str) -> Option<&'static str> {
  Some(match command {
    "export" => "fleet",
    "data pull" => "data-pull-summary",
    "data push" => "data-push-plan",
    "import" => "bundle-import-preview",
    "service adopt-data" | "service move" | "server set"
    | "service import" | "service clone" | "service rename" => "plan",
    "service files" | "service files ls" => "file_entry",
    "service files tail" => "file_tail",
    "service files grep" => "file_grep",
    "service files rm" => "file_rm",
    "service files mv" => "file_mv",
    "service files mkdir" => "file_mkdir",
    "wait server" | "wait dns" | "wait cert" => "wait",
    "status" => "status",
    "plan" | "plan show" => "plan",
    "plan list" => "plan_summary",
    "apply" | "run list" | "run show" | "run wait" => "run",
    "server list" | "server show" => "server_view",
    "service list" | "service show" => "service_view",
    "gateway list" | "gateway show" => "gateway_view",
    "route list" => "route_view",
    "doctor" => "doctor",
    "network" => "network",
    "data" => "data",
    "data cleanup" => "data_cleanup",
    "data cleanup policy" => "data_cleanup_policy",
    "server exposure" => "exposure",
    "alert list" => "alerts",
    "task ls" | "task show" => "task",
    "task logs" => "task_run",
    "backup move" => "run",
    "exec" => "host_exec",
    "service exec" => "service_exec",
    "service render" => "service_render",
    "service restart-schedule" => "restart_schedule",
    "service crash-guard" => "crash-guard",
    "service repair" => "service-repair",
    "service export-compose" => "service_compose_export",
    "var get" | "var list" => "var",
    "var set" | "var rm" => "plan",
    "service limits" => "service_limits",
    "backup list" => "backup",
    "backup ls" => "backup_ls",
    "backup extract" => "backup_extract",
    "backup diff" => "backup_diff",
    "backup keep" => "backup_keep",
    "backup set" => "backup_policy",
    "backup unlock" => "backup_unlock",
    "core resume" => "core_safe_mode",
    "service history" => "deployment",
    "edge list" | "edge show" => "edge",
    "account list" => "account",
    "secret list" | "secret unused" => "secret",
    "refs" | "secret refs" => "ref_report",
    "tree" => "tree",
    "search" => "search",
    "lint" => "lint",
    "defaults" | "config" | "config list" | "config get"
    | "config set" | "config unset" => "config",
    "secret import" => "secret_import",
    "service env" | "service env list" => "service_env",
    "service env sync" => "service_env_sync",
    "task artifacts" => "task_artifacts",
    "token list" => "token",
    "token explain" => "token_explain",
    "report" => "report",
    "top" => "top",
    "gateway logs" => "access_logs",
    "server probe" => "net_probe",
    "route cert" => "cert",
    "route dns-check" => "dns_check",
    "external list" => "external",
    "audit" => "audit",
    "core snapshot list" => "core_snapshots",
    "core key" => "core_key",
    "sso oidc" => "oidc",
    "service timeline" => "timeline",
    _ => return None,
  })
}

pub fn usable(prefix: &[String], me: &Value) -> Value {
  let mut result = commands(prefix);
  if let Some(commands) = result["commands"].as_array_mut() {
    commands.retain_mut(|command| {
      let path: Vec<_> = command["command"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .skip(1)
        .collect();
      let path = command_paths::business_path(&path);
      if matches!(path, ["var", ..])
        && me["services"]
          .as_array()
          .is_some_and(|scope| !scope.is_empty())
      {
        return false;
      }
      let has = |perm: &Value| {
        me["perms"]
          .as_array()
          .is_some_and(|perms| perms.contains(perm))
      };
      if command["perms"]
        .as_array()
        .is_some_and(|perms| perms.iter().all(has))
      {
        return true;
      }
      if command["read_when_no_args"] == true
        && !matches!(
          path,
          ["token", "set"] | ["server", "watch-unit" | "baseline"]
        )
        && has(&json!("read"))
      {
        command["usable_mode"] = json!("read_only");
        return true;
      }
      false
    });
  }
  result["whoami"] = json!({"name": me["name"], "perms": me["perms"], "services": me["services"]});
  result
}

/// `prefix` 不为空时只列这一组，例如 `["service"]`。
pub fn commands(prefix: &[String]) -> Value {
  let legacy = prefix
    .first()
    .is_some_and(|name| command_paths::group(name).is_some());
  let mut root = if legacy {
    crate::Cli::command()
  } else {
    command_paths::app()
  };
  root.build();
  let mut list = Vec::new();
  walk(&root, &mut Vec::new(), &mut list, legacy);
  if !prefix.is_empty() {
    let want = format!("wharf {}", prefix.join(" "));
    let descendants = format!("{want} ");
    list.retain(|c| {
      c["command"]
        .as_str()
        .is_some_and(|n| n == want || n.starts_with(&descendants))
    });
  }
  let globals: Vec<Value> = root
    .get_arguments()
    .filter(|a| a.is_global_set())
    .map(arg)
    .collect();
  json!({
    "build": env!("WHARF_CLI_BUILD"),
    "global_args": globals,
    "commands": list,
  })
}

#[cfg(test)]
mod tests {
  #[test]
  fn migrated_directory_preserves_every_entry_and_its_metadata() {
    use super::{command_paths::MOVES, commands, json};
    use std::collections::BTreeMap;

    let directory = commands(&[]);
    let entries = directory["commands"].as_array().unwrap();
    let canonical: BTreeMap<_, _> = entries
      .iter()
      .map(|row| (row["command"].as_str().unwrap(), row))
      .collect();
    assert_eq!(canonical.len(), entries.len());
    for &(old, group) in MOVES {
      let old_entries = commands(&[old.into()]);
      let old_entries = old_entries["commands"].as_array().unwrap();
      assert!(!old_entries.is_empty(), "{old}");
      let new_entries = commands(&[group.into(), old.into()]);
      assert_eq!(
        new_entries["commands"].as_array().unwrap().len(),
        old_entries.len(),
        "{old}"
      );
      for row in old_entries {
        let path = row["command"]
          .as_str()
          .unwrap()
          .strip_prefix("wharf ")
          .unwrap();
        assert!(
          !canonical.contains_key(row["command"].as_str().unwrap()),
          "{path}"
        );
        let new = format!("wharf {group} {path}");
        let mut expected = row.clone();
        expected["command"] = json!(new);
        assert_eq!(canonical[new.as_str()], &expected, "{path}");
      }
    }
  }

  #[test]
  fn var_commands_report_returns_and_respect_global_scope() {
    use super::{commands, json, usable};

    let prefix = ["var".into()];
    let described = commands(&prefix);
    let entries = described["commands"].as_array().unwrap();
    let entry = |name: &str| {
      entries.iter().find(|v| v["command"] == name).unwrap()
    };
    assert_eq!(entry("wharf var set")["returns"], "plan");
    assert_eq!(
      entry("wharf var set")["returns_without_value"],
      "var"
    );
    assert_eq!(entry("wharf var rm")["returns"], "plan");
    let scope = json!({"perms":["read"],"services":["app"]});
    let global = json!({"perms":["read"],"services":[]});
    for (prefix, name) in [
      (vec!["var".into()], "wharf var set"),
      (vec!["config".into(), "var".into()], "wharf config var set"),
    ] {
      assert_eq!(usable(&prefix, &scope)["commands"], json!([]));
      assert!(
        usable(&prefix, &global)["commands"]
          .as_array()
          .unwrap()
          .iter()
          .any(|cmd| cmd["command"] == name
            && cmd["usable_mode"] == "read_only")
      );
    }
  }

  #[test]
  fn commands_describe_data_and_import_flag_variants() {
    use serde_json::json;
    let index = super::commands(&[]);
    let command = |name: &str| {
      index["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["command"] == name)
        .unwrap()
    };
    let push = command("wharf data push");
    assert_eq!(
      push["flag_variants"]["--delete"]["apply_perms"],
      json!(["exec", "confirm"])
    );
    let export = command("wharf plan export");
    assert_eq!(
      export["flag_variants"]["--with-secrets"],
      json!({"perms": ["admin"], "returns": "bundle-export-summary"})
    );
    let import = command("wharf service import");
    assert_eq!(import["returns"], "plan");
    assert_eq!(
      import["flag_variants"]["--extract-secrets"]["returns"],
      "service-import-preview"
    );
  }

  #[test]
  fn service_limits_declares_read_plan_and_apply_results() {
    let v = super::commands(&["service".into(), "limits".into()]);
    let command = &v["commands"][0];
    assert_eq!(command["returns"], "service_limits");
    assert_eq!(command["returns_by_flag"]["--pids"], "plan");
    assert_eq!(command["returns_by_flag"]["--unset-pids"], "plan");
    assert_eq!(command["returns_by_flag"]["--apply"], "plan_run");
  }

  #[test]
  fn backup_move_declares_wait_and_no_wait_results() {
    let v = super::commands(&["backup".into(), "move".into()]);
    let command = &v["commands"][0];
    assert_eq!(command["returns"], "run");
    assert_eq!(
      command["returns_by_flag"]["--no-wait"],
      "apply_response"
    );
  }

  #[test]
  fn usable_keeps_ping_task_edits_with_apply_permission() {
    use serde_json::json;
    let prefix = ["task".into()];
    let apply =
      super::usable(&prefix, &json!({"perms": ["read", "apply"]}));
    let read = super::usable(&prefix, &json!({"perms": ["read"]}));
    let task = |result: &serde_json::Value, name: &str| {
      result["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["command"] == name)
        .cloned()
    };
    for name in
      ["wharf task enable", "wharf task disable", "wharf task set"]
    {
      assert!(task(&apply, name).is_some(), "{name}");
    }
    assert_eq!(
      task(&read, "wharf task set").unwrap()["usable_mode"],
      "read_only"
    );
  }

  #[test]
  fn usable_respects_host_and_baseline_permissions() {
    use serde_json::json;

    for (perms, host, baseline) in [
      (json!(["read", "exec", "apply"]), false, false),
      (json!(["read", "host"]), true, false),
      (json!(["read"]), false, false),
      (json!(["plan"]), false, true),
    ] {
      let result = super::usable(&[], &json!({"perms": perms}));
      let commands = result["commands"].as_array().unwrap();
      for (name, expected) in [
        ("wharf server exec", host),
        ("wharf server apt", host),
        ("wharf server baseline", baseline),
      ] {
        let command = commands.iter().find(|c| c["command"] == name);
        assert_eq!(command.is_some(), expected, "{name}");
        if let Some(command) = command {
          let permission = if name.ends_with("baseline") {
            "plan"
          } else {
            "host"
          };
          assert_eq!(command["perms"], json!([permission]));
        }
      }
    }
  }

  #[test]
  fn lists_leaf_commands() {
    let v = super::commands(&[]);
    let names: Vec<&str> = v["commands"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|c| c["command"].as_str())
      .collect();
    assert!(names.contains(&"wharf service deploy"));
    assert!(names.contains(&"wharf network egress"));
    let usable =
      super::usable(&[], &serde_json::json!({"perms": ["read"]}));
    let entries = usable["commands"].as_array().unwrap();
    assert!(
      entries
        .iter()
        .any(|e| e["command"] == "wharf service monitor"
          && e["usable_mode"] == "read_only")
    );
    assert!(
      !entries.iter().any(|e| e["command"] == "wharf service rm")
    );
    for name in [
      "log-alert",
      "log-alert add",
      "log-alert rm",
      "port-check",
      "heartbeat",
      "unmanaged-ignore",
    ] {
      assert!(
        names.contains(&format!("wharf service {name}").as_str())
      );
    }
    assert!(names.contains(&"wharf wait service"));
    assert!(!names.iter().any(|n| n.ends_with(" help")));
  }
}

#[test]
fn env_sync_advertises_preview_apply_and_import_permissions() {
  let report =
    usable(&["service".into()], &json!({"perms":["read"]}));
  let sync = report["commands"]
    .as_array()
    .unwrap()
    .iter()
    .find(|row| row["command"] == "wharf service env sync")
    .unwrap();
  assert_eq!(sync["perms"], json!(["read"]));
  assert_eq!(sync["apply_perms"], json!(["plan", "apply"]));
  assert_eq!(sync["import_perms"], json!(["admin"]));
  assert_eq!(sync["returns"], "service_env_sync");
}

#[cfg(test)]
mod view_meta_tests {
  #[test]
  fn added_view_commands_report_permissions_and_schemas() {
    let commands = super::commands(&[]);
    let commands = commands["commands"].as_array().unwrap();
    for (name, perm, schema) in [
      ("wharf service files tail", "read", "file_tail"),
      ("wharf service files rm", "exec", "file_rm"),
      ("wharf wait cert", "read", "wait"),
    ] {
      let entry = commands
        .iter()
        .find(|entry| entry["command"] == name)
        .unwrap();
      assert_eq!(entry["perms"][0], perm);
      assert_eq!(entry["returns"], schema);
    }
  }
}
