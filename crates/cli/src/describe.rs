//! `wharf commands`：全部命令的机器可读说明，AI 一次读完，不用反复试 `--help`。

use clap::CommandFactory;
use serde_json::{Value, json};

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

fn walk(
  cmd: &clap::Command,
  path: &mut Vec<String>,
  out: &mut Vec<Value>,
) {
  let subs: Vec<&clap::Command> = cmd
    .get_subcommands()
    .filter(|s| s.get_name() != "help")
    .collect();
  if subs.is_empty()
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
    let command = path.join(" ");
    let mut entry = compact(json!({
      "command": format!("wharf {command}"),
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
    if cmd.get_arguments().any(|a| a.get_long() == Some("dry-run")) {
      entry["dry_run"] = json!(true);
    }
    if cmd.get_arguments().any(|a| a.get_long() == Some("apply")) {
      entry["apply_perms"] = if command == "service env sync" {
        json!(["plan", "apply"])
      } else {
        json!(["apply"])
      };
    }
    if command == "service env sync" {
      entry["import_perms"] = json!(["admin"]);
    }
    out.push(entry);
  }
  for s in subs {
    path.push(s.get_name().to_string());
    walk(s, path, out);
    path.pop();
  }
}

fn read_when_no_args(command: &str) -> bool {
  matches!(
    command,
    "service auto-update"
      | "service monitor"
      | "service limits"
      | "service port-check"
      | "service heartbeat"
      | "service note"
      | "service log-alert"
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
      | "backup set"
      | "task set"
  )
}

fn effect(
  command: &str,
  cmd: &clap::Command,
) -> (&'static str, &'static [&'static str]) {
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
  if command == "gateway rotate-link" {
    return ("direct", &["apply"]);
  }
  if command == "egress presets" {
    return ("read", &[]);
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
    "server exposure" => "exposure",
    "alert list" => "alerts",
    "task ls" | "task show" => "task",
    "task logs" => "task_run",
    "exec" => "host_exec",
    "service exec" => "service_exec",
    "service render" => "service_render",
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
    "config" | "config list" | "config get" | "config set"
    | "config unset" => "config",
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
          command["command"].as_str(),
          Some(
            "wharf token set"
              | "wharf server watch-unit"
              | "wharf server baseline"
          )
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
  let mut root = crate::Cli::command();
  root.build();
  let mut list = Vec::new();
  walk(&root, &mut Vec::new(), &mut list);
  if !prefix.is_empty() {
    let want = format!("wharf {}", prefix.join(" "));
    list.retain(|c| {
      c["command"].as_str().is_some_and(|n| {
        n == want || n.starts_with(&format!("{want} "))
      })
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
        ("wharf exec", host),
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
    assert!(names.contains(&"wharf egress"));
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
