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
    "repeat": matches!(a.get_action(), clap::ArgAction::Append),
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
    || !path.is_empty()
      && cmd.get_arguments().any(|a| {
        !a.is_global_set()
          && (a.is_positional() || a.get_id() == "probe")
      })
  {
    let args: Vec<Value> = cmd
      .get_arguments()
      .filter(|a| {
        !a.is_global_set()
          && !matches!(a.get_id().as_str(), "help" | "version")
      })
      .map(arg)
      .collect();
    out.push(compact(json!({
      "command": format!("wharf {}", path.join(" ")),
      "about": cmd.get_about().map(|h| h.to_string()),
      "details": cmd.get_long_about().map(|h| h.to_string()),
      "args": args,
    })));
  }
  for s in subs {
    path.push(s.get_name().to_string());
    walk(s, path, out);
    path.pop();
  }
}

/// `prefix` 不为空时只列这一组，例如 `["service"]`。
pub fn commands(prefix: &[String]) -> Value {
  let root = crate::Cli::command();
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
  fn lists_leaf_commands() {
    let v = super::commands(&[]);
    let names: Vec<&str> = v["commands"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|c| c["command"].as_str())
      .collect();
    assert!(names.contains(&"wharf service deploy"));
    assert!(names.contains(&"wharf wait service"));
    assert!(!names.iter().any(|n| n.ends_with(" help")));
  }
}
