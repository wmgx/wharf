use std::process::Command;

#[test]
fn json_single_doc_exit_code_and_detect_only() {
  let wharf = env!("CARGO_BIN_EXE_wharf");
  let invalid = Command::new(wharf)
    .args(["service", "deploy", "--bad-flag", "--json"])
    .output()
    .unwrap();
  assert_eq!(invalid.status.code(), Some(1));
  assert!(invalid.stderr.is_empty());
  let error: serde_json::Value =
    serde_json::from_slice(&invalid.stdout).unwrap();
  assert_eq!(error["code"], "InvalidInput");

  let directory = tempfile::tempdir().unwrap();
  std::fs::write(directory.path().join("app.py"), "print('hi')")
    .unwrap();
  let detected = Command::new(wharf)
    .arg("deploy")
    .arg(directory.path())
    .args([
      "--name",
      "app",
      "--detect-only",
      "--json",
      "--url",
      "http://127.0.0.1:1",
    ])
    .output()
    .unwrap();
  assert!(detected.status.success());
  assert!(detected.stderr.is_empty());
  let detected: serde_json::Value =
    serde_json::from_slice(&detected.stdout).unwrap();
  assert_eq!(detected["language"], "python");
  assert_eq!(detected["default_port"]["port"], 8000);
}

#[test]
fn new_commands_explicitly_reject_quiet_with_one_json_error() {
  let wharf = env!("CARGO_BIN_EXE_wharf");
  for args in [
    &["task", "enable", "fixture"][..],
    &["task", "disable", "fixture"],
    &["task", "set", "fixture"],
    &["task", "cancel", "1"],
    &["service", "exec", "fixture", "--script", "fixture"],
    &["exec", "s1", "--script", "fixture"],
    &["task", "list"],
    &["ops", "task", "ls"],
    &["service", "env", "sync", "fixture", ".env"],
    &["task", "artifacts", "fixture"],
  ] {
    let result = Command::new(wharf)
      .args(["--json", "-q"])
      .args(args)
      .output()
      .unwrap();
    assert_eq!(result.status.code(), Some(1), "{args:?}");
    assert!(result.stderr.is_empty(), "{args:?}");
    let error: serde_json::Value =
      serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(error["code"], "InvalidInput");
  }
}

#[test]
fn validate_paths_preserve_output_errors_and_changed_history() {
  let dir = tempfile::tempdir().unwrap();
  let run = |args: &[&str]| {
    Command::new(env!("CARGO_BIN_EXE_wharf"))
      .current_dir(dir.path())
      .env("XDG_CACHE_HOME", dir.path())
      .args(args)
      .output()
      .unwrap()
  };
  use serde_json::Value;
  for (content, code) in [("", 0), ("[invalid", 1)] {
    std::fs::write(dir.path().join("app.toml"), content).unwrap();
    let old = run(&["validate", "app.toml"]);
    let new = run(&["plan", "validate", "app.toml"]);
    assert_eq!(old.status.code(), Some(code));
    assert_eq!(old.status, new.status);
    assert_eq!(old.stdout, new.stdout);
    assert_eq!(
      old.stderr,
      "请改用 wharf plan validate。\n".as_bytes()
    );
    assert!(new.stderr.is_empty());

    let old = run(&["validate", "app.toml", "--json"]);
    let new = run(&["--json", "plan", "validate", "app.toml"]);
    assert_eq!(old.status.code(), Some(code));
    assert_eq!(old.status, new.status);
    assert_eq!(old.stdout, new.stdout);
    assert!(old.stderr.is_empty() && new.stderr.is_empty());
    let body: Value = serde_json::from_slice(&old.stdout).unwrap();
    assert_eq!(body["ok"], code == 0);
  }

  let help = run(&["validate", "--help"]);
  assert!(help.status.success() && help.stderr.is_empty());
  assert!(
    String::from_utf8_lossy(&help.stdout)
      .contains("Usage: wharf validate")
  );
  let error = run(&["validate", "--bad-flag", "--json"]);
  assert_eq!(error.status.code(), Some(1));
  assert!(error.stderr.is_empty());
  let body: Value = serde_json::from_slice(&error.stdout).unwrap();
  assert_eq!(body["code"], "InvalidInput");

  std::fs::write(dir.path().join("app.toml"), "").unwrap();
  for (args, first) in [
    (&["validate", "app.toml", "--changed"][..], true),
    (&["plan", "validate", "app.toml", "--changed"][..], true),
    (&["validate", "app.toml", "--changed"][..], false),
  ] {
    let output = run(args);
    assert!(output.status.success() && output.stderr.is_empty());
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["first_run"], first);
  }
}

#[test]
fn schema_finds_commands_types_and_hidden_aliases() {
  use serde_json::Value;
  let schema = |words: &[&str]| {
    let output = Command::new(env!("CARGO_BIN_EXE_wharf"))
      .args(["schema", "--json"])
      .args(words)
      .output()
      .unwrap();
    assert!(output.stderr.is_empty(), "{words:?}");
    (
      output.status.code().unwrap(),
      serde_json::from_slice::<Value>(&output.stdout).unwrap(),
    )
  };
  let lookup = |words: &[&str]| {
    let (code, result) = schema(words);
    assert_eq!(code, 0, "{words:?}");
    result
  };
  let backup = lookup(&["data", "backup", "list"]);
  assert_eq!(backup, lookup(&["backup", "list"]));
  assert_eq!(backup["command"], "wharf data backup list");
  assert_eq!(backup["returns"], "backup");
  assert!(backup["schema"].is_object());
  assert_eq!(lookup(&["backup"])["type"], "object");
  assert_eq!(
    lookup(&["--command", "backup"])["command"],
    "wharf data backup"
  );
  for name in ["migrate", "cleanup-legacy"] {
    assert!(
      lookup(&["data", "backup"])["subcommands"]
        .as_array()
        .unwrap()
        .contains(&Value::from(name))
    );
    assert_eq!(
      lookup(&["data", "backup", name])["command"],
      format!("wharf data backup {name}")
    );
  }
  assert_eq!(
    lookup(&["task", "list"])["command"],
    "wharf ops task ls"
  );
  assert!(lookup(&["plan", "validate"])["returns"].is_null());
  let (code, error) = schema(&["plan", "validate", "--paths"]);
  assert_eq!(code, 1);
  assert_eq!(error["code"], "InvalidInput");
  let fields = lookup(&["service_view", "--paths"]);
  assert_eq!(fields, lookup(&["service", "show", "--paths"]));
  assert!(
    fields
      .as_array()
      .unwrap()
      .iter()
      .any(|row| row["path"] == "status.actual")
  );
}
