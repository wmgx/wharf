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
