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
fn repair_json_preserves_business_exit_without_signaling_confirmation()
 {
  use std::io::{Read, Write};
  let listener =
    std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
  let url = format!("http://{}", listener.local_addr().unwrap());
  let server = std::thread::spawn(move || {
    let (mut conn, _) = listener.accept().unwrap();
    conn
      .set_read_timeout(Some(std::time::Duration::from_secs(3)))
      .unwrap();
    let mut request = [0; 4096];
    let n = conn.read(&mut request).unwrap();
    assert!(
      request[..n].starts_with(b"POST /api/services/app/repair ")
    );
    let body = r#"{"service":"app","execution":{"service":"app","server":"s1","container":"repair","exit_code":2,"stdout":"","stderr":"","truncated":false,"duration_ms":1}}"#;
    write!(conn,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
  });
  let result = Command::new(env!("CARGO_BIN_EXE_wharf"))
    .args([
      "--url", &url, "--token", "fixture", "--json", "service",
      "repair", "app", "--", "exit", "2",
    ])
    .output()
    .unwrap();
  assert_eq!(result.status.code(), Some(1));
  assert!(result.stderr.is_empty(), "{:?}", result.stderr);
  let view: serde_json::Value =
    serde_json::from_slice(&result.stdout).unwrap();
  assert_eq!(view["execution"]["exit_code"], 2);
  server.join().unwrap();
}
