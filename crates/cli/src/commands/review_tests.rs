use super::*;
use clap::Parser;
use tokio::{
  io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
  net::TcpListener,
};

#[tokio::test]
async fn fixture_cli() {
  let Ok(endpoint) = std::env::var("WHARF_FIXTURE_CLI_ENDPOINT")
  else {
    return;
  };
  let args = std::env::var("WHARF_FIXTURE_CLI_ARGS").unwrap();
  let args: Vec<String> = serde_json::from_str(&args).unwrap();
  let cli =
    Cli::try_parse_from(std::iter::once("wharf".into()).chain(args))
      .unwrap();
  let client = Client::test_endpoint(endpoint);
  print::set_quiet(cli.quiet);
  println!("WHARF_FIXTURE_STDOUT");
  if let Some(fields) = &cli.fields {
    print::set_fields(fields);
  }
  let code = match dispatch(
    &client,
    cli.command,
    cli.json || cli.fields.is_some(),
  )
  .await
  {
    Ok(()) => 0,
    Err(CliError::Exit(code)) => code,
    Err(CliError::Api(error)) => {
      print::error(&error, cli.json);
      error.code.exit_code()
    }
  };
  std::process::exit(code);
}

async fn run_fixture(
  args: &[&str],
  replies: Vec<(&'static str, Value)>,
) -> (i32, Value) {
  let (code, value, _) = fixture_requests(args, replies).await;
  (code, value)
}

async fn fixture_requests(
  args: &[&str],
  replies: Vec<(&'static str, Value)>,
) -> (i32, Value, Vec<Value>) {
  let (code, stdout, stderr, requests) =
    fixture_output(args, replies).await;
  let json =
    &stdout[stdout.find(['{', '[']).unwrap_or(stdout.len())..];
  let value = serde_json::from_str(json).unwrap_or_else(|error| {
    panic!("{error}: {stdout:?}, stderr={stderr:?}")
  });
  (code, value, requests)
}

async fn fixture_output(
  args: &[&str],
  replies: Vec<(&'static str, Value)>,
) -> (i32, String, String, Vec<Value>) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let endpoint = format!("http://{}", listener.local_addr().unwrap());
  let server = async move {
    let mut requests = Vec::new();
    for (expected, body) in replies {
      let (socket, _) = listener.accept().await.unwrap();
      let mut socket = BufReader::new(socket);
      let mut line = String::new();
      socket.read_line(&mut line).await.unwrap();
      assert!(
        line.starts_with(expected),
        "{line:?} 应匹配 {expected:?}"
      );
      let mut len = 0;
      loop {
        line.clear();
        assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
          break;
        }
        if let Some(value) =
          line.to_ascii_lowercase().strip_prefix("content-length:")
        {
          len = value.trim().parse().unwrap();
        }
      }
      let mut request = vec![0; len];
      socket.read_exact(&mut request).await.unwrap();
      if !request.is_empty() {
        requests.push(serde_json::from_slice(&request).unwrap());
      }
      let body = body.to_string();
      let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
      );
      socket.write_all(response.as_bytes()).await.unwrap();
    }
    requests
  };
  let mut child =
    tokio::process::Command::new(std::env::current_exe().unwrap());
  child
    .args([
      "--exact",
      "commands::review_tests::fixture_cli",
      "--nocapture",
    ])
    // 子进程仍由测试运行器启动，给 CLI 的 dispatch future 留出主线程大小的栈。
    .env("RUST_MIN_STACK", "8388608")
    .env("WHARF_FIXTURE_CLI_ENDPOINT", endpoint)
    .env("WHARF_FIXTURE_CLI_ARGS", json!(args).to_string())
    .kill_on_drop(true);
  if args.starts_with(&["secret", "rotate"]) {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "fixture-value\n").unwrap();
    child.stdin(input.reopen().unwrap());
  }
  let (output, requests) =
    tokio::time::timeout(Duration::from_secs(10), async {
      let output = child.output();
      tokio::pin!(output, server);
      tokio::select! {
        biased;
        requests = &mut server => (output.await, requests),
        result = &mut output => {
          let result = result.unwrap();
          panic!(
            "CLI 在收到全部响应前退出（{}），stdout={:?}，stderr={:?}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
          );
        }
      }
    })
    .await
    .unwrap();
  let output = output.unwrap();
  let stdout = String::from_utf8(output.stdout).unwrap();
  let (_, stdout) = stdout
    .split_once("WHARF_FIXTURE_STDOUT\n")
    .unwrap_or_else(|| {
      panic!(
        "CLI 未执行分发：{stdout:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
      )
    });
  (
    output.status.code().unwrap(),
    stdout.to_owned(),
    String::from_utf8(output.stderr).unwrap(),
    requests,
  )
}

fn service_view() -> Value {
  json!({
    "name": "app", "note": "公开备注\nwharf-enc:v1:fixture",
    "host_ports": {}, "addresses": {}, "version": 1, "data": [],
    "spec": {"server": "s1", "source": {"image": "nginx"},
      "files": [{"path": "/etc/app.conf", "content": "fixture"}]}
  })
}

fn plan_response() -> Value {
  json!({
    "plan_id": "p_fixture", "status": "pending", "base_versions": {},
    "created_at": "2026-11-28T00:00:00Z", "expires_at": "2026-11-28T00:05:00Z",
    "items": [{"id": 1, "address": "service/app", "layer": "config",
      "action": "update", "reason": "更新服务"}]
  })
}

fn run_response(status: &str) -> Value {
  json!({
    "run_id": "r_fixture", "plan_id": "p_fixture", "status": status,
    "started_at": "2026-11-28T00:00:00Z", "steps": []
  })
}

#[tokio::test]
async fn e2e_auto_update_invocation_applies_plan() {
  let line = include_str!("../../../../scripts/e2e.sh")
    .lines()
    .find(|line| line.starts_with("wharf service auto-update app "))
    .unwrap();
  let args = line
    .split_whitespace()
    .skip(1)
    .chain(["--json"])
    .collect::<Vec<_>>();
  let (code, value) = run_fixture(
    &args,
    vec![
      ("GET /api/services/app ", service_view()),
      ("POST /api/plan ", plan_response()),
      ("POST /api/apply ", json!({"run_id": "r_fixture"})),
      ("GET /api/runs/r_fixture ", run_response("succeeded")),
    ],
  )
  .await;
  assert_eq!(code, 0);
  assert_eq!(value["run"]["status"], "succeeded");
}

#[tokio::test]
async fn read_only_views_strip_legacy_sealed_notes() {
  let server = json!({
    "name": "s1", "settings": {}, "joined": true, "online": true,
    "version": 1, "note": "公开备注\nwharf-enc:v1:fixture"
  });
  let route = json!({
    "id": "app.example.test", "url": "https://app.example.test", "version": 1,
    "spec": {"hostname": "app.example.test", "service": "app"},
    "note": "公开备注\nwharf-enc:v1:fixture"
  });
  for (args, request, body, list) in [
    (
      &["server", "list"][..],
      "GET /api/servers ",
      json!([server]),
      true,
    ),
    (
      &["service", "list"][..],
      "GET /api/services ",
      json!([service_view()]),
      true,
    ),
    (
      &["service", "deploy", "app"][..],
      "GET /api/services/app ",
      service_view(),
      false,
    ),
    (
      &["route", "add", "app.example.test"][..],
      "GET /api/routes ",
      json!([route]),
      false,
    ),
  ] {
    let args = [args, &["--json"]].concat();
    let (code, value) =
      run_fixture(&args, vec![(request, body)]).await;
    assert_eq!(code, 0, "{args:?}: {value}");
    let view = if list { &value[0] } else { &value };
    assert_eq!(view["note"], "公开备注", "{args:?}");
    assert_eq!(view["has_sealed_note"], true, "{args:?}");
  }
}

#[tokio::test]
async fn upgrade_partial_failure_prints_one_json_and_exits_four() {
  let (code, value) = run_fixture(
    &["upgrade", "--json"],
    vec![
      ("POST /api/servers/upgrade ", json!({})),
      ("GET /api/version ", json!({"build": "fixture"})),
      (
        "POST /api/upgrade ",
        json!({"image": "fixture", "started": false}),
      ),
      ("GET /api/servers ", json!([])),
      ("POST /api/servers/upgrade ", json!({"run_id": "r_fixture"})),
      ("GET /api/runs/r_fixture ", run_response("failed")),
    ],
  )
  .await;
  assert_eq!(code, 4);
  assert_eq!(value["post_agents"]["status"], "failed");
  assert_eq!(value["error"]["code"], "AgentFailed");
}

#[tokio::test]
async fn read_only_config_rejects_plan_flags() {
  let gateway = json!({
    "name": "edge", "routes": [], "version": 1,
    "spec": {"server": "s1", "kind": "caddy"}
  });
  for (args, request, body) in [
    (
      &["service", "update-ignore", "app"][..],
      "GET /api/services/app ",
      service_view(),
    ),
    (
      &["service", "file", "app"][..],
      "GET /api/services/app ",
      service_view(),
    ),
    (
      &["service", "file", "app", "/etc/app.conf"][..],
      "GET /api/services/app ",
      service_view(),
    ),
    (
      &["service", "log-alert", "app"][..],
      "GET /api/services/app ",
      service_view(),
    ),
    (
      &["gateway", "trusted-proxies", "edge"][..],
      "GET /api/gateways/edge ",
      gateway.clone(),
    ),
    (
      &["gateway", "timeouts", "edge"][..],
      "GET /api/gateways/edge ",
      gateway,
    ),
  ] {
    for flags in [
      &["--apply"][..],
      &["--note", "fixture"],
      &["--confirm", "service/app"],
    ] {
      let args = [args, flags, &["--json"]].concat();
      let (code, value) =
        run_fixture(&args, vec![(request, body.clone())]).await;
      assert_eq!(code, 1, "{args:?}: {value}");
      assert_eq!(value["code"], "InvalidInput", "{args:?}");
      assert_eq!(
        value["message"], "没有指定要修改的配置项",
        "{args:?}"
      );
    }
  }
}

#[tokio::test]
async fn deploy_plan_and_apply_omit_dockerfile_from_detection() {
  let directory = tempfile::tempdir().unwrap();
  std::fs::write(directory.path().join("app.py"), "print('hi')")
    .unwrap();
  for apply in [false, true] {
    let mut args = vec![
      "deploy",
      directory.path().to_str().unwrap(),
      "--name",
      "app",
      "--json",
    ];
    let mut replies = vec![
      ("GET /api/services/app ", service_view()),
      ("GET /api/uploads/", json!({"exists": true})),
      ("POST /api/plan ", plan_response()),
    ];
    if apply {
      args.push("--apply");
      replies.extend([
        ("POST /api/apply ", json!({"run_id": "r_fixture"})),
        ("GET /api/runs/r_fixture ", run_response("succeeded")),
      ]);
    }
    let (code, value) = run_fixture(&args, replies).await;
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["detected"]["language"], "python");
    assert!(value["detected"].get("dockerfile").is_none());
  }
}

#[tokio::test]
async fn service_deploy_removes_env_before_adding_and_replaces_ports()
{
  let mut service = service_view();
  service["spec"]["env"] = json!({"FOO": "old", "KEEP": "yes"});
  service["spec"]["ports"] =
    json!([{"name": "http", "container": 80}]);
  service["spec"]["port_checks"] = json!({"http": {"kind": "off"}});
  let (code, _, requests) = fixture_requests(
    &[
      "service",
      "deploy",
      "app",
      "--rm-env",
      "FOO",
      "--add-env",
      "FOO=new",
      "--port",
      "metrics=9090",
      "--json",
    ],
    vec![
      ("GET /api/services/app ", service),
      ("POST /api/plan ", plan_response()),
    ],
  )
  .await;
  assert_eq!(code, 0);
  let spec = &requests[0]["changes"][0]["spec"];
  assert_eq!(spec["env"], json!({"FOO": "new", "KEEP": "yes"}));
  assert_eq!(spec["ports"].as_array().unwrap().len(), 1);
  assert_eq!(spec["ports"][0]["name"], "metrics");
  assert!(spec["port_checks"].get("http").is_none());
}

#[tokio::test]
async fn incremental_flags_prepare_changes_without_a_mode_or_replacement()
 {
  let mut service = service_view();
  service["spec"]["ports"] =
    json!([{"name": "http", "container": 80}]);
  let (code, _, requests) = fixture_requests(
    &[
      "service",
      "deploy",
      "app",
      "--add-port",
      "metrics=9090",
      "--json",
    ],
    vec![
      ("GET /api/services/app ", service),
      ("POST /api/plan ", plan_response()),
    ],
  )
  .await;
  assert_eq!(code, 0);
  assert_eq!(
    requests[0]["changes"][0]["spec"]["ports"]
      .as_array()
      .unwrap()
      .len(),
    2
  );

  let route = json!({
    "id": "app.example.test", "url": "https://app.example.test", "version": 1,
    "spec": {"hostname": "app.example.test", "service": "app",
      "sso": {"mode":"gate", "skip_paths":["/health"]}}
  });
  let (code, _, requests) = fixture_requests(
    &[
      "route",
      "sso",
      "app.example.test",
      "--add-skip",
      "/ready",
      "--json",
    ],
    vec![
      ("GET /api/routes ", json!([route])),
      ("POST /api/plan ", plan_response()),
    ],
  )
  .await;
  assert_eq!(code, 0);
  assert_eq!(
    requests[0]["changes"][0]["spec"]["sso"]["skip_paths"],
    json!(["/health", "/ready"])
  );
}

#[tokio::test]
async fn exec_fields_keeps_single_document_and_remote_exit_code() {
  let response = json!({
    "exit_code": 2, "stdout": "fixture-out", "stderr": "fixture-err",
    "truncated": false, "duration_ms": 1, "output_bytes": 22
  });
  let (code, value) = run_fixture(
    &["exec", "s1", "--fields", "stdout", "--", "exit 2"],
    vec![("POST /api/servers/s1/exec ", response)],
  )
  .await;
  assert_eq!(code, 2);
  assert_eq!(value, json!({"stdout": "fixture-out"}));
}

#[tokio::test]
async fn task_set_dry_run_without_edits_rejects_before_fetching() {
  let (code, value) = run_fixture(
    &["task", "set", "fixture", "--dry-run", "--json"],
    vec![],
  )
  .await;
  assert_eq!(code, 1);
  assert_eq!(value["code"], "InvalidInput");
}

#[tokio::test]
async fn env_sync_preflights_confirmation_before_import() {
  let file = tempfile::NamedTempFile::new().unwrap();
  std::fs::write(file.path(), "API_KEY=fixture-sensitive").unwrap();
  let mut plan = plan_response();
  plan["needs_confirm"] = json!(["service/app"]);
  plan["items"][0]["impacts"] = json!(["public"]);
  let (code, body, requests) = fixture_requests(
    &[
      "service",
      "env",
      "sync",
      "app",
      file.path().to_str().unwrap(),
      "--apply",
      "--json",
    ],
    vec![
      ("GET /api/services/app ", service_view()),
      ("GET /api/secrets ", json!([])),
      ("POST /api/plan?preview_secrets=", plan),
    ],
  )
  .await;
  assert_eq!(code, 2);
  assert_eq!(body["code"], "ConfirmRequired");
  assert_eq!(
    body["details"]["needs_confirm"],
    json!(["service/app"])
  );
  assert!(
    body["hint"]
      .as_str()
      .unwrap()
      .contains("--confirm service/app")
  );
  assert_eq!(requests.len(), 1);
  assert!(!requests[0].to_string().contains("fixture-sensitive"));
}

#[tokio::test]
async fn env_sync_brief_masks_logs_and_preserves_machine_output() {
  let file = tempfile::NamedTempFile::new().unwrap();
  std::fs::write(
    file.path(),
    "DEBUG=1\nPORT=80\nAPI_KEY=fixture-sensitive",
  )
  .unwrap();
  let mut plan = plan_response();
  plan["plan_id"] = json!("p_180");
  let mut run = run_response("succeeded");
  run["plan_id"] = json!("p_180");
  run["run_id"] = json!("r_801");
  run["steps"] = json!([
    {"items":[1],"title":"应用","status":"done","log":["fixture-sensitive", "2", "3", "4", "5", "6"]},
    {"items":[1],"title":"验证","status":"done","log":["fixture-sensitive DEBUG=1 PORT=80"]}
  ]);
  let (code, body) = run_fixture(
    &[
      "service",
      "env",
      "sync",
      "app",
      file.path().to_str().unwrap(),
      "--apply",
      "--plain",
      "API_KEY",
      "--brief",
      "--json",
    ],
    vec![
      ("GET /api/services/app ", service_view()),
      ("GET /api/secrets ", json!([])),
      ("POST /api/plan?brief=1 ", plan),
      ("POST /api/apply ", json!({"run_id":"r_801"})),
      ("GET /api/runs/r_801 ", run),
    ],
  )
  .await;
  assert_eq!(code, 0);
  assert_eq!(body["plan"]["plan_id"], "p_180");
  assert_eq!(body["run"]["run_id"], "r_801");
  assert_eq!(body["run"]["status"], "succeeded");
  assert_eq!(
    body["run"]["steps"][0]["log"],
    json!(["<omitted 6 lines>"])
  );
  assert_eq!(
    body["run"]["steps"][1]["log"],
    json!(["*** DEBUG=1 PORT=80"])
  );
}

#[tokio::test]
async fn artifact_download_returns_manifest_fields() {
  let dir = tempfile::tempdir().unwrap();
  let file = dir.path().join("report.txt");
  let artifacts =
    json!([{"path":"report.txt","size":3,"sha256":"fixture"}]);
  let (code, body) = run_fixture(
    &["task", "artifacts", "fixture", "--get", "report.txt", "-o", file.to_str().unwrap(), "--fields", "artifacts"],
    vec![
      ("GET /api/tasks/fixture/artifacts ", json!({
        "task":"fixture","run_id":1,"started_at":"2026-11-28T00:00:00Z",
        "status":"succeeded","total_bytes":3,"artifacts":artifacts,
      })),
      ("GET /api/tasks/fixture/runs/1/artifacts/download?path=report.txt ", json!(123)),
    ],
  ).await;
  assert_eq!(code, 0);
  assert_eq!(body["artifacts"], artifacts);
  assert_eq!(std::fs::read(file).unwrap(), b"123");
}

#[tokio::test]
async fn quiet_secret_rotation_finishes_apply_or_exits_silently() {
  for (action, endpoint, status, exit) in [
    (
      "rotate",
      "POST /api/secrets/KEY/rotate ",
      Some("succeeded"),
      0,
    ),
    (
      "rollback",
      "POST /api/secrets/KEY/rollback ",
      Some("failed"),
      4,
    ),
    ("rollback", "POST /api/secrets/KEY/rollback ", None, 0),
  ] {
    let mut replies = vec![(
      endpoint,
      json!({
        "secret": {"name": "KEY", "updated_at": "2026-11-28T00:00:00Z"},
        "needs_plan": status.is_some(), "affected_services": [],
        "affected_gateways": [], "other_refs": [], "suggest": []
      }),
    )];
    if let Some(status) = status {
      replies.extend([
        ("POST /api/plan ", plan_response()),
        ("POST /api/apply ", json!({"run_id": "r_fixture"})),
        ("GET /api/runs/r_fixture ", run_response(status)),
      ]);
    }
    let (code, stdout, stderr, _) = fixture_output(
      &["secret", action, "KEY", "--apply", "-q"],
      replies,
    )
    .await;
    assert_eq!(code, exit, "{action}: {stderr}");
    assert_eq!(
      stdout,
      if status.is_some() { "r_fixture\n" } else { "" }
    );
    assert!(stderr.is_empty(), "{stderr}");
  }
}

#[tokio::test]
async fn quiet_history_prints_deployment_id() {
  let (code, stdout, stderr, _) = fixture_output(
    &["service", "history", "app", "-q"],
    vec![("GET /api/services/app/deployments ", json!([{
      "id": 42, "run_id": "r_fixture", "service": "app", "server": "s1",
      "compose": "", "hash": "", "images": [], "created_at": "2026-11-28T00:00:00Z"
    }]))],
  ).await;
  assert_eq!(code, 0, "{stderr}");
  assert_eq!(stdout, "42\n");
}

#[tokio::test]
async fn quiet_import_and_link_rotation_print_only_ids() {
  let (code, stdout, stderr, _) = fixture_output(
    &["service", "import", "s1", "--project", "app", "--print", "-q"],
    vec![
      ("POST /api/import ", json!({
        "name": "app", "spec": {"server": "s1", "source": {"compose": {"content": "services: {}"}}},
        "warnings": ["导入提醒"]
      })),
      ("POST /api/plan ", plan_response()),
    ],
  ).await;
  assert_eq!(code, 0, "{stderr}");
  assert_eq!(stdout, "p_fixture\n");
  let (code, stdout, stderr, _) = fixture_output(
    &["gateway", "rotate-link", "gw", "--apply", "-q"],
    vec![
      ("POST /api/gateways/gw/link/rotate ", json!({"gateway": "gw", "server": "s1", "rotated_token": true})),
      ("POST /api/plan ", plan_response()),
      ("POST /api/apply ", json!({"run_id": "r_fixture"})),
      ("GET /api/runs/r_fixture ", run_response("succeeded")),
    ],
  ).await;
  assert_eq!(code, 0, "{stderr}");
  assert_eq!(stdout, "r_fixture\n");
}
