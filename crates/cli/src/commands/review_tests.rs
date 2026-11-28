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
  let code = match dispatch(&client, cli.command, cli.json).await {
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
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let endpoint = format!("http://{}", listener.local_addr().unwrap());
  let server = async move {
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
      socket.read_exact(&mut vec![0; len]).await.unwrap();
      let body = body.to_string();
      let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
      );
      socket.write_all(response.as_bytes()).await.unwrap();
    }
  };
  let mut child =
    tokio::process::Command::new(std::env::current_exe().unwrap());
  child
    .args([
      "--exact",
      "commands::review_tests::fixture_cli",
      "--nocapture",
    ])
    .env("WHARF_FIXTURE_CLI_ENDPOINT", endpoint)
    .env("WHARF_FIXTURE_CLI_ARGS", json!(args).to_string())
    .kill_on_drop(true);
  let output = tokio::time::timeout(Duration::from_secs(10), async {
    let output = child.output();
    tokio::pin!(output);
    tokio::select! {
      output = &mut output => output,
      () = server => output.await,
    }
  })
  .await
  .unwrap_or_else(|_| panic!("CLI 测试超时：{args:?}"))
  .unwrap();
  let stdout = String::from_utf8(output.stdout).unwrap();
  let json =
    &stdout[stdout.find(['{', '[']).unwrap_or(stdout.len())..];
  let value = serde_json::from_str(json).unwrap_or_else(|error| {
    panic!(
      "{error}: {stdout:?}, stderr={:?}",
      String::from_utf8_lossy(&output.stderr)
    )
  });
  (output.status.code().unwrap(), value)
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
