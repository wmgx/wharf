use super::*;

#[test]
fn protocol_gate() {
  // 旧 agent 只能升级
  assert!(!protocol_ok(0));
  assert!(!protocol_ok(1));
  assert!(protocol_ok(PROTOCOL));
  assert!(!protocol_ok(PROTOCOL + 1));
  assert!(!protocol_ok(u32::MAX));
}

#[test]
fn old_hello_has_no_host_shell_capability() {
  let hello: AgentMsg = serde_json::from_value(serde_json::json!({
    "type": "hello",
    "server": "s1",
    "public_key": "k",
    "signature": "s",
    "nonce": "n",
    "version": "0.1.0",
    "protocol": 1
  }))
  .unwrap();
  let AgentMsg::Hello {
    host_shell,
    ssh_logins,
    ..
  } = hello
  else {
    panic!("不是 hello");
  };
  assert!(!host_shell);
  assert!(!ssh_logins);
}

#[test]
fn old_core_ignores_new_hello_capability() {
  #[allow(dead_code)]
  #[derive(serde::Deserialize)]
  #[serde(tag = "type", rename_all = "snake_case")]
  enum OldAgentMsg {
    Hello {
      server: String,
      public_key: String,
      signature: String,
      nonce: String,
      version: String,
      #[serde(default)]
      protocol: u32,
    },
  }

  let hello = AgentMsg::Hello {
    server: "s1".into(),
    public_key: "k".into(),
    signature: "s".into(),
    nonce: "n".into(),
    kx: Some("k".into()),
    version: "0.1.0".into(),
    protocol: PROTOCOL,
    host_shell: true,
    forward: true,
    service_checks: true,
    container_diagnosis: true,
    access_logs: true,
    net_probe: true,
    container_probe: true,
    ssh_logins: true,
    core_probe: true,
  };
  let json = serde_json::to_string(&hello).unwrap();
  let old = serde_json::from_str::<OldAgentMsg>(&json);
  assert!(old.is_ok());
}

#[tokio::test]
async fn agent_upgrade_needs_no_bound_core_server_or_probe_support() {
  let state = crate::rules::tests::test_state();
  state
    .db
    .call(|c| {
      let db = crate::db::Write::Upsert {
        kind: "server".into(),
        name: "s1".into(),
        spec: serde_json::json!({}),
        meta: serde_json::json!({}),
      };
      crate::db::apply_write(c, &db)?;
      let report =
        serde_json::to_string(&wharf_api_types::agent::AgentReport {
          build: "old".into(),
          ..Default::default()
        })
        .map_err(crate::db::json_err)?;
      c.execute(
        "INSERT INTO agents (server, report) VALUES ('s1', ?1)",
        [report],
      )
      .map_err(sql_err)?;
      assert!(crate::core_node::load_persisted(c)?.is_none());
      Ok(())
    })
    .await
    .unwrap();
  let (tx, mut rx) = mpsc::channel(1);
  let conn = Conn {
    conn_id: 1,
    public_key: String::new(),
    core_probe: false,
    tx,
    pending: Default::default(),
    closed: CancellationToken::new(),
    rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
    host_shell: false,
    forward: false,
    service_checks: false,
    container_diagnosis: false,
    access_logs: false,
    net_probe: false,
    container_probe: false,
    ssh_logins: false,
    upgrade_only: true,
  };
  state.hub.register("s1", conn.clone());
  let handle = async {
    let CoreMsg::Request {
      id,
      op: AgentOp::Upgrade(job),
      ..
    } = rx.recv().await.unwrap()
    else {
      panic!("没有收到 agent 自升级请求");
    };
    assert!(job.container.is_none());
    let pending = lock(&conn.pending).remove(&id).unwrap();
    pending.done.send(Ok(serde_json::json!({"image":"example.test/agent:latest", "started":false}))).unwrap();
  };
  let cancel = CancellationToken::new();
  let progress: ProgressFn = Arc::new(|_| {});
  let (result, ()) =
    tokio::time::timeout(Duration::from_secs(5), async {
      tokio::join!(
        crate::agent_upgrade::upgrade(
          &state, "s1", progress, &cancel
        ),
        handle
      )
    })
    .await
    .unwrap();
  result.unwrap();
}
