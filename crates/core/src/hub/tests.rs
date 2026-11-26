use super::*;

impl Hub {
  pub(crate) fn register_test_conn(
    &self,
    server: &str,
    core_probe: bool,
  ) -> mpsc::Receiver<CoreMsg> {
    let (tx, rx) = mpsc::channel(32);
    let conn = Conn {
      conn_id: self.next_conn.fetch_add(1, Ordering::Relaxed),
      tx,
      pending: Default::default(),
      closed: CancellationToken::new(),
      rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
      host_shell: true,
      forward: true,
      service_checks: true,
      container_diagnosis: true,
      access_logs: true,
      net_probe: true,
      container_probe: true,
      ssh_logins: true,
      core_probe,
      upgrade_only: false,
    };
    self.register(server, conn);
    rx
  }
}

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
    core_probe,
    ..
  } = hello
  else {
    panic!("不是 hello");
  };
  assert!(!host_shell);
  assert!(!ssh_logins);
  assert!(!core_probe);
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
