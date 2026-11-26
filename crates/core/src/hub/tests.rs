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
    gateway_extra_files: true,
  };
  let json = serde_json::to_string(&hello).unwrap();
  let old = serde_json::from_str::<OldAgentMsg>(&json);
  assert!(old.is_ok());
}

impl Hub {
  pub(crate) fn mock_agent(
    &self,
    server: &str,
    gateway_extra_files: bool,
    mut handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    let (tx, mut rx) = mpsc::channel(16);
    let pending =
      Arc::new(Mutex::new(HashMap::<u64, Pending>::new()));
    let closed = CancellationToken::new();
    self.register(
      server,
      Conn {
        conn_id: self.next_conn.fetch_add(1, Ordering::Relaxed),
        tx,
        pending: pending.clone(),
        closed: closed.clone(),
        rtt_ms: Default::default(),
        host_shell: false,
        forward: false,
        service_checks: false,
        container_diagnosis: false,
        access_logs: false,
        net_probe: false,
        container_probe: false,
        ssh_logins: false,
        gateway_extra_files,
        upgrade_only: false,
      },
    );
    tokio::spawn(async move {
      loop {
        let msg = tokio::select! {
          () = closed.cancelled() => break,
          msg = rx.recv() => msg,
        };
        let Some(msg) = msg else {
          break;
        };
        if let CoreMsg::Request { id, op, .. } = msg
          && let Some(p) = lock(&pending).remove(&id)
        {
          let _ = p.done.send(handle(op));
        }
      }
    });
  }
}
