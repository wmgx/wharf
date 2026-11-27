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
    "protocol": 2
  }))
  .unwrap();
  let AgentMsg::Hello {
    host_shell,
    ssh_logins,
    core_probe,
    gateway_extra_files,
    backup_isolation,
    safe_delete,
    key_rotation,
    ..
  } = hello
  else {
    panic!("不是 hello");
  };
  assert!(!host_shell);
  assert!(!ssh_logins);
  assert!(!core_probe);
  assert!(!gateway_extra_files);
  assert!(!backup_isolation);
  assert!(!safe_delete);
  assert!(!key_rotation);
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
    core_probe: true,
    backup_isolation: true,
    safe_delete: true,
    key_rotation: true,
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
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent_with_backup(
      server,
      gateway_extra_files,
      false,
      false,
      handle,
    );
  }

  pub(crate) fn mock_safe_delete_agent(
    &self,
    server: &str,
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent(server, false, handle);
    lock(&self.conns).get_mut(server).unwrap().safe_delete = true;
  }

  pub(crate) fn mock_agent_with_backup(
    &self,
    server: &str,
    gateway_extra_files: bool,
    backup_isolation: bool,
    core_probe: bool,
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent_options(
      server,
      gateway_extra_files,
      backup_isolation,
      core_probe,
      false,
      handle,
    );
  }

  pub(crate) fn mock_rotation_agent(
    &self,
    server: &str,
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self
      .mock_agent_options(server, false, false, false, true, handle);
  }

  fn mock_agent_options(
    &self,
    server: &str,
    gateway_extra_files: bool,
    backup_isolation: bool,
    core_probe: bool,
    key_rotation: bool,
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
        public_key: if core_probe {
          server.into()
        } else {
          String::new()
        },
        core_probe,
        key_rotation,
        authenticated_core: None,
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
        backup_isolation,
        safe_delete: false,
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
    key_rotation: false,
    authenticated_core: None,
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
    gateway_extra_files: false,
    backup_isolation: false,
    safe_delete: false,
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

fn probe_connection(
  id: u64,
  key: &str,
) -> (Conn, mpsc::Receiver<CoreMsg>) {
  let (tx, rx) = mpsc::channel(8);
  let conn = Conn {
    conn_id: id,
    public_key: key.into(),
    core_probe: true,
    key_rotation: false,
    authenticated_core: None,
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
    gateway_extra_files: false,
    backup_isolation: false,
    safe_delete: false,
    upgrade_only: false,
  };
  (conn, rx)
}

#[tokio::test]
async fn probe_reconnects_do_not_queue_or_block_foreground_verification()
 {
  let dir = tempfile::tempdir().unwrap();
  let mut state = crate::rules::tests::test_state();
  Arc::get_mut(&mut state).unwrap().data_dir =
    dir.path().to_path_buf();
  state
    .db
    .call(|c| {
      c.execute(
        "INSERT INTO agents (server, public_key) VALUES ('s2', 's2')",
        [],
      )
      .map_err(sql_err)?;
      crate::db::set_setting(
        c,
        crate::core_node::SERVER_KEY,
        Some("s2"),
      )?;
      crate::db::set_setting(
        c,
        crate::core_node::PUBKEY_KEY,
        Some("s2"),
      )
    })
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(3), async {
    let mut previous = None;
    for id in 1..=5 {
      let (conn, mut rx) = probe_connection(id, "s1");
      state.hub.register("s1", conn.clone());
      let task = crate::core_node::spawn_probe_on_connect(
        state.clone(),
        "s1".into(),
        id,
        conn.closed.clone(),
      );
      if let Some((old_task, old_conn, _old_rx)) = previous.take() {
        let old_conn: Conn = old_conn;
        let old_task: tokio::task::JoinHandle<()> = old_task;
        old_task.await.unwrap();
        assert!(lock(&old_conn.pending).is_empty());
      }
      assert!(matches!(
        rx.recv().await.unwrap(),
        CoreMsg::Request {
          op: AgentOp::ProbeCoreHost(_),
          ..
        }
      ));
      previous = Some((task, conn, rx));
    }
    let (conn, mut rx) = probe_connection(6, "s2");
    state.hub.register("s2", conn.clone());
    let reply = async {
      let CoreMsg::Request {
        id,
        op: AgentOp::ProbeCoreHost(probe),
        ..
      } = rx.recv().await.unwrap()
      else {
        panic!("前台没有向绑定节点发起挑战");
      };
      let token = std::fs::read_to_string(
        state.data_dir.join(".core-probe").join(probe.challenge_id),
      )
      .unwrap();
      lock(&conn.pending)
        .remove(&id)
        .unwrap()
        .done
        .send(Ok(serde_json::json!({"token":token})))
        .unwrap();
    };
    let cancel = CancellationToken::new();
    let (verified, ()) = tokio::join!(
      crate::core_node::require_verified(&state, &cancel),
      reply
    );
    assert_eq!(verified.unwrap().server, "s2");
    let (task, conn, _rx) = previous.unwrap();
    conn.closed.cancel();
    task.await.unwrap();
    assert!(lock(&conn.pending).is_empty());
  })
  .await
  .unwrap();
}

#[tokio::test]
async fn rotated_agent_promotes_only_on_registration_and_updates_core_binding()
 {
  use crate::{core_node, db, key_rotation};
  let state = crate::rules::tests::test_state();
  state.db.call(|c| {
    c.execute(
      "INSERT INTO agents (server, public_key, next_public_key, next_key_expires_at)
       VALUES ('s1', 'old', 'new', ?1)", params![now_ms() + 60_000],
    ).map_err(sql_err)?;
    db::set_setting(c, core_node::SERVER_KEY, Some("s1"))?;
    db::set_setting(c, core_node::PUBKEY_KEY, Some("old"))?;
    assert!(key_rotation::accepts_agent(c, "s1", "old", true)?);
    assert!(key_rotation::accepts_agent(c, "s1", "new", true)?);
    assert!(!key_rotation::accepts_agent(c, "s1", "new", false)?);
    assert_eq!(core_node::load_persisted(c)?, Some(("s1".into(), "old".into())));
    key_rotation::register_agent_key(c, "s1", "new", true)?;
    assert!(key_rotation::accepts_agent(c, "s1", "new", true)?);
    assert!(!key_rotation::accepts_agent(c, "s1", "old", true)?);
    assert_eq!(core_node::load_persisted(c)?, Some(("s1".into(), "new".into())));
    assert!(c.query_row(
      "SELECT next_public_key IS NULL AND next_key_expires_at IS NULL FROM agents WHERE server = 's1'",
      [], |r| r.get::<_, bool>(0),
    ).map_err(sql_err)?);
    Ok(())
  }).await.unwrap();
}
