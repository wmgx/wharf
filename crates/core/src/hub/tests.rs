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
    runtime_v2,
    backfill,
    monitor_v2,
    task_artifacts,
    service_checks,
    ssh_logins,
    core_probe,
    gateway_extra_files,
    backup_isolation,
    safe_delete,
    named_networks_v1,
    compose_env_v1,
    safe_host_bind_v1,
    project_files_v1,
    data_cleanup,
    exec_v2,
    shared_volumes,
    safe_gateway,
    safe_adopt,
    safe_migrate,
    safe_backup,
    backup_move,
    backup_v2,
    build_v2,
    safe_rollback,
    key_rotation,
    gateway_probe,
    frpc_reload,
    ..
  } = hello
  else {
    panic!("不是 hello");
  };
  assert!(!host_shell);
  assert!(!runtime_v2);
  assert!(!backfill);
  assert!(!monitor_v2);
  assert!(!task_artifacts);
  assert!(!service_checks);
  assert!(!ssh_logins);
  assert!(!core_probe);
  assert!(!gateway_extra_files);
  assert!(!backup_isolation);
  assert!(!safe_delete);
  assert!(!named_networks_v1);
  assert!(!compose_env_v1);
  assert!(!safe_host_bind_v1);
  assert!(!project_files_v1);
  assert!(!data_cleanup);
  assert!(!exec_v2);
  assert!(!shared_volumes);
  assert!(!safe_gateway);
  assert!(!safe_adopt);
  assert!(!safe_migrate);
  assert!(!safe_backup);
  assert!(!backup_move);
  assert!(!backup_v2);
  assert!(!build_v2);
  assert!(!safe_rollback);
  assert!(!key_rotation);
  assert!(!gateway_probe && !frpc_reload);
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
    runtime_v2: false,
    monitor_v2: true,
    task_artifacts: true,
    backfill: false,
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
    named_networks_v1: true,
    compose_env_v1: true,
    safe_host_bind_v1: true,
    project_files_v1: true,
    data_cleanup: false,
    exec_v2: true,
    shared_volumes: true,
    safe_gateway: true,
    gateway_probe: false,
    frpc_reload: false,
    safe_adopt: false,
    safe_migrate: true,
    migrate_v2: false,
    data_ops: false,
    safe_backup: true,
    backup_move: false,
    backup_v2: false,
    build_v2: true,
    deploy_v2: false,
    safe_rollback: true,
    files_v2: true,
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

  pub(crate) fn enable_mock_container_diagnosis(&self, server: &str) {
    lock(&self.conns)
      .get_mut(server)
      .unwrap()
      .container_diagnosis = true;
  }

  pub(crate) fn enable_mock_host_shell(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().host_shell = true;
  }

  pub(crate) fn mock_backup_move_agent(
    &self,
    server: &str,
    handle: impl FnMut(
      AgentOp,
      Option<ProgressFn>,
    ) -> Option<Result<Value, ApiError>>
    + Send
    + 'static,
  ) {
    self
      .mock_agent_options(server, false, true, false, false, handle);
    let mut all = lock(&self.conns);
    let conn = all.get_mut(server).unwrap();
    conn.safe_backup = true;
    conn.backup_move = true;
  }

  pub(crate) fn enable_mock_backup_v2(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().backup_v2 = true;
  }

  pub(crate) fn mock_safe_backup_agent(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().safe_backup = true;
  }

  pub(crate) fn enable_mock_files_v2(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().files_v2 = true;
  }

  pub(crate) fn enable_mock_exec_v2(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().exec_v2 = true;
  }

  pub(crate) fn enable_mock_monitor_v2(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().monitor_v2 = true;
  }

  pub(crate) fn enable_mock_build_v2(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().build_v2 = true;
  }

  pub(crate) fn enable_mock_failover_features(&self, server: &str) {
    let mut conns = lock(&self.conns);
    let conn = conns.get_mut(server).unwrap();
    conn.gateway_probe = true;
    conn.frpc_reload = true;
  }

  pub(crate) fn mock_shared_volumes_agent(&self, server: &str) {
    lock(&self.conns).get_mut(server).unwrap().shared_volumes = true;
  }

  pub(crate) fn mock_safe_gateway_agent(
    &self,
    server: &str,
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent(server, false, handle);
    lock(&self.conns).get_mut(server).unwrap().safe_gateway = true;
  }

  pub(crate) fn mock_data_cleanup_agent(
    &self,
    server: &str,
    handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent(server, false, handle);
    lock(&self.conns).get_mut(server).unwrap().data_cleanup = true;
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

  pub(crate) fn mock_migrate_v2_agent(&self, server: &str) {
    self
      .mock_agent(server, false, |_| panic!("此测试无需 agent 调用"));
    lock(&self.conns).get_mut(server).unwrap().migrate_v2 = true;
  }

  pub(crate) fn mock_safe_migrate_agent(
    &self,
    server: &str,
    handle: impl FnMut(
      AgentOp,
      Option<ProgressFn>,
    ) -> Option<Result<Value, ApiError>>
    + Send
    + 'static,
  ) -> CancellationToken {
    self
      .mock_agent_options(server, false, false, false, false, handle);
    let mut conns = lock(&self.conns);
    let conn = conns.get_mut(server).unwrap();
    conn.safe_migrate = true;
    conn.closed.clone()
  }

  pub(crate) fn mock_agent_with_backup(
    &self,
    server: &str,
    gateway_extra_files: bool,
    backup_isolation: bool,
    core_probe: bool,
    mut handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent_options(
      server,
      gateway_extra_files,
      backup_isolation,
      core_probe,
      false,
      move |op, _| Some(handle(op)),
    );
  }

  pub(crate) fn mock_rotation_agent(
    &self,
    server: &str,
    mut handle: impl FnMut(AgentOp) -> Result<Value, ApiError>
    + Send
    + 'static,
  ) {
    self.mock_agent_options(
      server,
      false,
      false,
      false,
      true,
      move |op, _| Some(handle(op)),
    );
  }

  fn mock_agent_options(
    &self,
    server: &str,
    gateway_extra_files: bool,
    backup_isolation: bool,
    core_probe: bool,
    key_rotation: bool,
    mut handle: impl FnMut(
      AgentOp,
      Option<ProgressFn>,
    ) -> Option<Result<Value, ApiError>>
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
        runtime_v2: false,
        monitor_v2: false,
        task_artifacts: false,
        backfill: false,
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
        named_networks_v1: false,
        compose_env_v1: false,
        safe_host_bind_v1: false,
        project_files_v1: false,
        data_cleanup: false,
        exec_v2: false,
        shared_volumes: false,
        safe_gateway: false,
        gateway_probe: false,
        frpc_reload: false,
        safe_adopt: false,
        safe_migrate: false,
        migrate_v2: false,
        data_ops: false,
        safe_backup: false,
        backup_move: false,
        backup_v2: false,
        build_v2: false,
        deploy_v2: false,
        safe_rollback: false,
        files_v2: false,
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
        if let CoreMsg::Request { id, op, .. } = msg {
          let progress =
            lock(&pending).get(&id).map(|p| p.progress.clone());
          if let Some(progress) = progress
            && let Some(result) = handle(op, progress)
            && let Some(p) = lock(&pending).remove(&id)
          {
            let _ = p.done.send(result);
          }
        }
      }
    });
  }
}

#[tokio::test]
async fn dispatched_cleanup_releases_apply_lock_and_sends_cancel() {
  let state = crate::rules::tests::test_state();
  state.hub.mock_safe_delete_agent("s1", |_| unreachable!());
  let (tx, mut rx) = mpsc::channel(4);
  lock(&state.hub.conns).get_mut("s1").unwrap().tx = tx;
  let guard = state
    .locks
    .acquire(
      crate::locks::LockSpec::apply(["s1".into(), "app".into()]),
      "测试",
    )
    .unwrap();
  let cancel = CancellationToken::new();
  let job = tokio::spawn({
    let state = state.clone();
    let cancel = cancel.clone();
    async move {
      state
        .hub
        .dispatch_cleanup(
          "s1",
          "s1",
          Arc::new(|_| {}),
          &cancel,
          guard,
        )
        .await
    }
  });
  let Some(CoreMsg::Request {
    id,
    op: AgentOp::RemoveData { .. },
    ..
  }) = rx.recv().await
  else {
    panic!("应发送清理请求");
  };
  assert!(
    state
      .locks
      .acquire(crate::locks::LockSpec::apply([]), "测试")
      .is_ok()
  );
  cancel.cancel();
  assert!(
    matches!(rx.recv().await, Some(CoreMsg::Cancel { id: cancelled }) if cancelled == id)
  );
  assert_eq!(
    job.await.unwrap().unwrap_err().code,
    ErrorCode::Cancelled
  );
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
    runtime_v2: false,
    monitor_v2: false,
    task_artifacts: false,
    backfill: false,
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
    named_networks_v1: false,
    compose_env_v1: false,
    safe_host_bind_v1: false,
    project_files_v1: false,
    data_cleanup: false,
    exec_v2: false,
    shared_volumes: false,
    safe_gateway: false,
    gateway_probe: false,
    frpc_reload: false,
    safe_adopt: false,
    safe_migrate: false,
    migrate_v2: false,
    data_ops: false,
    safe_backup: false,
    backup_move: false,
    backup_v2: false,
    build_v2: false,
    deploy_v2: false,
    safe_rollback: false,
    files_v2: false,
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
    runtime_v2: false,
    monitor_v2: false,
    task_artifacts: false,
    backfill: false,
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
    named_networks_v1: false,
    compose_env_v1: false,
    safe_host_bind_v1: false,
    project_files_v1: false,
    data_cleanup: false,
    exec_v2: false,
    shared_volumes: false,
    safe_gateway: false,
    gateway_probe: false,
    frpc_reload: false,
    safe_adopt: false,
    safe_migrate: false,
    migrate_v2: false,
    data_ops: false,
    safe_backup: false,
    backup_move: false,
    backup_v2: false,
    build_v2: false,
    deploy_v2: false,
    safe_rollback: false,
    files_v2: false,
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

#[tokio::test]
async fn old_agent_rejects_import_and_adoption_dispatch() {
  let hub = Hub::default();
  hub.mock_safe_delete_agent("s1", |_| {
    panic!("旧 agent 不应收到接管请求")
  });
  let target = wharf_api_types::agent::ImportTarget {
    project: None,
    container: Some("app".into()),
  };
  let up = serde_json::from_value(serde_json::json!({
    "project": "app", "compose": "", "hash": "", "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 10},
    "pull_missing_only": true
  })).unwrap();
  for op in [AgentOp::ImportRead(target), AgentOp::ProjectUp(up)] {
    let error = hub
      .call::<Value>(
        "s1",
        op,
        Duration::from_secs(1),
        None,
        &CancellationToken::new(),
      )
      .await
      .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.suggest, ["wharf upgrade"]);
  }
}

#[tokio::test]
async fn init_cmd_blocked_on_old_agent() {
  let hub = Hub::default();
  let (conn, mut rx) = probe_connection(1, "s1");
  hub.register("s1", conn);
  let op: AgentOp = serde_json::from_value(serde_json::json!({
    "op": "project_up", "project": "a", "compose": "services: {}", "hash": "h",
    "pull": {"mirrors": {}, "mirrors_only": false, "attempt_timeout_secs": 1},
    "init": {"service": "a", "command": "true"}
  })).unwrap();
  let error = hub
    .call::<Value>(
      "s1",
      op,
      Duration::from_secs(1),
      None,
      &CancellationToken::new(),
    )
    .await
    .unwrap_err();
  assert_eq!(error.code, ErrorCode::Conflict);
  assert_eq!(
    error.hint.as_deref(),
    Some("先运行 wharf upgrade 升级 agent 后重试")
  );
  assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn slow_report_db_does_not_block_progress_and_response() {
  let state = crate::rules::tests::test_state();
  let (conn, _rx) = probe_connection(1, "s1");
  let reports = Arc::new(ReportSlot::default());
  let (entered, started) = oneshot::channel();
  let (unlock, ready) = std::sync::mpsc::channel();
  let db = state.db.clone();
  let locked = tokio::spawn(async move {
    db.call(move |_| {
      let _ = entered.send(());
      let _ = ready.recv();
      Ok(())
    })
    .await
    .unwrap();
  });
  started.await.unwrap();
  let worker = tokio::spawn(report_worker(
    state,
    "s1".into(),
    conn.clone(),
    reports.clone(),
  ));
  reports.push(1, AgentReport::default());
  tokio::task::yield_now().await;
  reports.push(2, AgentReport::default());
  reports.push(3, AgentReport::default());
  assert_eq!(lock(&reports.latest).as_ref().unwrap().0, 3);
  let (done, response) = oneshot::channel();
  let (tx, mut lines) = mpsc::channel(1);
  lock(&conn.pending).insert(
    1,
    Pending {
      done,
      progress: Some(Arc::new(move |line| {
        tx.try_send(line).unwrap();
      })),
    },
  );
  conn.deliver_reply(AgentMsg::Progress {
    id: 1,
    line: "build".into(),
  });
  conn.deliver_reply(AgentMsg::Response {
    id: 1,
    result: Ok(Value::Null),
  });
  assert_eq!(lines.try_recv().unwrap(), "build");
  assert_eq!(response.await.unwrap().unwrap(), Value::Null);
  conn.closed.cancel();
  unlock.send(()).unwrap();
  worker.await.unwrap();
  locked.await.unwrap();
}

#[tokio::test]
async fn backfill_ingests_without_clock_skew_and_rejects_duplicate_or_foreign_samples()
 {
  let _guard = crate::rules::tests::TEST_LOCK.lock().await;
  crate::rules::tests::reset_memory();
  let state = crate::rules::tests::test_state();
  let now = now_ms();
  state.db.call(move |c| {
    c.execute("INSERT INTO agents (server, public_key) VALUES ('s1', 'fixture')", []).map_err(sql_err)?;
    c.execute("INSERT INTO points (name, subject, at, value) VALUES ('host.net_rx', 's1', ?1, 10)", [now - 6 * 60_000]).map_err(sql_err)?;
    for (kind, name, spec) in [
      ("server", "s1", serde_json::json!({})),
      ("server", "s2", serde_json::json!({})),
      ("service", "app", serde_json::json!({"server":"s1","source":{"image":"app:1"}})),
      ("service", "foreign", serde_json::json!({"server":"s2","source":{"image":"app:1"}})),
    ] {
      crate::db::apply_write(c, &crate::db::Write::Upsert { kind: kind.into(), name: name.into(), spec, meta: serde_json::json!({}) })?;
    }
    c.execute(
      "INSERT INTO deployments (service,server,run_id,hash,compose,images,created_at,instance_id) SELECT 'app','s1','fixture','fixture','','[]',?1,json_extract(meta,'$.instance_id') FROM resources WHERE kind='service' AND name='app'",
      [now - 7 * 60_000],
    ).map_err(sql_err)?;
    Ok(())
  }).await.unwrap();
  let alerts = crate::rules::resources::ReportQueue::default();
  let samples: Vec<_> = [
    25 * 60_000,
    0,
    -25_000,
    60_000,
    120_000,
    180_000,
    240_000,
    300_000,
  ]
  .into_iter()
  .map(|age| BufferedSample {
    at_ms: now - age,
    log_hits: vec![],
    metrics: Some(wharf_api_types::agent::Metrics {
      net_rx: 10,
      projects: std::collections::BTreeMap::from([
        ("app".into(), Default::default()),
        ("foreign".into(), Default::default()),
      ]),
      oom: (age == 300_000)
        .then(|| vec!["app".into(), "foreign".into()]),
      ..Default::default()
    }),
  })
  .collect();
  assert_eq!(
    ingest_backfill(
      &state,
      "s1",
      "fixture",
      now,
      samples.clone(),
      &alerts
    )
    .await
    .unwrap(),
    5
  );
  assert_eq!(
    ingest_backfill(&state, "s1", "fixture", now, samples, &alerts)
      .await
      .unwrap(),
    0
  );
  state.db.call(move |c| {
    let entry: (i64, i64, f64) = c.query_row(
      "SELECT COUNT(*), MAX(at), (SELECT SUM(value) FROM points WHERE name = 'traffic.rx')
       FROM points WHERE name = 'host.net_rx' AND subject = 's1'", [],
      |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).map_err(sql_err)?;
    assert_eq!(entry, (6, now - 60_000, 3_000.0));
    let (subject, at): (String, i64) = c.query_row(
      "SELECT subject, at FROM points WHERE name = 'oom.kill'", [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(sql_err)?;
    assert_eq!((subject.as_str(), at), ("app", now - 5 * 60_000));
    let subjects: String = c.query_row(
      "SELECT group_concat(DISTINCT subject) FROM points WHERE name = 'svc.cpu'", [], |r| r.get(0),
    ).map_err(sql_err)?;
    assert_eq!(subjects, "app");
    let stored: Option<String> = c.query_row("SELECT report FROM agents WHERE server = 's1'", [], |r| r.get(0)).map_err(sql_err)?;
    assert!(stored.is_none());
    Ok(())
  }).await.unwrap();
  assert!(crate::rules::firing_subjects("clock_skew").is_empty());
}

#[tokio::test]
async fn backup_move_blocks_old_agent_and_keeps_service_sync_compat()
{
  use wharf_api_types::agent::{
    OneTimeSecret, ResticAction, ResticJob, ResticRepo, SyncKind,
    SyncPass, SyncPush, SyncServe,
  };
  let hub = Hub::default();
  hub.mock_agent("s1", false, |_| panic!("旧 agent 不应收到新操作"));
  let serve = SyncServe {
    service: "app".into(),
    bind: "100.64.0.1".into(),
    allow: "100.64.0.2".into(),
    password: OneTimeSecret(String::new()),
    preserve_existing: false,
    require_empty: false,
    kind: SyncKind::ServiceData,
  };
  let serialized = serde_json::to_value(&serve).unwrap();
  assert!(
    serialized.get("kind").is_none()
      && serialized.get("require_empty").is_none()
  );
  let cancel = CancellationToken::new();
  for op in [
    AgentOp::SyncServe(SyncServe {
      kind: SyncKind::BackupRepo,
      ..serve
    }),
    AgentOp::SyncPush(SyncPush {
      service: "wharf-core".into(),
      host: "100.64.0.2".into(),
      port: 1000,
      password: OneTimeSecret(String::new()),
      pass: SyncPass::Final,
      kind: SyncKind::CoreBackupRepo,
      bwlimit_kbps: None,
    }),
    AgentOp::Restic(ResticJob {
      service: "wharf-core".into(),
      core_marker: None,
      repo: ResticRepo::LocalCore,
      password: OneTimeSecret(String::new()),
      action: ResticAction::Snapshots,
      bwlimit_kbps: None,
      pull: wharf_api_types::agent::PullPolicy {
        mirrors: Default::default(),
        mirrors_only: false,
        attempt_timeout_secs: 10,
        git_proxy: None,
        github_mirror: None,
        registry_proxy: None,
      },
    }),
  ] {
    let error = hub
      .call::<Value>("s1", op, Duration::from_secs(1), None, &cancel)
      .await
      .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.suggest, ["wharf upgrade"]);
  }
}
