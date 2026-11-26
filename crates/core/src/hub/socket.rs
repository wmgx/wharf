use super::*;

pub async fn agent_ws(
  State(state): State<Arc<AppState>>,
  ws: WebSocketUpgrade,
) -> Response {
  ws.max_message_size(crate::report_guard::MAX_WS_MESSAGE_BYTES)
    .on_upgrade(move |socket| async move {
      if let Err(e) = handle_socket(state, socket).await {
        tracing::warn!("agent 连接结束：{e}");
      }
    })
}

fn random_nonce() -> String {
  let mut bytes = [0u8; 24];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

fn decode_key(hex_key: &str) -> Option<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
  VerifyingKey::from_bytes(&bytes).ok()
}

fn decode_sig(hex_sig: &str) -> Option<Signature> {
  let bytes: [u8; 64] = hex::decode(hex_sig).ok()?.try_into().ok()?;
  Some(Signature::from_bytes(&bytes))
}

async fn recv_text(socket: &mut WebSocket) -> anyhow::Result<String> {
  loop {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
      .await
      .map_err(|_| anyhow::anyhow!("握手超时"))?
      .ok_or_else(|| anyhow::anyhow!("连接关闭"))??;
    match msg {
      Message::Text(text) => return Ok(text.to_string()),
      Message::Close(_) => anyhow::bail!("连接关闭"),
      _ => continue,
    }
  }
}

async fn send_msg(
  socket: &mut WebSocket,
  msg: &CoreMsg,
) -> anyhow::Result<()> {
  tokio::time::timeout(
    SOCKET_WRITE_TIMEOUT,
    socket.send(Message::text(serde_json::to_string(msg)?)),
  )
  .await
  .map_err(|_| anyhow::anyhow!("发送 WebSocket 消息超时"))??;
  Ok(())
}

/// 协议版本是否兼容。旧 agent（含不发这个字段的 0）只能明文连接，只接受升级请求。
pub(super) fn protocol_ok(agent: u32) -> bool {
  agent == PROTOCOL
}

/// 握手之后的收发：新 agent 全部加密；旧 agent 明文，只用于下发升级。
enum Wire {
  Plain,
  Sealed(Sealer, Opener),
}

impl Wire {
  fn encode(&mut self, msg: &CoreMsg) -> anyhow::Result<Message> {
    let text = serde_json::to_string(msg)?;
    Ok(match self {
      Wire::Plain => Message::text(text),
      Wire::Sealed(tx, _) => {
        Message::binary(tx.seal(text.as_bytes()))
      }
    })
  }

  /// `Ok(None)`：不是这种通道该收的帧，忽略。解密失败返回错误，调用方断开。
  fn decode(
    &mut self,
    msg: Message,
  ) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(match (self, msg) {
      (Wire::Plain, Message::Text(t)) => Some(t.as_bytes().to_vec()),
      (Wire::Sealed(_, rx), Message::Binary(b)) => Some(rx.open(&b)?),
      _ => None,
    })
  }
}

async fn handle_socket(
  state: Arc<AppState>,
  mut socket: WebSocket,
) -> anyhow::Result<()> {
  let nonce = random_nonce();
  send_msg(
    &mut socket,
    &CoreMsg::Challenge {
      nonce: nonce.clone(),
    },
  )
  .await?;
  let hello: AgentMsg =
    serde_json::from_str(&recv_text(&mut socket).await?)?;
  let AgentMsg::Hello {
    server,
    public_key,
    signature,
    nonce: agent_nonce,
    kx: agent_kx,
    version,
    protocol,
    host_shell,
    forward,
    service_checks,
    container_diagnosis,
    access_logs,
    net_probe,
    container_probe,
    ssh_logins,
    core_probe,
  } = hello
  else {
    anyhow::bail!("agent 没有先发 hello");
  };
  // 协议不一致也放行（认证照做），只接受升级请求，否则 agent 永远收不到升级指令。
  // 协议版本对但没交换密钥：不是正常 agent，拒绝。
  if protocol_ok(protocol) && agent_kx.is_none() {
    anyhow::bail!("服务器 {server} 的 agent 没有交换会话密钥");
  }
  let upgrade_only = !protocol_ok(protocol) || agent_kx.is_none();
  if upgrade_only {
    tracing::warn!(
      "服务器 {server} 的 agent 协议版本 {protocol}，控制面要求 {PROTOCOL}：只接受升级请求，请运行 wharf upgrade"
    );
  }
  let registered = {
    let server = server.clone();
    state
      .db
      .call(move |c| crate::db::agent(c, &server))
      .await
      .map_err(|e| anyhow::anyhow!("{e}"))?
      .and_then(|a| a.public_key)
  };
  let verified = registered.as_deref() == Some(public_key.as_str())
    && decode_key(&public_key)
      .zip(decode_sig(&signature))
      .is_some_and(|(key, sig)| {
        key
          .verify(
            &match &agent_kx {
              Some(kx) => {
                auth_payload_v2("agent", &server, &nonce, kx)
              }
              None => auth_payload("agent", &server, &nonce),
            },
            &sig,
          )
          .is_ok()
      });
  if !verified {
    let _ = tokio::time::timeout(
      SOCKET_WRITE_TIMEOUT,
      socket.send(Message::Close(Some(axum::extract::ws::CloseFrame {
        code: 4001,
        reason: "认证失败：服务器未加入或密钥不匹配，请重新 wharf server add".into(),
      }))),
    )
    .await;
    anyhow::bail!("服务器 {server} 认证失败");
  }
  let (welcome, mut wire) = match &agent_kx {
    Some(akx) => {
      let share = KeyShare::generate();
      let kx = share.public.clone();
      let sig = state.key.sign(&auth_payload_v2(
        "core",
        &server,
        &agent_nonce,
        &format!("{kx},{akx}"),
      ));
      let (tx, rx) = share
        .finish(akx, &format!("{nonce}{agent_nonce}"), Role::Core)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
      (
        CoreMsg::Welcome {
          signature: hex::encode(sig.to_bytes()),
          kx: Some(kx),
        },
        Wire::Sealed(tx, rx),
      )
    }
    None => {
      let sig =
        state.key.sign(&auth_payload("core", &server, &agent_nonce));
      (
        CoreMsg::Welcome {
          signature: hex::encode(sig.to_bytes()),
          kx: None,
        },
        Wire::Plain,
      )
    }
  };
  send_msg(&mut socket, &welcome).await?;

  let (tx, mut rx) = mpsc::channel(4096);
  let conn = Conn {
    conn_id: state.hub.next_conn.fetch_add(1, Ordering::Relaxed),
    public_key,
    core_probe: core_probe && !upgrade_only,
    tx,
    pending: Default::default(),
    closed: CancellationToken::new(),
    rtt_ms: Arc::new(AtomicU64::new(u64::MAX)),
    host_shell,
    forward,
    service_checks,
    container_diagnosis,
    access_logs,
    net_probe,
    container_probe,
    ssh_logins,
    upgrade_only,
  };
  let state_on_db = state.clone();
  let socket_server = server.clone();
  let socket_conn = conn.clone();
  state
    .db
    .call(move |c| {
      if !crate::db::agent(c, &socket_server)?.is_some_and(|a| {
        a.public_key.as_ref() == Some(&socket_conn.public_key)
      }) {
        return Err(ApiError::new(
          ErrorCode::Unauthorized,
          "agent 注册公钥已变更",
        ));
      }
      state_on_db.hub.register(&socket_server, socket_conn);
      Ok(())
    })
    .await?;
  if conn.core_probe {
    crate::core_node::spawn_probe_on_connect(
      state.clone(),
      server.clone(),
    );
  }
  tracing::info!("服务器 {server} 上线（agent {version}）");
  let seen = server.clone();
  state
    .db
    .call(move |c| {
      c.execute(
        "UPDATE agents SET last_seen = ?1 WHERE server = ?2",
        params![now_ms(), seen],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  crate::service_monitor::sync_watches(&state, Some(&server)).await;

  let (mut sink, mut stream) = socket.split();
  let mut ping = tokio::time::interval(PING_EVERY);
  let mut last_recv = tokio::time::Instant::now();
  let mut ping_sent: Option<tokio::time::Instant> = None;
  let mut agent_memory = None;
  let alerts = crate::rules::resources::report_queue(
    state.clone(),
    server.clone(),
    conn.closed.clone(),
  );
  let result: anyhow::Result<()> = loop {
    tokio::select! {
      biased;
      _ = conn.closed.cancelled() => break Ok(()),
      out = rx.recv() => {
        let Some(out) = out else { break Ok(()) };
        match tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(wire.encode(&out)?)).await {
          Ok(Ok(())) => {}
          Ok(Err(e)) => break Err(e.into()),
          Err(_) => break Err(anyhow::anyhow!("发送 WebSocket 消息超时")),
        }
      }
      _ = ping.tick() => {
        // agent 每 30 秒上报一次，再加上 pong，正常连接不会这么久没消息。
        if last_recv.elapsed() > IDLE_TIMEOUT {
          break Err(anyhow::anyhow!("{} 秒没有收到消息", IDLE_TIMEOUT.as_secs()));
        }
        match tokio::time::timeout(SOCKET_WRITE_TIMEOUT, sink.send(Message::Ping(Default::default()))).await {
          Ok(Ok(())) => {}
          Ok(Err(e)) => break Err(e.into()),
          Err(_) => break Err(anyhow::anyhow!("发送 WebSocket ping 超时")),
        }
        ping_sent = Some(tokio::time::Instant::now());
      }
      incoming = stream.next() => {
        let msg = match incoming {
          None => break Ok(()),
          Some(Err(e)) => break Err(e.into()),
          Some(Ok(msg)) => msg,
        };
        last_recv = tokio::time::Instant::now();
        let text = match msg {
          Message::Close(_) => break Ok(()),
          Message::Pong(_) => {
            if let Some(sent) = ping_sent.take() {
              conn.rtt_ms.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            continue;
          }
          msg => match wire.decode(msg) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(e) => break Err(e),
          },
        };
        match serde_json::from_slice::<AgentMsg>(&text) {
          Ok(AgentMsg::Report(mut report)) => {
            use crate::report_guard::RateDecision::*;
            match state.hub.report_rate.check(&server, conn.conn_id, report.metrics.is_some(), std::time::Instant::now()) {
              DropAll => continue,
              AcceptNoMetrics => report.metrics = None,
              AcceptAll => {}
            }
            let mut report = match crate::report_guard::record_report(&state.db, &server, &conn.public_key, *report).await {
              Ok(report) if !conn.closed.is_cancelled() => report,
              Ok(_) => continue,
              Err(e) => {
                tracing::warn!("校验服务器 {server} 上报失败：{e}");
                continue;
              }
            };
            crate::service_monitor::report(&server, std::mem::take(&mut report.log_hits));
            let received = now_ms();
            let agent_ms = report.time_ms;
            crate::clock::record(&state, &server, agent_ms).await;
            let settings = crate::rules::resources::settings(&state, &server).await;
            if !conn.upgrade_only && let Some(bytes) = settings.as_ref().map(|s| s.0)
              && agent_memory != Some(bytes)
              && conn.tx.try_send(CoreMsg::AgentMemory { bytes }).is_ok()
            {
              agent_memory = Some(bytes);
            }
            if let Some(m) = report.metrics.as_mut() {
              let oom = m.oom.take();
              let hosts = std::mem::take(&mut m.hosts);
              if !hosts.is_empty() {
                tokio::spawn(crate::http_stats::record(state.clone(), server.clone(), hosts));
              }
              crate::metrics::record_report(&state, &server, m).await;
              if let Some((wanted, limits)) = settings {
                let limit = report.agent_memory.as_ref().and_then(|m| m.limit).filter(|_| wanted > 0);
                let _ = alerts.try_send((received, m.as_ref().clone(), limits, limit));
              }
              let state = state.clone();
              let server = server.clone();
              tokio::spawn(async move {
                crate::oom::record(&state, &server, oom).await;
              });
            }
          }
          Ok(AgentMsg::Progress { id, line }) => {
            let progress = lock(&conn.pending).get(&id).and_then(|p| p.progress.clone());
            if let Some(progress) = progress {
              progress(line);
            }
          }
          Ok(AgentMsg::Response { id, result }) => {
            if let Some(pending) = lock(&conn.pending).remove(&id) {
              let _ = pending.done.send(result);
            }
          }
          Ok(AgentMsg::Hello { .. }) => {}
          Err(e) => tracing::debug!("无法解析 {server} 的消息：{:?}", e.classify()),
        }
      }
    }
  };
  conn.closed.cancel();
  state.hub.unregister(&server, &conn);
  tracing::info!("服务器 {server} 离线");
  result
}
