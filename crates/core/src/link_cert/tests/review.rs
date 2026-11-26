use super::*;

async fn store_leaf(state: &AppState, issued_at: i64) {
  state
    .db
    .call_credentials(move |c, key| {
      let tx = c.transaction().map_err(db::sql_err)?;
      ensure_gateway_cert(&tx, key, "gw-a", issued_at, false)?;
      tx.commit().map_err(db::sql_err)
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn offline_gateway_blocks_gateway_sync_but_allows_frpc_recovery()
 {
  let state = crate::rules::tests::test_state();
  let service = fake_agent(&state, "s3", true);
  seed(&state, world(false)).await;
  store_leaf(&state, db::now_ms()).await;

  let sync = Step::GatewaySync {
    gateway: "gw-a".into(),
    expect: None,
  };
  let err = apply::run_step(
    &state,
    "r1",
    &sync,
    Arc::new(|_| {}),
    &Default::default(),
  )
  .await
  .unwrap_err();
  assert_eq!(err.code, ErrorCode::AgentOffline);

  let recover = Step::LinkUp {
    server: "s3".into(),
    project: link::client_project("s1"),
  };
  apply::run_step(
    &state,
    "r1",
    &recover,
    Arc::new(|_| {}),
    &Default::default(),
  )
  .await
  .unwrap();
  assert!(
    service.lock().unwrap()[&link::client_project("s1")]
      .all_running()
  );
}

async fn leaf_alert_persisted(state: &AppState) -> bool {
  state.db.call(|c| {
    c.query_row(
      "SELECT EXISTS(SELECT 1 FROM alert_firing WHERE rule = 'link_cert_expiring' AND subject = 'gw-a')",
      [],
      |r| r.get(0),
    )
    .map_err(db::sql_err)
  }).await.unwrap()
}

#[tokio::test]
async fn leaf_alert_is_cleared_when_gateway_stops_carrying_tunnels() {
  let _lock = crate::rules::tests::TEST_LOCK.lock().await;
  crate::rules::tests::reset_memory();
  let state = crate::rules::tests::test_state();
  seed(&state, world(false)).await;
  let issued_at = (Utc::now() - Duration::days(LEAF_TTL_DAYS - 20))
    .timestamp_millis();
  store_leaf(&state, issued_at).await;
  let mut snap = snapshot::load(&state.db).await.unwrap();
  crate::alerts::observe_link_certificates(&state, &snap).await;
  assert!(leaf_alert_persisted(&state).await);

  snap.world.routes.clear();
  crate::alerts::observe_link_certificates(&state, &snap).await;
  assert!(!leaf_alert_persisted(&state).await);
  assert!(
    crate::rules::firing_subjects("link_cert_expiring").is_empty()
  );
  crate::rules::tests::reset_memory();
}
