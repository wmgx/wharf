use serde_json::json;

use super::*;
use crate::rules::tests::{
  TEST_LOCK, notice_titles, reset_memory, test_state,
};

fn actor() -> Actor {
  Actor {
    name: "operator".into(),
    source: "203.0.113.8".into(),
  }
}

fn config_item(
  address: &str,
  before: serde_json::Value,
  after: serde_json::Value,
) -> PlanItem {
  PlanItem {
    id: 1,
    address: address.into(),
    action: Action::Update,
    layer: Layer::Config,
    before: Some(before),
    after: Some(after),
    impacts: vec![],
    reason: String::new(),
    changes: vec![],
    host_access: vec![],
  }
}

#[tokio::test]
async fn purged_service_has_receipt() {
  let _lock = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  completed_step(
    &state,
    Some(&actor()),
    &Step::ServiceDown {
      server: "s1".into(),
      service: "example".into(),
      purge_data: true,
    },
    &Ok(()),
  )
  .await;
  assert_eq!(
    notice_titles(&state, "security_receipt").await,
    ["删除 s1 上的服务 example 及其数据"]
  );
}

#[tokio::test]
async fn disabling_route_gate_has_receipt() {
  let _lock = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let item = config_item(
    "route/app.example.com",
    json!({"sso": {"mode": "login"}}),
    json!({"sso": {"mode": "login", "public": true}}),
  );
  committed_config(&state, Some(&actor()), &[item]).await;
  assert_eq!(
    notice_titles(&state, "security_receipt").await,
    ["关闭路由 app.example.com 的门禁"]
  );
}

#[tokio::test]
async fn enabling_host_exec_has_receipt() {
  let _lock = TEST_LOCK.lock().await;
  reset_memory();
  let state = test_state();
  let item =
    config_item("server/s1", json!({}), json!({"host_exec": true}));
  committed_config(&state, Some(&actor()), &[item]).await;
  assert_eq!(
    notice_titles(&state, "security_receipt").await,
    ["开启服务器 s1 的宿主机命令执行"]
  );
}

pub(crate) fn auth(human: bool) -> crate::auth::Auth {
  crate::auth::Auth {
    name: "operator".into(),
    perms: Perm::ALL.into_iter().collect(),
    expires_at: None,
    allowed_from: Vec::new(),
    services: None,
    human,
  }
}
