//! 用同机文件证明确定可以接收控制面敏感操作的 agent。

use std::{
  io::Write,
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::PathBuf,
  sync::Arc,
  time::Duration,
};

use rusqlite::Connection;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, CoreHostProbe, CoreHostProbeResult, container_id,
  },
};

use crate::{
  db, hub::ProgressFn, snapshot::Snapshot, state::AppState,
};

pub const SERVER_KEY: &str = "core.server";
pub const PUBKEY_KEY: &str = "core.server_key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCore {
  pub server: String,
  pub public_key: String,
  pub container_id: Option<String>,
  conn_id: u64,
}

impl VerifiedCore {
  /// 证明绑定到这条连接，替换连接后必须重新证明。
  pub async fn call<T: serde::de::DeserializeOwned>(
    &self,
    state: &AppState,
    op: AgentOp,
    timeout: Duration,
    progress: Option<ProgressFn>,
    cancel: &CancellationToken,
  ) -> Result<T, ApiError> {
    state
      .hub
      .call_bound(
        (&self.server, self.conn_id),
        op,
        timeout,
        progress,
        cancel,
      )
      .await
  }
}

static VERIFY: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());
pub fn server_of(snap: &Snapshot) -> Option<String> {
  snap
    .core_server
    .clone()
    .filter(|server| snap.world.servers.contains_key(server))
}

pub fn load_persisted(
  c: &Connection,
) -> Result<Option<(String, String)>, ApiError> {
  Ok(db::setting(c, SERVER_KEY)?.zip(db::setting(c, PUBKEY_KEY)?))
}

pub fn clear_if_server(
  c: &Connection,
  server: &str,
) -> Result<(), ApiError> {
  if db::setting(c, SERVER_KEY)?.as_deref() == Some(server) {
    db::set_setting(c, SERVER_KEY, None)?;
    db::set_setting(c, PUBKEY_KEY, None)?;
  }
  Ok(())
}

/// 后台只探本次连接，断开时丢弃任务，不进入前台扫描的等待队列。
pub fn spawn_probe_on_connect(
  state: Arc<AppState>,
  server: String,
  conn_id: u64,
  closed: CancellationToken,
) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    let persisted = tokio::select! {
      biased;
      _ = closed.cancelled() => return,
      result = state.db.call(|c| load_persisted(c)) => result,
    };
    let result = match persisted {
      Ok(binding) => {
        probe_one(
          &state,
          &server,
          Some(conn_id),
          binding.as_ref(),
          true,
          &closed,
        )
        .await
      }
      Err(e) => Err(e),
    };
    if let Err(e) = result {
      tracing::debug!(
        "服务器 {server} 的上线校验未完成：{:?}",
        e.code
      );
    }
  })
}

pub async fn require_verified(
  state: &AppState,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  require_verified_with(state, true, cancel).await
}

pub(crate) async fn require_verified_readonly(
  state: &AppState,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  require_verified_with(state, false, cancel).await
}

async fn require_verified_with(
  state: &AppState,
  persist: bool,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  let _guard = tokio::select! {
    biased;
    _ = cancel.cancelled() => return Err(cancelled()),
    guard = VERIFY.lock() => guard,
  };
  find_verified(state, persist, cancel).await
}

async fn find_verified(
  state: &AppState,
  persist: bool,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  let persisted = state.db.call(|c| load_persisted(c)).await?;
  let (mut candidates, legacy) = state.hub.core_probe_servers();
  candidates.sort_unstable_by_key(|name| {
    persisted.as_ref().is_none_or(|p| &p.0 != name)
  });
  for server in candidates {
    if cancel.is_cancelled() {
      return Err(cancelled());
    }
    match probe_one(
      state,
      &server,
      None,
      persisted.as_ref(),
      persist,
      cancel,
    )
    .await
    {
      Ok(Some(verified)) => return Ok(verified),
      Ok(None) => {}
      Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
      Err(e) => tracing::debug!(
        "服务器 {server} 的控制面同机校验未完成：{:?}",
        e.code
      ),
    }
  }
  if legacy {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "找不到已完成可信校验的控制面所在节点（存在未升级的旧版 agent）",
    ).with_hint("先运行 wharf server upgrade --all 升级 agent，再重试"));
  }
  Err(ApiError::not_found("找不到和控制面在同一台机器上的在线 agent")
    .with_hint("确认控制面所在机器的 wharf-agent 在运行、已加入控制面，且数据目录挂载一致"))
}

async fn probe_one(
  state: &AppState,
  server: &str,
  expected_conn: Option<u64>,
  persisted: Option<&(String, String)>,
  persist: bool,
  cancel: &CancellationToken,
) -> Result<Option<VerifiedCore>, ApiError> {
  let Some((conn_id, public_key)) =
    state.hub.core_probe_identity(server)
  else {
    return Ok(None);
  };
  if expected_conn.is_some_and(|expected| conn_id != expected) {
    return Ok(None);
  }
  let container_id = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| container_id(&m));
  let challenge_id = random()?;
  let expected = random()?;
  let dir = state.data_dir.join(".core-probe");
  let mut builder = std::fs::DirBuilder::new();
  builder.mode(0o700);
  match builder.create(&dir) {
    Ok(()) => {}
    Err(e)
      if e.kind() == std::io::ErrorKind::AlreadyExists
        && dir.symlink_metadata().is_ok_and(|m| m.is_dir()) => {}
    Err(e) => return Err(probe_io(e)),
  }
  let path = dir.join(&challenge_id);
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(&path)
    .map_err(probe_io)?;
  let challenge = Challenge(path);
  file.write_all(expected.as_bytes()).map_err(probe_io)?;
  drop(file);

  let data_dir = state.data_dir.canonicalize().map_err(probe_io)?;
  let verified = VerifiedCore {
    server: server.to_string(),
    public_key,
    container_id,
    conn_id,
  };
  let probe = AgentOp::ProbeCoreHost(CoreHostProbe {
    challenge_id,
    data_dir: data_dir
      .to_str()
      .ok_or_else(|| ApiError::invalid("数据目录路径不合法"))?
      .to_string(),
    container_id: verified.container_id.clone(),
  });
  let response = tokio::select! {
    biased;
    _ = cancel.cancelled() => return Err(cancelled()),
    response = verified.call(state, probe, Duration::from_secs(25), None, cancel) => response,
  };
  drop(challenge);
  if state.hub.core_probe_identity(server).as_ref()
    != Some(&(conn_id, verified.public_key.clone()))
  {
    return Ok(None);
  }
  if persist {
    return finish_probe(
      state, verified, persisted, &expected, response,
    )
    .await;
  }
  match response {
    Ok(result) => Ok(
      valid_response(&expected, result.token.trim())
        .then_some(verified),
    ),
    Err(e) if e.code == ErrorCode::NotFound => Ok(None),
    Err(e) => Err(e),
  }
}

async fn finish_probe(
  state: &AppState,
  node: VerifiedCore,
  persisted: Option<&(String, String)>,
  expected: &str,
  response: Result<CoreHostProbeResult, ApiError>,
) -> Result<Option<VerifiedCore>, ApiError> {
  match response {
    Ok(result) if valid_response(expected, result.token.trim()) => {
      let candidate = node.clone();
      if !state
        .db
        .call(move |c| store_verified(c, &candidate))
        .await?
      {
        return Ok(None);
      }
      refresh_proxy_cache(state).await;
      return Ok(Some(node));
    }
    Ok(_) => {
      tracing::warn!(
        "服务器 {} 的控制面同机校验应答无效",
        node.server
      );
    }
    Err(e) if e.code == ErrorCode::NotFound => {}
    Err(e) => return Err(e),
  }
  if let Some(binding) = persisted
    .filter(|(server, key)| {
      server == &node.server && key == &node.public_key
    })
    .cloned()
    && state
      .db
      .call(move |c| clear_if_unchanged(c, &binding))
      .await?
  {
    refresh_proxy_cache(state).await;
  }
  Ok(None)
}

async fn refresh_proxy_cache(state: &AppState) {
  match crate::snapshot::load_inner(&state.db).await {
    Ok(snap) => crate::source_trust::refresh_core_proxies(
      &snap.world,
      &snap.net(&snap.world),
    ),
    Err(e) => tracing::warn!("刷新控制面可信来源失败：{e}"),
  }
}

fn clear_if_unchanged(
  c: &mut Connection,
  binding: &(String, String),
) -> Result<bool, ApiError> {
  let tx = c.transaction().map_err(db::sql_err)?;
  if load_persisted(&tx)?.as_ref() != Some(binding) {
    return Ok(false);
  }
  clear_if_server(&tx, &binding.0)?;
  tx.commit().map_err(db::sql_err)?;
  Ok(true)
}

fn valid_response(expected: &str, response: &str) -> bool {
  expected.len() == response.len()
    && expected
      .bytes()
      .zip(response.bytes())
      .fold(0, |acc, (a, b)| acc | (a ^ b))
      == 0
}

fn store_verified(
  c: &mut Connection,
  node: &VerifiedCore,
) -> Result<bool, ApiError> {
  let tx = c.transaction().map_err(db::sql_err)?;
  if !db::agent(&tx, &node.server)?.is_some_and(|row| {
    row.public_key.as_ref() == Some(&node.public_key)
  }) {
    return Ok(false);
  }
  db::set_setting(&tx, SERVER_KEY, Some(&node.server))?;
  db::set_setting(&tx, PUBKEY_KEY, Some(&node.public_key))?;
  tx.commit().map_err(db::sql_err)?;
  Ok(true)
}

struct Challenge(PathBuf);
impl Drop for Challenge {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.0);
  }
}

fn random() -> Result<String, ApiError> {
  let mut bytes = [0u8; 32];
  getrandom::fill(&mut bytes)
    .map_err(|_| ApiError::internal("生成同机挑战随机数失败"))?;
  Ok(hex::encode(bytes))
}

fn probe_io(e: std::io::Error) -> ApiError {
  ApiError::internal(format!("无法准备控制面同机挑战：{e}"))
}

fn cancelled() -> ApiError {
  ApiError::new(ErrorCode::Cancelled, "已取消控制面同机校验")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{db::Db, world::KIND_SERVER};
  use serde_json::json;

  fn fixture_node() -> VerifiedCore {
    VerifiedCore {
      server: "s1".into(),
      public_key: "s1".into(),
      container_id: None,
      conn_id: 1,
    }
  }

  #[tokio::test]
  async fn bad_proof_and_missing_host_clear_only_unchanged_binding() {
    let state = crate::rules::tests::test_state();
    let node = fixture_node();
    let binding = (node.server.clone(), node.public_key.clone());
    let expected = random().unwrap();
    for code in [
      None,
      Some(ErrorCode::NotFound),
      Some(ErrorCode::Timeout),
      Some(ErrorCode::AgentOffline),
      Some(ErrorCode::AgentFailed),
      Some(ErrorCode::Internal),
    ] {
      state
        .db
        .call(|c| {
          db::set_setting(c, SERVER_KEY, Some("s1"))?;
          db::set_setting(c, PUBKEY_KEY, Some("s1"))
        })
        .await
        .unwrap();
      let response = code.map_or_else(
        || {
          Ok(CoreHostProbeResult {
            token: "wrong".into(),
          })
        },
        |code| Err(ApiError::new(code, "测试应答")),
      );
      let result = finish_probe(
        &state,
        node.clone(),
        Some(&binding),
        &expected,
        response,
      )
      .await;
      let clears =
        code.is_none() || code == Some(ErrorCode::NotFound);
      assert_eq!(result.is_ok(), clears);
      let current =
        state.db.call(|c| load_persisted(c)).await.unwrap();
      assert_eq!(current, (!clears).then(|| binding.clone()));
    }

    state
      .db
      .call(|c| db::set_setting(c, PUBKEY_KEY, Some("new")))
      .await
      .unwrap();
    finish_probe(
      &state,
      node,
      Some(&binding),
      &expected,
      Ok(CoreHostProbeResult {
        token: "wrong".into(),
      }),
    )
    .await
    .unwrap();
    assert_eq!(
      state.db.call(|c| load_persisted(c)).await.unwrap(),
      Some(("s1".into(), "new".into()))
    );
  }

  #[tokio::test]
  async fn successful_probe_refreshes_core_lan_trust() {
    let state = crate::rules::tests::test_state();
    let local = std::net::Ipv4Addr::new(10, 254, 83, 11);
    state.db.call(move |c| {
      db::apply_write(c, &db::Write::Upsert {
        kind: KIND_SERVER.into(), name: "s1".into(),
        spec: json!({"lan_addrs": [local.to_string()]}), meta: json!({}),
      })?;
      c.execute("INSERT INTO agents (server, public_key) VALUES ('s1', 's1')", []).map_err(db::sql_err)?;
      Ok(())
    }).await.unwrap();
    let peer = std::net::Ipv4Addr::new(10, 254, 83, 12).to_string();
    assert!(matches!(
      crate::source_trust::classify_zone(&peer),
      crate::lockout::OriginZone::Public
    ));
    let proof = random().unwrap();
    finish_probe(
      &state,
      fixture_node(),
      None,
      &proof,
      Ok(CoreHostProbeResult {
        token: proof.clone(),
      }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
      crate::source_trust::classify_zone(&peer),
      crate::lockout::OriginZone::Internal
    ));
  }

  #[tokio::test]
  async fn core_node_verification_persists_and_rejects_forged_token()
  {
    let db = Db::memory();
    db.call(|c| {
      for name in ["s1", "s2"] {
        db::apply_write(c, &db::Write::Upsert { kind: KIND_SERVER.into(),
          name: name.into(), spec: json!({}), meta: json!({}) })?;
        c.execute("INSERT INTO agents (server, public_key, report) VALUES (?1, ?1, ?2)", rusqlite::params![
          name, json!({"version":"","hostname":name,"os":"","arch":"","data_dir":"",
            "private_addr":{"ip":"100.64.0.2","network":"tailscale"}}).to_string(),
        ]).map_err(db::sql_err)?;
      }
      let node = VerifiedCore { server: "s2".into(), public_key: "s2".into(), container_id: None, conn_id: 1 };
      let expected = random()?;
      assert!(!valid_response(&expected, "wrong"));
      assert_eq!(load_persisted(c)?, None);
      assert!(valid_response(&expected, &expected));
      assert!(store_verified(c, &node)?);
      assert_eq!(load_persisted(c)?, Some(("s2".into(), "s2".into())));
      Ok(())
    }).await.unwrap();
    let snap = crate::snapshot::load_inner(&db).await.unwrap();
    assert_eq!(server_of(&snap).as_deref(), Some("s2"));
    db.call(|c| {
      c.execute("UPDATE agents SET public_key = 'changed' WHERE server = 's2'", []).map_err(db::sql_err)?;
      Ok(())
    }).await.unwrap();
    assert!(
      server_of(&crate::snapshot::load_inner(&db).await.unwrap())
        .is_none()
    );
    db.call(|c| {
      clear_if_server(c, "s2")?;
      assert!(load_persisted(c)?.is_none());
      Ok(())
    })
    .await
    .unwrap();
  }
}
