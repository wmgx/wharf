//! 用同机文件证明确定可以接收控制面敏感操作的 agent。

use std::{
  io::Write,
  os::unix::fs::{DirBuilderExt, OpenOptionsExt},
  path::PathBuf,
  sync::{Arc, Mutex},
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
static VERIFIED_THIS_BOOT: Mutex<Option<VerifiedCore>> =
  Mutex::new(None);

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
    let mut verified =
      VERIFIED_THIS_BOOT.lock().unwrap_or_else(|p| p.into_inner());
    if verified.as_ref().is_some_and(|v| v.server == server) {
      *verified = None;
    }
  }
  Ok(())
}

pub fn spawn_probe_on_connect(state: Arc<AppState>, server: String) {
  tokio::spawn(async move {
    let cancel = CancellationToken::new();
    let _guard = VERIFY.lock().await;
    let already_verified = VERIFIED_THIS_BOOT
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .as_ref()
      .is_some_and(|v| {
        v.server != server
          && state.hub.conn_id(&v.server) == Some(v.conn_id)
      });
    if !already_verified {
      let _ = find_verified(&state, &cancel).await;
    }
  });
}

pub async fn require_verified(
  state: &AppState,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  let _guard = tokio::select! {
    biased;
    _ = cancel.cancelled() => return Err(cancelled()),
    guard = VERIFY.lock() => guard,
  };
  find_verified(state, cancel).await
}

async fn find_verified(
  state: &AppState,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  let persisted = state.db.call(|c| load_persisted(c)).await?;
  let cid = std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| container_id(&m));
  let (mut candidates, legacy) = state.hub.core_probe_servers();
  candidates.sort_unstable_by_key(|name| {
    persisted.as_ref().is_none_or(|p| &p.0 != name)
  });
  for server in candidates {
    if cancel.is_cancelled() {
      return Err(cancelled());
    }
    match probe_one(state, &server, cid.clone(), cancel).await {
      Ok(Some(verified)) => return Ok(verified),
      Ok(None) => {}
      Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
      Err(e) if e.code == ErrorCode::NotFound => {
        if let Some((bound, key)) = &persisted
          && bound == &server
        {
          let bound = bound.clone();
          let key = key.clone();
          state
            .db
            .call(move |c| {
              if load_persisted(c)?.as_ref()
                == Some(&(bound.clone(), key))
              {
                clear_if_server(c, &bound)?;
              }
              Ok(())
            })
            .await?;
        }
      }
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
  container_id: Option<String>,
  cancel: &CancellationToken,
) -> Result<Option<VerifiedCore>, ApiError> {
  let Some((conn_id, public_key)) =
    state.hub.core_probe_identity(server)
  else {
    return Ok(None);
  };
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
  let result: CoreHostProbeResult = verified
    .call(
      state,
      AgentOp::ProbeCoreHost(CoreHostProbe {
        challenge_id,
        data_dir: data_dir
          .to_str()
          .ok_or_else(|| ApiError::invalid("数据目录路径不合法"))?
          .to_string(),
        container_id: verified.container_id.clone(),
      }),
      Duration::from_secs(25),
      None,
      cancel,
    )
    .await?;
  drop(challenge);
  if state.hub.core_probe_identity(server).as_ref()
    != Some(&(conn_id, verified.public_key.clone()))
  {
    return Ok(None);
  }
  let candidate = verified.clone();
  let stored = state
    .db
    .call(move |c| {
      if !store_verified(
        c,
        &candidate,
        &expected,
        result.token.trim(),
      )? {
        return Ok(false);
      }
      *VERIFIED_THIS_BOOT.lock().unwrap_or_else(|p| p.into_inner()) =
        Some(candidate);
      Ok(true)
    })
    .await?;
  Ok(stored.then_some(verified))
}

fn store_verified(
  c: &mut Connection,
  node: &VerifiedCore,
  expected: &str,
  response: &str,
) -> Result<bool, ApiError> {
  if expected.len() != response.len()
    || expected
      .bytes()
      .zip(response.bytes())
      .fold(0, |acc, (a, b)| acc | (a ^ b))
      != 0
  {
    tracing::warn!("服务器 {} 的控制面同机校验应答无效", node.server);
    return Ok(false);
  }
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
      assert!(!store_verified(c, &node, &expected, "wrong")?);
      assert_eq!(load_persisted(c)?, None);
      assert!(store_verified(c, &node, &expected, &expected)?);
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
