//! 控制面所在节点的可信定位（无密钥文件系统挑战-应答 + settings 持久化绑定）。
//!
//! 原理：控制面在自身 `data_dir/.core-probe/<challenge_id>` 写入 256-bit 随机口令，
//! 仅把文件名通过只读 `AgentOp::ProbeCoreHost` 发给支持 `core_probe` 的在线 agent；
//! agent 必须从宿主机读回原文，控制面常量时间比对通过后，把 `(server, public_key)`
//! 持久化到 SQLite `settings` 表，全程不下发任何密钥。

use std::{
  io::Write,
  path::{Path, PathBuf},
  sync::Arc,
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, CoreHostProbe, CoreHostProbeResult, container_id,
  },
};

use crate::{
  db, hub::Hub, snapshot::Snapshot, state::AppState, world::World,
};

pub const SERVER_KEY: &str = "core.server";
pub const PUBKEY_KEY: &str = "core.server_key";
const PROBE_DIR: &str = ".core-probe";
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCore {
  pub server: String,
  /// 该节点经校验时的 agent Ed25519 公钥（hex）。
  pub public_key: String,
  /// 控制面当前容器 ID（若运行在容器内）。
  pub container_id: Option<String>,
}

/// 控制面当前所在的 Docker 容器 ID；非容器运行时返回 `None`。
pub fn self_container_id() -> Option<String> {
  std::fs::read_to_string("/proc/self/mountinfo")
    .ok()
    .and_then(|m| container_id(&m))
}

/// 同步只读查询：仅当持久化绑定的服务器仍在 `world.servers` 中，
/// 且 `snap.agents` 中记录的公钥与 `core.server_key` 一致时返回 `Some(server)`。
pub fn server_of_in(
  snap: &Snapshot,
  world: &World,
) -> Option<String> {
  let (server, expected_key) = snap.core_binding.as_ref()?;
  if !world.servers.contains_key(server) {
    return None;
  }
  let current_key =
    snap.agent(server).and_then(|a| a.public_key.as_deref())?;
  constant_time_eq(current_key, expected_key).then(|| server.clone())
}

/// 同步只读查询（给 `Snapshot` / `host_access` / `join` / `source_trust` 用，零 IO）。
pub fn server_of(snap: &Snapshot) -> Option<String> {
  server_of_in(snap, &snap.world)
}

/// 供 `Snapshot::load_inner` 在 SQLite 事务中读取已持久化绑定。
pub fn load_persisted(
  c: &rusqlite::Connection,
) -> Result<Option<(String, String)>, ApiError> {
  let server = db::setting(c, SERVER_KEY)?;
  let key = db::setting(c, PUBKEY_KEY)?;
  Ok(match (server, key) {
    (Some(s), Some(k)) if !s.is_empty() && !k.is_empty() => {
      Some((s, k))
    }
    _ => None,
  })
}

fn persist_binding(
  c: &rusqlite::Connection,
  server: &str,
  public_key: &str,
) -> Result<(), ApiError> {
  db::set_setting(c, SERVER_KEY, Some(server))?;
  db::set_setting(c, PUBKEY_KEY, Some(public_key))
}

fn clear_persisted(c: &rusqlite::Connection) -> Result<(), ApiError> {
  db::set_setting(c, SERVER_KEY, None)?;
  db::set_setting(c, PUBKEY_KEY, None)
}

/// 删除服务器或 `--rejoin` 换公钥时调用，清除失效绑定。
pub fn clear_if_server(
  c: &rusqlite::Connection,
  server: &str,
) -> Result<(), ApiError> {
  if db::setting(c, SERVER_KEY)?.as_deref() == Some(server) {
    clear_persisted(c)?;
  }
  Ok(())
}

/// 同时清除数据库与内存中的控制面节点绑定。
pub fn clear_memory_if_server(hub: &Hub, server: &str) {
  hub.clear_verified_core_if(server);
}

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
  a.len() == b.len()
    && a
      .bytes()
      .zip(b.bytes())
      .fold(0u8, |acc, (x, y)| acc | (x ^ y))
      == 0
}

fn random_hex_32() -> Result<String, ApiError> {
  let mut bytes = [0u8; 32];
  getrandom::fill(&mut bytes)
    .map_err(|e| ApiError::internal(format!("随机数不可用：{e}")))?;
  Ok(hex::encode(bytes))
}

struct ProbeFileGuard {
  path: PathBuf,
}

impl Drop for ProbeFileGuard {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}

fn write_probe_file(
  data_dir: &Path,
  challenge_id: &str,
  token: &str,
) -> Result<ProbeFileGuard, ApiError> {
  use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

  let dir = data_dir.join(PROBE_DIR);
  std::fs::create_dir_all(&dir).map_err(|e| {
    ApiError::internal(format!("创建 {} 失败：{e}", dir.display()))
  })?;
  let _ = std::fs::set_permissions(
    &dir,
    std::fs::Permissions::from_mode(0o700),
  );
  let path = dir.join(challenge_id);
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(&path)
    .map_err(|e| {
      ApiError::internal(format!("写入 {} 失败：{e}", path.display()))
    })?;
  file.write_all(token.as_bytes()).map_err(|e| {
    let _ = std::fs::remove_file(&path);
    ApiError::internal(format!("写入 {} 失败：{e}", path.display()))
  })?;
  Ok(ProbeFileGuard { path })
}

/// 校验控制面同机探测结果，纯函数方便单测。
pub(crate) fn verify_probe_token(
  server: &str,
  expected: &str,
  got: &CoreHostProbeResult,
) -> bool {
  let ok = constant_time_eq(got.token.trim(), expected);
  if !ok {
    tracing::warn!(
      "服务器 {server} 返回了错误的控制面同机校验口令，已拒绝"
    );
  }
  ok
}

async fn probe_one(
  state: &AppState,
  server: &str,
  container_id: Option<&str>,
  cancel: &CancellationToken,
) -> Result<Option<VerifiedCore>, ApiError> {
  if !state.hub.supports_core_probe(server) {
    return Ok(None);
  }
  let challenge_id = random_hex_32()?;
  let expected_token = random_hex_32()?;
  let _guard = write_probe_file(
    &state.data_dir,
    &challenge_id,
    &expected_token,
  )?;
  let data_dir = state
    .data_dir
    .canonicalize()
    .unwrap_or_else(|_| state.data_dir.clone())
    .to_string_lossy()
    .into_owned();
  let probe = CoreHostProbe {
    challenge_id,
    data_dir,
    container_id: container_id.map(str::to_string),
  };
  let result = state
    .hub
    .call::<CoreHostProbeResult>(
      server,
      AgentOp::ProbeCoreHost(probe),
      PROBE_TIMEOUT,
      None,
      cancel,
    )
    .await;
  match result {
    Ok(res) => {
      if !verify_probe_token(server, &expected_token, &res) {
        return Ok(None);
      }
      let srv = server.to_string();
      let pubkey = state
        .db
        .call(move |c| {
          Ok(db::agent(c, &srv)?.and_then(|a| a.public_key))
        })
        .await?;
      let Some(public_key) = pubkey else {
        return Ok(None);
      };
      Ok(Some(VerifiedCore {
        server: server.to_string(),
        public_key,
        container_id: container_id.map(str::to_string),
      }))
    }
    Err(e) if e.code == ErrorCode::Cancelled => Err(e),
    Err(_) => Ok(None),
  }
}

async fn save_verified(
  state: &AppState,
  verified: &VerifiedCore,
) -> Result<(), ApiError> {
  let srv = verified.server.clone();
  let key = verified.public_key.clone();
  state
    .db
    .call(move |c| persist_binding(c, &srv, &key))
    .await?;
  state.hub.set_verified_core(Some(verified.clone()));
  Ok(())
}

/// agent 连上 `/agent/ws`（`core_probe == true`）时由 `hub.rs` 后台触发。
pub fn spawn_probe_on_connect(state: Arc<AppState>, server: String) {
  if !state.hub.supports_core_probe(&server) {
    return;
  }
  tokio::spawn(async move {
    let persisted =
      state.db.call(load_persisted).await.ok().flatten();
    if let Some(verified) = state.hub.verified_core()
      && verified.server != server
    {
      return;
    }
    let cid = self_container_id();
    let cancel = CancellationToken::new();
    match probe_one(&state, &server, cid.as_deref(), &cancel).await {
      Ok(Some(verified)) => {
        if let Err(e) = save_verified(&state, &verified).await {
          tracing::warn!("持久化控制面节点绑定失败：{e}");
        } else {
          tracing::info!(
            "已确认控制面位于服务器 {}",
            verified.server
          );
          let _ = crate::snapshot::load(&state.db).await;
        }
      }
      Ok(None) => {
        if persisted.as_ref().is_some_and(|(s, _)| s == &server) {
          // 持久化节点验证未通过（如控制面已迁移）：清除旧绑定并探测其余在线节点。
          let _ = state.db.call(clear_persisted).await;
          state.hub.clear_verified_core_if(&server);
          for other in state.hub.core_probe_servers() {
            if other == server {
              continue;
            }
            if let Ok(Some(verified)) =
              probe_one(&state, &other, cid.as_deref(), &cancel).await
            {
              if save_verified(&state, &verified).await.is_ok() {
                tracing::info!(
                  "已确认控制面已迁移到服务器 {}",
                  verified.server
                );
                let _ = crate::snapshot::load(&state.db).await;
              }
              break;
            }
          }
        }
      }
      Err(_) => {}
    }
  });
}

/// 高敏操作（控制面备份、控制面升级等）前调用：
/// 现场执行一次实时无密钥挑战-应答，验证通过后持久化并返回 `VerifiedCore`。
pub async fn require_verified(
  state: &AppState,
  cancel: &CancellationToken,
) -> Result<VerifiedCore, ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;
  let persisted = state.db.call(load_persisted).await?;
  let cid = self_container_id();
  let mut saw_legacy = false;
  let mut tried_persisted: Option<String> = None;

  if let Some((ref server, _)) = persisted
    && snap.world.servers.contains_key(server)
    && state.hub.is_online(server)
  {
    if state.hub.supports_core_probe(server) {
      tried_persisted = Some(server.clone());
      if let Some(verified) =
        probe_one(state, server, cid.as_deref(), cancel).await?
      {
        save_verified(state, &verified).await?;
        return Ok(verified);
      }
    } else {
      saw_legacy = true;
    }
  }

  for server in snap.world.servers.keys() {
    if tried_persisted.as_deref() == Some(server.as_str()) {
      continue;
    }
    if !state.hub.is_online(server) {
      continue;
    }
    if !state.hub.supports_core_probe(server) {
      saw_legacy = true;
      continue;
    }
    if let Some(verified) =
      probe_one(state, server, cid.as_deref(), cancel).await?
    {
      save_verified(state, &verified).await?;
      return Ok(verified);
    }
  }

  if let Some(old_server) = tried_persisted {
    let _ = state
      .db
      .call(move |c| clear_if_server(c, &old_server))
      .await;
    state.hub.set_verified_core(None);
  }

  if saw_legacy {
    Err(
      ApiError::new(
        ErrorCode::Conflict,
        "找不到已完成可信校验的控制面所在节点（存在未升级的旧版 agent）",
      )
      .with_hint("先运行 wharf upgrade 升级 agent，再重试"),
    )
  } else {
    Err(
      ApiError::new(
        ErrorCode::NotFound,
        "找不到和控制面在同一台机器上的在线 agent",
      )
      .with_hint(
        "确认控制面所在机器的 wharf-agent 在运行、已加入控制面，且数据目录挂载一致",
      ),
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[tokio::test]
  async fn core_node_verification_persists_and_rejects_forged_token()
  {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::rules::tests::test_state();
    Arc::get_mut(&mut state).unwrap().data_dir =
      tmp.path().to_path_buf();

    let key_s1 = "11".repeat(32);
    let key_s2 = "22".repeat(32);
    let k1 = key_s1.clone();
    let k2 = key_s2.clone();
    state
      .db
      .call(move |c| {
        for (srv, key) in [("s1", k1), ("s2", k2)] {
          db::apply_write(
            c,
            &db::Write::Upsert {
              kind: "server".into(),
              name: srv.into(),
              spec: json!({}),
              meta: json!({}),
            },
          )?;
          c.execute(
            "INSERT INTO agents (server, public_key) VALUES (?1, ?2)",
            rusqlite::params![srv, key],
          )
          .map_err(db::sql_err)?;
        }
        Ok(())
      })
      .await
      .unwrap();

    // 1. 写入探测文件后，伪造口令被拒且不写入 core.server。
    let challenge_id = random_hex_32().unwrap();
    let expected = random_hex_32().unwrap();
    {
      let _guard =
        write_probe_file(&state.data_dir, &challenge_id, &expected)
          .unwrap();
      let probe_path =
        state.data_dir.join(PROBE_DIR).join(&challenge_id);
      assert!(probe_path.is_file());
      assert!(!verify_probe_token(
        "s1",
        &expected,
        &CoreHostProbeResult {
          token: "wrong".into(),
        },
      ));
      assert!(state.db.call(load_persisted).await.unwrap().is_none());

      // 2. 读回真实随机文件内容，验证通过并持久化绑定到 s2。
      let actual = std::fs::read_to_string(&probe_path).unwrap();
      assert!(verify_probe_token(
        "s2",
        &expected,
        &CoreHostProbeResult { token: actual },
      ));
    }
    // RAII Drop 保证临时文件立即删除。
    assert!(
      !state.data_dir.join(PROBE_DIR).join(&challenge_id).exists()
    );

    save_verified(
      &state,
      &VerifiedCore {
        server: "s2".into(),
        public_key: key_s2.clone(),
        container_id: None,
      },
    )
    .await
    .unwrap();

    // 3. s1 即使上报与 s2 相同的 IP，也不影响 server_of(&snap) 返回 Some("s2")。
    let mut snap = crate::snapshot::load(&state.db).await.unwrap();
    assert_eq!(server_of(&snap).as_deref(), Some("s2"));
    if let Some(a) = snap.agents.iter_mut().find(|a| a.server == "s1")
    {
      a.report = Some(wharf_api_types::agent::AgentReport {
        lan_ips: vec!["100.64.0.2".into()],
        ..Default::default()
      });
    }
    assert_eq!(server_of(&snap).as_deref(), Some("s2"));

    // 4. agents.public_key 变更后，server_of(&snap) 自动失效返回 None。
    if let Some(a) = snap.agents.iter_mut().find(|a| a.server == "s2")
    {
      a.public_key = Some("33".repeat(32));
    }
    assert!(server_of(&snap).is_none());

    // clear_if_server 清除持久化绑定。
    state.db.call(|c| clear_if_server(c, "s2")).await.unwrap();
    let reloaded = crate::snapshot::load(&state.db).await.unwrap();
    assert!(server_of(&reloaded).is_none());
  }
}
