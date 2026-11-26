//! agent 和控制面的通信身份轮换。

use std::{
  fs,
  io::Write,
  os::unix::fs::OpenOptionsExt,
  path::Path,
  sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use axum::{
  Json,
  extract::{ConnectInfo, Path as AxumPath, State},
  http::HeaderMap,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, KeyRotatePhase, RotateAgentKeyJob, RotateAgentKeyResult,
    TrustCoreKeyJob,
  },
  view::{AgentKeyRotation, CoreKeyView, Perm},
};

use crate::{
  api::{ApiResult, AppError},
  auth::Auth,
  db::{self, Db, now_ms, sql_err, to_time},
  state::AppState,
};

const CURRENT: &str = "core.key";
const PREVIOUS: &str = "core.key.prev";
const NEXT: &str = "core.key.next";
const EXPIRES: &str = "core_key.prev_expires_at";
const OP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct CoreKeys {
  current: SigningKey,
  previous: Option<(SigningKey, i64)>,
}

impl CoreKeys {
  pub fn public_key(&self) -> String {
    public_key(&self.current)
  }

  #[cfg(test)]
  pub fn verifying_key(&self) -> VerifyingKey {
    self.current.verifying_key()
  }

  pub fn previous_public_key(&self) -> Option<String> {
    self.previous.as_ref().map(|(key, _)| public_key(key))
  }

  pub fn sign(&self, payload: &[u8]) -> (String, Option<String>) {
    let sign =
      |key: &SigningKey| hex::encode(key.sign(payload).to_bytes());
    (
      sign(&self.current),
      self.previous.as_ref().map(|(key, _)| sign(key)),
    )
  }

  fn view(&self) -> CoreKeyView {
    let public_key = self.public_key();
    CoreKeyView {
      fingerprint: fingerprint(&public_key),
      public_key,
      previous_expires_at: self
        .previous
        .as_ref()
        .map(|(_, at)| to_time(*at)),
      pending_agents: Vec::new(),
    }
  }
}

pub struct CoreKeyRing {
  keys: RwLock<CoreKeys>,
  expiring: AtomicBool,
  pub operation: tokio::sync::Mutex<()>,
}

impl From<SigningKey> for CoreKeyRing {
  fn from(current: SigningKey) -> Self {
    Self {
      keys: RwLock::new(CoreKeys {
        current,
        previous: None,
      }),
      expiring: AtomicBool::new(false),
      operation: Default::default(),
    }
  }
}

impl CoreKeyRing {
  pub async fn load(
    db: &Db,
    dir: &Path,
    current: SigningKey,
  ) -> Result<Self, ApiError> {
    let stored = db.call(|c| db::setting(c, EXPIRES)).await?;
    let expires = stored
      .as_deref()
      .and_then(|value| value.parse::<i64>().ok())
      .filter(|time| *time > now_ms());
    let previous = match expires {
      Some(expires) => read_key(&dir.join(PREVIOUS))?
        .filter(|key| key.verifying_key() != current.verifying_key())
        .map(|key| (key, expires)),
      None => None,
    };
    if previous.is_none() {
      // 启动时没有在线 agent，重连后按当前公钥集合同步。
      remove_file(&dir.join(PREVIOUS))?;
      if stored.is_some() {
        db.call(|c| db::set_setting(c, EXPIRES, None)).await?;
      }
    }
    remove_file(&dir.join(NEXT))?;
    Ok(Self {
      keys: RwLock::new(CoreKeys { current, previous }),
      expiring: AtomicBool::new(false),
      operation: Default::default(),
    })
  }

  fn raw(&self) -> CoreKeys {
    self.keys.read().unwrap_or_else(|e| e.into_inner()).clone()
  }

  fn replace(
    &self,
    current: SigningKey,
    previous: Option<(SigningKey, i64)>,
  ) {
    *self.keys.write().unwrap_or_else(|e| e.into_inner()) =
      CoreKeys { current, previous };
  }
}

impl AppState {
  pub fn core_keys(self: &Arc<Self>) -> CoreKeys {
    let mut keys = self.key.raw();
    if keys
      .previous
      .as_ref()
      .is_some_and(|(_, at)| *at <= now_ms())
    {
      keys.previous = None;
      if !self.key.expiring.swap(true, Ordering::Relaxed) {
        let s = self.clone();
        tokio::spawn(async move {
          let _lock = s.key.operation.lock().await;
          if let Err(error) = expire(&s).await {
            tracing::warn!("清理过期控制面公钥失败：{error}");
          }
          s.key.expiring.store(false, Ordering::Relaxed);
        });
      }
    }
    keys
  }
}

fn public_key(key: &SigningKey) -> String {
  hex::encode(key.verifying_key().to_bytes())
}

pub fn fingerprint(public: &str) -> String {
  hex::encode(&Sha256::digest(public.as_bytes())[..6])
}

fn conflict(message: impl Into<String>) -> ApiError {
  ApiError::new(ErrorCode::Conflict, message)
}

fn fs_error(error: std::io::Error) -> ApiError {
  ApiError::internal(format!("读写控制面身份文件失败：{error}"))
}

fn read_key(path: &Path) -> Result<Option<SigningKey>, ApiError> {
  let text = match fs::read_to_string(path) {
    Ok(text) => text,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(None);
    }
    Err(e) => return Err(fs_error(e)),
  };
  let seed = hex::decode(text.trim())
    .ok()
    .and_then(|bytes| bytes.try_into().ok())
    .ok_or_else(|| ApiError::internal("控制面身份文件格式不对"))?;
  Ok(Some(SigningKey::from_bytes(&seed)))
}

fn write_key(path: &Path, key: &SigningKey) -> Result<(), ApiError> {
  let temp = path.with_file_name(format!(
    "{}.write-tmp",
    path.file_name().unwrap_or_default().to_string_lossy()
  ));
  let mut file = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(&temp)
    .map_err(fs_error)?;
  file
    .write_all(hex::encode(key.to_bytes()).as_bytes())
    .map_err(fs_error)?;
  file.sync_all().map_err(fs_error)?;
  fs::rename(temp, path).map_err(fs_error)
}

fn remove_file(path: &Path) -> Result<(), ApiError> {
  match fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(fs_error(e)),
  }
}

fn valid_public_key(value: &str) -> bool {
  hex::decode(value)
    .ok()
    .and_then(|bytes| bytes.try_into().ok())
    .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
    .is_some_and(|key| {
      !key.is_weak() && hex::encode(key.to_bytes()) == value
    })
}

pub fn accepts_agent(
  c: &Connection,
  server: &str,
  public: &str,
  capable: bool,
) -> Result<bool, ApiError> {
  c.query_row(
    "SELECT public_key IS NOT NULL AND (public_key = ?2 OR
      (?3 AND next_public_key IS NOT NULL AND next_public_key = ?2 AND next_key_expires_at > ?4))
     FROM agents WHERE server = ?1",
    params![server, public, capable, now_ms()],
    |r| r.get(0),
  ).optional().map_err(sql_err).map(|valid| valid.unwrap_or(false))
}

pub fn register_agent_key(
  c: &mut Connection,
  server: &str,
  public: &str,
  capable: bool,
) -> Result<(), ApiError> {
  let tx = c.transaction().map_err(sql_err)?;
  if !accepts_agent(&tx, server, public, capable)? {
    return Err(ApiError::new(
      ErrorCode::Unauthorized,
      "agent 注册公钥已变更",
    ));
  }
  let previous: String = tx
    .query_row(
      "SELECT public_key FROM agents WHERE server = ?1",
      [server],
      |r| r.get(0),
    )
    .map_err(sql_err)?;
  if previous != public {
    tx.execute(
      "UPDATE agents SET public_key = ?2, next_public_key = NULL, next_key_expires_at = NULL WHERE server = ?1",
      params![server, public],
    ).map_err(sql_err)?;
    if crate::core_node::load_persisted(&tx)?
      .as_ref()
      .is_some_and(|(name, key)| name == server && key == &previous)
    {
      db::set_setting(
        &tx,
        crate::core_node::PUBKEY_KEY,
        Some(public),
      )?;
    }
  }
  tx.execute("UPDATE agents SET key_rotation = ?2 WHERE server = ?1 AND key_rotation != ?2",
    params![server, capable]).map_err(sql_err)?;
  tx.commit().map_err(sql_err)
}

fn old_agent(server: &str) -> ApiError {
  conflict(format!(
    "服务器 {server} 的 agent 版本旧，不支持在线轮换密钥"
  ))
  .with_hint("先运行 wharf server upgrade 升级该机器的 agent")
}

async fn agent_op<T: serde::de::DeserializeOwned>(
  s: &AppState,
  server: &str,
  conn: u64,
  op: AgentOp,
) -> Result<T, ApiError> {
  let cancel = CancellationToken::new();
  tokio::time::timeout(
    OP_TIMEOUT,
    s.hub
      .call_bound((server, conn), op, OP_TIMEOUT, None, &cancel),
  )
  .await
  .map_err(|_| {
    ApiError::new(
      ErrorCode::Timeout,
      format!("服务器 {server} 的密钥操作超时"),
    )
  })?
}

pub async fn rotate_agent(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
  AxumPath(server): AxumPath<String>,
) -> ApiResult<AgentKeyRotation> {
  auth.require(Perm::Admin)?;
  let source = crate::login::source(peer.ip(), &headers);
  let response = tokio::spawn(async move {
    let lock = s.key.operation.lock().await;
    let result = rotate_agent_inner(&s, &server).await?;
    drop(lock);
    crate::security_receipt::send(
      &s,
      &auth.name,
      &source,
      format!("在线轮换服务器 {server} 的 agent 密钥"),
    )
    .await;
    Ok::<_, ApiError>(result)
  })
  .await
  .map_err(|_| ApiError::internal("agent 密钥操作任务失败"))??;
  Ok(Json(response))
}

async fn rotate_agent_inner(
  s: &AppState,
  server: &str,
) -> Result<AgentKeyRotation, ApiError> {
  let name = server.to_string();
  let old = s.db.call(move |c| {
    let joined = db::agent(c, &name)?.and_then(|a| a.public_key)
      .ok_or_else(|| ApiError::not_found(format!("服务器 {name} 尚未加入")))?;
    let rotating = c.query_row(
      "SELECT COALESCE(next_key_expires_at > ?2, 0) FROM agents WHERE server = ?1",
      params![name, now_ms()],
      |r| r.get::<_, bool>(0),
    ).map_err(sql_err)?;
    if rotating {
      return Err(conflict(format!("服务器 {name} 已有一笔身份轮换等待确认")));
    }
    Ok(joined)
  }).await?;
  let (conn, capable) = s
    .hub
    .key_connection(server)
    .ok_or_else(|| crate::hub::offline(server))?;
  if !capable {
    return Err(old_agent(server));
  }
  let prepare = AgentOp::RotateAgentKey(RotateAgentKeyJob {
    phase: KeyRotatePhase::Prepare,
    expected_public_key: None,
  });
  let result: RotateAgentKeyResult =
    agent_op(s, server, conn, prepare).await?;
  let public = result.public_key;
  if public == old || !valid_public_key(&public) {
    return Err(ApiError::invalid("agent 返回了无效的新公钥"));
  }
  let name = server.to_string();
  let next = public.clone();
  s.db.call(move |c| {
    let changed = c.execute(
      "UPDATE agents SET next_public_key = ?2, next_key_expires_at = ?3 WHERE server = ?1 AND public_key = ?4",
      params![name, next, now_ms() + 300_000, old],
    ).map_err(sql_err)?;
    if changed == 0 {
      return Err(conflict("agent 注册公钥已变更"));
    }
    Ok(())
  }).await?;
  let activate = AgentOp::RotateAgentKey(RotateAgentKeyJob {
    phase: KeyRotatePhase::Activate,
    expected_public_key: Some(public.clone()),
  });
  let ack: Result<(), _> = agent_op(s, server, conn, activate).await;
  if let Err(error) = &ack
    && error.code != ErrorCode::Timeout
  {
    let name = server.to_string();
    let next = public.clone();
    s.db.call(move |c| {
      c.execute(
        "UPDATE agents SET next_public_key = NULL, next_key_expires_at = NULL WHERE server = ?1 AND next_public_key = ?2",
        params![name, next],
      ).map_err(sql_err)?;
      Ok(())
    }).await?;
    return Err(error.clone());
  }
  // 回复可能在断线时丢失。以新连接的公钥为准。
  let confirmed = tokio::time::timeout(CONNECT_TIMEOUT, async {
    loop {
      if s
        .hub
        .connected_identity(server)
        .is_some_and(|(id, key)| id != conn && key == public)
      {
        break;
      }
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  })
  .await
  .is_ok();
  if !confirmed {
    ack?;
    return Err(ApiError::new(
      ErrorCode::Timeout,
      "等待新 agent 身份上线超时",
    ));
  }
  Ok(AgentKeyRotation {
    server: server.into(),
    key_fingerprint: fingerprint(&public),
    rotated_at: to_time(now_ms()),
  })
}

#[derive(Deserialize)]
pub struct RotateCoreRequest {
  window_hours: Option<u16>,
  #[serde(default)]
  force: bool,
  #[serde(default)]
  client_ready: bool,
}

pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreKeyView> {
  auth.require(Perm::Read)?;
  Ok(Json(s.core_keys().view()))
}

pub async fn rotate(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<RotateCoreRequest>,
) -> ApiResult<CoreKeyView> {
  auth.require(Perm::Admin)?;
  if !auth.human && !req.client_ready {
    return Err(
      conflict("当前 CLI 无法保存控制面公钥")
        .with_hint("升级 wharf，并确保本机 config.toml 可写")
        .into(),
    );
  }
  let hours = req.window_hours.unwrap_or(168);
  if !(1..=720).contains(&hours) {
    return Err(
      ApiError::invalid("过渡期须在 1 到 720 小时之间").into(),
    );
  }
  let source = crate::login::source(peer.ip(), &headers);
  let view = tokio::spawn(async move {
    let lock = s.key.operation.lock().await;
    let pending_agents = rotate_core(&s, hours, req.force).await?;
    let mut view = s.core_keys().view();
    view.pending_agents = pending_agents;
    drop(lock);
    crate::security_receipt::send(
      &s,
      &auth.name,
      &source,
      "在线轮换控制面公钥".into(),
    )
    .await;
    Ok::<_, ApiError>(view)
  })
  .await
  .map_err(|_| ApiError::internal("控制面密钥操作任务失败"))??;
  Ok(Json(view))
}

async fn preflight(
  s: &AppState,
  force: bool,
) -> Result<Vec<(String, u64)>, ApiError> {
  let joined = s.db.call(|c| {
    let mut stmt = c.prepare("SELECT server, key_rotation FROM agents WHERE public_key IS NOT NULL ORDER BY server")
      .map_err(sql_err)?;
    stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))
      .map_err(sql_err)?.collect::<Result<Vec<_>, _>>().map_err(sql_err)
  }).await?;
  let mut legacy = Vec::new();
  let mut offline = Vec::new();
  let mut online = Vec::new();
  for (server, known_capable) in joined {
    match s.hub.key_connection(&server) {
      Some((conn, true)) => online.push((server, conn)),
      Some((_, false)) => legacy.push(server),
      None if !known_capable && force => legacy.push(server),
      None => offline.push(server),
    }
  }
  if !legacy.is_empty() {
    return Err(
      conflict(format!(
        "存在不支持密钥轮换的旧版 agent：{}",
        legacy.join("、")
      ))
      .with_hint(
        "先运行 wharf upgrade 升级全部 agent 后再轮换控制面公钥",
      ),
    );
  }
  if !force && !offline.is_empty() {
    return Err(conflict(format!("存在离线服务器，无法同步新公钥：{}", offline.join("、")))
      .with_hint("确保全部服务器在线后重试，或加 --force 强制轮换（离线机器在过渡窗口外需要重新加入）"));
  }
  Ok(online)
}

async fn trust(
  s: &AppState,
  server: &str,
  conn: u64,
  current: &str,
  alt: Option<&str>,
  reconnect: bool,
) -> Result<(), ApiError> {
  agent_op(
    s,
    server,
    conn,
    AgentOp::TrustCoreKey(TrustCoreKeyJob {
      current: current.into(),
      alt: alt.map(str::to_string),
      reconnect,
    }),
  )
  .await
}

async fn push_trust(
  s: &AppState,
  agents: &[(String, u64)],
  current: &str,
  alt: Option<&str>,
  reconnect: bool,
) -> Vec<String> {
  futures_util::future::join_all(agents.iter().map(
    |(server, conn)| async move {
      trust(s, server, *conn, current, alt, reconnect)
        .await
        .err()
        .map(|_| server.clone())
    },
  ))
  .await
  .into_iter()
  .flatten()
  .collect()
}

async fn rotate_core(
  s: &AppState,
  hours: u16,
  force: bool,
) -> Result<Vec<String>, ApiError> {
  expire(s).await?;
  if s.key.raw().previous.is_some() {
    return Err(
      conflict("当前已有控制面公钥过渡窗口")
        .suggest("wharf core key"),
    );
  }
  let agents = preflight(s, force).await?;
  let old = s.key.raw().current;
  let old_public = public_key(&old);
  let mut seed = [0; 32];
  getrandom::fill(&mut seed)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  let next = SigningKey::from_bytes(&seed);
  let next_public = public_key(&next);
  let next_path = s.data_dir.join(NEXT);
  write_key(&next_path, &next)?;
  let failed =
    push_trust(s, &agents, &old_public, Some(&next_public), false)
      .await;
  let expires = now_ms() + i64::from(hours) * 3_600_000;
  let activated = async {
    if !failed.is_empty() {
      return Err(conflict(format!(
        "新公钥未同步到：{}",
        failed.join("、")
      )));
    }
    write_key(&s.data_dir.join(PREVIOUS), &old)?;
    s.db
      .call(move |c| {
        db::set_setting(c, EXPIRES, Some(&expires.to_string()))
      })
      .await?;
    fs::rename(&next_path, s.data_dir.join(CURRENT))
      .map_err(fs_error)?;
    Ok::<_, ApiError>(())
  }
  .await;
  if let Err(error) = activated {
    let _ = remove_file(&next_path);
    let _ = remove_file(&s.data_dir.join(PREVIOUS));
    let _ = s.db.call(|c| db::set_setting(c, EXPIRES, None)).await;
    let _ = push_trust(
      s,
      &s.hub.rotation_agents(),
      &old_public,
      None,
      false,
    )
    .await;
    return Err(error);
  }
  s.key.replace(next, Some((old, expires)));
  let _ =
    push_trust(s, &agents, &next_public, Some(&old_public), true)
      .await;
  let waiting = |server: &str, conn| {
    !s.hub.uses_core_key(server, Some(conn), &next_public)
  };
  let _ = tokio::time::timeout(CONNECT_TIMEOUT, async {
    while agents.iter().any(|(server, conn)| waiting(server, *conn)) {
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  })
  .await;
  Ok(
    agents
      .into_iter()
      .filter(|(server, conn)| waiting(server, *conn))
      .map(|(server, _)| server)
      .collect(),
  )
}

async fn finish(
  s: &AppState,
  rollback: bool,
  expired: bool,
) -> Result<CoreKeyView, ApiError> {
  let keys = s.key.raw();
  let Some((old, _)) =
    keys.previous.filter(|(_, at)| expired || *at > now_ms())
  else {
    return Err(
      conflict("当前没有正在进行的控制面公钥过渡窗口")
        .suggest("wharf core key"),
    );
  };
  let current = if rollback {
    write_key(&s.data_dir.join(CURRENT), &old)?;
    old
  } else {
    keys.current
  };
  let current_public = public_key(&current);
  s.key.replace(current, None);
  let cleanup = async {
    remove_file(&s.data_dir.join(PREVIOUS))?;
    s.db.call(|c| db::set_setting(c, EXPIRES, None)).await
  }
  .await;
  let _ = push_trust(
    s,
    &s.hub.rotation_agents(),
    &current_public,
    None,
    rollback,
  )
  .await;
  cleanup?;
  Ok(s.key.raw().view())
}

async fn finish_request(
  s: Arc<AppState>,
  auth: Auth,
  rollback: bool,
) -> Result<Json<CoreKeyView>, AppError> {
  auth.require(Perm::Admin)?;
  let view = tokio::spawn(async move {
    let _lock = s.key.operation.lock().await;
    expire(&s).await?;
    finish(&s, rollback, false).await
  })
  .await
  .map_err(|_| ApiError::internal("控制面密钥操作任务失败"))??;
  Ok(Json(view))
}

pub async fn commit(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreKeyView> {
  finish_request(s, auth, false).await
}

pub async fn rollback(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<CoreKeyView> {
  finish_request(s, auth, true).await
}

pub async fn cleanup(s: &AppState) -> Result<(), ApiError> {
  s.db.call(|c| {
    c.execute("UPDATE agents SET next_public_key = NULL, next_key_expires_at = NULL WHERE next_key_expires_at <= ?1", [now_ms()])
      .map_err(sql_err)?;
    Ok(())
  }).await?;
  let _lock = s.key.operation.lock().await;
  expire(s).await
}

async fn expire(s: &AppState) -> Result<(), ApiError> {
  if s.key.raw().previous.is_some_and(|(_, at)| at <= now_ms()) {
    finish(s, false, true).await?;
  }
  Ok(())
}

pub async fn sync_agent(
  s: Arc<AppState>,
  server: String,
  conn: u64,
  trusted_primary: Option<String>,
  trusted_alt: Option<String>,
) {
  let _lock = s.key.operation.lock().await;
  let keys = s.core_keys();
  let current = keys.public_key();
  let alt = keys.previous_public_key();
  if trusted_primary.as_deref() != Some(&current)
    || trusted_alt != alt
  {
    let _ =
      trust(&s, &server, conn, &current, alt.as_deref(), false).await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn reconnect_repairs_last_trusted_keys_after_window_closes() {
    let old = SigningKey::from_bytes(&[1; 32]);
    let new = SigningKey::from_bytes(&[2; 32]);
    let stale_primary = public_key(&new);
    let stale_alt = Some(public_key(&old));

    for end in ["commit", "expire", "rollback", "restart"] {
      let dir = tempfile::tempdir().unwrap();
      let mut s = crate::rules::tests::test_state();
      Arc::get_mut(&mut s).unwrap().data_dir = dir.path().into();
      let expires = if matches!(end, "expire" | "restart") {
        now_ms() - 1
      } else {
        now_ms() + 60_000
      };
      write_key(&dir.path().join(PREVIOUS), &old).unwrap();
      s.db
        .call(move |c| {
          db::set_setting(c, EXPIRES, Some(&expires.to_string()))
        })
        .await
        .unwrap();
      s.key.replace(new.clone(), Some((old.clone(), expires)));

      let (sent, mut pushed) = tokio::sync::mpsc::unbounded_channel();
      if end == "expire" {
        let sent = sent.clone();
        s.hub.mock_rotation_agent("s2", move |op| {
          sent.send(op).unwrap();
          Ok(serde_json::Value::Null)
        });
        assert!(s.core_keys().previous_public_key().is_none());
        let op =
          tokio::time::timeout(Duration::from_secs(5), pushed.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(op, AgentOp::TrustCoreKey(job)
          if job.current == stale_primary && job.alt.is_none()));
      } else if end == "restart" {
        let key = CoreKeyRing::load(&s.db, dir.path(), new.clone())
          .await
          .unwrap();
        Arc::get_mut(&mut s).unwrap().key = key;
      } else {
        finish(&s, end == "rollback", false).await.unwrap();
      }
      assert!(!dir.path().join(PREVIOUS).exists());
      assert_eq!(
        s.db.call(|c| db::setting(c, EXPIRES)).await.unwrap(),
        None
      );

      s.hub.mock_rotation_agent("s1", move |op| {
        sent.send(op).unwrap();
        Ok(serde_json::Value::Null)
      });
      let (conn, _) = s.hub.key_connection("s1").unwrap();
      sync_agent(
        s.clone(),
        "s1".into(),
        conn,
        Some(stale_primary.clone()),
        stale_alt.clone(),
      )
      .await;
      let AgentOp::TrustCoreKey(job) = pushed.try_recv().unwrap()
      else {
        panic!("重连后应纠正 agent 的信任集合");
      };
      let active = if end == "rollback" { &old } else { &new };
      assert_eq!(job.current, public_key(active), "{end}");
      assert!(job.alt.is_none(), "{end}");
      sync_agent(s, "s1".into(), conn, Some(job.current), None).await;
      assert!(pushed.try_recv().is_err(), "{end}");
    }
  }
}
