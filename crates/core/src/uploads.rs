//! 本机目录部署：CLI 把代码打成 tar.gz 上传到这里，按 sha256 存放；构建时 agent
//! 带一次性口令来下载。
//!
//! - 上传要 apply 权限，内容和地址里的 sha256 不一致就丢弃；
//! - 下载口令只能用一次，30 分钟内有效，只能下载签发时指定的那个包；
//! - 当前配置和近 30 天部署记录都没引用的包，由定时任务删除。

use std::{
  collections::HashMap,
  path::{Path as FsPath, PathBuf},
  sync::{Arc, Mutex},
  time::{Duration, Instant, SystemTime},
};

use axum::{
  Json,
  body::Body,
  extract::{Path, State},
  http::{HeaderMap, StatusCode, header},
  response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use wharf_api_types::{ApiError, spec::Source, view::TokenScope};

use crate::{
  api::{ApiResult, AppError},
  auth::Auth,
  db::sql_err,
  snapshot,
  state::AppState,
};

/// 代码包大小上限，和 agent 下载的上限一致。
pub const MAX_UPLOAD: usize = 512 * 1024 * 1024;
const TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// 没被引用的包保留多久。
const KEEP_UNUSED: Duration = Duration::from_secs(30 * 24 * 3600);

/// 签发出去还没用掉的下载口令：口令 → (sha256, 过期时间)。
#[derive(Default)]
pub struct Downloads(Mutex<HashMap<String, (String, Instant)>>);

impl Downloads {
  pub fn issue(&self, sha256: &str) -> String {
    let token = crate::backup::random_hex();
    let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    map.retain(|_, (_, exp)| *exp > now);
    map.insert(token.clone(), (sha256.to_string(), now + TOKEN_TTL));
    token
  }

  fn take(&self, token: &str, sha256: &str) -> bool {
    let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
    match map.remove(token) {
      Some((sha, exp)) => sha == sha256 && exp > Instant::now(),
      None => false,
    }
  }
}

pub fn dir(state: &AppState) -> PathBuf {
  state.data_dir.join("uploads")
}

fn file(state: &AppState, sha256: &str) -> PathBuf {
  dir(state).join(format!("{sha256}.tar.gz"))
}

pub fn check_sha(sha256: &str) -> Result<(), ApiError> {
  if sha256.len() == 64
    && sha256
      .bytes()
      .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
  {
    Ok(())
  } else {
    Err(ApiError::invalid("sha256 要写 64 位小写十六进制"))
  }
}

pub fn exists(state: &AppState, sha256: &str) -> bool {
  file(state, sha256).is_file()
}

/// 从代码包里读一个文本文件（单文件 Worker），最大 10 MiB。
pub fn read_file(
  state: &AppState,
  sha256: &str,
  path: &str,
) -> Result<String, ApiError> {
  use std::io::Read;
  const MAX: u64 = 10 * 1024 * 1024;
  let archive = file(state, sha256);
  let f = std::fs::File::open(&archive).map_err(|_| {
    ApiError::invalid(format!(
      "代码包 {} 不在控制面上",
      &sha256[..12]
    ))
    .with_hint("重新执行 wharf edge deploy 上传")
  })?;
  let want = path.trim_start_matches("./");
  let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(f));
  let entries = tar.entries().map_err(|e| io_error(&archive, e))?;
  for entry in entries {
    let entry = entry.map_err(|e| io_error(&archive, e))?;
    let name = entry
      .path()
      .map_err(|e| io_error(&archive, e))?
      .to_string_lossy()
      .trim_start_matches("./")
      .to_string();
    if name != want {
      continue;
    }
    if entry.size() > MAX {
      return Err(ApiError::invalid(format!("{want} 超过 10 MiB")));
    }
    let mut text = String::new();
    entry.take(MAX).read_to_string(&mut text).map_err(|_| {
      ApiError::invalid(format!("{want} 不是 UTF-8 文本"))
    })?;
    return Ok(text);
  }
  Err(ApiError::invalid(format!("代码包里没有 {want}")))
}

/// `GET /api/uploads/{sha256}`：CLI 上传前先问，已有就不用再传。
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(sha256): Path<String>,
) -> ApiResult<Value> {
  auth.require(TokenScope::Read)?;
  check_sha(&sha256)?;
  let size =
    std::fs::metadata(file(&s, &sha256)).ok().map(|m| m.len());
  Ok(Json(json!({ "exists": size.is_some(), "size": size })))
}

/// `PUT /api/uploads/{sha256}`：请求体是 tar.gz。
pub async fn put(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(sha256): Path<String>,
  body: Body,
) -> ApiResult<Value> {
  auth.require(TokenScope::ApplyAll)?;
  check_sha(&sha256)?;
  let target = file(&s, &sha256);
  if target.is_file() {
    return Ok(Json(json!({ "sha256": sha256, "existed": true })));
  }
  let dir = dir(&s);
  std::fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
  let part = dir
    .join(format!(".{sha256}.{}.part", crate::backup::random_hex()));
  let result = receive(body, &part, &sha256).await;
  match result {
    Ok(size) => {
      std::fs::rename(&part, &target)
        .map_err(|e| io_error(&target, e))?;
      Ok(Json(
        json!({ "sha256": sha256, "size": size, "existed": false }),
      ))
    }
    Err(e) => {
      let _ = std::fs::remove_file(&part);
      Err(e.into())
    }
  }
}

async fn receive(
  body: Body,
  part: &FsPath,
  sha256: &str,
) -> Result<u64, ApiError> {
  let mut out = open_private(part).await?;
  let mut hasher = Sha256::new();
  let mut size = 0usize;
  let mut stream = body.into_data_stream();
  while let Some(chunk) = stream.next().await {
    let chunk = chunk
      .map_err(|e| ApiError::invalid(format!("上传中断：{e}")))?;
    size += chunk.len();
    if size > MAX_UPLOAD {
      return Err(ApiError::invalid("代码包超过 512 MiB"));
    }
    hasher.update(&chunk);
    out.write_all(&chunk).await.map_err(|e| io_error(part, e))?;
  }
  out.flush().await.map_err(|e| io_error(part, e))?;
  if hex::encode(hasher.finalize()) != sha256 {
    return Err(ApiError::invalid(
      "上传内容的 sha256 和地址里的不一致",
    ));
  }
  Ok(size as u64)
}

async fn open_private(
  path: &FsPath,
) -> Result<tokio::fs::File, ApiError> {
  let mut opts = tokio::fs::OpenOptions::new();
  opts.write(true).create_new(true);
  #[cfg(unix)]
  opts.mode(0o600);
  opts.open(path).await.map_err(|e| io_error(path, e))
}

fn io_error(path: &FsPath, e: std::io::Error) -> ApiError {
  ApiError::internal(format!("{}：{e}", path.display()))
}

/// `GET /agent/uploads/{sha256}`：agent 构建时下载，`Authorization: Bearer <一次性口令>`。
pub async fn download(
  State(s): State<Arc<AppState>>,
  headers: HeaderMap,
  Path(sha256): Path<String>,
) -> Response {
  let token = headers
    .get(header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .unwrap_or_default();
  if check_sha(&sha256).is_err() || !s.downloads.take(token, &sha256)
  {
    return (StatusCode::UNAUTHORIZED, "下载口令无效或已过期")
      .into_response();
  }
  let path = file(&s, &sha256);
  match tokio::fs::File::open(&path).await {
    Ok(f) => (
      [(header::CONTENT_TYPE, "application/gzip")],
      Body::from_stream(tokio_util::io::ReaderStream::new(f)),
    )
      .into_response(),
    Err(_) => AppError(ApiError::not_found(
      "代码包不存在，重新执行 wharf deploy 上传",
    ))
    .into_response(),
  }
}

/// 删除没人引用、超过 30 天的代码包（当前配置和近 30 天的部署记录都算引用）。
pub async fn cleanup(state: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let mut used: Vec<String> = snap
    .world
    .services
    .values()
    .filter_map(|s| match &s.spec.source {
      Source::Build(b) => b.upload.clone(),
      _ => None,
    })
    .collect();
  let since = crate::db::now_ms() - KEEP_UNUSED.as_millis() as i64;
  let specs: Vec<String> = state
    .db
    .call(move |c| {
      let mut stmt = c
        .prepare("SELECT spec FROM deployments WHERE created_at >= ?1 AND spec IS NOT NULL")
        .map_err(sql_err)?;
      let rows = stmt
        .query_map(params![since], |r| r.get(0))
        .map_err(sql_err)?;
      rows.collect::<Result<_, _>>().map_err(sql_err)
    })
    .await?;
  used.extend(specs);
  let Ok(entries) = std::fs::read_dir(dir(state)) else {
    return Ok(());
  };
  for entry in entries.filter_map(Result::ok) {
    let name = entry.file_name().to_string_lossy().to_string();
    let Some(sha) = name.strip_suffix(".tar.gz") else {
      continue;
    };
    let old = entry
      .metadata()
      .and_then(|m| m.modified())
      .ok()
      .and_then(|t| SystemTime::now().duration_since(t).ok())
      .is_some_and(|age| age > KEEP_UNUSED);
    if old && !used.iter().any(|u| u.contains(sha)) {
      tracing::info!("删除不再使用的代码包 {sha}");
      let _ = std::fs::remove_file(entry.path());
    }
  }
  Ok(())
}
