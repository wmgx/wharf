//! 服务数据目录的文件浏览：列目录、下载、上传。文件内容由 agent 分块传，
//! 下载边读边发给浏览器，上传整个收下后分块写过去。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  body::{Body, Bytes},
  extract::{Path, Query, State},
  http::header,
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, FILE_CHUNK, FileChunk, FileEntry, FilesOp},
  view::Perm,
};

use crate::{
  api::{ApiResult, service_not_found},
  auth::Auth,
  snapshot,
  state::AppState,
};

const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
/// 上传整个放在内存里，限制大小。更大的文件用 scp 或备份恢复。
pub const MAX_UPLOAD: usize = 100 << 20;

#[derive(Deserialize)]
pub struct FileQuery {
  #[serde(default)]
  pub path: String,
}

pub(crate) async fn server_of(
  s: &AppState,
  service: &str,
) -> Result<String, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  snapshot::service_runtime_server(&snap, service)
    .map(str::to_string)
    .ok_or_else(|| service_not_found(service))
}

async fn call<T: serde::de::DeserializeOwned>(
  s: &AppState,
  server: &str,
  op: FilesOp,
) -> Result<T, ApiError> {
  s.hub
    .call(
      server,
      AgentOp::Files(op),
      CHUNK_TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await
}

/// `GET /api/services/{name}/files?path=`
pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<FileQuery>,
) -> ApiResult<Vec<FileEntry>> {
  auth.require(Perm::Read)?;
  let server = server_of(&s, &name).await?;
  Ok(Json(
    call(
      &s,
      &server,
      FilesOp::List {
        service: name,
        path: q.path,
      },
    )
    .await?,
  ))
}

/// `GET /api/services/{name}/files/download?path=`：先读第一块拿到大小和错误，
/// 再边读边发。
pub async fn download(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<FileQuery>,
) -> Result<Response, crate::api::AppError> {
  auth.require(Perm::Read)?;
  let server = server_of(&s, &name).await?;
  let (svc, path) = (name.clone(), q.path.clone());
  let read = move |offset: u64, expect| FilesOp::Read {
    service: svc.clone(),
    path: path.clone(),
    offset,
    len: FILE_CHUNK,
    expect,
  };
  let first: FileChunk = call(&s, &server, read(0, None)).await?;
  let size = first.size;
  let version = first.version;
  let first = decode(&first.data)?;
  let offset = checked_offset(0, first.len(), size)?;
  let state = (s, server, read, offset, version);
  let rest =
    futures_util::stream::unfold(Some(state), move |st| async move {
      let (s, server, read, offset, version) = st?;
      if offset >= size {
        return None;
      }
      let chunk =
        call::<FileChunk>(&s, &server, read(offset, version.clone()))
          .await
          .and_then(|c| {
            if version.is_some() && c.version != version {
              return Err(ApiError::new(
                ErrorCode::Conflict,
                "下载期间文件已变化",
              ));
            }
            let bytes = decode(&c.data)?;
            let next = checked_offset(offset, bytes.len(), size)?;
            Ok((bytes, next))
          });
      match chunk {
        Ok((b, next)) => Some((
          Ok(Bytes::from(b)),
          Some((s, server, read, next, version)),
        )),
        // 中途出错只能断开，浏览器会显示下载失败。
        Err(e) => Some((Err(std::io::Error::other(e.message)), None)),
      }
    });
  let body = futures_util::stream::once(async move {
    Ok::<_, std::io::Error>(Bytes::from(first))
  })
  .chain(rest);
  let filename =
    q.path.rsplit('/').next().unwrap_or("file").to_string();
  Ok(
    (
      [
        (
          header::CONTENT_TYPE,
          "application/octet-stream".to_string(),
        ),
        (header::CONTENT_LENGTH, size.to_string()),
        (
          header::CONTENT_DISPOSITION,
          format!(
            "attachment; filename*=UTF-8''{}",
            encode(&filename)
          ),
        ),
      ],
      Body::from_stream(body),
    )
      .into_response(),
  )
}

fn checked_offset(
  offset: u64,
  len: usize,
  size: u64,
) -> Result<u64, ApiError> {
  let next = offset.saturating_add(len as u64);
  if next > size || (offset < size && len == 0) {
    return Err(ApiError::new(
      ErrorCode::Conflict,
      "下载期间文件大小已变化",
    ));
  }
  Ok(next)
}

fn decode(data: &str) -> Result<Vec<u8>, ApiError> {
  STANDARD.decode(data).map_err(|e| {
    ApiError::internal(format!("agent 返回的数据不对：{e}"))
  })
}

/// RFC 5987：文件名里的非 ASCII 字符按 UTF-8 百分号编码。
fn encode(name: &str) -> String {
  name
    .bytes()
    .map(|b| {
      if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
        (b as char).to_string()
      } else {
        format!("%{b:02X}")
      }
    })
    .collect()
}

/// `PUT /api/services/{name}/files?path=`，请求体是文件内容。已有的文件会被覆盖。
pub async fn upload(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<FileQuery>,
  body: Bytes,
) -> ApiResult<serde_json::Value> {
  auth.require(Perm::Exec)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::apply([name.clone()]),
    "上传服务文件",
  )?;
  let server = server_of(&s, &name).await?;
  crate::pending::source_changed(&s, &name).await?;
  let chunks: Vec<&[u8]> = if body.is_empty() {
    vec![&[]]
  } else {
    body.chunks(FILE_CHUNK as usize).collect()
  };
  let mut offset = 0u64;
  for (i, chunk) in chunks.iter().enumerate() {
    call::<serde_json::Value>(
      &s,
      &server,
      FilesOp::Write {
        service: name.clone(),
        path: q.path.clone(),
        offset,
        data: STANDARD.encode(chunk),
        last: i + 1 == chunks.len(),
      },
    )
    .await?;
    offset += chunk.len() as u64;
  }
  tracing::info!("上传 {name}:{}（{} 字节）", q.path, body.len());
  Ok(Json(serde_json::json!({ "size": body.len() })))
}

#[cfg(test)]
mod tests {
  use super::checked_offset;

  #[test]
  fn rejects_short_and_oversized_download_chunks() {
    assert!(checked_offset(4, 0, 8).is_err());
    assert!(checked_offset(4, 5, 8).is_err());
    assert_eq!(checked_offset(4, 4, 8).unwrap(), 8);
  }

  #[test]
  fn encodes_filename() {
    assert_eq!(super::encode("a b.txt"), "a%20b.txt");
    assert_eq!(super::encode("数据.db"), "%E6%95%B0%E6%8D%AE.db");
  }
}

#[tokio::test]
async fn files_server_of_uses_migration_source_when_interrupted() {
  let state = crate::migrate::tests::seed_service(false).await;
  crate::migrate::tests::seed_migration(&state, "pending", false)
    .await;
  assert_eq!(server_of(&state, "notes").await.unwrap(), "s1");
}
