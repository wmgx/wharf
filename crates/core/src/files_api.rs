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
  ApiError,
  agent::{AgentOp, FILE_CHUNK, FileChunk, FileEntry, FilesOp},
  view::TokenScope,
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

async fn server_of(
  s: &AppState,
  service: &str,
) -> Result<String, ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let row = snap
    .world
    .services
    .get(service)
    .ok_or_else(|| service_not_found(service))?;
  Ok(row.spec.server.clone())
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
  auth.require(TokenScope::Read)?;
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
  auth.require(TokenScope::Read)?;
  let server = server_of(&s, &name).await?;
  let (svc, path) = (name.clone(), q.path.clone());
  let read = move |offset: u64| FilesOp::Read {
    service: svc.clone(),
    path: path.clone(),
    offset,
    len: FILE_CHUNK,
  };
  let first: FileChunk = call(&s, &server, read(0)).await?;
  let size = first.size;
  let first = decode(&first.data)?;
  let state = (s.clone(), server, read, first.len() as u64);
  let rest =
    futures_util::stream::unfold(Some(state), move |st| async move {
      let (s, server, read, offset) = st?;
      if offset >= size {
        return None;
      }
      let chunk = call::<FileChunk>(&s, &server, read(offset))
        .await
        .and_then(|c| decode(&c.data));
      match chunk {
        Ok(b) if b.is_empty() => None,
        Ok(b) => {
          let next = offset + b.len() as u64;
          Some((Ok(Bytes::from(b)), Some((s, server, read, next))))
        }
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
  auth.require(TokenScope::ApplyAll)?;
  let server = server_of(&s, &name).await?;
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
  #[test]
  fn encodes_filename() {
    assert_eq!(super::encode("a b.txt"), "a%20b.txt");
    assert_eq!(super::encode("数据.db"), "%E6%95%B0%E6%8D%AE.db");
  }
}
