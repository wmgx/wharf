//! 服务数据目录的文件浏览：列目录、下载、上传。文件内容由 agent 分块传，
//! 下载边读边发给浏览器，上传整个收下后分块写过去。

use std::{sync::Arc, time::Duration};

use axum::{
  Extension, Json,
  body::{Body, Bytes},
  extract::{Path, Query, State},
  http::{Method, header},
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, FILE_CHUNK, FileChunk, FileEntry, FileGrepResult,
    FileMkdirResult, FileMvResult, FileRmResult, FileTailResult,
    FileVersion, FilesOp,
  },
  view::Perm,
};

use crate::{
  api::{ApiResult, service_not_found},
  audit::AuditSlot,
  auth::Auth,
  snapshot,
  state::AppState,
};

pub(crate) const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
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
  let path = q.path.clone();
  stream_download(&q.path, None, move |offset, expect| {
    let state = Arc::clone(&s);
    let server = server.clone();
    let op = FilesOp::Read {
      service: name.clone(),
      path: path.clone(),
      offset,
      len: FILE_CHUNK,
      expect,
    };
    async move { call(&state, &server, op).await }
  })
  .await
}

pub(crate) async fn stream_download<F, Fut>(
  path: &str,
  expected_size: Option<u64>,
  read: F,
) -> Result<Response, crate::api::AppError>
where
  F: Fn(u64, Option<FileVersion>) -> Fut + Send + 'static,
  Fut: std::future::Future<Output = Result<FileChunk, ApiError>>
    + Send
    + 'static,
{
  let first = read(0, None).await?;
  let size = first.size;
  if expected_size.is_some_and(|expected| expected != size) {
    return Err(
      ApiError::new(ErrorCode::Conflict, "产物大小与任务清单不符")
        .into(),
    );
  }
  let version = first.version;
  let first = decode(&first.data)?;
  let offset = checked_offset(0, first.len(), size)?;
  let state = (read, offset, version);
  let rest =
    futures_util::stream::unfold(Some(state), move |st| async move {
      let (read, offset, version) = st?;
      if offset >= size {
        return None;
      }
      let chunk = read(offset, version.clone()).await.and_then(|c| {
        if c.size != size || version.is_some() && c.version != version
        {
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
        Ok((bytes, next)) => {
          Some((Ok(Bytes::from(bytes)), Some((read, next, version))))
        }
        Err(e) => Some((Err(std::io::Error::other(e.message)), None)),
      }
    });
  let body = futures_util::stream::once(async move {
    Ok::<_, std::io::Error>(Bytes::from(first))
  })
  .chain(rest);
  let filename =
    path.rsplit('/').next().unwrap_or("file").to_string();
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

#[derive(Deserialize)]
pub struct TailQuery {
  path: String,
  #[serde(default = "default_lines")]
  lines: u32,
  max_bytes: Option<u32>,
}

#[derive(Deserialize)]
pub struct GrepQuery {
  #[serde(default)]
  path: String,
  pattern: String,
  #[serde(default)]
  regex: bool,
  #[serde(default = "default_lines")]
  limit: u32,
}

fn default_lines() -> u32 {
  100
}

async fn read_v2<T: serde::de::DeserializeOwned>(
  s: &AppState,
  name: &str,
  op: FilesOp,
) -> Result<(T, Vec<String>), ApiError> {
  read_from_snapshot(s, &snapshot::load(&s.db).await?, name, op).await
}

pub(super) async fn read_from_snapshot<
  T: serde::de::DeserializeOwned,
>(
  s: &AppState,
  snap: &snapshot::Snapshot,
  name: &str,
  op: FilesOp,
) -> Result<(T, Vec<String>), ApiError> {
  let server = snapshot::service_runtime_server(snap, name)
    .ok_or_else(|| service_not_found(name))?;
  let conn = if matches!(op, FilesOp::ExtraLog { .. }) {
    s.hub.extra_logs_conn_id(server)?
  } else {
    s.hub.files_v2_conn_id(server, "文件查看")?
  };
  let mut values: Vec<_> = snap
    .render_values(&snap.world, name)
    .into_values()
    .collect();
  if let Some(row) = snap.world.services.get(name) {
    values.extend(crate::log_redact::service_values(&row.spec));
  }
  let cancel = CancellationToken::new();
  let _cancel_on_drop = cancel.clone().drop_guard();
  let out = s
    .hub
    .call_bound(
      (server, conn),
      AgentOp::Files(op),
      Duration::from_secs(30),
      None,
      &cancel,
    )
    .await
    .map_err(crate::log_redact::redact_error)?;
  Ok((out, values))
}

pub async fn tail(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<TailQuery>,
  Extension(audit): Extension<AuditSlot>,
) -> ApiResult<FileTailResult> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  audit
    .set_detail(format!("tail {name}:{} lines={}", q.path, q.lines));
  let (mut result, values): (FileTailResult, _) = read_v2(
    &s,
    &name,
    FilesOp::Tail {
      service: name.clone(),
      path: q.path,
      lines: q.lines,
      max_bytes: q.max_bytes,
    },
  )
  .await?;
  result.content =
    crate::log_redact::redact_text_with(&result.content, &values);
  Ok(Json(result))
}

pub async fn grep(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<GrepQuery>,
  Extension(audit): Extension<AuditSlot>,
) -> ApiResult<FileGrepResult> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  audit.set_detail(format!("grep {name}:{}", q.path));
  let (mut result, values): (FileGrepResult, _) = read_v2(
    &s,
    &name,
    FilesOp::Grep {
      service: name.clone(),
      path: q.path,
      pattern: q.pattern,
      regex: q.regex,
      limit: q.limit,
    },
  )
  .await?;
  for hit in &mut result.matches {
    hit.text =
      crate::log_redact::redact_text_with(&hit.text, &values);
  }
  Ok(Json(result))
}

#[derive(Deserialize)]
pub struct RmQuery {
  path: String,
  #[serde(default)]
  recursive: bool,
}

#[derive(Deserialize)]
pub struct MvRequest {
  from: String,
  to: String,
  #[serde(default)]
  force: bool,
}

#[derive(Deserialize)]
pub struct MkdirRequest {
  path: String,
  #[serde(default)]
  parents: bool,
}

async fn edit<T: serde::de::DeserializeOwned>(
  s: &AppState,
  auth: &Auth,
  audit: &AuditSlot,
  name: &str,
  op: FilesOp,
) -> Result<T, crate::api::AppError> {
  auth.require(Perm::Exec)?;
  crate::token_scope::require_service(auth, name)?;
  let _guard = s.locks.acquire(
    crate::locks::LockSpec::apply([name.to_owned()]),
    "修改服务文件",
  )?;
  let server = server_of(s, name).await?;
  let conn = s.hub.files_v2_conn_id(&server, "文件修改")?;
  let (method, suffix, detail, timeout) = match &op {
    FilesOp::Rm {
      path, recursive, ..
    } => (
      Method::DELETE,
      "",
      format!("rm {name}:{path} recursive={recursive}"),
      60,
    ),
    FilesOp::Mv {
      from, to, force, ..
    } => (
      Method::POST,
      "/mv",
      format!("mv {name}:{from} -> {to} force={force}"),
      30,
    ),
    FilesOp::Mkdir { path, parents, .. } => (
      Method::POST,
      "/mkdir",
      format!("mkdir {name}:{path} parents={parents}"),
      30,
    ),
    _ => unreachable!(),
  };
  audit
    .record_before_files(
      s,
      &auth.name,
      method,
      format!("/api/services/{name}/files{suffix}"),
      detail,
    )
    .await?;
  crate::pending::source_changed(s, name).await?;
  let cancel = CancellationToken::new();
  let _cancel_on_drop = cancel.clone().drop_guard();
  Ok(
    s.hub
      .call_bound(
        (&server, conn),
        AgentOp::Files(op),
        Duration::from_secs(timeout),
        None,
        &cancel,
      )
      .await
      .map_err(crate::log_redact::redact_error)?,
  )
}

pub async fn rm(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(q): Query<RmQuery>,
  Extension(audit): Extension<AuditSlot>,
) -> ApiResult<FileRmResult> {
  let result: FileRmResult = edit(
    &s,
    &auth,
    &audit,
    &name,
    FilesOp::Rm {
      service: name.clone(),
      path: q.path,
      recursive: q.recursive,
    },
  )
  .await?;
  audit.set_detail(format!(
    "rm {name}:{} recursive={} removed={}",
    result.path, q.recursive, result.removed
  ));
  Ok(Json(result))
}

pub async fn mv(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Json(q): Json<MvRequest>,
) -> ApiResult<FileMvResult> {
  Ok(Json(
    edit(
      &s,
      &auth,
      &audit,
      &name,
      FilesOp::Mv {
        service: name.clone(),
        from: q.from,
        to: q.to,
        force: q.force,
      },
    )
    .await?,
  ))
}

pub async fn mkdir(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Json(q): Json<MkdirRequest>,
) -> ApiResult<FileMkdirResult> {
  Ok(Json(
    edit(
      &s,
      &auth,
      &audit,
      &name,
      FilesOp::Mkdir {
        service: name.clone(),
        path: q.path,
        parents: q.parents,
      },
    )
    .await?,
  ))
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

#[tokio::test]
async fn file_edits_require_exec_service_scope_capability_and_audit()
{
  let state = crate::migrate::tests::seed_service(false).await;
  crate::migrate::tests::seed_migration(&state, "synced", false)
    .await;
  let calls =
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let counter = calls.clone();
  state.hub.mock_agent("s1", false, move |op| {
    assert!(matches!(op, AgentOp::Files(FilesOp::Rm { .. })));
    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(serde_json::json!({"path":"a","removed":1}))
  });
  let auth = |exec, service: &str| Auth {
    name: "fixture".into(),
    perms: if exec {
      [Perm::Read, Perm::Exec].into_iter().collect()
    } else {
      [Perm::Read].into()
    },
    services: Some([service.into()].into()),
    allowed_from: vec![],
    expires_at: None,
    human: false,
  };
  let request = |auth| {
    rm(
      State(state.clone()),
      auth,
      Path("notes".into()),
      Query(RmQuery {
        path: "a".into(),
        recursive: false,
      }),
      Extension(AuditSlot::default()),
    )
  };
  for (exec, service, code) in [
    (false, "notes", ErrorCode::Forbidden),
    (true, "other", ErrorCode::Forbidden),
    (true, "notes", ErrorCode::Conflict),
  ] {
    assert_eq!(
      request(auth(exec, service)).await.err().unwrap().0.code,
      code
    );
  }
  let old_read = tail(
    State(state.clone()),
    auth(false, "notes"),
    Path("notes".into()),
    Query(TailQuery {
      path: "a".into(),
      lines: 5,
      max_bytes: None,
    }),
    Extension(AuditSlot::default()),
  )
  .await;
  assert_eq!(old_read.err().unwrap().0.code, ErrorCode::Conflict);
  state.hub.enable_mock_files_v2("s1");
  assert_eq!(
    request(auth(true, "notes"))
      .await
      .map_err(|e| e.0)
      .unwrap()
      .0
      .removed,
    1
  );
  let (audit_count, phase) = state.db.call(|c| {
    let count: i64 = c.query_row("SELECT count(*) FROM audit_log WHERE method='DELETE' AND path='/api/services/notes/files'", [], |r| r.get(0)).map_err(crate::db::sql_err)?;
    let phase: String = c.query_row("SELECT phase FROM pending_steps WHERE target_key='notes'", [], |r| r.get(0)).map_err(crate::db::sql_err)?;
    Ok((count, phase))
  }).await.unwrap();
  assert_eq!((audit_count, phase.as_str()), (1, "pending"));
  state
    .db
    .call(|c| {
      c.execute("DROP TABLE audit_log", [])
        .map(|_| ())
        .map_err(crate::db::sql_err)
    })
    .await
    .unwrap();
  assert!(request(auth(true, "notes")).await.is_err());
  assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
