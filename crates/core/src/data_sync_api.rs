use std::{collections::BTreeSet, io, sync::Arc, time::Duration};

use axum::{
  Extension, Json,
  body::{Body, Bytes},
  extract::{Path, Query, State},
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use tokio::{
  io::{AsyncRead, AsyncReadExt},
  sync::mpsc,
};
use tokio_util::{io::StreamReader, sync::CancellationToken};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{AgentOp, FileChunk, FilesOp},
  data_sync::*,
  view::{AuditEntry, Perm},
};

use crate::{
  api::{ApiResult, AppError},
  audit::AuditSlot,
  auth::Auth,
  state::AppState,
};

#[derive(Clone)]
struct Transfer {
  state: Arc<AppState>,
  service: String,
  server: String,
  conn: u64,
  cancel: CancellationToken,
}

impl Transfer {
  async fn open(
    state: Arc<AppState>,
    service: String,
  ) -> Result<Self, ApiError> {
    let server =
      crate::files_api::server_of(&state, &service).await?;
    let conn = state.hub.require_data_ops(&server)?;
    Ok(Self {
      state,
      service,
      server,
      conn,
      cancel: CancellationToken::new(),
    })
  }

  async fn agent<T: serde::de::DeserializeOwned>(
    &self,
    op: AgentOp,
    seconds: u64,
  ) -> Result<T, ApiError> {
    self
      .state
      .hub
      .call_bound(
        (&self.server, self.conn),
        op,
        Duration::from_secs(seconds),
        None,
        &self.cancel,
      )
      .await
  }

  async fn files<T: serde::de::DeserializeOwned>(
    &self,
    op: FilesOp,
  ) -> Result<T, ApiError> {
    self.agent(AgentOp::Files(op), 60).await
  }

  fn cleanup(&self, op: AgentOp) {
    let mut tx = self.clone();
    tx.cancel = CancellationToken::new();
    tokio::spawn(async move {
      let _: Result<serde_json::Value, _> = tx.agent(op, 10).await;
    });
  }
}

pub(crate) async fn manifest(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Json(request): Json<ManifestRequest>,
) -> ApiResult<DataManifestResult> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  validate_manifest(&request)?;
  audit.skip_record();
  let tx = Transfer::open(state, name).await?;
  let _guard = tx.cancel.clone().drop_guard();
  Ok(Json(
    tx.agent(
      AgentOp::DataManifest {
        service: tx.service.clone(),
        request,
      },
      60,
    )
    .await?,
  ))
}

fn validate_manifest(
  request: &ManifestRequest,
) -> Result<(), ApiError> {
  path_parts(&request.subpath)?;
  if request.excludes.len() > 128
    || request.excludes.iter().any(|p| p.len() > 512)
  {
    return Err(ApiError::invalid("排除规则超过上限"));
  }
  Ok(())
}

pub(crate) async fn pull(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<PullRequest>,
) -> Result<Response, AppError> {
  auth.require(Perm::Read)?;
  crate::token_scope::require_service(&auth, &name)?;
  path_parts(&req.subpath)?;
  if req.paths.len() > MAX_FILES {
    return Err(ApiError::invalid("拉取文件数超过上限").into());
  }
  let mut unique = BTreeSet::new();
  for path in &req.paths {
    join(&req.subpath, path)?;
    if !unique.insert(path) {
      return Err(ApiError::invalid("拉取列表包含重复路径").into());
    }
  }
  let tx = Transfer::open(state, name).await?;
  let packets = req.error_packets;
  let cancel = tx.cancel.clone();
  let guard = cancel.clone().drop_guard();
  let (send, rx) = mpsc::channel::<Result<Bytes, io::Error>>(1);
  audit.skip_record();
  tokio::spawn(async move {
    let mut summary = DataSyncSummary::default();
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
      timeout(req.timeout_secs),
      pull_files(&tx, &req, &send, &mut summary),
    )
    .await;
    let result = result.unwrap_or_else(|_| {
      Err(ApiError::new(ErrorCode::Cancelled, "拉取超时"))
    });
    let status = if result.is_ok() { 200 } else { 500 };
    if result.is_err() {
      tx.cancel.cancel();
    }
    let _ = crate::audit::insert(&tx.state, AuditEntry {
      id: 0, at: crate::db::now_ms(), kind: "api".into(), actor: auth.name,
      method: "POST".into(), path: format!("/api/services/{}/data/pull", tx.service),
      status: Some(status), duration_ms: Some(started.elapsed().as_millis() as i64),
      detail: Some(format!("data_pull service={} subpath={} files={} bytes={} sqlite_safe={}",
        tx.service, req.subpath, summary.files, summary.bytes, req.sqlite_safe)),
      source: None,
    }).await;
    if let Err(e) = result {
      send_pull_error(&send, e).await;
    }
  });
  let stream = futures_util::stream::unfold(
    (rx, guard),
    move |(mut rx, guard)| async move {
      rx.recv().await.map(|bytes| {
        let bytes = if packets {
          Ok(pull_packet(bytes))
        } else {
          bytes
        };
        (bytes, (rx, guard))
      })
    },
  );
  let mut response = (
    [("content-type", "application/octet-stream")],
    Body::from_stream(stream),
  )
    .into_response();
  if packets {
    response.headers_mut().insert(
      PULL_PACKETS_HEADER,
      axum::http::HeaderValue::from_static("1"),
    );
  }
  Ok(response)
}

fn pull_packet(chunk: Result<Bytes, io::Error>) -> Bytes {
  let (bytes, flag) = match chunk {
    Ok(bytes) => (bytes, 0),
    Err(error) => (
      Bytes::from(
        error.to_string().chars().take(MAX_PATH).collect::<String>(),
      ),
      PULL_PACKET_ERROR,
    ),
  };
  let mut packet = Vec::with_capacity(4 + bytes.len());
  packet.extend((flag | bytes.len() as u32).to_be_bytes());
  packet.extend_from_slice(&bytes);
  packet.into()
}

async fn send_pull_error(
  send: &mpsc::Sender<Result<Bytes, io::Error>>,
  error: ApiError,
) {
  let _ = send.send(Err(io::Error::other(error.message))).await;
}

#[tokio::test]
async fn pull_delivers_error_after_buffered_chunk() {
  let (send, mut recv) = mpsc::channel(1);
  emit(&send, Bytes::from_static(MAGIC)).await.unwrap();
  let error = ApiError::invalid("文件已变化");
  let receive = async {
    assert_eq!(
      recv.recv().await.unwrap().unwrap(),
      Bytes::from_static(MAGIC)
    );
    assert_eq!(
      recv.recv().await.unwrap().unwrap_err().to_string(),
      "文件已变化"
    );
  };
  tokio::join!(send_pull_error(&send, error), receive);
}

fn timeout(seconds: Option<u64>) -> Duration {
  Duration::from_secs(seconds.unwrap_or(1800).clamp(10, 7200))
}

fn max_bytes(value: Option<u64>) -> u64 {
  value.unwrap_or(MAX_FILE_BYTES).min(MAX_BYTES)
}

fn frame_limit(size: u64, remaining: u64) -> Result<(), ApiError> {
  if size > MAX_FILE_BYTES || size > remaining {
    return Err(ApiError::invalid("数据超过传输大小上限"));
  }
  Ok(())
}

async fn emit(
  send: &mpsc::Sender<Result<Bytes, io::Error>>,
  bytes: impl Into<Bytes>,
) -> Result<(), ApiError> {
  send
    .send(Ok(bytes.into()))
    .await
    .map_err(|_| ApiError::new(ErrorCode::Cancelled, "传输已断开"))
}

struct Cleanup<'a> {
  tx: &'a Transfer,
  op: Option<AgentOp>,
}
impl Drop for Cleanup<'_> {
  fn drop(&mut self) {
    if let Some(op) = self.op.take() {
      self.tx.cleanup(op);
    }
  }
}

async fn pull_files(
  tx: &Transfer,
  req: &PullRequest,
  send: &mpsc::Sender<Result<Bytes, io::Error>>,
  summary: &mut DataSyncSummary,
) -> Result<(), ApiError> {
  emit(send, Bytes::from_static(MAGIC)).await?;
  for path in &req.paths {
    let remote = join(&req.subpath, path)?;
    let sqlite = req.sqlite_safe
      && path.rsplit_once('.').is_some_and(|(_, ext)| {
        matches!(ext, "db" | "sqlite" | "sqlite3")
      });
    let snap: Option<SqliteSnapHandle> = if sqlite {
      Some(
        tx.agent(
          AgentOp::DataSqliteSnap {
            service: tx.service.clone(),
            path: remote.clone(),
          },
          120,
        )
        .await?,
      )
    } else {
      None
    };
    let _cleanup = Cleanup {
      tx,
      op: snap.as_ref().map(|snap| AgentOp::DataSqliteClose {
        snap_id: snap.snap_id.clone(),
      }),
    };
    let mut offset = 0;
    let mut size = 0;
    let mut version = None;
    let mut digest = Sha256::new();
    loop {
      let chunk: FileChunk = if let Some(snap) = &snap {
        tx.agent(
          AgentOp::DataSqliteRead {
            snap_id: snap.snap_id.clone(),
            offset,
          },
          60,
        )
        .await?
      } else {
        tx.files(FilesOp::Read {
          service: tx.service.clone(),
          path: remote.clone(),
          offset,
          len: CHUNK as u32,
          expect: version.clone(),
        })
        .await?
      };
      if offset == 0 {
        size = chunk.size;
        version = chunk.version.clone();
        frame_limit(
          size,
          max_bytes(req.max_bytes).saturating_sub(summary.bytes),
        )?;
        emit(send, frame(1, path, size, chunk.mode.unwrap_or(0o600)))
          .await?;
      }
      if chunk.size != size || chunk.version != version {
        return Err(ApiError::new(
          ErrorCode::Conflict,
          "拉取期间文件已变化",
        ));
      }
      let bytes = STANDARD
        .decode(&chunk.data)
        .map_err(|_| ApiError::internal("文件块无法解码"))?;
      if bytes.len() > CHUNK
        || offset + bytes.len() as u64 > size
        || (offset < size && bytes.is_empty())
      {
        return Err(ApiError::invalid("文件大小与清单不符"));
      }
      digest.update(&bytes);
      offset += bytes.len() as u64;
      summary.bytes += bytes.len() as u64;
      if !bytes.is_empty() {
        emit(send, bytes).await?;
      }
      if offset == size {
        break;
      }
    }
    let hash = digest.finalize();
    if snap.is_some_and(|snap| snap.sha256 != hex::encode(hash)) {
      return Err(ApiError::internal("SQLite 快照校验失败"));
    }
    emit(send, Bytes::copy_from_slice(&hash)).await?;
    summary.files += 1;
  }
  emit(send, Bytes::from_static(&[0])).await
}

pub(crate) async fn push(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Extension(audit): Extension<AuditSlot>,
  Query(options): Query<PushOptions>,
  body: Body,
) -> ApiResult<DataSyncSummary> {
  auth.require(Perm::Exec)?;
  crate::token_scope::require_service(&auth, &name)?;
  if options.delete {
    auth.require(Perm::Confirm)?;
  }
  path_parts(&options.subpath)?;
  let _lock = state.locks.acquire(
    crate::locks::LockSpec::apply([name.clone()]),
    "推送服务数据",
  )?;
  crate::pending::source_changed(&state, &name).await?;
  let tx = Transfer::open(state, name).await?;
  let _guard = tx.cancel.clone().drop_guard();
  let body = body.into_data_stream().map_err(io::Error::other);
  let mut reader = StreamReader::new(body);
  let mut summary = DataSyncSummary::default();
  let result = tokio::time::timeout(
    timeout(options.timeout_secs),
    push_frames(&tx, &options, &mut reader, &mut summary),
  )
  .await;
  audit.set_detail(format!(
    "data_push service={} subpath={} uploaded={} deleted={} bytes={}",
    tx.service,
    options.subpath,
    summary.files,
    summary.deleted,
    summary.bytes
  ));
  result
    .map_err(|_| ApiError::new(ErrorCode::Cancelled, "推送超时"))??;
  summary.uploaded = Some(summary.files);
  Ok(Json(summary))
}

async fn push_frames(
  tx: &Transfer,
  opts: &PushOptions,
  reader: &mut (impl AsyncRead + Unpin),
  summary: &mut DataSyncSummary,
) -> Result<(), ApiError> {
  let io_err = |_| ApiError::invalid("数据帧不完整");
  let mut magic = [0; MAGIC.len()];
  reader.read_exact(&mut magic).await.map_err(io_err)?;
  if &magic != MAGIC {
    return Err(ApiError::invalid("数据帧格式不对"));
  }
  let mut paths = BTreeSet::new();
  let mut deletes = Vec::new();
  let mut bytes = vec![0; CHUNK];
  loop {
    let kind = reader.read_u8().await.map_err(io_err)?;
    if kind == 0 {
      if reader.read(&mut bytes[..1]).await.map_err(io_err)? != 0 {
        return Err(ApiError::invalid("结束帧后有多余数据"));
      }
      break;
    }
    let length = reader.read_u32().await.map_err(io_err)? as usize;
    if length == 0 || length > MAX_PATH || paths.len() >= MAX_FILES {
      return Err(ApiError::invalid("数据路径或文件数超过上限"));
    }
    let mut path = vec![0; length];
    reader.read_exact(&mut path).await.map_err(io_err)?;
    let path = String::from_utf8(path)
      .map_err(|_| ApiError::invalid("路径不是 UTF-8"))?;
    let path = join(&opts.subpath, &path)?;
    if !paths.insert(path.clone()) {
      return Err(ApiError::invalid("数据帧包含重复路径"));
    }
    let size = reader.read_u64().await.map_err(io_err)?;
    let mode = reader.read_u32().await.map_err(io_err)?;
    let service = tx.service.clone();
    match kind {
      1 => {
        frame_limit(
          size,
          max_bytes(opts.max_bytes).saturating_sub(summary.bytes),
        )?;
        let mut upload = [0; 16];
        getrandom::fill(&mut upload)
          .map_err(|_| ApiError::internal("随机数不可用"))?;
        let upload = hex::encode(upload);
        let mut cleanup = Cleanup {
          tx,
          op: Some(AgentOp::Files(FilesOp::AbortWrite {
            service: service.clone(),
            path: path.clone(),
            upload: upload.clone(),
          })),
        };
        let mut hash = Sha256::new();
        let mut offset = 0;
        loop {
          let n = (size - offset).min(CHUNK as u64) as usize;
          reader.read_exact(&mut bytes[..n]).await.map_err(io_err)?;
          hash.update(&bytes[..n]);
          let last = offset + n as u64 == size;
          if last {
            let mut expected = [0; 32];
            reader.read_exact(&mut expected).await.map_err(io_err)?;
            if <[u8; 32]>::from(hash.finalize_reset()) != expected {
              return Err(ApiError::invalid("文件 SHA-256 校验失败"));
            }
          }
          let _: serde_json::Value = tx
            .files(FilesOp::DataWrite {
              service: service.clone(),
              path: path.clone(),
              upload: upload.clone(),
              mode,
              offset,
              data: STANDARD.encode(&bytes[..n]),
              last,
            })
            .await?;
          offset += n as u64;
          summary.bytes += n as u64;
          if last {
            break;
          }
        }
        cleanup.op = None;
        summary.files += 1;
      }
      2 if size == 0 => {
        let _: serde_json::Value =
          tx.files(FilesOp::Mkdir { service, path }).await?;
      }
      3 if size == 0 && opts.delete => deletes.push(path),
      3 => {
        return Err(ApiError::new(
          ErrorCode::Forbidden,
          "删除数据需要 --delete 和确认权限",
        ));
      }
      _ => return Err(ApiError::invalid("未知的数据帧")),
    }
  }
  deletes.sort_unstable_by_key(|p| {
    std::cmp::Reverse(p.matches('/').count())
  });
  for path in deletes {
    let _: serde_json::Value = tx
      .files(FilesOp::Remove {
        service: tx.service.clone(),
        path,
      })
      .await?;
    summary.deleted += 1;
  }
  Ok(())
}

#[tokio::test]
async fn data_pull_push_security_scope_and_limits() {
  let state = crate::rules::tests::test_state();
  let mut auth = crate::host_access::tests::auth([Perm::Read], false);
  auth.services = Some(BTreeSet::from(["app".to_string()]));
  let req = PullRequest {
    subpath: String::new(),
    paths: vec![],
    sqlite_safe: false,
    error_packets: false,
    max_bytes: None,
    timeout_secs: None,
  };
  let denied = pull(
    State(state.clone()),
    auth,
    Path("other".into()),
    Extension(AuditSlot::default()),
    Json(req),
  )
  .await;
  assert_eq!(denied.err().unwrap().0.code, ErrorCode::Forbidden);
  let auth = crate::host_access::tests::auth([Perm::Exec], false);
  let opts = PushOptions {
    subpath: "data".into(),
    delete: true,
    max_bytes: None,
    timeout_secs: None,
  };
  let denied = push(
    State(state),
    auth,
    Path("app".into()),
    Extension(AuditSlot::default()),
    Query(opts),
    Body::empty(),
  )
  .await;
  assert_eq!(denied.err().unwrap().0.code, ErrorCode::Forbidden);
  assert!(frame_limit(MAX_FILE_BYTES + 1, MAX_BYTES).is_err());
  assert!(join("data", "../escape").is_err());
}
