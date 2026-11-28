use std::{
  fs::{self, File, OpenOptions},
  io::{self, BufReader, BufWriter, Read, Write},
  net::SocketAddr,
  os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
  path::{Path, PathBuf},
  sync::Arc,
  time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
  Extension, Json,
  body::Body,
  extract::{ConnectInfo, State},
  http::{HeaderMap, header},
  response::{AppendHeaders, IntoResponse, Response},
};
use chacha20poly1305::{
  ChaCha20Poly1305, KeyInit, aead::AeadInPlace,
};
use flate2::{Compression, bufread::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use wharf_api_types::{ApiError, ErrorCode, view::Perm};

use crate::{
  api::AppError, audit::AuditSlot, auth::Auth, core_backup,
  db_snapshot, locks::LockSpec, login, state::AppState,
};

const FORMAT: &str = "wharf-core-export-v1";
const HEADER: usize = 48;
const CHUNK: usize = 64 * 1024;
const LIMIT: u64 = 4 * 1024 * 1024 * 1024;
pub(crate) const REQUIRED: [&str; 3] =
  ["wharf.db", "secrets.key", "core.key"];
pub(crate) const OPTIONAL: [&str; 2] =
  ["core.key.prev", "admin.token"];
const MANIFEST: &str = "manifest.json";
static EXPORTS: tokio::sync::Semaphore =
  tokio::sync::Semaphore::const_new(2);

fn conflict(message: &str) -> ApiError {
  ApiError::new(ErrorCode::Conflict, message)
}

pub(crate) fn io_error(error: io::Error) -> ApiError {
  ApiError::internal(format!("访问灾备文件失败：{error}"))
}

fn invalid_data(message: &str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) struct TempDir(pub PathBuf);

impl TempDir {
  pub fn new(parent: &Path, prefix: &str) -> Result<Self, ApiError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random)
      .map_err(|_| conflict("随机数不可用"))?;
    let path =
      parent.join(format!("{prefix}{}", hex::encode(random)));
    fs::DirBuilder::new()
      .mode(0o700)
      .create(&path)
      .map_err(io_error)?;
    Ok(Self(path))
  }
}

impl Drop for TempDir {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

pub(crate) fn private_file(path: &Path) -> Result<File, ApiError> {
  OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW)
    .open(path)
    .map_err(io_error)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
  let file = OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
    .open(path)?;
  if !file.metadata()?.is_file() {
    return Err(invalid_data("灾备文件必须是普通文件"));
  }
  Ok(file)
}

pub fn cleanup_stale(data_dir: &Path) {
  let Ok(entries) = fs::read_dir(data_dir) else {
    return;
  };
  for entry in entries.flatten() {
    let name = entry.file_name();
    let name = name.to_string_lossy();
    if name.starts_with(".wharf-export-stage-")
      || name.starts_with(".wharf-export-out-")
    {
      let _ = fs::remove_dir_all(entry.path());
    }
  }
}

struct ZeroizingKey([u8; 32]);

impl Drop for ZeroizingKey {
  fn drop(&mut self) {
    for byte in &mut self.0 {
      // 避免编译器省略密钥清零。
      unsafe { std::ptr::write_volatile(byte, 0) };
    }
  }
}

fn new_header() -> Result<[u8; HEADER], ApiError> {
  let mut header = [0; HEADER];
  header[..12].copy_from_slice(b"WHARFENC\0\x01\x01\x01");
  for (offset, value) in [(12, 65536_u32), (16, 3), (20, 1)] {
    header[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
  }
  getrandom::fill(&mut header[24..])
    .map_err(|_| conflict("随机数不可用"))?;
  Ok(header)
}

fn cipher(
  header: &[u8; HEADER],
  password: &str,
) -> Result<ChaCha20Poly1305, ApiError> {
  if &header[..12] != b"WHARFENC\0\x01\x01\x01" {
    return Err(ApiError::invalid("不支持的控制面灾备包格式"));
  }
  let param = |offset| {
    u32::from_be_bytes(header[offset..offset + 4].try_into().unwrap())
  };
  let (m, t, p) = (param(12), param(16), param(20));
  if !(8192..=262144).contains(&m)
    || !(1..=10).contains(&t)
    || !(1..=4).contains(&p)
  {
    return Err(ApiError::invalid("灾备包密钥派生参数超出范围"));
  }
  let params = Params::new(m, t, p, Some(32))
    .map_err(|_| ApiError::invalid("灾备包密钥派生参数无效"))?;
  let mut key = ZeroizingKey([0; 32]);
  Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    .hash_password_into(
      password.as_bytes(),
      &header[24..40],
      &mut key.0,
    )
    .map_err(|_| ApiError::internal("无法派生灾备包密钥"))?;
  Ok(ChaCha20Poly1305::new((&key.0).into()))
}

struct Frames<I> {
  io: I,
  cipher: ChaCha20Poly1305,
  header: [u8; HEADER],
  idx: u32,
  buffer: Vec<u8>,
  offset: usize,
  ended: bool,
}

impl<I> Frames<I> {
  fn new(
    io: I,
    header: [u8; HEADER],
    password: &str,
  ) -> Result<Self, ApiError> {
    Ok(Self {
      io,
      cipher: cipher(&header, password)?,
      header,
      idx: 0,
      buffer: Vec::with_capacity(CHUNK + 16),
      offset: 0,
      ended: false,
    })
  }

  fn frame_auth(
    &mut self,
    flag: u8,
  ) -> io::Result<([u8; 12], [u8; HEADER + 5])> {
    let index = self.idx.to_be_bytes();
    self.idx = self
      .idx
      .checked_add(1)
      .ok_or_else(|| invalid_data("灾备包分块过多"))?;
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&self.header[40..]);
    nonce[8..].copy_from_slice(&index);
    let mut aad = [0; HEADER + 5];
    aad[..HEADER].copy_from_slice(&self.header);
    aad[HEADER..HEADER + 4].copy_from_slice(&index);
    aad[HEADER + 4] = flag;
    Ok((nonce, aad))
  }
}

impl<W: Write> Frames<W> {
  fn emit(&mut self, last: bool) -> io::Result<()> {
    let flag = u8::from(last);
    let (nonce, aad) = self.frame_auth(flag)?;
    let length = self.buffer.len() as u32;
    self
      .cipher
      .encrypt_in_place((&nonce).into(), &aad, &mut self.buffer)
      .map_err(|_| invalid_data("灾备包加密失败"))?;
    self.io.write_all(&[flag])?;
    self.io.write_all(&length.to_be_bytes())?;
    self.io.write_all(&self.buffer)?;
    self.buffer.clear();
    Ok(())
  }
}

impl<W: Write> Write for Frames<W> {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    if self.buffer.len() == CHUNK {
      self.emit(false)?;
    }
    let count = buf.len().min(CHUNK - self.buffer.len());
    self.buffer.extend_from_slice(&buf[..count]);
    Ok(count)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.io.flush()
  }
}

const AUTH_FAILURE: &str = "密码不对或导出文件已损坏";

impl<R: Read> Read for Frames<R> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    if self.offset == self.buffer.len() {
      if self.ended {
        return Ok(0);
      }
      let mut frame = [0; 5];
      self.io.read_exact(&mut frame)?;
      let len =
        u32::from_be_bytes(frame[1..].try_into().unwrap()) as usize;
      let flag = frame[0];
      if flag > 1 || len > CHUNK || (flag == 0 && len != CHUNK) {
        return Err(invalid_data("灾备包帧无效"));
      }
      self.buffer.resize(len + 16, 0);
      self.io.read_exact(&mut self.buffer)?;
      let (nonce, aad) = self.frame_auth(flag)?;
      self
        .cipher
        .decrypt_in_place((&nonce).into(), &aad, &mut self.buffer)
        .map_err(|_| invalid_data(AUTH_FAILURE))?;
      self.offset = 0;
      self.ended = flag == 1;
      if self.ended && self.io.read(&mut [0])? != 0 {
        return Err(invalid_data("灾备包有多余数据"));
      }
    }
    let count = buf.len().min(self.buffer.len() - self.offset);
    buf[..count].copy_from_slice(
      &self.buffer[self.offset..self.offset + count],
    );
    self.offset += count;
    Ok(count)
  }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Artifact {
  name: String,
  size: u64,
  sha256: String,
}

impl Artifact {
  fn read(dir: &Path, name: &str) -> Result<Self, ApiError> {
    let path = dir.join(name);
    Ok(Self {
      name: name.into(),
      size: fs::metadata(&path).map_err(io_error)?.len(),
      sha256: db_snapshot::hash(&path)?,
    })
  }
}

#[derive(Serialize, Deserialize)]
struct Manifest {
  format: String,
  created_at: chrono::DateTime<chrono::Utc>,
  wharf_version: String,
  wharf_build: String,
  schema_version: usize,
  core_key_fingerprint: String,
  secrets_key_fingerprint: String,
  core_server: Option<String>,
  files: Vec<Artifact>,
}

struct Cancellable<R>(R, CancellationToken);

impl<R: Read> Read for Cancellable<R> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    if self.1.is_cancelled() {
      return Err(io::Error::other("灾备导出已取消"));
    }
    self.0.read(buf)
  }
}

fn encrypt(
  database: &Path,
  keys: &[Vec<u8>],
  output: &Path,
  manifest: &Manifest,
  password: &str,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let manifest_bytes = serde_json::to_vec(manifest)
    .map_err(|_| conflict("无法生成灾备清单"))?;
  if manifest.files.iter().map(|file| file.size).sum::<u64>()
    + manifest_bytes.len() as u64
    > LIMIT
  {
    return Err(conflict("控制面灾备包超过 4 GiB"));
  }
  let header = new_header()?;
  let mut file = private_file(output)?;
  file.write_all(&header).map_err(io_error)?;
  let frames = Frames::new(BufWriter::new(file), header, password)?;
  let mut archive =
    tar::Builder::new(GzEncoder::new(frames, Compression::default()));
  let mut item = tar::Header::new_gnu();
  item.set_mode(0o600);
  item.set_size(manifest_bytes.len() as u64);
  item.set_cksum();
  archive
    .append_data(&mut item, MANIFEST, manifest_bytes.as_slice())
    .map_err(io_error)?;
  let mut item = tar::Header::new_gnu();
  item.set_mode(0o600);
  item.set_size(manifest.files[0].size);
  item.set_cksum();
  let file = open_regular(database).map_err(io_error)?;
  archive
    .append_data(
      &mut item,
      REQUIRED[0],
      Cancellable(file, cancel.clone()),
    )
    .map_err(io_error)?;
  for (entry, contents) in manifest.files[1..].iter().zip(keys) {
    let mut item = tar::Header::new_gnu();
    item.set_mode(0o600);
    item.set_size(entry.size);
    item.set_cksum();
    archive
      .append_data(&mut item, &entry.name, contents.as_slice())
      .map_err(io_error)?;
  }
  let mut frames = archive
    .into_inner()
    .map_err(io_error)?
    .finish()
    .map_err(io_error)?;
  frames.emit(true).map_err(io_error)?;
  frames.io.flush().map_err(io_error)
}

fn decode_error(error: io::Error) -> ApiError {
  if error.to_string() == AUTH_FAILURE {
    return ApiError::new(ErrorCode::Forbidden, AUTH_FAILURE);
  }
  ApiError::invalid("导出文件被截断、已损坏或包含无效条目")
}

pub(crate) fn decrypt_to_staging(
  encrypted: &Path,
  password: &str,
  staging: &Path,
) -> Result<(), ApiError> {
  let mut file = open_regular(encrypted).map_err(io_error)?;
  let mut header = [0; HEADER];
  file.read_exact(&mut header).map_err(decode_error)?;
  let frames = Frames::new(file, header, password)?;
  let mut archive =
    tar::Archive::new(GzDecoder::new(BufReader::new(frames)));
  let mut files = std::collections::BTreeSet::new();
  let mut total: u64 = 0;
  for item in archive.entries().map_err(decode_error)?.raw(true) {
    let mut item = item.map_err(decode_error)?;
    let path = item.path().map_err(decode_error)?;
    let name = path.to_str().unwrap_or_default().to_owned();
    if !item.header().entry_type().is_file()
      || !REQUIRED.contains(&name.as_str())
        && !OPTIONAL.contains(&name.as_str())
        && name != MANIFEST
      || !files.insert(name.clone())
    {
      return Err(ApiError::invalid("灾备包包含无效或重复文件"));
    }
    let size = item.size();
    total = total.saturating_add(size);
    if total > LIMIT || name == MANIFEST && size > 65536 {
      return Err(ApiError::invalid("灾备包解压大小超出范围"));
    }
    let mut dest = private_file(&staging.join(name))?;
    if io::copy(&mut item, &mut dest).map_err(decode_error)? != size {
      return Err(ApiError::invalid("灾备包文件不完整"));
    }
    dest.sync_all().map_err(io_error)?;
  }
  let mut decoder = archive.into_inner();
  // tar 在第一个结束标记停止，继续验证 gzip 尾部和最后一个 AEAD 帧。
  let mut tail = Vec::new();
  decoder
    .by_ref()
    .take(1025)
    .read_to_end(&mut tail)
    .map_err(decode_error)?;
  if tail.len() > 1024
    || tail.iter().any(|b| *b != 0)
    || decoder.into_inner().read(&mut [0]).map_err(decode_error)? != 0
  {
    return Err(ApiError::invalid("灾备包有多余数据"));
  }
  let manifest: Manifest = serde_json::from_reader(
    open_regular(&staging.join(MANIFEST)).map_err(io_error)?,
  )
  .map_err(|_| ApiError::invalid("灾备清单无效"))?;
  if manifest.format != FORMAT {
    return Err(ApiError::invalid("灾备清单格式无效"));
  }
  files.remove(MANIFEST);
  for artifact in &manifest.files {
    if !files.remove(&artifact.name)
      || Artifact::read(staging, &artifact.name)? != *artifact
    {
      return Err(ApiError::invalid("灾备包文件校验失败"));
    }
  }
  if !files.is_empty() {
    return Err(ApiError::invalid("灾备包包含未登记的文件"));
  }
  Ok(())
}

async fn build(
  state: Arc<AppState>,
  password: String,
  cancel: CancellationToken,
) -> Result<(TempDir, PathBuf, u64, String), ApiError> {
  let _maintenance = state
    .locks
    .acquire(LockSpec::CoreMaintenance, "导出控制面备份")?;
  let _key = state.key.operation.lock().await;
  let data_dir = &state.data_dir;
  let needed = ["wharf.db", "wharf.db-wal"]
    .iter()
    .try_fold(0_u64, |sum, name| {
      match fs::metadata(data_dir.join(name)) {
        Ok(m) => Ok(sum.saturating_add(m.len())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(sum),
        Err(e) => Err(io_error(e)),
      }
    })?
    .saturating_mul(2)
    .saturating_add(64 * 1024 * 1024);
  if db_snapshot::free_bytes(data_dir)? < needed {
    return Err(conflict("磁盘空间不足，无法导出控制面备份"));
  }
  let stage = TempDir::new(data_dir, ".wharf-export-stage-")?;
  let output = TempDir::new(data_dir, ".wharf-export-out-")?;
  let path = output.0.join("backup.enc");
  let staging_db = stage.0.join("wharf.db");
  let snapshot_cancel = cancel.clone();
  let (schema_version, stage) = state
    .db
    .call(move |c| {
      let started = Instant::now();
      db_snapshot::vacuum_into(c, &staging_db, move || {
        snapshot_cancel.is_cancelled()
          || started.elapsed() >= db_snapshot::TIMEOUT
      })?;
      fs::set_permissions(
        staging_db,
        fs::Permissions::from_mode(0o600),
      )
      .map_err(io_error)?;
      Ok((db_snapshot::schema_version(c)?, stage))
    })
    .await?;
  let snap = crate::snapshot::load(&state.db).await?;
  let core_server = crate::core_node::server_of(&snap);
  let dir = data_dir.clone();
  let exported = path.clone();
  let (size, sha256) = tokio::task::spawn_blocking(move || {
    let mut files = vec![Artifact::read(&stage.0, "wharf.db")?];
    let mut keys = Vec::new();
    // 密钥与 token 直接送进加密流，暂存目录仅用于 SQLite。
    for name in REQUIRED[1..].iter().chain(OPTIONAL.iter()) {
      match open_regular(&dir.join(name)) {
        Ok(source) => {
          let mut bytes = Vec::new();
          source
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
          if bytes.len() > 65536 {
            return Err(conflict("控制面凭据文件超出大小限制"));
          }
          files.push(Artifact {
            name: (*name).into(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
          });
          keys.push(bytes);
        }
        Err(e)
          if e.kind() == io::ErrorKind::NotFound
            && OPTIONAL.contains(name) => {}
        Err(e) => return Err(io_error(e)),
      }
    }
    let manifest = Manifest {
      format: FORMAT.into(),
      created_at: chrono::Utc::now(),
      wharf_version: wharf_api_types::VERSION.into(),
      wharf_build: wharf_api_types::BUILD.into(),
      schema_version,
      core_key_fingerprint: files[2].sha256.clone(),
      secrets_key_fingerprint: files[1].sha256.clone(),
      core_server,
      files,
    };
    encrypt(
      &stage.0.join("wharf.db"),
      &keys,
      &exported,
      &manifest,
      &password,
      &cancel,
    )?;
    drop(stage);
    Ok::<_, ApiError>((
      fs::metadata(&exported).map_err(io_error)?.len(),
      db_snapshot::hash(&exported)?,
    ))
  })
  .await
  .map_err(|_| conflict("控制面灾备包生成异常结束"))??;
  Ok((output, path, size, sha256))
}

pub async fn export(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Extension(audit): Extension<AuditSlot>,
  Json(req): Json<core_backup::PasswordRequest>,
) -> Result<Response, AppError> {
  auth.require(Perm::Admin)?;
  let source = core_backup::password_source(peer, &headers)?;
  let (_, hash) = login::admin(&s.db)
    .await?
    .ok_or_else(|| ApiError::invalid("尚未设置管理员密码"))?;
  core_backup::verify_backup_password(
    &s,
    &auth,
    &audit,
    &source,
    login::source(peer.ip(), &headers),
    req.password.clone(),
    hash,
  )
  .await?;
  let permit = EXPORTS.try_acquire().map_err(|_| {
    ApiError::new(ErrorCode::Busy, "已有两份控制面灾备包正在导出")
  })?;
  let cancel = CancellationToken::new();
  let _cancel = cancel.clone().drop_guard();
  let state = s.clone();
  let (output, path, size, sha256, permit) =
    tokio::spawn(async move {
      let (output, path, size, sha256) =
        build(state, req.password, cancel).await?;
      Ok::<_, ApiError>((output, path, size, sha256, permit))
    })
    .await
    .map_err(|_| conflict("控制面灾备导出异常结束"))??;
  let file = tokio::fs::File::open(path).await.map_err(io_error)?;
  audit.require_record("导出了控制面离线加密灾备包".into());
  crate::security_receipt::send(
    &s,
    &auth.name,
    &source,
    "导出控制面离线加密灾备包".into(),
  )
  .await;
  let stream = futures_util::StreamExt::map(
    ReaderStream::new(file),
    move |item| {
      let _keep = (&output, &permit);
      item
    },
  );
  let filename = format!(
    "wharf-core-{}.wharf-core.enc",
    chrono::Utc::now().format("%Y%m%d-%H%M%S")
  );
  Ok(
    (
      AppendHeaders([
        (header::CONTENT_TYPE, "application/octet-stream".into()),
        (header::CONTENT_LENGTH, size.to_string()),
        (header::CACHE_CONTROL, "no-store".into()),
        (
          header::CONTENT_DISPOSITION,
          format!("attachment; filename=\"{filename}\""),
        ),
        (
          axum::http::HeaderName::from_static("x-wharf-file-sha256"),
          sha256,
        ),
        (
          axum::http::HeaderName::from_static(
            "x-wharf-export-format",
          ),
          FORMAT.into(),
        ),
      ]),
      Body::from_stream(stream),
    )
      .into_response(),
  )
}

#[cfg(test)]
mod tests;
