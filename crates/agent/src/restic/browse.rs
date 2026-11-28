use std::{
  collections::{BTreeMap, HashMap},
  fs::File,
  os::{unix::ffi::OsStrExt, unix::fs::FileExt},
  sync::{Arc, Mutex, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
  io::{AsyncReadExt, AsyncSeekExt},
  sync::{OwnedSemaphorePermit, Semaphore},
};
use wharf_api_types::{
  agent::FileChunk,
  backup::{
    BackupExtractMeta, BackupFileEntry, BackupLsView, EXTRACT_CHUNK,
    EXTRACT_LIMIT, normalize_snapshot_rel,
  },
};

use super::*;

const TTL: Duration = Duration::from_secs(600);
pub(super) const INDEX_BYTES: u64 = 96 << 20;
pub(super) const DIFF_SCAN_CAP: usize = 100_000;

pub(super) fn entry_limit(limit: u32) -> usize {
  if limit == 0 {
    500
  } else {
    limit.min(5000) as usize
  }
}

#[derive(Deserialize)]
struct Record {
  #[serde(default)]
  struct_type: String,
  #[serde(default)]
  id: String,
  #[serde(default)]
  path: String,
  #[serde(default, rename = "type")]
  kind: String,
  #[serde(default)]
  size: u64,
  #[serde(default)]
  mode: u32,
  mtime: Option<chrono::DateTime<chrono::Utc>>,
  linktarget: Option<String>,
}

pub(super) type Index = BTreeMap<String, BackupFileEntry>;

pub(super) async fn index(
  j: &Job<'_>,
  root: &Path,
  id: &str,
  paths: &[&str],
  recursive: bool,
  ctx: &Ctx,
) -> Result<(String, Index, bool), ApiError> {
  check_snapshot(id)?;
  let mut args = vec!["ls", "--json"];
  if recursive {
    args.push("--recursive");
  }
  args.push(id);
  args.extend_from_slice(paths);
  let mut bytes = Vec::new();
  j.restic_to(&args, INDEX_BYTES, &mut bytes, ctx).await?;
  read_index(root, &bytes)
}

fn read_index(
  root: &Path,
  bytes: &[u8],
) -> Result<(String, Index, bool), ApiError> {
  let mut id = None;
  let mut nodes = Index::new();
  for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
    let r: Record = serde_json::from_slice(line)
      .map_err(|_| ApiError::internal("快照文件索引格式错误"))?;
    if r.struct_type == "snapshot" {
      check_snapshot(&r.id)?;
      if r.id.len() != 64 {
        return Err(ApiError::internal("restic 未返回完整快照 id"));
      }
      id = Some(r.id);
      continue;
    }
    if r.struct_type != "node" {
      continue;
    }
    let Ok(rel) = Path::new(&r.path).strip_prefix(root) else {
      continue;
    };
    let Some(rel) = rel.to_str() else { continue };
    if normalize_snapshot_rel(rel).is_err() {
      continue;
    }
    if nodes.len() >= DIFF_SCAN_CAP {
      return Ok((id.ok_or_else(no_snapshot)?, nodes, true));
    }
    let name = Path::new(&r.path)
      .file_name()
      .and_then(|n| n.to_str())
      .unwrap_or("")
      .to_owned();
    nodes.insert(
      rel.to_owned(),
      BackupFileEntry {
        path: rel.to_owned(),
        name,
        kind: r.kind,
        size: r.size,
        mode: r.mode & 0o777,
        modified: r.mtime,
        link_target: r.linktarget,
      },
    );
  }
  Ok((id.ok_or_else(no_snapshot)?, nodes, false))
}

fn no_snapshot() -> ApiError {
  ApiError::not_found("没有找到快照")
}

fn text(path: &Path) -> Result<&str, ApiError> {
  path
    .to_str()
    .ok_or_else(|| ApiError::invalid("快照路径无效"))
}

pub(super) async fn list(
  j: &Job<'_>,
  root: &Path,
  id: &str,
  path: &str,
  recursive: bool,
  limit: u32,
  ctx: &Ctx,
) -> Result<BackupLsView, ApiError> {
  let path = normalize_snapshot_rel(path)?;
  let full = root.join(path);
  let (snapshot, nodes, capped) =
    index(j, root, id, &[text(&full)?], recursive, ctx).await?;
  let (entries, truncated) =
    list_entries(nodes, path, recursive, entry_limit(limit))?;
  Ok(BackupLsView {
    service: j.service.into(),
    target: String::new(),
    snapshot,
    path: path.into(),
    recursive,
    entries,
    truncated: capped || truncated,
  })
}

fn list_entries(
  nodes: Index,
  path: &str,
  recursive: bool,
  limit: usize,
) -> Result<(Vec<BackupFileEntry>, bool), ApiError> {
  let prefix = if path.is_empty() {
    String::new()
  } else {
    format!("{path}/")
  };
  let mut entries = Vec::new();
  if !nodes.contains_key(path)
    && !nodes.keys().any(|p| p.starts_with(&prefix))
  {
    return Err(ApiError::not_found("快照中没有这个路径"));
  }
  for (rel, entry) in nodes {
    if rel == path {
      if entry.kind != "dir" {
        entries.push(entry);
      }
    } else if let Some(tail) = rel.strip_prefix(&prefix)
      && (recursive || !tail.contains('/'))
    {
      entries.push(entry);
    }
  }
  entries.sort_by(|a, b| {
    (b.kind == "dir")
      .cmp(&(a.kind == "dir"))
      .then(a.path.cmp(&b.path))
  });
  let truncated = entries.len() > limit;
  entries.truncate(limit);
  Ok((entries, truncated))
}

fn extract_node<'a>(
  nodes: &'a Index,
  path: &str,
) -> Result<&'a BackupFileEntry, ApiError> {
  let ancestors: Vec<_> =
    Path::new(path).ancestors().skip(1).collect();
  for dir in ancestors.into_iter().rev() {
    let entry = nodes
      .get(text(dir)?)
      .ok_or_else(|| ApiError::not_found("未找到快照中的父目录"))?;
    if entry.kind != "dir" {
      return Err(ApiError::invalid("路径包含符号链接或非目录祖先"));
    }
  }
  let entry = nodes
    .get(path)
    .ok_or_else(|| ApiError::not_found("快照中没有这个文件"))?;
  if entry.kind != "file" {
    return Err(
      ApiError::invalid("只能提取单个普通文件，路径不能是软链或目录")
        .with_hint("先用 wharf backup ls 确认快照路径"),
    );
  }
  Ok(entry)
}

struct Session {
  service: String,
  file: Arc<File>,
  size: u64,
  _permit: OwnedSemaphorePermit,
}

pub(crate) struct ExtractStore {
  dir: PathBuf,
  directory: OnceLock<DirFd>,
  slots: Arc<Semaphore>,
  sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl ExtractStore {
  pub(crate) fn new(data: &Path) -> Self {
    Self {
      dir: data.to_owned(),
      directory: OnceLock::new(),
      slots: Arc::new(Semaphore::new(4)),
      sessions: Default::default(),
    }
  }

  fn temporary(&self, token: &str) -> Result<File, ApiError> {
    let dir = if let Some(dir) = self.directory.get() {
      dir
    } else {
      let dir = DirFd::open_dir(&self.dir)
        .and_then(|base| base.ensure_subdir(c".wharf-extract", 0o700))
        .map_err(io_err(&self.dir))?;
      let st = dir.stat_self().map_err(io_err(&self.dir))?;
      if st.st_mode & 0o077 != 0 {
        return Err(ApiError::invalid("提取暂存目录必须为私有目录"));
      }
      // 文件打开后立即解除路径，进程无论怎样退出都会释放占用。
      let _ = self.directory.set(dir);
      self.directory.get().expect("已初始化暂存目录")
    };
    let name =
      component(std::ffi::OsStr::from_bytes(token.as_bytes()))
        .map_err(io_err(&self.dir))?;
    let file = dir
      .open_file(
        &name,
        libc::O_RDWR
          | libc::O_CREAT
          | libc::O_EXCL
          | libc::O_NOFOLLOW
          | libc::O_CLOEXEC,
        0o600,
      )
      .map_err(io_err(&self.dir))?;
    dir.unlink(&name).map_err(io_err(&self.dir))?;
    Ok(file.into())
  }

  pub(super) async fn prepare(
    &self,
    j: &Job<'_>,
    root: &Path,
    id: &str,
    path: &str,
    max_bytes: u64,
    ctx: &Ctx,
  ) -> Result<BackupExtractMeta, ApiError> {
    let path = normalize_snapshot_rel(path)?;
    if path.is_empty() {
      return Err(ApiError::invalid("请指定快照中的普通文件"));
    }
    let permit =
      self.slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(ErrorCode::Busy, "已有 4 个提取会话")
      })?;
    let full = root.join(path);
    let paths: Vec<_> = full
      .ancestors()
      .take_while(|p| p.starts_with(root))
      .map(text)
      .collect::<Result<_, _>>()?;
    let (snapshot, nodes, capped) =
      index(j, root, id, &paths, false, ctx).await?;
    if capped {
      return Err(ApiError::invalid(
        "快照索引过大，无法确认提取路径安全",
      ));
    }
    let node = extract_node(&nodes, path)?;
    let limit = max_bytes.min(EXTRACT_LIMIT);
    if node.size > limit {
      return Err(
        ApiError::invalid("文件超过单文件提取上限（512 MiB）")
          .with_hint("大文件可在备份机处理或使用整目录恢复"),
      );
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce)
      .map_err(|_| ApiError::internal("随机数不可用"))?;
    let token = hex::encode(nonce);
    let mut file = tokio::fs::File::from_std(self.temporary(&token)?);
    j.restic_to(
      &["dump", &snapshot, text(&full)?],
      node.size,
      &mut file,
      ctx,
    )
    .await?;
    file
      .seek(std::io::SeekFrom::Start(0))
      .await
      .map_err(io_err(&self.dir))?;
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut chunk = vec![0; EXTRACT_CHUNK as usize];
    loop {
      if ctx.cancel.is_cancelled() {
        return Err(ApiError::new(
          ErrorCode::Cancelled,
          "提取已取消",
        ));
      }
      let read =
        file.read(&mut chunk).await.map_err(io_err(&self.dir))?;
      if read == 0 {
        break;
      }
      size += read as u64;
      hash.update(&chunk[..read]);
    }
    if size != node.size {
      return Err(ApiError::internal("提取的文件大小和快照不一致"));
    }
    let file = Arc::new(file.into_std().await);
    self.sessions.lock().unwrap().insert(
      token.clone(),
      Session {
        service: j.service.into(),
        file,
        size,
        _permit: permit,
      },
    );
    let sessions = Arc::downgrade(&self.sessions);
    let expire = token.clone();
    tokio::spawn(async move {
      tokio::time::sleep(TTL).await;
      if let Some(sessions) = sessions.upgrade() {
        sessions.lock().unwrap().remove(&expire);
      }
    });
    Ok(BackupExtractMeta {
      token,
      size,
      mode: node.mode,
      name: node.name.clone(),
      snapshot,
      sha256: hex::encode(hash.finalize()),
    })
  }

  pub(crate) fn read(
    &self,
    service: &str,
    token: &str,
    offset: u64,
    len: u32,
  ) -> Result<FileChunk, ApiError> {
    let (file, size) = self
      .sessions
      .lock()
      .unwrap()
      .get(token)
      .filter(|s| s.service == service)
      .map(|s| (s.file.clone(), s.size))
      .ok_or_else(|| ApiError::not_found("提取会话已关闭"))?;
    if len == 0 || len > EXTRACT_CHUNK || offset > size {
      return Err(ApiError::invalid("提取分块范围无效"));
    }
    let end = size.min(offset + u64::from(len));
    let mut bytes = vec![0; (end - offset) as usize];
    file
      .read_exact_at(&mut bytes, offset)
      .map_err(io_err(&self.dir))?;
    Ok(FileChunk {
      data: STANDARD.encode(bytes),
      size,
      version: None,
      mode: None,
    })
  }

  pub(crate) fn close(&self, service: &str, token: &str) {
    let mut sessions = self.sessions.lock().unwrap();
    if sessions.get(token).is_some_and(|s| s.service == service) {
      sessions.remove(token);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn fixture() -> Index {
    let mut input = format!(
      "{{\"struct_type\":\"snapshot\",\"id\":\"{}\"}}\n",
      "a".repeat(64)
    );
    for (path, kind) in [
      ("/srv/app", "dir"),
      ("/srv/app/a.txt", "file"),
      ("/srv/app/sub", "dir"),
      ("/srv/app/sub/b.txt", "file"),
      ("/other/file", "file"),
      ("/srv/app/link", "symlink"),
      ("/srv/app/link/private", "file"),
    ] {
      input.push_str(&format!("{{\"struct_type\":\"node\",\"path\":\"{path}\",\"type\":\"{kind}\"}}\n"));
    }
    read_index(Path::new("/srv/app"), input.as_bytes())
      .unwrap()
      .1
  }

  #[test]
  fn ls_normalizes_path_and_filters_direct_children() {
    assert!(normalize_snapshot_rel("../etc").is_err());
    let (entries, _) =
      list_entries(fixture(), "", false, 10).unwrap();
    assert_eq!(
      entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
      ["sub", "a.txt", "link"]
    );
  }

  #[test]
  fn extract_rejects_symlink_node_and_symlink_ancestor() {
    let nodes = fixture();
    for path in ["link", "link/private", "link/deep/private"] {
      assert_eq!(
        extract_node(&nodes, path).unwrap_err().code,
        ErrorCode::InvalidInput
      );
    }
    assert!(extract_node(&nodes, "sub/b.txt").is_ok());
  }
}
