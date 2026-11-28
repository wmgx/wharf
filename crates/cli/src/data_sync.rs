use crate::{
  client::{CliError, CliResult, Client, seg},
  print,
};
use clap::{Args, Subcommand};
use futures_util::{StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use std::{
  collections::{BTreeMap, BTreeSet},
  ffi::{CStr, CString},
  fs::File,
  io,
  os::{
    fd::{AsRawFd, FromRawFd, IntoRawFd},
    unix::{
      ffi::OsStrExt,
      fs::{MetadataExt, PermissionsExt},
    },
  },
  path::{Component, Path, PathBuf},
  time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::io::{ReaderStream, StreamReader};
use wharf_api_types::{ApiError, ErrorCode, data_sync::*};
#[derive(Subcommand)]
pub enum DataCmd {
  /// 拉取服务数据到本地。
  Pull {
    #[command(flatten)]
    common: TransferArgs,
    #[arg(long)]
    sqlite_safe: bool,
  },
  /// 比较本地和远端数据，加 --apply 执行。
  Push {
    #[command(flatten)]
    common: TransferArgs,
    #[arg(long)]
    apply: bool,
  },
}
#[derive(Args)]
pub struct TransferArgs {
  service: String,
  local_dir: PathBuf,
  #[arg(long)]
  path: Option<String>,
  #[arg(long)]
  exclude: Vec<String>,
  #[arg(long)]
  delete: bool,
  #[arg(long, value_parser = parse_size)]
  max_size: Option<u64>,
  #[arg(long)]
  timeout: Option<u64>,
}
fn parse_size(input: &str) -> Result<u64, String> {
  let invalid = || "大小格式为字节数或 512M、1G，最大 1G".to_owned();
  let input = input.trim().to_ascii_uppercase();
  let (digits, scale) = match input.as_bytes().last() {
    Some(b'K') => (&input[..input.len() - 1], 1 << 10),
    Some(b'M') => (&input[..input.len() - 1], 1 << 20),
    Some(b'G') => (&input[..input.len() - 1], 1 << 30),
    _ => (input.as_str(), 1),
  };
  digits
    .parse::<u64>()
    .ok()
    .and_then(|v| v.checked_mul(scale))
    .filter(|v| *v <= MAX_BYTES)
    .ok_or_else(invalid)
}
const NOFOLLOW: libc::c_int =
  libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const DIRECTORY: libc::c_int =
  libc::O_RDONLY | libc::O_DIRECTORY | NOFOLLOW;
fn cstr(bytes: impl AsRef<[u8]>) -> io::Result<CString> {
  CString::new(bytes.as_ref()).map_err(io::Error::other)
}
fn open(
  parent: &File,
  name: &CStr,
  flags: libc::c_int,
  mode: libc::c_uint,
) -> io::Result<File> {
  let fd = unsafe {
    libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode)
  };
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}
fn mkdir(parent: &File, name: &CStr) -> io::Result<()> {
  let rc = unsafe {
    libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755)
  };
  if rc < 0 {
    let err = io::Error::last_os_error();
    if err.kind() != io::ErrorKind::AlreadyExists {
      return Err(err);
    }
  }
  Ok(())
}
fn local_root(path: &Path, create: bool) -> io::Result<File> {
  let mut dir =
    File::open(if path.is_absolute() { "/" } else { "." })?;
  for part in path.components() {
    let name = match part {
      Component::RootDir | Component::CurDir => continue,
      Component::ParentDir => c"..".to_owned(),
      Component::Normal(part) => cstr(part.as_bytes())?,
      _ => return Err(io::Error::other("本地目录无效")),
    };
    if create {
      mkdir(&dir, &name)?;
    }
    dir = open(&dir, &name, DIRECTORY, 0)?;
  }
  Ok(dir)
}
fn parent(
  root: &File,
  path: &str,
  create: bool,
) -> io::Result<(File, CString)> {
  let parts = path_parts(path).map_err(io::Error::other)?;
  let (name, dirs) = parts
    .split_last()
    .ok_or_else(|| io::Error::other("需要文件路径"))?;
  let mut dir = root.try_clone()?;
  for part in dirs {
    let name = cstr(part)?;
    if create {
      mkdir(&dir, &name)?;
    }
    dir = open(&dir, &name, DIRECTORY, 0)?;
  }
  Ok((dir, cstr(name)?))
}
fn read_names(parent: &File) -> io::Result<Vec<CString>> {
  struct Dir(*mut libc::DIR);
  impl Drop for Dir {
    fn drop(&mut self) {
      unsafe {
        libc::closedir(self.0);
      }
    }
  }
  let fd = open(parent, c".", DIRECTORY, 0)?;
  let dir = unsafe { libc::fdopendir(fd.as_raw_fd()) };
  if dir.is_null() {
    return Err(io::Error::last_os_error());
  }
  let _ = fd.into_raw_fd();
  let dir = Dir(dir);
  let mut names = Vec::new();
  loop {
    #[cfg(target_os = "linux")]
    let errno = unsafe { libc::__errno_location() };
    #[cfg(target_os = "macos")]
    let errno = unsafe { libc::__error() };
    let entry = unsafe {
      *errno = 0;
      libc::readdir(dir.0)
    };
    if entry.is_null() {
      if unsafe { *errno } != 0 {
        return Err(io::Error::last_os_error());
      }
      break;
    }
    let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
    if !matches!(name.to_bytes(), b"." | b"..") {
      names.push(name.to_owned());
      if names.len() > MAX_MANIFEST {
        return Err(io::Error::other("本地文件数超过上限"));
      }
    }
  }
  names.sort_unstable();
  Ok(names)
}
fn stat(parent: &File, name: &CStr) -> io::Result<libc::stat> {
  let mut st = std::mem::MaybeUninit::uninit();
  if unsafe {
    libc::fstatat(
      parent.as_raw_fd(),
      name.as_ptr(),
      st.as_mut_ptr(),
      libc::AT_SYMLINK_NOFOLLOW,
    )
  } < 0
  {
    Err(io::Error::last_os_error())
  } else {
    Ok(unsafe { st.assume_init() })
  }
}
fn local_manifest(
  dir: &File,
  prefix: &str,
  excludes: &[String],
  out: &mut DataManifestResult,
  budget: &mut u64,
) -> io::Result<()> {
  for name in read_names(dir)? {
    if out.entries.len() + out.skipped_special.len() >= MAX_MANIFEST {
      return Err(io::Error::other("本地文件数超过上限"));
    }
    let Ok(part) = name.to_str() else {
      out
        .skipped_special
        .push(format!("{prefix}[非 UTF-8 文件名]"));
      continue;
    };
    let path = format!("{prefix}{part}");
    if excluded(&path, excludes) {
      continue;
    }
    let mode = stat(dir, &name)?.st_mode;
    let kind = mode & libc::S_IFMT;
    if path_parts(&path).is_err()
      || !matches!(kind, libc::S_IFREG | libc::S_IFDIR)
    {
      out.skipped_special.push(path);
      continue;
    }
    let is_dir = kind == libc::S_IFDIR;
    let file = open(
      dir,
      &name,
      if is_dir {
        DIRECTORY
      } else {
        libc::O_RDONLY | NOFOLLOW
      },
      0,
    )?;
    let meta = file.metadata()?;
    if !is_dir && !meta.is_file() {
      return Err(io::Error::other("本地文件类型已变化"));
    }
    let size = if is_dir { 0 } else { meta.len() };
    let sha256 = if !is_dir && size <= (*budget).min(4 << 20) {
      use std::io::Read;
      let mut bytes = Vec::new();
      (&file).take(size + 1).read_to_end(&mut bytes)?;
      if bytes.len() as u64 != size {
        return Err(io::Error::other("本地文件大小已变化"));
      }
      *budget -= size;
      Some(hex::encode(Sha256::digest(bytes)))
    } else {
      None
    };
    out.entries.push(DataFileEntry {
      path: path.clone(),
      dir: is_dir,
      size,
      mtime_ms: meta.mtime().saturating_mul(1000),
      mode: meta.mode() & 0o777,
      sha256,
    });
    if is_dir {
      local_manifest(
        &file,
        &format!("{path}/"),
        excludes,
        out,
        budget,
      )?;
    }
  }
  Ok(())
}
fn same(a: &DataFileEntry, b: &DataFileEntry) -> bool {
  a.dir == b.dir
    && (a.dir
      || (a.size == b.size
        && a
          .sha256
          .as_ref()
          .zip(b.sha256.as_ref())
          .is_some_and(|(a, b)| a == b)))
}
fn transfer_plan(
  source: &DataManifestResult,
  target: &DataManifestResult,
  delete: bool,
) -> CliResult<DataPushPlan> {
  let dest: BTreeMap<_, _> = target
    .entries
    .iter()
    .map(|entry| (entry.path.as_str(), entry))
    .collect();
  let src: BTreeSet<_> = source
    .entries
    .iter()
    .map(|entry| entry.path.as_str())
    .collect();
  let skipped: BTreeSet<_> = source
    .skipped_special
    .iter()
    .chain(&target.skipped_special)
    .cloned()
    .collect();
  let obstructed = |path: &str| {
    skipped.iter().any(|skip| {
      path == skip
        || path
          .strip_prefix(skip)
          .is_some_and(|tail| tail.starts_with('/'))
    })
  };
  let diff = |entry: &DataFileEntry| DataDiffEntry {
    path: entry.path.clone(),
    size: entry.size,
    dir: entry.dir,
  };
  let mut result = DataPushPlan {
    dry_run: true,
    added: Vec::new(),
    mkdirs: Vec::new(),
    modified: Vec::new(),
    deleted: Vec::new(),
    total_bytes: 0,
    skipped: Vec::new(),
    warnings: Vec::new(),
    hint: "加 --apply 执行推送".into(),
  };
  for entry in &source.entries {
    path_parts(&entry.path)?;
    if obstructed(&entry.path) {
      continue;
    }
    match dest.get(entry.path.as_str()) {
      Some(other) if other.dir != entry.dir => {
        return Err(
          ApiError::invalid(format!("文件类型冲突：{}", entry.path))
            .into(),
        );
      }
      Some(other) if same(entry, other) => continue,
      Some(_) => result.modified.push(diff(entry)),
      None => result.added.push(diff(entry)),
    }
    result.total_bytes =
      result.total_bytes.saturating_add(entry.size);
  }
  if delete {
    for entry in &target.entries {
      path_parts(&entry.path)?;
      if !src.contains(entry.path.as_str())
        && !obstructed(&entry.path)
        && !skipped.iter().any(|p| {
          p.strip_prefix(&entry.path)
            .is_some_and(|tail| tail.starts_with('/'))
        })
      {
        result.deleted.push(diff(entry));
      }
    }
  }
  result.skipped = skipped.into_iter().collect();
  if !result.skipped.is_empty() {
    result
      .warnings
      .push("已跳过符号链接、特殊文件或保留路径".into());
  }
  Ok(result)
}
pub(crate) async fn run(
  c: &Client,
  cmd: DataCmd,
  j: bool,
) -> CliResult<()> {
  let future = async {
    match cmd {
      DataCmd::Push { common, apply } => {
        sync(c, common, Some(apply), false, j).await
      }
      DataCmd::Pull {
        common,
        sqlite_safe,
      } => sync(c, common, None, sqlite_safe, j).await,
    }
  };
  tokio::select! {
    result = future => result,
    _ = tokio::signal::ctrl_c() => Err(CliError::Exit(130)),
  }
}
async fn sync(
  c: &Client,
  args: TransferArgs,
  push: Option<bool>,
  sqlite: bool,
  j: bool,
) -> CliResult<()> {
  let (service, short) = args
    .service
    .split_once(':')
    .map_or((args.service.as_str(), None), |(s, p)| (s, Some(p)));
  if short.is_some() && args.path.is_some() {
    return Err(
      ApiError::invalid("服务名中的路径和 --path 只能给一个").into(),
    );
  }
  wharf_api_types::validate_name("服务", service)?;
  let subpath = short.or(args.path.as_deref()).unwrap_or_default();
  path_parts(subpath)?;
  let endpoint = format!("/api/services/{}/data", seg(service));
  let timeout =
    Duration::from_secs(args.timeout.unwrap_or(1800).clamp(10, 7200));
  let manifest_req = ManifestRequest {
    subpath: subpath.into(),
    excludes: args.exclude.clone(),
    ..Default::default()
  };
  let mut remote: DataManifestResult = c
    .post_timeout(
      &format!("{endpoint}/manifest"),
      &manifest_req,
      timeout,
    )
    .await?;
  if remote.truncated {
    return Err(
      ApiError::invalid("远端文件数超过上限，请缩小 --path 范围")
        .into(),
    );
  }
  let root = match local_root(&args.local_dir, false) {
    Ok(root) => Some(root),
    Err(err)
      if err.kind() == io::ErrorKind::NotFound && push.is_none() =>
    {
      None
    }
    Err(err) => return Err(anyhow::Error::from(err).into()),
  };
  let mut local = DataManifestResult::default();
  if let Some(root) = &root {
    local_manifest(
      root,
      "",
      &args.exclude,
      &mut local,
      &mut (32 << 20),
    )
    .map_err(anyhow::Error::from)?;
  }
  let mut warnings = Vec::new();
  if push.is_none() && sqlite {
    let sources: BTreeSet<_> = remote
      .entries
      .iter()
      .filter(|e| !e.dir && is_sqlite(&e.path))
      .map(|e| e.path.clone())
      .collect();
    remote.entries.retain_mut(|e| {
      if is_sqlite(&e.path) {
        e.sha256 = None;
      }
      !["-wal", "-shm", "-journal"].iter().any(|suffix| {
        e.path
          .strip_suffix(suffix)
          .is_some_and(|p| sources.contains(p))
      })
    });
    for e in &local.entries {
      if ["-wal", "-shm", "-journal"].iter().any(|suffix| {
        e.path
          .strip_suffix(suffix)
          .is_some_and(|p| sources.contains(p))
      }) {
        return Err(
          ApiError::new(
            ErrorCode::Conflict,
            format!("本地 SQLite 有日志文件：{}", e.path),
          )
          .with_hint("关闭本地数据库，或拉到空目录")
          .into(),
        );
      }
    }
  } else if push.is_none() && !remote.sqlite_wal_files.is_empty() {
    warnings.push(
      "发现 SQLite WAL，建议加 --sqlite-safe 取得一致快照".into(),
    );
  }
  let (source, target) = if push.is_some() {
    (&local, &remote)
  } else {
    (&remote, &local)
  };
  let mut plan = transfer_plan(source, target, args.delete)?;
  let limit = args.max_size.unwrap_or(MAX_FILE_BYTES);
  let changed: Vec<_> =
    plan.added.iter().chain(&plan.modified).cloned().collect();
  if changed.len() + plan.deleted.len() > MAX_FILES
    || plan.total_bytes > limit
    || changed.iter().any(|e| e.size > MAX_FILE_BYTES)
  {
    return Err(ApiError::invalid("文件数或大小超过传输上限").into());
  }
  plan.warnings.extend(warnings);
  if push == Some(false) {
    plan.mkdirs = plan
      .added
      .iter()
      .filter(|e| e.dir)
      .map(|e| e.path.clone())
      .collect();
    plan.added.retain(|e| !e.dir);
    crate::commands::out(j, &plan, |p| {
      println!(
        "新增 {}，修改 {}，删除 {}，共 {} 字节",
        p.added.len(),
        p.modified.len(),
        p.deleted.len(),
        p.total_bytes
      );
      for w in &p.warnings {
        println!("{w}");
      }
      println!("{}", p.hint);
    });
    return Ok(());
  }
  let root = match root {
    Some(root) => root,
    None => local_root(&args.local_dir, true)
      .map_err(anyhow::Error::from)?,
  };
  let mut result = if push.is_some() {
    let opts = PushOptions {
      subpath: subpath.into(),
      delete: args.delete,
      max_bytes: args.max_size,
      timeout_secs: args.timeout,
    };
    let (read, write) = tokio::io::duplex(CHUNK);
    let body = reqwest::Body::wrap_stream(ReaderStream::new(read));
    let upload =
      c.data_push(&format!("{endpoint}/push"), &opts, body, timeout);
    let produce = send_frames(root, changed, plan.deleted, write);
    let (response, ()) = tokio::try_join!(upload, async {
      produce
        .await
        .map_err(anyhow::Error::from)
        .map_err(CliError::from)
    })?;
    response
  } else {
    for entry in changed.iter().filter(|e| e.dir) {
      let (dir, name) = parent(&root, &entry.path, true)
        .map_err(anyhow::Error::from)?;
      mkdir(&dir, &name).map_err(anyhow::Error::from)?;
      open(&dir, &name, DIRECTORY, 0).map_err(anyhow::Error::from)?;
    }
    let paths: Vec<_> = changed
      .into_iter()
      .filter(|e| !e.dir)
      .map(|e| e.path)
      .collect();
    let response = c
      .data_pull(
        &format!("{endpoint}/pull"),
        &PullRequest {
          subpath: subpath.into(),
          paths: paths.clone(),
          sqlite_safe: sqlite,
          max_bytes: args.max_size,
          timeout_secs: args.timeout,
        },
        timeout,
      )
      .await?;
    let stream = response.bytes_stream().map_err(io::Error::other);
    let mut response = StreamReader::new(stream.boxed());
    let mut result =
      receive_frames(&root, &mut response, paths, limit)
        .await
        .map_err(anyhow::Error::from)?;
    plan.deleted.sort_unstable_by_key(|e| {
      std::cmp::Reverse(e.path.matches('/').count())
    });
    for entry in plan.deleted {
      let (dir, name) = parent(&root, &entry.path, false)
        .map_err(anyhow::Error::from)?;
      let mode =
        stat(&dir, &name).map_err(anyhow::Error::from)?.st_mode;
      if !matches!(mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
      {
        return Err(
          ApiError::invalid("不能删除本地链接或特殊文件").into(),
        );
      }
      unlink(&dir, &name, entry.dir).map_err(anyhow::Error::from)?;
      result.deleted += 1;
    }
    result
  };
  result.warnings.extend(plan.warnings);
  if push.is_some() {
    result.uploaded = Some(result.files);
  } else {
    result.downloaded = Some(result.files);
  }
  crate::commands::out(j, &result, |r| {
    println!(
      "传输 {} 个文件、{} 字节，删除 {} 项",
      r.files, r.bytes, r.deleted
    );
    for w in &r.warnings {
      println!("{w}");
    }
  });
  Ok(())
}
fn is_sqlite(path: &str) -> bool {
  path.rsplit_once('.').is_some_and(|(_, ext)| {
    matches!(ext, "db" | "sqlite" | "sqlite3")
  })
}
async fn send_frames(
  root: File,
  entries: Vec<DataDiffEntry>,
  deletes: Vec<DataDiffEntry>,
  mut writer: tokio::io::DuplexStream,
) -> io::Result<()> {
  writer.write_all(MAGIC).await?;
  let mut bytes = vec![0; CHUNK];
  for entry in entries {
    let (dir, name) = parent(&root, &entry.path, false)?;
    if entry.dir {
      open(&dir, &name, DIRECTORY, 0)?;
      writer.write_all(&frame(2, &entry.path, 0, 0)).await?;
      continue;
    }
    let file = open(&dir, &name, libc::O_RDONLY | NOFOLLOW, 0)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() != entry.size {
      return Err(io::Error::other("推送期间文件已变化"));
    }
    let mut file = tokio::fs::File::from_std(file);
    writer
      .write_all(&frame(
        1,
        &entry.path,
        entry.size,
        meta.mode() & 0o777,
      ))
      .await?;
    let mut hash = Sha256::new();
    let mut remain = entry.size;
    while remain > 0 {
      let n = remain.min(CHUNK as u64) as usize;
      file.read_exact(&mut bytes[..n]).await?;
      hash.update(&bytes[..n]);
      writer.write_all(&bytes[..n]).await?;
      remain -= n as u64;
    }
    let after = file.metadata().await?;
    if after.len() != meta.len()
      || after.modified()? != meta.modified()?
    {
      return Err(io::Error::other("推送期间文件已变化"));
    }
    writer.write_all(&hash.finalize()).await?;
  }
  for entry in deletes {
    writer.write_all(&frame(3, &entry.path, 0, 0)).await?;
  }
  writer.write_all(&[0]).await?;
  writer.shutdown().await
}
fn unlink(parent: &File, name: &CStr, dir: bool) -> io::Result<()> {
  let rc = unsafe {
    libc::unlinkat(
      parent.as_raw_fd(),
      name.as_ptr(),
      if dir { libc::AT_REMOVEDIR } else { 0 },
    )
  };
  if rc < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}
struct Temp<'a>(&'a File, CString);
impl Drop for Temp<'_> {
  fn drop(&mut self) {
    let _ = unlink(self.0, &self.1, false);
  }
}
async fn receive_frames(
  root: &File,
  reader: &mut (impl AsyncRead + Unpin),
  paths: Vec<String>,
  limit: u64,
) -> io::Result<DataSyncSummary> {
  let invalid = || io::Error::other("拉取数据帧或校验不正确");
  let mut magic = [0; MAGIC.len()];
  reader.read_exact(&mut magic).await?;
  if &magic != MAGIC {
    return Err(invalid());
  }
  let mut summary = DataSyncSummary::default();
  let mut bytes = vec![0; CHUNK];
  for path in paths {
    if reader.read_u8().await? != 1 {
      return Err(invalid());
    }
    if reader.read_u32().await? as usize != path.len() {
      return Err(invalid());
    }
    let mut received = vec![0; path.len()];
    reader.read_exact(&mut received).await?;
    if received != path.as_bytes() {
      return Err(invalid());
    }
    let size = reader.read_u64().await?;
    let mode = reader.read_u32().await?;
    if size > MAX_FILE_BYTES || summary.bytes + size > limit {
      return Err(invalid());
    }
    let (dir, name) = parent(root, &path, true)?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce)
      .map_err(|_| io::Error::other("随机数不可用"))?;
    let tmp_name =
      cstr(format!(".wharf-dl-{}.tmp", hex::encode(nonce)))?;
    let temp = open(
      &dir,
      &tmp_name,
      libc::O_WRONLY | libc::O_EXCL | libc::O_CREAT | NOFOLLOW,
      0o600,
    )?;
    let guard = Temp(&dir, tmp_name);
    let mut temp = tokio::fs::File::from_std(temp);
    let mut hash = Sha256::new();
    let mut remain = size;
    while remain > 0 {
      let n = remain.min(CHUNK as u64) as usize;
      reader.read_exact(&mut bytes[..n]).await?;
      hash.update(&bytes[..n]);
      temp.write_all(&bytes[..n]).await?;
      remain -= n as u64;
    }
    let mut expected = [0; 32];
    reader.read_exact(&mut expected).await?;
    if <[u8; 32]>::from(hash.finalize()) != expected {
      return Err(invalid());
    }
    temp
      .set_permissions(std::fs::Permissions::from_mode(mode & 0o777))
      .await?;
    temp.sync_all().await?;
    match stat(&dir, &name) {
      Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFREG => {}
      Err(e) if e.kind() == io::ErrorKind::NotFound => {}
      _ => return Err(io::Error::other("本地目标不是普通文件")),
    }
    let rc = unsafe {
      libc::renameat(
        dir.as_raw_fd(),
        guard.1.as_ptr(),
        dir.as_raw_fd(),
        name.as_ptr(),
      )
    };
    if rc < 0 {
      return Err(io::Error::last_os_error());
    }
    summary.files += 1;
    summary.bytes += size;
  }
  if reader.read_u8().await? != 0
    || reader.read(&mut bytes[..1]).await? != 0
  {
    return Err(invalid());
  }
  Ok(summary)
}
