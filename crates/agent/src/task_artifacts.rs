//! 任务运行结束后收集 /out，读取时逐级拒绝符号链接。

use std::{
  fs::File,
  io::{self, Read},
  os::unix::fs::MetadataExt,
  path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    FileChunk, FileVersion, TASK_DATA_PREFIX, TaskArtifact,
    TaskRunJob,
  },
  validate_name,
};

use crate::{
  dirfd::{DirFd, component, dir_error},
  docker::io_err,
  exec::Cmd,
};

const MAX_FILES: usize = 100;
const MIB: u64 = 1024 * 1024;

pub(crate) struct OutputDir {
  root: DirFd,
  host: PathBuf,
  run_id: i64,
  retain: bool,
}

fn task_root(
  base: &Path,
  task: &str,
  create: bool,
) -> Result<DirFd, ApiError> {
  validate_name("任务", task)?;
  let base_fd =
    DirFd::open_dir(base).map_err(|e| dir_error(base, e))?;
  let name = format!("{TASK_DATA_PREFIX}{task}");
  let key = component(name.as_ref()).map_err(io_err(base))?;
  let task_fd = if create {
    base_fd.ensure_subdir(&key, 0o700)
  } else {
    base_fd.open_subdir(&key)
  }
  .map_err(|e| dir_error(&base.join(name), e))?;
  let root = if create {
    task_fd.ensure_subdir(c"artifacts", 0o700)
  } else {
    task_fd.open_subdir(c"artifacts")
  };
  root.map_err(|e| dir_error(&base.join("artifacts"), e))
}

pub(crate) fn uses_out(mounts: &[String]) -> bool {
  mounts
    .iter()
    .filter_map(|m| m.split(':').nth(1))
    .any(|p| Path::new(p) == Path::new("/out"))
}

impl OutputDir {
  pub(crate) fn create(
    base: &Path,
    name: &str,
    run_id: i64,
  ) -> Result<Self, ApiError> {
    if run_id <= 0 {
      return Err(ApiError::invalid("任务运行编号必须大于 0"));
    }
    let root = task_root(base, name, true)?;
    let host = base
      .join(format!("{TASK_DATA_PREFIX}{name}"))
      .join("artifacts")
      .join(run_id.to_string());
    let run = component(run_id.to_string().as_ref())
      .map_err(io_err(&host))?;
    root.mkdir(&run, 0o700).map_err(io_err(&host))?;
    Ok(Self {
      root,
      host,
      run_id,
      retain: false,
    })
  }

  pub(crate) fn mount(&self, cmd: Cmd) -> Cmd {
    cmd.args([
      "-v",
      &format!("{}:/out", self.host.display()),
      "-e",
      "WHARF_OUT_DIR=/out",
      "-e",
      &format!("WHARF_RUN_ID={}", self.run_id),
    ])
  }

  fn collect(
    mut self,
    max: u64,
    keep: usize,
    cancel: &CancellationToken,
  ) -> Result<(Vec<TaskArtifact>, bool), ApiError> {
    let component = component(self.run_id.to_string().as_ref())
      .map_err(io_err(&self.host))?;
    let run = self
      .root
      .open_subdir(&component)
      .map_err(io_err(&self.host))?;
    let mut scan = Scan {
      remaining: max,
      files: Vec::new(),
      warning: false,
      cancel,
    };
    scan
      .collect(&run, Path::new(""), 0)
      .map_err(io_err(&self.host))?;
    if !scan.files.is_empty() {
      scan.files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
      let mut ids =
        run_ids(&self.root).map_err(io_err(&self.host))?;
      ids.sort_unstable_by(|a, b| b.cmp(a));
      self.retain =
        ids.iter().take(keep).any(|id| *id == self.run_id);
      let old = &ids[keep.min(ids.len())..];
      for id in old {
        remove_run(&self.root, *id, cancel)
          .map_err(io_err(&self.host))?;
      }
      if !self.retain {
        scan.files.clear();
        scan.warning = true;
      }
    }
    Ok((scan.files, scan.warning))
  }
}

impl Drop for OutputDir {
  fn drop(&mut self) {
    if !self.retain {
      let _ = remove_run(
        &self.root,
        self.run_id,
        &CancellationToken::new(),
      );
    }
  }
}

pub(crate) fn start(
  job: &TaskRunJob,
  mounts: &[String],
  warning: &mut Option<String>,
) -> Option<OutputDir> {
  let run = job.run_id?;
  if uses_out(mounts) {
    *warning = Some("已使用 /out 挂载，跳过产物收集".into());
    return None;
  }
  match OutputDir::create(Path::new("/srv"), &job.name, run) {
    Ok(dir) => Some(dir),
    Err(_) => {
      *warning = Some("无法创建产物目录".into());
      None
    }
  }
}

pub(crate) async fn finish(
  dir: OutputDir,
  job: &TaskRunJob,
  cancel: &CancellationToken,
) -> (Vec<TaskArtifact>, Option<String>) {
  let max = job
    .artifacts_max_bytes
    .unwrap_or(50 * MIB)
    .clamp(MIB, 200 * MIB);
  let keep = job.artifacts_keep.unwrap_or(5).clamp(1, 20) as usize;
  let cancel = cancel.clone();
  match tokio::task::spawn_blocking(move || {
    dir.collect(max, keep, &cancel)
  })
  .await
  {
    Ok(Ok((files, warning))) => {
      (files, warning.then(|| "已跳过超限或不安全的产物".into()))
    }
    _ => (Vec::new(), Some("任务产物收集失败".into())),
  }
}

struct Scan<'a> {
  remaining: u64,
  files: Vec<TaskArtifact>,
  warning: bool,
  cancel: &'a CancellationToken,
}

impl Scan<'_> {
  fn collect(
    &mut self,
    dir: &DirFd,
    prefix: &Path,
    depth: usize,
  ) -> io::Result<()> {
    let mut names = dir.read_names()?;
    names.sort_unstable();
    for name in names {
      check_cancel(self.cancel)?;
      let st = dir.lstat(&name)?;
      let mode = st.st_mode & libc::S_IFMT;
      let label = name
        .to_str()
        .ok()
        .filter(|s| !s.contains(['\\', '\r', '\n']));
      if let Some(label) = label {
        let path = prefix.join(label);
        if mode == libc::S_IFDIR && depth < 32 {
          self.collect(&dir.open_subdir(&name)?, &path, depth + 1)?;
          continue;
        }
        if mode == libc::S_IFREG
          && st.st_nlink == 1
          && self.files.len() < MAX_FILES
          && st.st_size >= 0
          && st.st_size as u64 <= self.remaining
          && let Some(path) =
            path.to_str().filter(|p| p.len() <= 1024)
          && let Some(file) = self.hash(dir, &name, path)?
        {
          self.remaining -= file.size;
          self.files.push(file);
          continue;
        }
      }
      self.warning = true;
      if mode == libc::S_IFDIR {
        dir.remove_tree(&name, &|| check_cancel(self.cancel))?;
      } else {
        dir.unlink(&name)?;
      }
    }
    Ok(())
  }

  fn hash(
    &self,
    dir: &DirFd,
    name: &std::ffi::CStr,
    path: &str,
  ) -> io::Result<Option<TaskArtifact>> {
    let mut file = File::from(dir.open_file(
      name,
      libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
      0,
    )?);
    let before = file.metadata()?;
    if !before.is_file()
      || before.nlink() != 1
      || before.len() > self.remaining
    {
      return Ok(None);
    }
    let mut sha = Sha256::new();
    let mut read = 0_u64;
    let mut buf = [0_u8; 32 * 1024];
    loop {
      check_cancel(self.cancel)?;
      let n = file.read(&mut buf)?;
      if n == 0 {
        break;
      }
      read += n as u64;
      if read > before.len() {
        return Ok(None);
      }
      sha.update(&buf[..n]);
    }
    let after = file.metadata()?;
    if read != before.len()
      || after.len() != read
      || after.mtime() != before.mtime()
      || after.mtime_nsec() != before.mtime_nsec()
      || after.nlink() != 1
    {
      return Ok(None);
    }
    Ok(Some(TaskArtifact {
      path: path.into(),
      size: read,
      sha256: hex::encode(sha.finalize()),
    }))
  }
}

fn check_cancel(cancel: &CancellationToken) -> io::Result<()> {
  if cancel.is_cancelled() {
    return Err(io::Error::from(io::ErrorKind::Interrupted));
  }
  Ok(())
}

fn run_ids(root: &DirFd) -> io::Result<Vec<i64>> {
  Ok(
    root
      .read_names()?
      .into_iter()
      .filter_map(|name| {
        let text = name.to_str().ok()?;
        let id: i64 = text.parse().ok()?;
        let st = root.lstat(&name).ok()?;
        (id > 0
          && text == id.to_string()
          && st.st_mode & libc::S_IFMT == libc::S_IFDIR)
          .then_some(id)
      })
      .collect(),
  )
}

fn remove_run(
  root: &DirFd,
  id: i64,
  cancel: &CancellationToken,
) -> io::Result<()> {
  let name = component(id.to_string().as_ref())?;
  match root.remove_tree(&name, &|| check_cancel(cancel)) {
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
    result => result,
  }
}

pub(crate) fn prune(
  task: &str,
  keep: &[i64],
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let base = Path::new("/srv");
  let root = match task_root(base, task, false) {
    Err(e) if e.code == ErrorCode::NotFound => return Ok(()),
    result => result?,
  };
  for id in run_ids(&root).map_err(io_err(base))? {
    if !keep.contains(&id) {
      remove_run(&root, id, cancel).map_err(io_err(base))?;
    }
  }
  Ok(())
}

pub(crate) fn read(
  task: &str,
  run_id: i64,
  path: &str,
  offset: u64,
  len: u32,
  expect: Option<&FileVersion>,
) -> Result<FileChunk, ApiError> {
  if run_id <= 0
    || path.is_empty()
    || path.len() > 1024
    || path.contains('\\')
    || path.split('/').any(|s| matches!(s, "" | "." | ".."))
  {
    return Err(ApiError::invalid("产物路径或运行编号不对"));
  }
  let root = task_root(Path::new("/srv"), task, false)?;
  let name = component(run_id.to_string().as_ref())
    .map_err(io_err(Path::new(path)))?;
  let run = root
    .open_subdir(&name)
    .map_err(|e| dir_error(Path::new(path), e))?;
  crate::files::read_root(run, path, offset, len, expect)
}

#[test]
fn retains_five_runs_and_discards_symlinks() {
  let temp = tempfile::tempdir().unwrap();
  let cancel = CancellationToken::new();
  let mut root = None;
  for id in 1..=7 {
    let folder = OutputDir::create(temp.path(), "t1", id).unwrap();
    std::fs::write(folder.host.join("report.txt"), b"fixture")
      .unwrap();
    std::os::unix::fs::symlink(
      "/etc/hosts",
      folder.host.join("unsafe"),
    )
    .unwrap();
    let path = folder.host.clone();
    let (files, warning) =
      folder.collect(50 * MIB, 5, &cancel).unwrap();
    assert!(warning && !path.join("unsafe").is_symlink());
    assert_eq!(files[0].path, "report.txt");
    assert_eq!(
      files[0].sha256,
      hex::encode(Sha256::digest(b"fixture"))
    );
    root = path.parent().map(Path::to_path_buf);
  }
  let mut runs =
    run_ids(&DirFd::open_dir(&root.unwrap()).unwrap()).unwrap();
  runs.sort_unstable();
  assert_eq!(runs, [3, 4, 5, 6, 7]);
}
