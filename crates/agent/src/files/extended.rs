use std::{
  ffi::{CStr, CString},
  io::{BufRead, BufReader},
  os::unix::ffi::OsStrExt,
};

use wharf_api_types::agent::{
  FileGrepMatch, FileGrepResult, FileMkdirResult, FileMvResult,
  FileRmResult, FileTailResult,
};

use super::*;

const MAX_DEPTH: usize = 16;
const MAX_FILES: u32 = 2000;
const MAX_FILE_BYTES: u64 = 16 << 20;
const MAX_TOTAL_BYTES: u64 = 64 << 20;
const MAX_ENTRIES: usize = 8000;
const MAX_LINE: usize = 64 << 10;

pub(super) fn handle(
  base: &Path,
  op: FilesOp,
  cancel: &CancellationToken,
) -> Result<Value, ApiError> {
  check_cancel(cancel)?;
  match op {
    FilesOp::Tail {
      service,
      path,
      lines,
      max_bytes,
    } => {
      let (parent, name) = resolve(
        DirFd::open_service_root(base, &service)?,
        &path,
        false,
      )?;
      to_value(tail(&parent, &name, &path, lines, max_bytes, cancel)?)
    }
    FilesOp::Grep {
      service,
      path,
      pattern,
      regex,
      limit,
    } => to_value(grep(
      DirFd::open_service_root(base, &service)?,
      &path,
      &pattern,
      regex,
      limit,
      cancel,
    )?),
    FilesOp::Rm {
      service,
      path,
      recursive,
    } => {
      let (parent, name) = resolve(
        DirFd::open_service_root(base, &service)?,
        &path,
        true,
      )?;
      let removed = rm(&parent, &name, &path, recursive, cancel)?;
      to_value(FileRmResult { path, removed })
    }
    FilesOp::Mv {
      service,
      from,
      to,
      force,
    } => {
      mv(
        DirFd::open_service_root(base, &service)?,
        &from,
        &to,
        force,
        cancel,
      )?;
      to_value(FileMvResult { from, to })
    }
    FilesOp::Mkdir {
      service,
      path,
      parents,
    } => {
      let created = mkdir(
        DirFd::open_service_root(base, &service)?,
        &path,
        parents,
        cancel,
      )?;
      to_value(FileMkdirResult { path, created })
    }
    _ => unreachable!(),
  }
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), ApiError> {
  if cancel.is_cancelled() {
    Err(ApiError::new(ErrorCode::Cancelled, "已取消"))
  } else {
    Ok(())
  }
}

fn relative(path: &str) -> Result<Vec<CString>, ApiError> {
  let parts = parse_rel(path)?;
  if parts
    .iter()
    .any(|p| p.to_bytes().ends_with(UPLOAD_SUFFIX.as_bytes()))
  {
    return Err(ApiError::invalid("不能操作上传临时文件"));
  }
  Ok(parts)
}

fn nonempty(
  parts: &[CString],
) -> Result<(&CString, &[CString]), ApiError> {
  parts
    .split_last()
    .ok_or_else(|| ApiError::invalid("不能操作服务根目录"))
}

fn resolve(
  root: DirFd,
  path: &str,
  write: bool,
) -> Result<(DirFd, CString), ApiError> {
  let mut parts = relative(path)?;
  let name = parts
    .pop()
    .ok_or_else(|| ApiError::invalid("不能操作服务根目录"))?;
  Ok((walk(root, &parts, path, write)?, name))
}

fn path_error(path: &str, e: io::Error) -> ApiError {
  match e.raw_os_error() {
    Some(libc::ENOENT) => ApiError::not_found(format!("没有 {path}")),
    Some(libc::ELOOP | libc::ENOTDIR) => {
      ApiError::invalid("路径经过符号链接或非目录")
    }
    _ => io_err(Path::new(path))(e),
  }
}

fn open_regular(
  dir: &DirFd,
  name: &CStr,
  path: &str,
) -> Result<(File, u64), ApiError> {
  let fd = dir
    .open_file(name, libc::O_RDONLY | NOFOLLOW, 0)
    .map_err(|e| path_error(path, e))?;
  let f = File::from(fd);
  let meta = f.metadata().map_err(io_err(Path::new(path)))?;
  if !meta.is_file() {
    return Err(ApiError::invalid("只能读普通文件"));
  }
  Ok((f, meta.len()))
}

fn tail(
  parent: &DirFd,
  name: &CStr,
  path: &str,
  lines: u32,
  max_bytes: Option<u32>,
  cancel: &CancellationToken,
) -> Result<FileTailResult, ApiError> {
  let (mut file, size) = open_regular(parent, name, path)?;
  let lines = lines.clamp(1, 2000) as usize;
  let bytes =
    max_bytes.unwrap_or(512 << 10).clamp(1024, 2 << 20) as u64;
  let from = size.saturating_sub(bytes);
  let err = io_err(Path::new(path));
  let mut end = size;
  let mut chunks = Vec::new();
  let mut breaks = 0;
  let mut complete = from == 0;
  while end > from {
    check_cancel(cancel)?;
    let start = end.saturating_sub(64 << 10).max(from);
    let mut chunk = vec![0; (end - start) as usize];
    file.seek(SeekFrom::Start(start)).map_err(&err)?;
    file.read_exact(&mut chunk).map_err(&err)?;
    if chunk.contains(&0) {
      return Err(
        ApiError::invalid("目标文件是二进制文件，不支持 tail")
          .with_hint("用 wharf service download 下载查看"),
      );
    }
    let cutoff =
      chunk.iter().enumerate().rev().find_map(|(i, &byte)| {
        if byte == b'\n' && start + (i as u64) + 1 != size {
          breaks += 1;
        }
        (breaks == lines).then_some(i + 1)
      });
    if let Some(i) = cutoff {
      chunks.push(chunk.split_off(i));
      complete = true;
      break;
    }
    chunks.push(chunk);
    end = start;
  }
  let data: Vec<u8> = chunks.into_iter().rev().flatten().collect();
  let skip = if complete {
    0
  } else {
    data.iter().take_while(|&&byte| byte & 0xc0 == 0x80).count()
  };
  let content = String::from_utf8_lossy(&data[skip..]).into_owned();
  Ok(FileTailResult {
    path: path.into(),
    size,
    lines: content.lines().count() as u32,
    content,
    truncated: !complete,
  })
}

struct Grep<'a> {
  matches: &'a dyn Fn(&str) -> bool,
  cancel: &'a CancellationToken,
  limit: usize,
  bytes: u64,
  entries: usize,
  visited_files: u32,
  result: FileGrepResult,
}

impl Grep<'_> {
  fn stopped(&mut self) -> Result<bool, ApiError> {
    check_cancel(self.cancel)?;
    let stop = self.entries >= MAX_ENTRIES
      || self.visited_files >= MAX_FILES
      || self.bytes >= MAX_TOTAL_BYTES
      || self.result.matches.len() >= self.limit;
    self.result.truncated |= stop;
    Ok(stop)
  }

  fn dir(
    &mut self,
    dir: &DirFd,
    path: &Path,
    depth: usize,
  ) -> Result<(), ApiError> {
    if depth >= MAX_DEPTH || self.stopped()? {
      self.result.truncated = true;
      return Ok(());
    }
    let names = dir
      .sorted_names(MAX_ENTRIES - self.entries + 1)
      .map_err(io_err(path))?;
    for name in names {
      if self.stopped()? {
        break;
      }
      self.entries += 1;
      if name.to_bytes().ends_with(UPLOAD_SUFFIX.as_bytes()) {
        continue;
      }
      let item =
        path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
      self.entry(dir, &name, &item, depth, false)?;
    }
    Ok(())
  }

  fn entry(
    &mut self,
    dir: &DirFd,
    name: &CStr,
    path: &Path,
    depth: usize,
    explicit: bool,
  ) -> Result<(), ApiError> {
    let path_text = path.to_string_lossy();
    let st = match dir.lstat(name) {
      Ok(st) => st,
      Err(err)
        if !explicit && err.kind() == io::ErrorKind::NotFound =>
      {
        return Ok(());
      }
      Err(err) => return Err(path_error(&path_text, err)),
    };
    match st.st_mode & libc::S_IFMT {
      libc::S_IFLNK if explicit => {
        Err(ApiError::invalid("不能搜索符号链接"))
      }
      libc::S_IFLNK => {
        self.result.skipped_links += 1;
        Ok(())
      }
      libc::S_IFDIR => {
        let sub = dir
          .open_subdir(name)
          .map_err(|e| path_error(&path_text, e))?;
        self.dir(&sub, path, depth + 1)
      }
      libc::S_IFREG => self.file(dir, name, &path_text),
      _ if explicit => {
        Err(ApiError::invalid("只能搜索普通文件或目录"))
      }
      _ => Ok(()),
    }
  }

  fn file(
    &mut self,
    dir: &DirFd,
    name: &CStr,
    path: &str,
  ) -> Result<(), ApiError> {
    check_cancel(self.cancel)?;
    self.visited_files += 1;
    let (file, size) = open_regular(dir, name, path)?;
    if size > MAX_FILE_BYTES {
      self.result.skipped_large += 1;
      return Ok(());
    }
    let budget = MAX_TOTAL_BYTES - self.bytes;
    let mut input =
      BufReader::with_capacity(8192, file.take(size.min(budget)));
    let err = io_err(Path::new(path));
    let first = input.fill_buf().map_err(&err)?;
    if first.contains(&0) {
      self.bytes += first.len() as u64;
      self.result.skipped_binary += 1;
      return Ok(());
    }
    self.result.scanned_files += 1;
    self.result.truncated |= size > budget;
    let mut line_no = 0;
    let mut line = Vec::new();
    loop {
      check_cancel(self.cancel)?;
      let chunk = input.fill_buf().map_err(&err)?;
      if chunk.is_empty() {
        if !line.is_empty() {
          self.hit(path, line_no + 1, &line);
        }
        break;
      }
      let eol = chunk.iter().position(|&b| b == b'\n');
      let len = eol.map_or(chunk.len(), |i| i + 1);
      let keep = len.min(MAX_LINE - line.len());
      line.extend_from_slice(&chunk[..keep]);
      self.result.truncated |= len > keep;
      input.consume(len);
      self.bytes += len as u64;
      if eol.is_some() {
        line_no += 1;
        self.hit(path, line_no, &line);
        line.clear();
        if self.result.matches.len() >= self.limit {
          self.result.truncated = true;
          break;
        }
      }
    }
    Ok(())
  }

  fn hit(&mut self, path: &str, line: u64, text: &[u8]) {
    let text = String::from_utf8_lossy(text);
    let text = text.trim_end_matches(['\r', '\n']);
    if (self.matches)(text) {
      self.result.matches.push(FileGrepMatch {
        path: path.into(),
        line,
        text: text.chars().take(500).collect(),
      });
    }
  }
}

fn grep(
  root: DirFd,
  path: &str,
  pattern: &str,
  regex: bool,
  limit: u32,
  cancel: &CancellationToken,
) -> Result<FileGrepResult, ApiError> {
  if pattern.is_empty() || pattern.chars().count() > 512 {
    return Err(ApiError::invalid("搜索表达式须为 1 到 512 字符"));
  }
  let re = regex
    .then(|| {
      regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
    })
    .transpose()
    .map_err(|_| ApiError::invalid("搜索正则表达式不合法"))?;
  let lower = pattern.to_lowercase();
  let matches = |line: &str| {
    re.as_ref().map_or_else(
      || line.to_lowercase().contains(&lower),
      |r| r.is_match(line),
    )
  };
  let mut scan = Grep {
    matches: &matches,
    cancel,
    limit: limit.clamp(1, 500) as usize,
    bytes: 0,
    entries: 0,
    visited_files: 0,
    result: FileGrepResult::default(),
  };
  let parts = relative(path)?;
  if let Some((name, dirs)) = parts.split_last() {
    let parent = walk(root, dirs, path, false)?;
    let relative = path.trim_start_matches('/');
    scan.entry(&parent, name, Path::new(relative), 0, true)?;
  } else {
    scan.dir(&root, Path::new(""), 0)?;
  }
  Ok(scan.result)
}

fn mkdir(
  root: DirFd,
  path: &str,
  parents: bool,
  cancel: &CancellationToken,
) -> Result<bool, ApiError> {
  let parts = relative(path)?;
  let (name, dirs) = nonempty(&parts)?;
  let (mut dir, names) = if parents {
    (root, parts.as_slice())
  } else {
    (walk(root, dirs, path, true)?, std::slice::from_ref(name))
  };
  let mut created = false;
  for name in names {
    check_cancel(cancel)?;
    let st = dir.stat_self().map_err(io_err(Path::new(path)))?;
    let new = match dir.mkdir(name, 0o755) {
      Ok(()) => true,
      Err(e)
        if e.kind() == io::ErrorKind::AlreadyExists && parents =>
      {
        false
      }
      Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
        return Err(
          ApiError::new(
            ErrorCode::Conflict,
            format!("路径 {path} 已存在"),
          )
          .with_hint("允许已存在可用 -p/--parents"),
        );
      }
      Err(e) => return Err(path_error(path, e)),
    };
    dir = dir.open_subdir(name).map_err(|e| path_error(path, e))?;
    if new {
      dir
        .fchown_self(st.st_uid, st.st_gid)
        .map_err(io_err(Path::new(path)))?;
      created = true;
    }
  }
  Ok(created)
}

fn mv(
  root: DirFd,
  from: &str,
  to: &str,
  force: bool,
  cancel: &CancellationToken,
) -> Result<(), ApiError> {
  let from_parts = relative(from)?;
  let to_parts = relative(to)?;
  let (from_name, from_dirs) = nonempty(&from_parts)?;
  let (to_name, to_dirs) = nonempty(&to_parts)?;
  if to_parts.starts_with(&from_parts) {
    return Err(ApiError::invalid("源和目标相同或目标在源目录内"));
  }
  let src = walk(
    root.clone_dir().map_err(io_err(Path::new(from)))?,
    from_dirs,
    from,
    true,
  )?;
  let dst = walk(root, to_dirs, to, true)?;
  if force {
    let src_mode = src
      .lstat(from_name)
      .map_err(|e| path_error(from, e))?
      .st_mode
      & libc::S_IFMT;
    match dst.lstat(to_name) {
      Ok(st) => {
        let mode = st.st_mode & libc::S_IFMT;
        if mode == libc::S_IFLNK
          || (mode == libc::S_IFDIR) != (src_mode == libc::S_IFDIR)
        {
          return Err(ApiError::invalid(
            "不能覆盖符号链接或不同类型的目录",
          ));
        }
      }
      Err(e) if e.kind() == io::ErrorKind::NotFound => {}
      Err(e) => return Err(path_error(to, e)),
    }
  }
  check_cancel(cancel)?;
  let result = if force {
    src.rename_to(from_name, &dst, to_name)
  } else {
    src.rename_noreplace(from_name, &dst, to_name)
  };
  result.map_err(|e| match e.raw_os_error() {
    Some(libc::EEXIST) if !force => {
      ApiError::new(ErrorCode::Conflict, format!("目标 {to} 已存在"))
        .with_hint("如需覆盖请加 --force")
    }
    Some(libc::ENOTEMPTY | libc::EEXIST) => {
      ApiError::invalid("不能覆盖非空目录")
    }
    Some(libc::EXDEV) => ApiError::invalid("不能跨文件系统移动"),
    Some(libc::EINVAL) => ApiError::invalid("不能将目录移入自身内部"),
    _ => path_error(from, e),
  })
}

fn rm(
  parent: &DirFd,
  name: &CStr,
  path: &str,
  recursive: bool,
  cancel: &CancellationToken,
) -> Result<u64, ApiError> {
  let st = parent.lstat(name).map_err(|e| path_error(path, e))?;
  check_cancel(cancel)?;
  let result = if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
    parent.unlink(name).map(|()| 1)
  } else if recursive {
    crate::dirfd::remove_dir_counted(parent, name, &|| {
      if cancel.is_cancelled() {
        Err(io::Error::from(io::ErrorKind::Interrupted))
      } else {
        Ok(())
      }
    })
  } else {
    parent.unlink_dir(name).map(|()| 1)
  };
  result.map_err(|e| match e.raw_os_error() {
    Some(libc::ENOTEMPTY | libc::EEXIST) if !recursive => {
      ApiError::invalid(format!("目录 {path} 非空"))
        .with_hint("确认要删除整个目录树时加 -r/--recursive")
    }
    _ if e.kind() == io::ErrorKind::Interrupted
      && cancel.is_cancelled() =>
    {
      ApiError::new(ErrorCode::Cancelled, "已取消")
    }
    _ => path_error(path, e),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{fs, os::unix::fs::symlink};

  #[test]
  fn tail_and_grep_read_only_text_inside_service() {
    let root = tempfile::tempdir().unwrap();
    let svc = root.path().join("app");
    fs::create_dir(&svc).unwrap();
    fs::write(svc.join("text"), "secret\n".repeat(500)).unwrap();
    fs::write(svc.join("bin"), b"secret\0").unwrap();
    fs::write(root.path().join("outside"), "secret outside").unwrap();
    symlink(root.path().join("outside"), svc.join("link")).unwrap();
    let cancel = CancellationToken::new();
    let dir = DirFd::open_service_root(root.path(), "app").unwrap();
    let r = tail(&dir, c"text", "text", 20, None, &cancel).unwrap();
    assert_eq!(r.content, "secret\n".repeat(20));
    for (name, path) in [(c"link", "link"), (c"bin", "bin")] {
      assert_eq!(
        tail(&dir, name, path, 20, None, &cancel).unwrap_err().code,
        ErrorCode::InvalidInput
      );
    }
    let r = grep(dir, "", "secret", false, 500, &cancel).unwrap();
    assert_eq!(
      (r.matches.len(), r.skipped_binary, r.skipped_links),
      (500, 1, 1)
    );
    assert!(r.matches.iter().all(|hit| hit.path == "text"));
  }

  #[test]
  fn mutations_reject_link_traversal_and_implicit_destruction() {
    let root = tempfile::tempdir().unwrap();
    let svc = root.path().join("app");
    fs::create_dir(&svc).unwrap();
    fs::write(root.path().join("external"), "保留").unwrap();
    symlink(root.path(), svc.join("escape")).unwrap();
    fs::write(svc.join("a"), "新文件").unwrap();
    fs::write(svc.join("b"), "旧文件").unwrap();
    let cancel = CancellationToken::new();
    let dir =
      || DirFd::open_service_root(root.path(), "app").unwrap();
    assert_eq!(
      mkdir(dir(), "escape/sub", true, &cancel).unwrap_err().code,
      ErrorCode::InvalidInput
    );
    assert_eq!(
      mv(dir(), "a", "escape/external", true, &cancel)
        .unwrap_err()
        .code,
      ErrorCode::InvalidInput
    );
    assert_eq!(
      rm(&dir(), c"escape", "escape", false, &cancel).unwrap(),
      1
    );
    assert_eq!(
      fs::read_to_string(root.path().join("external")).unwrap(),
      "保留"
    );
    assert_eq!(
      mv(dir(), "a", "b", false, &cancel).unwrap_err().code,
      ErrorCode::Conflict
    );
    mv(dir(), "a", "b", true, &cancel).unwrap();
    assert!(mkdir(dir(), "nested/child", true, &cancel).unwrap());
    assert!(rm(&dir(), c"nested", "nested", false, &cancel).is_err());
    assert_eq!(
      rm(&dir(), c"nested", "nested", true, &cancel).unwrap(),
      2
    );
  }
}
