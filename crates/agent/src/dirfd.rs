use std::{
  collections::BTreeMap,
  ffi::{CStr, CString, OsStr},
  io,
  mem::MaybeUninit,
  os::{
    fd::{AsRawFd, FromRawFd, OwnedFd},
    unix::ffi::OsStrExt,
  },
  path::{Component, Path, PathBuf},
};

use crate::docker::io_err;
use wharf_api_types::{ApiError, agent::FileEntry, validate_name};

pub(crate) const NOFOLLOW: libc::c_int =
  libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const DIRECTORY: libc::c_int =
  libc::O_RDONLY | libc::O_DIRECTORY | NOFOLLOW;

pub(crate) struct DirFd(OwnedFd);

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    // 成功的 open/openat 返回一个由调用者独占的新 fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
  }
}

pub(crate) fn check(rc: libc::c_int) -> io::Result<()> {
  if rc < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}

pub(crate) fn stat(fd: libc::c_int) -> io::Result<libc::stat> {
  let mut st = MaybeUninit::uninit();
  unsafe {
    check(libc::fstat(fd, st.as_mut_ptr()))?;
    Ok(st.assume_init())
  }
}

impl DirFd {
  pub(crate) fn fd_path(&self) -> PathBuf {
    Path::new("/proc/self/fd").join(self.0.as_raw_fd().to_string())
  }

  pub(crate) fn open_service_root(
    base: &Path,
    service: &str,
  ) -> Result<Self, ApiError> {
    validate_name("服务", service)?;
    let base_fd =
      Self::open_dir(base).map_err(|e| dir_error(base, e))?;
    let name = CString::new(service)
      .map_err(|_| ApiError::invalid("路径不对"))?;
    base_fd
      .open_subdir(&name)
      .map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => ApiError::not_found(format!(
          "这台机器上没有 {service} 的数据目录"
        )),
        Some(libc::ELOOP | libc::ENOTDIR) => {
          ApiError::invalid("不能访问数据目录以外的文件")
        }
        _ => io_err(base)(e),
      })
  }

  pub(crate) fn open_dir(path: &Path) -> io::Result<Self> {
    let name = component(path.as_os_str())?;
    owned(unsafe { libc::open(name.as_ptr(), DIRECTORY) }).map(Self)
  }

  pub(crate) fn open_absolute(path: &Path) -> io::Result<Self> {
    let Some(rel) = path.strip_prefix("/").ok() else {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "需要绝对路径",
      ));
    };
    let mut fd = Self::open_dir(Path::new("/"))?;
    for part in rel.components() {
      let Component::Normal(name) = part else {
        return Err(io::Error::new(
          io::ErrorKind::InvalidInput,
          "路径不合法",
        ));
      };
      fd = fd.open_subdir(&component(name)?)?;
    }
    Ok(fd)
  }

  pub(crate) fn mkdir(
    &self,
    name: &CStr,
    mode: libc::mode_t,
  ) -> io::Result<()> {
    check(unsafe {
      libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), mode)
    })
  }

  pub(crate) fn ensure_subdir(
    &self,
    name: &CStr,
    mode: libc::mode_t,
  ) -> io::Result<Self> {
    match self.mkdir(name, mode) {
      Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
        return Err(e);
      }
      _ => {}
    }
    self.open_subdir(name)
  }

  pub(crate) fn readlink(&self, name: &CStr) -> io::Result<PathBuf> {
    let mut buf = [0; 4096];
    let n = unsafe {
      libc::readlinkat(
        self.0.as_raw_fd(),
        name.as_ptr(),
        buf.as_mut_ptr().cast(),
        buf.len(),
      )
    };
    if n < 0 {
      return Err(io::Error::last_os_error());
    }
    if n as usize == buf.len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "符号链接目标太长",
      ));
    }
    Ok(OsStr::from_bytes(&buf[..n as usize]).into())
  }

  pub(crate) fn open_subdir(&self, name: &CStr) -> io::Result<Self> {
    self.open_file(name, DIRECTORY, 0).map(Self)
  }

  pub(crate) fn walk_dirs(
    self,
    segs: &[CString],
  ) -> io::Result<Self> {
    segs
      .iter()
      .try_fold(self, |dir, name| dir.open_subdir(name))
  }

  pub(crate) fn lstat(&self, name: &CStr) -> io::Result<libc::stat> {
    let mut st = MaybeUninit::uninit();
    // fstatat 仅在成功时初始化整个 stat。
    unsafe {
      check(libc::fstatat(
        self.0.as_raw_fd(),
        name.as_ptr(),
        st.as_mut_ptr(),
        libc::AT_SYMLINK_NOFOLLOW,
      ))?;
      Ok(st.assume_init())
    }
  }

  pub(crate) fn stat_self(&self) -> io::Result<libc::stat> {
    stat(self.0.as_raw_fd())
  }

  pub(crate) fn open_file(
    &self,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
  ) -> io::Result<OwnedFd> {
    owned(unsafe {
      libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, mode)
    })
  }

  pub(crate) fn unlink(&self, name: &CStr) -> io::Result<()> {
    check(unsafe {
      libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0)
    })
  }

  pub(crate) fn rename(
    &self,
    from: &CStr,
    to: &CStr,
  ) -> io::Result<()> {
    self.rename_to(from, self, to)
  }

  pub(crate) fn rename_to(
    &self,
    from: &CStr,
    dst: &Self,
    to: &CStr,
  ) -> io::Result<()> {
    check(unsafe {
      libc::renameat(
        self.0.as_raw_fd(),
        from.as_ptr(),
        dst.0.as_raw_fd(),
        to.as_ptr(),
      )
    })
  }

  pub(crate) fn remove_tree(
    &self,
    name: &CStr,
    cancelled: &impl Fn() -> io::Result<()>,
  ) -> io::Result<()> {
    cancelled()?;
    let dir = self.open_subdir(name)?;
    dir.visit_names(|entry| {
      cancelled()?;
      if dir.lstat(entry)?.st_mode & libc::S_IFMT == libc::S_IFDIR {
        dir.remove_tree(entry, cancelled)
      } else {
        dir.unlink(entry)
      }
    })?;
    cancelled()?;
    check(unsafe {
      libc::unlinkat(
        self.0.as_raw_fd(),
        name.as_ptr(),
        libc::AT_REMOVEDIR,
      )
    })
  }

  pub(crate) fn read_entries(
    &self,
    path: &Path,
  ) -> Result<Vec<FileEntry>, ApiError> {
    let mut out = Vec::new();
    for name in self.read_names().map_err(io_err(path))? {
      if name.to_bytes().ends_with(b".wharf-upload") {
        continue;
      }
      let Ok(st) = self.lstat(&name) else { continue };
      let mode = st.st_mode & libc::S_IFMT;
      out.push(FileEntry {
        name: name.to_string_lossy().into_owned(),
        dir: mode == libc::S_IFDIR,
        link: mode == libc::S_IFLNK,
        size: st.st_size.max(0) as u64,
        modified: st.st_mtime.saturating_mul(1000),
      });
    }
    out.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.cmp(&b.name)));
    Ok(out)
  }

  pub(crate) fn read_names(&self) -> io::Result<Vec<CString>> {
    let mut out = Vec::new();
    self.visit_names(|name| {
      out.push(name.to_owned());
      Ok(())
    })?;
    Ok(out)
  }

  fn visit_names(
    &self,
    mut visit: impl FnMut(&CStr) -> io::Result<()>,
  ) -> io::Result<()> {
    let fd = unsafe {
      libc::openat(self.0.as_raw_fd(), c".".as_ptr(), DIRECTORY)
    };
    if fd < 0 {
      return Err(io::Error::last_os_error());
    }
    // fdopendir 成功后接管 fd，失败时仍由调用方关闭。
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
      let error = io::Error::last_os_error();
      unsafe { libc::close(fd) };
      return Err(error);
    }
    let dir = DirGuard(dir);
    loop {
      let entry = unsafe {
        *errno() = 0;
        libc::readdir(dir.0)
      };
      if entry.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(0) {
          return Err(error);
        }
        break;
      }
      // d_name 在下一次 readdir 前有效。
      let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
      if !matches!(name.to_bytes(), b"." | b"..") {
        visit(name)?;
      }
    }
    Ok(())
  }
}

struct DirGuard(*mut libc::DIR);

impl Drop for DirGuard {
  fn drop(&mut self) {
    unsafe { libc::closedir(self.0) };
  }
}

fn errno() -> *mut libc::c_int {
  #[cfg(target_os = "linux")]
  unsafe {
    libc::__errno_location()
  }
  #[cfg(target_os = "macos")]
  unsafe {
    libc::__error()
  }
}

pub(crate) fn component(name: &OsStr) -> io::Result<CString> {
  CString::new(name.as_bytes()).map_err(io::Error::other)
}

pub(crate) fn dir_error(path: &Path, error: io::Error) -> ApiError {
  match error.raw_os_error() {
    Some(libc::ENOENT) => {
      ApiError::not_found(format!("目录 {} 不存在", path.display()))
    }
    Some(libc::ELOOP | libc::ENOTDIR) => ApiError::invalid(format!(
      "路径 {} 经过了符号链接或非目录，已拒绝",
      path.display()
    )),
    _ => io_err(path)(error),
  }
}

pub(crate) fn ensure_beneath(
  base: &Path,
  relative: &Path,
) -> Result<DirFd, ApiError> {
  let mut fd =
    DirFd::open_dir(base).map_err(|e| dir_error(base, e))?;
  for part in relative.components() {
    let Component::Normal(name) = part else {
      return Err(ApiError::invalid("目录必须位于数据根目录内"));
    };
    let name = component(name)
      .map_err(|_| ApiError::invalid("目录名不合法"))?;
    fd = fd
      .ensure_subdir(&name, 0o755)
      .map_err(|e| dir_error(relative, e))?;
  }
  Ok(fd)
}

pub(crate) async fn remove_service(
  base: &Path,
  service: &str,
  ctx: &crate::exec::Ctx,
) -> Result<(), ApiError> {
  let base = base.to_owned();
  let service = service.to_owned();
  let cancel = ctx.cancel.clone();
  tokio::task::spawn_blocking(move || {
    remove_service_tree(&base, &service, &cancel)
  })
  .await
  .map_err(|e| ApiError::internal(format!("删除目录任务中断：{e}")))?
}

fn remove_service_tree(
  base: &Path,
  service: &str,
  cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), ApiError> {
  validate_name(
    "服务",
    service
      .strip_prefix(wharf_api_types::agent::TASK_DATA_PREFIX)
      .unwrap_or(service),
  )?;
  let dir = base.join(service);
  let cancelled = || {
    if cancel.is_cancelled() {
      Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
      Ok(())
    }
  };
  let error = |e: io::Error| {
    if e.kind() == io::ErrorKind::Interrupted && cancel.is_cancelled()
    {
      ApiError::new(wharf_api_types::ErrorCode::Cancelled, "已取消")
    } else {
      io_err(&dir)(e)
    }
  };
  cancelled().map_err(error)?;
  let fd = match DirFd::open_dir(base).map_err(|e| dir_error(base, e))
  {
    Err(e) if e.code == wharf_api_types::ErrorCode::NotFound => {
      return Ok(());
    }
    result => result?,
  };
  let name = component(service.as_ref()).map_err(io_err(&dir))?;
  match fd.lstat(&name) {
    Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFDIR => {
      fd.remove_tree(&name, &cancelled).map_err(error)
    }
    Ok(_) => Err(ApiError::invalid(format!(
      "{} 是软链接或非目录，已拒绝删除",
      dir.display()
    ))),
    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(io_err(&dir)(e)),
  }
}

pub(crate) fn validate_tree(
  root: &DirFd,
  reject_root_links: bool,
) -> Result<(), ApiError> {
  let links = tree_symlinks(root)?;
  if reject_root_links
    && let Some((path, target)) = links
      .iter()
      .find(|(path, _)| path.components().count() == 1)
  {
    return Err(ApiError::invalid(format!(
      "一级卷 {} -> {} 是符号链接",
      path.display(),
      target.display()
    )));
  }
  wharf_api_types::symlink::validate_symlinks(&links)
}

/// 遍历目录项时从父目录打开，整个扫描过程都不跟随软链。
pub(crate) fn tree_symlinks(
  root: &DirFd,
) -> Result<BTreeMap<PathBuf, PathBuf>, ApiError> {
  fn scan(
    fd: &DirFd,
    rel: &Path,
    links: &mut BTreeMap<PathBuf, PathBuf>,
    depth: usize,
  ) -> Result<(), ApiError> {
    if depth > 64 {
      return Err(ApiError::invalid("目录层级超过 64 层"));
    }
    for name in fd.read_names().map_err(io_err(rel))? {
      let path = rel.join(OsStr::from_bytes(name.to_bytes()));
      let stat = fd.lstat(&name).map_err(io_err(&path))?;
      match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {
          let sub =
            fd.open_subdir(&name).map_err(|e| dir_error(&path, e))?;
          scan(&sub, &path, links, depth + 1)?;
        }
        libc::S_IFLNK => {
          let target = fd.readlink(&name).map_err(io_err(&path))?;
          links.insert(path, target);
        }
        _ => {}
      }
    }
    Ok(())
  }

  let mut links = BTreeMap::new();
  scan(root, Path::new(""), &mut links, 0)?;
  Ok(links)
}
