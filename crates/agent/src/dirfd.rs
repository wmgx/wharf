//! 基于目录文件描述符（`openat` + `O_NOFOLLOW`）的安全路径操作。
//!
//! 供文件浏览、备份恢复、迁移同步、构建目录校验与控制面同机探测共用，
//! 全程不跟随符号链接，避免中间目录替换带来的 TOCTOU 逃逸。

use std::{
  collections::BTreeMap,
  ffi::{CStr, CString, OsString},
  io,
  mem::MaybeUninit,
  os::{
    fd::{AsRawFd, FromRawFd, OwnedFd},
    unix::ffi::{OsStrExt, OsStringExt},
  },
  path::{Path, PathBuf},
};

use wharf_api_types::{ApiError, agent::FileEntry, validate_name};

use crate::docker::io_err;

pub(crate) const NOFOLLOW: libc::c_int =
  libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
pub(crate) const DIRECTORY: libc::c_int =
  libc::O_RDONLY | libc::O_DIRECTORY | NOFOLLOW;

const MAX_WALK_DEPTH: usize = 64;

pub(crate) struct DirFd(OwnedFd);

pub(crate) fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    // 成功的 open/openat 返回由调用方独占的新 fd。
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

pub(crate) fn fstat(fd: libc::c_int) -> io::Result<libc::stat> {
  let mut st = MaybeUninit::uninit();
  unsafe {
    check(libc::fstat(fd, st.as_mut_ptr()))?;
    Ok(st.assume_init())
  }
}

pub(crate) fn cstring(name: &str) -> Result<CString, ApiError> {
  if name.is_empty() || name.contains('/') || name.contains('\0') {
    return Err(ApiError::invalid(format!("路径分量不合法：{name}")));
  }
  CString::new(name)
    .map_err(|_| ApiError::invalid(format!("路径分量不合法：{name}")))
}

impl DirFd {
  pub(crate) fn open_dir(path: &Path) -> io::Result<Self> {
    let raw =
      CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "路径含空字节")
      })?;
    owned(unsafe { libc::open(raw.as_ptr(), DIRECTORY) }).map(Self)
  }

  pub(crate) fn open_service_root(
    base: &Path,
    service: &str,
  ) -> Result<Self, ApiError> {
    validate_name("服务", service)?;
    let base_fd =
      Self::open_dir(base).map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => ApiError::not_found(format!(
          "这台机器上没有 {service} 的数据目录"
        )),
        Some(libc::ELOOP | libc::ENOTDIR) => {
          ApiError::invalid("不能访问数据目录以外的文件")
        }
        _ => io_err(base)(e),
      })?;
    let name = cstring(service)?;
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

  pub(crate) fn open_subdir(&self, name: &CStr) -> io::Result<Self> {
    self.open_file(name, DIRECTORY, 0).map(Self)
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
      Ok(()) => {}
      Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
      Err(e) => return Err(e),
    }
    self.open_subdir(name)
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
    fstat(self.0.as_raw_fd())
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

  pub(crate) fn readlink(&self, name: &CStr) -> io::Result<PathBuf> {
    let mut size = 4096usize;
    loop {
      let mut buf = vec![0u8; size];
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
      let n = n as usize;
      if n < buf.len() {
        buf.truncate(n);
        return Ok(PathBuf::from(OsString::from_vec(buf)));
      }
      if size >= 65536 {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "软链接目标过长",
        ));
      }
      size *= 2;
    }
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
    dst_dir: &DirFd,
    to: &CStr,
  ) -> io::Result<()> {
    check(unsafe {
      libc::renameat(
        self.0.as_raw_fd(),
        from.as_ptr(),
        dst_dir.0.as_raw_fd(),
        to.as_ptr(),
      )
    })
  }

  pub(crate) fn read_names(&self) -> io::Result<Vec<CString>> {
    let fd = unsafe {
      libc::fcntl(self.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
    };
    if fd < 0 {
      return Err(io::Error::last_os_error());
    }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
      let error = io::Error::last_os_error();
      unsafe { libc::close(fd) };
      return Err(error);
    }
    let dir = DirGuard(dir);
    let mut out = Vec::new();
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
      let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
      if matches!(name.to_bytes(), b"." | b"..") {
        continue;
      }
      out.push(name.to_owned());
    }
    Ok(out)
  }

  pub(crate) fn read_entries(
    &self,
    path: &Path,
    skip_suffix: &str,
  ) -> Result<Vec<FileEntry>, ApiError> {
    let names = self.read_names().map_err(io_err(path))?;
    let mut out = Vec::new();
    for name in names {
      if name.to_bytes().ends_with(skip_suffix.as_bytes()) {
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
}

/// 递归收集目录树下全部软链接（全程 `O_NOFOLLOW`，绝不跟随目录软链）。
/// `forbid_top_level_symlink` 为 true 时，拒绝深度 0（根目录直接子项）出现任何软链。
pub(crate) fn collect_symlinks(
  dir: &DirFd,
  prefix: &Path,
  links: &mut BTreeMap<PathBuf, PathBuf>,
  depth: usize,
  forbid_top_level_symlink: bool,
) -> Result<(), ApiError> {
  if depth > MAX_WALK_DEPTH {
    return Err(ApiError::invalid("目录层级过深（超过 64 层）"));
  }
  let names = dir
    .read_names()
    .map_err(|e| ApiError::invalid(format!("读取目录失败：{e}")))?;
  for name in names {
    let st = dir.lstat(&name).map_err(|e| {
      ApiError::invalid(format!(
        "读取 {} 失败：{e}",
        name.to_string_lossy()
      ))
    })?;
    let seg = OsString::from_vec(name.to_bytes().to_vec());
    let rel = prefix.join(&seg);
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
      let target = dir.readlink(&name).map_err(|e| {
        ApiError::invalid(format!(
          "读取软链接 {} 失败：{e}",
          rel.display()
        ))
      })?;
      if forbid_top_level_symlink && depth == 0 {
        return Err(ApiError::invalid(format!(
          "目录 {} 下的顶层项 {} 是符号链接（-> {}），已拒绝",
          prefix.display(),
          rel.display(),
          target.display()
        )));
      }
      links.insert(rel, target);
    } else if kind == libc::S_IFDIR {
      let child = dir.open_subdir(&name).map_err(|e| {
        ApiError::invalid(format!(
          "打开子目录 {} 失败：{e}",
          rel.display()
        ))
      })?;
      collect_symlinks(
        &child,
        &rel,
        links,
        depth + 1,
        forbid_top_level_symlink,
      )?;
    }
  }
  Ok(())
}

/// 递归扫描目录树（不跟随软链）并用 `wharf_api_types::symlink::validate_symlinks` 校验。
pub(crate) fn validate_tree_symlinks(
  root: &DirFd,
  forbid_top_level_symlink: bool,
) -> Result<(), ApiError> {
  let mut links = BTreeMap::new();
  collect_symlinks(
    root,
    Path::new(""),
    &mut links,
    0,
    forbid_top_level_symlink,
  )?;
  wharf_api_types::symlink::validate_symlinks(&links)
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
