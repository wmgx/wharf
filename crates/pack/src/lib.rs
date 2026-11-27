//! 把目录打成代码包（tar.gz）。CLI 的 `wharf deploy` 和 agent 打包服务器上的目录共用。
//!
//! - 按 `.gitignore`、`.dockerignore` 排除文件（不要求是 git 仓库），不打包 `.git`；
//! - 内容相同就得到相同的包：文件按路径排序，时间、属主固定，权限只保留可执行位。
//!   代码没变时 sha256 不变，控制面不用重新接收，服务也不用重新构建。

use std::{
  collections::BTreeMap,
  io::{self, Read, Write},
  path::{Path, PathBuf},
};

use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use wharf_api_types::ApiError;

mod archive;
pub use archive::{unpack_validated, validate_archive};

/// 和控制面接收上传的上限一致。
pub const MAX_ARCHIVE: usize = 512 * 1024 * 1024;

pub fn gzip_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
  let mut encoder =
    flate2::write::GzEncoder::new(Vec::new(), Compression::default());
  encoder.write_all(data)?;
  encoder.finish()
}

pub fn gunzip_bytes(
  data: &[u8],
  max_bytes: usize,
) -> io::Result<Vec<u8>> {
  let mut out = Vec::new();
  flate2::read::GzDecoder::new(data)
    .take((max_bytes as u64).saturating_add(1))
    .read_to_end(&mut out)?;
  if out.len() > max_bytes {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "解压后超过大小限制",
    ));
  }
  Ok(out)
}

pub struct Packed {
  pub bytes: Vec<u8>,
  pub sha256: String,
  pub files: usize,
}

fn io_err(path: &Path, e: impl std::fmt::Display) -> ApiError {
  ApiError::invalid(format!("{}：{e}", path.display()))
}

/// 要打包的文件（相对路径，按路径排序）。
pub fn list_files(dir: &Path) -> Result<Vec<PathBuf>, ApiError> {
  list_files_with(dir, &[])
}

pub fn list_files_with(
  dir: &Path,
  keep: &[PathBuf],
) -> Result<Vec<PathBuf>, ApiError> {
  if !dir.is_dir() {
    return Err(ApiError::invalid(format!(
      "{} 不是目录",
      dir.display()
    )));
  }
  let walker = ignore::WalkBuilder::new(dir)
    .parents(false)
    .ignore(false)
    .hidden(false)
    .git_ignore(true)
    .git_exclude(true)
    .git_global(false)
    .require_git(false)
    .add_custom_ignore_filename(".dockerignore")
    .filter_entry(|e| e.file_name() != ".git")
    .build();
  let mut files = Vec::new();
  for entry in walker {
    let entry = entry.map_err(|e| io_err(dir, e))?;
    let is_file_or_link = entry
      .file_type()
      .is_some_and(|t| t.is_file() || t.is_symlink());
    if !is_file_or_link {
      continue;
    }
    let rel = entry
      .path()
      .strip_prefix(dir)
      .map_err(|e| io_err(entry.path(), e))?
      .to_path_buf();
    files.push(rel);
  }
  let root = dir.canonicalize().map_err(|e| io_err(dir, e))?;
  for rel in keep {
    wharf_api_types::symlink::check_relative_entry(rel)?;
    let path = root.join(rel);
    if path.is_file() {
      let resolved =
        path.canonicalize().map_err(|e| io_err(&path, e))?;
      if !resolved.starts_with(&root) {
        return Err(ApiError::invalid(format!(
          "{} 指向打包目录之外",
          rel.display()
        )));
      }
      files.push(rel.clone());
      if resolved != path {
        let target =
          resolved.strip_prefix(&root).expect("已检查目录");
        wharf_api_types::symlink::check_relative_entry(target)?;
        files.push(target.to_path_buf());
      }
    }
  }
  files.sort();
  files.dedup();
  Ok(files)
}

pub fn pack(dir: &Path) -> Result<Packed, ApiError> {
  pack_with(dir, &[])
}

pub fn pack_with(
  dir: &Path,
  keep: &[PathBuf],
) -> Result<Packed, ApiError> {
  pack_files(dir, list_files_with(dir, keep)?)
}

pub fn pack_file(file: &Path) -> Result<Packed, ApiError> {
  let name =
    file.file_name().ok_or_else(|| io_err(file, "缺少文件名"))?;
  if !file.symlink_metadata().is_ok_and(|m| m.is_file()) {
    return Err(io_err(file, "需要普通文件"));
  }
  pack_files(
    file
      .parent()
      .filter(|p| !p.as_os_str().is_empty())
      .unwrap_or(Path::new(".")),
    vec![name.into()],
  )
}

pub fn pack_files(
  dir: &Path,
  files: Vec<PathBuf>,
) -> Result<Packed, ApiError> {
  let (bytes, sha256, _) = write_archive(dir, &files, Vec::new())?;
  Ok(Packed {
    bytes,
    sha256,
    files: files.len(),
  })
}

pub fn pack_to_file(
  dir: &Path,
  out: &Path,
  keep: &[PathBuf],
) -> Result<(String, usize, usize), ApiError> {
  let files = list_files_with(dir, keep)?;
  let file =
    std::fs::File::create(out).map_err(|e| io_err(out, e))?;
  match write_archive(dir, &files, std::io::BufWriter::new(file)) {
    Ok((_, sha, len)) => Ok((sha, len, files.len())),
    Err(e) => {
      let _ = std::fs::remove_file(out);
      Err(e)
    }
  }
}

struct LimitWriter<W> {
  inner: W,
  written: usize,
  hash: Sha256,
  exceeded: bool,
}

impl<W: Write> Write for LimitWriter<W> {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    if self.exceeded || buf.len() > MAX_ARCHIVE - self.written {
      self.exceeded = true;
      return Err(std::io::Error::other("代码包压缩后超过 512 MiB"));
    }
    let n = self.inner.write(buf)?;
    self.written += n;
    self.hash.update(&buf[..n]);
    Ok(n)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    self.inner.flush()
  }
}

fn write_archive<W: Write>(
  dir: &Path,
  files: &[PathBuf],
  out: W,
) -> Result<(W, String, usize), ApiError> {
  if files.is_empty() {
    return Err(ApiError::invalid(format!(
      "{} 里没有要部署的文件",
      dir.display()
    )));
  }
  let root = dir.canonicalize().map_err(|e| io_err(dir, e))?;
  let mut links = BTreeMap::new();
  for rel in files {
    wharf_api_types::symlink::check_relative_entry(rel)?;
    let path = root.join(rel);
    if path.canonicalize().is_ok_and(|p| !p.starts_with(&root)) {
      return Err(io_err(rel, "软链接指向打包目录之外"));
    }
    if path
      .symlink_metadata()
      .map_err(|e| io_err(&path, e))?
      .is_symlink()
    {
      let target = path.read_link().map_err(|e| io_err(&path, e))?;
      links.insert(rel.clone(), target);
    }
  }
  wharf_api_types::symlink::validate_symlinks(&links)?;
  let gz = GzBuilder::new().mtime(0).write(
    LimitWriter {
      inner: out,
      written: 0,
      hash: Sha256::new(),
      exceeded: false,
    },
    Compression::default(),
  );
  let mut tar = tar::Builder::new(gz);
  for rel in files {
    let path = dir.join(rel);
    let meta = std::fs::symlink_metadata(&path)
      .map_err(|e| io_err(&path, e))?;
    let mut header = tar::Header::new_gnu();
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    let name = rel;
    if let Some(target) = links.get(rel) {
      header.set_entry_type(tar::EntryType::Symlink);
      header.set_size(0);
      header.set_mode(0o777);
      tar
        .append_link(&mut header, name, target)
        .map_err(|e| io_err(&path, e))?;
      continue;
    }
    if !meta.is_file() {
      return Err(ApiError::invalid(format!(
        "打包条目 {} 已变化",
        rel.display()
      )));
    }
    header.set_size(meta.len());
    header.set_mode(if executable(&meta) { 0o755 } else { 0o644 });
    let file =
      std::fs::File::open(&path).map_err(|e| io_err(&path, e))?;
    if let Err(e) = tar.append_data(&mut header, name, file) {
      return Err(if tar.get_ref().get_ref().exceeded {
        too_big()
      } else {
        io_err(&path, e)
      });
    }
  }
  let gz = tar.into_inner().map_err(|e| io_err(dir, e))?;
  let mut out = gz.finish().map_err(|e| io_err(dir, e))?;
  out.flush().map_err(|e| io_err(dir, e))?;
  Ok((out.inner, hex::encode(out.hash.finalize()), out.written))
}

fn too_big() -> ApiError {
  ApiError::invalid("打包后超过 512 MiB").with_hint(
    "把构建产物、数据文件、依赖目录写进 .gitignore 或 .dockerignore",
  )
}

#[cfg(unix)]
fn executable(meta: &std::fs::Metadata) -> bool {
  use std::os::unix::fs::PermissionsExt;
  meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &std::fs::Metadata) -> bool {
  false
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(unix)]
  #[test]
  fn pack_and_archive_reject_escaping_and_chained_symlinks() {
    use std::{fs, os::unix::fs::symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("src");
    fs::create_dir_all(root.join("sub")).unwrap();
    for target in
      [temp.path().join("outside"), PathBuf::from("../../outside")]
    {
      symlink(target, root.join("sub/link")).unwrap();
      assert!(pack(&root).is_err());
      fs::remove_file(root.join("sub/link")).unwrap();
    }
    symlink("..", root.join("sub/parent")).unwrap();
    symlink("parent/..", root.join("sub/link")).unwrap();
    assert!(pack(&root).is_err());
    fs::remove_file(root.join("sub/link")).unwrap();
    fs::remove_file(root.join("sub/parent")).unwrap();

    fs::create_dir(root.join("dist")).unwrap();
    fs::write(root.join("dist/main"), "hello").unwrap();
    symlink("../dist/main", root.join("sub/link")).unwrap();
    let archive = temp.path().join("source.tar.gz");
    fs::write(&archive, pack(&root).unwrap().bytes).unwrap();
    assert!(validate_archive(&archive).is_ok());
    let dest = temp.path().join("unpacked");
    unpack_validated(&archive, &dest).unwrap();
    assert_eq!(
      fs::read_to_string(dest.join("sub/link")).unwrap(),
      "hello"
    );

    let gz = flate2::write::GzEncoder::new(
      fs::File::create(&archive).unwrap(),
      Compression::default(),
    );
    let mut tar = tar::Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Link);
    header.set_size(0);
    tar.append_link(&mut header, "link", "../outside").unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    assert!(validate_archive(&archive).is_err());
    assert!(
      wharf_api_types::symlink::check_relative_entry(Path::new(
        "../outside"
      ))
      .is_err()
    );
  }

  #[test]
  fn respects_gitignore_and_is_reproducible() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join(".gitignore"), "venv/\n*.log\n").unwrap();
    std::fs::write(d.join("main.py"), "print(1)").unwrap();
    std::fs::write(d.join("x.log"), "noise").unwrap();
    std::fs::create_dir_all(d.join("venv/lib")).unwrap();
    std::fs::write(d.join("venv/lib/big"), "x").unwrap();
    std::fs::create_dir_all(d.join(".git")).unwrap();
    std::fs::write(d.join(".git/HEAD"), "ref").unwrap();
    assert_eq!(
      list_files(d).unwrap(),
      vec![PathBuf::from(".gitignore"), PathBuf::from("main.py")]
    );
    let a = pack(d).unwrap();
    let b = pack(d).unwrap();
    assert_eq!(a.sha256, b.sha256);
    std::fs::write(d.join("main.py"), "print(2)").unwrap();
    assert_ne!(pack(d).unwrap().sha256, a.sha256);
  }
}
