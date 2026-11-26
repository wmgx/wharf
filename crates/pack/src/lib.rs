//! 把目录打成代码包（tar.gz）。CLI 的 `wharf deploy` 和 agent 打包服务器上的目录共用。
//!
//! - 按 `.gitignore`、`.dockerignore` 排除文件（不要求是 git 仓库），不打包 `.git`；
//! - 内容相同就得到相同的包：文件按路径排序，时间、属主固定，权限只保留可执行位。
//!   代码没变时 sha256 不变，控制面不用重新接收，服务也不用重新构建；
//! - 拒绝指向目录之外的绝对/相对/链式软链接，保留指向目录内部的相对软链接。

use std::{
  collections::{BTreeMap, BTreeSet},
  io::Write,
  path::{Path, PathBuf},
};

use flate2::{Compression, GzBuilder, read::GzDecoder};
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError,
  symlink::{check_relative_entry, validate_symlinks},
};

/// 和控制面接收上传的上限一致。
pub const MAX_ARCHIVE: usize = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

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
  let walker = ignore::WalkBuilder::new(dir)
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
  files.sort();
  Ok(files)
}

pub fn pack(dir: &Path) -> Result<Packed, ApiError> {
  if !dir.is_dir() {
    return Err(ApiError::invalid(format!(
      "{} 不是目录",
      dir.display()
    )));
  }
  let root_canon = dir.canonicalize().map_err(|e| io_err(dir, e))?;
  let files = list_files(dir)?;
  if files.is_empty() {
    return Err(ApiError::invalid(format!(
      "{} 里没有要部署的文件",
      dir.display()
    )));
  }

  // 先全量收集并校验软链接（词法 + 链式展开 + 已存在目标的物理路径二次核验）。
  let mut links = BTreeMap::new();
  for rel in &files {
    let path = dir.join(rel);
    let meta = std::fs::symlink_metadata(&path)
      .map_err(|e| io_err(&path, e))?;
    if meta.file_type().is_symlink() {
      let target =
        std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
      links.insert(rel.clone(), target);
    }
  }
  validate_symlinks(&links)?;
  for rel in links.keys() {
    let path = dir.join(rel);
    if let Ok(resolved) = std::fs::canonicalize(&path)
      && !resolved.starts_with(&root_canon)
    {
      return Err(
        ApiError::invalid(format!(
          "软链接 {} 解析后指向了目录之外",
          rel.display()
        ))
        .with_hint(
          "删掉这个软链接、把它加入 .dockerignore / .gitignore，或改用目录内相对链接",
        ),
      );
    }
  }

  let gz = GzBuilder::new()
    .mtime(0)
    .write(Vec::new(), Compression::default());
  let mut tar = tar::Builder::new(gz);
  for rel in &files {
    let path = dir.join(rel);
    let meta = std::fs::symlink_metadata(&path)
      .map_err(|e| io_err(&path, e))?;
    let mut header = tar::Header::new_gnu();
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    let name = rel.to_string_lossy().replace('\\', "/");
    if meta.file_type().is_symlink() {
      let target =
        std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
      header.set_entry_type(tar::EntryType::Symlink);
      header.set_size(0);
      header.set_mode(0o777);
      tar
        .append_link(&mut header, &name, &target)
        .map_err(|e| io_err(&path, e))?;
      continue;
    }
    header.set_size(meta.len());
    header.set_mode(if executable(&meta) { 0o755 } else { 0o644 });
    let file =
      std::fs::File::open(&path).map_err(|e| io_err(&path, e))?;
    tar
      .append_data(&mut header, &name, file)
      .map_err(|e| io_err(&path, e))?;
    if tar.get_ref().get_ref().len() > MAX_ARCHIVE {
      return Err(too_big());
    }
  }
  let mut gz = tar.into_inner().map_err(|e| io_err(dir, e))?;
  gz.flush().map_err(|e| io_err(dir, e))?;
  let bytes = gz.finish().map_err(|e| io_err(dir, e))?;
  if bytes.len() > MAX_ARCHIVE {
    return Err(too_big());
  }
  let sha256 = hex::encode(Sha256::digest(&bytes));
  Ok(Packed {
    bytes,
    sha256,
    files: files.len(),
  })
}

/// 校验 `.tar.gz` 代码包：拒绝越界路径、特殊设备节点、逃逸软链接与硬链接。
pub fn validate_archive(path: &Path) -> Result<(), ApiError> {
  let file =
    std::fs::File::open(path).map_err(|e| io_err(path, e))?;
  let mut tar = tar::Archive::new(GzDecoder::new(file));
  let entries = tar
    .entries()
    .map_err(|e| ApiError::invalid(format!("代码包格式不对：{e}")))?;

  let mut count = 0usize;
  let mut links: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
  let mut hardlinks: BTreeSet<PathBuf> = BTreeSet::new();

  for entry in entries {
    count += 1;
    if count > MAX_ENTRIES {
      return Err(ApiError::invalid(format!(
        "代码包条目数超过上限（{MAX_ENTRIES}）"
      )));
    }
    let entry = entry.map_err(|e| {
      ApiError::invalid(format!("代码包格式不对：{e}"))
    })?;
    let raw_path = entry.path().map_err(|e| {
      ApiError::invalid(format!("归档路径读取失败：{e}"))
    })?;
    let rel = check_relative_entry(&raw_path)?;
    let kind = entry.header().entry_type();
    if matches!(
      kind,
      tar::EntryType::Char
        | tar::EntryType::Block
        | tar::EntryType::Fifo
    ) {
      return Err(ApiError::invalid(format!(
        "代码包包含不允许的特殊文件：{}",
        rel.display()
      )));
    }
    if kind == tar::EntryType::Symlink {
      if rel.as_os_str().is_empty() {
        return Err(ApiError::invalid("代码包包含空路径软链接"));
      }
      let target = entry
        .link_name()
        .map_err(|e| {
          ApiError::invalid(format!("读取软链接失败：{e}"))
        })?
        .ok_or_else(|| ApiError::invalid("软链接缺少目标路径"))?
        .into_owned();
      links.insert(rel, target);
    } else if kind == tar::EntryType::Link {
      if rel.as_os_str().is_empty() {
        return Err(ApiError::invalid("代码包包含空路径硬链接"));
      }
      let target = entry
        .link_name()
        .map_err(|e| {
          ApiError::invalid(format!("读取硬链接失败：{e}"))
        })?
        .ok_or_else(|| ApiError::invalid("硬链接缺少目标路径"))?;
      let norm = check_relative_entry(&target)?;
      if norm.as_os_str().is_empty() {
        return Err(ApiError::invalid("硬链接目标路径不能为空"));
      }
      hardlinks.insert(norm);
    }
  }

  validate_symlinks(&links)?;
  for target in &hardlinks {
    if links.contains_key(target) {
      return Err(ApiError::invalid(format!(
        "代码包包含指向软链接的硬链接：{}",
        target.display()
      )));
    }
  }
  Ok(())
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

  #[cfg(unix)]
  #[test]
  fn pack_and_archive_reject_escaping_and_chained_symlinks() {
    use std::os::unix::fs::symlink;

    // ① 绝对软链 a -> /etc/passwd：pack 拒绝。
    let d1 = tempfile::tempdir().unwrap();
    std::fs::write(d1.path().join("app.txt"), "ok").unwrap();
    symlink("/etc/passwd", d1.path().join("a")).unwrap();
    assert!(pack(d1.path()).is_err());

    // ② 相对越界软链 sub/a -> ../../outside：pack 拒绝。
    let d2 = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d2.path().join("sub")).unwrap();
    symlink("../../outside", d2.path().join("sub/a")).unwrap();
    assert!(pack(d2.path()).is_err());

    // ③ 链式逃逸软链 sub/l1 -> .. + sub/l2 -> l1/..：pack 拒绝。
    let d3 = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d3.path().join("sub")).unwrap();
    symlink("..", d3.path().join("sub/l1")).unwrap();
    symlink("l1/..", d3.path().join("sub/l2")).unwrap();
    assert!(pack(d3.path()).is_err());

    // ④ 目录内合法相对软链 bin/cli -> ../dist/cli.js：pack 与 validate_archive 均通过。
    let d4 = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d4.path().join("bin")).unwrap();
    std::fs::create_dir_all(d4.path().join("dist")).unwrap();
    std::fs::write(d4.path().join("dist/cli.js"), "console.log(1)")
      .unwrap();
    symlink("../dist/cli.js", d4.path().join("bin/cli")).unwrap();
    let packed = pack(d4.path()).unwrap();
    let ok_tar = d4.path().join("ok.tar.gz");
    std::fs::write(&ok_tar, &packed.bytes).unwrap();
    assert!(validate_archive(&ok_tar).is_ok());

    // ⑤ 手工构造含越界硬链接的 tar.gz：validate_archive 拒绝。
    let d5 = tempfile::tempdir().unwrap();
    let bad_hardlink = d5.path().join("bad-hl.tar.gz");
    {
      let f = std::fs::File::create(&bad_hardlink).unwrap();
      let gz = GzBuilder::new().write(f, Compression::default());
      let mut builder = tar::Builder::new(gz);
      let mut h = tar::Header::new_gnu();
      h.set_entry_type(tar::EntryType::Link);
      h.set_size(0);
      h.set_mode(0o644);
      builder
        .append_link(&mut h, "evil", "../etc/passwd")
        .unwrap();
      builder.into_inner().unwrap().finish().unwrap();
    }
    assert!(validate_archive(&bad_hardlink).is_err());

    // 手工构造含 ../evil 条目的 tar.gz：validate_archive 拒绝。
    let bad_entry = d5.path().join("bad-entry.tar.gz");
    {
      let f = std::fs::File::create(&bad_entry).unwrap();
      let gz = GzBuilder::new().write(f, Compression::default());
      let mut builder = tar::Builder::new(gz);
      let mut h = tar::Header::new_gnu();
      h.set_entry_type(tar::EntryType::Regular);
      h.set_size(1);
      h.set_mode(0o644);
      // 直接在 header 字节里写入越界路径，绕过 tar::Builder 的安全检查。
      let name = b"../evil";
      h.as_gnu_mut().unwrap().name[..name.len()]
        .copy_from_slice(name);
      h.set_cksum();
      builder.append(&h, &b"x"[..]).unwrap();
      builder.into_inner().unwrap().finish().unwrap();
    }
    assert!(validate_archive(&bad_entry).is_err());
  }
}
