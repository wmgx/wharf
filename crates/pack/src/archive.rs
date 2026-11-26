use std::{
  collections::BTreeMap,
  fs::File,
  io::{Read, Take},
  path::Path,
};

use flate2::read::GzDecoder;
use wharf_api_types::{
  ApiError,
  symlink::{check_relative_entry, validate_symlinks},
};

use crate::io_err;

const MAX_ENTRIES: usize = 100_000;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;

fn archive(
  path: &Path,
) -> Result<tar::Archive<Take<GzDecoder<File>>>, ApiError> {
  let file = File::open(path).map_err(|e| io_err(path, e))?;
  let mut archive =
    tar::Archive::new(GzDecoder::new(file).take(MAX_EXPANDED));
  archive.set_preserve_mtime(false);
  Ok(archive)
}

pub fn validate_archive(path: &Path) -> Result<(), ApiError> {
  let mut archive = archive(path)?;
  let entries = archive.entries().map_err(|e| io_err(path, e))?;
  let mut types = BTreeMap::new();
  let mut links = BTreeMap::new();
  let mut hardlinks = Vec::new();
  let mut total = 0_u64;
  for (count, entry) in entries.enumerate() {
    let entry = entry.map_err(|e| io_err(path, e))?;
    total = total.saturating_add(entry.size());
    if count >= MAX_ENTRIES || total >= MAX_EXPANDED {
      return Err(ApiError::invalid("代码包解压后过大"));
    }
    let rel = check_relative_entry(
      &entry.path().map_err(|e| io_err(path, e))?,
    )?;
    let kind = entry.header().entry_type();
    if rel.as_os_str().is_empty() && !kind.is_dir() {
      return Err(ApiError::invalid("代码包根条目必须是目录"));
    }
    if types.insert(rel.clone(), kind).is_some() {
      return Err(ApiError::invalid(format!(
        "代码包重复条目：{}",
        rel.display()
      )));
    }
    if kind.is_symlink() || kind.is_hard_link() {
      let target = entry
        .link_name()
        .map_err(|e| io_err(path, e))?
        .ok_or_else(|| ApiError::invalid("代码包链接缺少目标"))?
        .into_owned();
      if kind.is_symlink() {
        links.insert(rel, target);
      } else {
        hardlinks.push(check_relative_entry(&target)?);
      }
    } else if !kind.is_file() && !kind.is_dir() {
      return Err(ApiError::invalid(format!(
        "代码包条目类型不支持：{}",
        rel.display()
      )));
    }
  }
  if archive.into_inner().limit() == 0 {
    return Err(ApiError::invalid("代码包解压后过大"));
  }
  for rel in types.keys().chain(&hardlinks) {
    if rel
      .ancestors()
      .skip(1)
      .any(|p| types.get(p).is_some_and(|t| !t.is_dir()))
    {
      return Err(ApiError::invalid(format!(
        "代码包条目经过非目录：{}",
        rel.display()
      )));
    }
  }
  for target in hardlinks {
    if !types.get(&target).is_some_and(|t| t.is_file()) {
      return Err(ApiError::invalid(format!(
        "代码包硬链接目标不是普通文件：{}",
        target.display()
      )));
    }
  }
  validate_symlinks(&links)
}

/// 校验和解包使用同一个归档解析器。
pub fn unpack_validated(
  path: &Path,
  to: &Path,
) -> Result<(), ApiError> {
  validate_archive(path)?;
  archive(path)?.unpack(to).map_err(|e| io_err(path, e))
}
