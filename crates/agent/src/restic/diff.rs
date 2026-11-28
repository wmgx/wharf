use std::{
  collections::{BTreeSet, HashSet},
  ffi::{CStr, CString},
  io,
  os::unix::ffi::OsStrExt,
};

use chrono::DateTime;
use serde::Deserialize;
use wharf_api_types::{
  backup::{
    BackupDiffEntry, BackupDiffView, BackupFileEntry,
    normalize_snapshot_rel,
  },
  symlink::check_single_link,
};

use super::{
  browse::{self, Index},
  *,
};

const LIVE_NOTE: &str = "只读对比快照与当前目录（基于类型、大小和修改时间；线上服务未停止，运行中写入可能产生轻微差异）";

fn live_index(
  root: &Path,
  service: &str,
  ctx: &Ctx,
) -> Result<(Index, bool), ApiError> {
  fn scan(
    dir: &DirFd,
    parent: &str,
    nodes: &mut Index,
    ctx: &Ctx,
  ) -> io::Result<()> {
    dir.visit_names(|name| {
      if ctx.cancel.is_cancelled()
        || nodes.len() == browse::DIFF_SCAN_CAP
      {
        return Err(io::ErrorKind::Interrupted.into());
      }
      let name_str = name
        .to_str()
        .map_err(|_| io::Error::other("文件名不是 UTF-8"))?;
      let rel = if parent.is_empty() {
        name_str.to_owned()
      } else {
        format!("{parent}/{name_str}")
      };
      if normalize_snapshot_rel(&rel).is_err() {
        return Err(io::ErrorKind::Interrupted.into());
      }
      let st = match dir.lstat(name) {
        Ok(st) => st,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
          return Ok(());
        }
        Err(err) => return Err(err),
      };
      let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => "dir",
        libc::S_IFREG => "file",
        libc::S_IFLNK => {
          let target = dir.readlink(name)?;
          if check_single_link(Path::new(&rel), &target).is_err() {
            return Ok(());
          }
          "symlink"
        }
        _ => "other",
      };
      nodes.insert(
        rel.clone(),
        BackupFileEntry {
          path: rel.clone(),
          name: name_str.into(),
          kind: kind.into(),
          size: if kind == "file" {
            st.st_size.max(0) as u64
          } else {
            0
          },
          mode: st.st_mode & 0o777,
          modified: DateTime::from_timestamp(st.st_mtime, 0),
          link_target: None,
        },
      );
      if kind == "dir" {
        match dir.open_subdir(name) {
          Ok(sub) => scan(&sub, &rel, nodes, ctx)?,
          Err(e)
            if matches!(
              e.raw_os_error(),
              Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
            ) => {}
          Err(e) => return Err(e),
        }
      }
      Ok(())
    })
  }
  let dir = match DirFd::open_service_root(Path::new("/srv"), service)
  {
    Ok(dir) => dir,
    Err(e) if e.code == ErrorCode::NotFound => {
      return Ok((Index::new(), false));
    }
    Err(e) => return Err(e),
  };
  let mut nodes = Index::new();
  let truncated = match scan(&dir, "", &mut nodes, ctx) {
    Ok(()) => false,
    Err(e) if ctx.cancel.is_cancelled() => {
      return Err(
        ApiError::new(ErrorCode::Cancelled, "差异预览已取消")
          .with_hint(e.kind().to_string()),
      );
    }
    Err(e) if e.kind() == io::ErrorKind::Interrupted => true,
    Err(e) => return Err(dir_error(root, e)),
  };
  Ok((nodes, truncated))
}

struct Excludes(Vec<(bool, Vec<CString>)>);

impl Excludes {
  fn new(root: &Path, excludes: &[String]) -> Result<Self, ApiError> {
    let patterns = wharf_api_types::backup::restic_exclude_patterns(
      root, excludes,
    )?;
    let mut results = Vec::new();
    for pattern in patterns {
      let anchored = Path::new(&pattern).is_absolute();
      let rel = if anchored {
        Path::new(&pattern)
          .strip_prefix(root)
          .map_err(|_| ApiError::invalid("备份排除路径无效"))?
          .as_os_str()
          .as_bytes()
      } else {
        pattern.as_bytes()
      };
      let segments = rel
        .split(|&b| b == b'/')
        .map(CString::new)
        .collect::<Result<_, _>>()
        .map_err(|_| ApiError::invalid("备份排除路径无效"))?;
      results.push((anchored, segments));
    }
    Ok(Self(results))
  }

  fn matches(&self, path: &str) -> bool {
    if self.0.is_empty() {
      return false;
    }
    let segments: Vec<_> = path
      .split('/')
      .filter_map(|p| CString::new(p).ok())
      .collect();
    self.0.iter().any(|(anchored, pattern)| {
      if *anchored {
        matches_anchored(pattern, &segments)
      } else {
        segments
          .iter()
          .any(|part| matches_segment(&pattern[0], part))
      }
    })
  }
}

fn matches_segment(pattern: &CStr, part: &CStr) -> bool {
  unsafe {
    libc::fnmatch(pattern.as_ptr(), part.as_ptr(), libc::FNM_NOESCAPE)
      == 0
  }
}

fn matches_anchored(pattern: &[CString], path: &[CString]) -> bool {
  let mut reachable = vec![false; path.len() + 1];
  reachable[0] = true;
  for part in pattern {
    if part.as_c_str() == c"**" {
      for i in 1..reachable.len() {
        reachable[i] |= reachable[i - 1];
      }
    } else {
      for i in (1..reachable.len()).rev() {
        reachable[i] =
          reachable[i - 1] && matches_segment(part, &path[i - 1]);
      }
      reachable[0] = false;
    }
  }
  reachable.contains(&true)
}

fn compare(
  mut view: BackupDiffView,
  before: &Index,
  after: &Index,
  changed: impl Fn(&str, &BackupFileEntry, &BackupFileEntry) -> bool,
  excludes: &Excludes,
  limit: u32,
) -> BackupDiffView {
  let paths: BTreeSet<_> = before
    .keys()
    .chain(after.keys())
    .filter(|p| !p.is_empty())
    .collect();
  for path in paths {
    let old = before.get(path);
    let new = after.get(path);
    let before_size = old.map(|entry| entry.size);
    let after_size = new.map(|entry| entry.size);
    let excluded = new.is_none() && excludes.matches(path);
    let stats = &mut view.summary;
    let status = match (old, new) {
      (None, Some(new)) => {
        stats.added += 1;
        stats.added_bytes =
          stats.added_bytes.saturating_add(new.size);
        "added"
      }
      (Some(old), None) => {
        stats.removed += 1;
        stats.removed_bytes =
          stats.removed_bytes.saturating_add(old.size);
        if excluded {
          stats.removed_excluded_bytes =
            stats.removed_excluded_bytes.saturating_add(old.size);
        }
        "removed"
      }
      (Some(old), Some(new)) if changed(path, old, new) => {
        stats.modified += 1;
        stats.modified_before_bytes =
          stats.modified_before_bytes.saturating_add(old.size);
        stats.modified_after_bytes =
          stats.modified_after_bytes.saturating_add(new.size);
        "modified"
      }
      _ => {
        stats.unchanged += 1;
        continue;
      }
    };
    view.entries.push(BackupDiffEntry {
      path: path.clone(),
      status: status.into(),
      kind: new.or(old).unwrap().kind.clone(),
      before_size,
      after_size,
      excluded,
    });
  }
  view.entries.sort_by_key(|e| {
    let order = match e.status.as_str() {
      "removed" => 0,
      "modified" => 1,
      _ => 2,
    };
    (order, std::cmp::Reverse(e.before_size.max(e.after_size)))
  });
  let limit = browse::entry_limit(limit);
  view.truncated |= view.entries.len() > limit;
  view.entries.truncate(limit);
  view
}

fn compute_live_diff(
  service: &str,
  snapshot: String,
  snap: &Index,
  live: &Index,
  excludes: &Excludes,
  limit: u32,
  capped: bool,
) -> BackupDiffView {
  compare(
    BackupDiffView {
      service: service.into(),
      mode: "live".into(),
      base: "live".into(),
      target: snapshot,
      summary: Default::default(),
      entries: vec![],
      truncated: capped,
      note: Some(LIVE_NOTE.into()),
    },
    live,
    snap,
    |_, a, b| {
      a.kind != b.kind
        || a.kind == "file"
          && (a.size != b.size
            || a.modified.zip(b.modified).is_some_and(|(x, y)| {
              (x - y).num_milliseconds().unsigned_abs() > 1000
            }))
    },
    excludes,
    limit,
  )
}

pub(super) async fn live(
  j: &Job<'_>,
  root: &Path,
  id: &str,
  excludes: &[String],
  limit: u32,
  ctx: &Ctx,
) -> Result<BackupDiffView, ApiError> {
  let path = root
    .to_str()
    .ok_or_else(|| ApiError::invalid("快照路径无效"))?;
  let (snapshot, nodes, cap_snap) =
    browse::index(j, root, id, &[path], true, ctx).await?;
  if nodes.is_empty() {
    return Err(ApiError::not_found("快照中没有业务目录"));
  }
  let live_root = root.to_owned();
  let service = j.service.to_owned();
  let scan_ctx = ctx.clone();
  let (current, cap_live) = tokio::task::spawn_blocking(move || {
    live_index(&live_root, &service, &scan_ctx)
  })
  .await
  .map_err(|_| ApiError::internal("扫描当前目录失败"))??;
  if cap_snap || cap_live {
    return Ok(BackupDiffView {
      service: j.service.into(),
      mode: "live".into(),
      base: "live".into(),
      target: snapshot,
      summary: Default::default(),
      entries: vec![],
      truncated: true,
      note: Some("目录超过扫描上限，无法生成完整对比".into()),
    });
  }
  Ok(compute_live_diff(
    j.service,
    snapshot,
    &nodes,
    &current,
    &Excludes::new(root, excludes)?,
    limit,
    false,
  ))
}

#[derive(Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
enum ResticDiff {
  Change {
    path: String,
    modifier: String,
  },
  Statistics,
  #[serde(other)]
  Other,
}

pub(super) async fn snapshots(
  j: &Job<'_>,
  root: &Path,
  base: &str,
  target: &str,
  limit: u32,
  ctx: &Ctx,
) -> Result<BackupDiffView, ApiError> {
  check_snapshot(base)?;
  check_snapshot(target)?;
  let root = root
    .to_str()
    .ok_or_else(|| ApiError::invalid("快照路径无效"))?;
  let (base, old, cap_old) =
    browse::index(j, Path::new(root), base, &[root], true, ctx)
      .await?;
  let (target, new, cap_new) =
    browse::index(j, Path::new(root), target, &[root], true, ctx)
      .await?;
  if old.is_empty() || new.is_empty() {
    return Err(ApiError::not_found("快照中没有业务目录"));
  }
  let mut view = BackupDiffView {
    service: j.service.into(),
    mode: "snapshots".into(),
    base,
    target,
    summary: Default::default(),
    entries: vec![],
    truncated: cap_old || cap_new,
    note: None,
  };
  if view.truncated {
    view.note = Some("快照超过扫描上限，无法生成完整对比".into());
    return Ok(view);
  }
  let mut bytes = Vec::new();
  j.restic_to(
    &[
      "diff",
      "--json",
      "--metadata",
      &format!("{}:{root}", view.base),
      &format!("{}:{root}", view.target),
    ],
    browse::INDEX_BYTES,
    &mut bytes,
    ctx,
  )
  .await?;
  let mut changed = HashSet::new();
  let mut complete = false;
  for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
    match serde_json::from_slice(line)
      .map_err(|_| ApiError::internal("无法解析 restic 差异"))?
    {
      ResticDiff::Change { path, modifier }
        if modifier != "+" && modifier != "-" =>
      {
        changed.insert(normalize_snapshot_rel(&path)?.to_owned());
      }
      ResticDiff::Statistics => complete = true,
      _ => {}
    }
  }
  if !complete {
    return Err(ApiError::internal("restic 差异统计缺失"));
  }
  Ok(compare(
    view,
    &old,
    &new,
    |path, _, _| changed.contains(path),
    &Excludes(vec![]),
    limit,
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn compute_live_diff_marks_added_removed_modified_and_excluded() {
    let index = |data: &[(&str, u64)]| {
      data
        .iter()
        .map(|&(name, size)| {
          (
            name.into(),
            BackupFileEntry {
              path: name.into(),
              name: name.into(),
              kind: "file".into(),
              size,
              mode: 0,
              modified: None,
              link_target: None,
            },
          )
        })
        .collect()
    };
    let snap = index(&[("a.txt", 10), ("old.txt", 5)]);
    let live =
      index(&[("a.txt", 20), ("cur.txt", 30), ("cache/x", 100)]);
    let excludes =
      Excludes::new(Path::new("/srv/app"), &["cache/**".into()])
        .unwrap();
    let diff = compute_live_diff(
      "app",
      "id".into(),
      &snap,
      &live,
      &excludes,
      500,
      false,
    );
    assert_eq!(diff.summary.removed_excluded_bytes, 100);
    assert_eq!(
      (
        diff.summary.added,
        diff.summary.modified,
        diff.summary.removed
      ),
      (1, 1, 2)
    );
    assert_eq!(
      diff.entries[2].before_size.zip(diff.entries[2].after_size),
      Some((20, 10))
    );
  }
}
