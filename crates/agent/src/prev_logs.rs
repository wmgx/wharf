//! 在容器消失前抓取一份日志。调用方持有项目锁。

use std::{
  fs::{self, OpenOptions},
  io::{self, Read, Write},
  os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
  path::{Path, PathBuf},
  time::Duration,
};

use chrono::{DateTime, Utc};
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{PrevLogMeta, PrevLogOutput, TRIAL_PROJECT_PREFIX},
};

use crate::{docker::Docker, exec::Ctx};

const MAX_LINES: u32 = 2000;
const MAX_RAW_BYTES: usize = 4 * 1024 * 1024;
const MAX_GZIP_BYTES: usize = MAX_RAW_BYTES + 64 * 1024;
const KEEP_FILES: usize = 5;
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(15);

fn dir(data: &Path, project: &str) -> PathBuf {
  data.join("prev-logs").join(project)
}

pub async fn capture(
  docker: &Docker,
  project: &str,
  reason: &'static str,
  ctx: &Ctx,
) {
  if project.starts_with(TRIAL_PROJECT_PREFIX)
    || ctx.cancel.is_cancelled()
  {
    return;
  }
  let quiet = Ctx {
    cancel: ctx.cancel.child_token(),
    progress: None,
  };
  let cancel = quiet.cancel.clone();
  let timer = tokio::spawn(async move {
    tokio::time::sleep(CAPTURE_TIMEOUT).await;
    cancel.cancel();
  });
  let result = async {
    let state = docker.one_status(project, &quiet).await?;
    // 混有外部容器时 compose logs 可能读到不归此服务的日志。
    if state.containers.is_empty()
      || state.containers.iter().any(|c| c.foreign)
    {
      return Ok(());
    }
    let logs =
      docker.logs(project, MAX_LINES, None, None, &quiet).await?;
    if !logs.trim().is_empty() {
      let dir = dir(&docker.data_dir, project);
      tokio::task::spawn_blocking(move || save(&dir, reason, &logs))
        .await
        .map_err(|e| {
          ApiError::internal(format!("旧日志留存失败：{e}"))
        })?
        .map_err(io_error)?;
    }
    Ok::<_, ApiError>(())
  }
  .await;
  timer.abort();
  if let Err(e) = result {
    tracing::warn!(project, code = ?e.code, "旧日志留存失败");
  }
}

fn io_error(e: io::Error) -> ApiError {
  ApiError::new(
    ErrorCode::AgentFailed,
    format!("旧日志文件操作失败：{e}"),
  )
}

fn private_dir(dir: &Path) -> io::Result<()> {
  match fs::DirBuilder::new().mode(0o700).create(dir) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
      let metadata = dir.symlink_metadata()?;
      if !metadata.is_dir() {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "旧日志路径不是目录",
        ));
      }
      if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
      }
      Ok(())
    }
    Err(e) => Err(e),
  }
}

fn bounded_tail(logs: &str) -> &str {
  let start = logs.len().saturating_sub(MAX_RAW_BYTES);
  let mut start = logs.ceil_char_boundary(start);
  if start > 0
    && logs.as_bytes()[start - 1] != b'\n'
    && let Some((line, rest)) = logs[start..].split_once('\n')
    && !rest.trim().is_empty()
  {
    start += line.len() + 1;
  }
  let logs = &logs[start..];
  let end = logs.trim_end_matches('\n').len();
  let start = logs[..end]
    .rmatch_indices('\n')
    .nth(MAX_LINES as usize - 1)
    .map_or(0, |(offset, _)| offset + 1);
  &logs[start..]
}

fn save(dir: &Path, reason: &str, logs: &str) -> io::Result<()> {
  let logs = bounded_tail(logs);
  if logs.trim().is_empty() {
    return Ok(());
  }
  private_dir(dir.parent().unwrap())?;
  private_dir(dir)?;
  let bytes = wharf_pack::gzip_bytes(logs.as_bytes())?;
  let tmp = dir.join("capture.tmp");
  match fs::remove_file(&tmp) {
    Ok(()) => {}
    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
    Err(e) => return Err(e),
  }
  let mut at = Utc::now().timestamp_millis();
  if let Some((latest, _)) = entries(dir)?.first() {
    at = at.max(latest.at + 1);
  }
  let path = dir.join(format!("{at}-{reason}.log.gz"));
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(&tmp)?;
  file.write_all(&bytes)?;
  file.sync_all()?;
  fs::rename(&tmp, path)?;
  for (_, path) in entries(dir)?.into_iter().skip(KEEP_FILES) {
    fs::remove_file(path)?;
  }
  Ok(())
}

fn entries(dir: &Path) -> io::Result<Vec<(PrevLogMeta, PathBuf)>> {
  for path in [dir.parent().unwrap(), dir] {
    match path.symlink_metadata() {
      Ok(meta) if meta.is_dir() => {}
      Ok(_) => {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "旧日志路径不是目录",
        ));
      }
      Err(e) if e.kind() == io::ErrorKind::NotFound => {
        return Ok(vec![]);
      }
      Err(e) => return Err(e),
    }
  }
  let listing = fs::read_dir(dir)?;
  let mut rows = vec![];
  for entry in listing {
    let entry = entry?;
    let file = entry.file_name();
    let Some((stamp, reason)) = file
      .to_str()
      .and_then(|s| s.strip_suffix(".log.gz"))
      .and_then(|s| s.split_once('-'))
    else {
      continue;
    };
    let Ok(at) = stamp.parse::<i64>() else {
      continue;
    };
    if at <= 0
      || DateTime::from_timestamp_millis(at).is_none()
      || !matches!(reason, "recreate" | "rollback" | "remove")
      || !entry.file_type()?.is_file()
    {
      continue;
    }
    rows.push((
      PrevLogMeta {
        index: 0,
        at,
        reason: reason.into(),
        size_bytes: entry.metadata()?.len(),
      },
      entry.path(),
    ));
  }
  rows.sort_unstable_by(|(a, _), (b, _)| {
    b.at.cmp(&a.at).then(a.reason.cmp(&b.reason))
  });
  for (index, (item, _)) in rows.iter_mut().enumerate() {
    item.index = index as u32 + 1;
  }
  Ok(rows)
}

pub fn list(
  data: &Path,
  project: &str,
) -> Result<Vec<PrevLogMeta>, ApiError> {
  Ok(
    entries(&dir(data, project))
      .map_err(io_error)?
      .into_iter()
      .map(|(item, _)| item)
      .collect(),
  )
}

pub fn read(
  data: &Path,
  project: &str,
  index: u32,
  tail: u32,
  since: Option<&str>,
  until: Option<&str>,
) -> Result<PrevLogOutput, ApiError> {
  let rows = entries(&dir(data, project)).map_err(io_error)?;
  let available = rows.len() as u32;
  let index = index.max(1);
  let (item, path) = rows.get((index - 1) as usize).ok_or_else(|| {
    ApiError::not_found(format!("服务 {project} 没有第 {index} 份重建前日志（当前共有 {available} 份）"))
      .with_hint(format!("运行 wharf service logs {project} --previous-list 查看可用历史日志"))
  })?;
  let parse = |value: Option<&str>| {
    value
      .map(DateTime::parse_from_rfc3339)
      .transpose()
      .map_err(|_| ApiError::invalid("日志时间需为 RFC 3339"))
  };
  let since = parse(since)?;
  let until = parse(until)?;
  let mut raw = Vec::new();
  OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW)
    .open(path)
    .and_then(|f| {
      f.take(MAX_GZIP_BYTES as u64 + 1).read_to_end(&mut raw)
    })
    .map_err(io_error)?;
  if raw.len() > MAX_GZIP_BYTES {
    return Err(ApiError::invalid("旧日志压缩文件超过大小限制"));
  }
  let raw = wharf_pack::gunzip_bytes(&raw, MAX_RAW_BYTES)
    .map_err(io_error)?;
  let logs = String::from_utf8_lossy(&raw);
  let mut timestamp = None;
  let lines: Vec<_> = logs
    .lines()
    .filter(|line| {
      if since.is_none() && until.is_none() {
        return true;
      }
      let log =
        line.split_once(" | ").map_or(*line, |(_, body)| body);
      if let Some(at) = log
        .split_whitespace()
        .next()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
      {
        timestamp = Some(at);
      }
      timestamp.is_some_and(|at| {
        since.is_none_or(|from| at >= from)
          && until.is_none_or(|to| at <= to)
      })
    })
    .collect();
  let logs = lines[lines
    .len()
    .saturating_sub(tail.clamp(1, MAX_LINES) as usize)..]
    .join("\n");
  let logs = if logs.is_empty() {
    logs
  } else {
    format!("{logs}\n")
  };
  Ok(PrevLogOutput {
    index,
    at: item.at,
    reason: item.reason.clone(),
    available,
    logs,
  })
}

pub fn purge(data: &Path, project: &str) {
  if !data
    .join("prev-logs")
    .symlink_metadata()
    .is_ok_and(|m| m.is_dir())
  {
    return;
  }
  if let Err(e) = fs::remove_dir_all(dir(data, project))
    && e.kind() != io::ErrorKind::NotFound
  {
    tracing::warn!(project, kind = ?e.kind(), "清理旧日志失败");
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn saves_utf8_tail_when_last_line_exceeds_byte_limit() {
    let root = tempfile::tempdir().unwrap();
    let logs = format!(
      "earlier line\n{} end\n",
      "文".repeat(MAX_RAW_BYTES / 3 + 5)
    );
    save(&dir(root.path(), "app"), "recreate", &logs).unwrap();
    let result = read(root.path(), "app", 1, 1, None, None).unwrap();
    assert!(logs.ends_with(&result.logs));
    assert!(result.logs.ends_with(" end\n"));
    assert!(
      (MAX_RAW_BYTES - 2..=MAX_RAW_BYTES)
        .contains(&result.logs.len())
    );
  }

  #[test]
  fn until_keeps_only_eligible_timestamp_and_its_continuations() {
    let root = tempfile::tempdir().unwrap();
    let raw = "web | 2026-01-01T10:00:00Z old\nstack\nweb | 2026-01-01T10:30:00Z new\ndropped\n";
    save(&dir(root.path(), "app"), "recreate", raw).unwrap();
    let r = read(
      root.path(),
      "app",
      1,
      10,
      None,
      Some("2026-01-01T10:15:00Z"),
    )
    .unwrap();
    assert_eq!(r.logs, "web | 2026-01-01T10:00:00Z old\nstack\n");
  }

  #[test]
  fn capture_rotates_five_by_name_and_filters_since() {
    let root = tempfile::tempdir().unwrap();
    let dir = dir(root.path(), "app");
    for n in 0..7 {
      save(&dir, "recreate", &format!(
        "web-1  | 2026-01-01T00:00:00Z old {n}\nweb-1  | 2026-01-01T00:00:01Z new {n}\n"
      )).unwrap();
    }
    let entries = entries(&dir).unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(
      entries[0].1.metadata().unwrap().permissions().mode() & 0o777,
      0o600
    );
    let result = read(
      root.path(),
      "app",
      2,
      2,
      Some("2026-01-01T00:00:01Z"),
      None,
    )
    .unwrap();
    assert!(result.logs.ends_with("new 5\n"));
    assert!(!result.logs.contains("old"));
    purge(root.path(), "app");
    assert!(list(root.path(), "app").unwrap().is_empty());
  }
}
