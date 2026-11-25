use std::{
  fs::{self, OpenOptions},
  io::{ErrorKind, Read, Seek, SeekFrom},
  os::unix::fs::OpenOptionsExt,
  path::Path,
};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  access_logs::{
    AccessLogEntry, AccessLogsRequest, AccessLogsResult, MAX_TAIL,
  },
  validate_name,
};

use crate::{docker::io_err, exec::Ctx};

const BLOCK_SIZE: usize = 64 * 1024;
const MAX_LINES: usize = 50_000;
const MAX_BYTES: usize = 20 * 1024 * 1024;

#[derive(Deserialize)]
struct Row {
  #[serde(deserialize_with = "timestamp")]
  ts: DateTime<Utc>,
  request: Request,
  status: u16,
  duration: f64,
  size: u64,
}

#[derive(Deserialize)]
struct Request {
  host: String,
  method: String,
  uri: String,
  client_ip: String,
}

fn timestamp<'de, D: serde::Deserializer<'de>>(
  deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum Timestamp {
    Unix(f64),
    Rfc3339(DateTime<Utc>),
  }

  match Timestamp::deserialize(deserializer)? {
    Timestamp::Rfc3339(time) => Ok(time),
    Timestamp::Unix(seconds) => {
      let whole = seconds.floor();
      let nanos = ((seconds - whole) * 1e9).round() as u32;
      DateTime::from_timestamp(
        (whole as i64)
          .saturating_add(i64::from(nanos / 1_000_000_000)),
        nanos % 1_000_000_000,
      )
      .ok_or_else(|| serde::de::Error::custom("无效的 Unix 时间"))
    }
  }
}

fn redact_query(query: &str) -> String {
  const SENSITIVE: &[&str] = &[
    "token", "key", "secret", "pass", "pwd", "auth", "code", "sign",
    "sig", "jwt", "session", "ticket", "cred", "cookie",
  ];
  let mut result = String::with_capacity(query.len());
  for (i, param) in query.split('&').enumerate() {
    if i > 0 {
      result.push('&');
    }
    if let Some((key, value)) = param.split_once('=')
      && value != "REDACTED"
      && (value.starts_with("eyJ")
        || value.starts_with("wh_")
        || value.len() >= 32
        || {
          let key = key.to_ascii_lowercase();
          SENSITIVE.iter().any(|&part| key.contains(part))
        })
    {
      result.push_str(key);
      result.push_str("=***");
    } else {
      result.push_str(param);
    }
  }
  result
}

pub async fn read(
  job: AccessLogsRequest,
  ctx: &Ctx,
) -> Result<AccessLogsResult, ApiError> {
  validate_name("网关", &job.gateway)?;
  let cancel = ctx.cancel.clone();
  tokio::task::spawn_blocking(move || {
    let dir = format!("/srv/wharf-gw-{}/data", job.gateway);
    scan(Path::new(&dir), &job, &cancel)
  })
  .await
  .map_err(|e| ApiError::internal(e.to_string()))?
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), ApiError> {
  if cancel.is_cancelled() {
    return Err(ApiError::new(ErrorCode::Cancelled, "已取消"));
  }
  Ok(())
}

fn scan(
  dir: &Path,
  job: &AccessLogsRequest,
  cancel: &CancellationToken,
) -> Result<AccessLogsResult, ApiError> {
  let mut result = AccessLogsResult {
    missing: true,
    ..Default::default()
  };
  check_cancel(cancel)?;
  match dir.canonicalize() {
    Ok(path) if path == dir => {}
    Ok(_) => {
      return Err(ApiError::invalid("访问日志目录不能是符号链接"));
    }
    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(result),
    Err(e) => return Err(io_err(dir)(e)),
  }
  let files = match fs::read_dir(dir) {
    Ok(files) => files,
    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(result),
    Err(e) => return Err(io_err(dir)(e)),
  };
  let mut rotated = Vec::new();
  for file in files {
    check_cancel(cancel)?;
    let file = file.map_err(io_err(dir))?;
    let name = file.file_name();
    if let Some(name) = name.to_str()
      && name.starts_with("access-")
      && name.ends_with(".log")
    {
      rotated.push(file.path());
    }
  }
  rotated.sort_unstable();

  let tail = job.tail.min(MAX_TAIL) as usize;
  // shortcut: 倒读允许 5 秒时间乱序，观测到超过时再扩大窗口。
  let cutoff = job.since.and_then(|since| {
    since.checked_sub_signed(TimeDelta::seconds(5))
  });
  let mut block = vec![0; BLOCK_SIZE];
  let mut line = Vec::new();
  let mut scanned_bytes = 0;
  'files: for path in std::iter::once(dir.join("access.log"))
    .chain(rotated.into_iter().rev().take(3))
  {
    check_cancel(cancel)?;
    let mut file = match OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
      .open(&path)
    {
      Ok(file) => file,
      Err(e) if e.kind() == ErrorKind::NotFound => continue,
      Err(e) => return Err(io_err(&path)(e)),
    };
    let meta = file.metadata().map_err(io_err(&path))?;
    if !meta.is_file() {
      return Err(ApiError::invalid("访问日志必须是普通文件"));
    }
    result.scanned_files += 1;
    result.missing = false;
    let mut offset = meta.len();
    if tail == 0 {
      if offset > 0 {
        result.truncated = true;
        break;
      }
      continue;
    }
    let mut first = true;
    line.clear();
    while offset > 0 && scanned_bytes < MAX_BYTES {
      check_cancel(cancel)?;
      let len = offset
        .min(BLOCK_SIZE.min(MAX_BYTES - scanned_bytes) as u64)
        as usize;
      offset -= len as u64;
      file.seek(SeekFrom::Start(offset)).map_err(io_err(&path))?;
      file.read_exact(&mut block[..len]).map_err(io_err(&path))?;
      scanned_bytes += len;
      let mut bytes = &block[..len];
      if first {
        bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        first = false;
      }

      // 跨块的行从右往左累积，凑齐后再还原字节顺序。
      let mut parts = bytes.rsplit(|b| *b == b'\n').peekable();
      while let Some(part) = parts.next() {
        line.extend(part.iter().rev().copied());
        if offset > 0 && parts.peek().is_none() {
          break;
        }
        line.reverse();
        result.scanned_lines += 1;
        let row = serde_json::from_slice::<Row>(&line);
        line.clear();
        if result.scanned_lines.is_multiple_of(1024) {
          check_cancel(cancel)?;
        }
        if let Ok(row) = row {
          if cutoff.is_some_and(|cutoff| row.ts < cutoff) {
            break 'files;
          }
          if let Some(entry) = filter(row, job) {
            result.entries.push(entry);
          }
        } else {
          result.skipped += 1;
        }
        if result.entries.len() == tail
          || result.scanned_lines == MAX_LINES
        {
          break 'files;
        }
      }
    }
    if scanned_bytes == MAX_BYTES {
      break;
    }
  }
  result.truncated |= scanned_bytes == MAX_BYTES
    || result.scanned_lines == MAX_LINES
    || (tail > 0 && result.entries.len() == tail);
  // 并发请求可能不按时间戳写入。
  result.entries.reverse();
  result.entries.sort_by_key(|entry| entry.ts);
  result.matched = result.entries.len();
  Ok(result)
}

fn filter(
  row: Row,
  job: &AccessLogsRequest,
) -> Option<AccessLogEntry> {
  let Request {
    host,
    method,
    uri,
    client_ip,
  } = row.request;
  let (path, query) = uri.split_once('?').unwrap_or((&uri, ""));
  if job.since.is_some_and(|since| row.ts < since)
    || job
      .host
      .as_ref()
      .is_some_and(|wanted| !host.eq_ignore_ascii_case(wanted))
    || job
      .method
      .as_ref()
      .is_some_and(|wanted| !method.eq_ignore_ascii_case(wanted))
    || job
      .path
      .as_ref()
      .is_some_and(|prefix| !path.starts_with(prefix.as_str()))
    || job.status.as_ref().is_some_and(|ranges| {
      !ranges
        .iter()
        .any(|&(start, end)| (start..=end).contains(&row.status))
    })
  {
    return None;
  }
  Some(AccessLogEntry {
    ts: row.ts,
    host,
    method,
    path: path.into(),
    query: redact_query(query),
    status: row.status,
    duration_ms: row.duration * 1000.0,
    size: row.size,
    client_ip,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn scans_newest_file_and_stops_before_rotation() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap();
    let row = |ts, host, status| {
      format!(
        r#"{{"ts":{ts},"request":{{"host":"{host}","method":"GET","uri":"/x?page=2","client_ip":"127.0.0.1"}},"duration":0.002,"size":1,"status":{status}}}"#
      )
    };
    let old = row("1795607600.0", "a.test", 500);
    let first = row("1795607669.3479211", "A.test", 502);
    let last = row(r#""2026-11-25T11:55:00Z""#, "a.test", 503);
    let padding = " ".repeat(BLOCK_SIZE);
    fs::write(
      dir.join("access.log"),
      format!("{old}\n{padding}{first}\n{last}\n"),
    )
    .unwrap();
    // 轮转文件刻意复用旧行，便于验证没有打开它。
    fs::write(
      dir.join("access-2026-11-25T11-53-20.000.log"),
      format!("{old}\n"),
    )
    .unwrap();
    let mut job = AccessLogsRequest {
      gateway: "edge".into(),
      host: Some("a.test".into()),
      status: Some(vec![(500, 599)]),
      path: None,
      method: None,
      since: DateTime::from_timestamp(1795607660, 0),
      tail: 200,
    };
    let cancel = CancellationToken::new();
    let result = scan(&dir, &job, &cancel).unwrap();
    assert_eq!(
      (result.scanned_files, result.scanned_lines, result.matched),
      (1, 3, 2)
    );
    assert_eq!(result.entries[0].status, 502);
    assert_eq!(result.entries[1].status, 503);
    assert!(result.entries[0].ts < result.entries[1].ts);
    job.host = Some("b.test".into());
    assert_eq!(scan(&dir, &job, &cancel).unwrap().matched, 0);
    job.host = Some("a.test".into());
    job.status = Some(vec![(503, 503)]);
    assert_eq!(scan(&dir, &job, &cancel).unwrap().matched, 1);
  }

  #[test]
  fn masks_sensitive_query_values() {
    let (_, query) =
      "/a?page=2&my_token=abc&x=eyJhbGci.x.y&ok=1&token=REDACTED"
        .split_once('?')
        .unwrap();
    assert_eq!(
      redact_query(query),
      "page=2&my_token=***&x=***&ok=1&token=REDACTED"
    );
  }
}
