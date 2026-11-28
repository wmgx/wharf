use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ApiError;

pub const MAGIC: &[u8; 10] = b"WHARFDATA1";
pub const PULL_PACKETS_HEADER: &str = "x-wharf-pull-packets";
pub const PULL_PACKET_ERROR: u32 = 1 << 31;
pub const CHUNK: usize = 256 * 1024;
pub const MAX_PATH: usize = 4096;
pub const MAX_MANIFEST: usize = 20_000;
pub const MAX_FILES: usize = 10_000;
pub const MAX_FILE_BYTES: u64 = 512 << 20;
pub const MAX_BYTES: u64 = 1 << 30;

pub fn path_parts(path: &str) -> Result<Vec<&str>, ApiError> {
  if path.split('/').any(|part| part == ".wharf-init") {
    return Err(ApiError::invalid(
      "首次写入的受管目录不允许通过便携数据操作访问",
    ));
  }

  if path.is_empty() {
    return Ok(Vec::new());
  }
  let parts: Vec<_> = path.split('/').collect();
  if path.len() > MAX_PATH
    || parts.len() > 32
    || parts.iter().any(|p| {
      p.is_empty()
        || p.len() > 255
        || p.contains('\0')
        || matches!(*p, "." | "..")
        || p.ends_with(".wharf-upload")
        || p.starts_with(".wharf-")
    })
  {
    return Err(ApiError::invalid("数据路径无效或超出目录范围"));
  }
  Ok(parts)
}

pub fn join(subpath: &str, path: &str) -> Result<String, ApiError> {
  path_parts(subpath)?;
  if path_parts(path)?.is_empty() {
    return Err(ApiError::invalid("需要指定文件或子目录"));
  }
  let joined = if subpath.is_empty() {
    path.into()
  } else {
    format!("{subpath}/{path}")
  };
  path_parts(&joined)?;
  Ok(joined)
}

// 路径匹配以 / 为分隔，* 匹配一段，** 匹配任意层。
pub fn excluded(path: &str, patterns: &[String]) -> bool {
  fn segment(pattern: &str, value: &str) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    while v < value.len() {
      match pattern.get(p) {
        Some(b'*') => {
          star = Some(p);
          p += 1;
          retry = v;
        }
        Some(b'?') => {
          p += 1;
          v += 1;
        }
        Some(c) if *c == value[v] => {
          p += 1;
          v += 1;
        }
        _ if star.is_some() => {
          p = star.unwrap() + 1;
          retry += 1;
          v = retry;
        }
        _ => return false,
      }
    }
    pattern[p..].iter().all(|c| *c == b'*')
  }
  patterns.iter().any(|pattern| {
    if !pattern.contains('/') {
      return path.split('/').any(|part| segment(pattern, part));
    }
    let path: Vec<_> = path.split('/').collect();
    let mut reachable = vec![false; path.len() + 1];
    reachable[0] = true;
    for part in pattern.split('/') {
      if part == "**" {
        for i in 1..reachable.len() {
          reachable[i] |= reachable[i - 1];
        }
      } else {
        for i in (1..reachable.len()).rev() {
          reachable[i] =
            reachable[i - 1] && segment(part, path[i - 1]);
        }
        reachable[0] = false;
      }
    }
    reachable[path.len()]
  })
}

#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct ManifestRequest {
  #[serde(default)]
  pub subpath: String,
  #[serde(default)]
  pub excludes: Vec<String>,
  #[serde(default)]
  pub max_entries: Option<usize>,
  #[serde(default)]
  pub hash_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DataFileEntry {
  pub path: String,
  pub dir: bool,
  pub size: u64,
  pub mtime_ms: i64,
  pub mode: u32,
  #[serde(default)]
  pub sha256: Option<String>,
}

#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct DataManifestResult {
  pub entries: Vec<DataFileEntry>,
  pub total_bytes: u64,
  pub truncated: bool,
  pub skipped_special: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub excluded: Vec<String>,
  pub sqlite_wal_files: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PullRequest {
  #[serde(default)]
  pub subpath: String,
  pub paths: Vec<String>,
  #[serde(default)]
  pub sqlite_safe: bool,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub error_packets: bool,
  #[serde(default)]
  pub max_bytes: Option<u64>,
  #[serde(default)]
  pub timeout_secs: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PushOptions {
  #[serde(default)]
  pub subpath: String,
  #[serde(default)]
  pub delete: bool,
  #[serde(default)]
  pub max_bytes: Option<u64>,
  #[serde(default)]
  pub timeout_secs: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct DataDiffEntry {
  pub path: String,
  pub size: u64,
  pub dir: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DataPushPlan {
  pub dry_run: bool,
  pub added: Vec<DataDiffEntry>,
  #[serde(default)]
  pub mkdirs: Vec<String>,
  pub modified: Vec<DataDiffEntry>,
  pub deleted: Vec<DataDiffEntry>,
  pub skipped: Vec<String>,
  pub total_bytes: u64,
  pub warnings: Vec<String>,
  pub hint: String,
}

#[derive(Default, Serialize, Deserialize, JsonSchema)]
pub struct DataSyncSummary {
  pub files: usize,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub uploaded: Option<usize>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub downloaded: Option<usize>,
  pub deleted: usize,
  pub bytes: u64,
  #[serde(default)]
  pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SqliteSnapHandle {
  pub snap_id: String,
  pub size: u64,
  pub sha256: String,
}

pub fn frame(kind: u8, path: &str, size: u64, mode: u32) -> Vec<u8> {
  let mut frame = vec![kind];
  frame.extend((path.len() as u32).to_be_bytes());
  frame.extend(path.as_bytes());
  frame.extend(size.to_be_bytes());
  frame.extend(mode.to_be_bytes());
  frame
}

#[test]
fn data_paths_and_excludes_stay_relative() {
  assert!(join("data", "../escape").is_err());
  assert!(join("data", "/absolute").is_err());
  assert!(join("data", "a/file.wharf-upload").is_err());
  assert_eq!(join("data", "sub/file").unwrap(), "data/sub/file");
  assert!(excluded("data/nested/cache.db", &["data/**/*.db".into()]));
  assert!(!excluded("outside/cache.db", &["data/**/*.db".into()]));
}
