use std::{path::Path, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ApiError;

pub const KEEP_TAG: &str = "keep";
pub const NOTE_TAG_PREFIX: &str = "wharf-note:";

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
pub struct BackupRetention {
  #[serde(default = "daily")]
  pub daily: u16,
  #[serde(default = "weekly")]
  pub weekly: u16,
  #[serde(default = "monthly")]
  pub monthly: u16,
}

fn daily() -> u16 {
  7
}
fn weekly() -> u16 {
  4
}
fn monthly() -> u16 {
  6
}

impl Default for BackupRetention {
  fn default() -> Self {
    Self {
      daily: daily(),
      weekly: weekly(),
      monthly: monthly(),
    }
  }
}

pub fn validate_retention(
  r: BackupRetention,
) -> Result<(), ApiError> {
  if r.daily == 0 && r.weekly == 0 && r.monthly == 0 {
    return Err(ApiError::invalid("日、周、月保留份数不能全为 0")
      .with_hint("至少保留 1 份快照，例如 --keep-daily 7 --keep-weekly 4 --keep-monthly 6"));
  }
  if r.daily > 365 || r.weekly > 104 || r.monthly > 60 {
    return Err(ApiError::invalid(
      "日、周、月保留份数上限分别为 365、104、60",
    ));
  }
  Ok(())
}

pub fn validate_snapshot_id(id: &str) -> Result<(), ApiError> {
  if id == "latest"
    || ((8..=64).contains(&id.len())
      && id.bytes().all(|b| b.is_ascii_hexdigit()))
  {
    Ok(())
  } else {
    Err(ApiError::invalid(
      "快照 id 须为 latest 或 8 到 64 位十六进制",
    ))
  }
}

pub fn validate_note(note: &str) -> Result<&str, ApiError> {
  let trimmed = note.trim();
  if !(1..=120).contains(&trimmed.chars().count())
    || note.chars().any(char::is_control)
  {
    return Err(ApiError::invalid(
      "快照备注须为 1 到 120 个字符，不能含控制字符",
    ));
  }
  Ok(trimmed)
}

pub fn validate_backup_excludes(
  rules: &[String],
) -> Result<Vec<String>, ApiError> {
  if rules.len() > 64 {
    return Err(ApiError::invalid("备份排除规则最多 64 条"));
  }
  let mut result = Vec::new();
  for rule in rules {
    if rule.trim().is_empty()
      || rule.chars().count() > 256
      || rule.starts_with(['/', '-'])
      || rule.contains(['\0', '\r', '\n', '\\'])
      || rule.split('/').any(|part| matches!(part, "." | ".."))
    {
      return Err(ApiError::invalid(
        "备份排除规则须为相对路径或文件名通配符",
      ));
    }
    let rule = rule.trim_end_matches('/');
    if !result.iter().any(|r| r == rule) {
      result.push(rule.to_owned());
    }
  }
  Ok(result)
}

pub fn restic_exclude_patterns(
  root: &Path,
  rules: &[String],
) -> Result<Vec<String>, ApiError> {
  let valid = validate_backup_excludes(rules)?;
  Ok(
    valid
      .into_iter()
      .map(|rule| {
        if !rule.contains('/')
          && !rule.starts_with("**")
          && rule.contains(['*', '?', '['])
        {
          rule
        } else {
          root.join(rule).to_string_lossy().into_owned()
        }
      })
      .collect(),
  )
}

#[derive(
  Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct BackupRunRequest {
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub keep: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
}

impl BackupRunRequest {
  pub fn validate(&self) -> Result<(), ApiError> {
    if let Some(note) = &self.note {
      validate_note(note)?;
    }
    Ok(())
  }

  pub fn needs_backup_v2(&self) -> bool {
    self.keep || self.note.is_some()
  }
}

pub const RESTIC_INDEX_TIMEOUT: Duration = Duration::from_secs(180);
pub const RESTIC_DUMP_TIMEOUT: Duration = Duration::from_secs(300);

pub const EXTRACT_LIMIT: u64 = 512 << 20;
pub const EXTRACT_CHUNK: u32 = 512 << 10;

pub fn normalize_snapshot_rel(raw: &str) -> Result<&str, ApiError> {
  let path = raw.trim_matches('/');
  if raw.len() > 1024
    || path.contains(['\0', '\\'])
    || (!path.is_empty()
      && path.split('/').any(|part| matches!(part, "" | "." | "..")))
  {
    return Err(ApiError::invalid("快照路径无效"));
  }
  Ok(path)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BackupFileEntry {
  pub path: String,
  pub name: String,
  pub kind: String,
  pub size: u64,
  pub mode: u32,
  pub modified: Option<chrono::DateTime<chrono::Utc>>,
  pub link_target: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupLsView {
  pub service: String,
  pub target: String,
  pub snapshot: String,
  pub path: String,
  pub recursive: bool,
  pub entries: Vec<BackupFileEntry>,
  pub truncated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupExtractMeta {
  pub token: String,
  pub size: u64,
  pub mode: u32,
  pub sha256: String,
  pub name: String,
  pub snapshot: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupExtractResult {
  pub service: String,
  pub snapshot: String,
  pub path: String,
  pub output: String,
  pub size: u64,
  pub mode: u32,
  pub sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct BackupDiffSummary {
  pub added: u64,
  pub removed: u64,
  pub modified: u64,
  pub unchanged: u64,
  pub added_bytes: u64,
  pub removed_bytes: u64,
  pub removed_excluded_bytes: u64,
  pub modified_before_bytes: u64,
  pub modified_after_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupDiffEntry {
  pub path: String,
  pub status: String,
  pub kind: String,
  pub before_size: Option<u64>,
  pub after_size: Option<u64>,
  pub excluded: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupDiffView {
  pub service: String,
  pub mode: String,
  pub base: String,
  pub target: String,
  pub summary: BackupDiffSummary,
  pub entries: Vec<BackupDiffEntry>,
  pub truncated: bool,
  pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupKeepResult {
  pub service: String,
  pub target: String,
  pub old_snapshot: String,
  pub snapshot: crate::agent::Snapshot,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BackupPolicy {
  pub service: String,
  pub enabled: bool,
  pub to: Option<String>,
  pub exclude: Vec<String>,
  pub retention: Option<BackupRetention>,
  pub effective_retention: BackupRetention,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn backup_exclude_validates_anchors_and_preserves_globs() {
    for rule in ["/etc/passwd", "../x", "--option"] {
      assert!(validate_backup_excludes(&[rule.into()]).is_err());
    }
    assert_eq!(
      restic_exclude_patterns(
        Path::new("/srv/app"),
        &["cache/**".into(), "*.tmp".into()]
      )
      .unwrap(),
      ["/srv/app/cache/**", "*.tmp"]
    );
  }
}
