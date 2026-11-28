use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::ServerSettings;

/// Docker update 的 Memory=0 是忽略更新。用内核页对齐后的最大值表示不限。
pub const UNLIMITED_MEMORY: u64 = 0x7fff_ffff_ffff_0000;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LimitEvidence {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub start_ms: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub end_ms: Option<i64>,
  pub points: usize,
  pub hours: usize,
  pub resolution_minutes: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mean: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub peak: Option<f64>,
  pub peak_is_lower_bound: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LimitSuggestion {
  pub name: String,
  pub server: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub current_memory_mb: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub current_cpu_milli: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub memory_source: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cpu_source: Option<String>,
  /// MiB。
  pub memory: LimitEvidence,
  /// 整机 CPU 百分比，沿用旧统计。
  pub cpu: LimitEvidence,
  /// 细粒度采样的 millicore。
  pub fine_cpu: LimitEvidence,
  /// 按时间键去重后的 OOM 点数。
  pub oom_points: usize,
  pub memory_class: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub memory_mb: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cpu_milli: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub skip: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub memory_reason: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cpu_reason: Option<String>,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct AgentMemory {
  /// Docker 实际上限，0 表示不限。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub limit: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(
  Debug, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct AgentUsage {
  pub configured_limit: u64,
  pub cpu: Option<f32>,
  pub mem: Option<u64>,
  pub memory_limit: Option<u64>,
  pub memory_pct: Option<f64>,
  pub limit_error: Option<String>,
}

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
#[serde(rename_all = "snake_case")]
pub enum UsageKind {
  Service,
  Gateway,
  Agent,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UsageRow {
  pub name: String,
  pub kind: UsageKind,
  pub server: String,
  pub cpu: Option<f64>,
  pub mem: Option<u64>,
  pub memory_limit: Option<u64>,
  pub memory_pct: Option<f64>,
  pub net_rx: Option<u64>,
  pub net_tx: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LocalImage {
  pub id: String,
  pub image: String,
  pub size: u64,
  pub used_by: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImageRow {
  pub server: String,
  #[serde(flatten)]
  pub image: LocalImage,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ImagesView {
  pub rows: Vec<ImageRow>,
  pub unused: BTreeMap<String, u64>,
  pub errors: BTreeMap<String, String>,
}

pub fn percent(used: u64, total: u64) -> Option<f64> {
  (total > 0).then(|| used as f64 / total as f64 * 100.0)
}

impl ServerSettings {
  pub fn bg_bwlimit_kbps(&self) -> Option<u32> {
    parse_bwlimit_kbps(self.bg_bwlimit.as_deref()?)
      .ok()
      .filter(|v| *v > 0)
  }

  pub fn agent_memory_bytes(&self) -> u64 {
    self
      .agent_memory
      .as_deref()
      .and_then(|v| parse_agent_memory(v).ok())
      .unwrap_or(256 << 20)
  }
}

pub fn parse_agent_memory(
  value: &str,
) -> Result<u64, crate::ApiError> {
  let value = value.trim().to_ascii_lowercase();
  if value == "none" {
    return Ok(0);
  }
  let bytes = value
    .strip_suffix('m')
    .map(|v| (v, 1 << 20))
    .or_else(|| value.strip_suffix('g').map(|v| (v, 1 << 30)))
    .and_then(|(n, unit)| n.parse::<u64>().ok()?.checked_mul(unit))
    .filter(|&bytes| (6 << 20..UNLIMITED_MEMORY).contains(&bytes));
  bytes.ok_or_else(|| {
    crate::ApiError::invalid(
      "agent 内存上限至少 6 MiB，例如 256M、1G，或用 none 表示不限",
    )
  })
}

#[cfg(test)]
mod agent_memory_tests {
  use super::parse_agent_memory;

  #[test]
  fn parses_agent_memory_setting() {
    for (value, bytes) in [
      ("256M", 256 << 20),
      ("1G", 1 << 30),
      ("512m", 512 << 20),
      ("none", 0),
    ] {
      assert_eq!(parse_agent_memory(value).unwrap(), bytes);
    }
    for value in ["abc", "0", "-1"] {
      assert!(
        parse_agent_memory(value)
          .unwrap_err()
          .message
          .contains("256M")
      );
    }
  }
}

pub fn parse_bwlimit_kbps(raw: &str) -> Result<u32, crate::ApiError> {
  let input = raw.trim().to_ascii_lowercase();
  let invalid = || {
    crate::ApiError::invalid("带宽限速格式不对或超出范围").with_hint(
      "输入 16K 到 10G，例如 500K、1.5M，或输入 none 关闭限速",
    )
  };
  if matches!(input.as_str(), "0" | "none" | "off") {
    return Ok(0);
  }
  let split = input
    .find(|c: char| !c.is_ascii_digit() && c != '.')
    .ok_or_else(invalid)?;
  let (number, unit) = input.split_at(split);
  let scale = match unit {
    "k" | "kb" | "k/s" => 1,
    "m" | "mb" | "m/s" => 1024,
    "g" | "gb" | "g/s" => 1024 * 1024,
    _ => return Err(invalid()),
  };
  let (whole, fraction) =
    number.split_once('.').unwrap_or((number, "0"));
  if whole.is_empty()
    || fraction.len() != 1
    || !fraction.as_bytes()[0].is_ascii_digit()
  {
    return Err(invalid());
  }
  let whole: u64 = whole.parse().map_err(|_| invalid())?;
  let value = whole.saturating_mul(scale).saturating_add(
    u64::from(fraction.as_bytes()[0] - b'0') * scale / 10,
  );
  if !(16..=10_485_760).contains(&value) {
    return Err(invalid());
  }
  Ok(value as u32)
}

pub fn effective_bwlimit_kbps(
  explicit: Option<u32>,
  server_limits: &[Option<u32>],
) -> Option<u32> {
  explicit
    .or_else(|| {
      server_limits
        .iter()
        .flatten()
        .copied()
        .filter(|v| *v > 0)
        .min()
    })
    .filter(|v| *v > 0)
}

#[test]
fn bg_bwlimit_parses_units_and_respects_explicit_override() {
  let limits = [Some(parse_bwlimit_kbps("3M").unwrap()), Some(10240)];
  assert_eq!(parse_bwlimit_kbps("1.5MB").unwrap(), 1536);
  assert!(parse_bwlimit_kbps("2048").is_err());
  assert!(parse_bwlimit_kbps("18446744073709551615.9G").is_err());
  assert_eq!(effective_bwlimit_kbps(None, &limits), Some(3072));
  assert_eq!(effective_bwlimit_kbps(Some(0), &limits), None);
}
