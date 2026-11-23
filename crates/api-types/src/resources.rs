use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::ServerSettings;

/// Docker update 的 Memory=0 是忽略更新。用内核页对齐后的最大值表示不限。
pub const UNLIMITED_MEMORY: u64 = 0x7fff_ffff_ffff_0000;

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
