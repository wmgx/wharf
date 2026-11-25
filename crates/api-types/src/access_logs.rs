use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_TAIL: u32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogsRequest {
  pub gateway: String,
  pub host: Option<String>,
  pub status: Option<Vec<(u16, u16)>>,
  pub path: Option<String>,
  pub method: Option<String>,
  pub since: Option<DateTime<Utc>>,
  pub tail: u32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AccessLogEntry {
  pub ts: DateTime<Utc>,
  pub host: String,
  pub method: String,
  pub path: String,
  pub query: String,
  pub status: u16,
  pub duration_ms: f64,
  pub size: u64,
  pub client_ip: String,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct AccessLogsResult {
  pub entries: Vec<AccessLogEntry>,
  pub scanned_lines: usize,
  pub scanned_files: usize,
  pub matched: usize,
  pub truncated: bool,
  pub skipped: usize,
  pub missing: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub warnings: Vec<String>,
}
