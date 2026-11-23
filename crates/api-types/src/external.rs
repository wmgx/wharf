//! 只读外部检查的 API 结果。
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AclView {
  pub status: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub hint: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub raw: Option<String>,
  #[serde(default)]
  pub groups: BTreeMap<String, Vec<String>>,
  #[serde(default, rename = "tagOwners")]
  pub tag_owners: BTreeMap<String, Vec<String>>,
  #[serde(default)]
  pub acls: usize,
  #[serde(default)]
  pub grants: usize,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TailnetKey {
  pub expires: Option<DateTime<Utc>>,
  pub never_expires: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TailnetRelay {
  pub from: String,
  pub to: String,
  pub relay: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExternalStatus {
  pub name: String,
  pub url: String,
  pub enabled: bool,
  pub indicator: Option<String>,
  pub description: String,
  pub incidents: Vec<ExternalIncident>,
  pub checked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExternalIncident {
  pub name: String,
  pub url: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Upstream {
  DockerHub,
  GitHub,
  Cloudflare,
}

#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct EgressInfo {
  pub ipv4: Option<String>,
  pub ipv6: Option<String>,
  pub asn: Option<String>,
  pub operator: Option<String>,
  pub country: Option<String>,
  pub city: Option<String>,
}

#[derive(
  Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct DockerQuota {
  pub remaining: u32,
  pub limit: u32,
  pub window_secs: u32,
  pub checked_at: DateTime<Utc>,
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
pub enum DnsVerdict {
  Matches,
  Mismatch,
  Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DnsCheck {
  pub hostname: String,
  pub expected: String,
  pub effective: bool,
  pub resolvers: Vec<DnsResolver>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DnsResolver {
  pub resolver: String,
  pub a: Option<Vec<String>>,
  pub aaaa: Option<Vec<String>>,
  pub verdict: DnsVerdict,
  pub elapsed_ms: u64,
}
