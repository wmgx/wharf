use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{plan::Plan, view::SecretImportMode};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct EncryptedBundle {
  pub format: String,
  pub version: u8,
  pub kdf: BundleKdf,
  pub cipher: String,
  pub nonce: String,
  pub ciphertext: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct BundleKdf {
  pub m_kib: u32,
  pub t: u32,
  pub p: u32,
  pub salt: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExportBundleRequest {
  #[serde(default)]
  pub services: Vec<String>,
  pub passphrase: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ExportBundleResponse {
  pub bundle: EncryptedBundle,
  pub summary: BundleExportSummary,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct BundleExportSummary {
  pub services: Vec<String>,
  pub routes: Vec<String>,
  pub secret_names: Vec<String>,
  pub skipped_managed: Vec<String>,
  pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ImportBundleRequest {
  pub bundle: EncryptedBundle,
  pub passphrase: String,
  #[serde(default)]
  pub mode: SecretImportMode,
  #[serde(default)]
  pub keep_days: Option<u16>,
  #[serde(default)]
  pub server_map: BTreeMap<String, String>,
  #[serde(default)]
  pub default_server: Option<String>,
  #[serde(default)]
  pub gateway_map: BTreeMap<String, String>,
  #[serde(default)]
  pub no_routes: bool,
  #[serde(default = "preview")]
  pub dry_run: bool,
}

fn preview() -> bool {
  true
}

#[derive(
  Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct SecretChanges {
  pub create: Vec<String>,
  pub update: Vec<String>,
  pub skip: Vec<String>,
  pub conflicts: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct BundleImportPreview {
  pub services: Vec<String>,
  pub routes: Vec<String>,
  pub secrets: SecretChanges,
  pub missing_servers: Vec<String>,
  pub missing_gateways: Vec<String>,
  pub warnings: Vec<String>,
  pub hint: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SecretImportResponse {
  pub created: Vec<String>,
  pub updated: Vec<String>,
  pub skipped: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct BundleImportResponse {
  pub secrets: SecretImportResponse,
  pub plan: Plan,
  pub warnings: Vec<String>,
}
