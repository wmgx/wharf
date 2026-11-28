use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

use crate::{ApiError, validate_name};

#[derive(
  Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct AdoptMountSpec {
  #[serde(default)]
  pub target: Option<String>,
  #[serde(default)]
  pub source: Option<String>,
  #[serde(default)]
  pub volume_name: Option<String>,
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub rename_only: bool,
}

#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Serialize,
  Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AdoptSourceKind {
  ExternalDir,
  NamedVolume,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptSourceItem {
  pub kind: AdoptSourceKind,
  pub source: String,
  pub target: String,
  pub volume_name: String,
  pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptDataJob {
  pub service: String,
  pub items: Vec<AdoptSourceItem>,
  pub nonce: String,
}

impl AdoptSourceItem {
  pub fn validate(&self) -> Result<(), ApiError> {
    validate_name("卷", &self.volume_name)?;
    let path = Path::new(&self.source);
    let safe = match self.kind {
      AdoptSourceKind::ExternalDir => {
        let mut parts = path.components();
        let Some(Component::RootDir) = parts.next() else {
          return Err(ApiError::invalid("收编数据需要绝对路径"));
        };
        let root = parts
          .next()
          .and_then(|p| p.as_os_str().to_str())
          .unwrap_or_default();
        !matches!(
          root,
          "" | "srv"
            | "run"
            | "proc"
            | "sys"
            | "dev"
            | "etc"
            | "usr"
            | "bin"
            | "sbin"
            | "boot"
            | "root"
            | "tmp"
        ) && !root.starts_with("lib")
          && ![
            "/var/run",
            "/var/lib/docker",
            "/var/lib/wharf-agent",
            "/var/lib/wharf-core",
          ]
          .iter()
          .any(|p| path.starts_with(p))
          && self.source.split('/').skip(1).all(|p| {
            !matches!(p, "" | "." | "..") && !p.ends_with(".sock")
          })
          && !self.source.bytes().any(|c| {
            matches!(c, b',' | b'"' | 0) || c.is_ascii_control()
          })
      }
      AdoptSourceKind::NamedVolume => {
        self
          .source
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
          && self.source.bytes().all(|c| {
            c.is_ascii_alphanumeric()
              || matches!(c, b'_' | b'-' | b'.')
          })
          && !self.source.ends_with(".sock")
      }
    };
    if !safe {
      return Err(ApiError::invalid(
        "不能收编系统路径、共享卷、套接字或不安全的挂载名",
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdoptInspectEntry {
  pub volume_name: String,
  pub target_exists_nonempty: bool,
  #[serde(default)]
  pub is_dir: Option<bool>,
  pub in_use_by: Vec<String>,
  #[serde(default)]
  pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdoptDataInspectResult {
  pub entries: Vec<AdoptInspectEntry>,
  pub srv_avail_bytes: u64,
  #[serde(default)]
  pub mounts: Vec<crate::agent::ContainerMount>,
}
