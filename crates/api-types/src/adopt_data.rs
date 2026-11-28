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

fn safe_external_path(source: &str) -> bool {
  let path = Path::new(source);
  let mut parts = path.components();
  let Some(Component::RootDir) = parts.next() else {
    return false;
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
    && source
      .split('/')
      .skip(1)
      .all(|p| !matches!(p, "" | "." | "..") && !p.ends_with(".sock"))
    && !source
      .bytes()
      .any(|c| matches!(c, b',' | b'"' | 0) || c.is_ascii_control())
}

pub fn validate_host_bind(
  source: &str,
  target: &str,
) -> Result<(), ApiError> {
  let limited = source
    .strip_prefix('/')
    .and_then(|path| path.split_once('/'))
    .is_some_and(|(root, suffix)| {
      matches!(root, "mnt" | "media" | "opt") && !suffix.is_empty()
    });
  let plain = |path: &str| {
    path.bytes().all(|b| {
      b.is_ascii_alphanumeric()
        || matches!(b, b'/' | b'_' | b'-' | b'.')
    })
  };
  if !limited
    || !safe_external_path(source)
    || !safe_external_path(target)
    || !plain(source)
    || !plain(target)
    || ["/run", "/srv", "/var/run", "/var/lib/wharf", "/.wharf"]
      .iter()
      .any(|p| Path::new(target).starts_with(p))
  {
    return Err(
      ApiError::invalid(format!("外部挂载 {source} 不允许"))
        .with_hint(
          "选择 /mnt、/media 或 /opt 下已有目录，挂到容器的普通目录",
        ),
    );
  }
  Ok(())
}

impl AdoptSourceItem {
  pub fn validate(&self) -> Result<(), ApiError> {
    validate_name("卷", &self.volume_name)?;
    let path = Path::new(&self.source);
    let safe = match self.kind {
      AdoptSourceKind::ExternalDir => {
        if !path.is_absolute() {
          return Err(ApiError::invalid("收编数据需要绝对路径"));
        }
        safe_external_path(&self.source)
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

#[test]
fn host_bind_rejects_system_paths_and_traversal() {
  assert!(validate_host_bind("/mnt/test/files", "/media").is_ok());
  for source in [
    "/mnt",
    "/etc/data",
    "/opt/../mnt/data",
    "/media/docker.sock",
    "mnt/data",
  ] {
    assert!(
      validate_host_bind(source, "/media").is_err(),
      "{source}"
    );
  }
  assert!(validate_host_bind("/opt/data", "/var/run").is_err());
}
