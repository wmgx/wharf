//! agent 的密钥和加入信息，存在 data_dir 下，权限 0600。

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use wharf_api_types::view::{JoinRequest, JoinResponse};

const KEY_FILE: &str = "agent.key";
const JOIN_FILE: &str = "agent.json";

/// join 之后记下的信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Joined {
  /// 控制面地址，例如 `http://100.101.102.103:7700`。
  pub core_url: String,
  pub server: String,
  pub core_public_key: String,
}

impl Joined {
  pub fn ws_url(&self) -> String {
    let base = self.core_url.trim_end_matches('/');
    let base = base
      .strip_prefix("https://")
      .map(|rest| format!("wss://{rest}"))
      .or_else(|| {
        base
          .strip_prefix("http://")
          .map(|rest| format!("ws://{rest}"))
      })
      .unwrap_or_else(|| format!("ws://{base}"));
    format!("{base}/agent/ws")
  }

  pub fn core_key(&self) -> anyhow::Result<VerifyingKey> {
    parse_public_key(&self.core_public_key)
  }

  pub fn load(data_dir: &Path) -> anyhow::Result<Option<Self>> {
    let path = data_dir.join(JOIN_FILE);
    match std::fs::read_to_string(&path) {
      Ok(text) => Ok(Some(
        serde_json::from_str(&text)
          .with_context(|| format!("{} 格式不对", path.display()))?,
      )),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
      Err(e) => Err(e).context(format!("读取 {}", path.display())),
    }
  }

  fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
    write_private(
      &data_dir.join(JOIN_FILE),
      &serde_json::to_string_pretty(self)?,
    )
  }
}

pub fn parse_public_key(
  hex_key: &str,
) -> anyhow::Result<VerifyingKey> {
  let bytes: [u8; 32] = hex::decode(hex_key)
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("公钥格式不对")?;
  VerifyingKey::from_bytes(&bytes).context("公钥无效")
}

pub fn parse_signature(hex_sig: &str) -> anyhow::Result<Signature> {
  let bytes: [u8; 64] = hex::decode(hex_sig)
    .ok()
    .and_then(|b| b.try_into().ok())
    .context("签名格式不对")?;
  Ok(Signature::from_bytes(&bytes))
}

pub fn load_or_create_key(
  data_dir: &Path,
) -> anyhow::Result<SigningKey> {
  let path = data_dir.join(KEY_FILE);
  match std::fs::read_to_string(&path) {
    Ok(text) => {
      let seed: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{} 格式不对", path.display()))?;
      Ok(SigningKey::from_bytes(&seed))
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      let mut seed = [0u8; 32];
      getrandom::fill(&mut seed)
        .map_err(|e| anyhow::anyhow!("生成随机数失败：{e}"))?;
      write_private(&path, &hex::encode(seed))?;
      Ok(SigningKey::from_bytes(&seed))
    }
    Err(e) => Err(e).context(format!("读取 {}", path.display())),
  }
}

fn write_private(
  path: &PathBuf,
  content: &str,
) -> anyhow::Result<()> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
  }
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .with_context(|| format!("写入 {}", path.display()))?;
  file.write_all(content.as_bytes())?;
  Ok(())
}

/// 用一次性凭据加入控制面。
pub async fn join(
  data_dir: &Path,
  core_url: &str,
  join_token: &str,
) -> anyhow::Result<Joined> {
  let key = load_or_create_key(data_dir)?;
  let core_url = core_url.trim_end_matches('/').to_string();
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(20))
    .build()?;
  let resp = client
    .post(format!("{core_url}/agent/join"))
    .json(&JoinRequest {
      join_token: join_token.to_string(),
      public_key: hex::encode(key.verifying_key().to_bytes()),
    })
    .send()
    .await
    .with_context(|| format!("连接控制面 {core_url} 失败"))?;
  if !resp.status().is_success() {
    let status = resp.status();
    let body: serde_json::Value =
      resp.json().await.unwrap_or_default();
    bail!(
      "加入失败（HTTP {status}）：{}",
      body["message"].as_str().unwrap_or("未知错误")
    );
  }
  let joined: JoinResponse = resp.json().await?;
  parse_public_key(&joined.core_public_key)?;
  let joined = Joined {
    core_url,
    server: joined.server,
    core_public_key: joined.core_public_key,
  };
  joined.save(data_dir)?;
  Ok(joined)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ws_urls() {
    let j = |url: &str| Joined {
      core_url: url.into(),
      server: "node1".into(),
      core_public_key: String::new(),
    };
    assert_eq!(
      j("http://1.2.3.4:7700/").ws_url(),
      "ws://1.2.3.4:7700/agent/ws"
    );
    assert_eq!(
      j("https://wharf.x").ws_url(),
      "wss://wharf.x/agent/ws"
    );
  }

  #[test]
  fn key_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let a = load_or_create_key(dir.path()).unwrap();
    let b = load_or_create_key(dir.path()).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
  }
}
