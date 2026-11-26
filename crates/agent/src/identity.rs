//! agent 的密钥和加入信息，存在 data_dir 下，权限 0600。

use std::path::Path;

use anyhow::{Context, bail};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  agent::{
    KeyRotatePhase, RotateAgentKeyJob, RotateAgentKeyResult,
    TrustCoreKeyJob,
  },
  view::{JoinRequest, JoinResponse},
};

mod join_tunnel;

const KEY_FILE: &str = "agent.key";
const PENDING_KEY_FILE: &str = "agent.key.pending";
const PREVIOUS_KEY_FILE: &str = "agent.key.prev";
const JOIN_FILE: &str = "agent.json";

/// join 之后记下的信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Joined {
  /// 控制面地址，例如 `http://100.101.102.103:7700`。
  pub core_url: String,
  pub server: String,
  pub core_public_key: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub core_public_key_alt: Option<String>,
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

  pub fn verify_core(
    &self,
    payload: &[u8],
    signature: &str,
    alt: Option<&str>,
  ) -> Option<String> {
    [signature].into_iter().chain(alt).find_map(|signature| {
      let signature = parse_signature(signature).ok()?;
      [&self.core_public_key]
        .into_iter()
        .chain(self.core_public_key_alt.as_ref())
        .find(|public| {
          parse_public_key(public)
            .is_ok_and(|k| k.verify(payload, &signature).is_ok())
        })
        .cloned()
    })
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

fn read_key(path: &Path) -> anyhow::Result<Option<SigningKey>> {
  let text = match std::fs::read_to_string(path) {
    Ok(text) => text,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return Ok(None);
    }
    Err(e) => {
      return Err(e)
        .with_context(|| format!("读取 {}", path.display()));
    }
  };
  let seed: [u8; 32] = hex::decode(text.trim())
    .ok()
    .and_then(|b| b.try_into().ok())
    .with_context(|| format!("{} 格式不对", path.display()))?;
  Ok(Some(SigningKey::from_bytes(&seed)))
}

fn generate_key() -> anyhow::Result<SigningKey> {
  let mut seed = [0u8; 32];
  getrandom::fill(&mut seed)
    .map_err(|_| anyhow::anyhow!("生成随机数失败"))?;
  Ok(SigningKey::from_bytes(&seed))
}

pub fn load_key(data_dir: &Path) -> anyhow::Result<SigningKey> {
  let path = data_dir.join(KEY_FILE);
  if let Ok(Some(key)) = read_key(&path) {
    return Ok(key);
  }
  if let Some(key) = read_key(&data_dir.join(PREVIOUS_KEY_FILE))? {
    rollback_key(data_dir)?;
    return Ok(key);
  }
  read_key(&path)?.context("agent 身份文件不存在")
}

pub fn load_or_create_key(
  data_dir: &Path,
) -> anyhow::Result<SigningKey> {
  let path = data_dir.join(KEY_FILE);
  if path.try_exists()? || has_previous_key(data_dir) {
    return load_key(data_dir);
  }
  let key = generate_key()?;
  write_private(&path, &hex::encode(key.to_bytes()))?;
  Ok(key)
}

fn write_private(path: &Path, content: &str) -> anyhow::Result<()> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  if let Some(dir) = path.parent() {
    std::fs::create_dir_all(dir)?;
  }
  let temp = path.with_file_name(format!(
    "{}.write-tmp",
    path
      .file_name()
      .and_then(|name| name.to_str())
      .context("文件名无效")?
  ));
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(&temp)
    .with_context(|| format!("写入 {}", path.display()))?;
  file.write_all(content.as_bytes())?;
  file.sync_all()?;
  std::fs::rename(temp, path)?;
  Ok(())
}

pub fn has_previous_key(data_dir: &Path) -> bool {
  data_dir.join(PREVIOUS_KEY_FILE).exists()
}

fn remove_file(path: &Path) -> anyhow::Result<()> {
  match std::fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(e.into()),
  }
}

pub fn confirm_key(data_dir: &Path) -> anyhow::Result<()> {
  remove_file(&data_dir.join(PREVIOUS_KEY_FILE))
}

pub fn rollback_key(data_dir: &Path) -> anyhow::Result<()> {
  std::fs::rename(
    data_dir.join(PREVIOUS_KEY_FILE),
    data_dir.join(KEY_FILE),
  )?;
  Ok(())
}

pub fn rotate_key(
  data_dir: &Path,
  job: RotateAgentKeyJob,
) -> anyhow::Result<(serde_json::Value, bool)> {
  let pending = data_dir.join(PENDING_KEY_FILE);
  match job.phase {
    KeyRotatePhase::Prepare => {
      if has_previous_key(data_dir) {
        bail!("上一次身份密钥还在等待握手确认");
      }
      let key = generate_key()?;
      write_private(&pending, &hex::encode(key.to_bytes()))?;
      Ok((
        serde_json::to_value(RotateAgentKeyResult {
          public_key: hex::encode(key.verifying_key().to_bytes()),
        })?,
        false,
      ))
    }
    KeyRotatePhase::Activate => {
      let key =
        read_key(&pending)?.context("没有准备好的新身份密钥")?;
      if job.expected_public_key.as_deref()
        != Some(&hex::encode(key.verifying_key().to_bytes()))
      {
        bail!("待启用的身份公钥不匹配");
      }
      let current = load_key(data_dir)?;
      write_private(
        &data_dir.join(PREVIOUS_KEY_FILE),
        &hex::encode(current.to_bytes()),
      )?;
      if let Err(e) =
        std::fs::rename(pending, data_dir.join(KEY_FILE))
      {
        confirm_key(data_dir)?;
        return Err(e.into());
      }
      Ok((serde_json::Value::Null, true))
    }
    KeyRotatePhase::Abort => {
      remove_file(&pending)?;
      Ok((serde_json::Value::Null, false))
    }
  }
}

pub fn trust_core_key(
  data_dir: &Path,
  job: TrustCoreKeyJob,
) -> anyhow::Result<(serde_json::Value, bool)> {
  parse_public_key(&job.current)?;
  if let Some(alt) = &job.alt {
    parse_public_key(alt)?;
  }
  let mut joined =
    Joined::load(data_dir)?.context("agent 没有加入控制面")?;
  joined.core_public_key = job.current;
  joined.core_public_key_alt = job.alt;
  joined.save(data_dir)?;
  Ok((serde_json::Value::Null, job.reconnect))
}

/// 用一次性凭据加入控制面。
pub async fn join(
  data_dir: &Path,
  core_url: &str,
  join_token: &str,
  core_key: Option<&str>,
) -> anyhow::Result<Joined> {
  let core_url = core_url.trim_end_matches('/').to_string();
  let mut url =
    reqwest::Url::parse(&core_url).context("控制面地址不合法")?;
  let host = url.host_str().context("控制面地址缺少主机")?;
  if !matches!(url.scheme(), "http" | "https")
    || !url.username().is_empty()
    || url.password().is_some()
    || url.query().is_some()
    || url.fragment().is_some()
  {
    bail!("控制面地址不合法");
  }
  let local = matches!(host, "127.0.0.1" | "[::1]" | "localhost");
  let expected = core_key.map(parse_public_key).transpose()?;
  if !local && expected.is_none() {
    bail!(
      "加入非本机控制面必须提供 --core-key，防止中间人窃取加入凭据。直接复制 wharf server add 或页面生成的完整加入命令"
    );
  }
  let key = load_or_create_key(data_dir)?;
  let request = JoinRequest {
    join_token: join_token.to_string(),
    public_key: hex::encode(key.verifying_key().to_bytes()),
  };
  let joined = if let Some(expected) = &expected {
    join_tunnel::join(&url, expected, &request).await?
  } else {
    url.set_path(&format!(
      "{}/agent/join",
      url.path().trim_end_matches('/')
    ));
    join_local(url, &request).await?
  };
  let actual = parse_public_key(&joined.core_public_key)?;
  let previous = joined
    .previous_core_public_key
    .as_deref()
    .map(parse_public_key)
    .transpose()?;
  if expected.is_some_and(|expected| {
    expected != actual && previous != Some(expected)
  }) {
    bail!("加入响应的公钥和 --core-key 不一致");
  }
  let joined = Joined {
    core_url,
    server: joined.server,
    core_public_key: joined.core_public_key,
    core_public_key_alt: joined.previous_core_public_key,
  };
  joined.save(data_dir)?;
  Ok(joined)
}

async fn join_local(
  url: reqwest::Url,
  req: &JoinRequest,
) -> anyhow::Result<JoinResponse> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(20))
    .no_proxy()
    .redirect(reqwest::redirect::Policy::none())
    .resolve_to_addrs(
      "localhost",
      &["127.0.0.1:0".parse()?, "[::1]:0".parse()?],
    )
    .build()?;
  let mut resp = client
    .post(url)
    .json(req)
    .send()
    .await
    .map_err(|e| e.without_url())
    .context("连接本机控制面失败")?;
  let status = resp.status().as_u16();
  let mut body = Vec::new();
  while let Some(chunk) = resp.chunk().await? {
    if body.len() + chunk.len() > join_tunnel::MAX_RESPONSE {
      bail!("加入响应太大");
    }
    body.extend_from_slice(&chunk);
  }
  decode_response(status, &body)
}

fn decode_response(
  status: u16,
  body: &[u8],
) -> anyhow::Result<JoinResponse> {
  if !(200..300).contains(&status) {
    let body =
      serde_json::from_slice::<wharf_api_types::ApiError>(body).ok();
    bail!(
      "加入失败（HTTP {status}）：{}",
      body.map(|e| e.message).unwrap_or_default()
    );
  }
  Ok(serde_json::from_slice(body)?)
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
      core_public_key_alt: None,
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
