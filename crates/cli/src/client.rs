//! 控制面 HTTP 客户端和本地配置（`~/.config/wharf/config.toml`）。

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wharf_api_types::{ApiError, ErrorCode};

/// CLI 的错误：控制面返回的错误，或者需要特定退出码。
#[derive(Debug)]
pub enum CliError {
  Api(ApiError),
  /// 已经输出过结果，只需要以这个退出码结束（例如 run 失败是 4）。
  Exit(i32),
}

impl From<ApiError> for CliError {
  fn from(e: ApiError) -> Self {
    Self::Api(e)
  }
}

impl From<anyhow::Error> for CliError {
  fn from(e: anyhow::Error) -> Self {
    Self::Api(ApiError::new(
      ErrorCode::InvalidInput,
      format!("{e:#}"),
    ))
  }
}

pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
  pub url: Option<String>,
  pub token: Option<String>,
}

pub fn config_path() -> PathBuf {
  let base = std::env::var_os("XDG_CONFIG_HOME")
    .map(PathBuf::from)
    .or_else(|| {
      std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".config"))
    })
    .unwrap_or_else(|| PathBuf::from("."));
  base.join("wharf").join("config.toml")
}

impl Config {
  pub fn load() -> Config {
    std::fs::read_to_string(config_path())
      .ok()
      .and_then(|t| toml::from_str(&t).ok())
      .unwrap_or_default()
  }

  /// 以 0600 保存，里面有 token。
  pub fn save(&self) -> anyhow::Result<PathBuf> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let path = config_path();
    if let Some(dir) = path.parent() {
      std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .mode(0o600)
      .open(&path)?;
    file.write_all(toml::to_string(self)?.as_bytes())?;
    Ok(path)
  }
}

pub struct Client {
  http: reqwest::Client,
  base: String,
  token: Option<String>,
}

impl Client {
  pub fn new(
    url: Option<String>,
    token: Option<String>,
  ) -> CliResult<Self> {
    let config = Config::load();
    let base = url.or(config.url).ok_or_else(|| {
      ApiError::new(ErrorCode::InvalidInput, "不知道控制面地址")
        .with_hint(
          "设置环境变量 WHARF_URL，或执行 wharf login --url <地址>",
        )
        .suggest("wharf login --url http://100.101.102.103:7700")
    })?;
    Ok(Self {
      http: reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| ApiError::internal(e.to_string()))?,
      base: base.trim_end_matches('/').to_string(),
      token: token.or(config.token),
    })
  }

  async fn send<T: DeserializeOwned>(
    &self,
    req: reqwest::RequestBuilder,
  ) -> CliResult<T> {
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let resp = req.send().await.map_err(|e| {
      ApiError::new(
        ErrorCode::AgentOffline,
        format!("无法连接控制面 {}：{}", self.base, e.without_url()),
      )
      .with_hint("检查控制面是否在运行、地址是否正确（WHARF_URL 或 wharf login）")
    })?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
      ApiError::internal(format!("读取响应失败：{e}"))
    })?;
    if !status.is_success() {
      let err = serde_json::from_slice::<ApiError>(&bytes)
        .unwrap_or_else(|_| {
          ApiError::internal(format!(
            "控制面返回 HTTP {}：{}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
              .chars()
              .take(300)
              .collect::<String>()
          ))
        });
      return Err(err.into());
    }
    serde_json::from_slice(&bytes).map_err(|e| {
      ApiError::internal(format!("无法解析控制面响应：{e}")).into()
    })
  }

  /// 读取分块响应（日志流），收到一块就交给 `on_chunk`，直到服务端结束。
  pub async fn follow(
    &self,
    path: &str,
    mut on_chunk: impl FnMut(&[u8]),
  ) -> CliResult<()> {
    let req = self
      .http
      .get(format!("{}{path}", self.base))
      .timeout(Duration::from_secs(2 * 3600));
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let mut resp = req.send().await.map_err(|e| {
      ApiError::new(
        ErrorCode::AgentOffline,
        format!("无法连接控制面 {}：{}", self.base, e.without_url()),
      )
    })?;
    if !resp.status().is_success() {
      let bytes = resp.bytes().await.unwrap_or_default();
      return Err(
        serde_json::from_slice::<ApiError>(&bytes)
          .unwrap_or_else(|_| ApiError::internal("日志流请求失败"))
          .into(),
      );
    }
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
      ApiError::internal(format!("日志流中断：{}", e.without_url()))
    })? {
      on_chunk(&chunk);
    }
    Ok(())
  }

  pub async fn get<T: DeserializeOwned>(
    &self,
    path: &str,
  ) -> CliResult<T> {
    self
      .send(self.http.get(format!("{}{path}", self.base)))
      .await
  }

  pub async fn post<B: Serialize, T: DeserializeOwned>(
    &self,
    path: &str,
    body: &B,
  ) -> CliResult<T> {
    self
      .send(self.http.post(format!("{}{path}", self.base)).json(body))
      .await
  }

  pub async fn put<B: Serialize, T: DeserializeOwned>(
    &self,
    path: &str,
    body: &B,
  ) -> CliResult<T> {
    self
      .send(self.http.put(format!("{}{path}", self.base)).json(body))
      .await
  }

  pub async fn delete<T: DeserializeOwned>(
    &self,
    path: &str,
  ) -> CliResult<T> {
    self
      .send(self.http.delete(format!("{}{path}", self.base)))
      .await
  }
}

/// URL 路径段编码。
pub fn seg(s: &str) -> String {
  s.bytes()
    .map(|b| match b {
      b'A'..=b'Z'
      | b'a'..=b'z'
      | b'0'..=b'9'
      | b'-'
      | b'_'
      | b'.'
      | b'~' => (b as char).to_string(),
      _ => format!("%{b:02X}"),
    })
    .collect()
}

/// 读取密文：终端里不回显，管道里读一行。
pub fn read_secret(prompt: &str) -> anyhow::Result<String> {
  use std::io::IsTerminal;
  let value = if std::io::stdin().is_terminal() {
    rpassword::prompt_password(prompt)?
  } else {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line
  };
  let value = value.trim_end_matches(['\r', '\n']).to_string();
  if value.trim().is_empty() {
    anyhow::bail!("没有读到内容");
  }
  Ok(value)
}
