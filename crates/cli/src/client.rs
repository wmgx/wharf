//! 控制面 HTTP 客户端和本地配置（`~/.config/wharf/config.toml`）。

use std::{
  fs::OpenOptions,
  io::{self, Read},
  os::unix::fs::{OpenOptionsExt, PermissionsExt},
  path::{Path, PathBuf},
  process::Stdio,
  time::Duration,
};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

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

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub url: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token_file: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token_cmd: Option<String>,
  /// 控制面 ed25519 公钥（hex），建加密通道时验证控制面身份。
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub core_key: Option<String>,
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
  pub fn load_checked() -> Result<Self, ApiError> {
    Self::load_from(&config_path())
  }

  fn load_from(path: &Path) -> Result<Self, ApiError> {
    let failed = |reason: &str| {
      ApiError::invalid(format!(
        "读取配置文件 {} 失败：{reason}",
        path.display()
      ))
      .with_hint("检查 config.toml 格式，或重新执行 wharf login")
    };
    match std::fs::read_to_string(path) {
      Ok(text) => toml::from_str(&text)
        .map_err(|_| failed("TOML 语法或字段类型错误")),
      Err(e) if e.kind() == io::ErrorKind::NotFound => {
        Ok(Self::default())
      }
      Err(e) => Err(failed(&e.to_string())),
    }
  }

  /// 以 0600 保存配置，可能含明文 token。
  pub fn save(&self) -> anyhow::Result<PathBuf> {
    let path = config_path();
    self.save_to(&path)?;
    Ok(path)
  }

  pub(crate) fn check_writable(&self) -> anyhow::Result<()> {
    let path = config_path();
    if path.try_exists()? {
      std::fs::OpenOptions::new().write(true).open(&path)?;
    }
    let (file, temp) = Self::open_temp(&path)?;
    drop(file);
    std::fs::remove_file(temp)?;
    Ok(())
  }

  fn open_temp(
    path: &Path,
  ) -> anyhow::Result<(std::fs::File, PathBuf)> {
    if let Some(dir) = path.parent() {
      std::fs::create_dir_all(dir)?;
    }
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
      .map_err(|_| anyhow::anyhow!("随机数不可用"))?;
    let temp =
      path.with_extension(format!("{}.tmp", hex::encode(nonce)));
    let file = std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(&temp)?;
    Ok((file, temp))
  }

  pub(crate) fn save_to(&self, path: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    let raw = toml::to_string(self)?;
    let (mut file, temp) = Self::open_temp(path)?;
    let result = file
      .write_all(raw.as_bytes())
      .and_then(|()| file.sync_all())
      .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
      let _ = std::fs::remove_file(temp);
    }
    result.map_err(Into::into)
  }
}

pub async fn resolve_token(
  override_token: Option<String>,
  config: &Config,
) -> Result<Option<String>, ApiError> {
  if let Some(token) = override_token.filter(|t| !t.is_empty()) {
    return Ok(Some(token));
  }
  let token = match (&config.token, &config.token_file, &config.token_cmd) {
    (Some(token), None, None) => validate_token_text(token, "config.toml 的 token")?,
    (None, Some(path), None) => read_token_file(path)?,
    (None, None, Some(cmd)) => run_token_cmd(cmd).await?,
    (None, None, None) => return Ok(None),
    _ => return Err(ApiError::invalid("config.toml 中 token、token_file、token_cmd 只能配置其中一项")
      .with_hint("只保留一种凭据来源，或重新执行 wharf login")),
  };
  Ok(Some(token))
}

fn validate_token_text(
  text: &str,
  source: &str,
) -> Result<String, ApiError> {
  let token = text.trim();
  if token.is_empty() || token.contains(['\r', '\n']) {
    return Err(ApiError::invalid(format!(
      "{source} 必须提供非空的单行 token"
    )));
  }
  Ok(token.to_string())
}

fn read_token_file(path: &str) -> Result<String, ApiError> {
  let expanded = match path.strip_prefix("~/") {
    Some(relative) => std::env::var_os("HOME")
      .map(|home| {
        PathBuf::from(home).join(relative.trim_start_matches('/'))
      })
      .ok_or_else(|| {
        ApiError::invalid("无法展开 token_file 路径：未设置 HOME")
      })?,
    None => PathBuf::from(path),
  };
  let failed = |e: io::Error| {
    ApiError::invalid(format!("读取 token_file {path} 失败：{e}"))
      .with_hint("检查 token_file 路径和权限，或重新执行 wharf login")
  };
  let mut file = OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NONBLOCK)
    .open(expanded)
    .map_err(failed)?;
  let meta = file.metadata().map_err(failed)?;
  if !meta.is_file() {
    return Err(ApiError::invalid("token_file 必须指向普通文件"));
  }
  if meta.permissions().mode() & 0o077 != 0 {
    eprintln!("提醒：token 文件 {path} 权限过宽，建议改为 0600");
  }
  let mut text = String::new();
  file.read_to_string(&mut text).map_err(failed)?;
  validate_token_text(&text, "token_file")
}

struct TokenProcess {
  group: i32,
  tty_group: Option<i32>,
  finished: bool,
}

impl Drop for TokenProcess {
  fn drop(&mut self) {
    if !self.finished {
      // 终止整个命令组，管道里的进程也可能仍在运行。
      unsafe { libc::kill(-self.group, libc::SIGKILL) };
    }
    if let Some(group) = self.tty_group {
      foreground_tty(group);
    }
  }
}

fn foreground_tty(group: i32) -> bool {
  // 从后台恢复前台时屏蔽 SIGTTOU，避免 CLI 自己被终端挂起。
  unsafe {
    let mut signals = std::mem::zeroed();
    let mut old = std::mem::zeroed();
    libc::sigemptyset(&mut signals);
    libc::sigaddset(&mut signals, libc::SIGTTOU);
    if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, &mut old) != 0
    {
      return false;
    }
    let ok = libc::tcsetpgrp(libc::STDIN_FILENO, group) == 0;
    libc::pthread_sigmask(
      libc::SIG_SETMASK,
      &old,
      std::ptr::null_mut(),
    );
    ok
  }
}

async fn run_token_cmd(cmd: &str) -> Result<String, ApiError> {
  const TIMEOUT: Duration = Duration::from_secs(15);
  const LINE_LIMIT: u64 = 64 * 1024;
  let failed = |reason: &str| {
    ApiError::invalid(format!("执行 token_cmd 失败{reason}"))
      .with_hint(
        "检查 config.toml 中的 token_cmd，确认凭据工具已解锁",
      )
  };
  let mut child = tokio::process::Command::new("sh")
    .args(["-c", cmd])
    .stdin(Stdio::inherit())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .process_group(0)
    .kill_on_drop(true)
    .spawn()
    .map_err(|_| failed("：无法启动命令"))?;
  let group = child.id().expect("命令已启动") as i32;
  let tty_group = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
  let mut process = TokenProcess {
    group,
    tty_group: (tty_group > 0
      && tty_group == unsafe { libc::getpgrp() }
      && foreground_tty(group))
    .then_some(tty_group),
    finished: false,
  };
  // 子进程也可能在前台切换前先尝试读终端，从 SIGTTIN 恢复。
  if process.tty_group.is_some() {
    unsafe { libc::kill(-group, libc::SIGCONT) };
  }
  let mut stdout =
    BufReader::new(child.stdout.take().expect("已接入命令标准输出"));
  let read_output = async {
    let mut line = Vec::new();
    (&mut stdout)
      .take(LINE_LIMIT + 1)
      .read_until(b'\n', &mut line)
      .await?;
    tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await?;
    Ok::<_, io::Error>(line)
  };
  let result = tokio::time::timeout(TIMEOUT, async {
    tokio::try_join!(child.wait(), read_output)
  })
  .await;
  let (status, line) = match result {
    Ok(Ok(output)) => {
      process.finished = output.0.success();
      output
    }
    other => {
      drop(process);
      let _ = child.start_kill();
      let _ = child.wait().await;
      return Err(match other {
        Err(_) => ApiError::new(
          ErrorCode::Timeout,
          "执行 token_cmd 超时（15 秒）",
        )
        .with_hint(
          "先解锁凭据工具（如 1Password / Keychain），再重试",
        ),
        _ => failed("：无法读取命令结果"),
      });
    }
  };
  if !status.success() {
    let reason = status.code().map_or_else(
      || "（进程被信号终止）".to_string(),
      |code| format!("（退出码 {code}）"),
    );
    return Err(failed(&reason));
  }
  if line.len() as u64 > LINE_LIMIT {
    return Err(failed("：首行过长"));
  }
  let line = std::str::from_utf8(&line)
    .map_err(|_| failed("：首行不是 UTF-8"))?;
  validate_token_text(line, "token_cmd")
}

fn local_http() -> CliResult<reqwest::Client> {
  reqwest::Client::builder()
    .no_proxy()
    .connect_timeout(Duration::from_secs(15))
    .timeout(Duration::from_secs(180))
    .default_headers(default_headers())
    .build()
    .map_err(|e| ApiError::internal(e.to_string()).into())
}

pub(crate) struct DownloadMeta {
  pub filename: Option<String>,
  pub size: u64,
  pub sha256: String,
  pub format: String,
}

pub struct Client {
  http: reqwest::Client,
  /// 控制面地址，只用于提示。
  base: String,
  /// 实际发请求的地址：本机加密通道的入口。
  endpoint: String,
  tunnel_error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
  token: Option<String>,
}

impl Client {
  #[cfg(test)]
  pub(crate) fn test_endpoint(endpoint: String) -> Self {
    Self {
      http: local_http().expect("本地客户端可用"),
      base: endpoint.clone(),
      endpoint,
      tunnel_error: Default::default(),
      token: Some("fixture-token".into()),
    }
  }

  pub async fn new(
    url: Option<String>,
    token: Option<String>,
  ) -> CliResult<Self> {
    Self::with_key(url, token, None).await
  }

  /// 所有请求都经加密通道（[crate::tunnel]），`core_key` 不填时用 WHARF_CORE_KEY 或配置里的。
  pub async fn with_key(
    url: Option<String>,
    token: Option<String>,
    core_key: Option<String>,
  ) -> CliResult<Self> {
    let config =
      if url.is_some() && token.is_some() && core_key.is_some() {
        Config::default()
      } else {
        Config::load_checked()?
      };
    let token = resolve_token(token, &config).await?;
    let base = url.or(config.url).ok_or_else(|| {
      ApiError::new(ErrorCode::InvalidInput, "不知道控制面地址")
        .with_hint(
          "设置环境变量 WHARF_URL，或执行 wharf login --url <地址>",
        )
        .suggest("wharf login --url http://100.101.102.103:7700")
    })?;
    let base = base.trim_end_matches('/').to_string();
    let core_key = core_key
      .or_else(|| std::env::var("WHARF_CORE_KEY").ok())
      .or(config.core_key)
      .ok_or_else(|| {
        ApiError::new(ErrorCode::InvalidInput, "不知道控制面公钥，无法建立加密通道")
          .with_hint("在页面“设置 → CLI 与 AI 接入”复制带 --core-key 的 wharf login 命令重新登录，或设置环境变量 WHARF_CORE_KEY")
      })?;
    let core_key = crate::tunnel::parse_core_key(&core_key)?;
    let tunnel =
      crate::tunnel::start(&base, core_key).map_err(|e| {
        ApiError::internal(format!("启动加密通道失败：{e:#}"))
      })?;
    Ok(Self {
      http: local_http()?,
      base,
      endpoint: tunnel.local,
      tunnel_error: tunnel.last_error,
      token,
    })
  }

  pub(crate) fn is_for(&self, url: &str) -> bool {
    self.base == url.trim_end_matches('/')
  }

  /// 控制面和本机 CLI 的构建号不一致时提醒一次（写 stderr，不影响 `--json`）。
  fn check_build(&self, headers: &reqwest::header::HeaderMap) {
    static WARNED: std::sync::atomic::AtomicBool =
      std::sync::atomic::AtomicBool::new(false);
    let mine = env!("WHARF_CLI_BUILD");
    let Some(theirs) = headers
      .get(wharf_api_types::BUILD_HEADER)
      .and_then(|v| v.to_str().ok())
    else {
      return;
    };
    if mine == "dev"
      || theirs == "dev"
      || mine == theirs
      || WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
      return;
    }
    eprintln!(
      "提醒：本机 wharf 是构建 {mine}，控制面是 {theirs}；版本不同时新字段可能显示不出来。\n  更新：wharf self-update"
    );
  }

  /// 连接失败：多半是加密通道没建起来，附上原因。
  fn conn_error(&self, e: reqwest::Error) -> ApiError {
    let tunnel = self
      .tunnel_error
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .take();
    let reason =
      tunnel.unwrap_or_else(|| e.without_url().to_string());
    ApiError::new(
      ErrorCode::AgentOffline,
      format!("无法连接控制面 {}：{reason}", self.base),
    )
    .with_hint("检查控制面是否在运行、地址是否正确（WHARF_URL 或 wharf login）")
  }

  async fn send<T: DeserializeOwned>(
    &self,
    req: reqwest::RequestBuilder,
  ) -> CliResult<T> {
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let resp = req.send().await.map_err(|e| self.conn_error(e))?;
    self.check_build(resp.headers());
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
      ApiError::internal(format!("读取响应失败：{e}"))
    })?;
    if !status.is_success() {
      let err = serde_json::from_slice::<ApiError>(&bytes)
        .unwrap_or_else(|_| {
          // 请求体解析失败（缺字段等）：多半是本机 CLI 比控制面旧。
          if status.as_u16() == 422 {
            return ApiError::new(
              ErrorCode::InvalidInput,
              format!(
                "控制面不接受这个请求：{}",
                String::from_utf8_lossy(&bytes)
              ),
            )
            .with_hint(self.update_hint());
          }
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
      // 多半是控制面升级后多了字段，本机 CLI 还是旧的。
      ApiError::internal(format!("无法解析控制面响应：{e}"))
        .with_hint(self.update_hint())
        .into()
    })
  }

  /// WebSocket 请求：地址换成 ws(s)://，带上 token 和 CLI 标识。
  pub fn ws_request(
    &self,
    path: &str,
  ) -> CliResult<
    tokio_tungstenite::tungstenite::handshake::client::Request,
  > {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!("{}{path}", self.endpoint)
      .replacen("http://", "ws://", 1);
    let mut req = url
      .into_client_request()
      .map_err(|e| ApiError::internal(format!("地址无效：{e}")))?;
    let h = req.headers_mut();
    h.insert(
      wharf_api_types::CLI_API_HEADER,
      wharf_api_types::CLI_API.into(),
    );
    if let Some(token) = &self.token
      && let Ok(v) = format!("Bearer {token}").parse()
    {
      h.insert("authorization", v);
    }
    Ok(req)
  }

  fn update_hint(&self) -> String {
    "本机 wharf 可能比控制面旧，更新后再试：wharf self-update".into()
  }

  /// 读取分块响应（日志流），收到一块就交给 `on_chunk`，直到服务端结束。
  pub async fn follow(
    &self,
    path: &str,
    mut on_chunk: impl FnMut(&[u8]),
  ) -> CliResult<()> {
    let req = self
      .http
      .get(format!("{}{path}", self.endpoint))
      .timeout(Duration::from_secs(2 * 3600));
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let mut resp =
      req.send().await.map_err(|e| self.conn_error(e))?;
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

  /// 控制面地址（配置里写的那个）。
  pub fn base(&self) -> &str {
    &self.base
  }

  /// 边收边交给 `on_chunk`（下载文件），总共最多 `timeout`。
  pub async fn download(
    &self,
    path: &str,
    timeout: Duration,
    mut on_chunk: impl FnMut(&[u8]) -> std::io::Result<()>,
  ) -> CliResult<()> {
    let req = self
      .http
      .get(format!("{}{path}", self.endpoint))
      .timeout(timeout);
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let mut resp =
      req.send().await.map_err(|e| self.conn_error(e))?;
    if !resp.status().is_success() {
      let status = resp.status().as_u16();
      let bytes = resp.bytes().await.unwrap_or_default();
      return Err(
        serde_json::from_slice::<ApiError>(&bytes)
          .unwrap_or_else(|_| {
            ApiError::internal(format!("下载失败：HTTP {status}"))
          })
          .into(),
      );
    }
    let expected = resp.content_length();
    let mut received = 0;
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
      ApiError::internal(format!("下载中断：{}", e.without_url()))
    })? {
      received += chunk.len() as u64;
      on_chunk(&chunk)
        .map_err(|e| ApiError::internal(format!("写入失败：{e}")))?;
    }
    if expected.is_some_and(|n| received != n) {
      return Err(
        ApiError::internal(
          "下载不完整：传输中断或远端文件在下载期间已变化",
        )
        .with_hint("重新执行下载命令")
        .into(),
      );
    }
    Ok(())
  }

  pub(crate) async fn post_download(
    &self,
    path: &str,
    body: &impl Serialize,
    timeout: Duration,
    mut on_chunk: impl FnMut(&[u8]) -> io::Result<()>,
  ) -> CliResult<DownloadMeta> {
    use sha2::{Digest, Sha256};
    let req = self
      .http
      .post(format!("{}{path}", self.endpoint))
      .json(body)
      .timeout(timeout);
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let mut response =
      req.send().await.map_err(|e| self.conn_error(e))?;
    if !response.status().is_success() {
      let status = response.status();
      let bytes = response.bytes().await.unwrap_or_default();
      return Err(
        serde_json::from_slice::<ApiError>(&bytes)
          .unwrap_or_else(|_| {
            ApiError::internal(format!("导出失败：HTTP {status}"))
          })
          .into(),
      );
    }
    let missing = || ApiError::internal("导出响应缺少文件校验信息");
    let header = |name| {
      response
        .headers()
        .get(name)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(missing)
    };
    let size = response.content_length().ok_or_else(missing)?;
    let sha256 = header("x-wharf-file-sha256")?;
    let format = header("x-wharf-export-format")?;
    let filename =
      header("content-disposition").ok().and_then(|value| {
        value
          .strip_prefix("attachment; filename=\"")
          .and_then(|name| name.strip_suffix('"'))
          .filter(|name| {
            name.starts_with("wharf-core-")
              && name.ends_with(".wharf-core.enc")
              && name.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
              })
          })
          .map(str::to_owned)
      });
    if format != "wharf-core-export-v1"
      || sha256.len() != 64
      || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
      return Err(
        ApiError::invalid("导出文件格式或 SHA-256 无效").into(),
      );
    }
    let mut received = 0;
    let mut digest = Sha256::new();
    while let Some(chunk) =
      response.chunk().await.map_err(|e| self.conn_error(e))?
    {
      received += chunk.len() as u64;
      if received > size {
        return Err(ApiError::internal("导出文件长度不符").into());
      }
      digest.update(&chunk);
      on_chunk(&chunk)
        .map_err(|e| ApiError::internal(format!("写入失败：{e}")))?;
    }
    if received != size || hex::encode(digest.finalize()) != sha256 {
      return Err(
        ApiError::internal("导出文件长度或 SHA-256 校验失败").into(),
      );
    }
    Ok(DownloadMeta {
      filename,
      size,
      sha256,
      format,
    })
  }

  pub(crate) async fn require_exec_v2_core(&self) -> CliResult<()> {
    let identity: serde_json::Value = self.get("/api/whoami").await?;
    if identity["exec_v2"] != true {
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          "控制面版本旧，可能忽略新增的操作参数",
        )
        .with_hint("升级控制面和 agent 后重试：wharf upgrade")
        .into(),
      );
    }
    Ok(())
  }

  pub async fn get<T: DeserializeOwned>(
    &self,
    path: &str,
  ) -> CliResult<T> {
    self
      .send(self.http.get(format!("{}{path}", self.endpoint)))
      .await
  }

  pub async fn post<B: Serialize, T: DeserializeOwned>(
    &self,
    path: &str,
    body: &B,
  ) -> CliResult<T> {
    self
      .send(
        self
          .http
          .post(format!("{}{path}", self.endpoint))
          .json(body),
      )
      .await
  }

  pub async fn rotate_link(
    &self,
    gateway: &str,
    token: bool,
    cert: bool,
  ) -> CliResult<serde_json::Value> {
    self
      .post(
        &format!("/api/gateways/{}/link/rotate", seg(gateway)),
        &serde_json::json!({"token": token, "cert": cert}),
      )
      .await
  }

  /// POST 执行流。旧控制面可能返回非流式 JSON，交给调用方处理。
  pub async fn post_stream<B: Serialize>(
    &self,
    path: &str,
    body: &B,
    timeout: Duration,
    mut on_line: impl FnMut(&str) -> CliResult<()>,
  ) -> CliResult<Option<Vec<u8>>> {
    let req = self
      .http
      .post(format!("{}{path}", self.endpoint))
      .timeout(timeout)
      .json(body);
    let req = match &self.token {
      Some(token) => req.bearer_auth(token),
      None => req,
    };
    let mut resp =
      req.send().await.map_err(|e| self.conn_error(e))?;
    self.check_build(resp.headers());
    if !resp.status().is_success() {
      let status = resp.status();
      let bytes = resp.bytes().await.unwrap_or_default();
      return Err(
        serde_json::from_slice::<ApiError>(&bytes)
          .unwrap_or_else(|_| {
            ApiError::internal(format!("执行请求失败：HTTP {status}"))
          })
          .into(),
      );
    }
    if !resp
      .headers()
      .get("content-type")
      .and_then(|v| v.to_str().ok())
      .is_some_and(|v| v.starts_with("application/x-ndjson"))
    {
      return Ok(Some(
        resp.bytes().await.map_err(|e| self.conn_error(e))?.to_vec(),
      ));
    }
    let mut pending = Vec::new();
    while let Some(chunk) =
      resp.chunk().await.map_err(|e| self.conn_error(e))?
    {
      for part in chunk.split_inclusive(|&b| b == b'\n') {
        if pending.len() + part.len() > 256 * 1024 {
          return Err(
            ApiError::internal("执行流事件超过大小上限").into(),
          );
        }
        pending.extend_from_slice(part);
        if part.last() == Some(&b'\n') {
          let line =
            std::str::from_utf8(&pending[..pending.len() - 1])
              .map_err(|_| {
                ApiError::internal("执行流事件不是 UTF-8")
              })?;
          on_line(line)?;
          pending.clear();
        }
      }
    }
    if !pending.is_empty() {
      return Err(ApiError::internal("执行流在事件中间断开").into());
    }
    Ok(None)
  }

  pub async fn post_timeout<B: Serialize, T: DeserializeOwned>(
    &self,
    path: &str,
    body: &B,
    timeout: Duration,
  ) -> CliResult<T> {
    self
      .send(
        self
          .http
          .post(format!("{}{path}", self.endpoint))
          .timeout(timeout)
          .json(body),
      )
      .await
  }

  pub async fn put<B: Serialize, T: DeserializeOwned>(
    &self,
    path: &str,
    body: &B,
  ) -> CliResult<T> {
    self
      .send(
        self.http.put(format!("{}{path}", self.endpoint)).json(body),
      )
      .await
  }

  /// 上传二进制内容（代码包），大文件慢，单独给 30 分钟。
  pub async fn put_bytes<T: DeserializeOwned>(
    &self,
    path: &str,
    bytes: Vec<u8>,
  ) -> CliResult<T> {
    self
      .send(
        self
          .http
          .put(format!("{}{path}", self.endpoint))
          .header("content-type", "application/gzip")
          .timeout(Duration::from_secs(30 * 60))
          .body(bytes),
      )
      .await
  }

  pub async fn delete<T: DeserializeOwned>(
    &self,
    path: &str,
  ) -> CliResult<T> {
    self
      .send(self.http.delete(format!("{}{path}", self.endpoint)))
      .await
  }
}

/// `--reason`：这次操作的原因，跟着每个请求发给控制面，记进操作记录。
pub static REASON: std::sync::OnceLock<String> =
  std::sync::OnceLock::new();

fn default_headers() -> reqwest::header::HeaderMap {
  use reqwest::header::{HeaderName, HeaderValue};
  let mut h = reqwest::header::HeaderMap::new();
  h.insert(
    HeaderName::from_static(wharf_api_types::CLI_API_HEADER),
    HeaderValue::from(wharf_api_types::CLI_API),
  );
  // 请求头只能放 ASCII，中文按百分号编码。
  if let Some(reason) = REASON.get()
    && let Ok(v) = HeaderValue::from_str(&seg(reason))
  {
    h.insert(HeaderName::from_static("x-wharf-reason"), v);
  }
  h
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

#[tokio::test]
async fn resolves_token_sources_and_reports_bad_configuration() {
  let temp = tempfile::tempdir().unwrap();
  let path = temp.path().join("config.toml");
  let expected = format!("fixture-{}", std::process::id());
  if let Some(home_config) =
    std::env::var_os("WHARF_TEST_TOKEN_FILE_HOME")
  {
    use clap::Parser;
    let config = Config::load_from(Path::new(&home_config)).unwrap();
    let token = resolve_token(None, &config).await.unwrap().unwrap();
    let expected = std::env::var("WHARF_TOKEN").unwrap();
    assert!(token == expected);
    let cli =
      crate::Cli::try_parse_from(["wharf", "status"]).unwrap();
    let config = Config {
      token_cmd: Some("exit 42".into()),
      ..Default::default()
    };
    assert!(
      resolve_token(cli.token, &config).await.unwrap()
        == Some(expected)
    );
    return;
  }
  let file = temp.path().join("t.tok");
  std::fs::write(&file, format!(" \t{expected}\r\n")).unwrap();
  Config {
    token_file: Some("~/t.tok".into()),
    ..Default::default()
  }
  .save_to(&path)
  .unwrap();
  let child = std::process::Command::new(
    std::env::current_exe().unwrap(),
  )
  .args([
    "--exact",
    "client::resolves_token_sources_and_reports_bad_configuration",
  ])
  .env("HOME", temp.path())
  .env("WHARF_TEST_TOKEN_FILE_HOME", &path)
  .env("WHARF_TOKEN", &expected)
  .output()
  .unwrap();
  assert!(child.status.success());
  assert!(
    String::from_utf8_lossy(&child.stdout).contains("1 passed")
  );
  let config = Config {
    token_cmd: Some(
      "printf '  fixture-command\\r\\nignored\\n'".into(),
    ),
    ..Default::default()
  };
  config.save_to(&path).unwrap();
  let config = Config::load_from(&path).unwrap();
  assert!(
    resolve_token(None, &config).await.unwrap().as_deref()
      == Some("fixture-command")
  );
  assert!(
    !std::fs::read_to_string(&path)
      .unwrap()
      .lines()
      .any(|line| line.starts_with("token ="))
  );
  let config = Config {
    token: Some(expected.clone()),
    token_file: Some("unreadable".into()),
    ..Default::default()
  };
  assert!(
    resolve_token(None, &config)
      .await
      .unwrap_err()
      .message
      .contains("只能配置其中一项")
  );
  let config = Config {
    token_cmd: Some("exit 42".into()),
    ..Default::default()
  };
  assert!(
    resolve_token(Some(expected.clone()), &config)
      .await
      .unwrap()
      == Some(expected.clone())
  );
  std::fs::write(&path, format!("token = '{expected}")).unwrap();
  let bad = Config::load_from(&path).err().unwrap();
  assert!(bad.message.contains("TOML 语法"));
  assert!(!bad.message.contains(&expected));
}

#[tokio::test]
async fn token_command_times_out_and_reaps_shell() {
  let dir = tempfile::tempdir().unwrap();
  let pid = dir.path().join("pid");
  let command = format!(
    "printf '%s' \"$$\" > '{}'; sleep 30 | cat",
    pid.display()
  );
  let err = run_token_cmd(&command).await.unwrap_err();
  assert_eq!(err.code, ErrorCode::Timeout);
  let pid: i32 =
    std::fs::read_to_string(pid).unwrap().parse().unwrap();
  assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
  assert_eq!(
    io::Error::last_os_error().raw_os_error(),
    Some(libc::ESRCH)
  );
  let output = format!("fixture-{}", std::process::id());
  let err = run_token_cmd(&format!(
    "printf %s '{output}'; printf %s '{output}' >&2; exit 42"
  ))
  .await
  .unwrap_err();
  assert!(err.message.contains("42"));
  assert!(!err.message.contains(&output));
}

#[tokio::test]
async fn local_bearer_bypasses_environment_proxy() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  const ENDPOINT: &str = "WHARF_FIXTURE_LOOPBACK_HTTP";
  if let Ok(endpoint) = std::env::var(ENDPOINT) {
    let value: serde_json::Value = Client::test_endpoint(endpoint)
      .get("/api/version")
      .await
      .unwrap();
    assert_eq!(value, serde_json::json!({}));
    return;
  }
  let local =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
  let endpoint = format!("http://{}", local.local_addr().unwrap());
  let serving = tokio::spawn(async move {
    let (mut socket, _) = local.accept().await.unwrap();
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n\r\n") && line.len() < 8192 {
      line.push(socket.read_u8().await.unwrap());
    }
    let request =
      String::from_utf8(line).unwrap().to_ascii_lowercase();
    assert!(request.contains("authorization: bearer fixture-token"));
    socket
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
      .await
      .unwrap();
  });
  let mut child =
    tokio::process::Command::new(std::env::current_exe().unwrap());
  child
    .args([
      "--exact",
      "client::local_bearer_bypasses_environment_proxy",
    ])
    .env(ENDPOINT, endpoint)
    .env("HTTP_PROXY", &proxy_url)
    .env("http_proxy", &proxy_url)
    .env_remove("NO_PROXY")
    .env_remove("no_proxy")
    .kill_on_drop(true);
  let result =
    tokio::time::timeout(Duration::from_secs(10), child.output())
      .await
      .unwrap()
      .unwrap();
  assert!(result.status.success());
  serving.await.unwrap();
  assert!(
    tokio::time::timeout(Duration::from_millis(50), proxy.accept())
      .await
      .is_err()
  );
}
