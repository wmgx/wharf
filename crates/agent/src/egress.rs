//! 出口（p8），两种监听都跑在 agent 进程里：
//!
//! - 提供出口（serve）：在内网地址的 8118 端口起 HTTP 代理，要 `Proxy-Authorization: Basic wharf:<口令>`；
//! - 本地分流（route）：在 8119 端口起 HTTP 代理，只接受本机和 docker 网段来的连接。
//!   命中规则的经出口（CONNECT 隧道）出去，其余直连；出口连不上时也直连。
//!   dockerd、构建、拉代码都指向它，改规则不用重启 dockerd。
//!
//! 安全边界（R21.2）：仅放行公网单播 IP（`is_public`），拦截回环、未指定、链路本地、
//! 云元数据、私网、组网段及控制面自身入口；直连已校验 `SocketAddr` 防 DNS 重绑定；
//! 单端口限制最大并发与双向空闲超时。

use std::{
  net::{IpAddr, Ipv6Addr, SocketAddr},
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::Duration,
};

use base64::Engine;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  sync::Semaphore,
  time::Instant,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{EgressConfig, EgressRoute},
  egress::{LOCAL_PORT, SERVE_PORT, via_exit},
  net_probe::is_public,
};

pub fn local_url() -> String {
  format!("http://127.0.0.1:{LOCAL_PORT}")
}

const FILE: &str = "egress.json";
const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 连出口的超时：超过就当出口不通，改用直连。
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
/// 双向拷贝空闲超时：超过无流量自动关闭。
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// 单个代理端口最大并发连接数。
const MAX_CONNS: usize = 128;

/// 正在运行的配置和停止它用的 token。
static RUNNING: Mutex<Option<(EgressConfig, CancellationToken)>> =
  Mutex::new(None);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
  host: String,
  port: u16,
}

impl Target {
  fn to_authority(&self) -> String {
    if self.host.contains(':') {
      format!("[{}]:{}", self.host, self.port)
    } else {
      format!("{}:{}", self.host, self.port)
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoreTarget {
  host: String,
  port: u16,
  ip: Option<IpAddr>,
}

fn parse_core_url(core_url: &str) -> Option<CoreTarget> {
  let parsed = reqwest::Url::parse(core_url.trim()).ok()?;
  let raw_host = parsed.host_str()?;
  let bare = raw_host
    .trim_matches(['[', ']'])
    .trim_end_matches('.')
    .to_ascii_lowercase();
  if bare.is_empty() {
    return None;
  }
  let port = parsed.port_or_known_default()?;
  let ip = bare.parse::<IpAddr>().ok().map(IpAddr::to_canonical);
  Some(CoreTarget {
    host: bare,
    port,
    ip,
  })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
  PublicOnly,
  #[cfg(test)]
  AllowLoopbackForTest,
}

/// agent 启动时按上次保存的配置恢复。
pub fn restore(data_dir: &Path, core_url: &str) {
  let Ok(text) = std::fs::read_to_string(data_dir.join(FILE)) else {
    return;
  };
  let cfg = match serde_json::from_str::<EgressConfig>(&text) {
    Ok(cfg) => cfg,
    Err(e) => {
      tracing::warn!("出口配置读不了：{e}");
      return;
    }
  };
  let core = parse_core_url(core_url).map(Arc::new);
  // 开机时组网可能还没起来，内网地址绑不上：每 10 秒重试，最多 10 分钟。
  tokio::spawn(async move {
    for attempt in 1..=60 {
      // 控制面已经下发过新配置，不用再恢复旧的。
      if RUNNING.lock().map(|r| r.is_some()).unwrap_or(true) {
        return;
      }
      match start(cfg.clone(), core.clone()) {
        Ok(()) => return,
        Err(e) if attempt == 1 || attempt == 60 => {
          tracing::warn!(
            "恢复出口失败（第 {attempt} 次）：{}",
            e.message
          )
        }
        Err(_) => {}
      }
      tokio::time::sleep(Duration::from_secs(10)).await;
    }
  });
}

/// 设置出口。配置没变时什么都不做。
pub async fn apply(
  data_dir: PathBuf,
  core_url: &str,
  cfg: EgressConfig,
) -> Result<(), ApiError> {
  let same = RUNNING
    .lock()
    .map(|r| r.as_ref().map(|(c, _)| c) == Some(&cfg))
    .unwrap_or(false);
  if same {
    return Ok(());
  }
  stop();
  let path = data_dir.join(FILE);
  if cfg.serve.is_none() && cfg.route.is_none() {
    let _ = std::fs::remove_file(&path);
    return Ok(());
  }
  let core = parse_core_url(core_url).map(Arc::new);
  start(cfg.clone(), core)?;
  write_private(
    &path,
    &serde_json::to_string(&cfg).unwrap_or_default(),
  )
}

fn write_private(path: &Path, text: &str) -> Result<(), ApiError> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};
  let mut f = std::fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .map_err(|e| {
      ApiError::internal(format!("保存出口配置失败：{e}"))
    })?;
  f.write_all(text.as_bytes())
    .map_err(|e| ApiError::internal(format!("保存出口配置失败：{e}")))
}

fn stop() {
  if let Ok(mut r) = RUNNING.lock()
    && let Some((_, cancel)) = r.take()
  {
    cancel.cancel();
  }
}

fn basic(token: &str) -> String {
  format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD
      .encode(format!("wharf:{token}"))
  )
}

#[derive(Clone)]
enum Mode {
  /// 提供出口：要口令，直连目标。
  Serve { expected: String },
  /// 本地分流：按规则经出口或直连。
  Route(Arc<EgressRoute>),
}

fn listen(addr: (&str, u16)) -> Result<TcpListener, ApiError> {
  let l = std::net::TcpListener::bind(addr).map_err(|e| {
    ApiError::invalid(format!(
      "出口不能监听 {}:{}：{e}",
      addr.0, addr.1
    ))
  })?;
  l.set_nonblocking(true)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  TcpListener::from_std(l)
    .map_err(|e| ApiError::internal(e.to_string()))
}

fn start(
  cfg: EgressConfig,
  core: Option<Arc<CoreTarget>>,
) -> Result<(), ApiError> {
  // 先把要监听的都绑上，有一个失败就都不起。
  let mut listeners = Vec::new();
  if let Some(s) = &cfg.serve {
    listeners.push((
      listen((s.bind.as_str(), SERVE_PORT))?,
      Mode::Serve {
        expected: basic(&s.token),
      },
    ));
    tracing::info!("出口代理监听 {}:{SERVE_PORT}", s.bind);
  }
  if let Some(r) = &cfg.route {
    listeners.push((
      listen(("0.0.0.0", LOCAL_PORT))?,
      Mode::Route(Arc::new(r.clone())),
    ));
    tracing::info!("本地分流代理监听 {LOCAL_PORT}，出口 {}", r.exit);
  }
  let cancel = CancellationToken::new();
  for (listener, mode) in listeners {
    let stop = cancel.clone();
    let core = core.clone();
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    tokio::spawn(async move {
      loop {
        let accepted = tokio::select! {
          a = listener.accept() => a,
          _ = stop.cancelled() => break,
        };
        let Ok((conn, peer)) = accepted else { continue };
        if matches!(mode, Mode::Route(_)) && !local_peer(peer) {
          continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
          drop(conn);
          continue;
        };
        let mode = mode.clone();
        let stop = stop.clone();
        let core = core.clone();
        tokio::spawn(async move {
          let _permit = permit;
          tokio::select! {
            r = handle(conn, &mode, core.as_deref(), Policy::PublicOnly) => {
              if let Err(e) = r {
                tracing::debug!("出口连接结束：{e}");
              }
            }
            _ = stop.cancelled() => {}
          }
        });
      }
    });
  }
  if let Ok(mut r) = RUNNING.lock() {
    *r = Some((cfg, cancel));
  }
  Ok(())
}

/// 本地分流只接受本机和 docker 网段（172.16.0.0/12）来的连接。
fn local_peer(peer: SocketAddr) -> bool {
  match peer.ip() {
    IpAddr::V4(ip) => {
      let o = ip.octets();
      ip.is_loopback() || (o[0] == 172 && (16..32).contains(&o[1]))
    }
    IpAddr::V6(ip) => {
      ip.is_loopback()
        || ip.to_ipv4_mapped().is_some_and(|v4| {
          local_peer(SocketAddr::new(IpAddr::V4(v4), peer.port()))
        })
    }
  }
}

fn is_blocked_hostname(
  host: &str,
  core: Option<&CoreTarget>,
) -> bool {
  let norm = host.trim_end_matches('.').to_ascii_lowercase();
  if norm == "localhost"
    || norm.ends_with(".localhost")
    || norm == "metadata"
    || norm == "metadata.google.internal"
  {
    return true;
  }
  core.is_some_and(|c| c.ip.is_none() && norm == c.host)
}

fn is_allowed_ip(
  ip: IpAddr,
  port: u16,
  core: Option<&CoreTarget>,
  policy: Policy,
) -> bool {
  let ip = ip.to_canonical();
  if let Some(c) = core
    && c.ip == Some(ip)
    && c.port == port
  {
    return false;
  }
  match policy {
    Policy::PublicOnly => is_public(ip),
    #[cfg(test)]
    Policy::AllowLoopbackForTest => true,
  }
}

async fn resolve_and_check(
  target: &Target,
  core: Option<&CoreTarget>,
  policy: Policy,
) -> Result<Vec<SocketAddr>, &'static str> {
  if let Ok(ip) = target.host.parse::<IpAddr>() {
    if !is_allowed_ip(ip, target.port, core, policy) {
      return Err("403 Forbidden");
    }
    return Ok(vec![SocketAddr::new(ip.to_canonical(), target.port)]);
  }
  let resolved = tokio::time::timeout(
    CONNECT_TIMEOUT,
    tokio::net::lookup_host((target.host.as_str(), target.port)),
  )
  .await
  .map_err(|_| "502 Bad Gateway")?
  .map_err(|_| "502 Bad Gateway")?;
  let addrs: Vec<SocketAddr> = resolved
    .map(|a| SocketAddr::new(a.ip().to_canonical(), a.port()))
    .collect();
  if addrs.is_empty() {
    return Err("502 Bad Gateway");
  }
  if addrs
    .iter()
    .any(|a| !is_allowed_ip(a.ip(), a.port(), core, policy))
  {
    return Err("403 Forbidden");
  }
  Ok(addrs)
}

async fn handle(
  mut client: TcpStream,
  mode: &Mode,
  core: Option<&CoreTarget>,
  policy: Policy,
) -> std::io::Result<()> {
  let head =
    tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client))
      .await
      .map_err(|_| std::io::Error::other("读请求头超时"))??;
  let Some(req) = parse(&head.text) else {
    return reply(&mut client, "400 Bad Request").await;
  };
  if let Mode::Serve { expected } = mode
    && !same(req.auth.unwrap_or_default(), expected)
  {
    return client
      .write_all(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wharf\"\r\nContent-Length: 0\r\n\r\n",
      )
      .await;
  }

  // 所有请求入口（8119 与 8118）先拦黑名单域名与非法 IP 字面量，绝不发往出口也不直连。
  if policy == Policy::PublicOnly {
    if is_blocked_hostname(&req.target.host, core) {
      return reply(&mut client, "403 Forbidden").await;
    }
    if let Ok(ip) = req.target.host.parse::<IpAddr>()
      && !is_allowed_ip(ip, req.target.port, core, policy)
    {
      return reply(&mut client, "403 Forbidden").await;
    }
  }

  let tunneled = match mode {
    Mode::Serve { .. } => None,
    Mode::Route(r)
      if via_exit(&req.target.host, r.all, &r.domains) =>
    {
      // 命中走出口的域名不在国内本地解析（防 GFW DNS 污染误杀），交由海外出口解析并校验。
      match through_exit(r, &req.target).await {
        Ok(Ok(t)) => Some(t),
        // 出口明确拒绝（如 403/407）或连不上目标：原样透传，绝不回退直连。
        Ok(Err(status)) => return reply(&mut client, &status).await,
        Err(e) => {
          tracing::debug!(
            "出口 {} 连不上（{e}），{} 改用直连",
            r.exit,
            req.target.to_authority()
          );
          None
        }
      }
    }
    Mode::Route(_) => None,
  };

  let (mut upstream, early) = match tunneled {
    Some(t) => t,
    None => {
      let addrs =
        match resolve_and_check(&req.target, core, policy).await {
          Ok(a) => a,
          Err(status) => return reply(&mut client, status).await,
        };
      match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(addrs.as_slice()),
      )
      .await
      {
        Ok(Ok(s)) => (s, Vec::new()),
        _ => return reply(&mut client, "502 Bad Gateway").await,
      }
    }
  };
  match req.forward {
    None => {
      client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
      client.write_all(&early).await?;
      upstream.write_all(&head.rest).await?;
    }
    Some(first) => {
      upstream.write_all(first.as_bytes()).await?;
      upstream.write_all(&head.rest).await?;
    }
  }
  copy_with_idle_timeout(&mut client, &mut upstream, IDLE_TIMEOUT)
    .await?;
  Ok(())
}

/// 带空闲超时的双向流拷贝：任一方向读写到数据即刷新空闲计时器，超时后关闭连接。
async fn copy_with_idle_timeout(
  client: &mut TcpStream,
  upstream: &mut TcpStream,
  idle: Duration,
) -> std::io::Result<()> {
  let (mut cr, mut cw) = client.split();
  let (mut ur, mut uw) = upstream.split();
  let mut cbuf = [0u8; 8192];
  let mut ubuf = [0u8; 8192];
  let mut c_eof = false;
  let mut u_eof = false;
  let mut deadline = Instant::now() + idle;

  while !(c_eof && u_eof) {
    tokio::select! {
      _ = tokio::time::sleep_until(deadline) => {
        break;
      }
      res = cr.read(&mut cbuf), if !c_eof => {
        let n = res?;
        if n == 0 {
          c_eof = true;
          let _ = uw.shutdown().await;
        } else {
          deadline = Instant::now() + idle;
          tokio::time::timeout(idle, uw.write_all(&cbuf[..n]))
            .await
            .map_err(|_| std::io::Error::other("写上游超时"))??;
        }
      }
      res = ur.read(&mut ubuf), if !u_eof => {
        let n = res?;
        if n == 0 {
          u_eof = true;
          let _ = cw.shutdown().await;
        } else {
          deadline = Instant::now() + idle;
          tokio::time::timeout(idle, cw.write_all(&ubuf[..n]))
            .await
            .map_err(|_| std::io::Error::other("写客户端超时"))??;
        }
      }
    }
  }
  Ok(())
}

/// 经出口打通到 `target` 的隧道。外层错误表示出口本身连不上（应改用直连），
/// 内层错误是出口返回的失败状态。
async fn through_exit(
  r: &EgressRoute,
  target: &Target,
) -> std::io::Result<Result<(TcpStream, Vec<u8>), String>> {
  let authority = target.to_authority();
  let mut exit =
    tokio::time::timeout(EXIT_TIMEOUT, TcpStream::connect(&r.exit))
      .await
      .map_err(|_| std::io::Error::other("连接超时"))??;
  exit
    .write_all(
      format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {}\r\n\r\n",
        basic(&r.token)
      )
      .as_bytes(),
    )
    .await?;
  let head =
    tokio::time::timeout(CONNECT_TIMEOUT, read_head(&mut exit))
      .await
      .map_err(|_| std::io::Error::other("出口应答超时"))??;
  let status = head.text.lines().next().unwrap_or("").to_string();
  let code = status.split(' ').nth(1).unwrap_or("");
  Ok(match code {
    "200" => Ok((exit, head.rest)),
    "" => Err("502 Bad Gateway".into()),
    _ => Err(
      status
        .split_once(' ')
        .map_or("502 Bad Gateway".into(), |(_, s)| s.to_string()),
    ),
  })
}

async fn reply(
  client: &mut TcpStream,
  status: &str,
) -> std::io::Result<()> {
  client
    .write_all(
      format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .as_bytes(),
    )
    .await
}

struct Head {
  text: String,
  /// 请求头之后已经读到的字节（请求体或 TLS 握手）。
  rest: Vec<u8>,
}

async fn read_head(c: &mut TcpStream) -> std::io::Result<Head> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let n = c.read(&mut chunk).await?;
    if n == 0 {
      return Err(std::io::Error::other("连接提前关闭"));
    }
    buf.extend_from_slice(&chunk[..n]);
    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
      let rest = buf.split_off(i + 4);
      return Ok(Head {
        text: String::from_utf8_lossy(&buf).into_owned(),
        rest,
      });
    }
    if buf.len() > HEAD_LIMIT {
      return Err(std::io::Error::other("请求头太长"));
    }
  }
}

#[derive(Debug, PartialEq)]
struct Request<'a> {
  target: Target,
  auth: Option<&'a str>,
  /// 普通 HTTP：改写成相对路径后发给上游的请求头。CONNECT 时为 `None`。
  forward: Option<String>,
}

fn parse_authority(
  raw: &str,
  default_port: Option<u16>,
) -> Option<Target> {
  if raw.is_empty()
    || raw.bytes().any(|b| {
      b.is_ascii_control()
        || b.is_ascii_whitespace()
        || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#')
    })
  {
    return None;
  }
  if let Some(rest) = raw.strip_prefix('[') {
    let end = rest.find(']')?;
    let ip_str = &rest[..end];
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let after = &rest[end + 1..];
    let port = if after.is_empty() {
      default_port?
    } else if let Some(p) = after.strip_prefix(':') {
      parse_port(p)?
    } else {
      return None;
    };
    return Some(Target {
      host: ip.to_string(),
      port,
    });
  }
  let (host, port) = match raw.rsplit_once(':') {
    Some((h, p)) => (h, parse_port(p)?),
    None => (raw, default_port?),
  };
  if host.is_empty()
    || host.contains(':')
    || host.starts_with('.')
    || !host.bytes().all(|b| {
      b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
    })
  {
    return None;
  }
  Some(Target {
    host: host.to_string(),
    port,
  })
}

fn parse_port(raw: &str) -> Option<u16> {
  if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
    return None;
  }
  raw.parse::<u16>().ok().filter(|p| *p != 0)
}

fn parse(head: &str) -> Option<Request<'_>> {
  let mut lines = head.split("\r\n");
  let first = lines.next()?;
  let mut parts = first.split(' ');
  let (method, uri, version) =
    (parts.next()?, parts.next()?, parts.next()?);
  if parts.next().is_some()
    || method.is_empty()
    || uri.is_empty()
    || !version.starts_with("HTTP/1.")
    || uri
      .bytes()
      .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
  {
    return None;
  }
  let headers: Vec<(&str, &str)> = lines
    .filter(|l| !l.is_empty())
    .filter_map(|l| {
      l.split_once(':').map(|(k, v)| (k.trim(), v.trim()))
    })
    .collect();
  let auth = headers
    .iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
    .map(|(_, v)| *v);
  if method.eq_ignore_ascii_case("CONNECT") {
    let target = parse_authority(uri, None)?;
    return Some(Request {
      target,
      auth,
      forward: None,
    });
  }
  let rest = uri.strip_prefix("http://")?;
  let split = rest.find(['/', '?']);
  let (authority, path) = match split {
    Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], &rest[i..]),
    Some(i) => (&rest[..i], &rest[i..]),
    None => (rest, "/"),
  };
  let target = parse_authority(authority, Some(80))?;
  let path_str = if path.starts_with('/') {
    path.to_string()
  } else {
    format!("/{path}")
  };
  // 每个连接只转发一次，强制 `Connection: close`，不支持复用到别的主机。
  let mut out = format!("{method} {path_str} {version}\r\n");
  for (k, v) in &headers {
    let skip =
      ["proxy-authorization", "proxy-connection", "connection"]
        .iter()
        .any(|s| k.eq_ignore_ascii_case(s));
    if !skip {
      out.push_str(&format!("{k}: {v}\r\n"));
    }
  }
  out.push_str("Connection: close\r\n\r\n");
  Some(Request {
    target,
    auth,
    forward: Some(out),
  })
}

/// 比较口令，耗时和内容无关。
fn same(a: &str, b: &str) -> bool {
  a.len() == b.len()
    && a
      .bytes()
      .zip(b.bytes())
      .fold(0u8, |acc, (x, y)| acc | (x ^ y))
      == 0
}

#[cfg(test)]
mod tests;
