//! 出口（p8），两种监听都跑在 agent 进程里：
//!
//! - 提供出口（serve）：在内网地址的 8118 端口起 HTTP 代理，要 `Proxy-Authorization: Basic wharf:<口令>`；
//! - 本地分流（route）：在 8119 端口起 HTTP 代理，只接受本机和 docker 网段来的连接。
//!   命中规则的经出口（CONNECT 隧道）出去，其余直连；出口连不上时也直连。
//!   dockerd、构建、拉代码都指向它，改规则不用重启 dockerd。
//!
//! 两种都支持 `CONNECT host:port` 和绝对地址的普通 HTTP 请求。
//! 配置存在数据目录的 `egress.json`，agent 重启后自动恢复。

use std::{
  net::{IpAddr, SocketAddr},
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::Duration,
};

use base64::Engine;
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  sync::Semaphore,
  time::Instant,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{EgressConfig, EgressRoute},
  egress::{LOCAL_PORT, SERVE_PORT, via_exit},
};

mod target;
use target::Target;

pub fn local_url() -> String {
  format!("http://127.0.0.1:{LOCAL_PORT}")
}

const FILE: &str = "egress.json";
const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 连出口的超时：超过就当出口不通，改用直连。
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNS: usize = 128;

#[derive(Clone, Copy)]
enum Policy {
  PublicOnly,
  #[cfg(test)]
  AllowLoopbackForTest,
}

/// 正在运行的配置和停止它用的 token。
static RUNNING: Mutex<Option<(EgressConfig, CancellationToken)>> =
  Mutex::new(None);

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
  // 开机时组网可能还没起来，内网地址绑不上：每 10 秒重试，最多 10 分钟。
  let core = Arc::new(Target::core(core_url));
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
  start(cfg.clone(), Arc::new(Target::core(core_url)))?;
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
  core: Arc<Option<Target>>,
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
    let permits = Arc::new(Semaphore::new(MAX_CONNS));
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
        let Ok(permit) = permits.clone().try_acquire_owned() else {
          continue;
        };
        let mode = mode.clone();
        let stop = stop.clone();
        let core = core.clone();
        tokio::spawn(async move {
          let _permit = permit;
          tokio::select! {
            r = handle(conn, &mode, core.as_ref().as_ref(), Policy::PublicOnly) => {
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

pub(crate) fn workload_ready() -> bool {
  RUNNING.lock().is_ok_and(|state| {
    state.as_ref().is_some_and(|(cfg, cancel)| {
      cfg.route.is_some() && !cancel.is_cancelled()
    })
  })
}

/// 本地分流只接受本机和 docker 网段（172.16.0.0/12）来的连接。
pub(crate) fn local_peer(peer: SocketAddr) -> bool {
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

async fn handle(
  mut client: TcpStream,
  mode: &Mode,
  core: Option<&Target>,
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
    return client.write_all(
      b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wharf\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ).await;
  }
  if req.target.blocked(core, policy) {
    return reply(&mut client, "403 Forbidden").await;
  }
  let tunneled = match mode {
    Mode::Route(r)
      if via_exit(&req.target.host, r.all, &r.domains) =>
    {
      match through_exit(r, &req.target.authority()).await {
        Ok(Ok(t)) => Some(t),
        // 出口连上了但它连不上目标：照实告诉客户端。
        Ok(Err(status)) => return reply(&mut client, &status).await,
        Err(e) => {
          tracing::debug!(
            "出口 {} 连不上（{e}），{} 改用直连",
            r.exit,
            req.target.authority()
          );
          None
        }
      }
    }
    Mode::Route(_) | Mode::Serve { .. } => None,
  };
  let (mut upstream, early) = match tunneled {
    Some(t) => t,
    None => {
      let addrs = match req.target.resolve(core, policy).await {
        Ok(addrs) => addrs,
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
  let (to_upstream, to_client) = match req.forward {
    None => {
      let mut response =
        b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
      response.extend_from_slice(&early);
      (head.rest, response)
    }
    Some(first) => {
      let mut request = first.into_bytes();
      request.extend_from_slice(&head.rest);
      (request, early)
    }
  };
  forward(
    &mut client,
    &mut upstream,
    &to_upstream,
    &to_client,
    IDLE_TIMEOUT,
  )
  .await
}

async fn forward(
  client: impl AsyncRead + AsyncWrite + Unpin,
  upstream: impl AsyncRead + AsyncWrite + Unpin,
  to_upstream: &[u8],
  to_client: &[u8],
  idle_timeout: Duration,
) -> std::io::Result<()> {
  let (client_read, client_write) = tokio::io::split(client);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let activity = Mutex::new(Instant::now());
  let transfer = async {
    tokio::try_join!(
      copy(to_upstream.chain(client_read), upstream_write, &activity),
      copy(to_client.chain(upstream_read), client_write, &activity),
    )?;
    Ok(())
  };
  let idle = async {
    loop {
      let deadline =
        *activity.lock().unwrap_or_else(|p| p.into_inner())
          + idle_timeout;
      tokio::time::sleep_until(deadline).await;
      if activity.lock().unwrap_or_else(|p| p.into_inner()).elapsed()
        >= idle_timeout
      {
        return Ok(());
      }
    }
  };
  tokio::select! {
    result = transfer => result,
    result = idle => result,
  }
}

async fn copy(
  mut read: impl AsyncRead + Unpin,
  mut write: impl AsyncWrite + Unpin,
  activity: &Mutex<Instant>,
) -> std::io::Result<()> {
  let mut buf = [0; 8192];
  loop {
    let n = read.read(&mut buf).await?;
    if n == 0 {
      return write.shutdown().await;
    }
    *activity.lock().unwrap_or_else(|p| p.into_inner()) =
      Instant::now();
    let mut remaining = &buf[..n];
    while !remaining.is_empty() {
      let n = write.write(remaining).await?;
      if n == 0 {
        return Err(std::io::ErrorKind::WriteZero.into());
      }
      remaining = &remaining[n..];
      *activity.lock().unwrap_or_else(|p| p.into_inner()) =
        Instant::now();
    }
  }
}

/// 经出口打通到 `target` 的隧道。外层错误表示出口本身连不上（应改用直连），
/// 内层错误是出口返回的失败状态。
async fn through_exit(
  r: &EgressRoute,
  target: &str,
) -> std::io::Result<Result<(TcpStream, Vec<u8>), String>> {
  let mut exit =
    tokio::time::timeout(EXIT_TIMEOUT, TcpStream::connect(&r.exit))
      .await
      .map_err(|_| std::io::Error::other("连接超时"))??;
  exit
    .write_all(
      format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
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
    "403" => Err("403 Forbidden".into()),
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
      if i + 4 > HEAD_LIMIT {
        return Err(std::io::Error::other("请求头太长"));
      }
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

fn parse(head: &str) -> Option<Request<'_>> {
  let mut lines = head.split("\r\n");
  let first = lines.next()?;
  let mut parts = first.split(' ');
  let (method, uri, version) =
    (parts.next()?, parts.next()?, parts.next()?);
  if parts.next().is_some()
    || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    || !method.bytes().all(|b| b.is_ascii_alphabetic())
    || method.is_empty()
    || uri.bytes().any(|b| {
      b.is_ascii_control() || b.is_ascii_whitespace() || b == b'#'
    })
  {
    return None;
  }
  let mut headers = Vec::new();
  for line in lines.take_while(|l| !l.is_empty()) {
    let (key, value) = line.split_once(':')?;
    if key.is_empty()
      || !key.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
      })
      || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
    {
      return None;
    }
    headers.push((key, value.trim()));
  }
  let auth = headers
    .iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
    .map(|(_, v)| *v);
  if method.eq_ignore_ascii_case("CONNECT") {
    return Some(Request {
      target: Target::parse(uri, None)?,
      auth,
      forward: None,
    });
  }
  let rest = uri.strip_prefix("http://")?;
  let end = rest.find(['/', '?']).unwrap_or(rest.len());
  let (authority, suffix) = rest.split_at(end);
  let target = Target::parse(authority, Some(80))?;
  let path = if suffix.starts_with('/') {
    suffix.to_owned()
  } else {
    format!("/{suffix}")
  };
  // 每个连接只转发一次，强制 `Connection: close`，不支持复用到别的主机。
  let mut out = format!("{method} {path} {version}\r\n");
  for (k, v) in &headers {
    let skip = [
      "host",
      "proxy-authorization",
      "proxy-connection",
      "connection",
    ]
    .iter()
    .any(|s| k.eq_ignore_ascii_case(s));
    if !skip {
      out.push_str(&format!("{k}: {v}\r\n"));
    }
  }
  out.push_str(&format!(
    "Host: {}\r\nConnection: close\r\n\r\n",
    target.http_host()
  ));
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
mod tests {
  use super::*;

  #[test]
  fn parses_connect_and_http() {
    let c = parse("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic abc\r\n\r\n").unwrap();
    assert_eq!(c.target.authority(), "api.example.com:443");
    assert_eq!(c.auth, Some("Basic abc"));
    assert!(c.forward.is_none());
    let h = parse("GET http://deb.example.org/dists/x HTTP/1.1\r\nHost: deb.example.org\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
    assert_eq!(h.target.authority(), "deb.example.org:80");
    let f = h.forward.unwrap();
    assert!(f.starts_with("GET /dists/x HTTP/1.1\r\n"));
    assert!(!f.contains("Proxy-"));
    assert!(f.ends_with("Connection: close\r\n\r\n"));
    assert!(parse("GET /local HTTP/1.1\r\n\r\n").is_none());
  }

  #[tokio::test]
  async fn route_rejects_legacy_numeric_hosts_before_exit() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mode = Mode::Route(Arc::new(EgressRoute {
      exit: exit.local_addr().unwrap().to_string(),
      token: String::new(),
      all: true,
      domains: vec![],
    }));
    for host in ["0177.0.0.1", "2130706433", "0x7f000001", "127.1"] {
      let mut client =
        TcpStream::connect(proxy.local_addr().unwrap())
          .await
          .unwrap();
      let (incoming, _) = proxy.accept().await.unwrap();
      client
        .write_all(
          format!("CONNECT {host}:80 HTTP/1.1\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
      tokio::select! {
        result = handle(incoming, &mode, None, Policy::PublicOnly) => result.unwrap(),
        _ = exit.accept() => panic!("非法地址被转发到出口"),
        _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("代理未结束"),
      }
      assert!(
        read_head(&mut client)
          .await
          .unwrap()
          .text
          .starts_with("HTTP/1.1 403 ")
      );
    }
  }

  #[test]
  fn http_host_omits_default_port() {
    for (authority, expected) in [
      ("example.test", "example.test"),
      ("example.test:80", "example.test"),
      ("example.test:8080", "example.test:8080"),
      ("[2001:db9::1]:80", "[2001:db9::1]"),
    ] {
      let request = format!(
        "GET http://{authority}/ HTTP/1.1\r\nHost: other.test\r\n\r\n"
      );
      let forwarded = parse(&request).unwrap().forward.unwrap();
      assert!(
        forwarded.contains(&format!("\r\nHost: {expected}\r\n"))
      );
    }
  }

  #[tokio::test]
  async fn forward_drains_both_directions_under_backpressure() {
    let (a, client) = tokio::io::duplex(8);
    let (upstream, b) = tokio::io::duplex(8);
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let first = [b'a'; 32];
    let second = [b'b'; 32];
    let transfer = async {
      let ((), (), (), (), ()) = tokio::try_join!(
        forward(
          client,
          upstream,
          &first,
          &second,
          Duration::from_secs(2)
        ),
        async {
          aw.write_all(b"left").await?;
          aw.shutdown().await
        },
        async {
          bw.write_all(b"right").await?;
          bw.shutdown().await
        },
        async {
          let mut got = Vec::new();
          ar.read_to_end(&mut got).await?;
          assert_eq!(got, [&second[..], b"right"].concat());
          std::io::Result::Ok(())
        },
        async {
          let mut got = Vec::new();
          br.read_to_end(&mut got).await?;
          assert_eq!(got, [&first[..], b"left"].concat());
          std::io::Result::Ok(())
        },
      )?;
      std::io::Result::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(3), transfer)
      .await
      .unwrap()
      .unwrap();
  }

  #[tokio::test]
  async fn egress_blocks_loopback_metadata_private_mesh_and_core_url()
  {
    let core = Target::core("https://core.example.test").unwrap();
    for host in [
      "127.0.0.1:7700",
      "[::1]:7700",
      "[::ffff:127.0.0.1]:7700",
      "0.0.0.0:7700",
      "169.254.169.254:80",
      "100.100.100.200:80",
      "[fd00:ec2::254]:80",
      "10.0.0.1:80",
      "172.17.0.1:7700",
      "100.64.0.2:7700",
      "core.example.test:443",
      "localhost:7700",
    ] {
      let request = format!("CONNECT {host} HTTP/1.1\r\n\r\n");
      assert!(
        parse(&request)
          .unwrap()
          .target
          .blocked(Some(&core), Policy::PublicOnly)
      );
    }
    let private = std::net::Ipv4Addr::new(192, 168, 1, 2);
    assert!(
      Target::parse(&format!("{private}:7700"), None)
        .unwrap()
        .blocked(Some(&core), Policy::PublicOnly)
    );
    let req =
      parse("GET http://[2001:db9::1]/ HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(req.target.authority(), "[2001:db9::1]:80");
    assert!(!req.target.blocked(Some(&core), Policy::PublicOnly));
    assert!(
      parse("GET http://user@host.test/ HTTP/1.1\r\n\r\n").is_none()
    );
    assert!(
      parse("CONNECT host.test\n:80 HTTP/1.1\r\n\r\n").is_none()
    );
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let mut fixture = [0; 16];
    getrandom::fill(&mut fixture).unwrap();
    let fixture = hex::encode(fixture);
    let auth = basic(&fixture);
    let request = format!(
      "CONNECT {target} HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    let route = EgressRoute {
      exit: target.to_string(),
      token: fixture.clone(),
      all: true,
      domains: Vec::new(),
    };
    for mode in
      [Mode::Serve { expected: auth }, Mode::Route(Arc::new(route))]
    {
      let mut client =
        TcpStream::connect(proxy.local_addr().unwrap())
          .await
          .unwrap();
      client.write_all(request.as_bytes()).await.unwrap();
      let (conn, _) = proxy.accept().await.unwrap();
      tokio::time::timeout(
        Duration::from_secs(2),
        handle(conn, &mode, Some(&core), Policy::PublicOnly),
      )
      .await
      .unwrap()
      .unwrap();
      assert!(
        read_head(&mut client)
          .await
          .unwrap()
          .text
          .starts_with("HTTP/1.1 403 ")
      );
    }
    let exit_addr = upstream.local_addr().unwrap();
    let exit = async {
      let (mut conn, _) = upstream.accept().await.unwrap();
      assert!(
        read_head(&mut conn)
          .await
          .unwrap()
          .text
          .starts_with("CONNECT a.example.test:443 ")
      );
      reply(&mut conn, "403 Forbidden").await.unwrap();
    };
    let client = async {
      let mut client =
        TcpStream::connect(proxy.local_addr().unwrap())
          .await
          .unwrap();
      client
        .write_all(b"CONNECT a.example.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
      read_head(&mut client).await.unwrap()
    };
    let route = Mode::Route(Arc::new(EgressRoute {
      exit: exit_addr.to_string(),
      token: fixture,
      all: true,
      domains: vec![],
    }));
    let server = async {
      let (conn, _) = proxy.accept().await.unwrap();
      handle(conn, &route, Some(&core), Policy::PublicOnly)
        .await
        .unwrap();
    };
    let (head, (), ()) =
      tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(client, exit, server)
      })
      .await
      .unwrap();
    assert!(head.text.starts_with("HTTP/1.1 403 "));
  }

  #[tokio::test]
  async fn tunnels_with_token_only() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    tokio::spawn(async move {
      while let Ok((mut c, _)) = upstream.accept().await {
        let _ = c.write_all(b"hi").await;
      }
    });
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let mode = Mode::Serve {
      expected: basic("t0ken"),
    };
    tokio::spawn(async move {
      while let Ok((c, _)) = proxy.accept().await {
        let m = mode.clone();
        tokio::spawn(async move {
          handle(c, &m, None, Policy::AllowLoopbackForTest).await
        });
      }
    });
    let ask = |auth: &'static str| async move {
      let mut c = TcpStream::connect(addr).await.unwrap();
      let req = format!(
        "CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
      );
      c.write_all(req.as_bytes()).await.unwrap();
      let mut out = String::new();
      let _ = tokio::time::timeout(
        Duration::from_secs(2),
        c.read_to_string(&mut out),
      )
      .await;
      out
    };
    // base64("wharf:t0ken")
    let ok = ask("d2hhcmY6dDBrZW4=").await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(ok.ends_with("hi"), "{ok}");
    let bad = ask("d2hhcmY6d3Jvbmc=").await;
    assert!(bad.starts_with("HTTP/1.1 407"), "{bad}");
  }

  #[tokio::test]
  async fn routes_through_exit() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap().to_string();
    tokio::spawn(async move {
      while let Ok((mut c, _)) = upstream.accept().await {
        let _ = c.write_all(b"hi").await;
      }
    });
    let exit = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit.local_addr().unwrap().to_string();
    let mode = Mode::Serve {
      expected: basic("t0ken"),
    };
    tokio::spawn(async move {
      while let Ok((c, _)) = exit.accept().await {
        let m = mode.clone();
        tokio::spawn(async move {
          handle(c, &m, None, Policy::AllowLoopbackForTest).await
        });
      }
    });
    let route = |token: &str, exit: &str| EgressRoute {
      exit: exit.into(),
      token: token.into(),
      all: true,
      domains: vec![],
    };
    let (mut s, _) =
      through_exit(&route("t0ken", &exit_addr), &target)
        .await
        .unwrap()
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert_eq!(out, "hi");
    let denied = through_exit(&route("bad", &exit_addr), &target)
      .await
      .unwrap();
    assert!(denied.unwrap_err().starts_with("407"));
    // 出口不在：外层错误，调用方改直连。
    assert!(
      through_exit(&route("t0ken", "127.0.0.1:1"), &target)
        .await
        .is_err()
    );
    assert_eq!(Target::parse("[::1]:443", None).unwrap().host, "::1");
    assert_eq!(
      Target::parse("github.com:443", None).unwrap().host,
      "github.com"
    );
    assert!(local_peer("172.17.0.2:1".parse().unwrap()));
    assert!(!local_peer("100.64.0.2:1".parse().unwrap()));
  }
}
