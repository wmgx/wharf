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
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{EgressConfig, EgressRoute},
  egress::{LOCAL_PORT, SERVE_PORT, via_exit},
};

const FILE: &str = "egress.json";
const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 连出口的超时：超过就当出口不通，改用直连。
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);

/// 正在运行的配置和停止它用的 token。
static RUNNING: Mutex<Option<(EgressConfig, CancellationToken)>> =
  Mutex::new(None);

/// agent 启动时按上次保存的配置恢复。
pub fn restore(data_dir: &Path) {
  let Ok(text) = std::fs::read_to_string(data_dir.join(FILE)) else {
    return;
  };
  match serde_json::from_str::<EgressConfig>(&text) {
    Ok(cfg) => {
      if let Err(e) = start(cfg) {
        tracing::warn!("恢复出口失败：{}", e.message);
      }
    }
    Err(e) => tracing::warn!("出口配置读不了：{e}"),
  }
}

/// 设置出口。配置没变时什么都不做。
pub async fn apply(
  data_dir: PathBuf,
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
  start(cfg.clone())?;
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

fn start(cfg: EgressConfig) -> Result<(), ApiError> {
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
        let mode = mode.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
          tokio::select! {
            r = handle(conn, &mode) => {
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

async fn handle(
  mut client: TcpStream,
  mode: &Mode,
) -> std::io::Result<()> {
  let head =
    tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client))
      .await
      .map_err(|_| std::io::Error::other("读请求头超时"))??;
  let Some(req) = parse(&head.text) else {
    return reply(&mut client, "400 Bad Request").await;
  };
  let tunneled = match mode {
    Mode::Serve { expected } => {
      if !same(req.auth.unwrap_or_default(), expected) {
        return client
          .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wharf\"\r\nContent-Length: 0\r\n\r\n",
          )
          .await;
      }
      None
    }
    Mode::Route(r)
      if via_exit(host_of(&req.target), r.all, &r.domains) =>
    {
      match through_exit(r, &req.target).await {
        Ok(Ok(t)) => Some(t),
        // 出口连上了但它连不上目标：照实告诉客户端。
        Ok(Err(status)) => return reply(&mut client, &status).await,
        Err(e) => {
          tracing::debug!(
            "出口 {} 连不上（{e}），{} 改用直连",
            r.exit,
            req.target
          );
          None
        }
      }
    }
    Mode::Route(_) => None,
  };
  let (mut upstream, early) = match tunneled {
    Some(t) => t,
    None => match tokio::time::timeout(
      CONNECT_TIMEOUT,
      TcpStream::connect(&req.target),
    )
    .await
    {
      Ok(Ok(s)) => (s, Vec::new()),
      _ => return reply(&mut client, "502 Bad Gateway").await,
    },
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
  tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
  Ok(())
}

/// `host:port` 或 `[v6]:port` 里的主机部分。
fn host_of(target: &str) -> &str {
  match target.rsplit_once(':') {
    Some((h, _)) => h.trim_matches(['[', ']']),
    None => target,
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
  /// `host:port`
  target: String,
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
    if !uri.contains(':') {
      return None;
    }
    return Some(Request {
      target: uri.to_string(),
      auth,
      forward: None,
    });
  }
  let rest = uri.strip_prefix("http://")?;
  let (host, path) = match rest.find('/') {
    Some(i) => (&rest[..i], &rest[i..]),
    None => (rest, "/"),
  };
  if host.is_empty() {
    return None;
  }
  let target = if host.contains(':') {
    host.to_string()
  } else {
    format!("{host}:80")
  };
  // 每个连接只转发一次，强制 `Connection: close`，不支持复用到别的主机。
  let mut out = format!("{method} {path} {version}\r\n");
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
mod tests {
  use super::*;

  #[test]
  fn parses_connect_and_http() {
    let c = parse("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic abc\r\n\r\n").unwrap();
    assert_eq!(c.target, "api.example.com:443");
    assert_eq!(c.auth, Some("Basic abc"));
    assert!(c.forward.is_none());
    let h = parse("GET http://deb.example.org/dists/x HTTP/1.1\r\nHost: deb.example.org\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
    assert_eq!(h.target, "deb.example.org:80");
    let f = h.forward.unwrap();
    assert!(f.starts_with("GET /dists/x HTTP/1.1\r\n"));
    assert!(!f.contains("Proxy-"));
    assert!(f.ends_with("Connection: close\r\n\r\n"));
    assert!(parse("GET /local HTTP/1.1\r\n\r\n").is_none());
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
        tokio::spawn(async move { handle(c, &m).await });
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
        tokio::spawn(async move { handle(c, &m).await });
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
    assert_eq!(host_of("[::1]:443"), "::1");
    assert_eq!(host_of("github.com:443"), "github.com");
    assert!(local_peer("172.17.0.2:1".parse().unwrap()));
    assert!(!local_peer("100.64.0.2:1".parse().unwrap()));
  }
}
