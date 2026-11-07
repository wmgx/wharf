//! 出口：在内网地址上跑一个 HTTP 代理，给别的机器访问海外地址用。
//!
//! - 支持 `CONNECT host:port`（https）和绝对地址的普通 HTTP 请求（`GET http://…`）；
//! - 要 `Proxy-Authorization: Basic wharf:<口令>`，不对一律 407；
//! - 配置存在数据目录的 `egress.json`，agent 重启后自动恢复。

use std::{
  path::{Path, PathBuf},
  sync::Mutex,
  time::Duration,
};

use base64::Engine;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{ApiError, agent::EgressConfig};

const FILE: &str = "egress.json";
const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// 正在运行的代理：配置和停止它用的 token。
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
        tracing::warn!("恢复出口代理失败：{}", e.message);
      }
    }
    Err(e) => tracing::warn!("出口配置读不了：{e}"),
  }
}

/// 设置出口：`None` 关闭。配置没变时什么都不做。
pub async fn apply(
  data_dir: PathBuf,
  cfg: Option<EgressConfig>,
) -> Result<(), ApiError> {
  let same = RUNNING
    .lock()
    .map(|r| r.as_ref().map(|(c, _)| c) == cfg.as_ref())
    .unwrap_or(false);
  if same && cfg.is_some() {
    return Ok(());
  }
  stop();
  let path = data_dir.join(FILE);
  match cfg {
    Some(cfg) => {
      // 先确认能监听，再保存配置。
      let probe =
        std::net::TcpListener::bind((cfg.bind.as_str(), cfg.port));
      drop(probe.map_err(|e| {
        ApiError::invalid(format!(
          "出口不能监听 {}:{}：{e}",
          cfg.bind, cfg.port
        ))
      })?);
      start(cfg.clone())?;
      write_private(
        &path,
        &serde_json::to_string(&cfg).unwrap_or_default(),
      )
    }
    None => {
      let _ = std::fs::remove_file(&path);
      Ok(())
    }
  }
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

fn start(cfg: EgressConfig) -> Result<(), ApiError> {
  let cancel = CancellationToken::new();
  let std_listener =
    std::net::TcpListener::bind((cfg.bind.as_str(), cfg.port))
      .map_err(|e| {
        ApiError::invalid(format!(
          "出口不能监听 {}:{}：{e}",
          cfg.bind, cfg.port
        ))
      })?;
  std_listener
    .set_nonblocking(true)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  let listener = TcpListener::from_std(std_listener)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  let expected = format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD
      .encode(format!("wharf:{}", cfg.token))
  );
  tracing::info!("出口代理监听 {}:{}", cfg.bind, cfg.port);
  let stop = cancel.clone();
  tokio::spawn(async move {
    loop {
      let accepted = tokio::select! {
        a = listener.accept() => a,
        _ = stop.cancelled() => break,
      };
      let Ok((conn, _)) = accepted else { continue };
      let expected = expected.clone();
      let stop = stop.clone();
      tokio::spawn(async move {
        tokio::select! {
          r = handle(conn, &expected) => {
            if let Err(e) = r {
              tracing::debug!("出口连接结束：{e}");
            }
          }
          _ = stop.cancelled() => {}
        }
      });
    }
  });
  if let Ok(mut r) = RUNNING.lock() {
    *r = Some((cfg, cancel));
  }
  Ok(())
}

async fn handle(
  mut client: TcpStream,
  expected: &str,
) -> std::io::Result<()> {
  let head =
    tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client))
      .await
      .map_err(|_| std::io::Error::other("读请求头超时"))??;
  let Some(req) = parse(&head.text) else {
    return reply(&mut client, "400 Bad Request").await;
  };
  if !same(req.auth.unwrap_or_default(), expected) {
    return client
      .write_all(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wharf\"\r\nContent-Length: 0\r\n\r\n",
      )
      .await;
  }
  let upstream = match tokio::time::timeout(
    CONNECT_TIMEOUT,
    TcpStream::connect(&req.target),
  )
  .await
  {
    Ok(Ok(s)) => s,
    _ => return reply(&mut client, "502 Bad Gateway").await,
  };
  let mut upstream = upstream;
  match req.forward {
    None => {
      client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
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
    let expected = format!(
      "Basic {}",
      base64::engine::general_purpose::STANDARD.encode("wharf:t0ken")
    );
    tokio::spawn(async move {
      while let Ok((c, _)) = proxy.accept().await {
        let e = expected.clone();
        tokio::spawn(async move { handle(c, &e).await });
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
}
