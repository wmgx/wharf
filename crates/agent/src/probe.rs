//! 连通性探测：每个 agent 在探测端口回一行 `wharf <服务器名>`；
//! 控制面让网关所在机器的 agent 去连服务所在机器，判断网关能不能直连服务。

use std::time::Duration;

use tokio::{
  io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
  net::{TcpListener, TcpStream},
};
use wharf_api_types::agent::ProbeTarget;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn banner(server: &str) -> String {
  format!("wharf {server}\n")
}

/// 在探测端口上回答。端口被占用时只记日志，不影响 agent 其他功能。
pub async fn serve(server: String, port: u16) {
  let listener = match TcpListener::bind(("0.0.0.0", port)).await {
    Ok(l) => l,
    Err(e) => {
      tracing::warn!(
        "探测端口 {port} 监听失败，别的机器会判断为连不到这台：{e}"
      );
      return;
    }
  };
  let line = banner(&server);
  loop {
    let Ok((mut stream, _)) = listener.accept().await else {
      continue;
    };
    let line = line.clone();
    tokio::spawn(async move {
      let _ = tokio::time::timeout(
        CONNECT_TIMEOUT,
        stream.write_all(line.as_bytes()),
      )
      .await;
    });
  }
}

/// 并行探测，结果和 `targets` 一一对应。
pub async fn check(targets: Vec<ProbeTarget>) -> Vec<bool> {
  futures_util::future::join_all(targets.iter().map(one)).await
}

async fn one(target: &ProbeTarget) -> bool {
  let attempt = async {
    let stream = TcpStream::connect(&target.addr).await.ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await.ok()?;
    Some(line == banner(&target.server))
  };
  tokio::time::timeout(CONNECT_TIMEOUT, attempt)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn checks_server_name() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
      loop {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(banner("home1").as_bytes()).await.unwrap();
      }
    });
    let target = |server: &str| ProbeTarget {
      server: server.into(),
      addr: addr.clone(),
    };
    let unused = ProbeTarget {
      server: "home1".into(),
      addr: "127.0.0.1:1".into(),
    };
    assert_eq!(
      check(vec![target("home1"), target("edge1"), unused]).await,
      vec![true, false, false]
    );
  }
}
