use super::*;

#[test]
fn parses_connect_and_http() {
  let c = parse("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic abc\r\n\r\n").unwrap();
  assert_eq!(c.target.to_authority(), "api.example.com:443");
  assert_eq!(c.auth, Some("Basic abc"));
  assert!(c.forward.is_none());
  let h = parse("GET http://deb.example.org/dists/x HTTP/1.1\r\nHost: deb.example.org\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
  assert_eq!(h.target.to_authority(), "deb.example.org:80");
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
  let target = parse_authority(
    &upstream.local_addr().unwrap().to_string(),
    None,
  )
  .unwrap();
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
  let (mut s, _) = through_exit(&route("t0ken", &exit_addr), &target)
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
  assert!(local_peer("172.17.0.2:1".parse().unwrap()));
  assert!(!local_peer("100.64.0.2:1".parse().unwrap()));
}

#[tokio::test]
async fn egress_blocks_loopback_metadata_private_mesh_and_core_url() {
  let core =
    parse_core_url("https://core.example.test").map(Arc::new);

  let serve_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let serve_addr = serve_l.local_addr().unwrap();
  let serve_mode = Mode::Serve {
    expected: basic("t0ken"),
  };
  let core_s = core.clone();
  tokio::spawn(async move {
    while let Ok((c, _)) = serve_l.accept().await {
      let m = serve_mode.clone();
      let core = core_s.clone();
      tokio::spawn(async move {
        handle(c, &m, core.as_deref(), Policy::PublicOnly).await
      });
    }
  });

  let route_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let route_addr = route_l.local_addr().unwrap();
  let route_mode = Mode::Route(Arc::new(EgressRoute {
    exit: serve_addr.to_string(),
    token: "t0ken".into(),
    all: true,
    domains: vec![],
  }));
  let core_r = core.clone();
  tokio::spawn(async move {
    while let Ok((c, _)) = route_l.accept().await {
      let m = route_mode.clone();
      let core = core_r.clone();
      tokio::spawn(async move {
        handle(c, &m, core.as_deref(), Policy::PublicOnly).await
      });
    }
  });

  let send_raw = |addr: SocketAddr, raw: String| async move {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(raw.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(
      Duration::from_secs(2),
      c.read_to_string(&mut out),
    )
    .await;
    out
  };

  let blocked_requests = [
    // ① 回环与未指定地址
    "CONNECT 127.0.0.1:7700 HTTP/1.1\r\n\r\n",
    "CONNECT [::1]:7700 HTTP/1.1\r\n\r\n",
    "CONNECT [::ffff:127.0.0.1]:7700 HTTP/1.1\r\n\r\n",
    "CONNECT 0.0.0.0:7700 HTTP/1.1\r\n\r\n",
    // ② 云元数据
    "GET http://169.254.169.254/latest/meta-data HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
    "GET http://100.100.100.200/latest/meta-data HTTP/1.1\r\nHost: 100.100.100.200\r\n\r\n",
    "CONNECT [fd00:ec2::254]:80 HTTP/1.1\r\n\r\n",
    // ③ 私网与 CGNAT 组网段
    "CONNECT 10.0.0.1:80 HTTP/1.1\r\n\r\n",
    "CONNECT 172.17.0.1:7700 HTTP/1.1\r\n\r\n",
    "CONNECT 100.64.0.2:7700 HTTP/1.1\r\n\r\n",
    // ④ 控制面入口与 localhost
    "CONNECT core.example.test:443 HTTP/1.1\r\n\r\n",
    "CONNECT localhost:7700 HTTP/1.1\r\n\r\n",
  ];
  for req in blocked_requests {
    let resp = send_raw(route_addr, req.to_string()).await;
    assert!(
      resp.starts_with("HTTP/1.1 403"),
      "route 应拦截 {req:?}，实得 {resp:?}"
    );
    let authed = req.replacen(
      "\r\n\r\n",
      &format!("\r\nProxy-Authorization: {}\r\n\r\n", basic("t0ken")),
      1,
    );
    let resp = send_raw(serve_addr, authed).await;
    assert!(
      resp.starts_with("HTTP/1.1 403"),
      "serve 应拦截 {req:?}，实得 {resp:?}"
    );
  }

  // ⑤ 无端口 IPv6 字面量正确补全 :80 且判为公网合法。
  let v6 = parse("GET http://[2001:4860:4860::8888]/ HTTP/1.1\r\nHost: [2001:4860:4860::8888]\r\n\r\n").unwrap();
  assert_eq!(v6.target.host, "2001:4860:4860::8888");
  assert_eq!(v6.target.port, 80);
  assert!(is_allowed_ip(
    v6.target.host.parse().unwrap(),
    v6.target.port,
    core.as_deref(),
    Policy::PublicOnly
  ));

  // ⑥ 含 user@ 或注入的非法 target 返回 400 Bad Request。
  for bad in [
    "CONNECT user@127.0.0.1:7700 HTTP/1.1\r\n\r\n",
    "CONNECT example.com:443\tHTTP/1.1\r\n\r\n",
    "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
  ] {
    let resp = send_raw(route_addr, bad.to_string()).await;
    assert!(
      resp.starts_with("HTTP/1.1 400"),
      "非法请求应回 400：{bad:?}，实得 {resp:?}"
    );
  }
}
