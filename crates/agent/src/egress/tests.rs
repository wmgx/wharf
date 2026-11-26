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
async fn egress_blocks_loopback_metadata_private_mesh_and_core_url() {
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
  assert!(parse("CONNECT host.test\n:80 HTTP/1.1\r\n\r\n").is_none());
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
    let mut client = TcpStream::connect(proxy.local_addr().unwrap())
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
    let mut client = TcpStream::connect(proxy.local_addr().unwrap())
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
  assert_eq!(Target::parse("[::1]:443", None).unwrap().host, "::1");
  assert_eq!(
    Target::parse("github.com:443", None).unwrap().host,
    "github.com"
  );
  assert!(local_peer("172.17.0.2:1".parse().unwrap()));
  assert!(!local_peer("100.64.0.2:1".parse().unwrap()));
}
