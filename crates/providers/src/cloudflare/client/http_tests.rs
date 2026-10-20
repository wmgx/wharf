//! Real loopback HTTP fixtures exercising the production reqwest code path.
//! No Cloudflare endpoints, accounts, or credentials are contacted.
use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use reqwest::Client;
use serde_json::{Value, json};

use super::CloudflareClient;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
  task::JoinHandle,
};

#[allow(dead_code)]
struct Request {
  method: String,
  path: String,
  body: Value,
}
struct Response {
  status: u16,
  body: Value,
  delay: Duration,
}
impl Response {
  fn ok(result: Value) -> Self {
    Self {
      status: 200,
      body: json!({"success":true,"result":result}),
      delay: Duration::ZERO,
    }
  }
  fn error(status: u16) -> Self {
    Self {
      status,
      body: json!({"success":false,"errors":[{"message":"fixture-secret must never leak"}]}),
      delay: Duration::ZERO,
    }
  }
}
struct Fixture {
  base: String,
  task: JoinHandle<()>,
}
impl Drop for Fixture {
  fn drop(&mut self) {
    self.task.abort();
  }
}
impl Fixture {
  async fn start(
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
  ) -> Self {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
      while let Ok((mut stream, _)) = listener.accept().await {
        let handler = handler.clone();
        tokio::spawn(async move {
          let mut bytes = Vec::new();
          let mut buf = [0u8; 4096];
          let header_end = loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
              return;
            }
            bytes.extend_from_slice(&buf[..n]);
            if let Some(pos) =
              bytes.windows(4).position(|s| s == b"\r\n\r\n")
            {
              break pos + 4;
            }
            assert!(
              bytes.len() < 65536,
              "unexpected fixture request size"
            );
          };
          let headers = String::from_utf8_lossy(&bytes[..header_end])
            .into_owned();
          let length = headers
            .lines()
            .find_map(|line| {
              let (name, value) = line.split_once(':')?;
              name
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
          while bytes.len() < header_end + length {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
              return;
            }
            bytes.extend_from_slice(&buf[..n]);
          }
          let mut first =
            headers.lines().next().unwrap().split_whitespace();
          let request = Request {
            method: first.next().unwrap().into(),
            path: first.next().unwrap().into(),
            body: if length == 0 {
              Value::Null
            } else {
              serde_json::from_slice(
                &bytes[header_end..header_end + length],
              )
              .unwrap()
            },
          };
          let response = handler(request);
          if !response.delay.is_zero() {
            tokio::time::sleep(response.delay).await;
          }
          let body = response.body.to_string();
          let head = format!(
            "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n",
            response.status,
            body.len()
          );
          let _ = stream.write_all(head.as_bytes()).await;
          let _ = stream.write_all(body.as_bytes()).await;
        });
      }
    });
    Self { base, task }
  }
  fn client(&self, timeout: Duration) -> CloudflareClient {
    CloudflareClient {
      client: Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap(),
      token: "fixture-secret".into(),
      base_url: Some(self.base.clone()),
    }
  }
}

#[tokio::test]
async fn dns_http_paginates_and_filters_exact_hostname() {
  let paths = Arc::new(Mutex::new(Vec::new()));
  let seen = paths.clone();
  let fixture = Fixture::start(move |request| {
    assert_eq!(request.method, "GET");
    seen.lock().unwrap().push(request.path.clone());
    let mut response = if request.path.contains("page=1&") {
      Response::ok(json!(
        (0..100)
          .map(|i| json!({
            "id": format!("record{i}"),
            "name": "app.example.com",
            "type": "A",
            "content": "192.0.2.1"
          }))
          .collect::<Vec<_>>()
      ))
    } else {
      Response::ok(json!([
        { "id": "last", "name": "app.example.com", "type": "A" },
        { "id": "foreign", "name": "other.example.com", "type": "A" }
      ]))
    };
    response.body["result_info"] = json!({ "total_pages": 2 });
    response
  })
  .await;
  let records = fixture
    .client(Duration::from_secs(2))
    .list_dns("zone", "app.example.com")
    .await
    .unwrap();
  assert_eq!(records.len(), 101);
  assert!(records.iter().all(|r| r["name"] == "app.example.com"));
  let paths = paths.lock().unwrap();
  assert_eq!(paths.len(), 2);
  assert!(paths[1].contains("page=2&"));
}

#[tokio::test]
async fn dns_http_retries_get_and_sanitizes_authorization_errors() {
  let count = Arc::new(Mutex::new(0u32));
  let seen = count.clone();
  let fixture = Fixture::start(move |request| {
    if request.path.contains("denied.example.com") {
      return Response::error(403);
    }
    let mut count = seen.lock().unwrap();
    *count += 1;
    if *count == 1 {
      Response::error(429)
    } else {
      Response::ok(json!([]))
    }
  })
  .await;
  let client = fixture.client(Duration::from_secs(2));
  assert!(
    client
      .list_dns("zone", "ok.example.com")
      .await
      .unwrap()
      .is_empty()
  );
  assert_eq!(*count.lock().unwrap(), 2);
  let error = client
    .list_dns("zone", "denied.example.com")
    .await
    .unwrap_err();
  assert_eq!(error.code, "AuthFailed");
  assert!(!error.retryable);
  let rendered = format!("{error} {error:?}");
  assert!(!rendered.contains("fixture-secret"));
}

#[tokio::test]
async fn discover_lists_zones() {
  let fixture = Fixture::start(|request| {
    assert_eq!(request.method, "GET");
    assert!(request.path.starts_with("/zones"));
    Response::ok(json!([
      { "id": "z1", "name": "Example.com" },
      { "id": "z2", "name": "example.com" }
    ]))
  })
  .await;
  let found = super::super::discover_with(
    &fixture.client(Duration::from_secs(2)),
  )
  .await
  .unwrap();
  assert_eq!(found.zones, vec!["example.com"]);
  assert!(found.warnings.is_empty());
}
