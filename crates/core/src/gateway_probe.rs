use std::{
  net::{IpAddr, SocketAddr},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, GatewayProbeJob, GatewayProbeResult, ProbeTarget,
    ProjectState,
  },
  spec::{GatewayKind, GatewayTls, RouteSpec},
};

use crate::{
  render::Net, snapshot::Snapshot, state::AppState,
  world::gateway_project,
};

fn entry(
  ok: bool,
  stage: &str,
  detail: impl Into<String>,
) -> GatewayProbeResult {
  GatewayProbeResult {
    ok,
    stage: stage.into(),
    status: None,
    cert_pending: false,
    detail: detail.into(),
  }
}

pub(crate) async fn check_entry(
  state: &AppState,
  snap: &Snapshot,
  net: &Net,
  target: (&str, &RouteSpec, &str),
  project: Option<&ProjectState>,
  cancel: &CancellationToken,
) -> GatewayProbeResult {
  let (host, route, gateway) = target;
  let Some(row) = snap.world.gateways.get(gateway) else {
    return entry(false, "gateway_unreachable", "目标网关已不存在");
  };
  let gw = &row.spec;
  if !state.hub.is_online(&gw.server) {
    return entry(false, "server_offline", "网关所在服务器离线");
  }
  if !project.is_some_and(ProjectState::all_running) {
    return entry(false, "gateway_stopped", "网关容器未运行");
  }
  let upstream = if route.redirect.is_some() {
    None
  } else {
    match snap.world.route_upstream(net, gw, host, route) {
      Ok(upstream) => Some(upstream),
      Err(_) => {
        return entry(
          false,
          "upstream_unreachable",
          "无法解析网关上游",
        );
      }
    }
  };
  if gw.kind == GatewayKind::Caddy
    && state.hub.supports_gateway_probe(&gw.server)
  {
    let job = GatewayProbeJob {
      hostname: host.into(),
      path: path(snap, net, host, route).into(),
      tls: gw.tls != GatewayTls::Off,
      http_port: gw.http_port.unwrap_or(80),
      https_port: gw.https_port.unwrap_or(443),
      upstream,
      upstream_only: route.cf_origin_only,
      timeout_secs: 5,
    };
    return state
      .hub
      .call(
        &gw.server,
        AgentOp::GatewayProbe(job),
        Duration::from_secs(7),
        None,
        cancel,
      )
      .await
      .unwrap_or_else(|_| {
        entry(false, "gateway_unreachable", "网关本机探测未完成")
      });
  }
  if let Some(addr) = upstream {
    let result: Result<Vec<bool>, ApiError> = state
      .hub
      .call(
        &gw.server,
        AgentOp::Probe {
          targets: vec![ProbeTarget {
            server: gateway.into(),
            addr,
            plain: true,
          }],
        },
        Duration::from_secs(6),
        None,
        cancel,
      )
      .await;
    if !matches!(result.as_deref(), Ok([true])) {
      return entry(false, "upstream_unreachable", "网关连不上上游");
    }
  }
  entry(true, "upstream_only", "网关与上游可达")
}

pub(crate) async fn current_project(
  state: &AppState,
  server: &str,
  gateway: &str,
  cancel: &CancellationToken,
) -> Result<Option<ProjectState>, ApiError> {
  let project = gateway_project(gateway);
  let projects: Vec<ProjectState> = state
    .hub
    .call(
      server,
      AgentOp::ProjectStatus {
        projects: vec![project.clone()],
        include_links: false,
      },
      Duration::from_secs(6),
      None,
      cancel,
    )
    .await?;
  Ok(projects.into_iter().find(|p| p.project == project))
}

fn path(
  snap: &Snapshot,
  net: &Net,
  host: &str,
  route: &RouteSpec,
) -> &'static str {
  if route.core_mesh_only
    || crate::gate::is_core_host(&snap.world, net, host)
  {
    "/healthz"
  } else {
    "/"
  }
}

fn conflict(host: &str, gateway: &str, detail: &str) -> ApiError {
  ApiError::new(
    ErrorCode::Conflict,
    format!("改 DNS 前预验失败：网关 {gateway} {detail}，已中止写入 {host} 的 DNS"),
  )
  .with_hint("检查目标网关、上游和安全组，或加 --no-verify-before-dns 跳过预验")
  .suggest(format!("wharf doctor {host}"))
  .suggest(format!("wharf gateway logs {gateway}"))
}

pub(crate) async fn verify_before_dns(
  state: &AppState,
  snap: &Snapshot,
  net: &Net,
  target: (&str, &RouteSpec, &str),
  cancel: &CancellationToken,
) -> Result<GatewayProbeResult, ApiError> {
  crate::apply::cancellable(
    cancel,
    verify(state, snap, net, target, cancel),
  )
  .await
}

async fn verify(
  state: &AppState,
  snap: &Snapshot,
  net: &Net,
  target: (&str, &RouteSpec, &str),
  cancel: &CancellationToken,
) -> Result<GatewayProbeResult, ApiError> {
  let (host, route, gateway) = target;
  let gw = &snap
    .world
    .gateways
    .get(gateway)
    .ok_or_else(|| conflict(host, gateway, "已不存在"))?
    .spec;
  let project = current_project(state, &gw.server, gateway, cancel)
    .await
    .map_err(|_| conflict(host, gateway, "无法读取容器状态"))?;
  let local =
    check_entry(state, snap, net, target, project.as_ref(), cancel)
      .await;
  if !local.ok {
    return Err(conflict(host, gateway, &local.detail));
  }
  if gw.kind != GatewayKind::Caddy || route.cf_origin_only {
    return Ok(local);
  }
  let ip =
    if net.core_server.as_deref() == Some(gw.server.as_str()) {
      Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    } else {
      let address = if route.internal {
        net.private.get(&gw.server).map(|address| &address.ip)
      } else {
        net.public_ip.get(&gw.server)
      };
      address.and_then(|s| s.parse().ok())
    }
    .ok_or_else(|| conflict(host, gateway, "没有可直连的 IP"))?;
  let tls = gw.tls != GatewayTls::Off;
  let http_port = gw.http_port.unwrap_or(80);
  let port = if tls {
    gw.https_port.unwrap_or(443)
  } else {
    http_port
  };
  let client = |port| {
    reqwest::Client::builder()
      .no_proxy()
      .redirect(reqwest::redirect::Policy::none())
      .user_agent("wharf-verify")
      .retry(reqwest::retry::never())
      .tls_danger_accept_invalid_certs(true)
      .timeout(Duration::from_secs(8))
      .resolve(host, SocketAddr::new(ip, port))
      .build()
      .map_err(|_| conflict(host, gateway, "无法创建直连客户端"))
  };
  let direct = client(port)?;
  let url = |tls, port| {
    let scheme = if tls { "https" } else { "http" };
    format!(
      "{scheme}://{host}:{port}{}",
      path(snap, net, host, route)
    )
  };
  let mut detail = String::new();
  for attempt in 0..2 {
    if attempt != 0 {
      tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let (response, cert_pending) =
      tokio::time::timeout(Duration::from_secs(8), async {
        let response = direct
          .get(url(tls, port))
          .header("Host", host)
          .send()
          .await;
        Ok::<_, ApiError>(match response {
          Err(error)
            if gw.tls == GatewayTls::Auto && tls_failed(&error) =>
          {
            (
              client(http_port)?
                .get(url(false, http_port))
                .header("Host", host)
                .send()
                .await
                .ok(),
              true,
            )
          }
          response => (response.ok(), false),
        })
      })
      .await
      .unwrap_or(Ok((None, false)))?;
    match response {
      Some(r) if !matches!(r.status().as_u16(), 502 | 504) => {
        let code = r.status().as_u16();
        let mut result = entry(
          true,
          "direct",
          format!("直连 {ip} 返回 HTTP {code}，通过"),
        );
        result.status = Some(code);
        result.cert_pending = cert_pending || local.cert_pending;
        return Ok(result);
      }
      Some(r) => {
        detail = format!(
          "直连 {ip}:{port} 返回 HTTP {}",
          r.status().as_u16()
        )
      }
      None => {
        detail = format!("本机正常，但控制面无法直连 {ip}:{port}")
      }
    }
  }
  let mut error = conflict(host, gateway, &detail);
  if snap.world.servers.get(&gw.server).is_some_and(|row| {
    row.settings.region
      == Some(wharf_api_types::spec::Region::Overseas)
  }) && detail.contains("无法直连")
  {
    error = error.with_hint(format!(
      "检查安全组和防火墙是否放行 {port}；若仅是控制面国际线路波动，可加 --no-verify-before-dns 跳过预验"
    ));
  }
  Err(error)
}

fn tls_failed(e: &reqwest::Error) -> bool {
  let mut cause = std::error::Error::source(e);
  while let Some(error) = cause {
    let text = error.to_string().to_ascii_lowercase();
    if ["tls", "handshake", "certificate", "ssl", "eof"]
      .iter()
      .any(|s| text.contains(s))
    {
      return true;
    }
    cause = error.source();
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn origin_only_skips_http_and_unhealthy_gateway_blocks_dns() {
    let state = crate::rules::tests::test_state();
    let mut snap = Snapshot::default();
    let gw: wharf_api_types::spec::GatewaySpec =
      serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
        .unwrap();
    snap.world.gateways.insert(
      "gw2".into(),
      crate::world::GatewayRow {
        spec: gw,
        version: 1,
      },
    );
    let host = "check.example.test";
    let mut route: RouteSpec = serde_json::from_value(serde_json::json!({
      "hostname":host, "upstream":"100.64.0.1:8080", "core_mesh_only":true
    })).unwrap();
    state.hub.mock_agent("s1", false, |op| Ok(match op {
      AgentOp::ProjectStatus { .. } => serde_json::json!([{
        "project":"wharf-gw-gw2","containers":[{"name":"gw2-1","service":"caddy","state":"running"}]
      }]),
      AgentOp::GatewayProbe(job) => {
        assert_eq!(job.path, "/healthz");
        let ok = job.upstream_only || !job.tls;
        serde_json::json!({
          "ok":ok,
          "stage":"fixture",
          "detail": if ok { "入口可达" } else { "HTTP 502" },
        })
      }
      _ => panic!("收到意外探测请求"),
    }));
    state.hub.enable_mock_failover_features("s1");
    let mut net = snap.net(&snap.world);
    let cancel = CancellationToken::new();
    let err = verify_before_dns(
      &state,
      &snap,
      &net,
      (host, &route, "gw2"),
      &cancel,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    assert!(err.message.contains("HTTP 502"));
    route.cf_origin_only = true;
    assert!(
      verify_before_dns(
        &state,
        &snap,
        &net,
        (host, &route, "gw2"),
        &cancel
      )
      .await
      .unwrap()
      .ok
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let http = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let gw = &mut snap.world.gateways.get_mut("gw2").unwrap().spec;
    gw.tls = GatewayTls::Off;
    gw.http_port = Some(http.local_addr().unwrap().port());
    net.core_server = Some("s1".into());
    route.cf_origin_only = false;
    let server = tokio::spawn(async move {
      let (mut stream, _) = http.accept().await.unwrap();
      let mut request = [0; 4096];
      assert!(stream.read(&mut request).await.unwrap() > 0);
      stream
        .write_all(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    });
    let direct = verify_before_dns(
      &state,
      &snap,
      &net,
      (host, &route, "gw2"),
      &cancel,
    )
    .await;
    server.abort();
    assert_eq!(direct.unwrap().status, Some(302));
  }
}
