use std::{
  net::{IpAddr, SocketAddr},
  time::Duration,
};

use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{
    AgentOp, GatewayProbeJob, GatewayProbeResult, OneTimeSecret,
    ProbeTarget, ProjectState,
  },
  gateway_http::{inspect, tls_failed},
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

fn has_gate(route: &RouteSpec) -> bool {
  !route.cf_origin_only
    && route.redirect.is_none()
    && route.sso.as_ref().is_some_and(|sso| sso.gated())
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
    let gate_cookie = if has_gate(route) {
      match crate::gate::probe_cookie(&state.db, host)
        .await
        .and_then(|cookie| cookie.to_str().ok().map(str::to_owned))
      {
        Some(cookie) => Some(OneTimeSecret(cookie)),
        None => {
          return entry(
            false,
            "gateway_auth_rejected",
            "无法签发门禁探测凭证",
          );
        }
      }
    } else {
      None
    };
    let job = GatewayProbeJob {
      hostname: host.into(),
      path: path(snap, net, host, route).into(),
      tls: gw.tls != GatewayTls::Off,
      allow_pending_cert: gw.tls == GatewayTls::Auto,
      gate_cookie,
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
  if gw.kind == GatewayKind::Caddy && has_gate(route) {
    return entry(
      false,
      "gateway_auth_rejected",
      format!(
        "服务器 {} 的 agent 不支持门禁探测，请先 wharf server upgrade {}",
        gw.server, gw.server
      ),
    );
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
  if has_gate(route) && !tls && !ip.is_loopback() {
    return Err(conflict(host, gateway, "门禁直连预验需要 HTTPS"));
  }
  let gated = has_gate(route);
  // 内部自签证书的后端已由网关本机验证，此处只验证直连路径。
  let send_cookie =
    gated && (ip.is_loopback() || gw.tls == GatewayTls::Auto);
  let gate_cookie = if send_cookie {
    Some(
      crate::gate::probe_cookie(&state.db, host)
        .await
        .ok_or_else(|| {
          conflict(host, gateway, "无法签发门禁探测凭证")
        })?,
    )
  } else {
    None
  };
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
      .tls_danger_accept_invalid_certs(
        !send_cookie || ip.is_loopback(),
      )
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
  let mut attempted_port = port;
  for attempt in 0..2 {
    if attempt != 0 {
      tokio::time::sleep(Duration::from_secs(1)).await;
    }
    attempted_port = port;
    let outcome =
      tokio::time::timeout(Duration::from_secs(8), async {
        let mut request =
          direct.get(url(tls, port)).header("Host", host);
        if let Some(cookie) = &gate_cookie {
          request =
            request.header(reqwest::header::COOKIE, cookie.clone());
        }
        let (response, pending) = match request.send().await {
          Err(error)
            if gw.tls == GatewayTls::Auto && tls_failed(&error) =>
          {
            attempted_port = http_port;
            (
              client(http_port)?
                .get(url(false, http_port))
                .header("Host", host)
                .send()
                .await,
              true,
            )
          }
          response => (response, false),
        };
        let response = match response {
          Ok(response) => response,
          Err(error) => return Ok(Err(network_error(&error))),
        };
        let (code, rejected, _) =
          inspect(response, !pending && send_cookie, false).await;
        if !pending && send_cookie && rejected {
          return Ok(Err("Wharf 门禁未放行探测请求".into()));
        }
        Ok::<_, ApiError>(Ok((code, pending)))
      })
      .await;
    match outcome.unwrap_or_else(|_| Ok(Err("请求超时".into())))?
    {
      Ok((code, cert_pending))
        if !code.is_server_error()
          && (!cert_pending
            || matches!(code.as_u16(), 301 | 308)) =>
      {
        let code = code.as_u16();
        let mut result = entry(
          true,
          "direct",
          format!("直连 {ip} 返回 HTTP {code}，通过"),
        );
        result.status = Some(code);
        result.cert_pending = cert_pending || local.cert_pending;
        return Ok(result);
      }
      Ok((code, _)) => {
        detail = format!(
          "直连 {ip}:{attempted_port} 返回 HTTP {}",
          code.as_u16()
        );
      }
      Err(error) => {
        detail = format!(
          "本机正常，但控制面直连 {ip}:{attempted_port} 失败（{error}）"
        );
      }
    }
  }
  let server = &gw.server;
  let hint = if snap.world.servers.get(server).is_some_and(|row| {
    row.settings.region
      == Some(wharf_api_types::spec::Region::Overseas)
  }) {
    format!(
      "检查服务器 {server} 的安全组和防火墙是否放行 {attempted_port}；若仅是控制面国际线路波动，可加 --no-verify-before-dns 跳过预验"
    )
  } else {
    format!(
      "检查目标网关、上游及服务器 {server} 的安全组和防火墙是否放行 {attempted_port}，或加 --no-verify-before-dns 跳过预验"
    )
  };
  Err(conflict(host, gateway, &detail).with_hint(hint))
}

fn network_error(error: &reqwest::Error) -> String {
  let mut detail = error.to_string();
  let mut cause = std::error::Error::source(error);
  while let Some(next) = cause {
    detail.push_str(&format!("，{next}"));
    cause = next.source();
  }
  detail
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn dns_preverify_probes_local_and_direct_with_gate_credentials()
   {
    let state = crate::rules::tests::test_state();
    state
      .db
      .call(|c| crate::gate::rotate_seed(c, "gate.key"))
      .await
      .unwrap();
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
        if !job.tls {
          assert!(job.gate_cookie.is_some());
        }
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
    route.sso = Some(
      serde_json::from_value(serde_json::json!({"mode":"header"}))
        .unwrap(),
    );
    let server = tokio::spawn(async move {
      for code in [403, 502, 502] {
        let (mut stream, _) = http.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
          request.push(stream.read_u8().await.unwrap());
        }
        let request =
          String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.contains("\r\nhost: check.example.test\r\n"));
        assert!(request.contains("\r\ncookie: wharf_gate="));
        stream
          .write_all(
            format!(
              "HTTP/1.1 {code} Fixture\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
          )
          .await
          .unwrap();
      }
    });
    let direct = verify_before_dns(
      &state,
      &snap,
      &net,
      (host, &route, "gw2"),
      &cancel,
    )
    .await;
    assert_eq!(direct.unwrap().status, Some(403));
    let err = verify_before_dns(
      &state,
      &snap,
      &net,
      (host, &route, "gw2"),
      &cancel,
    )
    .await
    .unwrap_err();
    assert!(err.message.contains("HTTP 502"));
    server.await.unwrap();
    let err = verify_before_dns(
      &state,
      &snap,
      &net,
      (host, &route, "gw2"),
      &cancel,
    )
    .await
    .unwrap_err();
    assert!(
      err
        .message
        .to_ascii_lowercase()
        .contains("connection refused"),
      "{}",
      err.message
    );
    let hint = err.hint.unwrap();
    assert!(hint.contains("s1"));
    assert!(
      hint.contains(
        &snap.world.gateways["gw2"]
          .spec
          .http_port
          .unwrap()
          .to_string()
      )
    );
  }
}
