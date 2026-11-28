//! 证书申请状态：从网关最近的日志里读这个域名的证书事件；申请失败时可以让网关立刻重试。

use crate::{api::ApiResult, auth::Auth, snapshot, state::AppState};
use axum::{
  Json,
  extract::{Path, State},
};
use serde_json::Value;
use std::{
  collections::BTreeMap,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::AgentOp,
  spec::{GatewayKind, GatewayTls},
  view::{CertState, CertStatus, Perm},
};

/// 读网关最近多少行日志。访问日志不进容器日志，几千行能覆盖好几天的证书事件。
const LOG_TAIL: u32 = 5000;
/// 同一个入口两次重新申请至少隔这么久，免得触发 Let's Encrypt 的频率限制。
const RETRY_GAP: Duration = Duration::from_secs(60);

static LAST_RETRY: LazyLock<Mutex<BTreeMap<String, Instant>>> =
  LazyLock::new(Default::default);

/// 从日志里读出的状态（不含域名和网关）。
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
  pub state: Option<CertState>,
  pub since: Option<i64>,
  pub error: Option<String>,
  pub failed_at: Option<i64>,
  pub next_retry_at: Option<i64>,
  pub attempts: u32,
}

/// 按时间顺序扫一遍 Caddy 的 JSON 日志，只看证书标识是 `ids` 之一的事件。
pub fn parse(logs: &str, ids: &[String]) -> Parsed {
  let ids: Vec<_> =
    ids.iter().map(|id| id.to_ascii_lowercase()).collect();
  let mut out = Parsed::default();
  for line in logs.lines() {
    let Some(start) = line.find('{') else {
      continue;
    };
    let Ok(v) = serde_json::from_str::<Value>(&line[start..]) else {
      continue;
    };
    let logger = v["logger"].as_str().unwrap_or_default();
    if !logger.starts_with("tls") && logger != "http" {
      continue;
    }
    let mine =
      v["identifier"].as_str().is_some_and(|i| {
        ids.iter().any(|x| x.eq_ignore_ascii_case(i))
      }) || v["identifiers"].as_array().is_some_and(|a| {
        a.iter().any(|i| {
          i.as_str().is_some_and(|i| {
            ids.iter().any(|x| x.eq_ignore_ascii_case(i))
          })
        })
      }) || v["error"].as_str().is_some_and(|e| {
        let e = e.to_ascii_lowercase();
        ids.iter().any(|x| {
          e.contains(&format!("[{x}]"))
            || e.starts_with(&format!("{x}:"))
            || e.contains(&format!(" {x}:"))
        })
      });
    if !mine {
      continue;
    }
    let ts = v["ts"].as_f64().map(|t| (t * 1000.0) as i64);
    match v["msg"].as_str().unwrap_or_default() {
      "obtaining certificate" => {
        if out.state != Some(CertState::Failed) {
          out.since = ts;
          out.attempts = 0;
          out.error = None;
          out.failed_at = None;
        }
        out.state = Some(CertState::Obtaining);
        out.next_retry_at = None;
      }
      "renewing certificate" => {
        out = Parsed {
          state: Some(CertState::Obtaining),
          since: ts,
          ..Default::default()
        };
      }
      "trying to solve challenge"
      | "waiting on internal rate limiter" => {
        out.state = Some(CertState::Obtaining);
        out.next_retry_at = None;
      }
      "could not get certificate from issuer" => {
        out.state = Some(CertState::Failed);
        out.error = v["error"].as_str().map(str::to_string);
        out.failed_at = ts;
      }
      "could not renew certificate"
      | "failed to renew certificate"
      | "error renewing certificate" => {
        out.state = Some(CertState::Failed);
        out.error = v["error"].as_str().map(str::to_string);
        out.failed_at = ts;
        out.attempts += 1;
      }
      "will retry" => {
        out.state = Some(CertState::Failed);
        out.error = v["error"]
          .as_str()
          .map(str::to_string)
          .or(out.error.take());
        out.failed_at = ts;
        out.attempts =
          v["attempt"].as_u64().unwrap_or(out.attempts as u64 + 1)
            as u32;
        out.next_retry_at = match (ts, v["retrying_in"].as_f64()) {
          // retrying_in 是秒，也可能是 Go 的纳秒时长。
          (Some(t), Some(r)) if r > 1e6 => Some(t + (r / 1e6) as i64),
          (Some(t), Some(r)) => Some(t + (r * 1000.0) as i64),
          _ => None,
        };
      }
      "certificate obtained successfully"
      | "certificate renewed successfully" => {
        out = Parsed {
          state: Some(CertState::Ok),
          since: ts,
          ..Default::default()
        };
      }
      _ => {}
    }
  }
  out
}

/// 把 ACME 的报错翻成人话。认不出来的返回 None，页面只显示原始报错。
pub fn reason(error: &str) -> Option<&'static str> {
  let e = error.to_ascii_lowercase();
  let rules: [(&[&str], &str); 7] = [
    (
      &["ratelimited", "too many"],
      "触发了 Let's Encrypt 的频率限制，要过一段时间才能再申请",
    ),
    (
      &[
        "acme:error:dns",
        "nxdomain",
        "dns problem",
        "no valid a records",
        "no valid aaaa",
      ],
      "Let's Encrypt 查不到这个域名的解析，检查 DNS 是否已经指向入口",
    ),
    (
      &[
        "acme:error:connection",
        "timeout during connect",
        "connection refused",
      ],
      "Let's Encrypt 连不上入口机器的 80 或 443 端口，检查防火墙和安全组",
    ),
    (
      &["acme:error:unauthorized", "invalid response"],
      "Let's Encrypt 的验证没通过，这个域名可能没有指向这个入口",
    ),
    (
      &["acme:error:caa"],
      "域名的 CAA 记录不允许 Let's Encrypt 签证书",
    ),
    (
      &["letsencrypt.org", "acme-v02"],
      "入口机器连 Let's Encrypt 超时或出错，网关会自动重试",
    ),
    (
      &["timeout", "deadline exceeded", "i/o timeout"],
      "申请时网络超时，网关会自动重试",
    ),
  ];
  // 连 Let's Encrypt 本身出错的规则要求同时带超时字样，免得把带 URL 的验证失败误判。
  for (keys, text) in rules {
    let hit = keys.iter().any(|k| e.contains(k));
    let lets = keys.contains(&"letsencrypt.org");
    if hit
      && (!lets
        || e.contains("timeout")
        || e.contains("eof")
        || e.contains("connection reset"))
    {
      return Some(text);
    }
  }
  None
}

/// 证书的标识：域名本身，入口开了泛域名证书时还有 `*.<zone>`。
fn identifiers(host: &str, wildcard: &[String]) -> Vec<String> {
  let mut ids = vec![host.to_string()];
  if let Some((_, zone)) = host.split_once('.')
    && wildcard.iter().any(|z| z == zone)
  {
    ids.push(format!("*.{zone}"));
  }
  ids
}

/// 域名用的入口（主入口），只有自动签证书的 caddy 入口才有申请过程。
fn gateway_of(
  snap: &snapshot::Snapshot,
  host: &str,
) -> Result<(String, String, Vec<String>), ApiError> {
  let route = snap.world.routes.get(host).ok_or_else(|| {
    ApiError::not_found(format!("域名 {host} 不存在"))
      .suggest("wharf route list")
  })?;
  let name = snap
    .world
    .route_gateway(&route.spec)
    .ok_or_else(|| {
      ApiError::invalid(format!("域名 {host} 没有入口"))
    })?
    .to_string();
  let gw = &snap.world.gateways[&name];
  if gw.spec.kind != GatewayKind::Caddy
    || gw.spec.tls != GatewayTls::Auto
  {
    return Err(ApiError::invalid(format!(
      "入口 {name} 不自动签证书（Cloudflare 隧道、自签证书或只走 HTTP），没有申请过程"
    )));
  }
  Ok((name, gw.spec.server.clone(), gw.spec.wildcard.clone()))
}

/// `GET /api/routes/{hostname}/cert`
pub async fn status(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(hostname): Path<String>,
) -> ApiResult<CertStatus> {
  auth.require(Perm::Read)?;
  let host = hostname.trim().to_ascii_lowercase();
  let snap = snapshot::load(&s.db).await?;
  crate::token_scope::require_route_by_host(
    &auth,
    &snap.world,
    &host,
  )?;
  let (gateway, server, wildcard) = gateway_of(&snap, &host)?;
  let logs: String = s
    .hub
    .call(
      &server,
      AgentOp::Logs {
        project: crate::world::gateway_project(&gateway),
        tail: LOG_TAIL,
        follow: false,
        since: None,
      },
      Duration::from_secs(40),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let p = parse(&logs, &identifiers(&host, &wildcard));
  let error = p
    .error
    .as_deref()
    .map(|e| e.chars().take(400).collect::<String>());
  Ok(Json(CertStatus {
    reason: p.error.as_deref().and_then(reason).map(str::to_string),
    error,
    hostname: host,
    gateway,
    state: p.state.unwrap_or(CertState::Unknown),
    since: p.since,
    failed_at: p.failed_at,
    next_retry_at: p.next_retry_at,
    attempts: p.attempts,
  }))
}

/// `POST /api/routes/{hostname}/cert/retry`：配置不变，强制热重载入口，证书立刻重新申请。
pub async fn retry(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(hostname): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Apply)?;
  let host = hostname.trim().to_ascii_lowercase();
  let snap = snapshot::load(&s.db).await?;
  crate::token_scope::require_route_by_host(
    &auth,
    &snap.world,
    &host,
  )?;
  let (gateway, server, _) = gateway_of(&snap, &host)?;
  {
    let mut last = LAST_RETRY.lock().unwrap();
    if let Some(t) = last.get(&gateway)
      && t.elapsed() < RETRY_GAP
    {
      let wait = (RETRY_GAP - t.elapsed()).as_secs() + 1;
      return Err(
        ApiError::new(
          ErrorCode::Conflict,
          format!("入口 {gateway} 刚重新申请过，{wait} 秒后再试"),
        )
        .into(),
      );
    }
    last.insert(gateway.clone(), Instant::now());
  }
  let _: String = s
    .hub
    .call(
      &server,
      AgentOp::GatewayReload {
        project: crate::world::gateway_project(&gateway),
      },
      Duration::from_secs(90),
      None,
      &CancellationToken::new(),
    )
    .await
    .map_err(|e| {
      e.with_hint("确认入口所在机器的 agent 在线并已升级到最新版本")
    })?;
  Ok(Json(serde_json::json!({ "gateway": gateway })))
}

#[cfg(test)]
mod tests {
  use super::*;

  const LOGS: &str = r#"caddy-1  | 2026-11-21T17:14:25Z {"level":"info","ts":1795281265.99,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"a.example.com"}
caddy-1  | 2026-11-21T17:14:26Z {"level":"info","ts":1795281266.0,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"b.example.com"}
caddy-1  | 2026-11-21T17:16:08Z {"level":"error","ts":1795281368.05,"logger":"tls.obtain","msg":"will retry","error":"[a.example.com] Obtain: solving challenges: Post \"https://acme-v02.api.letsencrypt.org/acme/authz/1\": http2: timeout awaiting response headers","attempt":1,"retrying_in":60}
"#;

  #[test]
  fn cert_status_recognizes_tls_renew_recovery() {
    let logs = r#"{"logger":"tls.renew","ts":1,"msg":"renewing certificate","identifier":"A.EXAMPLE.COM"}
{"logger":"tls.renew","ts":2,"msg":"will retry","error":"renewing certificate: [A.EXAMPLE.COM] timeout","retrying_in":60}"#;
    let ids = ["a.example.com".into()];
    assert_eq!(parse(logs, &ids).next_retry_at, Some(62_000));
    let logs = format!(
      "{logs}\n{}",
      r#"{"logger":"tls.renew","ts":3,"msg":"certificate renewed successfully","identifiers":["A.EXAMPLE.COM"]}"#
    );
    assert_eq!(
      parse(&logs, &ids),
      Parsed {
        state: Some(CertState::Ok),
        since: Some(3_000),
        ..Default::default()
      }
    );
  }

  #[test]
  fn reads_failure_and_next_retry() {
    let p = parse(LOGS, &["a.example.com".into()]);
    assert_eq!(p.state, Some(CertState::Failed));
    assert_eq!(p.attempts, 1);
    assert_eq!(p.next_retry_at, Some(1795281368050 + 60_000));
    assert_eq!(p.since, Some(1795281265990));
    assert_eq!(
      reason(p.error.as_deref().unwrap()),
      Some("入口机器连 Let's Encrypt 超时或出错，网关会自动重试")
    );
    let ok = format!(
      "{LOGS}{}",
      r#"x {"level":"info","ts":1795281576.16,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"a.example.com"}"#
    );
    assert_eq!(
      parse(&ok, &["a.example.com".into()]).state,
      Some(CertState::Ok)
    );
  }
}
