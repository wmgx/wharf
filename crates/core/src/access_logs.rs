use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  access_logs::{AccessLogsRequest, AccessLogsResult, MAX_TAIL},
  agent::AgentOp,
  spec::GatewayKind,
  view::Perm,
};

use crate::{
  api::{ApiResult, gateway_not_found},
  auth::Auth,
  multi_logs::anchor_since,
  snapshot,
  state::AppState,
  world::World,
};

#[derive(Deserialize)]
pub struct AccessLogsQuery {
  host: Option<String>,
  status: Option<String>,
  path: Option<String>,
  method: Option<String>,
  since: Option<String>,
  tail: Option<u32>,
}

fn status_code(code: &str) -> Option<u16> {
  if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
    return None;
  }
  let code = code.parse().ok()?;
  (100..=599).contains(&code).then_some(code)
}

fn parse_status(value: &str) -> Result<Vec<(u16, u16)>, ApiError> {
  value
    .split(',')
    .map(|part| {
      let part = part.trim();
      match part.as_bytes() {
        [first @ b'1'..=b'5', b'x', b'x'] => {
          let start = u16::from(*first - b'0') * 100;
          Some((start, start + 99))
        }
        _ => {
          if let Some((start, end)) = part.split_once('-') {
            let (start, end) =
              (status_code(start)?, status_code(end)?);
            (start <= end).then_some((start, end))
          } else {
            let code = status_code(part)?;
            Some((code, code))
          }
        }
      }
    })
    .collect::<Option<Vec<_>>>()
    .ok_or_else(|| {
      ApiError::invalid("状态码筛选格式无效")
        .with_hint("写成 502、5xx、400-499，或逗号分隔如 401,403,5xx")
    })
}

pub async fn gateway(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Query(query): Query<AccessLogsQuery>,
) -> ApiResult<AccessLogsResult> {
  auth.require(Perm::Read)?;
  let snap = snapshot::load(&state.db).await?;
  Ok(Json(fetch(&state, &snap.world, &name, query).await?))
}

pub async fn route(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Path(host): Path<String>,
  Query(mut query): Query<AccessLogsQuery>,
) -> ApiResult<AccessLogsResult> {
  auth.require(Perm::Read)?;
  let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
  let snap = snapshot::load(&state.db).await?;
  let route = snap.world.routes.get(&host).ok_or_else(|| {
    ApiError::not_found(format!("域名 {host} 不存在"))
      .suggest("wharf route list")
  })?;
  let name =
    snap.world.route_gateway(&route.spec).ok_or_else(|| {
      ApiError::invalid(format!("域名 {host} 没有入口"))
    })?;
  query.host = Some(host);
  let mut result = fetch(&state, &snap.world, name, query).await?;
  if let Some(backup) = &route.spec.backup_gateway {
    result.warnings.push(format!(
      "本次只查询主网关 {name}。备用网关可用 wharf gateway logs {backup} --access 单独查询"
    ));
  }
  Ok(Json(result))
}

async fn fetch(
  state: &AppState,
  world: &World,
  name: &str,
  query: AccessLogsQuery,
) -> Result<AccessLogsResult, ApiError> {
  let gateway = world
    .gateways
    .get(name)
    .ok_or_else(|| gateway_not_found(name))?;
  if gateway.spec.kind != GatewayKind::Caddy {
    return Err(ApiError::invalid(format!(
      "{name} 是 Cloudflare 隧道，本地没有访问日志，到 Cloudflare 控制台看"
    )));
  }
  let status =
    query.status.as_deref().map(parse_status).transpose()?;
  let since = query
    .since
    .as_deref()
    .filter(|value| !value.trim().is_empty())
    .map(|value| {
      anchor_since(value)
        .and_then(|time| DateTime::parse_from_rfc3339(&time).ok())
        .map(|time| time.with_timezone(&Utc))
        .ok_or_else(|| {
          ApiError::invalid(format!("时间范围 {value} 看不懂"))
            .with_hint(
              "写成 30m、2h、3d，或 2026-11-22T08:00:00+08:00",
            )
        })
    })
    .transpose()?;
  let job = AccessLogsRequest {
    gateway: name.to_string(),
    host: query.host,
    status,
    path: query.path,
    method: query.method,
    since,
    tail: query.tail.unwrap_or(200).min(MAX_TAIL),
  };
  let mut result: AccessLogsResult = state
    .hub
    .call(
      &gateway.spec.server,
      AgentOp::AccessLogs(job),
      Duration::from_secs(30),
      None,
      &CancellationToken::new(),
    )
    .await?;
  if result.missing {
    result.warnings.push(
      "网关还没开访问日志或还没有请求；刚升级的话先 wharf plan && wharf apply 让网关热重载".into(),
    );
  }
  for entry in &mut result.entries {
    entry.path = crate::log_redact::redact_text(&entry.path);
  }
  for warning in &mut result.warnings {
    *warning = crate::log_redact::redact_text(warning);
  }
  Ok(result)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_status_filters() {
    for (value, expected) in [
      ("502", vec![(502, 502)]),
      ("5xx", vec![(500, 599)]),
      ("400-499", vec![(400, 499)]),
      ("401,403,5xx", vec![(401, 401), (403, 403), (500, 599)]),
    ] {
      assert_eq!(parse_status(value).unwrap(), expected);
    }
    for value in ["6xx", "abc", "499-400"] {
      assert_eq!(
        parse_status(value).unwrap_err().code,
        wharf_api_types::ErrorCode::InvalidInput
      );
    }
  }
}
