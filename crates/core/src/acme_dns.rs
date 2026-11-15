//! 网关签证书时的 DNS 验证：Caddy 的 acmedns 插件把 TXT 值发到这里，控制面用厂商账号写进 DNS。
//! 厂商 token 不离开控制面。协议是 acme-dns 的 /update。

use std::{sync::Arc, time::Duration};

use axum::{
  Json,
  extract::{State, rejection::JsonRejection},
  http::{HeaderMap, StatusCode},
  response::{IntoResponse, Response},
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::json;
use wharf_api_types::spec::GatewayKind;
use wharf_providers::Owner;

use crate::{db, render, snapshot, state::AppState, world::World};

pub fn secret_name(gateway: &str) -> String {
  format!("WHARF_ACME_DNS_{gateway}")
}

pub fn allowed(world: &World, gateway: &str) -> Vec<String> {
  let mut names = world
    .gateways
    .get(gateway)
    .map(|g| g.spec.wildcard.clone())
    .unwrap_or_default();
  names.extend(
    world
      .routes
      .iter()
      .filter(|(_, r)| {
        r.spec.internal
          && world.route_gateway(&r.spec) == Some(gateway)
      })
      .map(|(host, _)| host.clone()),
  );
  names
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  a.iter().zip(b).fold(0, |diff, (a, b)| diff | (a ^ b)) == 0
}

pub fn fill(config: &str, key: &str, url: &str) -> String {
  config.replace(render::ACME_DNS_KEY, key).replace(
    render::ACME_DNS_URL,
    &format!("{}/agent/acme-dns", url.trim_end_matches('/')),
  )
}

#[derive(Deserialize)]
pub struct Update {
  subdomain: String,
  txt: String,
}

fn error(status: StatusCode, message: impl AsRef<str>) -> Response {
  (status, Json(json!({"error": message.as_ref()}))).into_response()
}

pub async fn update(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  body: Result<Json<Update>, JsonRejection>,
) -> Response {
  let (Some(gateway), Some(key), Ok(Json(body))) = (
    headers.get("X-Api-User").and_then(|v| v.to_str().ok()),
    headers.get("X-Api-Key").and_then(|v| v.to_str().ok()),
    body,
  ) else {
    return error(StatusCode::BAD_REQUEST, "请求不完整");
  };
  let Update { subdomain, txt } = body;
  if txt.len() != 43
    || !txt
      .bytes()
      .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
  {
    return error(StatusCode::BAD_REQUEST, "txt 不是验证值");
  }
  let name = secret_name(gateway);
  let stored: Option<String> = match state
    .db
    .call(move |c| {
      c.query_row(
        "SELECT value FROM secrets WHERE name = ?1",
        [&name],
        |r| r.get(0),
      )
      .optional()
      .map_err(db::sql_err)
    })
    .await
  {
    Ok(value) => value,
    Err(e) => {
      return error(StatusCode::INTERNAL_SERVER_ERROR, e.message);
    }
  };
  if !stored
    .as_deref()
    .is_some_and(|v| constant_time_eq(v.as_bytes(), key.as_bytes()))
  {
    return error(StatusCode::UNAUTHORIZED, "凭据不对");
  }
  let snap = match snapshot::load(&state.db).await {
    Ok(snap) => snap,
    Err(e) => {
      return error(StatusCode::INTERNAL_SERVER_ERROR, e.message);
    }
  };
  if !snap
    .world
    .gateways
    .get(gateway)
    .is_some_and(|g| g.spec.kind == GatewayKind::Caddy)
  {
    return error(StatusCode::UNAUTHORIZED, "凭据不对");
  }
  if !allowed(&snap.world, gateway).contains(&subdomain) {
    return error(
      StatusCode::FORBIDDEN,
      format!("这个入口不能签 {subdomain}"),
    );
  }
  let Some((account, _)) = snap.account_for(&subdomain) else {
    return error(
      StatusCode::UNPROCESSABLE_ENTITY,
      format!("没有厂商账号管理 {subdomain}"),
    );
  };
  let result = tokio::time::timeout(Duration::from_secs(25), async {
    let provider = snapshot::dns_provider(account)?;
    let name = format!("_acme-challenge.{subdomain}");
    let owner = Owner {
      id: format!("acme:{gateway}"),
    };
    let records = snapshot::with_timeout(
      "读取 DNS 验证记录",
      provider.list_txt(&name, &owner),
    )
    .await?;
    for record in records {
      snapshot::with_timeout(
        "删除 DNS 验证记录",
        provider.delete(
          &record.scope,
          &record.remote_id,
          Some(&owner),
        ),
      )
      .await?;
    }
    snapshot::with_timeout(
      "写入 DNS 验证记录",
      provider.create_txt(&name, &txt, &owner),
    )
    .await
  })
  .await;
  match result {
    Ok(Ok(_)) => {
      tracing::info!(
        "入口 {gateway} 写入 _acme-challenge.{subdomain}"
      );
      Json(json!({"txt": txt})).into_response()
    }
    Ok(Err(e)) => error(
      StatusCode::BAD_GATEWAY,
      format!("写 DNS 记录失败：{}", e.message),
    ),
    Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "写 DNS 记录超时"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn acme_dns_allowed() {
    let mut world = World::default();
    for (name, zone) in
      [("edge", "example.com"), ("other", "other.com")]
    {
      world.gateways.insert(
        name.into(),
        crate::world::GatewayRow {
          spec: serde_json::from_value(
            json!({"kind":"caddy", "server":"s1", "wildcard":[zone]}),
          )
          .unwrap(),
          version: 1,
        },
      );
    }
    let zones = allowed(&world, "edge");
    assert!(zones.contains(&"example.com".into()));
    assert!(!zones.contains(&"other.com".into()));
    assert!(!zones.contains(&"a.example.com".into()));
    for (host, internal) in
      [("i.example.com", true), ("a.example.com", false)]
    {
      world.routes.insert(host.into(), crate::world::RouteRow {
        id:host.into(), spec:serde_json::from_value(json!({"hostname":host, "gateway":"edge", "upstream":"127.0.0.1:8080", "internal":internal})).unwrap(), version:1,
      });
    }
    let names = allowed(&world, "edge");
    assert!(names.contains(&"i.example.com".into()));
    assert!(!names.contains(&"a.example.com".into()));
    assert!(
      !allowed(&world, "other").contains(&"i.example.com".into())
    );
  }

  #[test]
  fn constant_time_eq_works() {
    assert!(constant_time_eq(b"key", b"key"));
    assert!(!constant_time_eq(b"key", b"keys"));
    assert!(!constant_time_eq(b"key", b"kez"));
  }

  #[test]
  fn fill_points_at_update_route() {
    let config = fill(
      "server_url [[WHARF_ACME_DNS_URL]]\npassword [[WHARF_ACME_DNS_KEY]]",
      "k",
      "https://core.example.com",
    );
    assert!(config.contains(
      "server_url https://core.example.com/agent/acme-dns"
    ));
    assert!(config.contains("password k"));
    assert_eq!(
      fill("unchanged", "k", "https://core.example.com"),
      "unchanged"
    );
  }
}
