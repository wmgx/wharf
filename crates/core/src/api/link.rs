use std::sync::Arc;

use axum::{
  Extension, Json,
  extract::{Path, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  spec::{GatewayKind, GatewayTls},
  view::Perm,
};

use crate::{
  audit::AuditSlot, auth::Auth, db, link, link_cert, render,
  snapshot, state::AppState,
};

use super::ApiResult;

#[derive(Deserialize)]
pub(super) struct RotateLinkRequest {
  #[serde(default = "enabled")]
  token: bool,
  #[serde(default = "enabled")]
  cert: bool,
}

fn enabled() -> bool {
  true
}

#[derive(Serialize)]
pub(super) struct RotateLinkResponse {
  gateway: String,
  server: String,
  rotated_token: bool,
  rotated_cert: bool,
  cert_expires_at: Option<DateTime<Utc>>,
  cert_fingerprint: Option<String>,
  suggest: [&'static str; 1],
}

pub(super) async fn rotate(
  State(state): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  Path(name): Path<String>,
  Json(req): Json<RotateLinkRequest>,
) -> ApiResult<RotateLinkResponse> {
  auth.require(Perm::Admin)?;
  let what = match (req.token, req.cert) {
    (true, true) => "token 和证书",
    (true, false) => "token",
    (false, true) => "证书",
    (false, false) => {
      return Err(
        ApiError::invalid("至少选择轮换 token 或 cert 中的一项")
          .into(),
      );
    }
  };
  let _guard = state
    .apply_lock
    .try_lock()
    .map_err(|_| state.runs.busy_error())?;
  let snap = snapshot::load(&state.db).await?;
  let gateway = snap.world.gateways.get(&name).ok_or_else(|| {
    ApiError::not_found(format!("网关 {name} 不存在"))
      .suggest("wharf gateway list")
  })?;
  let spec = &gateway.spec;
  if spec.kind != GatewayKind::Caddy {
    return Err(
      ApiError::invalid(format!(
        "网关 {name} 不是 Caddy 网关，不使用 frp 反向隧道"
      ))
      .into(),
    );
  }
  if spec.tls == GatewayTls::Off {
    return Err(
      ApiError::invalid(format!(
        "网关 {name} 关闭了 TLS，不支持加密反向隧道"
      ))
      .into(),
    );
  }
  let server = spec.server.clone();
  if let Some((actual, _)) = link::link_gateway(&snap.world, &server)
    && actual != name
  {
    return Err(
      ApiError::invalid(format!(
        "服务器 {server} 的反向隧道由网关 {actual} 承载"
      ))
      .suggest(format!("wharf gateway rotate-link {actual}"))
      .into(),
    );
  }
  if req.cert && state.hub.is_online(&server) {
    link_cert::require_gateway_agent(&state.hub, &server, &name)?;
  }
  audit
    .require_record(format!("轮换网关 {name} 的隧道凭据（{what}）"));
  let gateway = name.clone();
  let (cert_expires_at, cert_fingerprint) = state
    .db
    .call_credentials(move |c, key| {
      let tx = c.transaction().map_err(db::sql_err)?;
      let now = db::now_ms();
      if req.token {
        db::rotate_scoped_secret(
          &tx,
          key,
          link::TOKEN_PREFIX,
          &gateway,
          now,
        )?;
      }
      let cert = if req.cert {
        Some(
          link_cert::ensure_gateway_cert(
            &tx, key, &gateway, now, true,
          )?
          .cert,
        )
      } else {
        None
      };
      tx.commit().map_err(db::sql_err)?;
      Ok((
        cert.as_deref().and_then(crate::cert::pem_not_after),
        cert
          .as_deref()
          .map(|cert| render::hash(cert)[..12].to_string()),
      ))
    })
    .await?;
  Ok(Json(RotateLinkResponse {
    gateway: name,
    server,
    rotated_token: req.token,
    rotated_cert: req.cert,
    cert_expires_at,
    cert_fingerprint,
    suggest: ["wharf plan"],
  }))
}
