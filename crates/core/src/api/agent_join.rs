use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use super::ApiResult;
use crate::{
  auth::{self, Auth},
  db::{self, now_ms, sql_err},
  state::AppState,
  world::KIND_SERVER,
};
use axum::{
  Extension, Json,
  extract::{ConnectInfo, State},
  http::HeaderMap,
};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode, validate_name,
  view::{JoinInfo, JoinRequest, JoinResponse, Perm},
};

#[derive(Deserialize)]
pub(super) struct AddServer {
  name: String,
  #[serde(default)]
  rejoin: bool,
  /// agent 连接控制面用的地址，不给时用启动配置或请求的 Host。
  #[serde(default)]
  core_url: Option<String>,
  /// agent 镜像，不给时用控制面的默认镜像。国内机器可以换成镜像站地址。
  #[serde(default)]
  agent_image: Option<String>,
}

const JOIN_TTL_HOURS: i64 = 24;

pub(super) async fn add_server(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  headers: HeaderMap,
  Json(req): Json<AddServer>,
) -> ApiResult<JoinInfo> {
  auth.require(Perm::Admin)?;
  validate_name("服务器", &req.name)?;
  let image = match req.agent_image.as_deref().map(str::trim) {
    Some(i) if !i.is_empty() && i != s.agent_image => {
      Some(crate::join::check_image(i)?)
    }
    _ => None,
  };
  let core_url =
    match req.core_url.as_deref().filter(|u| !u.trim().is_empty()) {
      Some(u) => Some(crate::join::check_core_url(u)?),
      None => None,
    };
  let token = auth::new_token().replacen("wh_", "wj_", 1);
  let hash = auth::hash_token(&token);
  let expires = Utc::now() + chrono::Duration::hours(JOIN_TTL_HOURS);
  let name = req.name.clone();
  let rejoin = req.rejoin;
  let expires_ms = expires.timestamp_millis();
  s.db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let joined: Option<Option<String>> = tx
        .query_row(
          "SELECT public_key FROM agents WHERE server = ?1",
          params![name],
          |r| r.get(0),
        )
        .optional()
        .map_err(sql_err)?;
      if matches!(joined, Some(Some(_))) && !rejoin {
        return Err(
          ApiError::new(ErrorCode::AlreadyExists, format!("服务器 {name} 已经加入"))
            .with_hint("换机器或重装 agent 时用 --rejoin 生成新的加入命令，旧密钥会失效")
            .suggest(format!("wharf server add {name} --rejoin")),
        );
      }
      let exists: bool = tx
        .query_row(
          "SELECT 1 FROM resources WHERE kind = ?1 AND name = ?2",
          params![KIND_SERVER, name],
          |_| Ok(()),
        )
        .optional()
        .map_err(sql_err)?
        .is_some();
      if !exists {
        db::apply_write(
          &tx,
          &db::Write::Upsert {
            kind: KIND_SERVER.into(),
            name: name.clone(),
            spec: json!({}),
            meta: json!({}),
          },
        )?;
      }
      tx.execute(
        "INSERT INTO agents (server, join_token_hash, join_expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (server) DO UPDATE SET join_token_hash = excluded.join_token_hash,
           join_expires_at = excluded.join_expires_at",
        params![name, hash, expires_ms],
      )
      .map_err(sql_err)?;
      tx.commit().map_err(sql_err)
    })
    .await?;

  let core_url = match core_url {
    Some(u) => Some(u),
    None => crate::join::default_url(&s).await,
  };
  let core_url = core_url.unwrap_or_else(|| {
    let host = headers
      .get(axum::http::header::HOST)
      .and_then(|h| h.to_str().ok())
      .unwrap_or("127.0.0.1:7700");
    format!("http://{host}")
  });
  let core_key = hex::encode(s.key.verifying_key().to_bytes());
  let mut commands = BTreeMap::from([
    (
      "docker".to_string(),
      format!(
        "docker run -d --label wharf.system=agent --name wharf-agent --restart unless-stopped --network host \
         -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/wharf:/var/lib/wharf -v /srv:/srv \
         -e WHARF_CORE_URL={core_url} -e WHARF_JOIN_TOKEN={token} -e WHARF_CORE_KEY={core_key} {}",
        image.as_deref().unwrap_or(&s.agent_image)
      ),
    ),
    (
      "binary".to_string(),
      format!(
        "wharf-agent join {core_url} {token} --core-key {core_key} && wharf-agent run"
      ),
    ),
  ]);
  if crate::join::allows_script_install(&core_url) {
    commands.insert(
      "script".into(),
      crate::join::script_command(
        &core_url,
        &token,
        &core_key,
        image.as_deref(),
      ),
    );
  }
  Ok(Json(JoinInfo {
    server: req.name,
    join_token: token,
    expires_at: expires,
    commands,
    core_url,
  }))
}

pub(super) async fn agent_join(
  State(s): State<Arc<AppState>>,
  sealed: Option<Extension<crate::cli_tunnel::Sealed>>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<JoinRequest>,
) -> ApiResult<JoinResponse> {
  if sealed.is_none()
    && !crate::source_trust::is_direct_local(peer.ip(), &headers)
  {
    return Err(
      ApiError::new(
        ErrorCode::Unauthorized,
        "控制面已拒绝明文提交加入凭据",
      )
      .with_hint(
        "先拉取最新的 wharf-agent 镜像，再用最新的加入命令重试",
      )
      .into(),
    );
  }
  let hash = auth::hash_token(req.join_token.trim());
  let key = req.public_key.clone();
  if hex::decode(&key).map(|b| b.len()).unwrap_or(0) != 32 {
    return Err(ApiError::invalid("公钥格式不对").into());
  }
  let hub = s.clone();
  let server = s
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      let found: Option<(String, i64)> = tx
        .query_row(
          "SELECT server, join_expires_at FROM agents WHERE join_token_hash = ?1",
          params![hash],
          |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql_err)?;
      let Some((server, expires)) = found else {
        return Err(
          ApiError::new(ErrorCode::Unauthorized, "加入凭据无效或已经用过")
            .with_hint("在控制面重新执行 wharf server add <name> --rejoin"),
        );
      };
      if expires < now_ms() {
        return Err(
          ApiError::new(ErrorCode::Unauthorized, "加入凭据已过期")
            .suggest(format!("wharf server add {server} --rejoin")),
        );
      }
      tx.execute(
        "UPDATE agents SET public_key = ?1, join_token_hash = NULL, join_expires_at = NULL, report = NULL, last_seen = NULL
         WHERE server = ?2",
        params![key, server],
      )
      .map_err(sql_err)?;
      crate::core_node::clear_if_server(&tx, &server)?;
      tx.commit().map_err(sql_err)?;
      hub.hub.disconnect(&server);
      Ok(server)
    })
    .await?;
  tracing::info!("服务器 {server} 完成加入");
  Ok(Json(JoinResponse {
    server,
    core_public_key: hex::encode(s.key.verifying_key().to_bytes()),
  }))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn agent_join_rejects_plaintext_non_local_and_accepts_sealed()
  {
    let state = crate::rules::tests::test_state();
    for (peer, forwarded, sealed, allowed) in [
      ("203.0.113.5:4000", false, false, false),
      ("127.0.0.1:4000", true, false, false),
      ("203.0.113.5:4000", false, true, true),
      ("127.0.0.1:4000", false, false, true),
    ] {
      let token = auth::new_token();
      let hash = auth::hash_token(&token);
      state.db.call(move |c| {
        c.execute("INSERT OR REPLACE INTO agents (server, join_token_hash, join_expires_at) VALUES ('s1', ?1, ?2)", params![hash, now_ms() + 60_000])
          .map_err(sql_err)?;
        Ok(())
      }).await.unwrap();
      let mut headers = HeaderMap::new();
      if forwarded {
        headers
          .insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
      }
      let key = hex::encode(state.key.verifying_key().to_bytes());
      let result = agent_join(
        State(state.clone()),
        sealed.then_some(Extension(crate::cli_tunnel::Sealed)),
        ConnectInfo(peer.parse().unwrap()),
        headers,
        Json(JoinRequest {
          join_token: token,
          public_key: key,
        }),
      )
      .await;
      if allowed {
        assert!(result.is_ok());
      } else {
        let Err(error) = result else {
          panic!("明文加入被放行")
        };
        assert_eq!(error.0.code, ErrorCode::Unauthorized);
      }
      let consumed = state.db.call(|c| c.query_row("SELECT join_token_hash IS NULL FROM agents WHERE server = 's1'",
        [], |r| r.get::<_, bool>(0)).map_err(sql_err)).await.unwrap();
      assert_eq!(consumed, allowed);
    }
  }
}
