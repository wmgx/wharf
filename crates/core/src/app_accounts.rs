use std::{
  collections::BTreeMap,
  net::SocketAddr,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};

use axum::{
  Extension, Json,
  extract::{ConnectInfo, Path, State},
  http::{HeaderMap, HeaderValue, header},
};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::{Value, json};
use wharf_api_types::{
  ApiError, ErrorCode, validate_name,
  view::{AppAccountDomain, AppAccountView, Perm},
};

use crate::{
  api::{ApiResult, AppError},
  audit::AuditSlot,
  auth::{Auth, hash_token},
  db::{now_ms, sql_err, to_time},
  login,
  state::AppState,
  world::normalize_hostname,
};

const REVEAL_TTL: Duration = Duration::from_secs(5 * 60);
static VERIFIED: LazyLock<Mutex<BTreeMap<String, Instant>>> =
  LazyLock::new(Default::default);

pub type AccountLinks = std::collections::BTreeSet<(String, String)>;

pub fn account_links(
  c: &rusqlite::Connection,
) -> Result<AccountLinks, ApiError> {
  let mut stmt = c
    .prepare("SELECT account, hostname FROM app_account_domains")
    .map_err(sql_err)?;
  stmt
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .and_then(Iterator::collect)
    .map_err(sql_err)
}

pub fn linked_account(
  world: &crate::world::World,
  service: &str,
  account: &str,
  links: &AccountLinks,
) -> bool {
  links.iter().any(|(name, host)| {
    name == account
      && world
        .routes
        .get(host)
        .is_some_and(|r| r.spec.service == service)
  })
}

pub fn defaults(
  conn: &Connection,
) -> Result<BTreeMap<String, String>, ApiError> {
  let mut stmt = conn
    .prepare("SELECT hostname, account FROM app_account_domains WHERE is_default = 1")
    .map_err(sql_err)?;
  stmt
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .and_then(Iterator::collect)
    .map_err(sql_err)
}

fn views(
  conn: &Connection,
  name: Option<&str>,
) -> Result<Vec<AppAccountView>, ApiError> {
  let mut stmt = conn.prepare(
    "SELECT a.name, a.username, a.note, a.updated_at, d.hostname, d.is_default,
            EXISTS (SELECT 1 FROM resources WHERE kind = 'route' AND name = d.hostname)
     FROM app_accounts a LEFT JOIN app_account_domains d ON d.account = a.name
     WHERE (?1 IS NULL OR a.name = ?1) ORDER BY a.name, d.hostname",
  ).map_err(sql_err)?;
  let mut rows = stmt.query([name]).map_err(sql_err)?;
  let mut accounts: Vec<AppAccountView> = Vec::new();
  while let Some(row) = rows.next().map_err(sql_err)? {
    let name: String = row.get(0).map_err(sql_err)?;
    if accounts.last().is_none_or(|a| a.name != name) {
      accounts.push(AppAccountView {
        name,
        username: row.get(1).map_err(sql_err)?,
        note: row.get(2).map_err(sql_err)?,
        updated_at: to_time(row.get(3).map_err(sql_err)?),
        domains: Vec::new(),
      });
    }
    if let Some(hostname) =
      row.get::<_, Option<String>>(4).map_err(sql_err)?
    {
      accounts.last_mut().unwrap().domains.push(AppAccountDomain {
        hostname,
        is_default: row.get(5).map_err(sql_err)?,
        exists: row.get(6).map_err(sql_err)?,
      });
    }
  }
  Ok(accounts)
}

fn missing(name: &str) -> ApiError {
  ApiError::not_found(format!("应用账号 {name} 不存在"))
    .with_hint("用 wharf sso account list 查看现有账号")
}

fn account(
  conn: &Connection,
  name: &str,
) -> Result<AppAccountView, ApiError> {
  views(conn, Some(name))?.pop().ok_or_else(|| missing(name))
}

pub async fn list(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<Vec<AppAccountView>> {
  auth.require(Perm::Admin)?;
  Ok(Json(s.db.call(|c| views(c, None)).await?))
}

pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<AppAccountView> {
  auth.require(Perm::Admin)?;
  Ok(Json(s.db.call(move |c| account(c, &name)).await?))
}

#[derive(Deserialize)]
pub struct SetAccount {
  username: String,
  password: Option<String>,
  note: Option<String>,
}

pub async fn set(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(req): Json<SetAccount>,
) -> ApiResult<AppAccountView> {
  auth.require(Perm::Admin)?;
  validate_name("应用账号", &name)?;
  if req.username.is_empty() || req.password.as_deref() == Some("") {
    return Err(ApiError::invalid("用户名和密码都不能为空").into());
  }
  let view = s.db.call_credentials(move |c, key| {
    let tx = c.transaction().map_err(sql_err)?;
    let now = now_ms();
    if let Some(password) = req.password {
      key.put_app_account(&tx, &name, &req.username, &password, req.note.as_deref(), now)?;
    } else if tx.execute(
      "UPDATE app_accounts SET username = ?2, note = COALESCE(?3, note), updated_at = ?4 WHERE name = ?1",
      params![name, req.username, req.note, now],
    ).map_err(sql_err)? == 0 {
      return Err(ApiError::invalid("新建应用账号需要密码").with_hint("输入密码后重试"));
    }
    let view = account(&tx, &name)?;
    tx.commit().map_err(sql_err)?;
    Ok(view)
  }).await?;
  Ok(Json(view))
}

fn delete_account(
  conn: &Connection,
  name: &str,
) -> Result<(), ApiError> {
  let view = account(conn, name)?;
  if !view.domains.is_empty() {
    let hosts: Vec<_> =
      view.domains.iter().map(|d| d.hostname.as_str()).collect();
    return Err(
      ApiError::invalid(format!(
        "应用账号 {name} 仍关联域名 {}",
        hosts.join("、")
      ))
      .with_hint(format!(
        "先对关联域名运行 wharf sso account unlink {name} <域名>"
      )),
    );
  }
  conn
    .execute("DELETE FROM app_accounts WHERE name = ?1", [name])
    .map_err(sql_err)?;
  Ok(())
}

pub async fn remove(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<Value> {
  auth.require(Perm::Admin)?;
  s.db.call(move |c| delete_account(c, &name)).await?;
  Ok(Json(json!({"removed": true})))
}

#[derive(Deserialize)]
pub struct LinkAccount {
  #[serde(default)]
  is_default: bool,
}

pub async fn link(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((name, host)): Path<(String, String)>,
  Json(req): Json<LinkAccount>,
) -> ApiResult<AppAccountView> {
  auth.require(Perm::Admin)?;
  let host = normalize_hostname(&host)?;
  let view = s.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    account(&tx, &name)?;
    let exists = tx.query_row(
      "SELECT EXISTS (SELECT 1 FROM resources WHERE kind = 'route' AND name = ?1)",
      [&host],
      |r| r.get::<_, bool>(0),
    ).map_err(sql_err)?;
    if !exists {
      return Err(ApiError::not_found(format!("域名 {host} 不存在")).with_hint("用 wharf route list 查看现有域名"));
    }
    if req.is_default {
      tx.execute("UPDATE app_account_domains SET is_default = 0 WHERE hostname = ?1 AND is_default = 1", [&host]).map_err(sql_err)?;
    }
    tx.execute(
      "INSERT INTO app_account_domains (account, hostname, is_default) VALUES (?1, ?2, ?3)
       ON CONFLICT (account, hostname) DO UPDATE SET is_default = MAX(app_account_domains.is_default, excluded.is_default)",
      params![name, host, req.is_default],
    ).map_err(sql_err)?;
    let view = account(&tx, &name)?;
    tx.commit().map_err(sql_err)?;
    Ok(view)
  }).await?;
  Ok(Json(view))
}

pub async fn unlink(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path((name, host)): Path<(String, String)>,
) -> ApiResult<AppAccountView> {
  auth.require(Perm::Admin)?;
  let host = normalize_hostname(&host)?;
  Ok(Json(s.db.call(move |c| {
    c.execute("DELETE FROM app_account_domains WHERE account = ?1 AND hostname = ?2", params![name, host]).map_err(sql_err)?;
    account(c, &name)
  }).await?))
}

#[derive(Deserialize)]
pub struct RevealRequest {
  password: Option<String>,
}

async fn verify_reveal(
  state: &AppState,
  headers: &HeaderMap,
  auth: &Auth,
  peer: SocketAddr,
  password: Option<String>,
) -> Result<(), ApiError> {
  let Some((_, hash)) = login::admin(&state.db).await? else {
    return Err(ApiError::new(ErrorCode::Forbidden, "还没有设置 Wharf 管理员登录密码")
      .with_hint("打开控制面页面并用初始化码设置，或在控制面服务器运行 docker exec -it wharf-core wharf-core reset-password"));
  };
  let session = auth
    .human
    .then(|| login::cookie_value(headers).map(hash_token))
    .flatten();
  let Some(password) = password.filter(|p| !p.is_empty()) else {
    let mut verified =
      VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    verified.retain(|_, until| *until > Instant::now());
    if session.as_ref().is_some_and(|id| verified.contains_key(id)) {
      return Ok(());
    }
    return Err(ApiError::new(
      ErrorCode::PasswordRequired,
      "请验证 Wharf 登录密码",
    ));
  };
  let key = login::client_key(peer.ip(), headers);
  if let Some(minutes) = login::locked(&key) {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      format!("输错次数太多，{minutes} 分钟后再试"),
    ));
  }
  if !tokio::task::spawn_blocking(move || {
    login::verify_password(&password, &hash)
  })
  .await
  .map_err(|_| ApiError::internal("验证登录密码失败"))?
  {
    login::record_failure(&key);
    tokio::time::sleep(Duration::from_secs(1)).await;
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "Wharf 登录密码不对",
    ));
  }
  login::clear_failures(&key);
  if let Some(session) = session {
    let mut verified =
      VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    verified.retain(|_, until| *until > now);
    verified.insert(session, now + REVEAL_TTL);
  }
  Ok(())
}

pub async fn reveal(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Extension(audit): Extension<AuditSlot>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  Path(name): Path<String>,
  headers: HeaderMap,
  req: Option<Json<RevealRequest>>,
) -> Result<
  ([(header::HeaderName, HeaderValue); 1], Json<Value>),
  AppError,
> {
  auth.require(Perm::Admin)?;
  validate_name("应用账号", &name)?;
  if let Err(error) = verify_reveal(
    &s,
    &headers,
    &auth,
    peer,
    req.and_then(|Json(req)| req.password),
  )
  .await
  {
    audit.set_detail(format!(
      "查看应用账号 {name} 的密码被拒绝：{}",
      error.message
    ));
    return Err(error.into());
  }
  let detail = format!("查看了应用账号 {name} 的密码");
  let password: String = s
    .db
    .call_credentials(move |c, key| {
      key.app_password(c, &name)?.ok_or_else(|| missing(&name))
    })
    .await?;
  audit.require_record(detail);
  Ok((
    [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
    Json(json!({"password": password})),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn reveal_rejects_missing_and_incorrect_passwords() {
    use axum::{
      body::Body,
      http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let state = Arc::new(AppState {
      db: crate::db::Db::memory(),
      hub: Default::default(),
      key: ed25519_dalek::SigningKey::from_bytes(&[0; 32]),
      runs: Default::default(),
      apply_lock: Default::default(),
      public_url: None,
      agent_image: String::new(),
      listen_port: 7700,
      data_dir: Default::default(),
      downloads: Default::default(),
      edge_syncing: Default::default(),
    });
    state
      .db
      .call_credentials(|c, key| {
        crate::auth::insert_token(
          c,
          "fixture",
          &Perm::ALL,
          "fixture-token",
        )?;
        key.put_app_account(
          c,
          "example",
          "fixture-user",
          "fixture-value",
          None,
          0,
        )?;
        Ok(())
      })
      .await
      .unwrap();
    let app = crate::api::router(state.clone());
    let request = |body: &'static str| {
      app.clone().oneshot(
        Request::post("/api/sso/accounts/example/password")
          .header(header::CONTENT_TYPE, "application/json")
          .header(header::AUTHORIZATION, "Bearer fixture-token")
          .extension(ConnectInfo(
            "127.0.0.20:1234".parse::<SocketAddr>().unwrap(),
          ))
          .body(Body::from(body))
          .unwrap(),
      )
    };
    let unset = request("{}").await.unwrap();
    assert_eq!(unset.status(), StatusCode::FORBIDDEN);
    let body =
      axum::body::to_bytes(unset.into_body(), 4096).await.unwrap();
    assert!(
      serde_json::from_slice::<ApiError>(&body)
        .unwrap()
        .hint
        .is_some()
    );
    state
      .db
      .call(|c| {
        login::set_admin(
          c,
          "admin",
          &login::hash_password("fixture-wharf")?,
        )
      })
      .await
      .unwrap();
    for body in ["{}", r#"{"password":"fixture-wrong"}"#] {
      assert_eq!(
        request(body).await.unwrap().status(),
        StatusCode::FORBIDDEN
      );
    }
  }

  #[tokio::test]
  async fn linked_account_cannot_be_deleted() {
    crate::db::Db::memory().call(|c| {
      c.execute_batch(
        "INSERT INTO app_accounts (name, username, password, updated_at) VALUES ('x', 'fixture', 'fixture', 0);
         INSERT INTO app_account_domains (account, hostname) VALUES ('x', 'app.example.com');",
      ).unwrap();
      let error = delete_account(c, "x").unwrap_err();
      assert!(error.message.contains("app.example.com"));
      assert!(error.hint.unwrap().contains("wharf sso account unlink"));
      assert!(account(c, "x").is_ok());
      Ok(())
    }).await.unwrap();
  }
}
