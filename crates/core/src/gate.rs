//! 门禁凭据与一次性票据；页面会话仍是唯一的登录状态。
use crate::{
  api::AppError,
  auth::{Auth, hash_token, new_token},
  db::{self, Db, now_ms, sql_err},
  state::AppState,
};
use axum::{
  extract::{ConnectInfo, Path, Query, State},
  http::{HeaderMap, header},
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use std::{
  collections::BTreeMap,
  sync::{Arc, LazyLock, Mutex, OnceLock},
};
use wharf_api_types::{
  ApiError, validate_name,
  view::{GateKeyRequest, GateKeyView, Perm},
};

mod credentials;
mod paths;
pub(crate) mod revocations;
use credentials::{
  access_cookie, credential_host, rt_parse, rt_sign, rt_user,
};
use paths::{login_rd, rd_url, site_gate_rd};
pub(crate) use paths::{
  normalize_skip_path, site_endpoints, takeover_path,
};

// 同步渲染只读的启动参数和公钥，不保存私钥。
static RENDER: OnceLock<(String, u16, Option<String>, bool)> =
  OnceLock::new();
static TICKETS: LazyLock<Mutex<BTreeMap<String, Ticket>>> =
  LazyLock::new(|| Mutex::new(BTreeMap::new()));
struct Ticket {
  host: String,
  session_hash: String,
  expires: i64,
}

const RT_SEED: &str = "gate.rt_key";

#[cfg(test)]
pub(crate) fn fixture_ticket(insert: bool) -> bool {
  let mut tickets = TICKETS.lock().unwrap_or_else(|e| e.into_inner());
  if insert {
    tickets.insert(
      "revoke-all-fixture".into(),
      Ticket {
        host: "a.example.test".into(),
        session_hash: "fixture-session".into(),
        expires: i64::MAX,
      },
    );
  }
  tickets.contains_key("revoke-all-fixture")
}

pub(crate) fn clear_tickets() {
  TICKETS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

pub(crate) fn rotate_seed(
  c: &rusqlite::Connection,
  name: &str,
) -> Result<(), ApiError> {
  let mut seed = [0; 32];
  getrandom::fill(&mut seed)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  db::set_setting(c, name, Some(&hex::encode(seed)))
}

pub(crate) fn seed(
  c: &rusqlite::Connection,
  name: &str,
) -> Result<[u8; 32], ApiError> {
  let text = match db::setting(c, name)? {
    Some(text) => text,
    None => {
      rotate_seed(c, name)?;
      db::setting(c, name)?
        .ok_or_else(|| ApiError::internal("门禁密钥未保存"))?
    }
  };
  hex::decode(text)
    .ok()
    .and_then(|b| b.try_into().ok())
    .ok_or_else(|| ApiError::internal("门禁密钥格式不对"))
}
async fn key(db: &Db) -> Result<SigningKey, ApiError> {
  db.call(|c| Ok(SigningKey::from_bytes(&seed(c, "gate.key")?)))
    .await
}
pub(crate) async fn probe_cookie(
  db: &Db,
  host: &str,
) -> Option<axum::http::HeaderValue> {
  let seed = db.call(|c| db::setting(c, "gate.key")).await.ok()??;
  let seed = hex::decode(seed).ok()?.try_into().ok()?;
  let key = SigningKey::from_bytes(&seed);
  let token = credentials::probe_token(&key, host, now_ms() / 1000);
  let mut cookie =
    axum::http::HeaderValue::from_str(&format!("wharf_gate={token}"))
      .ok()?;
  cookie.set_sensitive(true);
  Some(cookie)
}

async fn rt_key(db: &Db) -> Result<[u8; 32], ApiError> {
  db.call(|c| seed(c, RT_SEED)).await
}
pub async fn init(
  s: &AppState,
  loopback_only: bool,
) -> Result<(), ApiError> {
  let public = public_b64(&key(&s.db).await?);
  RENDER
    .set((public, s.listen_port, s.public_url.clone(), loopback_only))
    .map_err(|_| ApiError::internal("门禁重复初始化"))
}
pub(crate) fn core_listener() -> Option<(u16, bool)> {
  RENDER
    .get()
    .map(|(_, port, _, loopback)| (*port, *loopback))
}

pub(crate) fn public_url() -> Option<&'static str> {
  RENDER.get()?.2.as_deref()
}

pub fn render_context(
  world: &crate::world::World,
  net: &crate::render::Net,
) -> (Option<String>, Option<String>) {
  if !world.routes.values().any(|r| r.spec.sso.is_some()) {
    return (None, None);
  }
  let Some((public, port, fallback, _)) = RENDER.get() else {
    return (None, None);
  };
  let login = crate::join::route_urls(world, net, *port)
    .into_iter()
    .next()
    .or_else(|| fallback.clone());
  (Some(public.clone()), login)
}
pub fn is_core_host(
  world: &crate::world::World,
  net: &crate::render::Net,
  host: &str,
) -> bool {
  RENDER.get().is_some_and(|(_, port, _, _)| {
    world.routes.get(host).is_some_and(|route| {
      crate::join::is_core_route(world, net, &route.spec, *port)
    })
  })
}
fn public_b64(key: &SigningKey) -> String {
  STANDARD.encode(key.verifying_key().to_bytes())
}
pub(crate) async fn session(
  db: &Db,
  hash: String,
) -> Result<Option<(String, i64)>, ApiError> {
  db.call(move |c| c.query_row("SELECT a.username, s.expires_at FROM sessions s, admin a WHERE s.hash=?1 AND s.expires_at>?2 AND a.id=1",params![hash, now_ms()],|r| Ok((r.get(0)?,r.get::<_,i64>(1)?/1000))).optional().map_err(sql_err)).await
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
  headers
    .get_all(header::COOKIE)
    .iter()
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(';'))
    .find_map(|p| {
      p.trim()
        .split_once('=')
        .filter(|(k, v)| *k == name && !v.is_empty())
        .map(|(_, v)| v)
    })
}
fn response(
  status: u16,
  location: Option<&str>,
  body: &str,
  cookies: &[String],
) -> Response {
  let mut r = (
    axum::http::StatusCode::from_u16(status).unwrap(),
    body.to_string(),
  )
    .into_response();
  r.headers_mut()
    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
  if let Some(location) = location
    && let Ok(value) = location.parse()
  {
    r.headers_mut().insert(header::LOCATION, value);
  }
  for cookie in cookies {
    r.headers_mut()
      .append(header::SET_COOKIE, cookie.parse().unwrap());
  }
  r
}
fn gate_cookie(name: &str, value: &str, age: i64) -> String {
  format!(
    "{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={age}"
  )
}
fn take_ticket(
  tickets: &mut BTreeMap<String, Ticket>,
  code: &str,
  host: &str,
  now: i64,
) -> Option<Ticket> {
  tickets
    .remove(code)
    .filter(|t| t.host == host && t.expires > now)
}
#[derive(Deserialize)]
pub struct LoginQuery {
  rd: String,
  hop: Option<String>,
  silent: Option<String>,
  native: Option<String>,
}
fn login_path(rd: &str) -> String {
  format!(
    "/gate/login?{}",
    reqwest::Url::parse_with_params(
      "https://example.test",
      [("rd", rd)]
    )
    .unwrap()
    .query()
    .unwrap()
  )
}

fn silent_native(
  world: &crate::world::World,
  url: &reqwest::Url,
  rd: &str,
) -> Option<reqwest::Url> {
  use crate::sso_login::takeover_matches;
  use wharf_api_types::spec::SsoMode;
  let config =
    world.routes.get(url.host_str()?)?.spec.sso.as_ref()?;
  let takeover = config.login.as_ref()?.takeover.as_ref()?;
  if !config.public
    || config.mode != SsoMode::Login
    || url.path() != "/_wharf/login"
    || !takeover_matches(&takeover_path(rd)?, &takeover.paths)
  {
    return None;
  }
  let mut target = url.clone();
  target.set_path("/_wharf/native");
  target.set_query(None);
  target.set_fragment(None);
  target.query_pairs_mut().append_pair("rd", rd);
  Some(target)
}

pub async fn login(
  State(s): State<Arc<AppState>>,
  Query(q): Query<LoginQuery>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let snap = crate::snapshot::load(&s.db).await?;
  let Some(url) = rd_url(&snap.world, &q.rd) else {
    return Ok(response(400, None, "跳转地址不对", &[]));
  };
  let native_target = if q.silent.as_deref() == Some("1") {
    let Some(target) = q
      .native
      .as_deref()
      .and_then(|rd| silent_native(&snap.world, &url, rd))
    else {
      return Ok(response(400, None, "原生登录地址不对", &[]));
    };
    Some(target)
  } else {
    None
  };
  if let Some(user) = crate::login::session_user(&s, &headers).await?
  {
    let hash =
      hash_token(crate::login::cookie_value(&headers).unwrap());
    let code = new_token();
    let now = now_ms() / 1000;
    {
      let mut tickets =
        TICKETS.lock().unwrap_or_else(|e| e.into_inner());
      tickets.retain(|_, t| t.expires > now);
      if tickets.len() >= 1000 {
        return Ok(response(
          503,
          None,
          "登录请求太多，稍后重试",
          &[],
        ));
      }
      tickets.insert(
        code.clone(),
        Ticket {
          host: url.host_str().unwrap().into(),
          session_hash: hash,
          expires: now + 60,
        },
      );
    }
    let mut target = url.clone();
    target.set_path("/_wharf/gate");
    target.set_query(None);
    target.set_fragment(None);
    let rd = format!(
      "{}{}",
      url.path(),
      url.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    target
      .query_pairs_mut()
      .append_pair("code", &code)
      .append_pair("rd", &rd);
    let host = url.host_str().unwrap().to_string();
    s.db.call(move|c|{c.execute("INSERT INTO audit_log (at,kind,actor,method,path) VALUES (?1,'login',?2,'gate',?3)",params![now_ms(),user,host]).map_err(sql_err)?;Ok(())}).await?;
    return Ok(response(302, Some(target.as_str()), "", &[]));
  }
  let mut path = login_path(&q.rd);
  if let Some(target) = &native_target {
    if q.hop.as_deref() == Some("1") {
      return Ok(response(302, Some(target.as_str()), "", &[]));
    }
    path.push_str("&silent=1&native=");
    path.push_str(&urlencoding::encode(q.native.as_deref().unwrap()));
  }
  if q.hop.as_deref() != Some("1") {
    let target = format!("{path}&hop=1")
      .replace('&', "&amp;")
      .replace('"', "&quot;");
    let mut r = response(
      200,
      None,
      &format!(
        "<meta http-equiv=\"refresh\" content=\"0;url={target}\">正在跳转…"
      ),
      &[],
    );
    r.headers_mut().insert(
      header::CONTENT_TYPE,
      "text/html; charset=utf-8".parse().unwrap(),
    );
    return Ok(r);
  }
  let next = reqwest::Url::parse_with_params(
    "https://example.test/login",
    [("next", path)],
  )
  .unwrap();
  Ok(response(
    302,
    Some(&format!("/login?{}", next.query().unwrap())),
    "",
    &[],
  ))
}
#[derive(Deserialize)]
pub struct SiteQuery {
  code: String,
  rd: Option<String>,
}
pub async fn site_gate(
  State(s): State<Arc<AppState>>,
  Query(q): Query<SiteQuery>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let Some(host) = credential_host(peer.ip(), &headers) else {
    return Ok(response(403, None, "请求未经过可信网关", &[]));
  };
  let now = now_ms() / 1000;
  let ticket = take_ticket(
    &mut TICKETS.lock().unwrap_or_else(|e| e.into_inner()),
    &q.code,
    &host,
    now,
  );
  let expired =
    || response(400, None, "登录链接已经过期，重新打开页面", &[]);
  let Some(ticket) = ticket else {
    return Ok(expired());
  };
  let Some((user, exp)) =
    session(&s.db, ticket.session_hash.clone()).await?
  else {
    return Ok(expired());
  };
  let cookies = vec![
    access_cookie(&key(&s.db).await?, &user, &ticket.host, now),
    gate_cookie(
      "wharf_gate_rt",
      &rt_sign(
        &rt_key(&s.db).await?,
        &ticket.session_hash,
        &ticket.host,
        exp,
      ),
      exp - now,
    ),
  ];
  Ok(response(
    302,
    Some(site_gate_rd(q.rd.as_deref().unwrap_or("/"))),
    "",
    &cookies,
  ))
}
pub async fn refresh(
  State(s): State<Arc<AppState>>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let Some(host) = credential_host(peer.ip(), &headers) else {
    return Ok(response(401, None, "{\"error\":\"需要登录\"}", &[]));
  };
  let now = now_ms() / 1000;
  let rt_key = rt_key(&s.db).await?;
  if let Some(hash) = cookie(&headers, "wharf_gate_rt")
    .and_then(|t| rt_parse(&rt_key, t, &host, now))
    && let Some((user, _)) = session(&s.db, hash).await?
  {
    let mut r = response(
      200,
      None,
      "",
      &[access_cookie(&key(&s.db).await?, &user, &host, now)],
    );
    if let Ok(value) = user.parse() {
      r.headers_mut().insert("X-Wharf-User", value);
    }
    return Ok(r);
  }
  let cookies = [gate_cookie("wharf_gate_rt", "", 0)];
  if let Some(rd) =
    credentials::refresh_return_url(peer.ip(), &headers, &host)
  {
    let login =
      crate::join::default_url(&s).await.unwrap_or_default();
    Ok(response(
      302,
      Some(&format!("{login}{}", login_path(&rd))),
      "",
      &cookies,
    ))
  } else {
    Ok(response(401, None, "{\"error\":\"需要登录\"}", &cookies))
  }
}
fn storage_page(
  values: &[(bool, String, String)],
  rd: &str,
) -> String {
  let js = |s: &str| {
    serde_json::to_string(s).unwrap().replace('<', "\\u003c")
  };
  let mut script = String::new();
  for (local, key, value) in values {
    script.push_str(&format!(
      "{}Storage.setItem({},{});",
      if *local { "local" } else { "session" },
      js(key),
      js(value)
    ));
  }
  format!(
    "<!doctype html><meta charset=\"utf-8\"><script>{script}location.replace({});</script><noscript>需要开启脚本才能自动登录</noscript>",
    js(rd)
  )
}
#[derive(Deserialize)]
pub struct SiteLoginQuery {
  rd: Option<String>,
}
pub async fn site_login(
  State(s): State<Arc<AppState>>,
  Query(q): Query<SiteLoginQuery>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  use wharf_api_types::spec::{LoginWrite, SsoMode};
  let Some(host) = credential_host(peer.ip(), &headers) else {
    return Ok(response(403, None, "请求未经过可信网关", &[]));
  };
  let snap = crate::snapshot::load(&s.db).await?;
  let Some(route) = snap.world.routes.get(&host) else {
    return Ok(response(404, None, "域名没有配置代登录", &[]));
  };
  let Some(login) = route
    .spec
    .sso
    .as_ref()
    .filter(|s| s.mode == SsoMode::Login)
    .and_then(|s| s.login.as_ref())
  else {
    return Ok(response(404, None, "域名没有配置代登录", &[]));
  };
  let rd = if login.takeover.is_some() {
    crate::sso_login::takeover_rd(login, q.rd.as_deref())
  } else {
    login_rd(
      q.rd.as_deref().or(login.entry.as_deref()).unwrap_or("/"),
    )
  };
  let signing = key(&s.db).await?;
  let authenticated =
    revocations::access_user(&s.db, &signing, &headers, &host)
      .await?
      .is_some()
      || rt_user(&s.db, &headers, &host).await?.is_some();
  if !authenticated {
    let target = format!(
      "https://{host}/_wharf/login?rd={}",
      urlencoding::encode(rd)
    );
    let core = crate::join::default_url(&s).await.unwrap_or_default();
    return Ok(response(
      302,
      Some(&format!("{core}{}", login_path(&target))),
      "",
      &[],
    ));
  }
  let secrets = crate::secret_policy::login_secrets(
    &snap.world,
    &route.spec,
    &snap.secrets,
  );
  let outcome = crate::sso_login::run(&s, &host).await;
  let mut cookies = Vec::new();
  let mut storage = Vec::new();
  let result = (|| -> Result<bool, ApiError> {
    let outcome = outcome.as_ref().map_err(|e| e.clone())?;
    if !outcome.ok {
      return Ok(false);
    }
    let scripted = outcome.script_log.is_some();
    if scripted != login.script.is_some() {
      return Err(ApiError::invalid("代登录配置已改变"));
    }
    let writes = if scripted {
      cookies.extend(outcome.set_cookies.clone());
      storage.extend(outcome.script_storage.clone());
      &[]
    } else {
      login.write.as_slice()
    };
    for write in writes {
      match write {
        LoginWrite::Cookies(_) => {
          cookies.extend(outcome.set_cookies.clone())
        }
        LoginWrite::Cookie {
          name,
          value,
          http_only,
        } => {
          let value =
            crate::sso_login::render(value, &outcome.vars, &secrets)?;
          cookies.push(crate::sso_login::cookie_header(
            name, &value, *http_only,
          )?);
        }
        LoginWrite::LocalStorage { key, value }
        | LoginWrite::SessionStorage { key, value } => {
          storage.push((
            matches!(write, LoginWrite::LocalStorage { .. }),
            key.clone(),
            crate::sso_login::render(value, &outcome.vars, &secrets)?,
          ))
        }
      }
    }
    if cookies
      .iter()
      .any(|v| v.parse::<axum::http::HeaderValue>().is_err())
    {
      return Err(ApiError::invalid("应用 cookie 格式不对"));
    }
    Ok(true)
  })();
  let ok = result.as_ref().is_ok_and(|ok| *ok);
  // 执行器已记录步骤结果；交接失败也覆盖最近状态，不保存任何值。
  if let Err(e) = result
    && outcome.is_ok()
  {
    crate::sso_login::record(&s, &host, false, Some(e.message))
      .await?;
  }
  if !ok {
    let age = std::env::var("WHARF_SSO_FAIL_SECS")
      .ok()
      .and_then(|s| s.parse::<i64>().ok())
      .filter(|n| *n > 0 && *n <= 300)
      .unwrap_or(300);
    return Ok(response(
      302,
      Some(rd),
      "",
      &[gate_cookie("wharf_sso", "fail", age)],
    ));
  }
  cookies.push(gate_cookie(
    "wharf_sso",
    "1",
    i64::from(login.ttl_hours) * 3600,
  ));
  if storage.is_empty() {
    return Ok(response(302, Some(rd), "", &cookies));
  }
  let mut response =
    response(200, None, &storage_page(&storage, rd), &cookies);
  response.headers_mut().insert(
    header::CONTENT_TYPE,
    "text/html; charset=utf-8".parse().unwrap(),
  );
  Ok(response)
}

pub async fn site_logout() -> Response {
  response(
    200,
    None,
    "已退出",
    &[
      gate_cookie("wharf_gate", "", 0),
      gate_cookie("wharf_gate_rt", "", 0),
    ],
  )
}

pub fn trusted_ranges(
  net: &crate::render::Net,
  server: &str,
) -> Vec<String> {
  crate::source_trust::gate_trusted_ranges(net, server)
}

pub async fn list_keys(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> Result<axum::Json<Vec<GateKeyView>>, AppError> {
  auth.require(Perm::Admin)?;
  Ok(axum::Json(s.db.call(|c| {
    let mut stmt = c.prepare("SELECT name, hosts, created_at, last_used_at FROM gate_keys ORDER BY name").map_err(sql_err)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?,r.get::<_, i64>(2)?,r.get::<_, Option<i64>>(3)?))).map_err(sql_err)?;
    rows.map(|r| {
      let (name, hosts, created_at, last_used_at) = r.map_err(sql_err)?;
      Ok(GateKeyView { name, hosts: serde_json::from_str(&hosts).map_err(|_| ApiError::internal("访问凭证域名格式不对"))?, created_at, last_used_at })
    }).collect()
  }).await?))
}

pub async fn put_key(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  axum::Json(req): axum::Json<GateKeyRequest>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
  auth.require(Perm::Admin)?;
  validate_name("访问凭证", &name)?;
  if req.hosts.is_empty() {
    return Err(ApiError::invalid("至少选一个域名").into());
  }
  let world = crate::snapshot::load(&s.db).await?.world;
  for host in &req.hosts {
    if world
      .routes
      .get(host)
      .and_then(|r| r.spec.sso.as_ref())
      .is_none_or(|s| !s.gated())
    {
      return Err(
        ApiError::invalid(format!("域名 {host} 没开门禁")).into(),
      );
    }
  }
  Ok(axum::Json(s.db.call(move |c| {
    let hosts = serde_json::to_string(&req.hosts).map_err(|_| ApiError::internal("访问凭证域名格式不对"))?;
    let tx = c.unchecked_transaction().map_err(sql_err)?;
    let changed = tx.execute("UPDATE gate_keys SET hosts=?2 WHERE name=?1", params![name,hosts]).map_err(sql_err)?;
    let mut result = json!({"name":name,"hosts":req.hosts});
    if changed == 0 {
      let key = format!("wgk_{}", new_token());
      tx.execute("INSERT INTO gate_keys (name,hash,hosts,created_at) VALUES (?1,?2,?3,?4)",params![name,hash_token(&key),hosts,now_ms()]).map_err(sql_err)?;
      result["key"] = key.into();
    }
    tx.commit().map_err(sql_err)?;
    Ok(result)
  }).await?))
}

pub async fn remove_key(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
  auth.require(Perm::Admin)?;
  let removed = s
    .db
    .call(move |c| {
      c.execute("DELETE FROM gate_keys WHERE name=?1", [name])
        .map_err(sql_err)
    })
    .await?;
  Ok(axum::Json(json!({"removed":removed > 0})))
}

fn key_allowed(
  c: &rusqlite::Connection,
  key: &str,
  host: &str,
  now: i64,
) -> Result<bool, ApiError> {
  let hash = hash_token(key);
  let hosts: Option<String> = c
    .query_row(
      "SELECT hosts FROM gate_keys WHERE hash=?1",
      [&hash],
      |r| r.get(0),
    )
    .optional()
    .map_err(sql_err)?;
  let allowed = hosts
    .and_then(|h| serde_json::from_str::<Vec<String>>(&h).ok())
    .is_some_and(|h| h.iter().any(|h| h == host));
  if allowed {
    c.execute("UPDATE gate_keys SET last_used_at=?2 WHERE hash=?1 AND (last_used_at IS NULL OR last_used_at<=?2-60000)",params![hash,now]).map_err(sql_err)?;
  }
  Ok(allowed)
}

pub async fn check_key(
  State(s): State<Arc<AppState>>,
  ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  use crate::lockout::{self, LockScope};

  let Some(host) = credential_host(peer.ip(), &headers) else {
    return Ok(response(403, None, "请求未经过可信网关", &[]));
  };

  let source = crate::login::client_key(peer.ip(), &headers);
  if lockout::locked(LockScope::GateKey, &source).is_some() {
    tracing::warn!(source = %source, "门禁访问凭证来源已锁定");
    return Ok(response(
      401,
      None,
      "{\"error\":\"访问凭证无效\"}",
      &[],
    ));
  }
  let key = headers
    .get("x-wharf-key")
    .and_then(|v| v.to_str().ok())
    .unwrap_or_default()
    .to_string();
  let key_host = host.clone();
  if s
    .db
    .call(move |c| key_allowed(c, &key, &key_host, now_ms()))
    .await?
  {
    lockout::clear(LockScope::GateKey, &source);
    return Ok(response(200, None, "", &[]));
  }
  lockout::record_and_notify(
    &s,
    LockScope::GateKey,
    &source,
    Some(&host),
  )
  .await;
  crate::audit::login_event(&s, "gate_key_failed", &host, source)
    .await;
  tokio::time::sleep(std::time::Duration::from_millis(200)).await;
  Ok(response(401, None, "{\"error\":\"访问凭证无效\"}", &[]))
}

#[cfg(test)]
mod tests {
  #[test]
  fn login_redirect_path() {
    for bad in
      ["//evil", "/\\evil", "/_wharf/login", "/docs/../index"]
    {
      assert_eq!(super::login_rd(bad), "/");
    }
    assert_eq!(super::login_rd("/a?x=1&y=2"), "/a?x=1&y=2");
    let login = "/_wharf/login?rd=%2Fa";
    assert_eq!(super::site_gate_rd(login), login);
    assert_eq!(super::site_gate_rd("/_wharf/logout"), "/");
  }
  #[test]
  fn storage_script_escape() {
    let page = super::storage_page(
      &[(true, "</script>".into(), "</script>".into())],
      "/</script>",
    );
    assert_eq!(page.matches("</script>").count(), 1);
    assert!(page.contains("\\u003c/script>"));
  }

  use super::*;
  use wharf_api_types::spec::RouteSpec;
  fn world() -> crate::world::World {
    let mut w = crate::world::World::default();
    let spec: RouteSpec = serde_json::from_value(json!({"hostname":"a.example.test","upstream":"127.0.0.1:8080","sso":{"mode":"gate"}})).unwrap();
    w.routes.insert(
      spec.hostname.clone(),
      crate::world::RouteRow {
        id: "r1".into(),
        spec,
        version: 1,
      },
    );
    w
  }
  #[test]
  fn trusted_lan_ranges() {
    let net = crate::render::Net {
      lan_ips: BTreeMap::from([(
        "s1".into(),
        ["203.0.113.7", "10.20.0.5", "172.20.0.1"]
          .map(str::to_string)
          .to_vec(),
      )]),
      docker_subnets: BTreeMap::from([(
        "s1".into(),
        vec!["172.20.0.0/16".into()],
      )]),
      ..Default::default()
    };
    assert_eq!(
      trusted_ranges(&net, "s1"),
      ["10.20.0.0/24", "127.0.0.0/8", "::1/128"]
    );
    assert_eq!(
      trusted_ranges(&net, "s2"),
      ["127.0.0.0/8", "::1/128"]
    );
  }
  fn key_db() -> rusqlite::Connection {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE gate_keys (name TEXT PRIMARY KEY,hash TEXT UNIQUE,hosts TEXT,created_at INTEGER,last_used_at INTEGER);").unwrap();
    c.execute("INSERT INTO gate_keys VALUES ('k1',?1,'[\"a.example.test\"]',0,NULL)",[hash_token("lab-key")]).unwrap();
    c
  }
  #[test]
  fn key_scope_and_last_use() {
    let c = key_db();
    assert!(
      !key_allowed(&c, "wrong", "a.example.test", 100000).unwrap()
    );
    assert!(
      !key_allowed(&c, "lab-key", "b.example.test", 100000).unwrap()
    );
    assert!(
      key_allowed(&c, "lab-key", "a.example.test", 100000).unwrap()
    );
    assert!(
      key_allowed(&c, "lab-key", "a.example.test", 100001).unwrap()
    );
    let used: i64 = c
      .query_row("SELECT last_used_at FROM gate_keys", [], |r| {
        r.get(0)
      })
      .unwrap();
    assert_eq!(used, 100000);
    assert!(
      key_allowed(&c, "lab-key", "a.example.test", 160000).unwrap()
    );
    let used: i64 = c
      .query_row("SELECT last_used_at FROM gate_keys", [], |r| {
        r.get(0)
      })
      .unwrap();
    assert_eq!(used, 160000);
  }
  #[test]
  fn key_revocation_is_immediate() {
    let c = key_db();
    assert!(
      key_allowed(&c, "lab-key", "a.example.test", 100000).unwrap()
    );
    c.execute("DELETE FROM gate_keys", []).unwrap();
    assert!(
      !key_allowed(&c, "lab-key", "a.example.test", 100001).unwrap()
    );
  }
  #[test]
  fn rd_query_roundtrip() {
    let rd = "https://a.example.test/x?a=1&b=2";
    let path = login_path(rd);
    let url = reqwest::Url::parse(&format!(
      "https://core.example.test{path}"
    ))
    .unwrap();
    assert_eq!(
      url.query_pairs().find(|(k, _)| k == "rd").unwrap().1,
      rd
    );
    assert_eq!(
      rd_url(&world(), rd).unwrap().query(),
      Some("a=1&b=2")
    );
    assert_eq!(login_rd("//evil.example"), "/");
    assert_eq!(login_rd("/\\evil.example"), "/");
  }
  #[test]
  fn rd_requires_gate() {
    let mut w = world();
    assert!(rd_url(&w, "https://evil.example/").is_none());
    assert!(rd_url(&w, "http://a.example.test/").is_none());
    let spec = &mut w.routes.get_mut("a.example.test").unwrap().spec;
    let sso = spec.sso.as_mut().unwrap();
    sso.mode = wharf_api_types::spec::SsoMode::Oidc;
    sso.public = true;
    assert!(rd_url(&w, "https://a.example.test/").is_none());
    w.routes.get_mut("a.example.test").unwrap().spec.sso = None;
    assert!(rd_url(&w, "https://a.example.test/").is_none());
  }
  #[test]
  fn ticket_once_and_host_bound() {
    let mut tickets = BTreeMap::new();
    let add = |tickets: &mut BTreeMap<_, _>| {
      tickets.insert(
        "code".into(),
        Ticket {
          host: "a.example.test".into(),
          session_hash: "hash".into(),
          expires: 100,
        },
      );
    };
    add(&mut tickets);
    assert!(
      take_ticket(&mut tickets, "code", "b.example.test", 1)
        .is_none()
    );
    assert!(
      take_ticket(&mut tickets, "code", "a.example.test", 1)
        .is_none()
    );
    add(&mut tickets);
    assert!(
      take_ticket(&mut tickets, "code", "a.example.test", 1)
        .is_some()
    );
    assert!(
      take_ticket(&mut tickets, "code", "a.example.test", 1)
        .is_none()
    );
    add(&mut tickets);
    assert!(
      take_ticket(&mut tickets, "code", "a.example.test", 100)
        .is_none()
    );
  }
}
