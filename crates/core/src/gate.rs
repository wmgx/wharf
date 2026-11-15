//! 门禁凭据与一次性票据；页面会话仍是唯一的登录状态。
use crate::{
  api::AppError,
  auth::{hash_token, new_token},
  db::{self, Db, now_ms, sql_err},
  state::AppState,
};
use axum::{
  extract::{Query, State},
  http::{HeaderMap, header},
  response::{IntoResponse, Response},
};
use base64::{
  Engine,
  engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::{
  collections::BTreeMap,
  sync::{Arc, LazyLock, Mutex, OnceLock},
};
use wharf_api_types::ApiError;

const ACCESS_TTL: i64 = 600;
// 同步渲染只读的启动参数和公钥，不保存私钥。
static RENDER: OnceLock<(String, u16, Option<String>)> =
  OnceLock::new();
static TICKETS: LazyLock<Mutex<BTreeMap<String, Ticket>>> =
  LazyLock::new(|| Mutex::new(BTreeMap::new()));
struct Ticket {
  host: String,
  session_hash: String,
  expires: i64,
}

fn seed(
  c: &rusqlite::Connection,
  name: &str,
) -> Result<[u8; 32], ApiError> {
  let text = match db::setting(c, name)? {
    Some(text) => text,
    None => {
      let mut seed = [0; 32];
      getrandom::fill(&mut seed)
        .map_err(|_| ApiError::internal("随机数不可用"))?;
      let text = hex::encode(seed);
      db::set_setting(c, name, Some(&text))?;
      text
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
async fn rt_key(db: &Db) -> Result<[u8; 32], ApiError> {
  db.call(|c| seed(c, "gate.rt_key")).await
}
pub async fn init(s: &AppState) -> Result<(), ApiError> {
  let public = public_b64(&key(&s.db).await?);
  RENDER
    .set((public, s.listen_port, s.public_url.clone()))
    .map_err(|_| ApiError::internal("门禁重复初始化"))
}
pub fn render_context(
  world: &crate::world::World,
  net: &crate::render::Net,
) -> (Option<String>, Option<String>) {
  if !world.routes.values().any(|r| r.spec.sso.is_some()) {
    return (None, None);
  }
  let Some((public, port, fallback)) = RENDER.get() else {
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
  RENDER.get().is_some_and(|(_, port, _)| {
    crate::join::route_urls(world, net, *port)
      .iter()
      .any(|url| {
        reqwest::Url::parse(url)
          .ok()
          .is_some_and(|u| u.host_str() == Some(host))
      })
  })
}
fn sign(key: &SigningKey, username: &str, now: i64) -> String {
  sign_ttl(key, username, now, ACCESS_TTL)
}
fn sign_ttl(
  key: &SigningKey,
  username: &str,
  now: i64,
  ttl: i64,
) -> String {
  let header =
    URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
  let claims = URL_SAFE_NO_PAD.encode(
    json!({"iss":"wharf","sub":username,"iat":now,"exp":now+ttl})
      .to_string(),
  );
  let raw = format!("{header}.{claims}");
  format!(
    "{raw}.{}",
    URL_SAFE_NO_PAD.encode(key.sign(raw.as_bytes()).to_bytes())
  )
}
fn public_b64(key: &SigningKey) -> String {
  STANDARD.encode(key.verifying_key().to_bytes())
}
fn rt_sign(key: &[u8], hash: &str, exp: i64) -> String {
  let raw = format!("{hash}.{exp}");
  let mut mac = Hmac::<Sha256>::new_from_slice(key)
    .expect("HMAC 接受任意长度密钥");
  mac.update(raw.as_bytes());
  format!(
    "{raw}.{}",
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
  )
}
fn rt_parse(key: &[u8], text: &str, now: i64) -> Option<String> {
  let (raw, sig) = text.rsplit_once('.')?;
  let (hash, exp) = raw.split_once('.')?;
  if hash.len() != 64
    || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    || exp.parse::<i64>().ok()? <= now
  {
    return None;
  }
  let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
  mac.update(raw.as_bytes());
  mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).ok()?).ok()?;
  Some(hash.into())
}
async fn session(
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
fn access_cookie(key: &SigningKey, user: &str, now: i64) -> String {
  // 只给隔离 lab 缩短凭据，不改变正式的十分钟有效期。
  let ttl = std::env::var("WHARF_GATE_ACCESS_SECS")
    .ok()
    .and_then(|v| v.parse::<i64>().ok())
    .filter(|n| *n > 0 && *n <= ACCESS_TTL)
    .unwrap_or(ACCESS_TTL);
  let token = if ttl == ACCESS_TTL {
    sign(key, user, now)
  } else {
    sign_ttl(key, user, now, ttl)
  };
  gate_cookie("wharf_gate", &token, ttl)
}
fn rd_url(
  world: &crate::world::World,
  rd: &str,
) -> Option<reqwest::Url> {
  let url = reqwest::Url::parse(rd).ok()?;
  if url.scheme() != "https"
    || !url.username().is_empty()
    || url.password().is_some()
    || url.port().is_some()
  {
    return None;
  }
  world
    .routes
    .get(url.host_str()?)
    .filter(|r| r.spec.sso.is_some())?;
  Some(url)
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
pub async fn login(
  State(s): State<Arc<AppState>>,
  Query(q): Query<LoginQuery>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let snap = crate::snapshot::load(&s.db).await?;
  let Some(url) = rd_url(&snap.world, &q.rd) else {
    return Ok(response(400, None, "跳转地址不对", &[]));
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
  let path = login_path(&q.rd);
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
fn forwarded_host(headers: &HeaderMap) -> &str {
  headers
    .get("x-forwarded-host")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("")
    .split(':')
    .next()
    .unwrap_or("")
}
fn safe_path(rd: &str) -> &str {
  if rd.starts_with('/')
    && !rd.starts_with("//")
    && !rd.contains(['\\', '\r', '\n'])
  {
    rd
  } else {
    "/"
  }
}
pub async fn site_gate(
  State(s): State<Arc<AppState>>,
  Query(q): Query<SiteQuery>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let now = now_ms() / 1000;
  let ticket = take_ticket(
    &mut TICKETS.lock().unwrap_or_else(|e| e.into_inner()),
    &q.code,
    forwarded_host(&headers),
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
    access_cookie(&key(&s.db).await?, &user, now),
    gate_cookie(
      "wharf_gate_rt",
      &rt_sign(&rt_key(&s.db).await?, &ticket.session_hash, exp),
      exp - now,
    ),
  ];
  Ok(response(
    302,
    Some(safe_path(q.rd.as_deref().unwrap_or("/"))),
    "",
    &cookies,
  ))
}
pub async fn refresh(
  State(s): State<Arc<AppState>>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let now = now_ms() / 1000;
  let rt_key = rt_key(&s.db).await?;
  if let Some(hash) = cookie(&headers, "wharf_gate_rt")
    .and_then(|t| rt_parse(&rt_key, t, now))
    && let Some((user, _)) = session(&s.db, hash).await?
  {
    let mut r = response(
      200,
      None,
      "",
      &[access_cookie(&key(&s.db).await?, &user, now)],
    );
    if let Ok(value) = user.parse() {
      r.headers_mut().insert("X-Wharf-User", value);
    }
    return Ok(r);
  }
  let cookies = [gate_cookie("wharf_gate_rt", "", 0)];
  if headers
    .get("x-forwarded-method")
    .and_then(|v| v.to_str().ok())
    == Some("GET")
    && headers
      .get(header::ACCEPT)
      .and_then(|v| v.to_str().ok())
      .is_some_and(|v| v.contains("text/html"))
  {
    let field = |name| {
      headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
    };
    let rd = format!(
      "{}://{}{}",
      field("x-forwarded-proto"),
      field("x-forwarded-host"),
      field("x-forwarded-uri")
    );
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

#[cfg(test)]
mod tests {
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
    assert_eq!(safe_path("//evil.example"), "/");
    assert_eq!(safe_path("/\\evil.example"), "/");
  }
  #[test]
  fn rd_requires_gate() {
    let mut w = world();
    assert!(rd_url(&w, "https://evil.example/").is_none());
    assert!(rd_url(&w, "http://a.example.test/").is_none());
    w.routes.get_mut("a.example.test").unwrap().spec.sso = None;
    assert!(rd_url(&w, "https://a.example.test/").is_none());
  }
  #[test]
  fn refresh_signature_and_expiry() {
    let hash = "a".repeat(64);
    let key = [7; 32];
    let good = rt_sign(&key, &hash, 2000);
    assert_eq!(rt_parse(&key, &good, 1000), Some(hash));
    assert!(rt_parse(&[8; 32], &good, 1000).is_none());
    assert!(rt_parse(&key, &good, 2000).is_none());
    assert!(
      rt_parse(&key, &good.replace(".2000.", ".3000."), 1000)
        .is_none()
    );
  }
  #[test]
  fn credential_formats_and_fixture() {
    let key = SigningKey::from_bytes(&[0; 32]);
    let token = sign(&key, "admin", 1700000000);
    assert!(rt_parse(&[0; 32], &token, 1700000000).is_none());
    let rt = rt_sign(&[0; 32], &"a".repeat(64), 1700000600);
    assert!(
      URL_SAFE_NO_PAD
        .decode(rt.split('.').next().unwrap())
        .is_ok()
    );
    assert!(
      serde_json::from_slice::<serde_json::Value>(
        &URL_SAFE_NO_PAD
          .decode(rt.split('.').next().unwrap())
          .unwrap()
      )
      .is_err()
    );
    assert_eq!(
      token,
      "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDAwMDA2MDAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoid2hhcmYiLCJzdWIiOiJhZG1pbiJ9.J-x_gW3JdQqN7lpvfll72TH40DsjtJCgW3TDzgM20dlmY78RWQESgnYWBtD2X4Pki4WpS-F6s0poysRCdKrGAg"
    );
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
