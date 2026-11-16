//! Wharf 当 OIDC 身份提供方：单用户、授权码流程（可带 PKCE）、RS256 签名。
//! 登录状态就是页面会话；会话失效后，应用的 refresh token 也一起失效。
use crate::{
  api::AppError,
  auth::{Auth, hash_token, new_token},
  db::{self, Db, now_ms, sql_err},
  state::AppState,
};
use aws_lc_rs::{
  encoding::AsDer,
  rand::SystemRandom,
  rsa::{KeyPair as RsaKeyPair, KeySize},
  signature::{
    KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
    UnparsedPublicKey,
  },
};
use axum::{
  Form, Json,
  extract::{Path, Query, State},
  http::{HeaderMap, StatusCode, header},
  response::{IntoResponse, Response},
};
use base64::{
  Engine,
  engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
  collections::BTreeMap,
  sync::{Arc, LazyLock, Mutex, OnceLock},
};
use wharf_api_types::{
  ApiError,
  spec::{OidcClientSpec, SsoMode, SsoSpec},
  view::{
    OidcClientView, OidcSecretView, OidcSettingsRequest, OidcView,
    Perm,
  },
};

const CODE_TTL: i64 = 60;
const TOKEN_TTL: i64 = 3600;
const MAX_CODES: usize = 1000;

struct Signer {
  pair: RsaKeyPair,
  kid: String,
  n: String,
  e: String,
}
static SIGNER: OnceLock<Signer> = OnceLock::new();
static CODES: LazyLock<Mutex<BTreeMap<String, Code>>> =
  LazyLock::new(|| Mutex::new(BTreeMap::new()));

#[derive(Clone)]
struct Code {
  client_id: String,
  redirect_uri: String,
  nonce: Option<String>,
  challenge: Option<(String, String)>,
  scope: String,
  session_hash: String,
  auth_time: i64,
  expires: i64,
}

/// 服务环境变量里引用 client 密钥用的名字。
pub fn secret_name(host: &str) -> String {
  format!(
    "OIDC_{}",
    host.to_ascii_uppercase().replace(['.', '-'], "_")
  )
}

fn mac(key: &[u8], text: &str) -> Hmac<Sha256> {
  let mut mac = Hmac::<Sha256>::new_from_slice(key)
    .expect("HMAC 接受任意长度密钥");
  mac.update(text.as_bytes());
  mac
}

/// client 密钥由主密钥派生，不单独存，部署时一定存在。
fn client_secret(key: &[u8], client_id: &str) -> String {
  hex::encode(
    mac(key, &format!("client:{client_id}"))
      .finalize()
      .into_bytes(),
  )
}

fn secret_ok(key: &[u8], client_id: &str, secret: &str) -> bool {
  hex::decode(secret).is_ok_and(|b| {
    mac(key, &format!("client:{client_id}"))
      .verify_slice(&b)
      .is_ok()
  })
}

/// 启动时读出的 client 主密钥；只在内存里，用来派生各 client 的密钥。
static CLIENT_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// 给密钥表补上 world 里各 client 的密钥，`[[OIDC_…]]` 就能直接替换。
/// 规划时传 desired world，同一次计划里新加的 client 也能用。
pub fn with_client_secrets(
  world: &crate::world::World,
  secrets: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
  let mut out = secrets.clone();
  if let Some(key) = CLIENT_KEY.get() {
    for (host, r) in &world.routes {
      if r.spec.sso.as_ref().is_some_and(is_oidc) {
        // 派生值优先：手动设的同名密钥会和校验用的值对不上。
        out.insert(secret_name(host), client_secret(key, host));
      }
    }
  }
  out
}

fn is_oidc(sso: &SsoSpec) -> bool {
  sso.mode == SsoMode::Oidc
}

pub async fn init(s: &AppState) -> Result<(), ApiError> {
  let der = s
    .db
    .call(|c| {
      let _ =
        CLIENT_KEY.set(crate::gate::seed(c, "oidc.client_key")?);
      crate::gate::seed(c, "oidc.refresh_key")?;
      if db::setting(c, "oidc.sub")?.is_none() {
        let sub =
          hex::encode(&crate::gate::seed(c, "oidc.sub_seed")?[..16]);
        db::set_setting(c, "oidc.sub", Some(&sub))?;
      }
      if let Some(text) = db::setting(c, "oidc.rsa")? {
        return hex::decode(text)
          .map_err(|_| ApiError::internal("OIDC 签名密钥格式不对"));
      }
      let pair = RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| ApiError::internal("生成 OIDC 签名密钥失败"))?;
      let der = pair
        .as_der()
        .map_err(|_| ApiError::internal("导出 OIDC 签名密钥失败"))?
        .as_ref()
        .to_vec();
      db::set_setting(c, "oidc.rsa", Some(&hex::encode(&der)))?;
      Ok(der)
    })
    .await?;
  let pair = RsaKeyPair::from_pkcs8(&der)
    .map_err(|_| ApiError::internal("OIDC 签名密钥格式不对"))?;
  let public = pair.public_key();
  let n = URL_SAFE_NO_PAD
    .encode(public.modulus().big_endian_without_leading_zero());
  let e = URL_SAFE_NO_PAD
    .encode(public.exponent().big_endian_without_leading_zero());
  let kid = hex::encode(&Sha256::digest(n.as_bytes())[..8]);
  SIGNER
    .set(Signer { pair, kid, n, e })
    .map_err(|_| ApiError::internal("OIDC 重复初始化"))
}

fn signer() -> Result<&'static Signer, ApiError> {
  SIGNER
    .get()
    .ok_or_else(|| ApiError::internal("OIDC 没有初始化"))
}

fn sign(claims: &Value, typ: &str) -> Result<String, ApiError> {
  let signer = signer()?;
  let header = URL_SAFE_NO_PAD.encode(
    json!({"alg":"RS256","typ":typ,"kid":signer.kid}).to_string(),
  );
  let raw = format!(
    "{header}.{}",
    URL_SAFE_NO_PAD.encode(claims.to_string())
  );
  let mut sig = vec![0; signer.pair.public_modulus_len()];
  signer
    .pair
    .sign(
      &RSA_PKCS1_SHA256,
      &SystemRandom::new(),
      raw.as_bytes(),
      &mut sig,
    )
    .map_err(|_| ApiError::internal("OIDC 签名失败"))?;
  Ok(format!("{raw}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

fn verify(token: &str, issuer: &str, now: i64) -> Option<Value> {
  let signer = signer().ok()?;
  let (raw, sig) = token.rsplit_once('.')?;
  let (_, body) = raw.split_once('.')?;
  UnparsedPublicKey::new(
    &RSA_PKCS1_2048_8192_SHA256,
    signer.pair.public_key().as_ref(),
  )
  .verify(raw.as_bytes(), &URL_SAFE_NO_PAD.decode(sig).ok()?)
  .ok()?;
  let claims: Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?)
      .ok()?;
  (claims["iss"] == issuer
    && claims["exp"].as_i64().is_some_and(|e| e > now))
  .then_some(claims)
}

/// OIDC 要求 issuer 是 https 地址；控制面没有对外 https 域名时不可用。
async fn issuer(s: &AppState) -> Option<String> {
  crate::join::default_url(s)
    .await
    .map(|u| u.trim_end_matches('/').to_string())
    .filter(|u| u.starts_with("https://"))
}

fn no_issuer() -> ApiError {
  ApiError::invalid(
    "控制面没有对外的 https 地址，不能当 OIDC 身份提供方",
  )
  .with_hint("给控制面加一个域名，或用 --public-url 启动控制面")
}

fn client<'a>(
  world: &'a crate::world::World,
  id: &str,
) -> Option<&'a OidcClientSpec> {
  world
    .routes
    .get(id)
    .and_then(|r| r.spec.sso.as_ref())
    .filter(|s| is_oidc(s))
    .and_then(|s| s.oidc.as_ref())
}

/// 把配置里的回调地址展开成完整地址。
pub fn redirect_uris(
  host: &str,
  spec: &OidcClientSpec,
) -> Vec<String> {
  spec
    .redirect_uris
    .iter()
    .map(|u| {
      if u.starts_with('/') {
        format!("https://{host}{u}")
      } else {
        u.clone()
      }
    })
    .collect()
}

/// 回调地址：本域名路径、本域名的 https 地址，或手机 app 的自定义协议。
pub fn validate(host: &str, sso: &SsoSpec) -> Result<(), ApiError> {
  let fail = |s: &str| ApiError::invalid(format!("域名 {host}：{s}"));
  if is_oidc(sso) != sso.oidc.is_some() {
    return Err(fail(
      "只有 oidc 方式才能写回调地址，oidc 方式必须有回调地址",
    ));
  }
  let Some(spec) = &sso.oidc else {
    return Ok(());
  };
  if !(1..=10).contains(&spec.redirect_uris.len()) {
    return Err(fail("回调地址须为 1 到 10 个"));
  }
  for uri in redirect_uris(host, spec) {
    let ok = reqwest::Url::parse(&uri).is_ok_and(|u| {
      let custom = !matches!(
        u.scheme(),
        "http"
          | "https"
          | "javascript"
          | "data"
          | "file"
          | "vbscript"
      );
      u.fragment().is_none()
        && u.username().is_empty()
        && u.password().is_none()
        && (custom
          || (u.scheme() == "https"
            && u.host_str() == Some(host)
            && u.port().is_none()))
    }) && !uri.contains(['\r', '\n', ' ']);
    if !ok {
      return Err(fail(&format!(
        "回调地址 {uri} 写得不对：要是本域名的路径或 https 地址，或手机 app 的自定义协议"
      )));
    }
  }
  Ok(())
}

/// 两个域名换算出同一个密钥名时拒绝（例如 a-b.com 和 a.b.com）。
pub fn validate_names(
  world: &crate::world::World,
) -> Result<(), ApiError> {
  let mut seen = BTreeMap::new();
  for (host, r) in &world.routes {
    if r.spec.sso.as_ref().is_some_and(is_oidc)
      && let Some(other) = seen.insert(secret_name(host), host)
    {
      return Err(ApiError::invalid(format!(
        "域名 {other} 和 {host} 的 OIDC 密钥名相同，只能有一个用 oidc 方式"
      )));
    }
  }
  Ok(())
}

fn no_store(mut r: Response) -> Response {
  r.headers_mut()
    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
  r.headers_mut()
    .insert(header::PRAGMA, "no-cache".parse().unwrap());
  r
}

fn cors(mut r: Response) -> Response {
  r.headers_mut().insert(
    header::ACCESS_CONTROL_ALLOW_ORIGIN,
    "*".parse().unwrap(),
  );
  r
}

fn redirect(location: &str) -> Response {
  no_store(
    (
      StatusCode::FOUND,
      [(header::LOCATION, location.to_string())],
    )
      .into_response(),
  )
}

fn page(status: StatusCode, text: &str) -> Response {
  no_store(
    (
      status,
      [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
      text.to_string(),
    )
      .into_response(),
  )
}

fn token_error(
  status: StatusCode,
  error: &str,
  text: &str,
) -> Response {
  no_store(
    (
      status,
      Json(json!({"error":error,"error_description":text})),
    )
      .into_response(),
  )
}

pub async fn discovery(
  State(s): State<Arc<AppState>>,
) -> Result<Response, AppError> {
  let issuer = issuer(&s).await.ok_or_else(no_issuer)?;
  Ok(cors(
    Json(json!({
      "issuer": issuer,
      "authorization_endpoint": format!("{issuer}/oidc/authorize"),
      "token_endpoint": format!("{issuer}/oidc/token"),
      "userinfo_endpoint": format!("{issuer}/oidc/userinfo"),
      "jwks_uri": format!("{issuer}/oidc/jwks"),
      "end_session_endpoint": format!("{issuer}/oidc/logout"),
      "response_types_supported": ["code"],
      "response_modes_supported": ["query"],
      "grant_types_supported": ["authorization_code", "refresh_token"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["RS256"],
      "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
      "code_challenge_methods_supported": ["S256", "plain"],
      "scopes_supported": ["openid", "profile", "email", "groups", "offline_access"],
      "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "email", "email_verified", "groups"],
      "authorization_response_iss_parameter_supported": true,
    }))
    .into_response(),
  ))
}

pub async fn jwks() -> Result<Response, AppError> {
  let signer = signer()?;
  Ok(cors(
    Json(json!({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":signer.kid,"n":signer.n,"e":signer.e}]}))
      .into_response(),
  ))
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
  #[serde(default)]
  response_type: String,
  #[serde(default)]
  client_id: String,
  #[serde(default)]
  redirect_uri: String,
  #[serde(default)]
  scope: String,
  state: Option<String>,
  nonce: Option<String>,
  code_challenge: Option<String>,
  code_challenge_method: Option<String>,
  prompt: Option<String>,
  hop: Option<String>,
}

fn with_params(uri: &str, pairs: &[(&str, &str)]) -> String {
  let mut url = reqwest::Url::parse(uri).expect("回调地址已校验");
  {
    let mut q = url.query_pairs_mut();
    for (k, v) in pairs {
      q.append_pair(k, v);
    }
  }
  url.to_string()
}

pub async fn authorize(
  State(s): State<Arc<AppState>>,
  Query(q): Query<AuthorizeQuery>,
  headers: HeaderMap,
  uri: axum::http::Uri,
) -> Result<Response, AppError> {
  let issuer = issuer(&s).await.ok_or_else(no_issuer)?;
  let snap = crate::snapshot::load(&s.db).await?;
  let Some(spec) = client(&snap.world, &q.client_id) else {
    return Ok(page(
      StatusCode::BAD_REQUEST,
      "这个应用没有配置用 Wharf 登录",
    ));
  };
  if !redirect_uris(&q.client_id, spec).contains(&q.redirect_uri) {
    return Ok(page(
      StatusCode::BAD_REQUEST,
      "回调地址不在这个应用的配置里",
    ));
  }
  let state = q.state.clone().unwrap_or_default();
  let fail = |error: &str| {
    let mut pairs = vec![("error", error), ("iss", issuer.as_str())];
    if q.state.is_some() {
      pairs.push(("state", state.as_str()));
    }
    redirect(&with_params(&q.redirect_uri, &pairs))
  };
  if q.response_type != "code" {
    return Ok(fail("unsupported_response_type"));
  }
  if !q.scope.split(' ').any(|v| v == "openid") {
    return Ok(fail("invalid_scope"));
  }
  let challenge =
    match (&q.code_challenge, q.code_challenge_method.as_deref()) {
      (None, _) => None,
      (Some(c), None | Some("plain")) => {
        Some((c.clone(), "plain".into()))
      }
      (Some(c), Some("S256")) => Some((c.clone(), "S256".into())),
      _ => return Ok(fail("invalid_request")),
    };
  let Some(user) = crate::login::session_user(&s, &headers).await?
  else {
    if q.prompt.as_deref() == Some("none") {
      return Ok(fail("login_required"));
    }
    // 会话 cookie 是 SameSite=Strict，从应用跳过来时带不上；先在本站跳一次。
    let path = uri
      .path_and_query()
      .map(|p| p.as_str().to_string())
      .unwrap_or_default();
    if q.hop.as_deref() != Some("1") {
      let target = format!("{path}&hop=1")
        .replace('&', "&amp;")
        .replace('"', "&quot;");
      return Ok(page(
        StatusCode::OK,
        &format!(
          "<meta http-equiv=\"refresh\" content=\"0;url={target}\">正在跳转…"
        ),
      ));
    }
    let next = path.replace("&hop=1", "");
    return Ok(redirect(&format!(
      "/login?next={}",
      urlencoding::encode(&next)
    )));
  };
  let hash =
    hash_token(crate::login::cookie_value(&headers).unwrap());
  let now = now_ms() / 1000;
  let session_hash = hash.clone();
  let auth_time = s
    .db
    .call(move |c| {
      c.query_row(
        "SELECT created_at FROM sessions WHERE hash=?1",
        params![session_hash],
        |r| r.get::<_, i64>(0),
      )
      .optional()
      .map_err(sql_err)
    })
    .await?
    .map(|ms| ms / 1000)
    .unwrap_or(now);
  let code = new_token();
  {
    let mut codes = CODES.lock().unwrap_or_else(|e| e.into_inner());
    codes.retain(|_, c| c.expires > now);
    if codes.len() >= MAX_CODES {
      return Ok(fail("temporarily_unavailable"));
    }
    codes.insert(
      code.clone(),
      Code {
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        nonce: q.nonce.clone(),
        challenge,
        scope: q.scope.clone(),
        session_hash: hash,
        auth_time,
        expires: now + CODE_TTL,
      },
    );
  }
  let host = q.client_id.clone();
  s.db
    .call(move |c| {
      c.execute(
        "INSERT INTO audit_log (at,kind,actor,method,path) VALUES (?1,'login',?2,'oidc',?3)",
        params![now_ms(), user, host],
      )
      .map_err(sql_err)?;
      Ok(())
    })
    .await?;
  let mut pairs =
    vec![("code", code.as_str()), ("iss", issuer.as_str())];
  if q.state.is_some() {
    pairs.push(("state", state.as_str()));
  }
  Ok(redirect(&with_params(&q.redirect_uri, &pairs)))
}

#[derive(Deserialize)]
pub struct TokenForm {
  #[serde(default)]
  grant_type: String,
  code: Option<String>,
  redirect_uri: Option<String>,
  code_verifier: Option<String>,
  client_id: Option<String>,
  client_secret: Option<String>,
  refresh_token: Option<String>,
}

/// client 认证：Basic 头或表单里的 client_id/client_secret。
fn credentials(
  headers: &HeaderMap,
  form: &TokenForm,
) -> Option<(String, String)> {
  if let Some(basic) = headers
    .get(header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Basic "))
  {
    let text =
      String::from_utf8(STANDARD.decode(basic.trim()).ok()?).ok()?;
    let (id, secret) = text.split_once(':')?;
    return Some((
      urlencoding::decode(id).ok()?.into_owned(),
      urlencoding::decode(secret).ok()?.into_owned(),
    ));
  }
  Some((form.client_id.clone()?, form.client_secret.clone()?))
}

fn pkce_ok(
  challenge: &Option<(String, String)>,
  verifier: Option<&str>,
) -> bool {
  match (challenge, verifier) {
    (None, _) => true,
    (Some(_), None) => false,
    (Some((c, m)), Some(v)) if m == "S256" => {
      URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == *c
    }
    (Some((c, _)), Some(v)) => c == v,
  }
}

fn refresh_sign(
  key: &[u8],
  session_hash: &str,
  client_id: &str,
  scope: &str,
  auth_time: i64,
) -> String {
  let raw = format!(
    "{session_hash}.{}.{}.{auth_time}",
    URL_SAFE_NO_PAD.encode(client_id),
    URL_SAFE_NO_PAD.encode(scope)
  );
  format!(
    "{raw}.{}",
    URL_SAFE_NO_PAD.encode(mac(key, &raw).finalize().into_bytes())
  )
}

/// 返回 (会话哈希, client_id, scope, auth_time)。
fn refresh_parse(
  key: &[u8],
  token: &str,
) -> Option<(String, String, String, i64)> {
  let (raw, sig) = token.rsplit_once('.')?;
  mac(key, raw)
    .verify_slice(&URL_SAFE_NO_PAD.decode(sig).ok()?)
    .ok()?;
  let mut parts = raw.split('.');
  let hash = parts.next()?.to_string();
  let client =
    String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?)
      .ok()?;
  let scope =
    String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?)
      .ok()?;
  let auth_time = parts.next()?.parse().ok()?;
  Some((hash, client, scope, auth_time))
}

struct Identity {
  sub: String,
  username: String,
  email: Option<String>,
}

async fn identity(db: &Db) -> Result<Identity, ApiError> {
  db.call(|c| {
    let username: String = c
      .query_row("SELECT username FROM admin WHERE id=1", [], |r| {
        r.get(0)
      })
      .map_err(sql_err)?;
    Ok(Identity {
      sub: db::setting(c, "oidc.sub")?
        .ok_or_else(|| ApiError::internal("OIDC 没有初始化"))?,
      username,
      email: db::setting(c, "oidc.email")?,
    })
  })
  .await
}

/// 按 scope 给出用户信息字段。
fn profile(
  who: &Identity,
  scope: &str,
) -> serde_json::Map<String, Value> {
  let has = |name: &str| scope.split(' ').any(|v| v == name);
  let mut out = serde_json::Map::new();
  out.insert("sub".into(), json!(who.sub));
  if has("profile") {
    out.insert("name".into(), json!(who.username));
    out.insert("preferred_username".into(), json!(who.username));
  }
  if has("email")
    && let Some(email) = &who.email
  {
    out.insert("email".into(), json!(email));
    out.insert("email_verified".into(), json!(true));
  }
  if has("groups") {
    out.insert("groups".into(), json!(["admin"]));
  }
  out
}

pub async fn token(
  State(s): State<Arc<AppState>>,
  headers: HeaderMap,
  Form(form): Form<TokenForm>,
) -> Result<Response, AppError> {
  let Some(issuer) = issuer(&s).await else {
    return Ok(token_error(
      StatusCode::BAD_REQUEST,
      "invalid_request",
      "控制面没有对外的 https 地址",
    ));
  };
  let snap = crate::snapshot::load(&s.db).await?;
  let key = *CLIENT_KEY
    .get()
    .ok_or_else(|| ApiError::internal("OIDC 没有初始化"))?;
  let Some((client_id, _)) =
    credentials(&headers, &form).filter(|(id, secret)| {
      client(&snap.world, id).is_some() && secret_ok(&key, id, secret)
    })
  else {
    return Ok(token_error(
      StatusCode::UNAUTHORIZED,
      "invalid_client",
      "应用的 client_id 或密钥不对",
    ));
  };
  let refresh_key = s
    .db
    .call(|c| crate::gate::seed(c, "oidc.refresh_key"))
    .await?;
  let now = now_ms() / 1000;
  let invalid = || {
    token_error(
      StatusCode::BAD_REQUEST,
      "invalid_grant",
      "授权码或 refresh token 无效，重新登录",
    )
  };
  let (session_hash, scope, nonce, auth_time) =
    match form.grant_type.as_str() {
      "authorization_code" => {
        let code = form.code.as_deref().unwrap_or("");
        let found = CODES
          .lock()
          .unwrap_or_else(|e| e.into_inner())
          .remove(code)
          .filter(|c| c.expires > now && c.client_id == client_id);
        let Some(found) = found.filter(|c| {
          form.redirect_uri.as_deref()
            == Some(c.redirect_uri.as_str())
            && pkce_ok(&c.challenge, form.code_verifier.as_deref())
        }) else {
          return Ok(invalid());
        };
        (
          found.session_hash,
          found.scope,
          found.nonce,
          found.auth_time,
        )
      }
      "refresh_token" => {
        let Some((hash, _, scope, auth_time)) = form
          .refresh_token
          .as_deref()
          .and_then(|t| refresh_parse(&refresh_key, t))
          .filter(|(_, c, _, _)| *c == client_id)
        else {
          return Ok(invalid());
        };
        (hash, scope, None, auth_time)
      }
      _ => {
        return Ok(token_error(
          StatusCode::BAD_REQUEST,
          "unsupported_grant_type",
          "只支持 authorization_code 和 refresh_token",
        ));
      }
    };
  if crate::gate::session(&s.db, session_hash.clone())
    .await?
    .is_none()
  {
    return Ok(invalid());
  }
  let who = identity(&s.db).await?;
  let mut id_claims = profile(&who, &scope);
  for (k, v) in [
    ("iss", json!(issuer)),
    ("aud", json!(client_id)),
    ("azp", json!(client_id)),
    ("iat", json!(now)),
    ("exp", json!(now + TOKEN_TTL)),
    ("auth_time", json!(auth_time)),
  ] {
    id_claims.insert(k.into(), v);
  }
  if let Some(nonce) = nonce {
    id_claims.insert("nonce".into(), json!(nonce));
  }
  let access = sign(
    &json!({"iss":issuer,"sub":who.sub,"aud":client_id,"client_id":client_id,"scope":scope,"iat":now,"exp":now+TOKEN_TTL,"jti":new_token()}),
    "at+jwt",
  )?;
  let id_token = sign(&Value::Object(id_claims), "JWT")?;
  let refresh = refresh_sign(
    &refresh_key,
    &session_hash,
    &client_id,
    &scope,
    auth_time,
  );
  Ok(no_store(
    Json(json!({
      "access_token": access,
      "token_type": "Bearer",
      "expires_in": TOKEN_TTL,
      "id_token": id_token,
      "refresh_token": refresh,
      "scope": scope,
    }))
    .into_response(),
  ))
}

pub async fn userinfo(
  State(s): State<Arc<AppState>>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let unauthorized = || {
    let mut r = token_error(
      StatusCode::UNAUTHORIZED,
      "invalid_token",
      "access token 无效或过期",
    );
    r.headers_mut().insert(
      header::WWW_AUTHENTICATE,
      "Bearer error=\"invalid_token\"".parse().unwrap(),
    );
    r
  };
  let Some(issuer) = issuer(&s).await else {
    return Ok(unauthorized());
  };
  let Some(claims) = headers
    .get(header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .and_then(|t| verify(t.trim(), &issuer, now_ms() / 1000))
  else {
    return Ok(unauthorized());
  };
  let who = identity(&s.db).await?;
  if claims["sub"] != who.sub.as_str()
    || claims.get("client_id").is_none()
  {
    return Ok(unauthorized());
  }
  let scope = claims["scope"].as_str().unwrap_or("openid");
  Ok(cors(no_store(
    Json(Value::Object(profile(&who, scope))).into_response(),
  )))
}

#[derive(Deserialize)]
pub struct LogoutQuery {
  post_logout_redirect_uri: Option<String>,
  state: Option<String>,
}

/// 应用发起的退出：只跳回应用，不退出 Wharf 本身的登录。
pub async fn logout(
  State(s): State<Arc<AppState>>,
  Query(q): Query<LogoutQuery>,
) -> Result<Response, AppError> {
  let snap = crate::snapshot::load(&s.db).await?;
  let target = q.post_logout_redirect_uri.as_deref().filter(|uri| {
    reqwest::Url::parse(uri).is_ok_and(|u| {
      u.scheme() == "https"
        && u.port().is_none()
        && u
          .host_str()
          .is_some_and(|h| client(&snap.world, h).is_some())
    })
  });
  Ok(match target {
    Some(uri) => {
      let pairs: Vec<(&str, &str)> = q
        .state
        .as_deref()
        .map(|v| ("state", v))
        .into_iter()
        .collect();
      redirect(&with_params(uri, &pairs))
    }
    None => page(StatusCode::OK, "已退出应用"),
  })
}

pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> Result<Json<OidcView>, AppError> {
  auth.require(Perm::Read)?;
  let issuer = issuer(&s).await;
  let snap = crate::snapshot::load(&s.db).await?;
  let who = identity(&s.db).await?;
  let clients = snap
    .world
    .routes
    .iter()
    .filter_map(|(host, r)| {
      let sso = r.spec.sso.as_ref().filter(|s| is_oidc(s))?;
      Some(OidcClientView {
        client_id: host.clone(),
        secret_ref: format!("[[{}]]", secret_name(host)),
        redirect_uris: redirect_uris(host, sso.oidc.as_ref()?),
        public: sso.public,
      })
    })
    .collect();
  Ok(Json(OidcView {
    discovery: issuer
      .as_ref()
      .map(|i| format!("{i}/.well-known/openid-configuration")),
    issuer,
    username: who.username,
    email: who.email,
    clients,
  }))
}

fn email_ok(email: &str) -> bool {
  email.len() <= 254
    && email.split_once('@').is_some_and(|(a, b)| {
      !a.is_empty()
        && b.contains('.')
        && !b.starts_with('.')
        && !b.ends_with('.')
    })
    && !email.contains([' ', '\r', '\n', '<', '>', '"'])
}

pub async fn settings(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<OidcSettingsRequest>,
) -> Result<Json<Value>, AppError> {
  auth.require(Perm::Admin)?;
  let email = req
    .email
    .map(|e| e.trim().to_string())
    .filter(|e| !e.is_empty());
  if email.as_deref().is_some_and(|e| !email_ok(e)) {
    return Err(ApiError::invalid("邮箱格式不对").into());
  }
  s.db
    .call(move |c| db::set_setting(c, "oidc.email", email.as_deref()))
    .await?;
  Ok(Json(json!({"ok": true})))
}

/// 给不由 Wharf 部署的应用手工配置用；只能在页面上登录后查看。
pub async fn secret(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(host): Path<String>,
) -> Result<Json<OidcSecretView>, AppError> {
  auth.require(Perm::Admin)?;
  crate::login::require_human(&auth)?;
  let snap = crate::snapshot::load(&s.db).await?;
  if client(&snap.world, &host).is_none() {
    return Err(
      ApiError::not_found(format!("域名 {host} 没有用 oidc 方式"))
        .into(),
    );
  }
  let key = *CLIENT_KEY
    .get()
    .ok_or_else(|| ApiError::internal("OIDC 没有初始化"))?;
  Ok(Json(OidcSecretView {
    client_secret: client_secret(&key, &host),
    client_id: host,
  }))
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn client_secret_and_pkce() {
    let key = [7u8; 32];
    let secret = client_secret(&key, "a.example.test");
    assert!(secret_ok(&key, "a.example.test", &secret));
    assert!(!secret_ok(&key, "b.example.test", &secret));
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = Some((
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
      "S256".into(),
    ));
    assert!(pkce_ok(&challenge, Some(verifier)));
    assert!(!pkce_ok(&challenge, Some("wrong")));
    assert!(!pkce_ok(&challenge, None));
  }
  #[test]
  fn rs256_sign_and_verify() {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let public = pair.public_key();
    let n = URL_SAFE_NO_PAD
      .encode(public.modulus().big_endian_without_leading_zero());
    let _ = SIGNER.set(Signer {
      pair,
      kid: "k".into(),
      n,
      e: "AQAB".into(),
    });
    let token = sign(
      &json!({"iss":"https://w.example.test","sub":"x","exp":200}),
      "JWT",
    )
    .unwrap();
    assert_eq!(
      verify(&token, "https://w.example.test", 100).unwrap()["sub"],
      "x"
    );
    assert!(verify(&token, "https://w.example.test", 300).is_none());
    assert!(
      verify(&token, "https://other.example.test", 100).is_none()
    );
    let (raw, _) = token.rsplit_once('.').unwrap();
    assert!(
      verify(&format!("{raw}.AAAA"), "https://w.example.test", 100)
        .is_none()
    );
  }
  #[test]
  fn refresh_round_trip() {
    let key = [3u8; 32];
    let t =
      refresh_sign(&key, "abc", "a.example.test", "openid email", 9);
    assert_eq!(
      refresh_parse(&key, &t),
      Some((
        "abc".into(),
        "a.example.test".into(),
        "openid email".into(),
        9
      ))
    );
    assert!(refresh_parse(&key, &t.replace("abc", "abd")).is_none());
  }
  #[test]
  fn redirect_rules() {
    let sso = |uris: &[&str]| -> SsoSpec {
      serde_json::from_value(
        json!({"mode":"oidc","oidc":{"redirect_uris":uris}}),
      )
      .unwrap()
    };
    let host = "a.example.test";
    validate(
      host,
      &sso(&[
        "/cb",
        "https://a.example.test/x",
        "app.immich:///oauth-callback",
      ]),
    )
    .unwrap();
    for bad in [
      "https://evil.test/cb",
      "http://a.example.test/cb",
      "javascript:alert(1)",
      "https://a.example.test:8443/cb",
    ] {
      assert!(validate(host, &sso(&[bad])).is_err(), "{bad}");
    }
  }
}
