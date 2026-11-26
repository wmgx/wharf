//! 两步验证和一次性恢复码；密钥仅在设置时返回。
use crate::{
  api::{ApiResult, AppError},
  auth::{Auth, hash_token},
  db::{Db, now_ms, sql_err},
  lockout::{self, LockScope},
  login,
  state::AppState,
};
use axum::{
  Json,
  extract::{ConnectInfo, State},
  http::HeaderMap,
};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use std::{
  net::SocketAddr,
  sync::{Arc, LazyLock, Mutex},
  time::{Duration, Instant},
};
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{Issue, IssueLevel, TotpView},
};

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
fn base32_encode(bytes: &[u8]) -> String {
  let (mut acc, mut bits) = (0u32, 0);
  let mut out = String::new();
  for b in bytes {
    acc = (acc << 8) | u32::from(*b);
    bits += 8;
    while bits >= 5 {
      bits -= 5;
      out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
    }
  }
  if bits > 0 {
    out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
  }
  out
}
fn base32_decode(text: &str) -> Option<Vec<u8>> {
  let (mut acc, mut bits) = (0u32, 0);
  let mut out = Vec::new();
  for b in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
    let n =
      ALPHABET.iter().position(|v| *v == b.to_ascii_uppercase())?;
    acc = (acc << 5) | n as u32;
    bits += 5;
    if bits >= 8 {
      bits -= 8;
      out.push((acc >> bits) as u8);
    }
  }
  (!out.is_empty()).then_some(out)
}
fn code_at(secret: &[u8], step: u64) -> u32 {
  let mut mac = Hmac::<Sha1>::new_from_slice(secret)
    .expect("HMAC 接受任意长度的密钥");
  mac.update(&step.to_be_bytes());
  let bytes = mac.finalize().into_bytes();
  let offset = (bytes[19] & 15) as usize;
  (u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    & 0x7fffffff)
    % 1_000_000
}
fn check(
  secret: &str,
  input: &str,
  now_secs: u64,
  last_step: Option<u64>,
) -> Option<u64> {
  let input: Vec<_> =
    input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
  if input.len() != 6 || !input.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let secret = base32_decode(secret)?;
  let step = now_secs / 30;
  for candidate in [step.saturating_sub(1), step, step + 1] {
    let expected = format!("{:06}", code_at(&secret, candidate));
    let diff = expected
      .bytes()
      .zip(&input)
      .fold(0u8, |a, (b, c)| a | (b ^ c));
    if diff == 0 && last_step.is_none_or(|last| candidate > last) {
      return Some(candidate);
    }
  }
  None
}
fn random<const N: usize>() -> Result<[u8; N], ApiError> {
  let mut bytes = [0; N];
  getrandom::fill(&mut bytes)
    .map_err(|_| ApiError::internal("随机数不可用"))?;
  Ok(bytes)
}
fn otpauth_uri(username: &str, secret: &str) -> String {
  format!(
    "otpauth://totp/Wharf:{username}?secret={secret}&issuer=Wharf"
  )
}
fn normalized(code: &str) -> String {
  code
    .chars()
    .filter(|c| !c.is_whitespace() && *c != '-')
    .flat_map(char::to_lowercase)
    .collect()
}
fn new_codes(c: &Connection) -> Result<Vec<String>, ApiError> {
  const CHARS: &[u8] = b"23456789abcdefghijkmnpqrstuvwxyz";
  let mut codes = Vec::new();
  c.execute("DELETE FROM recovery_codes", [])
    .map_err(sql_err)?;
  while codes.len() < 10 {
    let mut code = String::new();
    // 拒绝有偏的尾段，避免取模降低恢复码熵。
    while code.len() < 10 {
      let b = random::<1>()?[0] as usize;
      if b < 256 / CHARS.len() * CHARS.len() {
        code.push(CHARS[b % CHARS.len()] as char);
      }
    }
    c.execute(
      "INSERT INTO recovery_codes (hash) VALUES (?1)",
      [hash_token(&code)],
    )
    .map_err(sql_err)?;
    codes.push(format!("{}-{}", &code[..5], &code[5..]));
  }
  Ok(codes)
}
fn left(c: &Connection) -> Result<u32, ApiError> {
  c.query_row(
    "SELECT count(*) FROM recovery_codes WHERE used_at IS NULL",
    [],
    |r| r.get(0),
  )
  .map_err(sql_err)
}
pub async fn view(db: &Db) -> Result<TotpView, ApiError> {
  db.call(|c| Ok(TotpView { enabled: c.query_row("SELECT EXISTS(SELECT 1 FROM admin WHERE totp_secret IS NOT NULL)", [], |r| r.get(0)).map_err(sql_err)?, recovery_left: left(c)? })).await
}
/// 返回 Some(true) 表示用掉恢复码，Some(false) 表示验证码；条件更新防并发重放。
pub fn verify(
  c: &Connection,
  code: &str,
) -> Result<Option<bool>, ApiError> {
  let (secret, last): (Option<String>, Option<u64>) = c
    .query_row(
      "SELECT totp_secret, totp_last_step FROM admin WHERE id = 1",
      [],
      |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(sql_err)?;
  let Some(secret) = secret else {
    return Ok(None);
  };
  let code = normalized(code);
  if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
    let Some(step) =
      check(&secret, &code, now_ms() as u64 / 1000, last)
    else {
      return Ok(None);
    };
    let n = c.execute("UPDATE admin SET totp_last_step = ?1 WHERE id = 1 AND (totp_last_step IS NULL OR totp_last_step < ?1)", [step]).map_err(sql_err)?;
    Ok((n == 1).then_some(false))
  } else {
    let n = c.execute("UPDATE recovery_codes SET used_at = ?1 WHERE hash = ?2 AND used_at IS NULL", params![now_ms(), hash_token(&code)]).map_err(sql_err)?;
    Ok((n == 1).then_some(true))
  }
}
pub async fn used(state: &AppState, actor: &str, source: String) {
  crate::audit::login_event(
    state,
    "recovery_used",
    actor,
    source.clone(),
  )
  .await;
  if let Ok(view) = view(&state.db).await {
    crate::rules::notice(
      state,
      "recovery",
      None,
      false,
      crate::notify::Event {
        title: "用掉了一个恢复码".into(),
        body: format!(
          "还剩 {} 个。来源：{source}",
          view.recovery_left
        ),
      },
    )
    .await;
  }
}
pub async fn issues(db: &Db) -> Result<Vec<Issue>, ApiError> {
  let v = view(db).await?;
  Ok(if v.enabled && v.recovery_left < 3 {
    vec![Issue {
      code: "recovery_low".into(),
      level: IssueLevel::Warn,
      subject: None,
      title: format!("恢复码只剩 {} 个", v.recovery_left),
      hint: Some("在“设置 → 登录与安全”重新生成".into()),
      ack: None,
      alert: None,
    }]
  } else {
    vec![]
  })
}
#[derive(Deserialize)]
pub struct Proof {
  #[serde(default)]
  password: String,
  #[serde(default)]
  code: String,
}
fn guard(
  auth: &Auth,
  peer: SocketAddr,
  headers: &HeaderMap,
) -> Result<String, AppError> {
  login::require_human(auth)?;
  let key = login::client_key(peer.ip(), headers);
  if let Some(minutes) = lockout::locked(LockScope::AdminLogin, &key)
  {
    return Err(
      ApiError::new(
        ErrorCode::Forbidden,
        format!("输错次数太多，{minutes} 分钟后再试"),
      )
      .into(),
    );
  }
  Ok(key)
}
struct PendingSetup {
  secret: String,
  session_hash: String,
  rebind_verified: bool,
  expires: Instant,
}

static PENDING_REBIND: LazyLock<Mutex<Option<PendingSetup>>> =
  LazyLock::new(Default::default);

async fn verify_admin_password(
  db: &Db,
  password: String,
) -> Result<Option<String>, ApiError> {
  let Some((_, hash)) = login::admin(db).await? else {
    return Ok(None);
  };
  Ok(
    login::verify_password_async(password, hash.clone())
      .await?
      .then_some(hash),
  )
}

fn password_current(
  c: &Connection,
  verified_hash: &str,
) -> Result<bool, ApiError> {
  c.query_row(
    "SELECT EXISTS(SELECT 1 FROM admin WHERE id = 1 AND password_hash = ?1)",
    [verified_hash],
    |r| r.get(0),
  ).map_err(sql_err)
}
async fn failure(
  s: &AppState,
  auth: &Auth,
  key: &str,
  source: String,
) -> AppError {
  lockout::record_and_notify(
    s,
    LockScope::AdminLogin,
    key,
    Some("两步验证"),
  )
  .await;
  crate::audit::login_event(s, "login_failed", &auth.name, source)
    .await;
  tokio::time::sleep(Duration::from_secs(1)).await;
  ApiError::new(ErrorCode::Forbidden, "密码或验证码不对").into()
}
pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<TotpView> {
  login::require_human(&auth)?;
  Ok(Json(view(&s.db).await?))
}
pub async fn begin(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<Proof>,
) -> ApiResult<Value> {
  let key = guard(&auth, peer, &headers)?;
  let source = login::source(peer.ip(), &headers);
  let Some(session_hash) =
    login::cookie_value(&headers).map(hash_token)
  else {
    return Err(
      ApiError::new(ErrorCode::Forbidden, "需要页面登录").into(),
    );
  };
  let Some(hash) = verify_admin_password(&s.db, req.password).await?
  else {
    return Err(failure(&s, &auth, &key, source).await);
  };
  let secret = base32_encode(&random::<20>()?);
  let username =
    auth.name.strip_prefix("页面:").unwrap_or(&auth.name);
  let uri = otpauth_uri(username, &secret);
  let qr_svg = qrcode::QrCode::new(uri.as_bytes())
    .map_err(|_| ApiError::internal("二维码生成失败"))?
    .render::<qrcode::render::svg::Color>()
    .build();
  let pending = secret.clone();
  let result = s
    .db
    .call(move |c| {
      let tx = c.transaction().map_err(sql_err)?;
      if !password_current(&tx, &hash)? {
        return Ok(None);
      }
      let enabled: bool = tx
        .query_row(
          "SELECT totp_secret IS NOT NULL FROM admin WHERE id = 1",
          [],
          |r| r.get(0),
        )
        .map_err(sql_err)?;
      let recovery = if enabled {
        let Some(recovery) = verify(&tx, &req.code)? else {
          return Ok(None);
        };
        recovery
      } else {
        false
      };
      tx.execute(
        "UPDATE admin SET totp_pending = ?1 WHERE id = 1",
        [&pending],
      )
      .map_err(sql_err)?;
      tx.commit().map_err(sql_err)?;
      // Db::call 串行更新数据库和内存，避免并发覆盖新绑定。
      *PENDING_REBIND.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(PendingSetup {
          secret: pending,
          session_hash,
          rebind_verified: enabled,
          expires: Instant::now() + Duration::from_secs(600),
        });
      Ok(Some(recovery))
    })
    .await?;
  let Some(recovery) = result else {
    return Err(failure(&s, &auth, &key, source).await);
  };
  lockout::clear(LockScope::AdminLogin, &key);
  if recovery {
    used(&s, &auth.name, source).await;
  }
  Ok(Json(
    json!({ "secret": secret, "uri": uri, "qr_svg": qr_svg }),
  ))
}
pub async fn enable(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<Proof>,
) -> ApiResult<Value> {
  let key = guard(&auth, peer, &headers)?;
  let session_hash = login::cookie_value(&headers).map(hash_token);
  let codes = s.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    let (secret, enabled): (Option<String>, bool) = tx.query_row(
      "SELECT totp_pending, totp_secret IS NOT NULL FROM admin WHERE id = 1",
      [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(sql_err)?;
    let Some(secret) = secret else { return Ok(None); };
    let mut pending = PENDING_REBIND.lock().unwrap_or_else(|e| e.into_inner());
    match pending.as_ref().filter(|p| p.secret == secret) {
      Some(p) if Some(p.session_hash.as_str()) == session_hash.as_deref()
        && p.expires > Instant::now() && p.rebind_verified == enabled => {}
      None if !enabled => {}
      _ => return Ok(None),
    }
    let Some(step) = check(&secret, &req.code, now_ms() as u64 / 1000, None) else { return Ok(None); };
    tx.execute("UPDATE admin SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ?1 WHERE id = 1", [step]).map_err(sql_err)?;
    let codes = new_codes(&tx)?;
    tx.commit().map_err(sql_err)?;
    *pending = None;
    Ok(Some(codes))
  }).await?;
  let Some(codes) = codes else {
    return Err(
      failure(&s, &auth, &key, login::source(peer.ip(), &headers))
        .await,
    );
  };
  lockout::clear(LockScope::AdminLogin, &key);
  crate::audit::login_event(
    &s,
    "totp_enable",
    &auth.name,
    login::source(peer.ip(), &headers),
  )
  .await;
  crate::security_receipt::send(
    &s,
    &auth.name,
    &key,
    "启用或重设两步验证".into(),
  )
  .await;
  Ok(Json(json!({ "recovery_codes": codes })))
}
async fn change(
  s: Arc<AppState>,
  auth: Auth,
  peer: SocketAddr,
  headers: HeaderMap,
  req: Proof,
  disable: bool,
) -> ApiResult<Value> {
  let key = guard(&auth, peer, &headers)?;
  let Some(hash) = verify_admin_password(&s.db, req.password).await?
  else {
    return Err(
      failure(&s, &auth, &key, login::source(peer.ip(), &headers))
        .await,
    );
  };
  let result = s.db.call(move |c| {
    let tx = c.transaction().map_err(sql_err)?;
    if !password_current(&tx, &hash)? { return Ok(None); }
    let Some(recovery) = verify(&tx, &req.code)? else { return Ok(None); };
    // 重新生成只接受认证器验证码；关闭也允许一次性恢复码。
    if recovery && !disable { return Ok(None); }
    let codes = if disable {
      tx.execute("UPDATE admin SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = 1", []).map_err(sql_err)?;
      tx.execute("DELETE FROM recovery_codes", []).map_err(sql_err)?;
      Vec::new()
    } else { new_codes(&tx)? };
    tx.commit().map_err(sql_err)?;
    if disable {
      *PENDING_REBIND.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    Ok(Some((codes, recovery)))
  }).await?;
  let Some((codes, recovery)) = result else {
    return Err(
      failure(&s, &auth, &key, login::source(peer.ip(), &headers))
        .await,
    );
  };
  lockout::clear(LockScope::AdminLogin, &key);
  if recovery {
    used(&s, &auth.name, login::source(peer.ip(), &headers)).await;
  }
  crate::audit::login_event(
    &s,
    if disable {
      "totp_disable"
    } else {
      "totp_recovery"
    },
    &auth.name,
    login::source(peer.ip(), &headers),
  )
  .await;
  crate::security_receipt::send(
    &s,
    &auth.name,
    &key,
    if disable {
      "关闭两步验证"
    } else {
      "重生成两步验证恢复码"
    }
    .into(),
  )
  .await;
  Ok(Json(json!({ "recovery_codes": codes })))
}
pub async fn disable(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<Proof>,
) -> ApiResult<Value> {
  change(s, auth, peer, headers, req, true).await
}
pub async fn recovery(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(req): Json<Proof>,
) -> ApiResult<Value> {
  change(s, auth, peer, headers, req, false).await
}

#[cfg(test)]
mod tests {
  use super::*;
  #[tokio::test]
  async fn changing_totp_has_receipts() {
    use crate::{
      rules::tests::{
        TEST_LOCK, notice_titles, reset_memory, test_state,
      },
      security_receipt::tests::auth,
    };

    let _lock = TEST_LOCK.lock().await;
    reset_memory();
    let state = test_state();
    let secret = b"12345678901234567890";
    let password = "fixture-password";
    state
      .db
      .call(move |c| {
        login::set_admin(
          c,
          "operator",
          &login::hash_password(password)?,
        )?;
        c.execute(
          "UPDATE admin SET totp_pending = ?1",
          [base32_encode(secret)],
        )
        .map_err(sql_err)?;
        Ok(())
      })
      .await
      .unwrap();
    let peer = "203.0.113.8:1234".parse().unwrap();
    let proof = || Proof {
      password: password.into(),
      code: format!(
        "{:06}",
        code_at(secret, now_ms() as u64 / 1000 / 30)
      ),
    };
    assert!(
      enable(
        State(state.clone()),
        auth(true),
        ConnectInfo(peer),
        HeaderMap::new(),
        Json(proof())
      )
      .await
      .is_ok()
    );
    state
      .db
      .call(|c| {
        c.execute("UPDATE admin SET totp_last_step = NULL", [])
          .map_err(sql_err)?;
        Ok(())
      })
      .await
      .unwrap();
    assert!(
      recovery(
        State(state.clone()),
        auth(true),
        ConnectInfo(peer),
        HeaderMap::new(),
        Json(proof())
      )
      .await
      .is_ok()
    );
    state
      .db
      .call(|c| {
        c.execute("UPDATE admin SET totp_last_step = NULL", [])
          .map_err(sql_err)?;
        Ok(())
      })
      .await
      .unwrap();
    assert!(
      disable(
        State(state.clone()),
        auth(true),
        ConnectInfo(peer),
        HeaderMap::new(),
        Json(proof())
      )
      .await
      .is_ok()
    );
    assert_eq!(
      notice_titles(&state, "security_receipt").await,
      ["启用或重设两步验证", "重生成两步验证恢复码", "关闭两步验证",]
    );
  }

  #[tokio::test]
  async fn totp_status_stays_available_during_public_lockout() {
    use crate::{
      rules::tests::{TEST_LOCK, test_state},
      security_receipt::tests::auth,
    };

    let _lock = TEST_LOCK.lock().await;
    lockout::clear_public_admin_failures_for_test();
    let state = test_state();
    state
      .db
      .call(|c| {
        login::set_admin(
          c,
          "operator",
          &login::hash_password("fixture-password")?,
        )
      })
      .await
      .unwrap();
    for _ in 0..20 {
      lockout::record_and_notify(
        &state,
        LockScope::AdminLogin,
        "203.0.113.21",
        None,
      )
      .await;
    }
    let peer = "203.0.113.22:12345".parse::<SocketAddr>().unwrap();
    assert!(
      lockout::locked(LockScope::AdminLogin, &peer.ip().to_string())
        .is_some()
    );
    assert!(show(State(state.clone()), auth(true)).await.is_ok());
    let attempt = || {
      disable(
        State(state.clone()),
        auth(true),
        ConnectInfo(peer),
        HeaderMap::new(),
        Json(Proof {
          password: "fixture-wrong".into(),
          code: String::new(),
        }),
      )
    };
    let locked = attempt().await;
    lockout::clear_public_admin_failures_for_test();
    let failure = attempt().await;
    lockout::clear_public_admin_failures_for_test();
    let locked = locked.err().unwrap().0;
    assert_eq!(locked.code, ErrorCode::Forbidden);
    assert!(locked.message.contains("分钟后再试"));
    let failure = failure.err().unwrap().0;
    assert_eq!(failure.code, ErrorCode::Forbidden);
    assert_eq!(failure.message, "密码或验证码不对");
  }

  #[tokio::test]
  async fn rebind_rejects_missing_old_code_and_legacy_pending_secret()
  {
    use crate::{
      rules::tests::{TEST_LOCK, test_state},
      security_receipt::tests::auth,
    };

    let _lock = TEST_LOCK.lock().await;
    let state = test_state();
    let password = "fixture-password";
    let old = "MZXW6";
    let pending = b"12345678901234567890";
    state.db.call(move |c| {
      login::set_admin(c, "operator", &login::hash_password(password)?)?;
      c.execute("UPDATE admin SET totp_secret = ?1, totp_pending = ?2", params![old, base32_encode(pending)]).map_err(sql_err)?;
      c.execute("INSERT INTO recovery_codes (hash) VALUES ('fixture-recovery')", []).map_err(sql_err)?;
      Ok(())
    }).await.unwrap();
    let peer = "203.0.113.23:12345".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
      "cookie",
      "wharf_session=fixture-session".parse().unwrap(),
    );
    let begin_error = begin(
      State(state.clone()),
      auth(true),
      ConnectInfo(peer),
      headers.clone(),
      Json(Proof {
        password: password.into(),
        code: String::new(),
      }),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(begin_error.0.code, ErrorCode::Forbidden);
    let enable_error = enable(
      State(state.clone()),
      auth(true),
      ConnectInfo(peer),
      headers,
      Json(Proof {
        password: String::new(),
        code: format!(
          "{:06}",
          code_at(pending, now_ms() as u64 / 1000 / 30)
        ),
      }),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(enable_error.0.code, ErrorCode::Forbidden);
    state.db.call(move |c| {
      let (secret, pending_secret): (String, String) = c.query_row("SELECT totp_secret, totp_pending FROM admin WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?))).map_err(sql_err)?;
      assert_eq!(secret, old);
      assert_eq!(pending_secret, base32_encode(pending));
      assert_eq!(left(c)?, 1);
      let recovery: String = c.query_row("SELECT hash FROM recovery_codes", [], |r| r.get(0)).map_err(sql_err)?;
      assert_eq!(recovery, "fixture-recovery");
      Ok(())
    }).await.unwrap();
    lockout::clear(LockScope::AdminLogin, &peer.ip().to_string());
  }

  #[test]
  fn rfc6238_sha1() {
    assert_eq!(code_at(b"12345678901234567890", 59 / 30), 287082);
  }
  #[test]
  fn rejects_replay() {
    let secret = base32_encode(b"12345678901234567890");
    assert_eq!(check(&secret, "287082", 59, None), Some(1));
    assert_eq!(check(&secret, "287082", 59, Some(1)), None);
  }
  #[test]
  fn base32_round_trip() {
    let bytes = b"12345678901234567890";
    assert_eq!(base32_encode(b"foo"), "MZXW6");
    assert_eq!(
      base32_decode(&base32_encode(bytes).to_lowercase()).unwrap(),
      bytes
    );
    assert_eq!(base32_decode("m z x w 6").unwrap(), b"foo");
  }
}
