use super::{cookie, gate_cookie, rt_key, session};
use crate::db::{Db, now_ms};
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use wharf_api_types::ApiError;

const ACCESS_TTL: i64 = 600;

pub(super) fn credential_host(headers: &HeaderMap) -> Option<String> {
  normalize_host(headers.get("x-forwarded-host")?.to_str().ok()?)
}

fn normalize_host(raw: &str) -> Option<String> {
  let raw = raw.trim();
  if raw.is_empty()
    || raw.chars().any(|c| c.is_whitespace() || c.is_control())
  {
    return None;
  }
  let host = if let Some((host, port)) = raw.rsplit_once(':') {
    port.parse::<u16>().ok()?;
    host
  } else {
    raw
  };
  (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn sign(
  key: &SigningKey,
  username: &str,
  host: &str,
  now: i64,
) -> String {
  sign_ttl(key, username, host, now, ACCESS_TTL)
}
fn sign_ttl(
  key: &SigningKey,
  username: &str,
  host: &str,
  now: i64,
  ttl: i64,
) -> String {
  let header =
    URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
  let claims = URL_SAFE_NO_PAD.encode(
    json!({"iss":"wharf","sub":username,"aud":host,"iat":now,"exp":now+ttl})
      .to_string(),
  );
  let raw = format!("{header}.{claims}");
  format!(
    "{raw}.{}",
    URL_SAFE_NO_PAD.encode(key.sign(raw.as_bytes()).to_bytes())
  )
}
pub(super) fn rt_sign(
  key: &[u8],
  hash: &str,
  host: &str,
  exp: i64,
) -> String {
  let raw = format!("{hash}.{}.{exp}", URL_SAFE_NO_PAD.encode(host));
  let mut mac = Hmac::<Sha256>::new_from_slice(key)
    .expect("HMAC 接受任意长度密钥");
  mac.update(raw.as_bytes());
  format!(
    "{raw}.{}",
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
  )
}
pub(super) fn rt_parse(
  key: &[u8],
  text: &str,
  host: &str,
  now: i64,
) -> Option<String> {
  let (raw, sig) = text.rsplit_once('.')?;
  let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
  mac.update(raw.as_bytes());
  mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).ok()?).ok()?;
  let (hash, rest) = raw.split_once('.')?;
  let (audience, exp) = rest.split_once('.')?;
  if host.is_empty()
    || URL_SAFE_NO_PAD.decode(audience).ok()?.as_slice()
      != host.as_bytes()
    || hash.len() != 64
    || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    || exp.parse::<i64>().ok()? <= now
  {
    return None;
  }
  Some(hash.into())
}
pub(super) fn access_cookie(
  key: &SigningKey,
  user: &str,
  host: &str,
  now: i64,
) -> String {
  // 只给隔离 lab 缩短凭据，不改变正式的十分钟有效期。
  let ttl = std::env::var("WHARF_GATE_ACCESS_SECS")
    .ok()
    .and_then(|v| v.parse::<i64>().ok())
    .filter(|n| *n > 0 && *n <= ACCESS_TTL)
    .unwrap_or(ACCESS_TTL);
  let token = if ttl == ACCESS_TTL {
    sign(key, user, host, now)
  } else {
    sign_ttl(key, user, host, now, ttl)
  };
  gate_cookie("wharf_gate", &token, ttl)
}
pub(super) async fn rt_user(
  db: &Db,
  headers: &HeaderMap,
  host: &str,
) -> Result<Option<String>, ApiError> {
  let key = rt_key(db).await?;
  let Some(hash) = cookie(headers, "wharf_gate_rt")
    .and_then(|t| rt_parse(&key, t, host, now_ms() / 1000))
  else {
    return Ok(None);
  };
  Ok(session(db, hash).await?.map(|(user, _)| user))
}
pub(super) fn verify(
  key: &SigningKey,
  token: &str,
  host: &str,
  now: i64,
) -> Option<String> {
  let parts: Vec<_> = token.split('.').collect();
  if parts.len() != 3 {
    return None;
  }
  let head: serde_json::Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?)
      .ok()?;
  if head["alg"] != "EdDSA" {
    return None;
  }
  let signature = ed25519_dalek::Signature::from_slice(
    &URL_SAFE_NO_PAD.decode(parts[2]).ok()?,
  )
  .ok()?;
  key
    .verifying_key()
    .verify_strict(
      format!("{}.{}", parts[0], parts[1]).as_bytes(),
      &signature,
    )
    .ok()?;
  let claims: serde_json::Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?)
      .ok()?;
  if host.is_empty()
    || claims["iss"] != "wharf"
    || claims["aud"].as_str() != Some(host)
    || claims["exp"].as_i64()? <= now
  {
    return None;
  }
  let user = claims["sub"].as_str()?;
  (!user.is_empty()).then(|| user.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  const HOST: &str = "a.example.test";

  #[test]
  fn access_verify() {
    let key = SigningKey::from_bytes(&[0; 32]);
    let token = sign(&key, "admin", HOST, 1700000000);
    assert_eq!(
      token,
      "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhLmV4YW1wbGUudGVzdCIsImV4cCI6MTcwMDAwMDYwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJ3aGFyZiIsInN1YiI6ImFkbWluIn0.mA9nTq0irJFh-Gxp7BiJFOSovAJbyyicFL_a5cl1FOH-8FbuBVqAHoZJnLqLNxiiYBckxNthjjFNUc8gi6NDBQ"
    );
    assert_eq!(
      verify(&key, &token, HOST, 1700000001).as_deref(),
      Some("admin")
    );
    assert!(
      verify(&key, &token, "b.example.test", 1700000001).is_none()
    );
    assert!(verify(&key, &token, HOST, 1700000600).is_none());
    assert!(
      verify(
        &SigningKey::from_bytes(&[2; 32]),
        &token,
        HOST,
        1700000001
      )
      .is_none()
    );
    assert!(rt_parse(&[0; 32], &token, HOST, 1700000001).is_none());
  }

  #[test]
  fn refresh_signature_and_expiry() {
    let hash = "a".repeat(64);
    let key = [7; 32];
    let good = rt_sign(&key, &hash, HOST, 2000);
    assert_eq!(rt_parse(&key, &good, HOST, 1000), Some(hash.clone()));
    assert!(rt_parse(&key, &good, "b.example.test", 1000).is_none());
    assert!(rt_parse(&[8; 32], &good, HOST, 1000).is_none());
    assert!(rt_parse(&key, &good, HOST, 2000).is_none());
    assert!(
      rt_parse(&key, &good.replace(".2000.", ".3000."), HOST, 1000)
        .is_none()
    );

    let legacy = format!("{hash}.2000");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(legacy.as_bytes());
    let legacy = format!(
      "{legacy}.{}",
      URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    assert!(rt_parse(&key, &legacy, HOST, 1000).is_none());
  }

  #[test]
  fn host_normalization() {
    assert_eq!(
      normalize_host(" A.example.test:443 ").as_deref(),
      Some(HOST)
    );
    assert_eq!(normalize_host("a.example.test :443"), None);
  }
}
