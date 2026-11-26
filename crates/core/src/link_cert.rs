//! 反向隧道的集群 CA 和网关叶证书。

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use rcgen::{
  BasicConstraints, Certificate, CertificateParams, DnType,
  ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
  PKCS_ECDSA_P256_SHA256,
};
use rusqlite::Transaction;
use time::OffsetDateTime;
use wharf_api_types::{
  ApiError, ErrorCode,
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::{
  cert::pem_not_after,
  db::{self, CredentialsKey},
  hub::Hub,
  link::{
    self, CA_CERT_SECRET, CA_KEY_SECRET, CERT_PREFIX, KEY_PREFIX,
    LINK_HOST,
  },
  render::{self, Net},
  snapshot::Snapshot,
};

pub const CA_TTL_DAYS: i64 = 3650;
pub const LEAF_TTL_DAYS: i64 = 1095;
pub const LEAF_RENEW_DAYS: i64 = 90;
pub const LEAF_ALERT_DAYS: i64 = 30;
pub const CA_WARN_DAYS: i64 = 180;

pub struct CertPair {
  pub cert: String,
  pub key: String,
}

#[derive(Debug, Clone)]
pub struct LinkCertState {
  pub fingerprint: String,
  pub expires_at: Option<DateTime<Utc>>,
}

impl LinkCertState {
  pub fn from_secrets(
    secrets: &BTreeMap<String, String>,
  ) -> BTreeMap<String, Self> {
    secrets
      .iter()
      .filter_map(|(name, cert)| {
        let gateway = name.strip_prefix(CERT_PREFIX)?;
        let key = secrets.get(&format!("{KEY_PREFIX}{gateway}"))?;
        Some((
          gateway.to_string(),
          Self {
            fingerprint: fingerprint(cert, key),
            expires_at: pem_not_after(cert),
          },
        ))
      })
      .collect()
  }
}

fn signing_error(_: rcgen::Error) -> ApiError {
  ApiError::internal("无法签发隧道证书")
}

fn validity(
  params: &mut CertificateParams,
  now: OffsetDateTime,
  days: i64,
) {
  params.not_before = now - time::Duration::minutes(5);
  params.not_after = now + time::Duration::days(days);
}

fn ca_params(now: OffsetDateTime) -> CertificateParams {
  let mut params = CertificateParams::default();
  validity(&mut params, now, CA_TTL_DAYS);
  params
    .distinguished_name
    .push(DnType::CommonName, "Wharf Link CA");
  params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
  params.key_usages =
    vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
  params
}

fn generate_ca(
  now: OffsetDateTime,
) -> Result<(Certificate, KeyPair), rcgen::Error> {
  let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
  Ok((ca_params(now).self_signed(&key)?, key))
}

fn issue_gateway_cert(
  issuer: &Certificate,
  issuer_key: &KeyPair,
  gateway: &str,
  now: OffsetDateTime,
) -> Result<(Certificate, KeyPair), rcgen::Error> {
  let mut params =
    CertificateParams::new(vec![LINK_HOST.to_string()])?;
  validity(&mut params, now, LEAF_TTL_DAYS);
  params
    .distinguished_name
    .push(DnType::CommonName, LINK_HOST);
  params
    .distinguished_name
    .push(DnType::OrganizationName, "Wharf");
  params.distinguished_name.push(
    DnType::OrganizationalUnitName,
    format!("gateway:{gateway}"),
  );
  params.key_usages = vec![
    KeyUsagePurpose::DigitalSignature,
    KeyUsagePurpose::KeyEncipherment,
  ];
  params.extended_key_usages =
    vec![ExtendedKeyUsagePurpose::ServerAuth];
  let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
  Ok((params.signed_by(&key, issuer, issuer_key)?, key))
}

fn signing_time(now: i64) -> Result<OffsetDateTime, ApiError> {
  OffsetDateTime::from_unix_timestamp_nanos(
    i128::from(now) * 1_000_000,
  )
  .map_err(|_| ApiError::internal("签发隧道证书的时间不合法"))
}

pub fn ensure_ca(
  conn: &Transaction<'_>,
  key: &CredentialsKey,
  now: i64,
) -> Result<CertPair, ApiError> {
  match (
    key.secret(conn, CA_CERT_SECRET)?,
    key.secret(conn, CA_KEY_SECRET)?,
  ) {
    (Some(cert), Some(key)) => Ok(CertPair { cert, key }),
    (None, None) => {
      let (cert, ca_key) =
        generate_ca(signing_time(now)?).map_err(signing_error)?;
      let pair = CertPair {
        cert: cert.pem(),
        key: ca_key.serialize_pem(),
      };
      key.put_secret(conn, CA_CERT_SECRET, &pair.cert, now, false)?;
      key.put_secret(conn, CA_KEY_SECRET, &pair.key, now, false)?;
      Ok(pair)
    }
    _ => Err(ApiError::internal("隧道 CA 证书和私钥不完整")),
  }
}

pub fn ensure_gateway_cert(
  conn: &Transaction<'_>,
  key: &CredentialsKey,
  gateway: &str,
  now: i64,
  force_rotate: bool,
) -> Result<CertPair, ApiError> {
  let cert_name = db::scoped_secret_name(CERT_PREFIX, gateway)?;
  let key_name = db::scoped_secret_name(KEY_PREFIX, gateway)?;
  let ca = ensure_ca(conn, key, now)?;
  if !force_rotate
    && let (Some(cert), Some(key)) =
      (key.secret(conn, &cert_name)?, key.secret(conn, &key_name)?)
    && !needs_renew(pem_not_after(&cert), db::to_time(now))
  {
    return Ok(CertPair { cert, key });
  }

  let now_time = signing_time(now)?;
  let ca_key = KeyPair::from_pem(&ca.key).map_err(signing_error)?;
  // rcgen 0.13 用签发者证书携带 DN 和密钥用途。用同一私钥重建签发参数，库内的信任根保持原样。
  let issuer = ca_params(now_time)
    .self_signed(&ca_key)
    .map_err(signing_error)?;
  let (cert, leaf_key) =
    issue_gateway_cert(&issuer, &ca_key, gateway, now_time)
      .map_err(signing_error)?;
  let pair = CertPair {
    cert: cert.pem(),
    key: leaf_key.serialize_pem(),
  };
  key.put_secret(conn, &cert_name, &pair.cert, now, true)?;
  key.put_secret(conn, &key_name, &pair.key, now, true)?;
  Ok(pair)
}

pub fn fingerprint(cert: &str, key: &str) -> String {
  render::hash(&format!("{cert}\n{key}"))
}

pub fn config_hash(config: &str, tag: &str) -> String {
  render::hash(&format!("{config}\n#wharf-link-cert:{tag}"))
}

pub fn needs_renew(
  expires_at: Option<DateTime<Utc>>,
  now: DateTime<Utc>,
) -> bool {
  expires_at
    .is_none_or(|at| at - now <= Duration::days(LEAF_RENEW_DAYS))
}

pub fn days_left(
  expires_at: DateTime<Utc>,
  now: DateTime<Utc>,
) -> i64 {
  let remaining = expires_at - now;
  let days = remaining.num_days();
  days + i64::from(remaining > Duration::days(days.max(0)))
}

pub fn require_gateway_agent(
  hub: &Hub,
  server: &str,
  gateway: &str,
) -> Result<(), ApiError> {
  if hub.supports_gateway_extra_files(server) {
    return Ok(());
  }
  Err(ApiError::new(
    ErrorCode::Conflict,
    format!("服务器 {server} 的 agent 版本旧，不支持下发隧道证书（网关 {gateway} 需要反向隧道）"),
  )
  .with_hint("先升级这台机器的 agent，再重新 plan / apply")
  .suggest(format!("wharf server upgrade {server}")))
}

/// 只检查当前承载反向隧道的网关。CA 的到期时间单独从库内证书读取。
pub fn leaf_expiries<'a>(
  snap: &'a Snapshot,
  net: &'a Net,
) -> impl Iterator<Item = (&'a str, DateTime<Utc>)> {
  net.link_certs.iter().filter_map(|(name, cert)| {
    let gateway = snap.world.gateways.get(name)?;
    if !link::caddy_site(&snap.world, net, name, &gateway.spec)
      .unwrap_or(false)
    {
      return None;
    }
    Some((name.as_str(), cert.expires_at?))
  })
}

pub fn ca_expiry(snap: &Snapshot) -> Option<DateTime<Utc>> {
  snap
    .secrets
    .get(CA_CERT_SECRET)
    .and_then(|pem| pem_not_after(pem))
}

pub fn issues(snap: &Snapshot, net: &Net) -> Vec<Issue> {
  issues_at(snap, net, Utc::now())
}

fn issues_at(
  snap: &Snapshot,
  net: &Net,
  now: DateTime<Utc>,
) -> Vec<Issue> {
  let mut issues: Vec<_> = leaf_expiries(snap, net)
    .filter_map(|(name, at)| {
      let days = days_left(at, now);
      (days <= LEAF_RENEW_DAYS).then(|| {
        let (alert, ack) =
          crate::rules::issue_alert("link_cert_expiring", name);
        Issue {
          code: "link_cert_expiring".into(),
          level: if days <= 0 {
            IssueLevel::Fault
          } else {
            IssueLevel::Warn
          },
          subject: Some(IssueSubject {
            kind: "gateway".into(),
            name: name.into(),
          }),
          title: if days <= 0 {
            format!("网关 {name} 的隧道证书已过期")
          } else {
            format!("网关 {name} 的隧道证书 {days} 天后到期")
          },
          hint: Some(
            "执行 wharf plan && wharf apply 自动续签".into(),
          ),
          ack,
          alert,
        }
      })
    })
    .collect();
  if let Some(at) = ca_expiry(snap) {
    let days = days_left(at, now);
    if days <= CA_WARN_DAYS {
      let (alert, ack) =
        crate::rules::issue_alert("link_ca_expiring", "ca");
      issues.push(Issue {
        code: "link_ca_expiring".into(),
        level: if days <= 0 {
          IssueLevel::Fault
        } else {
          IssueLevel::Warn
        },
        subject: None,
        title: if days <= 0 {
          "集群隧道 CA 证书已过期".into()
        } else {
          format!("集群隧道 CA 证书 {days} 天后到期")
        },
        hint: None,
        ack,
        alert,
      });
    }
  }
  issues
}

#[cfg(test)]
mod tests;
