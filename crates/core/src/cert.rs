//! 从 DER 编码的叶证书读取到期时间和探测所需的标识信息。

use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};
use wharf_api_types::net_probe::NetProbeCertificate;

/// 少于这么多天标黄。
pub const WARN_DAYS: i64 = 14;

/// 读一个 TLV，返回 (标签, 内容, 剩余)。
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
  let (&tag, b) = b.split_first()?;
  let (&first, mut b) = b.split_first()?;
  let len = if first < 0x80 {
    first as usize
  } else {
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < n {
      return None;
    }
    let len = b[..n].iter().fold(0usize, |a, &x| a << 8 | x as usize);
    b = &b[n..];
    len
  };
  (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

fn issuer_and_rest(der: &[u8]) -> Option<(&[u8], &[u8])> {
  let (0x30, cert, _) = tlv(der)? else {
    return None;
  };
  let (0x30, tbs, _) = tlv(cert)? else {
    return None;
  };
  let (tag, _, mut rest) = tlv(tbs)?;
  if tag == 0xa0 {
    // 有版本号时，序列号在后面。
    rest = tlv(rest)?.2;
  }
  let rest = tlv(rest)?.2; // 签名算法
  let (0x30, issuer, rest) = tlv(rest)? else {
    return None;
  };
  Some((issuer, rest))
}

pub fn pem_not_after(pem: &str) -> Option<DateTime<Utc>> {
  use base64::{Engine, engine::general_purpose::STANDARD};
  let base64: String = pem
    .trim()
    .strip_prefix("-----BEGIN CERTIFICATE-----")?
    .strip_suffix("-----END CERTIFICATE-----")?
    .lines()
    .map(str::trim)
    .collect();
  not_after(&STANDARD.decode(base64).ok()?)
}

pub fn not_after(der: &[u8]) -> Option<DateTime<Utc>> {
  let (_, rest) = issuer_and_rest(der)?;
  let (0x30, validity, _) = tlv(rest)? else {
    return None;
  };
  expiry(validity)
}

fn expiry(validity: &[u8]) -> Option<DateTime<Utc>> {
  let (_, _, rest) = tlv(validity)?;
  let (tag, time, _) = tlv(rest)?;
  let text = std::str::from_utf8(time).ok()?;
  let full = match tag {
    0x17 => {
      let yy: u32 = text.get(..2)?.parse().ok()?;
      format!("{}{text}", if yy >= 50 { "19" } else { "20" })
    }
    0x18 => text.to_string(),
    _ => return None,
  };
  NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%SZ")
    .ok()
    .map(|t| t.and_utc())
}

pub fn probe_info(
  der: &[u8],
  host: &str,
  now: DateTime<Utc>,
) -> Option<(NetProbeCertificate, bool)> {
  let (issuer, rest) = issuer_and_rest(der)?;
  let (0x30, validity, rest) = tlv(rest)? else {
    return None;
  };
  let (0x30, subject, rest) = tlv(rest)? else {
    return None;
  };
  let (_, _, rest) = tlv(rest)?; // subjectPublicKeyInfo
  let not_after = expiry(validity)?;
  let subject_cn = attribute(subject, 3);
  let issuer = attribute(issuer, 3).or_else(|| attribute(issuer, 10));
  let host_ip = host.parse::<IpAddr>().ok();
  let mut san = Vec::new();
  let mut matches_host = false;
  if let Some(names) = alternative_names(rest) {
    for (tag, name) in elements(names) {
      match tag {
        0x82 => {
          if let Ok(name) = std::str::from_utf8(name) {
            matches_host |=
              host_ip.is_none() && dns_name_matches(name, host);
            if san.len() < 20 {
              san.push(name.to_string());
            }
          }
        }
        0x87 => {
          let ip = match name.len() {
            4 => <[u8; 4]>::try_from(name).ok().map(IpAddr::from),
            16 => <[u8; 16]>::try_from(name).ok().map(IpAddr::from),
            _ => None,
          };
          matches_host |= host_ip.is_some() && ip == host_ip;
        }
        _ => {}
      }
    }
  }
  Some((
    NetProbeCertificate {
      subject_cn,
      issuer,
      san,
      not_after,
      days_left: (not_after - now).num_days(),
    },
    matches_host,
  ))
}

fn elements(mut der: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
  std::iter::from_fn(move || {
    let (tag, data, rest) = tlv(der)?;
    der = rest;
    Some((tag, data))
  })
}

fn attribute(name: &[u8], id: u8) -> Option<String> {
  elements(name)
    .filter(|(tag, _)| *tag == 0x31)
    .flat_map(|(_, rdn)| elements(rdn))
    .filter(|(tag, _)| *tag == 0x30)
    .find_map(|(_, entry)| {
      let (0x06, oid, rest) = tlv(entry)? else {
        return None;
      };
      if oid != [0x55, 0x04, id] {
        return None;
      }
      let (tag, value, _) = tlv(rest)?;
      match tag {
        0x0c | 0x13 | 0x16 => {
          std::str::from_utf8(value).ok().map(str::to_string)
        }
        0x1e if value.len().is_multiple_of(2) => String::from_utf16(
          &value
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
        )
        .ok(),
        _ => None,
      }
    })
}

fn alternative_names(extensions: &[u8]) -> Option<&[u8]> {
  let (_, explicit) =
    elements(extensions).find(|(tag, _)| *tag == 0xa3)?;
  let (0x30, list, _) = tlv(explicit)? else {
    return None;
  };
  elements(list).filter(|(tag, _)| *tag == 0x30).find_map(
    |(_, extension)| {
      let (0x06, [0x55, 0x1d, 0x11], value) = tlv(extension)? else {
        return None;
      };
      let (0x04, octets) =
        elements(value).find(|(tag, _)| *tag == 0x04)?
      else {
        return None;
      };
      let (0x30, names, _) = tlv(octets)? else {
        return None;
      };
      Some(names)
    },
  )
}

fn dns_name_matches(name: &str, host: &str) -> bool {
  let host = host.trim_end_matches('.');
  name.eq_ignore_ascii_case(host)
    || name.strip_prefix("*.").is_some_and(|suffix| {
      host.split_once('.').is_some_and(|(label, rest)| {
        !label.is_empty() && suffix.eq_ignore_ascii_case(rest)
      })
    })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_probe_certificate() {
    let der = include_bytes!("testdata/net-probe.der");
    let now = DateTime::parse_from_rfc3339("2027-11-24T13:12:25Z")
      .unwrap()
      .to_utc();
    let (cert, matches_host) =
      probe_info(der, "www.probe.example.test", now).unwrap();
    assert_eq!(
      cert.subject_cn.as_deref(),
      Some("probe.example.test")
    );
    assert_eq!(cert.issuer.as_deref(), Some("probe.example.test"));
    assert_eq!(
      cert.san,
      ["probe.example.test", "*.probe.example.test"]
    );
    assert_eq!(
      cert.not_after.to_rfc3339(),
      "2027-11-25T13:12:25+00:00"
    );
    assert_eq!(cert.days_left, 1);
    assert!(matches_host);
    assert!(!probe_info(der, "other.example.test", now).unwrap().1);
    assert!(probe_info(der, "192.0.2.1", now).unwrap().1);
  }

  #[test]
  fn reads_not_after() {
    // 手拼的最小结构：版本、序列号、算法、签发者、有效期（UTCTime）。
    let validity = [
      0x30, 0x1e, 0x17, 0x0d, b'2', b'6', b'0', b'1', b'0', b'1',
      b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x17, 0x0d, b'2',
      b'7', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'5', b'0',
      b'6', b'Z',
    ];
    let mut tbs =
      vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
    tbs.extend([0x30, 0x00, 0x30, 0x00]);
    tbs.extend(validity);
    let mut cert = vec![0x30, tbs.len() as u8];
    cert.extend(tbs);
    let mut der = vec![0x30, cert.len() as u8];
    der.extend(cert);
    assert_eq!(
      not_after(&der).unwrap().to_rfc3339(),
      "2027-02-03T04:05:06+00:00"
    );
    assert!(not_after(&der[..10]).is_none());
  }
}
