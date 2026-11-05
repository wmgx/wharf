//! 从 DER 编码的证书里读到期时间，只走到 tbsCertificate.validity.notAfter，不校验。

use chrono::{DateTime, NaiveDateTime, Utc};

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

pub fn not_after(der: &[u8]) -> Option<DateTime<Utc>> {
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
  let rest = tlv(rest)?.2; // 签发者
  let (0x30, validity, _) = tlv(rest)? else {
    return None;
  };
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

#[cfg(test)]
mod tests {
  use super::*;

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
