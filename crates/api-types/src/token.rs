//! 访问令牌设置的规范化，控制面保存和 CLI 预览使用同一份规则。

use std::net::IpAddr;

use chrono::DateTime;
use ipnet::IpNet;

use crate::{
  ApiError, validate_name,
  view::{Perm, TokenSettings},
};

impl TokenSettings {
  pub fn normalize(&mut self) -> Result<(), ApiError> {
    self.expires_at = self.expires_at.and_then(|time| {
      DateTime::from_timestamp_millis(time.timestamp_millis())
    });
    for value in &mut self.allowed_from {
      let raw = value.trim();
      let range = raw
        .parse::<IpNet>()
        .or_else(|_| raw.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| {
          ApiError::invalid(format!(
            "来源地址 {raw} 不是合法的地址或网段"
          ))
          .with_hint(
            "例如 100.64.0.0/10、fd7a:115c:a1e0::/48 或 203.0.113.7",
          )
        })?;
      *value = range.trunc().to_string();
    }
    self.allowed_from.sort_unstable();
    self.allowed_from.dedup();
    for name in &self.services {
      validate_name("服务", name)?;
    }
    self.services.sort_unstable();
    self.services.dedup();
    self.perms.push(Perm::Read);
    self.perms.sort_unstable();
    self.perms.dedup();
    Ok(())
  }
}

pub fn ip_in_ranges(ip: IpAddr, ranges: &[String]) -> bool {
  ranges.iter().any(|range| {
    range.parse::<IpNet>().is_ok_and(|net| {
      net.contains(&ip) || net.contains(&ip.to_canonical())
    })
  })
}
