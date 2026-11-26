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
      if raw.is_empty() {
        return Err(ApiError::invalid("allowed_from 里不能有空项"));
      }
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
      if name.trim().is_empty() {
        return Err(ApiError::invalid("services 里不能有空项"));
      }
      validate_name("服务", name)?;
    }
    self.services.sort_unstable();
    self.services.dedup();
    if self.perms.is_empty() {
      return Err(
        ApiError::invalid("perms 不能为空，至少要指定一个权限点")
          .with_hint(
            "可选：read、plan、apply、confirm、exec、host、admin",
          ),
      );
    }
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
