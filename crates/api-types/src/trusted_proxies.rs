use std::net::IpAddr;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ApiError;

/// Caddy 网关的可信上游代理配置。
#[derive(
  Debug,
  Clone,
  Default,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  JsonSchema,
)]
pub struct TrustedProxiesSpec {
  /// 自动同步并信任 Cloudflare 官方回源网段（IPv4 + IPv6）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub cloudflare: bool,
  /// 自动包含本集群所有网关和组网服务器的实际地址（精确 /32 或 /128）。
  #[serde(default, skip_serializing_if = "std::ops::Not::not")]
  pub cluster: bool,
  /// 额外手动指定的可信代理 IP 或 CIDR（如前置 CDN 或局域网反代）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub cidrs: Vec<String>,
}

impl TrustedProxiesSpec {
  pub fn is_empty(&self) -> bool {
    !self.cloudflare && !self.cluster && self.cidrs.is_empty()
  }

  pub fn normalize(&mut self) -> Result<(), ApiError> {
    if self.cidrs.len() > 64 {
      return Err(ApiError::invalid(
        "trusted_proxies 最多允许 64 条自定义地址",
      ));
    }
    let mut cidrs = self
      .cidrs
      .iter()
      .map(|cidr| parse_cidr(cidr).map(|net| net.to_string()))
      .collect::<Result<Vec<_>, _>>()?;
    cidrs.sort();
    cidrs.dedup();
    self.cidrs = cidrs;
    Ok(())
  }
}

pub fn parse_cidr(raw: &str) -> Result<IpNet, ApiError> {
  let raw = raw.trim();
  let net = raw
    .parse::<IpNet>()
    .or_else(|_| {
      raw
        .parse::<IpAddr>()
        .map(|ip| IpNet::from(ip.to_canonical()))
    })
    .map_err(|_| {
      ApiError::invalid("trusted_proxies 地址必须是合法的 IP 或 CIDR")
    })?
    .trunc();
  let net = match net {
    IpNet::V6(v6) if v6.prefix_len() >= 96 => {
      if let Some(ip) = v6.addr().to_ipv4_mapped() {
        IpNet::V4(
          ipnet::Ipv4Net::new(ip, v6.prefix_len() - 96)
            .expect("mapped IPv4 prefix"),
        )
      } else {
        net
      }
    }
    _ => net,
  };
  if net.prefix_len() == 0 {
    return Err(ApiError::invalid(
      "trusted_proxies 不能填写 0.0.0.0/0 或 ::/0，否则任何人都能伪造客户端地址",
    ));
  }
  Ok(net)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn normalizes_and_deduplicates() {
    let mut spec = TrustedProxiesSpec {
      cidrs: ["203.0.113.7/24", "203.0.113.0/24", "100.64.0.7"]
        .map(str::to_string)
        .to_vec(),
      ..Default::default()
    };
    spec.normalize().unwrap();
    assert_eq!(spec.cidrs, ["100.64.0.7/32", "203.0.113.0/24"]);
  }

  #[test]
  fn rejects_invalid_or_excessive_ranges() {
    for bad in ["", "invalid", "0.0.0.0/0", "::/0", "::ffff:0:0/96"] {
      assert!(parse_cidr(bad).is_err());
    }
    assert!(
      TrustedProxiesSpec {
        cidrs: vec!["203.0.113.7".into(); 65],
        ..Default::default()
      }
      .normalize()
      .is_err()
    );
  }
}
