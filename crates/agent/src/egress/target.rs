use std::net::{IpAddr, SocketAddr};

use wharf_api_types::net_probe::{dns_target, is_public};

use super::{CONNECT_TIMEOUT, Policy};

#[derive(Debug, PartialEq)]
pub(super) struct Target {
  pub host: String,
  port: u16,
}

impl Target {
  pub fn parse(raw: &str, default: Option<u16>) -> Option<Self> {
    let (host, port) = if let Some(v6) = raw.strip_prefix('[') {
      let (host, rest) = v6.split_once(']')?;
      host.parse::<std::net::Ipv6Addr>().ok()?;
      let port = if rest.is_empty() {
        None
      } else {
        Some(rest.strip_prefix(':')?)
      };
      (host, port)
    } else {
      let (host, port) = raw
        .split_once(':')
        .map_or((raw, None), |(h, p)| (h, Some(p)));
      if host.contains(':') || !dns_target(host) {
        return None;
      }
      (host, port)
    };
    let port = match port {
      None => default?,
      Some(port) if port.bytes().all(|b| b.is_ascii_digit()) => {
        port.parse().ok()?
      }
      _ => return None,
    };
    (port != 0).then(|| Self {
      host: host.to_ascii_lowercase(),
      port,
    })
  }

  pub fn core(core_url: &str) -> Option<Self> {
    let url = reqwest::Url::parse(core_url).ok()?;
    Some(Self {
      host: url
        .host_str()?
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase(),
      port: url.port_or_known_default()?,
    })
  }

  pub fn authority(&self) -> String {
    if self.host.contains(':') {
      format!("[{}]:{}", self.host, self.port)
    } else {
      format!("{}:{}", self.host, self.port)
    }
  }

  pub fn blocked(&self, core: Option<&Self>, policy: Policy) -> bool {
    let host = self.host.trim_end_matches('.');
    if let Ok(ip) = host.parse::<IpAddr>() {
      return !self.allowed(ip, core, policy);
    }
    host == "localhost"
      || host.ends_with(".localhost")
      || matches!(host, "metadata" | "metadata.google.internal")
      || core.is_some_and(|core| {
        host == core.host && core.host.parse::<IpAddr>().is_err()
      })
  }

  fn allowed(
    &self,
    ip: IpAddr,
    core: Option<&Self>,
    policy: Policy,
  ) -> bool {
    let ip = ip.to_canonical();
    #[cfg(test)]
    if matches!(policy, Policy::AllowLoopbackForTest)
      && ip.is_loopback()
    {
      return true;
    }
    let _ = policy;
    is_public(ip)
      && !core.is_some_and(|core| {
        core.port == self.port
          && core
            .host
            .parse::<IpAddr>()
            .is_ok_and(|c| c.to_canonical() == ip)
      })
  }

  pub async fn resolve(
    &self,
    core: Option<&Self>,
    policy: Policy,
  ) -> Result<Vec<SocketAddr>, &'static str> {
    let addresses = if let Ok(ip) = self.host.parse::<IpAddr>() {
      vec![SocketAddr::new(ip.to_canonical(), self.port)]
    } else {
      tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::lookup_host((self.host.as_str(), self.port)),
      )
      .await
      .ok()
      .and_then(Result::ok)
      .ok_or("502 Bad Gateway")?
      .collect::<Vec<_>>()
    };
    if addresses.is_empty() {
      return Err("502 Bad Gateway");
    }
    if addresses
      .iter()
      .any(|a| !self.allowed(a.ip(), core, policy))
    {
      return Err("403 Forbidden");
    }
    Ok(addresses)
  }
}
