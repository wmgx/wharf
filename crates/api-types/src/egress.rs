//! 出口的分流规则（p8）：哪些域名经出口机器出去，其余直连。控制面和 agent 共用。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 出口机器上的 HTTP 代理端口（只听内网地址，要口令）。
pub const SERVE_PORT: u16 = 8118;
/// 使用出口的机器上，本地分流代理的端口（只听 127.0.0.1 和 docker 网桥地址）。
pub const LOCAL_PORT: u16 = 8119;

/// 服务器设置 `egress`：这台提供出口，以及经它出去的规则。
#[derive(
  Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct EgressSpec {
  /// `true`：除内网外全部经出口；`false`：只有命中预置分组和自定义域名的经出口。
  #[serde(default)]
  pub all: bool,
  /// 预置分组，见 [PRESETS]。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub presets: Vec<String>,
  /// 自定义域名：`example.com` 只匹配它自己，`*.example.com` 匹配所有子域名（不含自己）。
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub domains: Vec<String>,
}

/// 预置分组：(名字, 说明, 域名)。
pub const PRESETS: &[(&str, &str, &[&str])] = &[
  (
    "github",
    "GitHub（代码、release、ghcr）",
    &[
      "github.com",
      "*.github.com",
      "*.githubusercontent.com",
      "ghcr.io",
      "*.ghcr.io",
    ],
  ),
  (
    "dockerhub",
    "Docker Hub",
    &[
      "docker.io",
      "*.docker.io",
      "*.docker.com",
      "production.cloudflare.docker.com",
    ],
  ),
  ("cloudflare", "Cloudflare API", &["api.cloudflare.com"]),
  ("tailscale", "Tailscale", &["*.tailscale.com"]),
  (
    "go",
    "Go 模块",
    &[
      "proxy.golang.org",
      "sum.golang.org",
      "go.dev",
      "dl.google.com",
    ],
  ),
  ("npm", "npm", &["registry.npmjs.org", "*.npmjs.org"]),
  ("pypi", "PyPI", &["pypi.org", "files.pythonhosted.org"]),
];

impl EgressSpec {
  /// 展开成域名清单（预置分组 + 自定义），未知的分组名忽略。
  pub fn domains(&self) -> Vec<String> {
    let mut out: Vec<String> = PRESETS
      .iter()
      .filter(|(n, _, _)| self.presets.iter().any(|p| p == n))
      .flat_map(|(_, _, d)| d.iter().map(|s| s.to_string()))
      .chain(self.domains.iter().map(|d| d.trim().to_lowercase()))
      .filter(|d| !d.is_empty())
      .collect();
    out.sort();
    out.dedup();
    out
  }

  /// 不认识的分组名和写错的域名。
  pub fn validate(&self) -> Result<(), String> {
    if let Some(p) = self
      .presets
      .iter()
      .find(|p| !PRESETS.iter().any(|(n, _, _)| n == p))
    {
      let names: Vec<&str> =
        PRESETS.iter().map(|(n, _, _)| *n).collect();
      return Err(format!(
        "没有预置分组 {p}（可选：{}）",
        names.join("、")
      ));
    }
    for d in &self.domains {
      let bare = d.trim().trim_start_matches("*.");
      let ok = bare.contains('.')
        && bare.bytes().all(|c| {
          c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
        });
      if !ok {
        return Err(format!(
          "域名 {d} 写法不对，例如 example.com 或 *.example.com"
        ));
      }
    }
    Ok(())
  }
}

/// 这台主机要不要经出口：内网和本机地址永远直连。
pub fn via_exit(host: &str, all: bool, domains: &[String]) -> bool {
  let host = host.trim_end_matches('.').to_lowercase();
  if is_local(&host) {
    return false;
  }
  if all {
    return true;
  }
  domains.iter().any(|d| match d.strip_prefix("*.") {
    Some(base) => host.ends_with(&format!(".{base}")),
    None => host == *d,
  })
}

/// 本机、内网、组网地址和不带点的主机名（容器名等）。
fn is_local(host: &str) -> bool {
  if host == "localhost" || !host.contains('.') && !host.contains(':')
  {
    return true;
  }
  match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
    Ok(std::net::IpAddr::V4(ip)) => {
      let o = ip.octets();
      ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (64..128).contains(&o[1]))
    }
    Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback(),
    Err(_) => false,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn routes_by_rules() {
    let spec = EgressSpec {
      all: false,
      presets: vec!["github".into()],
      domains: vec!["*.example.com".into()],
    };
    let d = spec.domains();
    assert!(via_exit("github.com", false, &d));
    assert!(via_exit("objects.githubusercontent.com", false, &d));
    assert!(via_exit("a.example.com", false, &d));
    assert!(!via_exit("example.com", false, &d));
    assert!(!via_exit("registry.npmmirror.com", false, &d));
    assert!(via_exit("registry.npmmirror.com", true, &d));
    assert!(!via_exit("100.64.0.3", true, &d));
    assert!(!via_exit("192.168.1.2", true, &d));
    assert!(!via_exit("db", true, &d));
    assert!(spec.validate().is_ok());
    assert!(
      EgressSpec {
        presets: vec!["nope".into()],
        ..Default::default()
      }
      .validate()
      .is_err()
    );
    assert!(
      EgressSpec {
        domains: vec!["bad host".into()],
        ..Default::default()
      }
      .validate()
      .is_err()
    );
  }
}
