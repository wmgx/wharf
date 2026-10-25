//! 机器信息上报：内网地址、公网 IP、docker 版本。

use std::{
  net::Ipv4Addr,
  sync::Arc,
  time::{Duration, Instant},
};

use tokio::sync::Mutex;
use wharf_api_types::{
  agent::{AgentReport, Disk},
  spec::{PrivateAddr, PrivateNetwork},
};

use crate::docker::Docker;

/// 公网 IP 探测地址，国内的放前面。
const PUBLIC_IP_URLS: &[&str] =
  &["https://4.ipw.cn", "https://api.ipify.org"];
const PUBLIC_IP_TTL: Duration = Duration::from_secs(30 * 60);

/// 探测时间和结果。
type CachedIp = (Instant, Option<String>);

#[derive(Clone)]
pub struct Reporter {
  docker: Docker,
  /// 环境变量 `WHARF_PUBLIC_IP` 的覆盖值。
  public_ip: Option<String>,
  cache: Arc<Mutex<Option<CachedIp>>>,
}

impl Reporter {
  pub fn new(docker: Docker, public_ip: Option<String>) -> Self {
    Self {
      docker,
      public_ip,
      cache: Default::default(),
    }
  }

  pub async fn report(&self, refresh: bool) -> AgentReport {
    let (docker_version, compose_version) =
      self.docker.versions().await;
    AgentReport {
      version: wharf_api_types::VERSION.to_string(),
      hostname: hostname(),
      os: std::env::consts::OS.to_string(),
      arch: std::env::consts::ARCH.to_string(),
      docker_version,
      compose_version,
      private_addr: detect_private(),
      lan_ips: lan_ips(),
      public_ip: self.public_ip(refresh).await,
      data_dir: self.docker.data_dir.display().to_string(),
      build: wharf_api_types::BUILD.to_string(),
      disk: disk(&self.docker.data_dir),
    }
  }

  async fn public_ip(&self, refresh: bool) -> Option<String> {
    if let Some(ip) = &self.public_ip {
      return Some(ip.clone());
    }
    let mut cache = self.cache.lock().await;
    if let Some((at, ip)) = &*cache
      && !refresh
      && at.elapsed() < PUBLIC_IP_TTL
    {
      return ip.clone();
    }
    let ip = detect_public_ip().await;
    *cache = Some((Instant::now(), ip.clone()));
    ip
  }
}

fn hostname() -> String {
  let mut buf = [0u8; 256];
  // SAFETY: buf 足够大，gethostname 保证以 0 结尾或截断。
  let ok = unsafe {
    libc::gethostname(
      buf.as_mut_ptr() as *mut libc::c_char,
      buf.len(),
    )
  } == 0;
  if !ok {
    return String::new();
  }
  let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
  String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// 组网检测：按顺序尝试，第一个命中的就是内网地址。
/// 以后支持别的组网工具时，在这里加一项。
const DETECTORS: &[(PrivateNetwork, Detector)] =
  &[(PrivateNetwork::Tailscale, is_tailscale)];

type Detector = fn(&Iface) -> bool;

struct Iface {
  name: String,
  ip: Ipv4Addr,
}

/// 只看网卡，不依赖组网工具的命令，所以 agent 在容器里（host 网络）也能拿到。
fn ifaces() -> Vec<Iface> {
  if_addrs::get_if_addrs()
    .unwrap_or_default()
    .into_iter()
    .filter_map(|iface| match iface.ip() {
      std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(Iface {
        name: iface.name,
        ip,
      }),
      _ => None,
    })
    .collect()
}

fn detect_private() -> Option<PrivateAddr> {
  let ifaces = ifaces();
  DETECTORS.iter().find_map(|(network, matches)| {
    ifaces.iter().find(|i| matches(i)).map(|i| PrivateAddr {
      ip: i.ip.to_string(),
      network: *network,
    })
  })
}

/// 不属于任何组网、也不是 docker 网桥的地址。
fn lan_ips() -> Vec<String> {
  ifaces()
    .into_iter()
    .filter(|i| !DETECTORS.iter().any(|(_, m)| m(i)))
    .filter(|i| !is_bridge(&i.name))
    .map(|i| i.ip.to_string())
    .collect()
}

fn is_bridge(name: &str) -> bool {
  name == "docker0"
    || name.starts_with("br-")
    || name.starts_with("veth")
}

/// Tailscale 的地址段是 100.64.0.0/10。
fn is_tailscale(iface: &Iface) -> bool {
  is_cgnat(iface.ip)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
  let [a, b, ..] = ip.octets();
  a == 100 && (64..128).contains(&b)
}

async fn detect_public_ip() -> Option<String> {
  let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(5))
    .build()
    .ok()?;
  for url in PUBLIC_IP_URLS {
    let Ok(resp) = client.get(*url).send().await else {
      continue;
    };
    let Ok(text) = resp.text().await else {
      continue;
    };
    if let Ok(ip) = text.trim().parse::<Ipv4Addr>() {
      return Some(ip.to_string());
    }
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cgnat_range() {
    assert!(is_cgnat("100.64.0.1".parse().unwrap()));
    assert!(is_cgnat("100.101.102.103".parse().unwrap()));
    assert!(!is_cgnat("100.128.0.1".parse().unwrap()));
    assert!(!is_cgnat("192.168.1.10".parse().unwrap()));
  }
}

/// 挂载进来的数据目录在宿主机的磁盘上，statvfs 看到的就是宿主机的容量。
fn disk(path: &std::path::Path) -> Option<Disk> {
  use std::os::unix::ffi::OsStrExt;
  let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
  let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
  if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
    return None;
  }
  let block = st.f_frsize as u64;
  Some(Disk {
    total: st.f_blocks as u64 * block,
    free: st.f_bavail as u64 * block,
  })
}
