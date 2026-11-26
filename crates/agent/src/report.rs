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

use crate::{
  docker::Docker,
  network_subnets::{self, is_bridge},
};

/// 公网 IPv4 探测地址：国内能直连的放前面，海外兜底放后面。
const PUBLIC_IP_URLS: &[&str] = &[
  "https://4.ipw.cn",
  "https://ip.3322.net",
  "https://ddns.oray.com/checkip",
  "https://myip.ipip.net",
  "https://api4.ipify.org",
  "https://api.ipify.org",
];
const PUBLIC_IP_TTL: Duration = Duration::from_secs(30 * 60);
const PUBLIC_IP_RETRY_TTL: Duration = Duration::from_secs(5 * 60);

/// 探测时间和结果。
type CachedIp = (Instant, Option<String>);

#[derive(Clone)]
pub struct Reporter {
  docker: Docker,
  /// 环境变量 `WHARF_PUBLIC_IP` 的覆盖值。
  public_ip: Option<String>,
  cache: Arc<Mutex<Option<CachedIp>>>,
  sampler: Arc<Mutex<crate::metrics::Sampler>>,
  egress: Arc<Mutex<crate::external::EgressCache>>,
  subnets: Arc<Mutex<network_subnets::Cache>>,
}

impl Reporter {
  pub fn new(docker: Docker, public_ip: Option<String>) -> Self {
    Self {
      docker,
      public_ip,
      cache: Default::default(),
      sampler: Default::default(),
      egress: Default::default(),
      subnets: Default::default(),
    }
  }

  /// 资源采样，只由定时上报调用（速率按两次调用的间隔算）。
  pub async fn metrics(
    &self,
    ctx: &crate::exec::Ctx,
  ) -> Option<wharf_api_types::agent::Metrics> {
    let disk = disk_stat(&self.docker.data_dir);
    self
      .sampler
      .lock()
      .await
      .sample(&self.docker, disk, ctx)
      .await
  }

  pub async fn report(&self, refresh: bool) -> AgentReport {
    let (
      (docker_version, compose_version),
      egress,
      quota,
      (host_subnets, docker_subnets),
    ) = tokio::join!(
      self.docker.versions(),
      async {
        let ipv4 = self.public_ip(refresh).await;
        self.egress.lock().await.get(ipv4).await
      },
      crate::external::quota(),
      async { self.subnets.lock().await.collect(&self.docker).await },
    );
    AgentReport {
      version: wharf_api_types::VERSION.to_string(),
      hostname: hostname(),
      os: std::env::consts::OS.to_string(),
      arch: std::env::consts::ARCH.to_string(),
      docker_version,
      compose_version,
      private_addr: detect_private(),
      lan_ips: lan_ips(),
      public_ip: self
        .public_ip
        .clone()
        .or_else(|| egress.ipv4.clone()),
      egress_info: Some(egress),
      docker_quota: Some(quota),
      data_dir: self.docker.data_dir.display().to_string(),
      build: wharf_api_types::BUILD.to_string(),
      disk: disk(&self.docker.data_dir),
      docker_disk: docker_disk(&self.docker.data_dir),
      agent_memory: None,
      metrics: None,
      time_ms: None,
      log_hits: vec![],
      host_subnets,
      docker_subnets,
    }
  }

  async fn public_ip(&self, refresh: bool) -> Option<String> {
    let mut cache = self.cache.lock().await;
    if let Some((at, ip)) = &*cache
      && !refresh
      && at.elapsed()
        < if ip.is_some() {
          PUBLIC_IP_TTL
        } else {
          PUBLIC_IP_RETRY_TTL
        }
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

fn lan_ips() -> Vec<String> {
  filter_lan_ips(&ifaces())
}

/// 仅保留 RFC 1918 私网地址，排除组网和 Docker 网桥。
fn filter_lan_ips(ifaces: &[Iface]) -> Vec<String> {
  let mut ips: Vec<_> = ifaces
    .iter()
    .filter(|i| i.ip.is_private())
    .filter(|i| !DETECTORS.iter().any(|(_, m)| m(i)))
    .filter(|i| !is_bridge(&i.name))
    .map(|i| i.ip.to_string())
    .collect();
  ips.sort();
  ips.dedup();
  ips
}

/// Tailscale 的地址段是 100.64.0.0/10。
fn is_tailscale(iface: &Iface) -> bool {
  !is_bridge(&iface.name) && is_cgnat(iface.ip)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
  let [a, b, ..] = ip.octets();
  a == 100 && (64..128).contains(&b)
}

fn extract_ipv4(text: &str) -> Option<Ipv4Addr> {
  let usable = |ip: Ipv4Addr| {
    !ip.is_private()
      && !ip.is_loopback()
      && !ip.is_link_local()
      && !ip.is_unspecified()
      && !ip.is_broadcast()
  };
  if let Ok(ip) = text.trim().parse::<Ipv4Addr>()
    && usable(ip)
  {
    return Some(ip);
  }
  text
    .split(|c: char| !c.is_ascii_digit() && c != '.')
    .filter_map(|token| token.parse::<Ipv4Addr>().ok())
    .find(|&ip| usable(ip))
}

async fn detect_public_ip_from(
  client: &reqwest::Client,
  urls: &[&str],
) -> Option<String> {
  for url in urls {
    let resp = match client.get(*url).send().await {
      Ok(r) if r.status().is_success() => r,
      Ok(r) => {
        tracing::debug!(
          "公网 IP 探测 {url} 返回 HTTP {}",
          r.status().as_u16()
        );
        continue;
      }
      Err(e) => {
        tracing::debug!("公网 IP 探测 {url} 失败：{e}");
        continue;
      }
    };
    let Ok(text) = resp.text().await else {
      continue;
    };
    if let Some(ip) = extract_ipv4(&text) {
      return Some(ip.to_string());
    }
  }
  None
}

async fn detect_public_ip() -> Option<String> {
  let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(6))
    .redirect(reqwest::redirect::Policy::none())
    .no_proxy()
    .user_agent("wharf-agent")
    .build()
    .ok()?;
  detect_public_ip_from(&client, PUBLIC_IP_URLS).await
}

/// agent 容器的根目录是 overlay，statvfs 看到的是 Docker 存储目录所在的磁盘。
/// 和数据目录是同一块盘（容量相同）时不重复报。
fn docker_disk(data_dir: &std::path::Path) -> Option<Disk> {
  let d = disk(std::path::Path::new("/"))?;
  (disk(data_dir).map(|x| x.total) != Some(d.total)).then_some(d)
}

fn disk(path: &std::path::Path) -> Option<Disk> {
  disk_stat(path).map(|(disk, _)| disk)
}

pub(crate) type DiskSample = (Disk, Option<(u64, u64)>);

/// 挂载进来的数据目录在宿主机的磁盘上，statvfs 看到的就是宿主机的容量。
fn disk_stat(path: &std::path::Path) -> Option<DiskSample> {
  use std::os::unix::ffi::OsStrExt;
  let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
  let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
  if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
    return None;
  }
  let block = st.f_frsize as u64;
  let total = st.f_files as u64;
  let free = st.f_ffree as u64;
  Some((
    Disk {
      total: st.f_blocks as u64 * block,
      free: st.f_bavail as u64 * block,
    },
    (total > 0).then(|| (total.saturating_sub(free), total)),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn lan_ips_only_reports_private_interfaces() {
    let ifaces = [
      ("eth0", "10.20.0.5"),
      ("eth1", "203.0.113.7"),
      ("eth2", "169.254.1.2"),
      ("tailscale0", "100.64.0.2"),
      ("docker0", "172.20.0.1"),
    ]
    .map(|(name, ip)| Iface {
      name: name.into(),
      ip: ip.parse().unwrap(),
    });
    assert_eq!(filter_lan_ips(&ifaces), ["10.20.0.5"]);
  }

  #[test]
  fn cgnat_range() {
    assert!(is_cgnat("100.64.0.1".parse().unwrap()));
    assert!(is_cgnat("100.101.102.103".parse().unwrap()));
    assert!(!is_cgnat("100.128.0.1".parse().unwrap()));
    assert!(!is_cgnat("192.168.1.10".parse().unwrap()));
  }

  #[test]
  fn extract_ipv4_parses_plain_and_text_responses() {
    assert_eq!(
      extract_ipv4("203.0.113.8\n"),
      Some("203.0.113.8".parse().unwrap())
    );
    assert_eq!(
      extract_ipv4(
        "<html><body>Current IP Address: 198.51.100.24</body></html>"
      ),
      Some("198.51.100.24".parse().unwrap())
    );
    assert_eq!(
      extract_ipv4("当前 IP：198.51.100.9  来自于：中国 北京 电信"),
      Some("198.51.100.9".parse().unwrap())
    );
    assert_eq!(extract_ipv4("127.0.0.1"), None);
    assert_eq!(extract_ipv4("192.168.1.1"), None);
  }

  #[tokio::test]
  async fn detect_public_ip_falls_back_to_second_url() {
    use tokio::{
      io::{AsyncReadExt, AsyncWriteExt},
      net::TcpListener,
    };

    async fn serve(reply: &'static str) -> String {
      let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
      let addr = listener.local_addr().unwrap();
      tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
          let mut buf = [0u8; 1024];
          let _ = conn.read(&mut buf).await;
          let _ = conn.write_all(reply.as_bytes()).await;
        }
      });
      format!("http://{addr}")
    }

    let first = serve(
      "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\n203.0.113.1",
    )
    .await;
    let second = serve(
      "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n203.0.113.42",
    )
    .await;
    let client = reqwest::Client::builder()
      .timeout(Duration::from_secs(2))
      .redirect(reqwest::redirect::Policy::none())
      .no_proxy()
      .user_agent("wharf-agent")
      .build()
      .unwrap();
    let urls = [first.as_str(), second.as_str()];
    assert_eq!(
      detect_public_ip_from(&client, &urls).await.as_deref(),
      Some("203.0.113.42")
    );
  }
}
