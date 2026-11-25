//! 上报宿主机和 Docker bridge 已占用的 IPv4 网段。

use std::{
  collections::{BTreeMap, BTreeSet},
  net::Ipv4Addr,
  time::{Duration, Instant},
};

use serde::Deserialize;
use wharf_api_types::agent::DockerSubnet;

use crate::{docker::Docker, exec::Ctx};

const QUICK: Duration = Duration::from_secs(5);
const TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub struct Cache {
  ids: Vec<String>,
  inspected_at: Option<Instant>,
  subnets: Vec<DockerSubnet>,
  bridge_ifaces: BTreeSet<String>,
}

impl Cache {
  pub async fn collect(
    &mut self,
    docker: &Docker,
  ) -> (Vec<String>, Vec<DockerSubnet>) {
    let ctx = Ctx::detached();
    let listed = docker
      .cmd()
      .args([
        "network",
        "ls",
        "--filter",
        "driver=bridge",
        "--no-trunc",
        "-q",
      ])
      .timeout(QUICK)
      .run(&ctx)
      .await;
    let Ok(listed) = listed else {
      return (host_subnets(&self.bridge_ifaces), vec![]);
    };
    if !listed.success {
      return (host_subnets(&self.bridge_ifaces), vec![]);
    }
    let mut ids: Vec<_> = listed
      .stdout
      .split_whitespace()
      .map(str::to_string)
      .collect();
    ids.sort_unstable();
    if ids != self.ids
      || self.inspected_at.is_none_or(|at| at.elapsed() >= TTL)
    {
      *self = Self {
        ids,
        inspected_at: Some(Instant::now()),
        ..Self::default()
      };
      if !self.ids.is_empty() {
        let inspected = docker
          .cmd()
          .args(["network", "inspect", "--"])
          .args(self.ids.iter().map(String::as_str))
          .timeout(QUICK)
          .run(&ctx)
          .await;
        if let Ok(out) = inspected
          && out.success
          && let Ok(networks) =
            serde_json::from_str::<Vec<Bridge>>(&out.stdout)
        {
          for bridge in networks {
            if let Some(name) =
              bridge.options.as_ref().and_then(|options| {
                options.get("com.docker.network.bridge.name")
              })
            {
              self.bridge_ifaces.insert(name.clone());
            }
            self.subnets.extend(
              bridge.ipam.config.into_iter().flatten().filter_map(
                |pool| {
                  let subnet = pool.subnet?;
                  subnet
                    .split_once('/')?
                    .0
                    .parse::<Ipv4Addr>()
                    .ok()?;
                  Some(DockerSubnet {
                    name: bridge.name.clone(),
                    subnet,
                  })
                },
              ),
            );
          }
        }
      }
    }
    (host_subnets(&self.bridge_ifaces), self.subnets.clone())
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Bridge {
  name: String,
  options: Option<BTreeMap<String, String>>,
  #[serde(rename = "IPAM")]
  ipam: Ipam,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ipam {
  config: Option<Vec<Pool>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Pool {
  subnet: Option<String>,
}

pub fn is_bridge(name: &str) -> bool {
  matches!(name, "docker0" | "docker_gwbridge")
    || name.starts_with("br-")
    || name.starts_with("veth")
}

fn host_subnets(bridge_ifaces: &BTreeSet<String>) -> Vec<String> {
  let non_docker = |name: &str| {
    name != "lo" && !is_bridge(name) && !bridge_ifaces.contains(name)
  };
  let mut subnets: BTreeSet<String> = if_addrs::get_if_addrs()
    .unwrap_or_default()
    .into_iter()
    .filter(|iface| non_docker(&iface.name))
    .filter_map(|iface| {
      let if_addrs::IfAddr::V4(v4) = iface.addr else {
        return None;
      };
      (!v4.ip.is_loopback())
        .then(|| cidr(v4.ip, v4.netmask))
        .flatten()
    })
    .collect();
  let routes =
    std::fs::read_to_string("/proc/net/route").unwrap_or_default();
  subnets.extend(routes.lines().skip(1).filter_map(|line| {
    let mut fields = line.split_whitespace();
    if !non_docker(fields.next()?) {
      return None;
    }
    let addr = route_ipv4(fields.next()?)?;
    let flags = u32::from_str_radix(fields.nth(1)?, 16).ok()?;
    let mask = route_ipv4(fields.nth(3)?)?;
    if flags & 1 == 0
      || mask.is_unspecified()
      || addr.is_loopback()
      || addr.is_link_local()
    {
      return None;
    }
    cidr(addr, mask)
  }));
  subnets.into_iter().collect()
}

fn route_ipv4(hex: &str) -> Option<Ipv4Addr> {
  Some(Ipv4Addr::from(
    u32::from_str_radix(hex, 16).ok()?.to_le_bytes(),
  ))
}

fn cidr(addr: Ipv4Addr, mask: Ipv4Addr) -> Option<String> {
  let mask = u32::from(mask);
  let prefix = mask.leading_ones();
  (prefix != 0 && prefix + mask.trailing_zeros() == 32).then(|| {
    format!("{}/{prefix}", Ipv4Addr::from(u32::from(addr) & mask))
  })
}
