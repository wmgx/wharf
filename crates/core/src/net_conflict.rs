//! 对照已上报的 Docker bridge 网段和现有宿主机、组网及跨机地址。

use std::{collections::BTreeSet, net::Ipv4Addr};

use ipnet::Ipv4Net;
use wharf_api_types::{
  spec::{PrivateAddr, PrivateNetwork},
  view::{Issue, IssueLevel, IssueSubject},
};

use crate::snapshot::Snapshot;

pub const FIX: &str = r#"在 /etc/docker/daemon.json 设置不重叠的 default-address-pools（例如 [{"base":"10.200.0.0/16","size":24}]），再重建冲突的 Docker 网络"#;

pub fn conflicts(snap: &Snapshot) -> Vec<(&str, String)> {
  let mut has_tailscale = false;
  let mut peers = BTreeSet::new();
  for (name, server) in &snap.world.servers {
    let report = snap.agent(name).and_then(|a| a.report.as_ref());
    let private = server
      .settings
      .private_addr
      .iter()
      .chain(report.and_then(|r| r.private_addr.as_ref()));
    for PrivateAddr { ip, network } in private {
      has_tailscale |= *network == PrivateNetwork::Tailscale;
      if let Ok(ip) = ip.parse::<Ipv4Addr>() {
        peers.insert((name.as_str(), ip));
      }
    }
    for ip in server
      .settings
      .lan_addrs
      .iter()
      .chain(report.into_iter().flat_map(|r| &r.lan_ips))
    {
      if let Ok(ip) = ip.parse::<Ipv4Addr>() {
        peers.insert((name.as_str(), ip));
      }
    }
  }

  let tailscale: Ipv4Net = "100.64.0.0/10".parse().unwrap();
  let mut conflicts = Vec::new();
  for name in snap.world.servers.keys() {
    let Some(report) =
      snap.agent(name).and_then(|a| a.report.as_ref())
    else {
      continue;
    };
    let local: Vec<Ipv4Net> = report
      .host_subnets
      .iter()
      .filter_map(|net| net.parse().ok())
      .collect();
    for bridge in &report.docker_subnets {
      let Ok(net) = bridge.subnet.parse::<Ipv4Net>() else {
        continue;
      };
      let mut overlaps_with: Vec<_> = local
        .iter()
        .filter(|&&other| overlaps(net, other))
        .map(|other| format!("本机网段 {other}"))
        .collect();
      if has_tailscale && overlaps(net, tailscale) {
        overlaps_with.push(format!("Tailscale 网段 {tailscale}"));
      }
      overlaps_with.extend(
        peers
          .iter()
          .filter(|(server, ip)| {
            *server != name.as_str() && net.contains(ip)
          })
          .map(|(server, ip)| format!("{server} 的内网地址 {ip}")),
      );
      if !overlaps_with.is_empty() {
        conflicts.push((
          name.as_str(),
          format!(
            "Docker 网络 {}（{net}）与{}冲突",
            bridge.name,
            overlaps_with.join("、")
          ),
        ));
      }
    }
  }
  conflicts
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
  a.contains(&b.network()) || b.contains(&a.network())
}

pub fn issues(snap: &Snapshot) -> impl Iterator<Item = Issue> {
  conflicts(snap).into_iter().map(|(server, detail)| Issue {
    code: "docker_subnet_conflict".into(),
    level: IssueLevel::Warn,
    subject: Some(IssueSubject {
      kind: "server".into(),
      name: server.into(),
    }),
    title: format!("{server} 上的 {detail}"),
    hint: Some(format!("。{FIX}")),
    ack: None,
    alert: None,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::agent::{AgentReport, DockerSubnet};

  #[test]
  fn finds_local_and_peer_subnet_conflicts() {
    assert!(overlaps(
      "192.168.16.0/20".parse().unwrap(),
      "192.168.31.0/24".parse().unwrap()
    ));
    assert!(!overlaps(
      "172.17.0.0/16".parse().unwrap(),
      "172.24.0.0/20".parse().unwrap()
    ));

    let mut snap = Snapshot::default();
    for name in ["docker-host", "peer"] {
      snap.world.servers.insert(
        name.into(),
        crate::world::ServerRow {
          settings: Default::default(),
          version: 1,
        },
      );
    }
    snap
      .world
      .servers
      .get_mut("peer")
      .unwrap()
      .settings
      .lan_addrs = vec!["192.168.31.250".into()];
    snap.agents.push(crate::db::AgentRow {
      server: "docker-host".into(),
      public_key: None,
      report: Some(AgentReport {
        docker_subnets: vec![DockerSubnet {
          name: "bridge-test".into(),
          subnet: "192.168.16.0/20".into(),
        }],
        ..Default::default()
      }),
      last_seen: None,
    });
    let found = conflicts(&snap);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "docker-host");
    assert!(found[0].1.contains("peer 的内网地址 192.168.31.250"));
  }
}
