//! 读取已有组网连接状态；普通内网地址和组网地址不同时，单独保存探测结果。
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::RwLock, time::Duration};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{
    AgentOp, HostExecJob, HostExecOutcome, PROBE_PORT, ProbeTarget,
  },
  external::TailnetRelay,
  spec::PrivateNetwork,
  view::ReachView,
};

use crate::{
  db, rules,
  snapshot::{self, Snapshot},
  state::AppState,
};

type AdditionalReach =
  BTreeMap<(String, String), (String, ReachView)>;
static REACH: RwLock<AdditionalReach> = RwLock::new(BTreeMap::new());
static RELAYS: RwLock<Vec<TailnetRelay>> = RwLock::new(Vec::new());
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn addresses(snap: &Snapshot) -> BTreeMap<String, String> {
  snap
    .world
    .servers
    .keys()
    .filter_map(|name| {
      Some((name.clone(), address(snap, name)?.to_string()))
    })
    .collect()
}

pub fn address<'a>(
  snap: &'a Snapshot,
  name: &str,
) -> Option<&'a str> {
  let configured =
    snap.world.servers.get(name)?.settings.private_addr.as_ref();
  let reported = snap
    .agent(name)
    .and_then(|a| a.report.as_ref())
    .and_then(|r| r.private_addr.as_ref());
  reported
    .into_iter()
    .chain(configured)
    .find(|a| a.network == PrivateNetwork::Tailscale)
    .map(|a| a.ip.as_str())
}

pub async fn probe_extra(
  s: &AppState,
  snap: &Snapshot,
  net: &crate::render::Net,
) {
  let addresses = addresses(snap);
  let targets = addresses
    .iter()
    .filter(|(name, ip)| {
      net.private.get(*name).is_none_or(|a| a.ip != **ip)
    })
    .collect::<Vec<_>>();
  let calls = addresses
    .keys()
    .filter(|from| s.hub.is_online(from))
    .map(|from| {
      let targets = &targets;
      async move {
        let peers: Vec<_> = targets
          .iter()
          .copied()
          .filter(|(to, _)| *to != from)
          .collect();
        if peers.is_empty() {
          return vec![];
        }
        let targets = peers
          .iter()
          .map(|(to, ip)| ProbeTarget {
            server: (*to).clone(),
            addr: if ip.contains(':') {
              format!("[{ip}]:{PROBE_PORT}")
            } else {
              format!("{ip}:{PROBE_PORT}")
            },
            plain: false,
          })
          .collect();
        let result: Result<Vec<bool>, _> = s
          .hub
          .call(
            from,
            AgentOp::Probe { targets },
            TIMEOUT,
            None,
            &CancellationToken::new(),
          )
          .await;
        match result {
          Ok(oks) if oks.len() == peers.len() => peers
            .into_iter()
            .zip(oks)
            .map(|((to, ip), ok)| {
              let view = ReachView {
                from: from.clone(),
                to: to.clone(),
                ok,
                checked_at: Utc::now(),
                stale: false,
              };
              ((from.clone(), to.clone()), (ip.clone(), view))
            })
            .collect(),
          _ => vec![],
        }
      }
    });
  let results = futures_util::future::join_all(calls).await;
  if let Ok(mut saved) = REACH.write() {
    saved.retain(|(from, to), (ip, _)| {
      addresses.contains_key(from) && addresses.get(to) == Some(ip)
    });
    saved.extend(results.into_iter().flatten());
  }
}

pub fn reach(snap: &Snapshot, reach: &[ReachView]) -> Vec<ReachView> {
  let addresses = addresses(snap);
  let net = snap.net(&snap.world);
  let mut out: Vec<_> = reach
    .iter()
    .filter(|r| {
      addresses.contains_key(&r.from)
        && addresses.get(&r.to).is_some_and(|ip| {
          net.private.get(&r.to).is_some_and(|a| &a.ip == ip)
        })
    })
    .cloned()
    .collect();
  if let Ok(extra) = REACH.read() {
    out.extend(extra.values().filter_map(|(ip, r)| {
      if !addresses.contains_key(&r.from)
        || addresses.get(&r.to) != Some(ip)
        || net.private.get(&r.to).is_some_and(|a| &a.ip == ip)
      {
        return None;
      }
      let mut row = r.clone();
      row.stale = row.checked_at.timestamp_millis()
        < db::now_ms() - db::REACH_TTL_MS;
      Some(row)
    }));
  }
  out
}

pub fn relays(snap: &Snapshot) -> Vec<TailnetRelay> {
  RELAYS
    .read()
    .map(|rows| {
      rows
        .iter()
        .filter(|r| {
          snap.world.servers.contains_key(&r.from)
            && snap.world.servers.contains_key(&r.to)
        })
        .cloned()
        .collect()
    })
    .unwrap_or_default()
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Status {
  peer: BTreeMap<String, Peer>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Peer {
  #[serde(rename = "TailscaleIPs")]
  ips: Option<Vec<String>>,
  cur_addr: String,
  relay: String,
  peer_relay: String,
  active: bool,
  last_write: Option<DateTime<Utc>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Connection<'a> {
  Direct,
  Derp(&'a str),
  Idle,
}

fn connection(peer: &Peer, now: DateTime<Utc>) -> Connection<'_> {
  let recent = peer.active
    && peer.last_write.is_some_and(|at| {
      (0..=300).contains(&(now - at).num_seconds())
    });
  if !recent {
    return Connection::Idle;
  }
  if !peer.cur_addr.is_empty() {
    Connection::Direct
  } else if !peer.relay.is_empty() && peer.peer_relay.is_empty() {
    Connection::Derp(&peer.relay)
  } else {
    Connection::Idle
  }
}

async fn status(s: &AppState, server: &str) -> Option<Status> {
  if !s.hub.supports_host_shell(server) {
    return None;
  }
  // 系统客户端可用时优先用它。容器名由现有固定 compose 项目生成。
  let command = "if command -v tailscale >/dev/null 2>&1; then if timeout 4 tailscale status --json 2>/dev/null; then exit 0; fi; fi; docker exec wharf-tailscale-tailscale-1 timeout 4 tailscale status --json 2>/dev/null";
  let result = s
    .hub
    .call::<HostExecOutcome>(
      server,
      AgentOp::HostExec(HostExecJob {
        command: command.into(),
        timeout_secs: 8,
        cwd: "/".into(),
      }),
      TIMEOUT,
      None,
      &CancellationToken::new(),
    )
    .await
    .ok()?;
  match result {
    HostExecOutcome::Finished(r)
      if r.exit_code == 0 && !r.truncated =>
    {
      serde_json::from_str(&r.stdout).ok()
    }
    _ => None,
  }
}

pub async fn refresh(
  s: &AppState,
) -> Result<(), wharf_api_types::ApiError> {
  let snap = snapshot::load(&s.db).await?;
  let addresses = addresses(&snap);
  if addresses.len() < 2 {
    if let Ok(mut relays) = RELAYS.write() {
      relays.clear();
    }
    return Ok(());
  }
  let statuses =
    futures_util::future::join_all(addresses.keys().map(
      |server| async move { (server, status(s, server).await) },
    ))
    .await;
  let names: Vec<_> = addresses.keys().collect();
  let now = Utc::now();
  let mut current = Vec::new();
  for (i, from) in names.iter().enumerate() {
    for to in &names[i + 1..] {
      let get = |from: &String, to: &String| {
        statuses
          .iter()
          .find(|(server, _)| *server == from)
          .and_then(|(_, status)| status.as_ref())
          .and_then(|status| {
            status.peer.values().find(|peer| {
              peer
                .ips
                .as_ref()
                .is_some_and(|ips| ips.contains(&addresses[to]))
            })
          })
          .map_or(Connection::Idle, |peer| connection(peer, now))
      };
      let (value, detail) = match (get(from, to), get(to, from)) {
        (Connection::Derp(relay), _)
        | (_, Connection::Derp(relay)) => {
          current.push(TailnetRelay {
            from: (*from).clone(),
            to: (*to).clone(),
            relay: relay.into(),
          });
          (
            1.0,
            format!(
              "{from} 和 {to} 经 {relay} 中继。直连失败通常是 UDP 被拦，检查两边防火墙和 NAT"
            ),
          )
        }
        (Connection::Direct, _) | (_, Connection::Direct) => {
          (0.0, format!("{from} 和 {to} 已恢复直连"))
        }
        _ => (0.5, String::new()),
      };
      rules::observe(
        s,
        "tailnet.relay",
        &format!("{from}>{to}"),
        value,
        &detail,
      )
      .await;
    }
  }
  if let Ok(mut relays) = RELAYS.write() {
    *relays = current;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn tailscale_status_peer_connection() {
    let now = Utc::now();
    for (addr, active, last_write, expected) in [
      ("203.0.113.5:41641", true, now, Connection::Direct),
      ("", true, now, Connection::Derp("sin")),
      (
        "",
        false,
        now - chrono::TimeDelta::hours(1),
        Connection::Idle,
      ),
    ] {
      let status: Status = serde_json::from_value(json!({
        "Peer": {"nodekey:sample": {
          "TailscaleIPs": ["100.64.0.2"], "CurAddr": addr, "Relay": "sin",
          "Active": active, "LastWrite": last_write
        }}
      })).unwrap();
      assert_eq!(
        connection(&status.peer["nodekey:sample"], now),
        expected
      );
    }
  }
}
