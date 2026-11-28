//! 暴露面只读缓存；确认和通知去重持久保存。
use crate::{
  api::ApiResult,
  auth::Auth,
  db,
  snapshot::{self, Snapshot},
  state::AppState,
};
use axum::{
  Json,
  extract::{Path, State},
};
use serde::Deserialize;
use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::Duration,
};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, AgentReport, ExposureReport, Listen},
  view::{
    ExposureView, Issue, IssueLevel, IssueSubject, Perm, PortRow,
    RiskRow,
  },
};

static LAST: Mutex<BTreeMap<String, (i64, ExposureReport)>> =
  Mutex::new(BTreeMap::new());
// 串行化刷新、通知与确认，避免并发读改写丢失设置。
static WRITE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());
type Ports = BTreeMap<String, BTreeSet<String>>;

fn outdated(snap: &Snapshot, server: &str) -> bool {
  crate::agent_upgrade::outdated(
    snap
      .agent(server)
      .and_then(|a| a.report.as_ref())
      .map(|r| r.build.as_str()),
  )
}

fn public_ip<'a>(
  snap: &'a Snapshot,
  server: &str,
) -> Option<&'a str> {
  snap
    .world
    .servers
    .get(server)
    .and_then(|s| s.settings.public_ip.as_deref())
    .or_else(|| {
      snap
        .agent(server)
        .and_then(|a| a.report.as_ref())
        .and_then(|r| r.public_ip.as_deref())
    })
}

fn classify(
  l: &Listen,
  report: &AgentReport,
  gateways: &[(String, String, u16)],
  services: &BTreeMap<String, Vec<(String, u16)>>,
) -> Option<PortRow> {
  let wildcard = matches!(l.addr.as_str(), "0.0.0.0" | "::" | "*");
  let is_public_bind =
    report.public_ip.as_deref() == Some(l.addr.as_str());
  if !wildcard && !is_public_bind {
    let other_public =
      l.addr.parse::<std::net::IpAddr>().is_ok_and(|ip| {
        crate::source_trust::is_global_unicast(ip.to_canonical())
      });
    if report.private_addr.as_ref().is_some_and(|a| a.ip == l.addr)
      || !other_public
    {
      return None;
    }
  }
  let project = l.project.as_deref().unwrap_or("");
  let gateway = gateways.iter().find(|(name, proto, port)| {
    project == format!("wharf-gw-{name}")
      || (*port == l.port
        && *proto == l.proto
        && l.process == "caddy")
  });
  let (owner, name, expected) = if let Some((name, _, _)) = gateway {
    ("gateway", name.clone(), true)
  } else if l.process == "wharf-core"
    || project.starts_with("wharf-")
    || matches!(
      l.container.as_deref(),
      Some("wharf-agent" | "wharf-core")
    )
    || (matches!(l.port, 7701 | 8118 | 8119 | 7710)
      && l.process == "wharf-agent")
  {
    (
      "wharf",
      l.container.clone().unwrap_or_else(|| l.process.clone()),
      true,
    )
  } else if let Some((name, _)) =
    services.get_key_value(project).or_else(|| {
      services.iter().find(|(_, ports)| {
        ports
          .iter()
          .any(|(proto, port)| proto == &l.proto && *port == l.port)
      })
    })
  {
    ("service", name.clone(), false)
  } else if let Some(c) = &l.container {
    ("container", c.clone(), false)
  } else if !l.process.is_empty() {
    (
      "host",
      l.process.clone(),
      matches!(l.process.as_str(), "sshd" | "tailscaled")
        || (l.proto == "udp"
          && ((l.port == 68 && l.process == "dhclient")
            || (l.port == 123
              && matches!(
                l.process.as_str(),
                "ntpd"
                  | "chronyd"
                  | "systemd-timesyncd"
                  | "systemd-timesyn"
              )))),
    )
  } else {
    ("unknown", "未知".into(), false)
  };
  Some(PortRow {
    proto: l.proto.clone(),
    port: l.port,
    addr: l.addr.clone(),
    owner: owner.into(),
    name,
    expected,
    acked: false,
  })
}

fn port_key(p: &PortRow) -> String {
  format!("{}/{}", p.proto, p.port)
}

fn rows(
  snap: &Snapshot,
  server: &str,
  report: &ExposureReport,
) -> (Vec<PortRow>, Vec<RiskRow>) {
  let mut agent = snap
    .agent(server)
    .and_then(|a| a.report.clone())
    .unwrap_or_default();
  agent.public_ip = public_ip(snap, server).map(str::to_string);
  let services: BTreeMap<_, _> = snap
    .world
    .services
    .iter()
    .filter(|(_, r)| r.spec.server == server)
    .map(|(name, r)| {
      (
        name.clone(),
        r.spec
          .ports
          .iter()
          .filter_map(|p| {
            p.host.or_else(|| r.host_ports.get(&p.name).copied()).map(
              |port| (if p.udp { "udp" } else { "tcp" }.into(), port),
            )
          })
          .collect(),
      )
    })
    .collect();
  let mut gateways = vec![];
  for (name, g) in &snap.world.gateways {
    if g.spec.server != server {
      continue;
    }
    if g.spec.kind != wharf_api_types::spec::GatewayKind::Caddy {
      gateways.push((name.clone(), String::new(), 0));
      continue;
    }
    for port in [
      g.spec.http_port.unwrap_or(80),
      g.spec.https_port.unwrap_or(443),
    ] {
      gateways.push((name.clone(), "tcp".into(), port));
    }
    gateways.push((
      name.clone(),
      "udp".into(),
      g.spec.https_port.unwrap_or(443),
    ));
    for f in &g.spec.layer4 {
      gateways.push((
        name.clone(),
        if f.udp { "udp" } else { "tcp" }.into(),
        f.listen,
      ));
    }
  }
  let mut ports: Vec<PortRow> = vec![];
  for l in &report.listens {
    if let Some(p) = classify(l, &agent, &gateways, &services) {
      if let Some(prev) = ports.iter_mut().find(|r| {
        r.proto == p.proto
          && r.port == p.port
          && matches!(r.addr.as_str(), "0.0.0.0" | "::" | "*")
          && matches!(p.addr.as_str(), "0.0.0.0" | "::" | "*")
      }) {
        if prev.owner == "unknown" || prev.name == "docker-proxy" {
          *prev = p;
        }
      } else {
        ports.push(p);
      }
    }
  }
  ports.sort_by_key(|p| (p.port, p.proto.clone(), p.addr.clone()));
  let risks = report
    .containers
    .iter()
    .map(|c| {
      let own = c
        .project
        .as_deref()
        .is_some_and(|p| p.starts_with("wharf-"))
        || matches!(c.name.as_str(), "wharf-agent" | "wharf-core");
      RiskRow {
        container: c.name.clone(),
        project: c.project.clone(),
        service: c
          .project
          .as_ref()
          .filter(|p| services.contains_key(*p) && !own)
          .cloned(),
        risks: c.risks.clone(),
        own,
      }
    })
    .collect();
  (ports, risks)
}

async fn setting(
  state: &AppState,
  key: &'static str,
) -> Result<Ports, ApiError> {
  state.db.call(move |c| read(c, key)).await
}

fn read(
  c: &rusqlite::Connection,
  key: &str,
) -> Result<Ports, ApiError> {
  db::setting(c, key)?
    .map(|s| {
      serde_json::from_str(&s)
        .map_err(|_| ApiError::internal("暴露面设置解析失败"))
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

fn new_ports<'a>(
  ports: &'a [PortRow],
  seen: Option<&BTreeSet<String>>,
  has_public_ip: bool,
) -> Vec<&'a PortRow> {
  if !has_public_ip {
    return vec![];
  }
  let Some(seen) = seen else { return vec![] };
  ports
    .iter()
    .filter(|p| !p.expected && !seen.contains(&port_key(p)))
    .collect()
}

pub async fn refresh(
  state: &AppState,
  server: &str,
) -> Result<(), ApiError> {
  let _guard = WRITE.lock().await;
  let snap = snapshot::load(&state.db).await?;
  if !snap.world.servers.contains_key(server) {
    return Err(crate::world::server_not_found(server));
  }
  if outdated(&snap, server) {
    return Err(
      ApiError::invalid("agent 版本太旧，没有数据")
        .with_hint("先升级这台服务器的 agent"),
    );
  }
  let report: ExposureReport = state
    .hub
    .call(
      server,
      AgentOp::Exposure,
      Duration::from_secs(40),
      None,
      &CancellationToken::new(),
    )
    .await?;
  let (ports, _) = rows(&snap, server, &report);
  let mut seen = setting(state, "exposure.seen").await?;
  let new = new_ports(
    &ports,
    seen.get(server),
    public_ip(&snap, server).is_some(),
  );
  let body = new
    .iter()
    .map(|p| format!("{} · {}", port_key(p), p.name))
    .collect::<Vec<_>>()
    .join("\n");
  seen
    .entry(server.into())
    .or_default()
    .extend(ports.iter().map(port_key));
  let value = serde_json::to_string(&seen)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  state
    .db
    .call(move |c| db::set_setting(c, "exposure.seen", Some(&value)))
    .await?;
  LAST
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(server.into(), (db::now_ms(), report));
  if !body.is_empty() {
    crate::rules::notice(
      state,
      "exposure",
      Some(server),
      None,
      false,
      crate::notify::Event {
        title: format!("{server} 新开了对公网的端口"),
        body,
      },
    )
    .await;
  }
  Ok(())
}

fn should_refresh(
  online: bool,
  outdated: bool,
  checked_at: Option<i64>,
  now: i64,
) -> bool {
  online
    && !outdated
    && checked_at.is_none_or(|at| now.saturating_sub(at) > 3_600_000)
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(180)).await;
    loop {
      if let Ok(snap) = snapshot::load(&state.db).await {
        LAST.lock().unwrap_or_else(|e| e.into_inner()).retain(
          |s, _| {
            snap.world.servers.contains_key(s) && !outdated(&snap, s)
          },
        );
        for server in snap.world.servers.keys() {
          let checked_at = LAST
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(server)
            .map(|(at, _)| *at);
          if should_refresh(
            state.hub.is_online(server),
            outdated(&snap, server),
            checked_at,
            db::now_ms(),
          ) && let Err(e) = refresh(&state, server).await
          {
            tracing::warn!("检查 {server} 暴露面失败：{e}");
          }
        }
      }
      tokio::time::sleep(Duration::from_secs(300)).await;
    }
  });
}

pub async fn view(
  state: &AppState,
  server: &str,
) -> Result<ExposureView, ApiError> {
  let snap = snapshot::load(&state.db).await?;
  if !snap.world.servers.contains_key(server) {
    return Err(crate::world::server_not_found(server));
  }
  if outdated(&snap, server) {
    return Ok(ExposureView {
      outdated: true,
      ..Default::default()
    });
  }
  let last = LAST
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .get(server)
    .cloned();
  let Some((at, report)) = last else {
    return Ok(ExposureView::default());
  };
  let (mut ports, risks) = rows(&snap, server, &report);
  let ack = setting(state, "exposure.ack").await?;
  for p in &mut ports {
    p.acked =
      ack.get(server).is_some_and(|a| a.contains(&port_key(p)));
  }
  Ok(ExposureView {
    checked_at: Some(at),
    outdated: false,
    ports,
    risks,
  })
}

pub async fn issues(
  state: &AppState,
) -> Result<Vec<Issue>, ApiError> {
  let snap = snapshot::load(&state.db).await?;
  let mut issues = vec![];
  for server in snap.world.servers.keys() {
    if public_ip(&snap, server).is_none() {
      continue;
    }
    let open: Vec<_> = view(state, server)
      .await?
      .ports
      .into_iter()
      .filter(|p| !p.expected && !p.acked)
      .collect();
    if let Some(title) = exposed_title(server, &open) {
      issues.push(Issue {
        code: "exposed_port".into(),
        level: IssueLevel::Warn,
        subject: Some(IssueSubject {
          kind: "server".into(),
          name: server.clone(),
        }),
        title,
        hint: Some("确认没问题就在服务器详情里点“我知道”".into()),
        ack: None,
        alert: None,
      });
    }
  }
  Ok(issues)
}

/// 一台服务器的未确认端口合成一条待处理，只列前 3 个。
fn exposed_title(server: &str, open: &[PortRow]) -> Option<String> {
  match open {
    [] => None,
    [p] => Some(format!(
      "{server} 的 {} 对公网开放（{}）",
      port_key(p),
      p.name
    )),
    _ => {
      let names: Vec<_> = open.iter().take(3).map(port_key).collect();
      let more = if open.len() > 3 { " 等" } else { "" };
      Some(format!(
        "{server} 有 {} 个未确认的公网端口：{}{more}",
        open.len(),
        names.join("、")
      ))
    }
  }
}

pub fn service_risks(server: &str, service: &str) -> Vec<String> {
  LAST
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .get(server)
    .map(|(_, r)| {
      r.containers
        .iter()
        .filter(|c| {
          c.project.as_deref() == Some(service)
            && !service.starts_with("wharf-")
        })
        .flat_map(|c| c.risks.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
    })
    .unwrap_or_default()
}

pub async fn show(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ExposureView> {
  auth.require(Perm::Read)?;
  Ok(Json(view(&s, &name).await?))
}

pub async fn refresh_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
) -> ApiResult<ExposureView> {
  auth.require(Perm::Plan)?;
  refresh(&s, &name).await?;
  Ok(Json(view(&s, &name).await?))
}

#[derive(Deserialize)]
pub struct Ack {
  port: String,
  acked: bool,
}

pub async fn ack(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Path(name): Path<String>,
  Json(body): Json<Ack>,
) -> ApiResult<ExposureView> {
  auth.require(Perm::Apply)?;
  let Some((proto, port)) = body.port.split_once('/') else {
    return Err(
      ApiError::invalid("端口格式应为 tcp/8080 或 udp/8080").into(),
    );
  };
  if !matches!(proto, "tcp" | "udp")
    || port.parse::<u16>().is_err()
    || port == "0"
  {
    return Err(
      ApiError::invalid("端口格式应为 tcp/8080 或 udp/8080").into(),
    );
  }
  let _guard = WRITE.lock().await;
  view(&s, &name).await?;
  let mut a = setting(&s, "exposure.ack").await?;
  let ports = a.entry(name.clone()).or_default();
  if body.acked {
    ports.insert(body.port);
  } else {
    ports.remove(&body.port);
  }
  let value = serde_json::to_string(&a)
    .map_err(|e| ApiError::internal(e.to_string()))?;
  s.db
    .call(move |c| db::set_setting(c, "exposure.ack", Some(&value)))
    .await?;
  Ok(Json(view(&s, &name).await?))
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn exposed_title_groups_per_server() {
    let row = |port: u16| PortRow {
      proto: "tcp".into(),
      port,
      name: "x".into(),
      addr: "*".into(),
      owner: "host".into(),
      expected: false,
      acked: false,
    };
    assert_eq!(exposed_title("s", &[]), None);
    assert_eq!(
      exposed_title("s", &[row(1)]).unwrap(),
      "s 的 tcp/1 对公网开放（x）"
    );
    assert_eq!(
      exposed_title("s", &[row(1), row(2), row(3), row(4)]).unwrap(),
      "s 有 4 个未确认的公网端口：tcp/1、tcp/2、tcp/3 等"
    );
  }

  #[test]
  fn public_bind_is_detected_with_legacy_lan_report() {
    let report = AgentReport {
      public_ip: Some("203.0.113.7".into()),
      lan_ips: vec!["203.0.113.7".into(), "10.20.0.5".into()],
      ..Default::default()
    };
    for (addr, public) in [
      ("203.0.113.7", true),
      ("198.51.100.7", true),
      ("10.20.0.5", false),
    ] {
      let listen = Listen {
        addr: addr.into(),
        port: 5432,
        ..Default::default()
      };
      assert_eq!(
        classify(&listen, &report, &[], &BTreeMap::new()).is_some(),
        public
      );
    }
  }

  #[test]
  fn declared_host_port_belongs_to_service() {
    let services =
      BTreeMap::from([("app".into(), vec![("tcp".into(), 8090)])]);
    let l = Listen {
      proto: "tcp".into(),
      addr: "0.0.0.0".into(),
      port: 8090,
      process: "java".into(),
      ..Default::default()
    };
    let p =
      classify(&l, &AgentReport::default(), &[], &services).unwrap();
    assert_eq!(
      (p.owner.as_str(), p.name.as_str(), p.expected),
      ("service", "app", false)
    );
  }
  #[test]
  fn core_and_local_tunnel_are_expected() {
    let l = Listen {
      addr: "0.0.0.0".into(),
      process: "wharf-core".into(),
      ..Default::default()
    };
    assert!(
      classify(&l, &AgentReport::default(), &[], &BTreeMap::new())
        .unwrap()
        .expected
    );
    let l = Listen {
      process: "cloudflared".into(),
      project: Some("wharf-gw-edge".into()),
      ..l
    };
    let p = classify(
      &l,
      &AgentReport::default(),
      &[("edge".into(), String::new(), 0)],
      &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
      (p.owner.as_str(), p.name.as_str(), p.expected),
      ("gateway", "edge", true)
    );
  }
  #[test]
  fn system_udp_clients_are_expected() {
    let l = Listen {
      proto: "udp".into(),
      addr: "0.0.0.0".into(),
      port: 68,
      process: "dhclient".into(),
      ..Default::default()
    };
    assert!(
      classify(&l, &AgentReport::default(), &[], &BTreeMap::new())
        .unwrap()
        .expected
    );
    let l = Listen {
      port: 123,
      process: "ntpd".into(),
      ..l
    };
    assert!(
      classify(&l, &AgentReport::default(), &[], &BTreeMap::new())
        .unwrap()
        .expected
    );
  }
  #[test]
  fn no_public_address_does_not_notify() {
    let ports = vec![PortRow {
      proto: "tcp".into(),
      port: 8090,
      addr: "0.0.0.0".into(),
      owner: "service".into(),
      name: "app".into(),
      expected: false,
      acked: false,
    }];
    assert!(
      new_ports(&ports, Some(&BTreeSet::new()), false).is_empty()
    );
    assert_eq!(
      new_ports(&ports, Some(&BTreeSet::new()), true).len(),
      1
    );
  }
  #[test]
  fn refresh_only_online_current_and_missing_or_expired() {
    let now = 7_200_000;
    assert!(should_refresh(true, false, None, now));
    assert!(should_refresh(true, false, Some(now - 3_600_001), now));
    assert!(!should_refresh(true, false, Some(now - 3_600_000), now));
    assert!(!should_refresh(true, false, Some(now), now));
    assert!(!should_refresh(true, false, Some(now + 1), now));
    assert!(!should_refresh(false, false, None, now));
    assert!(!should_refresh(true, true, None, now));
  }

  #[test]
  fn gateway_expected_container_not_expected() {
    let l = Listen {
      proto: "tcp".into(),
      addr: "0.0.0.0".into(),
      port: 443,
      project: Some("wharf-gw-edge".into()),
      ..Default::default()
    };
    let g = vec![("edge".into(), "tcp".into(), 443)];
    let p =
      classify(&l, &AgentReport::default(), &g, &BTreeMap::new())
        .unwrap();
    assert!(p.expected);
    assert_eq!(p.owner, "gateway");
    let l = Listen {
      project: None,
      container: Some("s1".into()),
      ..l
    };
    let p =
      classify(&l, &AgentReport::default(), &g, &BTreeMap::new())
        .unwrap();
    assert!(!p.expected);
    assert_eq!(p.owner, "container");
  }
  #[test]
  fn tailscaled_is_expected() {
    let l = Listen {
      proto: "udp".into(),
      addr: "0.0.0.0".into(),
      port: 41641,
      process: "tailscaled".into(),
      ..Default::default()
    };
    let p =
      classify(&l, &AgentReport::default(), &[], &BTreeMap::new())
        .unwrap();
    assert!(p.expected);
    assert_eq!(p.owner, "host");
    assert!(new_ports(&[p], Some(&BTreeSet::new()), true).is_empty());
  }
  #[test]
  fn private_listeners_excluded() {
    let l = Listen {
      addr: "100.64.0.1".into(),
      ..Default::default()
    };
    assert!(
      classify(&l, &AgentReport::default(), &[], &BTreeMap::new())
        .is_none()
    );
  }
  #[test]
  fn first_check_silent_then_only_new() {
    let p = PortRow {
      proto: "tcp".into(),
      port: 8080,
      addr: "0.0.0.0".into(),
      owner: "container".into(),
      name: "s1".into(),
      expected: false,
      acked: false,
    };
    let ports = vec![p];
    assert!(new_ports(&ports, None, true).is_empty());
    assert_eq!(
      new_ports(&ports, Some(&BTreeSet::new()), true).len(),
      1
    );
    assert!(
      new_ports(
        &ports,
        Some(&BTreeSet::from(["tcp/8080".into()])),
        true
      )
      .is_empty()
    );
  }
}
