//! 只给手动 doctor 已发现的路由故障补充容器现场。

use std::{
  collections::{BTreeMap, BTreeSet},
  net::SocketAddr,
  time::Duration,
};

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use wharf_api_types::{
  agent::{AgentOp, ContainerDiagnosis, ContainerLogKeyword},
  view::{CheckStatus, DoctorCheck},
};

use crate::{doctor::check, state::AppState};

const TIMEOUT: Duration = Duration::from_secs(15);
const UPGRADE: &str =
  "agent 版本旧，升级后能看到原因（wharf upgrade）";

pub struct Target {
  pub service: String,
  pub server: String,
  pub port: Option<u16>,
  pub local_loopback_ok: bool,
  pub http_failed: bool,
  pub link_unreachable: bool,
  pub link_subject: Option<String>,
  pub container_subject: String,
}

pub fn should_diagnose(
  manual: bool,
  link_failed: bool,
  bad_gateway: bool,
  gateway_ok: bool,
  container_bad: bool,
  active: bool,
) -> bool {
  manual
    && (link_failed
      || container_bad
      || (bad_gateway && gateway_ok && active))
}

pub async fn enrich<'a>(
  state: &AppState,
  checks: impl IntoIterator<
    Item = (&'a mut Vec<DoctorCheck>, Vec<Target>),
  >,
) {
  let mut checks: Vec<_> = checks.into_iter().collect();
  let mut services: BTreeMap<(String, String), Vec<(usize, Target)>> =
    BTreeMap::new();
  for (i, (route, targets)) in checks.iter_mut().enumerate() {
    for target in std::mem::take(targets)
      .into_iter()
      .filter(|t| state.hub.is_online(&t.server))
    {
      if !state.hub.supports_container_diagnosis(&target.server) {
        set_cause(route, &target, UPGRADE, false);
        continue;
      }
      services
        .entry((target.server.clone(), target.service.clone()))
        .or_default()
        .push((i, target));
    }
  }

  let total = TIMEOUT * (services.len() as u32).clamp(1, 4);
  let cancel = CancellationToken::new();
  let _guard = cancel.clone().drop_guard();
  let _ = tokio::time::timeout(total, async {
    // 一次只查一个服务，避免一批故障同时起多个辅助容器。
    for ((server, service), targets) in services {
      let ports: BTreeSet<_> =
        targets.iter().filter_map(|(_, t)| t.port).collect();
      let Ok(results) = state
        .hub
        .call::<Vec<ContainerDiagnosis>>(
          &server,
          AgentOp::DiagnoseContainer {
            project: service,
            ports: ports.into_iter().collect(),
          },
          TIMEOUT,
          None,
          &cancel,
        )
        .await
      else {
        continue;
      };
      for (i, target) in targets {
        if let Some(host) = target.port {
          if let Some((result, &port)) = results
            .iter()
            .find_map(|r| r.ports.get(&host).map(|p| (r, p)))
          {
            apply(checks[i].0, &target, result, Some(port));
          }
        } else {
          for result in
            results.iter().filter(|r| !r.running || r.restarting)
          {
            apply(checks[i].0, &target, result, None);
          }
        }
      }
    }
  })
  .await;
}

fn set_cause(
  checks: &mut [DoctorCheck],
  target: &Target,
  cause: &str,
  confirmed: bool,
) {
  for c in checks {
    if c.layer == "container"
      && c.subject == target.container_subject
      && !confirmed
      && c.status == CheckStatus::Bad
    {
      c.detail.push('。');
      c.detail.push_str(cause);
    }
    if c.status != CheckStatus::Bad {
      continue;
    }
    if c.layer == "link"
      && target.link_subject.as_deref() != Some(c.subject.as_str())
    {
      continue;
    }
    let http = target.http_failed
      && matches!(c.layer.as_str(), "http" | "https");
    match (c.layer.as_str(), confirmed, http) {
      ("link", true, _) => c.detail = cause.into(),
      (_, true, true) => {
        c.detail = c.detail.replacen("网关连不上上游", cause, 1)
      }
      ("link", false, _) | (_, false, true) => {
        c.detail.push('。');
        c.detail.push_str(cause);
      }
      _ => {}
    }
  }
}

fn apply(
  checks: &mut Vec<DoctorCheck>,
  target: &Target,
  result: &ContainerDiagnosis,
  port: Option<u16>,
) {
  let failed = !result.running || result.restarting;
  let permission_error = result.log_keywords.iter().any(|word| {
    matches!(
      word,
      ContainerLogKeyword::PermissionDenied
        | ContainerLogKeyword::Eacces
        | ContainerLogKeyword::ReadOnlyFileSystem
    )
  });
  if failed {
    let cause = exit_cause(result);
    if let Some(c) = checks.iter_mut().find(|c| {
      c.layer == "container" && c.subject == target.container_subject
    }) {
      c.detail.push('。');
      c.detail.push_str(&cause);
    }
    set_cause(checks, target, &cause, true);
  } else if let (Some(listeners), Some(port)) =
    (&result.listeners, port)
  {
    let host_network = result.network_mode == "host";
    let recent_start =
      DateTime::parse_from_rfc3339(&result.started_at).is_ok_and(
        |at| Utc::now().signed_duration_since(at).num_seconds() < 15,
      );
    let cause = match listening(listeners, port, host_network, target.local_loopback_ok) {
      Listening::Loopback(addr) => Some(format!(
        "应用只监听 {addr}，网关连不上。把应用的监听地址改成 0.0.0.0:{port}"
      )),
      Listening::Missing if recent_start => {
        Some(format!("容器刚启动，应用尚未监听 {port}，可稍后重试或查看容器日志"))
      }
      Listening::OtherPorts(ports) => {
        let names = ports.iter().map(u16::to_string).collect::<Vec<_>>().join("、");
        Some(format!("容器没有监听 {port}，实际在监听 {names}"))
      }
      Listening::Missing => Some(format!("应用尚未监听 {port}，可能还未就绪或已挂起，可查看容器日志")),
      Listening::Ready if !target.local_loopback_ok && target.link_unreachable => {
        Some("应用在监听，问题在两台机器之间的网络（wharf network --probe）".into())
      }
      // 网关连得上、应用也在监听，502/504 是应用自己返回的（例如它反代的上游不通）。
      Listening::Ready if target.http_failed && !target.link_unreachable => Some(format!(
        "应用在监听 {port}、网关也连得上，错误是应用自己返回的（例如它反代的上游不通或响应太慢）；看 wharf service logs {}",
        target.service
      )),
      Listening::Ready => None,
    };
    if let Some(cause) = cause {
      set_cause(checks, target, &cause, true);
    }
  }

  for m in &result.mounts {
    let (detail, status) = match (&m.permissions, result.user) {
      (None, _) => ("挂载目录权限未检查".into(), CheckStatus::Skip),
      (Some(p), None)
        if failed
          && permission_error
          && p.uid == 0
          && p.mode & 0o003 != 0o003 =>
      {
        (
          format!(
            "{} 属主 {}:{}（{:o}），容器用户未知且日志出现权限拒绝，检查目录属主（chown）",
            m.source, p.uid, p.gid, p.mode
          ),
          CheckStatus::Warn,
        )
      }
      (Some(_), None) => (
        "容器用户未知，挂载目录的可写性未检查".into(),
        CheckStatus::Skip,
      ),
      (Some(p), Some(_)) if p.writable.is_none() => (
        "容器主组未知，挂载目录的可写性未检查".into(),
        CheckStatus::Skip,
      ),
      (Some(p), Some(u)) if p.writable == Some(false) => {
        let source = &m.source;
        let owner = u.gid.map_or_else(
          || u.uid.to_string(),
          |gid| format!("{}:{gid}", u.uid),
        );
        let mut detail = format!(
          "{source} 属主 {}:{}（{:o}），容器以 {owner} 运行，写不进去",
          p.uid, p.gid, p.mode
        );
        if p.mode & 0o300 == 0o300 {
          let path = if source.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"/_.-".contains(&b)
          }) {
            source.clone()
          } else {
            format!("'{}'", source.replace('\'', "'\"'\"'"))
          };
          detail.push_str(&format!(
            "。可在服务器上执行 chown -R {owner} {path}"
          ));
        } else {
          detail.push_str("。检查目录属主以及写入和进入权限");
        }
        (
          detail,
          if failed && permission_error {
            CheckStatus::Bad
          } else {
            CheckStatus::Warn
          },
        )
      }
      _ => continue,
    };
    checks.push(check(
      "container",
      &target.container_subject,
      status,
      detail,
    ));
  }
}

fn exit_cause(result: &ContainerDiagnosis) -> String {
  let state = if result.restarting {
    "正在重启"
  } else {
    "已停止"
  };
  let mut detail = format!(
    "容器 {} {state}，退出码 {}",
    result.name, result.exit_code
  );
  if result.restart_count > 0 {
    detail.push_str(&format!("，已重启 {} 次", result.restart_count));
  }
  if result.oom_killed {
    detail.push_str("。内存不够被杀，调高内存上限");
  }
  for keyword in &result.log_keywords {
    let cause = match keyword {
      ContainerLogKeyword::PermissionDenied => "permission denied",
      ContainerLogKeyword::Eacces => "EACCES",
      ContainerLogKeyword::ReadOnlyFileSystem => {
        "read-only file system"
      }
      ContainerLogKeyword::ExecFormatError => {
        detail.push_str(
          "。日志命中 exec format error，镜像架构和机器不符",
        );
        continue;
      }
    };
    detail.push_str(&format!(
      "。日志命中 {cause}，可能是挂载目录权限不对"
    ));
  }
  detail
}

#[derive(Debug, PartialEq, Eq)]
enum Listening {
  Loopback(SocketAddr),
  OtherPorts(BTreeSet<u16>),
  Missing,
  Ready,
}

fn listening(
  listeners: &[SocketAddr],
  port: u16,
  host_network: bool,
  local_loopback_ok: bool,
) -> Listening {
  let mut matched =
    listeners.iter().filter(|addr| addr.port() == port);
  if let Some(first) = matched.next() {
    if !first.ip().is_loopback()
      || matched.any(|addr| !addr.ip().is_loopback())
      || (host_network && local_loopback_ok)
    {
      return Listening::Ready;
    }
    return Listening::Loopback(*first);
  }
  // host 网络中的其他端口可能属于宿主机上的其他服务。
  if !host_network {
    let ports: BTreeSet<_> = listeners
      .iter()
      .filter(|a| !a.ip().is_loopback())
      .map(SocketAddr::port)
      .collect();
    if !ports.is_empty() {
      return Listening::OtherPorts(ports);
    }
  }
  Listening::Missing
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_expected_listening_port() {
    let loopback = "127.0.0.1:3000".parse().unwrap();
    let wrong_port = "0.0.0.0:8080".parse().unwrap();
    let expected = "0.0.0.0:3000".parse().unwrap();
    assert_eq!(
      listening(&[loopback], 3000, false, true),
      Listening::Loopback(loopback)
    );
    assert_eq!(
      listening(&[wrong_port], 3000, false, false),
      Listening::OtherPorts(BTreeSet::from([8080]))
    );
    assert_eq!(
      listening(&[expected], 3000, false, false),
      Listening::Ready
    );
    assert_eq!(
      listening(&[loopback], 3000, true, true),
      Listening::Ready
    );
  }

  #[test]
  fn tunnel_crashed_and_host_loopback_diagnosis() {
    assert!(should_diagnose(true, false, false, true, true, false));
    let loopback = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(
      listening(&[loopback], 8080, true, true),
      Listening::Ready
    );
    assert!(!should_diagnose(false, true, true, true, false, true));
    assert!(!should_diagnose(false, false, true, true, false, true));
    assert!(should_diagnose(true, true, false, false, false, false));
    assert!(should_diagnose(true, false, true, true, false, true));
    assert!(!should_diagnose(true, false, true, false, false, true));
    assert!(!should_diagnose(true, false, true, true, false, false));
  }
}
