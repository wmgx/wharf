use std::net::IpAddr;

use serde_yaml_ng::Value;
use wharf_api_types::{
  ApiError,
  spec::{GatewayKind, ServiceSpec},
};

use crate::world::{World, is_reserved_host_port};

use super::compose;

fn merged_compose(content: &str) -> Result<Value, ApiError> {
  let mut doc: Value =
    serde_yaml_ng::from_str(content).map_err(|e| {
      ApiError::invalid(format!("compose YAML 不合法：{e}"))
    })?;
  doc.apply_merge().map_err(|e| {
    ApiError::invalid(format!("compose YAML 合并不合法：{e}"))
  })?;
  Ok(doc)
}

fn services(doc: &Value) -> impl Iterator<Item = (&Value, &Value)> {
  doc["services"].as_mapping().into_iter().flatten()
}

pub fn compose_host_reasons(
  service: &str,
  content: &str,
) -> Vec<String> {
  let Ok(doc) = merged_compose(content) else {
    return vec![];
  };
  let mut reasons = Vec::new();
  for (component, body) in services(&doc) {
    let prefix =
      format!("compose 容器 {}", component.as_str().unwrap_or("?"));
    if body["privileged"].as_bool() == Some(true) {
      reasons.push(format!("{prefix} 开启了 privileged"));
    }
    for key in
      ["pid", "network_mode", "ipc", "uts", "cgroup", "userns_mode"]
    {
      let val = body[key]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
      if val == "host"
        || (matches!(key, "pid" | "network_mode" | "ipc")
          && val.starts_with("container:"))
      {
        reasons.push(format!("{prefix} 设置了 {key}: {val}"));
      }
    }
    for (key, reason) in [
      ("cap_add", "添加了内核能力 cap_add"),
      ("devices", "挂载了宿主机设备 devices"),
      ("device_cgroup_rules", "设置了 device_cgroup_rules"),
      ("security_opt", "修改了安全选项 security_opt"),
      ("sysctls", "修改了内核参数 sysctls"),
      ("volumes_from", "引用了其他容器卷 volumes_from"),
    ] {
      let val = &body[key];
      if val.as_sequence().is_some_and(|s| !s.is_empty())
        || (key == "cap_add"
          && val.as_str().is_some_and(|s| !s.trim().is_empty()))
        || (key == "sysctls"
          && val.as_mapping().is_some_and(|m| !m.is_empty()))
      {
        reasons.push(format!("{prefix} {reason}"));
      }
    }
    for volume in body["volumes"].as_sequence().into_iter().flatten()
    {
      let source = if let Some(short) = volume.as_str() {
        let Some((source, _)) = short.split_once(':') else {
          continue;
        };
        if named_volume(source) {
          continue;
        }
        source
      } else {
        let kind = volume["type"].as_str().unwrap_or_default();
        let source = volume["source"].as_str().unwrap_or_default();
        if matches!(kind, "tmpfs" | "volume")
          || (kind.is_empty() && named_volume(source))
        {
          continue;
        }
        source
      };
      if !is_allowed_service_bind(service, source) {
        let reason = if source.contains("docker.sock") {
          format!("挂载了 docker.sock（{source}）")
        } else {
          format!("挂载了宿主机路径 {source}")
        };
        reasons.push(format!("{prefix} {reason}"));
      }
    }
  }
  for (name, volume) in
    doc["volumes"].as_mapping().into_iter().flatten()
  {
    let opts = &volume["driver_opts"];
    let device = opts["device"].as_str().unwrap_or_default();
    let bind = opts["o"].as_str().is_some_and(|o| o.contains("bind"));
    let allowed = is_allowed_service_bind(service, device);
    if (opts.get("device").is_some() && !allowed)
      || (bind && !(allowed && device.starts_with('/')))
    {
      reasons.push(format!(
        "compose 顶层卷 {} 使用 driver_opts 绑定了宿主机路径",
        name.as_str().unwrap_or("?")
      ));
    }
  }
  reasons
}

fn named_volume(source: &str) -> bool {
  !source.is_empty()
    && !source.starts_with(['/', '.', '~', '$'])
    && !source.contains('/')
}

fn is_allowed_service_bind(service: &str, source: &str) -> bool {
  if source.contains(['$', '~'])
    || source.ends_with("docker.sock")
    || source.split('/').any(|p| p == "..")
  {
    return false;
  }
  if source == "." || source.starts_with("./") {
    return true;
  }
  let root = format!("/srv/{service}");
  (source == root
    || source
      .strip_prefix(&root)
      .is_some_and(|p| p.starts_with('/')))
    && !source.split('/').any(|p| p == ".")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
  pub host_ip: Option<String>,
  pub host_port: u16,
  pub udp: bool,
}

pub fn compose_has_host_network(content: &str) -> bool {
  merged_compose(content).is_ok_and(|doc| {
    services(&doc).any(|(_, body)| {
      body["network_mode"]
        .as_str()
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("host"))
    })
  })
}

pub fn compose_published_ports(
  content: &str,
) -> Result<Vec<PublishedPort>, ApiError> {
  let doc = merged_compose(content)?;
  let mut out = Vec::new();
  for (_, body) in services(&doc) {
    for port in body["ports"].as_sequence().into_iter().flatten() {
      let (ip, published, protocol) =
        if let Some(short) = port.as_str() {
          let (address, protocol) =
            short.rsplit_once('/').unwrap_or((short, "tcp"));
          let Some((host, _)) = address.rsplit_once(':') else {
            continue;
          };
          match host.rsplit_once(':') {
            Some((ip, published)) => (ip, published.into(), protocol),
            None => ("", host.into(), protocol),
          }
        } else if port.is_mapping() {
          let ip = match &port["host_ip"] {
            Value::Null => "",
            Value::String(ip) => ip,
            _ => {
              return Err(ApiError::invalid(
                "compose 端口绑定地址必须是合法的 IP 字符串",
              ));
            }
          };
          let published = &port["published"];
          let published = published
            .as_str()
            .map(String::from)
            .or_else(|| published.as_u64().map(|n| n.to_string()))
            .unwrap_or_default();
          (ip, published, port["protocol"].as_str().unwrap_or("tcp"))
        } else {
          continue;
        };
      let ip = ip
        .strip_prefix('[')
        .and_then(|ip| ip.strip_suffix(']'))
        .unwrap_or(ip);
      let host_ip = if ip.is_empty() {
        None
      } else {
        Some(
          ip.parse::<IpAddr>()
            .map_err(|_| {
              ApiError::invalid(format!(
                "compose 端口绑定地址 {ip} 不是合法的 IP 地址"
              ))
            })?
            .to_string(),
        )
      };
      if published.is_empty() || !matches!(protocol, "tcp" | "udp") {
        continue;
      }
      let (first, last) = published
        .split_once('-')
        .unwrap_or((&published, &published));
      let (Ok(first), Ok(last)) =
        (first.parse::<u16>(), last.parse::<u16>())
      else {
        return Err(ApiError::invalid(format!(
          "compose 宿主机端口 {published} 不合法"
        )));
      };
      if last < first || last - first >= 1024 {
        return Err(ApiError::invalid(format!(
          "compose 宿主机端口段 {published} 不合法或超过 1024 个端口"
        )));
      }
      out.extend((first..=last).filter(|p| *p != 0).map(
        |host_port| PublishedPort {
          host_ip: host_ip.clone(),
          host_port,
          udp: protocol == "udp",
        },
      ));
    }
  }
  Ok(out)
}

pub fn validate_service_ports(
  world: &World,
  name: &str,
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  let published = if let Some(content) = compose(spec) {
    let published = compose_published_ports(content)?;
    (!compose_has_host_network(content)).then_some(published)
  } else {
    None
  };
  for p in &spec.ports {
    let Some(host) = p.host else { continue };
    let label =
      format!("服务 {name} 的端口 {}（宿主机端口 {host}）", p.name);
    if is_reserved_host_port(host) {
      return Err(ApiError::invalid(format!(
        "{label}是 Wharf 保留端口，不能使用"
      )));
    }
    if !p.udp
      && world.gateways.values().any(|g| {
        g.spec.kind == GatewayKind::Caddy
          && g.spec.server == spec.server
          && (host == g.spec.http_port.unwrap_or(80)
            || host == g.spec.https_port.unwrap_or(443))
      })
    {
      return Err(ApiError::invalid(format!(
        "{label}与同机网关端口冲突"
      )));
    }
    if published.as_ref().is_some_and(|ports| {
      !ports.iter().any(|x| x.host_port == host && x.udp == p.udp)
    }) {
      return Err(
        ApiError::invalid(format!(
          "{label}没有在 compose 的 ports 里发布"
        ))
        .with_hint(
          "先在 compose 的 ports 里映射这个端口，或删掉这条端口声明",
        ),
      );
    }
  }
  Ok(())
}

pub fn compose_public_binds(content: &str) -> Vec<PublishedPort> {
  compose_published_ports(content)
    .unwrap_or_default()
    .into_iter()
    .filter(|p| {
      p.host_ip
        .as_deref()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .is_none_or(|ip| match ip.to_canonical() {
          IpAddr::V4(ip) => {
            !ip.is_loopback()
              && !ip.is_private()
              && !(ip.octets()[0] == 100
                && ip.octets()[1] & 0xc0 == 64)
          }
          IpAddr::V6(ip) => {
            !ip.is_loopback() && !ip.is_unique_local()
          }
        })
    })
    .collect()
}

pub fn has_new_public_bind(
  current: &World,
  name: &str,
  spec: &ServiceSpec,
) -> bool {
  let Some(content) = compose(spec) else {
    return false;
  };
  let old = current
    .services
    .get(name)
    .and_then(|row| compose(&row.spec))
    .map_or_else(Vec::new, compose_public_binds);
  compose_public_binds(content)
    .iter()
    .any(|p| !old.contains(p))
}
