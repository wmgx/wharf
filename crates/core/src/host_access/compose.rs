//! Compose 触达宿主机能力检查与端口/绑定地址解析。

use std::net::IpAddr;

use serde_yaml_ng::Value;
use wharf_api_types::ApiError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
  /// Compose 中写的宿主机绑定 IP（去掉 IPv6 方括号）；未写时为 None（Docker 默认 0.0.0.0/::）。
  pub host_ip: Option<String>,
  pub host_port: u16,
  pub udp: bool,
}

/// 检查 Compose 文件中触达宿主机的配置项。
pub fn compose_host_reasons(
  service: &str,
  content: &str,
) -> Vec<String> {
  let Ok(mut doc) = serde_yaml_ng::from_str::<Value>(content) else {
    return vec![];
  };
  let _ = doc.apply_merge();
  let mut reasons = Vec::new();
  if let Some(services) =
    doc.get("services").and_then(Value::as_mapping)
  {
    for (k, body) in services {
      let comp = k.as_str().unwrap_or("?");
      check_compose_service(service, comp, body, &mut reasons);
    }
  }
  if let Some(volumes) =
    doc.get("volumes").and_then(Value::as_mapping)
  {
    for (k, val) in volumes {
      let vol = k.as_str().unwrap_or("?");
      let Some(opts) =
        val.get("driver_opts").filter(|v| v.is_mapping())
      else {
        continue;
      };
      let device =
        opts.get("device").and_then(Value::as_str).map(str::trim);
      let is_bind =
        opts.get("o").and_then(Value::as_str).is_some_and(|o| {
          o.split(',').any(|p| p.trim().eq_ignore_ascii_case("bind"))
        });
      let bad_device =
        device.is_some_and(|d| !is_allowed_service_bind(service, d));
      let bad_bind = is_bind
        && device
          .is_none_or(|d| !is_allowed_service_bind(service, d));
      if bad_device || bad_bind {
        reasons.push(format!(
          "compose 顶层卷 {vol} 使用 driver_opts 绑定了宿主机路径"
        ));
      }
    }
  }
  reasons
}

fn check_compose_service(
  service: &str,
  comp: &str,
  body: &Value,
  reasons: &mut Vec<String>,
) {
  if body.get("privileged").and_then(Value::as_bool) == Some(true) {
    reasons.push(format!("compose 容器 {comp} 开启了 privileged"));
  }
  for field in ["pid", "network_mode", "ipc"] {
    if let Some(raw) = body.get(field).and_then(Value::as_str) {
      let val = raw.trim().to_ascii_lowercase();
      if val == "host" || val.starts_with("container:") {
        reasons.push(format!(
          "compose 容器 {comp} 设置了 {field}: {}",
          raw.trim()
        ));
      }
    }
  }
  for field in ["uts", "cgroup", "userns_mode"] {
    if body
      .get(field)
      .and_then(Value::as_str)
      .is_some_and(|v| v.trim().eq_ignore_ascii_case("host"))
    {
      reasons
        .push(format!("compose 容器 {comp} 设置了 {field}: host"));
    }
  }
  if non_empty_seq_or_str(body.get("cap_add")) {
    reasons
      .push(format!("compose 容器 {comp} 添加了内核能力 cap_add"));
  }
  if non_empty_seq(body.get("devices")) {
    reasons
      .push(format!("compose 容器 {comp} 挂载了宿主机设备 devices"));
  }
  if non_empty_seq(body.get("device_cgroup_rules")) {
    reasons.push(format!(
      "compose 容器 {comp} 设置了 device_cgroup_rules"
    ));
  }
  if non_empty_seq(body.get("security_opt")) {
    reasons.push(format!(
      "compose 容器 {comp} 修改了安全选项 security_opt"
    ));
  }
  if non_empty_seq_or_map(body.get("sysctls")) {
    reasons
      .push(format!("compose 容器 {comp} 修改了内核参数 sysctls"));
  }
  if non_empty_seq(body.get("volumes_from")) {
    reasons.push(format!(
      "compose 容器 {comp} 引用了其他容器卷 volumes_from"
    ));
  }
  if let Some(vols) = body.get("volumes").and_then(Value::as_sequence)
  {
    for v in vols {
      check_compose_volume(service, comp, v, reasons);
    }
  }
}

fn check_compose_volume(
  service: &str,
  comp: &str,
  v: &Value,
  reasons: &mut Vec<String>,
) {
  let source = match v {
    Value::String(s) => {
      let Some((src, _)) = s.trim().split_once(':') else {
        return;
      };
      let src = src.trim();
      if is_named_volume(src) {
        return;
      }
      src
    }
    Value::Mapping(_) => {
      let kind = v
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("volume")
        .trim()
        .to_ascii_lowercase();
      if kind == "tmpfs" {
        return;
      }
      let src =
        v.get("source").and_then(Value::as_str).unwrap_or("").trim();
      if kind == "volume" && (src.is_empty() || is_named_volume(src))
      {
        return;
      }
      src
    }
    _ => return,
  };
  if is_allowed_service_bind(service, source) {
    return;
  }
  if source.contains("docker.sock") {
    reasons.push(format!(
      "compose 容器 {comp} 挂载了 docker.sock（{source}）"
    ));
  } else {
    reasons
      .push(format!("compose 容器 {comp} 挂载了宿主机路径 {source}"));
  }
}

fn is_named_volume(src: &str) -> bool {
  !src.is_empty()
    && !src.starts_with(['/', '.', '~', '$'])
    && !src.contains('/')
}

fn is_allowed_service_bind(service: &str, source: &str) -> bool {
  let s = source.trim();
  if s.is_empty()
    || s.contains('$')
    || s.contains('~')
    || s.ends_with("docker.sock")
  {
    return false;
  }
  let own = format!("/srv/{service}");
  if s == own {
    return true;
  }
  if let Some(rest) = s.strip_prefix(&format!("{own}/")) {
    return !rest.split('/').any(|seg| seg == "." || seg == "..");
  }
  if s == "." {
    return true;
  }
  if let Some(rest) = s.strip_prefix("./") {
    return !rest.split('/').any(|seg| seg == "..");
  }
  false
}

fn non_empty_seq(v: Option<&Value>) -> bool {
  v.and_then(Value::as_sequence)
    .is_some_and(|s| !s.is_empty())
}

fn non_empty_seq_or_str(v: Option<&Value>) -> bool {
  match v {
    Some(Value::Sequence(s)) => !s.is_empty(),
    Some(Value::String(s)) => !s.trim().is_empty(),
    _ => false,
  }
}

fn non_empty_seq_or_map(v: Option<&Value>) -> bool {
  match v {
    Some(Value::Sequence(s)) => !s.is_empty(),
    Some(Value::Mapping(m)) => !m.is_empty(),
    _ => false,
  }
}

/// 解析 Compose YAML 中所有 `services.*.ports` 实际发布的宿主机端口。
/// 先调用 `apply_merge()` 展开 YAML 锚点；支持短写法与长写法、IPv6 `[::1]:8080:80`、
/// 协议 `/tcp` `/udp` 及端口段 `8080-8082:80-82`（单段上限 1024 防爆内存）。
pub fn compose_published_ports(
  content: &str,
) -> Result<Vec<PublishedPort>, ApiError> {
  let Ok(mut doc) = serde_yaml_ng::from_str::<Value>(content) else {
    return Ok(vec![]);
  };
  let _ = doc.apply_merge();
  let mut out = Vec::new();
  let Some(services) =
    doc.get("services").and_then(Value::as_mapping)
  else {
    return Ok(out);
  };
  for body in services.values() {
    let Some(ports) = body.get("ports").and_then(Value::as_sequence)
    else {
      continue;
    };
    for p in ports {
      match p {
        Value::String(raw) => parse_short_port(raw, &mut out)?,
        Value::Mapping(_) => parse_long_port(p, &mut out)?,
        _ => {}
      }
    }
  }
  Ok(out)
}

fn parse_short_port(
  raw: &str,
  out: &mut Vec<PublishedPort>,
) -> Result<(), ApiError> {
  let s = raw.trim();
  let (main, udp) = match s.rsplit_once('/') {
    Some((head, proto)) => {
      match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => (head, false),
        "udp" => (head, true),
        _ => return Ok(()),
      }
    }
    None => (s, false),
  };
  let (host_ip, pub_part) = if let Some(rest) = main.strip_prefix('[')
  {
    let Some((ip, tail)) = rest.split_once("]:") else {
      return Ok(());
    };
    parse_host_ip(ip)?;
    let Some((pub_part, _)) = tail.split_once(':') else {
      return Ok(());
    };
    (Some(ip.to_string()), pub_part)
  } else {
    let parts: Vec<&str> = main.split(':').collect();
    match parts.as_slice() {
      [_container] => return Ok(()),
      [pub_part, _container] => (None, *pub_part),
      [ip, pub_part, _container] => {
        let ip = ip.trim();
        let host_ip = if ip.is_empty() {
          None
        } else {
          parse_host_ip(ip)?;
          Some(ip.to_string())
        };
        (host_ip, *pub_part)
      }
      _ => return Ok(()),
    }
  };
  for host_port in expand_port_range(pub_part)? {
    out.push(PublishedPort {
      host_ip: host_ip.clone(),
      host_port,
      udp,
    });
  }
  Ok(())
}

fn parse_long_port(
  p: &Value,
  out: &mut Vec<PublishedPort>,
) -> Result<(), ApiError> {
  let proto = p
    .get("protocol")
    .and_then(Value::as_str)
    .unwrap_or("tcp")
    .trim()
    .to_ascii_lowercase();
  let udp = match proto.as_str() {
    "tcp" => false,
    "udp" => true,
    _ => return Ok(()),
  };
  let host_ip = p
    .get("host_ip")
    .and_then(Value::as_str)
    .map(|s| s.trim().trim_start_matches('[').trim_end_matches(']'))
    .filter(|s| !s.is_empty())
    .map(str::to_string);
  if let Some(ip) = &host_ip {
    parse_host_ip(ip)?;
  }
  let ports = match p.get("published") {
    Some(Value::Number(n)) => n
      .as_u64()
      .and_then(|v| u16::try_from(v).ok())
      .into_iter()
      .collect(),
    Some(Value::String(s)) => expand_port_range(s)?,
    _ => vec![],
  };
  for host_port in ports {
    out.push(PublishedPort {
      host_ip: host_ip.clone(),
      host_port,
      udp,
    });
  }
  Ok(())
}

fn parse_host_ip(ip: &str) -> Result<IpAddr, ApiError> {
  ip.parse::<IpAddr>().map_err(|_| {
    ApiError::invalid(format!(
      "compose 端口绑定地址 {ip} 不是合法的 IP 地址"
    ))
  })
}

fn expand_port_range(raw: &str) -> Result<Vec<u16>, ApiError> {
  let s = raw.trim();
  if s.is_empty() {
    return Ok(vec![]);
  }
  if let Some((a, b)) = s.split_once('-') {
    let (Ok(start), Ok(end)) =
      (a.trim().parse::<u16>(), b.trim().parse::<u16>())
    else {
      return Ok(vec![]);
    };
    if start > end {
      return Ok(vec![]);
    }
    if usize::from(end - start) + 1 > 1024 {
      return Err(ApiError::invalid(format!(
        "compose 端口段 {s} 超过 1024 个端口"
      )));
    }
    return Ok((start..=end).collect());
  }
  Ok(s.parse::<u16>().into_iter().collect())
}

/// 判断 Compose 中是否存在 `network_mode: host` 的容器。
pub fn compose_has_host_network(content: &str) -> bool {
  let Ok(mut doc) = serde_yaml_ng::from_str::<Value>(content) else {
    return false;
  };
  let _ = doc.apply_merge();
  doc.get("services").and_then(Value::as_mapping).is_some_and(
    |services| {
      services.values().any(|body| {
        body
          .get("network_mode")
          .and_then(Value::as_str)
          .is_some_and(|v| v.trim().eq_ignore_ascii_case("host"))
      })
    },
  )
}

/// 筛出 Compose 中绑定到通配（未写 IP / `0.0.0.0` / `::`）或公网 IP 的发布端口。
pub fn compose_public_binds(content: &str) -> Vec<PublishedPort> {
  compose_published_ports(content)
    .unwrap_or_default()
    .into_iter()
    .filter(|p| is_public_bind(p.host_ip.as_deref()))
    .collect()
}

fn is_public_bind(ip: Option<&str>) -> bool {
  let Some(raw) = ip else {
    return true;
  };
  let Ok(addr) = raw.parse::<IpAddr>() else {
    return true;
  };
  is_public_ip(addr)
}

fn is_public_ip(addr: IpAddr) -> bool {
  match addr {
    IpAddr::V4(v4) => {
      if v4.is_unspecified() {
        return true;
      }
      let oct = v4.octets();
      let cgnat = oct[0] == 100 && (oct[1] & 0b1100_0000) == 64;
      !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || cgnat)
    }
    IpAddr::V6(v6) => {
      if let Some(v4) = v6.to_ipv4_mapped() {
        return is_public_ip(IpAddr::V4(v4));
      }
      if v6.is_unspecified() {
        return true;
      }
      let seg = v6.segments();
      let ula = (seg[0] & 0xfe00) == 0xfc00;
      let link_local = (seg[0] & 0xffc0) == 0xfe80;
      !(v6.is_loopback() || ula || link_local)
    }
  }
}
