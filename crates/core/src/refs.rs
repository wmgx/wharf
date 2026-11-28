//! 服务互相引用（P9）：env 和 compose 内容里的 `[[@db]]` 部署时换成 db 的 `内网地址:宿主机端口`。
//!
//! - `[[@db]]`：第一个端口；`[[@db.http]]`：指定端口名；
//! - 末尾加 `:host` 或 `:port` 只取地址或端口，例如 `[[@db:host]]`、`[[@db.http:port]]`。
//!
//! 同机也用内网地址：端口本来就绑在内网地址上，服务换机器时写法不变。
//! 替换结果进部署内容的指纹，被引用的服务换了机器或端口，引用它的服务自动进计划重新部署。

use wharf_api_types::ApiError;

use crate::{render::Net, world::World};

use wharf_api_types::references::{Part, Ref, parse_service_ref};

/// 文本里引用到的服务（去重、按出现顺序）。
pub fn used(text: &str) -> Vec<String> {
  let mut out: Vec<String> = Vec::new();
  scan(text, |r| {
    if !out.iter().any(|s| s == r.service) {
      out.push(r.service.to_string());
    }
    Ok(String::new())
  })
  .ok();
  out
}

/// 服务配置里引用到的服务。
pub fn uses(
  spec: &wharf_api_types::spec::ServiceSpec,
) -> Vec<String> {
  use wharf_api_types::spec::Source;
  let mut text: String =
    spec.env.values().map(|v| format!("{v}\n")).collect();
  if let Source::Compose {
    content: Some(c), ..
  } = &spec.source
  {
    text.push_str(c);
  }
  for f in &spec.files {
    text.push('\n');
    text.push_str(&f.content);
  }
  used(&text)
}

/// 逐个替换 `[[@...]]`，其余内容原样保留。
fn scan(
  text: &str,
  mut f: impl FnMut(&Ref) -> Result<String, ApiError>,
) -> Result<String, ApiError> {
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  while let Some(start) = rest.find("[[@") {
    let Some(len) = rest[start + 2..].find("]]") else {
      break;
    };
    let end = start + 2 + len;
    let start = rest[start + 2..end]
      .rfind("[[@")
      .map_or(start, |i| start + 2 + i);
    let inner = &rest[start + 2..end];
    out.push_str(&rest[..start]);
    match parse_service_ref(inner) {
      Some(r) => out.push_str(&f(&r)?),
      None => out.push_str(&rest[start..end + 2]),
    }
    rest = &rest[end + 2..];
  }
  out.push_str(rest);
  Ok(out)
}

/// 把服务 `me` 的部署内容里的引用换成实际地址。
pub fn resolve(
  text: &str,
  me: &str,
  world: &World,
  net: &Net,
) -> Result<String, ApiError> {
  resolve_with_host_style(text, me, world, net, false)
}

pub(crate) fn resolve_with_host_style(
  text: &str,
  me: &str,
  world: &World,
  net: &Net,
  legacy: bool,
) -> Result<String, ApiError> {
  resolve_refs(text, me, world, net, legacy, true)
}

pub(crate) fn probe_address(
  me: &str,
  world: &World,
  net: &Net,
  service: &str,
  port: &str,
) -> Result<String, ApiError> {
  resolve_refs(
    &format!("[[@{service}.{port}]]"),
    me,
    world,
    net,
    false,
    false,
  )
}

fn resolve_refs(
  text: &str,
  me: &str,
  world: &World,
  net: &Net,
  legacy: bool,
  check_reach: bool,
) -> Result<String, ApiError> {
  if !text.contains("[[@") {
    return Ok(text.to_string());
  }
  let my_server = &world.services[me].spec.server;
  scan(text, |r| {
    let row = world.services.get(r.service).ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {me} 引用的服务 {} 不存在",
        r.service
      ))
      .with_hint("引用写作 [[@服务名]] 或 [[@服务名.端口名]]")
      .suggest("wharf service list")
    })?;
    let port_name = match r.port {
      Some(p) => p.to_string(),
      None => {
        row.spec.ports.first().map(|p| p.name.clone()).ok_or_else(
          || {
            ApiError::invalid(format!(
              "服务 {me} 引用的服务 {} 没有端口",
              r.service
            ))
          },
        )?
      }
    };
    let port = row.host_ports.get(&port_name).ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {me} 引用的服务 {} 没有端口 {port_name}",
        r.service
      ))
      .with_hint(format!(
        "可用的端口：{}",
        row
          .spec
          .ports
          .iter()
          .map(|p| p.name.as_str())
          .collect::<Vec<_>>()
          .join("、")
      ))
    })?;
    let target = &row.spec.server;
    let addr = net.private.get(target).ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {me} 引用了 {}，但 {target} 没有内网地址",
        r.service
      ))
      .with_hint("服务之间经内网地址互相访问，先让这台接入组网")
      .suggest("wharf network")
    })?;
    if check_reach
      && target != my_server
      && net.reach.get(&(my_server.clone(), target.clone()))
        == Some(&false)
    {
      return Err(
        ApiError::invalid(format!(
          "服务 {me} 引用了 {}，但 {my_server} 连不到 {target} 的内网地址",
          r.service
        ))
        .with_hint("确认两台都接入了组网后重新探测")
        .suggest("wharf network --probe"),
      );
    }
    let host = if addr.ip.contains(':') {
      format!("[{}]", addr.ip)
    } else {
      addr.ip.clone()
    };
    Ok(match r.part {
      Part::Both => format!("{host}:{port}"),
      Part::Host if legacy => host,
      Part::Host => addr.ip.clone(),
      Part::Port => port.to_string(),
    })
  })
}

#[cfg(test)]
mod tests {
  #[test]
  fn unclosed_at_bracket_does_not_swallow_resolved_ref() {
    let mut world = World::default();
    world.servers.insert(
      "s1".into(),
      crate::world::ServerRow {
        settings: Default::default(),
        version: 1,
      },
    );
    world.apply_changes(&[
      serde_json::from_value(serde_json::json!({
        "op": "upsert_service", "name": "db",
        "spec": {"server": "s1", "source": {"image": "postgres:16"},
          "ports": [{"name": "sql", "container": 5432, "host": 21000}]}
      })).unwrap(),
    ]).unwrap();
    world.allocate_ports().unwrap();
    let mut net = Net::default();
    net.private.insert(
      "s1".into(),
      wharf_api_types::spec::PrivateAddr {
        ip: "100.64.0.1".into(),
        network: wharf_api_types::spec::PrivateNetwork::Tailscale,
      },
    );
    net.private.get_mut("s1").unwrap().ip = "2001:db8::1".into();
    assert_eq!(
      resolve("[[@db:host]] [[@db]]", "db", &world, &net).unwrap(),
      "2001:db8::1 [2001:db8::1]:21000"
    );
    assert_eq!(
      resolve_with_host_style(
        "[[@db:host]]",
        "db",
        &world,
        &net,
        true
      )
      .unwrap(),
      "[2001:db8::1]"
    );
    net.private.get_mut("s1").unwrap().ip = "100.64.0.1".into();
    let text = "URL=prefix[[@bad [[@db]]";
    assert_eq!(used(text), ["db"]);
    assert_eq!(
      resolve(text, "db", &world, &net).unwrap(),
      "URL=prefix[[@bad 100.64.0.1:21000"
    );
  }

  use super::*;

  #[test]
  fn parses_forms() {
    assert_eq!(
      parse_service_ref("@db"),
      Some(Ref {
        service: "db",
        port: None,
        part: Part::Both
      })
    );
    assert_eq!(
      parse_service_ref("@db.http:port"),
      Some(Ref {
        service: "db",
        port: Some("http"),
        part: Part::Port
      })
    );
    assert_eq!(parse_service_ref("@db:nope"), None);
    assert_eq!(parse_service_ref("SECRET"), None);
  }

  #[test]
  fn lists_used_services_and_keeps_other_text() {
    let text =
      "A=[[@db]] B=[[@cache.redis:host]] C=[[@db:port]] D=[[S]]";
    assert_eq!(used(text), vec!["db", "cache"]);
    let out = scan(text, |r| Ok(r.service.to_uppercase())).unwrap();
    assert_eq!(out, "A=DB B=CACHE C=DB D=[[S]]");
  }
}
