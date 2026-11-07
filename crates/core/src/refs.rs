//! 服务互相引用（P9）：env 和 compose 内容里的 `[[@db]]` 部署时换成 db 的 `内网地址:宿主机端口`。
//!
//! - `[[@db]]`：第一个端口；`[[@db.http]]`：指定端口名；
//! - 末尾加 `:host` 或 `:port` 只取地址或端口，例如 `[[@db:host]]`、`[[@db.http:port]]`。
//!
//! 同机也用内网地址：端口本来就绑在内网地址上，服务换机器时写法不变。
//! 替换结果进部署内容的指纹，被引用的服务换了机器或端口，引用它的服务自动进计划重新部署。

use wharf_api_types::ApiError;

use crate::{render::Net, world::World};

/// 一处引用。
#[derive(Debug, PartialEq)]
pub struct Ref<'a> {
  pub service: &'a str,
  pub port: Option<&'a str>,
  pub part: Part,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Part {
  Both,
  Host,
  Port,
}

fn parse(inner: &str) -> Option<Ref<'_>> {
  let body = inner.strip_prefix('@')?;
  let (body, part) = match body.rsplit_once(':') {
    Some((b, "host")) => (b, Part::Host),
    Some((b, "port")) => (b, Part::Port),
    Some(_) => return None,
    None => (body, Part::Both),
  };
  let (service, port) = match body.split_once('.') {
    Some((s, p)) => (s, Some(p)),
    None => (body, None),
  };
  let ok = |s: &str| {
    !s.is_empty()
      && s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
  };
  (ok(service) && port.is_none_or(ok)).then_some(Ref {
    service,
    port,
    part,
  })
}

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

/// 服务配置里引用到的服务：env 的值和 compose 内容。
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
    let inner = &rest[start + 2..start + 2 + len];
    out.push_str(&rest[..start]);
    match parse(inner) {
      Some(r) => out.push_str(&f(&r)?),
      None => out.push_str(&rest[start..start + 4 + len]),
    }
    rest = &rest[start + 4 + len..];
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
    if target != my_server
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
      Part::Host => host,
      Part::Port => port.to_string(),
    })
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_forms() {
    assert_eq!(
      parse("@db"),
      Some(Ref {
        service: "db",
        port: None,
        part: Part::Both
      })
    );
    assert_eq!(
      parse("@db.http:port"),
      Some(Ref {
        service: "db",
        port: Some("http"),
        part: Part::Port
      })
    );
    assert_eq!(parse("@db:nope"), None);
    assert_eq!(parse("SECRET"), None);
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
