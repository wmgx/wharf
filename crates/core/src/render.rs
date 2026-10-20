//! 由期望状态渲染出 compose 文件和 Caddyfile。纯函数，不碰网络和数据库。

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError,
  spec::{GatewaySpec, GatewayTls, ServiceSpec, Source},
};

use crate::world::{World, gateway_project};

pub const DEFAULT_CADDY_IMAGE: &str = "caddy:2";
/// 和 agent 里的 `CADDY_ADMIN` 一致：管理接口走 unix socket，不占端口。
const CADDY_ADMIN: &str = "unix//config/caddy-admin.sock";

pub fn hash(content: &str) -> String {
  hex::encode(Sha256::digest(content.as_bytes()))
}

/// 每台服务器的网络信息，来自 agent 上报和服务器设置。
#[derive(Debug, Clone, Default)]
pub struct Net {
  pub tailscale_ip: BTreeMap<String, String>,
  pub public_ip: BTreeMap<String, String>,
}

/// 服务数据目录：`/srv/<service>/<volume>`。
pub fn volume_dir(service: &str, volume: &str) -> String {
  format!("/srv/{service}/{volume}")
}

pub fn service_dirs(name: &str, spec: &ServiceSpec) -> Vec<String> {
  spec
    .volumes
    .iter()
    .map(|v| volume_dir(name, &v.name))
    .collect()
}

#[derive(Serialize)]
struct ComposeFile {
  name: String,
  services: BTreeMap<String, ComposeService>,
}

#[derive(Serialize)]
struct ComposeService {
  image: String,
  restart: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  network_mode: Option<&'static str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  command: Option<Vec<&'static str>>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  environment: BTreeMap<String, String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  ports: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  volumes: Vec<String>,
  labels: BTreeMap<String, String>,
}

fn to_yaml(file: &ComposeFile) -> String {
  let body = serde_yaml_ng::to_string(file).unwrap_or_default();
  format!("# 由 Wharf 生成，不要手改。\n{body}")
}

/// 把 `[[NAME]]` 换成密钥。`secrets` 为空时原样保留（用于展示和部署历史）。
pub fn substitute(
  text: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  let Some(secrets) = secrets else {
    return Ok(text.to_string());
  };
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  let mut missing = Vec::new();
  while let Some(start) = rest.find("[[") {
    let Some(len) = rest[start + 2..].find("]]") else {
      break;
    };
    let name = &rest[start + 2..start + 2 + len];
    let is_name = !name.is_empty()
      && name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    out.push_str(&rest[..start]);
    if is_name {
      match secrets.get(name) {
        Some(value) => out.push_str(value),
        None => missing.push(name.to_string()),
      }
    } else {
      out.push_str(&rest[start..start + 4 + len]);
    }
    rest = &rest[start + 4 + len..];
  }
  out.push_str(rest);
  if !missing.is_empty() {
    missing.sort();
    missing.dedup();
    let first = missing[0].clone();
    return Err(
      ApiError::invalid(format!(
        "密钥不存在：{}",
        missing.join("、")
      ))
      .with_hint("先设置密钥，值从标准输入读取，不会出现在命令行里")
      .suggest(format!("wharf secret set {first}")),
    );
  }
  Ok(out)
}

/// 服务的 compose 文件。image 来源自动生成；compose 来源原样使用。
/// 端口只绑定 127.0.0.1 和 Tailscale IP，不绑定 0.0.0.0。
pub fn service_compose(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  tailscale_ip: Option<&str>,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  match &spec.source {
    Source::Compose { content, .. } => {
      substitute(content.as_deref().unwrap_or_default(), secrets)
    }
    Source::Image(image) => {
      let mut environment = BTreeMap::new();
      for (key, value) in &spec.env {
        // compose 会对 `$` 做变量插值，原样传给容器要写成 `$$`。
        let value = substitute(value, secrets)?;
        environment.insert(key.clone(), value.replace('$', "$$"));
      }
      let mut ports = Vec::new();
      for port in &spec.ports {
        let Some(host) = host_ports.get(&port.name) else {
          continue;
        };
        ports.push(format!("127.0.0.1:{host}:{}", port.port));
        if let Some(ip) = tailscale_ip {
          ports.push(format!("{ip}:{host}:{}", port.port));
        }
      }
      let volumes = spec
        .volumes
        .iter()
        .map(|v| {
          format!("{}:{}", volume_dir(name, &v.name), v.target)
        })
        .collect();
      let file = ComposeFile {
        name: name.to_string(),
        services: BTreeMap::from([(
          name.to_string(),
          ComposeService {
            image: image.clone(),
            restart: "unless-stopped",
            network_mode: None,
            command: None,
            environment,
            ports,
            volumes,
            labels: BTreeMap::from([(
              "wharf.service".to_string(),
              name.to_string(),
            )]),
          },
        )]),
      };
      Ok(to_yaml(&file))
    }
  }
}

/// compose 来源的基本检查：必须有 services，P1 不支持 build。
pub fn check_compose(
  name: &str,
  content: &str,
) -> Result<(), ApiError> {
  let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(content)
    .map_err(|e| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 不是合法的 YAML：{e}"
      ))
    })?;
  let services = value
    .get("services")
    .and_then(|s| s.as_mapping())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "服务 {name} 的 compose 里没有 services"
      ))
    })?;
  for (svc, body) in services {
    if body.get("build").is_some() {
      return Err(
        ApiError::invalid(format!(
          "服务 {name} 的 compose 里 {} 用了 build，不在服务器上构建",
          svc.as_str().unwrap_or("?")
        ))
        .with_hint("先构建并推送镜像，compose 里改用 image"),
      );
    }
  }
  Ok(())
}

pub fn gateway_image(spec: &GatewaySpec) -> String {
  spec
    .image
    .clone()
    .unwrap_or_else(|| DEFAULT_CADDY_IMAGE.to_string())
}

/// caddy 网关的 compose：host 网络，这样上游用 127.0.0.1 和 Tailscale IP 都能访问。
pub fn gateway_compose(name: &str, spec: &GatewaySpec) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    name: project.clone(),
    services: BTreeMap::from([(
      "caddy".to_string(),
      ComposeService {
        image: gateway_image(spec),
        restart: "unless-stopped",
        network_mode: Some("host"),
        command: Some(vec![
          "caddy",
          "run",
          "--config",
          "/etc/caddy/Caddyfile",
          "--adapter",
          "caddyfile",
        ]),
        environment: BTreeMap::new(),
        ports: vec![],
        volumes: vec![
          "./conf:/etc/caddy:ro".to_string(),
          format!("/srv/{project}/data:/data"),
          format!("/srv/{project}/config:/config"),
        ],
        labels: BTreeMap::from([(
          "wharf.gateway".to_string(),
          name.to_string(),
        )]),
      },
    )]),
  };
  to_yaml(&file)
}

/// 路由的上游地址。网关和服务在同一台机器上用 127.0.0.1，否则用 Tailscale IP。
pub fn upstream(
  world: &World,
  net: &Net,
  gateway_server: &str,
  service: &str,
  port: &str,
) -> Result<String, ApiError> {
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::invalid(format!("服务 {service} 不存在"))
  })?;
  let host_port = row.host_ports.get(port).ok_or_else(|| {
    ApiError::internal(format!(
      "服务 {service} 的端口 {port} 没有分配"
    ))
  })?;
  if row.spec.server == gateway_server {
    return Ok(format!("127.0.0.1:{host_port}"));
  }
  let ip = net.tailscale_ip.get(&row.spec.server).ok_or_else(|| {
    ApiError::invalid(format!(
      "服务器 {} 没有上报 Tailscale IP，网关 {gateway_server} 无法跨机器访问服务 {service}",
      row.spec.server
    ))
    .with_hint("确认这台机器上 Tailscale 已登录，或者用 WHARF_TAILSCALE_IP 告诉 agent")
  })?;
  Ok(format!("{ip}:{host_port}"))
}

/// 一条 Caddy 站点：hostname → 上游。
#[derive(Debug, Clone, PartialEq)]
pub struct Site {
  pub hostname: String,
  pub upstream: String,
}

pub fn caddyfile(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
) -> String {
  let mut out = format!(
    "# 由 Wharf 生成，不要手改。网关：{name}\n# 手写的站点放到 conf/extra.d/*.caddy\n{{\n\tadmin {CADDY_ADMIN}\n"
  );
  if let Some(port) = spec.http_port.filter(|p| *p != 80) {
    out.push_str(&format!("\thttp_port {port}\n"));
  }
  if let Some(port) = spec.https_port.filter(|p| *p != 443) {
    out.push_str(&format!("\thttps_port {port}\n"));
  }
  if let Some(email) = &spec.email {
    out.push_str(&format!("\temail {email}\n"));
  }
  match spec.tls {
    GatewayTls::Auto => {}
    GatewayTls::Internal => out.push_str("\tlocal_certs\n"),
    GatewayTls::Off => out.push_str("\tauto_https off\n"),
  }
  out.push_str("}\n\nimport /etc/caddy/extra.d/*.caddy\n");
  let scheme = match spec.tls {
    GatewayTls::Off => "http://",
    _ => "",
  };
  let mut sites = sites.to_vec();
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  for site in sites {
    out.push_str(&format!(
      "\n{scheme}{} {{\n\treverse_proxy {}\n}}\n",
      site.hostname, site.upstream
    ));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::spec::{GatewayKind, PortSpec, VolumeSpec};

  fn spec() -> ServiceSpec {
    ServiceSpec {
      server: "node1".into(),
      source: Source::Image("traefik/whoami".into()),
      ports: vec![PortSpec {
        name: "http".into(),
        port: 80,
        host_port: None,
      }],
      env: BTreeMap::from([
        ("A".to_string(), "x$y".to_string()),
        ("TOKEN".to_string(), "[[WHO_TOKEN]]".to_string()),
      ]),
      volumes: vec![VolumeSpec {
        name: "data".into(),
        target: "/data".into(),
      }],
    }
  }

  #[test]
  fn image_compose_binds_loopback_and_tailscale_only() {
    let ports = BTreeMap::from([("http".to_string(), 20000)]);
    let secrets = BTreeMap::from([(
      "WHO_TOKEN".to_string(),
      "s3$cret".to_string(),
    )]);
    let out = service_compose(
      "whoami",
      &spec(),
      &ports,
      Some("100.1.2.3"),
      Some(&secrets),
    )
    .unwrap();
    let yaml: serde_yaml_ng::Value =
      serde_yaml_ng::from_str(&out).unwrap();
    let svc = &yaml["services"]["whoami"];
    assert_eq!(svc["ports"][0], "127.0.0.1:20000:80");
    assert_eq!(svc["ports"][1], "100.1.2.3:20000:80");
    assert_eq!(svc["environment"]["A"], "x$$y");
    assert_eq!(svc["environment"]["TOKEN"], "s3$$cret");
    assert_eq!(svc["volumes"][0], "/srv/whoami/data:/data");
    assert!(!out.contains("0.0.0.0"));
    // 不带密钥渲染时保留占位符，用于展示。
    let template =
      service_compose("whoami", &spec(), &ports, None, None).unwrap();
    assert!(template.contains("[[WHO_TOKEN]]"));
    assert!(!template.contains("s3"));
  }

  #[test]
  fn missing_secret_suggests_command() {
    let err =
      substitute("a [[NOPE]] b", Some(&BTreeMap::new())).unwrap_err();
    assert_eq!(err.suggest, vec!["wharf secret set NOPE"]);
    // 不像名字的 [[...]] 原样保留。
    assert_eq!(
      substitute("[[a b]] [x]", Some(&BTreeMap::new())).unwrap(),
      "[[a b]] [x]"
    );
  }

  #[test]
  fn compose_checks() {
    assert!(
      check_compose("x", "services:\n  web:\n    image: nginx\n")
        .is_ok()
    );
    assert!(check_compose("x", "services: {}\n").is_err());
    assert!(
      check_compose("x", "services:\n  web:\n    build: .\n")
        .is_err()
    );
    assert!(check_compose("x", "::: nope").is_err());
  }

  #[test]
  fn caddyfile_lists_sites_sorted() {
    let gw = GatewaySpec {
      kind: GatewayKind::Caddy,
      server: "edge1".into(),
      default: true,
      http_port: Some(8080),
      https_port: None,
      email: None,
      image: None,
      tls: GatewayTls::Auto,
    };
    let out = caddyfile(
      "edge",
      &gw,
      &[
        Site {
          hostname: "z.example.com".into(),
          upstream: "127.0.0.1:1".into(),
        },
        Site {
          hostname: "a.example.com".into(),
          upstream: "100.1.1.1:2".into(),
        },
      ],
    );
    assert!(out.contains("http_port 8080"));
    assert!(!out.contains("https_port"));
    assert!(!out.contains("auto_https"));
    assert!(
      out.find("a.example.com").unwrap()
        < out.find("z.example.com").unwrap()
    );
    let compose = gateway_compose("edge", &gw);
    assert!(compose.contains("network_mode: host"));
    assert!(compose.contains("name: wharf-gw-edge"));
    let off = GatewaySpec {
      tls: GatewayTls::Off,
      ..gw
    };
    let out = caddyfile(
      "edge",
      &off,
      &[Site {
        hostname: "a.example.com".into(),
        upstream: "127.0.0.1:1".into(),
      }],
    );
    assert!(out.contains("auto_https off"));
    assert!(out.contains("\nhttp://a.example.com {"));
  }
}
