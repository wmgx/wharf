//! 由期望状态渲染出 compose 文件和 Caddyfile。纯函数，不碰网络和数据库。

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use wharf_api_types::{
  ApiError,
  agent::BUILD_IMAGE_PREFIX,
  spec::{
    BuildSource, GatewayKind, GatewaySpec, GatewayTls, PortSpec,
    PrivateAddr, ServiceSpec, Source,
  },
};

use crate::world::{World, gateway_project};

pub const DEFAULT_CADDY_IMAGE: &str = "caddy:2";
pub const DEFAULT_CLOUDFLARED_IMAGE: &str =
  "cloudflare/cloudflared:2026.9.3";
/// 隧道连接器 compose 里 token 的占位，执行时才替换，不进计划、不算进哈希。
pub const TUNNEL_TOKEN_SECRET: &str = "WHARF_TUNNEL_TOKEN";
/// 和 agent 里的 `CADDY_ADMIN` 一致：管理接口走 unix socket，不占端口。
const CADDY_ADMIN: &str = "unix//config/caddy-admin.sock";

pub fn hash(content: &str) -> String {
  hex::encode(Sha256::digest(content.as_bytes()))
}

/// 每台服务器的网络信息，来自 agent 上报和服务器设置。
#[derive(Debug, Clone, Default)]
pub struct Net {
  /// 实际使用的内网地址：服务器设置的覆盖值，否则是 agent 检测到的组网地址。
  pub private: BTreeMap<String, PrivateAddr>,
  /// agent 上报的其他网卡地址，用来在缺内网地址时给出建议命令。
  pub lan_ips: BTreeMap<String, Vec<String>>,
  pub public_ip: BTreeMap<String, String>,
  /// 登录保护的账号（密钥 BASIC_AUTH）。不是网络信息，但渲染网关时要用，放在这里不必到处传。
  pub basic_auth: Option<BasicAuth>,
}

/// 密钥 BASIC_AUTH 的名字。写入时值是 `用户名:密码`，保存的是 `用户名 bcrypt哈希`。
pub const BASIC_AUTH_SECRET: &str = "BASIC_AUTH";

#[derive(Debug, Clone, PartialEq)]
pub struct BasicAuth {
  pub user: String,
  pub hash: String,
}

impl BasicAuth {
  /// 解析保存的值 `用户名 bcrypt哈希`。
  pub fn parse(stored: &str) -> Option<Self> {
    let (user, hash) = stored.split_once(' ')?;
    (!user.is_empty() && hash.starts_with("$2")).then(|| Self {
      user: user.into(),
      hash: hash.into(),
    })
  }

  /// 把写入的 `用户名:密码` 转成保存的值。盐是随机的，只在写入时算一次，
  /// 这样网关配置是稳定的，不会每次 plan 都显示变化。
  pub fn hash_input(input: &str) -> Result<String, ApiError> {
    let (user, password) =
      input.split_once(':').ok_or_else(|| {
        ApiError::invalid("BASIC_AUTH 的值要写成 用户名:密码")
      })?;
    let user_ok = !user.is_empty()
      && user
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c));
    if !user_ok {
      return Err(ApiError::invalid(
        "BASIC_AUTH 的用户名只能用字母、数字、. _ -",
      ));
    }
    if password.len() < 8 {
      return Err(ApiError::invalid("BASIC_AUTH 的密码至少 8 位"));
    }
    let hash =
      bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| {
        ApiError::internal(format!("计算密码哈希失败：{e}"))
      })?;
    Ok(format!("{user} {hash}"))
  }
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
  command: Option<Vec<String>>,
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

/// 构建来源的镜像名：`wharf-build/<服务>:<指纹>`。指纹来自构建配置和端口
/// （端口决定模板里的 `$PORT`），配置不变就不用重新构建。
pub fn build_image(
  name: &str,
  build: &BuildSource,
  ports: &[PortSpec],
) -> String {
  // 模板只用到容器端口（`$PORT`），宿主机端口变了不用重新构建。
  let input =
    serde_json::json!({ "build": build, "port": build_port(ports) });
  let key = hash(&input.to_string());
  format!("{BUILD_IMAGE_PREFIX}{name}:{}", &key[..12])
}

/// 构建来源模板里的 `$PORT`：第一个端口，没有端口时 8080。
pub fn build_port(ports: &[PortSpec]) -> u16 {
  ports.first().map_or(8080, |p| p.port)
}

/// 服务的 compose 文件。image 来源自动生成；compose 来源原样使用。
/// 端口只绑定 127.0.0.1 和内网地址，不绑定 0.0.0.0。
pub fn service_compose(
  name: &str,
  spec: &ServiceSpec,
  host_ports: &BTreeMap<String, u16>,
  private_ip: Option<&str>,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  match &spec.source {
    Source::Compose { content, .. } => {
      substitute(content.as_deref().unwrap_or_default(), secrets)
    }
    Source::Image(_) | Source::Build(_) => {
      let image = match &spec.source {
        Source::Build(b) => build_image(name, b, &spec.ports),
        Source::Image(image) => image.clone(),
        Source::Compose { .. } => unreachable!(),
      };
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
        if let Some(ip) = private_ip {
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
            image,
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
  spec.image.clone().unwrap_or_else(|| {
    match spec.kind {
      GatewayKind::Caddy => DEFAULT_CADDY_IMAGE,
      GatewayKind::CloudflareTunnel => DEFAULT_CLOUDFLARED_IMAGE,
    }
    .to_string()
  })
}

/// cloudflare_tunnel 网关的连接器：host 网络，上游用 127.0.0.1 和内网地址都能访问。
pub fn tunnel_compose(name: &str, spec: &GatewaySpec) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    name: project,
    services: BTreeMap::from([(
      "cloudflared".to_string(),
      ComposeService {
        image: gateway_image(spec),
        restart: "unless-stopped",
        network_mode: Some("host"),
        command: Some(
          ["tunnel", "--no-autoupdate", "run"]
            .map(String::from)
            .to_vec(),
        ),
        environment: BTreeMap::from([(
          "TUNNEL_TOKEN".to_string(),
          format!("[[{TUNNEL_TOKEN_SECRET}]]"),
        )]),
        ports: vec![],
        volumes: vec![],
        labels: BTreeMap::from([(
          "wharf.gateway".to_string(),
          name.to_string(),
        )]),
      },
    )]),
  };
  to_yaml(&file)
}

/// caddy 网关的 compose：host 网络，这样上游用 127.0.0.1 和内网地址都能访问。
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
        command: Some(
          [
            "caddy",
            "run",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
          ]
          .map(String::from)
          .to_vec(),
        ),
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

/// 备份服务器上的 rest-server：只监听内网地址，要账号，只能追加
/// （备份来源的机器被攻破也删不掉备份，清理旧快照在备份服务器本机做）。
/// `htpasswd` 是 `用户名:bcrypt哈希`。
pub fn backup_server_compose(
  listen_ip: &str,
  htpasswd: &str,
) -> String {
  use wharf_api_types::agent::{
    BACKUP_ROOT, REST_SERVER_IMAGE, REST_SERVER_PORT,
  };
  let host = if listen_ip.contains(':') {
    format!("[{listen_ip}]")
  } else {
    listen_ip.to_string()
  };
  let script = format!(
    "printf '%s\\n' \"$$HTPASSWD\" > /tmp/htpasswd && exec rest-server --path /data --htpasswd-file /tmp/htpasswd --listen {host}:{REST_SERVER_PORT} --append-only"
  );
  let file = ComposeFile {
    name: BACKUP_PROJECT.to_string(),
    services: BTreeMap::from([(
      "rest-server".to_string(),
      ComposeService {
        image: REST_SERVER_IMAGE.to_string(),
        restart: "unless-stopped",
        network_mode: Some("host"),
        command: Some(vec!["sh".into(), "-c".into(), script]),
        environment: BTreeMap::from([(
          "HTPASSWD".to_string(),
          htpasswd.replace('$', "$$"),
        )]),
        ports: vec![],
        volumes: vec![format!("{BACKUP_ROOT}:/data")],
        labels: BTreeMap::from([(
          "wharf.backup".to_string(),
          "rest-server".to_string(),
        )]),
      },
    )]),
  };
  to_yaml(&file)
}

/// 备份服务器上 rest-server 的 project 名。
pub const BACKUP_PROJECT: &str = "wharf-backup";

/// 路由的上游地址。网关和服务在同一台机器上用 127.0.0.1，否则用服务所在机器的内网地址。
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
  let server = &row.spec.server;
  let addr = net.private.get(server).ok_or_else(|| {
    let err = ApiError::invalid(format!(
      "服务器 {server} 没有内网地址，网关 {gateway_server} 无法跨机器访问服务 {service}"
    ))
    .with_hint(
      "装上组网工具（Tailscale / Headscale）后 agent 会自动检测；两台机器内网直通时，手动指定内网地址",
    );
    match net.lan_ips.get(server).and_then(|ips| ips.first()) {
      Some(ip) => err.suggest(format!(
        "wharf server set {server} --private-ip {ip} --apply"
      )),
      None => err,
    }
  })?;
  Ok(format!("{}:{host_port}", addr.ip))
}

/// 一条 Caddy 站点：hostname → 上游。
#[derive(Debug, Clone, PartialEq)]
pub struct Site {
  pub hostname: String,
  pub upstream: String,
  pub auth: bool,
  /// 按路径转发：（路径，上游）。
  pub paths: Vec<(String, String)>,
}

pub fn caddyfile(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
  auth: Option<&BasicAuth>,
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
    out.push_str(&format!("\n{scheme}{} {{\n", site.hostname));
    if let (true, Some(a)) = (site.auth, auth) {
      out.push_str(&format!(
        "\tbasic_auth {{\n\t\t{} {}\n\t}}\n",
        a.user, a.hash
      ));
    }
    // 带路径的 reverse_proxy 由 Caddy 排在不带路径的前面。
    for (path, upstream) in &site.paths {
      out.push_str(&format!("\treverse_proxy {path} {upstream}\n"));
    }
    out.push_str(&format!("\treverse_proxy {}\n}}\n", site.upstream));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use wharf_api_types::spec::{GatewayKind, PortSpec, VolumeSpec};

  fn spec() -> ServiceSpec {
    ServiceSpec {
      backup: None,
      adopt: None,
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
  fn image_compose_binds_loopback_and_private_only() {
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
      account: None,
    };
    let out = caddyfile(
      "edge",
      &gw,
      &[
        Site {
          hostname: "z.example.com".into(),
          upstream: "127.0.0.1:1".into(),
          auth: true,
          paths: vec![],
        },
        Site {
          hostname: "a.example.com".into(),
          upstream: "100.1.1.1:2".into(),
          auth: false,
          paths: vec![("/ws".into(), "127.0.0.1:17891".into())],
        },
      ],
      BasicAuth::parse("admin $2b$12$abc").as_ref(),
    );
    // 只有开了 auth 的站点带 basic_auth。
    let z = &out[out.find("z.example.com").unwrap()..];
    assert!(z.contains("basic_auth {\n\t\tadmin $2b$12$abc\n\t}"));
    assert_eq!(out.matches("basic_auth").count(), 1);
    assert!(out.contains(
      "a.example.com {\n\treverse_proxy /ws 127.0.0.1:17891\n\treverse_proxy 100.1.1.1:2\n}"
    ));
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
        auth: false,
        paths: vec![],
      }],
      None,
    );
    assert!(out.contains("auto_https off"));
    assert!(out.contains("\nhttp://a.example.com {"));
  }

  #[test]
  fn tunnel_compose_holds_only_a_token_placeholder() {
    let spec = GatewaySpec {
      kind: GatewayKind::CloudflareTunnel,
      server: "edge1".into(),
      default: false,
      http_port: None,
      https_port: None,
      email: None,
      image: None,
      tls: GatewayTls::Auto,
      account: Some("cf".into()),
    };
    let out = tunnel_compose("cf", &spec);
    assert!(
      out.contains("TUNNEL_TOKEN: '[[WHARF_TUNNEL_TOKEN]]'"),
      "{out}"
    );
    assert!(out.contains("network_mode: host"));
    assert!(out.contains(DEFAULT_CLOUDFLARED_IMAGE));
  }

  #[test]
  fn basic_auth_input_is_checked() {
    assert!(BasicAuth::hash_input("no-colon").is_err());
    assert!(BasicAuth::hash_input("ad min:longenough").is_err());
    assert!(BasicAuth::hash_input("admin:short").is_err());
    assert!(BasicAuth::parse("admin plaintext").is_none());
  }
}
