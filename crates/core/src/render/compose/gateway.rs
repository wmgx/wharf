use super::*;

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
pub fn tunnel_compose(
  name: &str,
  spec: &GatewaySpec,
  token: Option<&str>,
) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    name: project,
    services: BTreeMap::from([(
      "cloudflared".to_string(),
      ComposeService {
        image: gateway_image(spec),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: None,
        command: Some(
          ["tunnel", "--no-autoupdate", "run"]
            .map(String::from)
            .to_vec(),
        ),
        environment: BTreeMap::from([(
          "TUNNEL_TOKEN".to_string(),
          token.map_or_else(
            || format!("[[{TUNNEL_TOKEN_SECRET}]]"),
            str::to_string,
          ),
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
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: None,
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
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: None,
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

/// 路由的上游地址：同机用 127.0.0.1，能直连用服务所在机器的内网地址，否则走反向隧道。
pub fn upstream(
  world: &World,
  net: &Net,
  gateway: &GatewaySpec,
  service: &str,
  port: &str,
  mode: wharf_api_types::spec::LinkMode,
) -> Result<String, ApiError> {
  let row = world.services.get(service).ok_or_else(|| {
    ApiError::invalid(format!("服务 {service} 不存在"))
  })?;
  let host_port = row.host_ports.get(port).ok_or_else(|| {
    ApiError::internal(format!(
      "服务 {service} 的端口 {port} 没有分配"
    ))
  })?;
  use crate::link::{Choice, choose, tunnel_upstream};
  Ok(match choose(world, net, gateway, service, mode)? {
    Choice::Local => format!("127.0.0.1:{host_port}"),
    Choice::Direct(ip) => format!("{ip}:{host_port}"),
    Choice::Tunnel => {
      tunnel_upstream(world, net, &gateway.server, service, port)?
    }
  })
}

pub const FRPS_IMAGE: &str = "snowdreamtech/frps:0.61.1";
pub const FRPC_IMAGE: &str = "snowdreamtech/frpc:0.61.1";

/// frp 容器：配置放在环境变量里，启动时写成文件；密钥是占位，部署时替换。
fn frp_service(
  image: &str,
  bin: &str,
  config: String,
) -> ComposeService {
  ComposeService {
    image: image.to_string(),
    restart: "unless-stopped",
    mem_limit: None,
    cpus: None,
    network_mode: Some("host"),
    entrypoint: Some(vec!["sh".into(), "-c".into()]),
    command: Some(vec![format!(
      "printf '%s\\n' \"$$FRP_CONFIG\" > /tmp/frp.toml && exec {bin} -c /tmp/frp.toml"
    )]),
    environment: BTreeMap::from([
      ("FRP_CONFIG".to_string(), config),
      (
        "FRP_TOKEN".to_string(),
        format!("[[{}]]", crate::link::TOKEN_SECRET),
      ),
    ]),
    ports: vec![],
    volumes: vec![],
    labels: BTreeMap::from([(
      "wharf.link".to_string(),
      bin.to_string(),
    )]),
  }
}

/// 网关所在机器上的 frps：只监听 127.0.0.1，由 Caddy 转发 websocket 进来；
/// 隧道端口也只绑 127.0.0.1，只允许 Wharf 的隧道端口范围。
pub fn frps_compose(project: &str) -> String {
  let config = format!(
    "bindAddr = \"127.0.0.1\"\nbindPort = {}\nproxyBindAddr = \"127.0.0.1\"\nallowPorts = [{{ start = 30000, end = 39999 }}]\nauth.token = \"{{{{ .Envs.FRP_TOKEN }}}}\"\n",
    crate::link::FRPS_PORT
  );
  to_yaml(&ComposeFile {
    name: project.to_string(),
    services: BTreeMap::from([(
      "frps".to_string(),
      frp_service(FRPS_IMAGE, "frps", config),
    )]),
  })
}

/// 服务所在机器上的 frpc：经网关的 Caddy 用 wss 连 frps。`proxies` 是 (名字, 本机端口, 隧道端口)。
pub fn frpc_compose(
  project: &str,
  server_addr: &str,
  server_port: u16,
  proxies: &[(String, u16, u16)],
) -> String {
  let mut config = format!(
    "serverAddr = \"{server_addr}\"\nserverPort = {server_port}\nloginFailExit = false\nauth.token = \"{{{{ .Envs.FRP_TOKEN }}}}\"\ntransport.protocol = \"wss\"\ntransport.tls.serverName = \"{}\"\n",
    crate::link::LINK_HOST
  );
  for (name, local, remote) in proxies {
    config.push_str(&format!(
      "\n[[proxies]]\nname = \"{name}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {local}\nremotePort = {remote}\n"
    ));
  }
  to_yaml(&ComposeFile {
    name: project.to_string(),
    services: BTreeMap::from([(
      "frpc".to_string(),
      frp_service(FRPC_IMAGE, "frpc", config),
    )]),
  })
}
