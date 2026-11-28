use super::{
  BTreeMap, ComposeConfigDef, ComposeConfigRef, ComposeFile,
  ComposeService, FRPC_IMAGE, FRPS_IMAGE, hash, to_yaml,
};

const CA_FILE: &str = "/etc/frp/ca.pem";

fn compose(
  project: &str,
  image: &str,
  bin: &str,
  config: String,
  ca: Option<&str>,
) -> String {
  let config_path = format!("/etc/frp/{bin}.toml");
  let mut configs = BTreeMap::new();
  let mut mounts = Vec::new();
  for (kind, target, content) in [
    ("cfg", config_path.as_str(), Some(config.as_str())),
    ("ca", CA_FILE, ca),
  ] {
    if let Some(content) = content {
      let source =
        format!("wharf-{bin}-{kind}-{}", &hash(content)[..12]);
      configs.insert(
        source.clone(),
        ComposeConfigDef {
          content: content.replace('$', "$$"),
        },
      );
      mounts.push(ComposeConfigRef {
        source,
        target: target.to_string(),
      });
    }
  }
  to_yaml(&ComposeFile {
    name: project.to_string(),
    services: BTreeMap::from([(
      bin.to_string(),
      ComposeService {
        stop_grace_period: None,
        stop_signal: None,
        image: image.to_string(),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: Some(vec![bin.into(), "-c".into(), config_path]),
        command: None,
        environment: BTreeMap::new(),
        ports: vec![],
        volumes: vec![],
        configs: mounts,
        labels: BTreeMap::from([("wharf.link".into(), bin.into())]),
      },
    )]),
    configs,
  })
}

pub fn frps_compose(project: &str, token: &str) -> String {
  let config = format!(
    "bindAddr = \"127.0.0.1\"\nbindPort = {}\nproxyBindAddr = \"127.0.0.1\"\nallowPorts = [{{ start = 30000, end = 39999 }}]\nauth.method = \"token\"\nauth.token = \"{token}\"\n",
    crate::link::FRPS_PORT
  );
  compose(project, FRPS_IMAGE, "frps", config, None)
}

fn frpc_config(
  server_addr: &str,
  server_port: u16,
  proxies: &[(String, u16, u16)],
  token: &str,
  admin: Option<(u16, &str)>,
) -> String {
  let mut config = format!(
    "serverAddr = \"{server_addr}\"\nserverPort = {server_port}\nloginFailExit = false\nauth.method = \"token\"\nauth.token = \"{token}\"\ntransport.protocol = \"wss\"\ntransport.tls.enable = true\ntransport.tls.serverName = \"{}\"\ntransport.tls.trustedCaFile = \"{CA_FILE}\"\n",
    crate::link::LINK_HOST
  );
  if let Some((port, password)) = admin {
    config.push_str(&format!(
      "webServer.addr = \"127.0.0.1\"\nwebServer.port = {port}\nwebServer.user = \"wharf\"\nwebServer.password = \"{password}\"\n"
    ));
  }
  for (name, local, remote) in proxies {
    config.push_str(&format!(
      "\n[[proxies]]\nname = \"{name}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {local}\nremotePort = {remote}\ntransport.useEncryption = true\n"
    ));
  }
  config
}

pub fn frpc_compose(
  project: &str,
  server_addr: &str,
  server_port: u16,
  proxies: &[(String, u16, u16)],
  token: &str,
  ca: &str,
) -> String {
  let config =
    frpc_config(server_addr, server_port, proxies, token, None);
  compose(project, FRPC_IMAGE, "frpc", config, Some(ca))
}

pub struct FrpcRender {
  pub compose: String,
  pub config: String,
  pub config_hash: String,
  pub extra_files: BTreeMap<String, String>,
}

pub fn frpc_render(
  project: &str,
  (server_addr, server_port): (&str, u16),
  admin_port: u16,
  proxies: &[(String, u16, u16)],
  token: &str,
  ca: &str,
) -> FrpcRender {
  let password =
    hash(&format!("wharf-frpc-admin\0{token}\0{project}"));
  let config = frpc_config(
    server_addr,
    server_port,
    proxies,
    token,
    Some((admin_port, &password[..32])),
  );
  let base_hash = hash(&format!(
    "{server_addr}\0{server_port}\0{admin_port}\0{token}\0{ca}"
  ));
  let compose = to_yaml(&ComposeFile {
    name: project.into(),
    services: BTreeMap::from([(
      "frpc".into(),
      ComposeService {
        stop_grace_period: None,
        stop_signal: None,
        image: FRPC_IMAGE.into(),
        restart: "unless-stopped",
        mem_limit: None,
        cpus: None,
        network_mode: Some("host"),
        entrypoint: Some(vec![
          "frpc".into(),
          "-c".into(),
          "/etc/frp/frpc.toml".into(),
        ]),
        command: None,
        environment: BTreeMap::new(),
        ports: vec![],
        volumes: vec!["./conf:/etc/frp:ro".into()],
        configs: vec![],
        labels: BTreeMap::from([
          ("wharf.link".into(), "frpc".into()),
          ("wharf.link.base".into(), base_hash[..16].into()),
        ]),
      },
    )]),
    configs: BTreeMap::new(),
  });
  FrpcRender {
    compose,
    config_hash: hash(&config),
    config,
    extra_files: BTreeMap::from([("ca.pem".into(), ca.into())]),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn only_connection_settings_change_the_compose() {
    let render = |proxies: &[(_, _, _)], token: &str| {
      frpc_render(
        "wharf-link-s1",
        ("203.0.113.1", 443),
        47401,
        proxies,
        token,
        "fixture-ca",
      )
    };
    let one = render(&[("app.http".into(), 80, 30000)], "fixture-a");
    let two = render(
      &[
        ("app.http".into(), 80, 30000),
        ("app2.http".into(), 81, 30001),
      ],
      "fixture-a",
    );
    assert_eq!(one.compose, two.compose);
    assert_ne!(one.config_hash, two.config_hash);
    assert_ne!(one.compose, render(&[], "fixture-b").compose);
    assert!(!one.compose.contains("fixture-a"));
    assert!(one.config.contains("transport.useEncryption = true"));
    assert!(one.config.contains("transport.tls.trustedCaFile"));
  }
}
