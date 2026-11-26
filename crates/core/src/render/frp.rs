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

pub fn frpc_compose(
  project: &str,
  server_addr: &str,
  server_port: u16,
  proxies: &[(String, u16, u16)],
  token: &str,
  ca: &str,
) -> String {
  let mut config = format!(
    "serverAddr = \"{server_addr}\"\nserverPort = {server_port}\nloginFailExit = false\nauth.method = \"token\"\nauth.token = \"{token}\"\ntransport.protocol = \"wss\"\ntransport.tls.enable = true\ntransport.tls.serverName = \"{}\"\ntransport.tls.trustedCaFile = \"{CA_FILE}\"\n",
    crate::link::LINK_HOST
  );
  for (name, local, remote) in proxies {
    config.push_str(&format!(
      "\n[[proxies]]\nname = \"{name}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {local}\nremotePort = {remote}\ntransport.useEncryption = true\n"
    ));
  }
  compose(project, FRPC_IMAGE, "frpc", config, Some(ca))
}
