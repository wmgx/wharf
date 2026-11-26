use super::*;
use wharf_api_types::spec::Limits;
use wharf_api_types::spec::{GatewayKind, PortSpec, VolumeSpec};

#[test]
fn files_become_configs_named_by_content() {
  let base =
    service_compose("whoami", &spec(), &BTreeMap::new(), &[], None)
      .unwrap();
  let secrets =
    BTreeMap::from([("PASS".to_string(), "p$w".to_string())]);
  let content = file_content(
    "[[servers]]\npass = \"[[PASS]]\"\n",
    Some(&secrets),
  );
  assert_eq!(content, "[[servers]]\npass = \"p$w\"\n");
  let files = vec![("/etc/app.toml".to_string(), content)];
  let out = add_files("whoami", &spec(), &base, &files).unwrap();
  let v: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).unwrap();
  let r = &v["services"]["whoami"]["configs"][0];
  assert_eq!(r["target"].as_str(), Some("/etc/app.toml"));
  let id = r["source"].as_str().unwrap();
  assert_eq!(
    v["configs"][id]["content"].as_str(),
    Some("[[servers]]\npass = \"p$$w\"\n")
  );
  let changed = vec![("/etc/app.toml".to_string(), "x".to_string())];
  let out2 = add_files("whoami", &spec(), &base, &changed).unwrap();
  assert!(!out2.contains(id));
  assert_eq!(add_files("whoami", &spec(), &base, &[]).unwrap(), base);
}

fn spec() -> ServiceSpec {
  ServiceSpec {
    backup: None,
    stopped: false,
    monitor: None,
    log_alerts: vec![],
    port_checks: Default::default(),
    heartbeat: None,
    limits: None,
    auto_update: false,
    container: None,
    files: vec![],
    server: "node1".into(),
    source: Source::Image("traefik/whoami".into()),
    ports: vec![PortSpec {
      name: "http".into(),
      container: Some(80),
      host: None,
      udp: false,
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
fn caddyfile_share_expires() {
  let gw: GatewaySpec =
    serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
      .unwrap();
  let mut site = Site {
    hostname: "a.example.com".into(),
    expires_at: Some(1_800_000_000_000),
    ..Default::default()
  };
  let out = caddyfile("edge", &gw, &[site.clone()], &[], false, None);
  assert_eq!(out.matches("order abort before basic_auth").count(), 1);
  assert!(out.contains(
    "@wharf_expired expression `int({time.now.unix}) >= 1800000000`"
  ));
  assert!(out.contains("abort @wharf_expired"));
  assert!(
    out.find("import wharf_errors").unwrap()
      < out.find("@wharf_expired").unwrap()
  );
  site.expires_at = None;
  assert!(
    !caddyfile("edge", &gw, &[site], &[], false, None)
      .contains("wharf_expired")
  );
}

#[test]
fn caddyfile_internal_site() {
  let gw: GatewaySpec =
    serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
      .unwrap();
  let mut site = Site {
    hostname: "i.example.com".into(),
    upstream: "127.0.0.1:21000".into(),
    internal: true,
    dns: Some("i.example.com".into()),
    ..Default::default()
  };
  let out = caddyfile("edge", &gw, &[site.clone()], &[], false, None);
  assert!(out.contains("dns acmedns {"));
  assert!(!out.contains("import wharf_access"));
  assert!(out.contains("@wharf_outside not remote_ip 127.0.0.0/8 ::1/128\n\tabort @wharf_outside"));
  for broad in
    ["private_ranges", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]
  {
    assert!(!out.contains(broad));
  }
  assert!(
    out.find("import wharf_errors").unwrap()
      < out.find("\ttls {").unwrap()
  );
  assert!(
    out.find("\ttls {").unwrap()
      < out.find("@wharf_outside").unwrap()
  );
  assert_eq!(out.matches("order abort before basic_auth").count(), 1);
  site.dns = None;
  site.internal_ranges =
    ["10.20.0.0/24", "100.64.0.7/32", "127.0.0.0/8", "::1/128"]
      .map(str::to_string)
      .to_vec();
  let out = caddyfile("edge", &gw, &[site.clone()], &[], false, None);
  assert!(out.contains("@wharf_outside not remote_ip 10.20.0.0/24 100.64.0.7/32 127.0.0.0/8 ::1/128"));
  assert!(!out.contains("dns acmedns"));
  site.internal = false;
  let out = caddyfile("edge", &gw, &[site], &[], false, None);
  assert!(!out.contains("wharf_outside"));
  assert!(!out.contains("dns acmedns"));
  assert!(!out.contains("order abort"));
}

#[test]
fn caddyfile_trusted_proxies_controls_headers_and_rate_limit() {
  let mut spec: GatewaySpec = serde_json::from_value(serde_json::json!({
      "kind": "caddy", "server": "s1", "error_page": "fixture",
      "trusted_proxies": {"cloudflare": true, "cluster": true, "cidrs": ["203.0.113.0/24"]}
    })).unwrap();
  let net = Net::default();
  let ranges = crate::source_trust::gateway_trusted_proxies(
    &crate::world::World::default(),
    &net,
    &spec,
    &["173.245.48.0/20".into()],
  );
  let sites = [Site {
    hostname: "example.com".into(),
    upstream: "127.0.0.1:20005".into(),
    rate_limit: Some(42),
    ..Default::default()
  }];
  let out = caddyfile_with_fill(
    "edge",
    &spec,
    &sites,
    &[],
    false,
    None,
    &ranges,
    CaddyFill::default(),
  );
  assert!(out.contains("trusted_proxies static 127.0.0.1/32 173.245.48.0/20 203.0.113.0/24 ::1/128\n\t\ttrusted_proxies_strict"));
  assert!(out.contains("(wharf_strip_forwarded)"));
  assert!(out.contains("import wharf_strip_forwarded"));
  assert!(out.contains(
    "request_header @wharf_untrusted_proxy -CF-Connecting-IP"
  ));
  assert!(out.contains("request_header X-Real-IP {client_ip}"));
  assert!(out.contains("key {client_ip}"));
  spec.trusted_proxies = None;
  let legacy = caddyfile("edge", &spec, &sites, &[], false, None);
  assert!(!legacy.contains("trusted_proxies"));
  assert!(!legacy.contains("wharf_strip_forwarded"));
  assert!(legacy.contains("key {remote_host}"));
  assert_eq!(out.matches("\n\tservers {").count(), 1);
  assert!(out.contains("\tgrace_period 10s\n\tservers {"));
  assert!(out.contains("\t\t\tread_header 10s\n\t\t\tidle 2m"));
  assert_eq!(legacy.matches("\n\tservers {").count(), 1);
  let before_edge_protection = legacy
      .replace("\tgrace_period 10s\n\tservers {\n\t\ttimeouts {\n\t\t\tread_header 10s\n\t\t\tidle 2m\n\t\t}\n\t}\n", "")
      .replace("\nhttp://:80 {\n\tabort\n}\n", "");
  assert_eq!(
    hash(&before_edge_protection),
    "3304837aead9414fe3d3192bbabc2f263fc2817e5ee805cabeac7885c01b2cdf"
  );
}

#[test]
fn caddyfile_layer4_only_when_used() {
  let gw: GatewaySpec = serde_json::from_value(
    serde_json::json!({"kind":"caddy","server":"s1"}),
  )
  .unwrap();
  let sites = vec![Site {
    hostname: "example.com".into(),
    upstream: "127.0.0.1:20005".into(),
    ..Default::default()
  }];
  let empty = caddyfile("edge", &gw, &sites, &[], false, None);
  assert!(!empty.contains("layer4"));
  let out = caddyfile(
    "edge",
    &gw,
    &sites,
    &[
      (false, 15432, "127.0.0.1:20005".into()),
      (false, 2222, "127.0.0.1:20007".into()),
      (true, 27015, "127.0.0.1:20006".into()),
    ],
    false,
    None,
  );
  assert_eq!(out.matches("layer4 {").count(), 1);
  assert!(
    out.find(":2222 {").unwrap() < out.find(":15432 {").unwrap()
  );
  assert!(out.contains(
    ":15432 {\n\t\t\troute {\n\t\t\t\tproxy 127.0.0.1:20005"
  ));
  assert!(out.contains("udp/:27015 {"));
  assert!(out.contains("proxy udp/127.0.0.1:20006"));
  assert_eq!(
    &out[out.find("\nexample.com {").unwrap()..],
    &empty[empty.find("\nexample.com {").unwrap()..]
  );
  let mut svc = spec();
  svc.env.clear();
  svc.ports.push(PortSpec {
    name: "game".into(),
    container: Some(27015),
    host: None,
    udp: true,
  });
  let compose = service_compose(
    "app",
    &svc,
    &BTreeMap::from([("http".into(), 20005), ("game".into(), 20006)]),
    &["100.64.0.1".into()],
    None,
  )
  .unwrap();
  assert!(compose.contains("127.0.0.1:20006:27015/udp"));
  assert!(compose.contains("100.64.0.1:20006:27015/udp"));
  assert!(compose.contains("127.0.0.1:20005:80"));
  assert!(!compose.contains("20005:80/"));
}

#[test]
fn caddyfile_access_logs_skip_wildcard() {
  let gw = serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
    .unwrap();
  let sites = [
    Site {
      hostname: "a.example.com".into(),
      upstream: "127.0.0.1:21000".into(),
      ..Default::default()
    },
    Site {
      hostname: "*.example.com".into(),
      wildcard: true,
      ..Default::default()
    },
  ];
  let out = caddyfile("edge", &gw, &sites, &[], false, None);
  assert_eq!(out.matches("(wharf_access) {").count(), 1);
  assert!(out.contains("output file /data/access.log {"));
  assert!(out.contains("a.example.com {\n\timport wharf_access\n"));
  assert!(out.contains("*.example.com {\n\tabort\n}"));
  assert_eq!(out.matches("import wharf_access").count(), 1);
}

#[test]
fn caddyfile_wildcard_site() {
  let mut gw: GatewaySpec =
    serde_json::from_str(r#"{"kind":"caddy","server":"s1"}"#)
      .unwrap();
  let mut site = Site {
    hostname: "*.example.com".into(),
    wildcard: true,
    dns: Some("example.com".into()),
    ..Default::default()
  };
  let empty = caddyfile("edge", &gw, &[], &[], false, None);
  let auto = caddyfile(
    "edge",
    &gw,
    std::slice::from_ref(&site),
    &[],
    false,
    None,
  );
  for text in [
    "*.example.com {",
    "dns acmedns {",
    "username edge",
    "password [[WHARF_ACME_DNS_KEY]]",
    "subdomain example.com",
    "server_url [[WHARF_ACME_DNS_URL]]",
    "\tabort\n}",
  ] {
    assert!(auto.contains(text), "{text}");
  }
  assert!(auto.ends_with("\tabort\n}\n"));
  gw.tls = GatewayTls::Internal;
  site.dns = None;
  let internal = caddyfile("edge", &gw, &[site], &[], false, None);
  assert!(!internal.contains("acmedns"));
  let global =
    |s: &str| s.split("\n(wharf_errors)").next().unwrap().to_string();
  assert_eq!(global(&auto), global(&empty));
  assert_eq!(
    global(&internal),
    global(&caddyfile("edge", &gw, &[], &[], false, None))
  );
  for out in [&empty, &auto, &internal] {
    assert!(!out.contains("prefer_wildcard"));
  }
}

#[test]
fn gateway_uses_fixed_default_image() {
  let spec = serde_json::from_value(serde_json::json!({
    "server": "s1", "kind": "caddy"
  }))
  .unwrap();
  assert!(
    gateway_compose("edge", &spec).contains(DEFAULT_CADDY_IMAGE)
  );
  assert!(!DEFAULT_CADDY_IMAGE.contains("latest"));
  assert!(!DEFAULT_CADDY_IMAGE.contains("sha-"));
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
    &["100.1.2.3".to_string(), "192.168.1.5".to_string()],
    Some(&secrets),
  )
  .unwrap();
  let yaml: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).unwrap();
  let svc = &yaml["services"]["whoami"];
  assert_eq!(svc["ports"][0], "127.0.0.1:20000:80");
  assert_eq!(svc["ports"][1], "100.1.2.3:20000:80");
  assert_eq!(svc["ports"][2], "192.168.1.5:20000:80");
  assert_eq!(svc["environment"]["A"], "x$$y");
  assert_eq!(svc["environment"]["TOKEN"], "s3$$cret");
  assert_eq!(svc["volumes"][0], "/srv/whoami/data:/data");
  assert!(!out.contains("0.0.0.0"));
  // 不带密钥渲染时保留占位符，用于展示。
  let template =
    service_compose("whoami", &spec(), &ports, &[], None).unwrap();
  assert!(template.contains("[[WHO_TOKEN]]"));
  assert!(!template.contains("s3"));
}

#[test]
fn trial_compose_does_not_publish_ports() {
  let mut spec = spec();
  spec.volumes.clear();
  let out = trial_compose("s1", &spec, None).unwrap();
  let yaml: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).unwrap();
  let service = &yaml["services"]["s1"];
  assert_eq!(yaml["name"], "wharf-try-s1");
  assert_eq!(service["restart"], "no");
  assert_eq!(service["environment"]["A"], "x$$y");
  assert_eq!(service["labels"]["wharf.trial"], "s1");
  assert!(service.get("ports").is_none());
  assert!(!out.contains("wharf.service"));
}

#[test]
fn service_limits_are_optional() {
  let mut spec = spec();
  let out = service_compose("s1", &spec, &BTreeMap::new(), &[], None)
    .unwrap();
  assert!(!out.contains("mem_limit"));
  assert!(!out.contains("cpus"));
  spec.limits = Some(wharf_api_types::spec::Limits {
    memory_mb: Some(512),
    cpu_milli: Some(500),
  });
  let out = service_compose("s1", &spec, &BTreeMap::new(), &[], None)
    .unwrap();
  let yaml: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(&out).unwrap();
  let svc = &yaml["services"]["s1"];
  assert_eq!(svc["mem_limit"], "512m");
  assert_eq!(svc["cpus"], "0.5");
  assert_eq!(cpus_text(1000), "1");
  assert_eq!(cpus_text(1250), "1.25");
}

fn compose_spec(
  content: &str,
  memory: Option<u32>,
  cpu: Option<u32>,
  env: &[(&str, &str)],
  container: Option<&str>,
) -> ServiceSpec {
  let mut spec: ServiceSpec =
    serde_json::from_value(serde_json::json!({
      "server": "s1",
      "source": { "compose": { "content": content } },
    }))
    .unwrap();
  if memory.is_some() || cpu.is_some() {
    spec.limits = Some(Limits {
      memory_mb: memory,
      cpu_milli: cpu,
    });
  }
  spec.env = env
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
  spec.container = container.map(str::to_string);
  spec
}

#[test]
fn compose_limits_keep_original_text() {
  let source = "# 原样保留\nservices: # 服务\n  # 注释\n  web: # 容器\n    image: nginx\n    environment:\n      KEY: [[SECRET]]\n    ports:\n      - \"127.0.0.1:8080:80\"\n";
  let expected = "# 原样保留\nservices: # 服务\n  # 注释\n  web: # 容器\n    mem_limit: 512m\n    cpus: \"0.5\"\n    image: nginx\n    environment:\n      KEY: [[SECRET]]\n    ports:\n      - \"127.0.0.1:8080:80\"\n";
  let with = |cpu| {
    compose_with_settings(
      "s1",
      source,
      &compose_spec(source, Some(512), cpu, &[], None),
    )
    .unwrap()
  };
  assert_eq!(with(Some(500)), expected);
  assert_eq!(with(None), expected.replace("    cpus: \"0.5\"\n", ""));
}

#[test]
fn compose_env_goes_to_chosen_container() {
  let source = "services:\n  db:\n    image: mysql\n    environment:\n      - A=1\n  app:\n    image: halo # 主容器\n    environment:\n      KEY: [[SECRET]]\n  side:\n    image: x\n";
  // 多个容器：没选容器时报错，提示可选的容器。
  let error = compose_with_settings(
    "s1",
    source,
    &compose_spec(source, None, None, &[("B", "2")], None),
  )
  .unwrap_err();
  assert!(error.message.contains("3 个容器"));
  // mapping 写法的 environment 里追加，`$` 转义。
  let out = compose_with_settings(
    "s1",
    source,
    &compose_spec(
      source,
      Some(256),
      None,
      &[("B", "a$b")],
      Some("app"),
    ),
  )
  .unwrap();
  assert_eq!(
    out,
    "services:\n  db:\n    image: mysql\n    environment:\n      - A=1\n  app:\n    mem_limit: 256m\n    image: halo # 主容器\n    environment:\n      B: \"a$$b\"\n      KEY: [[SECRET]]\n  side:\n    image: x\n"
  );
  // 列表写法。
  let out = compose_with_settings(
    "s1",
    source,
    &compose_spec(source, None, None, &[("B", "2")], Some("db")),
  )
  .unwrap();
  assert!(
    out.contains("    environment:\n      - \"B=2\"\n      - A=1\n")
  );
  // 没有 environment 的容器新加一段。
  let out = compose_with_settings(
    "s1",
    source,
    &compose_spec(source, None, None, &[("B", "2")], Some("side")),
  )
  .unwrap();
  assert!(out.ends_with(
    "  side:\n    environment:\n      B: \"2\"\n    image: x\n"
  ));
  // 和 compose 里重复的变量。
  let error = compose_with_settings(
    "s1",
    source,
    &compose_spec(source, None, None, &[("A", "2")], Some("db")),
  )
  .unwrap_err();
  assert!(error.message.contains("已经写了"));
  let error = compose_with_settings(
    "s1",
    source,
    &compose_spec(source, None, None, &[("B", "2")], Some("nope")),
  )
  .unwrap_err();
  assert!(error.message.contains("没有容器 nope"));
}

#[test]
fn compose_limits_reject_unsupported_forms() {
  let check = |source: &str| {
    compose_with_settings(
      "s1",
      source,
      &compose_spec(source, Some(512), None, &[], None),
    )
    .unwrap_err()
    .message
  };
  assert!(check("services:\n  web:\n    image: nginx\n  worker:\n    image: nginx\n").contains("2 个容器"));
  assert!(
    check(
      "services:\n  web:\n    image: nginx\n    mem_limit: 64m\n"
    )
    .contains("已经写了 mem_limit")
  );
  assert!(
    check("services: {web: {image: nginx}}")
      .contains("写法没法自动加上")
  );
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
fn renders_account_password() {
  let spec = serde_json::from_value(serde_json::json!({
    "server": "s1", "source": {"image": "example/app"},
    "env": {"APP_PASSWORD": "[[account.x.password]]"}
  }))
  .unwrap();
  let credentials = BTreeMap::from([(
    "account.x.password".into(),
    "fixture-value".into(),
  )]);
  let render = |values| {
    service_compose("app", &spec, &BTreeMap::new(), &[], values)
      .unwrap()
  };
  assert!(
    render(Some(&credentials))
      .contains("APP_PASSWORD: fixture-value")
  );
  assert!(render(None).contains("[[account.x.password]]"));
}

#[test]
fn compose_checks() {
  assert!(
    check_compose("x", "services:\n  web:\n    image: nginx\n")
      .is_ok()
  );
  assert!(check_compose("x", "services: {}\n").is_err());
  assert!(
    check_compose("x", "services:\n  web:\n    build: .\n").is_err()
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
    error_page: None,
    wildcard: vec![],
    layer4: vec![],
    trusted_proxies: None,
    read_header_timeout: None,
    idle_timeout: None,
    grace_period: None,
  };
  let out = caddyfile(
    "edge",
    &gw,
    &[
      Site {
        hostname: "z.example.com".into(),
        upstream: "127.0.0.1:1".into(),
        auth: BasicAuth::parse("admin $2b$12$abc"),
        paths: vec![],
        redirect: None,
        ..Default::default()
      },
      Site {
        hostname: "a.example.com".into(),
        upstream: "100.1.1.1:2".into(),
        auth: None,
        paths: vec![("/ws".into(), "127.0.0.1:17891".into())],
        redirect: None,
        ..Default::default()
      },
    ],
    &[],
    true,
    None,
  );
  assert!(out.contains(
      "link.wharf.internal {\n\ttls internal\n\treverse_proxy /~!frp 127.0.0.1:7000\n}"
    ));
  // 只有开了 auth 的站点带 basic_auth。
  let z = &out[out.find("z.example.com").unwrap()..];
  assert!(z.contains("basic_auth {\n\t\tadmin $2b$12$abc\n\t}"));
  assert_eq!(out.matches("basic_auth").count(), 1);
  assert!(out.contains(
      "a.example.com {\n\timport wharf_access\n\timport wharf_errors\n\treverse_proxy /ws 127.0.0.1:17891 {\n\t\timport wharf_upstream\n\t}\n\treverse_proxy 100.1.1.1:2 {\n\t\timport wharf_upstream\n\t}\n}"
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
      auth: None,
      paths: vec![],
      redirect: None,
      ..Default::default()
    }],
    &[],
    false,
    None,
  );
  assert!(out.contains("auto_https off"));
  assert!(out.contains("\nhttp://a.example.com {"));
}

include!("tests/caddy_cases.rs");
