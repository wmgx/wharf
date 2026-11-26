/// 试跑用的 compose：同一个镜像和环境变量，不发布端口、不自动重启。
/// 只用于 image、build 来源且没有数据卷的服务。
pub fn trial_compose(
  name: &str,
  spec: &ServiceSpec,
  secrets: Option<&BTreeMap<String, String>>,
) -> Result<String, ApiError> {
  let mut service = image_service(name, spec, secrets)?;
  service.restart = "no";
  service.labels =
    BTreeMap::from([("wharf.trial".into(), name.into())]);
  Ok(to_yaml(&ComposeFile {
    configs: BTreeMap::new(),
    name: format!("{TRIAL_PROJECT_PREFIX}{name}"),
    services: BTreeMap::from([(name.to_string(), service)]),
  }))
}

/// 配置文件内容里的 `[[密钥名]]` 只替换确实存在的密钥，别的原样保留
/// （TOML 的 `[[servers]]` 这类写法不能当成密钥引用）。`secrets` 为空时原样返回。
pub fn file_content(
  content: &str,
  secrets: Option<&BTreeMap<String, String>>,
) -> String {
  let Some(secrets) = secrets else {
    return content.to_string();
  };
  let mut out = String::with_capacity(content.len());
  let mut rest = content;
  while let Some((start, name)) = next_placeholder(rest) {
    let end = start + 4 + name.len();
    out.push_str(&rest[..start]);
    match secrets.get(name) {
      Some(value) => out.push_str(value),
      None => out.push_str(&rest[start..end]),
    }
    rest = &rest[end..];
  }
  out.push_str(rest);
  out
}

/// 把配置文件放进 compose：顶层 `configs` 用 `content` 写内容，容器的 `configs` 引用它。
/// compose 判断要不要重建容器时不看内容，所以名字里带内容的哈希，内容一变名字就变，容器跟着重建。
/// `files` 是（容器内路径，已替换好的内容）。没有配置文件时原样返回，不重新生成 YAML。
pub fn add_files(
  name: &str,
  spec: &ServiceSpec,
  compose: &str,
  files: &[(String, String)],
) -> Result<String, ApiError> {
  if files.is_empty() {
    return Ok(compose.to_string());
  }
  let target = match &spec.source {
    Source::Compose { .. } => {
      compose_target(name, compose, spec.container.as_deref())?
    }
    _ => name.to_string(),
  };
  let bad = || {
    ApiError::invalid(format!(
      "服务 {name} 的 compose 写法没法自动加上配置文件"
    ))
    .with_hint(
      "直接写在 compose 文件的 configs 里，然后去掉设置里的配置文件",
    )
  };
  let mut doc: serde_yaml_ng::Value =
    serde_yaml_ng::from_str(compose).map_err(|_| bad())?;
  let key = |s: &str| serde_yaml_ng::Value::String(s.to_string());
  let mut defs = serde_yaml_ng::Mapping::new();
  let mut refs = Vec::new();
  for (i, (path, content)) in files.iter().enumerate() {
    let content = content.replace('$', "$$");
    let id = format!("wharf-file-{i}-{}", &hash(&content)[..12]);
    let mut def = serde_yaml_ng::Mapping::new();
    def.insert(key("content"), key(&content));
    defs.insert(key(&id), serde_yaml_ng::Value::Mapping(def));
    let mut r = serde_yaml_ng::Mapping::new();
    r.insert(key("source"), key(&id));
    r.insert(key("target"), key(path));
    refs.push(serde_yaml_ng::Value::Mapping(r));
  }
  let root = doc.as_mapping_mut().ok_or_else(bad)?;
  match root.entry(key("configs")).or_insert_with(|| {
    serde_yaml_ng::Value::Mapping(Default::default())
  }) {
    serde_yaml_ng::Value::Mapping(m) => m.extend(defs),
    _ => return Err(bad()),
  }
  let svc = root
    .get_mut("services")
    .and_then(|s| s.get_mut(target.as_str()))
    .and_then(|s| s.as_mapping_mut())
    .ok_or_else(bad)?;
  match svc
    .entry(key("configs"))
    .or_insert_with(|| serde_yaml_ng::Value::Sequence(vec![]))
  {
    serde_yaml_ng::Value::Sequence(list) => list.extend(refs),
    _ => return Err(bad()),
  }
  let head = if compose.starts_with('#') {
    compose
      .lines()
      .next()
      .map(|l| format!("{l}\n"))
      .unwrap_or_default()
  } else {
    String::new()
  };
  Ok(format!(
    "{head}{}",
    serde_yaml_ng::to_string(&doc).map_err(|_| bad())?
  ))
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
pub fn tunnel_compose(
  name: &str,
  spec: &GatewaySpec,
  token: Option<&str>,
) -> String {
  let project = gateway_project(name);
  let file = ComposeFile {
    configs: BTreeMap::new(),
    name: project,
    services: BTreeMap::from([(
      "cloudflared".to_string(),
      ComposeService {
        configs: vec![],
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
    configs: BTreeMap::new(),
    name: project.clone(),
    services: BTreeMap::from([(
      "caddy".to_string(),
      ComposeService {
        configs: vec![],
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
    configs: BTreeMap::new(),
    name: BACKUP_PROJECT.to_string(),
    services: BTreeMap::from([(
      "rest-server".to_string(),
      ComposeService {
        configs: vec![],
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

/// 一条 Caddy 站点：hostname → 上游。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Site {
  pub gate: Option<Gate>,
  pub hostname: String,
  pub upstream: String,
  /// 登录保护的账号，没开是 `None`。
  pub auth: Option<BasicAuth>,
  /// 按路径转发：（路径，上游）。
  pub paths: Vec<(String, String)>,
  /// 跳转目标。有值时这个站点只做跳转，`upstream`、`auth`、`paths` 不用。
  pub redirect: Option<String>,
  /// 每分钟限速次数，没开是 `None`。
  pub rate_limit: Option<u32>,
  /// 拦截常见扫描。
  pub block_scanners: bool,
  /// 自定义 Caddy 配置，原样插进站点块。
  pub custom: Option<String>,
  /// 只放行内网来源。
  pub internal: bool,
  pub internal_ranges: Vec<String>,
  pub protection: crate::entry_protection::SiteProtection,
  /// 临时分享的到期时间（毫秒），过了就断开。
  pub expires_at: Option<i64>,
  /// 泛域名站点：只签证书，未匹配具体域名的请求直接断开。
  pub wildcard: bool,
  /// DNS 验证的 subdomain（zone 或域名本身）。
  pub dns: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
  /// 公开站点只处理代登录入口和配置了接管的路径。
  pub public: bool,
  pub site_endpoints: bool,
  pub app_login: bool,
  pub user_header: Option<String>,
  pub trusted: Vec<String>,
  pub login: String,
  pub core: String,
  pub skip_paths: Vec<String>,
  pub takeover: Option<(LoginTakeover, String)>,
}

/// 内置的错误页。
const DEFAULT_ERROR_PAGE: &str = include_str!("error_page.html");
/// 错误页在 Caddyfile 里的结束标记；内容里不能出现它。
pub const ERROR_PAGE_END: &str = "WHARF_ERROR_PAGE";

/// 错误页的 snippet：网关自己产生的 502、503、504 返回这张页面。没填或是空的用内置的默认页。
fn error_snippet(spec: &GatewaySpec) -> String {
  let page = spec
    .error_page
    .as_deref()
    .filter(|p| !p.trim().is_empty())
    .unwrap_or(DEFAULT_ERROR_PAGE);
  let mut out = format!(
    "\n(wharf_errors) {{\n\thandle_errors 502 503 504 {{\n\t\theader Content-Type \"text/html; charset=utf-8\"\n\t\trespond <<{ERROR_PAGE_END}\n"
  );
  for line in page.lines() {
    if !line.is_empty() {
      out.push_str("\t\t");
      out.push_str(line);
    }
    out.push('\n');
  }
  out.push_str(&format!(
    "\t\t{ERROR_PAGE_END} {{err.status_code}}\n\t}}\n}}\n"
  ));
  out
}

#[derive(Clone, Copy)]
pub struct AcmeDnsFill<'a> {
  pub key: &'a str,
  pub url: &'a str,
}

#[derive(Clone, Copy, Default)]
pub struct CaddyFill<'a> {
  pub acme_dns: Option<AcmeDnsFill<'a>>,
  pub gate_revocation_key: Option<&'a str>,
}

fn dns_tls(
  gateway: &str,
  subdomain: &str,
  fill: Option<AcmeDnsFill<'_>>,
) -> String {
  let url = fill.map(|f| {
    format!("{}/agent/acme-dns", f.url.trim_end_matches('/'))
  });
  let url = url.as_deref().unwrap_or(ACME_DNS_URL);
  let key = fill.map_or(ACME_DNS_KEY, |f| f.key);
  format!(
    "\ttls {{\n\t\tdns acmedns {{\n\t\t\tusername {gateway}\n\t\t\tpassword {key}\n\t\t\tsubdomain {subdomain}\n\t\t\tserver_url {url}\n\t\t}}\n\t}}\n"
  )
}

const ACCESS_LOG_SNIPPET: &str = r#"
(wharf_access) {
	log {
		output file /data/access.log {
			roll_size 5MiB
			roll_keep 3
			roll_keep_for 168h
			roll_uncompressed
		}
		format filter {
			request>headers delete
			resp_headers delete
			request>tls delete
			request>uri query {
				replace token REDACTED
				replace access_token REDACTED
				replace refresh_token REDACTED
				replace id_token REDACTED
				replace key REDACTED
				replace api_key REDACTED
				replace apikey REDACTED
				replace secret REDACTED
				replace password REDACTED
				replace passwd REDACTED
				replace pwd REDACTED
				replace auth REDACTED
				replace code REDACTED
				replace sign REDACTED
				replace signature REDACTED
				replace sig REDACTED
				replace session REDACTED
				replace ticket REDACTED
				replace jwt REDACTED
				replace rd REDACTED
				replace state REDACTED
			}
		}
	}
}
"#;

#[cfg(test)]
fn caddyfile(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
  forwards: &[(bool, u16, String)],
  link: bool,
  gate_public: Option<&str>,
) -> String {
  caddyfile_with_fill(
    name,
    spec,
    sites,
    forwards,
    link,
    gate_public,
    &[],
    CaddyFill::default(),
  )
}

#[allow(clippy::too_many_arguments)]
pub fn caddyfile_with_fill(
  name: &str,
  spec: &GatewaySpec,
  sites: &[Site],
  forwards: &[(bool, u16, String)],
  link: bool,
  gate_public: Option<&str>,
  trusted_proxies: &[String],
  fill: CaddyFill<'_>,
) -> String {
  let mut out = format!(
    "# 由 Wharf 生成，不要手改。网关：{name}\n# 手写的站点放到 conf/extra.d/*.caddy\n{{\n\tadmin {CADDY_ADMIN}\n\tmetrics {{\n\t\tper_host\n\t}}\n"
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
  crate::entry_protection::render_abort_order(&mut out, sites);
  if sites
    .iter()
    .any(|s| s.redirect.is_none() && s.block_scanners)
  {
    out.push_str("\torder respond before basic_auth\n");
  }
  if sites
    .iter()
    .any(|s| s.redirect.is_none() && s.rate_limit.is_some())
  {
    out.push_str("\torder rate_limit before basic_auth\n");
  }
  if sites.iter().any(|s| s.gate.is_some()) {
    out.push_str("\torder wharf_sso before basic_auth\n");
  }
  crate::entry_protection::render_servers(
    &mut out,
    spec,
    trusted_proxies,
  );
  if !forwards.is_empty() {
    out.push_str("\tlayer4 {\n");
    let mut forwards = forwards.to_vec();
    forwards.sort_by_key(|(udp, listen, _)| (*udp, *listen));
    for (udp, listen, upstream) in forwards {
      let protocol = if udp { "udp/" } else { "" };
      out.push_str(&format!("\t\t{protocol}:{listen} {{\n\t\t\troute {{\n\t\t\t\tproxy {protocol}{upstream}\n\t\t\t}}\n\t\t}}\n"));
    }
    out.push_str("\t}\n");
  }
  out.push_str("}\n");
  out.push_str(ACCESS_LOG_SNIPPET);
  out.push_str(&error_snippet(spec));
  out.push_str(&format!(
    "\n(wharf_upstream) {{\n\tlb_try_duration {UPSTREAM_TRY_DURATION}\n\tlb_try_interval {UPSTREAM_TRY_INTERVAL}\n}}\n"
  ));
  crate::source_trust::render_proxy_headers(
    &mut out,
    trusted_proxies,
  );
  if sites.iter().any(|s| s.block_scanners) {
    out.push_str(&format!(
      "\n(wharf_scanners) {{\n\t@wharf_scanner_path path {SCANNER_PATHS}\n\t@wharf_scanner_ua header_regexp User-Agent \"{SCANNER_UA}\"\n\trespond @wharf_scanner_path 404\n\trespond @wharf_scanner_ua 404\n}}\n"
    ));
  }
  out.push_str("\nimport /etc/caddy/extra.d/*.caddy\n");
  let scheme = match spec.tls {
    GatewayTls::Off => "http://",
    _ => "",
  };
  let mut sites = sites.to_vec();
  sites.sort_by(|a, b| a.hostname.cmp(&b.hostname));
  for site in sites {
    site.protection.render_http_redirect(
      &mut out,
      spec,
      &site.hostname,
    );
    out.push_str(&format!("\n{scheme}{} {{\n", site.hostname));
    site.protection.render_matchers(&mut out);
    if site.wildcard {
      if let Some(subdomain) = &site.dns {
        out.push_str(&dns_tls(name, subdomain, fill.acme_dns));
      }
      out.push_str("\tabort\n}\n");
      continue;
    }
    if !site.internal {
      out.push_str("\timport wharf_access\n");
    }
    if let Some(target) = &site.redirect {
      out.push_str(&format!(
        "\tredir {target}{{uri}} permanent\n}}\n"
      ));
      continue;
    }
    out.push_str("\timport wharf_errors\n");
    if !trusted_proxies.is_empty() {
      out.push_str("\timport wharf_strip_forwarded\n");
    }
    if let Some(ms) = site.expires_at {
      out.push_str(&format!(
        "\t@wharf_expired expression `int({{time.now.unix}}) >= {}`\n\tabort @wharf_expired\n",
        ms / 1000
      ));
    }
    if let Some(subdomain) = &site.dns {
      out.push_str(&dns_tls(name, subdomain, fill.acme_dns));
    }
    if site.internal {
      let ranges = if site.internal_ranges.is_empty() {
        "127.0.0.0/8 ::1/128".to_string()
      } else {
        site.internal_ranges.join(" ")
      };
      out.push_str(&format!("\t@wharf_outside not remote_ip {ranges}\n\tabort @wharf_outside\n"));
    }
    if site.block_scanners {
      out.push_str("\timport wharf_scanners\n");
    }
    if let Some(n) = site.rate_limit {
      let zone = site.hostname.replace('.', "_");
      let key = if trusted_proxies.is_empty() {
        "{remote_host}"
      } else {
        "{client_ip}"
      };
      out.push_str(&format!(
        "\trate_limit {{\n\t\tzone wharf_{zone} {{\n\t\t\tkey {key}\n\t\t\tevents {n}\n\t\t\twindow 1m\n\t\t}}\n\t}}\n"
      ));
    }
    if let Some(custom) = &site.custom {
      for line in custom.lines() {
        let line = line.trim_end();
        if !line.is_empty() {
          out.push('\t');
          out.push_str(line);
        }
        out.push('\n');
      }
    }
    if let Some(gate) = &site.gate {
      gate::render_gate(
        &mut out,
        gate,
        gate_public,
        fill.gate_revocation_key,
      );
    }
    if let Some(a) = &site.auth {
      out.push_str(&format!(
        "\tbasic_auth {{\n\t\t{} {}\n\t}}\n",
        a.user, a.hash
      ));
    }
    // 带路径的 reverse_proxy 由 Caddy 排在不带路径的前面。
    for (path, upstream) in &site.paths {
      out.push_str(&format!(
        "\treverse_proxy {path} {upstream} {{\n\t\timport wharf_upstream\n\t}}\n"
      ));
    }
    out.push_str(&format!(
      "\treverse_proxy {} {{\n\t\timport wharf_upstream\n\t}}\n}}\n",
      site.upstream
    ));
  }
  crate::entry_protection::render_http_fallback(&mut out, spec);
  // frpc 按 IP 连进来，用固定 SNI 校验集群 CA 签发的证书。
  if link {
    out.push_str(&format!(
      "\n{} {{\n\ttls /etc/caddy/link.crt /etc/caddy/link.key\n\treverse_proxy {} 127.0.0.1:{}\n}}\n",
      crate::link::LINK_HOST,
      crate::link::FRP_PATH,
      crate::link::FRPS_PORT
    ));
  }
  out
}
