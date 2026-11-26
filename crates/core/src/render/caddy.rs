use super::*;

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
pub(super) fn caddyfile(
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
  // 反向隧道：frpc 按 IP 连进来，握手带固定名字，用 Caddy 自己签的证书。
  if link {
    let tls = match spec.tls {
      GatewayTls::Auto => "\ttls internal\n",
      _ => "",
    };
    out.push_str(&format!(
      "\n{scheme}{} {{\n{tls}\treverse_proxy {} 127.0.0.1:{}\n}}\n",
      crate::link::LINK_HOST,
      crate::link::FRP_PATH,
      crate::link::FRPS_PORT
    ));
  }
  out
}
