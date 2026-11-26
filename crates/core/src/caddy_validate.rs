//! 校验插入 Caddyfile 的配置值，以及自定义片段的修改权限。

use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Action, Layer, Plan},
  spec::{GatewaySpec, RouteSpec},
};

pub(crate) fn normalized_caddy(raw: Option<&str>) -> Option<&str> {
  raw.filter(|s| !s.trim().is_empty())
}

pub(crate) fn route_caddy_changed(
  before: Option<&RouteSpec>,
  after: Option<&RouteSpec>,
) -> bool {
  normalized_caddy(before.and_then(|r| r.caddy.as_deref()))
    != normalized_caddy(after.and_then(|r| r.caddy.as_deref()))
}

fn caddy_field(spec: Option<&Value>) -> Option<&str> {
  normalized_caddy(spec?.get("caddy")?.as_str())
}

pub(crate) fn require_route_caddy(
  plan: &Plan,
  admin: bool,
) -> Result<(), ApiError> {
  if !admin
    && plan.items.iter().any(|item| {
      item.layer == Layer::Config
        && item.address.starts_with("route/")
        && item.action != Action::Delete
        && caddy_field(item.before.as_ref())
          != caddy_field(item.after.as_ref())
    })
  {
    return Err(ApiError::new(
      ErrorCode::Forbidden,
      "新增或修改路由的自定义 Caddy 配置需要 admin 权限",
    ));
  }
  Ok(())
}

fn has_control_chars(text: &str) -> bool {
  text.bytes().enumerate().any(|(i, b)| match b {
    b'\n' | b'\t' => false,
    b'\r' => text.as_bytes().get(i + 1) != Some(&b'\n'),
    _ => b.is_ascii_control(),
  })
}

fn has_env_placeholder(text: &str) -> bool {
  text.contains("{$")
    || text
      .as_bytes()
      .windows(5)
      .any(|s| s.eq_ignore_ascii_case(b"{env."))
}

pub(crate) fn check_custom_caddy(
  text: &str,
) -> Result<(), &'static str> {
  if text.len() > 8000 {
    return Err("太长，最多 8000 个字符");
  }
  if has_control_chars(text) {
    return Err("里不能使用控制字符或孤立的回车");
  }
  if has_env_placeholder(text) {
    return Err("里不能使用 {$ 或 {env. 环境变量占位符");
  }

  let mut rest = text;
  let mut depth = 0;
  loop {
    rest = rest.trim_start_matches(char::is_whitespace);
    let Some(first) = rest.chars().next() else {
      break;
    };
    if first == '#' {
      let end = rest.find('\n').unwrap_or(rest.len());
      // Caddy 在忽略注释前处理反斜杠，可能延续逻辑行。
      if rest[..end].contains('\\') {
        return Err("的注释里不能使用反斜杠");
      }
      rest = &rest[end..];
      continue;
    }
    if matches!(first, '"' | '`') {
      rest = after_quoted_token(rest, first)?;
      if !rest.is_empty()
        && !rest.starts_with([' ', '\t', '\n', '\r'])
      {
        return Err("的引号参数后需要空白");
      }
      continue;
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let (token, tail) = rest.split_at(end);
    rest = tail;
    // 渲染前会去掉行尾空白；独立的反斜杠还会跨过空白影响下一个 token。
    if token == "\\"
      || (token.ends_with('\\')
        && rest
          .split('\n')
          .next()
          .is_some_and(|s| s.trim().is_empty()))
    {
      return Err("里不能使用反斜杠续行");
    }
    if token.starts_with("<<") {
      return Err("里不能使用 heredoc");
    }
    if token.contains(['"', '`', '#']) {
      return Err("的参数含引号或 #，请用双引号包裹");
    }
    match token {
      "{" => depth += 1,
      "}" if depth == 0 => {
        return Err("里的 } 多了，不能跳出这个域名的站点块");
      }
      "}" => depth -= 1,
      _ if !balanced_token(token) => {
        return Err("里的参数括号没有配对");
      }
      _ => {}
    }
  }
  if depth != 0 {
    return Err("里的括号没有配对");
  }
  Ok(())
}

fn after_quoted_token(
  text: &str,
  quote: char,
) -> Result<&str, &'static str> {
  let mut chars = text.char_indices().skip(1);
  while let Some((i, c)) = chars.next() {
    if c == quote {
      return Ok(&text[i + 1..]);
    }
    if quote == '"' && c == '\\' {
      chars.next();
    }
  }
  Err("里的引号或转义未闭合")
}

fn balanced_token(token: &str) -> bool {
  let mut depth = 0;
  for b in token.bytes() {
    match b {
      b'{' => depth += 1,
      b'}' if depth == 0 => return false,
      b'}' => depth -= 1,
      _ => {}
    }
  }
  depth == 0
}

fn ascii_with(text: &str, extra: &[u8]) -> bool {
  text
    .bytes()
    .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

fn valid_port(port: &str) -> bool {
  (1..=5).contains(&port.len())
    && !port.starts_with('0')
    && port.bytes().all(|b| b.is_ascii_digit())
    && port.parse::<u16>().is_ok()
}

fn valid_host(host: &str) -> bool {
  if let Some(ip) =
    host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
  {
    return ip.parse::<Ipv6Addr>().is_ok();
  }
  host.parse::<Ipv4Addr>().is_ok()
    || (host.len() <= 253
      && host.bytes().any(|b| b.is_ascii_alphabetic() || b == b'-')
      && host.split('.').all(|label| {
        (1..=63).contains(&label.len())
          && !label.starts_with('-')
          && !label.ends_with('-')
          && ascii_with(label, b"-")
      }))
}

pub(crate) fn valid_upstream(up: &str) -> bool {
  up.len() <= 265
    && up.rsplit_once(':').is_some_and(|(host, port)| {
      valid_host(host) && valid_port(port)
    })
}

fn unambiguous_path(path: &str) -> bool {
  !path.contains("//")
    && !path.split('/').any(|p| matches!(p, "." | ".."))
}

pub(crate) fn validate_route_path(
  path: &str,
) -> Result<(), &'static str> {
  if path.len() > 200
    || !path.starts_with('/')
    || !ascii_with(path, b"/_-.*")
  {
    return Err(
      "要以 / 开头，最多 200 字节，只能用字母、数字和 / _ - . *",
    );
  }
  if !unambiguous_path(path) {
    return Err("不能包含 //、. 或 .. 路径段");
  }
  let base = path.strip_suffix("/*").unwrap_or(path);
  if base.contains('*') {
    return Err("通配符只能放在末尾的 /*");
  }
  let norm = base.trim_end_matches('/');
  if norm.is_empty()
    || norm
      .split('/')
      .nth(1)
      .is_some_and(|segment| segment.eq_ignore_ascii_case("_wharf"))
  {
    return Err("不能覆盖根路径或 /_wharf");
  }
  Ok(())
}

fn http_target(target: &str) -> Option<(&str, &str)> {
  if target.len() > 2048 {
    return None;
  }
  let rest = target
    .strip_prefix("https://")
    .or_else(|| target.strip_prefix("http://"))?;
  let (authority, path) =
    rest.split_at(rest.find('/').unwrap_or(rest.len()));
  let (host, port) = if authority.starts_with('[') {
    let (host, suffix) = authority.split_at(authority.find(']')? + 1);
    (
      host,
      if suffix.is_empty() {
        None
      } else {
        Some(suffix.strip_prefix(':')?)
      },
    )
  } else {
    authority
      .split_once(':')
      .map_or((authority, None), |(host, port)| (host, Some(port)))
  };
  (valid_host(host)
    && port.is_none_or(valid_port)
    && unambiguous_path(path))
  .then_some((host, path))
}

pub(crate) fn redirect_host(target: &str) -> Option<&str> {
  let (host, path) = http_target(target)?;
  (!path.ends_with('/') && ascii_with(path, b"/._~-")).then_some(host)
}

pub(crate) fn valid_public_url(url: &str) -> bool {
  http_target(url).is_some_and(|(_, path)| ascii_with(path, b"/._-"))
}

pub(crate) fn validate_public_url(
  url: Option<&str>,
) -> anyhow::Result<()> {
  anyhow::ensure!(
    url.is_none_or(valid_public_url),
    "--public-url / WHARF_PUBLIC_URL 不合法，须为 http(s)://主机[:端口][/路径]"
  );
  Ok(())
}

pub(crate) fn validate_route_hostname(
  host: &str,
  hostname: &str,
) -> Result<(), ApiError> {
  if crate::world::normalize_hostname(host)? != host
    || hostname != host
  {
    return Err(ApiError::invalid(format!(
      "路由 {host} 的域名未规范化或与资源名不一致"
    )));
  }
  Ok(())
}

pub(crate) fn validate_gateway(
  name: &str,
  spec: &GatewaySpec,
) -> Result<(), ApiError> {
  wharf_api_types::validate_name("网关", name)?;
  if let Some(email) = &spec.email {
    validate_email(email).map_err(|msg| {
      ApiError::invalid(format!("网关 {name} 的邮箱{msg}"))
    })?;
  }
  Ok(())
}

pub(crate) fn validate_email(
  email: &str,
) -> Result<(), &'static str> {
  let invalid = "格式不合法，例如 ops@example.com";
  let (local, domain) = email.split_once('@').ok_or(invalid)?;
  if !(3..=254).contains(&email.len())
    || !(1..=64).contains(&local.len())
    || local.starts_with('.')
    || local.ends_with('.')
    || local.contains("..")
    || !ascii_with(local, b"._+-")
    || !ascii_with(domain, b".-")
    || domain.ends_with('.')
    || crate::world::normalize_hostname(domain).is_err()
  {
    return Err(invalid);
  }
  Ok(())
}

pub(crate) fn check_error_page(
  name: &str,
  page: &str,
) -> Result<(), ApiError> {
  if page.len() > 64 * 1024 {
    return Err(
      ApiError::invalid(format!("网关 {name} 的错误页超过 64 KB"))
        .with_hint("图片用外链，或压缩后再放"),
    );
  }
  if page.contains(crate::render::ERROR_PAGE_END) {
    return Err(ApiError::invalid(format!(
      "网关 {name} 的错误页里不能出现 {}",
      crate::render::ERROR_PAGE_END
    )));
  }
  if has_env_placeholder(page) {
    return Err(
      ApiError::invalid(format!(
        "网关 {name} 的错误页里不能使用环境变量占位符"
      ))
      .with_hint("改写 {$名字} 或 {env.名字}"),
    );
  }
  if has_control_chars(page) {
    return Err(ApiError::invalid(format!(
      "网关 {name} 的错误页里不能使用控制字符或孤立的回车"
    )));
  }
  Ok(())
}

pub(crate) fn valid_basic_auth_user(user: &str) -> bool {
  (1..=64).contains(&user.len()) && ascii_with(user, b"._-")
}

pub(crate) fn valid_basic_auth(user: &str, hash: &str) -> bool {
  valid_basic_auth_user(user)
    && hash.len() <= 128
    && hash.starts_with("$2")
    && ascii_with(hash, b"./$")
}

pub(crate) fn valid_acme_dns_key(key: &str) -> bool {
  (1..=128).contains(&key.len()) && ascii_with(key, b"_-")
}

pub(crate) fn validate_acme_dns_fill(
  key: &str,
  url: &str,
) -> Result<(), ApiError> {
  if !valid_acme_dns_key(key) || !valid_public_url(url) {
    return Err(ApiError::internal(
      "不能生成 DNS 验证配置，密钥或控制面地址格式不合法",
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests;
