//! Caddyfile 相关输入的严格校验与自定义片段权限门槛。

use std::{
  borrow::Cow,
  net::{Ipv4Addr, Ipv6Addr},
};

use serde_json::Value;
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::{Action, Layer, Plan},
  spec::RouteSpec,
};

#[cfg(test)]
#[path = "caddy_validate/tests.rs"]
mod tests;

/// 归一化自定义 Caddy 配置：`None` 与纯空白视为等价"无配置"。
pub(crate) fn normalized_caddy(raw: Option<&str>) -> Option<&str> {
  raw.filter(|s| !s.trim().is_empty())
}

/// 两条路由配置的自定义 Caddy 片段是否有实质变化。
pub(crate) fn route_caddy_changed(
  before: Option<&RouteSpec>,
  after: Option<&RouteSpec>,
) -> bool {
  normalized_caddy(before.and_then(|r| r.caddy.as_deref()))
    != normalized_caddy(after.and_then(|r| r.caddy.as_deref()))
}

/// 非 admin 执行计划时，禁止新增、修改或清空路由的自定义 Caddy 配置。
pub(crate) fn require_route_caddy(
  plan: &Plan,
  admin: bool,
) -> Result<(), ApiError> {
  if admin {
    return Ok(());
  }
  for item in &plan.items {
    if item.layer != Layer::Config
      || !item.address.starts_with("route/")
      || item.action == Action::Delete
    {
      continue;
    }
    let before = item
      .before
      .as_ref()
      .and_then(|v| v.get("caddy"))
      .and_then(Value::as_str);
    let after = item
      .after
      .as_ref()
      .and_then(|v| v.get("caddy"))
      .and_then(Value::as_str);
    if normalized_caddy(before) != normalized_caddy(after) {
      return Err(ApiError::new(
        ErrorCode::Forbidden,
        "新增或修改路由的自定义 Caddy 配置需要 admin 权限",
      ));
    }
  }
  Ok(())
}

/// 是否包含禁止的控制字符：仅允许 `\t`、`\n` 以及成对的 `\r\n`。
fn has_disallowed_control_chars(text: &str) -> bool {
  let bytes = text.as_bytes();
  for (i, &b) in bytes.iter().enumerate() {
    match b {
      b'\t' | b'\n' => {}
      b'\r' if bytes.get(i + 1) == Some(&b'\n') => {}
      0x00..=0x1f | 0x7f => return true,
      _ => {}
    }
  }
  false
}

/// 自定义 Caddy 配置的词法防逃逸检查：
/// 识别 `#` 行注释、双引号转义、反引号原始串，禁止 heredoc、行尾续行、
/// 裸 token 混入引号/`#`/不配平 `{}`、`{$`/`{env.` 环境变量占位符与控制字符，
/// 并确保块级 `{}` 始终配平且不跳出当前站点块。
pub(crate) fn check_custom_caddy(
  text: &str,
) -> Result<(), &'static str> {
  if text.len() > 8000 {
    return Err("太长，最多 8000 个字符");
  }
  if has_disallowed_control_chars(text) {
    return Err("里不能包含控制字符");
  }
  if text.contains("{$")
    || text.to_ascii_lowercase().contains("{env.")
  {
    return Err("里不能使用 {$ 或 {env. 环境变量占位符");
  }
  let normalized: Cow<'_, str> = if text.contains('\r') {
    Cow::Owned(text.replace("\r\n", "\n"))
  } else {
    Cow::Borrowed(text)
  };
  let is_ws = |c: char| matches!(c, ' ' | '\t' | '\n');
  let mut chars = normalized.chars().peekable();
  let mut depth = 0i32;

  loop {
    while chars.peek().copied().is_some_and(is_ws) {
      chars.next();
    }
    let Some(first) = chars.next() else {
      break;
    };
    match first {
      '#' => {
        for c in chars.by_ref() {
          if c == '\n' {
            break;
          }
        }
      }
      '"' => {
        let mut closed = false;
        while let Some(c) = chars.next() {
          match c {
            '\\' if chars.next().is_none() => {
              return Err("里的引号或转义没有闭合");
            }
            '"' => {
              closed = true;
              break;
            }
            _ => {}
          }
        }
        if !closed {
          return Err("里的引号没有闭合");
        }
        if chars.peek().copied().is_some_and(|c| !is_ws(c)) {
          return Err("里的引号后面必须有空白或换行");
        }
      }
      '`' => {
        let mut closed = false;
        for c in chars.by_ref() {
          if c == '`' {
            closed = true;
            break;
          }
        }
        if !closed {
          return Err("里的反引号没有闭合");
        }
        if chars.peek().copied().is_some_and(|c| !is_ws(c)) {
          return Err("里的反引号后面必须有空白或换行");
        }
      }
      _ => {
        let mut token = String::new();
        token.push(first);
        while let Some(&c) = chars.peek() {
          if is_ws(c) {
            break;
          }
          token.push(c);
          chars.next();
        }
        if token == "\\" && matches!(chars.peek(), None | Some('\n'))
        {
          return Err("里不能使用行尾反斜杠续行");
        }
        if token.starts_with("<<") {
          return Err("里不能使用 << 多行文本语法");
        }
        if token.contains(['"', '`', '#']) {
          return Err("里的参数包含引号或 # 时请用双引号包裹");
        }
        if token == "{" {
          depth += 1;
        } else if token == "}" {
          depth -= 1;
          if depth < 0 {
            return Err("里的 } 多了，不能跳出这个域名的站点块");
          }
        } else {
          let mut inner = 0i32;
          for c in token.chars() {
            match c {
              '{' => inner += 1,
              '}' => {
                inner -= 1;
                if inner < 0 {
                  return Err("里的花括号没有配对");
                }
              }
              _ => {}
            }
          }
          if inner != 0 {
            return Err("里的花括号没有配对");
          }
        }
      }
    }
  }
  if depth != 0 {
    return Err("里的括号没有配对");
  }
  Ok(())
}

/// 端口白名单：1..=65535，无前导零。
pub(crate) fn valid_port(port: &str) -> bool {
  (1..=5).contains(&port.len())
    && !port.starts_with('0')
    && port.bytes().all(|b| b.is_ascii_digit())
    && port.parse::<u16>().is_ok_and(|p| p >= 1)
}

/// 主机白名单：带方括号 IPv6、IPv4 或 RFC 主机名（拒绝全数字标签组合）。
pub(crate) fn valid_host(host: &str) -> bool {
  if let Some(inner) =
    host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
  {
    return inner.parse::<Ipv6Addr>().is_ok();
  }
  if host.parse::<Ipv4Addr>().is_ok() {
    return true;
  }
  if host.is_empty()
    || host.len() > 253
    || host.starts_with('.')
    || host.ends_with('.')
  {
    return false;
  }
  let mut all_numeric = true;
  for label in host.split('.') {
    if label.is_empty()
      || label.len() > 63
      || label.starts_with('-')
      || label.ends_with('-')
      || !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
      return false;
    }
    if !label.bytes().all(|b| b.is_ascii_digit()) {
      all_numeric = false;
    }
  }
  !all_numeric
}

/// 上游地址白名单：`IPv4:端口`、`[IPv6]:端口` 或 `RFC主机名:端口`。
pub(crate) fn valid_upstream(up: &str) -> bool {
  if up.is_empty()
    || up.len() > 265
    || !up.bytes().all(|b| b.is_ascii_graphic())
  {
    return false;
  }
  let Some((host, port)) = up.rsplit_once(':') else {
    return false;
  };
  valid_host(host) && valid_port(port)
}

/// 路由按路径转发的路径白名单。
pub(crate) fn validate_route_path(
  raw: &str,
) -> Result<(), &'static str> {
  if raw.is_empty() || raw.len() > 200 || !raw.starts_with('/') {
    return Err("要以 / 开头，长度在 1 到 200 个字符之间");
  }
  if !raw
    .bytes()
    .all(|b| b.is_ascii_alphanumeric() || b"/_-.*".contains(&b))
  {
    return Err("只能包含字母、数字和 / _ - . *");
  }
  if raw.contains("//") {
    return Err("不能包含连续的 //");
  }
  let without_wild = if raw.contains('*') {
    let Some(prefix) = raw.strip_suffix("/*") else {
      return Err("* 只能写成末尾的 /*");
    };
    if prefix.contains('*') {
      return Err("* 只能写成末尾的 /*");
    }
    prefix
  } else {
    raw
  };
  let norm = without_wild.trim_end_matches('/');
  if norm.is_empty() {
    return Err("不能是根路径 / 或 /*");
  }
  if norm.split('/').skip(1).any(|seg| seg == "." || seg == "..") {
    return Err("不能包含 . 或 ..");
  }
  if norm == "/_wharf" || norm.starts_with("/_wharf/") {
    return Err("不能使用保留路径 /_wharf");
  }
  Ok(())
}

fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
  if authority.starts_with('[') {
    let close = authority.find(']')?;
    let host = &authority[..=close];
    let after = &authority[close + 1..];
    if after.is_empty() {
      Some((host, None))
    } else {
      let port = after.strip_prefix(':')?;
      Some((host, Some(port)))
    }
  } else {
    match authority.split_once(':') {
      Some((host, port)) => Some((host, Some(port))),
      None => Some((authority, None)),
    }
  }
}

fn parse_http_url_host(
  target: &str,
  allow_tilde: bool,
) -> Option<&str> {
  if target.len() > 2048 {
    return None;
  }
  let rest = target
    .strip_prefix("https://")
    .or_else(|| target.strip_prefix("http://"))?;
  let (authority, path) =
    rest.split_at(rest.find('/').unwrap_or(rest.len()));
  let (host, port) = split_authority(authority)?;
  if !valid_host(host) || !port.is_none_or(valid_port) {
    return None;
  }
  let extra: &[u8] = if allow_tilde { b"/._~-" } else { b"/._-" };
  let path_ok = !path.ends_with('/')
    && !path.contains("//")
    && path
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    && !path.split('/').any(|seg| seg == "." || seg == "..");
  path_ok.then_some(host)
}

/// 跳转目标白名单：`http(s)://主机[:端口][/路径]`，返回主机部分。
pub(crate) fn redirect_host(target: &str) -> Option<&str> {
  parse_http_url_host(target, true)
}

/// 控制面公开地址白名单：允许 `http(s)://` + 合法主机 + 可选非零端口 + 可选安全路径。
pub(crate) fn valid_public_url(url: &str) -> bool {
  parse_http_url_host(url, false).is_some()
}

/// 网关 ACME 邮箱白名单。
pub(crate) fn validate_email(
  email: &str,
) -> Result<(), &'static str> {
  if !(3..=254).contains(&email.len())
    || !email.bytes().all(|b| b.is_ascii_graphic())
  {
    return Err("格式不对，不能包含空白或控制字符");
  }
  let Some((local, domain)) = email.split_once('@') else {
    return Err("格式不对，需要包含 @");
  };
  if domain.contains('@') {
    return Err("格式不对，只能包含一个 @");
  }
  let local_ok = (1..=64).contains(&local.len())
    && !local.starts_with('.')
    && !local.ends_with('.')
    && !local.contains("..")
    && local
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
  if !local_ok {
    return Err("用户名部分不合法");
  }
  let domain_ok = !domain.is_empty()
    && !domain.starts_with('.')
    && !domain.ends_with('.')
    && domain
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    && crate::world::normalize_hostname(domain).is_ok();
  if !domain_ok {
    return Err("域名部分不合法");
  }
  Ok(())
}

/// 自定义错误页能否安全放入 Caddyfile heredoc。
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
  if page.contains("{$")
    || page.to_ascii_lowercase().contains("{env.")
  {
    return Err(
      ApiError::invalid(format!(
        "网关 {name} 的错误页里不能出现 {{$ 或 {{env."
      ))
      .with_hint(
        "Caddy 会把 {$名字} 和 {env.名字} 换成环境变量；改写成别的写法",
      ),
    );
  }
  if has_disallowed_control_chars(page) {
    return Err(ApiError::invalid(format!(
      "网关 {name} 的错误页里不能包含控制字符"
    )));
  }
  Ok(())
}

/// Basic Auth 用户名白名单。
pub(crate) fn valid_basic_auth_user(user: &str) -> bool {
  (1..=64).contains(&user.len())
    && user
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Basic Auth 渲染白名单：用户名与 bcrypt 哈希均不含 Caddyfile 元字符。
pub(crate) fn valid_basic_auth(user: &str, hash: &str) -> bool {
  valid_basic_auth_user(user)
    && (1..=128).contains(&hash.len())
    && hash.starts_with("$2")
    && hash
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b"./$".contains(&b))
}

/// acme-dns 密钥渲染兜底白名单。
pub(crate) fn valid_acme_dns_key(key: &str) -> bool {
  (1..=128).contains(&key.len())
    && key
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
