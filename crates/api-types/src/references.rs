//! 意图文本里的服务、密钥和应用账号引用。

use crate::ApiError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretMode {
  Plain,
  Url,
  B64,
  Json,
  File,
}

pub struct Placeholder<'a> {
  pub mode: SecretMode,
  pub name: &'a str,
}

fn bare_secret(name: &str) -> bool {
  !name.is_empty()
    && name
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub fn parse_placeholder(
  inner: &str,
  allow_account: bool,
) -> Result<Option<Placeholder<'_>>, ApiError> {
  if inner.starts_with('@') {
    return Ok(None);
  }
  let valid = |name| {
    bare_secret(name)
      || (allow_account && account_ref(name).is_some())
  };
  let (mode, name) = match inner.split_once(':') {
    None if valid(inner) => (SecretMode::Plain, inner),
    None => return Ok(None),
    Some((prefix, name)) => {
      let mode = match prefix {
        "url" => SecretMode::Url,
        "b64" => SecretMode::B64,
        "json" => SecretMode::Json,
        "FILE" => SecretMode::File,
        _ if bare_secret(prefix) && valid(name) => {
          return Err(ApiError::invalid(format!("不支持的密钥修饰符：{prefix}"))
            .with_hint("可用修饰符：[[SECRET]]、[[url:SECRET]]、[[b64:SECRET]]、[[json:SECRET]]、[[FILE:SECRET]]"));
        }
        _ => return Ok(None),
      };
      if !valid(name) {
        return Err(ApiError::invalid(format!("密钥引用 [[{inner}]] 格式不对"))
          .with_hint("写成 [[url:密钥名]]、[[b64:密钥名]]、[[json:密钥名]] 或 [[FILE:密钥名]]，密钥名只能用字母、数字、_ 和 -"));
      }
      (mode, name)
    }
  };
  Ok(Some(Placeholder { mode, name }))
}

pub fn account_ref(name: &str) -> Option<&str> {
  let (account, field) =
    name.strip_prefix("account.")?.split_once('.')?;
  (matches!(field, "username" | "password")
    && crate::validate_name("应用账号", account).is_ok())
  .then_some(account)
}

pub fn next_placeholder(text: &str) -> Option<(usize, &str)> {
  let start = text.find("[[")?;
  let end = start + 2 + text[start + 2..].find("]]")?;
  let inner_start = start + 1;
  let start = text[inner_start..end]
    .rfind("[[")
    .map_or(start, |inner| inner_start + inner);
  Some((start, &text[start + 2..end]))
}

pub fn placeholders(mut text: &str) -> impl Iterator<Item = &str> {
  std::iter::from_fn(move || {
    let (start, inner) = next_placeholder(text)?;
    text = &text[start + inner.len() + 4..];
    Some(inner)
  })
}

/// 一处引用。
#[derive(Debug, PartialEq)]
pub struct Ref<'a> {
  pub service: &'a str,
  pub port: Option<&'a str>,
  pub part: Part,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Part {
  Both,
  Host,
  Port,
}

pub fn parse_service_ref(inner: &str) -> Option<Ref<'_>> {
  let body = inner.strip_prefix('@')?;
  let (body, part) = match body.rsplit_once(':') {
    Some((b, "host")) => (b, Part::Host),
    Some((b, "port")) => (b, Part::Port),
    Some(_) => return None,
    None => (body, Part::Both),
  };
  let (service, port) = match body.split_once('.') {
    Some((s, p)) => (s, Some(p)),
    None => (body, None),
  };
  let ok = |s: &str| {
    !s.is_empty()
      && s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
  };
  (ok(service) && port.is_none_or(ok)).then_some(Ref {
    service,
    port,
    part,
  })
}
