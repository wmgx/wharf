//! 环境变量和配置文本里的明文密钥识别规则。

use crate::references::{
  parse_placeholder, parse_service_ref, placeholders,
};

pub fn has_wharf_ref(value: &str) -> bool {
  has_compose_var(value)
    || placeholders(value).any(|p| {
      parse_service_ref(p).is_some()
        || parse_placeholder(p, true).is_ok_and(|p| p.is_some())
    })
}

pub fn detect_secret_value(value: &str) -> Option<&'static str> {
  let value = value.trim();
  if let Some((_, rest)) = value.split_once("://")
    && let Some((auth, _)) = rest
      .split(['/', '?', '#'])
      .next()
      .and_then(|s| s.rsplit_once('@'))
    && auth.split_once(':').is_some_and(|(_, pass)| {
      !pass.is_empty() && !has_wharf_ref(pass)
    })
  {
    return Some("URL 内嵌密码");
  }
  known_format(value)
}

pub fn is_placeholder_value(trimmed: &str) -> bool {
  let trimmed = trimmed.trim();
  let lower = trimmed.to_ascii_lowercase();
  trimmed.starts_with('/')
    || trimmed.bytes().all(|c| c.is_ascii_digit())
    || matches!(
      lower.as_str(),
      "true"
        | "false"
        | "yes"
        | "no"
        | "on"
        | "off"
        | "changeme"
        | "example"
        | "placeholder"
        | "xxx"
        | "none"
        | "null"
        | "test"
        | "disabled"
    )
    || lower.starts_with("your_")
}

pub fn has_compose_var(value: &str) -> bool {
  let mut bytes = value.bytes().peekable();
  while let Some(b) = bytes.next() {
    if b != b'$' {
      continue;
    }
    match bytes.next_if(|b| *b == b'$') {
      Some(_) => continue,
      None
        if bytes
          .peek()
          .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') =>
      {
        return true;
      }
      None if bytes.next_if_eq(&b'{').is_some() => {
        return bytes
          .next()
          .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
          && bytes.any(|b| b == b'}');
      }
      None => {}
    }
  }
  false
}

pub fn is_sensitive_env_key(key: &str) -> bool {
  let key = key.to_ascii_uppercase().replace('-', "_");
  if key == "PUBLIC_KEY"
    || key.ends_with("_PUBLIC_KEY")
    || key.rsplit_once('_').is_some_and(|(_, suffix)| {
      matches!(
        suffix,
        "FILE"
          | "PATH"
          | "DIR"
          | "ENABLED"
          | "ENABLE"
          | "MODE"
          | "TYPE"
          | "HEADER"
          | "NAME"
          | "USER"
          | "USERNAME"
          | "EMAIL"
          | "HOST"
          | "PORT"
          | "URL"
          | "TTL"
          | "TIMEOUT"
          | "EXPIRY"
          | "EXPIRES"
          | "LENGTH"
          | "ALGO"
          | "ALGORITHM"
          | "METHOD"
      )
    })
  {
    return false;
  }
  let mut previous = "";
  for word in key.split('_') {
    if matches!(
      word,
      "PASSWORD"
        | "PASSWD"
        | "PASS"
        | "SECRET"
        | "TOKEN"
        | "APIKEY"
        | "CREDENTIAL"
        | "CREDENTIALS"
    ) || (word == "KEY"
      && matches!(
        previous,
        "API"
          | "ACCESS"
          | "PRIVATE"
          | "AUTH"
          | "SIGNING"
          | "ENCRYPTION"
      ))
    {
      return true;
    }
    previous = word;
  }
  false
}

pub fn private_key_header(value: &str) -> bool {
  value
    .strip_prefix("-----BEGIN ")
    .is_some_and(|rest| rest.contains("PRIVATE KEY-----"))
}

pub fn known_format(value: &str) -> Option<&'static str> {
  if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
    .into_iter()
    .any(|p| value.starts_with(p))
  {
    Some("GitHub 令牌格式")
  } else if value.starts_with("sk-ant-")
    || (value.starts_with("sk-") && value.len() >= 20)
  {
    Some("API 密钥格式")
  } else if value.starts_with("sk_live_")
    || value.starts_with("rk_live_")
  {
    Some("Stripe 密钥格式")
  } else if value.starts_with("xoxb-") || value.starts_with("xoxp-") {
    Some("Slack 令牌格式")
  } else if value.strip_prefix("AKIA").is_some_and(|id| {
    id.len() == 16
      && id
        .bytes()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
  }) {
    Some("AWS 访问密钥 ID 格式")
  } else if private_key_header(value) {
    Some("PEM 私钥格式")
  } else if value.starts_with("eyJ")
    && value.len() >= 40
    && value.split('.').count() == 3
    && value.split('.').all(|part| {
      !part.is_empty()
        && part.bytes().all(|c| {
          c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')
        })
    })
  {
    Some("JWT 格式")
  } else {
    None
  }
}
