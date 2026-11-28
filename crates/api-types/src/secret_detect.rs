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

pub fn detect_secret_value(value: &str) -> Option<&'static str> {
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

pub fn url_credentials(
  text: &str,
) -> impl Iterator<Item = (usize, usize)> + '_ {
  text.match_indices("://").filter_map(|(index, _)| {
    let start = index + 3;
    let authority = text[start..]
      .split(|c: char| {
        c.is_whitespace()
          || matches!(c, '/' | '?' | '#' | '\'' | '"' | '<' | '>')
      })
      .next()?;
    let (userinfo, _) = authority.rsplit_once('@')?;
    userinfo
      .contains(':')
      .then_some((start, start + userinfo.len()))
  })
}

pub fn has_url_credentials(value: &str) -> bool {
  url_credentials(value).next().is_some()
}

pub fn has_wharf_ref(value: &str) -> bool {
  value.contains("[[") && value.contains("]]")
}

pub fn is_placeholder_value(value: &str) -> bool {
  let value = value.trim();
  value.is_empty()
    || value.contains("${")
    || has_wharf_ref(value)
    || value.starts_with('/')
    || value.to_ascii_lowercase().starts_with("your_")
    || matches!(
      value.to_ascii_lowercase().as_str(),
      "true"
        | "false"
        | "yes"
        | "no"
        | "on"
        | "off"
        | "changeme"
        | "placeholder"
        | "xxx"
        | "none"
        | "null"
        | "disabled"
    )
}

pub fn env_secret_reason(
  key: &str,
  value: &str,
) -> Option<&'static str> {
  if is_placeholder_value(value) {
    return None;
  }
  if has_url_credentials(value) {
    return Some("URL 内嵌密码");
  }
  detect_secret_value(value)
    .or_else(|| is_sensitive_env_key(key).then_some("敏感变量名"))
}
