//! 统一脱敏模块：任务口令、命令行参数/URL 凭据、导入预览高敏环境变量。

use serde_yaml_ng::Value;
use wharf_api_types::view::{TaskKind, TaskSpec};

const REDACTED_SECRET_PLACEHOLDER: &str = "[[请替换为密钥名]]";

const SENSITIVE_FLAG_WORDS: &[&str] = &[
  "token",
  "password",
  "passwd",
  "pass",
  "secret",
  "api-key",
  "apikey",
  "auth",
  "auth-token",
  "access-key",
  "private-key",
  "dsn",
  "webhook",
  "cookie",
  "client-secret",
];

const SENSITIVE_ENV_KEYWORDS: &[&str] = &[
  "TOKEN",
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "PRIVATE_KEY",
  "API_KEY",
  "APIKEY",
  "CREDENTIAL",
  "AUTH",
  "COOKIE",
  "DSN",
  "WEBHOOK",
];

const CMD_ENV_KEYWORDS: &[&str] = &[
  "TOKEN",
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "KEY",
  "AUTH",
  "COOKIE",
  "CREDENTIAL",
  "DSN",
  "WEBHOOK",
];

pub fn mask_url_token(prefix: &str, token: &str) -> String {
  let head: String = token.chars().take(4).collect();
  format!("{prefix}{head}…")
}

pub fn redact_task_spec(spec: &TaskSpec) -> TaskSpec {
  let mut out = spec.clone();
  match &mut out.how {
    TaskKind::Ping { token, .. } => token.clear(),
    TaskKind::Script { hook: Some(t), .. } => t.clear(),
    _ => {}
  }
  out
}

pub fn task_urls(
  spec: &TaskSpec,
  base: Option<&str>,
  reveal: bool,
) -> (Option<String>, Option<String>) {
  let b = base.map(|u| u.trim_end_matches('/'));
  let ping = match (&spec.how, reveal, b) {
    (TaskKind::Ping { token, .. }, true, Some(b))
      if !token.is_empty() =>
    {
      Some(format!("{b}/ping/{token}"))
    }
    (TaskKind::Ping { token, .. }, false, _) if !token.is_empty() => {
      Some(mask_url_token("/ping/", token))
    }
    _ => None,
  };
  let hook = match (&spec.how, reveal, b) {
    (TaskKind::Script { hook: Some(t), .. }, true, Some(b))
      if !t.is_empty() =>
    {
      Some(format!("{b}/hook/{t}"))
    }
    (TaskKind::Script { hook: Some(t), .. }, false, _)
      if !t.is_empty() =>
    {
      Some(mask_url_token("/hook/", t))
    }
    _ => None,
  };
  (ping, hook)
}

pub fn redact_command(cmd: &str) -> String {
  let step1 = redact_url_credentials(cmd);
  let step2 = redact_auth_headers(&step1);
  redact_cmd_tokens(&step2)
}

pub fn is_sensitive_env_key(key: &str) -> bool {
  let upper = key.trim().to_ascii_uppercase();
  if upper.is_empty()
    || matches!(
      upper.as_str(),
      "PUBLIC_KEY"
        | "KEY_PATH"
        | "LANG"
        | "PATH"
        | "TZ"
        | "AUTH_TYPE"
        | "AUTH_METHOD"
        | "AUTH_MODE"
    )
    || upper.ends_with("_PUBLIC_KEY")
    || upper.ends_with("_KEY_PATH")
  {
    return false;
  }
  SENSITIVE_ENV_KEYWORDS.iter().any(|kw| upper.contains(kw))
    || upper.ends_with("_KEY")
    || upper.ends_with("_PASS")
}

pub fn redact_compose_secrets(yaml: &str) -> (String, Vec<String>) {
  let Ok(mut doc) = serde_yaml_ng::from_str::<Value>(yaml) else {
    return (yaml.to_string(), vec![]);
  };
  let Some(services) =
    doc.get_mut("services").and_then(Value::as_mapping_mut)
  else {
    return (yaml.to_string(), vec![]);
  };
  let mut redacted = Vec::new();
  for svc in services.values_mut() {
    let Some(env) = svc.get_mut("environment") else {
      continue;
    };
    match env {
      Value::Mapping(map) => {
        for (k, v) in map.iter_mut() {
          let Some(key) = k.as_str() else { continue };
          if v.is_null() {
            continue;
          }
          let val_str = v.as_str();
          if val_str.is_some_and(is_placeholder) {
            continue;
          }
          let has_creds = val_str.is_some_and(has_url_credentials);
          if is_sensitive_env_key(key) || has_creds {
            *v = Value::String(REDACTED_SECRET_PLACEHOLDER.into());
            push_unique(&mut redacted, key);
          }
        }
      }
      Value::Sequence(seq) => {
        for item in seq.iter_mut() {
          let Some(raw) = item.as_str() else { continue };
          let Some((key, val)) = raw.split_once('=') else {
            continue;
          };
          if val.trim().is_empty() || is_placeholder(val) {
            continue;
          }
          if is_sensitive_env_key(key) || has_url_credentials(val) {
            let replaced =
              format!("{key}={REDACTED_SECRET_PLACEHOLDER}");
            push_unique(&mut redacted, key);
            *item = Value::String(replaced);
          }
        }
      }
      _ => {}
    }
  }
  if redacted.is_empty() {
    return (yaml.to_string(), vec![]);
  }
  let rendered = serde_yaml_ng::to_string(&doc)
    .unwrap_or_else(|_| yaml.to_string());
  (rendered, redacted)
}

fn push_unique(list: &mut Vec<String>, key: &str) {
  if !list.iter().any(|k| k == key) {
    list.push(key.to_string());
  }
}

fn is_placeholder(val: &str) -> bool {
  let t = val.trim();
  t.starts_with("[[") && t.ends_with("]]") && t.len() > 4
}

fn has_url_credentials(s: &str) -> bool {
  redact_url_credentials(s) != s
}

fn is_scheme_char(b: u8) -> bool {
  b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

fn redact_url_credentials(input: &str) -> String {
  let bytes = input.as_bytes();
  let mut out = String::with_capacity(input.len());
  let mut i = 0;
  while i < input.len() {
    let Some(rel) = input[i..].find("://") else {
      out.push_str(&input[i..]);
      break;
    };
    let scheme_end = i + rel;
    let mut scheme_start = scheme_end;
    while scheme_start > i && is_scheme_char(bytes[scheme_start - 1])
    {
      scheme_start -= 1;
    }
    if scheme_start == scheme_end {
      out.push_str(&input[i..scheme_end + 3]);
      i = scheme_end + 3;
      continue;
    }
    let auth_start = scheme_end + 3;
    let mut auth_end = auth_start;
    while auth_end < input.len() {
      let b = bytes[auth_end];
      if b.is_ascii_whitespace()
        || matches!(
          b,
          b'/' | b'?' | b'#' | b'\'' | b'"' | b')' | b'>'
        )
      {
        break;
      }
      auth_end += 1;
    }
    let authority = &input[auth_start..auth_end];
    if let Some(at_pos) = authority.rfind('@') {
      let userinfo = &authority[..at_pos];
      if userinfo.contains(':') {
        out.push_str(&input[i..auth_start]);
        out.push_str("***:***");
        out.push_str(&authority[at_pos..]);
        i = auth_end;
        continue;
      }
    }
    out.push_str(&input[i..auth_end]);
    i = auth_end;
  }
  out
}

fn redact_auth_headers(input: &str) -> String {
  let lower = input.to_ascii_lowercase();
  let mut out = String::with_capacity(input.len());
  let mut i = 0;
  let needle = "authorization:";
  while i < input.len() {
    let Some(rel) = lower[i..].find(needle) else {
      out.push_str(&input[i..]);
      break;
    };
    let start = i + rel;
    let after_colon = start + needle.len();
    out.push_str(&input[i..after_colon]);
    let mut pos = after_colon;
    let bytes = input.as_bytes();
    while pos < input.len() && matches!(bytes[pos], b' ' | b'\t') {
      out.push(bytes[pos] as char);
      pos += 1;
    }
    let rest_lower = &lower[pos..];
    let scheme_len =
      ["bearer", "basic", "token"].iter().find_map(|scheme| {
        let len = scheme.len();
        (rest_lower.starts_with(scheme)
          && bytes
            .get(pos + len)
            .is_some_and(|b| matches!(b, b' ' | b'\t')))
        .then_some(len)
      });
    if let Some(slen) = scheme_len {
      out.push_str(&input[pos..pos + slen]);
      pos += slen;
      while pos < input.len() && matches!(bytes[pos], b' ' | b'\t') {
        out.push(bytes[pos] as char);
        pos += 1;
      }
    }
    let val_start = pos;
    while pos < input.len() {
      let b = bytes[pos];
      if b.is_ascii_whitespace()
        || matches!(b, b'\'' | b'"' | b',' | b';')
      {
        break;
      }
      pos += 1;
    }
    if pos > val_start {
      out.push_str("***");
    }
    i = pos;
  }
  out
}

fn redact_cmd_tokens(input: &str) -> String {
  let mut out = String::with_capacity(input.len());
  let bytes = input.as_bytes();
  let mut i = 0;
  let mut cmd_name: Option<String> = None;
  let mut redact_next = false;

  while i < input.len() {
    if bytes[i].is_ascii_whitespace() {
      let start = i;
      while i < input.len() && bytes[i].is_ascii_whitespace() {
        if bytes[i] == b'\n' {
          cmd_name = None;
          redact_next = false;
        }
        i += 1;
      }
      out.push_str(&input[start..i]);
      continue;
    }
    let start = i;
    let mut quote: Option<u8> = None;
    while i < input.len() {
      let b = bytes[i];
      match quote {
        Some(q) => {
          if b == b'\\' && q == b'"' && i + 1 < input.len() {
            i += 2;
            continue;
          }
          if b == q {
            quote = None;
          }
          i += 1;
        }
        None => {
          if b.is_ascii_whitespace() {
            break;
          }
          if matches!(b, b'\'' | b'"') {
            quote = Some(b);
          }
          i += 1;
        }
      }
    }
    let tok = &input[start..i];
    if matches!(tok, "|" | "||" | "&&" | ";" | "&") {
      cmd_name = None;
      redact_next = false;
      out.push_str(tok);
      continue;
    }
    if redact_next {
      redact_next = false;
      if !tok.starts_with('-') {
        out.push_str(&mask_token_preserving_quotes(tok));
        continue;
      }
    }
    if cmd_name.is_none()
      && !tok.starts_with('-')
      && !is_env_assignment(tok)
    {
      let base = tok
        .trim_matches(['\'', '"'])
        .rsplit('/')
        .next()
        .unwrap_or(tok);
      cmd_name = Some(base.to_ascii_lowercase());
      out.push_str(tok);
      continue;
    }
    if let Some(replaced) =
      redact_flag_token(tok, cmd_name.as_deref(), &mut redact_next)
    {
      out.push_str(&replaced);
      continue;
    }
    if let Some(replaced) = redact_env_token(tok) {
      out.push_str(&replaced);
      continue;
    }
    out.push_str(tok);
  }
  out
}

fn mask_token_preserving_quotes(tok: &str) -> String {
  if tok.len() >= 2
    && ((tok.starts_with('\'') && tok.ends_with('\''))
      || (tok.starts_with('"') && tok.ends_with('"')))
  {
    let q = tok.as_bytes()[0] as char;
    format!("{q}***{q}")
  } else {
    "***".into()
  }
}

fn is_sensitive_flag(name: &str, cmd_name: Option<&str>) -> bool {
  if name == "p" {
    return matches!(cmd_name, Some("mysql" | "redis-cli" | "pass"));
  }
  let normalized = name.replace('_', "-");
  if normalized == "bypass" || normalized.ends_with("-bypass") {
    return false;
  }
  SENSITIVE_FLAG_WORDS
    .iter()
    .any(|w| normalized == *w || normalized.ends_with(w))
}

fn redact_flag_token(
  tok: &str,
  cmd_name: Option<&str>,
  redact_next: &mut bool,
) -> Option<String> {
  if !tok.starts_with('-') || tok == "-" || tok == "--" {
    return None;
  }
  if let Some((flag, _val)) = tok.split_once('=') {
    let name = flag.trim_start_matches('-').to_ascii_lowercase();
    if is_sensitive_flag(&name, cmd_name) {
      return Some(format!("{flag}=***"));
    }
    return None;
  }
  if tok.starts_with("-p")
    && !tok.starts_with("--")
    && tok.len() > 2
    && matches!(cmd_name, Some("mysql" | "redis-cli" | "pass"))
  {
    return Some("-p***".into());
  }
  let name = tok.trim_start_matches('-').to_ascii_lowercase();
  if is_sensitive_flag(&name, cmd_name) {
    *redact_next = true;
  }
  None
}

fn is_env_assignment(tok: &str) -> bool {
  let inner = strip_outer_quotes(tok).0;
  inner
    .split_once('=')
    .is_some_and(|(k, _)| is_env_key_shape(k))
}

fn is_env_key_shape(k: &str) -> bool {
  !k.is_empty()
    && k.bytes().any(|b| b.is_ascii_uppercase())
    && k.bytes().all(|b| {
      b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
    })
}

fn strip_outer_quotes(tok: &str) -> (&str, Option<char>) {
  if tok.len() >= 2
    && ((tok.starts_with('\'') && tok.ends_with('\''))
      || (tok.starts_with('"') && tok.ends_with('"')))
  {
    (&tok[1..tok.len() - 1], Some(tok.as_bytes()[0] as char))
  } else {
    (tok, None)
  }
}

fn redact_env_token(tok: &str) -> Option<String> {
  let (inner, quote) = strip_outer_quotes(tok);
  let (key, _val) = inner.split_once('=')?;
  if !is_env_key_shape(key) {
    return None;
  }
  let sensitive = CMD_ENV_KEYWORDS.iter().any(|kw| key.contains(kw));
  if !sensitive {
    return None;
  }
  Some(match quote {
    Some(q) => format!("{q}{key}=***{q}"),
    None => format!("{key}=***"),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::host_access::{self, HostTarget, tests::auth};
  use wharf_api_types::{
    ErrorCode,
    service_checks::HeartbeatSpec,
    spec::{ServiceSpec, Source},
    view::{Perm, ScriptRuntime},
  };

  #[test]
  fn import_preview_requires_admin_and_redacts_sensitive_env() {
    let err = host_access::require(
      &auth([Perm::Plan, Perm::Apply], false),
      HostTarget::ImportPreview {
        server: "s1",
        target: "app",
      },
    )
    .unwrap_err()
    .0;
    assert_eq!(err.code, ErrorCode::Forbidden);

    let yaml = r#"
services:
  app:
    image: nginx
    environment:
      DATABASE_PASSWORD: s3cr3t
      APP_PORT: "8080"
      REDIS_URL: redis://user:pw@host:6379
"#;
    let (redacted, keys) = redact_compose_secrets(yaml);
    assert!(!redacted.contains("s3cr3t"));
    assert!(!redacted.contains("user:pw"));
    assert!(redacted.contains("8080"));
    assert_eq!(keys, vec!["DATABASE_PASSWORD", "REDIS_URL"]);
  }

  #[test]
  fn read_only_redacts_task_tokens_and_rollback_heartbeat() {
    let script_spec = TaskSpec {
      server: "s1".into(),
      schedule: String::new(),
      how: TaskKind::Script {
        runtime: ScriptRuntime::Shell,
        code: "echo ok".into(),
        deps: String::new(),
        image: None,
        env: Default::default(),
        hook: Some("wh_secret_hook".into()),
      },
      timeout_secs: 60,
      enabled: true,
      notify: true,
    };
    let ping_spec = TaskSpec {
      server: "s1".into(),
      schedule: "0 * * * *".into(),
      how: TaskKind::Ping {
        token: "wh_secret_ping".into(),
        grace_mins: 60,
      },
      timeout_secs: 60,
      enabled: true,
      notify: true,
    };
    let r_script = redact_task_spec(&script_spec);
    assert!(matches!(
      r_script.how,
      TaskKind::Script { hook: Some(ref t), .. } if t.is_empty()
    ));
    let r_ping = redact_task_spec(&ping_spec);
    assert!(matches!(
      r_ping.how,
      TaskKind::Ping { ref token, .. } if token.is_empty()
    ));
    assert_eq!(
      mask_url_token("/hook/", "wh_secret_hook"),
      "/hook/wh_s…"
    );
    assert_eq!(
      mask_url_token("/ping/", "wh_secret_ping"),
      "/ping/wh_s…"
    );
    let read_only = auth([Perm::Read], false);
    assert_eq!(
      crate::tasks::need_perm(&read_only, &script_spec)
        .unwrap_err()
        .0
        .code,
      ErrorCode::Forbidden
    );
    assert_eq!(
      crate::tasks::need_perm(&read_only, &ping_spec)
        .unwrap_err()
        .0
        .code,
      ErrorCode::Forbidden
    );
    let svc = ServiceSpec {
      server: "s1".into(),
      source: Source::Image("nginx".into()),
      ports: vec![],
      env: Default::default(),
      volumes: vec![],
      backup: None,
      stopped: false,
      monitor: None,
      log_alerts: vec![],
      port_checks: Default::default(),
      heartbeat: Some(HeartbeatSpec {
        every_mins: 10,
        grace_mins: 5,
        token: "wh_secret_hb".into(),
      }),
      limits: None,
      auto_update: false,
      container: None,
      files: vec![],
    };
    let redacted_svc =
      crate::service_monitor::heartbeat::redact(&svc);
    assert_eq!(redacted_svc.heartbeat.as_ref().unwrap().token, "");
  }

  #[test]
  fn host_units_require_admin_and_redact_exec_start() {
    let err = host_access::require(
      &auth([Perm::Read, Perm::Apply], false),
      HostTarget::HostUnits { server: "s1" },
    )
    .unwrap_err()
    .0;
    assert_eq!(err.code, ErrorCode::Forbidden);

    let out = redact_command(
      "cloudflared tunnel run --token eyJhbGci --url https://u:p@a.com",
    );
    assert!(!out.contains("eyJhbGci"), "out={out}");
    assert!(!out.contains("u:p"), "out={out}");
    assert!(out.contains("--token ***"), "out={out}");
    assert!(out.contains("https://***:***@a.com"), "out={out}");
  }

  #[test]
  fn shell_log_redacts_commands_and_audit_records_sensitive_reads() {
    let out = redact_command(
      "curl -H 'Authorization: Bearer tok123' -e API_KEY=xyz https://example.com",
    );
    assert!(!out.contains("tok123"), "out={out}");
    assert!(!out.contains("xyz"), "out={out}");
    assert!(out.contains("Bearer ***"), "out={out}");
    assert!(out.contains("API_KEY=***"), "out={out}");

    use axum::http::Method;
    for path in [
      "/api/shell-log",
      "/api/oidc/clients/a.com/secret",
      "/api/servers/s1/dirs",
      "/api/edge/w/script",
      "/api/servers/s1/host-units",
    ] {
      assert!(
        crate::audit::should_record(&Method::GET, path),
        "expected audit::should_record(GET, {path}) == true"
      );
    }
  }
}
