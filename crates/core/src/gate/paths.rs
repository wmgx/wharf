use crate::world::World;
use wharf_api_types::spec::{SsoMode, SsoSpec};

pub(crate) fn site_endpoints(sso: &SsoSpec) -> bool {
  !sso.public || sso.mode == SsoMode::Login
}

fn local_path(raw: &str) -> Option<&str> {
  if !raw.starts_with('/')
    || raw.contains('\\')
    || raw.chars().any(char::is_control)
  {
    return None;
  }
  raw.split(['?', '#']).next()
}

pub(crate) fn takeover_path(raw: &str) -> Option<String> {
  let path = urlencoding::decode(local_path(raw)?).ok()?;
  if path.contains("//")
    || path.contains('\\')
    || path.chars().any(char::is_control)
    || path.split('/').any(|part| matches!(part, "." | ".."))
    || path == "/_wharf"
    || path.starts_with("/_wharf/")
  {
    return None;
  }
  Some(path.into_owned())
}

pub(super) fn login_rd(rd: &str) -> &str {
  if takeover_path(rd).is_some() { rd } else { "/" }
}

pub(super) fn site_gate_rd(rd: &str) -> &str {
  if !rd.contains('#') && local_path(rd) == Some("/_wharf/login") {
    rd
  } else {
    login_rd(rd)
  }
}

pub(crate) fn normalize_skip_path(
  raw: &str,
) -> Result<&str, &'static str> {
  let path = raw.trim_end_matches('/');
  if raw.len() > 100
    || !raw.starts_with('/')
    || !raw
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    || raw.contains("//")
    || raw.split('/').any(|part| matches!(part, "." | ".."))
    || path.is_empty()
    || path == "/_wharf"
    || path.starts_with("/_wharf/")
  {
    return Err("路径无效");
  }
  Ok(path)
}

pub(super) fn rd_url(
  world: &World,
  rd: &str,
) -> Option<reqwest::Url> {
  let url = reqwest::Url::parse(rd).ok()?;
  if url.scheme() != "https"
    || !url.username().is_empty()
    || url.password().is_some()
    || url.port().is_some()
  {
    return None;
  }
  world
    .routes
    .get(url.host_str()?)
    .filter(|r| r.spec.sso.as_ref().is_some_and(site_endpoints))?;
  Some(url)
}
