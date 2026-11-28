use super::{
  ApiError, CliResult, PathRoute, PortSpec, parse_path_route,
  parse_port,
};
use wharf_api_types::spec::SsoSpec;

pub(crate) fn remove_named<T>(
  items: &mut Vec<T>,
  name: &str,
  label: &str,
  key: impl Fn(&T) -> &str,
) -> CliResult<()> {
  let index = items
    .iter()
    .position(|item| key(item) == name)
    .ok_or_else(|| {
      let names =
        items.iter().map(key).collect::<Vec<_>>().join("、");
      ApiError::invalid(format!("{label} {name} 不存在"))
        .with_hint(format!("现有{label}：{names}"))
    })?;
  items.remove(index);
  Ok(())
}

pub(super) fn apply_port_edits(
  ports: &mut Vec<PortSpec>,
  replace: &[String],
  add: &[String],
  rm: &[String],
  clear: bool,
) -> CliResult<()> {
  if clear {
    ports.clear();
  } else if !replace.is_empty() {
    *ports = replace
      .iter()
      .map(|p| parse_port(p))
      .collect::<CliResult<_>>()?;
  } else {
    for name in rm {
      remove_named(ports, name, "端口", |p| &p.name)?;
    }
    for arg in add {
      let port = parse_port(arg)?;
      if let Some(p) = ports.iter_mut().find(|p| p.name == port.name)
      {
        *p = port;
      } else {
        ports.push(port);
      }
    }
  }
  Ok(())
}

pub(super) fn apply_path_edits(
  paths: &mut Vec<PathRoute>,
  add: &[String],
  rm: &[String],
) -> CliResult<()> {
  for path in rm {
    remove_named(paths, path, "路径转发", |p| &p.path)?;
  }
  for arg in add {
    let route = parse_path_route(arg)?;
    if let Some(p) = paths.iter_mut().find(|p| p.path == route.path) {
      *p = route;
    } else {
      paths.push(route);
    }
  }
  Ok(())
}

pub(super) fn apply_sso_list_edits(
  sso: &mut SsoSpec,
  add_skip: &[String],
  rm_skip: &[String],
  add_redirect: &[String],
  rm_redirect: &[String],
) -> CliResult<()> {
  for path in rm_skip {
    remove_named(
      &mut sso.skip_paths,
      path,
      "排除路径",
      String::as_str,
    )?;
  }
  for path in add_skip {
    if !sso.skip_paths.contains(path) {
      sso.skip_paths.push(path.clone());
    }
  }
  if !add_redirect.is_empty() || !rm_redirect.is_empty() {
    let oidc = sso.oidc.as_mut().ok_or_else(|| {
      ApiError::invalid("只有 oidc 方式才能修改 --redirect")
    })?;
    for uri in rm_redirect {
      remove_named(
        &mut oidc.redirect_uris,
        uri,
        "回调地址",
        String::as_str,
      )?;
    }
    for uri in add_redirect {
      if !oidc.redirect_uris.contains(uri) {
        oidc.redirect_uris.push(uri.clone());
      }
    }
    if oidc.redirect_uris.is_empty() {
      return Err(
        ApiError::invalid("oidc 方式至少要保留一个回调地址").into(),
      );
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn port_edits_keep_other_ports() {
    let mut ports = vec![
      parse_port("http=80").unwrap(),
      parse_port("admin=8080").unwrap(),
    ];
    apply_port_edits(
      &mut ports,
      &[],
      &["metrics=9090".into()],
      &["admin".into()],
      false,
    )
    .unwrap();
    assert_eq!(
      ports.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
      ["http", "metrics"]
    );
    assert!(
      apply_port_edits(
        &mut ports,
        &[],
        &[],
        &["admin".into()],
        false
      )
      .is_err()
    );
  }

  #[test]
  fn path_and_sso_edits_keep_other_entries() {
    let mut paths = vec![
      parse_path_route("/api/*=svc1").unwrap(),
      parse_path_route("/ws=svc2").unwrap(),
    ];
    apply_path_edits(
      &mut paths,
      &["/metrics=svc3".into()],
      &["/ws".into()],
    )
    .unwrap();
    assert_eq!(
      paths.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
      ["/api/*", "/metrics"]
    );
    let mut sso: SsoSpec =
      serde_json::from_value(serde_json::json!({
        "mode": "gate", "skip_paths": ["/health"]
      }))
      .unwrap();
    apply_sso_list_edits(&mut sso, &["/ready".into()], &[], &[], &[])
      .unwrap();
    assert_eq!(sso.skip_paths, ["/health", "/ready"]);
  }
}
