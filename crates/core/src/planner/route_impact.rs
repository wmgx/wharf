use super::{Action, Impact};
use wharf_api_types::spec::{RouteSpec, SsoSpec};

fn gated(sso: Option<&SsoSpec>) -> Option<&SsoSpec> {
  sso.filter(|s| s.gated())
}

fn added_skip_paths<'a>(
  before: &[String],
  after: &'a [String],
) -> Vec<&'a str> {
  after
    .iter()
    .map(|path| path.trim_end_matches('/'))
    .filter(|path| {
      !before
        .iter()
        .map(|prefix| prefix.trim_end_matches('/'))
        .any(|prefix| {
          *path == prefix
            || path
              .strip_prefix(prefix)
              .is_some_and(|rest| rest.starts_with('/'))
        })
    })
    .collect()
}

pub(super) fn route_impact(
  before: Option<&RouteSpec>,
  after: Option<&RouteSpec>,
  action: Action,
) -> (Vec<Impact>, String) {
  if action == Action::Delete {
    return (
      vec![Impact::Downtime],
      "删除路由，域名将无法访问".into(),
    );
  }
  let Some(route) = after else {
    return (vec![], "修改配置".into());
  };
  let gate = gated(route.sso.as_ref());
  let auth = route.auth || gate.is_some();
  let public = !auth && !route.internal && route.redirect.is_none();

  if action == Action::Create {
    if route.redirect.is_some() {
      return (vec![], "新增跳转".into());
    }
    if gate.is_some_and(|s| !s.skip_paths.is_empty()) {
      return (vec![Impact::Public], "免登录路径对公网开放".into());
    }
    if let Some(ms) = route.expires_at {
      let time = chrono::DateTime::from_timestamp_millis(ms)
        .unwrap()
        .with_timezone(
          &chrono::FixedOffset::east_opt(8 * 3600).unwrap(),
        );
      let reason = format!(
        "新增临时分享，{} 到期失效",
        time.format("%m-%d %H:%M")
      );
      return if public {
        (vec![Impact::Public], format!("{reason}，未开启登录保护"))
      } else {
        (vec![], reason)
      };
    }
    if route.internal {
      return (vec![], "新增内网域名".into());
    }
    if auth {
      return (vec![], "新增路由".into());
    }
    return (
      vec![Impact::Public],
      "新增公网路由，未开启 auth".into(),
    );
  }

  if let Some(before) = before {
    let old_gate = gated(before.sso.as_ref());
    if let Some(old_gate) = old_gate {
      if !auth {
        return (
          vec![Impact::Public],
          "去掉门禁后这个域名对公网开放".into(),
        );
      }
      if gate.is_some_and(|new_gate| {
        !added_skip_paths(&old_gate.skip_paths, &new_gate.skip_paths)
          .is_empty()
      }) {
        return (vec![Impact::Public], "免登录路径对公网开放".into());
      }
    }
    if before.internal
      && !route.internal
      && !route.auth
      && route.redirect.is_none()
    {
      return (
        vec![Impact::Public],
        "内网域名改成公网域名，未开启 auth".into(),
      );
    }
    if let Some(old_expiry) = before.expires_at {
      match route.expires_at {
        Some(expiry) if public && expiry > old_expiry => {
          return (
            vec![Impact::Public],
            "续期临时分享，未开启登录保护".into(),
          );
        }
        None if !auth && !route.internal => {
          return (
            vec![Impact::Public],
            "临时分享改成长期公网路由，未开启 auth".into(),
          );
        }
        _ => {}
      }
    }
  }
  (vec![], "修改配置".into())
}

#[cfg(test)]
mod tests {
  use super::super::{Builder, World, config_items};
  use crate::world::RouteRow;
  use serde_json::json;

  fn assert_confirm(current: &World, desired: &World, confirm: bool) {
    let mut builder = Builder::default();
    config_items(
      &mut builder,
      current,
      desired,
      &desired.writes_from(current),
    );
    assert_eq!(builder.items.len(), 1);
    assert_eq!(builder.items[0].needs_confirm(), confirm);
  }

  #[test]
  fn only_unprotected_temporary_shares_require_confirm() {
    let host = "share.example.test";
    let current = World::default();
    for (protection, confirm) in [
      (json!({}), true),
      (json!({"auth":true}), false),
      (json!({"sso":{"mode":"gate"}}), false),
      (json!({"internal":true}), false),
    ] {
      let mut spec = json!({"hostname":host,"service":"app","expires_at":1700000000000_i64});
      spec
        .as_object_mut()
        .unwrap()
        .extend(protection.as_object().unwrap().clone());
      let mut desired = current.clone();
      desired.routes.insert(
        host.into(),
        RouteRow {
          id: "share".into(),
          spec: serde_json::from_value(spec).unwrap(),
          version: 1,
        },
      );
      assert_confirm(&current, &desired, confirm);

      let mut renewed = desired.clone();
      renewed.routes.get_mut(host).unwrap().spec.expires_at =
        Some(1700000001000);
      assert_confirm(&desired, &renewed, confirm);
    }
  }

  #[test]
  fn broadening_skip_paths_requires_confirm() {
    let host = "app.example.test";
    let mut current = World::default();
    current.routes.insert(host.into(), RouteRow {
      id: "app".into(),
      spec: serde_json::from_value(json!({"hostname":host,"service":"app","sso":{"mode":"gate","skip_paths":["/api/health/"]}})).unwrap(),
      version: 1,
    });
    assert_confirm(&World::default(), &current, true);
    for (paths, confirm) in [
      (vec!["/api"], true),
      (vec!["/api/health/status"], false),
      (vec![], false),
    ] {
      let mut desired = current.clone();
      desired
        .routes
        .get_mut(host)
        .unwrap()
        .spec
        .sso
        .as_mut()
        .unwrap()
        .skip_paths = paths.into_iter().map(str::to_owned).collect();
      assert_confirm(&current, &desired, confirm);
    }
  }
}
