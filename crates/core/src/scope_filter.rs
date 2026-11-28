use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  spec::Fleet,
  view::{
    AlertsView, DataView, DoctorReport, Issue, SecretView, Status,
  },
};

use crate::{token_scope::route_spec_in_scope, world::World};

fn route_in_scope(
  services: &BTreeSet<String>,
  world: &World,
  host: &str,
) -> bool {
  world
    .routes
    .get(host)
    .is_some_and(|row| route_spec_in_scope(services, &row.spec))
}

pub fn alert_in_scope(
  services: &BTreeSet<String>,
  world: &World,
  custom_rule_service: Option<&str>,
  rule_id: &str,
  subject: Option<&str>,
) -> bool {
  if let Some(service) = custom_rule_service {
    return services.contains(service);
  }
  subject.is_some_and(|subject| {
    if let Some(service) =
      crate::rules::service_overrides::service_of_subject(
        rule_id, subject,
      )
    {
      services.contains(service)
    } else {
      matches!(rule_id, "domain_down" | "cert_expiring")
        && route_in_scope(services, world, subject)
    }
  })
}

fn issue_in_scope(
  services: &BTreeSet<String>,
  world: &World,
  issue: &Issue,
) -> bool {
  issue.subject.as_ref().is_some_and(|subject| {
    match subject.kind.as_str() {
      "service" => services.contains(&subject.name),
      "route" => route_in_scope(services, world, &subject.name),
      _ => false,
    }
  })
}

pub fn filter_status(
  services: &BTreeSet<String>,
  world: &World,
  status: &mut Status,
) {
  status.servers.clear();
  status.gateways.clear();
  status.edge_apps.clear();
  status.edge_unmanaged.clear();
  status.bookmarks.clear();
  status.services.retain(|s| services.contains(&s.name));
  status
    .routes
    .retain(|r| route_spec_in_scope(services, &r.spec));
  status.issues.retain(|i| issue_in_scope(services, world, i));
  status.problems = crate::views::problems_text(&status.issues);
  if let Some(updates) = &mut status.updates {
    updates.services.retain(|name, _| services.contains(name));
    updates.pending = None;
  }
  if let Some(health) = &mut status.health {
    filter_doctor(services, world, health);
  }
}

pub fn filter_doctor(
  services: &BTreeSet<String>,
  world: &World,
  report: &mut DoctorReport,
) {
  report.servers.clear();
  report.vendors.clear();
  report.checks.retain(|c| services.contains(&c.subject));
  report
    .routes
    .retain(|r| route_in_scope(services, world, &r.hostname));
  report.config.retain(|c| {
    c.subject
      .strip_prefix("服务 ")
      .is_some_and(|name| services.contains(name))
      || c
        .subject
        .strip_prefix("路由 ")
        .is_some_and(|host| route_in_scope(services, world, host))
  });
}

pub fn filter_data(services: &BTreeSet<String>, data: &mut DataView) {
  data.services.retain(|s| services.contains(&s.name));
}

pub fn filter_export(services: &BTreeSet<String>, fleet: &mut Fleet) {
  fleet.bookmarks.clear();
  fleet.servers.clear();
  fleet.gateways.clear();
  fleet.edge_apps.clear();
  fleet.services.retain(|name, _| services.contains(name));
  fleet
    .routes
    .retain(|route| route_spec_in_scope(services, route));
}

pub fn filter_secrets(
  services: &BTreeSet<String>,
  list: &mut Vec<SecretView>,
) {
  list.retain_mut(|s| {
    s.other_refs.clear();
    s.used_by.retain(|name| services.contains(name));
    if let Some(allowed) = &mut s.allowed_services {
      allowed.retain(|name| services.contains(name));
    }
    !s.managed && s.system.is_none() && !s.used_by.is_empty()
  });
}

pub fn filter_alerts(
  services: &BTreeSet<String>,
  world: &World,
  alerts: &mut AlertsView,
  history_subjects: &[(String, Option<String>)],
) {
  alerts.rules.retain(|r| {
    crate::rules::service_overrides::is_service_rule(&r.id)
      || matches!(r.id.as_str(), "domain_down" | "cert_expiring")
  });
  alerts.notices.clear();
  alerts.builtin_suppressions.clear();
  alerts.suppressions.clear();
  let custom_map: BTreeMap<_, _> = alerts
    .custom_rules
    .iter()
    .map(|r| (r.name.clone(), r.service.clone()))
    .collect();
  alerts
    .custom_rules
    .retain(|rule| services.contains(&rule.service));
  alerts
    .service_overrides
    .retain(|rule| services.contains(&rule.service));
  alerts.firing.retain(|f| {
    let custom = custom_map.get(&f.rule).map(String::as_str);
    if custom.is_some_and(|service| service != f.subject) {
      return false;
    }
    alert_in_scope(services, world, custom, &f.rule, Some(&f.subject))
  });
  let mut subjects = history_subjects.iter();
  alerts.history.retain(|_| {
    subjects.next().is_some_and(|(rule, subject)| {
      if let Some(service) = custom_map.get(rule) {
        // 规则删掉后可以同名重建，必须确认历史记录里的服务。
        return subject.as_deref() == Some(service.as_str())
          && services.contains(service);
      }
      alert_in_scope(services, world, None, rule, subject.as_deref())
    })
  });
}

pub async fn test_route_sso(
  state: axum::extract::State<std::sync::Arc<crate::state::AppState>>,
  auth: crate::auth::Auth,
  host: axum::extract::Path<String>,
) -> crate::api::ApiResult<wharf_api_types::view::SsoTestResult> {
  auth.require(wharf_api_types::view::Perm::Admin)?;
  if auth.services.is_some() {
    let snap = crate::snapshot::load(&state.0.db).await?;
    crate::token_scope::require_route_by_host(
      &auth,
      &snap.world,
      &host.0,
    )?;
  }
  crate::sso_login::test(state, auth, host).await
}

#[cfg(test)]
pub(crate) mod tests;
