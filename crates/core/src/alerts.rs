//! 每分钟采一次服务器在线、容器是否在重启，交给 [crate::rules] 按规则判断推送。

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use wharf_api_types::view::{Issue, IssueLevel, IssueSubject};

use crate::state::AppState;

const EVERY: Duration = Duration::from_secs(60);

/// 正在反复重启的服务，进"需要注意"。
pub fn issues(world: &crate::world::World) -> Vec<Issue> {
  crate::rules::firing_subjects("container_restarting")
    .into_iter()
    .filter(|(name, _)| {
      crate::rules::lifecycle::running_service(world, name)
    })
    .map(|(name, title)| {
      let (alert, ack) =
        crate::rules::issue_alert("container_restarting", &name);
      Issue {
        code: "container_restarting".into(),
        level: IssueLevel::Fault,
        subject: Some(IssueSubject {
          kind: "service".into(),
          name,
        }),
        title,
        hint: None,
        ack,
        alert,
      }
    })
    .collect()
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    // 刚启动时 agent 还在陆续连回来。
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
      if let Err(e) = round(&state).await {
        tracing::warn!("告警检查失败：{}", e.message);
      }
      tokio::time::sleep(EVERY).await;
    }
  });
}

async fn round(
  state: &AppState,
) -> Result<(), wharf_api_types::ApiError> {
  let snap = crate::snapshot::load(&state.db).await?;

  // 离线：只看完成加入的服务器。
  let servers: Vec<(String, bool)> = snap
    .world
    .servers
    .keys()
    .filter_map(|n| crate::views::server_view(state, &snap, n))
    .filter(|v| v.joined)
    .map(|v| (v.name, v.online))
    .collect();

  let keep = servers.iter().map(|(name, _)| name.clone()).collect();
  crate::rules::retain_subjects(state, "server_offline", &keep).await;

  let live = crate::views::cached_live(state, &snap.world).await;
  let restarting: Vec<(String, bool)> = snap
    .world
    .services
    .iter()
    .filter(|(_, row)| !row.spec.stopped)
    .filter_map(|(name, row)| {
      let projects = live.get(&row.spec.server)?.as_ref().ok()?;
      let seen = projects.get(name).is_some_and(|p| {
        p.containers.iter().any(|c| c.state == "restarting")
      });
      Some((name.clone(), seen))
    })
    .collect();

  let down_gateways: std::collections::BTreeSet<String> = snap
    .world
    .gateways
    .iter()
    .filter_map(|(name, row)| {
      let project = crate::world::gateway_project(name);
      match live.get(&row.spec.server) {
        Some(Ok(projects)) => {
          let running =
            projects.get(&project).is_some_and(|p| p.all_running());
          (!running).then(|| name.clone())
        }
        Some(Err(_)) | None => {
          (!state.hub.is_online(&row.spec.server))
            .then(|| name.clone())
        }
      }
    })
    .collect();
  crate::rules::sync_unavailable_gateways(state, down_gateways).await;
  observe_link_certificates(state, &snap).await;
  for (name, online) in &servers {
    crate::rules::observe(
      state,
      "server.online",
      name,
      f64::from(u8::from(*online)),
      "",
    )
    .await;
  }
  for (name, seen) in &restarting {
    crate::rules::observe(
      state,
      "container.restarting",
      name,
      f64::from(u8::from(*seen)),
      "",
    )
    .await;
  }
  crate::rules::lifecycle::reconcile_world(state, snap).await?;
  crate::rules::flush_unsuppressed(state, crate::db::now_ms()).await;
  Ok(())
}

pub(crate) async fn observe_link_certificates(
  state: &AppState,
  snap: &crate::snapshot::Snapshot,
) {
  let net = snap.net(&snap.world);
  let now = chrono::Utc::now();
  let mut active = BTreeSet::new();
  for (name, expires) in crate::link_cert::leaf_expiries(snap, &net) {
    active.insert(name.to_string());
    let days = (expires - now).num_seconds() as f64 / 86_400.0;
    crate::rules::observe(state, "link_cert.days", name, days, "")
      .await;
  }
  crate::rules::retain_subjects(state, "link_cert_expiring", &active)
    .await;
  if let Some(expires) = crate::link_cert::ca_expiry(snap) {
    let days = (expires - now).num_seconds() as f64 / 86_400.0;
    crate::rules::observe(state, "link_ca.days", "ca", days, "")
      .await;
  }
}
