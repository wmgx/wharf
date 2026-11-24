//! 每分钟采一次服务器在线、容器是否在重启，交给 [crate::rules] 按规则判断推送。

use std::{sync::Arc, time::Duration};

use wharf_api_types::view::{Issue, IssueLevel, IssueSubject};

use crate::state::AppState;

const EVERY: Duration = Duration::from_secs(60);

/// 正在反复重启的服务，进"需要注意"。
pub fn issues() -> Vec<Issue> {
  crate::rules::firing_subjects("container_restarting")
    .into_iter()
    .map(|(name, title)| Issue {
      alert: crate::rules::issue_target(
        "container_restarting",
        &name,
      ),
      ack: None,
      code: "container_restarting".into(),
      level: IssueLevel::Fault,
      subject: Some(IssueSubject {
        kind: "service".into(),
        name,
      }),
      title,
      hint: None,
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

  let live = crate::views::cached_live(state, &snap.world).await;
  let restarting: Vec<(String, bool)> = snap
    .world
    .services
    .iter()
    .filter_map(|(name, row)| {
      let projects = live.get(&row.spec.server)?.as_ref().ok()?;
      let seen = projects.get(name).is_some_and(|p| {
        p.containers.iter().any(|c| c.state == "restarting")
      });
      Some((name.clone(), seen))
    })
    .collect();

  let keep = servers.iter().map(|(name, _)| name.clone()).collect();
  crate::rules::retain_subjects(state, "server_offline", &keep).await;
  crate::rules::retain_subjects(state, "disk_full", &keep).await;
  let keep = snap.world.gateways.keys().cloned().collect();
  crate::rules::retain_subjects(state, "gateway_down", &keep).await;
  for (name, _) in servers.iter().filter(|(_, online)| !online) {
    crate::rules::observe(state, "server.online", name, 0.0, "")
      .await;
  }
  for (name, row) in &snap.world.gateways {
    if !state.hub.is_online(&row.spec.server) {
      continue;
    }
    let Some(Ok(projects)) = live.get(&row.spec.server) else {
      continue;
    };
    let running = projects
      .get(&crate::world::gateway_project(name))
      .is_some_and(|p| p.all_running());
    crate::rules::observe(
      state,
      "gateway.running",
      name,
      if running { 1.0 } else { 0.0 },
      &format!("服务器 {}", row.spec.server),
    )
    .await;
  }
  for (name, _) in servers.iter().filter(|(_, online)| *online) {
    crate::rules::observe(state, "server.online", name, 1.0, "")
      .await;
  }
  for (name, _) in servers.iter().filter(|(_, online)| *online) {
    if let Some(report) =
      snap.agent(name).and_then(|a| a.report.as_ref())
    {
      let disks = [
        ("磁盘", report.disk),
        ("Docker 所在磁盘", report.docker_disk),
      ]
      .into_iter()
      .filter_map(|(label, disk)| {
        disk.filter(|d| d.total > 0).map(|d| (label, d))
      })
      .collect::<Vec<_>>();
      if !disks.is_empty() {
        let full = disks
          .iter()
          .filter(|(_, disk)| disk.free == 0)
          .map(|(label, _)| *label)
          .collect::<Vec<_>>();
        crate::rules::observe(
          state,
          "disk.available",
          name,
          if full.is_empty() { 1.0 } else { 0.0 },
          &full.join("、"),
        )
        .await;
      }
    }
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
  Ok(())
}
