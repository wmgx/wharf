//! 每分钟采一次服务器在线、容器是否在重启，交给 [crate::rules] 按规则判断推送。

use std::{sync::Arc, time::Duration};

use wharf_api_types::view::{Issue, IssueLevel};

use crate::state::AppState;

const EVERY: Duration = Duration::from_secs(60);

/// 正在反复重启的服务，进"需要注意"。
pub fn issues() -> Vec<Issue> {
  crate::rules::firing("container_restarting")
    .into_iter()
    .map(|title| Issue {
      code: "container_restarting".into(),
      level: IssueLevel::Fault,
      subject: None,
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
  Ok(())
}
