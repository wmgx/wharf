//! 每分钟检查一次，出事推送、恢复再推（[crate::notify::on_result] 只在状态变化时发）：
//!
//! - 服务器离线：agent 连续 [OFFLINE_MINUTES] 分钟不在线；
//! - 容器反复重启：最近 [WINDOW] 次检查里有 [RESTART_HITS] 次看到容器处于 `restarting`，
//!   整个窗口都没看到时算恢复。
//!
//! 计数只存在内存里，控制面重启后重新累计。

use std::{
  collections::{BTreeMap, VecDeque},
  sync::{Arc, Mutex},
  time::Duration,
};

use crate::{notify, state::AppState};

const EVERY: Duration = Duration::from_secs(60);
const OFFLINE_MINUTES: u32 = 3;
const WINDOW: usize = 10;
const RESTART_HITS: usize = 2;

#[derive(Default)]
struct Memory {
  offline: BTreeMap<String, u32>,
  restarts: BTreeMap<String, VecDeque<bool>>,
}

static MEMORY: Mutex<Option<Memory>> = Mutex::new(None);

/// 正在反复重启的服务，进"需要注意"。
pub fn problems() -> Vec<String> {
  let Ok(m) = MEMORY.lock() else { return vec![] };
  m.as_ref()
    .map(|m| {
      m.restarts
        .iter()
        .filter(|(_, w)| hits(w) >= RESTART_HITS)
        .map(|(s, _)| format!("服务 {s} 的容器在反复重启"))
        .collect()
    })
    .unwrap_or_default()
}

fn hits(w: &VecDeque<bool>) -> usize {
  w.iter().filter(|x| **x).count()
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
  let mut events = Vec::new();

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

  {
    let mut guard = MEMORY.lock().unwrap_or_else(|e| e.into_inner());
    let m = guard.get_or_insert_with(Memory::default);
    m.offline.retain(|n, _| servers.iter().any(|(s, _)| s == n));
    for (name, online) in &servers {
      let n = m.offline.entry(name.clone()).or_default();
      *n = if *online { 0 } else { *n + 1 };
      if *online {
        events.push((
          format!("agent.{name}"),
          true,
          offline_event(name, true),
        ));
      } else if *n == OFFLINE_MINUTES {
        events.push((
          format!("agent.{name}"),
          false,
          offline_event(name, false),
        ));
      }
    }
    m.restarts
      .retain(|n, _| restarting.iter().any(|(s, _)| s == n));
    for (name, seen) in &restarting {
      let w = m.restarts.entry(name.clone()).or_default();
      w.push_back(*seen);
      while w.len() > WINDOW {
        w.pop_front();
      }
      let h = hits(w);
      if h == RESTART_HITS && *seen {
        events.push((
          format!("restart.{name}"),
          false,
          restart_event(name, false),
        ));
      } else if h == 0 {
        events.push((
          format!("restart.{name}"),
          true,
          restart_event(name, true),
        ));
      }
    }
  }
  for (key, ok, event) in events {
    notify::on_result(state, &key, ok, event).await;
  }
  Ok(())
}

fn offline_event(name: &str, ok: bool) -> notify::Event {
  if ok {
    notify::Event {
      title: format!("服务器 {name} 恢复在线"),
      body: format!("{name} 的 agent 已经连回控制面"),
    }
  } else {
    notify::Event {
      title: format!("服务器 {name} 离线"),
      body: format!(
        "{name} 的 agent 已经 {OFFLINE_MINUTES} 分钟没有连上控制面：可能是机器关机、网络断了或 agent 挂了"
      ),
    }
  }
}

fn restart_event(name: &str, ok: bool) -> notify::Event {
  if ok {
    notify::Event {
      title: format!("服务 {name} 不再反复重启"),
      body: format!("最近 {WINDOW} 分钟没有看到 {name} 的容器重启"),
    }
  } else {
    notify::Event {
      title: format!("服务 {name} 的容器在反复重启"),
      body: format!(
        "最近 {WINDOW} 分钟里多次看到容器处于重启中，多半是启动就崩溃。看日志：wharf service logs {name}"
      ),
    }
  }
}
