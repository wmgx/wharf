//! 边缘应用的同步：把 Cloudflare 那边的现状、版本、账号里的项目存进控制面，页面直接读。
//!
//! - 定时任务每 5 分钟同步一次；Wharf 发布、回滚后立刻同步；页面读到的数据旧了就在后台补一次；
//! - Wharf 记下线上应该是哪个版本（发布、回滚、导入后第一次同步、"以线上为准"时更新），
//!   之后线上版本变了、项目没了，就算差异提示出来。

use std::{
  collections::HashSet, sync::Arc, sync::Mutex, time::Duration,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use wharf_api_types::{
  ApiError,
  spec::{EdgeAppSpec, EdgeKind},
  view::{EdgeLive, EdgeProjectView, EdgeVersionView},
};

use crate::{
  db::{self, EdgeExpected, now_ms},
  edge::{self, provider_kind},
  snapshot::{self, Snapshot, with_timeout},
  state::AppState,
};

/// 页面读到的数据超过这个时间，就在后台再同步一次。
pub const STALE: Duration = Duration::from_secs(60);

/// 一个边缘应用的同步结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCache {
  /// 同步的是哪个厂商项目（账号/类型/项目名）；配置改了指向别的项目时作废。
  pub target: String,
  pub live: EdgeLive,
  #[serde(default)]
  pub versions: Vec<EdgeVersionView>,
}

impl AppCache {
  /// 线上的版本 id，排序后用逗号连起来（Worker 可能同时跑两个版本）。
  pub fn active(&self) -> String {
    let mut ids: Vec<&str> = self
      .versions
      .iter()
      .filter(|v| v.active)
      .map(|v| v.id.as_str())
      .collect();
    ids.sort();
    ids.join(",")
  }
}

pub fn target(name: &str, spec: &EdgeAppSpec) -> String {
  format!(
    "{}/{}/{}",
    spec.account,
    spec.kind.as_str(),
    spec.project_name(name)
  )
}

fn short(ids: &str) -> String {
  ids
    .split(',')
    .map(|id| &id[..8.min(id.len())])
    .collect::<Vec<_>>()
    .join("、")
}

/// 和 Wharf 记录的不一致时的说明。
pub fn drift(
  target: &str,
  cache: Option<&AppCache>,
  expected: Option<&EdgeExpected>,
) -> Option<String> {
  let cache = cache.filter(|c| c.target == target)?;
  if cache.live.error.is_some() {
    return None;
  }
  if !cache.live.exists {
    return Some("Cloudflare 上已经没有这个项目".into());
  }
  let expected = expected.filter(|e| e.target == target)?;
  let active = cache.active();
  (!active.is_empty() && active != expected.versions).then(|| {
    format!(
      "线上版本 {} 不是 Wharf 记录的 {}（在 Cloudflare 面板或别处发布过）",
      short(&active),
      short(&expected.versions)
    )
  })
}

// SYNC

async fn read(
  snap: &Snapshot,
  name: &str,
  spec: &EdgeAppSpec,
) -> AppCache {
  let target = target(name, spec);
  let now = Utc::now();
  let failed = |message: String| AppCache {
    target: target.clone(),
    live: EdgeLive {
      exists: false,
      url: None,
      deployed_at: None,
      deployed_by: None,
      error: Some(message),
      checked_at: now,
    },
    versions: vec![],
  };
  let provider = match edge::account(snap, &spec.account)
    .and_then(snapshot::edge_provider)
  {
    Ok(p) => p,
    Err(e) => return failed(e.message),
  };
  let project = match with_timeout(
    &format!("读取 {name} 的状态"),
    provider.get(provider_kind(spec.kind), spec.project_name(name)),
  )
  .await
  {
    Ok(p) => p,
    Err(e) => return failed(e.message),
  };
  let Some(p) = project else {
    return AppCache {
      target,
      live: EdgeLive {
        exists: false,
        url: None,
        deployed_at: None,
        deployed_by: None,
        error: None,
        checked_at: now,
      },
      versions: vec![],
    };
  };
  let (versions, error) = match edge::versions(snap, name).await {
    Ok(v) => (v, None),
    Err(e) => (vec![], Some(format!("读取版本失败：{}", e.message))),
  };
  AppCache {
    target,
    live: EdgeLive {
      exists: true,
      url: p.url,
      deployed_at: p.deployed_at,
      deployed_by: p.deployed_by,
      error,
      checked_at: now,
    },
    versions,
  }
}

/// 同步一个边缘应用。`adopt`：把现在的线上版本记为 Wharf 期望的版本
/// （没记过、或记的是别的项目时也会记）。
pub async fn sync_app(
  state: &AppState,
  snap: &Snapshot,
  name: &str,
  adopt: bool,
) -> Result<(), ApiError> {
  let spec = &snap
    .world
    .edge_apps
    .get(name)
    .ok_or_else(|| edge::edge_not_found(name))?
    .spec;
  let cache = read(snap, name, spec).await;
  let data = serde_json::to_string(&cache).map_err(db::json_err)?;
  let fresh = cache.live.exists && cache.live.error.is_none();
  let expected = snap.edge_expected.get(name);
  let record = fresh
    && !cache.active().is_empty()
    && (adopt || expected.is_none_or(|e| e.target != cache.target));
  let app = name.to_string();
  let row = EdgeExpected {
    target: cache.target.clone(),
    versions: cache.active(),
  };
  state
    .db
    .call(move |c| {
      db::put_edge_cache(c, &format!("app:{app}"), &data)?;
      if record {
        db::put_edge_expected(c, &app, &row)?;
      }
      Ok(())
    })
    .await
}

/// 同步账号里的 Workers / Pages 项目列表。
pub async fn sync_account(
  state: &AppState,
  snap: &Snapshot,
  account: &str,
) -> Result<Vec<EdgeProjectView>, ApiError> {
  let provider =
    snapshot::edge_provider(edge::account(snap, account)?)?;
  let list =
    with_timeout("读取 Workers / Pages 项目", provider.list())
      .await?;
  let projects: Vec<EdgeProjectView> = list
    .into_iter()
    .map(|(kind, p)| EdgeProjectView {
      account: account.to_string(),
      kind: match kind {
        wharf_providers::EdgeKind::Worker => EdgeKind::Worker,
        wharf_providers::EdgeKind::Pages => EdgeKind::Pages,
      },
      project: p.name,
      url: p.url,
      modified_at: p.modified_at,
      managed_as: None,
    })
    .collect();
  let data =
    serde_json::to_string(&projects).map_err(db::json_err)?;
  let key = format!("account:{account}");
  state
    .db
    .call(move |c| db::put_edge_cache(c, &key, &data))
    .await?;
  Ok(projects)
}

/// 标出已经导入的项目。
pub fn mark_managed(snap: &Snapshot, list: &mut [EdgeProjectView]) {
  for p in list {
    p.managed_as = snap
      .world
      .edge_apps
      .iter()
      .find(|(n, r)| {
        r.spec.account == p.account
          && r.spec.kind == p.kind
          && r.spec.project_name(n) == p.project
      })
      .map(|(n, _)| n.clone());
  }
}

/// 定时任务：所有边缘应用和所有 Cloudflare 账号。
pub async fn sync_all(state: &AppState) -> Result<(), ApiError> {
  let snap = snapshot::load(&state.db).await?;
  for name in snap.world.edge_apps.keys() {
    if let Err(e) = sync_app(state, &snap, name, false).await {
      tracing::warn!("同步边缘应用 {name} 失败：{e}");
    }
  }
  for account in
    snap.accounts.iter().filter(|a| a.kind == "cloudflare")
  {
    if let Err(e) = sync_account(state, &snap, &account.name).await {
      tracing::warn!(
        "同步账号 {} 的 Workers / Pages 失败：{e}",
        account.name
      );
    }
  }
  Ok(())
}

/// Wharf 发布、回滚之后：同步并把新的线上版本记为期望版本。
pub async fn after_change(state: &AppState, name: &str) {
  let result = match snapshot::load(&state.db).await {
    Ok(snap) => sync_app(state, &snap, name, true).await,
    Err(e) => Err(e),
  };
  if let Err(e) = result {
    tracing::warn!("同步边缘应用 {name} 失败：{e}");
  }
}

/// 正在后台同步的应用，同一个不重复发起。
#[derive(Default)]
pub struct Syncing(Mutex<HashSet<String>>);

/// 数据旧了（或还没同步过）就在后台同步，不等结果。
pub fn sync_if_stale(
  state: &Arc<AppState>,
  snap: &Snapshot,
  name: &str,
) {
  let stale = snap
    .edge_checked
    .get(&format!("app:{name}"))
    .is_none_or(|t| now_ms() - t > STALE.as_millis() as i64);
  if !stale {
    return;
  }
  {
    let mut running = state
      .edge_syncing
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner());
    if !running.insert(name.to_string()) {
      return;
    }
  }
  let state = state.clone();
  let name = name.to_string();
  tokio::spawn(async move {
    if let Ok(snap) = snapshot::load(&state.db).await
      && let Err(e) = sync_app(&state, &snap, &name, false).await
    {
      tracing::warn!("同步边缘应用 {name} 失败：{e}");
    }
    state
      .edge_syncing
      .0
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .remove(&name);
  });
}

#[cfg(test)]
mod tests {
  use super::*;

  fn cache(active: &[&str]) -> AppCache {
    AppCache {
      target: "cf/worker/w".into(),
      live: EdgeLive {
        exists: true,
        url: None,
        deployed_at: None,
        deployed_by: None,
        error: None,
        checked_at: Utc::now(),
      },
      versions: ["aaaaaaaa1", "bbbbbbbb2"]
        .iter()
        .map(|id| EdgeVersionView {
          id: id.to_string(),
          created_at: String::new(),
          source: None,
          message: None,
          active: active.contains(id),
          url: None,
        })
        .collect(),
    }
  }

  #[test]
  fn drift_when_live_version_is_not_the_recorded_one() {
    let expected = EdgeExpected {
      target: "cf/worker/w".into(),
      versions: "aaaaaaaa1".into(),
    };
    let t = "cf/worker/w";
    assert_eq!(
      drift(t, Some(&cache(&["aaaaaaaa1"])), Some(&expected)),
      None
    );
    assert!(
      drift(t, Some(&cache(&["bbbbbbbb2"])), Some(&expected))
        .unwrap()
        .contains("bbbbbbbb")
    );
    // 指向别的项目了：旧记录不算数。
    assert_eq!(
      drift(
        "cf/worker/x",
        Some(&cache(&["bbbbbbbb2"])),
        Some(&expected)
      ),
      None
    );
  }
}
