//! 后台检查（P6 待办"镜像更新和配置漂移提醒"）：
//! - 每 6 小时查 image 来源的镜像标签、git 构建来源的分支现在指向哪个版本，和固定的版本不同就是"有新版本"；
//!   只读清单和 `git ls-remote`，不拉镜像、不下载代码，查不到只记原因、沿用上次的结论。
//! - 每 10 分钟按现在的配置算一次计划（不保存），列出还没执行的改动。
//!
//! 结果只放在内存里，控制面重启后重新查。

use std::{
  collections::BTreeMap,
  sync::{Arc, RwLock},
  time::Duration,
};

use axum::{Json, extract::State};
use chrono::Utc;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ResolveCommit, ResolveImages, ResolvedImage},
  plan::PlanRequest,
  spec::Source,
  view::{PendingCheck, Perm, UpdatesView, VersionCheck},
};

use crate::{
  api::ApiResult,
  auth::Auth,
  snapshot::{self, Snapshot},
  state::AppState,
};

const FIRST_TICK: Duration = Duration::from_secs(90);
const PENDING_EVERY: Duration = Duration::from_secs(10 * 60);
/// 版本检查每几次计划检查做一次：6 小时。
const VERSIONS_EVERY: u32 = 36;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);
const COMMIT_TIMEOUT: Duration = Duration::from_secs(180);

static LAST: RwLock<Option<UpdatesView>> = RwLock::new(None);

pub fn last() -> Option<UpdatesView> {
  LAST.read().ok().and_then(|l| l.clone())
}

fn update(f: impl FnOnce(&mut UpdatesView)) {
  if let Ok(mut last) = LAST.write() {
    f(last.get_or_insert_with(UpdatesView::default));
  }
}

pub fn spawn(state: Arc<AppState>) {
  tokio::spawn(async move {
    tokio::time::sleep(FIRST_TICK).await;
    let mut n = 0u32;
    loop {
      if n.is_multiple_of(VERSIONS_EVERY) {
        versions(&state).await;
      }
      pending(&state).await;
      n = n.wrapping_add(1);
      tokio::time::sleep(PENDING_EVERY).await;
    }
  });
}

/// `POST /api/updates/check`：现在查一次版本和未执行的改动。
pub async fn check_now(
  State(s): State<Arc<AppState>>,
  auth: Auth,
) -> ApiResult<UpdatesView> {
  auth.require(Perm::Read)?;
  versions(&s).await;
  pending(&s).await;
  Ok(Json(last().unwrap_or_default()))
}

/// 算一次计划，不保存。
async fn pending(state: &AppState) {
  let result =
    crate::planner::make_plan(state, PlanRequest::default()).await;
  let check = match result {
    Ok(p) => PendingCheck {
      at: Utc::now(),
      items: p.plan.items.iter().map(|i| i.address.clone()).collect(),
      error: None,
    },
    Err(e) => PendingCheck {
      at: Utc::now(),
      items: last()
        .and_then(|l| l.pending)
        .map(|p| p.items)
        .unwrap_or_default(),
      error: Some(e.message),
    },
  };
  update(|u| u.pending = Some(check));
}

/// 查一个服务的结果：(查到的版本, 固定的版本) 或者错误。
type Found = Result<(String, String), String>;

async fn versions(state: &AppState) {
  let snap = match snapshot::load(&state.db).await {
    Ok(s) => s,
    Err(e) => {
      tracing::warn!("检查新版本：读配置失败：{e}");
      return;
    }
  };
  let mut found: BTreeMap<String, Found> = images(state, &snap).await;
  found.extend(commits(state, &snap).await);
  let now = Utc::now();
  update(|u| {
    let old = std::mem::take(&mut u.services);
    for (name, r) in found {
      let check = match r {
        Ok((latest, pinned)) => VersionCheck {
          at: now,
          newer: latest != pinned,
          latest: Some(latest),
          error: None,
        },
        Err(e) => VersionCheck {
          at: now,
          newer: old.get(&name).is_some_and(|c| c.newer),
          latest: old.get(&name).and_then(|c| c.latest.clone()),
          error: Some(e),
        },
      };
      u.services.insert(name, check);
    }
  });
}

/// image 来源：按服务器分组，一台 agent 一次查完。没固定版本或标签本身就是 digest 的跳过。
async fn images(
  state: &AppState,
  snap: &Snapshot,
) -> BTreeMap<String, Found> {
  let mut by_server: BTreeMap<&str, Vec<(&str, &str, &str)>> =
    BTreeMap::new();
  for (name, row) in &snap.world.services {
    let Source::Image(image) = &row.spec.source else {
      continue;
    };
    let Some(pinned) = row.pins.get(image) else {
      continue;
    };
    if image.contains('@') {
      continue;
    }
    by_server
      .entry(&row.spec.server)
      .or_default()
      .push((name, image, pinned));
  }
  let mut out = BTreeMap::new();
  for (server, items) in by_server {
    let Some(row) = snap.world.servers.get(server) else {
      continue;
    };
    let result: Result<Vec<ResolvedImage>, ApiError> = state
      .hub
      .call(
        server,
        AgentOp::ResolveImages(ResolveImages {
          images: items.iter().map(|i| i.1.to_string()).collect(),
          pull: snapshot::pull_policy(row),
        }),
        RESOLVE_TIMEOUT,
        None,
        &Default::default(),
      )
      .await;
    for (name, image, pinned) in items {
      let r = match &result {
        Err(e) => Err(e.message.clone()),
        Ok(list) => {
          let hit = list.iter().find(|r| r.image == image);
          match hit.and_then(|r| r.digest.clone()) {
            Some(d) => Ok((d, pinned.to_string())),
            None => Err(
              hit
                .and_then(|r| r.error.clone())
                .unwrap_or_else(|| "agent 没有返回结果".into()),
            ),
          }
        }
      };
      out.insert(name.to_string(), r);
    }
  }
  out
}

/// git 构建来源：在构建机上 `git ls-remote`，没固定 commit 的跳过。
async fn commits(
  state: &AppState,
  snap: &Snapshot,
) -> BTreeMap<String, Found> {
  let mut out = BTreeMap::new();
  for (name, row) in &snap.world.services {
    let Source::Build(build) = &row.spec.source else {
      continue;
    };
    let (Some(git), Some(pinned)) = (build.git.as_ref(), &row.commit)
    else {
      continue;
    };
    let Some(server) = snap.world.servers.get(&row.spec.server)
    else {
      continue;
    };
    let r = async {
      let fetch = crate::build::code_fetch(
        state,
        snap,
        &format!("服务 {name}"),
        None,
        Some(git),
        None,
      )?;
      state
        .hub
        .call::<String>(
          &row.spec.server,
          AgentOp::ResolveCommit(ResolveCommit {
            service: name.clone(),
            fetch,
            pull: snapshot::pull_policy(server),
          }),
          COMMIT_TIMEOUT,
          None,
          &Default::default(),
        )
        .await
    }
    .await;
    out.insert(
      name.clone(),
      r.map(|c| (c, pinned.clone())).map_err(|e| e.message),
    );
  }
  out
}
