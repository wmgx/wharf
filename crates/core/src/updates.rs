//! 后台检查（P6 待办"镜像更新和配置漂移提醒"）：
//! - 每 6 小时查镜像标签（image 来源和 compose 里的镜像）、git 构建来源的分支现在指向哪个版本，和固定的版本不同就是"有新版本"；
//!   顺便列出仓库里更高版本的标签（例如 2.20 → 2.21），只提醒，换标签要改配置；
//!   只读清单和 `git ls-remote`，不拉镜像、不下载代码，查不到只记原因、沿用上次的结论。
//! - 每 10 分钟按现在的配置算一次计划（不保存），列出还没执行的改动。
//!
//! 结果只放在内存里，控制面重启后重新查。

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, RwLock},
  time::Duration,
};

use axum::{Json, extract::State};
use chrono::Utc;
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ResolveCommit, ResolveImages, ResolvedImage},
  spec::Source,
  view::{NewerTag, PendingCheck, Perm, UpdatesView, VersionCheck},
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
/// 查 digest 之外还要列标签（agent 每个镜像最多 30 秒，各镜像同时查）。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(120);
const COMMIT_TIMEOUT: Duration = Duration::from_secs(180);

static LAST: RwLock<Option<UpdatesView>> = RwLock::new(None);

pub fn last() -> Option<UpdatesView> {
  LAST.read().ok().and_then(|l| l.clone())
}

/// 按现在的配置修正上次的结论：检查之后服务已经换了标签或升级过，
/// 旧镜像的"更高版本"和已经固定下来的"新版本"都不再提示，等下次检查重新算。
pub fn current(snap: &Snapshot) -> Option<UpdatesView> {
  let mut view = last()?;
  view.services.retain(|name, check| {
    let Some(row) = snap.world.services.get(name) else {
      return false;
    };
    let images = crate::pins::images(&row.spec.source);
    check.tags.retain(|t| images.contains(&t.image));
    if check
      .latest
      .as_ref()
      .is_some_and(|l| row.pins.values().any(|p| p == l))
    {
      check.newer = false;
    }
    true
  });
  Some(view)
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
      crate::auto_update::tick(&state).await;
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

/// 算一次计划，不保存，也不为已有 pin 补查迁移平台。
async fn pending(state: &AppState) {
  let result = crate::planner::pending_plan(state).await;
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

pub(crate) async fn versions(state: &AppState) {
  let snap = match snapshot::load(&state.db).await {
    Ok(s) => s,
    Err(e) => {
      tracing::warn!("检查新版本：读配置失败：{e}");
      return;
    }
  };
  let (mut found, tags) = images(state, &snap).await;
  found.extend(commits(state, &snap).await);
  let fresh: Vec<(String, String)> = found
    .iter()
    .filter_map(|(n, r)| match r {
      Ok((latest, pinned)) if latest != pinned => {
        Some((n.clone(), latest.clone()))
      }
      _ => None,
    })
    .collect();
  let now = Utc::now();
  let names: BTreeSet<String> =
    found.keys().chain(tags.keys()).cloned().collect();
  update(|u| {
    let old = std::mem::take(&mut u.services);
    for name in names {
      let prev = old.get(&name);
      let mut check = match found.remove(&name) {
        Some(Ok((latest, pinned))) => VersionCheck {
          at: now,
          newer: latest != pinned,
          latest: Some(latest),
          error: None,
          tags: vec![],
        },
        Some(Err(e)) => VersionCheck {
          at: now,
          newer: prev.is_some_and(|c| c.newer),
          latest: prev.and_then(|c| c.latest.clone()),
          error: Some(e),
          tags: vec![],
        },
        None => VersionCheck {
          at: now,
          newer: false,
          latest: None,
          error: None,
          tags: vec![],
        },
      };
      check.tags = match tags.get(&name) {
        Some(t) => t.clone(),
        None if check.error.is_some() => {
          prev.map(|c| c.tags.clone()).unwrap_or_default()
        }
        None => vec![],
      };
      u.services.insert(name, check);
    }
  });
  for (name, latest) in fresh {
    notify_newer(state, &name, &latest).await;
  }
  for (name, list) in &tags {
    notify_tags(state, name, list).await;
  }
}

/// 更高版本的标签同样只推一次。
async fn notify_tags(
  state: &AppState,
  name: &str,
  tags: &[NewerTag],
) {
  if tags.is_empty() {
    return;
  }
  let text = tags
    .iter()
    .map(|t| {
      let major = if t.major { "（大版本）" } else { "" };
      format!("{} → {}{major}", t.image, t.tag)
    })
    .collect::<Vec<_>>()
    .join("，");
  if seen(state, &format!("notify.tag.{name}"), &text).await {
    return;
  }
  let first = &tags[0];
  let event = crate::notify::Event {
    title: format!("服务 {name} 有更高版本的镜像"),
    body: format!(
      "{text}。换标签要改配置，不会自动升级：wharf service retag {name} {} {}（或在页面上点\u{201c}升级到 {}\u{201d}）",
      first.image, first.tag, first.tag
    ),
  };
  crate::rules::notice(state, "update", None, true, event).await;
}

/// 记下这次推送的内容，和上次一样就返回 true。
async fn seen(state: &AppState, key: &str, value: &str) -> bool {
  let key = key.to_string();
  let value = value.to_string();
  state
    .db
    .call(move |c| {
      let prev = crate::db::setting(c, &key)?;
      if prev.as_deref() != Some(value.as_str()) {
        crate::db::set_setting(c, &key, Some(&value))?;
      }
      Ok(prev.as_deref() == Some(value.as_str()))
    })
    .await
    .unwrap_or(true)
}

/// 同一个新版本只推一次：推过的版本记在设置 `notify.update.<服务>` 里。
async fn notify_newer(state: &AppState, name: &str, latest: &str) {
  let seen =
    seen(state, &format!("notify.update.{name}"), latest).await;
  if seen {
    return;
  }
  let short: String = latest
    .trim_start_matches("sha256:")
    .chars()
    .take(12)
    .collect();
  let event = crate::notify::Event {
    title: format!("服务 {name} 有新版本"),
    body: format!(
      "最新版本 {short}。看改动：wharf plan，要更新：wharf service update {name}（或在页面上点\u{201c}更新\u{201d}）"
    ),
  };
  crate::rules::notice(state, "update", None, true, event).await;
}

/// (服务, 镜像, 固定的版本)。
type Item<'a> = (&'a str, String, Option<&'a str>);

/// 服务 → 更高版本的标签。
type Tags = BTreeMap<String, Vec<NewerTag>>;

/// image 来源和 compose 里的镜像：按服务器分组，一台 agent 一次查完，顺便列出更高版本的标签。
/// 固定了版本的镜像比 digest；没固定的（例如查不到版本的私有仓库）只看标签。
async fn images(
  state: &AppState,
  snap: &Snapshot,
) -> (BTreeMap<String, Found>, Tags) {
  // 服务器 → [(服务, 镜像, 固定的版本)]
  let mut by_server: BTreeMap<&str, Vec<Item>> = BTreeMap::new();
  for (name, row) in &snap.world.services {
    for image in crate::pins::images(&row.spec.source) {
      if image.contains('@') {
        continue;
      }
      let pinned = row.pins.get(&image).map(String::as_str);
      by_server
        .entry(&row.spec.server)
        .or_default()
        .push((name, image, pinned));
    }
  }
  let mut found: BTreeMap<String, Found> = BTreeMap::new();
  let mut tags = Tags::new();
  for (server, items) in by_server {
    let Some(row) = snap.world.servers.get(server) else {
      continue;
    };
    let result: Result<Vec<ResolvedImage>, ApiError> = state
      .hub
      .call(
        server,
        AgentOp::ResolveImages(ResolveImages {
          images: items.iter().map(|i| i.1.clone()).collect(),
          pull: snapshot::pull_policy(row),
          tags: true,
        }),
        RESOLVE_TIMEOUT,
        None,
        &Default::default(),
      )
      .await;
    for (name, image, pinned) in items {
      let hit = result
        .as_ref()
        .ok()
        .and_then(|l| l.iter().find(|r| r.image == image));
      if let Some(hit) = hit {
        let list = tags.entry(name.to_string()).or_default();
        for tag in &hit.newer_tags {
          list.push(NewerTag {
            image: image.clone(),
            tag: tag.clone(),
            major: major(tag) != major(current_tag(&image)),
          });
        }
      }
      let Some(pinned) = pinned else { continue };
      let r = match (&result, hit.and_then(|r| r.digest.clone())) {
        (Err(e), _) => Err(e.message.clone()),
        (Ok(_), Some(d)) => Ok((d, pinned.to_string())),
        (Ok(_), None) => Err(
          hit
            .and_then(|r| r.error.clone())
            .unwrap_or_else(|| "agent 没有返回结果".into()),
        ),
      };
      // 一个服务里有一个镜像变了就是有新版本；查失败的优先报出来。
      let keep = match (found.get(name), &r) {
        (None, _) => true,
        (Some(Err(_)), _) => false,
        (Some(Ok(_)), Err(_)) => true,
        (Some(Ok((l, p))), Ok(_)) => l == p,
      };
      if keep {
        found.insert(name.to_string(), r);
      }
    }
  }
  tags.retain(|_, l| !l.is_empty());
  (found, tags)
}

/// 镜像现在写的标签，没写就是 `latest`。
fn current_tag(image: &str) -> &str {
  let slash = image.rfind('/').map_or(0, |i| i + 1);
  image[slash..].split_once(':').map_or("latest", |(_, t)| t)
}

/// 标签的大版本：开头的数字（`v` 前缀不算）。
fn major(tag: &str) -> Option<u64> {
  let t = tag.strip_prefix('v').unwrap_or(tag);
  let end = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
  t[..end].parse().ok()
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
      r.map(|c| (c, pinned.clone())).map_err(|e| e.to_string()),
    );
  }
  out
}
