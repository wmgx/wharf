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
  time::{Duration, Instant},
};

use axum::{Json, extract::State};
use chrono::Utc;
use futures_util::{StreamExt, stream};
use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ResolveCommit, ResolveImages, ResolvedImage},
  spec::{
    ServiceSpec, Source, UpdateIgnoreScope, UpdateIgnoreSpec,
    image_repo,
  },
  view::{
    ImageVersionCheck, NewerTag, PendingCheck, Perm, UpdatesView,
    VersionCheck,
  },
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

const COOLDOWN: Duration = Duration::from_secs(60);
static CHECK_NOW: tokio::sync::Mutex<Option<Instant>> =
  tokio::sync::Mutex::const_new(None);
static VERSION_CHECK: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());
static PENDING_CHECK: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());
static LAST: RwLock<Option<UpdatesView>> = RwLock::new(None);

pub fn last() -> Option<UpdatesView> {
  LAST.read().ok().and_then(|l| l.clone())
}

fn effective_ignore(
  rules: &[UpdateIgnoreSpec],
  image: &str,
) -> Option<UpdateIgnoreScope> {
  rules
    .iter()
    .filter(|rule| {
      rule.image == "*"
        || rule.image == image
        || rule.image == image_repo(image)
    })
    .map(|r| r.scope)
    .min()
}

fn ignore_all_source(rules: &[UpdateIgnoreSpec]) -> bool {
  rules
    .iter()
    .any(|r| r.image == "*" && r.scope == UpdateIgnoreScope::All)
}

pub(crate) fn validate_ignore(
  spec: &ServiceSpec,
) -> Result<(), ApiError> {
  if spec.update_ignore.len() > 32 {
    return Err(ApiError::invalid(
      "每个服务最多设 32 条更新忽略规则",
    ));
  }
  let mut names = BTreeSet::new();
  for rule in &spec.update_ignore {
    if rule.image.is_empty()
      || rule.image.contains('@')
      || rule
        .image
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
      || !names.insert(&rule.image)
    {
      return Err(ApiError::invalid(
        "更新忽略规则的镜像名无效或重复",
      ));
    }
    if matches!(spec.source, Source::Build(_))
      && (rule.image != "*" || rule.scope != UpdateIgnoreScope::All)
    {
      return Err(ApiError::invalid(
        "构建来源服务只能用 --image '*' --all 忽略更新提醒",
      ));
    }
  }
  Ok(())
}

/// 按现在的配置修正上次的结论：检查之后服务已经换了标签或升级过，
/// 旧镜像的"更高版本"和已经固定下来的"新版本"都不再提示，等下次检查重新算。
pub fn current(snap: &Snapshot) -> Option<UpdatesView> {
  let mut view = last()?;
  view.services.retain(|name, check| {
    snap.world.services.get(name).is_some_and(|row| {
      reconcile(row, check);
      filter_ignored(row, check);
      !row.spec.stopped
    })
  });
  Some(view)
}

fn reconcile(
  row: &crate::world::ServiceRow,
  check: &mut VersionCheck,
) {
  let images = crate::pins::images(&row.spec.source);
  check.tags.retain(|t| images.contains(&t.image));
  if matches!(row.spec.source, Source::Build(_)) {
    check.newer = check.latest.as_ref().is_some_and(|latest| {
      row.commit.as_ref().is_some_and(|pin| pin != latest)
    });
    return;
  }
  check.images.retain(|image, _| {
    images.contains(image) && row.pins.contains_key(image)
  });
  for (image, found) in &mut check.images {
    found.newer = found
      .latest
      .as_ref()
      .is_some_and(|latest| latest != &row.pins[image]);
  }
  summarize_images(check);
}

fn filter_ignored(
  row: &crate::world::ServiceRow,
  check: &mut VersionCheck,
) {
  let rules = &row.spec.update_ignore;
  check.tags.retain(|tag| {
    match effective_ignore(rules, &tag.image) {
      Some(UpdateIgnoreScope::All) => false,
      Some(UpdateIgnoreScope::Major) => !tag.major,
      None => true,
    }
  });
  if matches!(row.spec.source, Source::Build(_)) {
    check.newer &= !ignore_all_source(rules);
    return;
  }
  check.images.retain(|image, _| {
    effective_ignore(rules, image) != Some(UpdateIgnoreScope::All)
  });
  summarize_images(check);
}

fn summarize_images(check: &mut VersionCheck) {
  check.newer_images = check
    .images
    .iter()
    .filter(|(_, image)| image.newer)
    .map(|(name, _)| name.clone())
    .collect();
  check.newer = !check.newer_images.is_empty();
  check.latest = check
    .images
    .values()
    .find(|image| image.newer)
    .and_then(|image| image.latest.clone())
    .or_else(|| {
      check.images.values().find_map(|image| image.latest.clone())
    });
  let errors: Vec<_> = check
    .images
    .iter()
    .filter_map(|(name, image)| {
      image.error.as_ref().map(|error| format!("{name}: {error}"))
    })
    .collect();
  check.error = (!errors.is_empty()).then(|| errors.join("；"));
}

pub(crate) fn newer_fingerprint(
  check: &VersionCheck,
) -> Option<String> {
  if !check.newer {
    return None;
  }
  if check.images.len() <= 1 {
    return check.latest.clone();
  }
  Some(
    check
      .images
      .iter()
      .filter_map(|(name, image)| {
        image
          .latest
          .as_ref()
          .filter(|_| image.newer)
          .map(|latest| format!("{name}={latest}"))
      })
      .collect::<Vec<_>>()
      .join("\n"),
  )
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
  auth.require(Perm::Plan)?;
  {
    let mut checked = CHECK_NOW.lock().await;
    if checked.is_none_or(|at| at.elapsed() >= COOLDOWN) {
      versions(&s).await;
      pending(&s).await;
      *checked = Some(Instant::now());
    }
  }
  let snap = snapshot::load(&s.db).await?;
  Ok(Json(current(&snap).unwrap_or_default()))
}

/// 算一次计划，不保存，也不为已有 pin 补查迁移平台。
async fn pending(state: &AppState) {
  let _guard = PENDING_CHECK.lock().await;
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
  let _guard = VERSION_CHECK.lock().await;
  refresh(state, None).await;
}

pub(crate) async fn refresh_services(
  state: &AppState,
  names: BTreeSet<String>,
) {
  let _guard = VERSION_CHECK.lock().await;
  refresh(state, Some(&names)).await;
}

async fn refresh(state: &AppState, only: Option<&BTreeSet<String>>) {
  let snap = match snapshot::load(&state.db).await {
    Ok(snap) => snap,
    Err(e) => {
      tracing::warn!("检查新版本：读配置失败：{e}");
      return;
    }
  };
  let ((mut images, mut tags), mut commits) = tokio::join!(
    images(state, &snap, only),
    commits(state, &snap, only)
  );
  let Ok(fresh) = snapshot::load(&state.db).await else {
    return;
  };
  let now = Utc::now();
  let mut updated = Vec::new();
  update(|u| {
    u.services.retain(|name, _| {
      fresh
        .world
        .services
        .get(name)
        .is_some_and(|row| !row.spec.stopped)
    });
    for (name, row) in &fresh.world.services {
      let valid = included(only, name, row)
        && snap.world.services.get(name).is_some_and(|old| {
          old.instance_id == row.instance_id
            && old.spec.source == row.spec.source
            && snapshot::service_runtime_server(&snap, name)
              == snapshot::service_runtime_server(&fresh, name)
        });
      if !valid {
        continue;
      }
      let image_results = images.remove(name).unwrap_or_default();
      let commit = commits.remove(name);
      let mut tags = tags.remove(name).unwrap_or_default();
      if image_results.is_empty()
        && commit.is_none()
        && tags.is_empty()
      {
        u.services.remove(name);
        continue;
      }
      let previous = u.services.remove(name);
      let mut check = VersionCheck {
        at: now,
        newer: false,
        latest: None,
        error: None,
        tags: vec![],
        images: BTreeMap::new(),
        newer_images: vec![],
      };
      for (image, result) in image_results {
        let prior =
          previous.as_ref().and_then(|p| p.images.get(&image));
        if result.is_err()
          && let Some(previous) = &previous
        {
          tags.extend(
            previous
              .tags
              .iter()
              .filter(|tag| tag.image == image)
              .cloned(),
          );
        }
        check.images.insert(image, merge_image(result, prior));
      }
      if let Some(result) = commit {
        check.latest = match result {
          Ok((latest, _)) => Some(latest),
          Err(error) => {
            check.error = Some(error);
            previous.and_then(|p| p.latest)
          }
        };
      }
      tags
        .sort_by(|a, b| (&a.image, &a.tag).cmp(&(&b.image, &b.tag)));
      tags.dedup();
      check.tags = tags;
      reconcile(row, &mut check);
      let mut visible = check.clone();
      filter_ignored(row, &mut visible);
      updated.push((name.clone(), visible));
      u.services.insert(name.clone(), check);
    }
  });
  for (name, check) in updated {
    if let (Some(fingerprint), Some(latest)) =
      (newer_fingerprint(&check), &check.latest)
    {
      notify_newer(state, &name, latest, &fingerprint).await;
    }
    notify_tags(state, &name, &check.tags).await;
  }
}

fn merge_image(
  result: Found,
  prior: Option<&ImageVersionCheck>,
) -> ImageVersionCheck {
  match result {
    Ok((latest, pinned)) => ImageVersionCheck {
      newer: latest != pinned,
      latest: Some(latest),
      error: None,
    },
    Err(error) => ImageVersionCheck {
      error: Some(error),
      ..prior.cloned().unwrap_or_default()
    },
  }
}

fn included(
  only: Option<&BTreeSet<String>>,
  name: &str,
  row: &crate::world::ServiceRow,
) -> bool {
  !row.spec.stopped && only.is_none_or(|names| names.contains(name))
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
  crate::rules::notice(
    state,
    "update",
    Some(name),
    None,
    true,
    event,
  )
  .await;
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
async fn notify_newer(
  state: &AppState,
  name: &str,
  latest: &str,
  fingerprint: &str,
) {
  let seen =
    seen(state, &format!("notify.update.{name}"), fingerprint).await;
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
  crate::rules::notice(
    state,
    "update",
    Some(name),
    None,
    true,
    event,
  )
  .await;
}

/// (服务, 镜像, 固定的版本)。
type Item = (String, String, Option<String>);

/// 服务 → 更高版本的标签。
type Tags = BTreeMap<String, Vec<NewerTag>>;
type ImageFindings = BTreeMap<String, BTreeMap<String, Found>>;

/// image 来源和 compose 里的镜像：按服务器分组，一台 agent 一次查完，顺便列出更高版本的标签。
/// 固定了版本的镜像比 digest；没固定的（例如查不到版本的私有仓库）只看标签。
async fn images(
  state: &AppState,
  snap: &Snapshot,
  only: Option<&BTreeSet<String>>,
) -> (ImageFindings, Tags) {
  // 服务器 → [(服务, 镜像, 固定的版本)]
  let mut by_server: BTreeMap<String, Vec<Item>> = BTreeMap::new();
  for (name, row) in &snap.world.services {
    if !included(only, name, row) {
      continue;
    }
    let Some(server) = snapshot::service_runtime_server(snap, name)
    else {
      continue;
    };
    for image in crate::pins::images(&row.spec.source) {
      if image.contains('@')
        || effective_ignore(&row.spec.update_ignore, &image)
          == Some(UpdateIgnoreScope::All)
      {
        continue;
      }
      let pinned = row.pins.get(&image).cloned();
      by_server.entry(server.to_string()).or_default().push((
        name.clone(),
        image,
        pinned,
      ));
    }
  }
  let mut found = ImageFindings::new();
  let mut tags = Tags::new();
  let jobs = by_server.into_iter().filter_map(|(server, items)| {
    let pull =
      snapshot::pull_policy(snap.world.servers.get(&server)?);
    Some(async move {
      let result: Result<Vec<ResolvedImage>, ApiError> = state
        .hub
        .call(
          &server,
          AgentOp::ResolveImages(ResolveImages {
            images: items
              .iter()
              .map(|i| i.1.clone())
              .collect::<BTreeSet<_>>()
              .into_iter()
              .collect(),
            pull,
            tags: true,
          }),
          RESOLVE_TIMEOUT,
          None,
          &Default::default(),
        )
        .await;
      (items, result)
    })
  });
  for (items, result) in futures_util::future::join_all(jobs).await {
    for (name, image, pinned) in items {
      let hit = result
        .as_ref()
        .ok()
        .and_then(|l| l.iter().find(|r| r.image == image));
      if let Some(hit) = hit {
        let list = tags.entry(name.clone()).or_default();
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
        (Ok(_), Some(d)) => Ok((d, pinned)),
        (Ok(_), None) => Err(
          hit
            .and_then(|r| r.error.clone())
            .unwrap_or_else(|| "agent 没有返回结果".into()),
        ),
      };
      found.entry(name).or_default().insert(image, r);
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
  only: Option<&BTreeSet<String>>,
) -> BTreeMap<String, Found> {
  let mut out = BTreeMap::new();
  let mut jobs = BTreeMap::new();
  for (name, row) in &snap.world.services {
    if !included(only, name, row)
      || ignore_all_source(&row.spec.update_ignore)
    {
      continue;
    }
    let Source::Build(build) = &row.spec.source else {
      continue;
    };
    let (Some(git), Some(pinned), Some(server)) = (
      build.git.as_ref(),
      &row.commit,
      snapshot::service_runtime_server(snap, name),
    ) else {
      continue;
    };
    let Some(server_row) = snap.world.servers.get(server) else {
      continue;
    };
    let fetch = match crate::build::code_fetch(
      state,
      &crate::secret_policy::service_secrets(
        &snap.world,
        name,
        &snap.secrets,
      ),
      &format!("服务 {name}"),
      None,
      Some(git),
      None,
    ) {
      Ok(fetch) => fetch,
      Err(e) => {
        out.insert(name.clone(), Err(e.message));
        continue;
      }
    };
    let key = (
      server.to_string(),
      git.repo.clone(),
      git.reference.clone(),
      git.token_secret.clone(),
      git.user.clone(),
    );
    let (_, services) = jobs.entry(key).or_insert_with(|| {
      (
        ResolveCommit {
          service: name.clone(),
          fetch,
          pull: snapshot::pull_policy(server_row),
        },
        Vec::new(),
      )
    });
    services.push((name.clone(), pinned.clone()));
  }
  let results = stream::iter(jobs)
    .map(|((server, ..), (job, services))| async move {
      let result = state
        .hub
        .call::<String>(
          &server,
          AgentOp::ResolveCommit(job),
          COMMIT_TIMEOUT,
          None,
          &Default::default(),
        )
        .await;
      (services, result.map_err(|e| e.message))
    })
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
  for (services, result) in results {
    out.extend(services.into_iter().map(|(name, pinned)| {
      (name, result.clone().map(|latest| (latest, pinned)))
    }));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn update_check_rejects_read_only_tokens() {
    let state = crate::rules::tests::test_state();
    let auth = crate::host_access::tests::auth([Perm::Read], false);
    let error = check_now(State(state), auth).await.unwrap_err();
    assert_eq!(error.0.code, wharf_api_types::ErrorCode::Forbidden);
  }

  #[tokio::test]
  async fn auto_update_run_updates_then_skips_same_failed_digest() {
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let state = crate::rules::tests::test_state();
    let image = "fixture:latest";
    let [old, good, bad] =
      ["a", "b", "c"].map(|c| format!("sha256:{}", c.repeat(64)));
    let pin = old.clone();
    state
      .db
      .call(move |c| {
        use crate::db::{Write, apply_write};
        apply_write(c, &Write::Upsert {
          kind: "server".into(),
          name: "s1".into(),
          spec: json!({}),
          meta: json!({}),
        })?;
        apply_write(c, &Write::Upsert {
          kind: "service".into(),
          name: "app".into(),
          spec: json!({
            "server": "s1", "source": {"image": image}, "auto_update": true,
            "ports": [{"name": "http", "container": 80}],
          }),
          meta: json!({
            "pins": {image: pin}, "host_ports": {"http": 20000}, "instance_id": "svc_app",
          }),
        })
      })
      .await
      .unwrap();

    let snap = snapshot::load(&state.db).await.unwrap();
    let (compose, mut live_hash) = snapshot::service_resolved(
      &snap.world,
      &snap.net(&snap.world),
      "app",
      &snap.render_values(&snap.world, "app"),
    )
    .unwrap();
    let hash = live_hash.clone();
    let images = json!([{
      "image": image, "id": &old, "digest": format!("fixture@{old}"),
    }])
    .to_string();
    state
      .db
      .call(move |c| {
        c.execute(
          "INSERT INTO deployments (service, server, run_id, hash, compose, images, created_at, instance_id)
           VALUES ('app', 's1', 'r-old', ?1, ?2, ?3, 1, 'svc_app')",
          rusqlite::params![hash, compose, images],
        )
        .map_err(crate::db::sql_err)?;
        Ok(())
      })
      .await
      .unwrap();
    let pushed = Arc::new(AtomicUsize::new(0));
    let published = pushed.clone();
    let digests = [old.clone(), good.clone(), bad.clone()];
    let mut live_digest = old;
    state.hub.mock_agent("s1", false, move |op| {
      let latest = &digests[published.load(Ordering::Relaxed)];
      match op {
        AgentOp::ResolveImages(req) => Ok(json!(
          req.images.iter().map(|image| json!({
            "image": image, "digest": latest, "config": latest,
          })).collect::<Vec<_>>()
        )),
        AgentOp::ProjectStatus { .. } => Ok(json!([{
          "project": "app", "hash": live_hash,
          "containers": [{"name": "app-1", "service": "app", "state": "running"}],
        }])),
        AgentOp::ProjectUp(up) => {
          assert_eq!(&up.pins[image], latest);
          if latest == &digests[2] {
            assert_eq!(live_digest, digests[1]);
            assert!(up.trial.is_some());
            return Err(ApiError::new(wharf_api_types::ErrorCode::AgentFailed, "试跑失败"));
          }
          live_hash = up.hash;
          live_digest = latest.clone();
          Ok(json!({
            "containers": [{"name": "app-1", "service": "app", "state": "running"}],
            "images": [{"image": image, "id": latest, "digest": format!("fixture@{latest}")}],
          }))
        }
        _ => panic!("意外的 agent 请求"),
      }
    });

    let auth = crate::host_access::tests::auth([Perm::Plan], false);
    let Json(before) = check_now(State(state.clone()), auth)
      .await
      .map_err(|e| e.0)
      .unwrap();
    assert!(!before.services["app"].newer);

    for (version, status, digest) in [
      (1, "updated", &good),
      (2, "failed", &bad),
      (2, "skipped", &bad),
    ] {
      pushed.store(version, Ordering::Relaxed);
      let result = crate::auto_update::run(&state).await;
      assert_eq!(
        result.iter().map(|r| r.status.as_str()).collect::<Vec<_>>(),
        [status],
        "{result:?}",
      );
      assert_eq!(result[0].latest.as_ref(), Some(digest));
      if status == "failed" {
        assert_eq!(result[0].reason.as_deref(), Some("试跑失败"));
      } else if status == "skipped" {
        assert_eq!(
          result[0].reason.as_deref(),
          Some("这个版本上次自动更新失败过，等下一个版本"),
        );
      }
    }
  }

  #[test]
  fn multi_image_partial_error_single_update_git_and_stopped() {
    let world = crate::world::World::from_rows(vec![crate::db::ResourceRow {
      kind: "service".into(), name: "web".into(), version: 1,
      spec: serde_json::json!({"server":"s1", "source":{"compose":{"content":"services: {web: {image: app:1}, cache: {image: cache:1}}"}}}),
      meta: serde_json::json!({"pins":{"app:1":"old-a", "cache:1":"old-b"}}),
    }]).unwrap();
    let mut snap = Snapshot {
      world,
      ..Default::default()
    };
    let mut check = VersionCheck {
      newer_images: vec![],
      at: Utc::now(),
      newer: false,
      latest: None,
      tags: vec![],
      error: None,
      images: BTreeMap::from([
        (
          "app:1".into(),
          merge_image(Ok(("new-a".into(), "old-a".into())), None),
        ),
        (
          "cache:1".into(),
          merge_image(
            Err("超时".into()),
            Some(&ImageVersionCheck {
              newer: true,
              latest: Some("new-b".into()),
              error: None,
            }),
          ),
        ),
      ]),
    };
    let row = snap.world.services.get_mut("web").unwrap();
    reconcile(row, &mut check);
    assert_eq!(check.latest.as_deref(), Some("new-a"));
    assert!(check.error.is_some());
    row.pins.insert("app:1".into(), "new-a".into());
    reconcile(row, &mut check);
    assert_eq!(check.latest.as_deref(), Some("new-b"));
    assert!(check.newer && !check.images["app:1"].newer);
    row.spec.source = serde_json::from_value(serde_json::json!({
      "build": {"git":{"repo":"https://git.example.test/team/repo","ref":"main"}}
    })).unwrap();
    row.commit = Some("new-b".into());
    reconcile(row, &mut check);
    assert!(!check.newer);
    row.spec.stopped = true;
    assert!(!included(None, "web", row));
  }
}

#[test]
fn update_ignore_hides_major_and_all_immediately_without_restart() {
  let spec = serde_json::from_value(serde_json::json!({
    "server":"s1","source":{"compose":{"content":"services: {app: {image: 'app:1.0'}, db: {image: 'db:15'}}"}}
  })).unwrap();
  let old = crate::world::ServiceRow {
    instance_id: "svc_fixture".into(),
    spec,
    host_ports: BTreeMap::new(),
    import: None,
    pins: BTreeMap::new(),
    commit: None,
    version: 1,
  };
  let mut row = old.clone();
  row.spec.update_ignore = vec![
    UpdateIgnoreSpec {
      image: "app".into(),
      scope: UpdateIgnoreScope::All,
    },
    UpdateIgnoreSpec {
      image: "db".into(),
      scope: UpdateIgnoreScope::Major,
    },
  ];
  let mut check = VersionCheck {
    at: Utc::now(),
    latest: Some("sha256:test".into()),
    newer: true,
    error: None,
    newer_images: vec!["app:1.0".into(), "db:15".into()],
    images: ["app:1.0", "db:15"]
      .into_iter()
      .map(|name| {
        (
          name.into(),
          ImageVersionCheck {
            newer: true,
            latest: Some("sha256:test".into()),
            error: None,
          },
        )
      })
      .collect(),
    tags: [
      ("app:1.0", "1.1", false),
      ("db:15", "16", true),
      ("db:15", "15.1", false),
    ]
    .into_iter()
    .map(|(image, tag, major)| NewerTag {
      image: image.into(),
      tag: tag.into(),
      major,
    })
    .collect(),
  };
  filter_ignored(&row, &mut check);
  assert!(crate::service_monitor::config_only(&old, &row));
  assert!(check.newer);
  assert_eq!(check.newer_images, ["db:15"]);
  assert_eq!(check.tags.len(), 1);
  assert_eq!(check.tags[0].tag, "15.1");
}

#[test]
fn pinned_and_ignored_images_clear_cached_updates() {
  let row = crate::world::ServiceRow {
    instance_id: "svc_fixture".into(),
    spec: serde_json::from_value(serde_json::json!({
      "server":"s1","source":{"compose":{"content":"services: {app: {image: 'app:1.0'}, db: {image: 'db:15'}}"}},
      "update_ignore":[{"image":"db","scope":"all"}],
    })).unwrap(),
    host_ports: BTreeMap::new(),
    import: None,
    pins: BTreeMap::from([("app:1.0".into(), "sha256:app-new".into())]),
    commit: None,
    version: 1,
  };
  let mut check = VersionCheck {
    at: Utc::now(),
    latest: Some("sha256:db-new".into()),
    newer: true,
    error: None,
    newer_images: vec![],
    images: BTreeMap::from([
      (
        "app:1.0".into(),
        ImageVersionCheck {
          newer: true,
          latest: Some("sha256:app-new".into()),
          error: None,
        },
      ),
      (
        "db:15".into(),
        ImageVersionCheck {
          newer: true,
          latest: Some("sha256:db-new".into()),
          error: None,
        },
      ),
    ]),
    tags: vec![],
  };
  reconcile(&row, &mut check);
  filter_ignored(&row, &mut check);
  assert!(!check.newer);
  assert!(check.newer_images.is_empty());
}
