//! 计划时固定 image 来源服务的镜像版本：没固定过的（新服务、换了镜像、检查更新）
//! 由服务所在机器的 agent 查出标签当前的 digest，执行时按它拉取，不会被中途更新的标签替换。

use std::collections::{BTreeMap, BTreeSet};

use wharf_api_types::{
  ApiError,
  agent::{AgentOp, ResolveCommit, ResolveImages, ResolvedImage},
  spec::Source,
  view::Applied,
};

use crate::{
  snapshot::{self, Snapshot},
  state::AppState,
  world::World,
};

const RESOLVE_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(60);
/// 比 agent 里 `git ls-remote` 的上限长，失败时带回 git 的报错而不是超时。
const COMMIT_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(180);

pub struct Resolved {
  /// 这次查到的镜像 ID：服务 → `sha256:…`，用来判断正在跑的是不是这个版本。
  pub image_ids: BTreeMap<String, String>,
  pub warnings: Vec<String>,
}

/// 给还没固定版本的 image 来源服务定版本。`refresh` 是这次要检查更新的服务。
/// 部署过、镜像没换的：固定到正在跑的版本，不会因为补查版本而升级；
/// 正在跑的版本查不清又不是最新的，不固定，提醒用户检查更新。
pub async fn resolve(
  state: &AppState,
  applied: &BTreeMap<String, Applied>,
  desired: &mut World,
  refresh: &BTreeSet<String>,
) -> Result<Resolved, ApiError> {
  let mut out = Resolved {
    image_ids: BTreeMap::new(),
    warnings: Vec::new(),
  };
  // 服务器 → [(服务, 镜像)]
  let mut todo: BTreeMap<String, Vec<(String, String)>> =
    BTreeMap::new();
  for (name, row) in desired.services.iter_mut() {
    let Source::Image(image) = &row.spec.source else {
      continue;
    };
    if row.pins.contains_key(image) {
      continue;
    }
    let same = applied
      .get(name)
      .filter(|a| a.image.as_deref() == Some(image.as_str()));
    if !refresh.contains(name)
      && let Some(digest) = same.and_then(|a| a.digest.clone())
    {
      row.pins.insert(image.clone(), digest);
      continue;
    }
    todo
      .entry(row.spec.server.clone())
      .or_default()
      .push((name.clone(), image.clone()));
  }
  for (server, items) in todo {
    let images = items.iter().map(|(_, i)| i.clone()).collect();
    let resolved: Vec<ResolvedImage> = state
      .hub
      .call(
        &server,
        AgentOp::ResolveImages(ResolveImages {
          images,
          pull: snapshot::pull_policy(&desired.servers[&server]),
        }),
        RESOLVE_TIMEOUT,
        None,
        &Default::default(),
      )
      .await
      .map_err(|e| {
        e.with_hint("确认这台机器的 agent 在线并已升级；查不到镜像版本就没法固定要部署的版本")
      })?;
    for (name, image) in items {
      let found = resolved.iter().find(|r| r.image == image);
      let digest =
        found.and_then(|r| r.digest.clone()).ok_or_else(|| {
          let why = found
            .and_then(|r| r.error.clone())
            .unwrap_or_else(|| "agent 没有返回结果".into());
          ApiError::invalid(format!(
            "查不到服务 {name} 的镜像 {image} 现在的版本：{why}"
          ))
          .with_hint(
            "镜像名写错了，或者仓库暂时连不上；稍后重新 plan",
          )
        })?;
      let config = found.and_then(|r| r.config.clone());
      let running = applied
        .get(&name)
        .filter(|a| a.image.as_deref() == Some(image.as_str()));
      if !refresh.contains(&name)
        && let Some(a) = running
        && (config.is_none() || a.image_id != config)
      {
        out.warnings.push(format!(
          "服务 {name} 正在跑的镜像不是仓库里 {image} 的最新版本，这次不固定版本；要更新执行 wharf service update {name}"
        ));
        continue;
      }
      if let Some(config) = config {
        out.image_ids.insert(name.clone(), config);
      }
      if let Some(row) = desired.services.get_mut(&name) {
        row.pins.insert(image, digest);
      }
    }
  }
  Ok(out)
}

/// git 构建来源固定 commit，规则和镜像一样：部署过、仓库分支没换的，固定到当时构建的 commit；
/// 当时没记下 commit 的不固定，提醒检查更新；其余由构建机的 agent 查分支现在的 commit。
pub async fn resolve_commits(
  state: &AppState,
  snap: &Snapshot,
  desired: &mut World,
  refresh: &BTreeSet<String>,
  warnings: &mut Vec<String>,
) -> Result<(), ApiError> {
  let mut todo = Vec::new();
  for (name, row) in desired.services.iter_mut() {
    let Some(git) = crate::world::git_ref(&row.spec) else {
      continue;
    };
    if row.commit.is_some() {
      continue;
    }
    let same = snap
      .applied
      .get(name)
      .filter(|a| a.git.as_deref() == Some(git.as_str()));
    if !refresh.contains(name)
      && let Some(a) = same
    {
      match &a.commit {
        Some(c) => row.commit = Some(c.clone()),
        None => warnings.push(format!(
          "服务 {name} 部署时没有记下 commit，这次不固定代码版本；要按最新代码构建执行 wharf service update {name}"
        )),
      }
      continue;
    }
    todo.push(name.clone());
  }
  for name in todo {
    let row = &desired.services[&name];
    let Source::Build(build) = &row.spec.source else {
      continue;
    };
    let server = row.spec.server.clone();
    let fetch = crate::build::code_fetch(
      state,
      snap,
      &format!("服务 {name}"),
      None,
      build.git.as_ref(),
      None,
    )?;
    let commit: String = state
      .hub
      .call(
        &server,
        AgentOp::ResolveCommit(ResolveCommit {
          service: name.clone(),
          fetch,
          pull: snapshot::pull_policy(&desired.servers[&server]),
        }),
        COMMIT_TIMEOUT,
        None,
        &Default::default(),
      )
      .await
      .map_err(|e| {
        ApiError::new(
          e.code,
          format!("查不到服务 {name} 的代码版本：{}", e.message),
        )
        .with_hint(
          "确认仓库地址、分支和 token；仓库暂时连不上时稍后重新 plan",
        )
      })?;
    if let Some(row) = desired.services.get_mut(&name) {
      row.commit = Some(commit);
    }
  }
  Ok(())
}

/// git 构建来源要换代码：(上次部署的，看得懂的写法, 这次固定的)。
pub fn commit_change(
  applied: Option<&Applied>,
  commit: Option<&str>,
) -> Option<(String, String)> {
  let new = commit?;
  let applied = applied?;
  match &applied.commit {
    Some(old) if old != new => {
      Some((old[..old.len().min(12)].to_string(), new.to_string()))
    }
    None => Some(("当前版本未知".into(), new.to_string())),
    _ => None,
  }
}

/// image 来源的服务要换镜像版本：(上次部署的，看得懂的写法, 这次固定的)。
/// 部署记录里没有 digest 时（经镜像源拉取的旧部署），用这次查到的镜像 ID 和部署时的比。
pub fn change(
  applied: Option<&Applied>,
  pins: &BTreeMap<String, String>,
  config: Option<&str>,
) -> Option<(String, String)> {
  let new = pins.values().next()?;
  let applied = applied?;
  match (&applied.digest, config) {
    (Some(old), _) if old != new => {
      Some((short(old).into(), new.clone()))
    }
    (None, Some(config))
      if applied.image_id.as_deref() != Some(config) =>
    {
      Some(("当前版本未知".into(), new.clone()))
    }
    _ => None,
  }
}

/// `sha256:` 后面取前 12 位，计划里看得清。
pub fn short(digest: &str) -> &str {
  let d = digest.trim_start_matches("sha256:");
  &d[..d.len().min(12)]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn compares_digest_or_image_id() {
    let pins =
      BTreeMap::from([("x:latest".into(), "sha256:new".into())]);
    let applied = |digest: Option<&str>| Applied {
      hash: "h".into(),
      at: Default::default(),
      digest: digest.map(str::to_string),
      image: Some("x:latest".into()),
      image_id: Some("sha256:id1".into()),
      commit: None,
      git: None,
    };
    assert_eq!(
      change(Some(&applied(Some("sha256:new"))), &pins, None),
      None
    );
    assert_eq!(
      change(Some(&applied(Some("sha256:old"))), &pins, None),
      Some(("old".into(), "sha256:new".into()))
    );
    // 部署记录里没有 digest：查到的镜像 ID 和部署时的一样，就是同一个版本。
    assert_eq!(
      change(Some(&applied(None)), &pins, Some("sha256:id1")),
      None
    );
    assert_eq!(
      change(Some(&applied(None)), &pins, Some("sha256:id2")),
      Some(("当前版本未知".into(), "sha256:new".into()))
    );
    assert_eq!(change(Some(&applied(None)), &pins, None), None);
  }
}
