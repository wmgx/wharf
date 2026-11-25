//! 计划时固定镜像版本（image 来源和 compose 里的各个镜像）：没固定过的（新服务、换了镜像、检查更新）
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
  /// 这次查到的镜像 ID：服务 → 镜像 → `sha256:…`，用来判断正在跑的是不是这个版本。
  pub image_ids: BTreeMap<String, BTreeMap<String, String>>,
  pub warnings: Vec<String>,
}

struct ImageLookup {
  service: String,
  image: String,
  reference: String,
}

/// 服务里能固定版本、能检查更新的镜像（compose 里写的名字）：image 来源就是那个镜像；
/// compose 来源是各组件的 `image`，跳过写了 digest、用了 `${变量}`、或者本地构建（有 `build`）的。
pub fn images(source: &Source) -> Vec<String> {
  let content = match source {
    Source::Image(image) => return vec![image.clone()],
    Source::Compose { content, .. } => {
      content.as_deref().unwrap_or_default()
    }
    Source::Build(_) => return vec![],
  };
  let Ok(compose) =
    serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content)
  else {
    return vec![];
  };
  let mut out: Vec<String> = compose["services"]
    .as_mapping()
    .into_iter()
    .flat_map(|m| m.values())
    .filter(|svc| svc.get("build").is_none())
    .filter_map(|svc| svc["image"].as_str())
    .map(str::trim)
    .filter(|i| !i.is_empty() && !i.contains('@') && !i.contains('$'))
    .map(str::to_string)
    .collect();
  out.sort();
  out.dedup();
  out
}

/// 为什么这个服务没法检查更新；能检查时为空。
pub fn unsupported(source: &Source) -> Option<&'static str> {
  match source {
    Source::Compose { .. } if images(source).is_empty() => Some(
      "compose 里的镜像都写了 digest、用了变量或在本地构建，没有可以检查的标签",
    ),
    Source::Build(b) if b.git.is_none() => {
      Some("从本机目录构建的服务没有远端版本，要更新请重新上传代码包")
    }
    _ => None,
  }
}

/// 计划里要检查更新的范围：整个服务是服务名，单个镜像是 `服务名\n镜像`。
pub fn refresh_key(name: &str, image: Option<&str>) -> String {
  image.map_or_else(|| name.to_string(), |i| format!("{name}\n{i}"))
}

fn refreshing(
  refresh: &BTreeSet<String>,
  name: &str,
  image: &str,
) -> bool {
  refresh.contains(name)
    || refresh.contains(&refresh_key(name, Some(image)))
}

/// 上次部署时这个镜像的 (digest, 镜像 ID)。
fn running(
  a: &Applied,
  image: &str,
) -> (Option<String>, Option<String>) {
  let old = a.image.as_deref() == Some(image);
  (
    a.digests
      .get(image)
      .cloned()
      .or_else(|| a.digest.clone().filter(|_| old)),
    a.image_ids
      .get(image)
      .cloned()
      .or_else(|| a.image_id.clone().filter(|_| old)),
  )
}

fn needs_migration_check<'a>(
  previous: Option<&str>,
  target: &str,
  arch: impl Fn(&str) -> Option<&'a str>,
) -> bool {
  previous.is_some_and(|old| {
    old != target
      && arch(old)
        .zip(arch(target))
        .is_none_or(|(old, new)| old != new)
  })
}

fn pinned_reference(image: &str, digest: &str) -> String {
  let name = image.split_once('@').map_or(image, |(name, _)| name);
  let tag_start = name.rfind('/').map_or(0, |i| i + 1);
  let name = name
    .rfind(':')
    .filter(|i| *i >= tag_start)
    .map_or(name, |i| &name[..i]);
  format!("{name}@{digest}")
}

fn platform_warning(
  name: &str,
  image: &str,
  server: &str,
  found: &ResolvedImage,
) -> Option<String> {
  let platforms = found.platforms.as_ref()?;
  let host = found.host_platform.as_deref()?;
  if platforms.is_empty() || platforms.iter().any(|p| p == host) {
    return None;
  }
  Some(format!(
    "服务 {name} 的镜像 {image} 只有 {}，服务器 {server} 是 {host}，部署后可能拉取失败或起不来",
    platforms.join("、")
  ))
}

fn registry_hint(why: &str) -> Option<&'static str> {
  // agent 按镜像源和原仓库的尝试顺序返回错误，优先采用末尾可分类的原因。
  why.rsplit('；').find_map(|error| {
    let status = error
      .split_once("HTTP status client error (")
      .or_else(|| error.split_once("HTTP "))
      .and_then(|(_, rest)| rest.split([' ', ')']).next())
      .or_else(|| {
        (error.contains("仓库要求登录")
          || error.contains("仓库的认证信息不完整"))
        .then_some("401")
      });
    match status {
      Some("401" | "403") => {
        Some("私有仓库需要登录，请在目标服务器登录镜像仓库")
      }
      Some("404") => Some("镜像或标签不存在，请检查镜像名和标签"),
      Some("429") => {
        Some("Docker Hub 可能触发限流，请更换镜像源或登录")
      }
      _ => None,
    }
  })
}

/// 给还没固定版本的镜像定版本。`refresh` 是这次要检查更新的服务。
/// 部署过、镜像没换的：固定到正在跑的版本，不会因为补查版本而升级；
/// 正在跑的版本查不清又不是最新的，不固定，提醒用户检查更新。
/// compose 来源查不到时（例如要登录的私有仓库）只提醒，照旧按标签拉取。
pub async fn resolve(
  state: &AppState,
  snap: &Snapshot,
  desired: &mut World,
  refresh: &BTreeSet<String>,
  check_migrated_images: bool,
) -> Result<Resolved, ApiError> {
  let mut out = Resolved {
    image_ids: BTreeMap::new(),
    warnings: Vec::new(),
  };
  let applied = &snap.applied;
  let arch = |server: &str| {
    snap
      .agent(server)
      .and_then(|agent| agent.report.as_ref())
      .map(|report| report.arch.trim())
      .filter(|arch| !arch.is_empty() && *arch != "unknown")
  };
  // 平台补查和定版本分开调用，补查超时不影响同一台机器上的定版本。
  let mut todo: BTreeMap<(String, bool), Vec<ImageLookup>> =
    BTreeMap::new();
  for (name, row) in desired.services.iter_mut() {
    // 导入时按本机已有的镜像启动，不查仓库里的最新版本；部署后记下实际的版本。
    if row.import.is_some() && !applied.contains_key(name) {
      continue;
    }
    let check_platform = check_migrated_images
      && needs_migration_check(
        snap.deployed.get(name).map(String::as_str),
        &row.spec.server,
        arch,
      );
    for image in images(&row.spec.source) {
      let pinned = if refreshing(refresh, name, &image) {
        None
      } else {
        if !row.pins.contains_key(&image)
          && let Some(digest) =
            applied.get(name).and_then(|a| running(a, &image).0)
        {
          row.pins.insert(image.clone(), digest);
        }
        match row.pins.get(&image) {
          Some(digest) if check_platform => {
            Some(pinned_reference(&image, digest))
          }
          Some(_) => continue,
          None => None,
        }
      };
      todo
        .entry((row.spec.server.clone(), pinned.is_some()))
        .or_default()
        .push(ImageLookup {
          service: name.clone(),
          reference: pinned.unwrap_or_else(|| image.clone()),
          image,
        });
    }
  }
  // 各台机器同时查，一台慢不拖累别的。
  let calls =
    todo.into_iter().map(|((server, platform_only), items)| {
      let pull = snapshot::pull_policy(&desired.servers[&server]);
      async move {
        let images = items
          .iter()
          .map(|item| item.reference.clone())
          .collect::<BTreeSet<_>>()
          .into_iter()
          .collect();
        let resolved: Result<Vec<ResolvedImage>, ApiError> = state
          .hub
          .call(
            &server,
            AgentOp::ResolveImages(ResolveImages {
              images,
              pull,
              tags: false,
            }),
            RESOLVE_TIMEOUT,
            None,
            &Default::default(),
          )
          .await;
        (server, platform_only, items, resolved)
      }
    });
  for (server, platform_only, items, resolved) in
    futures_util::future::join_all(calls).await
  {
    if platform_only && resolved.is_err() {
      continue;
    }
    let resolved = resolved.map_err(|e| {
      e.with_hint("确认这台机器的 agent 在线并已升级；查不到镜像版本就没法固定要部署的版本")
    })?;
    for ImageLookup {
      service: name,
      image,
      reference,
    } in items
    {
      let found = resolved.iter().find(|r| r.image == reference);
      if let Some(warning) = found
        .and_then(|f| platform_warning(&name, &image, &server, f))
      {
        out.warnings.push(warning);
      }
      if platform_only {
        continue;
      }
      let compose = matches!(
        desired.services.get(&name).map(|r| &r.spec.source),
        Some(Source::Compose { .. })
      );
      let digest = match found.and_then(|r| r.digest.clone()) {
        Some(d) => d,
        None => {
          let why = found
            .and_then(|r| r.error.clone())
            .unwrap_or_else(|| "agent 没有返回结果".into());
          let hint = registry_hint(&why);
          if compose {
            let why = match hint {
              Some(hint) => format!("{why}（{hint}）"),
              None => why,
            };
            out.warnings.push(format!(
              "查不到服务 {name} 的镜像 {image} 现在的版本，这次不固定、照旧按标签拉取：{why}"
            ));
            continue;
          }
          return Err(
            ApiError::invalid(format!(
              "查不到服务 {name} 的镜像 {image} 现在的版本：{why}"
            ))
            .with_hint(hint.unwrap_or(
              "镜像名写错了，或者仓库暂时连不上；稍后重新 plan",
            )),
          );
        }
      };
      let config = found.and_then(|r| r.config.clone());
      let deployed = applied
        .get(&name)
        .filter(|_| !refreshing(refresh, &name, &image))
        .filter(|a| {
          a.digests.contains_key(&image)
            || a.image_ids.contains_key(&image)
            || a.image.as_deref() == Some(image.as_str())
        });
      if let Some(a) = deployed
        && (config.is_none() || running(a, &image).1 != config)
      {
        out.warnings.push(format!(
          "服务 {name} 正在跑的镜像 {image} 不是仓库里的最新版本，这次不固定版本；要更新执行 wharf service update {name}"
        ));
        continue;
      }
      if let Some(config) = config {
        out
          .image_ids
          .entry(name.clone())
          .or_default()
          .insert(image.clone(), config);
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

/// 服务要换镜像版本：(哪个镜像, 上次部署的，看得懂的写法, 这次固定的)，只报第一个变了的。
/// 部署记录里没有 digest 时（经镜像源拉取的旧部署），用这次查到的镜像 ID 和部署时的比。
pub fn change(
  applied: Option<&Applied>,
  pins: &BTreeMap<String, String>,
  configs: Option<&BTreeMap<String, String>>,
) -> Option<(String, String, String)> {
  let applied = applied?;
  pins.iter().find_map(|(image, new)| {
    let (digest, id) = running(applied, image);
    let config = configs.and_then(|c| c.get(image));
    let old = match (digest, config) {
      (Some(old), _) if old != *new => short(&old).to_string(),
      (None, Some(config)) if id.as_ref() != Some(config) => {
        "当前版本未知".into()
      }
      _ => return None,
    };
    Some((image.clone(), old, new.clone()))
  })
}

/// 把镜像换成同一仓库的另一个标签：`halo/halo:2.20` + `2.21` → `halo/halo:2.21`。
pub fn with_tag(image: &str, tag: &str) -> Result<String, ApiError> {
  let bad = |m: &str| {
    ApiError::invalid(m.to_string()).with_hint(
      "标签只能有字母、数字和 . _ -，例如 2.21；看可用的标签：wharf service show <服务>",
    )
  };
  if tag.is_empty()
    || !tag.chars().all(|c| {
      c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
    })
  {
    return Err(bad(&format!("标签 {tag} 不合法")));
  }
  if image.contains('@') {
    return Err(bad(&format!(
      "镜像 {image} 写的是 digest，没有标签可换"
    )));
  }
  let slash = image.rfind('/').map_or(0, |i| i + 1);
  let name = match image[slash..].find(':') {
    Some(i) => &image[..slash + i],
    None => image,
  };
  Ok(format!("{name}:{tag}"))
}

/// 服务换标签后的来源：image 来源直接换；compose 来源只改值和 `image` 一字不差的 `image:` 行，
/// 其余内容（注释、引号、缩进）不动。
pub fn retag(
  source: &Source,
  image: &str,
  tag: &str,
) -> Result<Source, ApiError> {
  let new = with_tag(image, tag)?;
  let missing = || {
    ApiError::invalid(format!("服务里没有镜像 {image}"))
      .suggest("wharf service show <服务>")
  };
  match source {
    Source::Image(i) if i == image => Ok(Source::Image(new)),
    Source::Compose {
      content: Some(content),
      file,
    } => {
      let mut hit = false;
      let lines: Vec<String> = content
        .split_inclusive('\n')
        .map(|line| {
          let body = line.trim_end_matches(['\n', '\r']);
          let indent = &body[..body.len() - body.trim_start().len()];
          let Some(value) = body.trim_start().strip_prefix("image:")
          else {
            return line.to_string();
          };
          let (value, comment) = match value.find(" #") {
            Some(i) => (&value[..i], &value[i..]),
            None => (value, ""),
          };
          let quote = value
            .trim()
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\''));
          let bare = value.trim().trim_matches(['"', '\'']);
          if bare != image {
            return line.to_string();
          }
          hit = true;
          let q = quote.map(String::from).unwrap_or_default();
          let end = &line[body.len()..];
          format!("{indent}image: {q}{new}{q}{comment}{end}")
        })
        .collect();
      if !hit {
        return Err(missing());
      }
      Ok(Source::Compose {
        content: Some(lines.concat()),
        file: file.clone(),
      })
    }
    _ => Err(missing()),
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
  fn warns_only_for_known_platform_mismatch() {
    let mut found: ResolvedImage = serde_json::from_value(
      serde_json::json!({ "image": "nginx:1" }),
    )
    .unwrap();
    found.host_platform = Some("linux/arm64".into());
    found.platforms = Some(vec!["linux/amd64".into()]);
    let warning = |found: &ResolvedImage| {
      platform_warning("web", "nginx:1", "edge", found)
    };
    assert_eq!(
      warning(&found).as_deref(),
      Some(
        "服务 web 的镜像 nginx:1 只有 linux/amd64，服务器 edge 是 linux/arm64，部署后可能拉取失败或起不来"
      )
    );
    found.platforms.as_mut().unwrap().push("linux/arm64".into());
    assert_eq!(warning(&found), None);
    found.platforms = None;
    assert_eq!(warning(&found), None);
  }

  #[test]
  fn checks_pinned_images_only_for_possible_cross_arch_migration() {
    let arch = |server: &str| match server {
      "old" | "same-arch" => Some("x86_64"),
      "new" => Some("aarch64"),
      _ => None,
    };
    assert!(needs_migration_check(Some("old"), "new", arch));
    assert!(needs_migration_check(Some("old"), "unknown", arch));
    assert!(!needs_migration_check(Some("old"), "old", arch));
    assert!(!needs_migration_check(Some("old"), "same-arch", arch));
    assert_eq!(
      pinned_reference("registry:5000/team/app:v1", "sha256:abc"),
      "registry:5000/team/app@sha256:abc"
    );
  }

  #[test]
  fn classifies_registry_lookup_errors() {
    assert_eq!(
      registry_hint(
        "registry.example：取 token 失败：HTTP status client error (401 Unauthorized)"
      ),
      Some("私有仓库需要登录，请在目标服务器登录镜像仓库")
    );
    assert_eq!(
      registry_hint("registry.example：HTTP 404 Not Found"),
      Some("镜像或标签不存在，请检查镜像名和标签")
    );
    assert_eq!(
      registry_hint(
        "mirror.example：连接失败；registry-1.docker.io：HTTP 429 Too Many Requests"
      ),
      Some("Docker Hub 可能触发限流，请更换镜像源或登录")
    );
  }

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
      digests: Default::default(),
      image_ids: Default::default(),
      commit: None,
      git: None,
      spec: None,
    };
    let id =
      |v: &str| BTreeMap::from([("x:latest".into(), v.into())]);
    assert_eq!(
      change(Some(&applied(Some("sha256:new"))), &pins, None),
      None
    );
    assert_eq!(
      change(Some(&applied(Some("sha256:old"))), &pins, None),
      Some(("x:latest".into(), "old".into(), "sha256:new".into()))
    );
    // 部署记录里没有 digest：查到的镜像 ID 和部署时的一样，就是同一个版本。
    assert_eq!(
      change(Some(&applied(None)), &pins, Some(&id("sha256:id1"))),
      None
    );
    assert_eq!(
      change(Some(&applied(None)), &pins, Some(&id("sha256:id2"))),
      Some((
        "x:latest".into(),
        "当前版本未知".into(),
        "sha256:new".into()
      ))
    );
    assert_eq!(change(Some(&applied(None)), &pins, None), None);
    // compose：按镜像比，只报变了的那个。
    let compose = Applied {
      digests: BTreeMap::from([
        ("db:8".into(), "sha256:db".into()),
        ("app:2".into(), "sha256:a1".into()),
      ]),
      ..applied(None)
    };
    let pins = BTreeMap::from([
      ("db:8".into(), "sha256:db".into()),
      ("app:2".into(), "sha256:a2".into()),
    ]);
    assert_eq!(
      change(Some(&compose), &pins, None),
      Some(("app:2".into(), "a1".into(), "sha256:a2".into()))
    );
  }

  #[test]
  fn compose_images() {
    let source = Source::Compose {
      content: Some(
        "services:\n  db:\n    image: mysql:8.0.36\n  app:\n    image: \"halo/halo:2.20\"\n  x:\n    image: a@sha256:1\n  y:\n    image: ${IMG}\n  z:\n    build: .\n    image: local:1\n"
          .into(),
      ),
      file: None,
    };
    assert_eq!(
      images(&source),
      vec!["halo/halo:2.20", "mysql:8.0.36"]
    );
    let Source::Compose {
      content: Some(c), ..
    } = retag(&source, "halo/halo:2.20", "2.21").unwrap()
    else {
      panic!()
    };
    assert!(c.contains("    image: \"halo/halo:2.21\"\n"));
    assert!(c.contains("image: mysql:8.0.36\n"));
    assert!(retag(&source, "nope:1", "2").is_err());
    assert_eq!(
      with_tag("reg.io:5000/a/b:1", "2").unwrap(),
      "reg.io:5000/a/b:2"
    );
    assert_eq!(with_tag("nginx", "1.27").unwrap(), "nginx:1.27");
  }
}
