use super::{CORE, entry, reserved, valid};
use crate::{
  docker::{Docker, parse_bind_mounts},
  exec::Ctx,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path, time::Duration};
use wharf_api_types::{
  ApiError,
  agent::{
    AgentCleanupEntry, BUILD_IMAGE_PREFIX, BindMountUser,
    CleanupKind::*, TASK_DATA_PREFIX,
  },
};

pub(super) const PROJECT: &str = "com.docker.compose.project";

type Labels = BTreeMap<String, String>;

#[derive(Deserialize)]
pub(super) struct Container(
  String,
  pub(super) String,
  pub(super) String,
  DateTime<Utc>,
  String,
  pub(super) Option<Labels>,
  Option<Vec<Mount>>,
  Option<BTreeMap<String, serde_json::Value>>,
);

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
  #[serde(rename = "Type")]
  kind: String,
  #[serde(default)]
  name: String,
}

#[derive(Deserialize)]
struct Image(
  String,
  Option<Vec<String>>,
  Option<Vec<String>>,
  i64,
  DateTime<Utc>,
  Option<Labels>,
);

#[derive(Deserialize)]
struct Network(
  String,
  String,
  Option<Labels>,
  Option<BTreeMap<String, serde_json::Value>>,
);

#[derive(Deserialize)]
struct Volume(String, Option<Labels>);

#[derive(Default)]
pub(super) struct Runtime {
  pub(super) containers: Vec<Container>,
  pub(super) binds: Vec<BindMountUser>,
  volumes: Vec<Volume>,
  networks: Vec<Network>,
  images: Vec<Image>,
}

async fn docker_output(
  docker: &Docker,
  args: &[&str],
  ctx: &Ctx,
) -> Result<String, ApiError> {
  Ok(
    docker
      .cmd()
      .args(args.iter().copied())
      .timeout(Duration::from_secs(25))
      .run(ctx)
      .await?
      .check("读取 Docker 清单")?
      .stdout,
  )
}

fn decode_rows<T: serde::de::DeserializeOwned>(
  output: &str,
) -> Result<Vec<T>, ApiError> {
  output
    .lines()
    .map(|line| {
      serde_json::from_str(line).map_err(|_| {
        ApiError::internal("Docker 返回的清理清单不完整")
      })
    })
    .collect()
}

async fn inspect(
  docker: &Docker,
  kind: &str,
  list: &str,
  format: &str,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  let mut ids: Vec<_> = list.split_whitespace().collect();
  ids.sort_unstable();
  ids.dedup();
  if ids.is_empty() {
    return Ok(String::new());
  }
  let mut args = vec![kind, "inspect", "--format", format, "--"];
  args.extend(ids.iter().copied());
  let out = docker_output(docker, &args, ctx).await?;
  if out.lines().count() != ids.len() {
    return Err(ApiError::internal("Docker 返回的清理清单不完整"));
  }
  Ok(out)
}

pub(super) async fn containers(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Runtime, ApiError> {
  let ids =
    docker_output(docker, &["ps", "-aq", "--no-trunc"], ctx).await?;
  let out = inspect(docker, "container", &ids,
    r#"{{json .Name}} {{json (index .Config.Labels "wharf.system")}} {{json (index .Config.Labels "com.docker.compose.project")}} {{json .Mounts}}	[{{json .Id}},{{json .Name}},{{json .State.Status}},{{json .Created}},{{json .Image}},{{json .Config.Labels}},{{json .Mounts}},{{json .NetworkSettings.Networks}}]"#, ctx).await?;
  let mut bind_rows = String::new();
  let mut rows = String::new();
  for line in out.lines() {
    let (binds, row) = line
      .rsplit_once("|[")
      .ok_or_else(|| ApiError::internal("Docker 容器清单不完整"))?;
    bind_rows.push_str(binds);
    bind_rows.push('\n');
    rows.push('[');
    rows.push_str(row);
    rows.push('\n');
  }
  Ok(Runtime {
    binds: parse_bind_mounts(&bind_rows)?,
    containers: decode_rows(&rows)?,
    ..Default::default()
  })
}

pub(super) async fn runtime(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Runtime, ApiError> {
  let (mut current, volumes, networks, images) = tokio::try_join!(
    containers(docker, ctx),
    docker_output(docker, &["volume", "ls", "-q"], ctx),
    docker_output(
      docker,
      &[
        "network",
        "ls",
        "-q",
        "--no-trunc",
        "--filter",
        "type=custom"
      ],
      ctx
    ),
    docker_output(docker, &["image", "ls", "-aq", "--no-trunc"], ctx),
  )?;
  let (volumes, networks, images) = tokio::try_join!(
    inspect(
      docker,
      "volume",
      &volumes,
      r#"[{{json .Name}},{{json .Labels}}]"#,
      ctx
    ),
    inspect(
      docker,
      "network",
      &networks,
      r#"[{{json .Id}},{{json .Name}},{{json .Labels}},{{json .Containers}}]"#,
      ctx
    ),
    inspect(
      docker,
      "image",
      &images,
      r#"[{{json .Id}},{{json .RepoTags}},{{json .RepoDigests}},{{json .Size}},{{json .Created}},{{json .Config.Labels}}]"#,
      ctx
    ),
  )?;
  current.volumes = decode_rows(&volumes)?;
  current.networks = decode_rows(&networks)?;
  current.images = decode_rows(&images)?;
  Ok(current)
}

pub(super) fn label<'a>(
  labels: &'a Option<Labels>,
  key: &str,
) -> Option<&'a str> {
  labels
    .as_ref()?
    .get(key)
    .map(String::as_str)
    .filter(|s| !s.is_empty())
}

pub(super) fn docker_entries(
  current: &Runtime,
  docker: &Docker,
  now: DateTime<Utc>,
) -> Vec<AgentCleanupEntry> {
  let mut entries = Vec::new();
  for Container(id, name, state, created, _, labels, _, _) in
    &current.containers
  {
    let project = label(labels, PROJECT);
    if project.is_some_and(reserved)
      || label(labels, "wharf.system").is_some()
    {
      continue;
    }
    let task = project.and_then(|p| p.strip_prefix(TASK_DATA_PREFIX));
    let restic = label(labels, "wharf.restic.service");
    let ephemeral = task.is_some()
      || restic.is_some()
      || label(labels, "wharf.temp") == Some("1");
    let stopped =
      matches!(state.as_str(), "exited" | "dead" | "created");
    let owned = project.is_some_and(|p| {
      valid(p)
        && (label(labels, "com.docker.compose.project.working_dir")
          .is_some_and(|dir| Path::new(dir) == docker.project_dir(p))
          || label(labels, "wharf.service") == Some(p))
    });
    if if ephemeral {
      stopped
        && now.signed_duration_since(*created).num_minutes() >= 10
    } else {
      owned
    } {
      let mut item =
        entry(OrphanContainer, restic.or(project), id.clone());
      item.display = name.trim_start_matches('/').to_string();
      item.created_at = Some(created.timestamp_millis());
      if !stopped {
        item.blocked_by.push(item.display.clone());
      }
      item.is_core = restic == Some(CORE);
      entries.push(item);
    }
  }
  for Volume(name, labels) in &current.volumes {
    let owner = label(labels, PROJECT)
      .or_else(|| label(labels, "wharf.service"));
    if owner.is_some_and(reserved)
      || current.containers.iter().any(|c| {
        c.6
          .iter()
          .flatten()
          .any(|m| m.kind == "volume" && &m.name == name)
      })
    {
      continue;
    }
    let mut item = entry(OrphanVolume, owner, name.clone());
    item.unlabeled = owner.is_none();
    entries.push(item);
  }
  for Network(id, name, labels, endpoints) in &current.networks {
    let owner = label(labels, PROJECT)
      .or_else(|| label(labels, "wharf.service"))
      .or_else(|| label(labels, "wharf.gateway"));
    if owner.is_some_and(reserved)
      || matches!(
        name.as_str(),
        "bridge" | "host" | "none" | "ingress" | "docker_gwbridge"
      )
      || (owner.is_none()
        && !labels
          .iter()
          .flat_map(|l| l.keys())
          .any(|k| k.starts_with("wharf.")))
      || endpoints.as_ref().is_some_and(|e| !e.is_empty())
      || current.containers.iter().any(|c| {
        c.7
          .as_ref()
          .is_some_and(|networks| networks.contains_key(name))
      })
    {
      continue;
    }
    let mut item = entry(OrphanNetwork, owner, id.clone());
    item.display = name.clone();
    entries.push(item);
  }
  for Image(id, tags, digests, size, created, labels) in
    &current.images
  {
    if current.containers.iter().any(|c| &c.4 == id) {
      continue;
    }
    let tags = tags.as_deref().unwrap_or_default();
    let owner = label(labels, "wharf.service").or_else(|| {
      tags
        .first()?
        .split_once(':')?
        .0
        .strip_prefix(BUILD_IMAGE_PREFIX)
        .or_else(|| {
          tags[0].split_once(':')?.0.strip_prefix("wharf-build-")
        })
    });
    if (tags.is_empty()
      && owner.is_none()
      && digests.as_ref().is_some_and(|digests| !digests.is_empty()))
      || (!tags.is_empty()
        && !owner.is_some_and(|owner| {
          valid(owner)
            && tags.iter().all(|tag| {
              tag
                .starts_with(&format!("{BUILD_IMAGE_PREFIX}{owner}:"))
                || tag.starts_with(&format!("wharf-build-{owner}:"))
            })
        }))
    {
      continue;
    }
    let mut item = entry(OrphanImage, owner, id.clone());
    item.display =
      tags.first().cloned().unwrap_or_else(|| id.clone());
    item.size_bytes = u64::try_from(*size).ok();
    item.created_at = Some(created.timestamp_millis());
    entries.push(item);
  }
  entries
}

#[test]
fn orphan_docker_resources_skip_in_use_and_third_party() {
  use serde_json::json;
  let (_temp, docker) = crate::docker::fake_docker("exit 0");
  let now = Utc::now();
  let created = now - chrono::Duration::minutes(30);
  let current = Runtime {
    containers: vec![
      serde_json::from_value(json!(["temp","/temp","exited",created,"used",{"wharf.temp":"1"},[],{}])).unwrap(),
      serde_json::from_value(json!(["third","/third","exited",created,"used",{},[{"Type":"volume","Name":"used-vol"}],{"used-net":{}}])).unwrap(),
    ],
    volumes: vec![Volume("used-vol".into(), None), Volume("free-vol".into(), Some(Labels::from([(PROJECT.into(), "old".into())])))],
    networks: vec![
      Network("unmanaged".into(), "unmanaged".into(), None, None),
      Network("used".into(), "used-net".into(), Some(Labels::from([(PROJECT.into(), "old".into())])), None),
      Network("empty".into(), "empty".into(), Some(Labels::from([(PROJECT.into(), "old".into())])), None),
    ],
    images: vec![
      Image("used".into(), None, None, 2, created, None),
      Image("old".into(), Some(vec!["wharf-build/old:1".into()]), None, 2, created, None),
    ],
    ..Default::default()
  };
  let entries = docker_entries(&current, &docker, now);
  assert_eq!(
    entries
      .iter()
      .map(|item| item.target.as_str())
      .collect::<Vec<_>>(),
    ["temp", "free-vol", "empty", "old"]
  );
}
