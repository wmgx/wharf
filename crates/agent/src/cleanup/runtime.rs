use super::{CORE, entry, frpc_project, reserved, valid};
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

impl Runtime {
  pub(super) fn image_tags(&self, id: &str) -> &[String] {
    self
      .images
      .iter()
      .find(|image| image.0 == id)
      .and_then(|image| image.1.as_deref())
      .unwrap_or_default()
  }

  fn removable_stopped(
    docker: &Docker,
    project: &str,
    c: &Container,
  ) -> bool {
    matches!(c.2.as_str(), "exited" | "dead" | "created")
      && label(&c.5, "com.docker.compose.project.working_dir")
        .is_some_and(|dir| {
          Path::new(dir) == docker.project_dir(project)
        })
  }

  pub(super) fn project_blockers(
    &self,
    docker: &Docker,
    project: &str,
  ) -> Vec<String> {
    self
      .containers
      .iter()
      .filter(|c| {
        label(&c.5, PROJECT) == Some(project)
          && !Self::removable_stopped(docker, project, c)
      })
      .map(|c| c.1.trim_start_matches('/').into())
      .collect()
  }

  pub(super) fn owned_stops<'a>(
    &'a self,
    docker: &Docker,
    project: &str,
  ) -> Vec<&'a str> {
    self
      .containers
      .iter()
      .filter(|c| {
        label(&c.5, PROJECT) == Some(project)
          && Self::removable_stopped(docker, project, c)
      })
      .map(|c| c.0.as_str())
      .collect()
  }

  pub(super) fn project_binds(
    &self,
    docker: &Docker,
    project: &str,
  ) -> Vec<BindMountUser> {
    self
      .binds
      .iter()
      .filter(|m| {
        !self.containers.iter().any(|c| {
          c.1.trim_start_matches('/') == m.container
            && (label(&c.5, PROJECT) == Some(project)
              && Self::removable_stopped(docker, project, c)
              || (label(&c.5, "wharf.system") == Some("agent")
                || (label(&c.5, "wharf.system") == Some("1")
                  && m.container == "wharf-agent"))
                && Path::new(&m.source) == docker.data_dir)
        })
      })
      .cloned()
      .collect()
  }
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
  let out = inspect(
    docker,
    "container",
    &ids,
    concat!(
      r#"{{json .Name}} {{json (index .Config.Labels "wharf.system")}} {{json (index .Config.Labels "com.docker.compose.project")}} {{json .Mounts}}"#,
      "\t",
      r#"[{{json .Id}},{{json .Name}},{{json .State.Status}},{{json .Created}},{{json .Image}},{{json .Config.Labels}},{{json .Mounts}},{{json .NetworkSettings.Networks}}]"#,
    ),
    ctx,
  )
  .await?;
  let mut bind_rows = String::new();
  let mut rows = String::new();
  for line in out.lines() {
    let (binds, row) = line
      .split_once('\t')
      .ok_or_else(|| ApiError::internal("Docker 容器清单不完整"))?;
    bind_rows.push_str(binds);
    bind_rows.push('\n');
    rows.push_str(row);
    rows.push('\n');
  }
  Ok(Runtime {
    binds: parse_bind_mounts(&bind_rows)?,
    containers: decode_rows(&rows)?,
    ..Default::default()
  })
}

pub(super) async fn project_networks(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Runtime, ApiError> {
  let (mut current, ids) = tokio::try_join!(
    containers(docker, ctx),
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
  )?;
  let networks = inspect(
    docker,
    "network",
    &ids,
    r#"[{{json .Id}},{{json .Name}},{{json .Labels}},{{json .Containers}}]"#,
    ctx,
  ).await?;
  current.networks = decode_rows(&networks)?;
  Ok(current)
}

pub(super) async fn runtime(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Runtime, ApiError> {
  let (mut current, volumes, images) = tokio::try_join!(
    project_networks(docker, ctx),
    docker_output(docker, &["volume", "ls", "-q"], ctx),
    docker_output(docker, &["image", "ls", "-aq", "--no-trunc"], ctx),
  )?;
  let (volumes, images) = tokio::try_join!(
    inspect(
      docker,
      "volume",
      &volumes,
      r#"[{{json .Name}},{{json .Labels}}]"#,
      ctx
    ),
    inspect(
      docker,
      "image",
      &images,
      r#"[{{json .Id}},{{json .RepoTags}},{{json .Size}},{{json .Created}},{{json .Config.Labels}}]"#,
      ctx
    ),
  )?;
  current.volumes = decode_rows(&volumes)?;
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
    let task = label(labels, "wharf.task")
      .or_else(|| {
        project.and_then(|p| p.strip_prefix(TASK_DATA_PREFIX))
      })
      .filter(|name| valid(name))
      .map(|name| format!("{TASK_DATA_PREFIX}{name}"));
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
      let mut item = entry(
        OrphanContainer,
        task.as_deref().or(restic).or(project),
        id.clone(),
      );
      item.ephemeral = ephemeral;
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
    let system_project =
      label(labels, PROJECT).is_some_and(|project| {
        frpc_project(project)
          || project.strip_prefix("wharf-gw-").is_some_and(valid)
      });
    if (owner.is_some_and(reserved) && !system_project)
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
  for Image(id, tags, size, created, labels) in &current.images {
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
    if !tags.is_empty()
      && !owner.is_some_and(|owner| {
        valid(owner)
          && tags.iter().all(|tag| {
            tag.starts_with(&format!("{BUILD_IMAGE_PREFIX}{owner}:"))
              || tag.starts_with(&format!("wharf-build-{owner}:"))
          })
      })
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
      Image("used".into(), None, 2, created, None),
      Image("old".into(), Some(vec!["wharf-build/old:1".into()]), 2, created, None),
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

#[test]
fn upgraded_agent_root_mount_is_ignored_only_for_project_cleanup() {
  use serde_json::json;

  let (_tmp, docker) = crate::docker::fake_docker("exit 0");
  let mut current = Runtime::default();
  for (name, role, source) in [
    ("wharf-agent", "1", docker.data_dir.clone()),
    ("backup", "1", docker.data_dir.clone()),
  ] {
    current.containers.push(
      serde_json::from_value(json!([
        name, format!("/{name}"), "running", Utc::now(), "image",
        {"wharf.system":role}, [], {}
      ]))
      .unwrap(),
    );
    current.binds.push(BindMountUser {
      container: name.into(),
      project: None,
      source: source.display().to_string(),
      rw: true,
    });
  }
  for project in ["wharf-gw-old", "wharf-link-old"] {
    let users = crate::docker::containers_using_path(
      &docker.project_dir(project),
      &current.project_binds(&docker, project),
    );
    assert_eq!(users, ["backup"]);
  }
}

#[test]
fn stale_ephemeral_containers_include_tasks_without_compose_labels() {
  use serde_json::json;

  let (_tmp, docker) = crate::docker::fake_docker("exit 0");
  let now = Utc::now();
  let old = now - chrono::Duration::minutes(30);
  let current = Runtime {
    containers: [
      (
        "backup",
        "exited",
        old,
        json!({"wharf.restic.service":"app"}),
      ),
      (
        "temp",
        "dead",
        old,
        json!({"wharf.temp":"1", PROJECT:"app"}),
      ),
      ("task", "exited", old, json!({"wharf.task":"nightly"})),
      ("running", "running", old, json!({"wharf.task":"nightly"})),
      ("recent", "exited", now, json!({"wharf.task":"nightly"})),
    ]
    .into_iter()
    .map(|(name, status, created, labels)| {
      serde_json::from_value(json!([
        name,
        format!("/{name}"),
        status,
        created,
        "image",
        labels,
        [],
        {}
      ]))
      .unwrap()
    })
    .collect(),
    ..Default::default()
  };
  let entries = docker_entries(&current, &docker, now);
  assert_eq!(
    entries
      .iter()
      .map(|e| (
        e.display.as_str(),
        e.service.as_deref(),
        e.ephemeral
      ))
      .collect::<Vec<_>>(),
    [
      ("backup", Some("app"), true),
      ("temp", Some("app"), true),
      ("task", Some("wharf-task-nightly"), true),
    ]
  );
}
