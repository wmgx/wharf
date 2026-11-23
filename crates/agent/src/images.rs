use std::{
  collections::{BTreeMap, BTreeSet},
  time::Duration,
};

use wharf_api_types::{ApiError, agent::LocalImage};

use crate::{docker::Docker, exec::Ctx};

const TIMEOUT: Duration = Duration::from_secs(15);

pub async fn list(
  docker: &Docker,
  ctx: &Ctx,
) -> Result<Vec<LocalImage>, ApiError> {
  let run = |args: Vec<&str>| {
    let cmd = docker.cmd().args(args).timeout(TIMEOUT);
    async move {
      Ok::<_, ApiError>(
        cmd.run(ctx).await?.check("docker 镜像查询")?.stdout,
      )
    }
  };
  let (image_ids, containers) = tokio::try_join!(
    run(vec!["image", "ls", "-aq", "--no-trunc"]),
    run(vec!["ps", "-aq", "--no-trunc"]),
  )?;
  let image_ids: BTreeSet<_> = image_ids.lines().collect();
  let containers: Vec<_> = containers.lines().collect();
  let (inspect, usage) = tokio::try_join!(
    async {
      if image_ids.is_empty() {
        return Ok(String::new());
      }
      let mut args = vec![
        "image",
        "inspect",
        "-f",
        "{{.Id}}\t{{.Size}}\t{{json .RepoTags}}",
      ];
      args.extend(image_ids.iter().copied());
      run(args).await
    },
    async {
      if containers.is_empty() {
        return Ok(String::new());
      }
      let mut args =
        vec!["container", "inspect", "-f", "{{.Image}}\t{{.Name}}"];
      args.extend(containers.iter().copied());
      run(args).await
    }
  )?;
  if inspect.lines().count() != image_ids.len()
    || usage.lines().count() != containers.len()
  {
    return Err(ApiError::internal(
      "Docker 镜像或容器列表不完整，请重试",
    ));
  }
  let bad_row =
    || ApiError::internal("Docker 镜像或容器信息无法解析");
  let mut used = BTreeMap::<_, Vec<_>>::new();
  for line in usage.lines() {
    let (id, name) = line.split_once('\t').ok_or_else(bad_row)?;
    used
      .entry(id)
      .or_default()
      .push(name.trim_start_matches('/').to_string());
  }
  let mut images = Vec::new();
  for line in inspect.lines() {
    let mut fields = line.splitn(3, '\t');
    let id = fields.next().ok_or_else(bad_row)?;
    let size = fields
      .next()
      .and_then(|s| s.parse().ok())
      .ok_or_else(bad_row)?;
    let mut tags: Vec<String> =
      serde_json::from_str::<Option<Vec<String>>>(
        fields.next().ok_or_else(bad_row)?,
      )
      .map_err(|_| bad_row())?
      .unwrap_or_default();
    if tags.is_empty() {
      tags.push(id.to_string());
    }
    let mut used_by = used.remove(id).unwrap_or_default();
    used_by.sort();
    images.extend(tags.into_iter().map(|image| LocalImage {
      id: id.to_string(),
      image,
      size,
      used_by: used_by.clone(),
    }));
  }
  Ok(images)
}
