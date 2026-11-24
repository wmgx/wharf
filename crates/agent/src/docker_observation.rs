use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};

use crate::{docker::Docker, exec::Ctx};

pub async fn finished_at(
  docker: &Docker,
  containers: &[&str],
  ctx: &Ctx,
) -> BTreeMap<String, DateTime<Utc>> {
  if containers.is_empty() {
    return BTreeMap::new();
  }
  let Ok(out) = docker
    .cmd()
    .args([
      "inspect",
      "--type",
      "container",
      "--format",
      "{{.Name}} {{.State.FinishedAt}}",
      "--",
    ])
    .args(containers.iter().copied())
    .timeout(Duration::from_secs(10))
    .run(ctx)
    .await
  else {
    return BTreeMap::new();
  };
  out
    .stdout
    .lines()
    .filter_map(|line| {
      let (name, at) = line.split_once(' ')?;
      let at =
        DateTime::parse_from_rfc3339(at).ok()?.with_timezone(&Utc);
      (at.timestamp() > 0)
        .then(|| (name.trim_start_matches('/').to_string(), at))
    })
    .collect()
}
