use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};

use crate::{docker::Docker, exec::Ctx};

pub struct StoppedObservation {
  pub finished_at: Option<DateTime<Utc>>,
  pub exit_code: Option<i64>,
  pub restart_policy: Option<String>,
}

pub async fn inspect_stopped(
  docker: &Docker,
  containers: &[&str],
  ctx: &Ctx,
) -> BTreeMap<String, StoppedObservation> {
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
      "{{.Name}}\t{{.State.FinishedAt}}\t{{.State.ExitCode}}\t{{.HostConfig.RestartPolicy.Name}}",
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
      let mut cols = line.split('\t');
      let name = cols.next()?.trim_start_matches('/');
      let finished_at = DateTime::parse_from_rfc3339(cols.next()?)
        .ok()
        .filter(|at| at.timestamp() > 0)
        .map(|at| at.with_timezone(&Utc));
      let exit_code = cols.next()?.parse().ok();
      let restart_policy = cols
        .next()
        .map(|p| if p.is_empty() { "no" } else { p }.to_string());
      Some((
        name.to_string(),
        StoppedObservation {
          finished_at,
          exit_code,
          restart_policy,
        },
      ))
    })
    .collect()
}
