use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};

use crate::{docker::Docker, exec::Ctx};

pub struct StoppedObservation {
  pub finished_at: Option<DateTime<Utc>>,
  pub exit_code: Option<i64>,
  pub restart_policy: Option<String>,
  pub container_id: Option<String>,
  pub restart_count: Option<u32>,
  pub observed_at: i64,
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
      "{{.Name}}\t{{.State.FinishedAt}}\t{{.State.ExitCode}}\t{{.HostConfig.RestartPolicy.Name}}\t{{.HostConfig.RestartPolicy.MaximumRetryCount}}\t{{.Id}}\t{{.RestartCount}}",
      "--",
    ])
    .args(containers.iter().copied())
    .timeout(Duration::from_secs(10))
    .run(ctx)
    .await
  else {
    return BTreeMap::new();
  };
  let observed_at = Utc::now().timestamp_millis();
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
      let policy = cols.next();
      let max = cols.next().and_then(|p| p.parse::<u32>().ok());
      let restart_policy = policy.map(|p| match (p, max) {
        ("on-failure", Some(n)) if n > 0 => format!("on-failure:{n}"),
        ("", _) => "no".into(),
        _ => p.to_string(),
      });
      let container_id =
        cols.next().filter(|id| id.len() == 64).map(str::to_owned);
      let restart_count = cols.next().and_then(|n| n.parse().ok());
      Some((
        name.to_string(),
        StoppedObservation {
          finished_at,
          exit_code,
          restart_policy,
          container_id,
          restart_count,
          observed_at,
        },
      ))
    })
    .collect()
}
