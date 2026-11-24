use std::{
  collections::{BTreeMap, HashMap},
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use wharf_api_types::service_checks::{
  LogAlertSpec, LogHit, LogWatch,
};

use crate::{docker::Docker, exec::Ctx};

pub type Hits = Arc<Mutex<BTreeMap<String, LogHit>>>;

pub struct Watches {
  docker: Docker,
  cancel: CancellationToken,
  hits: Hits,
  projects: BTreeMap<String, Worker>,
  cursors: Cursors,
}

struct Worker {
  watches: Vec<LogWatch>,
  cancel: CancellationToken,
}

pub type Cursors = Arc<Mutex<BTreeMap<String, Cursor>>>;
type Cursor = Arc<Mutex<DateTime<Utc>>>;

impl Watches {
  pub fn new(
    docker: Docker,
    cancel: CancellationToken,
    hits: Hits,
    cursors: Cursors,
  ) -> Self {
    Self {
      docker,
      cancel,
      hits,
      projects: BTreeMap::new(),
      cursors,
    }
  }

  pub fn replace(&mut self, watches: Vec<LogWatch>) {
    let mut projects = BTreeMap::<String, Vec<LogWatch>>::new();
    for watch in watches {
      if wharf_api_types::validate_name("服务", &watch.project)
        .is_ok()
      {
        projects
          .entry(watch.project.clone())
          .or_default()
          .push(watch);
      }
    }
    self.projects.retain(|project, worker| {
      if projects.contains_key(project) {
        true
      } else {
        worker.cancel.cancel();
        false
      }
    });
    let mut cursors = self.cursors.lock().unwrap();
    cursors.retain(|project, _| projects.contains_key(project));
    for (project, watches) in projects {
      if self
        .projects
        .get(&project)
        .is_some_and(|w| w.watches == watches)
      {
        continue;
      }
      if let Some(worker) = self.projects.remove(&project) {
        worker.cancel.cancel();
      }
      let cursor = cursors
        .entry(project.clone())
        .or_insert_with(|| Arc::new(Mutex::new(Utc::now())))
        .clone();
      let cancel = self.cancel.child_token();
      self.projects.insert(
        project.clone(),
        Worker {
          watches: watches.clone(),
          cancel: cancel.clone(),
        },
      );
      tokio::spawn(follow(
        self.docker.clone(),
        project,
        watches,
        self.hits.clone(),
        cursor,
        cancel,
      ));
    }
    self.hits.lock().unwrap().retain(|id, _| {
      self
        .projects
        .values()
        .any(|p| p.watches.iter().any(|w| &w.id == id))
    });
  }
}

struct Matcher {
  watch: LogWatch,
  regex: Option<regex::Regex>,
}

fn matches(
  spec: &LogAlertSpec,
  regex: Option<&regex::Regex>,
  line: &str,
) -> bool {
  regex.map_or_else(
    || line.contains(&spec.pattern),
    |regex| regex.is_match(line),
  )
}

async fn follow(
  docker: Docker,
  project: String,
  watches: Vec<LogWatch>,
  hits: Hits,
  cursor: Cursor,
  cancel: CancellationToken,
) {
  let watches: Arc<Vec<_>> = Arc::new(
    watches
      .into_iter()
      .filter_map(|watch| {
        let regex = watch.spec.compile().ok()?;
        Some(Matcher { watch, regex })
      })
      .collect(),
  );
  if watches.is_empty() {
    return;
  }
  let mut retry = 10;
  let ctx = Ctx {
    cancel: cancel.clone(),
    progress: None,
  };
  while !cancel.is_cancelled() {
    let started = tokio::time::Instant::now();
    let mut containers = HashMap::new();
    if watches.iter().any(|m| m.watch.spec.container.is_some())
      && let Ok(state) = docker.one_status(&project, &ctx).await
    {
      for c in state.containers {
        for separator in ['-', '_'] {
          if let Some(short) =
            c.name.strip_prefix(&format!("{project}{separator}"))
          {
            containers.insert(short.to_string(), c.service.clone());
          }
        }
        containers.insert(c.name, c.service);
      }
    }
    let since = *cursor.lock().unwrap();
    let line = {
      let (watches, hits, cursor, cancel) = (
        watches.clone(),
        hits.clone(),
        cursor.clone(),
        cancel.clone(),
      );
      move |line: &str| {
        if cancel.is_cancelled() {
          return;
        }
        let Some((prefix, line)) = line.split_once(" | ") else {
          return;
        };
        let Some((timestamp, content)) =
          line.trim_start().split_once(' ')
        else {
          return;
        };
        let Ok(timestamp) = DateTime::parse_from_rfc3339(timestamp)
        else {
          return;
        };
        let at = timestamp.with_timezone(&Utc);
        if at < since {
          return;
        }
        let mut next = cursor.lock().unwrap();
        *next = (*next).max(at + chrono::Duration::nanoseconds(1));
        drop(next);
        for m in watches.iter() {
          let spec = &m.watch.spec;
          if spec.container.as_ref().is_some_and(|want| {
            containers.get(prefix.trim()) != Some(want)
              && prefix.trim() != want
          }) || !matches(spec, m.regex.as_ref(), content)
          {
            continue;
          }
          let mut hits = hits.lock().unwrap();
          let hit =
            hits.entry(m.watch.id.clone()).or_insert_with(|| {
              LogHit {
                id: m.watch.id.clone(),
                count: 0,
                at: 0,
                lines: vec![],
              }
            });
          hit.count = hit.count.saturating_add(1);
          hit.at = hit.at.max(at.timestamp_millis());
          if hit.lines.len() == 3 {
            hit.lines.remove(0);
          }
          hit.lines.push(content.chars().take(300).collect());
        }
      }
    };
    docker
      .compose(&project)
      .args([
        "logs",
        "--follow",
        "--no-color",
        "--timestamps",
        "--since",
      ])
      .arg(since.to_rfc3339())
      .timeout(Duration::from_secs(30 * 60))
      .stream_bounded(&ctx, &line)
      .await;
    if started.elapsed() >= Duration::from_secs(60) {
      retry = 10;
    }
    tokio::select! {
      _ = cancel.cancelled() => return,
      _ = tokio::time::sleep(Duration::from_secs(retry)) => {}
    }
    retry = (retry * 2).min(60);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn text_and_regex_match_once() {
    for (pattern, regex) in [("error", false), ("err[oa]r", true)] {
      let spec = LogAlertSpec {
        pattern: pattern.into(),
        regex,
        min_count: 1,
        window_mins: 5,
        container: None,
      };
      let compiled = spec.compile().unwrap();
      assert_eq!(
        ["Error", "no error", "normal"]
          .into_iter()
          .filter(|line| matches(&spec, compiled.as_ref(), line))
          .count(),
        1
      );
    }
  }
}
