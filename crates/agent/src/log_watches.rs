use std::{
  collections::{BTreeMap, HashMap, VecDeque},
  fs,
  hash::{DefaultHasher, Hash, Hasher},
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use wharf_api_types::service_checks::{
  LogAlertSpec, LogHit, LogWatch,
};

use crate::{docker::Docker, exec::Ctx};

const REPLAY: TimeDelta = TimeDelta::minutes(5);
const MAX_PENDING: usize = 1000;

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

pub type Cursors = Arc<CursorStore>;
type Cursor = Arc<Mutex<ProjectCursor>>;
type Watermarks = BTreeMap<String, DateTime<Utc>>;

pub struct CursorStore {
  path: PathBuf,
  projects: Mutex<BTreeMap<String, Cursor>>,
  // 只允许一个落盘线程更新文件和判断是否有变化。
  last_saved: Mutex<Vec<u8>>,
}

impl CursorStore {
  pub fn load(data_dir: &Path) -> Cursors {
    let path = data_dir.join("log-cursors.json");
    let bytes = fs::read(&path).unwrap_or_default();
    let restored: BTreeMap<String, Watermarks> =
      serde_json::from_slice(&bytes).unwrap_or_default();
    Arc::new(Self {
      path,
      projects: Mutex::new(
        restored
          .into_iter()
          .map(|(name, times)| {
            (
              name,
              Arc::new(Mutex::new(ProjectCursor {
                times,
                ..Default::default()
              })),
            )
          })
          .collect(),
      ),
      last_saved: Mutex::new(bytes),
    })
  }

  pub fn save(&self) {
    let mut last = self.last_saved.lock().unwrap();
    let times: BTreeMap<_, _> = self
      .projects
      .lock()
      .unwrap()
      .iter()
      .map(|(name, cursor)| {
        (name.clone(), cursor.lock().unwrap().times.clone())
      })
      .collect();
    let Ok(next) = serde_json::to_vec(&times) else {
      return;
    };
    if *last == next {
      return;
    }
    let tmp = self.path.with_extension("tmp");
    match fs::write(&tmp, &next)
      .and_then(|()| fs::rename(&tmp, &self.path))
    {
      Ok(()) => *last = next,
      Err(e) => tracing::warn!("保存日志监听游标失败：{e}"),
    }
  }
}

#[derive(Default)]
struct ProjectCursor {
  times: Watermarks,
  recent: VecDeque<(String, DateTime<Utc>, u64)>,
}

impl ProjectCursor {
  fn start(&self, now: DateTime<Utc>) -> DateTime<Utc> {
    self
      .times
      .iter()
      .filter(|(prefix, _)| *prefix != "*")
      .map(|(_, at)| *at)
      .min()
      .or_else(|| self.times.get("*").copied())
      .unwrap_or(now)
      .max(now - REPLAY)
      .min(now)
  }

  fn accept(
    &mut self,
    prefix: &str,
    at: DateTime<Utc>,
    line: &str,
  ) -> bool {
    let previous = self
      .times
      .get(prefix)
      .or_else(|| self.times.get("*"))
      .copied();
    if previous.is_some_and(|prev| at < prev) {
      return false;
    }
    let mut hasher = DefaultHasher::new();
    line.hash(&mut hasher);
    let hash = hasher.finish();
    if self
      .recent
      .iter()
      .any(|(p, ts, h)| p == prefix && *ts == at && *h == hash)
    {
      return false;
    }
    self.times.insert(prefix.to_string(), at);
    if self.recent.len() >= 512 {
      self.recent.pop_front();
    }
    self.recent.push_back((prefix.to_string(), at, hash));
    true
  }
}

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
    let mut cursors = self.cursors.projects.lock().unwrap();
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
        .or_insert_with(|| {
          Arc::new(Mutex::new(ProjectCursor {
            times: BTreeMap::from([("*".into(), Utc::now())]),
            ..Default::default()
          }))
        })
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
        let regex = match watch.spec.compile_stored() {
          Ok(regex) => regex,
          Err(e) => {
            tracing::warn!(
              "日志监听规则 {project} 编译失败：{}",
              e.message
            );
            return None;
          }
        };
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
  let targeted = watches
    .iter()
    .any(|matcher| matcher.watch.spec.container.is_some());
  while !cancel.is_cancelled() {
    let started = Instant::now();
    let since = cursor.lock().unwrap().start(Utc::now());
    let mut containers = if targeted {
      container_names(&docker, &project, &ctx).await
    } else {
      HashMap::new()
    };
    let mut refreshed = Instant::now();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
    let cmd = docker
      .compose(&project)
      .args([
        "logs",
        "--follow",
        "--no-color",
        "--timestamps",
        "--since",
      ])
      .arg(since.to_rfc3339())
      .timeout(Duration::from_secs(30 * 60));
    let consume = async {
      while let Some(line) = rx.recv().await {
        if cancel.is_cancelled() {
          break;
        }
        let Some((prefix, at, content)) = parse_line(&line) else {
          continue;
        };
        if at < since
          || !cursor.lock().unwrap().accept(prefix, at, content)
        {
          continue;
        }
        if targeted
          && !containers.contains_key(prefix)
          && refreshed.elapsed() >= Duration::from_secs(10)
          && watches.iter().any(|m| {
            m.watch.spec.container.is_some()
              && matches(&m.watch.spec, m.regex.as_ref(), content)
          })
        {
          containers = container_names(&docker, &project, &ctx).await;
          refreshed = Instant::now();
        }
        for m in watches.iter() {
          let spec = &m.watch.spec;
          if spec.container.as_ref().is_some_and(|want| {
            containers.get(prefix) != Some(want) && prefix != want
          }) || !matches(spec, m.regex.as_ref(), content)
          {
            continue;
          }
          let mut hits = hits.lock().unwrap();
          if hits.len() >= MAX_PENDING
            && !hits.contains_key(&m.watch.id)
          {
            continue;
          }
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
    let (normal, ()) =
      tokio::join!(cmd.stream_bounded(&ctx, tx), consume);
    if started.elapsed() >= Duration::from_secs(60) {
      retry = 10;
    }
    if normal
      && !cancel.is_cancelled()
      && started.elapsed() >= Duration::from_secs(1)
    {
      continue;
    }
    tokio::select! {
      _ = cancel.cancelled() => return,
      _ = tokio::time::sleep(Duration::from_secs(retry)) => {}
    }
    retry = (retry * 2).min(60);
  }
}

fn parse_line(line: &str) -> Option<(&str, DateTime<Utc>, &str)> {
  let (prefix, line) = line.split_once(" | ")?;
  let (timestamp, content) = line.trim_start().split_once(' ')?;
  let at = DateTime::parse_from_rfc3339(timestamp)
    .ok()?
    .with_timezone(&Utc);
  Some((prefix.trim(), at, content))
}

async fn container_names(
  docker: &Docker,
  project: &str,
  ctx: &Ctx,
) -> HashMap<String, String> {
  let mut names = HashMap::new();
  if let Ok(state) = docker.one_status(project, ctx).await {
    for c in state.containers {
      for separator in ['-', '_'] {
        if let Some(short) =
          c.name.strip_prefix(&format!("{project}{separator}"))
        {
          names.insert(short.to_string(), c.service.clone());
        }
      }
      names.insert(c.name, c.service);
    }
  }
  names
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn log_watch_keeps_independent_container_cursors_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let store = CursorStore::load(dir.path());
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let at = |ms| now + TimeDelta::milliseconds(ms);
    let cursor = Arc::new(Mutex::new(ProjectCursor::default()));
    {
      let mut cur = cursor.lock().unwrap();
      assert!(cur.accept("web-1", at(500), "later"));
      assert!(cur.accept("worker-1", at(200), "earlier"));
      assert!(!cur.accept("worker-1", at(200), "earlier"));
      assert!(cur.accept("worker-1", at(200), "same timestamp"));
    }
    store.projects.lock().unwrap().insert("web".into(), cursor);
    store.save();
    let restored = CursorStore::load(dir.path());
    let stored = restored.projects.lock().unwrap();
    let cur = stored["web"].lock().unwrap();
    assert_eq!(cur.start(at(1000)), at(200));
    assert_eq!(cur.start(now + TimeDelta::minutes(10)), now + REPLAY);
  }

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
