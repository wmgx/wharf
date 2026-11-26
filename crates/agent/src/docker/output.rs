use super::*;

pub(super) fn read_trimmed(path: &Path) -> Option<String> {
  std::fs::read_to_string(path)
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsLine {
  #[serde(default)]
  names: String,
  #[serde(default)]
  state: String,
  #[serde(default)]
  status: String,
  #[serde(default)]
  image: String,
  #[serde(default)]
  labels: String,
}

/// 解析 `docker ps --format '{{json .}}'`，按 compose project 分组。
pub fn parse_ps(
  stdout: &str,
) -> BTreeMap<String, Vec<ContainerInfo>> {
  let mut out: BTreeMap<String, Vec<ContainerInfo>> = BTreeMap::new();
  for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
    let Ok(ps) = serde_json::from_str::<PsLine>(line) else {
      continue;
    };
    let labels: BTreeMap<&str, &str> = ps
      .labels
      .split(',')
      .filter_map(|kv| kv.split_once('='))
      .collect();
    let Some(project) = labels.get("com.docker.compose.project")
    else {
      continue;
    };
    let health = ["healthy", "unhealthy", "health: starting"]
      .into_iter()
      .find(|h| ps.status.contains(&format!("({h})")))
      .map(|h| h.trim_start_matches("health: ").to_string());
    out
      .entry(project.to_string())
      .or_default()
      .push(ContainerInfo {
        service: labels
          .get("com.docker.compose.service")
          .unwrap_or(&"")
          .to_string(),
        name: ps.names,
        state: ps.state,
        status: ps.status,
        health,
        image: ps.image,
        foreign: false,
        finished_at: None,
        working_dir: labels
          .get("com.docker.compose.project.working_dir")
          .map(|w| w.to_string()),
      });
  }
  for containers in out.values_mut() {
    containers.sort_by(|a, b| a.name.cmp(&b.name));
  }
  out
}

/// 镜像引用拆成 (registry, 路径, 标签或 digest 后缀)。
pub(crate) fn split_image(image: &str) -> (String, String, String) {
  let (name, suffix) = match image.find('@') {
    Some(i) => (&image[..i], image[i..].to_string()),
    None => {
      let last_slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
      match image[last_slash..].find(':') {
        Some(i) => (
          &image[..last_slash + i],
          image[last_slash + i..].to_string(),
        ),
        None => (image, ":latest".to_string()),
      }
    }
  };
  let (registry, path) = match name.split_once('/') {
    Some((first, rest))
      if first.contains('.')
        || first.contains(':')
        || first == "localhost" =>
    {
      (first.to_string(), rest.to_string())
    }
    _ => ("docker.io".to_string(), name.to_string()),
  };
  let path = if registry == "docker.io" && !path.contains('/') {
    format!("library/{path}")
  } else {
    path
  };
  (registry, path, suffix)
}

/// 拉取顺序：镜像源在前，原地址最后（`mirrors_only` 时不试原地址）。
/// digest 引用不能重新打标签，所以只试原地址。
pub fn pull_candidates(
  image: &str,
  policy: &PullPolicy,
) -> Vec<String> {
  let (registry, path, suffix) = split_image(image);
  let mirrors = policy
    .mirrors
    .get(&registry)
    .filter(|_| !suffix.starts_with('@'))
    .cloned()
    .unwrap_or_default();
  let mut out: Vec<String> = mirrors
    .iter()
    .map(|m| format!("{}/{path}{suffix}", m.trim_end_matches('/')))
    .collect();
  if out.is_empty() || !policy.mirrors_only {
    out.push(image.to_string());
  }
  out
}

pub(super) fn pick_digest(
  image: &str,
  digests: &str,
) -> Option<String> {
  let (registry, path, _) = split_image(image);
  let digests: Vec<&str> =
    digests.split(',').filter(|d| !d.is_empty()).collect();
  digests
    .iter()
    .find(|d| {
      let repo = d.split('@').next().unwrap_or_default();
      let (r, p, _) = split_image(repo);
      r == registry && p == path
    })
    .or(digests.first())
    .map(|d| d.to_string())
}

/// `docker pull` 非终端输出是逐层状态行，如 `0a1b2c3d4e5f: Download complete`。
/// 汇总成已下载、已解压的层数，只在数字变化时报一次。
#[derive(Default)]
pub(super) struct Layers {
  seen: BTreeSet<String>,
  downloaded: BTreeSet<String>,
  extracted: BTreeSet<String>,
  last: (usize, usize, usize),
}

impl Layers {
  pub(super) fn feed(&mut self, line: &str) -> Option<String> {
    let (id, status) = line.split_once(": ")?;
    let id = id.trim();
    if !(id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit()))
    {
      return id.eq("Status").then(|| status.trim().to_string());
    }
    self.seen.insert(id.to_string());
    let status = status.trim();
    if matches!(
      status,
      "Download complete" | "Already exists" | "Pull complete"
    ) {
      self.downloaded.insert(id.to_string());
    }
    if matches!(status, "Already exists" | "Pull complete") {
      self.extracted.insert(id.to_string());
    }
    let now =
      (self.seen.len(), self.downloaded.len(), self.extracted.len());
    let changed = (now.1, now.2) != (self.last.1, self.last.2);
    self.last = now;
    if !changed {
      return None;
    }
    Some(format!(
      "镜像层：已下载 {}/{}，已解压 {}/{}",
      now.1, now.0, now.2, now.0
    ))
  }
}

pub(super) fn layer_progress(ctx: &Ctx, policy: &PullPolicy) -> Ctx {
  let Some(outer) = ctx.progress.clone() else {
    return ctx.clone();
  };
  let layers = Arc::new(Mutex::new(Layers::default()));
  let policy = policy.clone();
  Ctx {
    cancel: ctx.cancel.clone(),
    progress: Some(Arc::new(move |line: String| {
      let msg = layers.lock().ok().and_then(|mut l| l.feed(&line));
      if let Some(msg) = msg {
        outer(policy.redact(&msg));
      }
    })),
  }
}

/// `docker logs --timestamps` 的每行以 RFC 3339 时间开头，按它排序把两路输出合成一份。
/// 同一时间的行保持原来的先后。
pub(super) fn merge_by_time(stdout: &str, stderr: &str) -> String {
  let mut lines: Vec<&str> =
    stdout.lines().chain(stderr.lines()).collect();
  lines.sort_by_key(|l| l.split_once(' ').map_or(*l, |(t, _)| t));
  let mut out = lines.join("\n");
  if !out.is_empty() {
    out.push('\n');
  }
  out
}

/// 去掉终端颜色之类的控制序列（`ESC [ ... 字母`）。
pub(super) fn strip_ansi(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  let mut chars = text.chars();
  while let Some(c) = chars.next() {
    if c != '\x1b' {
      out.push(c);
      continue;
    }
    if chars.next() == Some('[') {
      for c in chars.by_ref() {
        if c.is_ascii_alphabetic() {
          break;
        }
      }
    }
  }
  out
}
