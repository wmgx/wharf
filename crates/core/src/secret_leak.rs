//! 匿名拉取公开仓库，只在控制面内存里比对密钥。

use std::{
  collections::{BTreeMap, BTreeSet},
  path::{Path, PathBuf},
  process::Stdio,
  sync::Arc,
  time::Duration,
};

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command, time::Instant};
use wharf_api_types::{
  ApiError, mask_values, spec::Source, view::Perm,
};

use crate::{
  api::ApiResult, auth::Auth, db, log_redact, snapshot,
  state::AppState,
};

const HISTORY: usize = 20;
const MAX_OUTPUT: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
pub struct Request {
  repo: Option<String>,
}

#[derive(Default, Serialize)]
pub struct Report {
  scanned: BTreeSet<String>,
  failed: Vec<Failure>,
  hits: BTreeSet<Hit>,
}

#[derive(Serialize)]
struct Failure {
  repo: String,
  reference: String,
  message: String,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Hit {
  repo: String,
  file: String,
  commit: String,
  secret: String,
}

pub async fn check(
  State(s): State<Arc<AppState>>,
  auth: Auth,
  Json(req): Json<Request>,
) -> ApiResult<Report> {
  auth.require(Perm::Admin)?;
  let snap = snapshot::load(&s.db).await?;
  let filter = req
    .repo
    .as_deref()
    .map(|url| {
      github_repo(url)
        .ok_or_else(|| ApiError::invalid("只支持公开 GitHub 仓库"))
    })
    .transpose()?;
  let repos: BTreeSet<_> = snap
    .world
    .services
    .values()
    .filter_map(|row| {
      let Source::Build(build) = &row.spec.source else {
        return None;
      };
      let git = build.git.as_ref()?;
      let repo = github_repo(&git.repo)?;
      Some((repo, git.reference.as_str()))
    })
    .filter(|(repo, _)| {
      filter
        .as_ref()
        .is_none_or(|wanted| wanted.eq_ignore_ascii_case(repo))
    })
    .collect();
  if filter.is_some() && repos.is_empty() {
    return Err(
      ApiError::invalid("没有服务引用该 GitHub 仓库").into(),
    );
  }
  let proxy = snap
    .core_server
    .as_ref()
    .and_then(|name| snap.world.servers.get(name))
    .and_then(|server| snapshot::pull_policy(server).git_proxy);
  let values =
    s.db.call_credentials(|c, key| db::secrets(c, key)).await?;
  let patterns = Patterns::new(values);
  let mut report = Report::default();
  let deadline = Instant::now() + Duration::from_secs(150);
  for (repo, reference) in repos {
    let result = tokio::time::timeout_at(
      deadline.min(Instant::now() + Duration::from_secs(90)),
      scan(
        &repo,
        reference,
        proxy.as_deref(),
        &patterns,
        &mut report.hits,
      ),
    )
    .await
    .unwrap_or(Err("仓库检查超时"));
    match result {
      Ok(()) => {
        report.scanned.insert(patterns.mask(&repo));
      }
      Err(message) => report.failed.push(Failure {
        repo: patterns.mask(&repo),
        reference: patterns.mask(reference),
        message: message.into(),
      }),
    }
  }
  Ok(Json(report))
}

fn github_repo(url: &str) -> Option<String> {
  let path = url
    .trim()
    .strip_prefix("https://github.com/")?
    .trim_end_matches('/');
  let (owner, repo) = path.split_once('/')?;
  let repo = repo.strip_suffix(".git").unwrap_or(repo);
  let valid = |part: &str| {
    !matches!(part, "" | "." | "..")
      && part
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
  };
  (valid(owner) && valid(repo))
    .then(|| format!("https://github.com/{owner}/{repo}.git"))
}

struct Patterns {
  by_name: BTreeMap<String, Vec<String>>,
  all: Vec<String>,
}

impl Patterns {
  fn new(values: BTreeMap<String, String>) -> Self {
    let by_name: BTreeMap<_, _> = values
      .into_iter()
      .filter(|(_, value)| value.chars().take(8).count() == 8)
      .map(|(name, value)| {
        let mut variants = vec![value];
        log_redact::add_encoded_values(&mut variants);
        (name, variants)
      })
      .collect();
    let all = by_name.values().flatten().cloned().collect();
    Self { by_name, all }
  }

  fn mask(&self, text: &str) -> String {
    mask_values(text, &self.all)
  }

  fn record(
    &self,
    hits: &mut BTreeSet<Hit>,
    repo: &str,
    file: &[u8],
    commit: &str,
    bytes: &[u8],
  ) {
    let text = std::str::from_utf8(bytes).ok();
    for (name, variants) in &self.by_name {
      if variants.iter().any(|value| match text {
        Some(text) => text.contains(value),
        None => bytes
          .windows(value.len())
          .any(|chunk| chunk == value.as_bytes()),
      }) {
        hits.insert(Hit {
          repo: self.mask(repo),
          file: self.mask(&String::from_utf8_lossy(file)),
          commit: self.mask(commit),
          secret: self.mask(name),
        });
      }
    }
  }
}

// 每次只拉受管引用，加深一层以便计算最后一个提交的 diff。
fn fetch_args<'a>(
  repo: &'a str,
  reference: &'a str,
  proxy: &'a str,
  patterns: &Patterns,
) -> Result<Vec<&'a str>, &'static str> {
  if [repo, reference, proxy]
    .iter()
    .any(|part| patterns.all.iter().any(|value| part.contains(value)))
  {
    return Err("拉取配置含密钥，已跳过");
  }
  if reference.starts_with('-') || reference.is_empty() {
    return Err("不支持该 Git 引用");
  }
  Ok(vec![
    "fetch",
    "--quiet",
    "--no-tags",
    "--no-recurse-submodules",
    "--no-auto-maintenance",
    "--depth=21",
    "--",
    repo,
    reference,
  ])
}

async fn scan(
  repo: &str,
  reference: &str,
  proxy: Option<&str>,
  patterns: &Patterns,
  hits: &mut BTreeSet<Hit>,
) -> Result<(), &'static str> {
  let proxy = proxy.unwrap_or_default();
  if !proxy.is_empty()
    && !reqwest::Url::parse(proxy).is_ok_and(|url| {
      matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
    })
  {
    return Err("公开仓库检查只支持无需认证的 HTTP 代理");
  }
  let args = fetch_args(repo, reference, proxy, patterns)?;
  let dir = ScanDir::new()?;
  git(
    &dir.0,
    "",
    &["check-ref-format", "--allow-onelevel", reference],
  )
  .await
  .map_err(|_| "不支持该 Git 引用")?;
  git(&dir.0, "", &["init", "--bare", "--quiet", "--template="])
    .await?;
  git(&dir.0, proxy, &args)
    .await
    .map_err(|_| "匿名拉取 GitHub 仓库失败")?;
  scan_history(&dir.0, repo, "FETCH_HEAD", patterns, hits).await
}

async fn scan_history(
  dir: &Path,
  repo: &str,
  head: &str,
  patterns: &Patterns,
  hits: &mut BTreeSet<Hit>,
) -> Result<(), &'static str> {
  let commits = git(
    dir,
    "",
    &[
      "rev-list",
      "--parents",
      &format!("--max-count={HISTORY}"),
      head,
    ],
  )
  .await?;
  let commits =
    std::str::from_utf8(&commits).map_err(|_| "无法读取提交")?;
  let tip =
    commits.split_whitespace().next().ok_or("引用没有提交")?;
  let files = git(dir, "", &["ls-tree", "-rz", tip]).await?;
  for entry in
    files.split(|&b| b == 0).filter(|entry| !entry.is_empty())
  {
    let (meta, path) = entry.split_at(
      entry
        .iter()
        .position(|&b| b == b'\t')
        .ok_or("无法读取文件路径")?,
    );
    let meta =
      std::str::from_utf8(meta).map_err(|_| "无法读取文件信息")?;
    if let [_, "blob", oid] =
      meta.split_whitespace().collect::<Vec<_>>().as_slice()
    {
      let content = git(dir, "", &["cat-file", "blob", oid]).await?;
      patterns.record(hits, repo, &path[1..], tip, &content);
    }
  }
  for row in commits.lines() {
    let mut ids = row.split_whitespace();
    let commit = ids.next().ok_or("无法读取提交")?;
    let mut args = vec![
      "diff-tree",
      "--root",
      "-r",
      "-z",
      "--raw",
      "--no-renames",
      "--no-abbrev",
      "--no-commit-id",
    ];
    args.extend(ids.next());
    args.push(commit);
    let entries = git(dir, "", &args).await?;
    let mut entries =
      entries.split(|&b| b == 0).filter(|entry| !entry.is_empty());
    while let Some(meta) = entries.next() {
      let path = entries.next().ok_or("无法读取变更路径")?;
      let meta =
        std::str::from_utf8(meta).map_err(|_| "无法读取变更信息")?;
      let [before, after, old, new, _] =
        meta.split_whitespace().collect::<Vec<_>>()[..]
      else {
        return Err("无法读取变更信息");
      };
      let is_blob = |mode| !matches!(mode, "000000" | "160000");
      match (is_blob(before.trim_start_matches(':')), is_blob(after))
      {
        (true, true) if old != new => {
          let patch = git(
            dir,
            "",
            &[
              "diff",
              "--text",
              "--no-color",
              "--no-ext-diff",
              "--no-textconv",
              "--unified=0",
              old,
              new,
              "--",
            ],
          )
          .await?;
          changed_text(&patch, |bytes| {
            patterns.record(hits, repo, path, commit, bytes)
          });
        }
        (true, false) | (false, true) => {
          let oid = if is_blob(after) { new } else { old };
          let content =
            git(dir, "", &["cat-file", "blob", oid]).await?;
          patterns.record(hits, repo, path, commit, &content);
        }
        _ => {}
      }
    }
  }
  Ok(())
}

fn changed_text(patch: &[u8], mut scan: impl FnMut(&[u8])) {
  let mut group = Vec::new();
  let mut marker = 0;
  let mut hunk = false;
  for line in patch.split_inclusive(|&b| b == b'\n') {
    let Some((&first, rest)) = line.split_first() else {
      continue;
    };
    if hunk && first == b'\\' {
      if group.last() == Some(&b'\n') {
        group.pop();
      }
      continue;
    }
    if marker != first || !matches!(first, b'+' | b'-') {
      if !group.is_empty() {
        scan(&group);
      }
      group.clear();
    }
    if hunk && matches!(first, b'+' | b'-') {
      group.extend_from_slice(rest);
    }
    hunk |= line.starts_with(b"@@ ");
    marker = first;
  }
  if !group.is_empty() {
    scan(&group);
  }
}

struct ScanDir(PathBuf);

impl ScanDir {
  fn new() -> Result<Self, &'static str> {
    let path = std::env::temp_dir()
      .join(format!("wharf-scan-{}", crate::auth::new_token()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
      use std::os::unix::fs::DirBuilderExt;
      builder.mode(0o700);
    }
    builder.create(&path).map_err(|_| "无法创建仓库临时目录")?;
    Ok(Self(path))
  }
}

impl Drop for ScanDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

// Git 会派生 HTTPS helper，取消时一起清理进程组。
struct GitGroup(Option<u32>);

impl Drop for GitGroup {
  fn drop(&mut self) {
    #[cfg(unix)]
    if let Some(pid) = self.0 {
      let _ = std::process::Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    }
  }
}

async fn git(
  dir: &Path,
  proxy: &str,
  args: &[&str],
) -> Result<Vec<u8>, &'static str> {
  git_with_env(dir, proxy, args, &[]).await
}

pub(crate) async fn git_with_env(
  dir: &Path,
  proxy: &str,
  args: &[&str],
  env: &[(&str, &str)],
) -> Result<Vec<u8>, &'static str> {
  let mut command = Command::new("git");
  command
    .current_dir(dir)
    .env_clear()
    .env("PATH", std::env::var_os("PATH").unwrap_or_default())
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("HTTPS_PROXY", proxy)
    .envs(env.iter().copied())
    .args([
      "-c",
      "protocol.allow=never",
      "-c",
      "protocol.https.allow=always",
      "-c",
      "http.followRedirects=false",
      "-c",
      "credential.helper=",
    ])
    .args(args)
    .stdin(Stdio::null())
    .stderr(Stdio::null())
    .stdout(Stdio::piped())
    .kill_on_drop(true);
  #[cfg(unix)]
  command.process_group(0);
  let mut child = command.spawn().map_err(|_| "无法启动 Git")?;
  let mut group = GitGroup(child.id());
  let mut out = Vec::new();
  child
    .stdout
    .take()
    .ok_or("无法读取 Git 输出")?
    .take(MAX_OUTPUT + 1)
    .read_to_end(&mut out)
    .await
    .map_err(|_| "无法读取 Git 输出")?;
  if out.len() as u64 > MAX_OUTPUT {
    return Err("Git 输出超过 32 MiB，未完成检查");
  }
  let status = child.wait().await.map_err(|_| "无法等待 Git")?;
  group.0 = None;
  if !status.success() {
    return Err("Git 命令失败");
  }
  Ok(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn scans_tree_and_deleted_history_without_reporting_values() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let history = "fixture/history-value";
    let current = "fixture/current-value\"";
    let patterns = Patterns::new(
      [
        ("PAST_KEY".into(), history.into()),
        ("CURRENT_KEY".into(), current.into()),
        ("SHORT_KEY".into(), "tiny123".into()),
      ]
      .into(),
    );
    git(dir, "", &["init", "--quiet", "--template="])
      .await
      .unwrap();
    std::fs::write(dir.join("history.txt"), history).unwrap();
    git(dir, "", &["add", "."]).await.unwrap();
    let commit = |message| {
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--quiet",
        "-m",
        message,
      ]
    };
    git(dir, "", &commit("first")).await.unwrap();
    let encoded = &patterns.by_name["CURRENT_KEY"][1];
    std::fs::write(
      dir.join(format!("{encoded}.txt")),
      format!("{encoded}\ntiny123"),
    )
    .unwrap();
    std::fs::write(dir.join("history.txt"), "replaced").unwrap();
    git(dir, "", &["add", "."]).await.unwrap();
    git(dir, "", &commit("second")).await.unwrap();
    let tip = git(dir, "", &["rev-parse", "HEAD"]).await.unwrap();
    let tip = std::str::from_utf8(&tip).unwrap().trim();

    let mut hits = BTreeSet::new();
    scan_history(
      dir,
      "https://github.com/example/repo.git",
      "HEAD",
      &patterns,
      &mut hits,
    )
    .await
    .unwrap();
    assert!(hits.iter().any(
      |hit| hit.file == "***.txt" && hit.secret == "CURRENT_KEY"
    ));
    assert!(hits.iter().any(|hit| hit.file == "history.txt"
      && hit.secret == "PAST_KEY"
      && hit.commit == tip));
    let report = serde_json::to_string(&hits).unwrap();
    for value in [history, current, encoded, "SHORT_KEY"] {
      assert!(!report.contains(value));
    }
  }

  #[test]
  fn blocks_secrets_in_outbound_git_arguments() {
    let value = "fixture-outbound";
    let patterns =
      Patterns::new([("KEY".into(), value.into())].into());
    let repo = "https://github.com/example/repo.git";
    let args = fetch_args(repo, "main", "", &patterns).unwrap();
    assert!(!args.iter().any(|arg| arg.contains(value)));
    assert!(fetch_args(repo, value, "", &patterns).is_err());
    assert!(
      fetch_args(
        repo,
        "main",
        &format!("https://{value}.example.test"),
        &patterns
      )
      .is_err()
    );
    assert!(
      fetch_args(
        &format!("https://github.com/example/{value}.git"),
        "main",
        "",
        &patterns
      )
      .is_err()
    );
  }
}
