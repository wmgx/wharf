//! 从代码构建镜像：取代码 → 定 Dockerfile（没有就按语言生成）→ 按镜像源先拉基础镜像 →
//! `docker build`。
//!
//! - 代码放在 `<数据目录>/builds/` 下的临时目录，结束后删除；数据目录在宿主机和
//!   agent 容器里路径相同，git 容器才能挂载它；
//! - git 克隆在临时容器里做（固定名字，取消或超时后按名字删掉），仓库地址、ref、
//!   token 都走环境变量，不出现在命令行里；
//! - 上传的代码包带一次性口令从控制面下载，校验 sha256 后再解压。

use std::{
  path::{Component, Path, PathBuf},
  time::Duration,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use wharf_api_types::{
  ApiError, ErrorCode,
  agent::{BuildFetch, BuildJob, BuildResult, GIT_IMAGE, PullPolicy},
  build::{self, SourceTree},
  validate_name,
};

use crate::{
  docker::{Docker, io_err},
  exec::{Cmd, Ctx},
};

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CLONE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const BUILD_TIMEOUT: Duration = Duration::from_secs(40 * 60);
/// 代码包大小上限，和控制面接收上传的上限一致。
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
/// 每个服务保留几个旧镜像，回滚到最近的版本时不用重新构建。
const KEEP_IMAGES: usize = 3;

pub async fn run(
  docker: &Docker,
  core_url: &str,
  job: &BuildJob,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  validate_name("service", &job.service)?;
  if !job.force && docker.image_exists(&job.image, ctx).await {
    ctx.say(format!("镜像 {} 已存在，跳过构建", job.image));
    return to_value(BuildResult {
      skipped: true,
      commit: None,
    });
  }
  let work = docker.data_dir.join("builds").join(format!(
    "{}-{}",
    job.service,
    random_suffix()
  ));
  std::fs::create_dir_all(&work).map_err(io_err(&work))?;
  let result = build_in(docker, core_url, job, &work, ctx).await;
  if let Err(e) = std::fs::remove_dir_all(&work) {
    tracing::warn!("删除构建目录 {} 失败：{e}", work.display());
  }
  let result = result?;
  prune_old_images(docker, &job.service, &job.image).await;
  to_value(result)
}

async fn build_in(
  docker: &Docker,
  core_url: &str,
  job: &BuildJob,
  work: &Path,
  ctx: &Ctx,
) -> Result<BuildResult, ApiError> {
  let src = work.join("src");
  let commit = fetch_code(
    docker,
    core_url,
    &job.service,
    &job.fetch,
    &job.pull,
    work,
    ctx,
  )
  .await?;

  let context = match &job.path {
    Some(p) => src.join(relative(p)?),
    None => src.clone(),
  };
  if !context.is_dir() {
    return Err(ApiError::invalid(format!(
      "代码里没有目录 {}",
      job.path.as_deref().unwrap_or_default()
    )));
  }
  let (dockerfile, images) = dockerfile(job, &context, work, ctx)?;

  let mut warnings = Vec::new();
  for image in &images {
    if let Err(e) =
      docker.pull(image, &job.pull, ctx, &mut warnings).await
    {
      if e.code == ErrorCode::Cancelled {
        return Err(e);
      }
      ctx.say(format!(
        "提醒：基础镜像 {image} 没有拉下来，交给 docker build 自己拉"
      ));
    }
  }

  ctx.say(format!("构建 {}", job.image));
  let mut cmd = docker
    .cmd()
    .args(["build", "--progress", "plain", "--pull=false"])
    .args(["-t", &job.image, "-f", &dockerfile.to_string_lossy()])
    .args(["--label", &format!("wharf.service={}", job.service)]);
  for (key, value) in &job.build_env {
    cmd = cmd.args(["--build-arg", &format!("{key}={value}")]);
  }
  let out = cmd
    .arg(context.to_string_lossy().to_string())
    .timeout(BUILD_TIMEOUT)
    .stream(true)
    .run(ctx)
    .await?;
  if !out.success {
    return Err(build_failed(&out.stderr));
  }
  ctx.say(format!("已构建 {}", job.image));
  Ok(BuildResult {
    skipped: false,
    commit,
  })
}

/// 把代码取到 `<work>/src`：下载控制面上的代码包，或在容器里 git clone。
/// 返回 git 来源的 commit。
pub async fn fetch_code(
  docker: &Docker,
  core_url: &str,
  name: &str,
  fetch: &BuildFetch,
  pull: &PullPolicy,
  work: &Path,
  ctx: &Ctx,
) -> Result<Option<String>, ApiError> {
  let src = work.join("src");
  std::fs::create_dir_all(&src).map_err(io_err(&src))?;
  let commit = match fetch {
    BuildFetch::Upload { sha256, token } => {
      let archive = work.join("source.tar.gz");
      download(core_url, sha256, &token.0, &archive, ctx).await?;
      ctx.say("解压代码");
      // 包里的修改时间都是 0（为了内容相同时 sha256 相同），解压时用当前时间：
      // BuildKit 按大小和修改时间判断构建上下文里的文件变没变，
      // 改了内容但大小没变的文件会被当成没变。
      Cmd::new("tar")
        .args([
          "-xzf",
          &archive.to_string_lossy(),
          "--no-same-owner",
          "-m",
        ])
        .arg("-C")
        .arg(src.to_string_lossy().to_string())
        .timeout(Duration::from_secs(300))
        .run(ctx)
        .await?
        .check("解压代码包")?;
      None
    }
    BuildFetch::Git {
      repo,
      reference,
      token,
    } => Some({
      // 先按服务器的镜像源拉 git 镜像，`docker run` 自己拉只认官方地址。
      if !docker.image_exists(GIT_IMAGE, ctx).await {
        docker.pull(GIT_IMAGE, pull, ctx, &mut Vec::new()).await?;
      }
      clone(
        docker,
        name,
        repo,
        reference,
        token.as_ref().map(|t| t.0.as_str()),
        &src,
        ctx,
      )
      .await?
    }),
  };
  Ok(commit)
}

/// 构建日志已经实时打出来了，错误里只留 BuildKit 报的 ERROR 行。
fn build_failed(stderr: &str) -> ApiError {
  let mut errors: Vec<&str> = Vec::new();
  for line in stderr.lines().filter(|l| l.contains("ERROR")) {
    let line = line.trim();
    if !errors.contains(&line) {
      errors.push(line);
    }
  }
  let detail = match errors.len() {
    0 => crate::exec::tail_lines(stderr, 5),
    n => errors[n.saturating_sub(3)..].join("\n"),
  };
  ApiError::new(ErrorCode::AgentFailed, format!("构建失败：{detail}"))
    .with_hint("完整的构建日志在这次执行的输出里")
}

/// 用代码里的 Dockerfile，没有就按语言生成到构建目录外面（不混进代码）。
/// 返回 Dockerfile 路径和要先拉的镜像。
fn dockerfile(
  job: &BuildJob,
  context: &Path,
  work: &Path,
  ctx: &Ctx,
) -> Result<(PathBuf, Vec<String>), ApiError> {
  if let Some(content) = &job.dockerfile_content {
    ctx.say("使用 Wharf 里保存的 Dockerfile");
    let path = work.join("Dockerfile.wharf");
    std::fs::write(&path, content).map_err(io_err(&path))?;
    return Ok((path, build::from_images(content)));
  }
  let own = match &job.dockerfile {
    Some(p) => {
      let path = context.join(relative(p)?);
      if !path.is_file() {
        return Err(ApiError::invalid(format!("代码里没有 {p}")));
      }
      Some(path)
    }
    // 指定了模板时不用代码里的 Dockerfile。
    None if job.template.is_some() => None,
    None => Some(context.join("Dockerfile")).filter(|p| p.is_file()),
  };
  if let Some(path) = own {
    ctx.say(format!(
      "使用代码里的 {}",
      path.strip_prefix(context).unwrap_or(&path).display()
    ));
    let content =
      std::fs::read_to_string(&path).map_err(io_err(&path))?;
    return Ok((path, build::from_images(&content)));
  }
  let generated = build::generate(
    &FsTree(context),
    &build::Options {
      service: &job.service,
      port: job.port,
      base: job.base.as_deref(),
      start: job.start.as_deref(),
      template: job.template.as_deref(),
      install: job.install.as_deref(),
    },
  )?;
  ctx.say(format!(
    "按 {} 模板生成 Dockerfile（启动：{}）：",
    generated.language,
    generated.start.replace('\n', "; ")
  ));
  for line in generated.dockerfile.lines() {
    ctx.say(format!("  {line}"));
  }
  let path = work.join("Dockerfile.wharf");
  std::fs::write(&path, &generated.dockerfile)
    .map_err(io_err(&path))?;
  Ok((path, generated.images))
}

/// 只接受代码里的相对路径，不能跳出去。
pub(crate) fn relative(p: &str) -> Result<PathBuf, ApiError> {
  let path = PathBuf::from(p.trim_start_matches("./"));
  let ok = !p.is_empty()
    && path
      .components()
      .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
  if ok {
    Ok(path)
  } else {
    Err(ApiError::invalid(format!(
      "路径 {p} 不合法：要写代码里的相对路径"
    )))
  }
}

struct FsTree<'a>(&'a Path);

impl SourceTree for FsTree<'_> {
  fn read(&self, path: &str) -> Option<String> {
    let path = self.0.join(path);
    // 只读小文件：判断语言用不到大文件。
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
      return None;
    }
    std::fs::read_to_string(path).ok()
  }

  fn list(&self, dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(self.0.join(dir)) else {
      return vec![];
    };
    entries
      .filter_map(Result::ok)
      .map(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
          format!("{name}/")
        } else {
          name
        }
      })
      .collect()
  }
}

async fn download(
  core_url: &str,
  sha256: &str,
  token: &str,
  to: &Path,
  ctx: &Ctx,
) -> Result<(), ApiError> {
  if sha256.len() != 64
    || !sha256.bytes().all(|c| c.is_ascii_hexdigit())
  {
    return Err(ApiError::invalid("代码包的 sha256 不合法"));
  }
  ctx.say("从控制面下载代码包");
  let url = format!(
    "{}/agent/uploads/{sha256}",
    core_url.trim_end_matches('/')
  );
  let fetch = async {
    let client = reqwest::Client::builder()
      .timeout(DOWNLOAD_TIMEOUT)
      .build()
      .map_err(|e| ApiError::internal(e.to_string()))?;
    let resp = client
      .get(&url)
      .bearer_auth(token)
      .send()
      .await
      .map_err(|e| download_err(&e.without_url().to_string()))?;
    if !resp.status().is_success() {
      return Err(download_err(&format!("HTTP {}", resp.status())));
    }
    let mut file =
      tokio::fs::File::create(to).await.map_err(io_err(to))?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut resp = resp;
    while let Some(chunk) = resp
      .chunk()
      .await
      .map_err(|e| download_err(&e.without_url().to_string()))?
    {
      size += chunk.len() as u64;
      if size > MAX_ARCHIVE {
        return Err(download_err("代码包超过 512 MiB"));
      }
      hasher.update(&chunk);
      file.write_all(&chunk).await.map_err(io_err(to))?;
    }
    file.flush().await.map_err(io_err(to))?;
    if hex::encode(hasher.finalize()) != sha256 {
      return Err(download_err("sha256 不一致"));
    }
    ctx.say(format!("已下载 {} KiB", size / 1024));
    Ok(())
  };
  tokio::select! {
    r = fetch => r,
    _ = ctx.cancel.cancelled() => Err(ApiError::new(ErrorCode::Cancelled, "下载代码包已取消")),
  }
}

fn download_err(detail: &str) -> ApiError {
  ApiError::new(
    ErrorCode::AgentFailed,
    format!("从控制面下载代码包失败：{detail}"),
  )
}

/// 在临时容器里浅克隆到 `src`，返回 commit。
async fn clone(
  docker: &Docker,
  service: &str,
  repo: &str,
  reference: &str,
  token: Option<&str>,
  src: &Path,
  ctx: &Ctx,
) -> Result<String, ApiError> {
  ctx.say(format!("拉取代码 {repo} @ {reference}"));
  let name = format!("wharf-git-{service}");
  remove_container(docker, &name).await;
  // GitHub 等用 `x-access-token:<token>` 的 basic 认证。
  let script = r#"set -e
git init -q
git remote add origin "$REPO"
if [ -n "$GIT_TOKEN" ]; then
  auth="Authorization: Basic $(printf 'x-access-token:%s' "$GIT_TOKEN" | base64 | tr -d '\n')"
  git -c http.extraHeader="$auth" fetch -q --depth 1 origin "$REF"
else
  git fetch -q --depth 1 origin "$REF"
fi
git -c advice.detachedHead=false checkout -q FETCH_HEAD
git rev-parse HEAD
rm -rf .git"#;
  let result = docker
    .cmd()
    .args(["run", "--rm", "--name", &name, "--network", "host"])
    .args(["-v", &format!("{}:/git", src.display()), "-w", "/git"])
    .args(["-e", "REPO", "-e", "REF", "-e", "GIT_TOKEN"])
    .args(["-e", "GIT_TERMINAL_PROMPT=0"])
    .args(["--entrypoint", "sh", GIT_IMAGE, "-c", script])
    .env("REPO", repo)
    .env("REF", reference)
    .env("GIT_TOKEN", token.unwrap_or_default())
    .timeout(CLONE_TIMEOUT)
    .run(ctx)
    .await;
  if result.is_err() {
    remove_container(docker, &name).await;
  }
  let out = result?.check("拉取代码")?;
  let commit = out
    .stdout
    .lines()
    .map(str::trim)
    .rfind(|l| {
      l.len() == 40 && l.bytes().all(|c| c.is_ascii_hexdigit())
    })
    .ok_or_else(|| {
      ApiError::new(ErrorCode::AgentFailed, "拉取代码后读不到 commit")
    })?
    .to_string();
  ctx.say(format!("commit {}", &commit[..12]));
  Ok(commit)
}

pub(crate) async fn remove_container(docker: &Docker, name: &str) {
  let _ = docker
    .cmd()
    .args(["rm", "-f", name])
    .timeout(Duration::from_secs(30))
    .run(&Ctx::detached())
    .await;
}

/// 删掉这个服务更早的镜像，保留最近几个。正在用的删不掉，忽略错误。
async fn prune_old_images(
  docker: &Docker,
  service: &str,
  current: &str,
) {
  let ctx = Ctx::detached();
  let Ok(out) = docker
    .cmd()
    .args([
      "images",
      "--filter",
      &format!("label=wharf.service={service}"),
      "--format",
      "{{.Repository}}:{{.Tag}}",
    ])
    .timeout(Duration::from_secs(30))
    .run(&ctx)
    .await
  else {
    return;
  };
  let old: Vec<&str> = out
    .stdout
    .lines()
    .map(str::trim)
    .filter(|l| {
      !l.is_empty() && *l != current && !l.ends_with(":<none>")
    })
    .skip(KEEP_IMAGES - 1)
    .collect();
  for image in old {
    let _ = docker
      .cmd()
      .args(["image", "rm", image])
      .timeout(Duration::from_secs(60))
      .run(&ctx)
      .await;
  }
}

pub(crate) fn random_suffix() -> String {
  let mut bytes = [0u8; 4];
  getrandom::fill(&mut bytes).expect("随机数不可用");
  hex::encode(bytes)
}

pub(crate) fn to_value<T: serde::Serialize>(
  v: T,
) -> Result<Value, ApiError> {
  serde_json::to_value(v)
    .map_err(|e| ApiError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn build_error_keeps_only_error_lines() {
    let log = "#8 RUN pip install\n#8 1.5 ERROR: HTTP 403\n#8 ERROR: exit 1\n------\n#8 1.5 ERROR: HTTP 403\nERROR: failed to solve";
    let e = build_failed(log);
    assert_eq!(
      e.message,
      "构建失败：#8 1.5 ERROR: HTTP 403\n#8 ERROR: exit 1\nERROR: failed to solve"
    );
  }

  #[test]
  fn paths_stay_inside_the_code() {
    assert!(relative("app").is_ok());
    assert!(relative("./svc/api").is_ok());
    for bad in ["", "/etc", "../x", "a/../../b"] {
      assert!(relative(bad).is_err(), "{bad}");
    }
  }

  #[test]
  fn tree_lists_dirs_with_slash() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("cmd")).unwrap();
    std::fs::write(dir.path().join("go.mod"), "module x").unwrap();
    let tree = FsTree(dir.path());
    let mut names = tree.list("");
    names.sort();
    assert_eq!(names, vec!["cmd/", "go.mod"]);
    assert_eq!(tree.read("go.mod").as_deref(), Some("module x"));
  }
}
