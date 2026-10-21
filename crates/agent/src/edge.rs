//! 边缘应用：取代码，在 node 容器里执行 wrangler 发布 Worker / Pages。
//!
//! - 代码放在 `<数据目录>/builds/` 下的临时目录，结束后删除；
//! - 项目里装了 wrangler 就用项目的，没装用固定版本；
//! - Cloudflare token 走环境变量，不出现在命令行里；npm 缓存放在数据目录，下次更快。

use std::time::Duration;

use serde_json::Value;
use wharf_api_types::{
  ApiError,
  agent::{
    EdgeBuildJob, EdgeBuildResult, NODE_IMAGE, WRANGLER_VERSION,
  },
  spec::EdgeKind,
  validate_name,
};

use crate::{
  build::{
    fetch_code, random_suffix, relative, remove_container, to_value,
  },
  docker::{Docker, io_err},
  exec::Ctx,
};

const DEPLOY_TIMEOUT: Duration = Duration::from_secs(30 * 60);

const WRANGLER_CONFIGS: [&str; 3] =
  ["wrangler.toml", "wrangler.json", "wrangler.jsonc"];

/// 容器里执行的脚本。参数都从环境变量读。
const SCRIPT: &str = r#"set -e
if [ -f package-lock.json ]; then npm ci --no-audit --no-fund
elif [ -f package.json ]; then npm install --no-audit --no-fund
fi
if [ -n "$BUILD_CMD" ]; then echo "> $BUILD_CMD"; sh -c "$BUILD_CMD"; fi
if [ -x node_modules/.bin/wrangler ]; then W=node_modules/.bin/wrangler
else W="npx --yes wrangler@$WRANGLER_VERSION"
fi
if [ "$KIND" = pages ]; then
  if [ ! -d "$OUTPUT" ]; then echo "发布目录 $OUTPUT 不存在" >&2; exit 1; fi
  $W pages deploy "$OUTPUT" --project-name "$PROJECT" --branch "$BRANCH" --commit-dirty=true
else
  $W deploy --name "$PROJECT" --keep-vars
fi"#;

pub async fn run(
  docker: &Docker,
  core_url: &str,
  job: &EdgeBuildJob,
  ctx: &Ctx,
) -> Result<Value, ApiError> {
  validate_name("边缘应用", &job.app)?;
  let work = docker.data_dir.join("builds").join(format!(
    "edge-{}-{}",
    job.app,
    random_suffix()
  ));
  std::fs::create_dir_all(&work).map_err(io_err(&work))?;
  let result = deploy_in(docker, core_url, job, &work, ctx).await;
  if let Err(e) = std::fs::remove_dir_all(&work) {
    tracing::warn!("删除构建目录 {} 失败：{e}", work.display());
  }
  to_value(result?)
}

async fn deploy_in(
  docker: &Docker,
  core_url: &str,
  job: &EdgeBuildJob,
  work: &std::path::Path,
  ctx: &Ctx,
) -> Result<EdgeBuildResult, ApiError> {
  let commit =
    fetch_code(docker, core_url, &job.app, &job.fetch, work, ctx)
      .await?;
  let src = work.join("src");
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
  let output = match (&job.output, &job.build) {
    (Some(o), _) => {
      relative(o)?;
      o.clone()
    }
    (None, Some(_)) => "dist".to_string(),
    (None, None) => ".".to_string(),
  };
  if job.kind == EdgeKind::Worker
    && !WRANGLER_CONFIGS.iter().any(|f| context.join(f).is_file())
  {
    return Err(
      ApiError::invalid("代码里没有 wrangler.toml / wrangler.json(c)")
        .with_hint(
          "wrangler 项目要有配置文件；单文件 Worker 用 wharf edge deploy <名字> --script <文件>",
        ),
    );
  }

  let mut warnings = Vec::new();
  docker
    .pull(NODE_IMAGE, &job.pull, ctx, &mut warnings)
    .await?;
  let cache = docker.data_dir.join("cache").join("npm");
  std::fs::create_dir_all(&cache).map_err(io_err(&cache))?;

  let name = format!("wharf-edge-{}", job.app);
  remove_container(docker, &name).await;
  ctx.say(match job.kind {
    EdgeKind::Worker => {
      format!("用 wrangler 发布 Worker {}", job.project)
    }
    EdgeKind::Pages => {
      format!("发布 Pages {}（目录 {output}）", job.project)
    }
  });
  let mut cmd = docker
    .cmd()
    .args(["run", "--rm", "--name", &name, "--network", "host"])
    .args([
      "-v",
      &format!("{}:/app", context.display()),
      "-w",
      "/app",
    ])
    .args(["-v", &format!("{}:/root/.npm", cache.display())])
    .args([
      "-e",
      "CLOUDFLARE_API_TOKEN",
      "-e",
      "CLOUDFLARE_ACCOUNT_ID",
      "-e",
      "KIND",
      "-e",
      "PROJECT",
      "-e",
      "BRANCH",
      "-e",
      "OUTPUT",
      "-e",
      "BUILD_CMD",
      "-e",
      "WRANGLER_VERSION",
    ])
    .args(["-e", "CI=true", "-e", "WRANGLER_SEND_METRICS=false"]);
  for (key, value) in &job.build_env {
    cmd = cmd.args(["-e", &format!("{key}={value}")]);
  }
  let result = cmd
    .args(["--entrypoint", "sh", NODE_IMAGE, "-c", SCRIPT])
    .env("CLOUDFLARE_API_TOKEN", &job.api_token.0)
    .env("CLOUDFLARE_ACCOUNT_ID", &job.account_id)
    .env("KIND", job.kind.as_str())
    .env("PROJECT", &job.project)
    .env("BRANCH", job.branch.as_deref().unwrap_or("main"))
    .env("OUTPUT", &output)
    .env("BUILD_CMD", job.build.as_deref().unwrap_or_default())
    .env("WRANGLER_VERSION", WRANGLER_VERSION)
    .timeout(DEPLOY_TIMEOUT)
    .stream(true)
    .run(ctx)
    .await;
  if result.is_err() {
    remove_container(docker, &name).await;
  }
  result?.check("发布")?;
  ctx.say("已发布");
  Ok(EdgeBuildResult { commit })
}
