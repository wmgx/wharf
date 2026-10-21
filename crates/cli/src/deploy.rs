//! 构建来源：`wharf deploy <目录>` 和 `wharf service deploy --git`。
//!
//! 本机目录先在本机预览（语言、启动命令、默认端口），再打包上传，最后照常生成计划。
//! 预览和上传进度打到标准错误，`--json` 时标准输出只有计划。

use std::path::Path;

use serde_json::Value;
use wharf_api_types::{
  ApiError,
  build::{self, SourceTree},
  spec::{BuildSource, GitSource, Source},
};

use crate::{
  BuildArgs,
  client::{CliResult, Client},
  pack::{self, LocalTree},
};

/// 新建构建来源服务时，没给 `--port` 用的端口。
pub struct Built {
  pub source: Source,
  pub default_port: u16,
}

/// 按参数得出构建来源。没给构建相关参数时返回 `None`（沿用现有来源）。
pub async fn source(
  c: &Client,
  name: &str,
  args: &BuildArgs,
  existing: Option<&Source>,
  port: Option<u16>,
) -> CliResult<Option<Built>> {
  let tweaks = args.path.is_some()
    || args.dockerfile.is_some()
    || args.base.is_some()
    || args.start.is_some();
  let mut b = match (&args.dir, &args.git, existing) {
    (Some(_), Some(_), _) => {
      return Err(
        ApiError::invalid("--dir 和 --git 只能给一个").into(),
      );
    }
    (None, Some(repo), _) => BuildSource {
      upload: None,
      git: Some(GitSource {
        repo: repo.trim_end_matches('/').to_string(),
        reference: args
          .git_ref
          .clone()
          .unwrap_or_else(|| "main".into()),
        token_secret: args.git_token_secret.clone(),
      }),
      path: None,
      dockerfile: None,
      base: None,
      start: None,
    },
    (Some(_), None, _) => BuildSource {
      upload: None,
      git: None,
      path: None,
      dockerfile: None,
      base: None,
      start: None,
    },
    (None, None, Some(Source::Build(b))) if tweaks => b.clone(),
    (None, None, _) if tweaks => {
      return Err(
        ApiError::invalid(format!(
          "--path、--dockerfile、--base、--start 只用于从代码构建的服务，{name} 不是"
        ))
        .into(),
      );
    }
    (None, None, _) => return Ok(None),
  };
  // 重新给出 --dir / --git 时，没给的选项沿用现有配置。
  let old = match existing {
    Some(Source::Build(old)) => Some(old),
    _ => None,
  };
  b.path = args
    .path
    .clone()
    .or_else(|| old.and_then(|o| o.path.clone()));
  b.dockerfile = args
    .dockerfile
    .clone()
    .or_else(|| old.and_then(|o| o.dockerfile.clone()));
  b.base = args
    .base
    .clone()
    .or_else(|| old.and_then(|o| o.base.clone()));
  b.start = args
    .start
    .clone()
    .or_else(|| old.and_then(|o| o.start.clone()));

  let mut default_port = 8080;
  if let Some(dir) = &args.dir {
    let context = match &b.path {
      Some(p) => dir.join(p),
      None => dir.clone(),
    };
    default_port = preview(name, &context, &b, port)?;
    b.upload = Some(upload(c, dir).await?);
  }
  Ok(Some(Built {
    source: Source::Build(b),
    default_port,
  }))
}

/// 在本机判断会怎么构建，返回默认端口。认不出来时直接报错，不用等到服务器上。
fn preview(
  name: &str,
  context: &Path,
  b: &BuildSource,
  port: Option<u16>,
) -> CliResult<u16> {
  let tree = LocalTree(context.to_path_buf());
  let dockerfile =
    b.dockerfile.clone().unwrap_or_else(|| "Dockerfile".into());
  if let Some(content) = tree.read(&dockerfile) {
    eprintln!("使用 {dockerfile}");
    let exposed = content.lines().find_map(|l| {
      let rest = l.trim().strip_prefix("EXPOSE ")?;
      rest
        .split_whitespace()
        .next()?
        .split('/')
        .next()?
        .parse()
        .ok()
    });
    return Ok(exposed.unwrap_or(8080));
  }
  if b.dockerfile.is_some() {
    return Err(
      ApiError::invalid(format!(
        "{} 里没有 {dockerfile}",
        context.display()
      ))
      .into(),
    );
  }
  let probe = |p: u16| {
    build::generate(
      &tree,
      &build::Options {
        service: name,
        port: p,
        base: b.base.as_deref(),
        start: b.start.as_deref(),
      },
    )
  };
  let lang = probe(port.unwrap_or(8080))?.language;
  let default = if lang == "python" { 8000 } else { 8080 };
  let g = probe(port.unwrap_or(default))?;
  eprintln!("识别为 {}，启动：{}", g.language, g.start);
  Ok(default)
}

/// 打包上传，返回 sha256。控制面已有同样的包就不再上传。
pub(crate) async fn upload(
  c: &Client,
  dir: &Path,
) -> CliResult<String> {
  let packed = pack::pack(dir)?;
  eprintln!(
    "打包 {} 个文件，{} KiB（{}）",
    packed.files,
    packed.bytes.len() / 1024,
    &packed.sha256[..12]
  );
  let path = format!("/api/uploads/{}", packed.sha256);
  let existing: Value = c.get(&path).await?;
  if existing["exists"] == true {
    eprintln!("控制面上已有这份代码，跳过上传");
  } else {
    eprintln!("上传到控制面");
    let _: Value = c.put_bytes(&path, packed.bytes).await?;
  }
  Ok(packed.sha256)
}
