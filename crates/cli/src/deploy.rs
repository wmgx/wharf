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
  BuildArgs, BuildOpts,
  client::{CliError, CliResult, Client},
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
  let o = &args.opts;
  let tweaks = o.path.is_some()
    || o.dockerfile.is_some()
    || o.dockerfile_file.is_some()
    || o.template.is_some()
    || o.base.is_some()
    || o.install.is_some()
    || o.start.is_some()
    || o.start_file.is_some();
  let old = match existing {
    Some(Source::Build(old)) => Some(old),
    _ => None,
  };
  // GitHub 私有仓库没指定 token 密钥时，借本机 gh 的登录。
  let token_secret = match (&args.git, &args.git_token_secret) {
    (Some(repo), None) => crate::gh::private_token(c, repo).await?,
    (_, t) => t.clone(),
  };
  // 重新给出 --dir / --git 时，没给的选项沿用现有配置。
  let mut b = match (&args.dir, &args.git, old) {
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
        token_secret,
      }),
      ..old.cloned().unwrap_or_default()
    },
    (Some(_), None, _) => BuildSource {
      upload: None,
      git: None,
      ..old.cloned().unwrap_or_default()
    },
    (None, None, Some(b)) if tweaks => b.clone(),
    (None, None, _) if tweaks => {
      return Err(
        ApiError::invalid(format!(
          "构建选项只用于从代码构建的服务，{name} 不是"
        ))
        .into(),
      );
    }
    (None, None, _) => return Ok(None),
  };
  apply_opts(&mut b, o)?;

  let mut default_port = 8080;
  if let Some(dir) = &args.dir {
    let context = match &b.path {
      Some(p) => dir.join(p),
      None => dir.clone(),
    };
    default_port =
      preview(name, &context, &b, port, o.print_dockerfile)?;
    b.upload = Some(upload(c, dir).await?);
  } else if o.print_dockerfile {
    return Err(
      ApiError::invalid("--print-dockerfile 只支持本机目录").into(),
    );
  }
  Ok(Some(Built {
    source: Source::Build(b),
    default_port,
  }))
}

fn read_file(path: &Path) -> CliResult<String> {
  std::fs::read_to_string(path).map_err(|e| {
    ApiError::invalid(format!("读取 {}：{e}", path.display())).into()
  })
}

/// 把命令行选项合进构建来源。写 Dockerfile 和用模板互斥，换一种时清掉另一种的设置。
fn apply_opts(b: &mut BuildSource, o: &BuildOpts) -> CliResult<()> {
  if let Some(p) = &o.path {
    b.path = Some(p.clone());
  }
  if let Some(file) = &o.dockerfile_file {
    *b = BuildSource {
      dockerfile_content: Some(read_file(file)?),
      upload: b.upload.take(),
      git: b.git.take(),
      path: b.path.take(),
      ..BuildSource::default()
    };
    return Ok(());
  }
  if let Some(p) = &o.dockerfile {
    b.dockerfile = Some(p.clone());
    b.dockerfile_content = None;
  }
  let template_opts = o.template.is_some()
    || o.base.is_some()
    || o.install.is_some()
    || o.start.is_some()
    || o.start_file.is_some();
  if template_opts {
    b.dockerfile_content = None;
  }
  match o.template.as_deref() {
    Some("auto") => b.template = None,
    Some(t) => b.template = Some(t.to_string()),
    None => {}
  }
  if let Some(v) = &o.base {
    b.base = Some(v.clone());
  }
  if let Some(v) = &o.install {
    b.install = Some(v.clone());
  }
  if let Some(v) = &o.start {
    b.start = Some(v.clone());
  }
  if let Some(file) = &o.start_file {
    b.start = Some(read_file(file)?.trim_end().to_string());
  }
  Ok(())
}

/// 各模板的默认端口。
fn default_port(template: &str) -> u16 {
  match template {
    "python" => 8000,
    "node" => 3000,
    _ => 8080,
  }
}

fn exposed_port(dockerfile: &str) -> Option<u16> {
  dockerfile.lines().find_map(|l| {
    let rest = l.trim().strip_prefix("EXPOSE ")?;
    rest
      .split_whitespace()
      .next()?
      .split('/')
      .next()?
      .parse()
      .ok()
  })
}

/// 在本机判断会怎么构建，返回默认端口。认不出来时直接报错，不用等到服务器上。
/// `print`：打印 Dockerfile 后结束。
fn preview(
  name: &str,
  context: &Path,
  b: &BuildSource,
  port: Option<u16>,
  print: bool,
) -> CliResult<u16> {
  let done = |text: &str| -> CliResult<()> {
    if print {
      print!("{text}");
      return Err(CliError::Exit(0));
    }
    Ok(())
  };
  if let Some(content) = &b.dockerfile_content {
    eprintln!("使用 Wharf 里保存的 Dockerfile");
    done(content)?;
    return Ok(exposed_port(content).unwrap_or(8080));
  }
  let tree = LocalTree(context.to_path_buf());
  let dockerfile =
    b.dockerfile.clone().unwrap_or_else(|| "Dockerfile".into());
  if b.template.is_none()
    && let Some(content) = tree.read(&dockerfile)
  {
    eprintln!("使用 {dockerfile}");
    done(&content)?;
    return Ok(exposed_port(&content).unwrap_or(8080));
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
  let template = match &b.template {
    Some(t) => t.clone(),
    None => build::detect(&tree)?.to_string(),
  };
  let default = default_port(&template);
  let g = build::generate(
    &tree,
    &build::Options {
      service: name,
      port: port.unwrap_or(default),
      base: b.base.as_deref(),
      start: b.start.as_deref(),
      template: Some(&template),
      install: b.install.as_deref(),
    },
  )?;
  eprintln!(
    "{} {} 模板，启动：{}",
    if b.template.is_some() {
      "使用"
    } else {
      "识别为"
    },
    g.language,
    g.start.replace('\n', "; ")
  );
  done(&g.dockerfile)?;
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

/// compose 文件最大 1MB。
const COMPOSE_MAX: usize = 1 << 20;

/// GitHub 的网页链接换成原始文件：`github.com/o/r/blob/<ref>/<路径>` →
/// `raw.githubusercontent.com/o/r/<ref>/<路径>`。
pub fn raw_url(url: &str) -> String {
  let url = url.trim();
  if let Some(rest) = url.strip_prefix("https://github.com/")
    && let [owner, repo, "blob", tail] =
      rest.splitn(4, '/').collect::<Vec<_>>().as_slice()
  {
    return format!(
      "https://raw.githubusercontent.com/{owner}/{repo}/{tail}"
    );
  }
  url.to_string()
}

/// 在本机下载 compose 文件，15 秒超时，最大 1MB，内容要有 `services`。
pub async fn fetch_compose(url: &str) -> CliResult<String> {
  let url = raw_url(url);
  if !url.starts_with("https://") && !url.starts_with("http://") {
    return Err(
      ApiError::invalid(format!("{url} 不是网址"))
        .with_hint("写完整的 http:// 或 https:// 地址")
        .into(),
    );
  }
  let fail = |e: String| -> CliError {
    ApiError::invalid(format!("下载 {url} 失败：{e}"))
      .with_hint("网络不通时先下载到本地，再用 --compose <文件>")
      .into()
  };
  let mut resp = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(15))
    .build()
    .map_err(|e| fail(e.to_string()))?
    .get(&url)
    .send()
    .await
    .map_err(|e| fail(e.to_string()))?;
  if !resp.status().is_success() {
    return Err(fail(format!("HTTP {}", resp.status().as_u16())));
  }
  let mut body = Vec::new();
  while let Some(chunk) =
    resp.chunk().await.map_err(|e| fail(e.to_string()))?
  {
    body.extend_from_slice(&chunk);
    if body.len() > COMPOSE_MAX {
      return Err(fail("文件超过 1MB，不像 compose 文件".into()));
    }
  }
  let text = String::from_utf8(body)
    .map_err(|_| fail("内容不是文本".into()))?;
  let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
    .map_err(|e| fail(format!("不是 YAML：{e}")))?;
  if !doc.get("services").is_some_and(|s| s.is_mapping()) {
    return Err(fail(
      "内容里没有 services，不是 compose 文件".into(),
    ));
  }
  if text.contains("${") {
    eprintln!(
      "提醒：compose 里用了 ${{变量}}，原来靠 .env 文件提供的值要直接写进 compose，密码用 [[密钥名]]"
    );
  }
  Ok(text)
}
