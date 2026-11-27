//! 构建来源：`wharf deploy <目录>` 和 `wharf service deploy --git`。
//!
//! 本机目录先在本机预览（语言、启动命令、默认端口），再打包上传，最后照常生成计划。
//! 预览和上传进度打到标准错误，`--json` 时标准输出只有计划。

use std::path::Path;

use serde_json::Value;
use wharf_api_types::{
  ApiError,
  build::{self, ResolvedDockerfile},
  spec::{BuildSource, GitSource, Source},
};

use crate::{
  BuildArgs, BuildOpts,
  client::{CliError, CliResult, Client},
  pack::PackedTree,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposedPort {
  pub port: u16,
  pub udp: bool,
}

impl ExposedPort {
  pub fn tcp(port: u16) -> Self {
    Self { port, udp: false }
  }
}

pub(crate) fn merge_git(
  old: Option<&GitSource>,
  repo: &str,
  reference: Option<String>,
  token_secret: Option<String>,
  user: Option<String>,
) -> GitSource {
  let repo = repo.trim_end_matches('/');
  let same = old.filter(|old| old.repo.trim_end_matches('/') == repo);
  GitSource {
    repo: repo.into(),
    reference: reference
      .or_else(|| same.map(|g| g.reference.clone()))
      .unwrap_or_else(|| "main".into()),
    token_secret: token_secret
      .or_else(|| same.and_then(|g| g.token_secret.clone())),
    user: user.or_else(|| same.and_then(|g| g.user.clone())),
  }
}

/// 新建构建来源服务时，没给 `--port` 用的端口。
pub struct Built {
  pub source: Source,
  pub default_port: ExposedPort,
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
  let git_tweaks = args.git_ref.is_some()
    || args.git_token_secret.is_some()
    || args.git_user.is_some();
  let tweaks = git_tweaks
    || o.path.is_some()
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
  // 重新给出 --dir / --git 时，没给的选项沿用现有配置。
  let mut b = match (&args.dir, &args.git, old) {
    (Some(_), Some(_), _) => {
      return Err(
        ApiError::invalid("--dir 和 --git 只能给一个").into(),
      );
    }
    (None, Some(_), _) | (Some(_), None, _) => BuildSource {
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
  if let Some(repo) = args.git.as_deref().or_else(|| {
    (git_tweaks && args.dir.is_none())
      .then(|| b.git.as_ref().map(|g| g.repo.as_str()))
      .flatten()
  }) {
    let mut git = merge_git(
      old.and_then(|b| b.git.as_ref()),
      repo,
      args.git_ref.clone(),
      args.git_token_secret.clone(),
      args.git_user.clone(),
    );
    if args.sync_gh_token
      || (args.git.is_some() && git.token_secret.is_none())
    {
      git.token_secret =
        crate::gh::private_token(c, repo, args.sync_gh_token).await?;
    }
    b.git = Some(git);
  } else if git_tweaks {
    return Err(ApiError::invalid("Git 参数需要 Git 来源").into());
  }
  apply_opts(&mut b, o)?;

  let mut default_port = ExposedPort::tcp(8080);
  if let Some(dir) = &args.dir {
    let relative = |s: &str| {
      wharf_api_types::symlink::check_relative_entry(Path::new(s))
    };
    let context_rel = relative(b.path.as_deref().unwrap_or("."))?;
    let root = dir
      .canonicalize()
      .map_err(|e| ApiError::invalid(format!("读取代码目录：{e}")))?;
    let context = root.join(&context_rel);
    let mut keep = vec![context_rel.join(".dockerignore")];
    if b.dockerfile_content.is_none() && b.template.is_none() {
      keep.push(context_rel.join(relative(
        b.dockerfile.as_deref().unwrap_or("Dockerfile"),
      )?));
    }
    let files = wharf_pack::list_files_with(&root, &keep)?;
    let tree = PackedTree {
      root: &context,
      allowed: files
        .iter()
        .filter_map(|p| {
          p.strip_prefix(&context_rel).ok().map(Path::to_path_buf)
        })
        .collect(),
    };
    default_port =
      preview(name, &tree, &b, port, o.print_dockerfile)?;
    b.upload = Some(
      upload_packed(c, wharf_pack::pack_files(&root, files)?).await?,
    );
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
  if o.dockerfile.is_some()
    && o.template.as_deref().is_some_and(|t| t != "auto")
  {
    return Err(ApiError::invalid("--dockerfile 和 --template 不能同时指定")
      .with_hint("用仓库里的 Dockerfile 就只传 --dockerfile，用内置模板就只传 --template").into());
  }
  if let Some(p) = &o.dockerfile {
    b.dockerfile = Some(p.clone());
    b.dockerfile_content = None;
    b.template = None;
    b.base = None;
    b.install = None;
    b.start = None;
  }
  let template_opts = o.template.is_some()
    || o.base.is_some()
    || o.install.is_some()
    || o.start.is_some()
    || o.start_file.is_some();
  if template_opts {
    b.dockerfile = None;
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

fn exposed_port(dockerfile: &str) -> Option<ExposedPort> {
  dockerfile.lines().find_map(|line| {
    let mut words = line.split('#').next()?.split_whitespace();
    if !words.next()?.eq_ignore_ascii_case("EXPOSE") {
      return None;
    }
    words.find_map(|word| {
      let (number, protocol) =
        word.split_once('/').unwrap_or((word, "tcp"));
      let udp = protocol.eq_ignore_ascii_case("udp");
      let port = number.parse::<u16>().ok()?;
      (port != 0 && (udp || protocol.eq_ignore_ascii_case("tcp")))
        .then_some(ExposedPort { port, udp })
    })
  })
}

fn preview(
  name: &str,
  tree: &PackedTree<'_>,
  b: &BuildSource,
  port: Option<u16>,
  print: bool,
) -> CliResult<ExposedPort> {
  let mut opts = build::Options {
    service: name,
    port: port.unwrap_or_default(),
    base: b.base.as_deref(),
    start: b.start.as_deref(),
    template: b.template.as_deref(),
    install: b.install.as_deref(),
  };
  let resolved = build::resolve_dockerfile(
    tree,
    b.dockerfile_content.as_deref(),
    b.dockerfile.as_deref(),
    &opts,
  )?;
  let (text, default) = match resolved {
    ResolvedDockerfile::Inline { content, .. } => {
      eprintln!("使用 Wharf 里保存的 Dockerfile");
      let default =
        exposed_port(&content).unwrap_or(ExposedPort::tcp(8080));
      (content, default)
    }
    ResolvedDockerfile::File { path, content, .. } => {
      eprintln!("使用 {path}");
      let default =
        exposed_port(&content).unwrap_or(ExposedPort::tcp(8080));
      (content, default)
    }
    ResolvedDockerfile::Template(mut g) => {
      let default = g.default_port();
      if port.is_none() {
        opts.port = default;
        g = build::generate(tree, &opts)?;
      }
      eprintln!(
        "使用 {} 模板，启动：{}",
        g.language,
        g.start.replace('\n', "; ")
      );
      (g.dockerfile, ExposedPort::tcp(default))
    }
  };
  if print {
    print!("{text}");
    return Err(CliError::Exit(0));
  }
  Ok(default)
}

/// 打包上传，返回 sha256。控制面已有同样的包就不再上传。
pub(crate) async fn upload(
  c: &Client,
  dir: &Path,
) -> CliResult<String> {
  upload_packed(c, wharf_pack::pack(dir)?).await
}

pub(crate) async fn upload_file(
  c: &Client,
  file: &Path,
) -> CliResult<String> {
  upload_packed(c, wharf_pack::pack_file(file)?).await
}

async fn upload_packed(
  c: &Client,
  packed: wharf_pack::Packed,
) -> CliResult<String> {
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
