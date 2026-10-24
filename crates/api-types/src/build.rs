//! 没有 Dockerfile 时按模板生成。agent 构建时用，CLI 部署前预览也用同一份逻辑。
//!
//! 模板可以指定（`template`），不指定时按文件识别：
//! - Go：`go.mod`。编译成静态二进制放进 alpine，不在最终镜像里装包（国内 apk 慢）；
//! - Node：`package.json`。有 lock 用 `npm ci`，有 build 脚本就执行；
//! - Python：`requirements.txt` / `pyproject.toml` / `*.py`。启动命令按 Procfile、
//!   FastAPI / Flask / Django 猜，猜不出来要求 `--start`；
//! - 静态站：`index.html`，用 Caddy 提供文件。
//!
//! 启动命令可以是多行（相当于启动脚本），用 `sh -c` 执行。
//! 生成的 Dockerfile 用 `$PORT`，容器里设成服务的端口。

use crate::ApiError;

pub const GO_BASE: &str = "golang:1.25-alpine";
pub const GO_RUNTIME: &str = "alpine:3.22";
pub const PYTHON_BASE: &str = "python:3.13-slim";
pub const NODE_BASE: &str = "node:22-bookworm-slim";
pub const STATIC_BASE: &str = "caddy:2-alpine";

/// 可选的模板：（id，名字，默认基础镜像）。
pub const TEMPLATES: [(&str, &str, &str); 4] = [
  ("python", "Python", PYTHON_BASE),
  ("node", "Node", NODE_BASE),
  ("go", "Go", GO_BASE),
  ("static", "静态站", STATIC_BASE),
];

/// 读取代码目录。路径用 `/` 分隔、相对构建目录。
pub trait SourceTree {
  fn read(&self, path: &str) -> Option<String>;
  /// 目录下的条目名，子目录以 `/` 结尾。
  fn list(&self, dir: &str) -> Vec<String>;
  fn exists(&self, path: &str) -> bool {
    self.read(path).is_some()
  }
}

pub struct Options<'a> {
  pub service: &'a str,
  pub port: u16,
  pub base: Option<&'a str>,
  pub start: Option<&'a str>,
  /// `python` / `node` / `go` / `static`，不填时按文件识别。
  pub template: Option<&'a str>,
  /// 覆盖安装依赖的命令（Python、Node）。
  pub install: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
  /// 用的模板：`go` / `node` / `python` / `static`。
  pub language: &'static str,
  pub dockerfile: String,
  /// 给人看的启动方式。
  pub start: String,
  /// 模板里要拉的镜像，构建前按服务器的镜像源先拉好。
  pub images: Vec<String>,
}

pub fn generate(
  tree: &dyn SourceTree,
  opts: &Options,
) -> Result<Generated, ApiError> {
  let template = match opts.template {
    Some(t) => t,
    None => detect(tree)?,
  };
  if opts.install.is_some() && matches!(template, "go" | "static") {
    return Err(ApiError::invalid(format!(
      "{template} 模板不支持自定义安装命令"
    )));
  }
  match template {
    "go" => go(tree, opts),
    "node" => node(tree, opts),
    "python" => python(tree, opts),
    "static" => Ok(static_site(opts)),
    other => Err(ApiError::invalid(format!(
      "没有模板 {other}，可选：python、node、go、static"
    ))),
  }
}

/// 按文件识别模板。
pub fn detect(
  tree: &dyn SourceTree,
) -> Result<&'static str, ApiError> {
  if tree.exists("go.mod") {
    return Ok("go");
  }
  if tree.exists("package.json") {
    return Ok("node");
  }
  let has_py = tree.exists("requirements.txt")
    || tree.exists("pyproject.toml")
    || tree.list("").iter().any(|f| f.ends_with(".py"));
  if has_py {
    return Ok("python");
  }
  if tree.exists("index.html") {
    return Ok("static");
  }
  Err(
    ApiError::invalid(
      "认不出语言：代码里没有 Dockerfile、go.mod、package.json、requirements.txt、pyproject.toml、.py 或 index.html",
    )
    .with_hint("用 --template 指定模板，或加一个 Dockerfile，或用 --path 指到项目所在的子目录"),
  )
}

fn has_main(tree: &dyn SourceTree, dir: &str) -> bool {
  tree.list(dir).iter().any(|f| {
    f.ends_with(".go")
      && !f.ends_with("_test.go")
      && tree.read(&format!("{dir}{f}")).is_some_and(|src| {
        src.lines().any(|l| l.trim() == "package main")
      })
  })
}

/// main 包在哪：根目录，或者 `cmd/` 下唯一的一个（多个时取和服务同名的）。
fn go_main(
  tree: &dyn SourceTree,
  service: &str,
) -> Result<String, ApiError> {
  if has_main(tree, "") {
    return Ok(".".into());
  }
  let mains: Vec<String> = tree
    .list("cmd/")
    .into_iter()
    .filter_map(|d| d.strip_suffix('/').map(str::to_string))
    .filter(|d| has_main(tree, &format!("cmd/{d}/")))
    .collect();
  match mains.as_slice() {
    [one] => Ok(format!("./cmd/{one}")),
    [] => Err(
      ApiError::invalid(
        "没找到 Go 的 main 包（根目录或 cmd/<名字>/）",
      )
      .with_hint(
        "加一个 Dockerfile，或用 --path 指到 main 包所在目录",
      ),
    ),
    many => {
      if many.iter().any(|d| d == service) {
        Ok(format!("./cmd/{service}"))
      } else {
        Err(
          ApiError::invalid(format!(
            "cmd/ 下有多个 main 包（{}），不知道构建哪个",
            many.join("、")
          ))
          .with_hint("服务名取成其中一个，或用 --path 指定"),
        )
      }
    }
  }
}

fn go(
  tree: &dyn SourceTree,
  opts: &Options,
) -> Result<Generated, ApiError> {
  let pkg = go_main(tree, opts.service)?;
  let base = opts.base.unwrap_or(GO_BASE);
  let sum = if tree.exists("go.sum") { " go.sum" } else { "" };
  let run = match opts.start {
    Some(cmd) => cmd_line(cmd),
    None => r#"ENTRYPOINT ["/app"]"#.to_string(),
  };
  let dockerfile = format!(
    r#"# Wharf 按 Go 模板生成
FROM {base} AS build
ARG GOPROXY
ARG GOSUMDB
WORKDIR /src
COPY go.mod{sum} ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/app {pkg}

FROM {GO_RUNTIME}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/app /app
ENV PORT={port}
EXPOSE {port}
{run}
"#,
    port = opts.port,
  );
  Ok(Generated {
    language: "go",
    dockerfile,
    start: opts
      .start
      .map(str::to_string)
      .unwrap_or_else(|| format!("编译 {pkg} 后运行")),
    images: vec![base.to_string(), GO_RUNTIME.to_string()],
  })
}

fn cmd_line(cmd: &str) -> String {
  let json = serde_json::to_string(&["sh", "-c", cmd])
    .unwrap_or_else(|_| "[]".into());
  format!("CMD {json}")
}

/// `app = FastAPI(` 里的 `app`。
fn assigned_var(src: &str, ctor: &str) -> Option<String> {
  src.lines().find_map(|line| {
    let (left, right) = line.split_once('=')?;
    if !right.trim_start().starts_with(ctor) {
      return None;
    }
    let name = left.trim();
    (!name.is_empty()
      && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
    .then(|| name.to_string())
  })
}

struct PyStart {
  cmd: String,
  /// 依赖里没有、要额外装的包。
  extra: Option<&'static str>,
}

fn python_start(
  tree: &dyn SourceTree,
  deps: &str,
) -> Result<PyStart, ApiError> {
  if let Some(web) = tree.read("Procfile").and_then(|p| {
    p.lines().find_map(|l| {
      l.strip_prefix("web:").map(|c| c.trim().to_string())
    })
  }) {
    return Ok(PyStart {
      cmd: web,
      extra: None,
    });
  }
  let need = |pkg: &'static str| (!deps.contains(pkg)).then_some(pkg);
  for file in ["main.py", "app.py", "server.py", "asgi.py", "wsgi.py"]
  {
    let Some(src) = tree.read(file) else { continue };
    let module = file.trim_end_matches(".py");
    if let Some(var) = assigned_var(&src, "FastAPI(") {
      return Ok(PyStart {
        cmd: format!(
          "uvicorn {module}:{var} --host 0.0.0.0 --port $PORT"
        ),
        extra: need("uvicorn"),
      });
    }
    if let Some(var) = assigned_var(&src, "Flask(") {
      return Ok(PyStart {
        cmd: format!("gunicorn -b 0.0.0.0:$PORT {module}:{var}"),
        extra: need("gunicorn"),
      });
    }
  }
  if tree.exists("manage.py") {
    let project = tree.list("").into_iter().find_map(|d| {
      let d = d.strip_suffix('/')?.to_string();
      tree.exists(&format!("{d}/wsgi.py")).then_some(d)
    });
    if let Some(project) = project {
      return Ok(PyStart {
        cmd: format!("gunicorn -b 0.0.0.0:$PORT {project}.wsgi"),
        extra: need("gunicorn"),
      });
    }
  }
  for file in ["main.py", "app.py", "server.py"] {
    if tree.exists(file) {
      return Ok(PyStart {
        cmd: format!("python {file}"),
        extra: None,
      });
    }
  }
  Err(
    ApiError::invalid("猜不出 Python 服务的启动命令")
      .with_hint(
        "用 --start 指定，例如 --start \"python run.py\"，监听端口用环境变量 $PORT",
      ),
  )
}

fn python(
  tree: &dyn SourceTree,
  opts: &Options,
) -> Result<Generated, ApiError> {
  let requirements = tree.read("requirements.txt");
  let pyproject = tree.read("pyproject.toml");
  let deps = format!(
    "{}\n{}",
    requirements.as_deref().unwrap_or_default(),
    pyproject.as_deref().unwrap_or_default()
  )
  .to_lowercase();
  let start = match opts.start {
    Some(cmd) => PyStart {
      cmd: cmd.to_string(),
      extra: None,
    },
    None => python_start(tree, &deps)?,
  };
  let base = opts.base.unwrap_or(PYTHON_BASE);
  let mut steps = Vec::new();
  if let Some(install) = opts.install {
    steps.push("COPY . .".to_string());
    steps.push(run_line(install));
  } else if requirements.is_some() {
    steps.push("COPY requirements.txt ./".to_string());
    steps.push("RUN pip install -r requirements.txt".to_string());
  }
  if opts.install.is_none() {
    steps.push("COPY . .".to_string());
  }
  if opts.install.is_none()
    && requirements.is_none()
    && pyproject
      .as_deref()
      .is_some_and(|p| p.contains("[project]"))
  {
    steps.push("RUN pip install .".to_string());
  }
  if let Some(extra) = start.extra {
    steps.push(format!("RUN pip install {extra}"));
  }
  let dockerfile = format!(
    r#"# Wharf 按 Python 模板生成
FROM {base}
ARG PIP_INDEX_URL
ARG PIP_TRUSTED_HOST
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PORT={port}
WORKDIR /app
{steps}
EXPOSE {port}
{run}
"#,
    port = opts.port,
    steps = steps.join("\n"),
    run = cmd_line(&start.cmd),
  );
  Ok(Generated {
    language: "python",
    dockerfile,
    start: start.cmd,
    images: vec![base.to_string()],
  })
}

/// `RUN` 一段 shell（可以多行）。
fn run_line(script: &str) -> String {
  let json = serde_json::to_string(&["sh", "-c", script])
    .unwrap_or_else(|_| "[]".into());
  format!("RUN {json}")
}

fn node_start(
  tree: &dyn SourceTree,
  pkg: &serde_json::Value,
) -> Result<String, ApiError> {
  if pkg["scripts"]["start"].is_string() {
    return Ok("npm start".into());
  }
  if let Some(main) = pkg["main"].as_str()
    && tree.exists(main)
  {
    return Ok(format!("node {main}"));
  }
  for file in ["server.js", "index.js", "app.js", "main.js"] {
    if tree.exists(file) {
      return Ok(format!("node {file}"));
    }
  }
  Err(
    ApiError::invalid("猜不出 Node 服务的启动命令")
      .with_hint("在 package.json 里加 start 脚本，或用 --start 指定，监听端口用环境变量 $PORT"),
  )
}

fn node(
  tree: &dyn SourceTree,
  opts: &Options,
) -> Result<Generated, ApiError> {
  let pkg: serde_json::Value = tree
    .read("package.json")
    .and_then(|s| serde_json::from_str(&s).ok())
    .unwrap_or_default();
  let start = match opts.start {
    Some(cmd) => cmd.to_string(),
    None => node_start(tree, &pkg)?,
  };
  let base = opts.base.unwrap_or(NODE_BASE);
  let mut steps = Vec::new();
  match opts.install {
    Some(install) => {
      steps.push("COPY . .".to_string());
      steps.push(run_line(install));
    }
    None => {
      let lock = tree.exists("package-lock.json");
      if tree.exists("package.json") {
        steps.push(
          if lock {
            "COPY package.json package-lock.json ./"
          } else {
            "COPY package.json ./"
          }
          .to_string(),
        );
        steps.push(
          if lock {
            "RUN npm ci"
          } else {
            "RUN npm install"
          }
          .to_string(),
        );
      }
      steps.push("COPY . .".to_string());
      if pkg["scripts"]["build"].is_string() {
        steps.push("RUN npm run build".to_string());
      }
    }
  }
  if pkg["scripts"]["build"].is_string() && runs_python(&start) {
    return Ok(node_then_python(tree, opts, base, steps, start));
  }
  let dockerfile = format!(
    r#"# Wharf 按 Node 模板生成
FROM {base}
ARG NPM_CONFIG_REGISTRY
ENV PORT={port}
WORKDIR /app
{steps}
EXPOSE {port}
{run}
"#,
    port = opts.port,
    steps = steps.join("\n"),
    run = cmd_line(&start),
  );
  Ok(Generated {
    language: "node",
    dockerfile,
    start,
    images: vec![base.to_string()],
  })
}

fn runs_python(start: &str) -> bool {
  matches!(
    start.split_whitespace().next(),
    Some("python" | "python3")
  )
}

/// 前端用 Node 构建、后端用 Python 跑：Node 只留在构建阶段，
/// 最终镜像是 Python 加上构建好的代码目录。
fn node_then_python(
  tree: &dyn SourceTree,
  opts: &Options,
  base: &str,
  steps: Vec<String>,
  start: String,
) -> Generated {
  let pip = if tree.exists("requirements.txt") {
    "\nARG PIP_INDEX_URL\nARG PIP_TRUSTED_HOST\nRUN pip install --no-cache-dir -r requirements.txt"
  } else {
    ""
  };
  let dockerfile = format!(
    r#"# Wharf 按 Node 模板生成：Node 构建，Python 运行
FROM {base} AS build
ARG NPM_CONFIG_REGISTRY
WORKDIR /app
{steps}
RUN rm -rf node_modules

FROM {PYTHON_BASE}
ENV PYTHONUNBUFFERED=1 PORT={port}
WORKDIR /app
COPY --from=build /app /app{pip}
EXPOSE {port}
{run}
"#,
    port = opts.port,
    steps = steps.join("\n"),
    run = cmd_line(&start),
  );
  Generated {
    language: "node",
    dockerfile,
    start,
    images: vec![base.to_string(), PYTHON_BASE.to_string()],
  }
}

fn static_site(opts: &Options) -> Generated {
  let base = opts.base.unwrap_or(STATIC_BASE);
  let start = opts
    .start
    .unwrap_or("caddy file-server --root /srv --listen :$PORT")
    .to_string();
  let dockerfile = format!(
    r#"# Wharf 按静态站模板生成
FROM {base}
WORKDIR /srv
COPY . /srv
ENV PORT={port}
EXPOSE {port}
{run}
"#,
    port = opts.port,
    run = cmd_line(&start),
  );
  Generated {
    language: "static",
    dockerfile,
    start,
    images: vec![base.to_string()],
  }
}

/// Dockerfile 里 `FROM` 用到的镜像（跳过前面阶段的别名和 `scratch`），构建前先按镜像源拉好。
pub fn from_images(dockerfile: &str) -> Vec<String> {
  let mut stages = Vec::new();
  let mut images = Vec::new();
  for line in dockerfile.lines() {
    let mut words = line.split_whitespace();
    if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("FROM")) {
      continue;
    }
    let mut words: Vec<&str> =
      words.filter(|w| !w.starts_with("--")).collect();
    if words.is_empty() {
      continue;
    }
    let image = words.remove(0).to_string();
    if let [as_kw, alias] = words.as_slice()
      && as_kw.eq_ignore_ascii_case("as")
    {
      stages.push(alias.to_lowercase());
    }
    if image == "scratch"
      || image.contains('$')
      || stages[..stages.len().saturating_sub(1)]
        .contains(&image.to_lowercase())
      || images.contains(&image)
    {
      continue;
    }
    images.push(image);
  }
  images
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::*;

  struct Mem(BTreeMap<&'static str, &'static str>);

  impl SourceTree for Mem {
    fn read(&self, path: &str) -> Option<String> {
      self.0.get(path).map(|s| s.to_string())
    }
    fn list(&self, dir: &str) -> Vec<String> {
      let mut out: Vec<String> = self
        .0
        .keys()
        .filter_map(|p| p.strip_prefix(dir))
        .map(|rest| match rest.split_once('/') {
          Some((d, _)) => format!("{d}/"),
          None => rest.to_string(),
        })
        .collect();
      out.dedup();
      out
    }
  }

  fn opts(start: Option<&str>) -> Options<'_> {
    Options {
      service: "api",
      port: 8000,
      base: None,
      start,
      template: None,
      install: None,
    }
  }

  #[test]
  fn node_uses_lock_build_and_start_script() {
    let tree = Mem(BTreeMap::from([
      (
        "package.json",
        r#"{"scripts":{"build":"vite build","start":"node dist/server.js"}}"#,
      ),
      ("package-lock.json", "{}"),
    ]));
    let g = generate(&tree, &opts(None)).unwrap();
    assert_eq!(g.language, "node");
    assert_eq!(g.start, "npm start");
    assert!(
      g.dockerfile
        .contains("RUN npm ci\nCOPY . .\nRUN npm run build")
    );
  }

  #[test]
  fn node_build_with_python_start_runs_on_python() {
    let tree = Mem(BTreeMap::from([
      ("package.json", r#"{"scripts":{"build":"vite build"}}"#),
      ("package-lock.json", "{}"),
    ]));
    let g =
      generate(&tree, &opts(Some("python3 server/app.py"))).unwrap();
    assert!(
      g.dockerfile
        .contains("RUN npm run build\nRUN rm -rf node_modules")
    );
    assert!(g.dockerfile.contains(&format!("FROM {PYTHON_BASE}\n")));
    assert!(g.dockerfile.contains("COPY --from=build /app /app"));
    assert_eq!(g.images, vec![NODE_BASE, PYTHON_BASE]);
  }

  #[test]
  fn explicit_template_install_and_script() {
    let tree = Mem(BTreeMap::from([("index.html", "")]));
    assert_eq!(
      generate(&tree, &opts(None)).unwrap().language,
      "static"
    );
    let o = Options {
      template: Some("python"),
      install: Some("pip install uv && uv sync"),
      ..opts(Some("alembic upgrade head\nexec python main.py"))
    };
    let g = generate(&tree, &o).unwrap();
    assert!(
      g.dockerfile
        .contains(r#"RUN ["sh","-c","pip install uv && uv sync"]"#)
    );
    assert!(g.dockerfile.contains(
      r#"CMD ["sh","-c","alembic upgrade head\nexec python main.py"]"#
    ));
    let go = Options {
      template: Some("go"),
      install: Some("x"),
      ..opts(None)
    };
    assert!(generate(&tree, &go).is_err());
  }

  #[test]
  fn go_finds_main_under_cmd() {
    let tree = Mem(BTreeMap::from([
      ("go.mod", "module x"),
      ("go.sum", ""),
      ("lib.go", "package lib"),
      ("cmd/api/main.go", "package main\nfunc main() {}"),
    ]));
    let g = generate(&tree, &opts(None)).unwrap();
    assert_eq!(g.language, "go");
    assert!(g.dockerfile.contains("COPY go.mod go.sum ./"));
    assert!(g.dockerfile.contains("-o /out/app ./cmd/api"));
    assert!(g.dockerfile.contains(r#"ENTRYPOINT ["/app"]"#));
    assert_eq!(g.images, vec![GO_BASE, GO_RUNTIME]);
  }

  #[test]
  fn python_fastapi_adds_uvicorn() {
    let tree = Mem(BTreeMap::from([
      ("requirements.txt", "fastapi==0.115.0"),
      ("main.py", "from fastapi import FastAPI\napi = FastAPI()\n"),
    ]));
    let g = generate(&tree, &opts(None)).unwrap();
    assert_eq!(
      g.start,
      "uvicorn main:api --host 0.0.0.0 --port $PORT"
    );
    assert!(
      g.dockerfile.contains("RUN pip install -r requirements.txt")
    );
    assert!(g.dockerfile.contains("RUN pip install uvicorn"));
    assert!(g.dockerfile.contains(
      r#"CMD ["sh","-c","uvicorn main:api --host 0.0.0.0 --port $PORT"]"#
    ));
  }

  #[test]
  fn python_without_entry_asks_for_start() {
    let tree =
      Mem(BTreeMap::from([("requirements.txt", ""), ("x/y.py", "")]));
    let err = generate(&tree, &opts(None)).unwrap_err();
    assert!(err.hint.unwrap().contains("--start"));
    let g = generate(&tree, &opts(Some("python -m x.y"))).unwrap();
    assert_eq!(g.start, "python -m x.y");
  }

  #[test]
  fn unknown_language_is_rejected() {
    let tree = Mem(BTreeMap::from([("index.js", "")]));
    assert!(generate(&tree, &opts(None)).is_err());
  }

  #[test]
  fn from_images_skips_stages_and_scratch() {
    let df = "FROM --platform=linux/amd64 golang:1.25 AS build\nFROM build AS again\nFROM scratch\nFROM alpine:3.22\n";
    assert_eq!(from_images(df), vec!["golang:1.25", "alpine:3.22"]);
  }
}
