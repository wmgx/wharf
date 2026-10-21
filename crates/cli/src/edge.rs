//! `wharf edge`：Cloudflare Workers / Pages。
//!
//! - `import` 纳管账号里已有的项目，Worker 顺便把线上脚本下载到 `./<名字>/`；
//! - 之后改本地文件再 `deploy`：单文件 Worker 直接上传（保留面板里的变量和绑定），
//!   有 wrangler 配置的目录和 Pages 交给服务器执行 wrangler；
//! - 回滚用 Cloudflare 自己的版本。

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::json;
use wharf_api_types::{
  ApiError, ErrorCode,
  plan::ApplyResponse,
  spec::{Change, EdgeAppSpec, EdgeKind, EdgeSource, GitSource},
  view::{
    AccountView, EdgeAppView, EdgeProjectView, EdgeScript,
    EdgeVersionView, RouteView,
  },
};

use crate::{
  ApplyFlags,
  client::{CliError, CliResult, Client, seg},
  commands::{changes, finish_task, out, pretty},
  deploy::upload,
};

const WRANGLER_CONFIGS: [&str; 3] =
  ["wrangler.toml", "wrangler.json", "wrangler.jsonc"];
/// 单文件 Worker 找脚本的顺序。
const SCRIPT_NAMES: [&str; 5] = [
  "worker.js",
  "index.js",
  "worker.mjs",
  "src/index.js",
  "src/worker.js",
];

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum EdgeCmd {
  /// 已纳管的边缘应用。
  List,
  /// 详情（实时读取厂商那边的状态）。
  Show { name: String },
  /// 列出厂商账号里的 Workers 和 Pages 项目，标出已导入的。
  Discover {
    /// 厂商账号，只有一个时可以不写。
    #[arg(long)]
    account: Option<String>,
  },
  /// 导入账号里已有的项目。Worker 执行后把线上脚本下载到 `./<名字>/`。
  Import {
    /// 厂商那边的项目名。
    project: String,
    /// Wharf 里的名字，默认和项目名相同。
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    account: Option<String>,
    /// 下载脚本的目录，默认 `./<名字>/`。
    #[arg(long)]
    dir: Option<PathBuf>,
    /// 不下载脚本。
    #[arg(long)]
    no_pull: bool,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 把 Worker 线上的脚本下载到本地。
  Pull {
    name: String,
    /// 默认 `./<名字>/`。
    #[arg(long)]
    dir: Option<PathBuf>,
    /// 覆盖本地已改过的文件。
    #[arg(long)]
    force: bool,
  },
  /// 发布。不给来源时用 `./<名字>/`（或当前目录）：有 wrangler 配置就用 wrangler，
  /// 否则找 worker.js / index.js 当单文件 Worker 上传。
  Deploy {
    name: String,
    /// 单文件 Worker 的脚本。
    #[arg(long, conflicts_with_all = ["dir", "git"])]
    script: Option<PathBuf>,
    /// 代码目录（wrangler 项目或 Pages）。
    #[arg(long, conflicts_with = "git")]
    dir: Option<PathBuf>,
    /// git 仓库（https）。
    #[arg(long)]
    git: Option<String>,
    #[arg(long = "ref")]
    git_ref: Option<String>,
    /// 私有仓库的 token 存成密钥后写密钥名。
    #[arg(long)]
    git_token_secret: Option<String>,
    /// 代码里的子目录。
    #[arg(long)]
    path: Option<String>,
    /// 新建时的类型，默认 Worker；给了 --build / --output 时是 Pages。
    #[arg(long, value_parser = ["worker", "pages"])]
    kind: Option<String>,
    /// Pages 的构建命令，例如 `npm run build`。
    #[arg(long)]
    build: Option<String>,
    /// Pages 发布的目录，默认有构建命令时 `dist`，没有时代码目录本身。
    #[arg(long)]
    output: Option<String>,
    /// 执行 wrangler 的服务器，默认挑一台在线的海外服务器。
    #[arg(long)]
    server: Option<String>,
    /// 厂商那边的项目名，默认和名字相同。
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    account: Option<String>,
    #[command(flatten)]
    apply: ApplyFlags,
  },
  /// 按现在的代码来源再发布一次（git 来源取最新）。
  Redeploy {
    name: String,
    #[arg(long)]
    no_wait: bool,
  },
  /// 厂商那边的版本，新的在前。
  Versions { name: String },
  /// 以线上为准：线上版本被别处改过时，把现在的线上版本记为 Wharf 期望的版本。
  Accept { name: String },
  /// 回滚到上一个版本，或 `--to` 指定的版本。
  Rollback {
    name: String,
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    no_wait: bool,
  },
  /// 不再纳管（厂商那边的项目保留，Wharf 绑定的域名会解绑）。
  Rm {
    name: String,
    #[command(flatten)]
    apply: ApplyFlags,
  },
}

pub async fn edge(
  c: &Client,
  cmd: EdgeCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    EdgeCmd::List => {
      let v: Vec<EdgeAppView> = c.get("/api/edge").await?;
      out(j, &v, |v| {
        for a in v {
          println!("{}", line(a));
        }
        if v.is_empty() {
          println!(
            "还没有边缘应用，导入已有项目：wharf edge discover"
          );
        }
      });
      Ok(())
    }
    EdgeCmd::Show { name } => {
      let v: EdgeAppView =
        c.get(&format!("/api/edge/{}?sync=1", seg(&name))).await?;
      out(j, &v, pretty);
      Ok(())
    }
    EdgeCmd::Discover { account } => {
      let account = pick_account(c, account).await?;
      let v = discover(c, &account).await?;
      out(j, &v, |v| {
        for p in v {
          println!(
            "{:<6} {:<30} {}{}",
            p.kind.as_str(),
            p.project,
            p.url.as_deref().unwrap_or("-"),
            p.managed_as
              .as_ref()
              .map(|n| format!("  已导入为 {n}"))
              .unwrap_or_default()
          );
        }
        if v.is_empty() {
          println!(
            "账号 {account} 里没有 Workers / Pages 项目（token 没有 Workers / Pages 读权限时也是空的）"
          );
        } else {
          println!("\n导入：wharf edge import <项目> --apply");
        }
      });
      Ok(())
    }
    EdgeCmd::Import {
      project,
      name,
      account,
      dir,
      no_pull,
      apply,
    } => {
      let account = pick_account(c, account).await?;
      let found = discover(c, &account)
        .await?
        .into_iter()
        .find(|p| p.project == project)
        .ok_or_else(|| {
          ApiError::not_found(format!(
            "账号 {account} 里没有项目 {project}"
          ))
          .suggest(format!("wharf edge discover --account {account}"))
        })?;
      if let Some(n) = &found.managed_as {
        return Err(
          ApiError::new(
            ErrorCode::AlreadyExists,
            format!("{project} 已经导入为 {n}"),
          )
          .into(),
        );
      }
      let name = name.unwrap_or_else(|| project.clone());
      let spec = EdgeAppSpec {
        account,
        kind: found.kind,
        project: (name != project).then_some(project),
        source: None,
        builder: None,
      };
      let applied = apply.apply;
      changes(
        c,
        vec![Change::UpsertEdgeApp {
          name: name.clone(),
          spec,
        }],
        apply,
        j,
      )
      .await?;
      if applied && found.kind == EdgeKind::Worker && !no_pull {
        let dir = dir.unwrap_or_else(|| PathBuf::from(&name));
        match pull(c, &name, &dir, false).await {
          Ok(file) => eprintln!(
            "已下载 {}，修改后执行 wharf edge deploy {name} --apply",
            file.display()
          ),
          Err(CliError::Api(e)) => {
            eprintln!("下载脚本失败：{}", e.message)
          }
          Err(e) => return Err(e),
        }
      }
      Ok(())
    }
    EdgeCmd::Pull { name, dir, force } => {
      let dir = dir.unwrap_or_else(|| PathBuf::from(&name));
      let file = pull(c, &name, &dir, force).await?;
      out(j, &json!({ "written": file }), |_| {
        println!("已写入 {}", file.display())
      });
      Ok(())
    }
    EdgeCmd::Deploy {
      name,
      script,
      dir,
      git,
      git_ref,
      git_token_secret,
      path,
      kind,
      build,
      output,
      server,
      project,
      account,
      apply,
    } => {
      let existing = existing(c, &name).await?;
      let kind = match (kind.as_deref(), &existing) {
        (Some("pages"), _) => EdgeKind::Pages,
        (Some(_), _) => EdgeKind::Worker,
        (None, Some(e)) => e.spec.kind,
        (None, None) if build.is_some() || output.is_some() => {
          EdgeKind::Pages
        }
        (None, None) => EdgeKind::Worker,
      };
      if existing.as_ref().is_some_and(|e| e.spec.kind != kind) {
        return Err(
          ApiError::invalid(format!(
            "{name} 已经是 {}，不能改类型",
            kind_name(
              existing.as_ref().map(|e| e.spec.kind).unwrap_or(kind)
            )
          ))
          .into(),
        );
      }
      let old = existing.as_ref().and_then(|e| e.spec.source.clone());
      let mut source = match (script, dir, git) {
        (Some(file), _, _) => script_source(c, &file).await?,
        (None, _, Some(repo)) => EdgeSource {
          git: Some(GitSource {
            repo: repo.trim_end_matches('/').to_string(),
            reference: git_ref.unwrap_or_else(|| "main".into()),
            token_secret: git_token_secret,
          }),
          ..EdgeSource::default()
        },
        (None, Some(dir), None) => {
          local_source(c, kind, &dir, old.as_ref(), path.as_deref())
            .await?
        }
        (None, None, None) => {
          let named = PathBuf::from(&name);
          let dir = if named.is_dir() {
            named
          } else {
            PathBuf::from(".")
          };
          local_source(c, kind, &dir, old.as_ref(), path.as_deref())
            .await?
        }
      };
      if source.path.is_none() && source.script.is_none() {
        source.path = path;
      }
      // 没给的选项沿用现有配置。
      source.build =
        build.or_else(|| old.as_ref().and_then(|o| o.build.clone()));
      source.output = output
        .or_else(|| old.as_ref().and_then(|o| o.output.clone()));
      let base = existing.map(|e| e.spec);
      let account = match (account, &base) {
        (Some(a), _) => a,
        (None, Some(b)) => b.account.clone(),
        (None, None) => pick_account(c, None).await?,
      };
      let spec = EdgeAppSpec {
        account,
        kind,
        project: project
          .filter(|p| p != &name)
          .or_else(|| base.as_ref().and_then(|b| b.project.clone())),
        source: Some(source),
        builder: server
          .or_else(|| base.as_ref().and_then(|b| b.builder.clone())),
      };
      changes(c, vec![Change::UpsertEdgeApp { name, spec }], apply, j)
        .await
    }
    EdgeCmd::Redeploy { name, no_wait } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/edge/{}/redeploy", seg(&name)),
          &json!({}),
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
    EdgeCmd::Versions { name } => {
      let v: Vec<EdgeVersionView> = c
        .get(&format!("/api/edge/{}/versions?sync=1", seg(&name)))
        .await?;
      out(j, &v, |v| {
        for x in v {
          println!(
            "{} {:<12} {:<20} {:<10} {}",
            if x.active { "*" } else { " " },
            &x.id[..12.min(x.id.len())],
            x.created_at.get(..19).unwrap_or(&x.created_at),
            x.source.as_deref().unwrap_or("-"),
            x.message.as_deref().unwrap_or("")
          );
        }
      });
      Ok(())
    }
    EdgeCmd::Rollback { name, to, no_wait } => {
      let r: ApplyResponse = c
        .post(
          &format!("/api/edge/{}/rollback", seg(&name)),
          &json!({ "version": to }),
        )
        .await?;
      finish_task(c, &r.run_id, !no_wait, j).await
    }
    EdgeCmd::Accept { name } => {
      let v: EdgeAppView = c
        .post(&format!("/api/edge/{}/accept", seg(&name)), &json!({}))
        .await?;
      out(j, &v, |v| println!("{}", line(v)));
      Ok(())
    }
    EdgeCmd::Rm { name, apply } => {
      // 指向它的域名一起移除。
      let routes: Vec<RouteView> = c.get("/api/routes").await?;
      let mut list: Vec<Change> = routes
        .into_iter()
        .filter(|r| r.spec.service == name)
        .map(|r| Change::RemoveRoute {
          hostname: r.spec.hostname,
        })
        .collect();
      list.push(Change::RemoveEdgeApp { name });
      changes(c, list, apply, j).await
    }
  }
}

fn kind_name(kind: EdgeKind) -> &'static str {
  match kind {
    EdgeKind::Worker => "Worker",
    EdgeKind::Pages => "Pages",
  }
}

fn line(a: &EdgeAppView) -> String {
  let state = match &a.live {
    _ if a.drift.is_some() => {
      format!("有差异：{}", a.drift.as_deref().unwrap_or_default())
    }
    None => "还没同步".to_string(),
    Some(l) => match (&l.error, l.exists) {
      (Some(e), _) => format!("读取失败：{e}"),
      (None, false) => "厂商那边不存在".to_string(),
      (None, true) => l.url.clone().unwrap_or_else(|| "在线".into()),
    },
  };
  format!(
    "{:<20} {:<6} {:<20} {}",
    a.name,
    a.spec.kind.as_str(),
    a.spec.project_name(&a.name),
    state
  )
}

async fn existing(
  c: &Client,
  name: &str,
) -> CliResult<Option<EdgeAppView>> {
  match c.get(&format!("/api/edge/{}", seg(name))).await {
    Ok(v) => Ok(Some(v)),
    Err(CliError::Api(e)) if e.code == ErrorCode::NotFound => {
      Ok(None)
    }
    Err(e) => Err(e),
  }
}

async fn discover(
  c: &Client,
  account: &str,
) -> CliResult<Vec<EdgeProjectView>> {
  c.get(&format!("/api/accounts/{}/edge?sync=1", seg(account)))
    .await
}

/// 没写 `--account` 时用唯一的 Cloudflare 账号。
async fn pick_account(
  c: &Client,
  account: Option<String>,
) -> CliResult<String> {
  if let Some(a) = account {
    return Ok(a);
  }
  let all: Vec<AccountView> = c.get("/api/accounts").await?;
  let cf: Vec<&AccountView> =
    all.iter().filter(|a| a.kind == "cloudflare").collect();
  match cf.as_slice() {
    [one] => Ok(one.name.clone()),
    [] => Err(
      ApiError::invalid("还没有 Cloudflare 账号")
        .suggest("wharf account add <名字> --kind cloudflare")
        .into(),
    ),
    _ => Err(
      ApiError::invalid(format!(
        "有多个 Cloudflare 账号，用 --account 指定：{}",
        cf.iter()
          .map(|a| a.name.as_str())
          .collect::<Vec<_>>()
          .join("、")
      ))
      .into(),
    ),
  }
}

/// 下载 Worker 脚本到 `dir`，返回写入的文件。本地文件和线上不同时不覆盖，除非 `force`。
async fn pull(
  c: &Client,
  name: &str,
  dir: &Path,
  force: bool,
) -> CliResult<PathBuf> {
  let s: EdgeScript =
    c.get(&format!("/api/edge/{}/script", seg(name))).await?;
  let file = dir.join(&s.filename);
  if !force
    && let Ok(local) = std::fs::read_to_string(&file)
    && local != s.content
  {
    return Err(
      ApiError::invalid(format!(
        "{} 和线上不一样，没有覆盖",
        file.display()
      ))
      .with_hint("确定要用线上版本覆盖本地修改时加 --force")
      .into(),
    );
  }
  let write = || -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(&file, &s.content)
  };
  write().map_err(|e| {
    ApiError::invalid(format!("写入 {}：{e}", file.display()))
  })?;
  Ok(file)
}

/// `--script 文件`：上传脚本所在目录，记下文件名。
async fn script_source(
  c: &Client,
  file: &Path,
) -> CliResult<EdgeSource> {
  if !file.is_file() {
    return Err(
      ApiError::invalid(format!("{} 不存在", file.display())).into(),
    );
  }
  let dir = match file.parent() {
    Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
    _ => PathBuf::from("."),
  };
  let filename = file
    .file_name()
    .map(|f| f.to_string_lossy().to_string())
    .unwrap_or_default();
  eprintln!("上传 {}（单文件 Worker）", file.display());
  Ok(EdgeSource {
    upload: Some(upload(c, &dir).await?),
    script: Some(filename),
    ..EdgeSource::default()
  })
}

/// 本机目录：Pages 和有 wrangler 配置的 Worker 整个目录交给 wrangler，
/// 其他 Worker 找一个脚本当单文件上传。
async fn local_source(
  c: &Client,
  kind: EdgeKind,
  dir: &Path,
  old: Option<&EdgeSource>,
  path: Option<&str>,
) -> CliResult<EdgeSource> {
  let root = match path {
    Some(p) => dir.join(p),
    None => dir.to_path_buf(),
  };
  if !root.is_dir() {
    return Err(
      ApiError::invalid(format!("目录 {} 不存在", root.display()))
        .into(),
    );
  }
  let wrangler =
    WRANGLER_CONFIGS.iter().any(|f| root.join(f).is_file());
  if kind == EdgeKind::Pages || wrangler {
    eprintln!(
      "上传 {}（{}）",
      dir.display(),
      if kind == EdgeKind::Pages {
        "Pages"
      } else {
        "wrangler 项目"
      }
    );
    return Ok(EdgeSource {
      upload: Some(upload(c, dir).await?),
      path: path.map(str::to_string),
      ..EdgeSource::default()
    });
  }
  let previous = old.and_then(|o| o.script.as_deref());
  let script = previous
    .into_iter()
    .chain(SCRIPT_NAMES)
    .find(|f| root.join(f).is_file())
    .ok_or_else(|| {
      ApiError::invalid(format!(
        "{} 里没有 wrangler 配置，也没有 worker.js / index.js",
        root.display()
      ))
      .with_hint("单文件 Worker 用 --script <文件> 指定")
    })?;
  eprintln!("上传 {}（单文件 Worker）", root.join(script).display());
  Ok(EdgeSource {
    upload: Some(upload(c, dir).await?),
    path: path.map(str::to_string),
    script: Some(script.to_string()),
    ..EdgeSource::default()
  })
}
