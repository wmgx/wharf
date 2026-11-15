//! `wharf task`：定时任务。改动直接生效，不走计划。

use std::{
  collections::BTreeMap, io::Read, path::Path, time::Duration,
};

use clap::{Args, Subcommand};
use wharf_api_types::{
  ApiError,
  view::{
    ScriptRuntime, TaskKind, TaskRunView, TaskSpec, TaskStatus,
    TaskView,
  },
};

use crate::{
  client::{CliError, CliResult, Client, seg},
  commands::out,
};

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum TaskCmd {
  /// 新建或修改（同名再执行一次就是整体替换）。命令写在 `--` 后面。
  ///
  /// 例：`wharf task add dump --exec blog --container db --schedule "0 4 * * *" -- mysqldump ...`
  Add(AddArgs),
  #[command(alias = "list")]
  Ls,
  Show {
    name: String,
  },
  /// 立即运行并等待结果；失败时退出码为 4。
  Run {
    name: String,
  },
  /// 最近的运行记录，最新一条带完整输出。
  Logs {
    name: String,
    #[arg(short = 'n', long, default_value_t = 10)]
    limit: u32,
  },
  /// 删除任务和它的运行记录。
  Rm {
    name: String,
  },
}

#[derive(Args)]
pub struct AddArgs {
  name: String,
  /// 5 段 cron，北京时间，例如 `30 3 * * *`。
  #[arg(long)]
  schedule: Option<String>,
  /// 从文件读取脚本，- 表示标准输入。
  #[arg(long, group = "how")]
  script: Option<String>,
  /// python、node 或 shell；默认按脚本扩展名判断。
  #[arg(long, requires = "script", value_parser = ["python", "node", "shell"])]
  runtime: Option<String>,
  /// 脚本使用的镜像。
  #[arg(long, requires = "script")]
  script_image: Option<String>,
  /// 开启网址触发。
  #[arg(long, requires = "script")]
  hook: bool,
  /// 在这个服务的容器里执行；服务器取服务所在的服务器。
  #[arg(long, group = "how")]
  exec: Option<String>,
  /// 跑一次性容器用的镜像。
  #[arg(long, group = "how")]
  image: Option<String>,
  /// 在宿主机执行（要服务器开了"命令执行"）。
  #[arg(long, group = "how")]
  host: bool,
  /// 外部报到：Wharf 不执行，脚本跑完请求报到地址；`--schedule` 写预期运行时间，
  /// 超过 `--grace` 分钟没报到就通知。保存后 `wharf task show` 看报到地址。
  #[arg(long, group = "how")]
  ping: bool,
  /// 外部报到的宽限分钟数。
  #[arg(long, default_value_t = 60)]
  grace: u32,
  /// 服务器；`--exec` 时可以不填。
  #[arg(long)]
  server: Option<String>,
  /// `--exec` 时的 compose 服务名，服务只有一个容器时不用填。
  #[arg(long)]
  container: Option<String>,
  /// 一次性容器的环境变量 `KEY=VALUE`，可以多次使用，值里可以写 `[[密钥]]`。
  #[arg(long)]
  env: Vec<String>,
  /// 一次性容器的挂载 `/宿主机路径:/容器路径[:ro]`，可以多次使用。
  #[arg(long)]
  mount: Vec<String>,
  /// 超时秒数。
  #[arg(long, default_value_t = 600)]
  timeout: u64,
  /// 先不启用。
  #[arg(long)]
  disabled: bool,
  /// 失败时不通知。
  #[arg(long)]
  no_notify: bool,
  /// 用 `sh -c` 执行的命令，可以写 `[[密钥]]`。
  #[arg(last = true)]
  command: Vec<String>,
}

pub async fn task(
  c: &Client,
  cmd: TaskCmd,
  j: bool,
) -> CliResult<()> {
  match cmd {
    TaskCmd::Add(a) => add(c, a, j).await,
    TaskCmd::Ls => {
      let v: Vec<TaskView> = c.get("/api/tasks").await?;
      out(j, &v, |v| {
        if v.is_empty() {
          println!("还没有定时任务");
        }
        for t in v {
          println!(
            "{:<16} {:<8} {:<16} {:<9} {}{}",
            t.name,
            t.spec.server,
            if t.spec.schedule.is_empty() {
              "不定时"
            } else {
              &t.spec.schedule
            },
            kind(&t.spec.how),
            t.last.as_ref().map_or("没运行过".into(), |r| format!(
              "{} {}",
              status(r.status),
              local(r.started_at)
            )),
            match (&t.next_at, t.spec.enabled) {
              (_, false) => "  已停用".into(),
              (Some(n), true) => format!("  下次 {}", local(*n)),
              (None, true) => String::new(),
            }
          );
        }
      });
      Ok(())
    }
    TaskCmd::Show { name } => {
      let v: Vec<TaskView> = c.get("/api/tasks").await?;
      let t =
        v.into_iter().find(|t| t.name == name).ok_or_else(|| {
          ApiError::not_found(format!("没有定时任务 {name}"))
            .with_hint("wharf task ls")
        })?;
      out(j, &t, |t| {
        println!(
          "{}",
          serde_json::to_string_pretty(&t.spec).unwrap_or_default()
        );
        if let TaskKind::Script { runtime, code, .. } = &t.spec.how {
          println!("运行环境：{}", runtime_name(*runtime));
          if let Some(url) = &t.hook_url {
            println!("触发地址：{url}");
          }
          print!("\n{code}");
        }
        if let Some(url) = &t.ping_url {
          println!("\n报到：脚本成功后 curl -fsS -m 10 {url}");
          println!("失败时：curl -fsS -m 10 {url}/fail");
        }
      });
      Ok(())
    }
    TaskCmd::Run { name } => run(c, &name, j).await,
    TaskCmd::Logs { name, limit } => {
      let v: Vec<TaskRunView> = c
        .get(&format!("/api/tasks/{}/runs?limit={limit}", seg(&name)))
        .await?;
      out(j, &v, |v| {
        for r in v {
          println!("{}", line(r));
        }
        if let Some(r) = v.first() {
          println!("\n{}", r.output);
        }
      });
      Ok(())
    }
    TaskCmd::Rm { name } => {
      let r: serde_json::Value =
        c.delete(&format!("/api/tasks/{}", seg(&name))).await?;
      out(j, &r, |_| println!("已删除定时任务 {name}"));
      Ok(())
    }
  }
}

async fn add(c: &Client, a: AddArgs, j: bool) -> CliResult<()> {
  let command = (!a.command.is_empty()).then(|| a.command.join(" "));
  let need_cmd = || {
    command.clone().ok_or_else(|| {
      ApiError::invalid("缺少命令").with_hint("命令写在 `--` 后面")
    })
  };
  let (how, server) = if let Some(file) = &a.script {
    let runtime = match a.runtime.as_deref().or_else(|| {
      match Path::new(file).extension().and_then(|s| s.to_str()) {
        Some("py") => Some("python"),
        Some("js" | "mjs") => Some("node"),
        Some("sh") => Some("shell"),
        _ => None,
      }
    }) {
      Some("python") => ScriptRuntime::Python,
      Some("node") => ScriptRuntime::Node,
      Some("shell") => ScriptRuntime::Shell,
      _ => {
        return Err(
          ApiError::invalid("无法判断运行环境")
            .with_hint("加 --runtime python、node 或 shell")
            .into(),
        );
      }
    };
    let code = if file == "-" {
      let mut code = String::new();
      std::io::stdin()
        .read_to_string(&mut code)
        .map_err(|_| ApiError::invalid("读取脚本失败"))?;
      code
    } else {
      std::fs::read_to_string(file)
        .map_err(|_| ApiError::invalid("读取脚本失败"))?
    };
    let tasks: Vec<TaskView> = c.get("/api/tasks").await?;
    let old =
      tasks.into_iter().find(|t| t.name == a.name).and_then(|t| {
        if let TaskKind::Script { hook, .. } = t.spec.how {
          hook
        } else {
          None
        }
      });
    let env = a
      .env
      .iter()
      .map(|e| {
        e.split_once('=')
          .map(|(k, v)| (k.to_string(), v.to_string()))
          .ok_or_else(|| {
            ApiError::invalid("环境变量要写成 KEY=VALUE")
          })
      })
      .collect::<Result<BTreeMap<_, _>, _>>()?;
    (
      TaskKind::Script {
        runtime,
        code,
        image: a.script_image,
        env,
        hook: if a.hook { Some(String::new()) } else { old },
      },
      need_server(a.server)?,
    )
  } else if let Some(service) = a.exec {
    let server = match a.server {
      Some(s) => s,
      None => {
        let v: serde_json::Value =
          c.get(&format!("/api/services/{}", seg(&service))).await?;
        v["spec"]["server"].as_str().unwrap_or_default().to_string()
      }
    };
    let how = TaskKind::Exec {
      service,
      container: a.container,
      command: need_cmd()?,
    };
    (how, server)
  } else if let Some(image) = a.image {
    let env = a
      .env
      .iter()
      .map(|e| {
        e.split_once('=')
          .map(|(k, v)| (k.to_string(), v.to_string()))
          .ok_or_else(|| {
            ApiError::invalid(format!(
              "环境变量要写成 KEY=VALUE：{e}"
            ))
          })
      })
      .collect::<Result<BTreeMap<_, _>, _>>()?;
    let how = TaskKind::Container {
      image,
      command,
      env,
      mounts: a.mount,
    };
    (how, need_server(a.server)?)
  } else if a.ping {
    (
      TaskKind::Ping {
        token: String::new(),
        grace_mins: a.grace,
      },
      need_server(a.server)?,
    )
  } else if a.host {
    (
      TaskKind::Host {
        command: need_cmd()?,
      },
      need_server(a.server)?,
    )
  } else {
    return Err(
      ApiError::invalid("要选一种任务形式")
        .with_hint("--exec <服务>、--image <镜像>、--host、--ping 或 --script <文件>")
        .into(),
    );
  };
  let spec = TaskSpec {
    server,
    schedule: match a.schedule {
      Some(s) => s,
      None if matches!(how, TaskKind::Script { .. }) => String::new(),
      None => {
        return Err(ApiError::invalid("缺少 --schedule").into());
      }
    },
    how,
    timeout_secs: a.timeout,
    enabled: !a.disabled,
    notify: !a.no_notify,
  };
  let r: TaskSpec = c
    .put(&format!("/api/tasks/{}", seg(&a.name)), &spec)
    .await?;
  out(j, &r, |_| println!("已保存定时任务 {}", a.name));
  Ok(())
}

fn need_server(s: Option<String>) -> Result<String, ApiError> {
  s.ok_or_else(|| ApiError::invalid("缺少 --server"))
}

/// 触发后每 2 秒查一次，直到这条记录结束。
async fn run(c: &Client, name: &str, j: bool) -> CliResult<()> {
  let r: serde_json::Value = c
    .post(
      &format!("/api/tasks/{}/run", seg(name)),
      &serde_json::json!({}),
    )
    .await?;
  let id = r["id"].as_i64().unwrap_or_default();
  if !j {
    println!("开始运行 {name}（#{id}）");
  }
  let done = loop {
    let runs: Vec<TaskRunView> = c
      .get(&format!("/api/tasks/{}/runs?limit=50", seg(name)))
      .await?;
    match runs.into_iter().find(|r| r.id == id) {
      Some(r) if r.status != TaskStatus::Running => break r,
      Some(_) => tokio::time::sleep(Duration::from_secs(2)).await,
      None => {
        return Err(ApiError::internal("运行记录不见了").into());
      }
    }
  };
  let ok = done.status == TaskStatus::Succeeded;
  out(j, &done, |r| {
    println!("{}\n{}", line(r), r.output);
  });
  if ok { Ok(()) } else { Err(CliError::Exit(4)) }
}

fn line(r: &TaskRunView) -> String {
  let secs = r
    .ended_at
    .map(|e| (e - r.started_at).num_seconds())
    .map_or(String::new(), |s| format!(" {s}s"));
  let code = r
    .exit_code
    .map_or(String::new(), |c| format!(" 退出码 {c}"));
  let by = match r.trigger.as_str() {
    "manual" => " 手动",
    "hook" => " 网址",
    _ => "",
  };
  format!(
    "#{} {} {}{secs}{code}{by}",
    r.id,
    local(r.started_at),
    status(r.status)
  )
}

fn kind(k: &TaskKind) -> &'static str {
  match k {
    TaskKind::Exec { .. } => "容器内",
    TaskKind::Container { .. } => "一次性容器",
    TaskKind::Host { .. } => "宿主机",
    TaskKind::Ping { .. } => "外部报到",
    TaskKind::Script { .. } => "脚本",
  }
}

fn status(s: TaskStatus) -> &'static str {
  match s {
    TaskStatus::Running => "运行中",
    TaskStatus::Succeeded => "成功",
    TaskStatus::Failed => "失败",
    TaskStatus::TimedOut => "超时",
    TaskStatus::Skipped => "跳过",
  }
}

fn local(t: chrono::DateTime<chrono::Utc>) -> String {
  t.with_timezone(
    &chrono::FixedOffset::east_opt(8 * 3600).expect("时区"),
  )
  .format("%m-%d %H:%M")
  .to_string()
}

fn runtime_name(runtime: ScriptRuntime) -> &'static str {
  match runtime {
    ScriptRuntime::Python => "Python",
    ScriptRuntime::Node => "Node",
    ScriptRuntime::Shell => "Shell",
  }
}
