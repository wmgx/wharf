//! `wharf task`：定时任务。改动直接生效，不走计划。

use std::{collections::BTreeMap, time::Duration};

use clap::{Args, Subcommand};
use wharf_api_types::{
  ApiError,
  view::{TaskKind, TaskRunView, TaskSpec, TaskStatus, TaskView},
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
  schedule: String,
  /// 在这个服务的容器里执行；服务器取服务所在的服务器。
  #[arg(long, group = "how")]
  exec: Option<String>,
  /// 跑一次性容器用的镜像。
  #[arg(long, group = "how")]
  image: Option<String>,
  /// 在宿主机执行（要服务器开了"命令执行"）。
  #[arg(long, group = "how")]
  host: bool,
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
            t.spec.schedule,
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
  let (how, server) = if let Some(service) = a.exec {
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
        .with_hint("--exec <服务>、--image <镜像> 或 --host")
        .into(),
    );
  };
  let spec = TaskSpec {
    server,
    schedule: a.schedule,
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
  let by = if r.trigger == "manual" { " 手动" } else { "" };
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
