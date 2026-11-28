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

#[path = "task_set.rs"]
mod edit;

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
    #[arg(long)]
    reveal: bool,
  },
  /// 立即运行并等待结果；失败时退出码为 4。
  Run {
    name: String,
    #[arg(long)]
    env: Vec<String>,
    #[arg(long)]
    no_wait: bool,
  },
  Enable {
    name: String,
    #[arg(long)]
    dry_run: bool,
  },
  Disable {
    name: String,
    #[arg(long)]
    dry_run: bool,
  },
  Set(edit::SetArgs),
  Cancel {
    run_id: i64,
  },
  /// 列出或下载任务运行产物。
  Artifacts(crate::task_artifacts::ArtifactArgs),
  /// 最近的运行记录，最新一条带完整输出。
  Logs {
    name: String,
    #[arg(short = 'n', long, default_value_t = 10)]
    limit: u32,
    #[arg(long, conflicts_with = "limit")]
    run: Option<i64>,
  },
  /// 删除任务和它的运行记录。
  Rm {
    name: String,
    #[arg(long)]
    data: bool,
    /// 只预览会改什么，不执行。
    #[arg(long)]
    dry_run: bool,
  },
}

#[derive(Args)]
pub struct AddArgs {
  name: String,
  /// 只预览会改什么，不保存。
  #[arg(long)]
  dry_run: bool,
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
  /// 从文件读取依赖清单。
  #[arg(long, requires = "script")]
  deps: Option<String>,
  /// 开启网址触发。
  #[arg(long, requires = "script")]
  hook: bool,
  /// 关闭网址触发。
  #[arg(long, requires = "script", conflicts_with = "hook")]
  no_hook: bool,
  /// 轮换网址触发或外部报到口令。
  #[arg(long, conflicts_with = "no_hook")]
  rotate_token: bool,
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
  #[arg(long, conflicts_with = "no_use_egress")]
  use_egress: bool,
  #[arg(long)]
  no_use_egress: bool,
  /// 关联服务停用时跳过，仅适用于容器内执行任务。
  #[arg(long)]
  skip_if_stopped: bool,
  /// 离线后允许补跑的分钟数（1～1440）。
  #[arg(long)]
  catch_up: Option<u32>,
  /// 每次运行最多保留多少 MiB 的产物。
  #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200))]
  artifacts_max_mb: Option<u32>,
  /// 保留最近多少次运行的产物。
  #[arg(long, value_parser = clap::value_parser!(u32).range(1..=20))]
  artifacts_keep: Option<u32>,
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
            if t.migrating {
              "迁移中"
            } else {
              t.target_server.as_deref().unwrap_or(&t.spec.server)
            },
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
    TaskCmd::Show { name, reveal } => {
      let query = if reveal { "?reveal=true" } else { "" };
      let t: TaskView =
        c.get(&format!("/api/tasks/{}{query}", seg(&name))).await?;
      show(&t, reveal, j);
      Ok(())
    }
    TaskCmd::Artifacts(args) => {
      crate::task_artifacts::run(c, args, j).await
    }
    TaskCmd::Run { name, env, no_wait } => {
      run(c, &name, &env, no_wait, j).await
    }
    TaskCmd::Enable { name, dry_run } => {
      edit::toggle(c, &name, true, dry_run, j).await
    }
    TaskCmd::Disable { name, dry_run } => {
      edit::toggle(c, &name, false, dry_run, j).await
    }
    TaskCmd::Set(args) => edit::set(c, args, j).await,
    TaskCmd::Cancel { run_id } => {
      let v: serde_json::Value = c
        .post(
          &format!("/api/tasks/runs/{run_id}/cancel"),
          &serde_json::json!({}),
        )
        .await?;
      out(j, &v, |_| println!("已请求取消任务运行 #{run_id}"));
      Ok(())
    }
    TaskCmd::Logs { name, limit, run } => {
      if let Some(id) = run {
        let v: TaskRunView = c.get(&run_path(&name, id)).await?;
        out(j, &v, |r| println!("{}\n{}", line(r), r.output));
        return Ok(());
      }
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
    TaskCmd::Rm {
      name,
      dry_run: true,
      ..
    } => {
      let before = crate::preview::get_or_null(
        c,
        &format!("/api/tasks/{}", seg(&name)),
      )
      .await?;
      if before.is_null() {
        return Err(
          ApiError::not_found(format!("定时任务 {name} 不存在"))
            .into(),
        );
      }
      crate::preview::show(
        j,
        &format!("task/{name}"),
        &before["spec"],
        &serde_json::Value::Null,
      )
    }
    TaskCmd::Rm { name, data, .. } => {
      let r: serde_json::Value = c
        .delete(&format!("/api/tasks/{}?data={data}", seg(&name)))
        .await?;
      out(j, &r, |_| println!("已删除定时任务 {name}"));
      Ok(())
    }
  }
}

fn show(t: &TaskView, reveal: bool, j: bool) {
  out(j, t, |t| {
    println!(
      "{}",
      serde_json::to_string_pretty(&t.spec).unwrap_or_default()
    );
    if let Some(server) = &t.target_server {
      println!("执行服务器：{server}");
    } else if t.migrating {
      println!("迁移中");
    }
    if let TaskKind::Script { runtime, code, .. } = &t.spec.how {
      println!("运行环境：{}", runtime_name(*runtime));
      if let Some(url) = &t.hook_url {
        println!("触发地址：{url}");
      }
      print!("\n{code}");
    }
    if let Some(url) = &t.ping_url {
      if reveal {
        println!("\n报到：脚本成功后 curl -fsS -m 10 {url}");
        println!("失败时：curl -fsS -m 10 {url}/fail");
      } else {
        println!("\n报到地址：{url}");
      }
    }
    if !reveal && (t.ping_url.is_some() || t.hook_url.is_some()) {
      println!("完整地址含口令，加上 --reveal 查看（需写权限）");
    }
  });
}

pub(super) fn shell_join(args: &[String]) -> String {
  if let [script] = args {
    return script.clone();
  }
  args
    .iter()
    .map(|arg| {
      if !arg.is_empty()
        && arg.bytes().all(|b| {
          b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b)
        })
      {
        arg.clone()
      } else {
        format!("'{}'", arg.replace(char::from(39), "'\\''"))
      }
    })
    .collect::<Vec<_>>()
    .join(" ")
}

async fn add(c: &Client, a: AddArgs, j: bool) -> CliResult<()> {
  let command =
    (!a.command.is_empty()).then(|| shell_join(&a.command));
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
    let old = if a.no_hook || a.hook {
      None
    } else {
      match c
        .get::<TaskView>(&format!("/api/tasks/{}", seg(&a.name)))
        .await
      {
        Ok(task) => match task.spec.how {
          TaskKind::Script { hook, .. } => {
            hook.map(|_| String::new())
          }
          _ => None,
        },
        Err(CliError::Api(error))
          if error.code == wharf_api_types::ErrorCode::NotFound =>
        {
          None
        }
        Err(error) => return Err(error),
      }
    };
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
        deps: a
          .deps
          .as_deref()
          .map(std::fs::read_to_string)
          .transpose()
          .map_err(|_| ApiError::invalid("读取依赖清单失败"))?
          .unwrap_or_default(),
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
      None if !matches!(how, TaskKind::Ping { .. }) => String::new(),
      None => {
        return Err(ApiError::invalid("缺少 --schedule").into());
      }
    },
    how,
    timeout_secs: a.timeout,
    enabled: !a.disabled,
    notify: !a.no_notify,
    use_egress: a.use_egress && !a.no_use_egress,
    skip_if_stopped: a.skip_if_stopped,
    catch_up_mins: a.catch_up,
    artifacts_max_mb: a.artifacts_max_mb,
    artifacts_keep: a.artifacts_keep,
  };
  if a.rotate_token
    && !matches!(
      &spec.how,
      TaskKind::Ping { .. } | TaskKind::Script { hook: Some(_), .. }
    )
  {
    return Err(ApiError::invalid("只有开启了 --hook 的脚本任务或 --ping 外部报到任务支持轮换口令").into());
  }
  if a.dry_run {
    let before = crate::preview::get_or_null(
      c,
      &format!("/api/tasks/{}", seg(&a.name)),
    )
    .await?;
    let mut after =
      serde_json::to_value(&spec).map_err(anyhow::Error::from)?;
    if a.rotate_token {
      after["token"] = serde_json::json!("<将轮换为新口令>");
    }
    return crate::preview::show(
      j,
      &format!("task/{}", a.name),
      &before["spec"],
      &after,
    );
  }
  let mut path = format!("/api/tasks/{}", seg(&a.name));
  if a.rotate_token {
    path.push_str("?rotate_token=true");
  }
  let mut r: TaskSpec = c.put(&path, &spec).await?;
  match &mut r.how {
    TaskKind::Ping { token, .. }
    | TaskKind::Script {
      hook: Some(token), ..
    } => token.clear(),
    _ => {}
  }
  out(j, &r, |_| println!("已保存定时任务 {}", a.name));
  Ok(())
}

fn need_server(s: Option<String>) -> Result<String, ApiError> {
  s.ok_or_else(|| ApiError::invalid("缺少 --server"))
}

fn run_path(name: &str, id: i64) -> String {
  format!("/api/tasks/{}/runs/{id}", seg(name))
}

/// 触发后每 2 秒查一次，直到这条记录结束。
async fn run(
  c: &Client,
  name: &str,
  env: &[String],
  no_wait: bool,
  j: bool,
) -> CliResult<()> {
  let body = if env.is_empty() {
    serde_json::json!({})
  } else {
    let env = edit::parse_env(env)?;
    c.require_exec_v2_core().await?;
    serde_json::json!({ "env": env })
  };
  let r: serde_json::Value = c
    .post(&format!("/api/tasks/{}/run", seg(name)), &body)
    .await?;
  let id = r["id"]
    .as_i64()
    .ok_or_else(|| ApiError::internal("缺少任务运行记录 id"))?;
  if no_wait {
    out(j, &r, |r| {
      if r["status"] == "skipped" {
        println!("上一次还没跑完，已跳过 #{id}");
      } else {
        println!("开始运行 {name}（#{id}）");
        println!(
          "查看：wharf task logs {name} --run {id}，取消：wharf task cancel {id}"
        );
      }
    });
    return Ok(());
  }
  if !j {
    println!("开始运行 {name}（#{id}）");
  }
  let path = run_path(name, id);
  let wait = async {
    loop {
      let run: TaskRunView = match c.get(&path).await {
        // 升级过渡期兼容尚未提供单条查询的控制面。
        Err(CliError::Api(e))
          if e.code == wharf_api_types::ErrorCode::NotFound =>
        {
          let runs: Vec<TaskRunView> = c
            .get(&format!("/api/tasks/{}/runs?limit=50", seg(name)))
            .await?;
          runs.into_iter().find(|run| run.id == id).ok_or(e)?
        }
        result => result?,
      };
      if run.status != TaskStatus::Running {
        break Ok::<_, CliError>(run);
      }
      tokio::time::sleep(Duration::from_secs(2)).await;
    }
  };
  let done = tokio::select! {
    result = wait => result?,
    _ = tokio::signal::ctrl_c() => {
      let hint = format!("任务 #{id} 仍在后台运行，可用 wharf task cancel {id} 取消");
      if j {
        crate::print::error(&ApiError::new(wharf_api_types::ErrorCode::Cancelled, "已停止本地等待").with_hint(hint), true);
      } else {
        eprintln!("已停止本地等待。{hint}");
      }
      return Err(CliError::Exit(130));
    }
  };
  let ok = done.status == TaskStatus::Succeeded;
  out(j, &done, |r| println!("{}\n{}", line(r), r.output));
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
    "catch_up" => " 补跑",
    _ => "",
  };
  let mem = r
    .mem_peak
    .map_or(String::new(), |m| format!(" 内存峰值 {m} 字节"));
  format!(
    "#{} {} {}{secs}{code}{by}{mem}",
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
    TaskStatus::Cancelled => "已取消",
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

#[test]
fn shell_join_preserves_multiword_argument() {
  assert_eq!(
    shell_join(&["psql".into(), "-c".into(), "SELECT 1".into()]),
    "psql -c 'SELECT 1'"
  );
  assert_eq!(
    shell_join(&["echo".into(), "a'b".into()]),
    "echo 'a'\\''b'"
  );
}
